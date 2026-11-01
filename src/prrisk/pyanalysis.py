"""Python-specific analysis with the standard `ast` module.

* which functions a change touches (by line range),
* how each touched function changed (added / modified / deleted, signature, complexity),
* which modules import a changed module, and which functions call a changed function by name.
"""

from __future__ import annotations

import ast
import enum
from collections import defaultdict
from dataclasses import dataclass, field

_BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler,
             ast.With, ast.AsyncWith, ast.Assert, ast.comprehension, ast.match_case)


@dataclass(frozen=True)
class FunctionInfo:
    qualname: str
    start: int
    end: int
    signature: str
    complexity: int
    is_test: bool

    @property
    def length(self) -> int:
        return self.end - self.start + 1

    @property
    def is_public(self) -> bool:
        return not any(part.startswith("_") for part in self.qualname.split("."))


class ChangeKind(enum.StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass(frozen=True)
class FunctionChange:
    path: str
    qualname: str
    kind: ChangeKind
    old: FunctionInfo | None
    new: FunctionInfo | None

    @property
    def signature_changed(self) -> bool:
        return self.old is not None and self.new is not None and \
            self.old.signature != self.new.signature

    @property
    def complexity_delta(self) -> int:
        return (self.new.complexity if self.new else 0) - (self.old.complexity if self.old else 0)

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]


def cyclomatic_complexity(node: ast.AST) -> int:
    """McCabe: 1 + decision points. Boolean operators add one per extra operand."""
    score = 1
    for child in ast.walk(node):
        if isinstance(child, _BRANCHES):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
    return score


def _signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return f"({ast.unparse(fn.args)})" + (f" -> {ast.unparse(fn.returns)}" if fn.returns else "")


def functions(source: str, path: str) -> dict[str, FunctionInfo]:
    """All functions and methods, keyed by dotted qualname (Class.method, outer.inner)."""
    tree = ast.parse(source, filename=path)
    is_test_file = path.rsplit("/", 1)[-1].startswith("test_") or "/tests/" in f"/{path}"
    out: dict[str, FunctionInfo] = {}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                qual = f"{prefix}{child.name}"
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                out[qual] = FunctionInfo(
                    qualname=qual,
                    start=start,
                    end=child.end_lineno or child.lineno,
                    signature=_signature(child),
                    complexity=cyclomatic_complexity(child),
                    is_test=is_test_file and child.name.startswith("test"),
                )
                visit(child, f"{qual}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")

    visit(tree, "")
    return out


def _innermost(funcs: dict[str, FunctionInfo], line: int) -> str | None:
    best: FunctionInfo | None = None
    for f in funcs.values():
        if f.start <= line <= f.end and (best is None or f.length < best.length):
            best = f
    return best.qualname if best else None


def changed_functions(
    path: str,
    old_src: str | None,
    new_src: str | None,
    added: set[int],
    removed: set[int],
) -> list[FunctionChange]:
    """Map changed line numbers onto the innermost enclosing function on each side."""
    old_funcs = functions(old_src, path) if old_src is not None else {}
    new_funcs = functions(new_src, path) if new_src is not None else {}
    touched: set[str] = set()
    for line in added:
        if (q := _innermost(new_funcs, line)) is not None:
            touched.add(q)
    for line in removed:
        if (q := _innermost(old_funcs, line)) is not None:
            touched.add(q)
    changes = []
    for qual in sorted(touched):
        old, new = old_funcs.get(qual), new_funcs.get(qual)
        kind = ChangeKind.ADDED if old is None else ChangeKind.DELETED if new is None \
            else ChangeKind.MODIFIED
        changes.append(FunctionChange(path, qual, kind, old, new))
    return changes


def module_name(path: str) -> str:
    parts = path[:-3].split("/") if path.endswith(".py") else path.split("/")
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


@dataclass
class RepoIndex:
    """Import graph and name-based call sites for every Python file at one revision."""

    importers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    callers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    test_mentions: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    unparsable: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, files: dict[str, str]) -> RepoIndex:
        index = cls()
        for path, src in files.items():
            try:
                tree = ast.parse(src, filename=path)
            except SyntaxError:
                index.unparsable.append(path)
                continue
            mod = module_name(path)
            is_test = path.rsplit("/", 1)[-1].startswith("test_") or "/tests/" in f"/{path}"
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        index.importers[alias.name].add(mod)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    index.importers[node.module].add(mod)
                    for alias in node.names:
                        index.importers[f"{node.module}.{alias.name}"].add(mod)
                        if is_test:
                            index.test_mentions[alias.name].add(path)
                elif isinstance(node, ast.Call):
                    func = node.func
                    name = func.id if isinstance(func, ast.Name) else \
                        func.attr if isinstance(func, ast.Attribute) else None
                    if name:
                        index.callers[name].add(path)
                        if is_test:
                            index.test_mentions[name].add(path)
        return index

    def dependents_of_module(self, path: str) -> set[str]:
        mod = module_name(path)
        return {m for key, mods in self.importers.items()
                if key == mod or key.startswith(mod + ".") for m in mods} - {mod}

    def call_sites(self, func_name: str, exclude: str) -> set[str]:
        return self.callers.get(func_name, set()) - {exclude}

    def tests_mentioning(self, func_name: str) -> set[str]:
        return set(self.test_mentions.get(func_name, set()))
