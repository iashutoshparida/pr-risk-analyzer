"""Deterministic checks. Every finding points at a line this PR added, so reviewers see only
problems the PR introduces, not old debt in files it happened to touch."""

from __future__ import annotations

import ast
import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass

from prrisk.diff import FileChange, Status
from prrisk.pyanalysis import ChangeKind, FunctionChange, RepoIndex


class Severity(enum.IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    category: str  # security | maintainability | compatibility | testing
    severity: Severity
    message: str
    function: str | None = None


COMPLEXITY_JUMP = 5
COMPLEXITY_LIMIT = 10
LONG_FUNCTION = 60

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     Severity.CRITICAL),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("hard-coded credential",
     re.compile(r"""(?i)\b(password|passwd|secret|api_?key|token)\b\s*[:=]\s*['"][^'"\s]{8,}['"]"""),
     Severity.HIGH),
]
_PLACEHOLDER = re.compile(r"(?i)(example|changeme|dummy|placeholder|your[_-]|xxx|\*\*\*|<.*>)")
_TODO = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_dynamic_string(node: ast.expr) -> bool:
    """f-strings, '...'.format(...), '...' % x and string concatenation with a non-literal."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, added: set[int]) -> None:
        self.path, self.added = path, added
        self.out: list[Finding] = []

    def _new(self, node: ast.AST) -> bool:
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start) or start
        return any(line in self.added for line in range(start, end + 1))

    def _add(self, node: ast.AST, rule: str, cat: str, sev: Severity, msg: str) -> None:
        self.out.append(Finding(self.path, getattr(node, "lineno", 0), rule, cat, sev, msg))

    def visit_Call(self, node: ast.Call) -> None:
        if self._new(node):
            name = _dotted(node.func)
            short = name.rsplit(".", 1)[-1]
            if name in ("eval", "exec"):
                self._add(node, "SEC001", "security", Severity.HIGH,
                          f"`{name}()` runs arbitrary code; avoid it on any external input")
            elif _is_true(_kw(node, "shell")) and name.startswith(("subprocess", "Popen", "run",
                                                                    "call", "check_")):
                self._add(node, "SEC002", "security", Severity.HIGH,
                          f"`{name}(..., shell=True)` allows shell injection; pass an argument list")
            elif name in ("os.system", "os.popen"):
                self._add(node, "SEC002", "security", Severity.MEDIUM,
                          f"`{name}()` goes through the shell; use subprocess with a list")
            elif name in ("pickle.load", "pickle.loads", "marshal.loads", "dill.loads"):
                self._add(node, "SEC003", "security", Severity.MEDIUM,
                          f"`{name}()` can execute code when the data is untrusted")
            elif name == "yaml.load" and _kw(node, "Loader") is None:
                self._add(node, "SEC004", "security", Severity.MEDIUM,
                          "`yaml.load()` without a Loader; use `yaml.safe_load()`")
            elif short in ("execute", "executemany", "raw") and node.args \
                    and _is_dynamic_string(node.args[0]):
                self._add(node, "SEC005", "security", Severity.HIGH,
                          "SQL built with string formatting; use bound parameters")
            elif _is_false(_kw(node, "verify")):
                self._add(node, "SEC006", "security", Severity.MEDIUM,
                          "TLS certificate verification disabled (`verify=False`)")
            elif name in ("hashlib.md5", "hashlib.sha1"):
                self._add(node, "SEC007", "security", Severity.LOW,
                          f"`{name}` is weak; do not use it for passwords or signatures")
            elif name in ("breakpoint", "pdb.set_trace", "ipdb.set_trace"):
                self._add(node, "MNT003", "maintainability", Severity.MEDIUM,
                          "debugger call left in the code")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if self._new(node):
            swallowed = all(isinstance(s, ast.Pass) for s in node.body)
            broad = node.type is None or _dotted(node.type) in ("Exception", "BaseException")
            if node.type is None:
                self._add(node, "MNT001", "maintainability", Severity.MEDIUM,
                          "bare `except:` also catches KeyboardInterrupt and SystemExit")
            elif broad and swallowed:
                self._add(node, "MNT001", "maintainability", Severity.MEDIUM,
                          "broad exception silently swallowed; errors will disappear")
        self.generic_visit(node)

    def _check_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if isinstance(default, ast.List | ast.Dict | ast.Set) and self._new(default):
                self._add(default, "MNT002", "maintainability", Severity.LOW,
                          f"mutable default argument in `{node.name}` is shared between calls")
        self.generic_visit(node)

    visit_FunctionDef = _check_defaults
    visit_AsyncFunctionDef = _check_defaults


def python_findings(path: str, new_src: str, added: set[int]) -> list[Finding]:
    try:
        tree = ast.parse(new_src, filename=path)
    except SyntaxError as exc:
        return [Finding(path, exc.lineno or 0, "MNT000", "maintainability", Severity.HIGH,
                        f"file does not parse: {exc.msg}")]
    visitor = _Visitor(path, added)
    visitor.visit(tree)
    return visitor.out


def text_findings(change: FileChange) -> list[Finding]:
    """Language-independent checks on added lines (any file type)."""
    out = []
    for line_no, text in change.added.items():
        for label, pattern, sev in _SECRET_PATTERNS:
            match = pattern.search(text)
            if match and not _PLACEHOLDER.search(match.group(0)):
                out.append(Finding(change.path, line_no, "SEC010", "security", sev,
                                   f"possible {label} committed to the repository"))
                break
        if _TODO.search(text):
            out.append(Finding(change.path, line_no, "MNT010", "maintainability", Severity.INFO,
                               "new TODO/FIXME: track it in an issue"))
    return out


def _first_line(fc: FunctionChange) -> int:
    info = fc.new or fc.old
    return info.start if info else 0


def change_findings(
    changes: Iterable[FunctionChange], index: RepoIndex, files: dict[str, FileChange]
) -> list[Finding]:
    """Findings that need the before/after view or the rest of the repository."""
    out: list[Finding] = []
    for fc in changes:
        info = fc.new or fc.old
        if info is None:
            continue
        callers = index.call_sites(fc.name, exclude=fc.path)
        if fc.kind is ChangeKind.DELETED and info.is_test:
            out.append(Finding(fc.path, _first_line(fc), "TST001", "testing", Severity.MEDIUM,
                               f"test `{fc.qualname}` deleted", fc.qualname))
            continue
        if info.is_test:
            continue
        if fc.kind is ChangeKind.DELETED and info.is_public and callers:
            out.append(Finding(fc.path, _first_line(fc), "CMP002", "compatibility",
                               Severity.CRITICAL,
                               f"`{fc.qualname}` deleted but still called from "
                               f"{len(callers)} file(s): {', '.join(sorted(callers)[:3])}",
                               fc.qualname))
        if fc.signature_changed and info.is_public and callers:
            assert fc.old is not None and fc.new is not None
            out.append(Finding(fc.path, _first_line(fc), "CMP001", "compatibility", Severity.HIGH,
                               f"signature of `{fc.qualname}` changed {fc.old.signature} -> "
                               f"{fc.new.signature}; {len(callers)} caller file(s) may break",
                               fc.qualname))
        if fc.new is not None:
            jump = fc.complexity_delta if fc.old is not None else 0
            if jump >= COMPLEXITY_JUMP or (fc.new.complexity > COMPLEXITY_LIMIT and
                                           fc.complexity_delta > 0):
                out.append(Finding(fc.path, fc.new.start, "MNT004", "maintainability",
                                   Severity.MEDIUM,
                                   f"complexity of `{fc.qualname}` is now {fc.new.complexity} "
                                   f"({fc.complexity_delta:+d}); consider splitting it",
                                   fc.qualname))
            if fc.new.length > LONG_FUNCTION and (fc.old is None or fc.old.length <= LONG_FUNCTION):
                out.append(Finding(fc.path, fc.new.start, "MNT005", "maintainability",
                                   Severity.LOW,
                                   f"`{fc.qualname}` is {fc.new.length} lines long",
                                   fc.qualname))
    for path, change in files.items():
        name = path.rsplit("/", 1)[-1]
        if change.status is Status.DELETED and (name.startswith("test_") or "/tests/" in f"/{path}"):
            out.append(Finding(path, 0, "TST001", "testing", Severity.MEDIUM,
                               "test file deleted"))
    return out


@dataclass(frozen=True)
class TestSuggestion:
    __test__ = False

    path: str
    function: str
    reason: str
    existing_tests: tuple[str, ...]


def missing_tests(
    changes: Iterable[FunctionChange], index: RepoIndex, changed_paths: set[str]
) -> list[TestSuggestion]:
    """Suggest a regression test for every changed, non-test function that no test in this PR
    touches. Existing tests that mention the function are listed so the author can extend them."""
    out = []
    for fc in changes:
        if fc.new is None or fc.new.is_test or fc.name.startswith("__"):
            continue
        mentioned = index.tests_mentioning(fc.name)
        if mentioned & changed_paths:
            continue  # this PR already updates a test that exercises the function
        if mentioned:
            reason = (f"`{fc.qualname}` changed but none of its tests changed in this PR; "
                      "add a case for the new behaviour")
        else:
            reason = f"`{fc.qualname}` has no test that references it"
        out.append(TestSuggestion(fc.path, fc.qualname, reason, tuple(sorted(mentioned))))
    return out
