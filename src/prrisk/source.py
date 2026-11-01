"""Read file contents at a revision. Two implementations: a local git repository and GitHub."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol

from prrisk.errors import SourceError

_REF_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-~^@{}")


class SourceProvider(Protocol):
    def read(self, ref: str, path: str) -> str | None:
        """File text at `ref`, or None if the file does not exist there."""

    def list_python_files(self, ref: str) -> list[str]:
        """Every .py path in the tree at `ref`."""


def _check_ref(ref: str) -> str:
    # Refs reach a subprocess argv (never a shell), but a leading '-' would be read as an option.
    if not ref or ref.startswith("-") or not set(ref) <= _REF_OK:
        raise SourceError(f"invalid git ref: {ref!r}")
    return ref


class LocalGitSource:
    def __init__(self, repo: Path, timeout_s: float = 30.0) -> None:
        self.repo = repo.resolve()
        self.timeout_s = timeout_s
        if not (self.repo / ".git").exists():
            raise SourceError(f"{self.repo} is not a git repository")

    def _git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603 - fixed argv, validated refs, no shell
            ["git", "-C", str(self.repo), *args],  # noqa: S607
            capture_output=True,
            timeout=self.timeout_s,
            check=False,
        )

    def diff(self, base: str, head: str) -> str:
        proc = self._git(
            "diff", "-M", "--no-color", "--no-ext-diff", f"{_check_ref(base)}...{_check_ref(head)}"
        )
        if proc.returncode != 0:
            raise SourceError(proc.stderr.decode(errors="replace").strip() or "git diff failed")
        return proc.stdout.decode("utf-8", errors="replace")

    def read(self, ref: str, path: str) -> str | None:
        if path.startswith("-") or ".." in Path(path).parts:
            raise SourceError(f"invalid path: {path!r}")
        proc = self._git("show", f"{_check_ref(ref)}:{path}")
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", errors="replace")

    def list_python_files(self, ref: str) -> list[str]:
        proc = self._git("ls-tree", "-r", "--name-only", _check_ref(ref))
        if proc.returncode != 0:
            raise SourceError(proc.stderr.decode(errors="replace").strip() or "git ls-tree failed")
        return [p for p in proc.stdout.decode().splitlines() if p.endswith(".py")]
