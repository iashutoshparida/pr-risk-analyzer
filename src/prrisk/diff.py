"""Parse unified diffs (`git diff`, GitHub's .diff media type) into per-file line sets.

Only line numbers are kept: `added` are line numbers in the new file, `removed` are line numbers
in the old file. Everything downstream (which functions changed, which findings are new) works
from these sets.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from prrisk.errors import DiffParseError

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_GIT_HEADER = re.compile(r"^diff --git a/(.*) b/(.*)$")


class Status(enum.StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


@dataclass
class FileChange:
    path: str  # path in the new tree (old path for deletions)
    old_path: str | None
    status: Status
    added: dict[int, str] = field(default_factory=dict)  # new line number -> text
    removed: dict[int, str] = field(default_factory=dict)  # old line number -> text
    binary: bool = False

    @property
    def churn(self) -> int:
        return len(self.added) + len(self.removed)

    @property
    def is_python(self) -> bool:
        return self.path.endswith(".py")


def _strip_prefix(raw: str) -> str | None:
    raw = raw.strip().split("\t")[0]
    if raw == "/dev/null":
        return None
    return raw[2:] if raw.startswith(("a/", "b/")) else raw


def parse_diff(text: str) -> list[FileChange]:
    files: list[FileChange] = []
    current: FileChange | None = None
    old_ln = new_ln = 0
    old_left = new_left = 0
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        header = _GIT_HEADER.match(line)
        if header:
            current = FileChange(
                path=header.group(2), old_path=header.group(1), status=Status.MODIFIED
            )
            files.append(current)
            old_left = new_left = 0
        elif current is not None and old_left == 0 and new_left == 0:
            if line.startswith("new file mode"):
                current.status, current.old_path = Status.ADDED, None
            elif line.startswith("deleted file mode"):
                current.status = Status.DELETED
                current.path = current.old_path or current.path
            elif line.startswith("rename from "):
                current.status, current.old_path = Status.RENAMED, line[len("rename from ") :]
            elif line.startswith("rename to "):
                current.path = line[len("rename to ") :]
            elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
                current.binary = True
            elif line.startswith("--- "):
                old = _strip_prefix(line[4:])
                if old is None:
                    current.status, current.old_path = Status.ADDED, None
            elif line.startswith("+++ "):
                new = _strip_prefix(line[4:])
                if new is None:
                    current.status = Status.DELETED
                elif current.status is not Status.DELETED:
                    current.path = new
            elif line.startswith(("+", "-", " ")) and not line.startswith(("+++ ", "--- ")):
                raise DiffParseError(f"hunk longer than its header says in {current.path}")
            elif line.startswith("@@"):
                match = _HUNK.match(line)
                if not match:
                    raise DiffParseError(f"malformed hunk header: {line!r}")
                old_ln, new_ln = int(match.group(1)), int(match.group(3))
                old_left = int(match.group(2)) if match.group(2) is not None else 1
                new_left = int(match.group(4)) if match.group(4) is not None else 1
        elif current is not None:
            # inside a hunk
            if line.startswith("\\"):  # "\ No newline at end of file"
                pass
            elif line.startswith("+"):
                current.added[new_ln] = line[1:]
                new_ln += 1
                new_left -= 1
            elif line.startswith("-"):
                current.removed[old_ln] = line[1:]
                old_ln += 1
                old_left -= 1
            elif line.startswith(" ") or line == "":
                old_ln += 1
                new_ln += 1
                old_left -= 1
                new_left -= 1
            else:
                raise DiffParseError(f"unexpected line inside hunk: {line[:60]!r}")
            if old_left < 0 or new_left < 0:
                raise DiffParseError(f"hunk longer than its header says in {current.path}")
        i += 1
    if text.strip() and not files:
        raise DiffParseError("input has no 'diff --git' file headers")
    if old_left > 0 or new_left > 0:
        raise DiffParseError("diff ended in the middle of a hunk (truncated input?)")
    return files
