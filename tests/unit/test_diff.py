import difflib
import subprocess

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prrisk.diff import Status, parse_diff
from prrisk.errors import DiffParseError


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@t")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "keep.py").write_text("a = 1\nb = 2\nc = 3\n")
    (tmp_path / "gone.py").write_text("x = 1\n")
    (tmp_path / "old_name.py").write_text("".join(f"line{i}\n" for i in range(20)))
    (tmp_path / "img.bin").write_bytes(b"\x00\x01\x02")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def test_real_git_diff_covers_every_change_type(repo):
    (repo / "keep.py").write_text("a = 1\nb = 20\nc = 3\nd = 4\n")
    (repo / "gone.py").unlink()
    (repo / "new.py").write_text("print('hi')\n")
    git(repo, "mv", "old_name.py", "new_name.py")
    text = (repo / "new_name.py").read_text().replace("line5\n", "LINE5\n")
    (repo / "new_name.py").write_text(text)
    (repo / "img.bin").write_bytes(b"\x00\x09\x02\xff")
    git(repo, "add", "-A")
    files = {f.path: f for f in parse_diff(git(repo, "diff", "--cached", "-M"))}

    keep = files["keep.py"]
    assert keep.status is Status.MODIFIED
    assert keep.added == {2: "b = 20", 4: "d = 4"} and keep.removed == {2: "b = 2"}
    assert files["gone.py"].status is Status.DELETED and files["gone.py"].removed == {1: "x = 1"}
    assert files["new.py"].status is Status.ADDED and files["new.py"].added == {1: "print('hi')"}
    renamed = files["new_name.py"]
    assert renamed.status is Status.RENAMED and renamed.old_path == "old_name.py"
    assert renamed.added == {6: "LINE5"} and renamed.removed == {6: "line5"}
    assert files["img.bin"].binary and files["img.bin"].churn == 0


def test_no_newline_marker_and_multiple_hunks(repo):
    body = "".join(f"v{i}\n" for i in range(40))
    (repo / "keep.py").write_text(body)
    git(repo, "commit", "-qam", "long")
    changed = body.replace("v2\n", "V2\n").replace("v35\n", "V35\n").rstrip("\n")
    (repo / "keep.py").write_text(changed)
    [f] = parse_diff(git(repo, "diff"))
    assert set(f.added) == {3, 36, 40} and set(f.removed) == {3, 36, 40}


def test_empty_diff_is_empty():
    assert parse_diff("") == []


@pytest.mark.parametrize(
    "text",
    [
        "just some text\n",
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ nonsense @@\n",
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n a\n",  # truncated
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n+c\n",  # too long
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n*a\n",
    ],
)
def test_malformed_diffs_are_rejected(text):
    with pytest.raises(DiffParseError):
        parse_diff(text)


lines = st.lists(st.sampled_from(["a", "b", "c", "d", "e", "x = 1", ""]), max_size=30)


@settings(max_examples=200)
@given(lines, lines)
def test_parsed_lines_reconstruct_both_versions(old, new):
    body = "".join(
        line if line.endswith("\n") else line + "\n"
        for line in difflib.unified_diff(
            [o + "\n" for o in old], [n + "\n" for n in new], "a/f.py", "b/f.py", n=3
        )
    )
    if not body:
        return
    [f] = parse_diff("diff --git a/f.py b/f.py\n" + body)
    kept_old = [line for i, line in enumerate(old, 1) if i not in f.removed]
    kept_new = [line for i, line in enumerate(new, 1) if i not in f.added]
    assert kept_old == kept_new
    assert all(new[i - 1] == text for i, text in f.added.items())
    assert all(old[i - 1] == text for i, text in f.removed.items())
