import json

import httpx
import pytest

from prrisk.errors import SourceError
from prrisk.github import GitHubClient
from prrisk.report import MARKER

DIFF = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"


class FakeGitHub:
    """Routes requests like the GitHub REST API and records what was called."""

    def __init__(self, comments=None, status=None):
        self.comments = comments or []
        self.status = status
        self.calls = []

    def __call__(self, request):
        path, method = request.url.path, request.method
        self.calls.append(
            (method, path, request.headers.get("accept"), request.headers.get("authorization"))
        )
        if self.status:
            return httpx.Response(self.status)
        if path == "/repos/o/r/pulls/7":
            if "diff" in request.headers["accept"]:
                return httpx.Response(200, text=DIFF)
            return httpx.Response(
                200, json={"base": {"sha": "b" * 40}, "head": {"sha": "h" * 40}, "title": "Fix"}
            )
        if path == "/repos/o/r/contents/pkg/a.py":
            return httpx.Response(200, text="x = 2\n")
        if path.startswith("/repos/o/r/contents/"):
            return httpx.Response(404)
        if path.startswith("/repos/o/r/git/trees/"):
            return httpx.Response(
                200,
                json={
                    "tree": [
                        {"path": "pkg/a.py", "type": "blob"},
                        {"path": "pkg", "type": "tree"},
                        {"path": "README.md", "type": "blob"},
                    ]
                },
            )
        if path == "/repos/o/r/issues/7/comments" and method == "GET":
            return httpx.Response(200, json=self.comments)
        if method in ("POST", "PATCH"):
            self.posted = json.loads(request.content)["body"]
            return httpx.Response(201 if method == "POST" else 200, json={})
        return httpx.Response(404)


def client(fake, token="t0k3n"):
    return GitHubClient("o/r", token, client=httpx.Client(transport=httpx.MockTransport(fake)))


def test_reads_pr_diff_files_and_tree():
    fake = FakeGitHub()
    gh = client(fake)
    assert gh.pull(7)["head_sha"] == "h" * 40
    assert gh.pull_diff(7) == DIFF
    assert gh.read("h" * 40, "pkg/a.py") == "x = 2\n"
    assert gh.read("h" * 40, "missing.py") is None
    assert gh.list_python_files("h" * 40) == ["pkg/a.py"]
    assert all(auth == "Bearer t0k3n" for *_, auth in fake.calls)


def test_comment_is_updated_not_duplicated():
    fake = FakeGitHub(comments=[{"id": 1, "body": "lgtm"}, {"id": 2, "body": f"{MARKER} old"}])
    assert client(fake).upsert_comment(7, "new report") == "updated"
    assert ("PATCH", "/repos/o/r/issues/comments/2") in [(m, p) for m, p, *_ in fake.calls]
    assert fake.posted.startswith(MARKER)


def test_comment_is_created_when_absent():
    fake = FakeGitHub(comments=[{"id": 1, "body": "lgtm"}])
    assert client(fake).upsert_comment(7, f"{MARKER}\nreport") == "created"


@pytest.mark.parametrize("status", [401, 403, 500])
def test_http_errors_never_leak_the_token(status):
    with pytest.raises(SourceError) as exc:
        client(FakeGitHub(status=status)).pull(7)
    assert "t0k3n" not in str(exc.value)


def test_missing_pr_and_bad_repo_name():
    with pytest.raises(SourceError, match="not found"):
        client(FakeGitHub()).pull(8)
    with pytest.raises(SourceError, match="owner/name"):
        GitHubClient("not a repo", None)


def test_network_failure_is_a_source_error():
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(SourceError, match="ConnectError"):
        client(boom).pull_diff(7)
