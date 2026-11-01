import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from prrisk import cli
from prrisk.api import Settings, create_app
from tests.integration.test_engine import BASE, git
from tests.unit.test_github import FakeGitHub

RISKY = "def find(cur, uid):\n    return cur.execute(f'SELECT * FROM u WHERE id = {uid}')\n"


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@t")
    git(tmp_path, "config", "user.name", "t")
    for path, text in BASE.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "base")
    git(tmp_path, "switch", "-qc", "feature")
    (tmp_path / "shop/db.py").write_text(RISKY)
    git(tmp_path, "commit", "-qam", "pr")
    return tmp_path


def test_cli_review_json_and_fail_gate(repo, tmp_path, capsys):
    out = tmp_path / "r.json"
    args = [
        "review",
        "--repo",
        str(repo),
        "--base",
        "main",
        "--head",
        "feature",
        "--format",
        "json",
        "--out",
        str(out),
    ]
    assert cli.main(args) == 0
    assert json.loads(out.read_text())["summary"]["risk_level"] == "high"
    assert cli.main([*args, "--fail-on", "high"]) == 1
    assert cli.main([*args, "--fail-on", "critical"]) == 0


def test_cli_review_markdown_to_stdout(repo, capsys):
    assert cli.main(["review", "--repo", str(repo), "--base", "main", "--head", "feature"]) == 0
    assert "SEC005" in capsys.readouterr().out


@pytest.mark.parametrize(
    "args",
    [
        ["review", "--repo", "/nonexistent", "--base", "main"],
        ["review", "--base", "main", "--head=-x"],
    ],
)
def test_cli_input_errors_exit_2(args, repo, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    assert cli.main(args) == 2
    assert capsys.readouterr().err.startswith("error:")


def test_cli_llm_needs_key(repo, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert cli.main(["review", "--repo", str(repo), "--base", "main", "--llm", "openai"]) == 2


def test_cli_github_with_comment(monkeypatch, capsys, tmp_path):
    fake = FakeGitHub()
    real_client = httpx.Client

    monkeypatch.setattr(
        cli,
        "GitHubClient",
        lambda repo, token: __import__("prrisk.github", fromlist=["GitHubClient"]).GitHubClient(
            repo, token, client=real_client(transport=httpx.MockTransport(fake))
        ),
    )
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    assert cli.main(["github", "--repo", "o/r", "--pr", "7", "--comment"]) == 0
    assert "PR comment created" in capsys.readouterr().err
    report_file = tmp_path / "r.md"
    report_file.write_text("hello")
    assert cli.main(["comment", "--repo", "o/r", "--pr", "7", "--file", str(report_file)]) == 0


KEY = "k-123"


@pytest.fixture
def api():
    settings = Settings(api_key_hashes=hashlib.sha256(KEY.encode()).hexdigest())
    return TestClient(create_app(settings), raise_server_exceptions=False)


DIFF = (
    "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,3 @@\n x = 1\n"
    "+eval(y)\n+token = 'abcdef1234567890'\n"
)


def test_api_review_diff(api):
    r = api.post("/v1/review/diff", json={"diff": DIFF}, headers={"X-API-Key": KEY})
    assert r.status_code == 200
    assert [f["rule"] for f in r.json()["findings"]] == ["SEC010"]  # diff-only: line checks


@pytest.mark.parametrize(
    ("body", "headers", "status"),
    [
        ({"diff": DIFF}, {}, 401),
        ({"diff": DIFF}, {"X-API-Key": "nope"}, 401),
        ({"diff": ""}, {"X-API-Key": KEY}, 422),
        ({"diff": "garbage"}, {"X-API-Key": KEY}, 422),
        ({"nodiff": 1}, {"X-API-Key": KEY}, 422),
    ],
)
def test_api_errors(api, body, headers, status):
    assert api.post("/v1/review/diff", json=body, headers=headers).status_code == status


def test_api_fails_closed_without_keys():
    app = TestClient(create_app(Settings(api_key_hashes="")))
    assert (
        app.post("/v1/review/diff", json={"diff": DIFF}, headers={"X-API-Key": "x"}).status_code
        == 503
    )
    assert app.get("/v1/health").json()["status"] == "ok"


def test_api_github_validation_and_upstream_error(api, monkeypatch):
    bad = api.post(
        "/v1/review/github", json={"repo": "no slash", "pr": 1}, headers={"X-API-Key": KEY}
    )
    assert bad.status_code == 422
    import prrisk.api as api_mod

    monkeypatch.setattr(
        api_mod,
        "GitHubClient",
        lambda repo, token: __import__("prrisk.github", fromlist=["GitHubClient"]).GitHubClient(
            repo, token, client=httpx.Client(transport=httpx.MockTransport(FakeGitHub(status=500)))
        ),
    )
    r = api.post("/v1/review/github", json={"repo": "o/r", "pr": 7}, headers={"X-API-Key": KEY})
    assert r.status_code == 502 and r.json()["error"] == "SourceError"
