import json
import subprocess

import pytest

from prrisk.engine import analyze
from prrisk.errors import DiffParseError, SourceError
from prrisk.source import LocalGitSource


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


BASE = {
    "shop/__init__.py": "",
    "shop/pricing.py": (
        "def price(qty, rate):\n"
        "    return qty * rate\n"
        "\n"
        "\n"
        "def label(name):\n"
        "    return name.title()\n"
    ),
    "shop/api.py": (
        "from shop.pricing import price\n" "\n" "\n" "def handler(q):\n" "    return price(q, 2)\n"
    ),
    "shop/db.py": "def find(cur, uid):\n    return cur.execute('SELECT * FROM u WHERE id = ?', (uid,))\n",
    "tests/test_pricing.py": (
        "from shop.pricing import price\n"
        "\n"
        "\n"
        "def test_price():\n"
        "    assert price(2, 3) == 6\n"
    ),
    "README.md": "# shop\n",
}


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
    return tmp_path


def commit_pr(repo, files):
    for path, text in files.items():
        target = repo / path
        if text is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "pr")
    src = LocalGitSource(repo)
    return analyze(src.diff("main", "feature"), src, "main", "feature")


def test_risky_pr_is_ranked_and_explained(repo):
    report = commit_pr(
        repo,
        {
            "shop/pricing.py": BASE["shop/pricing.py"].replace(
                "def price(qty, rate):", "def price(qty, rate, tax):"
            ),
            "shop/db.py": (
                "def find(cur, uid):\n"
                "    return cur.execute(f'SELECT * FROM u WHERE id = {uid}')\n"
            ),
            "README.md": "# shop\nsome docs\n",
        },
    )
    s = report.summary
    assert s.files_changed == 3 and s.risk_level in ("high", "critical")
    assert report.files[-1].path == "README.md" and report.files[-1].level == "low"
    rules = {(f.path, f.rule) for f in report.findings}
    assert ("shop/db.py", "SEC005") in rules
    assert ("shop/pricing.py", "CMP001") in rules
    pricing = next(f for f in report.files if f.path == "shop/pricing.py")
    assert pricing.modified_functions == ["price"]
    assert set(pricing.dependents) == {"shop.api", "tests.test_pricing"}
    suggested = {t.function: t for t in report.missing_tests}
    assert suggested["price"].existing_tests == ["tests/test_pricing.py"]
    assert "find" in suggested


def test_safe_pr_with_tests_is_low_risk(repo):
    report = commit_pr(
        repo,
        {
            "shop/pricing.py": BASE["shop/pricing.py"].replace(
                "name.title()", "name.strip().title()"
            ),
            "tests/test_pricing.py": BASE["tests/test_pricing.py"]
            + "\n\ndef test_label():\n    from shop.pricing import label\n    assert label(' a ') == 'A'\n",
        },
    )
    assert report.findings == []
    assert report.missing_tests == []
    assert report.summary.risk_level == "low"


def test_deleting_a_called_function_is_critical(repo):
    report = commit_pr(
        repo,
        {
            "shop/pricing.py": "def label(name):\n    return name.title()\n",
        },
    )
    [finding] = [f for f in report.findings if f.rule == "CMP002"]
    assert finding.severity == "critical" and "price" in finding.message
    assert report.summary.risk_level in ("high", "critical")


def test_deleted_test_file_and_new_secret(repo):
    report = commit_pr(
        repo,
        {
            "tests/test_pricing.py": None,
            "config/settings.py": "API_KEY = 'sk_live_9f8a7b6c5d4e3f2a1b0c'\n",
        },
    )
    rules = {f.rule for f in report.findings}
    assert {"TST001", "SEC010"} <= rules


def test_markdown_and_json_render(repo):
    report = commit_pr(repo, {"shop/db.py": "def find(cur, uid):\n    eval(uid)\n"})
    md = report.to_markdown()
    assert md.startswith("<!-- prrisk-report -->") and "SEC001" in md and "| Risk |" in md
    assert json.loads(report.model_dump_json())["summary"]["files_changed"] == 1


def test_diff_only_mode_runs_line_checks():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n x = 1\n"
        "+password = 'abcdefgh12345'\n"
    )
    report = analyze(diff)
    assert [f.rule for f in report.findings] == ["SEC010"]
    assert any("diff-only" in n for n in report.notes)


def test_bad_inputs(repo, tmp_path):
    with pytest.raises(DiffParseError):
        analyze("not a diff")
    src = LocalGitSource(repo)
    with pytest.raises(SourceError):
        src.diff("main", "--output=/tmp/x")
    with pytest.raises(SourceError):
        src.diff("main", "no-such-branch")
    with pytest.raises(SourceError):
        src.read("main", "../etc/passwd")
    with pytest.raises(SourceError):
        LocalGitSource(tmp_path / "nowhere")
    assert src.read("main", "missing.py") is None
