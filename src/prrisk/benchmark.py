"""Labelled benchmark: build a small repository, apply known risky and benign pull requests,
and measure detection, false alarms and ranking. Every PR goes through real `git diff` and the
same engine the CLI uses.

Limitation: the scenarios were written by the same person who wrote the rules. They show the
rules work as intended and do not over-fire on ordinary changes; they are not an estimate of
accuracy on arbitrary real-world PRs.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from prrisk.engine import analyze
from prrisk.source import LocalGitSource

BASE: dict[str, str] = {
    "shop/__init__.py": "",
    "shop/pricing.py": (
        "def price(qty, rate):\n    return qty * rate\n\n\n"
        "def discount(total, pct):\n    if pct < 0 or pct > 100:\n"
        "        raise ValueError('pct')\n    return total * (100 - pct) / 100\n"
    ),
    "shop/db.py": (
        "def find_user(cur, uid):\n"
        "    return cur.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()\n"
    ),
    "shop/api.py": (
        "from shop.pricing import discount, price\n\n\n"
        "def checkout(qty, rate, pct):\n    return discount(price(qty, rate), pct)\n"
    ),
    "shop/utils.py": "import subprocess\n\n\ndef git_head():\n"
    "    return subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True)\n",
    "shop/config.py": "import os\n\nAPI_KEY = os.environ.get('API_KEY', '')\n",
    "tests/__init__.py": "",
    "tests/test_pricing.py": (
        "from shop.pricing import discount, price\n\n\n"
        "def test_price():\n    assert price(2, 3) == 6\n\n\n"
        "def test_discount():\n    assert discount(100, 10) == 90\n"
    ),
    "README.md": "# shop\n",
}


@dataclass(frozen=True)
class Scenario:
    name: str
    changes: dict[str, str | None]
    expect: str | None  # rule that must fire; None = benign PR


def _sub(path: str, old: str, new: str) -> dict[str, str | None]:
    assert old in BASE[path], (path, old)
    return {path: BASE[path].replace(old, new)}


SCENARIOS: list[Scenario] = [
    # ---- risky
    Scenario(
        "sql-injection",
        _sub(
            "shop/db.py",
            "'SELECT * FROM users WHERE id = ?', (uid,)",
            "f'SELECT * FROM users WHERE id = {uid}'",
        ),
        "SEC005",
    ),
    Scenario(
        "shell-injection",
        _sub("shop/utils.py", "['git', 'rev-parse', 'HEAD']", "'git rev-parse ' + ref, shell=True"),
        "SEC002",
    ),
    Scenario("eval-input", {"shop/calc.py": "def calc(expr):\n    return eval(expr)\n"}, "SEC001"),
    Scenario(
        "hardcoded-secret",
        _sub("shop/config.py", "os.environ.get('API_KEY', '')", "'sk_live_51HxQe2kLm9PqR7t'"),
        "SEC010",
    ),
    Scenario(
        "unsafe-pickle",
        {"shop/cache.py": "import pickle\n\n\ndef load(b):\n" "    return pickle.loads(b)\n"},
        "SEC003",
    ),
    Scenario(
        "unsafe-yaml",
        {"shop/cfg.py": "import yaml\n\n\ndef read(t):\n" "    return yaml.load(t)\n"},
        "SEC004",
    ),
    Scenario(
        "tls-off",
        {
            "shop/http.py": "import requests\n\n\ndef get(u):\n"
            "    return requests.get(u, verify=False)\n"
        },
        "SEC006",
    ),
    Scenario(
        "breaking-signature",
        _sub("shop/pricing.py", "def price(qty, rate):", "def price(qty, rate, currency):"),
        "CMP001",
    ),
    Scenario(
        "delete-used-function",
        _sub("shop/pricing.py", "def price(qty, rate):\n    return qty * rate\n\n\n", ""),
        "CMP002",
    ),
    Scenario("delete-tests", {"tests/test_pricing.py": None}, "TST001"),
    Scenario(
        "complexity-spike",
        _sub(
            "shop/pricing.py",
            "    return qty * rate\n",
            "".join(f"    if qty == {i}:\n        return rate * {i}\n" for i in range(8))
            + "    return qty * rate\n",
        ),
        "MNT004",
    ),
    Scenario(
        "swallowed-errors",
        _sub(
            "shop/api.py",
            "    return discount(price(qty, rate), pct)\n",
            "    try:\n        return discount(price(qty, rate), pct)\n    except:\n"
            "        return 0\n",
        ),
        "MNT001",
    ),
    # ---- benign
    Scenario(
        "docstring",
        _sub(
            "shop/pricing.py",
            "def price(qty, rate):\n",
            'def price(qty, rate):\n    """Line total."""\n',
        ),
        None,
    ),
    Scenario("readme", {"README.md": "# shop\n\nRun `pytest`.\n"}, None),
    Scenario(
        "new-test",
        _sub(
            "tests/test_pricing.py",
            "assert discount(100, 10) == 90\n",
            "assert discount(100, 10) == 90\n\n\ndef test_zero():\n"
            "    assert price(0, 5) == 0\n",
        ),
        None,
    ),
    Scenario(
        "rename-local",
        _sub(
            "shop/api.py",
            "    return discount(price(qty, rate), pct)\n",
            "    subtotal = price(qty, rate)\n" "    return discount(subtotal, pct)\n",
        ),
        None,
    ),
    Scenario(
        "safe-sql-change",
        _sub("shop/db.py", "SELECT * FROM users", "SELECT id, name FROM users"),
        None,
    ),
    Scenario(
        "safe-subprocess",
        _sub(
            "shop/utils.py",
            "['git', 'rev-parse', 'HEAD']",
            "['git', 'rev-parse', '--short', 'HEAD']",
        ),
        None,
    ),
    Scenario(
        "safe-yaml",
        {"shop/cfg.py": "import yaml\n\n\ndef read(t):\n" "    return yaml.safe_load(t)\n"},
        None,
    ),
    Scenario(
        "comment-only",
        _sub("shop/config.py", "import os\n", "import os\n\n# Read the key at startup.\n"),
        None,
    ),
    Scenario(
        "tested-behaviour-change",
        {
            **_sub(
                "shop/pricing.py",
                "return total * (100 - pct) / 100",
                "return round(total * (100 - pct) / 100, 2)",
            ),
            **_sub(
                "tests/test_pricing.py",
                "assert discount(100, 10) == 90",
                "assert discount(100, 10) == 90\n    assert discount(10, 33) == 6.7",
            ),
        },
        None,
    ),
    Scenario(
        "new-constant", _sub("shop/config.py", "import os\n", "import os\n\nTIMEOUT_S = 30\n"), None
    ),
    Scenario(
        "placeholder-secret",
        _sub(
            "shop/config.py", "import os\n", 'import os\n\n# example: password = "changeme-later"\n'
        ),
        None,
    ),
    Scenario(
        "narrow-except",
        _sub(
            "shop/api.py",
            "    return discount(price(qty, rate), pct)\n",
            "    try:\n        return discount(price(qty, rate), pct)\n    except ValueError:\n"
            "        raise\n",
        ),
        None,
    ),
]


@dataclass
class Outcome:
    name: str
    expect: str | None
    rules: list[str]
    risk_score: int
    risk_level: str
    detected: bool
    false_alarm: bool
    seconds: float


def _git(repo: Path, *args: str) -> None:
    cmd = ["git", "-C", str(repo), *args]
    subprocess.run(cmd, check=True, capture_output=True)  # noqa: S603 - fixed argv, temp repo


def run_scenario(sc: Scenario) -> Outcome:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "bench@example.com")
        _git(repo, "config", "user.name", "bench")
        for path, text in BASE.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "base")
        _git(repo, "switch", "-qc", "pr")
        for path, change in sc.changes.items():
            target = repo / path
            if change is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(change)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", sc.name)
        source = LocalGitSource(repo)
        start = time.perf_counter()
        report = analyze(source.diff("main", "pr"), source, "main", "pr")
        elapsed = time.perf_counter() - start
    rules = sorted({f.rule for f in report.findings})
    serious = [f for f in report.findings if f.severity in ("medium", "high", "critical")]
    return Outcome(
        name=sc.name,
        expect=sc.expect,
        rules=rules,
        risk_score=report.summary.risk_score,
        risk_level=report.summary.risk_level,
        detected=sc.expect is not None and sc.expect in rules,
        false_alarm=sc.expect is None
        and (bool(serious) or report.summary.risk_level in ("high", "critical")),
        seconds=elapsed,
    )


def auc(risky: list[int], benign: list[int]) -> float:
    """Probability that a random risky PR scores above a random benign one (ties count half)."""
    pairs = [(r > b) + 0.5 * (r == b) for r in risky for b in benign]
    return sum(pairs) / len(pairs) if pairs else 0.0


def run_all() -> tuple[list[Outcome], str]:
    outcomes = [run_scenario(sc) for sc in SCENARIOS]
    risky = [o for o in outcomes if o.expect]
    benign = [o for o in outcomes if not o.expect]
    detected = sum(o.detected for o in risky)
    alarms = sum(o.false_alarm for o in benign)
    ranking = auc([o.risk_score for o in risky], [o.risk_score for o in benign])
    lines = [
        f"| Labelled PRs | {len(outcomes)} ({len(risky)} risky, {len(benign)} benign) |",
        "|---|---|",
        f"| Risky PRs where the expected rule fired | {detected} / {len(risky)} |",
        f"| Risky PRs rated high or critical | "
        f"{sum(o.risk_level in ('high', 'critical') for o in risky)} / {len(risky)} |",
        f"| Benign PRs with a medium+ finding or high risk (false alarms) | "
        f"{alarms} / {len(benign)} |",
        f"| Ranking AUC (risky scored above benign) | {ranking:.3f} |",
        f"| Median analysis time per PR | "
        f"{sorted(o.seconds for o in outcomes)[len(outcomes) // 2] * 1000:.0f} ms |",
        "",
        "| Scenario | Expected | Rules fired | Risk |",
        "|---|---|---|---|",
    ]
    for o in outcomes:
        lines.append(
            f"| {o.name} | {o.expect or 'benign'} | {', '.join(o.rules) or '-'} | "
            f"{o.risk_level} {o.risk_score} |"
        )
    return outcomes, "\n".join(lines)
