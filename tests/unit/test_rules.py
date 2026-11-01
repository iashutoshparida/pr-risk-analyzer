import textwrap

import pytest

from prrisk.diff import FileChange, Status
from prrisk.pyanalysis import RepoIndex, changed_functions
from prrisk.rules import Severity, change_findings, missing_tests, python_findings, text_findings


def rules_for(src, added=None):
    src = textwrap.dedent(src)
    lines = set(range(1, src.count("\n") + 2)) if added is None else added
    return {(f.rule, f.severity) for f in python_findings("app/x.py", src, lines)}


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("eval(user_input)\n", ("SEC001", Severity.HIGH)),
        ("import subprocess\nsubprocess.run(cmd, shell=True)\n", ("SEC002", Severity.HIGH)),
        ("import os\nos.system('ls ' + d)\n", ("SEC002", Severity.MEDIUM)),
        ("import pickle\npickle.loads(blob)\n", ("SEC003", Severity.MEDIUM)),
        ("import yaml\nyaml.load(text)\n", ("SEC004", Severity.MEDIUM)),
        ("cur.execute(f'SELECT * FROM t WHERE id = {uid}')\n", ("SEC005", Severity.HIGH)),
        ("cur.execute('SELECT * FROM t WHERE id = ' + uid)\n", ("SEC005", Severity.HIGH)),
        ("cur.execute('SELECT %s' % uid)\n", ("SEC005", Severity.HIGH)),
        ("requests.get(url, verify=False)\n", ("SEC006", Severity.MEDIUM)),
        ("import hashlib\nhashlib.md5(pw)\n", ("SEC007", Severity.LOW)),
        ("breakpoint()\n", ("MNT003", Severity.MEDIUM)),
        ("try:\n    go()\nexcept:\n    log()\n", ("MNT001", Severity.MEDIUM)),
        ("try:\n    go()\nexcept Exception:\n    pass\n", ("MNT001", Severity.MEDIUM)),
        ("def f(x=[]):\n    return x\n", ("MNT002", Severity.LOW)),
        ("def f(:\n", ("MNT000", Severity.HIGH)),
    ],
)
def test_each_rule_fires(src, expected):
    assert expected in rules_for(src)


@pytest.mark.parametrize(
    "src",
    [
        "cur.execute('SELECT * FROM t WHERE id = %s', (uid,))\n",  # parameterised
        "cur.execute('SELECT 1' + ' FROM t')\n",  # two literals
        "subprocess.run(['ls', d])\n",
        "yaml.load(text, Loader=yaml.SafeLoader)\n",
        "requests.get(url, verify=True)\n",
        "try:\n    go()\nexcept ValueError:\n    pass\n",  # narrow except is allowed
        "def f(x=None):\n    return x\n",
        "ast.literal_eval(s)\n",
    ],
)
def test_safe_code_is_not_flagged(src):
    assert rules_for(src) == set()


def test_only_added_lines_are_reported():
    src = "eval(a)\neval(b)\n"
    found = python_findings("x.py", src, added={2})
    assert [f.line for f in found] == [2]


def test_multiline_call_counts_if_any_line_is_new():
    src = "subprocess.run(\n    cmd,\n    shell=True,\n)\n"
    assert {f.rule for f in python_findings("x.py", src, added={3})} == {"SEC002"}


def change(path, added, status=Status.MODIFIED):
    return FileChange(path, path, status, added=dict(enumerate(added, 1)))


def test_secret_detection_and_placeholders():
    found = text_findings(change(".env.prod", [
        "AWS_KEY=AKIAABCDEFGHIJKLMNOP",
        'password = "hunter2hunter2"',
        'password = "changeme-please"',
        "-----BEGIN RSA PRIVATE KEY-----",
        "token: ghp_" + "a" * 36,
        "# TODO remove this",
    ]))
    by_line = {f.line: (f.rule, f.severity) for f in found}
    assert by_line[1] == ("SEC010", Severity.CRITICAL)
    assert by_line[2] == ("SEC010", Severity.HIGH)
    assert 3 not in by_line  # placeholder value
    assert by_line[4][1] is Severity.CRITICAL and by_line[5][1] is Severity.CRITICAL
    assert by_line[6] == ("MNT010", Severity.INFO)


REPO = {
    "shop/pricing.py": "def price(q, rate):\n    return q * rate\n\ndef _helper():\n    pass\n",
    "shop/api.py": "from shop.pricing import price\n\ndef handler():\n    return price(1, 2)\n",
    "tests/test_pricing.py": "from shop.pricing import price\n\ndef test_price():\n    assert price(2, 3) == 6\n",
}


def test_signature_change_with_callers_is_flagged():
    old = REPO["shop/pricing.py"]
    new = old.replace("def price(q, rate):", "def price(q, rate, tax):")
    fcs = changed_functions("shop/pricing.py", old, new, {1}, {1})
    found = change_findings(fcs, RepoIndex.build(REPO), {})
    [f] = [f for f in found if f.rule == "CMP001"]
    assert f.severity is Severity.HIGH and "(q, rate, tax)" in f.message


def test_deleting_called_function_is_critical_and_private_is_not():
    old = REPO["shop/pricing.py"]
    fcs = changed_functions("shop/pricing.py", old, "", set(), {1, 2, 4, 5})
    found = change_findings(fcs, RepoIndex.build(REPO), {})
    assert [(f.rule, f.function) for f in found] == [("CMP002", "price")]


def test_complexity_jump_and_long_function():
    old = "def f(x):\n    return x\n"
    body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(40))
    new = "def f(x):\n" + body + "    return x\n"
    fcs = changed_functions("m.py", old, new, set(range(1, 84)), {1, 2})
    rules = {f.rule for f in change_findings(fcs, RepoIndex(), {})}
    assert rules == {"MNT004", "MNT005"}


def test_deleted_tests_are_flagged():
    old = REPO["tests/test_pricing.py"]
    fcs = changed_functions("tests/test_pricing.py", old, "from shop.pricing import price\n",
                            set(), {3, 4})
    deleted_file = {"tests/test_old.py": change("tests/test_old.py", [], Status.DELETED)}
    found = change_findings(fcs, RepoIndex(), deleted_file)
    assert sorted(f.rule for f in found) == ["TST001", "TST001"]


def test_missing_test_suggestions():
    old = REPO["shop/pricing.py"]
    new = old.replace("q * rate", "round(q * rate, 2)") + "\ndef discount(x):\n    return x\n"
    fcs = changed_functions("shop/pricing.py", old, new, {2, 7, 8}, {2})
    index = RepoIndex.build({**REPO, "shop/pricing.py": new})
    suggestions = {s.function: s for s in missing_tests(fcs, index, {"shop/pricing.py"})}
    assert suggestions["price"].existing_tests == ("tests/test_pricing.py",)
    assert "none of its tests changed" in suggestions["price"].reason
    assert "no test" in suggestions["discount"].reason
    # once the PR also edits the test that calls price(), no suggestion for it
    covered = missing_tests(fcs, index, {"shop/pricing.py", "tests/test_pricing.py"})
    assert [s.function for s in covered] == ["discount"]
