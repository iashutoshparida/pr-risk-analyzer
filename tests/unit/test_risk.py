from prrisk.diff import FileChange, Status
from prrisk.risk import level_for, score_file
from prrisk.rules import Finding, Severity, TestSuggestion


def fc(path="app/x.py", n=5, status=Status.MODIFIED):
    return FileChange(path, path, status, added={i: "x" for i in range(1, n + 1)})


def finding(sev):
    return Finding("app/x.py", 1, "R", "security", sev, "m")


def test_levels():
    assert [level_for(s) for s in (0, 19, 20, 44, 45, 69, 70, 100)] == [
        "low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_trivial_change_is_low_and_explained():
    r = score_file(fc(n=2), [], [], 0, 0)
    assert r.level == "low" and r.factors == ["+2 2 lines changed"]


def test_worst_finding_sets_a_floor():
    assert score_file(fc(n=1), [finding(Severity.HIGH)], [], 0, 0).level == "high"
    crit = score_file(fc(n=1), [finding(Severity.CRITICAL)], [], 0, 0)
    assert crit.level == "critical" and any("raised to 70" in f for f in crit.factors)
    assert score_file(fc(n=1), [finding(Severity.LOW)], [], 0, 0).level == "low"


def test_factors_add_up_and_are_bounded():
    many = [finding(Severity.HIGH)] * 10
    tests = [TestSuggestion("app/x.py", f"f{i}", "r", ()) for i in range(10)]
    r = score_file(fc(path="app/auth/login.py", n=5000), many, tests, 1000, 50)
    assert r.score == 100 and r.level == "critical"
    assert any("security-sensitive" in f for f in r.factors)


def test_sensitive_and_infra_paths_and_deletion():
    ci = score_file(fc(path=".github/workflows/ci.yml", n=1), [], [], 0, 0)
    assert any("CI" in f for f in ci.factors)
    gone = score_file(fc(n=0, status=Status.DELETED), [], [], 0, 0)
    assert any("deleted" in f for f in gone.factors)
