"""Explainable per-file risk score in [0, 100].

Each factor adds bounded points and records why, so a reviewer can see what drove the score
instead of trusting an opaque number. Weights are deliberately simple and documented in
docs/adr/0002-explainable-risk-score.md.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from prrisk.diff import FileChange, Status
from prrisk.rules import Finding, Severity, TestSuggestion

# A file is never rated below its worst finding: one SQL injection is "high" however small the
# diff. Points above the floor still order files of the same level.
SEVERITY_FLOOR = {Severity.CRITICAL: 70, Severity.HIGH: 45, Severity.MEDIUM: 20}
SEVERITY_POINTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 1,
}
_SENSITIVE = re.compile(
    r"(?i)(auth|login|password|secret|token|crypto|payment|billing|"
    r"permission|acl|security|migrations?/)"
)
_INFRA = re.compile(
    r"(?i)(^|/)(\.github/workflows/|dockerfile|docker-compose|requirements[^/]*"
    r"\.txt$|pyproject\.toml$|setup\.py$|package\.json$|.*\.tf$)"
)


@dataclass
class FileRisk:
    path: str
    score: int
    level: str
    factors: list[str] = field(default_factory=list)


def level_for(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def score_file(
    change: FileChange,
    findings: Iterable[Finding],
    suggestions: Iterable[TestSuggestion],
    dependents: int,
    complexity_delta: int,
) -> FileRisk:
    points = 0.0
    factors: list[str] = []

    def add(value: float, reason: str) -> None:
        nonlocal points
        if value > 0:
            points += value
            factors.append(f"+{round(value)} {reason}")

    add(min(20.0, 6 * math.log2(1 + change.churn / 10)), f"{change.churn} lines changed")
    finding_pts = sum(SEVERITY_POINTS[f.severity] for f in findings)
    if finding_pts:
        worst = max(f.severity for f in findings)
        add(min(50, finding_pts), f"findings (worst: {worst.name.lower()})")
    add(min(20.0, 5 * math.log2(1 + dependents)), f"{dependents} dependent module(s)")
    if _SENSITIVE.search(change.path):
        add(15, "security-sensitive path")
    elif _INFRA.search(change.path):
        add(10, "build, CI or dependency file")
    untested = sum(1 for _ in suggestions)
    add(min(15, 5 * untested), f"{untested} changed function(s) without updated tests")
    add(min(10, complexity_delta), f"complexity +{complexity_delta}")
    if change.status is Status.DELETED:
        add(5, "file deleted")
    score = min(100, round(points))
    worst_found = max((f.severity for f in findings), default=None)
    if worst_found is not None and SEVERITY_FLOOR.get(worst_found, 0) > score:
        score = SEVERITY_FLOOR[worst_found]
        factors.append(f"raised to {score}: worst finding is {worst_found.name.lower()}")
    return FileRisk(change.path, score, level_for(score), factors)
