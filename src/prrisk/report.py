"""Structured review report, rendered as JSON (API, CI) or Markdown (PR comment)."""

from __future__ import annotations

from pydantic import BaseModel

MARKER = "<!-- prrisk-report -->"


class FindingOut(BaseModel):
    path: str
    line: int
    rule: str
    category: str
    severity: str
    message: str
    function: str | None = None


class FileRiskOut(BaseModel):
    path: str
    status: str
    score: int
    level: str
    churn: int
    factors: list[str]
    modified_functions: list[str]
    dependents: list[str]


class TestSuggestionOut(BaseModel):
    path: str
    function: str
    reason: str
    existing_tests: list[str]


class CommentOut(BaseModel):
    path: str
    line: int
    severity: str
    message: str


class Summary(BaseModel):
    risk_score: int
    risk_level: str
    files_changed: int
    lines_added: int
    lines_removed: int
    findings_by_severity: dict[str, int]
    functions_changed: int
    functions_without_tests: int


class Report(BaseModel):
    summary: Summary
    files: list[FileRiskOut]
    findings: list[FindingOut]
    missing_tests: list[TestSuggestionOut]
    llm_comments: list[CommentOut]
    notes: list[str]

    def to_markdown(self, max_findings: int = 30) -> str:
        s = self.summary
        sev = ", ".join(f"{n} {k}" for k, n in s.findings_by_severity.items() if n) or "none"
        out = [
            MARKER,
            f"## PR risk: **{s.risk_level.upper()}** ({s.risk_score}/100)",
            "",
            f"{s.files_changed} files, +{s.lines_added}/-{s.lines_removed} lines, "
            f"{s.functions_changed} functions changed. Findings: {sev}.",
            "",
            "### Review these first",
            "",
            "| Risk | File | Why |",
            "|---|---|---|",
        ]
        for f in self.files[:10]:
            why = "; ".join(f.factors[:4]) or "-"
            out.append(f"| {f.level} {f.score} | `{f.path}` | {why} |")
        if self.findings:
            out += ["", "### Findings", ""]
            for item in self.findings[:max_findings]:
                where = f"`{item.path}:{item.line}`" if item.line else f"`{item.path}`"
                out.append(f"- **{item.severity}** {where} {item.rule}: {item.message}")
            if len(self.findings) > max_findings:
                out.append(f"- ... and {len(self.findings) - max_findings} more (see JSON report)")
        if self.missing_tests:
            out += ["", "### Suggested regression tests", ""]
            for t in self.missing_tests[:15]:
                extra = (
                    f" Extend: {', '.join(f'`{p}`' for p in t.existing_tests[:3])}."
                    if t.existing_tests
                    else ""
                )
                out.append(f"- `{t.path}` {t.reason}.{extra}")
        if self.llm_comments:
            out += ["", "### AI reviewer (checked against the diff)", ""]
            for c in self.llm_comments[:15]:
                out.append(f"- {c.severity} `{c.path}:{c.line}` {c.message}")
        if self.notes:
            out += ["", "<sub>" + " · ".join(self.notes) + "</sub>"]
        return "\n".join(out) + "\n"
