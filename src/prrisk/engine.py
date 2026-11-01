"""Orchestration: diff -> changed functions -> findings -> risk -> report."""

from __future__ import annotations

import logging
from collections import defaultdict

from prrisk.diff import Status, parse_diff
from prrisk.errors import InputTooLargeError
from prrisk.llm import LLMProvider, review
from prrisk.pyanalysis import FunctionChange, RepoIndex, changed_functions
from prrisk.report import (
    CommentOut,
    FileRiskOut,
    FindingOut,
    Report,
    Summary,
    TestSuggestionOut,
)
from prrisk.risk import level_for, score_file
from prrisk.rules import (
    Finding,
    Severity,
    TestSuggestion,
    change_findings,
    missing_tests,
    python_findings,
    text_findings,
)
from prrisk.source import SourceProvider

log = logging.getLogger("prrisk.engine")

MAX_DIFF_BYTES = 5_000_000
MAX_INDEX_FILES = 3000


def analyze(
    diff_text: str,
    source: SourceProvider | None = None,
    base: str = "",
    head: str = "",
    llm: LLMProvider | None = None,
) -> Report:
    if len(diff_text.encode()) > MAX_DIFF_BYTES:
        raise InputTooLargeError(f"diff is larger than {MAX_DIFF_BYTES} bytes")
    files = [f for f in parse_diff(diff_text) if not f.binary]
    by_path = {f.path: f for f in files}
    notes: list[str] = []

    findings: list[Finding] = []
    fchanges: list[FunctionChange] = []
    for change in files:
        findings += text_findings(change)
        if not change.is_python or source is None:
            continue
        new_src = None if change.status is Status.DELETED else source.read(head, change.path)
        old_path = change.old_path or change.path
        old_src = None if change.status is Status.ADDED else source.read(base, old_path)
        if new_src is not None:
            findings += python_findings(change.path, new_src, set(change.added))
        try:
            fchanges += changed_functions(change.path, old_src, new_src,
                                          set(change.added), set(change.removed))
        except SyntaxError:
            notes.append(f"{change.path}: could not parse one side; function mapping skipped")

    index = RepoIndex()
    if source is not None and any(f.is_python for f in files):
        paths = source.list_python_files(head)
        if len(paths) > MAX_INDEX_FILES:
            notes.append(f"dependency index limited to {MAX_INDEX_FILES} of {len(paths)} files")
            paths = paths[:MAX_INDEX_FILES]
        texts = {p: t for p in paths if (t := source.read(head, p)) is not None}
        # Built from the head tree: a deleted function still called there is a real break.
        index = RepoIndex.build(texts)
    elif source is None:
        notes.append("diff-only mode: no repository source, so only line-level checks ran")

    findings += change_findings(fchanges, index, by_path)
    suggestions = missing_tests(fchanges, index, set(by_path))

    per_file_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        per_file_findings[f.path].append(f)
    per_file_tests: dict[str, list[TestSuggestion]] = defaultdict(list)
    for t in suggestions:
        per_file_tests[t.path].append(t)
    per_file_funcs: dict[str, list[FunctionChange]] = defaultdict(list)
    for fc in fchanges:
        per_file_funcs[fc.path].append(fc)

    file_out = []
    for change in files:
        dependents = sorted(index.dependents_of_module(change.path)) if change.is_python else []
        funcs = per_file_funcs[change.path]
        risk = score_file(
            change,
            per_file_findings[change.path],
            per_file_tests[change.path],
            len(dependents),
            max(0, sum(fc.complexity_delta for fc in funcs if fc.new is not None)),
        )
        file_out.append(FileRiskOut(
            path=change.path, status=change.status.value, score=risk.score, level=risk.level,
            churn=change.churn, factors=risk.factors,
            modified_functions=[fc.qualname for fc in funcs], dependents=dependents[:20],
        ))
    file_out.sort(key=lambda f: (-f.score, f.path))

    comments: list[CommentOut] = []
    if llm is not None:
        result = review(llm, files, findings)
        comments = [CommentOut(**c.__dict__) for c in result.comments]
        if result.note:
            notes.append(result.note)

    findings.sort(key=lambda f: (-f.severity, f.path, f.line))
    counts = {s.name.lower(): 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[f.severity.name.lower()] += 1
    top = max((f.score for f in file_out), default=0)
    # Several risky files add up: +5 per additional file at medium or above, capped at 100.
    extra = 5 * max(0, sum(1 for f in file_out if f.score >= 20) - 1)
    score = min(100, top + extra)
    return Report(
        summary=Summary(
            risk_score=score, risk_level=level_for(score), files_changed=len(files),
            lines_added=sum(len(f.added) for f in files),
            lines_removed=sum(len(f.removed) for f in files),
            findings_by_severity=counts, functions_changed=len(fchanges),
            functions_without_tests=len(suggestions),
        ),
        files=file_out,
        findings=[FindingOut(path=f.path, line=f.line, rule=f.rule, category=f.category,
                             severity=f.severity.name.lower(), message=f.message,
                             function=f.function) for f in findings],
        missing_tests=[TestSuggestionOut(path=t.path, function=t.function, reason=t.reason,
                                         existing_tests=list(t.existing_tests))
                       for t in suggestions],
        llm_comments=comments,
        notes=notes,
    )
