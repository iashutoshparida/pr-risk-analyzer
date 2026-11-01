# Architecture

| Module | Responsibility | I/O |
|---|---|---|
| `diff.py` | Parse unified diffs into added/removed line numbers per file; renames, new/deleted/binary files, multiple hunks, `\ No newline` | none |
| `source.py` | `SourceProvider` protocol; `LocalGitSource` reads files at a ref with `git show` (argv only, refs validated, no shell) | git subprocess |
| `github.py` | GitHub REST client that also implements `SourceProvider`; reads PR diff/files, upserts one marked comment | HTTPS |
| `pyanalysis.py` | AST: functions with line ranges, signatures, McCabe complexity; maps changed lines to the innermost function on each side; import graph and name-based call sites for the head tree | none |
| `rules.py` | Deterministic findings on added lines; compatibility and test-gap rules using the before/after view and the repo index | none |
| `risk.py` | Per-file score with an explanation per factor and a floor from the worst finding | none |
| `llm.py` | Provider protocol (OpenAI, Anthropic); prompt from added lines; JSON extraction; grounding filter | HTTPS |
| `engine.py` | Orchestration; size limits; diff-only mode when there is no source | — |
| `report.py` | Pydantic report model; Markdown rendering with a hidden marker for comment updates | none |
| `cli.py`, `api/` | Thin adapters over `engine.analyze` | — |

Design rules:

* Pure functions for parsing, analysis, rules and scoring; I/O is pushed to `source.py`, `github.py`
  and `llm.py`, each behind a small interface so tests use fakes or mocked HTTP.
* Findings are attached to added lines only, so a PR touching a legacy file is not blamed for old debt.
* Old and new versions are analysed separately; a function is matched by qualified name, so
  signature and complexity changes are measured on the same function.
* The repository index is built from the head tree: a function deleted in the PR that the head
  still calls is a real break.

Data flow for `prrisk review`:

1. `git diff -M base...head` (merge-base diff, like GitHub's PR view).
2. For each changed Python file: read both versions, run AST rules on added lines, map changed lines
   to functions.
3. Build the import and call index for all `.py` files at head (capped at 3,000 files).
4. Compatibility and test-gap rules; per-file scores; optional LLM pass; report.
