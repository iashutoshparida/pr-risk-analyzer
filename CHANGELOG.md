# Changelog

## 0.1.0
* Unified-diff parser; AST analysis of changed functions, complexity and signatures; import graph and call sites.
* 17 deterministic rules across security, maintainability, compatibility and testing, scoped to added lines.
* Explainable per-file risk score with a severity floor; prioritised Markdown/JSON report.
* Missing-regression-test suggestions that name existing tests to extend.
* Optional OpenAI/Anthropic review with a grounding filter.
* CLI, FastAPI service, GitHub REST client, PR-review workflow that updates a single comment, reusable action.
* Labelled benchmark (24 PRs) run in CI.
