# Contributing

1. Branch from `main`; one logical change per commit with a message that says why.
2. `pip install -e ".[dev]"`
3. New rule: add it to `rules.py`, a test that it fires and a test with a safe look-alike that it
   must not flag, and a benchmark scenario if it represents a new risk category.
4. Before pushing: `ruff check . && ruff format --check . && mypy && pytest --cov && prrisk benchmark`.
5. Open a PR; CI and the PR-risk workflow must be green.
