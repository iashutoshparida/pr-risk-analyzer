# PR Risk Analyzer (`prrisk`)

Reads a pull request's diff, works out which functions changed and what depends on them, flags
security, maintainability and compatibility problems in the new code, suggests the regression
tests that are missing, and ranks the changed files so reviewers look at the riskiest ones first.
It runs as a CLI, a GitHub Action that comments on every PR, and a FastAPI service.

Made by Ashutosh Parida.

## Why

Review time is limited, and most PRs mix trivial edits with one or two changes that deserve real
scrutiny. A good reviewer asks: what changed, who calls it, could it break callers, is it tested,
and does it introduce anything unsafe? `prrisk` answers those questions deterministically, then
optionally asks an LLM for extra comments and **keeps only comments that point at lines the PR
actually added** (see [ADR 0003](docs/adr/0003-llm-comments-are-grounded.md)).

## What it checks

| Area | Checks (only on lines the PR adds) |
|---|---|
| Security | `eval`/`exec`, `shell=True`/`os.system`, SQL built with f-strings / `%` / `+`, `pickle`/`marshal` loads, `yaml.load` without a safe loader, `verify=False`, MD5/SHA-1, hard-coded keys and tokens (AWS, GitHub, private keys, credentials, with placeholder filtering) |
| Maintainability | complexity jump (+5) or new complexity > 10, functions over 60 lines, bare or swallowed `except`, mutable defaults, debugger calls, new TODOs, files that no longer parse |
| Compatibility | public function's signature changed while other files call it; public function deleted while still called |
| Testing | deleted tests or test files; changed functions with no test that references them, listing the existing tests to extend |
| Risk | per-file score 0-100 from churn, findings, dependents, sensitive paths (auth, payments, migrations, CI, dependency files), untested changes and complexity, with every point explained |

## Results

**Labelled benchmark** (`prrisk benchmark`, also run in CI): 24 pull requests applied to a sample
repository with real `git` commits. See [docs/EVALUATION.md](docs/EVALUATION.md).

| Metric | Result |
|---|---|
| Risky PRs where the expected rule fired | 12 / 12 |
| Benign PRs that raised an alarm | 0 / 12 |
| Ranking AUC (risky scored above benign) | 1.000 |
| Median time per PR | 28 ms |

The scenarios were written by the same person as the rules, so this shows the rules behave as
designed; it is not an accuracy estimate for arbitrary real PRs.

**Real history**: run on 19 consecutive commit pairs from two real projects (CodePilot, TestLedger); each took
0.25-0.65 s. It flagged an `eval` call in CodePilot's sample legacy app (a deliberate defect,
correctly found) and a signature change in CodePilot's test generator that has callers.

## Quick start

```bash
pip install -e ".[dev]"
prrisk review --base origin/main --head HEAD            # Markdown report on stdout
prrisk review --base main --format json --out report.json --fail-on high
GITHUB_TOKEN=... prrisk github --repo owner/name --pr 42 --comment
prrisk benchmark
```

Exit codes: `0` ok, `1` risk at or above `--fail-on`, `2` bad input (unknown ref, bad repo, missing key).

### In another repository's CI

```yaml
on: pull_request
permissions: { contents: read, pull-requests: write }
jobs:
  risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: iashutoshparida/pr-risk-analyzer@main
        with: { fail-on: critical }
```

The action posts one comment and updates it on every push, instead of adding a new one each time.

### As a service

```bash
cp .env.example .env    # set PRRISK_API_KEY_HASHES and PRRISK_GITHUB_TOKEN
prrisk serve            # docs at http://127.0.0.1:8000/docs
```

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md).

### Optional LLM review

`--llm openai` or `--llm anthropic` (key from `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`). The model
sees only added lines plus the deterministic findings, cannot change the score, and any comment
on a line the PR did not add, with an unknown severity or malformed JSON, is dropped and counted.
Timeouts and API errors become a note in the report; the review still completes.

## Architecture

```
git diff / GitHub API ─> diff.py ─> pyanalysis.py ─> rules.py ─> risk.py ─> report.py ─> Markdown / JSON
                         (lines)    (functions,       (findings,   (explained   (PR comment, API,
                                     import graph,     test gaps)   scores)      CI artifact)
                                     call sites)            └─ llm.py (optional, grounded)
```

Details: [ARCHITECTURE.md](ARCHITECTURE.md), decisions in [docs/adr](docs/adr).

## Testing

101 tests (unit and integration), 96% line and branch coverage, ruff and strict mypy clean.
Integration tests build real git repositories and run real `git diff`; the diff parser is also
checked by a property test that reconstructs both file versions from 200 random diffs. GitHub and
LLM calls are tested against mocked HTTP transports. See [TESTING_STRATEGY.md](TESTING_STRATEGY.md).

## Limitations

* Function-level analysis is Python only; other files get line-level checks (secrets, TODOs).
* Call sites are matched by name, so two functions with the same name in different modules can
  produce a false "callers" match, and calls through dynamic dispatch are missed.
* "Missing test" means no test file references the function by name. Tests that reach code through
  an HTTP client or fixtures are not linked, so API code can be over-reported (seen on TestLedger).
* Pattern rules catch common mistakes, not every vulnerability; this is not a replacement for a
  full SAST tool or a human security review.
* The Docker image and the GitHub workflows were validated as files but not executed here; CI runs
  them on the first push.

## License

MIT
