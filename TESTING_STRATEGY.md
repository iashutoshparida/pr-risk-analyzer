# Testing strategy

101 tests, 96% line + branch coverage, warnings treated as errors.

| File | Tests | What |
|---|---|---|
| `unit/test_diff.py` | 9 | real `git diff` output for every change type; multiple hunks and `\ No newline`; 5 malformed inputs; property test (200 cases) that the parsed lines reconstruct both versions of a random file |
| `unit/test_pyanalysis.py` | 12 | nested functions and methods, decorator ranges, McCabe complexity, innermost-function mapping, added/deleted/signature changes, import graph, call sites, test linking, unparsable files |
| `unit/test_rules.py` | 31 | each rule fires (15 cases) and safe look-alikes do not (8 cases: parameterised SQL, argv subprocess, SafeLoader, narrow except, `ast.literal_eval`...); only added lines are reported; secrets with placeholders; compatibility and test-gap rules |
| `unit/test_risk.py` | 5 | level boundaries, severity floor, caps, sensitive and CI paths |
| `unit/test_llm.py` | 14 | hallucinated comments dropped (wrong file, unchanged line, bad severity, bad types); non-JSON and timeouts degrade to a note; both providers' requests and error handling with mocked HTTP |
| `unit/test_github.py` | 8 | PR/diff/file/tree reads, comment update vs create, 401/403/500 without leaking the token, network failure |
| `integration/test_engine.py` | 7 | end-to-end on real git repos: risky PR ranked and explained, safe PR with tests is low risk, deleting a called function is critical, deleted tests and secrets, rendering, diff-only mode, bad refs and path traversal |
| `integration/test_cli_api.py` | 15 | CLI exit codes and `--fail-on`, GitHub mode with comment, API auth/validation/fail-closed/upstream errors, the benchmark itself |

## Bugs caught by the tests while building

1. A hunk with more lines than its header declared was silently accepted; the extra lines were
   read as file-header noise. Found by a malformed-input test; now raises `DiffParseError`.
2. A SQL-injection file scored only "medium" because the score was a plain sum; added the
   severity floor so a file never ranks below its worst finding (ADR 0002).
3. `--head -x` style refs could reach `git` as options; refs are now validated before use.
