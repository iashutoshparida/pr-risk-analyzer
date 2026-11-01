# Evaluation

## 1. Labelled pull requests

`prrisk benchmark` creates a small shop repository, commits it, then applies each scenario as a
separate branch and analyses `main...pr` with real `git diff`, exactly as the CLI does. CI runs it
and fails if any risky PR is missed or any benign PR raises an alarm.

A risky PR counts as detected when its expected rule fires. A benign PR is a false alarm if it
produces any finding of medium severity or above, or an overall risk of high or critical.

| Labelled PRs | 24 (12 risky, 12 benign) |
|---|---|
| Risky PRs where the expected rule fired | 12 / 12 |
| Risky PRs rated high or critical | 6 / 12 |
| Benign PRs with a medium+ finding or high risk (false alarms) | 0 / 12 |
| Ranking AUC (risky scored above benign) | 1.000 |
| Median analysis time per PR | 28 ms |

| Scenario | Expected | Rules fired | Risk |
|---|---|---|---|
| sql-injection | SEC005 | SEC005 | high 45 |
| shell-injection | SEC002 | SEC002 | high 45 |
| eval-input | SEC001 | SEC001 | high 45 |
| hardcoded-secret | SEC010 | SEC010 | high 45 |
| unsafe-pickle | SEC003 | SEC003 | medium 20 |
| unsafe-yaml | SEC004 | SEC004 | medium 20 |
| tls-off | SEC006 | SEC006 | medium 20 |
| breaking-signature | CMP001 | CMP001 | high 45 |
| delete-used-function | CMP002 | CMP002 | critical 70 |
| delete-tests | TST001 | TST001 | medium 41 |
| complexity-spike | MNT004 | MNT004 | medium 39 |
| swallowed-errors | MNT001 | MNT001 | medium 20 |
| docstring | benign | - | low 14 |
| readme | benign | - | low 2 |
| new-test | benign | - | low 5 |
| rename-local | benign | - | low 7 |
| safe-sql-change | benign | - | low 7 |
| safe-subprocess | benign | - | low 7 |
| safe-yaml | benign | - | low 10 |
| comment-only | benign | - | low 2 |
| tested-behaviour-change | benign | - | low 10 |
| new-constant | benign | - | low 2 |
| placeholder-secret | benign | - | low 2 |
| narrow-except | benign | - | low 10 |

Half of the risky PRs are rated medium rather than high: unsafe deserialisation, `verify=False`,
swallowed exceptions, deleted tests and complexity spikes carry medium severity by design, because
they are often justified. They are still ranked above every benign PR (AUC 1.000).

**Threats to validity.** The scenarios and the rules were written by the same person, and each
risky PR contains exactly one problem. Real PRs mix several changes and can hide problems in ways
the rules do not anticipate. Treat these numbers as a regression suite, not an accuracy estimate.

## 2. Real commit histories

Every consecutive commit pair of two real repositories was analysed with `prrisk review`:

| Repository | Commits analysed | Time per commit | High/critical findings |
|---|---|---|---|
| CodePilot | 12 | 0.24-0.48 s | `eval` in the sample legacy app (deliberate defect); signature change of `testgen` function with callers |
| TestLedger | 7 | 0.29-0.64 s | none |

Observations:
* Large feature commits (300-1,600 added lines) were rated high or critical, mainly from churn and
  new modules; small follow-up commits were low. That matches how much review attention they need.
* Commits that added API endpoints reported many "functions without tests" even though tests were
  added, because those tests call the endpoints over HTTP rather than calling functions by name.
  This is a known limitation of name-based test linking.
