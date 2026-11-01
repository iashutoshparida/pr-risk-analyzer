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
