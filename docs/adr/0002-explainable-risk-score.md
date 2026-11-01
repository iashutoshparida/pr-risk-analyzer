# ADR 0002: Additive, explained risk score with a severity floor

Decision: each factor (churn, findings, dependents, sensitive path, untested functions,
complexity, deletion) adds bounded points and records a reason string shown in the report.
A plain sum let a one-line SQL injection score "medium" while a big harmless refactor scored
higher, so the worst finding sets a floor: critical 70, high 45, medium 20.
Rejected: a learned model. There is no labelled PR history to train on, and reviewers need to see
why a file is ranked first.
