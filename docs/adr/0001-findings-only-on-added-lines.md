# ADR 0001: Report findings only on lines the PR adds

Context: running every rule on every touched file blames a PR for old debt and buries the new
problem. Decision: AST and text rules receive the set of added line numbers and report a node only
if one of its lines is new (multi-line calls count if any line is new). Consequence: a PR that
moves risky code is flagged again (the lines are new), which is acceptable; old issues in
untouched lines are left to a full-repository scanner.
