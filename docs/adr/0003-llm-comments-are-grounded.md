# ADR 0003: LLM comments must point at added lines

LLMs invent line numbers and comment on code that did not change. Every comment must parse, use a
known severity, and reference a (path, line) pair in the PR's added lines; anything else is
dropped and counted in the report. The LLM never changes scores or deterministic findings, and any
provider error or timeout turns into a note so the review always completes.
