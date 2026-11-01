# Security

* **Running git safely**: argv lists only, never a shell; refs must match a strict character set and
  cannot start with `-`; paths with `..` are rejected; every call has a timeout.
* **Untrusted diffs**: 5 MB limit; malformed or truncated diffs are rejected, not half-parsed.
* **Tokens**: `GITHUB_TOKEN`, LLM keys and API keys come only from the environment, are sent only in
  headers, and never appear in errors or logs (tested). The API stores SHA-256 hashes of its keys,
  compares with `hmac.compare_digest`, and fails closed when none are set.
* **LLM output** is data, not instructions: it is parsed as JSON, validated field by field, and
  only kept if it points at an added line. It cannot change scores or findings.
* **Forks**: the PR workflow skips commenting on PRs from forks, where the token is read-only.
* **Container** runs as a non-root user.

Known gaps: no rate limiting on the API; pattern rules are not a full static security analysis.
Report vulnerabilities through a private GitHub security advisory.
