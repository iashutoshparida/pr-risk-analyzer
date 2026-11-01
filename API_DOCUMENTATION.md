# API

Start with `prrisk serve` or Docker. Interactive docs at `/docs`. All endpoints except
`/v1/health` need `X-API-Key`; the server stores only SHA-256 hashes (`PRRISK_API_KEY_HASHES`)
and returns 503 if none are configured.

| Method & path | Body | Result |
|---|---|---|
| `GET /v1/health` | - | `{"status": "ok"}` |
| `POST /v1/review/diff` | `{"diff": "<unified diff>"}` | Report; line-level checks only (no repository context) |
| `POST /v1/review/github` | `{"repo": "owner/name", "pr": 42, "comment": false}` | Full report using `PRRISK_GITHUB_TOKEN`; posts/updates the PR comment if `comment` is true |

Errors: `{"error": "...", "detail": "..."}` with 401 (key), 422 (validation, malformed diff),
413 (diff over 5 MB), 502 (GitHub error), 503 (no keys configured), 500 (unexpected; logged only).

Report shape (abridged):

```json
{
  "summary": {"risk_score": 45, "risk_level": "high", "files_changed": 3, "lines_added": 3,
              "lines_removed": 2, "findings_by_severity": {"critical": 0, "high": 2, "medium": 0,
              "low": 0, "info": 0}, "functions_changed": 2, "functions_without_tests": 2},
  "files": [{"path": "shop/db.py", "score": 45, "level": "high",
             "factors": ["+2 2 lines changed", "+25 findings (worst: high)", "raised to 45: worst finding is high"],
             "modified_functions": ["find"], "dependents": []}],
  "findings": [{"path": "shop/db.py", "line": 2, "rule": "SEC005", "severity": "high",
                "message": "SQL built with string formatting; use bound parameters"}],
  "missing_tests": [{"function": "find", "reason": "`find` has no test that references it"}],
  "llm_comments": [],
  "notes": []
}
```
