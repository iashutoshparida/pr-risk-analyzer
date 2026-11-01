"""Minimal GitHub REST client: read a PR, read files at a commit, upsert one review comment.

Implements the SourceProvider protocol, so the engine can analyse a PR without a local clone.
The token is sent only in the Authorization header and never logged or put in error messages.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx

from prrisk.errors import SourceError
from prrisk.report import MARKER

_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
API = "https://api.github.com"


class GitHubClient:
    def __init__(
        self,
        repo: str,
        token: str | None,
        client: httpx.Client | None = None,
        timeout_s: float = 20.0,
    ) -> None:
        if not _REPO.match(repo):
            raise SourceError(f"repository must look like owner/name, got {repo!r}")
        self.repo = repo
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "prrisk",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = client or httpx.Client()
        self._headers, self._timeout = headers, timeout_s

    def _request(
        self,
        method: str,
        path: str,
        *,
        accept: str | None = None,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        headers = dict(self._headers)
        if accept:
            headers["Accept"] = accept
        try:
            response = self._http.request(
                method,
                f"{API}{path}",
                headers=headers,
                params=params,
                json=json,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise SourceError(f"GitHub request failed: {type(exc).__name__}") from exc
        if response.status_code == 404:
            return response
        if response.status_code in (401, 403):
            raise SourceError(
                f"GitHub refused the request ({response.status_code}); "
                "check the token's permissions and rate limit"
            )
        if response.status_code >= 400:
            raise SourceError(f"GitHub returned {response.status_code} for {method} {path}")
        return response

    # ------------------------------------------------------------------ PR
    def pull(self, number: int) -> dict[str, str]:
        r = self._request("GET", f"/repos/{self.repo}/pulls/{number}")
        if r.status_code == 404:
            raise SourceError(f"pull request #{number} not found in {self.repo}")
        data = r.json()
        return {
            "base_sha": data["base"]["sha"],
            "head_sha": data["head"]["sha"],
            "title": data.get("title", ""),
        }

    def pull_diff(self, number: int) -> str:
        r = self._request(
            "GET", f"/repos/{self.repo}/pulls/{number}", accept="application/vnd.github.diff"
        )
        if r.status_code == 404:
            raise SourceError(f"pull request #{number} not found in {self.repo}")
        return r.text

    # ------------------------------------------------------- SourceProvider
    def read(self, ref: str, path: str) -> str | None:
        r = self._request(
            "GET",
            f"/repos/{self.repo}/contents/{quote(path)}",
            accept="application/vnd.github.raw+json",
            params={"ref": ref},
        )
        return None if r.status_code == 404 else r.text

    def list_python_files(self, ref: str) -> list[str]:
        r = self._request(
            "GET", f"/repos/{self.repo}/git/trees/{quote(ref)}", params={"recursive": "1"}
        )
        if r.status_code == 404:
            raise SourceError(f"revision {ref} not found")
        return [
            item["path"]
            for item in r.json().get("tree", [])
            if item.get("type") == "blob" and item["path"].endswith(".py")
        ]

    # ------------------------------------------------------------- comment
    def upsert_comment(self, number: int, body: str, max_pages: int = 10) -> str:
        """Update our previous report comment if there is one, so re-runs do not spam the PR."""
        if MARKER not in body:
            body = f"{MARKER}\n{body}"
        for page in range(1, max_pages + 1):
            r = self._request(
                "GET",
                f"/repos/{self.repo}/issues/{number}/comments",
                params={"per_page": 100, "page": page},
            )
            comments = r.json() if r.status_code == 200 else []
            for c in comments:
                if MARKER in (c.get("body") or ""):
                    self._request(
                        "PATCH",
                        f"/repos/{self.repo}/issues/comments/{c['id']}",
                        json={"body": body},
                    )
                    return "updated"
            if len(comments) < 100:
                break
        self._request("POST", f"/repos/{self.repo}/issues/{number}/comments", json={"body": body})
        return "created"
