"""Optional LLM review. The model only adds comments; it never changes the score or overrides
deterministic findings, and every comment it returns is checked against the diff."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Protocol

import httpx

from prrisk.diff import FileChange
from prrisk.rules import Finding

log = logging.getLogger("prrisk.llm")

MAX_PROMPT_LINES = 400
_SEVERITIES = {"info", "low", "medium", "high"}


class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, prompt: str) -> str: ...


class LLMUnavailableError(Exception):
    pass


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", timeout_s: float = 30.0,
                 client: httpx.Client | None = None) -> None:
        self._key, self._model, self._timeout = api_key, model, timeout_s
        self._client = client or httpx.Client()

    def complete(self, system: str, prompt: str) -> str:
        try:
            r = self._client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self._key}"},
                json={"model": self._model, "temperature": 0,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": prompt}]},
                timeout=self._timeout,
            )
            r.raise_for_status()
            content: str = r.json()["choices"][0]["message"]["content"]
            return content
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LLMUnavailableError(f"openai: {type(exc).__name__}") from exc


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5", timeout_s: float = 30.0,
                 client: httpx.Client | None = None) -> None:
        self._key, self._model, self._timeout = api_key, model, timeout_s
        self._client = client or httpx.Client()

    def complete(self, system: str, prompt: str) -> str:
        try:
            r = self._client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": self._key, "anthropic-version": "2023-06-01"},
                json={"model": self._model, "max_tokens": 1500, "system": system,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=self._timeout,
            )
            r.raise_for_status()
            content: str = r.json()["content"][0]["text"]
            return content
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LLMUnavailableError(f"anthropic: {type(exc).__name__}") from exc


@dataclass(frozen=True)
class ReviewComment:
    path: str
    line: int
    severity: str
    message: str


@dataclass(frozen=True)
class LLMReview:
    provider: str
    comments: list[ReviewComment]
    rejected: int
    note: str | None = None


SYSTEM = (
    "You review a pull request diff. Comment only on lines that start with '+'. "
    "Reply with a JSON array only, no prose: "
    '[{"path": str, "line": int, "severity": "info|low|medium|high", "message": str}]. '
    "Use the exact path and the new-file line number shown before each added line. "
    "Do not repeat the static-analysis findings listed. Return [] if nothing is worth saying."
)


def build_prompt(files: list[FileChange], findings: list[Finding]) -> str:
    parts, budget = [], MAX_PROMPT_LINES
    for change in files:
        if change.binary or not change.added or budget <= 0:
            continue
        parts.append(f"### {change.path}")
        for line_no in sorted(change.added)[:budget]:
            parts.append(f"{line_no}: +{change.added[line_no]}")
            budget -= 1
    known = "\n".join(f"- {f.path}:{f.line} {f.rule} {f.message}" for f in findings[:50])
    return f"Static-analysis findings already reported:\n{known or '- none'}\n\nDiff:\n" + \
        "\n".join(parts)


def _extract_json(text: str) -> object:
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end < start:
        raise ValueError("no JSON array in response")
    return json.loads(text[start : end + 1])


def review(provider: LLMProvider, files: list[FileChange], findings: list[Finding]) -> LLMReview:
    added = {(f.path, line) for f in files for line in f.added}
    try:
        raw = provider.complete(SYSTEM, build_prompt(files, findings))
        items = _extract_json(raw)
    except LLMUnavailableError as exc:
        log.warning("llm unavailable", extra={"error": str(exc)})
        return LLMReview(provider.name, [], 0, f"LLM review skipped: {exc}")
    except ValueError:
        return LLMReview(provider.name, [], 0, "LLM review skipped: response was not valid JSON")
    if not isinstance(items, list):
        return LLMReview(provider.name, [], 0, "LLM review skipped: expected a JSON array")

    accepted, rejected = [], 0
    for item in items:
        try:
            comment = ReviewComment(str(item["path"]), int(item["line"]),
                                    str(item["severity"]).lower(), str(item["message"]).strip())
        except (KeyError, TypeError, ValueError):
            rejected += 1
            continue
        # Grounding check: the model must point at a line this PR actually added.
        if (comment.path, comment.line) not in added or comment.severity not in _SEVERITIES \
                or not comment.message or len(comment.message) > 500:
            rejected += 1
            continue
        accepted.append(comment)
    note = f"{rejected} LLM comment(s) dropped: not on an added line or malformed" \
        if rejected else None
    return LLMReview(provider.name, accepted, rejected, note)
