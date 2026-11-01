import json

import httpx
import pytest

from prrisk.diff import FileChange, Status
from prrisk.llm import (
    AnthropicProvider,
    LLMUnavailableError,
    OpenAIProvider,
    build_prompt,
    review,
)
from prrisk.rules import Finding, Severity

FILES = [FileChange("app/x.py", "app/x.py", Status.MODIFIED,
                    added={10: "total = price * qty", 11: "return total"}, removed={10: "old"})]


class Fake:
    name = "fake"

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.prompts = reply, error, []

    def complete(self, system, prompt):
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        return self.reply


def test_grounded_comments_kept_hallucinated_ones_dropped():
    reply = "Sure! Here you go:\n" + json.dumps([
        {"path": "app/x.py", "line": 10, "severity": "medium", "message": "qty can be negative"},
        {"path": "app/x.py", "line": 99, "severity": "high", "message": "line not in diff"},
        {"path": "app/other.py", "line": 10, "severity": "low", "message": "file not in PR"},
        {"path": "app/x.py", "line": 11, "severity": "catastrophic", "message": "bad severity"},
        {"path": "app/x.py", "line": "eleven", "severity": "low", "message": "bad line"},
        {"line": 11},
    ])
    result = review(Fake(reply), FILES, [])
    assert [(c.line, c.message) for c in result.comments] == [(10, "qty can be negative")]
    assert result.rejected == 5 and "5 LLM comment(s) dropped" in result.note


@pytest.mark.parametrize(
    ("reply", "error", "note"),
    [
        ("I think the code looks fine.", None, "not valid JSON"),
        ('{"path": "app/x.py"}', None, "not valid JSON"),
        ("[1, 2", None, "not valid JSON"),
        (None, LLMUnavailableError("openai: ReadTimeout"), "ReadTimeout"),
    ],
)
def test_llm_failures_degrade_to_a_note(reply, error, note):
    result = review(Fake(reply, error), FILES, [])
    assert result.comments == [] and note in result.note


def test_prompt_contains_numbered_added_lines_and_known_findings():
    f = Finding("app/x.py", 10, "SEC005", "security", Severity.HIGH, "SQL built with formatting")
    prompt = build_prompt(FILES, [f])
    assert "10: +total = price * qty" in prompt and "SEC005" in prompt
    assert "old" not in prompt.split("Diff:")[1]


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_provider_request_and_parsing():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "[]"}}]})

    p = OpenAIProvider("sk-test", client=_client(handler))
    assert p.complete("sys", "hi") == "[]"
    assert seen["auth"] == "Bearer sk-test" and seen["body"]["temperature"] == 0


def test_anthropic_provider_request_and_parsing():
    def handler(request):
        assert request.headers["x-api-key"] == "k"
        return httpx.Response(200, json={"content": [{"text": "[]"}]})

    assert AnthropicProvider("k", client=_client(handler)).complete("s", "p") == "[]"


@pytest.mark.parametrize("provider_cls", [OpenAIProvider, AnthropicProvider])
@pytest.mark.parametrize(
    "handler",
    [
        lambda r: httpx.Response(500, json={}),
        lambda r: httpx.Response(200, json={"unexpected": True}),
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=r)),
    ],
)
def test_provider_errors_become_unavailable(provider_cls, handler):
    with pytest.raises(LLMUnavailableError):
        provider_cls("k", client=_client(handler)).complete("s", "p")
