"""The model entry point: the offline stub, the Ollama provider, timeouts, and the run-deadline cap."""

from __future__ import annotations

import json
import time

import httpx
import pytest

from agent import chat as chat_module
from agent.chat import ModelError, ModelTimeout, chat


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.request = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")

    def raise_for_status(self) -> None:
        if 400 <= self.status_code:
            raise httpx.HTTPStatusError("http error", request=self.request,
                                        response=httpx.Response(self.status_code, request=self.request))

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def _ollama_reply(content: str, *, tokens_in: int = 42, tokens_out: int = 7,
                  tool_calls: list | None = None) -> dict:
    """What `/api/chat` returns on success."""
    message: dict = {"content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"message": message, "prompt_eval_count": tokens_in, "eval_count": tokens_out}


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setenv("NETSEC_AGENT_USE_LIVE", "1")


@pytest.fixture
def ollama(monkeypatch, live):
    """Capture the last httpx.post call and return a configurable fake response."""
    seen: dict[str, object] = {}

    def fake_post(url, **kwargs):
        seen["url"] = url
        seen["body"] = kwargs.get("json")
        seen["timeout"] = kwargs.get("timeout")
        return seen["response"]

    monkeypatch.setattr(httpx, "post", fake_post)
    return seen


def test_the_offline_stub_runs_when_the_live_flag_is_off():
    out = chat([{"role": "user", "content": "x"}])
    assert (out["mode"], out["model"], out["tokens_in"], out["tokens_out"]) == ("offline-stub", "offline:stub", 0, 0)
    assert out["latency_s"] >= 0 and out["calls"] == 1


def test_an_unknown_provider_is_refused(live):
    with pytest.raises(NotImplementedError):
        chat([{"role": "user", "content": "x"}], provider="openai:gpt-4")


def test_a_provider_without_a_model_is_refused(live):
    with pytest.raises(ValueError, match="does not name a model"):
        chat([{"role": "user", "content": "x"}], provider="ollama:")


def test_an_ollama_call_builds_the_request_the_server_expects(ollama):
    ollama["response"] = _FakeResponse(_ollama_reply('{"action": "monitor"}'))
    out = chat([{"role": "user", "content": "scan on 10.0.0.5"}], json_format=True,
               provider="ollama:qwen2.5:3b", timeout=12)
    assert ollama["url"] == "http://127.0.0.1:11434/api/chat"
    body = ollama["body"]
    assert (body["model"], body["stream"], body["format"]) == ("qwen2.5:3b", False, "json")
    assert body["options"]["temperature"] == 0.1
    assert body["messages"][0]["content"] == "scan on 10.0.0.5"
    assert ollama["timeout"] == pytest.approx(12)
    assert (out["content"], out["model"], out["mode"], out["tokens_in"], out["tokens_out"]) == \
        ('{"action": "monitor"}', "ollama:qwen2.5:3b", "ollama", 42, 7)
    assert (out["calls"], out["tool_calls"]) == (1, [])


def test_the_default_provider_is_qwen(ollama):
    ollama["response"] = _FakeResponse(_ollama_reply("ok"))
    chat([{"role": "user", "content": "x"}])
    assert ollama["body"]["model"] == "qwen2.5:3b"


def test_the_default_provider_can_be_overridden(monkeypatch, ollama):
    monkeypatch.setenv("AGENT_LLM_PROVIDER", "ollama:llama3.2:3b")
    ollama["response"] = _FakeResponse(_ollama_reply("ok"))
    chat([{"role": "user", "content": "x"}])
    assert ollama["body"]["model"] == "llama3.2:3b"


def test_the_ollama_url_can_be_overridden(monkeypatch, ollama):
    monkeypatch.setenv("NETSEC_OLLAMA_URL", "http://ollama.lan:11434")
    ollama["response"] = _FakeResponse(_ollama_reply("ok"))
    chat([{"role": "user", "content": "x"}])
    assert ollama["url"] == "http://ollama.lan:11434/api/chat"


def test_tool_calls_come_through_in_the_shape_the_nodes_use(ollama):
    ollama["response"] = _FakeResponse(_ollama_reply("", tool_calls=[
        {"function": {"name": "check_finding_severity", "arguments": {"ip": "10.0.0.5"}}},
        {"name": "ignored_without_a_name"},
    ]))
    out = chat([{"role": "user", "content": "x"}])
    assert out["tool_calls"] == [{"name": "check_finding_severity", "arguments": {"ip": "10.0.0.5"}}]


def test_an_http_error_from_the_server_is_a_model_error(ollama):
    ollama["response"] = _FakeResponse({}, status_code=503)
    with pytest.raises(ModelError, match="HTTP 503"):
        chat([{"role": "user", "content": "x"}])


def test_a_network_timeout_is_a_model_timeout(monkeypatch, live):
    def raise_timeout(*args, **kwargs):
        raise httpx.ReadTimeout("slow server")

    monkeypatch.setattr(httpx, "post", raise_timeout)
    with pytest.raises(ModelTimeout, match="within"):
        chat([{"role": "user", "content": "x"}], timeout=5)


def test_a_connection_error_is_a_model_error(monkeypatch, live):
    def raise_connection(*args, **kwargs):
        raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(httpx, "post", raise_connection)
    with pytest.raises(ModelError, match="could not be reached"):
        chat([{"role": "user", "content": "x"}])


def test_a_non_json_body_is_a_model_error(ollama):
    ollama["response"] = _FakeResponse(None)
    with pytest.raises(ModelError, match="not JSON"):
        chat([{"role": "user", "content": "x"}])


def test_the_run_deadline_shrinks_the_single_call_timeout(ollama):
    ollama["response"] = _FakeResponse(_ollama_reply("ok"))
    chat([{"role": "user", "content": "x"}], timeout=100, deadline=time.time() + 4)
    # The configured timeout is 100s, but only 4s remain; the effective one is around 4.
    assert ollama["timeout"] < 5


def test_a_call_after_the_deadline_is_refused():
    with pytest.raises(TimeoutError):
        chat([{"role": "user", "content": "x"}], deadline=time.time() - 1)


def test_a_call_with_no_time_left_before_the_post_is_refused(ollama):
    """A deadline that is in the past when the body is built never even reaches the server."""
    ollama["response"] = _FakeResponse(_ollama_reply("ok"))
    with pytest.raises(TimeoutError):
        chat([{"role": "user", "content": "x"}], deadline=time.time() - 0.1)


def test_offline_tools_path_still_returns_a_tool_call():
    tools = [{"function": {"name": "check_finding_severity"}}]
    first = chat([{"role": "user", "content": "x"}], tools=tools)
    assert first["tool_calls"] == [{"name": "check_finding_severity", "arguments": {}}]
    second = chat([{"role": "user", "content": "x"}, {"role": "tool", "content": "{}"}], tools=tools)
    assert json.loads(second["content"])["action"] == "standard"


def test_the_default_timeout_falls_back_to_the_cap(monkeypatch, ollama):
    monkeypatch.setenv("AGENT_LLM_TIMEOUT_SECONDS", "42")
    ollama["response"] = _FakeResponse(_ollama_reply("ok"))
    chat([{"role": "user", "content": "x"}])
    assert ollama["timeout"] == pytest.approx(42, abs=0.5)


def test_deadline_now_reads_the_run_budget():
    from agent.chat import deadline_now
    from agent.state import new_budget, start_clock
    assert deadline_now({}) is None
    running = start_clock(new_budget())
    value = deadline_now({"budget": running})
    assert value is not None and value > time.time()


def test_module_names():
    # Imported directly in agent/nodes.py; a rename would break imports there.
    assert all(hasattr(chat_module, name) for name in ("chat", "use_live", "llm_skip_reason", "ModelError",
                                                        "ModelTimeout", "deadline_now"))
