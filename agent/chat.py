"""One entry point for every model call: the offline stub by default, Ollama when a provider is named."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import httpx

from agent.state import caps

LOGGER = logging.getLogger("netsec_agent")
DEFAULT_PROVIDER = "ollama:qwen2.5:3b"
OLLAMA_URL = "http://127.0.0.1:11434"


class ModelError(RuntimeError):
    """A model call failed and the run must fall back to the rule path."""


class ModelTimeout(ModelError):
    """A model call did not answer in time."""


def use_live() -> bool:
    return os.environ.get("NETSEC_AGENT_USE_LIVE", "0") == "1"


def default_provider() -> str:
    return os.environ.get("AGENT_LLM_PROVIDER") or DEFAULT_PROVIDER


def ollama_url() -> str:
    return os.environ.get("NETSEC_OLLAMA_URL") or OLLAMA_URL


def deadline_now(state: dict) -> float | None:
    """The wall-clock deadline of the run, when it is running, so model calls stay inside the budget."""
    from agent.state import deadline  # imported lazily to break a circular import with state
    budget = state.get("budget") if isinstance(state, dict) else None
    return deadline(budget) if isinstance(budget, dict) else None


def llm_skip_reason() -> str:
    """Why a node did not call a model; printed on its trace line."""
    if not use_live():
        return "offline (NETSEC_AGENT_USE_LIVE=0); the rule path stands"
    return "the model layer did not decide to speak; the rule path stands"


def _effective_timeout(timeout: float | None, deadline: float | None) -> float:
    """The timeout of this single call: the configured one, or the run's remaining time when it is shorter."""
    configured = float(timeout or caps()["llm_timeout_s"])
    if deadline is None:
        return configured
    remaining = float(deadline) - time.time()
    if remaining <= 0:
        raise TimeoutError("the run deadline passed before the model call")
    return min(configured, remaining)


def _chat_offline(messages: list[dict], tools: list[dict] | None) -> dict:
    """Deterministic stand-in: one tool call when tools are offered, then a reply without citations.

    A reply without citations cannot be grounded, so the rule tree decides; the loop still closes offline.
    """
    already_called = any(m.get("role") == "tool" for m in messages)
    if tools and not already_called:
        name = (tools[0].get("function") or {}).get("name") or tools[0].get("name") or "tool"
        return {"content": "", "tool_calls": [{"name": name, "arguments": {}}]}
    reply = {
        "reasoning": "offline stub",
        "action": "standard",
        "rationale": "offline stub reply without citations",
        "priority": 0,
        "cited_sources": [],
        "assessment": "",
    }
    return {"content": json.dumps(reply), "tool_calls": []}


def _chat_ollama(messages: list[dict], tools: list[dict] | None, model: str, timeout: float,
                 json_format: bool) -> dict:
    """One call to a local Ollama. Returns `content`, `tool_calls` and the token counts Ollama reports."""
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        # A low temperature for a decision engine: the same input should give the same verdict.
        "options": {"temperature": 0.1},
    }
    if json_format:
        body["format"] = "json"
    if tools:
        body["tools"] = tools
    try:
        response = httpx.post(f"{ollama_url()}/api/chat", json=body, timeout=timeout)
        response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise ModelTimeout(f"the model did not answer within {timeout:.1f}s") from exc
    except httpx.HTTPStatusError as exc:
        raise ModelError(f"the model returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise ModelError(f"the model could not be reached: {type(exc).__name__}") from exc
    try:
        data = response.json()
    except ValueError as exc:
        raise ModelError("the model returned something that is not JSON") from exc
    message = data.get("message") or {}
    calls = []
    for call in message.get("tool_calls") or []:
        # Ollama returns `{"function": {"name": ..., "arguments": ...}}`; anything else is noise.
        function = call.get("function") or {}
        name = function.get("name")
        if name:
            calls.append({"name": str(name), "arguments": function.get("arguments") or {}})
    return {
        "content": message.get("content") or "",
        "tool_calls": calls,
        "tokens_in": int(data.get("prompt_eval_count") or 0),
        "tokens_out": int(data.get("eval_count") or 0),
    }


def chat(
    messages: list[dict],
    *,
    provider: str | None = None,
    tools: list[dict] | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
    json_format: bool = False,
) -> dict[str, Any]:
    """Call a model named `provider:model`. Returns content, tool_calls and the call's accounting."""
    provider = provider or default_provider()
    started = time.time()
    if deadline is not None and started >= deadline:
        raise TimeoutError("the run deadline passed before the model call")
    if not use_live() or provider.startswith("offline"):
        out = _chat_offline(messages, tools)
        out.update(model="offline:stub", mode="offline-stub", tokens_in=0, tokens_out=0,
                   latency_s=round(time.time() - started, 3), calls=1)
        return out
    if not provider.startswith("ollama:"):
        raise NotImplementedError(f"provider {provider!r} is not available; only ollama:<model> is wired")
    _, _, model = provider.partition(":")
    if not model:
        raise ValueError(f"provider {provider!r} does not name a model")
    effective = _effective_timeout(timeout, deadline)
    out = _chat_ollama(messages, tools, model, effective, json_format)
    out.update(model=provider, mode="ollama", latency_s=round(time.time() - started, 3), calls=1)
    return out
