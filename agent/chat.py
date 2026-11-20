"""One entry point for every model call. Only the offline stub exists so far; the Ollama provider arrives in phase P2."""

from __future__ import annotations

import json
import os
import time
from typing import Any


def use_live() -> bool:
    return os.environ.get("NETSEC_AGENT_USE_LIVE", "0") == "1"


def llm_skip_reason() -> str:
    """Why a node did not call a model; printed on its trace line."""
    if not use_live():
        return "offline (NETSEC_AGENT_USE_LIVE=0); the rule path stands"
    return "the model layer is not wired yet (phase P2); the rule path stands"


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


def chat(
    messages: list[dict],
    *,
    provider: str | None = None,
    tools: list[dict] | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Call a model named `provider:model`. Returns content, tool_calls and the call's accounting."""
    provider = provider or os.environ.get("AGENT_LLM_PROVIDER") or "offline:stub"
    started = time.time()
    if deadline is not None and started >= deadline:
        raise TimeoutError("the run deadline passed before the model call")
    if not use_live() or provider.startswith("offline"):
        out = _chat_offline(messages, tools)
        out.update(model="offline:stub", mode="offline-stub", tokens_in=0, tokens_out=0,
                   latency_s=round(time.time() - started, 3))
        return out
    raise NotImplementedError(f"provider {provider!r} is not available yet; live model calls arrive in phase P2")
