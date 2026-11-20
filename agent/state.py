"""Graph state, the handoff contracts between agents, and the run budget."""

from __future__ import annotations

import operator
import os
import time
from typing import Annotated, Any, Literal, TypedDict

from agent import policy

Confidence = Literal["high", "medium", "low"]
Coverage = Literal["direct_match", "partial_match", "no_match", "not_applicable"]

GATED_ACTIONS = ("urgent", "human_review")

# Commercial-equivalent price per token, so a self-hosted run can still be costed.
PRICE_IN = 0.0003 / 1000
PRICE_OUT = 0.0006 / 1000


class PerceptionHandoff(TypedDict):
    sender: Literal["profile_builder"]
    recipient: Literal["rag_retriever", "decision"]
    finding_profile: dict
    confidence: Confidence
    missing_fields: list[str]


class ResearchHandoff(TypedDict):
    sender: Literal["rag_retriever"]
    recipient: Literal["decision"]
    procedures: list[dict]
    tool_result_ids: list[str]
    coverage: Coverage
    confidence: Confidence


class CaseState(TypedDict, total=False):
    case_id: str
    case: dict
    runtime: dict
    sanitized: dict
    intake_signals: dict
    supervisor_plan: dict
    profile: dict
    perception_confidence: str
    research: dict
    tool_result_ids: list[str]
    verdict: dict
    action: str
    priority: int
    rationale: str
    assessment: str
    cited_sources: list[str]
    approval: dict
    next_hop: str
    last_speaker: str
    budget: dict
    guard_fired: bool
    fallback_reason: str
    trace: Annotated[list[dict], operator.add]
    tokens_in: Annotated[int, operator.add]
    tokens_out: Annotated[int, operator.add]


class ContractError(ValueError):
    """A handoff between two agents broke its contract."""


def assert_perception_handoff(h: dict) -> bool:
    if h.get("sender") != "profile_builder" or h.get("recipient") not in ("rag_retriever", "decision"):
        raise ContractError(f"perception handoff has the wrong direction: {h.get('sender')} -> {h.get('recipient')}")
    if not isinstance(h.get("finding_profile"), dict) or "severity" not in h["finding_profile"]:
        raise ContractError("perception handoff carries no finding profile")
    if h.get("confidence") not in ("high", "medium", "low"):
        raise ContractError(f"perception handoff has an invalid confidence: {h.get('confidence')}")
    return True


def assert_research_handoff(h: dict) -> bool:
    if h.get("sender") != "rag_retriever" or h.get("recipient") != "decision":
        raise ContractError(f"research handoff has the wrong direction: {h.get('sender')} -> {h.get('recipient')}")
    if h.get("coverage") not in ("direct_match", "partial_match", "no_match", "not_applicable"):
        raise ContractError(f"research handoff has an invalid coverage: {h.get('coverage')}")
    ids = h.get("tool_result_ids")
    procedures = h.get("procedures")
    if not isinstance(ids, list) or not isinstance(procedures, list):
        raise ContractError("research handoff must carry procedures and tool_result_ids lists")
    if sorted(str(p.get("id")) for p in procedures) != sorted(str(i) for i in ids):
        raise ContractError("tool_result_ids do not match the retrieved procedures")
    return True


def assert_decision_grounded(action: str, cited_sources: list[str], tool_result_ids: list[str]) -> bool:
    """Every citation must be an id the retrieval step returned; some actions may cite nothing."""
    cited = [str(c) for c in cited_sources or []]
    allowed = {str(i) for i in tool_result_ids or []}
    unknown = [c for c in cited if c not in allowed]
    if unknown:
        raise ContractError(f"ungrounded citation(s): {', '.join(unknown)}")
    if not cited and action not in policy.get("grounding", "allow_empty_citations", default=[]):
        raise ContractError(f"action {action} needs at least one grounded citation")
    return True


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def caps() -> dict[str, float]:
    return {
        "max_iterations": _env_int("AGENT_MAX_ITERATIONS", 8),
        "max_tool_hops": _env_int("AGENT_MAX_TOOL_HOPS", 3),
        "cost_cap_usd": _env_float("AGENT_COST_CAP_USD", 0.10),
        "wall_clock_cap_s": _env_float("WALL_CLOCK_CAP_SECONDS", 360.0),
        "llm_timeout_s": _env_float("AGENT_LLM_TIMEOUT_SECONDS", 150.0),
    }


def new_budget() -> dict[str, Any]:
    return {"iterations": 0, "started_at": None, "tool_hops": {}}


def start_clock(budget: dict) -> dict:
    """The wall clock starts when the run enters the first node, not when the state is built."""
    if budget.get("started_at") is None:
        budget = dict(budget, started_at=time.time())
    return budget


def wall_seconds(budget: dict) -> float:
    started = budget.get("started_at")
    return 0.0 if started is None else max(0.0, time.time() - float(started))


def deadline(budget: dict) -> float | None:
    started = budget.get("started_at")
    return None if started is None else float(started) + caps()["wall_clock_cap_s"]


def cost_usd(tokens_in: int, tokens_out: int) -> float:
    return int(tokens_in or 0) * PRICE_IN + int(tokens_out or 0) * PRICE_OUT


def check_budget(budget: dict, tokens_in: int = 0, tokens_out: int = 0) -> tuple[bool, str]:
    c = caps()
    if int(budget.get("iterations", 0)) >= c["max_iterations"]:
        return True, f"AGENT_MAX_ITERATIONS ({int(c['max_iterations'])}) reached"
    spent = cost_usd(tokens_in, tokens_out)
    if spent >= c["cost_cap_usd"]:
        return True, f"AGENT_COST_CAP_USD (${c['cost_cap_usd']}) reached (spent ${spent:.4f})"
    if wall_seconds(budget) >= c["wall_clock_cap_s"]:
        return True, f"WALL_CLOCK_CAP_SECONDS ({c['wall_clock_cap_s']:.0f}) reached"
    return False, ""


def budget_state(budget: dict, tokens_in: int = 0, tokens_out: int = 0) -> dict:
    c = caps()
    return {
        "iterations": int(budget.get("iterations", 0)),
        "tokens_in": int(tokens_in or 0),
        "tokens_out": int(tokens_out or 0),
        "wall_s": round(wall_seconds(budget), 2),
        "wall_cap_s": c["wall_clock_cap_s"],
        "cost_cap_usd": c["cost_cap_usd"],
    }


def graceful_stop_decision(reason: str, state: dict | None = None) -> dict:
    """A budget cap is a legitimate human_review answer, not a crash."""
    parts = [f"budget guard fired: {reason}."]
    if state:
        parts.append(f"stopped at {state.get('last_speaker') or 'pre-sanitize'}.")
        profile = state.get("profile") or {}
        if profile:
            parts.append(
                f"profile_builder got as far as technique={profile.get('primary_technique') or 'none'} "
                f"severity={profile.get('severity') or '?'}."
            )
        research = state.get("research") or {}
        if research.get("coverage"):
            parts.append(
                f"rag_retriever got as far as coverage={research['coverage']} "
                f"with {len(research.get('tool_result_ids') or [])} passage(s)."
            )
        parts.append("decision was not reached; manual triage recommended.")
    return {
        "action": "human_review",
        "priority": policy.priority("human_review"),
        "rationale": " ".join(parts)[:500],
        "reason": "budget_guard",
        "source": "budget_guard",
        "cited_sources": [],
        "guard_fired": True,
    }
