"""The graph's nodes. Each appends one trace entry and names the next hop; the supervisor routes and guards the budget."""

from __future__ import annotations

import os
import re
import time
from typing import Any, Mapping

from agent import policy
from agent.chat import llm_skip_reason
from agent.db import get_db
from agent.profile import build_profile, fired_rules, own_adv_rows
from agent.research import query_security_standards
from agent.rule_tree import decide_rule_based
from agent.sanitize import sanitize_case
from agent.state import (
    GATED_ACTIONS,
    CaseState,
    ContractError,
    PerceptionHandoff,
    ResearchHandoff,
    assert_decision_grounded,
    assert_perception_handoff,
    assert_research_handoff,
    budget_state,
    check_budget,
    graceful_stop_decision,
    new_budget,
    start_clock,
)

_RULE_FAMILY = {"scan_alerts": "scan", "flood_alerts": "flood", "amp_alerts": "amplification", "arp_multi_mac": "arp_spoof"}
_SIGNAL_FAMILY = (
    ("arp", "arp_spoof"), ("rogue_dhcp", "dhcp"), ("beacon", "beaconing"), ("dns_tunnel", "dns_tunnel"),
    ("dga", "dga"), ("nxdomain", "dga"), ("tls", "tls"), ("rare_ja3", "tls"), ("sni", "tls"),
)
_NOTE_KEYWORDS = {
    "scan": r"\bscan\w*|\bprob(e|ing)\b|\bsweep\w*|\bnmap\b|\breconnaissance\b",
    "flood": r"\bflood\w*|\bddos\b|\bdenial of service\b",
    "amplification": r"\bamplif\w*|\breflect\w*",
    "arp_spoof": r"\barp\b|\bspoof\w*|\bmitm\b|\bman in the middle\b|\bpoison\w*",
    "beaconing": r"\bbeacon\w*|\bc2\b|\bcommand and control\b",
    "dns_tunnel": r"\btunnel\w*|\bexfil\w*",
    "dga": r"\bdga\b|\bgenerated domains?\b",
    "tls": r"\btls\b|\bcertificate\b|\bja3\b|\bsni\b",
}
_URGENCY = re.compile(r"\burgent\w*|\bcritical\b|\basap\b|\bimmediately\b|\bright now\b|דחוף", re.IGNORECASE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _entry(state: Mapping[str, Any], speaker: str, kind: str, content: dict) -> dict:
    return {
        "iter": int((state.get("budget") or {}).get("iterations", 0)),
        "speaker": speaker,
        "kind": kind,
        "ts": time.time(),
        "policy": policy.POLICY_VERSION,
        "content": content,
    }


def _db(state: Mapping[str, Any]):
    return get_db((state.get("runtime") or {}).get("db_path"))


def _signal_family(name: str) -> str | None:
    for prefix, family in _SIGNAL_FAMILY:
        if prefix in name:
            return family
    return None


def engine_families(case: Mapping[str, Any]) -> set[str]:
    """The attack families the engines themselves reported for a case."""
    context = case.get("context") or {}
    out = {_RULE_FAMILY[r] for r in fired_rules(context.get("rule_signals") or {})}
    min_score = float(policy.get("engines", "advanced_fired_min_score"))
    for name, block in (context.get("advanced_signals") or {}).items():
        if isinstance(block, dict) and float(block.get("score") or 0.0) >= min_score and _signal_family(name):
            out.add(_signal_family(name))
    for row in own_adv_rows(case):
        family = _signal_family(str(row.get("signal") or ""))
        if family:
            out.add(family)
    return out


def sanitize_node(state: CaseState) -> dict:
    budget = start_clock(state.get("budget") or new_budget())
    result = sanitize_case(state["case"])
    content = {k: result[k] for k in
               ("strings_checked", "traffic_suspicious", "note_suspicious", "suspicious", "hits", "pii_redacted")}
    probe = dict(state, budget=budget)
    return {
        "case": result["clean_case"],
        "sanitized": {k: v for k, v in result.items() if k != "clean_case"},
        "budget": budget,
        "last_speaker": "sanitize",
        "trace": [_entry(probe, "sanitize", "handoff", content)],
    }


def signal_extractor_node(state: CaseState) -> dict:
    """Intake: what the analyst note claims and where it contradicts the engines. Without a note it passes through."""
    note = (state.get("sanitized") or {}).get("note") or {}
    if not note.get("has_text"):
        content = {"has_text": False, "source": "none", "llm_used": False}
    elif note.get("suspicious"):
        content = {"has_text": True, "source": "none", "llm_used": False, "suspicious": True,
                   "mentioned": [], "devices": [], "urgency_claimed": False, "contradictions": []}
    else:
        text = note["text"].lower()
        mentioned = [family for family, rx in _NOTE_KEYWORDS.items() if re.search(rx, text)]
        reported = engine_families(state["case"])
        contradicts = bool(mentioned) and not (set(mentioned) & reported)
        content = {
            "has_text": True, "source": "rules", "llm_used": False, "llm_skipped_reason": llm_skip_reason(),
            "mentioned": mentioned, "reported_by_engines": sorted(reported),
            "devices": sorted(set(_IP.findall(note["text"])))[:5],
            "urgency_claimed": bool(_URGENCY.search(note["text"])),
            "contradictions": ["technique"] if contradicts else [],
        }
    return {
        "intake_signals": content,
        "next_hop": "supervisor",
        "last_speaker": "signal_extractor",
        "trace": [_entry(state, "signal_extractor", "handoff", content)],
    }


def _build_plan(state: Mapping[str, Any]) -> dict:
    sanitized = state.get("sanitized") or {}
    intake = state.get("intake_signals") or {}
    case = state.get("case") or {}
    context = case.get("context") or {}
    rules = fired_rules(context.get("rule_signals") or {})
    families = engine_families(case)
    routing = os.environ.get("AGENT_SUPERVISOR_ROUTING", "1") == "1"
    if sanitized.get("suspicious"):
        concern, difficulty = "input_ambiguous", "hard"
    elif intake.get("contradictions"):
        concern, difficulty = "likely_human_review", "hard"
    elif len(families) > 1 or (families and not rules):
        concern, difficulty = "none", "mid"
    else:
        concern, difficulty = "none", "simple"
    force = "human_review" if sanitized.get("suspicious") and routing else None
    ml = context.get("ml_signals") or {}
    note = (
        f"Candidate {case.get('candidate_id')}: rules={','.join(rules) or 'none'}  "
        f"ml_anomaly={ml.get('anomaly')}  families={','.join(sorted(families)) or 'none'}  "
        f"analyst_note={'present' if intake.get('has_text') else 'absent'}."
    )
    return {
        "pipeline_concern": concern, "expected_difficulty": difficulty, "force_action": force, "note": note,
        "llm_used": False, "llm_skipped_reason": llm_skip_reason(),
    }


def supervisor_node(state: CaseState) -> dict:
    """Runs before every worker: counts the iteration, checks the caps, routes to the hop the last worker named."""
    budget = dict(state.get("budget") or new_budget())
    if state.get("supervisor_plan") is not None and state.get("next_hop") in ("approval_gate", "end"):
        # The verdict exists; a cap that trips now must not discard it.
        return {"budget": budget, "next_hop": state["next_hop"]}
    budget["iterations"] = int(budget.get("iterations", 0)) + 1
    probe = dict(state, budget=budget)
    fired, reason = check_budget(budget, state.get("tokens_in", 0), state.get("tokens_out", 0))
    if fired:
        verdict = graceful_stop_decision(reason, state)
        return {
            "budget": budget, "guard_fired": True, "verdict": verdict, "action": verdict["action"],
            "priority": verdict["priority"], "rationale": verdict["rationale"], "cited_sources": [],
            "fallback_reason": "guard_fired", "next_hop": "approval_gate", "last_speaker": "budget_guard",
            "trace": [_entry(probe, "budget_guard", "guard_fired", {
                "reason": reason, "action": verdict["action"], "priority": verdict["priority"],
                "rationale": verdict["rationale"],
            })],
        }
    if state.get("supervisor_plan") is None:
        plan = _build_plan(state)
        return {
            "budget": budget, "supervisor_plan": plan,
            "next_hop": "decision" if plan["force_action"] else "profile_builder",
            "trace": [_entry(probe, "supervisor", "supervisor_plan", plan)],
        }
    return {"budget": budget, "next_hop": state.get("next_hop") or "end"}


def profile_builder_node(state: CaseState) -> dict:
    """Perception: the finding profile, and whether this capture and candidate are already catalogued."""
    case = state["case"]
    profile = build_profile(case)
    match = _db(state).catalogue_lookup(case.get("pcap_sha256"), case.get("candidate_id"))
    if match:
        catalogue = {"match": True, "id": match["id"], "source": match["source"], "label": match["label"],
                     "action": match["action"], "case_id": match["case_id"]}
    else:
        catalogue = {"match": False, "reason": "no catalogued pattern with this fingerprint"
                     if case.get("pcap_sha256") else "the case carries no capture sha256"}
    recipient = "decision" if catalogue["match"] else "rag_retriever"
    handoff: PerceptionHandoff = {
        "sender": "profile_builder", "recipient": recipient, "finding_profile": profile,
        "confidence": profile["confidence"], "missing_fields": [],
    }
    assert_perception_handoff(handoff)
    content = {
        "primary_technique": profile["primary_technique"], "others": profile["other_techniques"],
        "severity": profile["severity"], "confidence": profile["confidence"],
        "llm_used": False, "llm_skipped_reason": llm_skip_reason(),
        "engines": profile["engines_fired"], "rule_details": profile["rule_details"],
        "iso_score": profile["iso_score"], "fusion_score": profile["fusion_score"], "score": profile["score"],
        "asset": profile["asset"], "catalogue": catalogue, "quality_warnings": profile["quality_warnings"],
        "to": recipient,
    }
    return {
        "profile": dict(profile, catalogue=catalogue),
        "perception_confidence": profile["confidence"],
        "next_hop": recipient,
        "last_speaker": "profile_builder",
        "trace": [_entry(state, "profile_builder", "handoff", content)],
    }


def rag_retriever_node(state: CaseState) -> dict:
    """Research: sources about the technique. Skipped when no engine named one."""
    profile = state.get("profile") or {}
    technique = profile.get("primary_technique")
    found = query_security_standards(technique, (profile.get("asset") or {}).get("role"))
    coverage = found["coverage"]
    handoff: ResearchHandoff = {
        "sender": "rag_retriever", "recipient": "decision", "procedures": found["procedures"],
        "tool_result_ids": found["tool_result_ids"], "coverage": coverage,
        "confidence": {"direct_match": "high", "partial_match": "medium"}.get(coverage, "low"),
    }
    assert_research_handoff(handoff)
    content = {
        "skipped": technique is None,
        "coverage": coverage, "n_procedures": len(found["procedures"]),
        "tool_result_ids": found["tool_result_ids"], "decision_coverage": found["decision_coverage"],
        "rag_query": found["rag_query"], "rag_filter": found["rag_filter"], "backend": found["backend"],
        "passage_previews": [
            {"id": p["id"], "distance": p["distance"], "support": p["support"], "preview": p["text"][:2000]}
            for p in found["procedures"]
        ],
        "llm_used": False, "llm_skipped_reason": llm_skip_reason(), "to": "decision",
    }
    return {
        "research": found,
        "tool_result_ids": found["tool_result_ids"],
        "next_hop": "decision",
        "last_speaker": "rag_retriever",
        "trace": [_entry(state, "rag_retriever", "handoff", content)],
    }


def decision_node(state: CaseState) -> dict:
    """Decision. The rule tree always produces a verdict; no model is asked until phase P2."""
    profile = state.get("profile") or {}
    research = state.get("research") or {}
    tree = decide_rule_based(
        profile=profile, research=research, sanitized=state.get("sanitized"),
        intake=state.get("intake_signals"), catalogue=profile.get("catalogue"),
    )
    verdict = dict(tree)
    ids = list(state.get("tool_result_ids") or [])
    cited = ids[:3] if verdict["action"] in ("urgent", "standard") else []
    fallback = None
    try:
        assert_decision_grounded(verdict["action"], cited, ids)
    except ContractError as exc:
        fallback = "rule_verdict_not_grounded"
        verdict.update(
            action="human_review", priority=policy.priority("human_review"), reason=fallback,
            rationale=f"{fallback}: {exc}; routed to a human."[:500],
        )
        cited = []

    case = state["case"]
    tool_calls = []
    work_order_id = None
    if verdict["action"] in ("urgent", "standard"):
        kind = "containment_proposal" if verdict["action"] == "urgent" else "ticket"
        work_order_id = _db(state).create_work_order(
            state["case_id"], kind,
            f"{verdict['action']}: {profile.get('primary_technique') or 'anomaly'} on {case.get('candidate_id')}",
            f"{verdict['rationale']}\nsources: {', '.join(cited) or 'none'}\n"
            f"session {case.get('session_id')} ({case.get('pcap_name') or 'unknown capture'})",
        )
        tool_calls.append({"tool": "create_draft_ticket", "ok": True, "executed": True, "result": work_order_id})

    content = {
        "action": verdict["action"], "priority": verdict["priority"], "source": verdict["source"],
        "reason": verdict["reason"], "rationale": verdict["rationale"], "cited_sources": cited,
        "rule_tree_action": tree["action"], "llm_proposed_action": None, "floor_applied": False,
        "fallback_reason": fallback, "llm_used": False, "llm_skipped_reason": llm_skip_reason(),
        "tool_calls": tool_calls, "work_order_id": work_order_id,
        "worker_impact": {
            "profile_llm_changed": False, "research_llm_changed": False,
            "rule_hint_without_worker_llm": tree["action"], "rule_hint_with_worker_llm": tree["action"],
        },
        "budget_state": budget_state(state.get("budget") or {}, state.get("tokens_in", 0), state.get("tokens_out", 0)),
    }
    out = {
        "verdict": verdict, "action": verdict["action"], "priority": int(verdict["priority"]),
        "rationale": verdict["rationale"], "assessment": "", "cited_sources": cited,
        "next_hop": "approval_gate" if verdict["action"] in GATED_ACTIONS else "end",
        "last_speaker": "decision",
        "trace": [_entry(state, "decision", "final", content)],
    }
    if fallback:
        out["fallback_reason"] = fallback
    return out


def approval_gate_node(state: CaseState) -> dict:
    """Every urgent and human_review stops here on a pending approval row. A failed write fails the run."""
    approval_id = _db(state).create_approval(state["case_id"], state["action"], int(state.get("priority") or 0))
    content = {"approval_id": approval_id, "action": state["action"], "priority": state.get("priority")}
    return {
        "approval": content,
        "next_hop": "end",
        "last_speaker": "approval_gate",
        "trace": [_entry(state, "approval_gate", "handoff", content)],
    }
