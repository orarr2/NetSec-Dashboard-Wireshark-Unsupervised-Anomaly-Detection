"""The graph's nodes. Each appends one trace entry and names the next hop; the supervisor routes and guards the budget."""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Mapping

from agent import factcheck, policy, prompts

LOGGER = logging.getLogger("netsec_agent")
from agent.chat import ModelError, chat, deadline_now, llm_skip_reason, use_live
from agent.db import get_db
from agent.profile import build_profile, fired_rules, own_adv_rows
from agent.research import query_security_standards
from agent.rule_tree import apply_floors, decide_rule_based
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


def _rule_intake(note_text: str, families_reported: set[str]) -> dict:
    """The deterministic reading of a note: keywords, addresses, urgency, and a flag when it contradicts."""
    text = note_text.lower()
    mentioned = [family for family, rx in _NOTE_KEYWORDS.items() if re.search(rx, text)]
    contradicts = bool(mentioned) and not (set(mentioned) & families_reported)
    return {
        "mentioned": mentioned, "reported_by_engines": sorted(families_reported),
        "devices": sorted(set(_IP.findall(note_text)))[:5],
        "urgency_claimed": bool(_URGENCY.search(note_text)),
        "contradictions": ["technique"] if contradicts else [],
    }


def _llm_intake(note_text: str, families_reported: set[str], state_dict: Mapping[str, Any]) -> tuple[dict, dict]:
    """The LLM's reading of the same note. The rule reading stays the fallback on any failure."""
    reply = chat(
        [{"role": "system", "content": prompts.intake_prompt()},
         {"role": "user", "content": prompts.render_case(state_dict["case"],
                                                         extra={"analyst_note": note_text,
                                                                "engines_reported": sorted(families_reported)})}],
        json_format=True, deadline=deadline_now(state_dict),
    )
    parsed = factcheck.repair_json(reply["content"])
    mentioned = [str(f) for f in (parsed.get("mentioned_families") or []) if isinstance(f, str)]
    devices = [str(d) for d in (parsed.get("mentioned_devices") or []) if isinstance(d, str)][:5]
    urgency = bool(parsed.get("urgency_claimed"))
    disagrees = bool(parsed.get("disagrees_with_engines")) or (bool(mentioned)
                                                               and not (set(mentioned) & families_reported))
    return {
        "mentioned": mentioned, "reported_by_engines": sorted(families_reported), "devices": devices,
        "urgency_claimed": urgency, "contradictions": ["technique"] if disagrees else [],
    }, {"model": reply["model"], "calls": reply["calls"], "latency_s": reply["latency_s"],
        "tokens_in": reply["tokens_in"], "tokens_out": reply["tokens_out"], "mode": reply["mode"]}


def signal_extractor_node(state: CaseState) -> dict:
    """Intake: what the analyst note claims and where it contradicts the engines. Without a note it passes through."""
    note = (state.get("sanitized") or {}).get("note") or {}
    tokens_in = tokens_out = 0
    content: dict[str, Any] = {"has_text": bool(note.get("has_text")), "source": "none", "llm_used": False}

    if not note.get("has_text"):
        pass
    elif note.get("suspicious"):
        content.update(has_text=True, suspicious=True, mentioned=[], devices=[], urgency_claimed=False,
                       contradictions=[])
    else:
        reported = engine_families(state["case"])
        # The signal gate of the Intake worker: no note, no call.
        if use_live():
            try:
                parsed, llm = _llm_intake(note["text"], reported, state)
                content.update(parsed, source="llm", llm_used=True, llm=llm)
                tokens_in, tokens_out = llm["tokens_in"], llm["tokens_out"]
            except (ModelError, TimeoutError, ValueError, KeyError) as exc:
                LOGGER.warning("intake_llm_failed: %s", type(exc).__name__)
                content.update(_rule_intake(note["text"], reported), source="rules", llm_used=False,
                               llm_skipped_reason=f"model fallback: {type(exc).__name__}; the rule path stands")
        else:
            content.update(_rule_intake(note["text"], reported), source="rules", llm_used=False,
                           llm_skipped_reason=llm_skip_reason())
    return {
        "intake_signals": content,
        "next_hop": "supervisor",
        "last_speaker": "signal_extractor",
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
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


def _llm_decision(
    *,
    case: Mapping[str, Any], profile: Mapping[str, Any], research: Mapping[str, Any],
    sanitized: Mapping[str, Any], intake: Mapping[str, Any], tree: Mapping[str, Any],
    state_dict: Mapping[str, Any],
) -> tuple[dict, dict, list[str]]:
    """One ReAct hop: ask the model, repair, fact-check, and on failure ask once more with the reasons.

    Returns the verdict the model proposed, the accounting of the calls, and the reasons of the last
    fact-check pass (empty when the verdict is good).
    """
    base_messages = [
        {"role": "system", "content": prompts.decision_prompt()},
        {"role": "user", "content": prompts.render_case(case, profile, research,
                                                        extra={"rule_tree_verdict": dict(tree),
                                                               "intake_signals": dict(intake),
                                                               "sanitized_summary": {
                                                                   "suspicious": sanitized.get("suspicious"),
                                                                   "pii_redacted": sanitized.get("pii_redacted"),
                                                               }})},
    ]
    calls, tokens_in, tokens_out, latency = 0, 0, 0, 0.0
    model_name = "offline:stub"
    reasons: list[str] = []
    repair_rounds = int(policy.get("grounding", "retry_on_fail", default=1))
    attempt_messages = list(base_messages)
    verdict: dict = {}
    for attempt in range(1 + repair_rounds):
        reply = chat(attempt_messages, json_format=True, deadline=deadline_now(state_dict))
        calls += int(reply.get("calls") or 1)
        tokens_in += int(reply.get("tokens_in") or 0)
        tokens_out += int(reply.get("tokens_out") or 0)
        latency += float(reply.get("latency_s") or 0.0)
        model_name = reply.get("model") or model_name
        try:
            parsed = factcheck.repair_json(reply["content"])
        except (ValueError, KeyError, TypeError) as exc:
            reasons = [f"json_parse_failed: {type(exc).__name__}"]
            parsed = {}
        # The fact check only runs when the JSON parsed into a dict.
        verdict = {
            "action": parsed.get("action"),
            "priority": parsed.get("priority"),
            "rationale": parsed.get("rationale"),
            "cited_sources": parsed.get("cited_sources") or [],
            "assessment": parsed.get("assessment") or "",
        }
        ok, reasons = (False, reasons) if not parsed else factcheck.verify(
            verdict, case=case, profile=profile, research=research, sanitized=sanitized)
        if ok:
            reasons = []
            break
        if attempt >= repair_rounds:
            break
        # One repair round: the same prompt plus the reasons the check failed; the model answers again.
        attempt_messages = list(base_messages) + [
            {"role": "assistant", "content": reply["content"]},
            {"role": "user", "content": "Your reply did not pass the fact check: " + "; ".join(reasons)
             + ". Reply again with only the JSON object, fixing these points. Never cite an id that is not "
             + "in tool_result_ids."},
        ]
    llm = {"model": model_name, "calls": calls, "latency_s": round(latency, 3),
           "tokens_in": tokens_in, "tokens_out": tokens_out, "mode": "ollama"}
    return verdict, llm, reasons


def decision_node(state: CaseState) -> dict:
    """Decision. The rule tree always produces a verdict; on a live run the model is asked once, then floors apply."""
    profile = state.get("profile") or {}
    research = state.get("research") or {}
    sanitized = state.get("sanitized") or {}
    intake = state.get("intake_signals") or {}
    catalogue = profile.get("catalogue") or {}
    tree = decide_rule_based(profile=profile, research=research, sanitized=sanitized,
                             intake=intake, catalogue=catalogue)
    ids = list(state.get("tool_result_ids") or [])
    verdict = dict(tree)
    cited = ids[:3] if verdict["action"] in ("urgent", "standard") else []
    llm_proposed: str | None = None
    floor_applied = False
    floor_reason: str | None = None
    floor_trigger: str | None = None
    overridden: dict | None = None
    fallback: str | None = None
    llm: dict | None = None
    llm_used = False
    llm_reasons: list[str] = []

    # The signal gate: a catalogue match ends the case without a model; the tree verdict is final.
    skip_reason: str | None = None
    if catalogue.get("match"):
        skip_reason = "catalogue match; the rule tree decided without a model"
    elif sanitized.get("suspicious"):
        skip_reason = "suspicious input; no model is trusted on this case"
    elif tree.get("reason") == "nothing_to_triage":
        skip_reason = "nothing to triage; the rule tree decided without a model"
    elif not use_live():
        skip_reason = llm_skip_reason()

    if skip_reason is None:
        llm_used = True
        try:
            proposed, llm, llm_reasons = _llm_decision(
                case=state["case"], profile=profile, research=research, sanitized=sanitized,
                intake=intake, tree=tree, state_dict=state,
            )
            llm_proposed = proposed.get("action")
            if llm_reasons:
                # Fact-check failed twice: keep the rule tree's verdict but mark the model text as unverified.
                fallback = "rationale_unverified"
                verdict = dict(tree, rationale=factcheck.deterministic_rationale(tree, profile))
                cited = ids[:3] if verdict["action"] in ("urgent", "standard") else []
            else:
                # Apply the floors over the model verdict; a floor sends it to a human, never to monitor.
                final = apply_floors(proposed, tree_verdict=tree, profile=profile, research=research,
                                     sanitized=sanitized, intake=intake, catalogue=catalogue)
                floor_applied = bool(final.get("floor_applied"))
                floor_reason = final.get("floor_reason")
                floor_trigger = final.get("floor_trigger")
                overridden = final.get("overridden_llm_verdict")
                verdict = {
                    "action": final.get("action"),
                    "priority": final.get("priority"),
                    "reason": final.get("floor_reason") or final.get("reason") or tree.get("reason"),
                    "rationale": final.get("rationale") or proposed.get("rationale") or tree.get("rationale"),
                    "source": final.get("source") or "llm_react",
                }
                cited = list(proposed.get("cited_sources") or [])
                if floor_applied:
                    # A floor moves the verdict toward a human; its own rationale is deterministic, no cite needed.
                    cited = ids[:3] if verdict["action"] in ("urgent", "standard") else []
        except (ModelError, TimeoutError) as exc:
            llm_used = False
            fallback = f"llm_{type(exc).__name__}"
            LOGGER.warning("decision_llm_failed case_id=%s: %s", state.get("case_id"), type(exc).__name__)

    # The grounding assert over the final verdict: every cite must come from the retrieved ids.
    try:
        assert_decision_grounded(verdict["action"], cited, ids)
    except ContractError as exc:
        fallback = fallback or "rule_verdict_not_grounded"
        verdict = dict(tree, action="human_review", priority=policy.priority("human_review"),
                       reason=fallback, rationale=f"{fallback}: {exc}; routed to a human."[:500],
                       source="rule_based")
        cited = []
        floor_applied = False

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
        "action": verdict["action"], "priority": verdict["priority"], "source": verdict.get("source", "rule_based"),
        "reason": verdict.get("reason"), "rationale": verdict.get("rationale") or "", "cited_sources": cited,
        "rule_tree_action": tree["action"], "llm_proposed_action": llm_proposed,
        "floor_applied": floor_applied, "floor_reason": floor_reason, "floor_trigger": floor_trigger,
        "overridden_llm_verdict": overridden, "fallback_reason": fallback,
        "llm_used": llm_used, "llm_skipped_reason": skip_reason if not llm_used else None,
        "llm": llm, "tool_calls": tool_calls, "work_order_id": work_order_id,
        "worker_impact": {
            "profile_llm_changed": False, "research_llm_changed": False,
            "rule_hint_without_worker_llm": tree["action"], "rule_hint_with_worker_llm": tree["action"],
        },
        "budget_state": budget_state(state.get("budget") or {}, state.get("tokens_in", 0), state.get("tokens_out", 0)),
    }
    tokens_in = (llm or {}).get("tokens_in", 0)
    tokens_out = (llm or {}).get("tokens_out", 0)
    out = {
        "verdict": verdict, "action": verdict["action"], "priority": int(verdict["priority"]),
        "rationale": verdict.get("rationale") or "",
        "assessment": "" if fallback else "",  # the assessment field is wired here for a later phase
        "cited_sources": cited,
        "tokens_in": int(tokens_in), "tokens_out": int(tokens_out),
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
