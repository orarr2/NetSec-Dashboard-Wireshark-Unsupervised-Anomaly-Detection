"""The prompts: every one is rendered from policy.yaml, and render_case carries the facts the worker needs."""

from __future__ import annotations

import json

from agent import policy, prompts
from agent.adapter import normalize_case
from agent.profile import build_profile
from agent.research import query_security_standards
from agent.tests.builders import make_payload


def test_the_intake_prompt_names_the_safety_rule():
    text = prompts.intake_prompt()
    assert "UNTRUSTED packet content" in text and "REDACTED_SUSPICIOUS_STRING" in text
    for key in ("mentioned_families", "mentioned_devices", "urgency_claimed", "disagrees_with_engines"):
        assert key in text
    # The families match the ones the rule reader uses.
    for family in ("scan", "flood", "amplification", "arp_spoof", "beaconing", "dns_tunnel", "dga", "tls"):
        assert family in text


def test_the_decision_prompt_carries_the_policy_rules():
    text = prompts.decision_prompt()
    assert f"POLICY version {policy.POLICY_VERSION}" in text
    assert "urgent: one of the rules scan_alerts, flood_alerts" in text
    # Every allowed action appears in the output schema.
    for action in policy.get("actions"):
        assert action in text
    assert "tool_result_ids" in text and "refuses invented citations" in text
    # The safety rule is in every worker's prompt.
    assert "UNTRUSTED packet content" in text


def test_the_perception_prompt_asks_for_a_confidence_and_a_coherence_flag():
    text = prompts.perception_prompt()
    for key in ("cohere", "primary_technique", "confidence"):
        assert key in text
    assert "high, medium, low" in text


def test_the_research_prompt_lists_the_policy_questions():
    text = prompts.research_prompt()
    for question in policy.get("research", "questions", default=[]):
        assert question in text
    assert "answered" in text and "missing" in text


def test_render_case_carries_what_decision_needs(vm_candidates):
    payload = vm_candidates["2:192.168.1.1"]
    case = normalize_case(payload, {})
    profile = build_profile(case)
    research = query_security_standards(profile["primary_technique"], (profile.get("asset") or {}).get("role"))
    rendered = prompts.render_case(case, profile, research, extra={"rule_tree_verdict": {"action": "standard"}})
    parsed = json.loads(rendered)
    assert parsed["candidate_id"] == "192.168.1.1"
    assert parsed["engines"]["rules"] == ["arp_multi_mac", "amp_alerts"]
    assert parsed["primary_technique"] == "T1557.002"
    assert parsed["tool_result_ids"] == ["attack:T1557.002"]
    assert parsed["sources"][0]["id"] == "attack:T1557.002"
    # The extra field is merged on top.
    assert parsed["rule_tree_verdict"] == {"action": "standard"}
    # No raw asset secrets.
    assert "pcap_sha256" not in parsed


def test_render_case_without_a_profile_or_research_still_works():
    payload = make_payload("10.0.0.5", rules=["scan_alerts"])
    rendered = prompts.render_case(normalize_case(payload, {}))
    parsed = json.loads(rendered)
    assert parsed["candidate_id"] == "10.0.0.5"
    assert parsed["tool_result_ids"] == []
    assert parsed["sources"] == []
    assert parsed["primary_technique"] is None
