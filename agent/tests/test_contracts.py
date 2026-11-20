"""Handoff contracts, the run budget, the policy file, the model stub and the deterministic workers."""

from __future__ import annotations

import json
import re
import time

import pytest

from agent import chat as chat_module
from agent import policy
from agent.adapter import case_metadata, normalize_case
from agent.chat import chat, llm_skip_reason
from agent.profile import build_profile
from agent.research import query_security_standards
from agent.state import (
    ContractError,
    assert_decision_grounded,
    assert_perception_handoff,
    assert_research_handoff,
    budget_state,
    caps,
    check_budget,
    cost_usd,
    deadline,
    graceful_stop_decision,
    new_budget,
    start_clock,
)
from agent.tests.builders import make_payload

ML_AGREES = {"anomaly": True, "iso_score": -0.08, "cluster": -1}
PERCEPTION = {"sender": "profile_builder", "recipient": "rag_retriever", "finding_profile": {"severity": "high"},
              "confidence": "high", "missing_fields": []}
RESEARCH = {"sender": "rag_retriever", "recipient": "decision", "procedures": [{"id": "attack:T1046"}],
            "tool_result_ids": ["attack:T1046"], "coverage": "direct_match", "confidence": "high"}


# ---- handoff contracts ------------------------------------------------------

def test_valid_handoffs_pass():
    assert assert_perception_handoff(PERCEPTION) is True
    assert assert_perception_handoff(dict(PERCEPTION, recipient="decision")) is True
    assert assert_research_handoff(RESEARCH) is True
    assert assert_research_handoff(dict(RESEARCH, procedures=[], tool_result_ids=[], coverage="not_applicable")) is True


@pytest.mark.parametrize("change", [
    {"sender": "decision"},
    {"recipient": "approval_gate"},
    {"finding_profile": {}},
    {"finding_profile": None},
    {"confidence": "certain"},
])
def test_a_broken_perception_handoff_is_refused(change):
    with pytest.raises(ContractError):
        assert_perception_handoff(dict(PERCEPTION, **change))


@pytest.mark.parametrize("change", [
    {"sender": "profile_builder"},
    {"recipient": "supervisor"},
    {"coverage": "some_match"},
    {"tool_result_ids": None},
    {"procedures": None},
    {"tool_result_ids": ["attack:T1046", "attack:T9999"]},
    {"tool_result_ids": []},
])
def test_a_broken_research_handoff_is_refused(change):
    with pytest.raises(ContractError):
        assert_research_handoff(dict(RESEARCH, **change))


def test_citations_must_come_from_the_retrieved_ids():
    ids = ["attack:T1046", "attack:T1498.001"]
    assert assert_decision_grounded("standard", ["attack:T1046"], ids) is True
    assert assert_decision_grounded("urgent", ids, ids) is True
    with pytest.raises(ContractError, match="ungrounded citation"):
        assert_decision_grounded("standard", ["attack:T1046", "attack:T9999"], ids)
    with pytest.raises(ContractError, match="ungrounded citation"):
        assert_decision_grounded("human_review", ["attack:T9999"], ids)


@pytest.mark.parametrize("action, allowed", [
    ("urgent", False), ("standard", False), ("human_review", True), ("known_pattern", True), ("monitor", True),
])
def test_only_some_actions_may_cite_nothing(action, allowed):
    if allowed:
        assert assert_decision_grounded(action, [], ["attack:T1046"]) is True
    else:
        with pytest.raises(ContractError, match="needs at least one grounded citation"):
            assert_decision_grounded(action, [], ["attack:T1046"])


# ---- budget -----------------------------------------------------------------

def test_default_caps():
    assert caps() == {"max_iterations": 8, "max_tool_hops": 3, "cost_cap_usd": 0.10, "wall_clock_cap_s": 360.0,
                      "llm_timeout_s": 150.0}


def test_caps_come_from_the_environment_and_ignore_garbage(monkeypatch):
    monkeypatch.setenv("AGENT_MAX_ITERATIONS", "5")
    monkeypatch.setenv("WALL_CLOCK_CAP_SECONDS", "120")
    monkeypatch.setenv("AGENT_COST_CAP_USD", "not a number")
    assert (caps()["max_iterations"], caps()["wall_clock_cap_s"], caps()["cost_cap_usd"]) == (5, 120.0, 0.10)


def test_each_cap_stops_the_run_with_its_own_reason(monkeypatch):
    fresh = start_clock(new_budget())
    assert check_budget(fresh) == (False, "")
    assert check_budget(dict(fresh, iterations=7)) == (False, "")
    assert check_budget(dict(fresh, iterations=8)) == (True, "AGENT_MAX_ITERATIONS (8) reached")
    fired, reason = check_budget(fresh, tokens_in=200_000, tokens_out=100_000)
    assert fired and reason == "AGENT_COST_CAP_USD ($0.1) reached (spent $0.1200)"
    fired, reason = check_budget(dict(fresh, started_at=time.time() - 400))
    assert fired and reason == "WALL_CLOCK_CAP_SECONDS (360) reached"


def test_the_clock_starts_once_and_gives_the_run_a_deadline():
    budget = new_budget()
    assert budget == {"iterations": 0, "started_at": None, "tool_hops": {}}
    assert deadline(budget) is None
    started = start_clock(budget)
    assert budget["started_at"] is None
    assert start_clock(started) is started
    assert deadline(started) == pytest.approx(started["started_at"] + 360.0)


def test_cost_and_budget_state():
    assert cost_usd(1000, 500) == pytest.approx(0.0006)
    state = budget_state(dict(start_clock(new_budget()), iterations=3), 10, 20)
    assert (state["iterations"], state["tokens_in"], state["tokens_out"], state["wall_cap_s"], state["cost_cap_usd"]) == \
        (3, 10, 20, 360.0, 0.10)
    assert 0 <= state["wall_s"] < 5


def test_a_fired_cap_is_a_human_review_that_says_how_far_the_run_got():
    profile = {"primary_technique": "T1046", "severity": "high"}
    research = {"coverage": "direct_match", "tool_result_ids": ["attack:T1046"]}
    verdict = graceful_stop_decision("AGENT_MAX_ITERATIONS (8) reached",
                                     {"last_speaker": "rag_retriever", "profile": profile, "research": research})
    assert (verdict["action"], verdict["priority"], verdict["source"], verdict["reason"], verdict["guard_fired"]) == \
        ("human_review", 55, "budget_guard", "budget_guard", True)
    assert verdict["rationale"] == (
        "budget guard fired: AGENT_MAX_ITERATIONS (8) reached. stopped at rag_retriever. "
        "profile_builder got as far as technique=T1046 severity=high. "
        "rag_retriever got as far as coverage=direct_match with 1 passage(s). "
        "decision was not reached; manual triage recommended.")
    assert graceful_stop_decision("x")["rationale"] == "budget guard fired: x."


# ---- policy -----------------------------------------------------------------

def test_the_policy_file_carries_a_version_and_the_agreed_actions():
    # The date of the policy, with a revision number when it changed twice on one day.
    assert re.fullmatch(r"\d{4}\.\d{2}\.\d{2}(\.\d+)?", policy.POLICY_VERSION)
    assert policy.get("actions") == ["urgent", "standard", "human_review", "known_pattern", "monitor"]
    assert policy.get("decision", "urgent") == {"rules": ["scan_alerts", "flood_alerts"],
                                                "requires_ml_agreement": True, "requires_critical_asset": True,
                                                "session_scope_rules": ["flood_alerts"]}
    assert set(policy.get("engines", "rule_technique")) == set(policy.get("engines", "high_precision_rules"))
    assert policy.get("grounding", "allow_empty_citations") == ["human_review", "known_pattern", "monitor"]
    assert policy.get("no", "such", "key", default="fallback") == "fallback"
    assert policy.priority("urgent") == 90
    assert policy.priority("no_such_name") == policy.priority("human_review") == 55


def test_the_prompt_text_is_rendered_from_the_same_file():
    text = policy.render_policy_rules()
    assert text.splitlines()[0] == f"POLICY version {policy.POLICY_VERSION}"
    assert "Actions: urgent, standard, human_review, known_pattern, monitor." in text
    assert "one of the rules scan_alerts, flood_alerts fired, IsolationForest agrees" in text
    assert "On a session-level candidate (an aggregate event with no ML score and no asset) the rule flood_alerts " \
           "is enough. urgent always waits for a human approval." in text
    for trigger in policy.get("decision", "human_review", "triggers"):
        assert f"  - {trigger}" in text
    assert text.splitlines()[-1] == "Floors applied over your verdict: " + ", ".join(policy.get("floors")) + "."


def test_a_policy_file_without_a_version_is_refused(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("actions: [urgent]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a policy file with a version"):
        policy.load_policy(path)
    path.write_text('version: "2099.01.01"\nactions: [urgent]\n', encoding="utf-8")
    assert policy.load_policy(path)["version"] == "2099.01.01"


# ---- model stub -------------------------------------------------------------

def test_offline_the_stub_calls_a_tool_once_and_then_answers_without_citations():
    tools = [{"type": "function", "function": {"name": "check_finding_severity"}}]
    first = chat([{"role": "user", "content": "case"}], tools=tools)
    assert first["tool_calls"] == [{"name": "check_finding_severity", "arguments": {}}]
    assert (first["model"], first["mode"], first["tokens_in"], first["tokens_out"]) == ("offline:stub", "offline-stub", 0, 0)
    second = chat([{"role": "user", "content": "case"}, {"role": "tool", "content": "{}"}], tools=tools)
    assert second["tool_calls"] == []
    assert json.loads(second["content"])["cited_sources"] == []
    assert chat([{"role": "user", "content": "case"}])["tool_calls"] == []


def test_no_live_provider_exists_yet(monkeypatch):
    assert chat_module.use_live() is False
    assert llm_skip_reason() == "offline (NETSEC_AGENT_USE_LIVE=0); the rule path stands"
    monkeypatch.setenv("NETSEC_AGENT_USE_LIVE", "1")
    assert chat_module.use_live() is True
    assert llm_skip_reason() == "the model layer is not wired yet (phase P2); the rule path stands"
    with pytest.raises(NotImplementedError):
        chat([{"role": "user", "content": "case"}], provider="ollama:qwen2.5:3b")
    assert chat([{"role": "user", "content": "case"}], provider="offline:stub")["mode"] == "offline-stub"


def test_a_model_call_after_the_run_deadline_is_refused():
    with pytest.raises(TimeoutError):
        chat([{"role": "user", "content": "case"}], deadline=time.time() - 1)


# ---- adapter ----------------------------------------------------------------

def test_a_real_candidate_is_normalised(vm_candidates):
    case = normalize_case(vm_candidates["1:192.168.1.10"], {})
    assert (case["session_id"], case["candidate_id"], case["kind"], case["pcap_name"], case["analyst_note"]) == \
        (1, "192.168.1.10", "ip", "tcp_syn_scan.pcap", "")
    assert case["pcap_sha256"] == "dea976e9f081d758f13e988481ce09dd8262031d48efb59d0daa9764e816e23d"
    assert case["asset"] == {"role": "unknown", "oui_vendor": case["asset"]["oui_vendor"], "hostname": None,
                             "is_private": True, "is_my_device": False, "is_declared_infra": False,
                             "targets_infra": False}
    assert case["quality"] == {"duration_s": 1.2, "total_packets": 2020, "total_ips": 5, "lstm_ran": False,
                               "self_telemetry": False, "gaps": 0}


def test_asset_flags_come_from_the_environment():
    payload = make_payload("10.0.0.5", adv_rows=[
        {"signal": "beaconing", "score": 0.7, "peer": "100.64.0.9"},
        {"signal": "beaconing", "score": 0.7, "peer": "100.64.0.7", "device": "10.0.0.99"},
    ])
    assert normalize_case(payload, {"NETSEC_MY_DEVICE_IP": " 10.0.0.5 "})["asset"]["is_my_device"] is True
    assert normalize_case(payload, {"NETSEC_MY_DEVICE_IP": "10.0.0.6"})["asset"]["is_my_device"] is False
    assert normalize_case(payload, {"NETSEC_INFRA_DSTS": "10.0.0.1, 10.0.0.5"})["asset"]["is_declared_infra"] is True
    assert normalize_case(payload, {"NETSEC_INFRA_DSTS": "100.64.0.9"})["asset"]["targets_infra"] is True
    # A peer of another device's signal does not make this candidate a threat to infrastructure.
    assert normalize_case(payload, {"NETSEC_INFRA_DSTS": "100.64.0.7"})["asset"]["targets_infra"] is False
    assert normalize_case(payload, {})["asset"]["is_my_device"] is False


def test_the_environment_of_the_process_is_the_default(monkeypatch):
    monkeypatch.setenv("NETSEC_MY_DEVICE_IP", "10.0.0.5")
    assert normalize_case(make_payload("10.0.0.5"))["asset"]["is_my_device"] is True


def test_metadata_for_the_trace_header(vm_candidates):
    case = normalize_case(vm_candidates["2:192.168.1.1"], {})
    assert case_metadata(case, build_profile(case)) == {
        "candidate_id": "192.168.1.1", "kind": "ip", "session_id": 2, "pcap_name": "arpspoof.pcap",
        "pcap_sha256": "0ce605556689edec01ef50703df7cc88c97a0d1731c4938d54cabcb28a71837a",
        "technique": "T1557.002", "score": 0.9, "asset_role": "unknown",
        "engines": {"rules": ["arp_multi_mac", "amp_alerts"], "ml": ["dbscan_noise"], "advanced": ["arp_ip_multi_mac"]},
    }
    assert case_metadata(case)["technique"] is None


# ---- deterministic workers --------------------------------------------------

def test_profile_of_the_real_scan(vm_candidates):
    profile = build_profile(normalize_case(vm_candidates["1:192.168.1.10"], {}))
    assert profile["engines_fired"] == {"rules": ["scan_alerts"], "ml": ["isolation_forest", "dbscan_noise"],
                                        "advanced": []}
    assert profile["rule_details"] == {"scan_alerts": "SYN x1002 to 1 dst(s)"}
    assert (profile["primary_technique"], profile["other_techniques"]) == ("T1046", [])
    assert (profile["ml_agrees"], profile["ml_strong"], profile["iso_score"]) == (True, False, -0.0165)
    assert (profile["score"], profile["score_band"], profile["severity"], profile["confidence"]) == \
        (0.9, "strong", "high", "high")
    assert profile["quality_warnings"] == ["short_capture", "lstm_not_run"]
    assert profile["detector_found_nothing"] is False
    assert profile["asset"]["critical"] is False


@pytest.mark.parametrize("spec, expected", [
    ({}, ("none", "low", 0.0, "none", True)),
    ({"ml": {"cluster": -1}}, ("low", "high", 0.15, "weak", False)),
    ({"ml": ML_AGREES}, ("low", "medium", 0.3, "weak", False)),
    ({"ml": {"anomaly": True, "iso_score": -0.3}}, ("moderate", "medium", 0.5, "mid", False)),
    ({"advanced": {"dga": 0.6}}, ("moderate", "low", 0.6, "mid", False)),
    ({"rules": ["amp_alerts"]}, ("high", "medium", 0.7, "strong", False)),
    ({"rules": ["amp_alerts"], "ml": ML_AGREES}, ("high", "high", 0.9, "strong", False)),
    ({"rules": ["scan_alerts"], "ml": ML_AGREES, "category": "Network Infrastructure"},
     ("severe", "high", 0.9, "strong", False)),
    ({"rules": ["scan_alerts"], "fusion": 0.45}, ("high", "medium", 0.45, "mid", False)),
    ({"candidate": "session:S1", "kind": "session", "rules": ["flood_alerts"],
      "ml": {"anomaly": None, "cluster": None, "iso_score": None}}, ("severe", "medium", 0.7, "strong", False)),
])
def test_profile_bands(spec, expected):
    profile = build_profile(normalize_case(make_payload(**spec), {}))
    assert (profile["severity"], profile["confidence"], profile["score"], profile["score_band"],
            profile["detector_found_nothing"]) == expected


def test_profile_quality_warnings():
    payload = make_payload(duration_s=12.0, packets=400, ml={"lstm_bin_flag_count": 0})
    payload["ip_features"] = {"self_telemetry": 1}
    payload["gaps"] = 2
    profile = build_profile(normalize_case(payload, {}))
    assert profile["quality_warnings"] == ["short_capture", "few_packets", "self_telemetry", "capture_gaps"]
    assert build_profile(normalize_case(make_payload(ml={"lstm_bin_flag_count": 0}), {}))["quality_warnings"] == []


def test_research_names_its_sources_and_how_well_they_cover_the_question():
    direct = query_security_standards("T1046", "unknown")
    assert (direct["backend"], direct["coverage"], direct["tool_result_ids"]) == \
        ("static_table", "direct_match", ["attack:T1046"])
    assert direct["procedures"][0]["title"] == "Network Service Discovery"
    assert direct["rag_filter"] == {"technique": "T1046", "asset_role": "unknown", "k": 3}
    assert direct["decision_coverage"] == {"answered": [], "missing": ["containment", "severity", "false_positive"],
                                           "sufficiency": "insufficient_coverage"}
    parent = query_security_standards("T1090.004")
    assert (parent["coverage"], parent["tool_result_ids"], parent["procedures"][0]["support"]) == \
        ("partial_match", ["attack:T1090"], "parent")
    assert (query_security_standards("T1571")["coverage"], query_security_standards("T1571")["tool_result_ids"]) == \
        ("no_match", [])
    assert query_security_standards("T9999.001")["coverage"] == "no_match"
    assert query_security_standards(None)["coverage"] == "not_applicable"
    assert query_security_standards("T1046", k=1)["rag_filter"]["k"] == 1
