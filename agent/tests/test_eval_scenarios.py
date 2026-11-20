"""The offline evaluation set: every scenario runs through the whole graph without a model."""

from __future__ import annotations

import json

import pytest

from agent import policy
from agent.adapter import case_metadata
from agent.db import OPEN_ACTIONS, get_db
from agent.graph import run_graph
from agent.tests.builders import load_scenarios, scenario_payload
from agent.trace import format_trace_lines

SCENARIOS = load_scenarios()
IDS = [s["id"] for s in SCENARIOS]
GATED = ("urgent", "human_review")
TICKETED = ("urgent", "standard")


def _run(scenario, vm_candidates, monkeypatch):
    for name, value in (scenario.get("env") or {}).items():
        monkeypatch.setenv(name, value)
    payload = scenario_payload(scenario, vm_candidates)
    db = get_db()
    seed = scenario.get("catalogue")
    if seed is not None:
        sha256 = "cd" * 32 if seed.get("other_capture") else payload["session"]["pcap_sha256"]
        db.catalogue_add(sha256, seed.get("candidate") or payload["candidate_id"], label="approved earlier",
                         action="standard", source="approved_case", case_id="ns_earlier")
    case_id = f"ns_{scenario['id']}"
    return case_id, run_graph(case_id, payload), db


def _lines(case_id: str, final: dict) -> list[str]:
    return format_trace_lines(
        case_id, final["trace"], metadata=case_metadata(final["case"], final.get("profile")),
        verdict={"action": final["action"], "priority": final["priority"]},
        status="open" if final["action"] in OPEN_ACTIONS else "closed",
    )


def test_the_set_has_at_least_thirty_scenarios_with_unique_ids():
    assert len(IDS) >= 30
    assert len(IDS) == len(set(IDS))


def test_every_action_of_the_policy_is_exercised():
    assert {s["expect"]["action"] for s in SCENARIOS} == set(policy.get("actions"))


def test_every_real_candidate_is_a_scenario(vm_candidates):
    assert {s["base"] for s in SCENARIOS if s.get("base")} == set(vm_candidates)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_scenario_verdict(scenario, vm_candidates, monkeypatch):
    case_id, final, _ = _run(scenario, vm_candidates, monkeypatch)
    expect = scenario["expect"]
    verdict = final["verdict"]

    assert (final["action"], final["priority"], verdict["reason"]) == \
        (expect["action"], expect["priority"], expect["reason"])
    assert verdict["source"] == expect.get("source", "rule_based")
    assert final["rationale"].startswith(expect["reason"]) or verdict["source"] == "budget_guard"
    if "technique" in expect:
        assert (final.get("profile") or {}).get("primary_technique") == expect["technique"]
    if "cited" in expect:
        assert (final.get("cited_sources") or []) == expect["cited"]
    if "coverage" in expect:
        assert final["research"]["coverage"] == expect["coverage"]

    speakers = [e["speaker"] for e in final["trace"]]
    assert set(expect.get("present", [])) <= set(speakers)
    assert not set(expect.get("absent", [])) & set(speakers)
    for key, value in (expect.get("sanitized") or {}).items():
        assert final["sanitized"][key] == value, key
    for key, value in (expect.get("intake") or {}).items():
        assert final["intake_signals"][key] == value, key

    # A withheld string reaches neither the trace nor the terminal lines.
    shown = json.dumps(final["trace"], ensure_ascii=False) + "\n".join(_lines(case_id, final))
    for text in expect.get("withheld", []):
        assert text not in shown


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_scenario_invariants(scenario, vm_candidates, monkeypatch):
    """What holds for every run, whatever its verdict."""
    case_id, final, db = _run(scenario, vm_candidates, monkeypatch)
    action = final["action"]
    trace = final["trace"]
    speakers = [e["speaker"] for e in trace]

    assert action in policy.get("actions")
    assert speakers[:2] == ["sanitize", "signal_extractor"]
    assert speakers[2] in ("supervisor", "budget_guard")
    for entry in trace:
        assert set(entry) == {"iter", "speaker", "kind", "ts", "policy", "content"}
        assert entry["policy"] == policy.POLICY_VERSION
    assert [e["ts"] for e in trace] == sorted(e["ts"] for e in trace)
    assert [e["iter"] for e in trace] == sorted(e["iter"] for e in trace)

    # No model is called offline, so the verdict is the rule tree's or a guard's.
    assert not any(e["content"].get("llm_used") for e in trace)
    assert (final["tokens_in"], final["tokens_out"]) == (0, 0)
    decisions = [e["content"] for e in trace if e["speaker"] == "decision"]
    assert len(decisions) <= 1
    for content in decisions:
        assert content["floor_applied"] is False
        assert content["fallback_reason"] or content["rule_tree_action"] == action

    # Every urgent and human_review waits on exactly one pending approval; nothing else does.
    approvals = db.approvals_for_case(case_id)
    if action in GATED:
        assert [(a["action"], a["priority"], a["status"]) for a in approvals] == [(action, final["priority"], "pending")]
        assert speakers[-1] == "approval_gate"
    else:
        assert approvals == []
        assert "approval_gate" not in speakers

    # Every urgent and standard has one draft and cites only what the research step returned.
    orders = db.work_orders_for_case(case_id)
    cited = final.get("cited_sources") or []
    if action in TICKETED:
        assert [(o["kind"], o["status"]) for o in orders] == \
            [("containment_proposal" if action == "urgent" else "ticket", "draft")]
        assert cited and set(cited) <= set(final["tool_result_ids"])
    else:
        assert orders == []
        assert cited == []

    lines = _lines(case_id, final)
    assert lines[0] == "=" * 40
    assert lines[1].startswith(f"AGENT RUN  {case_id}")
    assert sum("[DONE    ]" in line for line in lines) == 1
    assert not any("UNGROUNDED" in line or "grounding check: FAIL" in line for line in lines)
