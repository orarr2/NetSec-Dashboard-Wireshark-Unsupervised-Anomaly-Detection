"""The rule tree's branch order and the floors applied over a model verdict."""

from __future__ import annotations

import pytest

from agent import policy
from agent.adapter import normalize_case
from agent.profile import build_profile
from agent.research import query_security_standards
from agent.rule_tree import apply_floors, decide_rule_based, urgent_preconditions
from agent.tests.builders import make_payload

ML_AGREES = {"anomaly": True, "iso_score": -0.08, "cluster": -1}
NO_ML = {"anomaly": None, "cluster": None, "iso_score": None, "iso_stability": None}
SUSPICIOUS = {"suspicious": True, "traffic_suspicious": True, "note_suspicious": False}
CONTRADICTION = {"contradictions": ["technique"], "mentioned": ["beaconing"]}
CATALOGUE = {"match": True, "id": "cat_1"}


def _profile(env: dict | None = None, **spec) -> dict:
    return build_profile(normalize_case(make_payload(**spec), env or {}))


def _research(profile: dict, sufficiency: str | None = None) -> dict:
    found = query_security_standards(profile["primary_technique"], profile["asset"]["role"])
    if sufficiency:
        found["decision_coverage"] = {"answered": ["containment", "severity", "false_positive"], "missing": [],
                                      "sufficiency": sufficiency}
    return found


def _model(action: str, priority: int = 40) -> dict:
    return {"action": action, "priority": priority, "rationale": "model text", "cited_sources": ["attack:T1046"]}


# ---- urgent preconditions ---------------------------------------------------

@pytest.mark.parametrize("spec, env, missing", [
    ({"rules": ["scan_alerts"], "ml": ML_AGREES, "category": "Network Infrastructure"}, {}, []),
    ({"rules": ["flood_alerts"], "ml": ML_AGREES}, {"NETSEC_MY_DEVICE_IP": "10.0.0.5"}, []),
    ({"rules": ["scan_alerts"], "ml": ML_AGREES}, {}, ["critical_asset"]),
    ({"rules": ["scan_alerts"], "category": "Network Infrastructure"}, {}, ["ml_agreement"]),
    ({"rules": ["amp_alerts"], "ml": ML_AGREES, "category": "Network Infrastructure"}, {},
     ["rule_in_scan_alerts_or_flood_alerts"]),
    ({}, {}, ["rule_in_scan_alerts_or_flood_alerts", "ml_agreement", "critical_asset"]),
    # An aggregate flood is a session-level candidate: no ML score and no asset exist, the rule is enough.
    ({"candidate": "session:S1", "kind": "session", "rules": ["flood_alerts"], "ml": NO_ML}, {}, []),
    ({"candidate": "session:S1", "kind": "session", "rules": ["scan_alerts"], "ml": NO_ML}, {},
     ["ml_agreement", "critical_asset"]),
    ({"candidate": "session:S1", "kind": "session", "ml": NO_ML}, {},
     ["rule_in_scan_alerts_or_flood_alerts", "ml_agreement", "critical_asset"]),
])
def test_urgent_preconditions(spec, env, missing):
    ok, lacking = urgent_preconditions(_profile(env, **spec))
    assert lacking == missing
    assert ok is (not missing)


# ---- branch order -----------------------------------------------------------

def test_suspicious_input_wins_over_every_other_branch():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES, category="Network Infrastructure")
    verdict = decide_rule_based(profile=profile, research=_research(profile), sanitized=SUSPICIOUS,
                                intake=CONTRADICTION, catalogue=CATALOGUE)
    assert (verdict["action"], verdict["reason"], verdict["priority"]) == ("human_review", "suspicious_input", 60)


def test_catalogue_match_wins_over_a_contradiction_and_over_the_rules():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES, category="Network Infrastructure")
    verdict = decide_rule_based(profile=profile, research=_research(profile), intake=CONTRADICTION,
                                catalogue=CATALOGUE)
    assert (verdict["action"], verdict["source"], verdict["priority"]) == ("known_pattern", "catalog_match", 0)


def test_contradiction_wins_over_the_rules():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES, category="Network Infrastructure")
    verdict = decide_rule_based(profile=profile, research=_research(profile), intake=CONTRADICTION)
    assert (verdict["action"], verdict["reason"]) == ("human_review", "intake_contradiction")


def test_missing_profile_goes_to_a_human():
    verdict = decide_rule_based(profile=None)
    assert (verdict["action"], verdict["reason"]) == ("human_review", "no_profile")


def test_no_source_for_the_technique_wins_over_a_fired_rule():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    verdict = decide_rule_based(profile=profile, research={"coverage": "no_match"})
    assert (verdict["action"], verdict["reason"]) == ("human_review", "coverage_no_match")


def test_rules_win_over_advanced_engines():
    profile = _profile(rules=["amp_alerts"], advanced={"beaconing": 0.9}, fusion=0.9, ml=ML_AGREES,
                       adv_rows=[{"signal": "beaconing", "score": 0.9, "technique": "T1071.001"}])
    verdict = decide_rule_based(profile=profile, research=_research(profile))
    assert (verdict["action"], verdict["reason"], verdict["priority"]) == ("standard", "rule_fired_with_ml", 70)


def test_advanced_engines_win_over_a_strong_ml_outlier():
    profile = _profile(advanced={"dga": 0.9}, fusion=0.9, ml={"anomaly": True, "iso_score": -0.4, "cluster": -1},
                       adv_rows=[{"signal": "dga", "score": 0.9, "technique": "T1568.002"}])
    verdict = decide_rule_based(profile=profile, research=_research(profile))
    assert (verdict["action"], verdict["reason"]) == ("standard", "advanced_with_ml")


def test_every_verdict_names_its_reason_first_and_uses_a_priority_of_the_policy():
    priorities = set(policy.get("priority").values())
    for spec in ({}, {"rules": ["scan_alerts"]}, {"ml": ML_AGREES}, {"ml": {"cluster": -1}}, {"fusion": 0.9},
                 {"advanced": {"dga": 0.9}}, {"ml": {"anomaly": True, "iso_score": -0.5}}):
        profile = _profile(**spec)
        verdict = decide_rule_based(profile=profile, research=_research(profile))
        assert verdict["rationale"].startswith(verdict["reason"] + ": ")
        assert verdict["priority"] in priorities
        assert len(verdict["rationale"]) <= 500


# ---- floors -----------------------------------------------------------------

def _floors(model: dict, profile: dict, research: dict | None = None, **kwargs) -> dict:
    research = research if research is not None else _research(profile, "sufficient_coverage")
    tree = decide_rule_based(profile=profile, research=research, **kwargs)
    return apply_floors(model, tree_verdict=tree, profile=profile, research=research, **kwargs)


def test_floor_suspicious_input():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    final = _floors(_model("standard"), profile, sanitized=SUSPICIOUS)
    assert (final["action"], final["floor_reason"], final["priority"]) == ("human_review", "suspicious_input", 60)
    assert final["overridden_llm_verdict"] == {"action": "standard", "priority": 40}
    assert final["source"] == "rule_based"


def test_floor_intake_contradiction():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    final = _floors(_model("monitor"), profile, intake=CONTRADICTION)
    assert (final["action"], final["floor_reason"]) == ("human_review", "intake_contradiction")


def test_floor_nothing_to_triage():
    profile = _profile()
    final = _floors(_model("monitor"), profile)
    assert (final["action"], final["floor_reason"], final["priority"]) == ("human_review", "nothing_to_triage", 30)


def test_floor_known_pattern_without_a_catalogue_match():
    profile = _profile(ml={"cluster": -1})
    final = _floors(_model("known_pattern", 0), profile)
    assert (final["action"], final["floor_reason"]) == ("human_review", "known_pattern_without_catalogue_match")


def test_known_pattern_stands_on_a_catalogue_match():
    profile = _profile(ml={"cluster": -1})
    final = _floors(_model("known_pattern", 0), profile, catalogue=CATALOGUE)
    assert (final["action"], final["floor_applied"]) == ("known_pattern", False)


def test_floor_urgent_preconditions_not_met():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    final = _floors(_model("urgent", 95), profile)
    assert (final["action"], final["floor_reason"]) == ("human_review", "urgent_preconditions_not_met")
    assert final["floor_trigger"] == "critical_asset"


def test_urgent_stands_when_the_preconditions_hold():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES, category="Network Infrastructure")
    final = _floors(_model("urgent", 95), profile)
    assert (final["action"], final["floor_applied"], final["source"]) == ("urgent", False, "llm_react")


def test_floor_coverage_no_match():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    final = _floors(_model("standard"), profile, research={"coverage": "no_match"})
    assert (final["action"], final["floor_reason"]) == ("human_review", "coverage_no_match")


def test_floor_insufficient_coverage_stops_a_model_standard():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    # The floor only fires on explicit `insufficient_coverage`; `stand_in_backend` (the default until
    # the real corpus is wired in phase P3) is exempt by design.
    final = _floors(_model("standard"), profile, research=_research(profile, "insufficient_coverage"))
    assert (final["action"], final["floor_reason"]) == ("human_review", "rag_insufficient_coverage")
    assert final["floor_trigger"] == ""


def test_insufficient_coverage_is_exempt_only_on_a_catalogue_match():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    final = _floors(_model("standard"), profile,
                    research=_research(profile, "insufficient_coverage"), catalogue=CATALOGUE)
    assert (final["action"], final["floor_applied"]) == ("standard", False)


def test_the_stand_in_backend_does_not_fire_the_floor():
    """Until the real corpus is wired, the research step's sufficiency is `stand_in_backend` and the floor
    does not fire; a model standard verdict on a fired rule stays standard."""
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    # The default research returns the stand-in backend.
    final = _floors(_model("standard"), profile, research=_research(profile))
    assert (final["action"], final["floor_applied"]) == ("standard", False)


def test_floor_rule_fired_lifts_a_model_monitor_to_the_tree_verdict():
    profile = _profile(rules=["arp_multi_mac"])
    final = _floors(_model("monitor", 5), profile)
    assert (final["action"], final["floor_reason"], final["priority"]) == ("standard", "rule_fired", 60)
    assert final["floor_trigger"] == "arp_multi_mac"


def test_floor_rule_fired_lifts_to_urgent_when_the_tree_says_urgent():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES, category="Network Infrastructure")
    final = _floors(_model("monitor", 5), profile)
    assert (final["action"], final["floor_reason"], final["priority"]) == ("urgent", "rule_fired", 90)


def test_an_aggregate_flood_is_urgent_and_a_model_cannot_lower_it_to_monitor():
    profile = _profile(candidate="session:S1", kind="session", rules=["flood_alerts"], ml=NO_ML)
    tree = decide_rule_based(profile=profile, research=_research(profile))
    assert (tree["action"], tree["priority"], tree["reason"]) == ("urgent", 90, "urgent_session_scope_rule")
    assert "session-level candidate" in tree["rationale"] and "IsolationForest agrees" not in tree["rationale"]
    assert (profile["scope"], profile["severity"], profile["ml_agrees"]) == ("session", "severe", False)
    lifted = _floors(_model("monitor", 5), profile)
    assert (lifted["action"], lifted["floor_reason"], lifted["priority"]) == ("urgent", "rule_fired", 90)
    kept = _floors(_model("urgent", 95), profile)
    assert (kept["action"], kept["floor_applied"]) == ("urgent", False)


def test_a_model_verdict_with_no_trigger_stands():
    profile = _profile(rules=["scan_alerts"], ml=ML_AGREES)
    final = _floors(_model("standard", 65), profile)
    assert (final["action"], final["priority"], final["floor_applied"], final["source"]) == \
        ("standard", 65, False, "llm_react")


@pytest.mark.parametrize("spec, kwargs", [
    ({"rules": ["scan_alerts"], "ml": ML_AGREES}, {}),
    ({"rules": ["scan_alerts"], "ml": ML_AGREES}, {"sanitized": SUSPICIOUS}),
    ({}, {}),
    ({"advanced": {"dga": 0.9}, "fusion": 0.9, "ml": ML_AGREES}, {"intake": CONTRADICTION}),
])
def test_a_model_human_review_is_never_moved(spec, kwargs):
    final = _floors(_model("human_review", 55), _profile(**spec), **kwargs)
    assert (final["action"], final["floor_applied"]) == ("human_review", False)


def test_the_floors_of_the_policy_are_the_floors_of_the_code():
    assert policy.get("floors") == [
        "suspicious_input", "intake_contradiction", "nothing_to_triage", "known_pattern_without_catalogue_match",
        "urgent_preconditions_not_met", "coverage_no_match", "rag_insufficient_coverage", "rule_fired",
    ]
