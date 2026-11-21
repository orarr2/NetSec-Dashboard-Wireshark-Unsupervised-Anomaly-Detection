"""JSON repair, fact check against the engines and the sources, and the deterministic rationale fallback."""

from __future__ import annotations

import pytest

from agent import factcheck

TREE = {"action": "standard", "priority": 60, "reason": "rule_fired", "rationale": "placeholder"}
PROFILE = {"engines_fired": {"rules": ["scan_alerts"], "ml": ["isolation_forest"], "advanced": []},
           "primary_technique": "T1046", "other_techniques": [], "severity": "high", "confidence": "high"}
RESEARCH = {"tool_result_ids": ["attack:T1046", "attack:T1557"], "catalogue": {"match": False}}
SANITIZED = {"note": {"has_text": False}, "suspicious": False}
VALID = {"action": "standard", "priority": 70, "rationale": "scan_alerts fired on this candidate", "cited_sources": ["attack:T1046"]}


# ---- JSON repair ------------------------------------------------------------

def test_a_plain_object_parses():
    assert factcheck.repair_json('{"action": "monitor", "priority": 5}') == {"action": "monitor", "priority": 5}


@pytest.mark.parametrize("payload", [
    '```json\n{"action": "monitor"}\n```',
    '```\n{"action": "monitor"}\n```',
    'Here is the verdict:\n```json\n{"action": "monitor"}\n```\nI hope this helps.',
])
def test_markdown_fences_are_stripped(payload):
    assert factcheck.repair_json(payload) == {"action": "monitor"}


def test_prose_on_either_side_of_the_object_is_stripped():
    assert factcheck.repair_json('The verdict is: {"action": "urgent"} - routing now.') == {"action": "urgent"}


def test_a_trailing_comma_is_tolerated():
    assert factcheck.repair_json('{"a": 1, "b": [1, 2,],}') == {"a": 1, "b": [1, 2]}


@pytest.mark.parametrize("payload", ["", "   ", None, "no object here"])
def test_a_reply_without_an_object_raises(payload):
    with pytest.raises((ValueError, TypeError)):
        factcheck.repair_json(payload)


def test_a_json_array_at_the_top_level_is_refused():
    with pytest.raises(ValueError, match="not a JSON object"):
        factcheck.repair_json('[1, 2, 3]')


# ---- fact check -------------------------------------------------------------

def test_a_well_formed_verdict_passes():
    ok, reasons = factcheck.verify(VALID, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert (ok, reasons) == (True, [])


@pytest.mark.parametrize("change, expected", [
    ({"action": "invented"}, "unknown_action"),
    ({"priority": 11}, "priority_outside_policy"),
    ({"priority": "high"}, "priority_outside_policy"),
    ({"rationale": ""}, "empty_rationale"),
    ({"rationale": "x" * 501}, "rationale_too_long"),
    ({"cited_sources": ["attack:T1046", "attack:invented"]}, "ungrounded_citation"),
    ({"cited_sources": []}, "no_citation_for_standard"),
])
def test_each_failure_is_reported(change, expected):
    verdict = dict(VALID, **change)
    ok, reasons = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert ok is False
    assert any(r.startswith(expected) for r in reasons), reasons


def test_a_claim_about_the_analyst_note_without_a_note_is_caught():
    verdict = dict(VALID, rationale="The analyst reported a scan on this host")
    ok, reasons = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert not ok and "rationale_claims_analyst_note_without_one" in reasons


def test_the_same_rationale_passes_when_there_is_a_note():
    verdict = dict(VALID, rationale="The analyst reported a scan on this host")
    sanitized = {"note": {"has_text": True, "text": "scan"}, "suspicious": False}
    ok, reasons = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=sanitized)
    assert ok is True


def test_a_claim_about_a_catalogue_match_without_one_is_caught():
    verdict = dict(VALID, rationale="This is a known pattern from the catalogue")
    ok, reasons = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert not ok and "rationale_claims_catalogue_without_one" in reasons


def test_a_known_pattern_action_may_speak_of_the_catalogue():
    verdict = dict(VALID, action="known_pattern", priority=0,
                   rationale="A known pattern of catalogued scans", cited_sources=[])
    ok, reasons = factcheck.verify(verdict, case={},
                                   profile=PROFILE, research={**RESEARCH, "catalogue": {"match": True}},
                                   sanitized=SANITIZED)
    assert ok, reasons


def test_an_invented_technique_in_the_rationale_is_caught():
    verdict = dict(VALID, rationale="scan_alerts fired, matching T9999.001 behaviour")
    ok, reasons = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert not ok and any(r.startswith("invented_technique: T9999") for r in reasons)


def test_the_parent_of_the_engine_technique_is_accepted():
    verdict = dict(VALID, rationale="T1046 covers port scans; this fits the T1046.001 pattern")
    ok, _ = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert ok


@pytest.mark.parametrize("action", ["human_review", "monitor", "known_pattern"])
def test_actions_that_may_cite_nothing(action):
    verdict = dict(VALID, action=action, priority=5 if action == "monitor" else 0 if action == "known_pattern" else 55,
                   cited_sources=[])
    ok, reasons = factcheck.verify(verdict, case={}, profile=PROFILE, research=RESEARCH, sanitized=SANITIZED)
    assert ok, reasons


# ---- deterministic rationale ------------------------------------------------

def test_deterministic_rationale_names_the_engines_and_the_technique():
    text = factcheck.deterministic_rationale(TREE, PROFILE)
    assert text.startswith("standard: rule_fired. engines rules=scan_alerts")
    assert "technique=T1046" in text and "severity=high" in text and "confidence=high" in text
    assert "fact check" in text and len(text) <= 500
