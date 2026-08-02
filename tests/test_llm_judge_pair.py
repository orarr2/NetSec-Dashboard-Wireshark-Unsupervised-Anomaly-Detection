"""Unit tests for judge_session_pair (dual-session S1 vs S2 comparison).

The pair-level judge builds a summary blob out of two per-session
verdict outputs and sends it as ONE prompt to every panel client.
These tests don't hit any network - they use scripted stub clients
and assert on the shape of the blob, the resolver logic, and the
graceful-degradation path when every judge fails.
"""
import json

import pytest

from llm_judge import judge_core as jc


# --------------------------------------------------------------------------
# build_pair_blob
# --------------------------------------------------------------------------
def _res(ip, verdict, category="benign_anomaly", confidence=0.7):
    return {"candidate_id": ip, "kind": "ip",
            "verdict": {"verdict": verdict, "category": category,
                        "confidence": confidence}}


def test_pair_blob_counts_and_flips():
    s1 = {"results": [_res("1.1.1.1", "benign"),
                      _res("2.2.2.2", "suspicious"),
                      _res("3.3.3.3", "malicious", "port_scan", 0.9),
                      _res("4.4.4.4", "benign")]}
    s2 = {"results": [_res("1.1.1.1", "malicious", "port_scan", 0.85),
                      _res("2.2.2.2", "benign"),
                      _res("5.5.5.5", "suspicious")]}
    blob = jc.build_pair_blob(s1, s2)
    assert blob["counts"] == {
        "s1": {"malicious": 1, "suspicious": 1, "benign": 2},
        "s2": {"malicious": 1, "suspicious": 1, "benign": 1}}
    assert blob["totals"] == {"s1": 4, "s2": 3}
    assert blob["unique_ips_s1_only"] == ["3.3.3.3", "4.4.4.4"]
    assert blob["unique_ips_s2_only"] == ["5.5.5.5"]
    # both 1.1.1.1 (benign->malicious) and 2.2.2.2 (suspicious->benign)
    # are real verdict flips
    flip_ips = {f["ip"] for f in blob["verdict_flips"]}
    assert flip_ips == {"1.1.1.1", "2.2.2.2"}
    assert blob["flip_count_total"] == 2


def test_pair_blob_handles_empty_inputs():
    blob = jc.build_pair_blob({}, {"results": []})
    assert blob["totals"] == {"s1": 0, "s2": 0}
    assert blob["verdict_flips"] == []
    assert blob["counts"] == {
        "s1": {"malicious": 0, "suspicious": 0, "benign": 0},
        "s2": {"malicious": 0, "suspicious": 0, "benign": 0}}


def test_top_non_benign_ranked_by_confidence():
    s1 = {"results": [_res("a", "malicious", "port_scan", 0.9),
                      _res("b", "suspicious", "benign_anomaly", 0.5),
                      _res("c", "malicious", "port_scan", 0.7),
                      _res("d", "benign")]}
    top = jc.build_pair_blob(s1, {})["top_non_benign_s1"]
    assert [t["ip"] for t in top] == ["a", "c", "b"]  # sorted by conf desc


# --------------------------------------------------------------------------
# build_pair_blob v2: capture metadata, category flow, annotated uniques
# --------------------------------------------------------------------------
def _ctx(start, n_packets=1000, file="a.pcap"):
    return {"time_range": [start, start], "duration_s": 60.0,
            "n_packets": n_packets, "total_ips": 10,
            "local_ips_count": 6, "external_ips_count": 4,
            "top_protocols": {"TCP": 800, "DNS": 100},
            "original_filename": file, "sensor_name": "lab",
            "not_flagged_ips": [{"ip": "9.9.9.9"}]}


def test_pair_blob_carries_capture_metadata_and_gap():
    s1 = {"results": [_res("1.1.1.1", "benign")],
          "context": _ctx("2026-08-01 10:00:00")}
    s2 = {"results": [_res("1.1.1.1", "benign")],
          "context": _ctx("2026-08-01 12:30:00", file="b.pcap")}
    blob = jc.build_pair_blob(s1, s2)
    cap = blob["capture"]
    assert cap["s1"]["file"] == "a.pcap"
    assert cap["s2"]["file"] == "b.pcap"
    assert cap["s1"]["n_packets"] == 1000
    assert cap["s1"]["cleared_ips"] == 1
    assert cap["s1"]["top_protocols"] == ["TCP", "DNS"]
    assert cap["gap_seconds"] == 2.5 * 3600


def test_pair_blob_no_capture_key_for_legacy_outputs():
    """verdicts.json written before report v2 has no 'context' - the
    blob must not invent one (renderers show '-' off its absence)."""
    blob = jc.build_pair_blob({"results": []}, {"results": []})
    assert "capture" not in blob


def test_pair_blob_category_flow_and_annotated_uniques():
    s1 = {"results": [_res("1.1.1.1", "suspicious"),
                      _res("2.2.2.2", "suspicious"),
                      _res("3.3.3.3", "benign"),
                      _res("6.6.6.6", "benign")]}
    ev = {"device": {"hostname": "cam-1", "vendor": "Hikvision",
                     "category": "camera"}}
    new_bad = dict(_res("5.5.5.5", "malicious", "port_scan", 0.9),
                   evidence=ev)
    s2 = {"results": [_res("1.1.1.1", "benign"),
                      _res("2.2.2.2", "malicious", "port_scan", 0.93),
                      _res("3.3.3.3", "benign"),
                      new_bad]}
    blob = jc.build_pair_blob(s1, s2)
    assert blob["category_flow"] == {"suspicious -> benign": 1,
                                     "suspicious -> malicious": 1}
    assert blob["unchanged_verdicts"] == 1          # 3.3.3.3
    # Annotated uniques carry verdict + device, non-benign sorted first.
    detail = blob["unique_s2_detail"]
    assert detail[0]["ip"] == "5.5.5.5"
    assert detail[0]["verdict"] == "malicious"
    assert detail[0]["device"] == "Hikvision cam-1"
    # ...and surface in the dedicated new_non_benign_s2 list.
    assert [r["ip"] for r in blob["new_non_benign_s2"]] == ["5.5.5.5"]
    # Flips carry the S2-side device when evidence exists.
    flip_242 = [f for f in blob["verdict_flips"] if f["ip"] == "2.2.2.2"]
    assert flip_242 and flip_242[0]["device"] is None  # no evidence given


def test_validate_caps_cut_at_word_boundary():
    """The 500-char cap must never shear a word in half - job 2 shipped
    a report ending 'Overall posture esc'."""
    words = ("alpha bravo charlie delta " * 40).strip()   # > 500 chars
    out = jc.validate_pair_verdict(dict(GOOD, reasoning=words))
    assert len(out["reasoning"]) <= 500
    assert out["reasoning"].endswith(" ...")
    tail = out["reasoning"][:-4].split()[-1]
    assert tail in ("alpha", "bravo", "charlie", "delta")  # whole word


# --------------------------------------------------------------------------
# validate_pair_verdict
# --------------------------------------------------------------------------
GOOD = {"posture_delta": "escalated", "confidence": 0.8,
        "headline": "Two new port scans in S2.",
        "reasoning": "counts.s2.malicious rose from 0 to 2.",
        "notable_flips": [{"ip": "1.2.3.4", "from": "benign",
                           "to": "malicious",
                           "why": "SYN scan rule fired in S2"}],
        "recommended_action": "investigate"}


def test_validate_pair_verdict_happy_path():
    out = jc.validate_pair_verdict(dict(GOOD))
    assert out["posture_delta"] == "escalated"
    assert out["confidence"] == 0.8
    assert out["notable_flips"][0]["ip"] == "1.2.3.4"


def test_validate_rejects_bad_posture():
    bad = dict(GOOD, posture_delta="scary")
    with pytest.raises(jc.JudgeValidationError):
        jc.validate_pair_verdict(bad)


def test_validate_rejects_out_of_range_confidence():
    with pytest.raises(jc.JudgeValidationError):
        jc.validate_pair_verdict(dict(GOOD, confidence=1.5))


def test_validate_folds_newlines_and_caps_length():
    long = "a" * 800
    out = jc.validate_pair_verdict(
        dict(GOOD, headline="one\ntwo\nthree", reasoning=long))
    assert "\n" not in out["headline"]
    assert out["headline"] == "one two three"
    assert len(out["reasoning"]) <= 500


def test_validate_drops_malformed_flips():
    out = jc.validate_pair_verdict(dict(
        GOOD,
        notable_flips=[{"ip": "1.1.1.1", "from": "benign", "to": "malicious"},
                       {"ip": "no from-to"},
                       "not a dict",
                       {"ip": "2.2.2.2", "from": "benign", "to": "suspicious",
                        "why": "iso_score dropped"}]))
    assert [f["ip"] for f in out["notable_flips"]] == ["1.1.1.1", "2.2.2.2"]


# --------------------------------------------------------------------------
# judge_session_pair + resolver
# --------------------------------------------------------------------------
class _StubClient:
    def __init__(self, model_id, reply):
        self.model_id = model_id
        self._reply = reply

    def judge(self, system_prompt, user_content, schema=None):
        if isinstance(self._reply, Exception):
            raise self._reply
        return json.dumps(self._reply)


def test_pair_judge_majority_wins():
    a = _StubClient("a", dict(GOOD, posture_delta="escalated",
                              confidence=0.9))
    b = _StubClient("b", dict(GOOD, posture_delta="escalated",
                              confidence=0.6))
    c = _StubClient("c", dict(GOOD, posture_delta="stable",
                              confidence=0.9, headline="Nothing changed."))
    out = jc.judge_session_pair({"results": []}, {"results": []},
                                [a, b, c])
    assert out["verdict"]["posture_delta"] == "escalated"
    assert out["verdict"]["panel_agreement"]["picked"] == "escalated"
    assert out["models_answered"] == ["a", "b", "c"]
    # majority-winner text taken from HIGHEST-confidence answer inside
    # the winning group - a's headline, not b's
    assert out["verdict"]["headline"] == "Two new port scans in S2."


def test_pair_judge_tie_picks_more_severe():
    a = _StubClient("a", dict(GOOD, posture_delta="stable",
                              confidence=0.9,
                              headline="Nothing changed."))
    b = _StubClient("b", dict(GOOD, posture_delta="escalated",
                              confidence=0.6))
    out = jc.judge_session_pair({"results": []}, {"results": []}, [a, b])
    assert out["verdict"]["posture_delta"] == "escalated"


def test_pair_judge_all_failed_returns_degraded_verdict():
    a = _StubClient("a", RuntimeError("quota exhausted"))
    b = _StubClient("b", RuntimeError("JSON validate failed"))
    out = jc.judge_session_pair({"results": []}, {"results": []}, [a, b])
    assert out["verdict"]["posture_delta"] == "mixed"
    assert out["verdict"]["confidence"] == 0.0
    assert "every panel judge failed" in out["verdict"]["headline"].lower()
    assert out["models_answered"] == []
    assert out["panel_report"]["a"]["answered"] is False
    assert "quota exhausted" in out["panel_report"]["a"]["error"]


def test_pair_judge_survives_partial_failure():
    a = _StubClient("a", RuntimeError("timeout"))
    b = _StubClient("b", dict(GOOD, posture_delta="de-escalated",
                              confidence=0.7))
    out = jc.judge_session_pair({"results": []}, {"results": []}, [a, b])
    assert out["verdict"]["posture_delta"] == "de-escalated"
    assert out["panel_report"]["a"]["answered"] is False
    assert out["panel_report"]["b"]["answered"] is True
    assert out["models_answered"] == ["b"]


def test_pair_judge_records_prompt_version():
    a = _StubClient("a", dict(GOOD))
    b = _StubClient("b", dict(GOOD))
    out = jc.judge_session_pair({"results": []}, {"results": []}, [a, b],
                                prompt_version="unit-test-1")
    assert out["prompt_version"] == "unit-test-1"
