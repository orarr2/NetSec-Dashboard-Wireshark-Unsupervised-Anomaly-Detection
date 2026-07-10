"""Unit tests for the optional llm_judge package.

Everything runs against a fake in-process client: no network, no API key,
no anthropic package, no tshark. The upstream S-dict/findings contract is
reproduced with a small synthetic session.
"""
import collections
import json
import os
import sys
from datetime import datetime, timedelta

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import judge_config, judge_core  # noqa: E402


# --------------------------------------------------------------------------
# Fixtures: a synthetic session shaped like run_pipeline.analyze_pcap output.
# --------------------------------------------------------------------------
def make_session(n_benign=2):
    ips = ["192.168.1.10"] + [f"10.0.0.{i}" for i in range(5, 5 + n_benign)]
    ip_agg = pd.DataFrame({
        "count": [1007] + [40] * n_benign,
        "total_bytes": [60420] + [21000] * n_benign,
        "mean_len": [60.0] + [525.0] * n_benign,
        "std_len": [0.0] + [310.0] * n_benign,
        "unique_dsts": [1000] + [3] * n_benign,
        "burst_score": [1007.0] + [0.13] * n_benign,
        "dominance": [1067.4] + [61.0] * n_benign,
        "syn_count": [1002] + [5] * n_benign,
        "rst_count": [0] + [1] * n_benign,
        "fin_count": [0] * (1 + n_benign),
        "null_count": [0] * (1 + n_benign),
        "xmas_count": [0] * (1 + n_benign),
        "iso_score": [-0.31] + [0.12] * n_benign,
        "iso_flag": [-1] + [1] * n_benign,
        "iso_stability": [1.0] + [0.0] * n_benign,
        "anomaly": [True] + [False] * n_benign,
        "cluster": [-1] + [0] * n_benign,
    }, index=ips)
    t0 = datetime(2026, 7, 10, 12, 0, 0)
    return {
        "label": "T1", "n_pkts": 2020, "t0": t0,
        "t1": t0 + timedelta(seconds=71.2),
        "ip_agg": ip_agg,
        "ips_src": collections.Counter({ip: 100 for ip in ips}),
    }


def make_findings(**over):
    base = {
        "scan_alerts": [{"src": "192.168.1.10", "type": "SYN", "count": 1002,
                         "unique_dsts": 1000, "ratio": 1.0}],
        "flood_alerts": [],
        "amp_alerts": [],
        "arp_spoofing_ips": {},
        "arp_spoofing_macs": {},
        "dns_nxdomain": 0,
        "dns_long_queries": [],
    }
    base.update(over)
    return base


def good_verdict(**over):
    v = {"verdict": "malicious", "category": "port_scan", "confidence": 0.95,
         "evidence_features": ["syn_count", "unique_dsts"],
         "reasoning": "SYN ratio 1.0 across 1000 destinations.",
         "recommended_action": "investigate"}
    v.update(over)
    return v


class FakeClient:
    """Scripted or heuristic in-process stand-in for an LLM provider."""
    model_id = "fake-model-v1"

    def __init__(self, responses=None):
        self.calls = 0
        self._responses = list(responses) if responses is not None else None

    def judge(self, system_prompt, user_content):
        self.calls += 1
        if self._responses is not None:
            item = self._responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        ctx = json.loads(user_content)
        if ctx["rule_signals"]["scan_alerts"]:
            return json.dumps(good_verdict())
        if ctx["rule_signals"]["flood_alerts"]:
            return json.dumps(good_verdict(category="syn_flood"))
        return json.dumps(good_verdict(
            verdict="benign", category="benign_anomaly", confidence=0.4,
            recommended_action="monitor",
            reasoning="Statistical outlier without an attack pattern."))


# --------------------------------------------------------------------------
# assemble_candidates
# --------------------------------------------------------------------------
def test_assemble_unions_ml_and_rule_triggers():
    out = judge_core.assemble_candidates(make_session(), make_findings())
    ids = {c["candidate_id"] for c in out["candidates"]}
    assert "192.168.1.10" in ids
    attacker = next(c for c in out["candidates"]
                    if c["candidate_id"] == "192.168.1.10")
    assert set(attacker["trigger_reasons"]) >= {"isolation_forest",
                                                "scan_rule"}
    assert attacker["rule_signals"]["scan_alerts"][0]["type"] == "SYN"
    assert attacker["ml_signals"]["anomaly"] is True
    assert attacker["features"]["syn_count"] == 1002
    assert attacker["enrichments"]["is_private"] is True
    # blob must be JSON-serializable (no numpy scalars)
    json.dumps(out["candidates"])


def test_assemble_cap_keeps_rule_triggered_first():
    S = make_session(n_benign=6)
    # every benign IP except one becomes a DBSCAN-noise candidate; keeping
    # one clustered IP keeps DBSCAN "meaningful" so noise still counts
    S["ip_agg"].loc[S["ip_agg"].index != "192.168.1.10", "cluster"] = -1
    S["ip_agg"].loc["10.0.0.5", "cluster"] = 0
    out = judge_core.assemble_candidates(S, make_findings(), max_candidates=1)
    kept = [c["candidate_id"] for c in out["candidates"] if c["kind"] == "ip"]
    assert kept == ["192.168.1.10"]      # the rule-triggered one survives
    assert len(out["capped"]) == 5       # the noise-only IPs get capped out
    assert "192.168.1.10" not in out["capped"]


def test_assemble_flood_adds_session_candidate_and_skips_noise():
    flood = [{"type": "SYN_FLOOD", "total_syn": 37623, "syn_sources": 37000,
              "syn_per_sec": 5000.0, "syn_per_source": 1.02,
              "spoofed_source_pattern": True}]
    S = make_session()
    S["ip_agg"]["cluster"] = -1  # DBSCAN degenerate: all noise
    out = judge_core.assemble_candidates(S, make_findings(flood_alerts=flood))
    sess = [c for c in out["candidates"] if c["kind"] == "session"]
    assert len(sess) == 1
    assert sess[0]["candidate_id"] == "session:T1"
    assert sess[0]["features"]["spoofed_source_pattern"] is True
    assert sess[0]["rule_signals"]["flood_alerts"] == flood
    # all-noise DBSCAN must not flood the queue with per-IP candidates
    noise_only = [c for c in out["candidates"]
                  if c["kind"] == "ip"
                  and c["trigger_reasons"] == ["dbscan_noise"]]
    assert noise_only == []


def test_assemble_arp_candidate_outside_ip_agg():
    findings = make_findings(
        scan_alerts=[],
        arp_spoofing_ips={"192.168.1.1": {"aa:aa", "bb:bb"}})
    out = judge_core.assemble_candidates(make_session(), findings)
    victim = next(c for c in out["candidates"]
                  if c["candidate_id"] == "192.168.1.1")
    assert victim["rule_signals"]["arp_multi_mac"] is True
    assert victim["features"]["count"] == 0.0  # no IP-layer rows for it
    json.dumps(victim)


# --------------------------------------------------------------------------
# validate_verdict
# --------------------------------------------------------------------------
def test_validate_verdict_normalizes():
    v = judge_core.validate_verdict(good_verdict(
        reasoning="line one\nline two  spaced", confidence=0.951234))
    assert "\n" not in v["reasoning"]
    assert v["confidence"] == 0.951


@pytest.mark.parametrize("mutation", [
    {"verdict": "evil"},
    {"category": "ransomware"},
    {"recommended_action": "nuke"},
    {"confidence": 1.5},
    {"confidence": "high"},
    {"evidence_features": "syn_count"},
    {"reasoning": ""},
])
def test_validate_verdict_rejects(mutation):
    with pytest.raises(judge_core.JudgeValidationError):
        judge_core.validate_verdict(good_verdict(**mutation))


def test_validate_verdict_rejects_missing_field():
    v = good_verdict()
    del v["category"]
    with pytest.raises(judge_core.JudgeValidationError):
        judge_core.validate_verdict(v)


# --------------------------------------------------------------------------
# fingerprint + cache
# --------------------------------------------------------------------------
def test_fingerprint_sensitivity():
    ctx = {"candidate_id": "1.2.3.4", "kind": "ip"}
    a = judge_core.fingerprint(ctx, "v0.1.0", "m1")
    assert a == judge_core.fingerprint(dict(ctx), "v0.1.0", "m1")
    assert a != judge_core.fingerprint(ctx, "v0.2.0", "m1")   # prompt bump
    assert a != judge_core.fingerprint(ctx, "v0.1.0", "m2")   # model swap


def test_cache_roundtrip(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cache = judge_core.JudgeCache(db)
    assert cache.get("fp1") is None
    cache.put("fp1", "v0.1.0", good_verdict(), "m1", 123)
    assert cache.get("fp1")["category"] == "port_scan"
    assert cache.stats()["entries"] == 1
    cache.close()


# --------------------------------------------------------------------------
# judge_candidates loop
# --------------------------------------------------------------------------
def _candidates():
    S = make_session()
    # one benign IP becomes DBSCAN noise so the batch has a second,
    # statistical-only candidate to rank against the attacker
    S["ip_agg"].loc["10.0.0.6", "cluster"] = -1
    return judge_core.assemble_candidates(S, make_findings())["candidates"]


def test_judge_ranks_attacker_first_and_caches(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cands = _candidates()
    client = FakeClient()
    out = judge_core.judge_candidates(cands, client=client, cache_db=db,
                                      verbose=False)
    assert out["stats"]["dropped"] == 0
    assert out["results"][0]["candidate_id"] == "192.168.1.10"
    assert out["results"][0]["verdict"]["category"] == "port_scan"
    assert out["results"][0]["priority"] > out["results"][-1]["priority"]
    first_calls = client.calls
    # second run: all verdicts must come from the cache
    out2 = judge_core.judge_candidates(cands, client=client, cache_db=db,
                                       verbose=False)
    assert client.calls == first_calls
    assert out2["stats"]["cache_hits"] == len(cands)


def test_judge_retries_once_then_drops(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cands = _candidates()[:1]
    # two bad responses -> dropped, nothing cached
    client = FakeClient(responses=["not json at all", "{\"still\": \"bad\"}"])
    out = judge_core.judge_candidates(cands, client=client, cache_db=db,
                                      verbose=False)
    assert out["results"] == []
    assert out["dropped"][0]["candidate_id"] == cands[0]["candidate_id"]
    assert client.calls == 2
    # bad then good -> kept after the retry
    client2 = FakeClient(responses=["garbage", json.dumps(good_verdict())])
    out2 = judge_core.judge_candidates(cands, client=client2, cache_db=db,
                                       verbose=False)
    assert client2.calls == 2
    assert out2["results"][0]["verdict"]["category"] == "port_scan"


def test_judge_disabled_flag_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", False)
    client = FakeClient()
    out = judge_core.judge_candidates(_candidates(), client=client,
                                      cache_db=str(tmp_path / "c.sqlite"),
                                      verbose=False)
    assert out["results"] == [] and out["stats"]["disabled"] is True
    assert client.calls == 0


# --------------------------------------------------------------------------
# calibration alignment (no pipeline run - synthetic results)
# --------------------------------------------------------------------------
def test_align_to_truth_scan_pcap():
    from llm_judge import calibration
    gt_entry = {"attack": "tcp_syn_scan",
                "attacker_ips": ["192.168.1.10"],
                "expect": {"aggregate_flood": False}}
    results = [
        {"candidate_id": "192.168.1.10", "kind": "ip",
         "verdict": good_verdict()},
        {"candidate_id": "10.0.0.5", "kind": "ip",
         "verdict": good_verdict(verdict="benign", category="benign_anomaly",
                                 confidence=0.3)},
    ]
    y_tc, y_pc, y_tv, y_pv = calibration.align_to_truth(results, gt_entry)
    assert y_tc == ["port_scan", "benign_anomaly"]
    assert y_pc == ["port_scan", "benign_anomaly"]
    assert y_tv == ["malicious", "benign"]
    assert calibration._safe_kappa(y_tc, y_pc,
                                   calibration.KAPPA_LABELS) == 1.0


def test_align_to_truth_flood_pcap_scores_session_only():
    from llm_judge import calibration
    gt_entry = {"attack": "spoofed_syn_flood", "attacker_ips": [],
                "expect": {"aggregate_flood": True}}
    results = [
        {"candidate_id": "1.2.3.4", "kind": "ip",
         "verdict": good_verdict(category="syn_flood")},
        {"candidate_id": "session:S1", "kind": "session",
         "verdict": good_verdict(category="syn_flood")},
    ]
    y_tc, y_pc, _, _ = calibration.align_to_truth(results, gt_entry)
    assert y_tc == ["syn_flood"] and y_pc == ["syn_flood"]
