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


def test_judge_skips_retry_on_permanent_error(tmp_path):
    """H3 fix: a JudgeClientError with permanent=True (4xx from the
    server: allam-2-7b's json_validate_failed, unknown model, bad key)
    must NOT be retried. A retry on a permanent error just burns quota
    and, on Groq's shared account limits, spawns 429s that stall a
    parallel panel. Regression: pre-fix this made 4 HTTP calls per
    broken candidate and took 30-90s per judge."""
    from llm_judge.llm_clients import JudgeClientError
    perm = JudgeClientError("model not found (400)", permanent=True)
    client = FakeClient(responses=[perm, perm])  # if retried, would raise
    out = judge_core.judge_candidates(_candidates()[:1], client=client,
                                      cache_db=str(tmp_path / "c.sqlite"),
                                      verbose=False)
    assert out["results"] == []
    assert client.calls == 1, (
        f"permanent error must not be retried; got {client.calls} calls")
    assert "model not found" in out["dropped"][0]["error"]


def test_judge_still_retries_transient_and_validation_errors(tmp_path):
    """A transient error (permanent unset or False - e.g. 429, 500,
    JudgeValidationError, bad JSON) MUST still be retried once - that
    behaviour is what covers a one-off bad JSON from the model."""
    from llm_judge.llm_clients import JudgeClientError
    transient = JudgeClientError("overloaded (503)")  # permanent=False
    client = FakeClient(responses=[transient, json.dumps(good_verdict())])
    out = judge_core.judge_candidates(_candidates()[:1], client=client,
                                      cache_db=str(tmp_path / "c.sqlite"),
                                      verbose=False)
    assert client.calls == 2, "transient error must be retried once"
    assert out["results"][0]["verdict"]["category"] == "port_scan"


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


# --------------------------------------------------------------------------
# Committee mode (opt-in): two judges vote, disputes -> needs_human_review.
# --------------------------------------------------------------------------
def _two_clients(a_resp, b_resp):
    """Two FakeClients with DISTINCT model ids so their cache fingerprints
    (which include model_id) don't collide and mask the combination logic."""
    a = FakeClient(responses=a_resp)
    a.model_id = "model-a"
    b = FakeClient(responses=b_resp)
    b.model_id = "model-b"
    return a, b


def test_combine_committee_policy():
    va = good_verdict(verdict="malicious", confidence=0.8)
    vb = good_verdict(verdict="benign", category="benign_anomaly",
                      confidence=0.9, recommended_action="monitor")
    # disagree -> more severe wins, flagged for review
    eff, info = judge_core.combine_committee(va, vb, "a", "b")
    assert eff["verdict"] == "malicious"
    assert info["needs_human_review"] is True and info["agreement"] is False
    # agree -> higher confidence wins, no review
    eff2, info2 = judge_core.combine_committee(
        good_verdict(verdict="malicious", confidence=0.6),
        good_verdict(verdict="malicious", confidence=0.91), "a", "b")
    assert eff2["confidence"] == 0.91
    assert info2["agreement"] is True and info2["needs_human_review"] is False
    # both failed -> no effective verdict, review flagged
    eff3, info3 = judge_core.combine_committee(None, None, "a", "b")
    assert eff3 is None and info3["needs_human_review"] is True


def test_committee_flags_disagreement(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cand = _candidates()[:1]  # the port_scan attacker (not benign; guardrail idle)
    a, b = _two_clients(
        [json.dumps(good_verdict(verdict="malicious", confidence=0.9))],
        [json.dumps(good_verdict(verdict="suspicious", confidence=0.7))])
    out = judge_core.judge_candidates_committee(
        cand, clients=[a, b], cache_db=db, verbose=False)
    assert out["stats"]["committee"] is True
    assert out["stats"]["needs_review"] == 1
    r = out["results"][0]
    assert r["verdict"]["verdict"] == "malicious"        # more severe wins
    assert r["committee"]["needs_human_review"] is True
    assert r["committee"]["agreement"] is False
    assert r["committee"]["judge_a"]["model"] == "model-a"
    assert r["committee"]["judge_b"]["verdict"] == "suspicious"


def test_committee_agreement_takes_higher_confidence(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cand = _candidates()[:1]
    a, b = _two_clients(
        [json.dumps(good_verdict(verdict="malicious", confidence=0.8))],
        [json.dumps(good_verdict(verdict="malicious", confidence=0.95))])
    out = judge_core.judge_candidates_committee(
        cand, clients=[a, b], cache_db=db, verbose=False)
    r = out["results"][0]
    assert r["committee"]["agreement"] is True
    assert r["committee"]["needs_human_review"] is False
    assert r["verdict"]["confidence"] == 0.95
    assert out["stats"]["needs_review"] == 0


def test_committee_surviving_judge_used_when_one_fails(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cand = _candidates()[:1]
    a, b = _two_clients(
        [json.dumps(good_verdict(verdict="malicious"))],
        ["not json", "also bad"])                       # both attempts fail
    out = judge_core.judge_candidates_committee(
        cand, clients=[a, b], cache_db=db, verbose=False)
    r = out["results"][0]
    assert r["verdict"]["verdict"] == "malicious"        # surviving judge
    assert r["committee"]["needs_human_review"] is True
    assert r["committee"]["judge_b"].get("failed") is True
    assert out["dropped"] == []


def test_committee_both_fail_drops_candidate(tmp_path):
    db = str(tmp_path / "cache.sqlite")
    cand = _candidates()[:1]
    a, b = _two_clients(["bad", "bad"], ["bad", "bad"])
    out = judge_core.judge_candidates_committee(
        cand, clients=[a, b], cache_db=db, verbose=False)
    assert out["results"] == []
    assert out["dropped"][0]["candidate_id"] == cand[0]["candidate_id"]


def test_committee_requires_two_clients(tmp_path):
    with pytest.raises(ValueError):
        judge_core.judge_candidates_committee(
            _candidates()[:1], clients=[FakeClient()],
            cache_db=str(tmp_path / "c.sqlite"), verbose=False)
    # 3+ clients is also rejected (exactly two required).
    a, b = _two_clients([json.dumps(good_verdict())], [json.dumps(good_verdict())])
    c = FakeClient([json.dumps(good_verdict())]); c.model_id = "model-c"
    with pytest.raises(ValueError):
        judge_core.judge_candidates_committee(
            _candidates()[:1], clients=[a, b, c],
            cache_db=str(tmp_path / "c.sqlite"), verbose=False)


def test_committee_rejects_identical_model_ids(tmp_path):
    # Two clients sharing a model_id would make judge B a cache hit of judge A
    # (fingerprint keys on model_id) -> false self-agreement. Refuse loudly.
    a = FakeClient([json.dumps(good_verdict())]); a.model_id = "same-model"
    b = FakeClient([json.dumps(good_verdict())]); b.model_id = "same-model"
    with pytest.raises(ValueError, match="different models"):
        judge_core.judge_candidates_committee(
            _candidates()[:1], clients=[a, b],
            cache_db=str(tmp_path / "c.sqlite"), verbose=False)


def test_committee_guardrail_forces_human_review(tmp_path):
    # Both judges say benign on a candidate whose scan rule fired -> they
    # "agree", but the guardrail escalates to suspicious. That both-models-wrong
    # case is exactly what committee mode must surface, so needs_review must be 1.
    db = str(tmp_path / "cache.sqlite")
    cand = _candidates()[:1]  # attacker with a fired scan_alert
    benign = json.dumps(good_verdict(verdict="benign", category="benign_anomaly",
                                     confidence=0.5,
                                     recommended_action="monitor",
                                     reasoning="Looks like normal traffic."))
    a, b = _two_clients([benign], [benign])
    out = judge_core.judge_candidates_committee(
        cand, clients=[a, b], cache_db=db, verbose=False)
    r = out["results"][0]
    assert r["guardrail"] is not None                    # guardrail fired
    assert r["verdict"]["verdict"] == "suspicious"       # escalated
    assert r["committee"]["needs_human_review"] is True  # forced by guardrail
    assert out["stats"]["needs_review"] == 1


def test_committee_warm_cache_accounting(tmp_path):
    # Second run against a warm cache: both judges are cache hits, so
    # cache_hits counts both and each result is marked cached.
    db = str(tmp_path / "cache.sqlite")
    cand = _candidates()[:1]
    mk = lambda: _two_clients(
        [json.dumps(good_verdict(verdict="malicious", confidence=0.9))],
        [json.dumps(good_verdict(verdict="malicious", confidence=0.8))])
    a1, b1 = mk()
    judge_core.judge_candidates_committee(cand, clients=[a1, b1], cache_db=db, verbose=False)
    a2, b2 = mk()
    out2 = judge_core.judge_candidates_committee(cand, clients=[a2, b2], cache_db=db, verbose=False)
    assert a2.calls == 0 and b2.calls == 0               # served from cache
    assert out2["stats"]["cache_hits"] == 2              # both judges, one candidate
    assert out2["results"][0]["cached"] is True


def test_single_judge_result_has_no_committee_key(tmp_path):
    # Downstream code does r.get("committee") - the single-judge path must
    # simply omit it (not set it to something truthy).
    db = str(tmp_path / "cache.sqlite")
    out = judge_core.judge_candidates(_candidates()[:1], client=FakeClient(),
                                      cache_db=db, verbose=False)
    assert "committee" not in out["results"][0]
    assert "committee" not in out["stats"]
    assert "needs_review" not in out["stats"]


# --------------------------------------------------------------------------
# Advanced signals + device context wiring (Stage 3)
# --------------------------------------------------------------------------
def test_assemble_populates_advanced_signals_and_device_context_when_passed():
    """Prove the wiring: when the caller passes an advanced_signals dict
    (from threats_to_advanced_signals) and a device_context dict (from
    local_inv_to_device_context), the per-IP data lands in the candidate
    blob instead of the all-null defaults. This was hardcoded null before
    Stage 3 - the audit's D1/D4 defect - and the schema now documents
    that it is populated when the pipeline runs the dashboard's advanced
    engines."""
    S = make_session()
    adv = {"192.168.1.10": {
        "beaconing": {"score": 0.85, "severity": "high", "count": 42,
                      "peer": "8.8.8.8"},
        "dns_tunneling": None, "dga": None, "tls_anomaly": None,
        "fusion_score": {"score": 0.9, "techniques": 2}}}
    dev = {"192.168.1.10": {"category": "Network Infra",
                            "hostname": "edge-router",
                            "oui_vendor": "Cisco"}}
    out = judge_core.assemble_candidates(
        S, make_findings(), advanced_signals=adv, device_context=dev)
    c = next(x for x in out["candidates"]
             if x["candidate_id"] == "192.168.1.10")
    assert c["advanced_signals"]["beaconing"]["score"] == 0.85
    assert c["advanced_signals"]["fusion_score"]["techniques"] == 2
    assert c["device_context"] == {"category": "Network Infra",
                                   "hostname": "edge-router",
                                   "oui_vendor": "Cisco"}
    # Backward compat: an IP not in the passed dict still gets the default
    # all-null block, so the schema stays stable.
    S2 = make_session()
    out2 = judge_core.assemble_candidates(S2, make_findings())
    for c in out2["candidates"]:
        assert c["advanced_signals"] == {"beaconing": None,
            "dns_tunneling": None, "dga": None, "tls_anomaly": None,
            "fusion_score": None}
        assert c["device_context"] == {"category": "unknown",
            "hostname": None, "oui_vendor": None}


def test_threats_to_advanced_signals_reshape():
    """Direct helper test: raw run_advanced_threats() output -> per-IP
    map, with per-engine {score, severity, count, peer} preserved and
    fusion_score attached from device_risk."""
    threats = {
        "available": True, "n_packets": 100,
        "per_engine": {
            "beaconing": [{"device": "10.0.0.1", "peer": "8.8.8.8",
                           "score": 0.9, "severity": "high", "count": 40}],
            "dns_tunnel": [{"device": "10.0.0.1", "peer": "",
                            "score": 0.62, "severity": "medium", "count": 30}],
            "dga": [], "arp_dhcp": [],
            "tls": [{"device": "10.0.0.2", "peer": "1.2.3.4",
                     "score": 0.5, "severity": "low", "count": 3}],
        },
        "device_risk": [
            {"device": "10.0.0.1", "risk": 0.9, "techniques_seen": 2}],
    }
    adv = judge_core.threats_to_advanced_signals(threats)
    assert set(adv) == {"10.0.0.1", "10.0.0.2"}
    assert adv["10.0.0.1"]["beaconing"]["score"] == 0.9
    assert adv["10.0.0.1"]["dns_tunneling"]["count"] == 30
    assert adv["10.0.0.1"]["fusion_score"]["techniques"] == 2
    assert adv["10.0.0.2"]["tls_anomaly"]["severity"] == "low"
    # unavailable / missing -> empty
    assert judge_core.threats_to_advanced_signals({"available": False}) == {}
    assert judge_core.threats_to_advanced_signals(None) == {}


def test_local_inv_to_device_context_accepts_df_and_records():
    """Same helper on both a list-of-dicts and a pandas DataFrame - the
    dashboard produces the frame, the run_pipeline path can produce the
    lightweight records shape."""
    records = [{"ip": "10.0.0.1", "device_name": "router",
                "category": "Network Infra", "vendor": "Cisco"},
               {"ip": "10.0.0.2", "device_name": "phone",
                "category": "Mobile", "vendor": "Apple"}]
    dev_from_records = judge_core.local_inv_to_device_context(records)
    df = pd.DataFrame(records)
    dev_from_df = judge_core.local_inv_to_device_context(df)
    assert dev_from_records == dev_from_df
    assert dev_from_records["10.0.0.1"]["hostname"] == "router"
    assert dev_from_records["10.0.0.2"]["oui_vendor"] == "Apple"
    assert judge_core.local_inv_to_device_context(None) == {}
    assert judge_core.local_inv_to_device_context([]) == {}


# --------------------------------------------------------------------------
# Pipeline-vs-judge findings contract (Stage 3: pin against D2 drift)
# --------------------------------------------------------------------------
def test_run_pipeline_findings_keys_match_what_assemble_reads():
    """The judge's assemble_candidates reads a specific set of keys off
    the findings dict: scan_alerts, amp_alerts, flood_alerts,
    arp_spoofing_ips. attack_tests/run_pipeline.py is the only detector
    layer that feeds the judge (the dashboard's own run_security_scans
    uses different names and is not the caller). If run_pipeline ever
    stops emitting one of these keys - or renames one - the judge
    silently drops that signal. Pin the contract with a static parse of
    the return dict so a rename breaks CI immediately."""
    import ast
    path = os.path.join(ROOT, "attack_tests", "run_pipeline.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) \
                and node.name == "run_security_scans":
            # find the final `return {...}` in the function body
            ret = next(s for s in reversed(node.body)
                       if isinstance(s, ast.Return)
                       and isinstance(s.value, ast.Dict))
            keys = {k.value for k in ret.value.keys
                    if isinstance(k, ast.Constant)}
            break
    else:
        pytest.fail("run_security_scans not found in run_pipeline.py")
    # Every key assemble_candidates reads must be present in the returned dict
    required = {"scan_alerts", "amp_alerts", "flood_alerts",
                "arp_spoofing_ips"}
    missing = required - keys
    assert not missing, (
        f"run_pipeline.run_security_scans dropped judge-consumed keys: "
        f"{sorted(missing)}. The judge reads them in judge_core."
        f"assemble_candidates; a silent rename breaks the LLM signal path.")
