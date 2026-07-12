"""Tests for app/ai_advisor_panel.py - the dashboard's AI Second Opinion
bridge to the llm_judge/ add-on. Renders only (no live LLM); the judging
path is exercised by tests/test_judge_cli.py."""
import collections
import json
import os
import sys
from datetime import datetime, timedelta

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))

import ai_advisor_panel as panel                       # noqa: E402


def _tree_text(component):
    """Recursively collect all text, ids, and style values from a Dash
    component tree - so tests can grep for them without needing a running
    Dash app."""
    parts = []

    def walk(node):
        if node is None:
            return
        if isinstance(node, str):
            parts.append(node)
            return
        if isinstance(node, (int, float, bool)):
            parts.append(str(node))
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                walk(item)
            return
        if isinstance(node, dict):
            for k, v in node.items():
                parts.append(str(k))
                walk(v)
            return
        # Dash component
        if hasattr(node, "id"):
            walk(node.id)
        if hasattr(node, "children"):
            walk(node.children)
        for attr in ("style", "className", "n_clicks"):
            if hasattr(node, attr):
                walk(getattr(node, attr))

    walk(component)
    return " ".join(parts)


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test starts with a clean cache."""
    panel.AI_JUDGE_CACHE["s1"] = None
    panel.AI_JUDGE_CACHE["s2"] = None
    yield
    panel.AI_JUDGE_CACHE["s1"] = None
    panel.AI_JUDGE_CACHE["s2"] = None


def _fake_S():
    """Minimal S dict with a rule-fired attacker + a few benign IPs."""
    ips = ["192.168.1.10", "10.0.0.5", "10.0.0.6"]
    ip_agg = pd.DataFrame({
        "count": [1007, 40, 38],
        "total_bytes": [60420, 21000, 20000],
        "mean_len": [60.0, 525.0, 520.0],
        "std_len": [0.0, 310.0, 300.0],
        "unique_dsts": [1000, 3, 3],
        "burst_score": [1007.0, 0.13, 0.13],
        "dominance": [1067.4, 61.0, 58.0],
        "syn_count": [1002, 5, 4],
        "rst_count": [0, 1, 1],
        "fin_count": [0, 0, 0],
        "null_count": [0, 0, 0],
        "xmas_count": [0, 0, 0],
        "iso_score": [-0.31, 0.12, 0.10],
        "iso_flag": [-1, 1, 1],
        "iso_stability": [1.0, 0.0, 0.0],
        "anomaly": [True, False, False],
        "cluster": [-1, 0, 0],
    }, index=ips)
    t0 = datetime(2026, 7, 12, 12, 0, 0)
    return {
        "label": "S1", "n_pkts": 2020, "t0": t0,
        "t1": t0 + timedelta(seconds=71.2),
        "ip_agg": ip_agg,
        "ips_src": collections.Counter({ip: 100 for ip in ips}),
        "macs": collections.Counter({f"aa:bb:cc:00:00:0{i}": 10
                                     for i in range(3)}),
        "protocols": collections.Counter({"TCP": 2007, "ARP": 9}),
    }


def _fake_findings():
    return {
        "scan_alerts": [{"src": "192.168.1.10", "type": "SYN",
                         "count": 1002, "unique_dsts": 1000, "ratio": 1.0}],
        "flood_alerts": [], "amp_alerts": [], "arp_spoofing_ips": {},
        "arp_spoofing_macs": {}, "dns_nxdomain": 0, "dns_long_queries": [],
    }


# --------------------------------------------------------------------------
# Provider status + import diagnostics
# --------------------------------------------------------------------------
def test_is_available_true_in_repo():
    assert panel.is_available() is True


def test_provider_status_claude_no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LLM_JUDGE_PROVIDER", "claude")
    # judge_config caches env vars at import - reload for a clean read
    import importlib
    from llm_judge import judge_config
    importlib.reload(judge_config)
    ok, provider, model, msg = panel.provider_status()
    assert provider == "claude"
    assert ok is False
    assert "ANTHROPIC_API_KEY" in msg


def test_provider_status_ollama(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "test-model")
    import importlib
    from llm_judge import judge_config
    importlib.reload(judge_config)
    ok, provider, model, msg = panel.provider_status()
    assert provider == "ollama" and model == "test-model"
    assert ok is True


# --------------------------------------------------------------------------
# Panel rendering
# --------------------------------------------------------------------------
def test_render_panel_no_session():
    div = panel.render_ai_advisor_panel("s1", None, None)
    text = _tree_text(div)
    assert "AI Second Opinion" in text
    assert "S1" in text


def test_render_panel_with_session_shows_run_state(monkeypatch):
    # provider must be "ready" for the Run button to appear
    monkeypatch.setenv("LLM_JUDGE_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "test-model")
    import importlib
    from llm_judge import judge_config
    importlib.reload(judge_config)
    div = panel.render_ai_advisor_panel("s1", _fake_S(), _fake_findings())
    text = _tree_text(div)
    assert "AI Second Opinion" in text
    assert "ai-run-btn" in text
    # candidate count hint should mention "1 candidate" (only 192.168.1.10)
    assert "1 candidate" in text


def test_render_panel_shows_cached_verdicts(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_PROVIDER", "ollama")
    import importlib
    from llm_judge import judge_config
    importlib.reload(judge_config)
    fake_verdicts = {
        "generated_at": "2026-07-12T15:00:00+00:00",
        "provider": "ollama", "model": "llama3.2",
        "prompt_version": "v0.3.0", "guardrail": True,
        "stats": {"total": 1, "judged": 1, "cache_hits": 0, "dropped": 0,
                  "prompt_version": "v0.3.0", "model": "llama3.2"},
        "results": [{"candidate_id": "192.168.1.10", "kind": "ip",
                     "cached": False, "latency_ms": 100,
                     "guardrail": None, "priority": 0.48,
                     "verdict": {
                         "verdict": "malicious", "category": "port_scan",
                         "confidence": 0.95,
                         "evidence_features": ["syn_count"],
                         "reasoning": "SYN scan detected.",
                         "recommended_action": "investigate"}}],
        "dropped": [], "capped": [],
        "context": {"n_packets": 2020, "duration_s": 71.2,
                    "total_ips": 3, "total_macs": 3,
                    "top_protocols": {"TCP": 2007},
                    "ml": {"isolation_forest_anomalies": 1,
                           "dbscan_noise": 1, "dbscan_clusters": 1,
                           "dbscan_meaningful": True},
                    "rules": {"scan_alerts": 1,
                              "scan_alerts_summary": [],
                              "flood_alerts": 0, "amp_alerts": 0,
                              "arp_spoofing_ips": 0,
                              "dns_nxdomain": 0, "dns_long_queries": 0}},
    }
    panel.AI_JUDGE_CACHE["s1"] = fake_verdicts
    div = panel.render_ai_advisor_panel("s1", _fake_S(), _fake_findings())
    text = _tree_text(div)
    assert "port_scan" in text
    assert "MALICIOUS" in text
    assert "192.168.1.10" in text
    assert "Re-run" in text
    assert "ai-run-btn" in text
    # metadata strip
    assert "prompt v0.3.0" in text
    assert "guardrail on" in text


def test_reset_cache_for_session():
    panel.AI_JUDGE_CACHE["s1"] = {"stub": 1}
    panel.AI_JUDGE_CACHE["s2"] = {"stub": 2}
    panel.reset_cache_for_session("s1")
    assert panel.AI_JUDGE_CACHE["s1"] is None
    assert panel.AI_JUDGE_CACHE["s2"] == {"stub": 2}
    panel.reset_cache_for_session("nope")  # ignores unknown keys


# --------------------------------------------------------------------------
# run_judge integration (with a fake client)
# --------------------------------------------------------------------------
def test_run_judge_end_to_end(monkeypatch):
    """Ensure the panel's run_judge glues assemble+judge+context correctly.
    Uses a fake OracleClient so no live LLM."""
    monkeypatch.setenv("LLM_JUDGE_PROVIDER", "ollama")
    import importlib
    from llm_judge import judge_config, judge_core
    importlib.reload(judge_config)

    class OracleClient:
        model_id = "oracle-test"

        def judge(self, sp, uc):
            cand = json.loads(uc)
            cat = (judge_core.rule_expected_category(cand)
                   or "benign_anomaly")
            v = "benign" if cat == "benign_anomaly" else "malicious"
            return json.dumps({
                "verdict": v, "category": cat, "confidence": 0.95,
                "evidence_features": ["rule_signals"],
                "reasoning": "Oracle test verdict.",
                "recommended_action": ("monitor" if v == "benign"
                                       else "investigate"),
            })

    monkeypatch.setattr(
        "llm_judge.llm_clients.make_client",
        lambda **_kw: OracleClient(),
    )
    out = panel.run_judge(_fake_S(), _fake_findings())
    assert out["provider"] == "ollama"
    assert out["model"] == "oracle-test"
    assert out["stats"]["judged"] >= 1
    assert any(r["candidate_id"] == "192.168.1.10" for r in out["results"])
    assert out["context"]["n_packets"] == 2020
    # JSON serializable (Dash stores it in dcc.Store)
    json.dumps(out)
