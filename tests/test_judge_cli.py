"""Unit tests for llm_judge/judge_cli.py.

Uses the committed benchmark fixtures + an in-process fake client, so no
network, no tshark, no LLM. Verifies the JSON+Markdown outputs the
GitHub Actions workflow relies on.
"""
import collections
import json
import os
import sys
from datetime import datetime, timedelta
from unittest import mock

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import benchmark, judge_config, judge_cli, judge_core  # noqa: E402


def _fake_client():
    """Small deterministic 'oracle' client - avoids real LLM calls."""

    class OracleClient:
        model_id = "fake-oracle"

        def judge(self, system_prompt, user_content):
            cand = json.loads(user_content)
            cat = (judge_core.rule_expected_category(cand)
                   or "benign_anomaly")
            verdict = "benign" if cat == "benign_anomaly" else "malicious"
            return json.dumps({
                "verdict": verdict, "category": cat, "confidence": 0.9,
                "evidence_features": ["rule_signals"],
                "reasoning": "Fake verdict for the CLI test.",
                "recommended_action": ("monitor" if verdict == "benign"
                                       else "investigate"),
            })

    return OracleClient()


def _judged_batch():
    """Real assemble + judge output using labeled fixtures + fake client."""
    fixtures = benchmark.load_fixtures()
    candidates = [f["candidate"] for f in fixtures]
    assembled = {"candidates": candidates, "capped": []}
    out = judge_core.judge_candidates(candidates, client=_fake_client(),
                                      cache_db=":memory:", verbose=False)
    return out, assembled, _fake_client()


def _fake_context(not_flagged_count=3):
    """A build_context() output shaped like a real pipeline run."""
    return {
        "n_packets": 2020,
        "duration_s": 71.2,
        "time_range": ["2026-07-10 12:00:00", "2026-07-10 12:01:11"],
        "total_ips": 5,
        "total_macs": 8,
        "top_protocols": {"TCP": 2007, "ARP": 9, "SSDP": 4},
        "ml": {"isolation_forest_anomalies": 1, "dbscan_noise": 1,
               "dbscan_clusters": 1, "dbscan_meaningful": True},
        "rules": {
            "scan_alerts": 1,
            "scan_alerts_summary": [
                "SYN from `192.168.1.10` (1002 pkts, ratio 1.0)"],
            "flood_alerts": 0, "amp_alerts": 0, "arp_spoofing_ips": 0,
            "dns_nxdomain": 0, "dns_long_queries": 0,
        },
        "flagged_ip_ids": ["192.168.1.10"],
        "not_flagged_ips": [
            {"ip": f"10.0.0.{i + 5}", "packets": 40 - i, "iso_score": 0.12,
             "cluster": 0}
            for i in range(not_flagged_count)
        ],
        "capped_ips": [],
    }


# --------------------------------------------------------------------------
# build_context - extracts facts from a real S / findings shape
# --------------------------------------------------------------------------
def _synthetic_session(n_benign=3):
    ips = ["192.168.1.10"] + [f"10.0.0.{i + 5}" for i in range(n_benign)]
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
        "label": "S1", "n_pkts": 2020, "t0": t0,
        "t1": t0 + timedelta(seconds=71.2),
        "ip_agg": ip_agg,
        "ips_src": collections.Counter({ip: 100 for ip in ips}),
        "macs": collections.Counter({f"aa:bb:cc:00:00:{i:02x}": 10
                                     for i in range(8)}),
        "protocols": collections.Counter({"TCP": 2007, "ARP": 9,
                                          "SSDP": 4}),
    }


def _synthetic_findings():
    return {
        "scan_alerts": [{"src": "192.168.1.10", "type": "SYN", "count": 1002,
                         "unique_dsts": 1000, "ratio": 1.0}],
        "flood_alerts": [], "amp_alerts": [], "arp_spoofing_ips": {},
        "arp_spoofing_macs": {}, "dns_nxdomain": 0, "dns_long_queries": [],
    }


def test_build_context_extracts_pipeline_facts():
    S = _synthetic_session(n_benign=3)
    findings = _synthetic_findings()
    assembled = judge_core.assemble_candidates(S, findings)
    ctx = judge_cli.build_context(S, findings, assembled)

    assert ctx["n_packets"] == 2020
    assert ctx["duration_s"] == 71.2
    assert ctx["total_ips"] == 4
    assert ctx["top_protocols"]["TCP"] == 2007
    assert ctx["ml"]["isolation_forest_anomalies"] == 1
    assert ctx["ml"]["dbscan_clusters"] == 1
    assert ctx["ml"]["dbscan_meaningful"] is True
    assert ctx["rules"]["scan_alerts"] == 1
    assert "192.168.1.10" in ctx["rules"]["scan_alerts_summary"][0]
    assert "192.168.1.10" in ctx["flagged_ip_ids"]
    assert len(ctx["not_flagged_ips"]) == 3
    # not-flagged IPs must be the benign ones with iso_score+cluster shown
    for entry in ctx["not_flagged_ips"]:
        assert entry["ip"].startswith("10.0.0.")
        assert entry["cluster"] == 0
        assert entry["iso_score"] == 0.12
    # JSON serializable (the CLI writes this to verdicts.json)
    json.dumps(ctx)


# --------------------------------------------------------------------------
# Markdown rendering - sections
# --------------------------------------------------------------------------
def test_render_markdown_has_expected_sections():
    out, assembled, client = _judged_batch()
    md = judge_cli._render_markdown("attack_tests/pcaps/tcp_syn_scan.pcap",
                                    out, assembled, client,
                                    context=_fake_context())
    assert md.startswith("# Judge verdicts")
    assert "tcp_syn_scan.pcap" in md
    assert "## Pipeline stats" in md
    assert "## Top verdict" in md
    assert "## Triaged queue" in md
    assert "## How to interpret" in md
    assert "| # | Candidate |" in md   # triaged table header
    for r in out["results"]:
        assert r["candidate_id"] in md
    assert judge_config.PROMPT_VERSION in md
    assert client.model_id in md


def test_render_markdown_pipeline_stats_content():
    """Pipeline stats section must reflect the context numbers."""
    out, assembled, client = _judged_batch()
    ctx = _fake_context()
    md = judge_cli._render_markdown("x.pcap", out, assembled, client,
                                    context=ctx)
    stats_section = md.split("## Pipeline stats")[1].split("##")[0]
    assert "2,020" in stats_section              # packets, comma formatted
    assert "71.2 seconds" in stats_section
    assert "TCP 2,007" in stats_section          # top protocol formatted
    assert "1 IsolationForest anomaly" in stats_section
    assert "1 scan alert(s)" in stats_section
    assert "192.168.1.10" in stats_section       # per-alert detail


def test_render_markdown_not_flagged_section_lists_ips():
    """The 'Not queued for judgment' section shows the analyzed clean IPs."""
    out, assembled, client = _judged_batch()
    ctx = _fake_context(not_flagged_count=4)
    md = judge_cli._render_markdown("x.pcap", out, assembled, client,
                                    context=ctx)
    assert "## Not queued for judgment" in md
    for entry in ctx["not_flagged_ips"]:
        assert entry["ip"] in md
    # nothing to include -> section is omitted
    empty = _fake_context(not_flagged_count=0)
    md2 = judge_cli._render_markdown("x.pcap", out, assembled, client,
                                     context=empty)
    assert "## Not queued for judgment" not in md2


def test_render_markdown_not_flagged_caps_long_list():
    out, assembled, client = _judged_batch()
    ctx = _fake_context(not_flagged_count=35)
    md = judge_cli._render_markdown("x.pcap", out, assembled, client,
                                    context=ctx)
    assert "## Not queued for judgment" in md
    # only the first 20 rows are rendered, plus a "more" hint
    for i in range(20):
        assert f"10.0.0.{i + 5}" in md
    assert "15 more" in md
    # rows past the cap are elided
    assert "10.0.0.34" not in md


def test_render_markdown_how_to_interpret_included():
    out, assembled, client = _judged_batch()
    md = judge_cli._render_markdown("x.pcap", out, assembled, client,
                                    context=_fake_context())
    assert "## How to interpret" in md
    assert "Verdict" in md
    assert "Rule guardrail" in md


def test_render_markdown_reasoning_lives_in_its_own_section():
    """Reasoning was moved out of the triaged-queue table because the
    long free-text field overflowed the 9-column layout in PDF / phone
    email clients. It now renders as a `> quote` under its own heading -
    so a `|` in the reasoning survives verbatim (no escaping needed) and
    the queue table stays 8 compact columns."""
    out = {
        "stats": {"total": 1, "judged": 1, "cache_hits": 0, "dropped": 0,
                  "prompt_version": "v", "model": "fake"},
        "results": [{
            "candidate_id": "1.2.3.4", "kind": "ip", "cached": False,
            "latency_ms": 10, "guardrail": None, "priority": 0.5,
            "verdict": {"verdict": "benign", "category": "benign_anomaly",
                        "confidence": 0.5, "evidence_features": [],
                        "reasoning": "before | after pipe",
                        "recommended_action": "monitor"},
        }],
        "dropped": [],
    }
    assembled = {"candidates": [{}], "capped": []}
    md = judge_cli._render_markdown("x.pcap", out, assembled,
                                    _fake_client(), context=_fake_context())

    # Queue table row has exactly 8 columns (# candidate verdict category
    # confidence priority flag action), no reasoning column.
    table_row = [ln for ln in md.splitlines()
                 if "`1.2.3.4`" in ln and ln.startswith("|")][0]
    assert table_row.count("|") == 9  # 8 columns + trailing edge
    assert "before" not in table_row  # reasoning NOT in the queue row

    # Reasoning shows under its own heading, as a blockquote.
    assert "### Reasoning per candidate" in md
    assert "> before | after pipe" in md


def test_render_markdown_empty_batch():
    """Zero flagged candidates -> friendly 'nothing to judge' section."""
    out = {"stats": {"total": 0, "judged": 0, "cache_hits": 0,
                     "dropped": 0, "prompt_version": "v",
                     "model": "fake"},
           "results": [], "dropped": []}
    assembled = {"candidates": [], "capped": []}
    md = judge_cli._render_markdown("clean.pcap", out, assembled,
                                    _fake_client(),
                                    context=_fake_context(
                                        not_flagged_count=0))
    assert "## No verdicts" in md
    assert "## Triaged queue" not in md


def test_render_markdown_notes_guardrail_when_used():
    out, assembled, client = _judged_batch()
    if out["results"]:
        out["results"][0]["guardrail"] = {"applied": True,
                                          "rule_category": "port_scan"}
    md = judge_cli._render_markdown("x.pcap", out, assembled, client,
                                    context=_fake_context())
    assert "⚑" in md
    assert "rule guardrail overrode" in md


def test_render_markdown_capped_section():
    out = {"stats": {"total": 0, "judged": 0, "cache_hits": 0,
                     "dropped": 0, "prompt_version": "v",
                     "model": "fake"},
           "results": [], "dropped": []}
    assembled = {"candidates": [],
                 "capped": [f"10.0.0.{i}" for i in range(25)]}
    md = judge_cli._render_markdown("x.pcap", out, assembled,
                                    _fake_client(),
                                    context=_fake_context(
                                        not_flagged_count=0))
    assert "## Capped" in md
    assert "10.0.0.0" in md and "10.0.0.19" in md


# --------------------------------------------------------------------------
# CLI end-to-end (mocked pipeline + client) via `main()`
# --------------------------------------------------------------------------
def test_main_writes_json_and_markdown(tmp_path):
    out, assembled, client = _judged_batch()
    ctx = _fake_context()
    fake_pcap = tmp_path / "sample.pcap"
    fake_pcap.write_bytes(b"not really a pcap but the CLI just checks it exists")

    with mock.patch.object(judge_cli, "analyze_and_judge",
                           return_value=(out, assembled, client, ctx)):
        rc = judge_cli.main([
            str(fake_pcap),
            "--output", str(tmp_path / "verdicts.json"),
            "--markdown", str(tmp_path / "verdicts.md"),
        ])

    assert rc == 0
    data = json.loads((tmp_path / "verdicts.json").read_text(encoding="utf-8"))
    assert data["pcap"] == "sample.pcap"
    assert data["model"] == client.model_id
    assert data["stats"]["judged"] >= 1
    assert isinstance(data["results"], list)
    # context is now persisted in the JSON too
    assert data["context"]["n_packets"] == 2020

    md = (tmp_path / "verdicts.md").read_text(encoding="utf-8")
    assert "# Judge verdicts" in md
    assert "sample.pcap" in md
    assert "## Pipeline stats" in md
    assert "## How to interpret" in md


def test_main_returns_nonzero_when_pcap_missing(tmp_path):
    rc = judge_cli.main([str(tmp_path / "does-not-exist.pcap"),
                         "--output", str(tmp_path / "verdicts.json")])
    assert rc == 2


# --------------------------------------------------------------------------
# Analyst commentary
# --------------------------------------------------------------------------
def test_analyst_commentary_returns_prose(monkeypatch):
    """A schema-less follow-up client yields a plain paragraph the CLI
    inserts at the top of the report."""
    from llm_judge import judge_core

    class ProseClient:
        model_id = "fake-prose"

        def judge(self, sp, uc):
            # Simulate a real analyst reply.
            return ("The capture shows a single host running a SYN "
                    "scan against many destinations. Priority for a "
                    "human review is high; recommend blocking that IP "
                    "at the perimeter and correlating with proxy logs.")

    monkeypatch.setattr("llm_judge.llm_clients.make_client",
                        lambda **_k: ProseClient())
    ctx = {"n_packets": 2020, "duration_s": 71.2, "total_ips": 5,
           "top_protocols": {"TCP": 2007},
           "ml": {"isolation_forest_anomalies": 1, "dbscan_noise": 1,
                  "dbscan_clusters": 1, "dbscan_meaningful": True},
           "rules": {"scan_alerts": 1, "flood_alerts": 0,
                     "amp_alerts": 0, "arp_spoofing_ips": 0,
                     "dns_nxdomain": 0, "dns_long_queries": 0,
                     "scan_alerts_summary": []},
           "not_flagged_ips": []}
    verdicts = {"results": [{
        "candidate_id": "192.168.1.10", "kind": "ip", "cached": False,
        "priority": 0.48, "latency_ms": 100, "guardrail": None,
        "verdict": {"verdict": "suspicious", "category": "port_scan",
                    "confidence": 0.6, "evidence_features": [],
                    "reasoning": "SYN scan.",
                    "recommended_action": "investigate"},
    }]}
    text = judge_core.analyst_commentary(None, ctx, verdicts,
                                          session_label="S1")
    assert "SYN scan" in text or "port scan" in text.lower()
    assert "\n" not in text                # single paragraph
    assert len(text) <= 2000


def test_analyst_commentary_swallows_errors(monkeypatch):
    """A dead provider must not crash the batch."""
    from llm_judge import judge_core

    class DeadClient:
        model_id = "fake-dead"

        def judge(self, sp, uc):
            raise RuntimeError("boom")

    monkeypatch.setattr("llm_judge.llm_clients.make_client",
                        lambda **_k: DeadClient())
    text = judge_core.analyst_commentary(None, {"n_packets": 0}, {"results": []})
    assert text.startswith("(Analyst commentary unavailable")
    assert "boom" in text


def test_main_includes_commentary_in_json_and_markdown(tmp_path):
    """End-to-end: the CLI writes analyst_commentary to both outputs."""
    out, assembled, client = _judged_batch()
    ctx = _fake_context()
    out["analyst_commentary"] = ("Overall the capture is dominated by "
                                 "DNS amplification traffic aimed at "
                                 "the victim; recommend blocking the "
                                 "reflector list and rate-limiting "
                                 "UDP/53 at the edge.")
    fake_pcap = tmp_path / "sample.pcap"
    fake_pcap.write_bytes(b"placeholder pcap bytes")

    with mock.patch.object(judge_cli, "analyze_and_judge",
                           return_value=(out, assembled, client, ctx)):
        rc = judge_cli.main([str(fake_pcap),
                             "--output", str(tmp_path / "verdicts.json"),
                             "--markdown", str(tmp_path / "verdicts.md")])
    assert rc == 0
    data = json.loads((tmp_path / "verdicts.json").read_text(encoding="utf-8"))
    assert "analyst_commentary" in data
    assert "DNS amplification" in data["analyst_commentary"]
    md = (tmp_path / "verdicts.md").read_text(encoding="utf-8")
    assert "## Analyst commentary" in md
    assert "> Overall the capture is dominated by" in md
    # The commentary must appear before the pipeline stats section
    assert md.index("## Analyst commentary") < md.index("## Pipeline stats")
