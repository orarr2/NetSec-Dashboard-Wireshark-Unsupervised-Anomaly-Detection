"""Unit tests for llm_judge/judge_cli.py.

Uses the committed benchmark fixtures + an in-process fake client, so no
network, no tshark, no LLM. Verifies the JSON+Markdown outputs the
GitHub Actions workflow relies on.
"""
import json
import os
import sys
from unittest import mock

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


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------
def test_render_markdown_has_expected_sections():
    out, assembled, client = _judged_batch()
    md = judge_cli._render_markdown("attack_tests/pcaps/tcp_syn_scan.pcap",
                                    out, assembled, client)
    assert md.startswith("# Judge verdicts")
    assert "tcp_syn_scan.pcap" in md
    assert "## Top verdict" in md
    assert "## Triaged queue" in md
    assert "| # | Candidate |" in md   # table header
    # every fixture must land in the table
    for r in out["results"]:
        assert r["candidate_id"] in md
    # provider + prompt version metadata are present
    assert judge_config.PROMPT_VERSION in md
    assert client.model_id in md


def test_render_markdown_escapes_pipe_in_reasoning():
    """A `|` inside reasoning must not break the markdown table."""
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
                                    _fake_client())
    # pick the actual TABLE row (not the top-verdict prose line)
    table_row = [ln for ln in md.splitlines()
                 if "`1.2.3.4`" in ln and ln.startswith("|")][0]
    assert table_row.count("|") >= 8   # a valid markdown table row
    assert "before \\| after pipe" in md
    # the raw pipe from reasoning must not appear unescaped in a row
    assert "before | after pipe" not in table_row


def test_render_markdown_empty_batch():
    """Zero flagged candidates -> friendly 'nothing to judge' section."""
    out = {"stats": {"total": 0, "judged": 0, "cache_hits": 0,
                     "dropped": 0, "prompt_version": "v",
                     "model": "fake"},
           "results": [], "dropped": []}
    assembled = {"candidates": [], "capped": []}
    md = judge_cli._render_markdown("clean.pcap", out, assembled,
                                    _fake_client())
    assert "## No verdicts" in md
    assert "## Triaged queue" not in md


def test_render_markdown_notes_guardrail_when_used():
    out, assembled, client = _judged_batch()
    # force guardrail on the first attack row so the note shows
    if out["results"]:
        out["results"][0]["guardrail"] = {"applied": True,
                                          "rule_category": "port_scan"}
    md = judge_cli._render_markdown("x.pcap", out, assembled, client)
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
                                    _fake_client())
    assert "## Capped" in md
    # cap section shows first 20 with ellipsis (25 total)
    assert "10.0.0.0" in md and "10.0.0.19" in md
    assert md.count("10.0.0.") <= 21   # 20 shown + 1 in raise-limit note maybe
    assert "…" in md


# --------------------------------------------------------------------------
# CLI end-to-end (mocked pipeline + client) via `main()`
# --------------------------------------------------------------------------
def test_main_writes_json_and_markdown(tmp_path):
    out, assembled, client = _judged_batch()
    fake_pcap = tmp_path / "sample.pcap"
    fake_pcap.write_bytes(b"not really a pcap but the CLI just checks it exists")

    with mock.patch.object(judge_cli, "analyze_and_judge",
                           return_value=(out, assembled, client)):
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

    md = (tmp_path / "verdicts.md").read_text(encoding="utf-8")
    assert "# Judge verdicts" in md
    assert "sample.pcap" in md


def test_main_returns_nonzero_when_pcap_missing(tmp_path):
    rc = judge_cli.main([str(tmp_path / "does-not-exist.pcap"),
                         "--output", str(tmp_path / "verdicts.json")])
    assert rc == 2
