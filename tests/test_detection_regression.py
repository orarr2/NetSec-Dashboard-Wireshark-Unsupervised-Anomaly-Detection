"""Regression tests: every detection layer fires on its target attack class.

Runs the five bundled attack PCAPs through the same extraction + ML + rule
code paths as the dashboard (attack_tests/run_pipeline.py) and asserts the
labeled ground truth in attack_tests/ground_truth.json is detected.

Requires tshark on PATH. Run with:  pytest tests/ -v
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "attack_tests"))

import evaluate  # noqa: E402

GT = {k: v for k, v in
      json.load(open(os.path.join(ROOT, "attack_tests", "ground_truth.json"))).items()
      if not k.startswith("_")}

_cache = {}


def result_for(name):
    """Each PCAP is analyzed once per test session (ML included)."""
    if name not in _cache:
        _cache[name] = evaluate.evaluate_pcap(name, GT[name], quiet=True)
    return _cache[name]


@pytest.mark.parametrize("name", list(GT.keys()))
def test_all_ground_truth_checks(name):
    r = result_for(name)
    failed = [c for c, ok in r["checks"].items() if not ok]
    assert not failed, f"{name}: failed checks: {failed} (all: {r['checks']})"


def test_syn_scanner_rule_is_exact():
    """Rule layer flags the SYN scanner and nothing else on the scan PCAP."""
    r = result_for("tcp_syn_scan.pcap")
    p, rec, f1 = r["metrics"]["rule"]
    assert rec == 1.0, "scanner not detected by rule layer"
    assert p == 1.0, "rule layer flagged non-attacker IPs on a clean scan PCAP"


def test_xmas_scanner_recall():
    r = result_for("xmas_scan.pcap")
    _, rec, _ = r["metrics"]["rule"]
    assert rec == 1.0, "Xmas scanner not detected by rule layer"


def test_syn_scan_ml_recall():
    """IsolationForest majority vote flags the scanner."""
    r = result_for("tcp_syn_scan.pcap")
    _, rec, _ = r["metrics"]["ml"]
    assert rec == 1.0, "IsolationForest did not flag the SYN scanner"


def test_dns_amp_reflectors_all_found():
    r = result_for("dns_amp.pcap")
    _, rec, _ = r["metrics"]["rule"]
    assert rec == 1.0, "not all known reflectors flagged by the amp rule"


def test_flood_rule_does_not_fire_on_scans():
    """A single-source scan is a scan, not a flood."""
    for name in ("tcp_syn_scan.pcap", "xmas_scan.pcap", "arpspoof.pcap"):
        r = result_for(name)
        assert r["checks"].get("aggregate_flood", True), \
            f"{name}: aggregate flood expectation failed"
