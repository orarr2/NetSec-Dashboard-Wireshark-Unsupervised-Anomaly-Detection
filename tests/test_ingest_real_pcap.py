"""Smoke test: ingest a real PCAP through the dashboard's own path.

Catches the class of regression where a rename or refactor breaks
_ingest_pcap_from_path -> process_session -> run_ml_on_session but
leaves the synthetic-session unit tests passing (they never hit the
real dashboard code paths). Runs against the smallest labeled PCAP so
CI wall time stays well under a minute.
"""
import io
import contextlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))


@pytest.fixture(scope="module")
def dashboard():
    """Import the dashboard module with app.run stubbed to a no-op so
    importing it does not try to open a Dash server socket."""
    import dash
    orig_run = dash.Dash.run
    dash.Dash.run = lambda *a, **kw: None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            from app import dashboard_module as d
        yield d
    finally:
        dash.Dash.run = orig_run


def test_ingest_tcp_syn_scan_smoke(dashboard):
    """The dashboard's own ingest path must reach a populated S1."""
    pcap = os.path.join(ROOT, "attack_tests", "pcaps", "tcp_syn_scan.pcap")
    with contextlib.redirect_stdout(io.StringIO()):
        ok, msg = dashboard._ingest_pcap_from_path(pcap, "S1")
    assert ok, f"ingest failed: {msg}"
    S = dashboard.S1
    assert S is not None
    assert S["n_pkts"] > 0
    ip_agg = S["ip_agg"]
    for col in ("anomaly", "iso_score", "iso_flag", "cluster"):
        assert col in ip_agg.columns, f"missing {col}"
    # The dashboard stores this for the diagnostics card - regression bait
    # for anyone editing the ML block.
    assert S.get("_chosen_contamination") is not None
