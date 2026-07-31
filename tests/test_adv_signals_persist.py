"""Regression: `results.write_adv_signals` persists S['threats'] into the
adv_signals and fusion_scores tables. Before the fix that added it, the
tables stayed empty even when the worker computed the signals - the
comment in server/results.py explicitly deferred the wiring, and the
2026-07-31 VM verification caught it: 17 signals from the worker log,
zero rows in the DB.

Also covers the graceful-degradation path (no S['threats'], or
`available: False`) that the historical docstring reserved space for.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import db, results  # noqa: E402


def _session(tmp_path):
    """Fresh DB + a queued session row so write_adv_signals has a FK."""
    db_path = tmp_path / "hist.db"
    conn = db.connect(str(db_path))
    conn.execute("INSERT INTO pcap_files (sha256, orig_name, size_bytes,"
                 " sensor_id, received_at, storage_path)"
                 " VALUES (?,?,?,?,?,?)",
                 ("a" * 64, "t.pcap", 1, None, "2026-07-31T12:00:00Z",
                  str(tmp_path / "t.pcap")))
    conn.execute("INSERT INTO sessions (pcap_id, label, kind, queued_at,"
                 " status) VALUES (1, 't', 'prod', '2026-07-31T12:00:00Z',"
                 " 'running')")
    conn.commit()
    return conn


def _threats_from(_signals_by_engine, _fusion):
    return {
        "available": True,
        "n_packets": 100,
        "per_engine": _signals_by_engine,
        "all_signals": [s for rows in _signals_by_engine.values() for s in rows],
        "device_risk": _fusion,
    }


def test_write_adv_signals_persists_engine_rows_and_fusion(tmp_path):
    conn = _session(tmp_path)
    S = {"threats": _threats_from(
        {"arp_dhcp": [{"device": "192.168.1.1", "peer": "aa:bb",
                       "signal": "arp_ip_multi_mac",
                       "tactic": "Collection / MITM",
                       "technique": "T1557.002", "score": 0.9,
                       "severity": "high", "count": 12,
                       "first_ts": 1.0, "last_ts": 9.0,
                       "detail": "..."}],
         "dga": [{"device": "192.168.1.104", "peer": "exploit-db",
                  "signal": "dga_domain", "tactic": "C2",
                  "technique": "T1568.002", "score": 0.41,
                  "severity": "medium", "count": 1,
                  "first_ts": 1.0, "last_ts": 2.0, "detail": ""}],
         "tls": [{"device": "192.168.1.104", "peer": "abcd1234",
                  "signal": "rare_ja3", "tactic": "C2",
                  "technique": "T1071.001", "score": 0.6,
                  "severity": "low", "count": 3,
                  "first_ts": 3.0, "last_ts": 5.0, "detail": ""}]},
        [{"device": "192.168.1.104", "risk": 0.85, "signals": 3,
          "signal_types": 2, "techniques": "T1568.002;T1071.001"}])}
    n_sig, n_fusion = results.write_adv_signals(conn, 1, S)
    assert (n_sig, n_fusion) == (3, 1)

    rows = conn.execute("SELECT device, signal, score, severity, technique"
                        " FROM adv_signals WHERE session_id=1"
                        " ORDER BY device, signal").fetchall()
    assert len(rows) == 3
    devices = {r[0] for r in rows}
    assert devices == {"192.168.1.1", "192.168.1.104"}
    signals = {r[1] for r in rows}
    assert signals == {"arp_ip_multi_mac", "dga_domain", "rare_ja3"}

    fus = conn.execute("SELECT device, score, engines_hit FROM"
                       " fusion_scores WHERE session_id=1").fetchone()
    assert tuple(fus) == ("192.168.1.104", 0.85, 2)


def test_write_adv_signals_noop_when_engines_unavailable(tmp_path):
    conn = _session(tmp_path)
    for threats in (
        None,                                                    # missing
        {},                                                      # empty
        {"available": False, "reason": "pcap empty or tshark missing"},
    ):
        n_sig, n_fusion = results.write_adv_signals(
            conn, 1, {"threats": threats})
        assert (n_sig, n_fusion) == (0, 0)
    # Also tolerates S not being a dict at all.
    assert results.write_adv_signals(conn, 1, None) == (0, 0)
    assert conn.execute("SELECT COUNT(*) FROM adv_signals").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM fusion_scores").fetchone()[0] == 0


def test_write_adv_signals_skips_row_without_device(tmp_path):
    conn = _session(tmp_path)
    S = {"threats": _threats_from(
        {"dga": [{"device": "", "peer": "x", "signal": "dga_domain",
                  "score": 0.4, "severity": "medium", "count": 1},
                 {"device": None, "peer": "y", "signal": "dga_domain",
                  "score": 0.5, "severity": "medium", "count": 1},
                 {"device": "192.168.1.10", "peer": "z",
                  "signal": "dga_domain", "score": 0.6,
                  "severity": "medium", "count": 1}]},
        [{"device": None, "risk": 0.9, "signal_types": 1},
         {"device": "192.168.1.10", "risk": 0.9, "signal_types": 1}])}
    n_sig, n_fusion = results.write_adv_signals(conn, 1, S)
    assert (n_sig, n_fusion) == (1, 1)


def test_write_all_reports_advanced_counts(tmp_path):
    """write_all's dict must expose the two counters so the worker log
    and any downstream reconciliation can distinguish 'engines fired
    but wrote 0 rows' from 'engines never ran'."""
    conn = _session(tmp_path)
    S = {"threats": _threats_from(
        {"arp_dhcp": [{"device": "10.0.0.1", "signal": "arp_gratuitous_flood",
                       "score": 0.55, "severity": "medium", "count": 20}]},
        [{"device": "10.0.0.1", "risk": 0.55, "signal_types": 1}])}
    counts = results.write_all(conn, 1, S, findings={},
                               assembled={"candidates": [], "capped": []},
                               out={"results": [], "stats": {}})
    assert counts["adv_signals"] == 1
    assert counts["fusion_scores"] == 1
    assert counts["candidates"] == 0
