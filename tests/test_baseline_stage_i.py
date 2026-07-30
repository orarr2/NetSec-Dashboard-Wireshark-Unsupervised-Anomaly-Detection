"""Stage I regression: per-device baselines from prod history and the
per-session deviation scoring. Stdlib only.
"""
import os
import sys
from datetime import datetime, timezone

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import auth, baseline, db  # noqa: E402

NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "netsec.db"))
    db.create_sensor(c, "s", auth.hash_token("t"), "sec")
    yield c
    c.close()


def _session(conn, kind="prod", status="done", pcap_sha=None):
    sha = pcap_sha or (f"{len(pcap_sha or ''):02x}" * 32)
    import secrets
    sha = secrets.token_hex(32)
    pid, _ = db.register_pcap(conn, sha, "c.pcap", 1, 1, "/x")
    sid = db.create_session(conn, pid, "S", kind)
    if status == "done":
        db.mark_done(conn, sid)
    return sid


def _feat(conn, sid, ip, count, syn=0, self_tel=0):
    conn.execute(
        "INSERT INTO ip_features (session_id, ip, count, syn_count,"
        " mean_len, std_len, burst_score, unique_dsts, rst_count,"
        " fin_count, null_count, xmas_count, bytes_src, bytes_dst,"
        " self_telemetry) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, ip, count, syn, 100.0, 10.0, 5.0, 3, 0, 0, 0, 0, count * 50,
         0, self_tel))
    conn.commit()


def test_baseline_needs_min_sessions(conn):
    sid = _session(conn)
    _feat(conn, sid, "10.0.0.5", count=100)
    # a single observation is not a baseline
    assert baseline.compute_baselines(conn, now=NOW, min_sessions=2) == 0
    assert baseline.get_baseline(conn, "10.0.0.5") is None


def test_baseline_computed_from_prod_only(conn):
    for _ in range(3):
        sid = _session(conn, kind="prod")
        _feat(conn, sid, "10.0.0.5", count=100)
    # a test-kind session with a wild value must NOT move the baseline
    tsid = _session(conn, kind="test")
    _feat(conn, tsid, "10.0.0.5", count=100000)

    assert baseline.compute_baselines(conn, now=NOW) == 1
    base = baseline.get_baseline(conn, "10.0.0.5")
    assert base["features"]["n"] == 3           # test session excluded
    assert base["features"]["features"]["count"]["mean"] == 100.0


def test_self_telemetry_excluded_from_baseline(conn):
    for _ in range(3):
        sid = _session(conn)
        _feat(conn, sid, "10.0.0.9", count=100, self_tel=1)
    assert baseline.compute_baselines(conn, now=NOW) == 0


def test_compare_flags_deviation(conn):
    # build a tight baseline around count=100
    for c in (98, 100, 102, 99, 101):
        sid = _session(conn)
        _feat(conn, sid, "10.0.0.5", count=c)
    baseline.compute_baselines(conn, now=NOW)

    # a fresh session where the device sends 10x its norm
    live = _session(conn)
    _feat(conn, live, "10.0.0.5", count=1000)
    devs = baseline.compare_session(conn, live, z_threshold=3.0)
    counts = [d for d in devs if d["feature"] == "count"]
    assert counts and counts[0]["z"] > 3
    assert counts[0]["baseline_mean"] == 100.0


def test_compare_skips_devices_without_baseline(conn):
    live = _session(conn)
    _feat(conn, live, "10.0.0.99", count=5000)
    assert baseline.compare_session(conn, live) == []   # no baseline -> skip


def test_write_baseline_findings(conn):
    for c in (98, 100, 102, 99, 101):     # varied -> non-flat baseline
        sid = _session(conn)
        _feat(conn, sid, "10.0.0.5", count=c)
    baseline.compute_baselines(conn, now=NOW)
    live = _session(conn)
    _feat(conn, live, "10.0.0.5", count=100000)
    n = baseline.write_baseline_findings(conn, live)
    assert n >= 1
    row = conn.execute("SELECT * FROM findings WHERE layer='baseline'"
                       " LIMIT 1").fetchone()
    assert row["ip"] == "10.0.0.5" and row["rule"].startswith("deviation:")
