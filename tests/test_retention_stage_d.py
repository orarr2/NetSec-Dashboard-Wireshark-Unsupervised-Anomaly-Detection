"""Stage D regression: retention (age + watermark + fields backfill +
DB backup) and the external watchdog's alert state machine. Stdlib only.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

from server import auth, db, retention  # noqa: E402
import watchdog  # noqa: E402


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@pytest.fixture
def env(tmp_path):
    conn = db.connect(str(tmp_path / "netsec.db"))
    db.create_sensor(conn, "s", auth.hash_token("t"), "sec")
    sensor = db.get_sensor(conn, "s")
    yield conn, sensor, str(tmp_path)
    conn.close()


def _add_pcap(conn, tmp, sensor, sha_prefix, age_days):
    sha = sha_prefix * 32
    path = os.path.join(tmp, f"{sha[:8]}.pcap")
    with open(path, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + sha_prefix.encode() * 100)
    pcap_id, _ = db.register_pcap(conn, sha, "c.pcap", 100, sensor["id"],
                                  path)
    received = _iso(datetime.now(timezone.utc) - timedelta(days=age_days))
    conn.execute("UPDATE pcap_files SET received_at=? WHERE id=?",
                 (received, pcap_id))
    conn.commit()
    return pcap_id, path, sha


def _fake_export(calls):
    def fn(pcap_path, out_path):
        calls.append((pcap_path, out_path))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(b"fields")
        return True
    return fn


def test_age_purge_backfills_fields_and_marks_deleted(env):
    conn, sensor, tmp = env
    old_id, old_path, old_sha = _add_pcap(conn, tmp, sensor, "a", 9)
    new_id, new_path, _ = _add_pcap(conn, tmp, sensor, "b", 2)
    calls = []

    purged = retention.purge_by_age(conn, tmp, days=7,
                                    export_fn=_fake_export(calls))
    assert purged == 1
    assert not os.path.exists(old_path)          # raw gone
    assert os.path.exists(new_path)              # young file untouched

    row = dict(conn.execute("SELECT * FROM pcap_files WHERE id=?",
                            (old_id,)).fetchone())
    assert row["deleted_at"] is not None
    assert row["fields_path"] and os.path.exists(row["fields_path"])
    assert calls and calls[0][0] == old_path     # index built BEFORE purge

    fresh = dict(conn.execute("SELECT * FROM pcap_files WHERE id=?",
                              (new_id,)).fetchone())
    assert fresh["deleted_at"] is None


def test_purge_skipped_when_index_not_producible(env):
    conn, sensor, tmp = env
    _, path, _ = _add_pcap(conn, tmp, sensor, "c", 30)
    purged = retention.purge_by_age(conn, tmp, days=7,
                                    export_fn=lambda p, o: False)
    assert purged == 0
    assert os.path.exists(path)                  # raw NOT lost
    row = conn.execute("SELECT deleted_at FROM pcap_files").fetchone()
    assert row["deleted_at"] is None


def test_watermark_purges_oldest_first(env):
    conn, sensor, tmp = env
    _, p_old, _ = _add_pcap(conn, tmp, sensor, "d", 5)
    _, p_new, _ = _add_pcap(conn, tmp, sensor, "e", 1)
    usage = iter([90.0, 70.0])                   # drops after one purge

    purged = retention.purge_by_watermark(
        conn, tmp, pct=85, export_fn=_fake_export([]),
        usage_fn=lambda root: next(usage))
    assert purged == 1
    assert not os.path.exists(p_old) and os.path.exists(p_new)


def test_watermark_stops_when_nothing_left(env):
    conn, _, tmp = env
    purged = retention.purge_by_watermark(conn, tmp, pct=85,
                                          usage_fn=lambda root: 99.0)
    assert purged == 0                           # no infinite loop


def test_dry_run_deletes_nothing(env):
    conn, sensor, tmp = env
    _, path, _ = _add_pcap(conn, tmp, sensor, "f", 30)
    summary = retention.run_cycle(conn, root=tmp, dry_run=True,
                                  export_fn=_fake_export([]),
                                  usage_fn=lambda root: 10.0)
    assert summary["purged_age"] == 1            # reported...
    assert os.path.exists(path)                  # ...but not deleted
    row = conn.execute("SELECT deleted_at FROM pcap_files").fetchone()
    assert row["deleted_at"] is None
    assert not os.path.exists(summary["backup"])  # backup skipped too


def test_backup_creates_and_prunes(env):
    conn, _, tmp = env
    for day in (1, 2, 3):
        retention.backup_db(conn, tmp, keep=2,
                            now=datetime(2026, 7, day,
                                         tzinfo=timezone.utc))
    bdir = os.path.join(tmp, "db", "backups")
    assert sorted(os.listdir(bdir)) == ["netsec-20260702.db",
                                        "netsec-20260703.db"]


def test_full_cycle_summary(env):
    conn, sensor, tmp = env
    _add_pcap(conn, tmp, sensor, "9", 9)
    summary = retention.run_cycle(conn, root=tmp,
                                  export_fn=_fake_export([]),
                                  usage_fn=lambda root: 10.0,
                                  now=datetime(2026, 7, 30,
                                               tzinfo=timezone.utc))
    assert summary["purged_age"] == 1
    assert summary["purged_watermark"] == 0
    assert summary["vacuum"] is False            # not the 1st of the month
    assert os.path.isfile(summary["backup"])


# ---- watchdog ------------------------------------------------------------

def test_watchdog_alerts_once_and_recovers():
    health = iter([True, False, False, False, False, True])
    alerts = []
    state = watchdog.run_loop(
        "http://vm/healthz", "a@b.co", interval=0, failures=3,
        check_fn=lambda: next(health),
        alert_fn=lambda subj, body: (alerts.append(subj), (True, "ok"))[1],
        sleep_fn=lambda s: None, max_cycles=6)
    assert len(alerts) == 2                      # one DOWN, one RECOVERED
    assert alerts[0].startswith("DOWN") and alerts[1].startswith("RECOVERED")
    assert state["alerted"] is False and state["misses"] == 0


def test_watchdog_no_alert_below_threshold():
    health = iter([False, False, True, True])
    alerts = []
    watchdog.run_loop("u", "a@b.co", interval=0, failures=3,
                      check_fn=lambda: next(health),
                      alert_fn=lambda s, b: (alerts.append(s), (True, ""))[1],
                      sleep_fn=lambda s: None, max_cycles=4)
    assert alerts == []


def test_watchdog_alert_requires_smtp_config():
    ok, msg = watchdog.send_alert("s", "b", "to@x.co", env={})
    assert ok is False and "not configured" in msg
