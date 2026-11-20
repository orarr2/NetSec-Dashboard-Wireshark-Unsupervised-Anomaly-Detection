"""Reading NETSEC's database: read-only, and in the shape the agents take."""

from __future__ import annotations

import sqlite3

import pytest

from agent import netsec_source
from agent.tests.builders import make_payload, write_netsec_db


@pytest.fixture
def source_db(tmp_path, vm_candidates):
    path = tmp_path / "netsec" / "netsec.db"
    write_netsec_db(path, vm_candidates.values())
    return path


def _read(path, limit: int = 50) -> tuple[list[dict], list[dict]]:
    conn = netsec_source.connect(str(path))
    try:
        sessions = netsec_source.finished_sessions(conn, limit)
        return sessions, [p for s in sessions for p in netsec_source.candidate_payloads(conn, s)]
    finally:
        conn.close()


def test_the_reader_reproduces_the_candidates_exported_from_the_machine(source_db, vm_candidates):
    sessions, payloads = _read(source_db)
    assert [(s["id"], s["n_candidates"], s["orig_name"]) for s in sessions] == \
        [(1, 1, "tcp_syn_scan.pcap"), (2, 10, "arpspoof.pcap")]
    assert {f"{p['session']['id']}:{p['candidate_id']}": p for p in payloads} == vm_candidates
    # Within a session the candidates come in the pipeline's own rank order.
    assert [p["rank"] for p in payloads if p["session"]["id"] == 2] == sorted(
        v["rank"] for v in vm_candidates.values() if v["session"]["id"] == 2)


def test_only_finished_sessions_are_listed_oldest_first_within_the_lookback(tmp_path):
    payloads = [make_payload("10.0.0.1", session_id=n, sha256=f"{n:064x}") for n in (1, 2, 3, 4)]
    path = tmp_path / "netsec.db"
    write_netsec_db(path, payloads, status={2: "running", 4: "error"})
    assert [s["id"] for s in _read(path)[0]] == [1, 3]
    assert [s["id"] for s in _read(path, limit=1)[0]] == [3]


def test_the_connection_cannot_write(source_db):
    conn = netsec_source.connect(str(source_db))
    try:
        for statement in ("UPDATE sessions SET label = 'x'", "DELETE FROM candidates", "CREATE TABLE t (a)",
                          "PRAGMA user_version = 99"):
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(statement)
        assert conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 11
    finally:
        conn.close()


def test_a_missing_database_is_an_error_and_is_not_created(tmp_path):
    missing = tmp_path / "nowhere" / "netsec.db"
    with pytest.raises(sqlite3.OperationalError):
        netsec_source.connect(str(missing))
    assert not missing.parent.exists()


def test_a_session_level_candidate_gets_the_aggregate_findings_only(tmp_path):
    flood = make_payload("session:S1", kind="session", rules=["flood_alerts"], session_id=7)
    flood["findings"] = [{"layer": "rules", "rule": "flood_alerts", "ip": None, "severity": "high",
                          "detail": {"total_syn": 60000}}]
    host = make_payload("10.0.0.5", rules=["scan_alerts"], session_id=7)
    host["rank"] = 1
    host["findings"] = [{"layer": "rules", "rule": "scan_alerts", "ip": "10.0.0.5", "severity": "high",
                         "detail": {"count": 800}}]
    path = tmp_path / "netsec.db"
    write_netsec_db(path, [flood, host])
    by = {p["candidate_id"]: p for p in _read(path)[1]}
    assert [f["rule"] for f in by["session:S1"]["findings"]] == ["flood_alerts"]
    assert [f["rule"] for f in by["10.0.0.5"]["findings"]] == ["scan_alerts"]
    assert (by["session:S1"]["kind"], by["session:S1"]["ip_features"], by["session:S1"]["judge_verdict"]) == \
        ("session", {}, None)


def test_a_context_that_is_not_json_becomes_an_empty_context(tmp_path):
    path = tmp_path / "netsec.db"
    write_netsec_db(path, [make_payload("10.0.0.5", session_id=3)])
    conn = sqlite3.connect(path)
    conn.execute("UPDATE candidates SET context_json = 'not json'")
    conn.commit()
    conn.close()
    assert _read(path)[1][0]["context"] == {}
