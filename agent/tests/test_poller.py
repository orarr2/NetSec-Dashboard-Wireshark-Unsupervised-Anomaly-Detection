"""The poller: the candidates of finished NETSEC sessions become cases, once each."""

from __future__ import annotations

import sqlite3
import time
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from agent import api
from agent.db import get_db
from agent.tests.builders import make_payload, write_netsec_db


@pytest.fixture
def source_db(tmp_path, vm_candidates, monkeypatch):
    path = tmp_path / "netsec" / "netsec.db"
    write_netsec_db(path, vm_candidates.values())
    monkeypatch.setenv("NETSEC_AGENT_SOURCE_DB", str(path))
    return path


def test_the_poller_is_off_without_a_source():
    assert api.create_app().state.poller is None


def test_one_pass_makes_a_case_of_every_candidate_and_the_next_pass_adds_none(source_db, vm_candidates):
    poller = api.create_app().state.poller
    first = poller.poll_once()
    assert (first["enabled"], first["sessions_seen"], first["submitted_total"], first["last_error"], first["polls"]) \
        == (True, 2, 11, None, 1)
    assert first["last_poll_at"] <= time.time()

    rows = get_db().list_cases()
    assert {(r["session_id"], r["candidate_id"]) for r in rows} == \
        {(v["session"]["id"], v["candidate_id"]) for v in vm_candidates.values()}
    assert Counter(r["action"] for r in rows) == {"standard": 3, "monitor": 8}
    assert {r["status"] for r in rows} == {"open", "closed"}
    # The older session is handled first.
    assert rows[-1]["session_id"] == 1

    second = poller.poll_once()
    assert (second["submitted_total"], second["polls"], second["last_error"]) == (11, 2, None)
    assert len(get_db().list_cases()) == 11


def test_the_source_database_is_not_changed_by_a_pass(source_db):
    def fingerprint():
        conn = sqlite3.connect(source_db)
        try:
            return {t: conn.execute(f"SELECT COUNT(*), COALESCE(MAX(rowid), 0) FROM {t}").fetchone()
                    for t in ("sessions", "candidates", "findings", "adv_signals", "fusion_scores", "verdicts")}
        finally:
            conn.close()

    before = fingerprint()
    api.create_app().state.poller.poll_once()
    assert fingerprint() == before


def test_a_session_is_left_alone_until_it_is_finished(tmp_path, monkeypatch):
    path = tmp_path / "netsec.db"
    write_netsec_db(path, [make_payload("10.0.0.5", session_id=5, rules=["scan_alerts"])], status={5: "running"})
    monkeypatch.setenv("NETSEC_AGENT_SOURCE_DB", str(path))
    poller = api.create_app().state.poller
    assert poller.poll_once()["submitted_total"] == 0

    conn = sqlite3.connect(path)
    conn.execute("UPDATE sessions SET status = 'done' WHERE id = 5")
    conn.commit()
    conn.close()
    assert poller.poll_once()["submitted_total"] == 1
    assert get_db().find_case(5, "10.0.0.5")["action"] == "standard"


def test_an_unreadable_source_is_reported_and_tried_again(tmp_path, monkeypatch, vm_candidates):
    path = tmp_path / "later" / "netsec.db"
    monkeypatch.setenv("NETSEC_AGENT_SOURCE_DB", str(path))
    poller = api.create_app().state.poller
    state = poller.poll_once()
    assert state["submitted_total"] == 0
    assert state["last_error"].startswith("OperationalError")

    write_netsec_db(path, [vm_candidates["1:192.168.1.10"]])
    state = poller.poll_once()
    assert (state["submitted_total"], state["last_error"]) == (1, None)


def test_a_candidate_the_service_refuses_is_skipped_and_reported_once(tmp_path, monkeypatch, caplog):
    path = tmp_path / "netsec.db"
    write_netsec_db(path, [make_payload("10.0.0.5\x07", session_id=9),
                           make_payload("10.0.0.6", session_id=9, rules=["scan_alerts"])])
    monkeypatch.setenv("NETSEC_AGENT_SOURCE_DB", str(path))
    poller = api.create_app().state.poller
    with caplog.at_level("WARNING", logger="netsec_agent"):
        assert poller.poll_once()["submitted_total"] == 1
        assert poller.poll_once()["submitted_total"] == 1
    assert sum("poll_candidate_rejected" in record.getMessage() for record in caplog.records) == 1
    assert [r["candidate_id"] for r in get_db().list_cases()] == ["10.0.0.6"]


def test_the_lookback_bounds_how_far_back_a_pass_reads(tmp_path, monkeypatch):
    path = tmp_path / "netsec.db"
    write_netsec_db(path, [make_payload("10.0.0.5", session_id=n, sha256=f"{n:064x}") for n in (1, 2, 3)])
    monkeypatch.setenv("NETSEC_AGENT_SOURCE_DB", str(path))
    monkeypatch.setenv("NETSEC_AGENT_POLL_LOOKBACK", "2")
    state = api.create_app().state.poller.poll_once()
    assert (state["sessions_seen"], state["submitted_total"]) == (2, 2)
    assert {r["session_id"] for r in get_db().list_cases()} == {2, 3}


def test_the_service_runs_the_poller_while_it_is_up(source_db, monkeypatch):
    monkeypatch.setenv("NETSEC_AGENT_POLL_SECONDS", "0.2")
    app = api.create_app()
    with TestClient(app) as client:
        deadline = time.time() + 60
        items: list[dict] = []
        while time.time() < deadline:
            items = client.get("/cases/history?limit=50").json()["items"]
            # The first pass is over once it has been counted; by then every case has its verdict.
            if len(items) == 11 and app.state.poller.snapshot()["polls"] >= 1:
                break
            time.sleep(0.1)
        assert len(items) == 11
        assert {i["status"] for i in items} == {"open", "closed"}
        poller = client.get("/status").json()["data"]["poller"]
        assert (poller["enabled"], poller["interval_s"], poller["last_error"]) == (True, 0.2, None)
        assert poller["submitted_total"] == 11
    assert app.state.poller._thread is None
