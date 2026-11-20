"""The agent's own SQLite store."""

from __future__ import annotations

import sqlite3
import time

import pytest

from agent.adapter import normalize_case
from agent.db import Database, db_path, get_db, new_id, reset_db_registry
from agent.tests.builders import SHA256, make_payload

TABLES = {"cases", "approvals", "work_orders", "agent_notes", "agent_feedback", "decision_cache", "catalogue"}


def _case(candidate: str = "10.0.0.5", **spec) -> dict:
    return normalize_case(make_payload(candidate, **spec), {})


def test_the_file_and_its_tables_appear_on_first_use(tmp_path):
    path = tmp_path / "nested" / "agent.db"
    db = Database(str(path))
    assert not path.exists()
    assert db.ready() is True
    assert path.exists()
    with db.connect() as conn:
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert TABLES <= tables


def test_a_path_that_cannot_hold_a_database_is_not_ready(tmp_path):
    assert Database(str(tmp_path)).ready() is False


def test_a_new_case_is_queued_with_what_the_engines_said():
    db = get_db()
    metadata = {"technique": "T1046", "score": 0.9, "asset_role": "unknown", "engines": {"rules": ["scan_alerts"]}}
    row = db.create_case("ns_1", _case(rules=["scan_alerts"]), metadata)
    assert (row["id"], row["status"], row["action"], row["priority"], row["decided_at"]) == ("ns_1", "queued", "", 0, None)
    assert (row["session_id"], row["candidate_id"], row["kind"], row["pcap_sha256"], row["pcap_name"]) == \
        (900, "10.0.0.5", "ip", SHA256, "synthetic.pcap")
    assert (row["technique"], row["score"], row["asset_role"], row["engines_json"]) == \
        ("T1046", 0.9, "unknown", '{"rules": ["scan_alerts"]}')
    assert (row["trace_json"], row["cited_sources_json"]) == ("[]", "[]")
    assert db.find_case(900, "10.0.0.5")["id"] == "ns_1"
    assert db.find_case(900, "10.0.0.6") is None
    assert db.find_case(None, "10.0.0.5") is None
    assert db.get_case("ns_missing") is None


def test_one_case_per_candidate_of_a_session():
    db = get_db()
    db.create_case("ns_1", _case())
    with pytest.raises(sqlite3.IntegrityError):
        db.create_case("ns_2", _case())
    db.create_case("ns_3", _case("10.0.0.6"))
    db.create_case("ns_4", _case(session_id=None))
    db.create_case("ns_5", _case(session_id=None))
    assert len(db.list_cases()) == 4


def test_update_list_and_interrupted_cases():
    db = get_db()
    for index in range(3):
        db.create_case(f"ns_{index}", _case(f"10.0.0.{index}"))
    db.update_case("ns_0", status="open", action="standard", priority=60, decided_at=time.time())
    db.update_case("ns_1", status="processing")
    db.update_case("ns_2", submitted_at=time.time() - 3 * 3600)
    db.update_case("ns_2")
    assert (db.get_case("ns_0")["status"], db.get_case("ns_0")["action"], db.get_case("ns_0")["priority"]) == \
        ("open", "standard", 60)
    assert {row["id"] for row in db.interrupted_cases()} == {"ns_1", "ns_2"}
    assert {row["id"] for row in db.list_cases(since=time.time() - 3600)} == {"ns_0", "ns_1"}
    assert [row["id"] for row in db.list_cases()][-1] == "ns_2"
    assert len(db.list_cases(limit=2)) == 2


def test_pending_approvals_come_highest_priority_first():
    db = get_db()
    low = db.create_approval("ns_1", "human_review", 30)
    high = db.create_approval("ns_2", "urgent", 90)
    mid = db.create_approval("ns_3", "human_review", 55)
    assert all(value.startswith("apr_") for value in (low, high, mid))
    assert [row["id"] for row in db.list_pending_approvals()] == [high, mid, low]
    assert [row["id"] for row in db.list_pending_approvals(limit=1)] == [high]
    row = db.approvals_for_case("ns_2")[0]
    assert (row["action"], row["priority"], row["status"], row["decided_at"], row["decided_by"], row["note"]) == \
        ("urgent", 90, "pending", None, None, None)
    with db.connect() as conn:
        conn.execute("UPDATE approvals SET status = 'approved' WHERE id = ?", (high,))
    assert [row["id"] for row in db.list_pending_approvals()] == [mid, low]


def test_work_orders_notes_and_feedback():
    db = get_db()
    order_id = db.create_work_order("ns_1", "ticket", "standard: T1046 on 10.0.0.5", "body")
    order = db.work_orders_for_case("ns_1")[0]
    assert (order["id"], order["kind"], order["status"], order["title"]) == \
        (order_id, "ticket", "draft", "standard: T1046 on 10.0.0.5")
    assert db.work_orders_for_case("ns_2") == []

    db.add_note("T1046", "unknown", "a scan from the lab laptop was approved as benign", "apr_1")
    db.add_note("T1046", "Network Infrastructure", "a scan from the gateway was escalated")
    db.add_note(None, None, "a lesson with no technique")
    assert len(db.recall_notes("T1046")) == 2
    assert [n["lesson"] for n in db.recall_notes("T1046", "unknown")] == \
        ["a scan from the lab laptop was approved as benign"]
    assert [n["lesson"] for n in db.recall_notes(None)] == ["a lesson with no technique"]
    assert db.recall_notes("T1557.002") == []

    first = db.add_feedback("ns_1", "finding", "agree", "analyst")
    second = db.add_feedback("ns_1", "priority", "too_low")
    assert second == first + 1


def test_the_decision_cache_expires():
    db = get_db()
    db.cache_put("10.0.0.5|scan", {"action": "standard"})
    db.cache_put("10.0.0.5|scan", {"action": "urgent"})
    db.cache_put("old", {"action": "monitor"}, ttl_s=-1)
    assert db.cache_get("10.0.0.5|scan") == {"action": "urgent"}
    assert db.cache_get("old") is None
    assert db.cache_get("missing") is None


def test_the_catalogue_is_keyed_by_capture_and_candidate():
    db = get_db()
    entry_id = db.catalogue_add(SHA256.upper(), "10.0.0.5", label="scan", action="standard", source="approved_case",
                                case_id="ns_1")
    assert entry_id.startswith("cat_")
    match = db.catalogue_lookup(SHA256, "10.0.0.5")
    assert (match["id"], match["label"], match["action"], match["source"], match["case_id"]) == \
        (entry_id, "scan", "standard", "approved_case", "ns_1")
    assert db.catalogue_lookup(SHA256.upper(), "10.0.0.5")["id"] == entry_id
    assert db.catalogue_lookup(SHA256, "10.0.0.6") is None
    assert db.catalogue_lookup("cd" * 32, "10.0.0.5") is None
    assert db.catalogue_lookup(None, "10.0.0.5") is None
    assert db.catalogue_lookup("", "10.0.0.5") is None
    assert db.catalogue_lookup(SHA256, None) is None
    # A second entry for the same capture and candidate replaces the first and keeps its id.
    again = db.catalogue_add(SHA256, "10.0.0.5", label="scan, confirmed", action="urgent", source="attack_tests")
    assert again == entry_id
    assert db.catalogue_lookup(SHA256, "10.0.0.5")["label"] == "scan, confirmed"


def test_an_in_memory_database_keeps_its_rows_between_calls():
    db = Database(":memory:")
    db.create_case("ns_1", _case())
    assert db.get_case("ns_1")["status"] == "queued"
    assert db.ready() is True


def test_one_database_object_per_path(tmp_path, monkeypatch):
    assert get_db() is get_db()
    assert get_db().path == db_path()
    other = get_db(str(tmp_path / "other.db"))
    assert other is not get_db()
    assert other is get_db(str(tmp_path / "other.db"))
    first = get_db()
    reset_db_registry()
    assert get_db() is not first
    monkeypatch.delenv("NETSEC_AGENT_DB_PATH")
    assert db_path() == "/var/lib/netsec-agent/netsec-agent.db"


def test_new_ids_are_prefixed_and_unique():
    ids = {new_id("ns") for _ in range(200)}
    assert len(ids) == 200
    assert all(len(value) == 15 and value.startswith("ns_") for value in ids)
