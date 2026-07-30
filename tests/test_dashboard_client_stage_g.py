"""Stage G regression: the dashboard's VM client helpers - HTTP upload
(scp replacement) and load-session-for-remote-viewing. No notebook import
and no network; the transport is injected.
"""
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from server import dashboard_client as dc  # noqa: E402


def test_upload_requires_config(tmp_path, monkeypatch):
    for var in ("NETSEC_INGEST_URL", "NETSEC_SENSOR_ID",
                "NETSEC_SENSOR_SECRET"):
        monkeypatch.delenv(var, raising=False)
    pcap = tmp_path / "c.pcap"
    pcap.write_bytes(b"x")
    r = dc.upload_session_via_api(str(pcap))
    assert r["ok"] is False and "NETSEC_INGEST_URL" in r["error"]


def test_upload_missing_file(monkeypatch):
    monkeypatch.setenv("NETSEC_INGEST_URL", "http://vm:8766")
    monkeypatch.setenv("NETSEC_SENSOR_ID", "s")
    monkeypatch.setenv("NETSEC_SENSOR_SECRET", "sec")
    r = dc.upload_session_via_api("/no/such.pcap")
    assert r["ok"] is False and "no such PCAP" in r["error"]


def test_load_session_not_done():
    calls = {}

    def fake_get(path):
        calls["path"] = path
        return {"id": 5, "status": "running"}

    out = dc.load_session_from_api(5, api_url="http://vm:8766",
                                   token="t", get_fn=fake_get)
    assert out["verdicts"] is None
    assert "running" in out["note"]
    assert calls["path"] == "/v1/sessions/5"


def test_load_session_done_fetches_verdicts():
    responses = {
        "/v1/sessions/7": {"id": 7, "status": "done", "sha256": "ab" * 32},
        "/v1/reports/7.json": {"results": [{"verdict": {"verdict":
                                                        "malicious"}}]},
    }
    out = dc.load_session_from_api(7, api_url="http://vm:8766", token="t",
                                   get_fn=lambda p: responses[p])
    assert out["session"]["id"] == 7
    assert out["verdicts"]["results"][0]["verdict"]["verdict"] == "malicious"


def test_load_session_missing_url_raises(monkeypatch):
    monkeypatch.delenv("NETSEC_INGEST_URL", raising=False)
    with pytest.raises(RuntimeError):
        dc.load_session_from_api(1, api_url=None)


def test_load_session_fetch_error_is_actionable():
    def boom(path):
        raise ConnectionError("refused")

    with pytest.raises(RuntimeError) as e:
        dc.load_session_from_api(9, api_url="http://vm:8766",
                                 get_fn=boom)
    assert "could not fetch session 9" in str(e.value)
