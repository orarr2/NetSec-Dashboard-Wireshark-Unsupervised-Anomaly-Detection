"""Stage YA regression: OSINT enrichment (Wigle + Shodan), the threat-
intel scorer and its priority activation, the worker re-rank, and the geo
map. Every external call is injected - no network, no API keys.
"""
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "llm_judge"))

from server import auth, db, enrich, report_map, worker  # noqa: E402
import judge_core  # noqa: E402
import threat_intel  # noqa: E402


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "netsec.db"))
    yield c
    c.close()


# ---- migration v2 --------------------------------------------------------

def test_schema_v2_migrated(conn):
    # v2 was the enrichment table + reports.kind widened to include 'map'.
    # Later migrations (v3 added sessions.notify_email) preserve the v2
    # artefacts, which is what this test still guards.
    assert conn.execute("PRAGMA user_version").fetchone()[0] >= 2
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "enrichment" in tables
    # reports now allows 'map'
    sid_pcap, _ = db.register_pcap(conn, "aa" * 32, "c", 1, 1, "/x")
    sid = db.create_session(conn, sid_pcap, "S", "prod")
    rid = db.add_report(conn, sid, "map", "/x/map.html")
    assert rid and db.get_report(conn, sid, "map")["path"] == "/x/map.html"


def test_enrichment_cache_roundtrip_and_staleness(conn):
    db.put_enrichment(conn, "shodan_ip", "1.2.3.4", {"ports": [80]})
    assert db.get_enrichment(conn, "shodan_ip", "1.2.3.4")["data"][
        "ports"] == [80]
    # a 0-day max-age treats any stored row as stale
    assert db.get_enrichment(conn, "shodan_ip", "1.2.3.4",
                             max_age_days=-1) is None
    assert db.get_enrichment(conn, "shodan_ip", "9.9.9.9") is None


# ---- Wigle ---------------------------------------------------------------

def test_wigle_lookup_caches(conn):
    calls = {"n": 0}

    def fake(bssid):
        calls["n"] += 1
        return {"ssid": "MyAP", "lat": 32.1, "lon": 34.8, "country": "IL"}

    a = enrich.wigle_bssid(conn, "AA:BB:CC:DD:EE:FF", fetch_fn=fake)
    b = enrich.wigle_bssid(conn, "aa:bb:cc:dd:ee:ff", fetch_fn=fake)
    assert a["lat"] == 32.1 and b == a
    assert calls["n"] == 1                     # second call served from cache


def test_wigle_no_key_returns_none(conn, monkeypatch):
    for v in ("WIGLE_API_NAME", "WIGLE_API_TOKEN", "WIGLE_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    assert enrich.wigle_bssid(conn, "aa:bb:cc:dd:ee:ff") is None


# ---- Shodan + threat intel ----------------------------------------------

def test_shodan_only_public_ips(conn):
    assert enrich.shodan_ip(conn, "192.168.1.5",
                            fetch_fn=lambda ip: {"ports": [1]}) is None
    got = enrich.shodan_ip(conn, "8.8.8.8",
                           fetch_fn=lambda ip: {"ports": [53], "vulns": [],
                                                "tags": []})
    assert got["ports"] == [53]


def test_ti_score_weighting():
    assert threat_intel.ti_score(None) == 0.0
    assert threat_intel.ti_score({"ports": [80], "vulns": [], "tags": []}) \
        == 0.0
    # two CVEs -> 0.4, malicious tag -> +0.4
    s = threat_intel.ti_score({"vulns": ["CVE-1", "CVE-2"],
                               "tags": ["c2"], "ports": []})
    assert s == pytest.approx(0.8)
    assert threat_intel.ti_score({"vulns": ["a", "b", "c", "d"],
                                  "tags": ["malware"], "ports": list(
                                      range(20))}) == 1.0   # capped


def test_priority_score_ti_default_is_unchanged():
    """A candidate without ti_signals must score exactly as before the
    weight was activated - this is what keeps the old judge tests valid."""
    cand = {"ml_signals": {"iso_score": 0.0}}
    verdict = {"confidence": 0.5, "category": "port_scan"}
    base = judge_core.priority_score(cand, verdict, None, None)
    cand_ti = dict(cand, ti_signals={"score": 1.0})
    hot = judge_core.priority_score(cand_ti, verdict, None, None)
    assert hot == round(base + judge_core.judge_config.W_TI, 4)
    assert hot > base


# ---- worker re-rank ------------------------------------------------------

def test_worker_threat_intel_rerank(conn, monkeypatch):
    monkeypatch.setenv("NETSEC_ENABLE_SHODAN", "1")
    import collections
    # both peers are globally routable; 45.33.32.156 is the flagged one
    S = {"ip_pairs": collections.Counter({("10.0.0.5", "8.8.8.8"): 10,
                                           ("10.0.0.5", "45.33.32.156"): 3})}
    assembled = {"candidates": [
        {"candidate_id": "10.0.0.5", "kind": "ip",
         "ml_signals": {"iso_score": 0.0}},
        {"candidate_id": "10.0.0.6", "kind": "ip",
         "ml_signals": {"iso_score": 0.0}}]}
    out = {"results": [
        {"candidate_id": "10.0.0.6", "verdict": {"confidence": 0.5,
         "category": "port_scan"}, "priority": 0.5},
        {"candidate_id": "10.0.0.5", "verdict": {"confidence": 0.5,
         "category": "port_scan"}, "priority": 0.5}]}

    def fake_shodan(ip):
        return {"vulns": ["CVE-x", "CVE-y", "CVE-z"], "tags": ["c2"],
                "ports": []} if ip == "45.33.32.156" else None

    n = worker.enrich_threat_intel(conn, out, assembled, S,
                                   shodan_fn=fake_shodan)
    assert n == 1
    # 10.0.0.5 (talks to the flagged host) now outranks 10.0.0.6
    assert out["results"][0]["candidate_id"] == "10.0.0.5"
    assert out["results"][0]["ti_signals"]["score"] == 1.0


def test_worker_rerank_off_without_env(conn, monkeypatch):
    monkeypatch.delenv("NETSEC_ENABLE_SHODAN", raising=False)
    out = {"results": [{"candidate_id": "x", "verdict": {}, "priority": 1}]}
    assert worker.enrich_threat_intel(conn, out, {"candidates": []},
                                      {}, shodan_fn=lambda ip: {}) == 0


def test_shodan_toggle_fail_closed(monkeypatch):
    """NETSEC_ENABLE_SHODAN gates a paid external lookup; the parser must
    default OFF for the common .env pitfall of leaving an inline comment
    on the value (some parsers keep '0    # comment' as the whole value).
    Also normalizes case/whitespace and rejects garbage."""
    from server.worker import _shodan_enabled
    # Off cases
    for v in ("", "  ", "0", "false", "FALSE", "off", "no",
              "0    # 1 = look up external peers on Shodan",
              "0\t# comment", "definitely-not-a-truthy-value"):
        monkeypatch.setenv("NETSEC_ENABLE_SHODAN", v)
        assert _shodan_enabled() is False, f"should be off: {v!r}"
    monkeypatch.delenv("NETSEC_ENABLE_SHODAN", raising=False)
    assert _shodan_enabled() is False
    # On cases (fail-closed: must be explicit)
    for v in ("1", "true", "TRUE", "yes", "on", "1 # note"):
        monkeypatch.setenv("NETSEC_ENABLE_SHODAN", v)
        assert _shodan_enabled() is True, f"should be on: {v!r}"


# ---- geo map -------------------------------------------------------------

def test_map_render_places_points(tmp_path):
    points = [{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Home",
               "lat": 32.08, "lon": 34.78, "rssi": -55, "distance_m": 4.2}]
    out = report_map.render(points, str(tmp_path / "map.html"))
    html = open(out, encoding="utf-8").read()
    assert "32.08" in html and "34.78" in html
    assert "Home" in html and "leaflet" in html.lower()


def test_map_render_empty_is_valid(tmp_path):
    out = report_map.render([{"bssid": "x", "lat": None, "lon": None}],
                            str(tmp_path / "map.html"))
    html = open(out, encoding="utf-8").read()
    assert "No geolocated access points" in html


def test_build_map_report_uses_wigle(conn):
    S = {"wifi_bssid": "AA:BB:CC:DD:EE:FF", "wifi_ssid": "Home",
         "wlan_features": {}}
    import tempfile
    out_path = os.path.join(tempfile.mkdtemp(), "map.html")

    def fake_wigle(bssid):
        return {"lat": 32.0, "lon": 34.8, "ssid": "Home"}

    got = worker.build_map_report(conn, S, out_path, wigle_fn=fake_wigle)
    assert got == out_path
    assert "32.0" in open(out_path, encoding="utf-8").read()
    # no located APs -> no map file
    assert worker.build_map_report(conn, {"wifi_bssid": "x"}, out_path,
                                   wigle_fn=lambda b: None) is None
