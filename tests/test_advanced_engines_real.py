"""The advanced-threat engines, verified against REAL captures.

The five deterministic + info-theoretic engines in app/advanced_engines.py
(ARP/DHCP, DNS tunnelling, DGA, beaconing, TLS) have thresholds that were
set by reasoning, not measured. This suite proves each un-covered signal
actually fires on a real, reputable capture that exhibits the behaviour -
and, just as important, that the high-severity engines stay QUIET on
benign home traffic (the false-positive guard).

Every capture is declared in attack_tests/advanced/sources.json. Small
redistributable ones are committed under attack_tests/advanced/pcaps/;
the rest are fetched on demand (attack_tests/advanced/fetch.py) into a
gitignored cache. A capture that has not been fetched is SKIPPED, so this
suite never fails for lack of a download and never blocks offline CI.

The whole module is skipped when tshark is not on PATH - the engines
shell out to it, so without it there is nothing to test.
"""
import json
import os
import shutil
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADV = os.path.join(REPO, "attack_tests", "advanced")
sys.path.insert(0, os.path.join(REPO, "app"))
sys.path.insert(0, ADV)

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="tshark not on PATH - the advanced engines need it")


def _load_registry():
    reg = os.path.join(ADV, "sources.json")
    if not os.path.isfile(reg):
        return []
    return json.load(open(reg, encoding="utf-8")).get("captures", [])


def _fired(pcap_path, label):
    """{signal: {'count', 'severity'}} for one capture."""
    from advanced_engines import run_advanced_threats
    r = run_advanced_threats(pcap_path, label)
    assert r.get("available"), f"engines unavailable: {r.get('reason')}"
    out = {}
    order = {"low": 0, "medium": 1, "high": 2}
    for rows in r["per_engine"].values():
        for row in rows:
            cur = out.setdefault(row["signal"], {"count": 0, "severity": "low"})
            cur["count"] += 1
            if order.get(row.get("severity"), 0) > order.get(cur["severity"], 0):
                cur["severity"] = row.get("severity")
    return out


_REGISTRY = _load_registry()
_HIGH_SEV = {
    "beaconing", "dns_tunneling", "dga_domain", "nxdomain_storm",
    "rogue_dhcp", "arp_mac_many_ips", "arp_ip_multi_mac",
    "arp_gratuitous_flood", "sni_ip_mismatch",
}


@pytest.mark.skipif(not _REGISTRY, reason="sources.json empty - no captures declared")
@pytest.mark.parametrize("entry", _REGISTRY, ids=[e["family"] for e in _REGISTRY])
def test_expected_signals_fire(entry):
    """Each registered capture must produce the signals its family targets,
    at or above the registry's minimum count."""
    from fetch import resolve_path
    path = resolve_path(entry)
    if not os.path.isfile(path):
        pytest.skip(f"{entry['file']} not fetched "
                    f"(run attack_tests/advanced/fetch.py {entry['family']})")
    fired = _fired(path, entry["family"])
    expected = entry.get("expected_signals") or {}
    assert expected, f"{entry['family']}: registry declares no expected_signals"
    for sig, min_count in expected.items():
        assert sig in fired, (
            f"{entry['family']}: expected {sig} to fire on {entry['file']}, "
            f"got {sorted(fired)}")
        assert fired[sig]["count"] >= min_count, (
            f"{entry['family']}: {sig} fired {fired[sig]['count']}x, "
            f"expected >= {min_count}")


def test_benign_home_stays_quiet_on_high_severity():
    """The false-positive guard: normal home browsing must not trip any
    high-severity advanced signal. Low-severity hints (a lone new JA3, an
    SNI-less handshake) are allowed - they are explicitly not incidents."""
    benign = os.path.join(REPO, "attack_tests", "pcaps", "benign_home.pcapng")
    if not os.path.isfile(benign):
        pytest.skip("benign_home.pcapng not present")
    fired = _fired(benign, "benign")
    offenders = {s: v for s, v in fired.items()
                 if s in _HIGH_SEV and v["severity"] in ("medium", "high")}
    assert not offenders, (
        f"benign traffic tripped high-severity advanced signals: {offenders}")
