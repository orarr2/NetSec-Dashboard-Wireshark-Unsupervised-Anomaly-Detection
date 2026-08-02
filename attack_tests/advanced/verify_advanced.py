#!/usr/bin/env python3
"""Run the six advanced-threat engines against every registered real
capture and print a fire/quiet matrix.

This is the on-demand companion to `tests/test_advanced_engines_real.py`:
the pytest asserts the expected signals fire (and stay skipped when a
fetch-only capture is absent), while this script is for eyeballing what
each capture actually produces - which is how you decide the expected
set in the first place.

    python attack_tests/advanced/fetch.py          # get the captures
    python attack_tests/advanced/verify_advanced.py

For each capture it prints the signals that fired with their counts and
peak severity, then flags any MISS against the registry's
`expected_signals`, and separately re-runs the benign baseline to prove
the high-severity engines stay quiet on normal traffic (the
false-positive guard).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "app"))

from advanced_engines import run_advanced_threats  # noqa: E402
from fetch import load_registry, resolve_path       # noqa: E402

# Signals that must NEVER fire on benign traffic at high severity - the
# false-positive guard. rare_ja3 / tls_no_sni are low-severity by design
# (a lone new client is not an incident) so they are allowed on benign.
HIGH_SEV_SIGNALS = {
    "beaconing", "dns_tunneling", "dga_domain", "nxdomain_storm",
    "rogue_dhcp", "arp_mac_many_ips", "arp_ip_multi_mac",
    "arp_gratuitous_flood", "sni_ip_mismatch",
}


def summarize(pcap_path, label):
    r = run_advanced_threats(pcap_path, label)
    if not r.get("available"):
        return None, r.get("reason")
    fired = {}
    for rows in r["per_engine"].values():
        for row in rows:
            s = row["signal"]
            cur = fired.setdefault(s, {"count": 0, "severity": "low"})
            cur["count"] += 1
            order = {"low": 0, "medium": 1, "high": 2}
            if order.get(row.get("severity"), 0) > order.get(cur["severity"], 0):
                cur["severity"] = row.get("severity")
    return fired, r.get("n_packets")


def main():
    caps = load_registry()
    if not caps:
        print("registry empty - populate sources.json first")
        return 1
    misses = 0
    print("=" * 72)
    for e in caps:
        path = resolve_path(e)
        if not os.path.isfile(path):
            print(f"{e['family']:20s} SKIP (not fetched: {e['file']})")
            continue
        fired, npk = summarize(path, e["family"])
        if fired is None:
            print(f"{e['family']:20s} UNAVAILABLE: {npk}")
            continue
        firestr = ", ".join(f"{s} x{v['count']}({v['severity']})"
                            for s, v in sorted(fired.items())) or "NONE"
        print(f"{e['family']:20s} [{npk:>7} pkts] {firestr}")
        for want in (e.get("expected_signals") or {}):
            if want not in fired:
                print(f"    !! MISS: expected {want} did not fire")
                misses += 1
    print("=" * 72)

    # false-positive guard on the committed benign baseline
    benign = os.path.join(REPO, "attack_tests", "pcaps", "benign_home.pcapng")
    if os.path.isfile(benign):
        fired, npk = summarize(benign, "benign")
        bad = {s: v for s, v in (fired or {}).items()
               if s in HIGH_SEV_SIGNALS and v["severity"] in ("medium", "high")}
        if bad:
            print(f"FP-GUARD  benign_home fired HIGH-sev: {bad}  <-- REVIEW")
            misses += 1
        else:
            low = ", ".join(sorted(fired or {})) or "nothing"
            print(f"FP-GUARD  benign_home clean of high-sev signals "
                  f"(low-sev only: {low})")
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
