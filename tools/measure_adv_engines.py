"""Measure per-engine fire count + FP/TP on the labelled attack PCAPs.

Produces the numbers `docs/SCIENTIFIC_AUDIT.md` §1.2 quotes. Runs the
five advanced engines (`_adv_detect_arp_dhcp`, `_adv_detect_dns_tunnel`,
`_adv_detect_dga`, `_adv_detect_beaconing`, `_adv_detect_tls`) plus
`run_advanced_threats` against every capture in `attack_tests/pcaps/`,
compares device attribution to `attack_tests/ground_truth.json`, and
prints a table of `n_signals / n_devices / FP / TP / top_score`.

"FP" here means the engine flagged a device that ground truth does
not label as an attacker or reflector for THIS PCAP's scenario. The
advanced engines target APT-style stealth patterns and can legitimately
notice a device on a capture whose declared attack is something else
(e.g. a DGA-shaped label on an ARP-spoof capture); those still count
as FPs against this PCAP's ground truth, which is the honest way to
measure per-capture false-positive floors.

The engines live in `app/advanced_engines.py`, a Dash-free module, so
this harness simply imports them - the same code the dashboard and the
VM worker run. (It used to exec three notebook cells in a scratch
namespace, because importing `app.dashboard_module` starts the Dash
server. That hack also silently under-reported on any host where tshark
is not on PATH, since the cell that discovers it was not among the three.)

    python3 tools/measure_adv_engines.py
    python3 tools/measure_adv_engines.py --json > baseline.json
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys


def load_advanced_engines(repo_root: str):
    """Return a namespace dict with `run_advanced_threats` (and the
    `_adv_*` helpers) usable without importing `app.dashboard_module`."""
    app_dir = os.path.join(repo_root, "app")
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
    import advanced_engines
    return vars(advanced_engines)


def load_ground_truth(repo_root: str):
    gt = json.load(open(os.path.join(repo_root, "attack_tests",
                                     "ground_truth.json"), encoding="utf-8"))
    out = {}
    for k, entry in gt.items():
        if k == "_comment":
            continue
        tp = set()
        for field in ("spoofed_ips", "attacker_ips",
                      "reflector_ips", "spoofing_macs"):
            for x in entry.get(field, []) or []:
                tp.add(x)
        out[k] = tp
    return out


def measure(repo_root: str):
    ns = load_advanced_engines(repo_root)
    run_adv = ns["run_advanced_threats"]
    gt = load_ground_truth(repo_root)
    pcaps_dir = os.path.join(repo_root, "attack_tests", "pcaps")

    per_pcap = {}
    for name in sorted(os.listdir(pcaps_dir)):
        if not name.endswith((".pcap", ".pcapng")):
            continue
        key = name.rsplit(".", 1)[0]  # strip extension
        tp_ips = gt.get(key, set())
        path = os.path.join(pcaps_dir, name)
        with contextlib.redirect_stdout(io.StringIO()):
            r = run_adv(path, "S1")
        engines = {}
        if r.get("available"):
            for eng, rows in (r.get("per_engine") or {}).items():
                devs = {row.get("device") for row in rows if row.get("device")}
                top = max((row.get("score") or 0.0) for row in rows) if rows else 0.0
                engines[eng] = {
                    "n_signals": len(rows),
                    "n_devices": len(devs),
                    "tp": len(devs & tp_ips),
                    "fp": len(devs - tp_ips),
                    "top_score": round(float(top), 2),
                }
        per_pcap[name] = {
            "available": bool(r.get("available")),
            "reason": r.get("reason"),
            "gt_ips": sorted(tp_ips),
            "engines": engines,
        }
    return per_pcap


def render_table(per_pcap: dict) -> str:
    lines = []
    header = ("%-22s | %-14s | %5s %5s %5s %5s %10s"
              % ("pcap", "engine", "n_sig", "fired", "fp", "tp", "top_score"))
    lines.append(header)
    lines.append("-" * len(header))
    for pcap, info in per_pcap.items():
        if not info["available"]:
            lines.append(f"{pcap:22} | UNAVAILABLE: {info.get('reason')}")
            continue
        for eng, m in info["engines"].items():
            if m["n_signals"] == 0:
                lines.append("%-22s | %-14s | %5d %5d %5d %5d %10s"
                             % (pcap, eng, 0, 0, 0, 0, "-"))
            else:
                lines.append("%-22s | %-14s | %5d %5d %5d %5d %10.2f"
                             % (pcap, eng, m["n_signals"], m["n_devices"],
                                m["fp"], m["tp"], m["top_score"]))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true",
                    help="Emit the raw per-pcap dict as JSON on stdout.")
    ap.add_argument("--repo", default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args(argv)
    result = measure(args.repo)
    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_table(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
