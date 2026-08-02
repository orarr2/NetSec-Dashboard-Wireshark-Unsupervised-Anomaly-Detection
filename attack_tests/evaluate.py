#!/usr/bin/env python3
"""Evaluate the detection pipeline against labeled ground truth.

Runs every PCAP listed in ground_truth.json through the same feature
extraction + ML + rule layers as the dashboard (via run_pipeline) and
reports per-layer precision / recall / F1 for the per-IP attacks, plus
pass/fail for the aggregate expectations (flood rule, DBSCAN guard).

usage: python3 attack_tests/evaluate.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_pipeline as rp  # noqa: E402

PCAP_DIR = os.path.join(HERE, "pcaps")
GT_PATH = os.path.join(HERE, "ground_truth.json")


def prf(detected, truth):
    """Precision / recall / F1 for two IP sets."""
    detected, truth = set(detected), set(truth)
    tp = len(detected & truth)
    p = tp / len(detected) if detected else (1.0 if not truth else 0.0)
    r = tp / len(truth) if truth else 1.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def evaluate_pcap(name, gt, quiet=False):
    """Run one PCAP through extraction + ML + rules; score vs ground truth.

    Returns a dict with per-layer metrics and expectation pass/fails.
    """
    path = os.path.join(PCAP_DIR, name)
    if quiet:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            S = rp.analyze_pcap(path, name)
            rp.run_ml_on_session(S)
            findings = rp.run_security_scans(S)
    else:
        S = rp.analyze_pcap(path, name)
        rp.run_ml_on_session(S)
        findings = rp.run_security_scans(S)

    expect = gt.get("expect", {})
    result = {"name": name, "attack": gt.get("attack"), "checks": {}, "metrics": {}}

    # --- per-IP truth sets -------------------------------------------------
    truth_ips = set(gt.get("attacker_ips", []))
    truth_ips |= set(gt.get("spoofed_ips", []))
    truth_ips |= set(gt.get("reflector_ips", []))

    # Rule layer: union of every per-IP rule detection.
    rule_ips = {a["src"] for a in findings["scan_alerts"]}
    rule_ips |= {a["src"] for a in findings["amp_alerts"]}
    rule_ips |= set(findings["arp_spoofing_ips"].keys())

    # ML layer: IsolationForest majority-vote anomalies.
    ip_agg = S["ip_agg"]
    ml_ips = set(ip_agg[ip_agg.get("anomaly", False) == True].index) if "anomaly" in ip_agg else set()

    if truth_ips:
        result["metrics"]["rule"] = prf(rule_ips, truth_ips)
        result["metrics"]["ml"] = prf(ml_ips, truth_ips)

    # --- expectation checks ------------------------------------------------
    checks = result["checks"]
    if "scan_alert_types" in expect:
        seen_types = {a["type"] for a in findings["scan_alerts"]
                      if a["src"] in truth_ips}
        for t in expect["scan_alert_types"]:
            checks[f"scan_alert_{t}"] = t in seen_types
    if expect.get("ml_should_flag_attacker"):
        checks["ml_flags_attacker"] = bool(truth_ips & ml_ips)
    if expect.get("arp_multi_mac"):
        spoofed = set(gt.get("spoofed_ips", []))
        checks["arp_multi_mac"] = spoofed <= set(findings["arp_spoofing_ips"])
        macs = set()
        for ip in spoofed & set(findings["arp_spoofing_ips"]):
            macs |= set(findings["arp_spoofing_ips"][ip])
        if gt.get("spoofing_macs"):
            checks["arp_macs_identified"] = set(gt["spoofing_macs"]) <= macs
    if "aggregate_flood" in expect:
        fired = bool(findings["flood_alerts"])
        checks["aggregate_flood"] = fired == expect["aggregate_flood"]
        if fired and expect.get("spoofed_source_pattern") is not None:
            checks["spoofed_source_pattern"] = (
                findings["flood_alerts"][0]["spoofed_source_pattern"]
                == expect["spoofed_source_pattern"])
        if fired and expect.get("min_syn_sources"):
            checks["min_syn_sources"] = (
                findings["flood_alerts"][0]["syn_sources"] >= expect["min_syn_sources"])
    if expect.get("dbscan_skipped"):
        checks["dbscan_skipped"] = bool((ip_agg["cluster"] == -1).all())
    if expect.get("amp_rule"):
        amp_ips = {a["src"] for a in findings["amp_alerts"]}
        checks["amp_rule"] = set(gt.get("reflector_ips", [])) <= amp_ips
    # SCIENTIFIC_AUDIT 3.6: benign-side checks. `no_scan_alerts` and its
    # siblings assert zero deterministic hits; `adv_engine_fp_bounds` puts
    # a per-engine ceiling on false positives so the FP-reducing changes in
    # 3.3-3.5 can regress visibly. Numbers frozen against the first live
    # measurement on the reference fixture - a change to any engine that
    # inflates its count breaks CI.
    if expect.get("no_scan_alerts"):
        checks["no_scan_alerts"] = len(findings["scan_alerts"]) == 0
    if expect.get("no_amp_alerts"):
        checks["no_amp_alerts"] = len(findings["amp_alerts"]) == 0
    if expect.get("no_arp_spoofing"):
        checks["no_arp_spoofing"] = len(findings["arp_spoofing_ips"]) == 0
    bounds = expect.get("adv_engine_fp_bounds") or {}
    if bounds:
        adv = findings.get("adv_signals") or {}
        for engine, ceiling in bounds.items():
            observed = len(adv.get(engine) or [])
            checks[f"adv_{engine}_fp_bound"] = observed <= ceiling

    return result


def main():
    gt_all = {k: v for k, v in json.load(open(GT_PATH)).items()
              if not k.startswith("_")}
    results = [evaluate_pcap(name, gt, quiet=True) for name, gt in gt_all.items()]

    print(f"{'PCAP':<22} {'attack':<20} {'layer':<6} "
          f"{'prec':>6} {'rec':>6} {'F1':>6}")
    print("-" * 70)
    for r in results:
        for layer, (p, rec, f1) in r["metrics"].items():
            print(f"{r['name']:<22} {r['attack']:<20} {layer:<6} "
                  f"{p:6.2f} {rec:6.2f} {f1:6.2f}")
    print()
    n_pass = n_fail = 0
    for r in results:
        for check, ok in r["checks"].items():
            mark = "PASS" if ok else "FAIL"
            if ok: n_pass += 1
            else:  n_fail += 1
            print(f"  [{mark}] {r['name']:<22} {check}")
    print(f"\n{n_pass} passed, {n_fail} failed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
