"""Calibration of the judge against attack_tests/ground_truth.json.

Cohen's kappa (spec section 8) is the single number that guards prompt
drift: run this after every prompt change, record the result in
PROMPT_CHANGELOG.md, and commit only if kappa did not regress.
tests/test_judge_kappa_regression.py gates CI on the latest committed
result file - it never calls an LLM itself.

Alignment rules:
- Normal PCAPs: every judged per-IP candidate gets a truth label -
  the attack category if the IP is in the ground-truth entity list,
  benign_anomaly otherwise.
- Aggregate-flood PCAPs (spoofed sources): per-IP identity is meaningless
  under spoofing, so only the session-level candidate is scored, with
  truth syn_flood.
"""
import json
import os
import sys
from datetime import datetime, timezone

try:
    from . import judge_config
    from . import judge_core
except ImportError:  # imported with llm_judge/ itself on sys.path
    import judge_config
    import judge_core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACK_TESTS_DIR = os.path.join(ROOT, "attack_tests")
GROUND_TRUTH_PATH = os.path.join(ATTACK_TESTS_DIR, "ground_truth.json")
PCAPS_DIR = os.path.join(ATTACK_TESTS_DIR, "pcaps")

# Judge category per ground-truth attack (spec section 4.4).
ATTACK_TO_CATEGORY = {
    "tcp_syn_scan": "port_scan",
    "tcp_xmas_scan": "port_scan",
    "arp_spoofing": "arp_mitm",
    "spoofed_syn_flood": "syn_flood",
    "dns_amplification": "dns_amp",
}

# Label order for linear-weighted kappa: benign at one end so an
# attack-vs-benign confusion always costs more than attack-vs-attack.
KAPPA_LABELS = ["benign_anomaly", "port_scan", "syn_flood", "dns_amp",
                "arp_mitm", "dns_tunnel", "beaconing_c2"]
VERDICT_LABELS = ["benign", "suspicious", "malicious"]

# Per-IP candidate cap applied ONLY to aggregate-flood PCAPs during
# calibration: those score only their session candidate, so judging more
# spoofed per-IP outliers just burns tokens (a full free-tier daily budget,
# on the 37k-source synflood capture) without moving kappa.
FLOOD_CALIBRATION_CAP = 3


def load_ground_truth():
    with open(GROUND_TRUTH_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    return {k: v for k, v in gt.items() if not k.startswith("_")}


def truth_entity_map(gt_entry):
    """{ip: category} for every labeled attack entity in one PCAP."""
    category = ATTACK_TO_CATEGORY[gt_entry["attack"]]
    ips = (list(gt_entry.get("attacker_ips", []))
           + list(gt_entry.get("spoofed_ips", []))
           + list(gt_entry.get("reflector_ips", [])))
    return {ip: category for ip in ips}


def align_to_truth(results, gt_entry):
    """(y_true_cat, y_pred_cat, y_true_verdict, y_pred_verdict) per candidate."""
    flood_pcap = bool(gt_entry.get("expect", {}).get("aggregate_flood"))
    truth = truth_entity_map(gt_entry)
    y_tc, y_pc, y_tv, y_pv = [], [], [], []
    for r in results:
        if flood_pcap:
            if r["kind"] != "session":
                continue  # spoofed per-IP candidates are not scoreable
            true_cat = ATTACK_TO_CATEGORY[gt_entry["attack"]]
        elif r["kind"] == "ip":
            true_cat = truth.get(r["candidate_id"], "benign_anomaly")
        else:
            continue  # session candidate on a non-flood PCAP: no truth label
        y_tc.append(true_cat)
        y_pc.append(r["verdict"]["category"])
        y_tv.append("benign" if true_cat == "benign_anomaly" else "malicious")
        y_pv.append(r["verdict"]["verdict"])
    return y_tc, y_pc, y_tv, y_pv


def _safe_kappa(y_true, y_pred, labels, weights=None):
    """cohen_kappa_score with the degenerate cases pinned down: perfect
    agreement on a single class is 1.0 (sklearn yields nan there)."""
    if not y_true:
        return None
    if y_true == y_pred:
        return 1.0
    from sklearn.metrics import cohen_kappa_score
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        k = cohen_kappa_score(y_true, y_pred, labels=labels, weights=weights)
    return None if k != k else round(float(k), 4)  # nan -> None


def _per_category_prf(y_true, y_pred):
    from sklearn.metrics import precision_recall_fscore_support
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        p, r, f, s = precision_recall_fscore_support(
            y_true, y_pred, labels=KAPPA_LABELS, zero_division=0)
    return {lab: {"precision": round(float(p[i]), 3),
                  "recall": round(float(r[i]), 3),
                  "f1": round(float(f[i]), 3),
                  "support": int(s[i])}
            for i, lab in enumerate(KAPPA_LABELS) if s[i] > 0}


def _confusion(y_true, y_pred):
    from sklearn.metrics import confusion_matrix
    m = confusion_matrix(y_true, y_pred, labels=KAPPA_LABELS)
    return {"labels": KAPPA_LABELS, "matrix": m.tolist()}


def run_calibration(client=None, pcaps_dir=None, results_path=None,
                    lstm_flags=None, verbose=True):
    """Judge every ground-truth PCAP and compute kappa. Writes the result
    JSON to llm_judge/calibration/results/<prompt_version>.json (committed,
    consumed by the CI gate) and returns the overall metrics dict.

    Requires tshark on PATH (same prerequisite as the whole project) and a
    reachable LLM provider. Verdicts are cached, so re-runs after a code-only
    change are free.
    """
    pcaps_dir = pcaps_dir or PCAPS_DIR
    sys.path.insert(0, ATTACK_TESTS_DIR)
    import run_pipeline as rp  # tshark + torch needed from here on

    gt = load_ground_truth()
    per_pcap = {}
    all_tc, all_pc, all_tv, all_pv = [], [], [], []
    total_dropped = 0
    for pcap_name, entry in gt.items():
        if verbose:
            print(f"\n=== calibrating on {pcap_name} "
                  f"({entry['attack']}) ===")
        S = rp.analyze_pcap(os.path.join(pcaps_dir, pcap_name), "S1")
        rp.run_ml_on_session(S)
        findings = rp.run_security_scans(S)
        # Aggregate-flood PCAPs score ONLY the session candidate (spoofed
        # per-IP sources have no truth label - see align_to_truth), so
        # judging the batch cap's worth of statistical-only outliers is
        # pure LLM cost with zero effect on kappa. Cap them hard for the
        # calibration run; assemble_candidates always appends the
        # session-level candidate after the per-IP cap, so it survives.
        flood_pcap = bool(entry.get("expect", {}).get("aggregate_flood"))
        max_cand = FLOOD_CALIBRATION_CAP if flood_pcap else None
        assembled = judge_core.assemble_candidates(S, findings,
                                                   lstm_flags=lstm_flags,
                                                   max_candidates=max_cand)
        out = judge_core.judge_candidates(assembled["candidates"],
                                          client=client, verbose=verbose)
        total_dropped += out["stats"]["dropped"]
        y_tc, y_pc, y_tv, y_pv = align_to_truth(out["results"], entry)
        per_pcap[pcap_name] = {
            "attack": entry["attack"],
            "candidates_judged": len(y_tc),
            "candidates_capped": len(assembled["capped"]),
            "llm_dropped": out["stats"]["dropped"],
            "category_kappa_linear": _safe_kappa(y_tc, y_pc, KAPPA_LABELS,
                                                 "linear"),
            "category_kappa_unweighted": _safe_kappa(y_tc, y_pc,
                                                     KAPPA_LABELS),
            "verdict_kappa": _safe_kappa(y_tv, y_pv, VERDICT_LABELS),
            "per_category": _per_category_prf(y_tc, y_pc),
        }
        all_tc += y_tc; all_pc += y_pc; all_tv += y_tv; all_pv += y_pv

    overall = {
        "category_kappa_linear": _safe_kappa(all_tc, all_pc, KAPPA_LABELS,
                                             "linear"),
        "category_kappa_unweighted": _safe_kappa(all_tc, all_pc,
                                                 KAPPA_LABELS),
        "verdict_kappa": _safe_kappa(all_tv, all_pv, VERDICT_LABELS),
        "candidates_scored": len(all_tc),
        "llm_dropped": total_dropped,
        "per_category": _per_category_prf(all_tc, all_pc),
        "confusion": _confusion(all_tc, all_pc),
    }

    report = {
        "prompt_version": judge_config.PROMPT_VERSION,
        "provider": judge_config.LLM_JUDGE_PROVIDER,
        "model": getattr(client, "model_id", None) or (
            judge_config.CLAUDE_MODEL
            if judge_config.LLM_JUDGE_PROVIDER == "claude"
            else judge_config.OLLAMA_MODEL),
        "generated_at": datetime.now(timezone.utc)
                               .isoformat(timespec="seconds"),
        "overall": overall,
        "per_pcap": per_pcap,
    }
    results_path = results_path or os.path.join(
        judge_config.RESULTS_DIR, f"{judge_config.PROMPT_VERSION}.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    if verbose:
        print(f"\n[calibration] overall category kappa (linear): "
              f"{overall['category_kappa_linear']} | verdict kappa: "
              f"{overall['verdict_kappa']}")
        print(f"[calibration] report written to {results_path}")
    return report


def latest_calibration_result(results_dir=None):
    """Newest committed calibration report, or None if none exists yet."""
    results_dir = results_dir or judge_config.RESULTS_DIR
    if not os.path.isdir(results_dir):
        return None
    files = [os.path.join(results_dir, f) for f in os.listdir(results_dir)
             if f.endswith(".json")]
    if not files:
        return None
    newest = max(files, key=os.path.getmtime)
    with open(newest, encoding="utf-8") as f:
        return json.load(f)
