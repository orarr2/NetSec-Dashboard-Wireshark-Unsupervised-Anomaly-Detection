"""Model benchmark: measure any judge model on labeled real candidates.

benchmark_fixtures.json holds candidate blobs extracted from the five
ground-truth PCAPs by the real pipeline, each labeled with its true
category. run_benchmark() judges every fixture with a given client and
reports accuracy + latency, so a model can be qualified BEFORE anyone
trusts its verdicts on live captures.

Deliberately independent of the SQLite verdict cache (cache hits would
fake the latency numbers) and of tshark (fixtures are pre-extracted), so
it runs anywhere in a couple of minutes per model.

Scoring (dropped fixtures - no valid verdict after one retry - count as
WRONG in every metric; a model that cannot answer is not a good model):
- category_accuracy  - judged category == truth category, over ALL fixtures
- detection_rate     - attack fixtures judged non-benign (suspicious or
                       malicious), over ALL attack fixtures
- benign_accuracy    - benign fixtures judged exactly benign, over ALL
                       benign fixtures
- guardrail_saves    - attack fixtures that were detected only because the
                       rule guardrail overrode a benign model verdict
"""
import json
import statistics
import time

try:
    from . import judge_config
    from . import judge_core
except ImportError:  # imported with llm_judge/ itself on sys.path
    import judge_config
    import judge_core


def load_fixtures(path=None):
    with open(path or judge_config.BENCHMARK_FIXTURES,
              encoding="utf-8") as f:
        return json.load(f)["fixtures"]


def _judge_once(client, candidate):
    """One judged fixture with the production retry-once semantics.
    Returns (verdict_or_None, error_or_None, latency_ms)."""
    last_err, verdict = None, None
    latency_ms = 0
    for _attempt in (1, 2):
        latency_ms = 0
        try:
            t0 = time.perf_counter()
            raw = client.judge(judge_core.SYSTEM_PROMPT,
                               json.dumps(candidate, indent=2))
            latency_ms = int((time.perf_counter() - t0) * 1000)
            verdict = judge_core.validate_verdict(json.loads(raw))
            break
        except Exception as e:
            last_err, verdict = e, None
    return verdict, last_err, latency_ms


def run_benchmark(client, fixtures=None, guardrail=None, verbose=True):
    """Judge every fixture with `client`; return the score report dict.

    guardrail: None = follow judge_config.RULE_GUARDRAIL; True/False to
    force. Rows keep both the raw model verdict and the effective
    (post-guardrail) one, so the guardrail's contribution is visible.
    """
    if guardrail is None:
        guardrail = judge_config.RULE_GUARDRAIL
    if fixtures is None:
        fixtures = load_fixtures()
    rows, latencies = [], []
    for i, fx in enumerate(fixtures, 1):
        cand, truth = fx["candidate"], fx["truth_category"]
        kind = fx["truth_kind"]
        verdict, err, latency_ms = _judge_once(client, cand)
        if verdict is None:
            # no valid verdict after a retry: wrong on every metric
            rows.append({"candidate_id": cand["candidate_id"],
                         "source_pcap": fx["source_pcap"],
                         "truth_category": truth, "truth_kind": kind,
                         "judged_category": None, "judged_verdict": None,
                         "model_category": None, "model_verdict": None,
                         "guardrail_applied": False, "correct": False,
                         "verdict_correct": False,
                         "latency_ms": None, "error": str(err)})
            if verbose:
                print(f"[bench] {i}/{len(fixtures)} "
                      f"{cand['candidate_id']:<24} DROPPED ({err})")
            continue
        model_category = verdict["category"]
        model_verdict = verdict["verdict"]
        gr_info = None
        if guardrail:
            verdict, gr_info = judge_core.apply_rule_guardrail(cand, verdict)
        correct = verdict["category"] == truth
        # verdict-level correctness: attacks must be non-benign, benign
        # fixtures must be exactly benign
        verdict_correct = (verdict["verdict"] != "benign"
                           if kind == "attack"
                           else verdict["verdict"] == "benign")
        latencies.append(latency_ms)
        rows.append({"candidate_id": cand["candidate_id"],
                     "source_pcap": fx["source_pcap"],
                     "truth_category": truth, "truth_kind": kind,
                     "judged_category": verdict["category"],
                     "judged_verdict": verdict["verdict"],
                     "model_category": model_category,
                     "model_verdict": model_verdict,
                     "guardrail_applied": bool(gr_info),
                     "correct": correct,
                     "verdict_correct": verdict_correct,
                     "latency_ms": latency_ms, "error": None})
        if verbose:
            mark = "OK  " if correct else "MISS"
            gr = " +guardrail" if gr_info else ""
            print(f"[bench] {i}/{len(fixtures)} "
                  f"{cand['candidate_id']:<24} truth={truth:<15} "
                  f"judged={verdict['category']:<15} {mark}{gr} "
                  f"({latency_ms} ms)")

    # every metric divides by the FULL fixture count of its slice, so
    # dropped fixtures always count as wrong
    attacks = [r for r in rows if r["truth_kind"] == "attack"]
    benigns = [r for r in rows if r["truth_kind"] == "benign"]
    dropped = sum(1 for r in rows if r["error"] is not None)
    guardrail_saves = sum(1 for r in attacks
                          if r["guardrail_applied"] and r["verdict_correct"]
                          and r["model_verdict"] == "benign")
    n = len(fixtures)
    report = {
        "model": client.model_id,
        "prompt_version": judge_config.PROMPT_VERSION,
        "guardrail": bool(guardrail),
        "fixtures": n,
        "dropped": dropped,
        "category_accuracy": round(
            sum(r["correct"] for r in rows) / n, 3) if n else None,
        "detection_rate": round(
            sum(r["verdict_correct"] for r in attacks) / len(attacks), 3)
            if attacks else None,
        "benign_accuracy": round(
            sum(r["verdict_correct"] for r in benigns) / len(benigns), 3)
            if benigns else None,
        "guardrail_saves": guardrail_saves,
        "latency_ms_mean": int(statistics.mean(latencies))
            if latencies else None,
        "latency_ms_median": int(statistics.median(latencies))
            if latencies else None,
        "rows": rows,
    }
    if verbose:
        print(f"\n[bench] {client.model_id}: "
              f"category accuracy {report['category_accuracy']}, "
              f"detection rate {report['detection_rate']}, "
              f"benign accuracy {report['benign_accuracy']}, "
              f"guardrail saves {guardrail_saves}, "
              f"dropped {dropped}, "
              f"median latency {report['latency_ms_median']} ms")
    return report


def verdict_line(report):
    """One-line qualification verdict for a benchmark report."""
    acc, det = report["category_accuracy"], report["detection_rate"]
    if report["fixtures"] and report["dropped"] * 3 >= report["fixtures"]:
        return ("NOT USABLE - the model failed to return valid verdicts "
                "for a third or more of the fixtures")
    if det is not None and det >= 1.0 and (acc or 0) >= 0.8:
        return "GOOD - catches every attack and classifies accurately"
    if det is not None and det >= 1.0:
        return ("ACCEPTABLE - catches every attack (guardrail included) "
                "but mislabels some categories")
    return ("WEAK - misses attacks; use a stronger model for real triage")
