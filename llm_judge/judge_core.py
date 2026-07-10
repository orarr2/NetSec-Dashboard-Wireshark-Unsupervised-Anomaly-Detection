"""Core of the LLM-as-Judge triage layer (design: docs/LLM_JUDGE_SPEC.md).

Standalone by design: nothing here imports from app/ or from the main
dashboard notebook. The only upstream contract is the S-dict / findings
shape produced by attack_tests/run_pipeline.py - the same code paths the
dashboard runs - which the judge notebook feeds in.

Flow (one PCAP):
    S = analyze_pcap(...); run_ml_on_session(S); findings = run_security_scans(S)
    candidates = assemble_candidates(S, findings)
    out = judge_candidates(candidates)          # cache -> LLM -> validate
    out["results"]                              # ranked by ensemble priority
"""
import hashlib
import ipaddress
import json
import os
import sqlite3
import time
from datetime import datetime, timezone

try:
    from . import judge_config
    from . import llm_clients
except ImportError:  # imported with llm_judge/ itself on sys.path
    import judge_config
    import llm_clients

# --------------------------------------------------------------------------
# Contract enums + verdict schema (spec sections 4.3 / 4.4).
# --------------------------------------------------------------------------
VERDICTS = ["benign", "suspicious", "malicious"]
CATEGORIES = ["beaconing_c2", "dns_tunnel", "dns_amp", "port_scan",
              "arp_mitm", "syn_flood", "benign_anomaly"]
ACTIONS = ["monitor", "investigate", "block"]

# Passed verbatim to the providers' structured-output modes, so it follows
# the structured-outputs subset: enums are enforced server-side; numeric
# range and string length are validated client-side in validate_verdict().
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": VERDICTS},
        "category": {"type": "string", "enum": CATEGORIES},
        "confidence": {
            "type": "number",
            "description": "0.0 to 1.0",
        },
        "evidence_features": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Field names (or dotted paths) from the input blob",
        },
        "reasoning": {
            "type": "string",
            "description": "One paragraph, no newlines, at most 400 characters",
        },
        "recommended_action": {"type": "string", "enum": ACTIONS},
    },
    "required": ["verdict", "category", "confidence", "evidence_features",
                 "reasoning", "recommended_action"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are a network-security triage analyst. You receive a JSON blob
describing one candidate (an IP, a flow, or the whole session) that at
least one unsupervised detector or deterministic rule has flagged. Your job:

1. Return a strict JSON object matching the schema below. No prose
   outside the JSON. No markdown fences.
2. Assign a verdict (benign | suspicious | malicious) and a category
   from the fixed enum.
3. Ground every claim in the input blob - cite feature names in
   evidence_features.
4. If the signals are contradictory or thin, prefer "suspicious" over
   "malicious". If they are strong and unambiguous, use "malicious".
5. Never invent facts not in the blob. If a field is null, it is unknown,
   not zero.
6. recommended_action is a suggestion for a human, never an action
   this system will execute.
7. confidence is a number between 0.0 and 1.0. reasoning is a single
   paragraph, no newlines, at most 400 characters.

Schema:
{schema}

Category cheat sheet:
- port_scan: high unique_dsts + one dominant TCP flag counter + high
  ratio of that flag to total packets. Attackers touch many destinations.
- syn_flood: session-level SYN rate high AND many spoofed sources (see
  session_context and rule_signals.flood_alerts). Candidates of kind
  "session" with a flood alert are this category.
- arp_mitm: rule_signals.arp_multi_mac is true.
- dns_amp: rule_signals.amp_alerts non-empty AND UDP/53 responses
  dominate.
- beaconing_c2: advanced_signals.beaconing non-null and periodic.
- dns_tunnel: advanced_signals.dns_tunneling non-null OR unusually long
  DNS query strings.
- benign_anomaly: any statistical outlier without a matching attack
  pattern in the signals. Prefer this over "malicious" when in doubt.
""".format(schema=json.dumps(VERDICT_SCHEMA, indent=2))


class JudgeValidationError(ValueError):
    """The LLM response failed schema validation."""


# --------------------------------------------------------------------------
# Fingerprint + cache (spec sections 6.3 / 7.2).
# --------------------------------------------------------------------------
def canonical_json(obj):
    """Sorted keys, no whitespace - the stable half of the cache key."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def fingerprint(candidate_context, prompt_version, model_id):
    """Cache key. The spec keys on (context, prompt_version); the model id
    is added so switching provider or model never reuses a stale verdict."""
    payload = canonical_json(candidate_context) + prompt_version + model_id
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class JudgeCache:
    """SQLite verdict cache. Only schema-validated verdicts are written."""

    def __init__(self, db_path):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS judge_cache (
                fingerprint TEXT PRIMARY KEY,
                prompt_version TEXT NOT NULL,
                verdict_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                llm_model TEXT NOT NULL,
                latency_ms INTEGER
            )""")
        self._conn.commit()

    def get(self, fp):
        row = self._conn.execute(
            "SELECT verdict_json FROM judge_cache WHERE fingerprint = ?",
            (fp,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, fp, prompt_version, verdict, model_id, latency_ms):
        self._conn.execute(
            "INSERT OR REPLACE INTO judge_cache VALUES (?, ?, ?, ?, ?, ?)",
            (fp, prompt_version, canonical_json(verdict),
             datetime.now(timezone.utc).isoformat(timespec="seconds"),
             model_id, int(latency_ms)))
        self._conn.commit()

    def stats(self):
        n, = self._conn.execute("SELECT COUNT(*) FROM judge_cache").fetchone()
        return {"entries": int(n)}

    def close(self):
        self._conn.close()


# --------------------------------------------------------------------------
# Verdict validation (spec section 4.3): strict on structure and enums,
# soft on evidence_features content; reasoning normalized to one line and
# hard-capped at 400 characters.
# --------------------------------------------------------------------------
def validate_verdict(obj):
    """Return a normalized verdict dict or raise JudgeValidationError."""
    if not isinstance(obj, dict):
        raise JudgeValidationError(f"verdict is {type(obj).__name__}, not object")
    missing = [k for k in VERDICT_SCHEMA["required"] if k not in obj]
    if missing:
        raise JudgeValidationError(f"missing fields: {missing}")
    if obj["verdict"] not in VERDICTS:
        raise JudgeValidationError(f"bad verdict {obj['verdict']!r}")
    if obj["category"] not in CATEGORIES:
        raise JudgeValidationError(f"bad category {obj['category']!r}")
    if obj["recommended_action"] not in ACTIONS:
        raise JudgeValidationError(
            f"bad recommended_action {obj['recommended_action']!r}")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) \
            or not (0.0 <= float(conf) <= 1.0):
        raise JudgeValidationError(f"confidence {conf!r} outside [0, 1]")
    if not isinstance(obj["evidence_features"], list):
        raise JudgeValidationError("evidence_features is not a list")
    if not isinstance(obj["reasoning"], str) or not obj["reasoning"].strip():
        raise JudgeValidationError("reasoning is empty or not a string")
    reasoning = " ".join(obj["reasoning"].split())
    return {
        "verdict": obj["verdict"],
        "category": obj["category"],
        "confidence": round(float(conf), 3),
        "evidence_features": [str(x) for x in obj["evidence_features"]][:12],
        "reasoning": reasoning[:400],
        "recommended_action": obj["recommended_action"],
    }


# --------------------------------------------------------------------------
# Candidate assembly (spec section 4.1 / 4.2).
# --------------------------------------------------------------------------
def _num(x, digits=4):
    """numpy scalar -> plain rounded float (stable fingerprints)."""
    try:
        return round(float(x), digits)
    except (TypeError, ValueError):
        return None


def _is_private(ip):
    try:
        return bool(ipaddress.ip_address(ip).is_private)
    except ValueError:
        return None


FEATURE_COLS = ["mean_len", "std_len", "count", "burst_score", "unique_dsts",
                "syn_count", "rst_count", "fin_count", "null_count",
                "xmas_count"]


def assemble_candidates(S, findings, lstm_flags=None, max_candidates=None):
    """Union of everything any detector flagged, one JSON blob each.

    lstm_flags: optional {ip: bin_flag_count} attribution from the LSTM
    layer (null in the blob when not provided - the standalone pipeline
    treats the LSTM as an optional, slow extra).

    Returns {"candidates": [...], "capped": [ids dropped by the batch cap]}.
    Rule-triggered candidates always survive the cap; the statistical-only
    remainder is ranked by iso_score (most anomalous first).
    """
    if max_candidates is None:
        max_candidates = judge_config.MAX_CANDIDATES_PER_BATCH
    ip_agg = S["ip_agg"]
    duration_s = max((S["t1"] - S["t0"]).total_seconds(), 0.0)
    session_context = {
        "duration_s": round(duration_s, 1),
        "total_packets": int(S["n_pkts"]),
        "total_ips": int(len(S["ips_src"])),
    }

    scan_by_src = {}
    for a in findings.get("scan_alerts", []):
        scan_by_src.setdefault(a["src"], []).append(
            {"type": a["type"], "count": int(a["count"]),
             "unique_dsts": int(a["unique_dsts"]), "ratio": float(a["ratio"])})
    amp_by_src = {a["src"]: {"responses": int(a["responses"]),
                             "mean_size": float(a["mean_size"])}
                  for a in findings.get("amp_alerts", [])}
    arp_ips = set(findings.get("arp_spoofing_ips", {}))
    flood_alerts = findings.get("flood_alerts", [])

    has_ml = "anomaly" in getattr(ip_agg, "columns", [])
    # A degenerate DBSCAN (skipped or all-noise, e.g. a spoofed flood) makes
    # "noise" meaningless as a per-IP signal - only use it when at least one
    # real cluster exists.
    dbscan_meaningful = (has_ml and "cluster" in ip_agg.columns
                         and bool((ip_agg["cluster"] != -1).any()))

    reasons = {}

    def _add(ip, reason):
        reasons.setdefault(ip, set()).add(reason)

    if has_ml:
        for ip in ip_agg.index[ip_agg["anomaly"] == True]:  # noqa: E712
            _add(ip, "isolation_forest")
        if dbscan_meaningful:
            for ip in ip_agg.index[ip_agg["cluster"] == -1]:
                _add(ip, "dbscan_noise")
    for src in scan_by_src:
        _add(src, "scan_rule")
    for src in amp_by_src:
        _add(src, "amp_rule")
    for ip in arp_ips:
        _add(ip, "arp_rule")
    for ip in (lstm_flags or {}):
        _add(ip, "lstm")

    rule_reasons = {"scan_rule", "amp_rule", "arp_rule"}

    def _rank_key(ip):
        is_rule = bool(reasons[ip] & rule_reasons)
        if has_ml and ip in ip_agg.index:
            iso = float(ip_agg.loc[ip, "iso_score"])
        else:
            iso = float("inf")  # no score -> after every scored candidate
        return (0 if is_rule else 1, iso)  # rules first, then most anomalous

    ordered = sorted(reasons, key=_rank_key)
    kept, capped = ordered[:max_candidates], ordered[max_candidates:]

    candidates = []
    for ip in kept:
        in_agg = ip in ip_agg.index
        row = ip_agg.loc[ip] if in_agg else None
        features = {c: (_num(row[c]) if in_agg else 0.0) for c in FEATURE_COLS}
        ml = {
            "iso_score": _num(row["iso_score"]) if (in_agg and has_ml) else None,
            "iso_stability": _num(row["iso_stability"]) if (in_agg and has_ml) else None,
            "anomaly": bool(row["anomaly"]) if (in_agg and has_ml) else None,
            "cluster": int(row["cluster"]) if (in_agg and has_ml
                                               and "cluster" in ip_agg.columns) else None,
            "silhouette": None,
            "lstm_bin_flag_count": int(lstm_flags[ip]) if (lstm_flags
                                                           and ip in lstm_flags) else None,
        }
        candidates.append({
            "candidate_id": ip,
            "kind": "ip",
            "session_context": session_context,
            "features": features,
            "ml_signals": ml,
            "rule_signals": {
                "scan_alerts": scan_by_src.get(ip, []),
                "flood_alerts": [],
                "amp_alerts": [amp_by_src[ip]] if ip in amp_by_src else [],
                "arp_multi_mac": ip in arp_ips,
            },
            "advanced_signals": {"beaconing": None, "dns_tunneling": None,
                                 "dga": None, "tls_anomaly": None,
                                 "fusion_score": None},
            "device_context": {"category": "unknown", "hostname": None,
                               "oui_vendor": None},
            "enrichments": {"is_private": _is_private(ip),
                            "reverse_dns": None, "asn": None,
                            "baseline_seen_before": None},
            "trigger_reasons": sorted(reasons[ip]),
        })

    # Session-level candidate for aggregate floods: thousands of spoofed
    # sources have no meaningful per-IP identity, so the flood is judged
    # once at session scope (kind "session" extends the spec's ip|flow).
    if flood_alerts:
        fa = flood_alerts[0]
        candidates.append({
            "candidate_id": f"session:{S.get('label', 'S1')}",
            "kind": "session",
            "session_context": session_context,
            "features": {
                "total_syn": int(fa["total_syn"]),
                "syn_sources": int(fa["syn_sources"]),
                "syn_per_sec": float(fa["syn_per_sec"]),
                "syn_per_source": float(fa["syn_per_source"]),
                "spoofed_source_pattern": bool(fa["spoofed_source_pattern"]),
            },
            "ml_signals": {"iso_score": None, "iso_stability": None,
                           "anomaly": None, "cluster": None,
                           "silhouette": None, "lstm_bin_flag_count": None},
            "rule_signals": {"scan_alerts": [], "flood_alerts": flood_alerts,
                             "amp_alerts": [], "arp_multi_mac": False},
            "advanced_signals": {"beaconing": None, "dns_tunneling": None,
                                 "dga": None, "tls_anomaly": None,
                                 "fusion_score": None},
            "device_context": {"category": "unknown", "hostname": None,
                               "oui_vendor": None},
            "enrichments": {"is_private": None, "reverse_dns": None,
                            "asn": None, "baseline_seen_before": None},
            "trigger_reasons": ["flood_rule"],
        })

    return {"candidates": candidates, "capped": capped}


# --------------------------------------------------------------------------
# Ensemble priority (spec section 9).
# --------------------------------------------------------------------------
def _iso_bounds(candidates):
    scores = [c["ml_signals"]["iso_score"] for c in candidates
              if isinstance(c["ml_signals"]["iso_score"], (int, float))]
    return (min(scores), max(scores)) if scores else (None, None)


def priority_score(candidate, verdict, iso_min, iso_max):
    iso = candidate["ml_signals"]["iso_score"]
    if isinstance(iso, (int, float)) and iso_min is not None \
            and iso_max is not None and iso_max > iso_min:
        norm_anom = (iso_max - float(iso)) / (iso_max - iso_min)  # lower = worse
    else:
        norm_anom = 0.0
    return round(
        judge_config.W_ANOM * norm_anom
        + judge_config.W_JUDGE_CONF * verdict["confidence"]
        + judge_config.W_CAT * judge_config.CATEGORY_WEIGHT[verdict["category"]]
        + judge_config.W_TI * 0.0,
        4)


# --------------------------------------------------------------------------
# The judge loop (spec section 5): cache -> LLM -> validate -> retry once ->
# drop-and-log. A single bad response never poisons the batch.
# --------------------------------------------------------------------------
def judge_candidates(candidates, client=None, cache_db=None,
                     prompt_version=None, verbose=True):
    """Judge a candidate batch. Returns
    {"results": [ranked verdicts], "dropped": [failures], "stats": {...}}."""
    prompt_version = prompt_version or judge_config.PROMPT_VERSION
    if not judge_config.LLM_JUDGE_ENABLED:
        if verbose:
            print("[judge] LLM_JUDGE_ENABLED=0 - skipping all candidates")
        return {"results": [], "dropped": [],
                "stats": {"total": len(candidates), "judged": 0,
                          "cache_hits": 0, "dropped": 0, "disabled": True}}
    if client is None:
        client = llm_clients.make_client(verdict_schema=VERDICT_SCHEMA)
    cache = JudgeCache(cache_db or judge_config.CACHE_DB)

    iso_min, iso_max = _iso_bounds(candidates)
    results, dropped, cache_hits = [], [], 0
    try:
        for i, cand in enumerate(candidates, 1):
            fp = fingerprint(cand, prompt_version, client.model_id)
            verdict = cache.get(fp)
            latency_ms, was_cached = 0, verdict is not None
            if was_cached:
                cache_hits += 1
            else:
                last_err = None
                for attempt in (1, 2):  # retry once on any failure
                    try:
                        t0 = time.perf_counter()
                        raw = client.judge(SYSTEM_PROMPT,
                                           json.dumps(cand, indent=2))
                        latency_ms = int((time.perf_counter() - t0) * 1000)
                        verdict = validate_verdict(json.loads(raw))
                        break
                    except Exception as e:
                        last_err, verdict = e, None
                if verdict is None:
                    dropped.append({"candidate_id": cand["candidate_id"],
                                    "error": str(last_err)})
                    if verbose:
                        print(f"[judge] {i}/{len(candidates)} "
                              f"{cand['candidate_id']}: DROPPED ({last_err})")
                    continue
                cache.put(fp, prompt_version, verdict, client.model_id,
                          latency_ms)
            results.append({
                "candidate_id": cand["candidate_id"],
                "kind": cand["kind"],
                "verdict": verdict,
                "priority": priority_score(cand, verdict, iso_min, iso_max),
                "cached": was_cached,
                "latency_ms": latency_ms,
            })
            if verbose:
                tag = "cache" if was_cached else f"{latency_ms} ms"
                v = verdict
                print(f"[judge] {i}/{len(candidates)} "
                      f"{cand['candidate_id']:<24} {v['verdict']:<10} "
                      f"{v['category']:<15} conf={v['confidence']:.2f} ({tag})")
    finally:
        cache.close()

    results.sort(key=lambda r: -r["priority"])
    return {"results": results, "dropped": dropped,
            "stats": {"total": len(candidates), "judged": len(results),
                      "cache_hits": cache_hits, "dropped": len(dropped),
                      "prompt_version": prompt_version,
                      "model": client.model_id}}


def save_verdicts(out, pcap_name, output_dir=None):
    """Write the judged batch to llm_judge/output/ as JSON; returns the path."""
    output_dir = output_dir or judge_config.OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.splitext(os.path.basename(pcap_name))[0]
    path = os.path.join(output_dir, f"verdicts_{base}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"pcap": os.path.basename(pcap_name),
                   "generated_at": datetime.now(timezone.utc)
                                          .isoformat(timespec="seconds"),
                   **out}, f, indent=2)
    return path
