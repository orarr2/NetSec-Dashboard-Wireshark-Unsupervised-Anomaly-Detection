# LLM Judge - what we ask, what the model sees, what it returns

The exact contract between the NetSec pipeline and the LLM judges. Every
judge in the panel receives the same three things per candidate: a system
prompt (fixed), a candidate blob (per-candidate JSON), and a JSON schema
they must match. No hidden context, no retrieval, no tools. One HTTP
call = one candidate = one verdict.

**Source of truth:** [llm_judge/judge_core.py](../llm_judge/judge_core.py)
(SYSTEM_PROMPT, VERDICT_SCHEMA, `_verdict_from_client`,
`judge_candidates_panel`). This doc is a mirror; if it drifts, the code
wins.

---

## 1. What a panel run looks like

For one PCAP:

1. Pipeline runs (`analyze_pcap` -> `run_ml_on_session` ->
   `run_security_scans`).
2. `assemble_candidates` picks the IPs / sessions any detector flagged and
   packages each one into a JSON blob (schema below).
3. For every candidate, `judge_candidates_panel` issues one HTTP request
   per judge, in parallel, through `_verdict_from_client`.
4. If judges disagree on the verdict label or category, each judge gets a
   second HTTP call - the debate turn - with the peers' anonymised
   analyses.
5. A deterministic resolver picks the effective verdict from all the
   post-debate positions (highest severity wins on splits; ties broken by
   confidence).
6. The rule guardrail forces "suspicious" (with the rule's category) on
   any candidate whose fired rule the panel called "benign".

Wall-clock is dominated by the slowest judge, not the number of judges.
Groq models answer in ~0.5-1 s; a CPU-only Ollama judge takes ~50 s.

---

## 2. The system prompt (fixed - every judge, every candidate)

Every request opens with this block, verbatim. It never changes at
runtime; the schema is inlined so a strict-mode server can enforce it.

```
You are a network-security triage analyst. You receive a JSON blob
describing one candidate (an IP, a flow, or the whole session) that at
least one unsupervised detector or deterministic rule has flagged. Your
job:

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
8. The deterministic rules are HIGH-PRECISION. If any rule has fired -
   rule_signals.scan_alerts / amp_alerts / flood_alerts is non-empty, or
   arp_multi_mac is true - classify into the matching attack category and
   do NOT return "benign". Only override a fired rule if you can name
   concrete evidence in the blob that it misfired.
```

Then the verdict schema is appended (see section 4), a category cheat
sheet, and two worked examples (a vertical SYN scan mapping to
`malicious/port_scan`, and an ML-only outlier mapping to
`benign/benign_anomaly`).

Total prompt size: ~1500 characters. Keep it tight - every candidate
pays the token cost again.

---

## 3. The candidate blob (per candidate - the whole context the model sees)

Every field the LLM has access to. Everything else about the capture -
raw packets, per-flow counters, PCAP metadata - stays in the pipeline
and never reaches the model.

```json
{
  "candidate_id": "192.168.1.10",
  "kind": "ip",

  "session_context": {
    "duration_s": 0.1,
    "total_packets": 2000,
    "total_ips": 2,
    "iso_timestamp": "2026-08-01T09:41:00",
    "hour_of_day": 9,
    "day_of_week": "Sat"
  },

  "features": {
    "mean_len": 54.0,
    "std_len": 0.0,
    "count": 1000.0,
    "burst_score": 1000.0,
    "unique_dsts": 1.0,
    "syn_count": 0.0,
    "rst_count": 0.0,
    "fin_count": 0.0,
    "null_count": 0.0,
    "xmas_count": 1000.0
  },

  "ml_signals": {
    "iso_score": 0.0,
    "iso_stability": 0.0,
    "anomaly": false,
    "cluster": -1,
    "silhouette": null,
    "lstm_bin_flag_count": null
  },

  "rule_signals": {
    "scan_alerts": [
      {"type": "XMAS", "count": 1000, "unique_dsts": 1, "ratio": 1.0}
    ],
    "flood_alerts": [],
    "amp_alerts": [],
    "arp_multi_mac": false
  },

  "advanced_signals": {
    "beaconing": null,
    "dns_tunneling": null,
    "dga": null,
    "tls_anomaly": null,
    "fusion_score": null
  },

  "device_context": {
    "category": "unknown",
    "hostname": "orarr-macbook.local",
    "oui_vendor": "Apple, Inc."
  },

  "websites": {
    "top_http_hosts": null,
    "top_tls_sni": [
      {"host": "cloudflare.com", "count": 87},
      {"host": "googleapis.com", "count": 34}
    ],
    "top_dns_queries": [
      {"host": "evil-c2.duckdns.org", "count": 128},
      {"host": "pool.ntp.org", "count": 12}
    ]
  },

  "traffic": {
    "top_dst_ports": [
      {"port_proto": "443/tcp", "count": 900},
      {"port_proto": "53/udp", "count": 30},
      {"port_proto": "80/tcp", "count": 20}
    ],
    "bytes_in": 3000000,
    "bytes_out": 1000000,
    "upload_ratio": 0.25
  },

  "enrichments": {
    "is_private": true,
    "reverse_dns": null,
    "asn": null,
    "baseline_seen_before": null
  },

  "trigger_reasons": ["scan_rule"]
}
```

### Field group semantics

- **`candidate_id` + `kind`** - identity. `kind` is `ip` for per-host
  candidates or `session` for aggregate rules (e.g. spoofed SYN flood).
- **`session_context`** - capture-level totals so the judge knows the
  scale ("1000 packets from this IP out of 2000 total = it dominates"),
  plus `iso_timestamp`, `hour_of_day` (0-23), and `day_of_week` (Mon..Sun)
  so off-hours activity carries weight. All three time fields are null
  when the caller built S without a real timestamp (e.g. unit tests).
- **`features`** - the 10 statistical columns the ML models train on.
  All counts and ratios are for the candidate IP alone.
- **`ml_signals`** - IsolationForest score + stability, DBSCAN cluster
  id (-1 = noise), silhouette (when a real cluster exists), and the
  LSTM bin flag count (only populated for captures with >= 20 usable
  time bins).
- **`rule_signals`** - the deterministic rule fires. These are
  **HIGH-PRECISION** - if any is non-empty, the schema-side cheat sheet
  and the prompt both instruct the LLM to route into the matching
  attack category and never return "benign".
- **`advanced_signals`** - the five per-IP engines (beaconing / DNS
  tunnel / DGA / TLS anomaly / fusion score). Populated only when the
  engine fired on this candidate; `null` means "not fired", not
  "clean" - the prompt teaches the model that distinction.
- **`device_context`** - `category` / `hostname` / `oui_vendor`. The
  dashboard path populates all three via `build_local_inventory` (device
  classifier + inventory). The worker path falls back to a lightweight
  derivation that uses only `S["ip_to_mac"]` (for `oui_vendor` via the
  `manuf` package) and `S["dns_per_ip"]` (for `hostname` via .local
  mDNS names). On the worker path `_lightweight_device_context` now
  derives a `category` from OUI / ports / DNS names as a fallback; a
  dashboard-produced inventory attached at `S["_local_inv"]` still
  takes precedence.
- **`websites`** - `top_http_hosts` / `top_tls_sni` / `top_dns_queries`,
  each an ordered list (up to 5, by count) of `{host, count}` items or
  `null` when the pipeline observed no traffic of that kind for this IP.
  mDNS (`.local`), `.arpa`, and PTR queries are filtered out before
  ranking so the list reflects real external browsing. Random-looking
  hostnames corroborate `advanced_signals.dga` / `.beaconing`.
- **`traffic`** - `top_dst_ports` (up to 5 `{port_proto, count}` items,
  proto = "tcp" or "udp"), `bytes_in` / `bytes_out` (directional totals),
  and `upload_ratio` (`bytes_out / (bytes_in + bytes_out)`, rounded to
  3 places). A high `upload_ratio` with meaningful `bytes_out` and a
  public destination is a data-exfiltration shape. Presence of
  `445/tcp`, `3389/tcp`, `22/tcp`, `5985/tcp` on an internal host is a
  lateral-movement signal.
- **`enrichments`** - `is_private` is the only field always populated.
  `reverse_dns`, `asn`, `baseline_seen_before` are reserved for future
  enrichment engines (Shodan is wired but off unless
  `NETSEC_ENABLE_SHODAN=1`).
- **`trigger_reasons`** - why this candidate was even picked (one or
  more of `isolation_forest`, `dbscan_noise`, `scan_rule`, `amp_rule`,
  `arp_rule`, `flood_rule`, `lstm`). The panel uses this to justify
  why an ML-only anomaly is not required to be malicious.

---

## 4. The verdict schema (what the LLM must return)

```json
{
  "type": "object",
  "properties": {
    "verdict":        {"type": "string", "enum": ["benign", "suspicious", "malicious"]},
    "category":       {"type": "string", "enum": ["beaconing_c2", "dns_tunnel", "dns_amp",
                                                  "port_scan", "arp_mitm", "syn_flood",
                                                  "benign_anomaly"]},
    "confidence":     {"type": "number"},
    "evidence_features": {"type": "array", "items": {"type": "string"}},
    "reasoning":      {"type": "string"},
    "recommended_action": {"type": "string", "enum": ["monitor", "investigate", "block"]}
  },
  "required": ["verdict", "category", "confidence", "evidence_features",
               "reasoning", "recommended_action"],
  "additionalProperties": false
}
```

Real answer from `qwen2.5:3b` on the candidate above:

```json
{
  "verdict": "suspicious",
  "category": "port_scan",
  "confidence": 0.95,
  "evidence_features": ["rule_signals.scan_alerts", "features.xmas_count"],
  "reasoning": "The high burst score suggests a more sophisticated attack.",
  "recommended_action": "investigate"
}
```

Client-side validation (`validate_verdict`) then:

- normalises `reasoning` to one line and truncates to 400 characters,
- coerces `confidence` to `round(float, 3)` and rejects outside [0, 1],
- trims `evidence_features` to 12 items,
- rejects anything outside the enums or a missing required field.

A malformed response is retried **once** (a JSON validation error is
usually a one-off model hiccup); a permanent 4xx from the server
(`allam-2-7b`'s `json_validate_failed`, an unknown model, a bad key) is
now tagged `permanent=True` and skips the retry loop entirely - the H3
fix.

---

## 5. The debate turn (only when judges disagree)

When two or more valid round-1 verdicts differ on `verdict` or
`category`, the panel fires a second call to every valid judge with the
peers' analyses anonymised as "Analyst 1", "Analyst 2", ..., and a
different schema (`DEBATE_SCHEMA`) that adds:

- `stance` (`maintain` | `revise`),
- `rebuttal` (one paragraph, <=300 chars, addressing the strongest
  opposing point).

The prompt reminds the judge that a fired deterministic rule is still
high-precision, so "benign" on a fired-rule candidate remains wrong even
if a peer argued for it.

Real debate rebuttal from the session-6 xmas scan (all three judges said
different things):

```
llama-3.1-8b-instant (maintain):
  "While Analyst 3's description of the scan as 'vertical' is accurate,
   it does not change the fact that the deterministic scan rule fired,
   indicating a malicious activity."

llama-3.3-70b-versatile (maintain):
  "Analysts 1 and 3 agree the scan rule fired, but 'suspicious'
   underestimates the threat; 1000 XMAS packets against one destination
   is a clear malicious indicator."

qwen2.5:3b (revise):
  "The high burst score suggests a more sophisticated attack."
```

The deterministic resolver then picks the effective verdict from the
post-debate positions (majority label wins; ties break on confidence;
splits use fail-safe severity and set `needs_human_review=True`).

---

## 6. Panel wall-clock and where time goes

Measured on the production VM (Oracle ARM 4 vCPU / 24 GB) with the
**balanced_4 4-judge panel** (activated 2026-08-01; the default preset
is now `reliable_hybrid_4`: groq:llama-3.1-8b-instant,
groq:openai/gpt-oss-120b, ollama:qwen2.5:3b, ollama:granite3.3:2b):

| Judge | Round 1 latency | Notes |
|---|---|---|
| `groq:llama-3.1-8b-instant` | ~500 ms | Groq HTTP + inference, 100k tok/day free |
| `groq:llama-3.3-70b-versatile` | ~700 ms | Groq HTTP + inference, 100k tok/day free |
| `ollama:qwen2.5:3b` | ~53 s | Local CPU-only inference on ARM (bottleneck) |
| `gemini:gemini-2.5-flash` | ~1-2 s | Google AI Studio Bearer-auth, 15 RPM / 1M tok/day free |

Panel wall-clock per candidate = **max(all judges)** because the panel
runs them concurrently through a `ThreadPoolExecutor`. So a full 4-judge
run still costs ~53 s per candidate, dominated by qwen (the three
network judges finish and idle waiting for the local model). A 5-candidate
PCAP takes ~4-5 minutes end to end.

If a judge fails (permanent 4xx, timeout, all retries exhausted), the
panel keeps running with the survivors; the effective verdict is still
produced and the failed judge is recorded in the participation report.
Concretely: with any 1 or 2 of the 4 judges down, `resolve_panel` still
returns a verdict; only if all 4 fail does the candidate land in
`dropped`.

**Why 4 and not 5 or 6?** Diminishing returns on diversity - two Groq
models (both Meta Llama family) give a strong "modern instruction-tuned
LLM" baseline; Gemini adds a genuinely different training corpus (Google
DeepMind); Qwen adds an out-of-family (Alibaba) local check that also
covers the "what if all cloud providers are down" case. Adding a 5th
model on Groq would double-count the family bias; adding a 5th slow
local model would push wall-clock past 2 minutes per candidate. The
4-judge config is the diversity-cost sweet spot documented in
`docs/VM_ARCHITECTURE_HE.md` section 10.

---

## 7. What was added in I2 (2026-08-01) and what remains open

Delivered in prompt version **v0.4.0** (current: **v0.5.0**):

- `session_context.hour_of_day` / `.day_of_week` / `.iso_timestamp`
- `device_context.oui_vendor` + `.hostname` (lightweight, worker path;
  full inventory still requires the dashboard's `build_local_inventory`)
- `websites` block with `top_http_hosts` / `top_tls_sni` / `top_dns_queries`
- `traffic` block with `top_dst_ports` / `bytes_in` / `bytes_out` /
  `upload_ratio`

Pipeline changes (`attack_tests/run_pipeline.py`):

- `FIELDS` gained `http.host` and `tls.handshake.extensions_server_name`
  (one extra tshark column each; unaffected packets return "").
- `analyze_pcap` now returns `ip_to_mac`, `dns_per_ip`, `http_host_per_ip`,
  `tls_sni_per_ip`, `dst_ports_per_ip` as per-IP Counter maps that
  `assemble_candidates` consumes.

Delivered in **v0.5.0** (previously open):

- `device_context.category` on the worker path - now derived by
  `judge_core._lightweight_device_category` from OUI / ports / DNS names.
- TLS versions + cipher suites - now exposed as the `tls` block via
  `judge_core._tls_for`.
- Baseline history (has this IP been seen before?) - now exposed as the
  `baseline_history` block via `judge_core._history_for`.

Every enrichment is additive; the prompt already teaches the model that
`null` = unknown, so new fields never falsely imply "observed zero".
Bumping `PROMPT_VERSION` (done: `v0.3.0` -> `v0.4.0` -> `v0.5.0`) invalidates every
cached verdict so the model re-judges with the richer input on next run.

---

## 8. Where to change what

| Change | File |
|---|---|
| Add / edit prompt sections | `llm_judge/judge_core.py` (`SYSTEM_PROMPT`, `DEBATE_SYSTEM_PROMPT`) |
| Add / edit output schema | `llm_judge/judge_core.py` (`VERDICT_SCHEMA`, `DEBATE_SCHEMA`) |
| Add / remove blob fields | `llm_judge/judge_core.py` (`assemble_candidates`) |
| Rate-limit / retry behaviour | `llm_judge/llm_clients.py` (`OpenAICompatClient._MAX_RETRIES`, `_MAX_WAIT_S`, `permanent`-tagging) |
| Which judges run | `LLM_JUDGE_PANEL` in `deploy/.env` |
| Debate on/off | `LLM_JUDGE_DEBATE` in `deploy/.env` |

A prompt change bumps `PROMPT_VERSION` in `llm_judge/judge_config.py`;
that version is part of the cache fingerprint, so bumping it invalidates
every cached verdict automatically.
