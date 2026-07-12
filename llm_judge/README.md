# LLM-as-Judge — Standalone Triage Notebook

An **optional, fully self-contained add-on** to the NetSec Dashboard.
The main dashboard (`app/Network_Security_Dashboard.ipynb`) runs exactly as
before and knows nothing about this folder; if you never open this notebook,
nothing here ever executes.

What it does (design: [`docs/LLM_JUDGE_SPEC.md`](../docs/LLM_JUDGE_SPEC.md)):
the detection pipeline already produces per-IP ML scores (IsolationForest,
DBSCAN), deterministic rule alerts (scans, floods, DNS amplification, ARP
spoofing) — but each signal arrives separately and the analyst is the one
fusing them. This notebook sends every flagged candidate, with all of its
signals in one compact JSON blob, to an LLM that returns a **single strict
JSON verdict**: `benign | suspicious | malicious`, an attack category, a
confidence, the evidence it used, and a one-paragraph reasoning trace. The
queue is then re-ranked by an ensemble score and shown as a table.

The judge **never acts** — `recommended_action: "block"` is a suggestion for
a human, wired to nothing.

## Providers — bring your own model

Three interchangeable providers; pick with `LLM_JUDGE_PROVIDER`:

| Provider | What it is | Setup | Cost |
|---|---|---|---|
| `claude` (default) | Anthropic API — best JSON quality | `pip install -r llm_judge/requirements.txt` + set `ANTHROPIC_API_KEY` with **your own** key | your key, cents per PCAP |
| `ollama` | Local model via the Ollama daemon | install from <https://ollama.com>, `ollama pull llama3.2` | free, offline |
| `openai_compat` | Any OpenAI-style chat-completions endpoint: LM Studio / llamafile / vLLM locally, or hosted services that expose the OpenAI protocol | set `OPENAI_COMPAT_BASE_URL` + `OPENAI_COMPAT_MODEL` (+ `OPENAI_COMPAT_API_KEY` if the endpoint needs one) | free locally; hosted per its own terms |

**No API key is ever stored in this repo.** Keys are read from the
environment at call time; each user pays (or doesn't) for their own usage.

## Quick start

```bash
# 1. Project prerequisites (once): root requirements + Wireshark installed
#    (tshark is auto-detected in the standard install folders - no PATH edit)
pip install -r requirements.txt

# 2. Pick a provider (see the table above), e.g. free local:
set LLM_JUDGE_PROVIDER=ollama          # Windows;  export ... on Linux/macOS

# 3. Open the notebook and run top to bottom
jupyter notebook llm_judge/LLM_Judge_Notebook.ipynb
```

## Qualify a model before trusting it — the benchmark

`benchmark_fixtures.json` holds **11 labeled candidates extracted from the
five real attack PCAPs** by the production pipeline. Section 0 of the
notebook judges all of them with any model you name and scores it:

- **detection rate** — attack candidates judged non-benign (with the rule
  guardrail this is 1.0 for any model that returns valid JSON);
- **category accuracy** — exact attack-category match: where model quality
  actually shows;
- **benign accuracy** — ML-only outliers correctly left benign.

Measured on a CPU-only machine (11 fixtures, guardrail on): `llama3.2`
(3B) scored 100% category accuracy — but 7 of its 7 attack verdicts were
guardrail rescues (raw model said benign); `gemma3:4b` scored 91% with
zero rescues (its raw verdicts were already non-benign). Small local
models are thus usable for detection-level triage; their raw judgment
quality only shows on candidates no rule covers, which is where a
stronger model still earns its keep.

## The rule guardrail

The deterministic rule layer is high-precision. Small local models were
measured overriding a fired rule with "benign" (while hallucinating that no
rule fired), so by default a candidate whose rule fired can never end up
benign: the verdict is raised to `suspicious` with the rule-implied
category, the model's original verdict is preserved in the result, and the
override is marked (⚑ column in the notebook). Disable with
`LLM_JUDGE_RULE_GUARDRAIL=0`. The raw model verdict is what gets cached, so
toggling the guardrail never needs a cache reset.

## Files

| File | Role |
|---|---|
| `LLM_Judge_Notebook.ipynb` | The user-facing entry point — the only thing you run |
| `judge_config.py` | Provider/model, guardrail, weights, thresholds, prompt version |
| `judge_core.py` | Candidate assembly, system prompt, verdict validation, rule guardrail, SQLite cache, ensemble ranking |
| `llm_clients.py` | `ClaudeClient` + `OllamaClient` + `OpenAICompatClient` |
| `benchmark.py` | Model qualification: judge the labeled fixtures, score accuracy/latency |
| `benchmark_fixtures.json` | 11 labeled candidates extracted from the attack PCAPs (committed) |
| `calibration.py` | Cohen's-kappa calibration against `attack_tests/ground_truth.json` |
| `schemas/*.schema.json` | The input/output JSON contracts |
| `PROMPT_CHANGELOG.md` | Prompt version history + kappa per version |
| `calibration/results/` | Committed calibration reports (CI gate reads the newest) |
| `cache/`, `output/` | Runtime artifacts — gitignored, safe to delete |

Tests live with the rest of the suite: `tests/test_llm_judge_unit.py` and
`tests/test_llm_judge_providers.py` (mocked LLM + in-process mock
OpenAI-compatible server — no network), and
`tests/test_judge_kappa_regression.py` (reads the committed calibration
result; skips until the first one exists).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_JUDGE_PROVIDER` | `claude` | `claude` \| `ollama` \| `openai_compat` |
| `ANTHROPIC_API_KEY` | — | Required for the Claude provider |
| `LLM_JUDGE_MODEL` | `claude-opus-4-8` | Claude model id |
| `OLLAMA_MODEL` | `llama3.2` | Local Ollama model name |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon address |
| `OPENAI_COMPAT_BASE_URL` | `http://localhost:1234/v1` | OpenAI-style endpoint (default: LM Studio local server) |
| `OPENAI_COMPAT_MODEL` | — | Model name at that endpoint (required for this provider) |
| `OPENAI_COMPAT_API_KEY` | — | Bearer key, only if the endpoint needs one |
| `LLM_JUDGE_RULE_GUARDRAIL` | `1` | `0` disables the benign-override guardrail |
| `LLM_JUDGE_EFFORT` | `medium` | Claude reasoning effort (`low`/`medium`/`high`) |
| `LLM_JUDGE_TIMEOUT_S` | `300` | Per-request timeout (local models can need minutes on first load) |
| `LLM_JUDGE_MAX_CANDIDATES` | `40` | Per-batch cap; rule-triggered candidates always survive |
| `LLM_JUDGE_ENABLED` | `1` | `0` turns the judge into a no-op |

## Cost & determinism

- Each candidate is one LLM call of roughly 2–4 KB input and a small JSON
  output. Verdicts are **cached in SQLite** by a fingerprint of
  (candidate blob, prompt version, model) — re-running the same PCAP is free
  and byte-identical. Local providers cost nothing; on Claude a typical
  PCAP (5–40 candidates) costs cents on the user's own key.
- Any model change should be followed by a benchmark run (notebook
  section 0) and, for real use, a calibration run — kappa is per model.

## Calibration — the number that guards the prompt

`attack_tests/ground_truth.json` labels five real attack PCAPs. The
notebook's calibration section runs the judge over all five and computes
**Cohen's kappa** between the judge's categories and the labels:

- per-IP candidates are scored against the labeled entity lists
  (unlisted flagged IPs count as `benign_anomaly` — the false positives the
  judge is supposed to down-rank);
- aggregate-flood PCAPs are scored **only** on the session-level candidate,
  because spoofed sources have no meaningful per-IP identity.

The report lands in `calibration/results/<prompt_version>.json` and is
committed; `tests/test_judge_kappa_regression.py` gates CI on it **without
calling any LLM**. The prompt-iteration loop is documented in
`PROMPT_CHANGELOG.md`.

## Deviations from the spec (documented on purpose)

| Spec said | Implemented | Why |
|---|---|---|
| candidate kind `ip \| flow` | + `session` | Spoofed floods (37k sources) need one session-scope verdict, not thousands of meaningless per-IP ones |
| temperature 0.0 / 0.2 | no sampling params on Claude (rejected by current models); 0.0 on local providers | Determinism comes from the verdict cache |
| 15 s request timeout | 300 s default | Local models loading from disk need minutes on the first call |
| prompt-only "strict JSON" | provider structured outputs + client-side validation | Schema-valid by construction on all providers; retry-once-then-drop still applies |
| LLM verdict is final | + rule guardrail (extension) | Measured failure: small models override fired high-precision rules with "benign"; the guardrail makes that impossible while preserving the model verdict for transparency |
| dashboard UI card + Model Diagnostics pill | notebook table + JSON export | This add-on is intentionally decoupled from `app/` — the dashboard stays untouched |
| `attack_tests/calibrate_judge.py` CLI | calibration + benchmark sections inside the notebook | The notebook is the single entry point by design |
