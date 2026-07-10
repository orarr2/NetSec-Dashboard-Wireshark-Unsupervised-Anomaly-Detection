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

## Quick start

```bash
# 1. Project prerequisites (once): tshark on PATH + root requirements.txt
pip install -r requirements.txt

# 2. Judge extras (once)
pip install -r llm_judge/requirements.txt

# 3. Pick a provider
#    Option A - Claude API (best JSON quality; you bring your own key):
set ANTHROPIC_API_KEY=sk-ant-...        # Windows;  export ... on Linux/macOS

#    Option B - Ollama (free, local, offline):
set LLM_JUDGE_PROVIDER=ollama
ollama pull llama3.1                    # once; daemon must be running

# 4. Open the notebook and run top to bottom
jupyter notebook llm_judge/LLM_Judge_Notebook.ipynb
```

**No API key is ever stored in this repo.** The Anthropic SDK reads
`ANTHROPIC_API_KEY` from your environment; each user pays for their own
usage. Ollama requires no key and no internet.

## Files

| File | Role |
|---|---|
| `LLM_Judge_Notebook.ipynb` | The user-facing entry point — the only thing you run |
| `judge_config.py` | Feature flag, provider/model, weights, thresholds, prompt version |
| `judge_core.py` | Candidate assembly, system prompt, verdict validation, SQLite cache, ensemble ranking |
| `llm_clients.py` | `ClaudeClient` (Anthropic SDK) + `OllamaClient` (stdlib REST) |
| `calibration.py` | Cohen's-kappa calibration against `attack_tests/ground_truth.json` |
| `schemas/*.schema.json` | The input/output JSON contracts |
| `PROMPT_CHANGELOG.md` | Prompt version history + kappa per version |
| `calibration/results/` | Committed calibration reports (CI gate reads the newest) |
| `cache/`, `output/` | Runtime artifacts — gitignored, safe to delete |

Tests live with the rest of the suite: `tests/test_llm_judge_unit.py`
(mocked LLM, no network) and `tests/test_judge_kappa_regression.py`
(reads the committed calibration result; skips until the first one exists).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_JUDGE_PROVIDER` | `claude` | `claude` or `ollama` |
| `ANTHROPIC_API_KEY` | — | Required for the Claude provider |
| `LLM_JUDGE_MODEL` | `claude-opus-4-8` | Claude model id |
| `OLLAMA_MODEL` | `llama3.1` | Local model name |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon address |
| `LLM_JUDGE_EFFORT` | `medium` | Claude reasoning effort (`low`/`medium`/`high`) |
| `LLM_JUDGE_MAX_CANDIDATES` | `40` | Per-batch cap; rule-triggered candidates always survive |
| `LLM_JUDGE_ENABLED` | `1` | `0` turns the judge into a no-op |

## Cost & determinism

- Each candidate is one LLM call of roughly 2–4 KB input and a small JSON
  output. Verdicts are **cached in SQLite** by a fingerprint of
  (candidate blob, prompt version, model) — re-running the same PCAP is free
  and byte-identical. On a typical PCAP (5–40 candidates) a Claude run costs
  cents; Ollama costs nothing.
- Cost-sensitive batches can switch to a smaller model via
  `LLM_JUDGE_MODEL` (e.g. `claude-haiku-4-5`) — re-run calibration after
  any model change, since kappa is measured per model.

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
| temperature 0.0 / 0.2 | no sampling params | Current Claude models reject `temperature`; determinism comes from the verdict cache instead |
| 15 s request timeout | 90 s default | Adaptive thinking needs headroom |
| prompt-only "strict JSON" | provider structured outputs + client-side validation | Schema-valid by construction on both providers; retry-once-then-drop still applies |
| dashboard UI card + Model Diagnostics pill | notebook table + JSON export | This add-on is intentionally decoupled from `app/` — the dashboard stays untouched |
| `attack_tests/calibrate_judge.py` CLI | calibration section inside the notebook | The notebook is the single entry point by design |
