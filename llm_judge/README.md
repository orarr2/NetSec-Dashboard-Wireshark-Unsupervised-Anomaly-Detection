# LLM-as-Judge - Standalone Triage Notebook

An **optional, fully self-contained add-on** to the NetSec Dashboard.
The main dashboard (`app/Network_Security_Dashboard.ipynb`) runs exactly as
before and knows nothing about this folder; if you never open this notebook,
nothing here ever executes.

What it does (design: [`docs/LLM_JUDGE_SPEC.md`](../docs/LLM_JUDGE_SPEC.md)):
the detection pipeline already produces per-IP ML scores (IsolationForest,
DBSCAN), deterministic rule alerts (scans, floods, DNS amplification, ARP
spoofing) - but each signal arrives separately and the analyst is the one
fusing them. This notebook sends every flagged candidate, with all of its
signals in one compact JSON blob, to an LLM that returns a **single strict
JSON verdict**: `benign | suspicious | malicious`, an attack category, a
confidence, the evidence it used, and a one-paragraph reasoning trace. The
queue is then re-ranked by an ensemble score and shown as a table.

The judge **never acts** - `recommended_action: "block"` is a suggestion for
a human, wired to nothing.

## Providers - bring your own model

Three built-in providers plus arbitrarily many **named endpoint
profiles**. Pick a single-judge run with `LLM_JUDGE_PROVIDER`, or a
multi-provider panel with `LLM_JUDGE_PANEL`:

| Provider | What it is | Setup | Cost |
|---|---|---|---|
| `claude` (default) | Anthropic API - best JSON quality | `pip install -r llm_judge/requirements.txt` + set `ANTHROPIC_API_KEY` with **your own** key | your key, cents per PCAP |
| `ollama` | Local model via the Ollama daemon | install from <https://ollama.com>, `ollama pull qwen2.5:14b` (or any other model) | free, offline |
| `openai_compat` | Any OpenAI-style chat-completions endpoint: LM Studio / llamafile / vLLM locally, or hosted services that expose the OpenAI protocol | set `OPENAI_COMPAT_BASE_URL` + `OPENAI_COMPAT_MODEL` (+ `OPENAI_COMPAT_API_KEY` if the endpoint needs one) | free locally; hosted per its own terms |
| **Endpoint profile** | A named OpenAI-compatible host, so one panel can mix several providers (Groq + Gemini + …) without editing code | Define three env vars per profile: `LLM_JUDGE_EP_<NAME>_BASE_URL`, `LLM_JUDGE_EP_<NAME>_MODEL`, `LLM_JUDGE_EP_<NAME>_KEY_ENV=<env-var-holding-the-key>`. `deploy/.env.example` ships five ready-to-go profiles: `GROQ`, `GEMINI`, `CEREBRAS`, `OPENROUTER`, `GITHUB`. Reference them in a panel as `groq:<model>`, `gemini:<model>`, ... | per provider's free-tier terms |

**No API key is ever stored in this repo.** Keys are read from the
environment at call time; each user pays (or doesn't) for their own usage.
The endpoint-profile mechanism deliberately does not borrow the global
`OPENAI_COMPAT_API_KEY` or `OPENAI_COMPAT_MODEL`: a profile's key and
model must be its own, so a wrong key never leaks across providers.

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

## Qualify a model before trusting it - the benchmark

`benchmark_fixtures.json` holds **11 labeled candidates extracted from the
five real attack PCAPs** by the production pipeline. Section 0 of the
notebook judges all of them with any model you name and scores it:

- **detection rate** - attack candidates judged non-benign (with the rule
  guardrail this is 1.0 for any model that returns valid JSON);
- **category accuracy** - exact attack-category match: where model quality
  actually shows;
- **benign accuracy** - ML-only outliers correctly left benign.

Measured on a CPU-only machine (11 fixtures, guardrail on): `llama3.2`
(3B) scored 100% category accuracy - but 7 of its 7 attack verdicts were
guardrail rescues (raw model said benign); `gemma3:4b` scored 91% with
zero rescues (its raw verdicts were already non-benign). Small local
models are thus usable for detection-level triage; their raw judgment
quality only shows on candidates no rule covers, which is where a
stronger model still earns its keep.

## Expert panel - a network of judges (opt-in)

Instead of trusting one model, `LLM_JUDGE_PANEL` runs every candidate
through **N independent judges** and makes them argue before anything is
reported:

```bash
# Two Groq models on one key (comma-separated, same provider):
set LLM_JUDGE_PANEL=llama-3.3-70b-versatile,llama-3.1-8b-instant
# Or mix providers explicitly with "provider:model" entries:
set LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,ollama:llama3.2
```

Flow per candidate:

1. **Independent round** - every judge returns a strict-schema verdict
   (cached per model, so re-runs are free).
2. **Debate round** - only when judges disagree on the verdict or the
   category: each judge sees the peers' anonymized analyses and must
   either **revise** its position or **defend** it with a rebuttal that
   cites fields from the candidate blob. Agreed candidates never trigger
   extra calls.
3. **Deterministic resolution** - consensus takes the highest-confidence
   verdict; a surviving dispute takes the fail-safe (more severe) side
   and flags `needs_human_review` (⚖). The rule guardrail still sits
   above the whole panel.

Every run also emits a **participation report** (in `verdicts.json` and
the markdown): per model - candidates received, valid verdicts, failures
(with examples), debates, revisions, agreement with the final verdict,
cache hits and mean latency. A judge that fails to initialize or answers
garbage is excluded/logged and the remaining judges carry the batch; the
run only fails when fewer than two judges can be constructed.

Adding another engine = adding one entry to `LLM_JUDGE_PANEL` (optionally
with a `provider:` prefix). No code changes. Two judges must not share a
model name - verdicts are cached per model id, so duplicates would fake
agreement.

The older `LLM_JUDGE_COMMITTEE` (fixed two-model shape, no debate) is
kept as a legacy mode; when both are set, the panel wins.

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
| `LLM_Judge_Notebook.ipynb` | Interactive entry point (Jupyter) |
| `judge_cli.py` | **Headless CLI** - same pipeline, no Jupyter, used by the GitHub Actions workflow (also handy locally) |
| `judge_config.py` | Provider/model, guardrail, weights, thresholds, prompt version |
| `judge_core.py` | Candidate assembly, system prompt, verdict validation, rule guardrail, SQLite cache, ensemble ranking |
| `llm_clients.py` | `ClaudeClient` + `OllamaClient` + `OpenAICompatClient` |
| `benchmark.py` | Model qualification: judge the labeled fixtures, score accuracy/latency |
| `benchmark_fixtures.json` | 11 labeled candidates extracted from the attack PCAPs (committed) |
| `calibration.py` | Cohen's-kappa calibration against `attack_tests/ground_truth.json` |
| `send_report.py` | Standalone SMTP delivery (used by `judge_cli --email`, by the GitHub Actions workflow, and importable from anywhere in the project - Gmail App Password default, any SMTP host works) |
| `threat_intel.py` | Merges Shodan reputation into a candidate's TI signal + ranking weight (`W_TI`); loaded by the VM worker's re-rank pass |
| `quota.py` | `QuotaStore` - a small SQLite counter for per-provider daily request / token counts, wired to the `usage` field the OpenAI-compatible clients return. Informational; nothing auto-skips a provider that hits its limit |
| `requirements.txt` | Optional judge-only deps (`anthropic`) on top of the project root `requirements.txt` |
| `schemas/*.schema.json` | The input/output JSON contracts |
| `PROMPT_CHANGELOG.md` | Prompt version history + kappa per version |
| `calibration/results/` | Committed calibration reports (CI gate reads the newest) |
| `cache/`, `output/` | Runtime artifacts - gitignored, safe to delete |

## Run without Jupyter - the CLI

```bash
python llm_judge/judge_cli.py path/to.pcap \
    --output verdicts.json \
    --markdown verdicts.md
```

Same detection pipeline as the notebook, same guardrail, same provider
env vars. Writes:

- `verdicts.json` - full machine-readable batch (stats + ranked results + drops + capped).
- `verdicts.md` - GitHub-Issue-friendly report with the verdict table.

This is the entry point of the autonomous-agent path below.

## Autonomous agent - GitHub Actions (no VM needed)

`.github/workflows/analyze-pcap.yml` turns the judge into a hands-off
agent that runs in GitHub's cloud, free of charge, on any PCAP you push
(or on demand from mobile). Flow:

1. Push a `.pcap`/`.pcapng` to `incoming/` (or **Actions → Analyze PCAP →
   Run workflow** for a manual trigger with a chosen path/model).
2. A GitHub-hosted runner: installs `tshark`, installs the project's
   Python deps, installs Ollama (default model `llama3.2`, cached
   between runs), and calls `judge_cli.py`.
3. Uploads `verdicts.json` + `verdicts.md` + logs as a run artifact.
4. Opens a **GitHub Issue** with the verdict table, labeled
   `judge-verdict` - visible from mobile without leaving GitHub.

Cost: `ubuntu-latest` runners are free (unlimited on public repos; 2,000
min/month on private). Ollama runs locally on the runner, so no LLM API
key or bill. See `incoming/README.md` for the full trigger reference.

Tests live with the rest of the suite: `tests/test_llm_judge_unit.py` and
`tests/test_llm_judge_providers.py` (mocked LLM + in-process mock
OpenAI-compatible server - no network), and
`tests/test_judge_kappa_regression.py` (reads the committed calibration
result; skips until the first one exists).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_JUDGE_PROVIDER` | `claude` | `claude` \| `ollama` \| `openai_compat` |
| `ANTHROPIC_API_KEY` | - | Required for the Claude provider |
| `LLM_JUDGE_MODEL` | `claude-opus-4-8` | Claude model id |
| `OLLAMA_MODEL` | `llama3.2` | Local Ollama model name |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon address |
| `OPENAI_COMPAT_BASE_URL` | `http://localhost:1234/v1` | OpenAI-style endpoint (default: LM Studio local server) |
| `OPENAI_COMPAT_MODEL` | - | Model name at that endpoint (required for this provider) |
| `OPENAI_COMPAT_API_KEY` | - | Bearer key, only if the endpoint needs one |
| `LLM_JUDGE_EP_<NAME>_BASE_URL` / `_MODEL` / `_KEY_ENV` | - | Named endpoint profile (see the Providers section). Any number of profiles; referenced in a panel as `<name>:<model>`. |
| `LLM_JUDGE_PANEL` | - | Expert panel: comma-separated judges (`model` or `provider:model`), min 2 distinct; empty = off. Wins over `LLM_JUDGE_PROVIDER` for the run |
| `LLM_JUDGE_DEBATE` | `1` | `0` skips the debate round (plain N-way vote) |
| `LLM_JUDGE_PANEL_QUORUM` | `majority` | How a split panel resolves. `majority`: a strict majority (>50%) of valid judges picks the label; with no majority the most severe side wins and the candidate is flagged `needs_human_review`. `fail-safe`: the most severe label always wins on any split (pre-v0.5 behaviour) |
| `LLM_JUDGE_GUARDRAIL_ESCAPE` | `1` | Narrow escape hatch for the rule guardrail: a `benign` verdict at confidence >= 0.85 citing whitelisted evidence (public resolver / anycast / known cloud provider) is let through instead of escalated. Every bypass is recorded as `guardrail_bypassed`. `0` overrides every benign-on-fired-rule |
| `LLM_JUDGE_BATCH_SIZE` | `1` | Candidates packed into one call during the panel's initial round. `1` = per-candidate. Size it from arithmetic: a request costs `1675 + n x 720` tokens (measured 2026-08 - the system prompt is ~1675 tokens paid once per call, each candidate blob ~720). Against Groq's free per-minute ceiling of 6000 for `llama-3.1-8b-instant`, `n=3` costs 3835 and fits with room; `n=5` costs 5275, i.e. 88% of the whole minute in one request, so any concurrent call throttles it into the per-candidate fallback it was meant to replace. `n=3` also spends 47% fewer tokens per capture than `n=1` |
| `LLM_JUDGE_COMMITTEE` | `0` | Legacy two-judge committee mode. Superseded by `LLM_JUDGE_PANEL` |
| `LLM_JUDGE_COMMITTEE_MODEL_B` | `llama-3.1-8b-instant` | Second model for the legacy committee |
| `LLM_JUDGE_RULE_GUARDRAIL` | `1` | `0` disables the benign-override guardrail |
| `LLM_JUDGE_EFFORT` | `medium` | Claude reasoning effort (`low`/`medium`/`high`) |
| `LLM_JUDGE_TIMEOUT_S` | `300` | Per-request timeout (local models can need minutes on first load) |
| `LLM_JUDGE_MAX_TOKENS` | `8192` | Max output tokens per verdict |
| `LLM_JUDGE_MAX_CANDIDATES` | `40` | Per-batch cap; rule-triggered candidates always survive |
| `LLM_JUDGE_KAPPA_THRESHOLD` | `0.60` | CI regression gate on category-kappa (`tests/test_judge_kappa_regression.py`) |
| `LLM_JUDGE_QUOTA_DB` | `llm_judge/cache/llm_quota.sqlite` | Where `QuotaStore` writes per-provider daily usage counters |
| `LLM_JUDGE_ENABLED` | `1` | `0` turns the judge into a no-op |
| `SMTP_USER` | - | Mailbox to send the report from (enables `--email`) |
| `SMTP_PASS` | - | App password for that mailbox |
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server |
| `SMTP_PORT` | `587` | `587` STARTTLS, `465` implicit TLS |
| `SMTP_FROM` | `SMTP_USER` | Override the From: header |

## Email the report

`send_report.py` mails a rendered report to any address, using stdlib
`smtplib` and whatever mailbox the SMTP variables above point at - no
third-party service, no account here:

```bash
# during a run
python llm_judge/judge_cli.py capture.pcap --email you@example.com

# or for a report that already exists
python llm_judge/send_report.py verdicts.md you@example.com --json verdicts.json
```

The markdown is converted to HTML for the body and kept as the
plain-text alternative, with `verdicts.json` attached. A delivery
failure is reported and returns a non-zero exit code from the standalone
CLI, but never aborts `judge_cli.py` - an analysis that already ran is
not thrown away because a mailbox rejected a login. The same module
backs the `notify_email` input of `.github/workflows/analyze-pcap.yml`.

## Cost & determinism

- Each candidate is one LLM call of roughly 2-4 KB input and a small JSON
  output. Verdicts are **cached in SQLite** by a fingerprint of
  (candidate blob, prompt version, model) - re-running the same PCAP is free
  and byte-identical. Local providers cost nothing; on Claude a typical
  PCAP (5-40 candidates) costs cents on the user's own key.
- Any model change should be followed by a benchmark run (notebook
  section 0) and, for real use, a calibration run - kappa is per model.

## Calibration - the number that guards the prompt

`attack_tests/ground_truth.json` labels five real attack PCAPs. The
notebook's calibration section runs the judge over all five and computes
**Cohen's kappa** between the judge's categories and the labels:

- per-IP candidates are scored against the labeled entity lists
  (unlisted flagged IPs count as `benign_anomaly` - the false positives the
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
| dashboard UI card + Model Diagnostics pill | notebook table + JSON export | This add-on is intentionally decoupled from `app/` - the dashboard stays untouched |
| `attack_tests/calibrate_judge.py` CLI | calibration + benchmark sections inside the notebook | The notebook is the single entry point by design |
