"""Configuration for the standalone LLM-as-Judge triage notebook.

Every value can be overridden with an environment variable, so switching
provider or model never requires editing code. No API key is stored here
or anywhere else in the repo: keys are read from the environment at call
time (ANTHROPIC_API_KEY / OPENAI_COMPAT_API_KEY); Ollama needs no key.
"""
import os

# Master switch (spec section 12.3). The notebook is opt-in by nature, so
# the flag mainly lets automation import the modules with the judge off.
LLM_JUDGE_ENABLED = os.environ.get("LLM_JUDGE_ENABLED", "1").lower() not in ("0", "false")

# Provider:
#   "claude"        - Anthropic API (user-supplied ANTHROPIC_API_KEY)
#   "ollama"        - local model, free, needs the Ollama daemon running
#   "openai_compat" - any OpenAI-compatible endpoint: LM Studio / llamafile /
#                     vLLM locally, or hosted services that expose an
#                     OpenAI-style API (several have free tiers) with the
#                     user's own key
LLM_JUDGE_PROVIDER = os.environ.get("LLM_JUDGE_PROVIDER", "claude")

# Models.
CLAUDE_MODEL = os.environ.get("LLM_JUDGE_MODEL", "claude-opus-4-8")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
# OpenAI-compatible endpoint. The default base URL is LM Studio's local
# server. The API key (only if the endpoint needs one) is read from
# OPENAI_COMPAT_API_KEY at call time and never stored anywhere.
OPENAI_COMPAT_BASE_URL = os.environ.get("OPENAI_COMPAT_BASE_URL",
                                        "http://localhost:1234/v1")
OPENAI_COMPAT_MODEL = os.environ.get("OPENAI_COMPAT_MODEL", "")

# Reasoning effort for the Claude call (low | medium | high). "medium"
# balances verdict quality against per-candidate cost; raise to "high" for
# calibration runs if kappa plateaus.
JUDGE_EFFORT = os.environ.get("LLM_JUDGE_EFFORT", "medium")

# Request limits. The spec drafted a 15 s timeout assuming a small instant
# model; measured reality: a local model that has to load from disk can
# spend 2-3 minutes on its first call, so the default gives real headroom.
JUDGE_MAX_TOKENS = int(os.environ.get("LLM_JUDGE_MAX_TOKENS", "8192"))
JUDGE_TIMEOUT_S = float(os.environ.get("LLM_JUDGE_TIMEOUT_S", "300"))

# Rule guardrail. The deterministic rule layer is high-precision, but small
# local models were measured overriding a fired rule with "benign" (and
# hallucinating that no rule fired). With the guardrail on, a candidate
# whose deterministic rule fired can never end up "benign": the verdict is
# raised to "suspicious" with the rule-implied category, the model's
# original verdict is preserved in the result for transparency, and the
# override is marked. Applied at result time - never written to the cache.
RULE_GUARDRAIL = os.environ.get("LLM_JUDGE_RULE_GUARDRAIL",
                                "1").lower() not in ("0", "false")

# Hard per-batch cap (spec section 17). A spoofed flood can make thousands
# of IPs statistical outliers; judging each one is cost without insight.
# Rule-triggered candidates are always kept; the remainder is ranked by
# iso_score and the overflow is reported as dropped.
MAX_CANDIDATES_PER_BATCH = int(os.environ.get("LLM_JUDGE_MAX_CANDIDATES", "40"))

# Committee mode (opt-in). When on, every candidate is judged by TWO models
# and the verdicts are combined: on agreement the higher-confidence verdict
# wins; on disagreement the more-severe verdict is used and the candidate is
# flagged needs_human_review. Doubles LLM calls, so it stays off by default.
# Judge A is the configured provider/model; Judge B is COMMITTEE_MODEL_B on
# the SAME provider (so a single Groq key drives both).
LLM_JUDGE_COMMITTEE = os.environ.get("LLM_JUDGE_COMMITTEE",
                                     "0").lower() not in ("0", "false")
COMMITTEE_MODEL_B = os.environ.get("LLM_JUDGE_COMMITTEE_MODEL_B",
                                   "llama-3.1-8b-instant")

# Prompt versioning (spec section 10). Bump on every prompt change, re-run
# the calibration section of the notebook, and record the kappa delta in
# PROMPT_CHANGELOG.md. The version is part of the cache fingerprint, so a
# bump automatically invalidates cached verdicts.
PROMPT_VERSION = "v0.3.0"

# Ensemble weights (spec section 9).
W_ANOM = 0.20        # baseline detector floor
W_JUDGE_CONF = 0.40  # the judge is the primary signal
W_CAT = 0.30         # punishes benign_anomaly, rewards attack categories
W_TI = 0.10          # reserved for future threat-intel integration
CATEGORY_WEIGHT = {
    "syn_flood": 1.0,
    "dns_amp": 1.0,
    "arp_mitm": 1.0,
    "port_scan": 0.8,
    "beaconing_c2": 0.9,
    "dns_tunnel": 0.9,
    "benign_anomaly": 0.0,
}

# Calibration gate (rollout step 5): start at 0.60, below the first
# measured value, and raise to 0.65 after two successful prompt iterations.
KAPPA_THRESHOLD = float(os.environ.get("LLM_JUDGE_KAPPA_THRESHOLD", "0.60"))

# Filesystem layout - runtime artifacts stay inside llm_judge/ and are
# gitignored; calibration results and benchmark fixtures are committed.
_HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DB = os.path.join(_HERE, "cache", "judge_cache.sqlite")
OUTPUT_DIR = os.path.join(_HERE, "output")
RESULTS_DIR = os.path.join(_HERE, "calibration", "results")
BENCHMARK_FIXTURES = os.path.join(_HERE, "benchmark_fixtures.json")
