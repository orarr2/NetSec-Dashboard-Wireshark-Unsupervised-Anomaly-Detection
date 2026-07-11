"""Configuration for the standalone LLM-as-Judge triage notebook.

Every value can be overridden with an environment variable, so switching
provider or model never requires editing code. No API key is stored here
or anywhere else in the repo: the Anthropic SDK reads ANTHROPIC_API_KEY
from the environment, and Ollama needs no key at all.
"""
import os

# Master switch (spec section 12.3). The notebook is opt-in by nature, so
# the flag mainly lets automation import the modules with the judge off.
LLM_JUDGE_ENABLED = os.environ.get("LLM_JUDGE_ENABLED", "1").lower() not in ("0", "false")

# Provider: "claude" (Anthropic API, user-supplied ANTHROPIC_API_KEY) or
# "ollama" (local model, free, needs the Ollama daemon running).
LLM_JUDGE_PROVIDER = os.environ.get("LLM_JUDGE_PROVIDER", "claude")

# Models.
CLAUDE_MODEL = os.environ.get("LLM_JUDGE_MODEL", "claude-opus-4-8")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

# Reasoning effort for the Claude call (low | medium | high). "medium"
# balances verdict quality against per-candidate cost; raise to "high" for
# calibration runs if kappa plateaus.
JUDGE_EFFORT = os.environ.get("LLM_JUDGE_EFFORT", "medium")

# Request limits. The spec drafted a 15 s timeout assuming a small instant
# model; adaptive thinking needs more headroom, hence 90 s.
JUDGE_MAX_TOKENS = int(os.environ.get("LLM_JUDGE_MAX_TOKENS", "8192"))
JUDGE_TIMEOUT_S = float(os.environ.get("LLM_JUDGE_TIMEOUT_S", "90"))

# Hard per-batch cap (spec section 17). A spoofed flood can make thousands
# of IPs statistical outliers; judging each one is cost without insight.
# Rule-triggered candidates are always kept; the remainder is ranked by
# iso_score and the overflow is reported as dropped.
MAX_CANDIDATES_PER_BATCH = int(os.environ.get("LLM_JUDGE_MAX_CANDIDATES", "40"))

# Prompt versioning (spec section 10). Bump on every prompt change, re-run
# the calibration section of the notebook, and record the kappa delta in
# PROMPT_CHANGELOG.md. The version is part of the cache fingerprint, so a
# bump automatically invalidates cached verdicts.
PROMPT_VERSION = "v0.2.0"

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
# gitignored; calibration results are committed.
_HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DB = os.path.join(_HERE, "cache", "judge_cache.sqlite")
OUTPUT_DIR = os.path.join(_HERE, "output")
RESULTS_DIR = os.path.join(_HERE, "calibration", "results")
