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

# Expert panel (opt-in; generalizes committee mode to N models plus a
# debate round). Comma-separated judge list; each entry is a model name on
# the configured provider, optionally prefixed with an explicit provider:
#   LLM_JUDGE_PANEL="llama-3.3-70b-versatile,llama-3.1-8b-instant"
#   LLM_JUDGE_PANEL="openai_compat:llama-3.3-70b-versatile,ollama:llama3.2"
# Empty (the default) = panel off. When set, the panel takes precedence
# over LLM_JUDGE_COMMITTEE. At least two distinct models are required
# (verdicts are cached per model id, so duplicates would fake agreement).
LLM_JUDGE_PANEL = os.environ.get("LLM_JUDGE_PANEL", "").strip()

# Debate round. When panel judges disagree on the verdict label or the
# category, each judge that returned a valid verdict receives the peers'
# anonymized analyses and must either revise its position or defend it
# with a rebuttal grounded in the candidate blob. Costs one extra call per
# valid judge per DISPUTED candidate only; agreed candidates never debate.
LLM_JUDGE_DEBATE = os.environ.get("LLM_JUDGE_DEBATE",
                                  "1").lower() not in ("0", "false")

# Panel resolution policy when judges split on the verdict label.
# "majority" (default v0.5) requires strict majority (>50%) to pick a label;
#     without a majority, falls back to fail-safe (most severe wins) and
#     flags needs_human_review. This is SCIENTIFIC_AUDIT 3.2 - one
#     hallucinating judge in a 3+ panel should not outvote two peers.
# "fail-safe" (pre-v0.5 behavior) always takes the most severe label on
#     any label split. Set this when you want the paranoid default.
LLM_JUDGE_PANEL_QUORUM = os.environ.get("LLM_JUDGE_PANEL_QUORUM",
                                         "majority").lower()

# SCIENTIFIC_AUDIT 3.1: narrow escape hatch for the rule guardrail. When
# on (default), a benign verdict at confidence >= 0.85 that cites one of
# the whitelisted evidence patterns (public resolver, anycast, known
# cloud provider) is allowed through instead of being escalated to
# suspicious. Every bypass is logged in the guardrail info as
# `guardrail_bypassed: True` for audit. Set to 0 to force the strict
# pre-v0.5 behaviour where every benign-on-fired-rule is overridden.
LLM_JUDGE_GUARDRAIL_ESCAPE = os.environ.get("LLM_JUDGE_GUARDRAIL_ESCAPE",
                                             "1").lower() not in ("0", "false")

# Named endpoint profiles (spec section 6.1, decision IDX-05). Each profile
# is an OpenAI-compatible host that can appear in a panel by name, so one
# panel can mix several providers (Groq + Gemini + local Ollama) - which a
# single global base_url/key could not express. Defined entirely by env:
#
#   LLM_JUDGE_EP_<NAME>_BASE_URL   required - the /v1 chat-completions root
#   LLM_JUDGE_EP_<NAME>_MODEL      default model for the profile
#   LLM_JUDGE_EP_<NAME>_KEY_ENV    name of the env var holding the API key
#                                  (indirection so keys are never inlined)
#
# A profile named GEMINI becomes provider "gemini" in a panel spec, e.g.
#   LLM_JUDGE_PANEL="groq:llama-3.3-70b-versatile,gemini:gemini-2.5-flash"
def endpoint_profiles(env=None):
    """Discover {name: {base_url, model, key_env, api_key}} from the
    environment. Only profiles with a base URL are returned."""
    env = os.environ if env is None else env
    prefix, suffix = "LLM_JUDGE_EP_", "_BASE_URL"
    profiles = {}
    for key, base_url in env.items():
        if not (key.startswith(prefix) and key.endswith(suffix)):
            continue
        name = key[len(prefix):-len(suffix)].lower()
        if not name or not base_url.strip():
            continue
        up = name.upper()
        key_env = env.get(f"{prefix}{up}_KEY_ENV", "").strip()
        profiles[name] = {
            "base_url": base_url.strip(),
            "model": env.get(f"{prefix}{up}_MODEL", "").strip() or None,
            "key_env": key_env or None,
            "api_key": env.get(key_env, "").strip() if key_env else "",
        }
    return profiles


# Where per-provider usage counters live (informational; spec 6.3,
# llm_quota schema). Lets you see how close a provider is to its free-tier
# limit - there is no automatic fallback, the panel simply runs whatever
# judges you selected. A standalone sqlite by default so llm_judge stays
# independent of the VM history DB; the worker can point this at netsec.db.
_HERE_Q = os.path.dirname(os.path.abspath(__file__))
QUOTA_DB = os.environ.get("LLM_JUDGE_QUOTA_DB",
                          os.path.join(_HERE_Q, "cache", "llm_quota.sqlite"))

# Prompt versioning (spec section 10). Bump on every prompt change, re-run
# the calibration section of the notebook, and record the kappa delta in
# PROMPT_CHANGELOG.md. The version is part of the cache fingerprint, so a
# bump automatically invalidates cached verdicts.
PROMPT_VERSION = "v0.4.0"  # I2: blob enrichments (time, device, websites, traffic)

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
