"""Curated LLM panel presets exposed in the dashboard "Send to VM" button.

Each preset is a `(id, label, spec, notes)` tuple where `spec` is a
valid `LLM_JUDGE_PANEL` string (comma-separated `provider:model` entries).

Guidance for picking a preset was measured on the reference VM
(Oracle Always Free ARM, 4 vCPU, 24 GB RAM, CPU-only Ollama):

* Wall-clock per candidate ≈ max(judge_latencies) because
  ThreadPoolExecutor fans out. BUT Ollama serialises inference on CPU
  when >1 local model is loaded, so N local models add N × 55 s.
* Cloud judges (Groq, Gemini) don't compete for VM CPU - they run on
  their own infrastructure. Cost 0 disk / 0 RAM here.
* Free tiers as of 2026-08:
    - Groq: 100k tokens/day per model, ~30 rpm
    - Gemini: 15 rpm, 1M tokens/day
    - Ollama: unlimited, but each candidate costs ~55 s per model.

Add a new preset here (name + spec) and it appears in the dashboard
dropdown automatically. Deleting or renaming a preset breaks any
historical audit that references its id, so append-only in prod.
"""

# id -> (label, spec, latency_hint, notes)
PRESETS = {
    "fast_cloud_3": {
        "label": "Fast cloud x3 (2 Groq + Gemini) - ~1-2 s / candidate",
        "spec": ("groq:llama-3.1-8b-instant,"
                 "groq:llama-3.3-70b-versatile,"
                 "gemini:gemini-2.5-flash"),
        "wallclock_per_candidate_s": 2,
        "notes": ("Fastest option. Three cloud judges, all parallel. "
                  "Diverse family split (2x Meta + 1x Google). Zero "
                  "load on the VM. Best for a 30+ candidate capture."),
    },
    "balanced_4": {
        "label": "Balanced x4 (2 Groq + Gemini + qwen local) - ~55 s / candidate",
        "spec": ("groq:llama-3.1-8b-instant,"
                 "groq:llama-3.3-70b-versatile,"
                 "gemini:gemini-2.5-flash,"
                 "ollama:qwen2.5:3b"),
        "wallclock_per_candidate_s": 55,
        "notes": ("Default. Three cloud + one local for zero-key "
                  "fallback + out-of-family diversity (Alibaba). "
                  "Qwen dominates wall-clock; Groq/Gemini idle waiting."),
    },
    "fresh_cloud_3": {
        "label": "Fresh-quota cloud x3 (2 GPT-OSS + Qwen3.6) - ~2-3 s / candidate",
        "spec": ("groq:openai/gpt-oss-20b,"
                 "groq:openai/gpt-oss-120b,"
                 "groq:qwen/qwen3.6-27b"),
        "wallclock_per_candidate_s": 3,
        "notes": ("Groq quotas are PER MODEL - these three share the "
                  "same API key as fast_cloud_3 but draw from three "
                  "SEPARATE daily token pools. Use when the llama pool "
                  "is exhausted (measured 2026-08-01: llama-70b hit its "
                  "100k TPD mid-run). OpenAI open-weights x2 + Alibaba."),
    },
    "cloud_max_6": {
        "label": "Cloud max x6 (2 llama + Gemini + 2 GPT-OSS + Qwen3.6) - ~3 s / candidate",
        "spec": ("groq:llama-3.1-8b-instant,"
                 "groq:llama-3.3-70b-versatile,"
                 "gemini:gemini-2.5-flash,"
                 "groq:openai/gpt-oss-20b,"
                 "groq:openai/gpt-oss-120b,"
                 "groq:qwen/qwen3.6-27b"),
        "wallclock_per_candidate_s": 3,
        "notes": ("Every cloud judge at once: Meta x2 + Google + "
                  "OpenAI x2 + Alibaba, six separate quota pools, zero "
                  "VM load, all parallel. The strongest fast option "
                  "for a big capture when diversity matters."),
    },
    "local_only_2": {
        "label": "Local only x2 (qwen + gemma, zero API) - ~110 s / candidate",
        "spec": "ollama:qwen2.5:3b,ollama:gemma2:2b",
        "wallclock_per_candidate_s": 110,
        "notes": ("Zero external calls. Runs entirely on the VM. Both "
                  "models compete for 4 vCPU so wall-clock is sum, not "
                  "max. Use when no cloud key is available or all "
                  "data must stay on the box."),
    },
    "local_diverse_5": {
        "label": "Local diverse x5 (qwen + gemma + phi3.5 + llama3.2 + granite) - ~250 s / candidate",
        "spec": ("ollama:qwen2.5:3b,ollama:gemma2:2b,"
                 "ollama:phi3.5,ollama:llama3.2:3b,ollama:granite3.3:2b"),
        "wallclock_per_candidate_s": 250,
        "notes": ("Alibaba + Google + Microsoft + Meta + IBM locally. "
                  "Five models compete for 4 vCPU serially: sum of "
                  "latencies. Highest zero-key family diversity - one "
                  "model per major LLM lab."),
    },
    "hybrid_6": {
        "label": "Hybrid x6 (2 Groq + Gemini + qwen + gemma + llama3.2) - ~165 s / candidate",
        "spec": ("groq:llama-3.1-8b-instant,"
                 "groq:llama-3.3-70b-versatile,"
                 "gemini:gemini-2.5-flash,"
                 "ollama:qwen2.5:3b,"
                 "ollama:gemma2:2b,"
                 "ollama:llama3.2:3b"),
        "wallclock_per_candidate_s": 165,
        "notes": ("Full diversity: 3 cloud + 3 local. Wall-clock ≈ "
                  "sum of the 3 local models. Best resolver stability "
                  "at 6+ voters. Adds Meta locally next to Google/Alibaba."),
    },
    "max_11": {
        "label": "Maximum x11 (6 cloud + 5 local) - ~250 s / candidate, VERY SLOW",
        "spec": ("groq:llama-3.1-8b-instant,"
                 "groq:llama-3.3-70b-versatile,"
                 "gemini:gemini-2.5-flash,"
                 "groq:openai/gpt-oss-20b,"
                 "groq:openai/gpt-oss-120b,"
                 "groq:qwen/qwen3.6-27b,"
                 "ollama:qwen2.5:3b,"
                 "ollama:gemma2:2b,"
                 "ollama:phi3.5,"
                 "ollama:llama3.2:3b,"
                 "ollama:granite3.3:2b"),
        "wallclock_per_candidate_s": 250,
        "notes": ("Every configured judge: 6 cloud (Meta x2, Google, "
                  "OpenAI x2, Alibaba) + 5 local (Alibaba, Google, "
                  "Microsoft, Meta, IBM). Ollama CPU contention makes "
                  "this slow (5 local serial). Only for tiny captures "
                  "(<5 candidates) where maximum diversity matters "
                  "more than anything."),
    },
    "reliable_hybrid_4": {
        "label": "Reliable hybrid x4 (2 proven cloud + 2 local) - ~55 s / candidate",
        "spec": ("groq:llama-3.1-8b-instant,"
                 "groq:openai/gpt-oss-120b,"
                 "ollama:qwen2.5:3b,"
                 "ollama:granite3.3:2b"),
        "wallclock_per_candidate_s": 55,
        "notes": ("Default. Picked from measured production yield, not "
                  "from model reputation. Over sessions 10-15 on the "
                  "reference VM: llama-3.1-8b answered 93% of assigned "
                  "candidates and gpt-oss-120b 88%, while "
                  "gemini-2.5-flash managed 4% (AI Studio credits "
                  "exhausted), llama-3.3-70b 22% (100k-token daily pool "
                  "spent inside one capture) and qwen3.6-27b 15%. The "
                  "two local judges have no quota at all and answered "
                  "every timed probe, so a dead cloud key degrades this "
                  "panel to 2 working judges instead of 0. Families: "
                  "Meta + OpenAI + Alibaba + IBM."),
    },
    "single_groq_fast": {
        "label": "Single judge (Groq 8B, no panel) - ~0.5 s / candidate, no debate",
        "spec": "",  # empty spec disables panel; single-judge fallback fires
        "single_judge_model": "llama-3.1-8b-instant",
        "wallclock_per_candidate_s": 0.5,
        "notes": ("Fastest possible. Single Groq call per candidate. "
                  "No debate, no resolver - the model's answer is "
                  "final. Use for smoke tests."),
    },
    # Two-choice UI presets (dashboard dropdown shows only these).
    # `cloud` fans out to every free cloud key wired on the VM; a judge
    # whose key is missing or whose endpoint 4xx's is logged as an
    # init/verdict failure and the panel keeps going with the rest.
    # `local` fans out to every chat-capable Ollama model installed on
    # the VM, so a new model that shows up in `ollama list` is added
    # here and lands in the dropdown automatically (no idle-VM models).
    "cloud": {
        "label": "Cloud",
        "spec": ("groq:llama-3.3-70b-versatile,"
                 "groq:openai/gpt-oss-20b,"
                 "groq:openai/gpt-oss-120b,"
                 "groq:qwen/qwen3.6-27b,"
                 "gemini:gemini-2.5-flash,"
                 "cerebras:llama-3.3-70b,"
                 "openrouter:deepseek/deepseek-r1:free,"
                 "github:gpt-4o-mini"),
        "wallclock_per_candidate_s": 5,
        "notes": ("Every free cloud key the operator has wired on the "
                  "VM: 4 Groq (Meta 70B, OpenAI 20B/120B, Alibaba "
                  "Qwen3.6) + Gemini + Cerebras + OpenRouter DeepSeek + "
                  "GitHub Models. Providers whose key is unset or whose "
                  "endpoint 4xx's are logged as failures and skipped; "
                  "the panel survives on the judges that answer."),
    },
    "local": {
        "label": "Local",
        "spec": ("ollama:qwen2.5:3b,"
                 "ollama:gemma2:2b,"
                 "ollama:phi3.5,"
                 "ollama:llama3.2:3b,"
                 "ollama:granite3.3:2b"),
        "wallclock_per_candidate_s": 250,
        "notes": ("Every chat-capable Ollama model installed on the "
                  "VM. Ollama serialises inference on CPU so wall-clock "
                  "is the sum of the five model latencies, not the max. "
                  "Zero external calls - all bytes stay on the box."),
    },
}

# The default preset ID for a new upload that did not pick one.
# The dashboard dropdown was collapsed to two entries in 2026-08 (Cloud /
# Local) so the operator picks how the report is judged with one click.
# Default is `local` so no bytes leave the VM until the operator asks.
DEFAULT_PRESET_ID = "local"


def preset_by_id(preset_id):
    """Return preset dict or None."""
    return PRESETS.get(preset_id)


def valid_spec(spec):
    """Quick shape check: comma-separated 'provider:model' entries or empty."""
    if spec is None:
        return False
    if spec == "":
        return True  # empty means single-judge fallback
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            return False
    return True


def choices_for_ui():
    """Return [(id, label)] pairs ordered for a dropdown.

    The dashboard sidebar shows only two entries - Cloud and Local -
    even though older preset ids stay in PRESETS for backward-compat
    with historical audit records that reference them by name.
    """
    ordered = ["cloud", "local"]
    return [(pid, PRESETS[pid]["label"]) for pid in ordered
            if pid in PRESETS]
