"""End-to-end for the per-upload panel selector (N1).

The dashboard's Send-to-VM dropdown lets the user pick which judges
run each upload. The choice rides a header (X-Judge-Panel) to ingest,
lands in the DB (sessions.judge_panel_override, schema v5), and the
worker reads it and passes to analyze_and_judge as panel_spec_override.

Missing any link means the dropdown is silently dead - so every link
gets an explicit test.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from server import auth, db  # noqa: E402
from llm_judge import panel_presets  # noqa: E402


# ---- presets module ------------------------------------------------------

def test_presets_contain_default():
    assert panel_presets.DEFAULT_PRESET_ID in panel_presets.PRESETS
    for pid, preset in panel_presets.PRESETS.items():
        assert "label" in preset, f"{pid} missing label"
        assert "spec" in preset, f"{pid} missing spec"
        assert "wallclock_per_candidate_s" in preset, f"{pid} missing latency hint"


def test_presets_include_fast_and_local_options():
    """A user MUST be able to pick a fast cloud-only path and a
    zero-key local-only path. If we ever accidentally remove those
    two, the dropdown loses its whole point."""
    labels = " ".join(p["label"] for p in panel_presets.PRESETS.values())
    assert "cloud" in labels.lower() or "Groq" in labels
    assert "local" in labels.lower() or "ollama" in labels.lower() or "Ollama" in labels


def test_preset_by_id_returns_dict_or_none():
    assert panel_presets.preset_by_id("fast_cloud_3")["spec"].startswith("groq:")
    assert panel_presets.preset_by_id("nonsense_id_xyz") is None


def test_valid_spec_accepts_our_own_presets():
    """Every preset's spec must round-trip through valid_spec()."""
    for pid, preset in panel_presets.PRESETS.items():
        assert panel_presets.valid_spec(preset["spec"]), \
            f"preset {pid} has invalid spec {preset['spec']!r}"


def test_valid_spec_rejects_junk():
    assert panel_presets.valid_spec("no-colon-here") is False
    assert panel_presets.valid_spec(None) is False


def test_valid_spec_allows_empty_for_single_judge_fallback():
    assert panel_presets.valid_spec("") is True


def test_choices_for_ui_is_ordered_and_lists_labels():
    choices = panel_presets.choices_for_ui()
    assert len(choices) >= 3
    # Ordered: fast_cloud first, single_groq last
    ids = [pid for pid, _ in choices]
    assert ids[0] == "fast_cloud_3"
    for pid, label in choices:
        assert isinstance(label, str) and label


def test_every_installed_local_model_appears_in_some_preset():
    """No idle model rule: llama3.2 was installed on the VM but never
    referenced in any preset - that regression must not recur."""
    installed_local = {"ollama:qwen2.5:3b", "ollama:gemma2:2b",
                       "ollama:phi3.5", "ollama:llama3.2:3b"}
    referenced = set()
    for preset in panel_presets.PRESETS.values():
        for entry in preset["spec"].split(","):
            entry = entry.strip()
            if entry:
                referenced.add(entry)
    missing = installed_local - referenced
    assert not missing, (
        f"these local models are installed on the VM but no preset "
        f"references them: {missing}. Either add them to a preset "
        f"or `ollama rm` them - no idle installed models.")


# ---- schema v5 + create_session ------------------------------------------

def _sensor(conn, name="paneltest"):
    token = "tok-" + name
    db.create_sensor(conn, name, auth.hash_token(token), "sec-" + name)
    return db.get_sensor(conn, name)


def test_schema_v5_adds_judge_panel_override_column(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)")]
    assert "judge_panel_override" in cols


def test_create_session_stores_override(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    sensor = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, "a" * 64, "t.pcap", 10,
                                   sensor["id"], "/tmp/t.pcap")
    spec = "groq:llama-3.1-8b-instant,ollama:qwen2.5:3b"
    sid = db.create_session(conn, pcap_id, "S1", "prod",
                            judge_panel_override=spec)
    row = conn.execute("SELECT judge_panel_override FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["judge_panel_override"] == spec


def test_create_session_defaults_override_to_null(tmp_path):
    conn = db.connect(str(tmp_path / "db.sqlite"))
    sensor = _sensor(conn)
    pcap_id, _ = db.register_pcap(conn, "b" * 64, "t.pcap", 10,
                                   sensor["id"], "/tmp/t.pcap")
    sid = db.create_session(conn, pcap_id, "S1", "prod")
    row = conn.execute("SELECT judge_panel_override FROM sessions WHERE id=?",
                       (sid,)).fetchone()
    assert row["judge_panel_override"] is None


# ---- _build_panel honors override ---------------------------------------

def test_build_panel_uses_override_over_env(monkeypatch):
    """When spec_override is passed, it wins - even when
    LLM_JUDGE_PANEL env is set to something completely different."""
    from llm_judge import judge_cli, judge_config, judge_core, llm_clients

    # a stub judge_core.parse_panel_spec that just records what it saw
    seen = []

    def _parse_stub(spec, default_provider=None):
        seen.append(spec)
        return [("openai_compat", "m1"), ("openai_compat", "m2")]

    def _make_clients(entries, verdict_schema=None):
        # 2 fake clients so the count check passes
        class _C:
            def __init__(self, mid): self.model_id = mid
        return [_C("m1"), _C("m2")], []

    monkeypatch.setattr(judge_core, "parse_panel_spec", _parse_stub)
    monkeypatch.setattr(judge_cli, "make_panel_clients", _make_clients)
    monkeypatch.setattr(judge_config, "LLM_JUDGE_PANEL",
                        "ollama:xxx-fallback,ollama:yyy-fallback")

    entries, clients, failures = judge_cli._build_panel(
        spec_override="groq:llama-3.1-8b-instant,gemini:gemini-2.5-flash")
    assert seen == ["groq:llama-3.1-8b-instant,gemini:gemini-2.5-flash"]
    assert len(clients) == 2


def test_build_panel_falls_back_to_env_when_no_override(monkeypatch):
    from llm_judge import judge_cli, judge_config, judge_core

    seen = []

    def _parse_stub(spec, default_provider=None):
        seen.append(spec)
        return [("openai_compat", "m1"), ("openai_compat", "m2")]

    def _make_clients(entries, verdict_schema=None):
        class _C:
            def __init__(self, mid): self.model_id = mid
        return [_C("m1"), _C("m2")], []

    monkeypatch.setattr(judge_core, "parse_panel_spec", _parse_stub)
    monkeypatch.setattr(judge_cli, "make_panel_clients", _make_clients)
    monkeypatch.setattr(judge_config, "LLM_JUDGE_PANEL",
                        "groq:x,groq:y")

    judge_cli._build_panel()  # no override
    assert seen == ["groq:x,groq:y"]


# ---- worker path resolves preset id -> spec (ingest stores raw header) ----

def _resolve_via_analyze(monkeypatch, override_value):
    """Drive judge_cli.analyze_and_judge just far enough to record the
    spec it ends up calling _build_panel with. We stub everything past
    the panel resolution so the pipeline never actually runs.

    Returns the spec string that _build_panel was called with (or
    the sentinel "<env_fallback>" if _build_panel was called with no
    override at all, which means the env LLM_JUDGE_PANEL kicks in).
    """
    from llm_judge import judge_cli, judge_config

    seen = {}

    def _fake_build(spec_override=None):
        seen["spec"] = spec_override
        # any 2 fake clients so downstream single-panel init passes
        class _C:
            def __init__(self, mid): self.model_id = mid
        return [("groq", "x"), ("groq", "y")], [_C("x"), _C("y")], []

    def _fake_validate():
        return None

    monkeypatch.setattr(judge_cli, "_build_panel", _fake_build)
    monkeypatch.setattr(judge_cli, "_validate_committee_config", _fake_validate)
    monkeypatch.setattr(judge_config, "LLM_JUDGE_PANEL",
                        "groq:env-default-a,groq:env-default-b")

    # analyze_and_judge imports run_pipeline lazily - swap it out
    fake_rp = type("rp", (), {})()
    fake_rp.analyze_pcap = lambda p, lbl: {"packets": [], "meta": {}}
    fake_rp.run_ml_on_session = lambda s: None
    fake_rp.run_security_scans = lambda s: []
    monkeypatch.setitem(sys.modules, "run_pipeline", fake_rp)

    # break the loop early - anything after panel resolution can raise
    def _bail(*a, **kw):
        raise RuntimeError("stop-after-resolution")
    monkeypatch.setattr(judge_cli, "assemble_candidates", _bail, raising=False)

    try:
        judge_cli.analyze_and_judge("dummy.pcap", label="T",
                                    verbose=False,
                                    panel_spec_override=override_value)
    except Exception:
        pass  # expected - we bail after resolution
    return seen.get("spec", "<env_fallback>")


def test_worker_resolves_preset_id_to_spec(monkeypatch):
    """Ingest stores the raw header ('fast_cloud_3'); the worker turns
    it into the spec string before building the panel."""
    resolved = _resolve_via_analyze(monkeypatch, "fast_cloud_3")
    fast_spec = panel_presets.preset_by_id("fast_cloud_3")["spec"]
    assert resolved == fast_spec


def test_worker_accepts_raw_spec_unchanged(monkeypatch):
    """A raw spec (with colons) passes through untouched."""
    raw = "groq:llama-3.1-8b-instant,gemini:gemini-2.5-flash"
    resolved = _resolve_via_analyze(monkeypatch, raw)
    assert resolved == raw


def test_worker_falls_back_when_preset_id_unknown(monkeypatch):
    """Unknown preset id -> silent fallback to env default. Never lose a run
    because of a UI typo in the dashboard dropdown."""
    resolved = _resolve_via_analyze(monkeypatch, "nonsense_preset_xyz")
    # env default fell through
    assert resolved is None or resolved == "groq:env-default-a,groq:env-default-b"
