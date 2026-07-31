"""Unit tests for the expert-panel mode of the llm_judge package.

Everything runs against in-process fake clients: no network, no key, no
tshark. Covers the panel spec parser, the debate round (convergence,
standoff, failure), the deterministic resolver, the guardrail escalation,
the per-model participation report, cache-warm determinism, and the
markdown rendering of the panel sections.
"""
import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import judge_config, judge_core  # noqa: E402
from llm_judge import judge_cli                 # noqa: E402


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
def scan_candidate():
    """A rule-triggered scan candidate (vertical SYN scan shape)."""
    return {
        "candidate_id": "192.168.1.10",
        "kind": "ip",
        "session_context": {"duration_s": 71.2, "total_packets": 2020,
                           "total_ips": 3},
        "features": {"mean_len": 60.0, "std_len": 0.0, "count": 1007,
                     "burst_score": 1007.0, "unique_dsts": 1,
                     "syn_count": 1002, "rst_count": 0, "fin_count": 0,
                     "null_count": 0, "xmas_count": 0},
        "ml_signals": {"iso_score": -0.31, "iso_stability": 1.0,
                       "anomaly": True, "cluster": -1, "silhouette": None,
                       "lstm_bin_flag_count": None},
        "rule_signals": {"scan_alerts": [{"type": "SYN", "count": 1002,
                                          "unique_dsts": 1, "ratio": 1.0}],
                         "flood_alerts": [], "amp_alerts": [],
                         "arp_multi_mac": False},
        "advanced_signals": {"beaconing": None, "dns_tunneling": None,
                             "dga": None, "tls_anomaly": None,
                             "fusion_score": None},
        "device_context": {"category": "unknown", "hostname": None,
                           "oui_vendor": None},
        "enrichments": {"is_private": True, "reverse_dns": None,
                        "asn": None, "baseline_seen_before": None},
        "trigger_reasons": ["isolation_forest", "scan_rule"],
    }


def ml_only_candidate():
    """A statistical-outlier candidate with no fired rule."""
    c = copy.deepcopy(scan_candidate())
    c["candidate_id"] = "10.0.0.5"
    c["features"].update(syn_count=5, count=40, unique_dsts=3,
                         burst_score=0.13)
    c["rule_signals"]["scan_alerts"] = []
    c["trigger_reasons"] = ["isolation_forest"]
    return c


def verdict(label="malicious", category="port_scan", conf=0.9, **over):
    v = {"verdict": label, "category": category, "confidence": conf,
         "evidence_features": ["rule_signals.scan_alerts", "syn_count"],
         "reasoning": "SYN ratio 1.0 toward one destination.",
         "recommended_action": "investigate"}
    v.update(over)
    return v


def debate_response(stance="maintain", label="malicious",
                    category="port_scan", conf=0.9,
                    rebuttal="The scan rule fired; ratio 1.0 is decisive."):
    d = verdict(label, category, conf)
    d["stance"] = stance
    d["rebuttal"] = rebuttal
    return d


class PanelFake:
    """Behavior-based fake judge: fixed round-1 verdict, scripted debate
    behavior. Distinguishes the two rounds by the system prompt object."""

    def __init__(self, model_id, round1, debate=None):
        self.model_id = model_id
        self._round1 = round1      # dict or Exception
        self._debate = debate      # dict, Exception, or None -> maintain
        self.round1_calls = 0
        self.debate_calls = 0

    def judge(self, system_prompt, user_content, schema=None):
        if system_prompt == judge_core.DEBATE_SYSTEM_PROMPT:
            self.debate_calls += 1
            # Faithful to the real clients: a debate turn must arrive with
            # the debate schema, or a strict provider could not emit
            # 'stance'/'rebuttal'. Enforcing it here means this fake can no
            # longer pass a debate the real (schema-bound) path would fail.
            assert schema is judge_core.DEBATE_SCHEMA, (
                "debate turn must pass DEBATE_SCHEMA to the client")
            if isinstance(self._debate, Exception):
                raise self._debate
            if self._debate is None:  # maintain the previous position
                prev = json.loads(user_content)["debate"][
                    "your_previous_verdict"]
                return json.dumps(debate_response(
                    "maintain", prev["verdict"], prev["category"],
                    prev["confidence"]))
            return json.dumps(self._debate)
        self.round1_calls += 1
        if isinstance(self._round1, Exception):
            raise self._round1
        return json.dumps(self._round1)


def run_panel(clients, candidates, tmp_path, debate=True, **kw):
    return judge_core.judge_candidates_panel(
        candidates, clients, cache_db=str(tmp_path / "cache.sqlite"),
        verbose=False, debate=debate, **kw)


class _SleepyPanelFake(PanelFake):
    """PanelFake whose round-1 and debate calls block for `delay_s`
    seconds - lets a wall-clock test tell parallel judges apart from
    sequential ones."""

    def __init__(self, model_id, round1, delay_s, debate=None):
        super().__init__(model_id, round1, debate)
        self._delay_s = delay_s

    def judge(self, system_prompt, user_content, schema=None):
        import time as _t
        _t.sleep(self._delay_s)
        return super().judge(system_prompt, user_content, schema=schema)


def test_panel_runs_judges_in_parallel_not_sequentially(tmp_path):
    """Three judges each block for 400 ms in judge(). Sequential run
    would take >=1200 ms; parallel run should stay <=750 ms (that
    leaves plenty of slack for GIL / scheduling on Windows CI). The
    test proves the panel actually fans out the round-1 verdicts
    through a ThreadPoolExecutor and does not just call them one after
    another in a for loop.

    Consensus verdict on the ml_only candidate means no debate round -
    so the time we measure is purely the initial-verdict parallelism.
    """
    import time as _t
    delay = 0.4
    clients = [
        _SleepyPanelFake("m-a", verdict("suspicious", "benign_anomaly",
                                        conf=0.6), delay),
        _SleepyPanelFake("m-b", verdict("suspicious", "benign_anomaly",
                                        conf=0.6), delay),
        _SleepyPanelFake("m-c", verdict("suspicious", "benign_anomaly",
                                        conf=0.6), delay),
    ]
    t0 = _t.perf_counter()
    out = run_panel(clients, [ml_only_candidate()], tmp_path, debate=False)
    elapsed = _t.perf_counter() - t0
    assert out["stats"]["debated_candidates"] == 0  # consensus, no debate
    # Sequential would be ~3*400 = 1200 ms.  Parallel is max(delays) + setup.
    # Give it 750 ms; anything close to 1200 ms means the pool did not fan
    # out and we regressed to per-client loop.
    assert elapsed < 0.75, (
        f"panel round-1 ran sequentially (elapsed {elapsed:.2f}s for "
        f"3 x {delay}s judges - expected <0.75s with parallel executor)")


def test_panel_parallel_debate_stays_under_sequential_bound(tmp_path):
    """When judges disagree, the debate round also fans out. Two judges
    each blocking 400 ms both in round-1 and in debate: sequential
    total would be >=1600 ms (round-1 800 + debate 800). Parallel
    stays under 1100 ms."""
    import time as _t
    delay = 0.4
    clients = [
        _SleepyPanelFake("m-a", verdict("malicious"), delay,
                         debate=debate_response("maintain", "malicious")),
        _SleepyPanelFake("m-b", verdict("suspicious", "benign_anomaly",
                                        conf=0.6), delay,
                         debate=debate_response(
                             "maintain", "suspicious", "benign_anomaly",
                             conf=0.6)),
    ]
    t0 = _t.perf_counter()
    out = run_panel(clients, [scan_candidate()], tmp_path, debate=True)
    elapsed = _t.perf_counter() - t0
    assert out["stats"]["debated_candidates"] == 1  # disagreement -> debate
    # Sequential: round-1 800ms + debate 800ms = 1600ms.
    # Parallel: max(400,400)*2 rounds + setup ~= 900ms.
    assert elapsed < 1.1, (
        f"panel debate ran sequentially (elapsed {elapsed:.2f}s for 2 "
        f"judges x 2 rounds x {delay}s - expected <1.1s with parallel exec)")


def test_panel_cache_is_thread_safe(tmp_path):
    """The parallel judges hit the same JudgeCache from different threads.
    Before the check_same_thread=False + Lock change this raised
    sqlite3.ProgrammingError; now it stays consistent under load."""
    delay = 0.05
    clients = [
        _SleepyPanelFake(f"m-{i}", verdict("suspicious", "benign_anomaly",
                                           conf=0.6), delay)
        for i in range(4)
    ]
    # 6 candidates x 4 judges = 24 parallel cache put()s across threads.
    cands = [copy.deepcopy(ml_only_candidate()) for _ in range(6)]
    for i, c in enumerate(cands):
        c["candidate_id"] = f"10.0.0.{i + 5}"  # unique per candidate
    out = run_panel(clients, cands, tmp_path, debate=False)
    assert len(out["results"]) == 6
    assert out["stats"]["cache_hits"] == 0
    # Every result carries a valid verdict - no thread lost a write.
    for r in out["results"]:
        assert r["verdict"]["verdict"] == "suspicious"


# --------------------------------------------------------------------------
# parse_panel_spec
# --------------------------------------------------------------------------
def test_parse_panel_spec_variants():
    assert judge_core.parse_panel_spec(
        "m-large, m-small", default_provider="openai_compat") == [
        ("openai_compat", "m-large"), ("openai_compat", "m-small")]
    assert judge_core.parse_panel_spec(
        "ollama:llama3.2, openai_compat:m-large ,claude:c1",
        default_provider="claude") == [
        ("ollama", "llama3.2"), ("openai_compat", "m-large"),
        ("claude", "c1")]


def test_parse_panel_spec_ollama_colon_model_names():
    """Ollama model names contain colons ("gemma3:4b") - a colon prefix is
    a provider only when it names a known provider."""
    assert judge_core.parse_panel_spec(
        "gemma3:4b, llama3.2", default_provider="ollama") == [
        ("ollama", "gemma3:4b"), ("ollama", "llama3.2")]
    assert judge_core.parse_panel_spec(
        "ollama:gemma3:4b, ollama:llama3.2",
        default_provider="claude") == [
        ("ollama", "gemma3:4b"), ("ollama", "llama3.2")]


@pytest.mark.parametrize("bad", ["", "solo-model", "openai_compat:,b",
                                 "same,same"])
def test_parse_panel_spec_rejects(bad):
    with pytest.raises(ValueError):
        judge_core.parse_panel_spec(bad, default_provider="openai_compat")


# --------------------------------------------------------------------------
# Consensus / debate flows
# --------------------------------------------------------------------------
def test_panel_consensus_skips_debate(tmp_path):
    clients = [PanelFake("m-a", verdict(conf=0.7)),
               PanelFake("m-b", verdict(conf=0.95)),
               PanelFake("m-c", verdict(conf=0.8))]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    assert out["stats"]["debated_candidates"] == 0
    assert all(c.debate_calls == 0 for c in clients)
    r = out["results"][0]
    assert r["panel"]["agreement"] is True
    assert r["panel"]["needs_human_review"] is False
    assert r["verdict"]["confidence"] == 0.95  # highest confidence wins
    report = out["stats"]["panel_report"]
    assert all(report[m]["agreed_with_final"] == 1
               for m in ("m-a", "m-b", "m-c"))


def test_panel_debate_convergence_clears_review(tmp_path):
    """A dissenting judge that revises to the majority position after the
    debate produces consensus - no human review needed."""
    dissent = PanelFake(
        "m-b", verdict("benign", "benign_anomaly", 0.6),
        debate=debate_response("revise", "malicious", "port_scan", 0.8,
                               rebuttal="Peer cited scan_alerts I missed."))
    clients = [PanelFake("m-a", verdict(conf=0.9)), dissent]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    assert out["stats"]["debated_candidates"] == 1
    assert dissent.debate_calls == 1
    r = out["results"][0]
    assert r["verdict"]["verdict"] == "malicious"
    assert r["panel"]["agreement"] is True
    assert r["panel"]["needs_human_review"] is False
    judges = {j["model"]: j for j in r["panel"]["judges"]}
    assert judges["m-b"]["revised"] is True
    assert judges["m-b"]["stance"] == "revise"
    assert judges["m-a"]["revised"] is False
    assert out["stats"]["panel_report"]["m-b"]["revised"] == 1


def test_panel_debate_standoff_flags_review(tmp_path):
    clients = [PanelFake("m-a", verdict(conf=0.9)),
               PanelFake("m-b", verdict("benign", "benign_anomaly", 0.7))]
    out = run_panel(clients, [ml_only_candidate()], tmp_path)
    r = out["results"][0]
    assert r["panel"]["debate"] is True
    assert r["panel"]["needs_human_review"] is True
    assert r["verdict"]["verdict"] == "malicious"  # fail-safe severity
    assert "disagree" in r["panel"]["note"]
    rebuttals = [j["rebuttal"] for j in r["panel"]["judges"]]
    assert all(rebuttals), "both maintaining judges must carry a rebuttal"
    assert out["stats"]["needs_review"] == 1


def test_panel_category_dispute_flags_review(tmp_path):
    clients = [PanelFake("m-a", verdict(category="port_scan", conf=0.9)),
               PanelFake("m-b", verdict(category="syn_flood", conf=0.8))]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    r = out["results"][0]
    assert r["verdict"]["verdict"] == "malicious"
    assert r["panel"]["agreement"] is False
    assert r["panel"]["needs_human_review"] is True
    assert "category" in r["panel"]["note"]


def test_panel_debate_failure_keeps_round1_position(tmp_path):
    """A judge whose debate call dies keeps its round-1 verdict; the
    failure is logged in the participation report, not fatal."""
    broken_debater = PanelFake(
        "m-b", verdict("benign", "benign_anomaly", 0.7),
        debate=RuntimeError("boom"))
    clients = [PanelFake("m-a", verdict(conf=0.9)), broken_debater]
    out = run_panel(clients, [ml_only_candidate()], tmp_path)
    r = out["results"][0]
    judges = {j["model"]: j for j in r["panel"]["judges"]}
    assert judges["m-b"]["verdict"]["verdict"] == "benign"
    assert judges["m-b"]["stance"] == "maintain"
    rep = out["stats"]["panel_report"]["m-b"]
    assert rep["failures"] == 1
    assert any("debate" in e for e in rep["failure_examples"])
    assert r["panel"]["needs_human_review"] is True


# --------------------------------------------------------------------------
# Failure semantics
# --------------------------------------------------------------------------
def test_panel_one_judge_down_continues_uncorroborated(tmp_path):
    clients = [PanelFake("m-a", verdict(conf=0.9)),
               PanelFake("m-b", RuntimeError("api down"))]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    r = out["results"][0]
    assert r["verdict"]["verdict"] == "malicious"
    assert r["panel"]["needs_human_review"] is True
    assert "only one" in r["panel"]["note"]
    judges = {j["model"]: j for j in r["panel"]["judges"]}
    assert judges["m-b"]["failed"] is True
    rep = out["stats"]["panel_report"]["m-b"]
    assert rep["assigned"] == 1 and rep["failures"] == 1
    assert rep["failure_examples"]


def test_panel_all_judges_down_drops_candidate(tmp_path):
    clients = [PanelFake("m-a", RuntimeError("down-a")),
               PanelFake("m-b", RuntimeError("down-b"))]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    assert out["results"] == []
    assert len(out["dropped"]) == 1
    assert "down-a" in out["dropped"][0]["error"]
    assert "down-b" in out["dropped"][0]["error"]


def test_panel_requires_two_distinct_clients(tmp_path):
    with pytest.raises(ValueError):
        run_panel([PanelFake("m-a", verdict())], [scan_candidate()],
                  tmp_path)
    with pytest.raises(ValueError):
        run_panel([PanelFake("dup", verdict()), PanelFake("dup", verdict())],
                  [scan_candidate()], tmp_path)


def test_panel_disabled_flag_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", False)
    clients = [PanelFake("m-a", verdict()), PanelFake("m-b", verdict())]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    assert out["stats"]["disabled"] is True
    assert clients[0].round1_calls == 0


# --------------------------------------------------------------------------
# Guardrail interaction
# --------------------------------------------------------------------------
def test_panel_guardrail_overrides_benign_consensus(tmp_path):
    """Both judges call a fired-rule candidate benign: the guardrail must
    override AND force human review even though the panel 'agreed'."""
    clients = [PanelFake("m-a", verdict("benign", "benign_anomaly", 0.6)),
               PanelFake("m-b", verdict("benign", "benign_anomaly", 0.5))]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    r = out["results"][0]
    assert r["guardrail"] is not None
    assert r["verdict"]["verdict"] == "suspicious"
    assert r["verdict"]["category"] == "port_scan"
    assert r["panel"]["needs_human_review"] is True
    assert "guardrail" in r["panel"]["note"]


# --------------------------------------------------------------------------
# Determinism / cache
# --------------------------------------------------------------------------
def test_panel_rerun_is_deterministic_and_free(tmp_path):
    """Second run over the same cache: byte-identical results, zero new
    LLM calls - including the debate round."""
    def build():
        return [PanelFake("m-a", verdict(conf=0.9)),
                PanelFake("m-b", verdict("benign", "benign_anomaly", 0.7))]

    cands = [scan_candidate(), ml_only_candidate()]
    first_clients = build()
    out1 = run_panel(first_clients, cands, tmp_path)
    second_clients = build()
    out2 = run_panel(second_clients, cands, tmp_path)
    assert all(c.round1_calls == 0 and c.debate_calls == 0
               for c in second_clients), "warm cache must make zero calls"
    strip = lambda o: [  # noqa: E731
        {k: r[k] for k in ("candidate_id", "verdict", "priority")}
        for r in o["results"]]
    assert strip(out1) == strip(out2)
    assert out2["stats"]["cache_hits"] > 0


def test_panel_agreement_matches_single_judge_verdicts(tmp_path):
    """Path parity: when every panel judge answers exactly like the single
    judge, the panel's effective verdicts, categories and priorities must
    be identical to the single-judge path. The CLI, the notebook and the
    Actions workflow all route through these two functions, so this pins
    them to each other."""
    from llm_judge import benchmark

    fixtures = benchmark.load_fixtures()
    candidates = [f["candidate"] for f in fixtures]

    class Oracle:
        def __init__(self, model_id):
            self.model_id = model_id

        def judge(self, system_prompt, user_content):
            cand = json.loads(user_content)
            cat = (judge_core.rule_expected_category(cand)
                   or "benign_anomaly")
            label = "benign" if cat == "benign_anomaly" else "malicious"
            return json.dumps(verdict(label, cat, 0.9))

    single = judge_core.judge_candidates(
        candidates, client=Oracle("oracle-a"), cache_db=":memory:",
        verbose=False)
    panel = judge_core.judge_candidates_panel(
        candidates, [Oracle("oracle-b"), Oracle("oracle-c")],
        cache_db=str(tmp_path / "parity.sqlite"), verbose=False)

    def key(out):
        return {r["candidate_id"]: (r["verdict"]["verdict"],
                                    r["verdict"]["category"],
                                    r["priority"])
                for r in out["results"]}

    assert key(single) == key(panel)
    assert panel["stats"]["debated_candidates"] == 0


# --------------------------------------------------------------------------
# Debate response validation
# --------------------------------------------------------------------------
def test_validate_debate_response_normalizes():
    v, stance, rebuttal = judge_core.validate_debate_response(
        debate_response(rebuttal="  spaced\n\nrebuttal  " + "x" * 400))
    assert stance == "maintain"
    assert "\n" not in rebuttal and len(rebuttal) <= 300
    assert v["verdict"] == "malicious"


@pytest.mark.parametrize("mutate", [
    {"stance": "argue"}, {"stance": None}, {"rebuttal": ""},
    {"rebuttal": None}, {"verdict": "iffy"}, {"confidence": 7}])
def test_validate_debate_response_rejects(mutate):
    bad = debate_response()
    bad.update(mutate)
    with pytest.raises(judge_core.JudgeValidationError):
        judge_core.validate_debate_response(bad)


# --------------------------------------------------------------------------
# Markdown rendering of the panel sections
# --------------------------------------------------------------------------
def test_render_markdown_panel_sections(tmp_path):
    clients = [PanelFake("m-a", verdict(conf=0.9)),
               PanelFake("m-b", verdict("benign", "benign_anomaly", 0.7))]
    cands = [scan_candidate(), ml_only_candidate()]
    out = run_panel(clients, cands, tmp_path)
    out["analyst_commentary"] = None
    md = judge_cli._render_markdown(
        "x.pcap", out, {"candidates": cands, "capped": []}, clients[0])
    assert "| **Panel** |" in md
    assert "### Panel disputes" in md
    assert "## Panel participation" in md
    assert "`m-a`" in md and "`m-b`" in md
    assert "⚖" in md
    assert "Debate positions" in md


def test_render_markdown_panel_shows_failed_judge(tmp_path):
    clients = [PanelFake("m-a", verdict(conf=0.9)),
               PanelFake("m-b", RuntimeError("api down"))]
    out = run_panel(clients, [scan_candidate()], tmp_path)
    out["analyst_commentary"] = None
    md = judge_cli._render_markdown(
        "x.pcap", out, {"candidates": [scan_candidate()], "capped": []},
        clients[0])
    assert "_failed_" in md
    assert "failure examples" in md


# --- commentary provider routing regression (panel path) ------------------

def test_commentary_provider_matches_the_client_type_not_the_default():
    """Panel entries like 'ollama:llama3.2' get an OllamaClient with no
    provider_name attribute. Falling back to the configured default
    (claude by default) would build a ClaudeClient with the wrong model
    for the commentary call - the exception is swallowed and the emailed
    report carries '(Analyst commentary unavailable: ...)'. The router
    must classify by the actual client type."""
    from llm_judge import judge_cli, llm_clients

    # Endpoint-profile client: honor provider_name
    class Prof: pass
    p = Prof(); p.provider_name = "gemini"; p.model_id = "x"
    assert judge_cli._commentary_provider(p) == "gemini"

    # Built-in classes: derive from the type, ignore the config default
    ol = llm_clients.OllamaClient.__new__(llm_clients.OllamaClient)
    ol.model_id = "llama3.2"; ol.provider_name = None
    assert judge_cli._commentary_provider(ol) == "ollama"

    oa = llm_clients.OpenAICompatClient.__new__(llm_clients.OpenAICompatClient)
    oa.model_id = "m"
    assert judge_cli._commentary_provider(oa) == "openai_compat"

    cl = llm_clients.ClaudeClient.__new__(llm_clients.ClaudeClient)
    cl.model_id = "claude-x"
    assert judge_cli._commentary_provider(cl) == "claude"
