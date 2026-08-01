"""Tests for the judge upgrades: rule guardrail, the OpenAI-compatible
client (against an in-process mock server - no network), and the model
benchmark harness with its committed fixtures."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import benchmark, judge_config, judge_core  # noqa: E402
from llm_judge.llm_clients import OpenAICompatClient  # noqa: E402


def good_verdict(**over):
    v = {"verdict": "malicious", "category": "port_scan", "confidence": 0.95,
         "evidence_features": ["syn_count"],
         "reasoning": "Scan rule fired.", "recommended_action": "investigate"}
    v.update(over)
    return v


def scan_candidate():
    return {"candidate_id": "192.168.1.10", "kind": "ip",
            "features": {"syn_count": 1002},
            "ml_signals": {"iso_score": -0.3, "iso_stability": 1.0,
                           "anomaly": True, "cluster": -1,
                           "silhouette": None, "lstm_bin_flag_count": None},
            "rule_signals": {"scan_alerts": [{"type": "SYN", "count": 1002,
                                              "unique_dsts": 1,
                                              "ratio": 1.0}],
                             "flood_alerts": [], "amp_alerts": [],
                             "arp_multi_mac": False}}


def ml_only_candidate():
    c = scan_candidate()
    c["candidate_id"] = "10.0.0.9"
    c["rule_signals"]["scan_alerts"] = []
    return c


# --------------------------------------------------------------------------
# Rule guardrail
# --------------------------------------------------------------------------
def test_guardrail_overrides_benign_on_fired_rule():
    benign = good_verdict(verdict="benign", category="benign_anomaly",
                          confidence=0.5, recommended_action="monitor")
    corrected, info = judge_core.apply_rule_guardrail(scan_candidate(),
                                                      benign)
    assert corrected["verdict"] == "suspicious"
    assert corrected["category"] == "port_scan"
    assert corrected["confidence"] >= 0.6
    assert corrected["reasoning"].startswith("[rule guardrail]")
    assert len(corrected["reasoning"]) <= 400
    assert info == {"applied": True, "rule_category": "port_scan",
                    "model_verdict": "benign",
                    "model_category": "benign_anomaly"}
    # the corrected verdict must still pass the strict validator
    judge_core.validate_verdict(corrected)


# --------------------------------------------------------------------------
# SCIENTIFIC_AUDIT 3.1 - guardrail escape hatch
# --------------------------------------------------------------------------
def _dns_amp_candidate():
    """Amp-rule-triggered candidate (a resolver-shaped source)."""
    return {"candidate_id": "8.8.8.8", "kind": "ip",
            "features": {"count": 200},
            "ml_signals": {"iso_score": 0.0, "iso_stability": 0.0,
                           "anomaly": False, "cluster": -1,
                           "silhouette": None, "lstm_bin_flag_count": None},
            "rule_signals": {"scan_alerts": [],
                             "flood_alerts": [],
                             "amp_alerts": [{"responses": 250,
                                             "mean_size": 400.0,
                                             "peer": "8.8.8.8"}],
                             "arp_multi_mac": False},
            "enrichments": {"is_private": False, "reverse_dns": "dns.google",
                            "asn": "AS15169", "baseline_seen_before": None}}


def test_guardrail_escape_lets_benign_public_resolver_pass():
    """SCIENTIFIC_AUDIT 3.1: a benign verdict at >=0.85 conf that cites
    the specific evidence 'public resolver' passes the guardrail."""
    benign = good_verdict(
        verdict="benign", category="benign_anomaly", confidence=0.9,
        evidence_features=["enrichments.reverse_dns",
                           "rule_signals.amp_alerts"],
        reasoning="Peer is a well-known public resolver (Google DNS 8.8.8.8); "
                  "the amp rule misfired on a legitimate resolver.")
    corrected, info = judge_core.apply_rule_guardrail(
        _dns_amp_candidate(), benign)
    assert corrected["verdict"] == "benign"
    assert info["guardrail_bypassed"] is True
    assert info["applied"] is False
    assert "public resolver" in info["note"]


def test_guardrail_escape_denies_without_specific_evidence():
    """A benign verdict without the specific whitelist evidence still gets
    overridden, even at high confidence."""
    benign = good_verdict(
        verdict="benign", category="benign_anomaly", confidence=0.95,
        evidence_features=["features.count"],
        reasoning="Low packet count looks normal")
    corrected, info = judge_core.apply_rule_guardrail(
        _dns_amp_candidate(), benign)
    assert corrected["verdict"] == "suspicious"  # overridden
    assert info["applied"] is True
    assert "guardrail_bypassed" not in info


def test_guardrail_escape_denies_below_confidence_threshold():
    """Even with correct evidence, confidence <0.85 is not enough to
    escape - "prefer suspicious over benign when signals are thin"."""
    benign = good_verdict(
        verdict="benign", category="benign_anomaly", confidence=0.7,
        evidence_features=["enrichments.reverse_dns"],
        reasoning="Peer is a public resolver.")
    corrected, info = judge_core.apply_rule_guardrail(
        _dns_amp_candidate(), benign)
    assert corrected["verdict"] == "suspicious"  # overridden
    assert info["applied"] is True


def test_guardrail_escape_can_be_disabled_by_config(monkeypatch):
    """Setting LLM_JUDGE_GUARDRAIL_ESCAPE=0 restores strict pre-v0.5
    behaviour: no benign passes on a fired-rule candidate."""
    monkeypatch.setattr(judge_config, "LLM_JUDGE_GUARDRAIL_ESCAPE", False)
    benign = good_verdict(
        verdict="benign", category="benign_anomaly", confidence=0.95,
        evidence_features=["enrichments.reverse_dns",
                           "rule_signals.amp_alerts"],
        reasoning="Public resolver, amp rule misfired.")
    corrected, info = judge_core.apply_rule_guardrail(
        _dns_amp_candidate(), benign)
    assert corrected["verdict"] == "suspicious"
    assert info["applied"] is True


def test_guardrail_escape_only_covers_dns_amp_today():
    """The whitelist only covers dns_amp for now - other rule categories
    (port_scan, arp_mitm, syn_flood) do not have escape entries and
    always land in the strict override path."""
    benign = good_verdict(
        verdict="benign", category="benign_anomaly", confidence=0.95,
        evidence_features=["enrichments.reverse_dns"],
        reasoning="Public resolver, amp rule misfired.")
    # scan candidate has scan_rule, not amp_rule - no escape entry
    corrected, info = judge_core.apply_rule_guardrail(
        scan_candidate(), benign)
    assert corrected["verdict"] == "suspicious"
    assert info["applied"] is True


def test_guardrail_leaves_non_benign_and_ml_only_alone():
    v, info = judge_core.apply_rule_guardrail(scan_candidate(),
                                              good_verdict())
    assert info is None and v["verdict"] == "malicious"
    benign = good_verdict(verdict="benign", category="benign_anomaly")
    v2, info2 = judge_core.apply_rule_guardrail(ml_only_candidate(), benign)
    assert info2 is None and v2["verdict"] == "benign"


@pytest.mark.parametrize("signals,expected", [
    ({"flood_alerts": [{"type": "SYN_FLOOD"}]}, "syn_flood"),
    ({"arp_multi_mac": True}, "arp_mitm"),
    ({"amp_alerts": [{"responses": 250}]}, "dns_amp"),
    ({"scan_alerts": [{"type": "SYN"}]}, "port_scan"),
    ({}, None),
])
def test_rule_expected_category(signals, expected):
    base = {"scan_alerts": [], "flood_alerts": [], "amp_alerts": [],
            "arp_multi_mac": False}
    base.update(signals)
    assert judge_core.rule_expected_category(
        {"rule_signals": base}) == expected


def test_judge_candidates_applies_guardrail(tmp_path, monkeypatch):
    monkeypatch.setattr(judge_config, "RULE_GUARDRAIL", True)

    class BenignClient:
        model_id = "always-benign"

        def judge(self, system_prompt, user_content):
            return json.dumps(good_verdict(
                verdict="benign", category="benign_anomaly",
                confidence=0.5, recommended_action="monitor"))

    out = judge_core.judge_candidates([scan_candidate()],
                                      client=BenignClient(),
                                      cache_db=str(tmp_path / "c.sqlite"),
                                      verbose=False)
    r = out["results"][0]
    assert r["verdict"]["verdict"] == "suspicious"
    assert r["verdict"]["category"] == "port_scan"
    assert r["guardrail"]["applied"] is True
    # priority must be computed from the POST-guardrail verdict:
    # single candidate -> norm_anom 0; 0.4*conf(0.6) + 0.3*weight(0.8)
    assert r["priority"] == pytest.approx(0.48, abs=1e-6)
    # the CACHE must keep the raw model verdict, not the corrected one
    fp = judge_core.fingerprint(scan_candidate(),
                                judge_config.PROMPT_VERSION, "always-benign")
    cache = judge_core.JudgeCache(str(tmp_path / "c.sqlite"))
    assert cache.get(fp)["verdict"] == "benign"
    cache.close()

    # second run: the verdict now comes from the CACHE (raw benign) and the
    # guardrail must still be applied to it
    out_cached = judge_core.judge_candidates([scan_candidate()],
                                             client=BenignClient(),
                                             cache_db=str(tmp_path
                                                          / "c.sqlite"),
                                             verbose=False)
    rc = out_cached["results"][0]
    assert rc["cached"] is True
    assert rc["verdict"]["verdict"] == "suspicious"
    assert rc["guardrail"]["applied"] is True

    # guardrail off -> raw verdict flows through
    monkeypatch.setattr(judge_config, "RULE_GUARDRAIL", False)
    out2 = judge_core.judge_candidates([scan_candidate()],
                                       client=BenignClient(),
                                       cache_db=str(tmp_path / "c.sqlite"),
                                       verbose=False)
    assert out2["results"][0]["verdict"]["verdict"] == "benign"
    assert out2["results"][0]["guardrail"] is None


# --------------------------------------------------------------------------
# OpenAI-compatible client against an in-process mock server
# --------------------------------------------------------------------------
class _MockOpenAIHandler(BaseHTTPRequestHandler):
    reject_json_schema = False
    reject_everything = False
    requests_seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(
            int(self.headers["Content-Length"])).decode("utf-8"))
        type(self).requests_seen.append(
            {"path": self.path, "body": body,
             "auth": self.headers.get("Authorization")})
        rf = body.get("response_format") or {}
        if type(self).reject_everything:
            self._send(400, b'{"error": "model not found"}')
            return
        if type(self).reject_json_schema and rf.get("type") == "json_schema":
            self._send(400, b'{"error": "json_schema not supported"}')
            return
        reply = {"choices": [{"finish_reason": "stop", "message": {
            "role": "assistant",
            "content": json.dumps(good_verdict())}}]}
        self._send(200, json.dumps(reply).encode("utf-8"))

    def _send(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture()
def mock_openai_server(monkeypatch):
    # a developer's real key in the environment must not leak into the
    # mock-server assertions
    monkeypatch.delenv("OPENAI_COMPAT_API_KEY", raising=False)
    _MockOpenAIHandler.requests_seen = []
    _MockOpenAIHandler.reject_json_schema = False
    _MockOpenAIHandler.reject_everything = False
    server = HTTPServer(("127.0.0.1", 0), _MockOpenAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()
    thread.join(timeout=5)


def test_openai_compat_happy_path(mock_openai_server):
    client = OpenAICompatClient(model="test-model",
                                base_url=mock_openai_server,
                                api_key="test-key", timeout_s=10,
                                verdict_schema=judge_core.VERDICT_SCHEMA)
    raw = client.judge("system prompt", "{\"candidate_id\": \"x\"}")
    verdict = judge_core.validate_verdict(json.loads(raw))
    assert verdict["category"] == "port_scan"
    req = _MockOpenAIHandler.requests_seen[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["auth"] == "Bearer test-key"
    assert req["body"]["model"] == "test-model"
    assert req["body"]["messages"][0]["role"] == "system"
    assert req["body"]["response_format"]["type"] == "json_schema"
    assert (req["body"]["response_format"]["json_schema"]["schema"]
            == judge_core.VERDICT_SCHEMA)


def test_openai_compat_falls_back_to_json_object(mock_openai_server):
    _MockOpenAIHandler.reject_json_schema = True
    client = OpenAICompatClient(model="test-model",
                                base_url=mock_openai_server,
                                timeout_s=10,
                                verdict_schema=judge_core.VERDICT_SCHEMA)
    raw = client.judge("system prompt", "{}")
    assert json.loads(raw)["category"] == "port_scan"
    kinds = [r["body"]["response_format"]["type"]
             for r in _MockOpenAIHandler.requests_seen]
    assert kinds == ["json_schema", "json_object"]
    # no Authorization header when no key was given
    assert _MockOpenAIHandler.requests_seen[-1]["auth"] is None
    # the downgrade sticks: the next call skips json_schema entirely
    client.judge("system prompt", "{}")
    assert (_MockOpenAIHandler.requests_seen[-1]["body"]
            ["response_format"]["type"]) == "json_object"


def test_openai_compat_unrelated_400_reports_both_attempts(
        mock_openai_server):
    from llm_judge.llm_clients import JudgeClientError
    _MockOpenAIHandler.reject_everything = True
    client = OpenAICompatClient(model="no-such-model",
                                base_url=mock_openai_server, timeout_s=10,
                                verdict_schema=judge_core.VERDICT_SCHEMA)
    with pytest.raises(JudgeClientError) as exc:
        client.judge("system prompt", "{}")
    msg = str(exc.value)
    assert "json_schema attempt" in msg and "json_object attempt" in msg
    assert "model not found" in msg          # server body surfaced
    assert client._schema_unsupported is False  # no bogus downgrade sticks


def test_openai_compat_requires_model():
    from llm_judge.llm_clients import JudgeClientError
    with pytest.raises(JudgeClientError):
        OpenAICompatClient(model="", base_url="http://localhost:9/v1")


# --------------------------------------------------------------------------
# Permanent-vs-transient error tagging (H3 fix): a 4xx from the server is
# permanent at this layer - retrying it just burns quota. That INCLUDES
# 429: _post already has its own burst-retry loop, and an error that
# survived _post's budget means the rate window is still hot - a further
# outer retry would just wait through it again. Only 5xx and network
# errors stay transient (retriable).
# --------------------------------------------------------------------------
def test_openai_compat_400_is_tagged_permanent(mock_openai_server):
    """A 400 from BOTH json_schema and json_object (e.g. allam-2-7b's
    json_validate_failed) must mark the JudgeClientError permanent so
    _verdict_from_client skips its own retry."""
    from llm_judge.llm_clients import JudgeClientError
    _MockOpenAIHandler.reject_everything = True
    client = OpenAICompatClient(model="broken-model",
                                base_url=mock_openai_server, timeout_s=10,
                                verdict_schema=judge_core.VERDICT_SCHEMA)
    with pytest.raises(JudgeClientError) as exc:
        client.judge("system prompt", "{}")
    assert exc.value.permanent is True


def test_openai_compat_unrelated_4xx_is_permanent():
    """A direct 404 (no schema-fallback path) also lands as permanent -
    covers the `except HTTPError` branch at judge()'s outer catch."""
    from llm_judge.llm_clients import JudgeClientError

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"nope"}')

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        # schema=None keeps us out of the strict/plain fallback and lands
        # HTTPError in the outer except HTTPError branch of judge()
        client = OpenAICompatClient(
            model="m", base_url=f"http://127.0.0.1:{srv.server_address[1]}/v1",
            api_key="k", timeout_s=5, verdict_schema=None)
        with pytest.raises(JudgeClientError) as exc:
            client.judge("s", "u")
        assert exc.value.permanent is True
    finally:
        srv.shutdown(); t.join(timeout=5)


def test_openai_compat_exhausted_429_is_permanent(monkeypatch):
    """A 429 that survived _post's internal retry budget is permanent at
    the outer layer: the burst-window already elapsed while we slept, so
    retrying the whole cycle just waits through the same rate window
    again. Was permanent=False before the follow-up H3 fix, which cost
    the panel ~16s per stuck judge for zero gain."""
    from llm_judge.llm_clients import JudgeClientError

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.end_headers()
            self.wfile.write(b'{"error":"rate limited"}')

        def log_message(self, *a):
            pass

    # Cap retry waits to 0.01s so the test stays fast
    monkeypatch.setattr(OpenAICompatClient, "_MAX_WAIT_S", 0.01)
    monkeypatch.setattr(OpenAICompatClient, "_MAX_RETRIES", 1)
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        client = OpenAICompatClient(
            model="m", base_url=f"http://127.0.0.1:{srv.server_address[1]}/v1",
            api_key="k", timeout_s=5, verdict_schema=None)
        with pytest.raises(JudgeClientError) as exc:
            client.judge("s", "u")
        assert exc.value.permanent is True
    finally:
        srv.shutdown(); t.join(timeout=5)


def test_openai_compat_5xx_is_not_permanent():
    """A 500 is a server hiccup - it CAN succeed on retry, so it stays
    transient (permanent=False) and the outer retry loop still runs."""
    from llm_judge.llm_clients import JudgeClientError

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b'{"error":"overloaded"}')

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        client = OpenAICompatClient(
            model="m", base_url=f"http://127.0.0.1:{srv.server_address[1]}/v1",
            api_key="k", timeout_s=5, verdict_schema=None)
        with pytest.raises(JudgeClientError) as exc:
            client.judge("s", "u")
        assert exc.value.permanent is False


    finally:
        srv.shutdown(); t.join(timeout=5)


def test_openai_compat_max_retries_and_wait_are_short():
    """Regression: _MAX_RETRIES and _MAX_WAIT_S were 3 and 30 before H3;
    30-second sleeps in a parallel panel stalled every judge together and
    made the batch look hung. Cap the retry budget to keep the panel
    responsive."""
    assert OpenAICompatClient._MAX_RETRIES == 2
    assert OpenAICompatClient._MAX_WAIT_S == 8.0


# --------------------------------------------------------------------------
# Benchmark harness + committed fixtures
# --------------------------------------------------------------------------
def test_fixture_file_is_valid():
    fixtures = benchmark.load_fixtures()
    assert len(fixtures) >= 8
    kinds = {f["truth_kind"] for f in fixtures}
    assert kinds == {"attack", "benign"}
    cats = {f["truth_category"] for f in fixtures}
    assert {"port_scan", "arp_mitm", "syn_flood",
            "dns_amp", "benign_anomaly"} <= cats
    for f in fixtures:
        c = f["candidate"]
        assert {"candidate_id", "kind", "features",
                "ml_signals", "rule_signals"} <= set(c)
        assert f["truth_category"] in judge_core.CATEGORIES
        # truth_kind and truth_category must agree - the scoring
        # partitions rely on it
        expected_kind = ("benign" if f["truth_category"] == "benign_anomaly"
                         else "attack")
        assert f["truth_kind"] == expected_kind
        json.dumps(c)  # serializable


class OracleClient:
    """Answers every fixture correctly using the same rule logic - the
    benchmark of the benchmark: a perfect model must score 1.0."""
    model_id = "oracle"

    def judge(self, system_prompt, user_content):
        cand = json.loads(user_content)
        cat = judge_core.rule_expected_category(cand) or "benign_anomaly"
        verdict = "benign" if cat == "benign_anomaly" else "malicious"
        action = "monitor" if verdict == "benign" else "investigate"
        return json.dumps(good_verdict(verdict=verdict, category=cat,
                                       confidence=0.9,
                                       recommended_action=action))


class AlwaysBenignClient:
    """Worst realistic case: the failure mode measured on a small local
    model. The guardrail must still rescue every rule-fired attack."""
    model_id = "always-benign"

    def judge(self, system_prompt, user_content):
        return json.dumps(good_verdict(
            verdict="benign", category="benign_anomaly", confidence=0.5,
            recommended_action="monitor"))


def test_benchmark_oracle_scores_perfect():
    report = benchmark.run_benchmark(OracleClient(), guardrail=True,
                                     verbose=False)
    assert report["category_accuracy"] == 1.0
    assert report["detection_rate"] == 1.0
    assert report["benign_accuracy"] == 1.0
    assert report["dropped"] == 0
    assert report["guardrail_saves"] == 0
    assert "GOOD" in benchmark.verdict_line(report)


def test_benchmark_guardrail_rescues_always_benign_model():
    with_gr = benchmark.run_benchmark(AlwaysBenignClient(), guardrail=True,
                                      verbose=False)
    without_gr = benchmark.run_benchmark(AlwaysBenignClient(),
                                         guardrail=False, verbose=False)
    # without the guardrail the model detects nothing
    assert without_gr["detection_rate"] == 0.0
    # with it, EVERY rule-fired attack is rescued to suspicious - and every
    # rescue is counted as a save (all attack fixtures are rule-fired)
    n_attacks = sum(1 for f in benchmark.load_fixtures()
                    if f["truth_kind"] == "attack")
    assert with_gr["detection_rate"] == 1.0
    assert with_gr["guardrail_saves"] == n_attacks
    # benign fixtures stay benign either way
    assert with_gr["benign_accuracy"] == 1.0


class FlakyOracleClient(OracleClient):
    """Oracle that fails hard (invalid JSON twice) on every syn_flood and
    dns_amp fixture - models a provider that chokes on some inputs."""
    model_id = "flaky-oracle"

    def judge(self, system_prompt, user_content):
        cand = json.loads(user_content)
        if judge_core.rule_expected_category(cand) in ("syn_flood",
                                                       "dns_amp"):
            return "***not json***"
        return super().judge(system_prompt, user_content)


def test_benchmark_dropped_fixtures_count_as_wrong():
    """A model that errors on attack fixtures must NOT get an inflated
    score - drops count against every metric (review finding)."""
    fixtures = benchmark.load_fixtures()
    n = len(fixtures)
    n_attacks = sum(1 for f in fixtures if f["truth_kind"] == "attack")
    n_flaky = sum(1 for f in fixtures
                  if f["truth_category"] in ("syn_flood", "dns_amp"))
    assert n_flaky > 0
    report = benchmark.run_benchmark(FlakyOracleClient(), guardrail=True,
                                     verbose=False)
    assert report["dropped"] == n_flaky
    # detection_rate divides by ALL attack fixtures, drops included
    assert report["detection_rate"] == round(
        (n_attacks - n_flaky) / n_attacks, 3)
    assert report["category_accuracy"] == round((n - n_flaky) / n, 3)
    assert "every attack" not in benchmark.verdict_line(report)
    # dropped rows carry the error and no latency
    err_rows = [r for r in report["rows"] if r["error"]]
    assert len(err_rows) == n_flaky
    assert all(r["latency_ms"] is None for r in err_rows)


# --- real-client panel debate (schema-bound provider) ---------------------

class _SchemaHonoringHandler(BaseHTTPRequestHandler):
    """Mock OpenAI endpoint that, like a real structured-output provider,
    emits ONLY the keys the request's json_schema allows. A verdict-schema
    request therefore cannot carry 'stance'; a debate-schema request can.
    Round-1 verdicts differ by model id so the panel debates."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n).decode())
        rf = req.get("response_format") or {}
        schema = (rf.get("json_schema") or {}).get("schema") or {}
        props = set(schema.get("properties", {}).keys())
        model = req.get("model", "")
        if "stance" in props:                       # debate schema
            content = {"stance": "maintain", "verdict": "malicious",
                       "category": "port_scan", "confidence": 0.8,
                       "evidence_features": ["rule_signals.scan_alerts"],
                       "reasoning": "Scan signature holds post-debate.",
                       "recommended_action": "investigate",
                       "rebuttal": "The port fan-out is the scan tell."}
        elif model.endswith("-b"):                  # round-1, disagree
            content = {"verdict": "benign", "category": "benign_anomaly",
                       "confidence": 0.7, "evidence_features": ["features.count"],
                       "reasoning": "Looks like normal low-volume noise.",
                       "recommended_action": "monitor"}
        else:                                        # round-1
            content = {"verdict": "malicious", "category": "port_scan",
                       "confidence": 0.75,
                       "evidence_features": ["rule_signals.scan_alerts"],
                       "reasoning": "Sequential SYNs across many ports.",
                       "recommended_action": "investigate"}
        body = json.dumps({"choices": [{"finish_reason": "stop",
                          "message": {"content": json.dumps(content)}}],
                          "usage": {"prompt_tokens": 10, "completion_tokens": 20}})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())


def test_panel_debate_works_against_schema_bound_provider(tmp_path):
    """End-to-end guard for the debate fix: with REAL OpenAICompatClients
    against a provider that strictly honors the response schema, the debate
    round must succeed (no 'bad stance' failures) - which is only possible
    when the debate turn is sent with the debate schema, not the verdict
    schema the client was built with."""
    srv = HTTPServer(("127.0.0.1", 0), _SchemaHonoringHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}/v1"
        ca = OpenAICompatClient(model="judge-a", base_url=base, api_key="k",
                                verdict_schema=judge_core.VERDICT_SCHEMA)
        cb = OpenAICompatClient(model="judge-b", base_url=base, api_key="k",
                                verdict_schema=judge_core.VERDICT_SCHEMA)
        cand = scan_candidate()
        out = judge_core.judge_candidates_panel(
            [cand], [ca, cb], cache_db=str(tmp_path / "c.sqlite"),
            verbose=False, debate=True)
    finally:
        srv.shutdown()
    rep = out["stats"]["panel_report"]
    total_debates = sum(r["debates"] for r in rep.values())
    total_failures = sum(r["failures"] for r in rep.values())
    total_revised = sum(r["revised"] for r in rep.values())
    assert total_debates >= 2, "both judges should take a debate turn"
    assert total_failures == 0, f"debate failed on a real client: {rep}"
    # the benign judge should revise toward the scan verdict after debate
    assert total_revised >= 1
    # and the panel converges to a single (malicious) verdict
    assert out["results"][0]["verdict"]["verdict"] == "malicious"
