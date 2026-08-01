"""Q3: batched judging - several candidates per LLM call.

The invariant under test everywhere: the batch is a PURE accelerator.
Anything that goes wrong (whole call fails, response doesn't parse, an
element fails validation, the model drops or hallucinates an id) must
leave the affected candidates on the ordinary per-candidate path, so
the worst case exactly equals batching off.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from llm_judge import judge_config, judge_core  # noqa: E402


class _PermanentError(Exception):
    """Stand-in for llm_clients.JudgeClientError with permanent=True -
    what a provider quota/schema rejection surfaces as."""
    def __init__(self, msg, permanent=True):
        super().__init__(msg)
        self.permanent = permanent


def _cand(cid, count=100):
    return {"candidate_id": cid, "kind": "ip",
            "features": {"count": count},
            "ml_signals": {"iso_score": -0.2, "iso_stability": 1.0,
                           "anomaly": True, "cluster": -1,
                           "silhouette": None, "lstm_bin_flag_count": None},
            "rule_signals": {"scan_alerts": [], "flood_alerts": [],
                             "amp_alerts": [], "arp_multi_mac": False},
            "enrichments": {"is_private": True, "reverse_dns": None,
                            "asn": None, "baseline_seen_before": None}}


def _verdict_json(cid):
    return {"candidate_id": cid, "verdict": "benign",
            "category": "benign_anomaly", "confidence": 0.9,
            "evidence_features": ["ml_signals.iso_score"],
            "reasoning": "Statistical outlier only, no attack shape.",
            "recommended_action": "monitor"}


class _BatchClient:
    """Fake client that answers batched calls with valid verdicts and
    records every judge() invocation."""

    def __init__(self, model_id="fake-batch"):
        self.model_id = model_id
        self.calls = []          # list of (system_tail, n_candidates, schema)
        self.last_usage = None

    def judge(self, system_prompt, user_content, schema=None):
        body = json.loads(user_content)
        if "candidates" in body:
            cands = body["candidates"]
            self.calls.append(("batch", len(cands), schema is not None))
            return json.dumps({"verdicts": [
                _verdict_json(c["candidate_id"]) for c in cands]})
        self.calls.append(("single", 1, schema is not None))
        v = _verdict_json("unused"); v.pop("candidate_id")
        return json.dumps(v)


@pytest.fixture
def cache(tmp_path):
    return judge_core.JudgeCache(str(tmp_path / "cache.sqlite"))


# ---- _batched_verdicts_from_client ---------------------------------------

def test_batched_returns_all_fresh(cache):
    cl = _BatchClient()
    cands = [_cand(f"10.0.0.{i}") for i in range(3)]
    out, permanent = judge_core._batched_verdicts_from_client(
        cands, cl, cache, "vT")
    assert set(out) == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}
    assert permanent is False
    verdict, share, was_cached, err = out["10.0.0.1"]
    assert verdict["verdict"] == "benign"
    assert was_cached is False and err is None
    assert len(cl.calls) == 1 and cl.calls[0][0] == "batch"


def test_batched_writes_per_candidate_cache(cache):
    cl = _BatchClient()
    cands = [_cand(f"10.0.0.{i}") for i in range(3)]
    judge_core._batched_verdicts_from_client(cands, cl, cache, "vT")
    # every candidate individually cached under the single-path key
    for c in cands:
        fp = judge_core.fingerprint(c, "vT", cl.model_id)
        assert cache.get(fp) is not None


def test_batched_skips_cached_candidates(cache):
    cl = _BatchClient()
    cands = [_cand(f"10.0.0.{i}") for i in range(4)]
    # pre-cache two of the four
    for c in cands[:2]:
        fp = judge_core.fingerprint(c, "vT", cl.model_id)
        v = _verdict_json(c["candidate_id"]); v.pop("candidate_id")
        cache.put(fp, "vT", judge_core.validate_verdict(v),
                  cl.model_id, 5)
    out, _ = judge_core._batched_verdicts_from_client(cands, cl, cache, "vT")
    # only the two fresh ones came back, and the call carried exactly 2
    assert set(out) == {"10.0.0.2", "10.0.0.3"}
    assert cl.calls == [("batch", 2, True)]


def test_batched_single_fresh_candidate_skips_call(cache):
    """<2 fresh candidates -> no batched call at all (nothing to gain)."""
    cl = _BatchClient()
    cands = [_cand("10.0.0.1"), _cand("10.0.0.2")]
    fp = judge_core.fingerprint(cands[0], "vT", cl.model_id)
    v = _verdict_json("10.0.0.1"); v.pop("candidate_id")
    cache.put(fp, "vT", judge_core.validate_verdict(v), cl.model_id, 5)
    out, permanent = judge_core._batched_verdicts_from_client(
        cands, cl, cache, "vT")
    assert out == {} and permanent is False and cl.calls == []


def test_batched_whole_call_failure_returns_empty(cache):
    class _Boom(_BatchClient):
        def judge(self, *a, **kw):
            raise judge_core.JudgeValidationError("no")
    out, permanent = judge_core._batched_verdicts_from_client(
        [_cand("a"), _cand("b")], _Boom(), cache, "vT")
    assert out == {}       # -> panel loop falls back per candidate
    assert permanent is False  # transient: later slices may still work


def test_batched_invalid_element_falls_back_only_that_one(cache):
    class _Half(_BatchClient):
        def judge(self, system_prompt, user_content, schema=None):
            cands = json.loads(user_content)["candidates"]
            good = _verdict_json(cands[0]["candidate_id"])
            bad = _verdict_json(cands[1]["candidate_id"])
            bad["verdict"] = "not-a-verdict"        # fails validation
            return json.dumps({"verdicts": [good, bad]})
    out, _ = judge_core._batched_verdicts_from_client(
        [_cand("ok"), _cand("broken")], _Half(), cache, "vT")
    assert set(out) == {"ok"}


def test_batched_hallucinated_id_ignored(cache):
    class _Wrong(_BatchClient):
        def judge(self, system_prompt, user_content, schema=None):
            return json.dumps({"verdicts": [_verdict_json("172.99.99.99")]})
    out, _ = judge_core._batched_verdicts_from_client(
        [_cand("a"), _cand("b")], _Wrong(), cache, "vT")
    assert out == {}


def test_batched_413_bisects_until_it_fits(cache):
    """Measured on Groq llama-8b (6k TPM vs ~7.3k for 5 candidates):
    a too-large rejection must split the batch and retry the halves,
    not give up. Fake provider: any call with >2 candidates dies with
    a permanent 413-shaped error; <=2 succeeds."""
    class _Tpm(_BatchClient):
        def judge(self, system_prompt, user_content, schema=None):
            cands = json.loads(user_content)["candidates"]
            self.calls.append(("batch", len(cands), schema is not None))
            if len(cands) > 2:
                raise _PermanentError(
                    "HTTP Error 413: Payload Too Large - Request too "
                    "large for model, TPM limit")
            return json.dumps({"verdicts": [
                _verdict_json(c["candidate_id"]) for c in cands]})

    cands = [_cand(f"10.9.0.{i}") for i in range(5)]
    out, permanent = judge_core._batched_verdicts_from_client(
        cands, _Tpm(), cache, "vT")
    # 5 -> halves (2, 3); the 3 -> halves (1, 2). The lone candidate
    # (index 2) skips batching entirely and rides the per-candidate
    # path - so 4 of 5 come back batched, none are lost.
    assert set(out) == {"10.9.0.0", "10.9.0.1", "10.9.0.3", "10.9.0.4"}
    assert permanent is False


def test_batched_quota_429_reports_permanent(cache):
    """An exhausted daily quota is permanent for EVERY remaining batch -
    the prefetch loop must learn to stop for this judge."""
    class _Quota(_BatchClient):
        def judge(self, *a, **kw):
            raise _PermanentError(
                "HTTP Error 429: Too Many Requests - tokens per day "
                "(TPD): Limit 100000")
    out, permanent = judge_core._batched_verdicts_from_client(
        [_cand("a"), _cand("b")], _Quota(), cache, "vT")
    assert out == {} and permanent is True


def test_prefetch_stops_after_permanent_failure(cache, tmp_path,
                                                monkeypatch):
    """A judge whose quota is gone gets exactly ONE batch attempt -
    the remaining slices are skipped instead of hammered."""
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", True)

    class _Quota(_BatchClient):
        def judge(self, system_prompt, user_content, schema=None):
            body = json.loads(user_content)
            if "candidates" in body:
                self.calls.append(("batch", len(body["candidates"]),
                                   schema is not None))
                raise _PermanentError("429 tokens per day")
            # per-candidate singles also die permanently (quota is quota)
            self.calls.append(("single", 1, schema is not None))
            raise _PermanentError("429 tokens per day")

    quota_cl = _Quota(model_id="fake-quota")
    ok_cl = _BatchClient(model_id="fake-ok")
    cands = [_cand(f"10.8.0.{i}") for i in range(6)]
    out = judge_core.judge_candidates_panel(
        cands, [quota_cl, ok_cl], cache_db=str(tmp_path / "c6.sqlite"),
        prompt_version="vT", verbose=False, debate=False, batch_size=2)
    # one batch attempt, then the loop's 6 single rescues (which fail
    # fast) - but NOT 3 batch attempts
    batch_attempts = [c for c in quota_cl.calls if c[0] == "batch"]
    assert len(batch_attempts) == 1, quota_cl.calls
    # the healthy judge still judged everything
    assert out["stats"]["judged"] == 6


# ---- panel integration ----------------------------------------------------

def _mk_panel_clients(n=2):
    return [_BatchClient(model_id=f"fake-{i}") for i in range(n)]


def test_panel_batch_reduces_call_count(cache, tmp_path, monkeypatch):
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", True)
    clients = _mk_panel_clients(2)
    cands = [_cand(f"10.1.0.{i}") for i in range(5)]
    out = judge_core.judge_candidates_panel(
        cands, clients, cache_db=str(tmp_path / "c2.sqlite"),
        prompt_version="vT", verbose=False, debate=False, batch_size=3)
    assert out["stats"]["judged"] == 5
    for cl in clients:
        batch_calls = [c for c in cl.calls if c[0] == "batch"]
        single_calls = [c for c in cl.calls if c[0] == "single"]
        # ceil(5/3) = 2 batched calls, zero per-candidate calls
        assert len(batch_calls) == 2, cl.calls
        assert len(single_calls) == 0, cl.calls


def test_panel_batch_size_1_means_off(cache, tmp_path, monkeypatch):
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", True)
    clients = _mk_panel_clients(2)
    cands = [_cand(f"10.2.0.{i}") for i in range(3)]
    out = judge_core.judge_candidates_panel(
        cands, clients, cache_db=str(tmp_path / "c3.sqlite"),
        prompt_version="vT", verbose=False, debate=False, batch_size=1)
    assert out["stats"]["judged"] == 3
    for cl in clients:
        assert all(kind == "single" for kind, _, _ in cl.calls)


def test_panel_batch_failure_degrades_to_single_calls(cache, tmp_path,
                                                      monkeypatch):
    """A client whose batched call always dies still judges everything -
    through the per-candidate fallback."""
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", True)

    class _NoBatch(_BatchClient):
        def judge(self, system_prompt, user_content, schema=None):
            body = json.loads(user_content)
            if "candidates" in body:
                self.calls.append(("batch", len(body["candidates"]),
                                   schema is not None))
                raise judge_core.JudgeValidationError("array schema rejected")
            return super().judge(system_prompt, user_content, schema)

    clients = [_NoBatch(model_id="fake-nobatch"),
               _BatchClient(model_id="fake-ok")]
    cands = [_cand(f"10.3.0.{i}") for i in range(4)]
    out = judge_core.judge_candidates_panel(
        cands, clients, cache_db=str(tmp_path / "c4.sqlite"),
        prompt_version="vT", verbose=False, debate=False, batch_size=4)
    assert out["stats"]["judged"] == 4
    nb = clients[0]
    # 2 failed batch attempts (retry) then 4 per-candidate rescues
    assert len([c for c in nb.calls if c[0] == "single"]) == 4
    # and no candidate was dropped
    assert out["stats"]["dropped"] == 0


def test_panel_batch_second_run_hits_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(judge_config, "LLM_JUDGE_ENABLED", True)
    db = str(tmp_path / "c5.sqlite")
    cands = [_cand(f"10.4.0.{i}") for i in range(4)]
    clients1 = _mk_panel_clients(2)
    judge_core.judge_candidates_panel(
        cands, clients1, cache_db=db, prompt_version="vT",
        verbose=False, debate=False, batch_size=2)
    clients2 = _mk_panel_clients(2)
    out2 = judge_core.judge_candidates_panel(
        cands, clients2, cache_db=db, prompt_version="vT",
        verbose=False, debate=False, batch_size=2)
    assert out2["stats"]["judged"] == 4
    assert out2["stats"]["cache_hits"] == 8  # 4 candidates x 2 judges
    for cl in clients2:
        assert cl.calls == []  # everything served from cache
