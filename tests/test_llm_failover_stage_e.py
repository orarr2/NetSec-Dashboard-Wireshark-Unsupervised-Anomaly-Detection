"""Stage E regression: endpoint profiles, failover chain, quota store.

No network and no provider SDKs - fake clients drive every path.
"""
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "llm_judge"))

import judge_config  # noqa: E402
import judge_core  # noqa: E402
import llm_clients  # noqa: E402
from quota import QuotaStore  # noqa: E402


# ---- endpoint profiles ---------------------------------------------------

def test_endpoint_profiles_parsed_from_env():
    env = {
        "LLM_JUDGE_EP_GEMINI_BASE_URL": "https://gemini.example/v1",
        "LLM_JUDGE_EP_GEMINI_MODEL": "gemini-2.5-flash",
        "LLM_JUDGE_EP_GEMINI_KEY_ENV": "GEMINI_API_KEY",
        "GEMINI_API_KEY": "secret-key",
        "LLM_JUDGE_EP_CEREBRAS_BASE_URL": "https://cerebras.example/v1",
        "LLM_JUDGE_EP_BAD_MODEL": "no base url so ignored",
    }
    profiles = judge_config.endpoint_profiles(env)
    assert set(profiles) == {"gemini", "cerebras"}
    assert profiles["gemini"]["base_url"] == "https://gemini.example/v1"
    assert profiles["gemini"]["model"] == "gemini-2.5-flash"
    assert profiles["gemini"]["api_key"] == "secret-key"
    assert profiles["cerebras"]["model"] is None


def test_panel_spec_accepts_profile_names(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_EP_GEMINI_BASE_URL",
                       "https://gemini.example/v1")
    monkeypatch.setenv("LLM_JUDGE_EP_GEMINI_MODEL", "gemini-2.5-flash")
    monkeypatch.setenv("LLM_JUDGE_EP_GROQ_BASE_URL",
                       "https://api.groq.com/openai/v1")
    entries = judge_core.parse_panel_spec(
        "groq:llama-3.3-70b,gemini:gemini-2.5-flash,ollama:qwen2.5:14b",
        default_provider="openai_compat")
    # all three prefixes resolve: two profiles + the ollama built-in
    assert ("groq", "llama-3.3-70b") in entries
    assert ("gemini", "gemini-2.5-flash") in entries
    assert ("ollama", "qwen2.5:14b") in entries


def test_make_client_resolves_profile(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_EP_CEREBRAS_BASE_URL",
                       "https://cerebras.example/v1")
    monkeypatch.setenv("LLM_JUDGE_EP_CEREBRAS_MODEL", "llama-3.3-70b")
    monkeypatch.setenv("LLM_JUDGE_EP_CEREBRAS_KEY_ENV", "CB_KEY")
    monkeypatch.setenv("CB_KEY", "k")
    client = llm_clients.make_client(provider="cerebras")
    assert isinstance(client, llm_clients.OpenAICompatClient)
    assert client.base_url == "https://cerebras.example/v1"
    assert client.model_id == "llama-3.3-70b"
    assert client.provider_name == "cerebras"


def test_make_client_unknown_provider_lists_profiles(monkeypatch):
    monkeypatch.delenv("LLM_JUDGE_EP_X_BASE_URL", raising=False)
    with pytest.raises(llm_clients.JudgeClientError) as e:
        llm_clients.make_client(provider="nope")
    assert "profile" in str(e.value)


# ---- failover ------------------------------------------------------------

class _Fake:
    def __init__(self, model, behavior):
        self.model_id = model
        self.behavior = behavior      # "ok" | "err" | "429"
        self.last_usage = {"tokens_in": 10, "tokens_out": 5}
        self.calls = 0

    def judge(self, system_prompt, user_content):
        self.calls += 1
        if self.behavior == "ok":
            return '{"verdict":"benign"}'
        if self.behavior == "429":
            raise llm_clients.JudgeClientError("HTTP Error 429: rate limit")
        raise llm_clients.JudgeClientError("boom")


def test_failover_uses_first_healthy(tmp_path):
    q = QuotaStore(str(tmp_path / "q.sqlite"))
    a, b = _Fake("a", "err"), _Fake("b", "ok")
    fc = llm_clients.FailoverClient([a, b], providers=["a", "b"], quota=q)
    assert fc.judge("s", "u") == '{"verdict":"benign"}'
    assert a.calls == 1 and b.calls == 1
    assert fc.model_id == "b" and fc.last_provider == "b"
    assert q.stats("b")["tokens"] == 15      # usage recorded
    q.close()


def test_failover_all_fail_raises(tmp_path):
    q = QuotaStore(str(tmp_path / "q.sqlite"))
    fc = llm_clients.FailoverClient(
        [_Fake("a", "err"), _Fake("b", "429")],
        providers=["a", "b"], quota=q)
    with pytest.raises(llm_clients.JudgeClientError) as e:
        fc.judge("s", "u")
    assert "all failover providers failed" in str(e.value)
    assert q.stats("b")["last_429_at"] is not None
    q.close()


def test_failover_skips_exhausted(tmp_path):
    q = QuotaStore(str(tmp_path / "q.sqlite"))
    # mark provider "a" as 429'd with no declared cap -> exhausted
    q.record("a", was_429=True)
    a, b = _Fake("a", "ok"), _Fake("b", "ok")
    fc = llm_clients.FailoverClient([a, b], providers=["a", "b"], quota=q)
    assert fc.judge("s", "u")
    assert a.calls == 0 and b.calls == 1     # a skipped without a call
    q.close()


# ---- quota ---------------------------------------------------------------

def test_quota_accumulates_and_exhaustion(tmp_path):
    q = QuotaStore(str(tmp_path / "q.sqlite"))
    q.record("groq", tokens=100)
    q.record("groq", tokens=50)
    s = q.stats("groq")
    assert s["requests"] == 2 and s["tokens"] == 150
    assert q.is_exhausted("groq") is False              # no 429 yet
    q.record("groq", tokens=1, was_429=True)
    assert q.is_exhausted("groq", token_cap=100) is True
    assert q.is_exhausted("groq", token_cap=10_000) is False
    q.close()
