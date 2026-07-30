"""Stage E regression: LLM endpoint profiles and the informational usage
counters. There is NO automatic fallback - which judges run is the user's
explicit panel choice - so this only covers profile resolution (letting
the panel mix providers) and the usage log. No network, no provider SDKs.
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


# ---- endpoint profiles (let one panel mix providers, spec 6.1) -----------

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


def test_no_failover_symbols_exist():
    """'No fallback' is a design rule, not an accident - guard against a
    failover client sneaking back in."""
    assert not hasattr(llm_clients, "FailoverClient")
    assert not hasattr(llm_clients, "make_failover_client")
    assert not hasattr(judge_config, "LLM_JUDGE_FAILOVER")


# ---- usage counters (informational - staying under free limits) ----------

def test_quota_accumulates(tmp_path):
    q = QuotaStore(str(tmp_path / "q.sqlite"))
    q.record("groq", tokens=100)
    q.record("groq", tokens=50)
    s = q.stats("groq")
    assert s["requests"] == 2 and s["tokens"] == 150
    assert q.stats("gemini")["requests"] == 0
    q.close()


def test_quota_limit_notice(tmp_path):
    q = QuotaStore(str(tmp_path / "q.sqlite"))
    q.record("groq", tokens=100)
    assert q.is_exhausted("groq") is False              # no 429 seen
    q.record("groq", tokens=1, was_429=True)
    assert q.is_exhausted("groq", token_cap=100) is True
    assert q.is_exhausted("groq", token_cap=10_000) is False
    q.close()
