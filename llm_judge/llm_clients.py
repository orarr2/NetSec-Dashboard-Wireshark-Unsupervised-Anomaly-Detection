"""LLM provider clients for the judge.

Two concrete implementations of the same one-method protocol:

    client.judge(system_prompt, user_content) -> raw response text
    client.model_id                           -> string used in the cache key

- ClaudeClient: Anthropic API via the official SDK. The key comes from the
  ANTHROPIC_API_KEY environment variable (never stored in the repo). Uses
  structured outputs, so the response is schema-valid JSON by construction.
- OllamaClient: local model over the Ollama REST API (stdlib urllib, no SDK,
  no key, no internet). Uses Ollama's structured-output "format" field.

Imports are lazy so that unit tests with a mocked client run without the
anthropic package or a local Ollama installed.
"""
import json
import urllib.request

try:
    from . import judge_config
except ImportError:  # imported with llm_judge/ itself on sys.path
    import judge_config


class JudgeClientError(RuntimeError):
    """A provider call failed (network, refusal, bad payload)."""


class ClaudeClient:
    """Anthropic API client. Requires ANTHROPIC_API_KEY in the environment."""

    def __init__(self, model=None, timeout_s=None, effort=None,
                 max_tokens=None, verdict_schema=None):
        try:
            import anthropic
        except ImportError as e:
            raise JudgeClientError(
                "The 'anthropic' package is not installed. "
                "Run: pip install -r llm_judge/requirements.txt") from e
        self._anthropic = anthropic
        self.model_id = model or judge_config.CLAUDE_MODEL
        self.effort = effort or judge_config.JUDGE_EFFORT
        self.max_tokens = max_tokens or judge_config.JUDGE_MAX_TOKENS
        self.verdict_schema = verdict_schema
        self._client = anthropic.Anthropic(
            timeout=timeout_s or judge_config.JUDGE_TIMEOUT_S)

    def judge(self, system_prompt, user_content):
        output_config = {"effort": self.effort}
        if self.verdict_schema is not None:
            output_config["format"] = {"type": "json_schema",
                                       "schema": self.verdict_schema}
        try:
            response = self._client.messages.create(
                model=self.model_id,
                max_tokens=self.max_tokens,
                system=system_prompt,
                thinking={"type": "adaptive"},
                output_config=output_config,
                messages=[{"role": "user", "content": user_content}],
            )
        except self._anthropic.APIError as e:
            raise JudgeClientError(f"Anthropic API error: {e}") from e
        if response.stop_reason == "refusal":
            raise JudgeClientError("model declined the request (refusal)")
        if response.stop_reason == "max_tokens":
            raise JudgeClientError("response truncated at max_tokens")
        text = next((b.text for b in response.content if b.type == "text"), "")
        if not text:
            raise JudgeClientError("empty response body")
        return text


class OllamaClient:
    """Local Ollama client (free, offline). Requires the Ollama daemon."""

    def __init__(self, model=None, host=None, timeout_s=None,
                 verdict_schema=None):
        self.model_id = model or judge_config.OLLAMA_MODEL
        self.host = (host or judge_config.OLLAMA_HOST).rstrip("/")
        self.timeout_s = timeout_s or judge_config.JUDGE_TIMEOUT_S
        self.verdict_schema = verdict_schema

    def judge(self, system_prompt, user_content):
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "stream": False,
            "options": {"temperature": 0.0},
        }
        if self.verdict_schema is not None:
            payload["format"] = self.verdict_schema
        req = urllib.request.Request(
            self.host + "/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                data = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            raise JudgeClientError(
                f"Ollama call failed ({self.host}): {e}. "
                "Is the Ollama daemon running? Try: ollama serve") from e
        text = (data.get("message") or {}).get("content", "")
        if not text:
            raise JudgeClientError("empty response body from Ollama")
        return text


def make_client(provider=None, verdict_schema=None):
    """Build the configured provider client."""
    provider = (provider or judge_config.LLM_JUDGE_PROVIDER).lower()
    if provider == "claude":
        return ClaudeClient(verdict_schema=verdict_schema)
    if provider == "ollama":
        return OllamaClient(verdict_schema=verdict_schema)
    raise JudgeClientError(
        f"unknown LLM_JUDGE_PROVIDER '{provider}' (expected claude | ollama)")
