"""LLM provider clients for the judge.

Three concrete implementations of the same one-method protocol:

    client.judge(system_prompt, user_content) -> raw response text
    client.model_id                           -> string used in the cache key

- ClaudeClient: Anthropic API via the official SDK. The key comes from the
  ANTHROPIC_API_KEY environment variable (never stored in the repo). Uses
  structured outputs, so the response is schema-valid JSON by construction.
- OllamaClient: local model over the Ollama REST API (stdlib urllib, no SDK,
  no key, no internet). Uses Ollama's structured-output "format" field.
- OpenAICompatClient: any endpoint speaking the OpenAI chat-completions
  protocol - LM Studio / llamafile / vLLM locally, or hosted services with
  the user's own key from OPENAI_COMPAT_API_KEY. Tries strict json_schema
  response_format first and falls back to json_object for servers that
  don't support schemas.

Imports are lazy so that unit tests with a mocked client run without the
anthropic package or a local Ollama installed.
"""
import json
import urllib.error
import urllib.request

try:
    from . import judge_config
except ImportError:  # imported with llm_judge/ itself on sys.path
    import judge_config


class JudgeClientError(RuntimeError):
    """A provider call failed (network, refusal, bad payload)."""


def _http_error_detail(e):
    """str(HTTPError) is just 'HTTP Error 400: Bad Request'; the server's
    actual explanation (model not found, bad key, context exceeded) is in
    the body - surface a snippet of it."""
    try:
        body = e.read().decode("utf-8", errors="replace")[:300]
    except Exception:
        body = ""
    return f"{e}" + (f" - {body}" if body.strip() else "")


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
        # Set after a model rejects adaptive thinking / effort (older model
        # generations) - later calls then skip those parameters.
        self._minimal_params = False
        self._client = anthropic.Anthropic(
            timeout=timeout_s or judge_config.JUDGE_TIMEOUT_S)

    def _create(self, system_prompt, user_content, minimal):
        kwargs = {
            "model": self.model_id,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_content}],
        }
        output_config = {}
        if not minimal:
            kwargs["thinking"] = {"type": "adaptive"}
            output_config["effort"] = self.effort
        if self.verdict_schema is not None:
            output_config["format"] = {"type": "json_schema",
                                       "schema": self.verdict_schema}
        if output_config:
            kwargs["output_config"] = output_config
        return self._client.messages.create(**kwargs)

    def judge(self, system_prompt, user_content):
        try:
            try:
                response = self._create(system_prompt, user_content,
                                        self._minimal_params)
            except self._anthropic.BadRequestError:
                if self._minimal_params:
                    raise
                # Older Claude generations reject adaptive thinking and/or
                # the effort parameter - degrade to a plain call once, then
                # remember the downgrade for the rest of the batch.
                response = self._create(system_prompt, user_content, True)
                self._minimal_params = True
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
            # keep the model resident between candidates - a batch is many
            # sequential calls and reloading from disk dominates latency
            "keep_alive": "30m",
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
        except urllib.error.HTTPError as e:
            raise JudgeClientError(
                f"Ollama call failed ({self.host}): {_http_error_detail(e)}."
                " Is the model pulled? "
                f"Try: ollama pull {self.model_id}") from e
        except Exception as e:
            raise JudgeClientError(
                f"Ollama call failed ({self.host}): {e}. "
                "Is the Ollama daemon running and the model pulled? "
                f"Try: ollama pull {self.model_id}") from e
        text = (data.get("message") or {}).get("content", "")
        if not text:
            raise JudgeClientError("empty response body from Ollama")
        return text


class OpenAICompatClient:
    """Client for any OpenAI-compatible chat-completions endpoint (stdlib
    urllib, no SDK). Works with LM Studio / llamafile / vLLM locally and
    with hosted OpenAI-style APIs using the user's own key."""

    def __init__(self, model=None, base_url=None, api_key=None,
                 timeout_s=None, verdict_schema=None, max_tokens=2048):
        import os
        self.model_id = model or judge_config.OPENAI_COMPAT_MODEL
        if not self.model_id:
            raise JudgeClientError(
                "OPENAI_COMPAT_MODEL is not set - the openai_compat "
                "provider needs an explicit model name")
        self.base_url = (base_url
                         or judge_config.OPENAI_COMPAT_BASE_URL).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_COMPAT_API_KEY", "")
        self.timeout_s = timeout_s or judge_config.JUDGE_TIMEOUT_S
        self.verdict_schema = verdict_schema
        self.max_tokens = max_tokens
        # Set to True only after the json_object fallback SUCCEEDS where
        # json_schema got a 400 - later calls then skip json_schema.
        self._schema_unsupported = False

    def _post(self, payload):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
            return json.loads(r.read().decode("utf-8"))

    def _payload(self, system_prompt, user_content, response_format):
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.0,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if response_format is not None:
            payload["response_format"] = response_format
        return payload

    def judge(self, system_prompt, user_content):
        plain = ({"type": "json_object"}
                 if self.verdict_schema is not None else None)
        strict = None
        if self.verdict_schema is not None and not self._schema_unsupported:
            strict = {"type": "json_schema",
                      "json_schema": {"name": "judge_verdict",
                                      "strict": True,
                                      "schema": self.verdict_schema}}
        try:
            if strict is not None:
                try:
                    data = self._post(self._payload(system_prompt,
                                                    user_content, strict))
                except urllib.error.HTTPError as e:
                    if e.code != 400:
                        raise
                    # Could be "json_schema unsupported" - or an unrelated
                    # 400 (bad model name, oversized prompt). Try plain
                    # JSON mode once; if that also fails, report BOTH
                    # errors and do not remember a bogus downgrade.
                    first_detail = _http_error_detail(e)
                    try:
                        data = self._post(self._payload(
                            system_prompt, user_content, plain))
                    except urllib.error.HTTPError as e2:
                        raise JudgeClientError(
                            f"OpenAI-compatible call failed ({self.base_url},"
                            f" model {self.model_id}). json_schema attempt: "
                            f"{first_detail}; json_object attempt: "
                            f"{_http_error_detail(e2)}") from e2
                    self._schema_unsupported = True
            else:
                data = self._post(self._payload(system_prompt,
                                                user_content, plain))
        except JudgeClientError:
            raise
        except urllib.error.HTTPError as e:
            raise JudgeClientError(
                f"OpenAI-compatible call failed ({self.base_url}, model "
                f"{self.model_id}): {_http_error_detail(e)}") from e
        except Exception as e:
            raise JudgeClientError(
                f"OpenAI-compatible call failed ({self.base_url}, model "
                f"{self.model_id}): {e}") from e
        choices = data.get("choices") or []
        if choices and choices[0].get("finish_reason") == "length":
            raise JudgeClientError(
                f"response truncated at max_tokens={self.max_tokens} - "
                "the JSON is incomplete; raise max_tokens or use a less "
                "verbose model")
        text = ((choices[0].get("message") or {}).get("content", "")
                if choices else "")
        if not text:
            raise JudgeClientError(
                "empty response body from OpenAI-compatible endpoint")
        return text


def make_client(provider=None, verdict_schema=None):
    """Build the configured provider client."""
    provider = (provider or judge_config.LLM_JUDGE_PROVIDER).lower()
    if provider == "claude":
        return ClaudeClient(verdict_schema=verdict_schema)
    if provider == "ollama":
        return OllamaClient(verdict_schema=verdict_schema)
    if provider == "openai_compat":
        return OpenAICompatClient(verdict_schema=verdict_schema)
    raise JudgeClientError(
        f"unknown LLM_JUDGE_PROVIDER '{provider}' "
        "(expected claude | ollama | openai_compat)")
