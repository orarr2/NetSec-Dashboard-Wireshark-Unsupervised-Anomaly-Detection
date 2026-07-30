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
import re
import time
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
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = {
                "tokens_in": getattr(usage, "input_tokens", None),
                "tokens_out": getattr(usage, "output_tokens", None)}
        return text


class OllamaClient:
    """Local Ollama client (free, offline). Requires the Ollama daemon."""

    def __init__(self, model=None, host=None, timeout_s=None,
                 verdict_schema=None):
        self.model_id = model or judge_config.OLLAMA_MODEL
        self.host = (host or judge_config.OLLAMA_HOST).rstrip("/")
        self.timeout_s = timeout_s or judge_config.JUDGE_TIMEOUT_S
        self.verdict_schema = verdict_schema
        self.last_usage = None

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
        self.last_usage = {"tokens_in": data.get("prompt_eval_count"),
                           "tokens_out": data.get("eval_count")}
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
        self.last_usage = None
        # Set to True only after the json_object fallback SUCCEEDS where
        # json_schema got a 400 - later calls then skip json_schema.
        self._schema_unsupported = False

    # Free tiers (Groq: 12k tokens/min) return HTTP 429 when a batch is
    # bursty. Retry a bounded number of times, honoring the server's stated
    # wait, so a single hot minute doesn't silently drop candidates.
    _MAX_RETRIES = 3
    _MAX_WAIT_S = 30.0

    @staticmethod
    def _retry_after_seconds(e):
        """Seconds to wait before retrying a 429, from the Retry-After header
        or the 'try again in Xs' hint Groq embeds in the JSON body. Falls
        back to 5s. Reads the body (safe: this HTTPError is being retried,
        not re-raised, so consuming it here is harmless)."""
        ra = e.headers.get("Retry-After") if e.headers else None
        if ra:
            try:
                return float(ra)
            except (TypeError, ValueError):
                pass
        try:
            body = e.read().decode("utf-8", errors="replace")
            m = re.search(r"try again in ([\d.]+)\s*s", body)
            if m:
                return float(m.group(1)) + 0.5  # small cushion
        except Exception:
            pass
        return 5.0

    def _post(self, payload):
        # User-Agent is mandatory - Groq / Cloudflare-protected endpoints
        # return HTTP 403 (error 1010) for the default Python-urllib UA.
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "netsec-llm-judge/0.1 (+llm_judge)",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = json.dumps(payload).encode("utf-8")
        for attempt in range(self._MAX_RETRIES + 1):
            req = urllib.request.Request(
                self.base_url + "/chat/completions",
                data=data, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                    return json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                # Only 429 is retryable here; 400/401/etc. propagate so the
                # json_schema-fallback logic in judge() still sees them.
                if e.code != 429 or attempt == self._MAX_RETRIES:
                    raise
                wait = min(max(self._retry_after_seconds(e), 1.0),
                           self._MAX_WAIT_S)
                time.sleep(wait)

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
        usage = data.get("usage") or {}
        self.last_usage = {"tokens_in": usage.get("prompt_tokens"),
                           "tokens_out": usage.get("completion_tokens")}
        return text


def make_panel_clients(entries, verdict_schema=None):
    """Build one client per (provider, model) panel entry.

    Construction failures (e.g. the anthropic package missing for a claude
    entry) do not abort the whole panel: the failed entry is recorded and
    the remaining judges carry on - the panel's whole point is surviving
    the loss of one expert. Returns (clients, init_failures) where
    init_failures is [{"entry", "error"}].
    """
    clients, init_failures = [], []
    for provider, model in entries:
        try:
            clients.append(make_client(provider=provider,
                                       verdict_schema=verdict_schema,
                                       model=model))
        except Exception as e:
            init_failures.append({"entry": f"{provider}:{model}",
                                  "error": str(e)})
    return clients, init_failures


def make_client(provider=None, verdict_schema=None, model=None):
    """Build the configured provider client.

    `model` overrides the provider's default model - used by committee mode
    to build a second judge (Judge B) on the same provider/key with a
    different model. None keeps each provider's configured default.

    `provider` may be one of the three built-ins (claude | ollama |
    openai_compat) or the name of an endpoint profile from
    judge_config.endpoint_profiles() (spec 6.1) - a profile resolves to
    an OpenAICompatClient carrying that host's base_url, model and key.
    """
    provider = (provider or judge_config.LLM_JUDGE_PROVIDER).lower()
    if provider == "claude":
        return ClaudeClient(verdict_schema=verdict_schema, model=model)
    if provider == "ollama":
        return OllamaClient(verdict_schema=verdict_schema, model=model)
    if provider == "openai_compat":
        return OpenAICompatClient(verdict_schema=verdict_schema, model=model)

    profiles = judge_config.endpoint_profiles()
    if provider in profiles:
        p = profiles[provider]
        client = OpenAICompatClient(
            verdict_schema=verdict_schema, model=model or p["model"],
            base_url=p["base_url"], api_key=p["api_key"] or None)
        # tag so the failover/quota layer records under the profile name,
        # not the shared "openai_compat" bucket
        client.provider_name = provider
        return client

    raise JudgeClientError(
        f"unknown provider '{provider}' (expected claude | ollama | "
        "openai_compat, or a defined LLM_JUDGE_EP_<NAME> profile: "
        f"{sorted(profiles) or 'none defined'})")


class FailoverClient:
    """Try an ordered list of clients until one returns a verdict (spec
    section 6.3). A client that raises JudgeClientError - or that quota
    marks exhausted for the day - is skipped; the next in the chain takes
    over. With a local Ollama last, the panel/judge slows down under
    quota pressure instead of failing. Records every attempt in the quota
    store so tomorrow's runs start fresh.

    Exposes the same (judge, model_id) shape as a single client, so it
    drops into judge_candidates/committee/panel unchanged. model_id
    reflects the client that actually answered the most recent call.
    """

    def __init__(self, clients, providers=None, quota=None):
        if not clients:
            raise JudgeClientError("FailoverClient needs at least one client")
        self._clients = clients
        self._providers = providers or [
            getattr(c, "provider_name", type(c).__name__) for c in clients]
        self._quota = quota
        self.model_id = clients[0].model_id
        self.last_provider = self._providers[0]

    def judge(self, system_prompt, user_content):
        errors = []
        for client, provider in zip(self._clients, self._providers):
            if self._quota is not None and self._quota.is_exhausted(provider):
                errors.append(f"{provider}: skipped (quota exhausted today)")
                continue
            try:
                text = client.judge(system_prompt, user_content)
            except JudgeClientError as e:
                was_429 = "429" in str(e)
                if self._quota is not None:
                    self._quota.record(provider, was_429=was_429)
                errors.append(f"{provider}: {e}")
                continue
            self.model_id = client.model_id
            self.last_provider = provider
            if self._quota is not None:
                usage = getattr(client, "last_usage", None) or {}
                self._quota.record(
                    provider,
                    tokens=(usage.get("tokens_in") or 0)
                    + (usage.get("tokens_out") or 0))
            return text
        raise JudgeClientError(
            "all failover providers failed or are exhausted: "
            + "; ".join(errors))


def make_failover_client(spec=None, verdict_schema=None, quota=None):
    """Build a FailoverClient from a comma-separated provider/profile
    chain (defaults to judge_config.LLM_JUDGE_FAILOVER). Unconstructible
    providers are dropped with a warning; at least one must remain."""
    spec = spec if spec is not None else judge_config.LLM_JUDGE_FAILOVER
    names = [n.strip().lower() for n in (spec or "").split(",") if n.strip()]
    if not names:
        raise JudgeClientError(
            "no failover chain configured (set LLM_JUDGE_FAILOVER)")
    clients, providers = [], []
    for name in names:
        try:
            clients.append(make_client(provider=name,
                                       verdict_schema=verdict_schema))
            providers.append(name)
        except Exception as e:
            print(f"[failover] provider {name!r} unavailable, skipping: {e}",
                  flush=True)
    if not clients:
        raise JudgeClientError(
            f"none of the failover providers {names} could be constructed")
    return FailoverClient(clients, providers=providers, quota=quota)
