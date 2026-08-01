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
    """A provider call failed (network, refusal, bad payload).

    `permanent=True` marks the failure as one that a retry cannot
    plausibly fix - a 4xx from the server (schema unsupported, bad
    model name, malformed prompt). Retrying such errors just burns
    quota and, on strict rate limits like Groq, triggers 429s that
    stall the panel for tens of seconds.
    """

    def __init__(self, message, permanent=False):
        super().__init__(message)
        self.permanent = bool(permanent)


def _http_error_detail(e):
    """str(HTTPError) is just 'HTTP Error 400: Bad Request'; the server's
    actual explanation (model not found, bad key, context exceeded) is in
    the body - surface a snippet of it."""
    try:
        body = e.read().decode("utf-8", errors="replace")[:300]
    except Exception:
        body = ""
    return f"{e}" + (f" - {body}" if body.strip() else "")


def _extract_json_block(text):
    """Cut the reply down to the outermost {...} JSON object. Models running
    with response_format omitted (the json_validate_failed rescue path)
    answer in plain text that usually IS the JSON, but may wrap it in
    markdown fences or a lead-in sentence."""
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start:end + 1]
    return text


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

    def _create(self, system_prompt, user_content, minimal, active_schema):
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
        if active_schema is not None:
            output_config["format"] = {"type": "json_schema",
                                       "schema": active_schema}
        if output_config:
            kwargs["output_config"] = output_config
        return self._client.messages.create(**kwargs)

    def judge(self, system_prompt, user_content, schema=None):
        # A per-call schema (e.g. the debate schema) overrides the one the
        # client was built with; None means "use the constructor schema".
        active = schema if schema is not None else self.verdict_schema
        try:
            try:
                response = self._create(system_prompt, user_content,
                                        self._minimal_params, active)
            except self._anthropic.BadRequestError:
                if self._minimal_params:
                    raise
                # Older Claude generations reject adaptive thinking and/or
                # the effort parameter - degrade to a plain call once, then
                # remember the downgrade for the rest of the batch.
                response = self._create(system_prompt, user_content, True,
                                        active)
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

    def judge(self, system_prompt, user_content, schema=None):
        active = schema if schema is not None else self.verdict_schema
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
        if active is not None:
            payload["format"] = active
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
                f"Try: ollama pull {self.model_id}",
                permanent=(e.code < 500)) from e
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
        # An explicit base_url means the caller is pointing at a specific
        # host (an endpoint profile). Every global default - the key AND
        # the model name - belongs to whatever host OPENAI_COMPAT_BASE_URL
        # names, so borrowing either one for a different host is wrong:
        # the key would leak one provider's secret to another, and the
        # model name would name a model that host has never heard of.
        # Only the default host may use the defaults.
        explicit_host = base_url is not None
        self.base_url = (base_url
                         or judge_config.OPENAI_COMPAT_BASE_URL).rstrip("/")
        if explicit_host:
            self.model_id = model
            self.api_key = api_key or ""
            if not self.model_id:
                raise JudgeClientError(
                    f"no model given for endpoint {self.base_url} - set "
                    "the profile's _MODEL variable (the global "
                    "OPENAI_COMPAT_MODEL belongs to a different host and "
                    "is deliberately not used here)")
        else:
            self.model_id = model or judge_config.OPENAI_COMPAT_MODEL
            self.api_key = api_key or os.environ.get("OPENAI_COMPAT_API_KEY",
                                                     "")
            if not self.model_id:
                raise JudgeClientError(
                    "OPENAI_COMPAT_MODEL is not set - the openai_compat "
                    "provider needs an explicit model name")
        self.timeout_s = timeout_s or judge_config.JUDGE_TIMEOUT_S
        self.verdict_schema = verdict_schema
        self.max_tokens = max_tokens
        self.last_usage = None
        # Set to True only after the json_object fallback SUCCEEDS where
        # json_schema got a 400 - later calls then skip json_schema.
        self._schema_unsupported = False
        # Set to True only after a no-format rescue SUCCEEDS where JSON
        # mode got 400 json_validate_failed (Groq's qwen3.6 in production:
        # the hidden reasoning pass consumes the completion budget under
        # JSON mode, so the validator sees an empty generation). Later
        # calls then skip response_format entirely and the JSON object is
        # cut out of the plain-text reply instead.
        self._json_mode_broken = False

    # Free tiers (Groq: 12k tokens/min) return HTTP 429 when a batch is
    # bursty. Retry a bounded number of times, honoring the server's stated
    # wait, so a single hot minute doesn't silently drop candidates. The
    # cap is deliberately short: a panel of N judges runs each retry in
    # parallel, so a 30-second wait would stall every judge together and
    # look like a hang. 8s x 2 retries = at most ~20s added on the hot
    # path - enough to survive one bursty batch, small enough that the
    # UI still feels alive.
    _MAX_RETRIES = 2
    _MAX_WAIT_S = 8.0

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

    # Reasoning models emit a thinking block before the answer; on Groq
    # the block bleeds into JSON-mode output and json_validate_failed
    # kills every call (measured: qwen3.6-27b failed 15/16 in session
    # 13). reasoning_format=hidden strips it server-side. The parameter
    # is REJECTED by non-reasoning models (llama: 400 "not supported"),
    # so it is sent only to model families known to need it.
    _REASONING_HIDDEN_MARKERS = ("qwen3", "deepseek-r1", "qwq")

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
        if any(m in self.model_id.lower()
               for m in self._REASONING_HIDDEN_MARKERS):
            payload["reasoning_format"] = "hidden"
        return payload

    def _no_format_rescue(self, system_prompt, user_content, prior_detail):
        """One attempt with response_format omitted, for models that answer
        fine as plain text but flunk the server-side JSON validator in JSON
        mode (Groq's qwen3.6, measured in production: HTTP 400
        json_validate_failed with an EMPTY failed_generation on 28/33
        calls). Success is remembered so later calls go straight to
        no-format instead of re-burning the doomed JSON modes."""
        try:
            data = self._post(self._payload(system_prompt, user_content,
                                            None))
        except urllib.error.HTTPError as e:
            raise JudgeClientError(
                f"OpenAI-compatible call failed ({self.base_url}, model "
                f"{self.model_id}). {prior_detail}; no-format attempt: "
                f"{_http_error_detail(e)}",
                permanent=(e.code < 500)) from e
        self._json_mode_broken = True
        return data

    def judge(self, system_prompt, user_content, schema=None):
        active = schema if schema is not None else self.verdict_schema
        plain = ({"type": "json_object"}
                 if active is not None and not self._json_mode_broken
                 else None)
        strict = None
        if (active is not None and not self._schema_unsupported
                and not self._json_mode_broken):
            strict = {"type": "json_schema",
                      "json_schema": {"name": "judge_verdict",
                                      "strict": True,
                                      "schema": active}}
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
                        second_detail = _http_error_detail(e2)
                        if (e2.code == 400
                                and "json_validate_failed" in second_detail):
                            # The model answers but flunks the server-side
                            # JSON validator. Last resort: no format
                            # constraint at all.
                            data = self._no_format_rescue(
                                system_prompt, user_content,
                                f"json_schema attempt: {first_detail}; "
                                f"json_object attempt: {second_detail}")
                        else:
                            # Both formats rejected by the server - the
                            # model is broken, the request is malformed, OR
                            # we already exhausted the internal 429 retry
                            # budget inside _post. A further retry cannot
                            # fix any of those and just burns quota, so
                            # mark permanent for every 4xx (429 included -
                            # _post already backed off).
                            raise JudgeClientError(
                                f"OpenAI-compatible call failed "
                                f"({self.base_url}, model {self.model_id})."
                                f" json_schema attempt: {first_detail}; "
                                f"json_object attempt: {second_detail}",
                                permanent=(e2.code < 500)) \
                                from e2
                    else:
                        self._schema_unsupported = True
            elif plain is not None:
                try:
                    data = self._post(self._payload(system_prompt,
                                                    user_content, plain))
                except urllib.error.HTTPError as e:
                    detail = _http_error_detail(e)
                    if e.code == 400 and "json_validate_failed" in detail:
                        data = self._no_format_rescue(
                            system_prompt, user_content,
                            f"json_object attempt: {detail}")
                    else:
                        raise JudgeClientError(
                            f"OpenAI-compatible call failed ({self.base_url},"
                            f" model {self.model_id}): {detail}",
                            permanent=(e.code < 500)) from e
            else:
                data = self._post(self._payload(system_prompt,
                                                user_content, None))
        except JudgeClientError:
            raise
        except urllib.error.HTTPError as e:
            # Every 4xx is permanent at this layer: 400/401/404 for a
            # wrong request cannot recover, and a 429 that reached here
            # already exhausted the burst-retry inside _post - the outer
            # retry would just wait through the same rate window again.
            # 5xx stays transient (server hiccup).
            raise JudgeClientError(
                f"OpenAI-compatible call failed ({self.base_url}, model "
                f"{self.model_id}): {_http_error_detail(e)}",
                permanent=(e.code < 500)) from e
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
        if self._json_mode_broken and active is not None:
            # No-format replies may wrap the JSON in prose or fences.
            text = _extract_json_block(text)
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
        # A profile that names a key variable but leaves it empty is a
        # half-finished setup. Fail here, loudly, rather than sending an
        # unauthenticated request that comes back as an opaque 401 - and
        # never silently borrow another provider's key.
        if p["key_env"] and not p["api_key"]:
            raise JudgeClientError(
                f"endpoint profile '{provider}' declares "
                f"LLM_JUDGE_EP_{provider.upper()}_KEY_ENV={p['key_env']}, "
                f"but {p['key_env']} is empty. Set it, or drop the "
                f"KEY_ENV line if this endpoint needs no key.")
        client = OpenAICompatClient(
            verdict_schema=verdict_schema, model=model or p["model"],
            base_url=p["base_url"], api_key=p["api_key"] or None)
        # tag so the usage/quota log records under the profile name, not
        # the shared "openai_compat" bucket
        client.provider_name = provider
        return client

    raise JudgeClientError(
        f"unknown provider '{provider}' (expected claude | ollama | "
        "openai_compat, or a defined LLM_JUDGE_EP_<NAME> profile: "
        f"{sorted(profiles) or 'none defined'})")

# There is no automatic fallback between providers by design: which judges
# run is the user's explicit choice (LLM_JUDGE_PANEL - one, two, or many).
# The panel runs every judge the user selected and returns all verdicts;
# a judge that errors is reported in the panel result, never silently
# swapped for another model. See llm_judge/quota.py for optional
# informational usage tracking (staying under free-tier limits).
