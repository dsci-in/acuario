from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from genai_pyo3 import (
    ChatMessage,
    ChatOptions,
    ChatRequest,
    ChatResponse,
    Client,
    JsonSpec,
    Tool,
)
from pydantic import BaseModel, RootModel

from acuario.llm.retry_policy import (
    KIND_RATE_LIMITED,
    KIND_REQUEST_ERROR,
    KIND_TRANSIENT,
    classify_error,
    max_attempts_for_kind,
)

logger = logging.getLogger(__name__)

# Sentinel distinguishing "caller did not override reasoning_effort" (use
# the client's construction-time default) from an explicit value like "low" or
# None. reasoning_effort is threaded as a PER-CALL override because a role that
# shares a cached client (the native cache key omits task) must still be able to
# ask for its own effort per call rather than inheriting the first builder's.
_REASONING_UNSET: Any = object()

# Generous default per-call wall-clock ceiling. A single LLM call must not
# run for hours (a hung variant has stalled for ~8h; the slowest *legit*
# call was ~28min), so 1h leaves ample headroom yet still reclaims a hung call.
# Tune via ACUARIO_LLM_CALL_TIMEOUT; disable by passing request_timeout_seconds=0.
_DEFAULT_CALL_TIMEOUT_S = 3600.0


def _run_coro_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("Synchronous wrapper called from a running event loop")


def response_text(response: ChatResponse) -> str:
    """Coalesce a :class:`ChatResponse`'s text segments into a single string.

    Prefers ``first_text()`` when it is non-empty; falls back to joining
    every non-empty segment in ``texts()``. Returns ``""`` when the
    response carries no text at all (e.g. a pure tool-call response).
    """
    first = response.first_text()
    if first:
        return first
    return "\n".join(segment for segment in response.texts() if segment)


def _is_root_model_type(schema_model: type[BaseModel]) -> bool:
    return issubclass(schema_model, RootModel)


def _validate_schema_response(schema_model: type[BaseModel], text: str) -> BaseModel:
    try:
        return schema_model.model_validate_json(text)
    except Exception:
        parsed_json = json.loads(text)
        if isinstance(parsed_json, list) and "results" in schema_model.model_fields:
            return schema_model.model_validate({"results": parsed_json})
        raise


@dataclass(slots=True)
class NativeToolSpec:
    name: str
    description: str
    schema: dict[str, Any]
    handler: Any

    async def ainvoke(self, arguments: dict[str, Any]) -> Any:
        if asyncio.iscoroutinefunction(self.handler):
            return await self.handler(**arguments)
        return await asyncio.to_thread(self.handler, **arguments)

    def invoke(self, arguments: dict[str, Any] | None = None) -> Any:
        return _run_coro_sync(self.ainvoke(arguments or {}))

    @property
    def input_schema(self) -> dict[str, Any]:
        return self.schema


class AsyncLLMClient:
    """Native async wrapper around genai-pyo3 for scanner/runtime use.

    This intentionally bypasses LangChain's message/result model and exposes
    only the pieces Acuario actually needs: text, tool calls, usage, and
    bounded concurrency.
    """

    def __init__(
        self,
        *,
        model_name: str,
        provider_name: str,
        api_key: str,
        base_url: str | None = None,
        max_concurrency: int = 4,
        default_system: str = "You are a helpful assistant.",
        rate_limit_max_retries: int = 6,
        rate_limit_initial_backoff_seconds: float = 1.0,
        rate_limit_max_backoff_seconds: float = 60.0,
        reasoning_effort: str | None = "medium",
        task_label: str = "",
        request_timeout_seconds: float | None = None,
    ) -> None:
        self.model_name = model_name
        self.provider_name = provider_name
        # Which pipeline role this client serves (analyzer / reviewer /
        # skeptic / …). Used only to attribute token spend per agent in the
        # CostTracker - purely observational, never affects behavior.
        self.task_label = task_label
        self.api_key = api_key
        self.base_url = base_url
        self._default_headers: dict[str, str] | None = None

        # `openai_codex` is acuario's label for the OAuth-authenticated
        # Responses API (the ChatGPT "Codex CLI" flow). It's not a distinct
        # rust-genai adapter - it *is* the openai_resp adapter plus three
        # extra request headers (`chatgpt-account-id`, `OpenAI-Beta`,
        # `originator`) and a proxy base_url. Resolve the OAuth token and
        # account-id once here; from this point on the Client behaves
        # exactly like any other openai_resp Client.
        #
        # Token refresh happens once at construction. If the token expires
        # during a long-running AsyncLLMClient instance, subsequent calls
        # will fail until the instance is rebuilt - accepted tradeoff for
        # avoiding per-call refresh overhead.
        if provider_name == "openai_codex":
            from acuario.providers.openai_oauth import (
                OPENAI_CODEX_DEFAULT_BASE_URL,
                ensure_fresh_openai_oauth_credentials,
                extract_account_id,
            )

            try:
                creds = ensure_fresh_openai_oauth_credentials()
                self.api_key = creds.access
            except Exception:
                if not self.api_key:
                    raise

            if not self.api_key:
                raise RuntimeError(
                    "Missing OpenAI OAuth access token. "
                    "Run: `acuario setup --provider openai-oauth`"
                )

            account_id = extract_account_id(self.api_key)
            if not account_id:
                raise RuntimeError("OpenAI OAuth access token is missing the ChatGPT account id.")

            # rust-genai's openai_resp adapter joins "responses" onto the
            # base_url, so set base to `.../codex/` and let it produce
            # `.../codex/responses`.
            self.base_url = self.base_url or f"{OPENAI_CODEX_DEFAULT_BASE_URL}/codex/"
            self._default_headers = {
                "chatgpt-account-id": account_id,
                "OpenAI-Beta": "responses=experimental",
                "originator": "pi",
                "user-agent": "acuario (python)",
            }

        self.default_system = default_system
        # `reasoning_effort` controls how much reasoning the provider
        # runs (for models that support it). "medium" is a sensible
        # default - higher for deeper-reasoning tasks, "none"/None to
        # opt out entirely. Accepted values: "none" | "minimal" | "low"
        # | "medium" | "high" | "xhigh" | "max" | "budget:<n>".
        self.reasoning_effort = reasoning_effort
        # Resolve the per-call wall-clock ceiling. Explicit arg wins; else
        # ACUARIO_LLM_CALL_TIMEOUT; else a generous 1h default. 0/None disables.
        if request_timeout_seconds is None:
            env_timeout = os.environ.get("ACUARIO_LLM_CALL_TIMEOUT", "").strip()
            if env_timeout:
                try:
                    request_timeout_seconds = float(env_timeout)
                except ValueError:
                    request_timeout_seconds = _DEFAULT_CALL_TIMEOUT_S
            else:
                request_timeout_seconds = _DEFAULT_CALL_TIMEOUT_S
        self.request_timeout_seconds = request_timeout_seconds
        self.rate_limit_max_retries = max(0, rate_limit_max_retries)
        self.rate_limit_initial_backoff_seconds = max(0.1, rate_limit_initial_backoff_seconds)
        self.rate_limit_max_backoff_seconds = max(
            self.rate_limit_initial_backoff_seconds,
            rate_limit_max_backoff_seconds,
        )
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        # Opt-in AIMD adaptive concurrency. When ACUARIO_ADAPTIVE_CONCURRENCY
        # is set, requests are gated by a self-tuning limiter that probes for
        # spare capacity on success and backs off on rate-limit/overload,
        # instead of the fixed semaphore above. Default off - the static
        # semaphore stays the proven path.
        self._adaptive_limiter: Any = None
        if os.environ.get("ACUARIO_ADAPTIVE_CONCURRENCY", "").strip() not in ("", "0", "false"):
            from acuario.llm.adaptive_concurrency import AdaptiveConcurrencyLimiter

            self._adaptive_limiter = AdaptiveConcurrencyLimiter(
                initial=max(1, max_concurrency), max_limit=max(32, max_concurrency)
            )
        # Cache the genai-pyo3 Client so we don't rebuild it (and re-open
        # CA-cert / TLS file descriptors) on every achat() call. Without
        # this, large source-audit runs exhaust the OS file-descriptor
        # limit after a few hundred LLM calls.
        self._cached_client: object | None = None

    async def achat(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None = None,
        tools: list[NativeToolSpec] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        reasoning_effort: Any = _REASONING_UNSET,
        usage_task: str | None = None,
        response_schema: type[BaseModel] | None = None,
        response_schema_name: str | None = None,
        response_schema_description: str | None = None,
    ) -> ChatResponse:
        effective_reasoning = (
            self.reasoning_effort if reasoning_effort is _REASONING_UNSET else reasoning_effort
        )
        request_tools = None
        if tools:
            request_tools = [
                Tool(
                    tool.name,
                    tool.description,
                    json.dumps(tool.schema),
                )
                for tool in tools
            ]

        request = ChatRequest(
            messages=list(messages),
            system=system or self.default_system,
            tools=request_tools,
        )
        options = ChatOptions(
            temperature=temperature,
            max_tokens=max_tokens,
            capture_content=True,
            capture_usage=True,
            capture_tool_calls=True,
            # Ask genai-pyo3 to surface the provider's reasoning output
            # (OpenAI Responses `reasoning.summary`, Anthropic thinking
            # blocks, etc.). `normalize_reasoning_content` unifies the
            # varied provider shapes into ChatResponse.reasoning_content,
            # so analyzer transcripts see a single string regardless of
            # backend.
            capture_reasoning_content=True,
            normalize_reasoning_content=True,
            reasoning_effort=effective_reasoning,
            response_json_spec=(
                _json_spec_from_model(
                    response_schema,
                    name=response_schema_name,
                    description=response_schema_description,
                )
                if response_schema is not None
                else None
            ),
        )

        request_summary = self._summarize_request(messages, system, tools)
        async with self._adaptive_limiter or self._semaphore:
            client = self._build_client(Client)
            response = await self._call_with_timeout(
                self._with_rate_limit_retries(
                    lambda: self._achat_with_provider_policy(client, request, options),
                    request_summary=request_summary,
                )
            )
        self._report_usage(response, usage_task)
        return response

    @staticmethod
    def _summarize_request(messages, system, tools) -> str:
        """Build a compact, logged-on-malformed-request summary of the
        controllable request shape.

        Captures tool names + their JSON schemas, message role/count, and
        system-prompt length - enough to root-cause a deterministic 4xx
        marshalling reject without dumping full prompts.
        """
        try:
            roles: dict[str, int] = {}
            for m in messages or []:
                role = getattr(m, "role", None) or "?"
                roles[str(role)] = roles.get(str(role), 0) + 1
            tool_descs = []
            for t in tools or []:
                tool_descs.append({"name": t.name, "schema": t.schema})
            return json.dumps(
                {
                    "message_roles": roles,
                    "message_count": len(messages or []),
                    "system_len": len(system or ""),
                    "tools": tool_descs,
                },
                default=str,
            )[:4000]
        except Exception:  # noqa: BLE001 - diagnostics must never break the call
            return "(summary unavailable)"

    async def _call_with_timeout(self, awaitable: Any) -> Any:
        """Bound one LLM call by the per-call wall-clock ceiling. The retry
        loop runs INSIDE the ceiling, so a hung call is aborted (not retried);
        a generous timeout never cuts a legitimately slow deep step.
        """
        timeout = self.request_timeout_seconds
        if not timeout or timeout <= 0:
            return await awaitable
        try:
            return await asyncio.wait_for(awaitable, timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "LLM call exceeded %.0fs wall-clock (task=%s, model=%s); "
                "aborting to free the pipeline",
                timeout,
                self.task_label or "?",
                self.model_name,
            )
            raise

    def _report_usage(self, response: ChatResponse, usage_task: str | None = None) -> None:
        """Forward this call's token usage to the global CostTracker.

        Centralizing this here means every caller (analyzer, prioritizer,
        reviewer, validator, exploit-dev) feeds the singleton without each
        one having to remember. Failures are swallowed - telemetry must
        never break a real audit.

        ``usage_task`` is the PER-CALL attribution. On a single shared
        endpoint every role reuses ONE cached client (the cache key omits task),
        so ``self.task_label`` alone bucketed every call under whichever role
        built the client first. The task-scoped wrapper passes the real caller
        per call; fall back to the client's own label, then "unattributed".
        """
        try:
            usage = getattr(response, "usage", None)
            if usage is None:
                return
            prompt = getattr(usage, "prompt_tokens", 0) or 0
            completion = getattr(usage, "completion_tokens", 0) or 0
            if prompt == 0 and completion == 0:
                return
            from acuario.observability.telemetry import CostTracker

            CostTracker().record_llm_call(
                input_tokens=int(prompt),
                output_tokens=int(completion),
                model=self.model_name,
                task=usage_task or self.task_label or "unattributed",
            )
        except Exception:  # noqa: BLE001 - telemetry must not break audits
            pass

    async def achat_stream(
        self,
        *,
        messages: list[ChatMessage],
        system: str | None = None,
        tools: list[NativeToolSpec] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        reasoning_effort: Any = _REASONING_UNSET,
        usage_task: str | None = None,
        on_text_delta: Callable[[str], None] | None = None,
    ) -> ChatResponse:
        """Like ``achat`` but streams text deltas via *on_text_delta*.

        Uses genai-pyo3's native ``astream_chat``. Falls back to
        non-streaming ``achat`` when no callback is given.
        """
        effective_reasoning = (
            self.reasoning_effort if reasoning_effort is _REASONING_UNSET else reasoning_effort
        )
        if on_text_delta is None:
            return await self.achat(
                messages=messages,
                system=system,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                reasoning_effort=reasoning_effort,
                usage_task=usage_task,
            )

        request_tools = None
        if tools:
            request_tools = [
                Tool(tool.name, tool.description, json.dumps(tool.schema)) for tool in tools
            ]
        request = ChatRequest(
            messages=list(messages),
            system=system or self.default_system,
            tools=request_tools,
        )
        options = ChatOptions(
            temperature=temperature,
            max_tokens=max_tokens,
            capture_content=True,
            capture_usage=True,
            capture_tool_calls=True,
            capture_reasoning_content=True,
            normalize_reasoning_content=True,
            reasoning_effort=effective_reasoning,
        )

        async def _consume() -> ChatResponse | None:
            client = self._build_client(Client)
            stream = await client.astream_chat(self.model_name, request, options)
            async for event in stream:
                if event.content:
                    on_text_delta(event.content)
                if event.end is not None:
                    self._report_usage(event.end, usage_task)
                    return event.end
            return None

        async with self._adaptive_limiter or self._semaphore:
            end = await self._call_with_timeout(_consume())
        if end is not None:
            return end
        # Fallback if stream ends without an end event
        return await self.achat(
            messages=messages,
            system=system,
            tools=tools,
            temperature=temperature,
            max_tokens=max_tokens,
            reasoning_effort=reasoning_effort,
            usage_task=usage_task,
        )

    def chat(self, **kwargs: Any) -> ChatResponse:
        return _run_coro_sync(self.achat(**kwargs))

    async def aask_text(
        self,
        *,
        system: str,
        user: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        reasoning_effort: Any = _REASONING_UNSET,
        usage_task: str | None = None,
        response_schema: type[BaseModel] | None = None,
        response_schema_name: str | None = None,
        response_schema_description: str | None = None,
    ) -> ChatResponse:
        return await self.achat(
            messages=[ChatMessage("user", user)],
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
            reasoning_effort=reasoning_effort,
            usage_task=usage_task,
            response_schema=response_schema,
            response_schema_name=response_schema_name,
            response_schema_description=response_schema_description,
        )

    async def aask_json(
        self,
        *,
        system: str,
        user: str,
        expect: str = "object",
        temperature: float | None = None,
        max_tokens: int | None = None,
        reasoning_effort: Any = _REASONING_UNSET,
        usage_task: str | None = None,
        schema_model: type[BaseModel] | None = None,
        schema_name: str | None = None,
        schema_description: str | None = None,
    ) -> tuple[Any, ChatResponse]:
        response = await self.aask_text(
            system=system,
            user=user,
            temperature=temperature,
            max_tokens=max_tokens,
            reasoning_effort=reasoning_effort,
            usage_task=usage_task,
            response_schema=schema_model,
            response_schema_name=schema_name,
            response_schema_description=schema_description,
        )
        text = response_text(response)
        if schema_model is not None:
            parsed_model = _validate_schema_response(schema_model, text)
            if _is_root_model_type(schema_model):
                return parsed_model.root, response
            return parsed_model.model_dump(), response
        if expect == "array":
            return extract_json_array(text), response
        return extract_json_object(text), response

    def _build_client(self, client_cls):
        # Return the cached client if we've already built one for this
        # AsyncLLMClient instance. Without this, every achat() call
        # constructed a fresh reqwest client, leaking TLS / CA-cert file
        # descriptors and eventually crashing with EMFILE.
        if self._cached_client is not None:
            return self._cached_client

        # openai_codex is not a rust-genai adapter - it's the openai_resp
        # adapter plus the extra headers __init__ stashed on
        # `self._default_headers`. Map the name here so genai-pyo3's
        # adapter-kind validator accepts it.
        rust_provider = (
            "openai_resp" if self.provider_name == "openai_codex" else self.provider_name
        )
        default_headers = self._default_headers
        base_url = self.base_url
        if base_url:
            base_url = base_url if base_url.endswith("/") else f"{base_url}/"
            if self.api_key:
                client = client_cls.with_api_key_and_base_url(
                    rust_provider,
                    self.api_key,
                    base_url,
                    default_headers=default_headers,
                )
            else:
                client = client_cls.with_base_url(
                    rust_provider, base_url, default_headers=default_headers
                )
        elif self.api_key:
            client = client_cls.with_api_key(
                rust_provider, self.api_key, default_headers=default_headers
            )
        else:
            client = client_cls()

        self._cached_client = client
        return client

    async def _achat_with_provider_policy(
        self,
        client: Client,
        request: ChatRequest,
        options: ChatOptions,
    ) -> ChatResponse:
        # Always go through `achat_via_stream`: it streams internally and
        # returns a fully-collected ChatResponse, so callers never see
        # chunk events. Necessary for backends that require `stream=true`
        # on the wire (our local openai_resp gateway, OpenAI's Responses
        # API with certain models), harmless for everyone else - every
        # adapter genai-pyo3 supports speaks SSE.
        return await client.achat_via_stream(self.model_name, request, options)

    async def _with_rate_limit_retries(self, op, *, request_summary=None) -> ChatResponse:
        attempt = 0
        backed_off = False  # did we hit a rate-limit/transient signal?
        while True:
            try:
                result = await op()
                # A clean (or recovered) success - probe for more capacity.
                await self._record_concurrency_outcome(success=True, backed_off=backed_off)
                return result
            except Exception as exc:
                kind = self._classify_retryable(exc)
                # Request errors (deterministic 4xx the server rejects on
                # the same body - e.g. the vLLM chat-template 400) get a single
                # cautious retry, not the full backoff budget. Everything else
                # gets the configured rate-limit budget.
                budget = max_attempts_for_kind(kind, default=self.rate_limit_max_retries)
                if kind == KIND_REQUEST_ERROR:
                    # Capture everything we control about the outbound request
                    # so the next live run can root-cause the marshalling bug
                    # (genai-pyo3 doesn't surface the raw wire body to us).
                    self._log_request_error(exc, request_summary)
                if kind in (KIND_RATE_LIMITED, KIND_TRANSIENT):
                    backed_off = True
                if kind is None or attempt >= budget:
                    # Terminal failure - back off if it was load-related.
                    await self._record_concurrency_outcome(success=False, backed_off=backed_off)
                    raise

                delay = self._retry_delay_seconds(exc, attempt)
                attempt += 1
                logger.warning(
                    "LLM call %s for model=%s provider=%s; retrying in %.2fs (attempt %d/%d): %s",
                    kind,
                    self.model_name,
                    self.provider_name,
                    delay,
                    attempt,
                    budget,
                    exc,
                )
                await asyncio.sleep(delay)

    async def _record_concurrency_outcome(self, *, success: bool, backed_off: bool) -> None:
        """Feed one call's result into the adaptive limiter (no-op when the
        static semaphore is in use)."""
        if self._adaptive_limiter is None:
            return
        try:
            await self._adaptive_limiter.record_outcome(success=success, backed_off=backed_off)
        except Exception:  # noqa: BLE001 - concurrency tuning must never break a call
            logger.debug("[concurrency] record_outcome failed", exc_info=True)

    def _log_request_error(self, exc: Exception, request_summary) -> None:
        """Log the controllable shape of a request the server rejected as
        malformed, so a deterministic 4xx can be root-caused offline.

        genai-pyo3 owns the wire serialization, so we log what we passed in:
        tool names + JSON schemas, message role/count, and system-prompt
        length. Best-effort - never raises into the retry loop.
        """
        try:
            logger.warning(
                "LLM request rejected as malformed (model=%s provider=%s): %s\n"
                "  request summary: %s",
                self.model_name,
                self.provider_name,
                str(exc)[:500],
                request_summary or "(not provided)",
            )
        except Exception:  # noqa: BLE001 - diagnostics must never break the call
            pass

    def _classify_retryable(self, exc: Exception) -> str | None:
        """Classify an error into a retry category (or None = surface it).

        Delegates to the shared :mod:`acuario.llm.retry_policy` so the LLM
        layer and the resume verifier stay in sync. Request errors (e.g. the
        deterministic vLLM chat-template 400) are recognized here but their
        *attempt budget* is capped in :meth:`_with_rate_limit_retries`.
        """
        return classify_error(exc)

    def _is_rate_limit_error(self, exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            " 429" in text
            or text.startswith("429")
            or "status code 429" in text
            or "too many requests" in text
            or "rate limit" in text
            or "ratelimit" in text
        )

    def _retry_delay_seconds(self, exc: Exception, attempt: int) -> float:
        retry_after = self._parse_retry_after_seconds(str(exc))
        if retry_after is not None:
            base_delay = retry_after
        else:
            base_delay = min(
                self.rate_limit_initial_backoff_seconds * (2**attempt),
                self.rate_limit_max_backoff_seconds,
            )

        jitter = min(1.0, base_delay * 0.2) * random.random()
        return min(base_delay + jitter, self.rate_limit_max_backoff_seconds)

    def _parse_retry_after_seconds(self, text: str) -> float | None:
        patterns = [
            r"retry[- ]after[:=]?\s*([0-9]+(?:\.[0-9]+)?)",
            r"try again in\s*([0-9]+(?:\.[0-9]+)?)s",
            r"wait\s*([0-9]+(?:\.[0-9]+)?)s",
        ]
        lowered = text.lower()
        for pattern in patterns:
            match = re.search(pattern, lowered)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    return None
        return None


def extract_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise ValueError("response did not contain a JSON object")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("response JSON was not an object")
    return parsed


def extract_json_array(text: str) -> list[Any]:
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        raise ValueError("response did not contain a JSON array")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, list):
        raise ValueError("response JSON was not an array")
    return parsed


def _json_spec_from_model(
    schema_model: type[BaseModel],
    *,
    name: str | None = None,
    description: str | None = None,
) -> JsonSpec:
    schema = schema_model.model_json_schema()
    return JsonSpec(
        name=name or _schema_name_for_model(schema_model),
        schema_json=json.dumps(schema),
        description=description,
    )


def _schema_name_for_model(schema_model: type[BaseModel]) -> str:
    raw_name = getattr(schema_model, "__name__", "response_schema")
    normalized = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_name).strip("_")
    return normalized or "response_schema"
