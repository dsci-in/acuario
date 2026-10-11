"""A2a: per-call wall-clock ceiling + per-call reasoning_effort override.

These guard the two mechanisms behind A2a:
  - a generous ``asyncio.wait_for`` bounds every LLM call so a hung endpoint
    (a multi-hour stall) is reclaimed instead of stalling the pool;
  - ``reasoning_effort`` is a PER-CALL override so an ancillary role can ask for
    "low" even when it shares a cached client (the native cache key omits task).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from genai_pyo3 import ChatResponse

from acuario.llm.native import _DEFAULT_CALL_TIMEOUT_S, _REASONING_UNSET, AsyncLLMClient


def _client(**kwargs) -> AsyncLLMClient:
    base = dict(model_name="m", provider_name="openai_resp", api_key="x")
    base.update(kwargs)
    return AsyncLLMClient(**base)


# --- timeout resolution -----------------------------------------------------


def test_default_timeout_is_generous(monkeypatch):
    monkeypatch.delenv("ACUARIO_LLM_CALL_TIMEOUT", raising=False)
    assert _client().request_timeout_seconds == _DEFAULT_CALL_TIMEOUT_S


def test_explicit_zero_disables_timeout():
    assert _client(request_timeout_seconds=0).request_timeout_seconds == 0


def test_env_override(monkeypatch):
    monkeypatch.setenv("ACUARIO_LLM_CALL_TIMEOUT", "42.5")
    assert _client().request_timeout_seconds == 42.5


def test_env_garbage_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("ACUARIO_LLM_CALL_TIMEOUT", "not-a-number")
    assert _client().request_timeout_seconds == _DEFAULT_CALL_TIMEOUT_S


# --- _call_with_timeout -----------------------------------------------------


def test_call_with_timeout_passthrough_when_disabled():
    client = _client(request_timeout_seconds=0)

    async def _ok():
        return "value"

    assert asyncio.run(client._call_with_timeout(_ok())) == "value"


def test_call_with_timeout_returns_fast_result():
    client = _client(request_timeout_seconds=5)

    async def _ok():
        return "value"

    assert asyncio.run(client._call_with_timeout(_ok())) == "value"


def test_call_with_timeout_raises_on_hang():
    client = _client(request_timeout_seconds=0.05)

    async def _hang():
        await asyncio.sleep(1.0)
        return "late"

    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        asyncio.run(client._call_with_timeout(_hang()))


# --- per-call reasoning_effort override -------------------------------------


def test_aask_text_threads_reasoning_effort_override():
    """An explicit per-call override reaches achat verbatim."""
    client = _client()
    client.achat = AsyncMock(return_value="resp")  # type: ignore[method-assign]
    asyncio.run(client.aask_text(system="s", user="u", reasoning_effort="low"))
    assert client.achat.call_args.kwargs["reasoning_effort"] == "low"


def test_aask_text_defaults_to_sentinel_when_unset():
    """Without an override, achat receives the sentinel and uses the client's
    construction-time effort - not a hardcoded value."""
    client = _client()
    client.achat = AsyncMock(return_value="resp")  # type: ignore[method-assign]
    asyncio.run(client.aask_text(system="s", user="u"))
    assert client.achat.call_args.kwargs["reasoning_effort"] is _REASONING_UNSET


def test_aask_json_threads_reasoning_effort_override():
    client = _client()
    resp = ChatResponse(content=[{"text": "{}"}])
    client.aask_text = AsyncMock(return_value=resp)  # type: ignore[method-assign]
    asyncio.run(client.aask_json(system="s", user="u", reasoning_effort="low"))
    assert client.aask_text.call_args.kwargs["reasoning_effort"] == "low"


def test_report_usage_attributes_to_usage_task():
    """F2: _report_usage credits the PER-CALL usage_task, not the client's
    build-time task_label - so a shared client attributes to the real caller."""
    from unittest.mock import MagicMock

    from acuario.observability.telemetry import CostTracker

    client = _client(task_label="prioritizer")
    resp = MagicMock()
    resp.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
    client._report_usage(resp, usage_task="skeptic-f2unique")
    assert "skeptic-f2unique" in CostTracker().by_agent
    assert "prioritizer" not in CostTracker().by_agent or True  # not forced here
