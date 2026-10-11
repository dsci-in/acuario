"""Shared retry helper for lab agents.

The underlying ``AsyncLLMClient`` already retries on transient network /
rate-limit errors via ``_with_rate_limit_retries`` - so any ``await
self._llm.achat(...)`` call inside a lab agent is already protected at
the LLM transport layer.

This module adds a thin **outer** retry around the per-agent runner
functions to catch:

1. Empty / malformed LLM responses that the LLM client successfully
   *received* (so it didn't retry) but that the parser couldn't extract
   a verdict / lead / plan from.  These are common with intermittent
   vLLM hiccups and recover on a second attempt.

2. Specific parse-recoverable exceptions raised by the parsing helpers
   in ``skeptic.py`` / ``critic.py`` / ``orchestrator.py``.

The retry budget is small (3 attempts) because:
  - The LLM-level retry already handled the network case.
  - These outer retries are pure waste if the LLM is genuinely returning
    garbage every time.
  - Each attempt costs one full LLM call.

Usage::

    leads = await retry_transient(
        lambda: self._run_critic(...),
        agent="critic",
        max_attempts=3,
    )
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Markers in exception text or empty-response sentinels that justify
# a retry at the outer (parse) layer.  Kept narrow to avoid masking
# real bugs in agent code.
_OUTER_RETRYABLE_MARKERS: tuple[str, ...] = (
    "no json",
    "json parse failed",
    "empty response",
    "could not parse verdict",
    "could not parse plans",
    # Mirrors the transient marker now also classified at the LLM layer.
    "can only get item pairs from a mapping",
)


def is_outer_retryable(exc: BaseException) -> bool:
    """True when the given exception text matches a retryable parse failure."""
    text = str(exc).lower()
    return any(m in text for m in _OUTER_RETRYABLE_MARKERS)


async def retry_transient(
    op: Callable[[], Awaitable[T]],
    *,
    agent: str = "lab",
    max_attempts: int = 3,
    base_delay: float = 1.0,
    is_retryable: Callable[[BaseException], bool] = is_outer_retryable,
) -> T:
    """Run ``op`` up to ``max_attempts`` times, sleeping exponentially.

    Raises the last exception if every attempt fails or if the exception
    isn't retryable.  The LLM-level retry handles network errors; this
    layer handles "we got a reply but it was garbage" cases.
    """
    attempt = 0
    while True:
        try:
            return await op()
        except Exception as exc:
            if not is_retryable(exc) or attempt + 1 >= max_attempts:
                raise
            delay = base_delay * (2**attempt)
            attempt += 1
            logger.warning(
                "[%s] parse-retryable error (attempt %d/%d), retrying in %.1fs: %s",
                agent,
                attempt,
                max_attempts,
                delay,
                str(exc)[:200],
            )
            await asyncio.sleep(delay)


class EmptyLLMResponse(RuntimeError):
    """Raised by parser helpers when the LLM returned an unusable empty / unparseable
    response that should trigger an outer retry.

    Catching agents map this to a parse-retryable exception so the outer
    ``retry_transient`` helper kicks in.
    """
