"""Adaptive concurrency limiter - AIMD over a dynamic permit count.

The per-client request cap is otherwise a static knob; this limiter makes it
*self-tuning*: it watches every call's outcome and adjusts how many requests it lets
run concurrently, using additive-increase / multiplicative-decrease (the same
control law TCP congestion control uses):

  - a clean streak of successes nudges the limit UP by 1 (additive increase),
    probing for spare server capacity;
  - any rate-limit / overload / transient-server signal halves the limit
    (multiplicative decrease), backing off fast when the endpoint strains.

The limit is clamped to ``[min_limit, max_limit]``.

Why not just resize an ``asyncio.Semaphore``: it has no public resize. This
limiter instead gates on a live ``_in_flight`` counter guarded by an
``asyncio.Condition`` - admission waits while ``_in_flight >= _limit``, and
*lowering* the limit simply means in-flight calls must drain before new ones
start. Correct under asyncio's single-threaded scheduling: the counter and
limit are only mutated inside the condition's lock.

Opt-in via ``ACUARIO_ADAPTIVE_CONCURRENCY=1``; the default path keeps the
static semaphore so the proven behavior is unchanged unless asked for.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


class AdaptiveConcurrencyLimiter:
    """A resizable concurrency gate driven by call outcomes (AIMD)."""

    def __init__(
        self,
        initial: int,
        *,
        min_limit: int = 1,
        max_limit: int = 32,
        increase_after_successes: int = 10,
    ) -> None:
        self._min = max(1, min_limit)
        self._max = max(self._min, max_limit)
        self._limit = max(self._min, min(initial, self._max))
        self._in_flight = 0
        self._cond = asyncio.Condition()
        # AIMD signal accumulators (reset each adjustment).
        self._consecutive_ok = 0
        self._increase_after = max(1, increase_after_successes)
        # Telemetry (read-only snapshot via stats()).
        self._increases = 0
        self._decreases = 0

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def stats(self) -> dict[str, int]:
        return {
            "limit": self._limit,
            "in_flight": self._in_flight,
            "increases": self._increases,
            "decreases": self._decreases,
            "min": self._min,
            "max": self._max,
        }

    async def acquire(self) -> None:
        """Block until a permit is free under the current (possibly lowered) limit."""
        async with self._cond:
            await self._cond.wait_for(lambda: self._in_flight < self._limit)
            self._in_flight += 1

    async def release(self) -> None:
        async with self._cond:
            if self._in_flight > 0:
                self._in_flight -= 1
            # A release may let exactly one more waiter through; if the limit
            # was just raised, notify enough waiters to fill the new headroom.
            self._cond.notify(max(1, self._limit - self._in_flight))

    async def __aenter__(self) -> AdaptiveConcurrencyLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.release()

    async def record_outcome(self, *, success: bool, backed_off: bool) -> None:
        """Feed one call's result into the AIMD controller and adjust the limit.

        ``backed_off`` means the call hit a rate-limit / overload / transient
        server signal - the strongest reason to shed concurrency.
        """
        async with self._cond:
            old = self._limit
            if backed_off:
                # Multiplicative decrease - back off hard.
                self._limit = max(self._min, self._limit // 2)
                self._consecutive_ok = 0
                if self._limit < old:
                    self._decreases += 1
            elif success:
                self._consecutive_ok += 1
                if self._consecutive_ok >= self._increase_after:
                    # Additive increase - probe for spare capacity.
                    self._limit = min(self._max, self._limit + 1)
                    self._consecutive_ok = 0
                    if self._limit > old:
                        self._increases += 1
            else:
                # A non-backoff failure (e.g. a parse error): neutral - reset
                # the success streak but don't change the limit.
                self._consecutive_ok = 0
            if self._limit != old:
                logger.debug(
                    "[concurrency] limit %d -> %d (in_flight=%d)",
                    old,
                    self._limit,
                    self._in_flight,
                )
                # Raising the limit may unblock waiters.
                if self._limit > old:
                    self._cond.notify(self._limit - old)
