"""Tests for the AIMD adaptive concurrency limiter (P3).

The limiter is the riskiest concurrency primitive added this cycle, so it's
tested in isolation (no LLM): we verify the control law (additive increase on
success streaks, multiplicative decrease on backoff, clamps) and - the
load-bearing safety property - that concurrent acquirers never exceed the
current limit, even while the limit changes underneath them.
"""

from __future__ import annotations

import asyncio

import pytest

from acuario.llm.adaptive_concurrency import AdaptiveConcurrencyLimiter


class TestAIMDControlLaw:
    @pytest.mark.asyncio
    async def test_additive_increase_after_success_streak(self):
        lim = AdaptiveConcurrencyLimiter(initial=4, max_limit=8, increase_after_successes=3)
        assert lim.limit == 4
        for _ in range(3):
            await lim.record_outcome(success=True, backed_off=False)
        assert lim.limit == 5  # +1 after the streak

    @pytest.mark.asyncio
    async def test_multiplicative_decrease_on_backoff(self):
        lim = AdaptiveConcurrencyLimiter(initial=16, min_limit=1, max_limit=32)
        await lim.record_outcome(success=False, backed_off=True)
        assert lim.limit == 8  # halved

    @pytest.mark.asyncio
    async def test_backoff_resets_success_streak(self):
        lim = AdaptiveConcurrencyLimiter(initial=4, max_limit=8, increase_after_successes=3)
        await lim.record_outcome(success=True, backed_off=False)
        await lim.record_outcome(success=True, backed_off=False)
        await lim.record_outcome(success=False, backed_off=True)  # resets streak, halves
        assert lim.limit == 2
        # Two more successes must NOT trigger an increase (streak was reset).
        await lim.record_outcome(success=True, backed_off=False)
        await lim.record_outcome(success=True, backed_off=False)
        assert lim.limit == 2

    @pytest.mark.asyncio
    async def test_clamped_to_min_and_max(self):
        lim = AdaptiveConcurrencyLimiter(
            initial=2, min_limit=2, max_limit=3, increase_after_successes=1
        )
        # Decrease can't go below min.
        await lim.record_outcome(success=False, backed_off=True)
        assert lim.limit == 2
        # Increase can't exceed max.
        await lim.record_outcome(success=True, backed_off=False)
        await lim.record_outcome(success=True, backed_off=False)
        await lim.record_outcome(success=True, backed_off=False)
        assert lim.limit == 3

    @pytest.mark.asyncio
    async def test_non_backoff_failure_is_neutral(self):
        lim = AdaptiveConcurrencyLimiter(initial=5, max_limit=8)
        await lim.record_outcome(success=False, backed_off=False)
        assert lim.limit == 5  # unchanged


class TestConcurrencySafety:
    @pytest.mark.asyncio
    async def test_never_exceeds_limit(self):
        lim = AdaptiveConcurrencyLimiter(initial=3, min_limit=1, max_limit=3)
        peak = 0
        active = 0
        lk = asyncio.Lock()

        async def worker():
            nonlocal peak, active
            async with lim:
                async with lk:
                    active += 1
                    peak = max(peak, active)
                await asyncio.sleep(0.01)
                async with lk:
                    active -= 1

        await asyncio.gather(*[worker() for _ in range(20)])
        assert peak <= 3
        assert lim.in_flight == 0  # all released

    @pytest.mark.asyncio
    async def test_lowering_limit_holds_new_acquirers(self):
        lim = AdaptiveConcurrencyLimiter(initial=4, min_limit=1, max_limit=4)
        # Fill 4 permits.
        for _ in range(4):
            await lim.acquire()
        assert lim.in_flight == 4
        # Lower the limit to 2 via backoff signals.
        await lim.record_outcome(success=False, backed_off=True)  # 4 -> 2
        assert lim.limit == 2
        # A new acquire must block (in_flight 4 >= limit 2) until releases drain.
        acq = asyncio.create_task(lim.acquire())
        await asyncio.sleep(0.01)
        assert not acq.done()  # still blocked
        await lim.release()  # 3
        await asyncio.sleep(0.01)
        assert not acq.done()  # still >= limit
        await lim.release()  # 2
        await asyncio.sleep(0.01)
        # in_flight is now 2 == limit; still no headroom, stays blocked.
        assert not acq.done()
        await lim.release()  # 1 < 2 → headroom
        await asyncio.sleep(0.01)
        assert acq.done()
        await acq  # the pending acquire completed
        await lim.release()


def test_stats_snapshot():
    lim = AdaptiveConcurrencyLimiter(initial=8, min_limit=2, max_limit=16)
    s = lim.stats()
    assert s["limit"] == 8 and s["min"] == 2 and s["max"] == 16
    assert s["in_flight"] == 0
