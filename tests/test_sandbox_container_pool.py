"""Tests for the warm container pool (N4).

The correctness contract: a container only re-enters the pool if it verifiably
reset to a pristine git state. The reset-hygiene and drop-on-dirty tests are
the load-bearing ones - a pool that leaked one file's edits into the next would
silently corrupt analysis.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from acuario.sandbox.container_pool import ContainerPool


@dataclass
class _Exec:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""


class FakeContainer:
    """A fake sandbox container scripted for pool reset/verify behavior.

    ``status_after_reset`` is the porcelain output the verify step sees: empty
    string = clean, non-empty = dirty (forces a drop).
    """

    _counter = 0

    def __init__(self, sha: str = "abc123", status_after_reset: str = ""):
        FakeContainer._counter += 1
        self.id = FakeContainer._counter
        self._sha = sha
        self._status_after_reset = status_after_reset
        self.stopped = False
        self.exec_calls: list[str] = []

    def exec(self, command, timeout=None, **kw):
        argv = command if isinstance(command, list) else ["sh", "-c", command]
        joined = " ".join(argv)
        self.exec_calls.append(joined)
        if "rev-parse HEAD" in joined:
            return _Exec(exit_code=0, stdout=self._sha + "\n")
        if "status --porcelain" in joined:
            return _Exec(exit_code=0, stdout=self._status_after_reset)
        return _Exec(exit_code=0, stdout="")

    def stop(self):
        self.stopped = True


@pytest.mark.asyncio
async def test_start_prewarms_containers():
    made: list[FakeContainer] = []

    def factory():
        c = FakeContainer()
        made.append(c)
        return c

    pool = ContainerPool(factory, size=3)
    live = await pool.start()
    assert live == 3
    assert pool.stats["spawned"] == 3
    # Each pristine SHA captured at warm-up.
    assert all("rev-parse HEAD" in " ".join(c.exec_calls) for c in made)


@pytest.mark.asyncio
async def test_acquire_release_roundtrip_resets_clean():
    pool = ContainerPool(lambda: FakeContainer(status_after_reset=""), size=1)
    await pool.start()
    c = await pool.acquire()
    assert c is not None
    await pool.release(c)
    # Clean reset → same container returns, not dropped.
    assert pool.stats["dropped_on_dirty_reset"] == 0
    c2 = await pool.acquire()
    assert c2 is c
    # Reset ran git reset --hard + clean + scratch wipe.
    joined = " | ".join(c.exec_calls)
    assert "reset --hard" in joined
    assert "clean -fdx" in joined
    assert "rm -rf /scratch" in joined


@pytest.mark.asyncio
async def test_dirty_reset_drops_and_replaces():
    # Container 1 fails to reset clean (porcelain shows a modified file).
    seq = [FakeContainer(status_after_reset=" M app.py"), FakeContainer(status_after_reset="")]
    it = iter(seq)
    pool = ContainerPool(lambda: next(it), size=1)
    await pool.start()
    dirty = await pool.acquire()
    await pool.release(dirty)
    # The dirty container was stopped and replaced.
    assert dirty.stopped is True
    assert pool.stats["dropped_on_dirty_reset"] == 1
    replacement = await pool.acquire()
    assert replacement is not dirty
    assert replacement.stopped is False


@pytest.mark.asyncio
async def test_no_git_baseline_is_treated_dirty():
    # A container whose workspace isn't a git tree (empty SHA) can't be proven
    # clean, so it must be dropped rather than risk leaking a writable mount.
    seq = [FakeContainer(sha=""), FakeContainer(sha="def456")]
    it = iter(seq)
    pool = ContainerPool(lambda: next(it), size=1)
    await pool.start()
    c = await pool.acquire()
    await pool.release(c)
    assert c.stopped is True
    assert pool.stats["dropped_on_dirty_reset"] == 1


@pytest.mark.asyncio
async def test_shutdown_stops_all():
    made: list[FakeContainer] = []

    def factory():
        c = FakeContainer()
        made.append(c)
        return c

    pool = ContainerPool(factory, size=3)
    await pool.start()
    await pool.shutdown()
    assert all(c.stopped for c in made)
    assert pool.stats["live"] == 0


@pytest.mark.asyncio
async def test_empty_pool_acquire_returns_none():
    # All spawns fail → start() reports 0 live → acquire returns None so the
    # caller falls back to a per-file spawn.
    def factory():
        raise RuntimeError("docker unavailable")

    pool = ContainerPool(factory, size=2)
    live = await pool.start()
    assert live == 0
    assert await pool.acquire() is None
