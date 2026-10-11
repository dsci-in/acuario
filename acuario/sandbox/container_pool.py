"""Warm container pool for analyzer parallelism.

Spawning a fresh Docker container per analyzed file pays a cold ``docker run``
on every one of dozens-to-hundreds of files. ``ContainerPool`` pre-spawns a
small set of containers once at audit start and lends them to the analyzer
pool, resetting each to a pristine state between files.

**Correctness over speed.** Analyzer containers in standard/deep mode mount a
*writable* copy of the source tree (the deep agent can edit/recompile), so a
reused container must be scrubbed of the previous file's edits before the next
file sees it - otherwise file B would be analyzed against file A's mutations.
The pool guarantees this by construction:

- At warm-up it records each container's pristine git SHA (the writable
  workspace is git-init'd with a full initial commit).
- On release it runs ``git reset --hard <sha> && git clean -fdx`` plus a
  ``/scratch`` wipe, then *verifies* the tree is clean.
- If the reset doesn't verify clean, the container is **dropped** (stopped)
  and a fresh one is spawned in its place. A container only ever re-enters the
  pool if it provably reset clean, so the worst case degrades to per-file
  spawn - it never leaks state between files.

Because of that hazard the pool is opt-in (``--warm-container-pool``); the
default path keeps spawning a guaranteed-fresh container per file.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class ContainerPool:
    """An asyncio-borrowable pool of pre-warmed sandbox containers."""

    def __init__(self, factory: Callable[[], Any], size: int) -> None:
        self._factory = factory
        self._size = max(1, size)
        self._queue: asyncio.Queue[Any] = asyncio.Queue()
        self._all: list[Any] = []
        self._pristine_sha: dict[int, str] = {}  # id(sandbox) -> sha ("" if not git)
        self._started = False
        self._spawned = 0
        self._dropped = 0

    @property
    def stats(self) -> dict[str, int]:
        return {
            "size": self._size,
            "spawned": self._spawned,
            "dropped_on_dirty_reset": self._dropped,
            "live": len(self._all),
        }

    async def start(self) -> int:
        """Pre-spawn the pool. Returns the number of live containers."""
        if self._started:
            return len(self._all)
        self._started = True
        results = await asyncio.gather(
            *[asyncio.to_thread(self._spawn_one) for _ in range(self._size)],
            return_exceptions=True,
        )
        for sb in results:
            if isinstance(sb, BaseException) or sb is None:
                logger.warning("[pool] warm-up spawn failed: %s", sb)
                continue
            self._all.append(sb)
            self._record_pristine(sb)
            self._queue.put_nowait(sb)
        logger.info(
            "[pool] warm container pool ready: %d/%d containers", len(self._all), self._size
        )
        return len(self._all)

    async def acquire(self) -> Any:
        """Borrow a container, blocking until one is free.

        Returns None only if the pool is empty (no container ever warmed up),
        so the caller can fall back to a per-file spawn.
        """
        if not self._all:
            return None
        return await self._queue.get()

    async def release(self, sandbox: Any) -> None:
        """Return a container after resetting it to pristine state.

        If the reset doesn't verify clean, the container is dropped and a
        fresh replacement is spawned, so a dirty container never re-enters
        circulation.
        """
        if sandbox is None:
            return
        clean = await asyncio.to_thread(self._reset, sandbox)
        if clean:
            self._queue.put_nowait(sandbox)
            return
        # Dirty reset: drop this container, spawn a replacement.
        self._dropped += 1
        logger.warning("[pool] container failed clean reset; dropping and replacing")
        try:
            await asyncio.to_thread(sandbox.stop)
        except Exception:
            logger.debug("[pool] drop-stop failed", exc_info=True)
        if sandbox in self._all:
            self._all.remove(sandbox)
        self._pristine_sha.pop(id(sandbox), None)
        replacement = await asyncio.to_thread(self._spawn_one)
        if replacement is not None:
            self._all.append(replacement)
            self._record_pristine(replacement)
            self._queue.put_nowait(replacement)

    async def shutdown(self) -> None:
        """Stop every container in the pool."""
        sandboxes = list(self._all)
        self._all.clear()
        await asyncio.gather(
            *[asyncio.to_thread(self._safe_stop, sb) for sb in sandboxes],
            return_exceptions=True,
        )
        logger.info("[pool] shut down (%s)", self.stats)

    # --- internals ----------------------------------------------------------

    def _spawn_one(self) -> Any:
        try:
            sb = self._factory()
            self._spawned += 1
            return sb
        except Exception:
            logger.debug("[pool] spawn failed", exc_info=True)
            return None

    def _record_pristine(self, sandbox: Any) -> None:
        """Capture the workspace's pristine git SHA, if it's a git tree."""
        sha = ""
        try:
            res = sandbox.exec(
                ["sh", "-c", "git -C /workspace rev-parse HEAD 2>/dev/null || true"],
                timeout=15,
            )
            sha = (getattr(res, "stdout", "") or "").strip()
        except Exception:
            logger.debug("[pool] pristine SHA capture failed", exc_info=True)
        self._pristine_sha[id(sandbox)] = sha

    def _reset(self, sandbox: Any) -> bool:
        """Scrub a container back to pristine. Return True iff verified clean.

        - Wipe /scratch unconditionally.
        - If the workspace is a git tree, hard-reset to the recorded SHA and
          remove untracked/ignored files, then verify ``git status`` is empty.
        - If the workspace is NOT a git tree, we cannot guarantee a clean
          revert of a writable mount, so report dirty (caller drops it).
        """
        try:
            sandbox.exec(
                ["sh", "-c", "rm -rf /scratch/* /scratch/.[!.]* 2>/dev/null || true"],
                timeout=30,
            )
        except Exception:
            logger.debug("[pool] scratch wipe failed", exc_info=True)
            return False

        sha = self._pristine_sha.get(id(sandbox), "")
        if not sha:
            # No git baseline → can't prove a writable workspace is clean.
            # Treat as dirty so the caller drops it (correctness over reuse).
            return False

        try:
            sandbox.exec(
                [
                    "sh",
                    "-c",
                    f"git -C /workspace reset --hard {sha} >/dev/null 2>&1 && "
                    f"git -C /workspace clean -fdx >/dev/null 2>&1",
                ],
                timeout=60,
            )
            verify = sandbox.exec(
                ["sh", "-c", "git -C /workspace status --porcelain 2>/dev/null"],
                timeout=30,
            )
            dirty = (getattr(verify, "stdout", "") or "").strip()
            return dirty == ""
        except Exception:
            logger.debug("[pool] git reset failed", exc_info=True)
            return False

    @staticmethod
    def _safe_stop(sandbox: Any) -> None:
        try:
            sandbox.stop()
        except Exception:
            logger.debug("[pool] stop failed", exc_info=True)
