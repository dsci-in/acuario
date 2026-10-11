"""Sandbox snapshot/rollback for exploit hypothesis branching.

Wraps ``acuario/sandbox/container.py::SandboxContainer`` to add Docker-commit-
based checkpoint and rollback capability.  Instead of tearing down and
rebuilding a container from scratch on every hypothesis failure, agents can:

  1. ``snapshot("before-exploit")`` - commit current container state to an
     intermediate image.
  2. Attempt the exploit.
  3. On failure: ``revert_to(handle)`` - stop current container, spawn a new
     one from the snapshot image.  The new container has the same mounts/env
     but the filesystem is back to the pre-exploit state.
  4. Try a different exploit variant without paying the sandbox setup cost.

Under the hood the snapshotter uses ``docker container.commit()`` which
creates an intermediate image.  On audit end, ``cleanup_snapshots()`` removes
all intermediate images created during this session.

Wire-in point: ``acuario/scanner/exploit_dev.py::ExploitDeveloper.aattempt()``
- snapshot before each exploit attempt, revert on failure.

Toggle: ``--sandbox-snapshots`` (default: on if Docker supports commit).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SnapshotHandle:
    """Reference to a committed container snapshot."""

    name: str  # Docker image name for this snapshot
    tag: str  # Docker image tag
    session_id: str
    label: str = ""  # human-readable label supplied by the caller

    @property
    def image_ref(self) -> str:
        return f"{self.name}:{self.tag}"


class SandboxSnapshotter:
    """Checkpoint/rollback wrapper around SandboxContainer.

    Parameters
    ----------
    container : SandboxContainer
        The primary sandbox container to wrap.
    session_id : str
        Used as the namespace prefix for snapshot image names.
    """

    _IMAGE_PREFIX = "acuario-snap"

    def __init__(self, container: Any, session_id: str = "") -> None:
        self._container = container
        self._session_id = session_id or uuid.uuid4().hex[:8]
        self._snapshots: list[SnapshotHandle] = []

    @property
    def snapshots(self) -> list[SnapshotHandle]:
        return list(self._snapshots)

    def snapshot(self, label: str = "") -> SnapshotHandle | None:
        """Commit current container state to an intermediate Docker image.

        Returns a SnapshotHandle on success, None if Docker commit fails
        (e.g., older daemon, non-fatal).
        """
        tag = uuid.uuid4().hex[:12]
        name = f"{self._IMAGE_PREFIX}-{self._session_id}"
        try:
            raw = self._container._container
            if raw is None:
                logger.debug("[lab/sandbox] snapshot: no container running")
                return None
            # docker-py: container.commit(repository, tag)
            raw.commit(repository=name, tag=tag)
            handle = SnapshotHandle(
                name=name,
                tag=tag,
                session_id=self._session_id,
                label=label,
            )
            self._snapshots.append(handle)
            logger.info(
                "[lab/sandbox] ◇ snapshot '%s' → %s",
                label or "unnamed",
                handle.image_ref,
            )
            return handle
        except Exception:
            logger.debug("[lab/sandbox] snapshot failed (non-fatal)", exc_info=True)
            return None

    def revert_to(self, handle: SnapshotHandle) -> bool:
        """Revert the sandbox to a previously snapshotted state.

        Stops the current container and starts a new one from the snapshot
        image, preserving the original mounts/env/config.

        Returns True on success, False on failure (caller keeps current state).
        """
        try:
            import docker  # type: ignore[import]

            client = docker.from_env()
            config = self._container.config

            # Stop the current container
            raw = self._container._container
            if raw is not None:
                try:
                    raw.stop(timeout=5)
                    raw.remove(force=True)
                except Exception:
                    pass

            # Translate mounts
            volumes: dict = {}
            for host_path, container_path, mode in config.mounts:
                volumes[host_path] = {"bind": container_path, "mode": mode}

            kwargs = {
                "image": handle.image_ref,
                "command": "sleep infinity",
                "detach": True,
                "network_mode": config.network_mode,
                "mem_limit": f"{config.memory_mb}m",
                "cpu_shares": config.cpu_shares,
                "volumes": volumes,
                "environment": config.env,
                "working_dir": config.working_dir,
                "pids_limit": config.pids_limit,
            }
            if config.security_opt:
                kwargs["security_opt"] = config.security_opt

            new_container = client.containers.run(**kwargs)
            self._container._container = new_container
            self._container._client = client

            logger.info(
                "[lab/sandbox] ◇ rollback to snapshot '%s' (%s)",
                handle.label or "unnamed",
                handle.image_ref,
            )
            return True
        except Exception:
            logger.debug("[lab/sandbox] revert_to failed (non-fatal)", exc_info=True)
            return False

    def cleanup_snapshots(self) -> int:
        """Delete all intermediate snapshot images created in this session.

        Returns the number of images successfully deleted.
        """
        if not self._snapshots:
            return 0
        deleted = 0
        try:
            import docker  # type: ignore[import]

            client = docker.from_env()
        except Exception:
            return 0

        for handle in self._snapshots:
            try:
                client.images.remove(handle.image_ref, force=True)
                deleted += 1
                logger.debug("[lab/sandbox] removed snapshot image %s", handle.image_ref)
            except Exception:
                logger.debug("[lab/sandbox] failed to remove %s", handle.image_ref, exc_info=True)
        self._snapshots.clear()
        logger.info("[lab/sandbox] cleaned up %d snapshot image(s)", deleted)
        return deleted


def prune_orphan_snapshots(older_than_hours: float = 2.0) -> int:
    """Remove leaked ``acuario-snap-*`` images from crashed prior runs.

    ``cleanup_snapshots()`` clears a session's own snapshots in the exploit-dev
    finally block, but a hard crash (or a kill mid-attempt) can leave
    intermediate images orphaned - Docker never garbage-collects them. Called
    best-effort at audit start to keep the image store from growing unbounded.

    ``older_than_hours`` guards against deleting a *concurrent* audit's live
    snapshots: only images created more than that many hours ago are removed
    (set to 0 to prune all acuario snapshots regardless of age). Returns the
    number of images removed.
    """
    import datetime as _dt

    removed = 0
    try:
        import docker  # type: ignore[import]

        client = docker.from_env()
    except Exception:
        logger.debug("[lab/sandbox] prune: docker unavailable", exc_info=True)
        return 0

    cutoff = None
    if older_than_hours > 0:
        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=older_than_hours)

    try:
        images = client.images.list()
    except Exception:
        logger.debug("[lab/sandbox] prune: image list failed", exc_info=True)
        return 0

    for img in images:
        tags = list(getattr(img, "tags", []) or [])
        if not any(t.startswith(SandboxSnapshotter._IMAGE_PREFIX) for t in tags):
            continue
        if cutoff is not None:
            created = _parse_docker_created(getattr(img, "attrs", {}) or {})
            if created is not None and created > cutoff:
                continue  # too fresh - could belong to a running audit
        for tag in tags:
            try:
                client.images.remove(tag, force=True)
                removed += 1
            except Exception:
                logger.debug("[lab/sandbox] prune: failed to remove %s", tag, exc_info=True)
    if removed:
        logger.info("[lab/sandbox] pruned %d orphaned snapshot image(s)", removed)
    return removed


def _parse_docker_created(attrs: dict) -> object | None:
    """Best-effort parse of a docker image's Created timestamp to aware UTC."""
    import datetime as _dt

    raw = attrs.get("Created")
    if not isinstance(raw, str):
        return None
    try:
        # Docker emits RFC3339 with nanoseconds; trim to microseconds + Z.
        cleaned = raw.replace("Z", "+00:00")
        # Drop sub-microsecond precision Python's fromisoformat can't take.
        if "." in cleaned:
            head, _, tail = cleaned.partition(".")
            frac = tail
            tz = ""
            for marker in ("+", "-"):
                if marker in frac:
                    frac, _, tz = frac.partition(marker)
                    tz = marker + tz
                    break
            cleaned = f"{head}.{frac[:6]}{tz}"
        parsed = _dt.datetime.fromisoformat(cleaned)
        # Always return an aware datetime: comparing a naive value against the
        # aware ``cutoff`` in prune_orphan_snapshots raises TypeError. Docker
        # timestamps without an explicit offset are UTC by convention.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed
    except Exception:
        return None
