"""Tests for acuario/lab/sandbox/snapshot.py - SandboxSnapshotter (Phase C1)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from acuario.lab.sandbox.snapshot import SandboxSnapshotter, SnapshotHandle

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_container(has_inner=True):
    """Return a minimal SandboxContainer-like mock."""
    container = MagicMock()
    container._container = MagicMock() if has_inner else None
    container.config = MagicMock()
    container.config.mounts = []
    container.config.network_mode = "none"
    container.config.memory_mb = 512
    container.config.cpu_shares = 1024
    container.config.env = {}
    container.config.working_dir = "/workspace"
    container.config.pids_limit = 512
    container.config.security_opt = []
    return container


# ---------------------------------------------------------------------------
# snapshot()
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_snapshot_returns_handle_on_success(self):
        container = _make_container()
        snapshotter = SandboxSnapshotter(container, session_id="test-sess")
        handle = snapshotter.snapshot("before-exploit")
        assert handle is not None
        assert isinstance(handle, SnapshotHandle)
        assert handle.label == "before-exploit"
        assert handle.session_id == "test-sess"
        assert "acuario-snap" in handle.name
        container._container.commit.assert_called_once()

    def test_snapshot_appends_to_internal_list(self):
        container = _make_container()
        snapshotter = SandboxSnapshotter(container, session_id="test-sess")
        h1 = snapshotter.snapshot("snap-1")
        h2 = snapshotter.snapshot("snap-2")
        assert len(snapshotter.snapshots) == 2
        assert snapshotter.snapshots[0] is h1
        assert snapshotter.snapshots[1] is h2

    def test_snapshot_returns_none_when_no_container(self):
        container = _make_container(has_inner=False)
        snapshotter = SandboxSnapshotter(container, session_id="test-sess")
        handle = snapshotter.snapshot("no-container")
        assert handle is None
        assert len(snapshotter.snapshots) == 0

    def test_snapshot_returns_none_on_docker_error(self):
        container = _make_container()
        container._container.commit.side_effect = RuntimeError("docker daemon error")
        snapshotter = SandboxSnapshotter(container, session_id="test-sess")
        handle = snapshotter.snapshot("fail")
        assert handle is None
        assert len(snapshotter.snapshots) == 0

    def test_snapshot_image_ref_format(self):
        container = _make_container()
        snapshotter = SandboxSnapshotter(container, session_id="abc123")
        handle = snapshotter.snapshot()
        assert handle is not None
        assert handle.image_ref == f"{handle.name}:{handle.tag}"
        assert handle.name.startswith("acuario-snap-abc123")


# ---------------------------------------------------------------------------
# revert_to()
# ---------------------------------------------------------------------------


class TestRevertTo:
    def test_revert_to_starts_new_container_from_snapshot(self):
        container = _make_container()
        handle = SnapshotHandle(
            name="acuario-snap-sess",
            tag="abc123",
            session_id="sess",
            label="pre-exploit",
        )
        mock_new_container = MagicMock()

        with patch("docker.from_env") as mock_from_env:
            mock_client = MagicMock()
            mock_from_env.return_value = mock_client
            mock_client.containers.run.return_value = mock_new_container

            snapshotter = SandboxSnapshotter(container, session_id="sess")
            result = snapshotter.revert_to(handle)

        assert result is True
        mock_client.containers.run.assert_called_once()
        # The container's _container attribute should be updated
        assert container._container is mock_new_container

    def test_revert_to_returns_false_on_docker_error(self):
        container = _make_container()
        handle = SnapshotHandle(
            name="acuario-snap-sess",
            tag="abc",
            session_id="sess",
            label="",
        )
        with patch("docker.from_env") as mock_from_env:
            mock_from_env.side_effect = Exception("daemon unavailable")
            snapshotter = SandboxSnapshotter(container, session_id="sess")
            result = snapshotter.revert_to(handle)

        assert result is False


# ---------------------------------------------------------------------------
# cleanup_snapshots()
# ---------------------------------------------------------------------------


class TestCleanupSnapshots:
    def test_cleanup_removes_all_snapshot_images(self):
        container = _make_container()
        snapshotter = SandboxSnapshotter(container, session_id="clean-sess")
        # Manually populate snapshot list
        h1 = SnapshotHandle("acuario-snap-x", "tag1", "clean-sess", "s1")
        h2 = SnapshotHandle("acuario-snap-x", "tag2", "clean-sess", "s2")
        snapshotter._snapshots.extend([h1, h2])

        with patch("docker.from_env") as mock_from_env:
            mock_client = MagicMock()
            mock_from_env.return_value = mock_client
            deleted = snapshotter.cleanup_snapshots()

        assert deleted == 2
        assert mock_client.images.remove.call_count == 2
        assert len(snapshotter.snapshots) == 0

    def test_cleanup_returns_zero_when_no_snapshots(self):
        container = _make_container()
        snapshotter = SandboxSnapshotter(container, session_id="empty")
        result = snapshotter.cleanup_snapshots()
        assert result == 0

    def test_cleanup_tolerates_partial_docker_failure(self):
        container = _make_container()
        snapshotter = SandboxSnapshotter(container, session_id="partial")
        h1 = SnapshotHandle("acuario-snap-p", "tag1", "partial", "s1")
        h2 = SnapshotHandle("acuario-snap-p", "tag2", "partial", "s2")
        snapshotter._snapshots.extend([h1, h2])

        with patch("docker.from_env") as mock_from_env:
            mock_client = MagicMock()
            mock_from_env.return_value = mock_client
            # First image removal fails, second succeeds
            mock_client.images.remove.side_effect = [Exception("not found"), None]
            deleted = snapshotter.cleanup_snapshots()

        # Only the successful one counted
        assert deleted == 1


# ---------------------------------------------------------------------------
# N6: orphan snapshot pruning
# ---------------------------------------------------------------------------


class TestPruneOrphanSnapshots:
    def _img(self, tags, created):
        m = MagicMock()
        m.tags = tags
        m.attrs = {"Created": created}
        return m

    def test_prunes_only_acuario_snapshots(self):
        from acuario.lab.sandbox.snapshot import prune_orphan_snapshots

        old = "2020-01-01T00:00:00.000000000Z"  # ancient → eligible
        with patch("docker.from_env") as mock_from_env:
            client = MagicMock()
            client.images.list.return_value = [
                self._img(["acuario-snap-sess1:abc"], old),
                self._img(["acuario-snap-sess2:def"], old),
                self._img(["python:3.12-slim"], old),  # must NOT be touched
                self._img([], old),  # untagged → ignored
            ]
            mock_from_env.return_value = client
            removed = prune_orphan_snapshots(older_than_hours=2.0)

        assert removed == 2
        removed_tags = {c.args[0] for c in client.images.remove.call_args_list}
        assert removed_tags == {"acuario-snap-sess1:abc", "acuario-snap-sess2:def"}
        assert "python:3.12-slim" not in removed_tags

    def test_age_guard_skips_fresh_snapshots(self):
        import datetime as dt

        from acuario.lab.sandbox.snapshot import prune_orphan_snapshots

        fresh = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
        with patch("docker.from_env") as mock_from_env:
            client = MagicMock()
            client.images.list.return_value = [self._img(["acuario-snap-live:xyz"], fresh)]
            mock_from_env.return_value = client
            removed = prune_orphan_snapshots(older_than_hours=2.0)

        # A snapshot created seconds ago could belong to a concurrent audit.
        assert removed == 0
        client.images.remove.assert_not_called()

    def test_zero_age_prunes_regardless_of_freshness(self):
        import datetime as dt

        from acuario.lab.sandbox.snapshot import prune_orphan_snapshots

        fresh = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
        with patch("docker.from_env") as mock_from_env:
            client = MagicMock()
            client.images.list.return_value = [self._img(["acuario-snap-x:1"], fresh)]
            mock_from_env.return_value = client
            removed = prune_orphan_snapshots(older_than_hours=0.0)

        assert removed == 1

    def test_docker_unavailable_returns_zero(self):
        from acuario.lab.sandbox.snapshot import prune_orphan_snapshots

        with patch("docker.from_env", side_effect=RuntimeError("no daemon")):
            assert prune_orphan_snapshots() == 0

    def test_naive_created_timestamp_does_not_raise(self):
        # Review fix: a Docker 'Created' value without a timezone offset must
        # parse to an aware datetime, else the age comparison raises TypeError
        # (and the whole prune is silently skipped by the outer except).
        from acuario.lab.sandbox.snapshot import _parse_docker_created

        parsed = _parse_docker_created({"Created": "2020-01-01T00:00:00.000000000"})
        assert parsed is not None
        assert parsed.tzinfo is not None  # coerced to UTC, comparison-safe

    def test_naive_timestamp_image_still_prunable(self):
        from acuario.lab.sandbox.snapshot import prune_orphan_snapshots

        old_naive = "2020-01-01T00:00:00.000000000"  # no offset → was a TypeError
        with patch("docker.from_env") as mock_from_env:
            client = MagicMock()
            img = MagicMock()
            img.tags = ["acuario-snap-sess:abc"]
            img.attrs = {"Created": old_naive}
            client.images.list.return_value = [img]
            mock_from_env.return_value = client
            removed = prune_orphan_snapshots(older_than_hours=2.0)
        assert removed == 1


# ---------------------------------------------------------------------------
# exploit_dev integration - snapshot/rollback hooks
# ---------------------------------------------------------------------------


class TestExploitDevSnapshotHooks:
    """Verify snapshot wiring in AgenticExploiter.aattempt().

    We mock the SandboxSnapshotter so no real Docker calls happen.
    """

    @pytest.mark.asyncio
    async def test_snapshot_taken_before_exploit_and_cleaned_up(self):
        """aattempt() should create a snapshotter, take a snapshot, and
        call cleanup_snapshots() in the finally block."""
        from unittest.mock import AsyncMock
        from unittest.mock import patch as _patch

        from acuario.scanner.exploit_dev import AgenticExploiter

        finding = {
            "id": "test-finding-snap",
            "cwe": "CWE-79",
            "file": "app.py",
            "line_number": 10,
            "evidence_level": "crash_reproduced",
            "verified": True,
            "severity": "high",
            "description": "XSS",
        }

        mock_sandbox = MagicMock()
        mock_sandbox.stop = MagicMock()

        mock_snap_handle = MagicMock()
        mock_snapshotter = MagicMock()
        mock_snapshotter.snapshot.return_value = mock_snap_handle
        mock_snapshotter.cleanup_snapshots.return_value = 1

        mock_run_result = MagicMock()
        mock_run_result.stop_reason = "budget_exhausted"
        mock_run_result.cost_usd = 0.01

        mock_llm = MagicMock()
        mock_sandbox_manager = MagicMock()
        mock_sandbox_manager.spawn.return_value = mock_sandbox

        agentic = AgenticExploiter(
            llm=mock_llm,
            sandbox_manager=mock_sandbox_manager,
            budget_band="standard",
            output_dir="",
            project_name="test",
        )

        with (
            _patch(
                "acuario.lab.sandbox.snapshot.SandboxSnapshotter",
                return_value=mock_snapshotter,
            ),
            _patch(
                "acuario.agent.tools.hunt.exploit_tools.build_exploit_agent_tools",
                return_value=[],
            ),
            _patch(
                "acuario.scanner.analyzer.NativeHunter",
            ) as mock_hunter_cls,
            _patch(
                "acuario.agent.tools.hunt.sandbox.HunterContext",
            ) as mock_ctx_cls,
        ):
            mock_hunter = MagicMock()
            mock_hunter.arun = AsyncMock(return_value=mock_run_result)
            mock_hunter_cls.return_value = mock_hunter

            mock_ctx = MagicMock()
            mock_ctx.exploit_result = None
            mock_ctx_cls.return_value = mock_ctx

            result = await agentic.aattempt(finding)

        # Snapshot should have been taken before the attempt
        mock_snapshotter.snapshot.assert_called_once_with("pre-exploit")
        # Cleanup should always happen (in finally)
        mock_snapshotter.cleanup_snapshots.assert_called_once()
        assert result.attempted is True
