"""P2: incremental per-file checkpoint hook (HuntPoolConfig.on_file_complete).

The pool must call on_file_complete with each file's findings AS the file
finishes - not batched at end-of-pool - so a mid-pool crash leaves the done
files recoverable. These tests use the same stub hunter_factory as the budget
tests (no LLM / no sandbox).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_scanner_pool_budget import _ft, _stub_hunter_factory

from acuario.scanner.pool import HunterPool, HuntPoolConfig, TierBudget


def _make_pool_with_hook(files, hook, per_call_cost=0.1):
    config = HuntPoolConfig(
        files=files,
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(per_call_cost),
        max_parallel=4,
        budget_usd=100.0,
        tier_budget=TierBudget(0.7, 0.25, 0.05),
        cost_limit_per_file_a=10.0,
        cost_limit_per_file_b=10.0,
        cost_limit_per_file_c=10.0,
        starting_band="deep",
        max_band="deep",
        redundancy_override=1,
        on_file_complete=hook,
    )
    return HunterPool(config)


@pytest.mark.asyncio
async def test_on_file_complete_called_per_file_with_its_findings():
    captured: list[list] = []

    def hook(file_findings):
        captured.append(file_findings)

    files = [_ft("a.c", 4, 2), _ft("b.c", 4, 2), _ft("c.c", 4, 2)]
    pool = _make_pool_with_hook(files, hook)
    await pool.arun()

    # One callback per completed file, each carrying that file's findings.
    assert len(captured) == 3
    seen_files = {f[0]["file"] for f in captured if f}
    assert seen_files == {"a.c", "b.c", "c.c"}
    # Each callback got exactly its own file's finding (incremental, not batched).
    for batch in captured:
        assert len(batch) == 1


@pytest.mark.asyncio
async def test_on_file_complete_hook_failure_does_not_abort_pool():
    def exploding_hook(file_findings):
        raise RuntimeError("DB down")

    files = [_ft("a.c", 4, 2), _ft("b.c", 4, 2)]
    pool = _make_pool_with_hook(files, exploding_hook)
    # The pool must complete despite the checkpoint hook raising every time.
    findings = await pool.arun()
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_critic_runs_once_at_terminal_band_not_per_band():
    """A4/O-K: the reflective critic must run ONCE per file - at the terminal
    band the file actually reaches - not on every completed band. A file with a
    finding promotes fast->standard, so the critic must fire exactly once (at
    standard), where before A4 it fired at both bands (2x)."""
    critic = MagicMock()
    critic.areflect = AsyncMock(return_value=[])
    fp = MagicMock()
    fp.add = AsyncMock()
    fp.all_findings = MagicMock(return_value=[])

    config = HuntPoolConfig(
        files=[_ft("a.c", 4, 2)],
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(0.1),  # returns 1 finding -> promotes
        max_parallel=1,
        budget_usd=100.0,
        tier_budget=TierBudget(0.7, 0.25, 0.05),
        cost_limit_per_file_a=10.0,
        cost_limit_per_file_b=10.0,
        cost_limit_per_file_c=10.0,
        starting_band="fast",
        max_band="standard",
        redundancy_override=1,
        critic_agent=critic,
        findings_pool=fp,
    )
    pool = HunterPool(config)
    # Isolate the A4 gating logic from file I/O the critic block does up front.
    pool._read_source_for_critic = lambda *a, **k: ""  # type: ignore[method-assign]
    pool._build_cross_file_context = lambda *a, **k: {}  # type: ignore[method-assign]

    await pool.arun()

    assert critic.areflect.call_count == 1


@pytest.mark.asyncio
async def test_no_hook_is_fine():
    files = [_ft("a.c", 4, 2)]
    config = HuntPoolConfig(
        files=files,
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(0.1),
        budget_usd=10.0,
        starting_band="deep",
        max_band="deep",
        redundancy_override=1,
        on_file_complete=None,
    )
    pool = HunterPool(config)
    findings = await pool.arun()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_progress_counts_distinct_files_not_work_items():
    """H3: a file re-hunted across bands / redundancy counts ONCE in progress -
    _completed_files never exceeds the distinct input file count (was the O-M
    '18/16 files' inflation from counting work-items)."""
    files = [_ft("a.c", 4, 2), _ft("b.c", 4, 2)]
    config = HuntPoolConfig(
        files=files,
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(0.1),  # 1 finding each -> promotes
        max_parallel=1,
        budget_usd=100.0,
        tier_budget=TierBudget(0.7, 0.25, 0.05),
        cost_limit_per_file_a=10.0,
        cost_limit_per_file_b=10.0,
        cost_limit_per_file_c=10.0,
        starting_band="fast",
        max_band="standard",  # promotes fast->standard: 2 work-items per file
        redundancy_override=1,
    )
    pool = HunterPool(config)
    await pool.arun()
    assert pool._completed_files == {"a.c", "b.c"}
    assert len(pool._completed_files) == len(files)


# --- A1: detached lab + phase-end join barrier (no finding lost) --------------


def _as_finding(d):
    """Build a real Finding object from a stub-hunter dict - findings_pool.add()
    requires Finding objects (production analyzers emit them; the shared stub
    hunter emits plain dicts)."""
    from acuario.findings.types import Finding as _F

    return _F(
        id=d.get("id", ""),
        file=d.get("file"),
        line_number=d.get("line_number"),
        cwe=d.get("cwe", ""),
        finding_type=d.get("finding_type", ""),
        description=d.get("description", ""),
        severity=d.get("severity", "low"),
        evidence_level=d.get("evidence_level", "suspicion"),
        discovered_by="analyzer",
    )


@pytest.mark.asyncio
async def test_lab_findings_survive_detached_join():
    """A1: skeptic-admitted AND critic-lead findings, produced by SLOW detached
    lab tasks, must all be in the pool before arun() returns. A real FindingsPool
    + 0.05s stubs make the race real: without the phase-end join barrier, arun()
    returns before the detached adds land and these assertions fail."""
    from types import SimpleNamespace

    from acuario.lab.agents.critic import CriticLead
    from acuario.scanner.findings_pool import FindingsPool

    class SlowSkeptic:
        async def ascreen_batch(self, findings, cross_file_contexts=None):
            await asyncio.sleep(0.05)
            # Return Finding OBJECTS as the real analyzer/skeptic would.
            return [_as_finding(f) for f in findings], [
                SimpleNamespace(verdict="accepted") for _ in findings
            ]

    class SlowCritic:
        def __init__(self):
            self.calls = 0

        async def areflect(
            self,
            *,
            file_path,
            existing_findings,
            trajectory_summary="",
            source_snippet="",
            cross_file_context="",
        ):
            self.calls += 1
            await asyncio.sleep(0.05)
            return [
                CriticLead(
                    file="lead.c",
                    line_number=999,
                    cwe="CWE-125",
                    finding_type="oob_read",
                    description="slow critic lead",
                )
            ]

    fp = FindingsPool()  # REAL pool - all_findings() truly reflects async adds
    critic = SlowCritic()
    config = HuntPoolConfig(
        files=[_ft("a.c", 4, 2)],
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(0.1),  # 1 finding -> promotes fast->standard
        max_parallel=1,
        budget_usd=100.0,
        tier_budget=TierBudget(0.7, 0.25, 0.05),
        cost_limit_per_file_a=10.0,
        cost_limit_per_file_b=10.0,
        cost_limit_per_file_c=10.0,
        starting_band="fast",
        max_band="standard",
        redundancy_override=1,
        skeptic_gate=SlowSkeptic(),
        critic_agent=critic,
        findings_pool=fp,
    )
    pool = HunterPool(config)
    pool._read_source_for_critic = lambda *a, **k: ""  # type: ignore[method-assign]
    pool._build_cross_file_context = lambda *a, **k: ""  # type: ignore[method-assign]
    pool._read_code_snippet_around = lambda *a, **k: ""  # type: ignore[method-assign]

    result = await pool.arun()

    files_in_pool = {f.get("file") for f in fp.all_findings()}
    assert "a.c" in files_in_pool  # skeptic-admitted analyzer finding
    # critic lead has a DISTINCT (file,line,cwe) so A3 dedup can't merge/false-pass
    assert any(f.get("finding_type") == "oob_read" for f in fp.all_findings())
    assert any(f.get("finding_type") == "oob_read" for f in result)
    assert critic.calls == 1  # A4 terminal-band invariant preserved
    assert pool._lab_tasks == []  # barrier drained all detached tasks


@pytest.mark.asyncio
async def test_debate_reinstatement_survives_detached_join():
    """A1: a debate-reinstated finding (skeptic refutes -> analyst rebuttal
    overturns) must survive the detached join - no pool-level test covered this
    third lab-output path before."""
    from types import SimpleNamespace

    from acuario.scanner.findings_pool import FindingsPool

    class RefuteThenReinstateSkeptic:
        async def ascreen_batch(self, findings, cross_file_contexts=None):
            await asyncio.sleep(0.05)
            return [], [SimpleNamespace(verdict="refuted") for _ in findings]

        async def adebate_batch(
            self, refuted_pairs, trajectory_summary="", cross_file_contexts=None
        ):
            await asyncio.sleep(0.05)
            out = []
            for f, _v in refuted_pairs:
                fo = _as_finding(f)  # reinstate as a real Finding object
                fo["debate_overturned"] = True
                out.append(fo)
            return out

    fp = FindingsPool()
    config = HuntPoolConfig(
        files=[_ft("a.c", 4, 2)],
        repo_path="/tmp/repo",
        sandbox_factory=None,
        hunter_factory=_stub_hunter_factory(0.1),
        max_parallel=1,
        budget_usd=100.0,
        tier_budget=TierBudget(0.7, 0.25, 0.05),
        cost_limit_per_file_a=10.0,
        cost_limit_per_file_b=10.0,
        cost_limit_per_file_c=10.0,
        starting_band="fast",
        max_band="fast",  # no promotion; isolates the debate path (no critic)
        redundancy_override=1,
        skeptic_gate=RefuteThenReinstateSkeptic(),
        findings_pool=fp,
    )
    pool = HunterPool(config)
    pool._build_cross_file_context = lambda *a, **k: ""  # type: ignore[method-assign]
    result = await pool.arun()

    assert any(f.get("debate_overturned") for f in fp.all_findings()), "reinstatement lost"
    assert any(f.get("debate_overturned") for f in result)
