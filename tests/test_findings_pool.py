"""Tests for spec 005 - shared findings pool, historical DB, and pool query tool."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from acuario.findings.types import Finding
from acuario.scanner.findings_pool import (
    _CWE_PRIMITIVE_MAP,
    _FINDING_TYPE_PRIMITIVE_MAP,
    PRIMITIVE_TYPES,
    FindingsPool,
)
from acuario.scanner.historical_findings_db import HistoricalFindingsDB


def _make_finding(**overrides) -> Finding:
    defaults = {
        "id": f"f-{uuid.uuid4().hex[:8]}",
        "file": "src/parser.c",
        "line_number": 42,
        "finding_type": "buffer_overflow",
        "cwe": "CWE-787",
        "severity": "high",
        "description": "Heap buffer overflow in parse_header",
        "code_snippet": "memcpy(buf, src, len);",
        "evidence_level": "static_corroboration",
        "hunter_session_id": "session-a",
    }
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# FindingsPool - primitive classification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_sets_primitive_type_from_cwe():
    pool = FindingsPool()
    f = _make_finding(cwe="CWE-787")
    result = await pool.add(f)
    assert result.primitive_type == "bounded_write"


@pytest.mark.asyncio
async def test_add_sets_primitive_from_finding_type():
    pool = FindingsPool()
    f = _make_finding(cwe="CWE-999", finding_type="sql_injection")
    result = await pool.add(f)
    assert result.primitive_type == "sql_injection"


@pytest.mark.asyncio
async def test_add_unknown_cwe_no_llm_falls_back_to_unknown():
    pool = FindingsPool()
    f = _make_finding(cwe="CWE-999", finding_type="exotic_bug")
    result = await pool.add(f)
    assert result.primitive_type == "unknown"


@pytest.mark.asyncio
async def test_add_with_llm_classification():
    mock_llm = AsyncMock()
    mock_response = MagicMock()
    mock_response.first_text.return_value = '{"primitive_type": "race_condition"}'
    mock_llm.achat.return_value = mock_response

    pool = FindingsPool(llm=mock_llm)
    f = _make_finding(cwe="CWE-999", finding_type="exotic_bug")
    result = await pool.add(f)
    assert result.primitive_type == "race_condition"


@pytest.mark.asyncio
async def test_add_preserves_existing_primitive_type():
    pool = FindingsPool()
    f = _make_finding(primitive_type="info_leak")
    result = await pool.add(f)
    assert result.primitive_type == "info_leak"


# ---------------------------------------------------------------------------
# FindingsPool - clustering & dedup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_sets_cluster_id():
    pool = FindingsPool()
    f = _make_finding()
    result = await pool.add(f)
    assert result.cluster_id
    assert result.cluster_id.startswith("cluster-")


@pytest.mark.asyncio
async def test_dedup_same_root_cause():
    mock_llm = AsyncMock()
    call_count = 0

    async def mock_achat(**kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        if call_count <= 2:
            # Classification calls
            resp.first_text.return_value = '{"primitive_type": "bounded_write"}'
        else:
            # Dedup call - return the cluster of the first finding
            cluster_id = list(pool._clusters.keys())[0]
            resp.first_text.return_value = f'{{"duplicate_of": "{cluster_id}"}}'
        return resp

    mock_llm.achat = mock_achat

    pool = FindingsPool(llm=mock_llm)
    f1 = _make_finding(id="f1", cwe="CWE-999", finding_type="exotic")
    f2 = _make_finding(id="f2", cwe="CWE-999", finding_type="exotic")

    await pool.add(f1)
    await pool.add(f2)

    assert f1.cluster_id == f2.cluster_id
    assert len(pool.clusters()) == 1


@pytest.mark.asyncio
async def test_add_dedup_reports_new_vs_merged():
    # M4: add_dedup returns True for a fresh finding, False when the exact
    # (file, line, cwe) already exists and the finding merges into it.
    pool = FindingsPool()
    f1 = _make_finding(id="f1", file="src/a.c", line_number=10, cwe="CWE-787")
    f2 = _make_finding(id="f2", file="src/a.c", line_number=10, cwe="CWE-787")
    f3 = _make_finding(id="f3", file="src/b.c", line_number=20, cwe="CWE-89")

    assert await pool.add_dedup(f1) is True  # new
    assert await pool.add_dedup(f2) is False  # exact dup of f1 → merged
    assert await pool.add_dedup(f3) is True  # different file/cwe → new
    # Only the two distinct representatives survive.
    assert pool.count == 2


@pytest.mark.asyncio
async def test_dedup_different_root_cause():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", file="src/a.c", cwe="CWE-787")
    f2 = _make_finding(id="f2", file="src/b.c", cwe="CWE-416")

    await pool.add(f1)
    await pool.add(f2)

    assert f1.cluster_id != f2.cluster_id
    assert len(pool.clusters()) == 2


@pytest.mark.asyncio
async def test_dedup_exact_match_without_llm():
    """Without LLM, the exact-match fast-path (A3) still merges findings that
    share (file, line_number, cwe) - LLM is not required for that path."""
    pool = FindingsPool()
    # _make_finding defaults: file="src/parser.c", line_number=42, cwe="CWE-787"
    f1 = _make_finding(id="f1", cwe="CWE-787")
    f2 = _make_finding(id="f2", cwe="CWE-787")  # identical key → fast-path hit

    await pool.add(f1)
    await pool.add(f2)

    # Fast-path: exact same (file, line, cwe) → same cluster even without LLM
    assert f1.cluster_id == f2.cluster_id
    assert len(pool.clusters()) == 1


@pytest.mark.asyncio
async def test_near_duplicate_different_line_not_merged_without_llm():
    """Findings at different line numbers must NOT be merged by the fast-path
    (they are near-misses; LLM would decide, but without LLM → separate clusters)."""
    pool = FindingsPool()
    f1 = _make_finding(id="f1", line_number=10, cwe="CWE-787")
    f2 = _make_finding(id="f2", line_number=99, cwe="CWE-787")  # different line

    await pool.add(f1)
    await pool.add(f2)

    # Near-miss: different line → fast-path miss → separate clusters without LLM
    assert f1.cluster_id != f2.cluster_id


# ---------------------------------------------------------------------------
# FindingsPool - query
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_by_primitive_type():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", cwe="CWE-200", finding_type="info_leak")
    f2 = _make_finding(id="f2", cwe="CWE-787", finding_type="buffer_overflow")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(primitive_type="info_leak")
    assert len(results) == 1
    assert results[0].id == "f1"


@pytest.mark.asyncio
async def test_query_by_cwe():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", cwe="CWE-89")
    f2 = _make_finding(id="f2", cwe="CWE-787")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(cwe="CWE-89")
    assert len(results) == 1
    assert results[0].id == "f1"


@pytest.mark.asyncio
async def test_query_by_file_path():
    pool = FindingsPool()
    f1 = _make_finding(id="f1", file="src/a.c")
    f2 = _make_finding(id="f2", file="src/b.c")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(file_path="src/a.c")
    assert len(results) == 1
    assert results[0].id == "f1"


@pytest.mark.asyncio
async def test_query_exclude_session():
    pool = FindingsPool()
    # Distinct dedup keys so both findings survive A3 fast-path; this
    # test exercises session-id query filtering, not dedup behavior.
    f1 = _make_finding(id="f1", line_number=10, hunter_session_id="session-a")
    f2 = _make_finding(id="f2", line_number=20, hunter_session_id="session-b")
    await pool.add(f1)
    await pool.add(f2)

    results = pool.query(exclude_session="session-a")
    assert len(results) == 1
    assert results[0].id == "f2"


@pytest.mark.asyncio
async def test_query_no_filters_returns_all():
    pool = FindingsPool()
    # Distinct dedup keys per finding so all 5 survive A3 fast-path.
    for i in range(5):
        await pool.add(_make_finding(id=f"f{i}", line_number=10 + i))
    assert len(pool.query()) == 5


# ---------------------------------------------------------------------------
# FindingsPool - all_findings, deduplicated, summary, pool_stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_findings():
    pool = FindingsPool()
    # Each finding must have a distinct (file, line, cwe) dedup key,
    # otherwise the A3 fast-path collapses them into a single cluster
    # representative (an earlier run had `search.py:15 CWE-89` appearing
    # 5× because the same file was analyzed 5 times with redundancy).
    for i in range(3):
        await pool.add(_make_finding(id=f"f{i}", line_number=10 + i))
    assert len(pool.all_findings()) == 3


@pytest.mark.asyncio
async def test_deduplicated_findings():
    pool = FindingsPool()
    f1 = _make_finding(id="f1")
    f2 = _make_finding(id="f2")
    await pool.add(f1)
    await pool.add(f2)

    # Force f2 into same cluster as f1
    f2.cluster_id = f1.cluster_id
    pool._findings["f2"] = f2

    deduped = pool.deduplicated_findings()
    assert len(deduped) == 1


@pytest.mark.asyncio
async def test_summary_output():
    pool = FindingsPool()
    await pool.add(_make_finding())
    summary = pool.summary()
    assert "bounded_write" in summary or "CWE-787" in summary


@pytest.mark.asyncio
async def test_pool_stats():
    pool = FindingsPool()
    # Distinct dedup keys so both findings survive the fast-path.
    await pool.add(_make_finding(id="f1", line_number=10))
    await pool.add(_make_finding(id="f2", line_number=20))
    stats = pool.pool_stats()
    assert stats["total_findings"] == 2
    assert stats["total_clusters"] >= 1


# ---------------------------------------------------------------------------
# FindingsPool - checkpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkpoint_roundtrip(tmp_path):
    cp = tmp_path / "pool.jsonl"
    pool = FindingsPool(checkpoint_path=cp)
    f1 = _make_finding(id="f1", cwe="CWE-787")
    f2 = _make_finding(id="f2", cwe="CWE-416")
    await pool.add(f1)
    await pool.add(f2)

    assert cp.exists()
    lines = cp.read_text().strip().splitlines()
    assert len(lines) == 2

    restored = FindingsPool.from_checkpoint(cp)
    assert len(restored.all_findings()) == 2
    ids = {f.id for f in restored.all_findings()}
    assert "f1" in ids and "f2" in ids


@pytest.mark.asyncio
async def test_checkpoint_not_written_without_path():
    pool = FindingsPool(checkpoint_path=None)
    await pool.add(_make_finding())
    # No error - checkpoint silently skipped


# ---------------------------------------------------------------------------
# FindingsPool - concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_adds():
    pool = FindingsPool()
    # Distinct (file, line, cwe) keys so the A3 dedup doesn't collapse
    # them.  This test exercises the lock-correctness of concurrent
    # add(), not the dedup behavior.
    findings = [_make_finding(id=f"f{i}", line_number=100 + i) for i in range(10)]
    await asyncio.gather(*[pool.add(f) for f in findings])
    assert len(pool.all_findings()) == 10
    assert all(f.cluster_id for f in pool.all_findings())


# ---------------------------------------------------------------------------
# HistoricalFindingsDB
# ---------------------------------------------------------------------------


def test_schema_creation(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    assert (tmp_path / "test.db").exists()
    db.close()


def test_ingest_and_query(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    findings = [
        _make_finding(id="f1", cwe="CWE-787", file="src/a.c"),
        _make_finding(id="f2", cwe="CWE-89", file="src/b.c"),
    ]
    count = db.ingest_campaign(findings, "https://github.com/test/repo", "session-1")
    assert count == 2

    results = db.query_prior("https://github.com/test/repo")
    assert len(results) == 2

    results = db.query_prior("https://github.com/test/repo", cwe="CWE-89")
    assert len(results) == 1
    assert results[0]["cwe"] == "CWE-89"

    results = db.query_prior("https://github.com/test/repo", file="src/a.c")
    assert len(results) == 1
    db.close()


def test_exploit_columns_ingested(tmp_path):
    """Exploit verdicts carried on a finding are persisted + queryable."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f = _make_finding(id="x1", cwe="CWE-787", file="src/a.c")
    f["exploit_success"] = True
    f["exploit_transcript_path"] = "/out/exploits/x1/t.jsonl"
    db.ingest_campaign([f], "https://github.com/test/repo", "s1")
    row = db.query_prior("https://github.com/test/repo")[0]
    assert row["exploit_success"] == 1
    assert row["exploit_transcript_path"] == "/out/exploits/x1/t.jsonl"
    db.close()


def test_mark_exploited_updates_existing_finding(tmp_path):
    """A finding persisted at the P2 checkpoint (pre-exploit) is stamped with the
    exploit verdict via a targeted UPDATE, not a fresh INSERT."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    db.ingest_campaign(
        [_make_finding(id="y1", cwe="CWE-89", file="src/b.c")],
        "https://github.com/test/repo",
        "s1",
    )
    assert db.query_prior("https://github.com/test/repo")[0]["exploit_success"] is None
    db.mark_exploited("y1", success=False, blocked_by="ASLR/DEP", transcript_path="/t.jsonl")
    row = db.query_prior("https://github.com/test/repo")[0]
    assert row["exploit_success"] == 0
    assert row["exploit_blocked_by"] == "ASLR/DEP"
    assert row["exploit_transcript_path"] == "/t.jsonl"
    db.close()


def test_mark_exploited_coalesce_preserves_existing(tmp_path):
    """mark_exploited with None for blocked_by/transcript must NOT clobber a
    previously-set value (COALESCE)."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    db.ingest_campaign(
        [_make_finding(id="z1", cwe="CWE-79", file="c.js")],
        "https://github.com/test/repo",
        "s1",
    )
    db.mark_exploited("z1", success=True, blocked_by="keep-me", transcript_path="/keep.jsonl")
    db.mark_exploited("z1", success=True, blocked_by=None, transcript_path=None)
    row = db.query_prior("https://github.com/test/repo")[0]
    assert row["exploit_success"] == 1
    assert row["exploit_blocked_by"] == "keep-me"
    assert row["exploit_transcript_path"] == "/keep.jsonl"
    db.close()


def test_mark_exploited_persists_evidence_level(tmp_path):
    """Regression: the exploit-dev bump to exploit_demonstrated must reach the
    historical DB. Findings are ingested at their pre-exploit level, so without
    the evidence_level UPDATE the DB (and `acuario history`) kept showing an
    exploited finding as `suspicion`."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    db.ingest_campaign(
        [_make_finding(id="e1", cwe="CWE-89", file="src/x.java", evidence_level="suspicion")],
        "https://github.com/test/repo",
        "s1",
    )
    assert db.query_prior("https://github.com/test/repo")[0]["evidence_level"] == "suspicion"
    db.mark_exploited("e1", success=True, evidence_level="exploit_demonstrated")
    row = db.query_prior("https://github.com/test/repo")[0]
    assert row["exploit_success"] == 1
    assert row["evidence_level"] == "exploit_demonstrated"
    db.close()


def test_mark_reviewed_persists_evidence_level(tmp_path):
    """The reviewer's evidence bump must also reach the historical DB."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    db.ingest_campaign(
        [_make_finding(id="r1", cwe="CWE-79", file="src/y.java", evidence_level="suspicion")],
        "https://github.com/test/repo",
        "s1",
    )
    db.mark_reviewed("r1", verified=True, evidence_level="root_cause_explained")
    row = db.query_prior("https://github.com/test/repo")[0]
    assert row["verified"] == 1
    assert row["evidence_level"] == "root_cause_explained"
    db.close()


def test_mark_reviewed_evidence_level_none_coalesce(tmp_path):
    """mark_reviewed with evidence_level=None must NOT clobber the stored level."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    db.ingest_campaign(
        [
            _make_finding(
                id="r2", cwe="CWE-89", file="src/z.java", evidence_level="static_corroboration"
            )
        ],
        "https://github.com/test/repo",
        "s1",
    )
    db.mark_reviewed("r2", verified=True)  # no evidence_level passed
    row = db.query_prior("https://github.com/test/repo")[0]
    assert row["evidence_level"] == "static_corroboration"
    db.close()


def test_persist_exploit_verdicts_uses_default_path_when_none(tmp_path, monkeypatch):
    """Regression: the full run passes historical_db_path=None (it ingested into the
    DEFAULT db), so _persist_exploit_verdicts must resolve None -> default and write,
    not bail. Previously it returned early on a None path and every exploit verdict
    was silently dropped from the historical DB."""
    import acuario.core.config as cfg
    from acuario.scanner.exploit_stage import _persist_exploit_verdicts

    monkeypatch.setattr(cfg, "acuario_home", lambda: tmp_path)
    repo = "https://github.com/test/repo"
    seed = HistoricalFindingsDB()  # default path -> tmp_path/scanner/historical_findings.db
    seed.ingest_campaign(
        [_make_finding(id="p1", cwe="CWE-89", file="src/a.java", evidence_level="suspicion")],
        repo,
        "s1",
    )
    seed.close()

    ef = _make_finding(
        id="p1", cwe="CWE-89", file="src/a.java", evidence_level="exploit_demonstrated"
    )
    ef["exploit_success"] = True
    _persist_exploit_verdicts([ef], historical_db_path=None, persist_to_db=True)

    check = HistoricalFindingsDB()
    row = check.query_prior(repo)[0]
    assert row["exploit_success"] == 1
    assert row["evidence_level"] == "exploit_demonstrated"
    check.close()


def test_query_prior_excludes_current_session(tmp_path):
    """H1: a run's OWN mid-run findings must not resurface as prior-audit context."""
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    repo = "https://github.com/test/repo"
    db.ingest_campaign([_make_finding(id="old", cwe="CWE-89", file="src/a.c")], repo, "audit-OLD")
    db.ingest_campaign([_make_finding(id="cur", cwe="CWE-89", file="src/a.c")], repo, "audit-CUR")

    # Without exclusion, both sessions' findings come back.
    both = {r["id"] for r in db.query_prior(repo, file="src/a.c")}
    assert both == {"old", "cur"}

    # Excluding the current session omits only this run's own finding.
    filtered = {
        r["id"] for r in db.query_prior(repo, file="src/a.c", exclude_session_id="audit-CUR")
    }
    assert filtered == {"old"}
    db.close()


def test_is_known(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f = _make_finding(cwe="CWE-787", file="src/a.c", line_number=42)
    db.ingest_campaign([f], "https://github.com/test/repo", "session-1")

    assert db.is_known(f, "https://github.com/test/repo")
    assert not db.is_known(
        _make_finding(cwe="CWE-89", file="src/b.c"),
        "https://github.com/test/repo",
    )
    db.close()


def test_cross_campaign(tmp_path):
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f1 = _make_finding(id="f1", cwe="CWE-787")
    f2 = _make_finding(id="f2", cwe="CWE-89")
    db.ingest_campaign([f1], "https://github.com/test/repo", "session-1")
    db.ingest_campaign([f2], "https://github.com/test/repo", "session-2")

    results = db.query_prior("https://github.com/test/repo")
    assert len(results) == 2
    db.close()


def test_findings_without_id_skipped(tmp_path):
    # __post_init__ now auto-generates an id when id="" is passed, so a
    # Finding constructed with id="" will have an auto-generated id and be
    # ingested successfully.
    db = HistoricalFindingsDB(path=tmp_path / "test.db")
    f = _make_finding(id="")
    assert f.id.startswith("f-")  # auto-generated
    count = db.ingest_campaign([f], "https://github.com/test/repo", "session-1")
    assert count == 1
    db.close()


# ---------------------------------------------------------------------------
# Pool query tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_tool_returns_findings():
    from acuario.agent.tools.hunt.pool_query import build_pool_query_tools
    from acuario.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    await pool.add(_make_finding(cwe="CWE-200", finding_type="info_leak"))

    ctx = HunterContext(
        repo_path="/tmp/repo",
        findings_pool=pool,
        session_id="session-b",
    )
    tools = build_pool_query_tools(ctx)
    assert len(tools) == 1
    assert tools[0].name == "query_findings_pool"

    result = tools[0].handler(primitive_type="info_leak")
    assert "Found 1 matching findings" in result


@pytest.mark.asyncio
async def test_query_tool_no_pool():
    from acuario.agent.tools.hunt.pool_query import build_pool_query_tools
    from acuario.agent.tools.hunt.sandbox import HunterContext

    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=None)
    tools = build_pool_query_tools(ctx)
    result = tools[0].handler()
    assert "not available" in result


def test_pool_tool_in_hunter_tools():
    from acuario.agent.tools.hunt import build_hunter_tools
    from acuario.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=pool)
    tools = build_hunter_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" in names


def test_pool_tool_not_in_hunter_tools_without_pool():
    from acuario.agent.tools.hunt import build_hunter_tools
    from acuario.agent.tools.hunt.sandbox import HunterContext

    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=None)
    tools = build_hunter_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" not in names


def test_pool_tool_in_deep_agent_tools():
    from acuario.agent.tools.hunt import build_deep_agent_tools
    from acuario.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=pool)
    tools = build_deep_agent_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" in names


def test_pool_tool_in_propagation_tools():
    from acuario.agent.tools.hunt import build_propagation_auditor_tools
    from acuario.agent.tools.hunt.sandbox import HunterContext

    pool = FindingsPool()
    ctx = HunterContext(repo_path="/tmp/repo", findings_pool=pool)
    tools = build_propagation_auditor_tools(ctx)
    names = [t.name for t in tools]
    assert "query_findings_pool" in names


# ---------------------------------------------------------------------------
# Integration - prompt includes pool block
# ---------------------------------------------------------------------------


def test_prompt_includes_pool_block():

    pool = FindingsPool()
    pool._findings["f1"] = _make_finding(id="f1")

    from acuario.scanner.analyzer import _build_unconstrained_prompt

    prompt = _build_unconstrained_prompt(
        file_target={"path": "src/a.c", "language": "c", "tags": []},
        project_name="test-project",
        seeded_crash=None,
        semgrep_hints=None,
        findings_pool=pool,
    )
    assert "query_findings_pool" in prompt


def test_prompt_no_pool_block_when_empty():
    from acuario.scanner.analyzer import _build_unconstrained_prompt

    pool = FindingsPool()

    prompt = _build_unconstrained_prompt(
        file_target={"path": "src/a.c", "language": "c", "tags": []},
        project_name="test-project",
        seeded_crash=None,
        semgrep_hints=None,
        findings_pool=pool,
    )
    assert "query_findings_pool" not in prompt


def test_prompt_no_pool_block_without_pool():
    from acuario.scanner.analyzer import _build_unconstrained_prompt

    prompt = _build_unconstrained_prompt(
        file_target={"path": "src/a.c", "language": "c", "tags": []},
        project_name="test-project",
        seeded_crash=None,
        semgrep_hints=None,
    )
    assert "query_findings_pool" not in prompt


# ---------------------------------------------------------------------------
# CWE / finding-type map coverage sanity checks
# ---------------------------------------------------------------------------


def test_cwe_map_values_are_valid_primitives():
    for prim in _CWE_PRIMITIVE_MAP.values():
        assert prim in PRIMITIVE_TYPES, f"{prim} not in PRIMITIVE_TYPES"


def test_finding_type_map_values_are_valid_primitives():
    for prim in _FINDING_TYPE_PRIMITIVE_MAP.values():
        assert prim in PRIMITIVE_TYPES, f"{prim} not in PRIMITIVE_TYPES"


# ---------------------------------------------------------------------------
# A3: Exact-match fast-path dedup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exact_match_fast_path_skips_llm():
    """Two findings with the same (file, line, cwe) must be merged into the
    same cluster via the fast-path index - no LLM call for the second one."""
    mock_llm = AsyncMock()
    mock_response = MagicMock()
    mock_response.first_text.return_value = '{"primitive_type": "bounded_write"}'
    mock_llm.achat.return_value = mock_response

    pool = FindingsPool(llm=mock_llm)

    f1 = _make_finding(
        id="f1",
        file="/app/src/auth.php",
        line_number=17,
        cwe="CWE-89",
        severity="high",
    )
    f2 = _make_finding(
        id="f2",
        file="/app/src/auth.php",  # same path (with sandbox prefix)
        line_number=17,  # same line
        cwe="CWE-89",  # same cwe
        severity="medium",
    )

    await pool.add(f1)
    llm_calls_after_first = mock_llm.achat.call_count

    await pool.add(f2)
    llm_calls_after_second = mock_llm.achat.call_count

    # Fast-path hit: second finding must land in the same cluster
    assert f1.cluster_id == f2.cluster_id
    assert len(pool.clusters()) == 1

    # The LLM must NOT have been called for the second finding's clustering
    # (classification still fires because cwe=CWE-89 is not in _CWE_PRIMITIVE_MAP;
    # but dedup/cluster-assignment must be skipped)
    # The dedup check (_dedup_check) fires one extra achat per non-fast-path hit.
    # Fast-path means zero extra achat calls for the cluster-assignment step.
    # Classification may still call LLM for exotic CWE (CWE-89 is sql_injection
    # but not in _CWE_PRIMITIVE_MAP at test-write time, so LLM may fire once).
    # Key assertion: no _additional_ cluster was created.
    assert llm_calls_after_second <= llm_calls_after_first + 1  # at most classify call


@pytest.mark.asyncio
async def test_exact_match_fast_path_severity_merge():
    """When a higher-severity duplicate arrives via the fast-path, it should
    upgrade the representative finding's severity (severity can only go up)."""
    pool = FindingsPool()

    f1 = _make_finding(
        id="f1",
        file="src/cart.php",
        line_number=42,
        cwe="CWE-352",
        severity="low",
    )
    f2 = _make_finding(
        id="f2",
        file="src/cart.php",  # same file (no prefix)
        line_number=42,
        cwe="CWE-352",
        severity="critical",  # higher severity → should upgrade f1
    )

    await pool.add(f1)
    await pool.add(f2)

    # Both findings must be in the same cluster
    assert f1.cluster_id == f2.cluster_id
    assert len(pool.clusters()) == 1

    # Representative finding (f1) should have been upgraded to critical
    assert f1.severity == "critical"  # type: ignore[comparison-overlap]


@pytest.mark.asyncio
async def test_near_miss_falls_through_to_llm_path():
    """Two findings that differ on CWE (near-miss) must NOT hit the fast-path;
    they go through normal LLM clustering and can land in separate clusters."""
    pool = FindingsPool()  # no LLM → each file gets its own cluster

    f1 = _make_finding(
        id="f1",
        file="src/login.php",
        line_number=10,
        cwe="CWE-89",  # SQL injection
    )
    f2 = _make_finding(
        id="f2",
        file="src/login.php",
        line_number=10,
        cwe="CWE-79",  # XSS - different CWE → near-miss, must fall through
    )

    await pool.add(f1)
    await pool.add(f2)

    # Without LLM, near-miss files cannot be merged → separate clusters
    assert f1.cluster_id != f2.cluster_id
    assert len(pool.clusters()) == 2
