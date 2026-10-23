"""The historical-DB reconcile step: post-pool stages (subsystem / SCA) run after
the 3.5 ingest closed the DB, so the runner re-ingests the canonical set at 5.9.
This locks in that reopen + INSERT OR IGNORE + canonical filter adds the missing
rows, keeps variant_loop out, and counts only rows actually inserted."""

from __future__ import annotations

import sqlite3

from acuario.findings.types import canonical_findings
from acuario.scanner.historical_findings_db import HistoricalFindingsDB


def _ids(db_path, sid):
    conn = sqlite3.connect(str(db_path))
    ids = {r[0] for r in conn.execute(
        "SELECT id FROM findings WHERE campaign_session_id=?", (sid,))}
    conn.close()
    return ids


def _f(fid, src, **kw):
    base = {"id": fid, "discovered_by": src, "file": "x.py", "line_number": 1,
            "severity": "high", "verified": True}
    base.update(kw)
    return base


def test_reconcile_adds_post_pool_findings_and_excludes_variants(tmp_path):
    db_path = tmp_path / "hist.db"
    sid = "audit-recon"

    # 3.5: ingest the pre-pool set, then close (as the runner does before subsystem).
    pre = [_f("a1", "analyzer:unconstrained"), _f("a2", "source_analyzer", verified=False)]
    db = HistoricalFindingsDB(path=db_path)
    db.ingest_campaign(pre, repo_url="/repo", session_id=sid)
    db.close()
    assert _ids(db_path, sid) == {"a1", "a2"}

    # Post-pool stages append subsystem + SCA findings and a variant_loop seed.
    post = pre + [
        _f("s1", "analyzer:subsystem"),
        _f("sca1", "sca", file="package.json"),
        _f("v1", "variant_loop", verified=False, file="results/pool.jsonl"),
    ]

    # 5.9 reconcile: reopen and ingest the canonical set.
    recon = HistoricalFindingsDB(path=db_path)
    added = recon.ingest_campaign(
        canonical_findings(post), repo_url="/repo", session_id=sid
    )
    recon.close()

    assert added == 2  # only s1 + sca1 are new (a1/a2 already there, v1 excluded)
    assert _ids(db_path, sid) == {"a1", "a2", "s1", "sca1"}  # subsystem+SCA in, variant out
