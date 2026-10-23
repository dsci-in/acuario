"""Historical findings database for cross-campaign dedup.

SQLite database at ~/.acuario/scanner/historical_findings.db.
Read at campaign start; written incrementally through the run - findings are
ingested (INSERT OR IGNORE) as files complete, then their verdicts are stamped
in place as later stages reach them: ``mark_reviewed`` after the reviewer pass
and ``mark_exploited`` after the exploit stage, each also re-persisting the
finding's bumped ``evidence_level``.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from acuario.findings.types import Finding

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    file TEXT,
    line_number INTEGER,
    finding_type TEXT,
    primitive_type TEXT,
    cluster_id TEXT,
    cwe TEXT,
    severity TEXT,
    description TEXT,
    code_snippet TEXT,
    evidence_level TEXT,
    repo_url TEXT,
    campaign_session_id TEXT,
    discovered_at REAL,
    verified INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_repo ON findings(repo_url);
CREATE INDEX IF NOT EXISTS idx_cwe ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_primitive ON findings(primitive_type);
CREATE INDEX IF NOT EXISTS idx_file ON findings(file);
"""

_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN crypto_protocol TEXT",
    "ALTER TABLE findings ADD COLUMN algorithm TEXT",
    "ALTER TABLE findings ADD COLUMN crypto_attack_class TEXT",
    "ALTER TABLE findings ADD COLUMN key_material_exposed TEXT",
    # Reviewer-state tracking. `reviewed_at` is the unix timestamp when
    # the reviewer last reached a verdict for the finding (positive OR
    # negative). `review_revision` is the cumulative count of times the
    # reviewer has touched the finding - every verdict update bumps it.
    # Together these make the resume path idempotent: we skip findings
    # whose verdict was reached, even if `verified=0`, because the
    # negative verdict is a real reviewer decision, not a transient
    # error. NULL `reviewed_at` means the finding never got a verdict
    # (either was newly inserted by the analyzer, or hit a transient
    # error during a prior reviewer pass).
    "ALTER TABLE findings ADD COLUMN reviewed_at REAL",
    "ALTER TABLE findings ADD COLUMN review_revision INTEGER DEFAULT 0",
    # Exploit-dev verdicts, so a durable cross-campaign query can answer "which
    # findings had a working exploit / what blocked it / where's the transcript".
    # exploit_success: 1 succeeded, 0 attempted-and-failed, NULL not attempted.
    "ALTER TABLE findings ADD COLUMN exploit_success INTEGER",
    "ALTER TABLE findings ADD COLUMN exploit_blocked_by TEXT",
    "ALTER TABLE findings ADD COLUMN exploit_transcript_path TEXT",
]


def _exploit_success_int(value: Any) -> int | None:
    """Map an exploit_success flag to the INTEGER column: 1 succeeded, 0
    attempted-and-failed, None (NULL) not attempted."""
    if value is None:
        return None
    return 1 if value else 0


def _default_db_path() -> Path:
    from acuario.core.config import acuario_home

    return acuario_home() / "scanner" / "historical_findings.db"


class HistoricalFindingsDB:
    """Cross-campaign findings database."""

    def __init__(self, path: Path | None = None):
        self._path = path or _default_db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        for migration in _MIGRATIONS:
            try:
                self._conn.execute(migration)
            except sqlite3.OperationalError:
                pass
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def mark_reviewed(
        self, finding_id: str, *, verified: bool, evidence_level: str | None = None
    ) -> None:
        """Stamp a finding as having reached a verdict.

        Records the verdict (verified True/False), the wall-clock time,
        and bumps the per-finding revision counter. Resume passes skip
        findings whose ``reviewed_at`` is non-NULL - that's how we
        avoid re-rolling the dice on findings the reviewer has already
        deliberately decided.

        ``evidence_level`` (optional) re-persists the reviewer's evidence
        bump. Findings are ingested at ``suspicion`` BEFORE review runs, so
        without this the historical DB (and ``acuario history``) would keep
        showing every finding at its pre-review level. COALESCE means a None
        does not clobber the stored value.
        """
        try:
            self._conn.execute(
                """UPDATE findings
                   SET verified = ?,
                       reviewed_at = ?,
                       review_revision = COALESCE(review_revision, 0) + 1,
                       evidence_level = COALESCE(?, evidence_level)
                   WHERE id = ?""",
                (1 if verified else 0, time.time(), evidence_level, finding_id),
            )
            self._conn.commit()
        except sqlite3.Error:
            logger.debug("Failed to mark reviewed %s", finding_id, exc_info=True)

    def mark_exploited(
        self,
        finding_id: str,
        *,
        success: Any = None,
        blocked_by: str | None = None,
        transcript_path: str | None = None,
        evidence_level: str | None = None,
    ) -> None:
        """Stamp an exploit-dev verdict onto an already-persisted finding.

        Findings are ingested (INSERT OR IGNORE) BEFORE the exploit stage runs,
        so exploit outcomes must be written with a targeted UPDATE. ``success``:
        True succeeded, False attempted-and-failed, None not attempted (leaves
        the column NULL). ``blocked_by`` / ``transcript_path`` / ``evidence_level``
        use COALESCE so a None does not clobber an existing value. ``evidence_level``
        re-persists the exploit-dev bump (e.g. ``exploit_demonstrated``) that
        otherwise never reaches the historical DB. Best-effort - a DB error never
        breaks the run.
        """
        try:
            self._conn.execute(
                """UPDATE findings
                   SET exploit_success = ?,
                       exploit_blocked_by = COALESCE(?, exploit_blocked_by),
                       exploit_transcript_path = COALESCE(?, exploit_transcript_path),
                       evidence_level = COALESCE(?, evidence_level)
                   WHERE id = ?""",
                (
                    _exploit_success_int(success),
                    blocked_by,
                    transcript_path,
                    evidence_level,
                    finding_id,
                ),
            )
            self._conn.commit()
        except sqlite3.Error:
            logger.debug("Failed to mark exploited %s", finding_id, exc_info=True)

    def ingest_campaign(
        self,
        findings: list[Finding],
        repo_url: str,
        session_id: str,
    ) -> int:
        """Insert findings from a completed campaign. Returns count inserted."""
        count = 0
        now = time.time()
        for f in findings:
            fid = f.get("id", "")
            if not fid:
                continue
            try:
                cur = self._conn.execute(
                    """INSERT OR IGNORE INTO findings
                    (id, file, line_number, finding_type, primitive_type,
                     cluster_id, cwe, severity, description, code_snippet,
                     evidence_level, repo_url, campaign_session_id,
                     discovered_at, verified,
                     crypto_protocol, algorithm, crypto_attack_class,
                     key_material_exposed,
                     exploit_success, exploit_blocked_by, exploit_transcript_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?,
                            ?, ?, ?)""",
                    (
                        fid,
                        f.get("file"),
                        f.get("line_number"),
                        f.get("finding_type", ""),
                        f.get("primitive_type", ""),
                        f.get("cluster_id", ""),
                        f.get("cwe", ""),
                        f.get("severity", "info"),
                        f.get("description", "")[:2000],
                        f.get("code_snippet", "")[:1000],
                        f.get("evidence_level", "suspicion"),
                        repo_url,
                        session_id,
                        now,
                        1 if f.get("verified") else 0,
                        f.get("crypto_protocol"),
                        f.get("algorithm"),
                        f.get("crypto_attack_class"),
                        f.get("key_material_exposed"),
                        _exploit_success_int(f.get("exploit_success")),
                        f.get("exploit_blocked_by"),
                        f.get("exploit_transcript_path"),
                    ),
                )
                count += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            except sqlite3.Error:
                logger.debug("Failed to insert finding %s", fid, exc_info=True)
        self._conn.commit()
        return count

    def query_prior(
        self,
        repo_url: str,
        cwe: str | None = None,
        file: str | None = None,
        exclude_session_id: str | None = None,
    ) -> list[dict]:
        """Return historical findings for this repo.

        ``exclude_session_id`` omits findings persisted under this campaign
        session, so a run's OWN mid-run findings (written via the checkpoint)
        do not resurface in its analyzer prompts as "from previous audits".
        """
        query = "SELECT * FROM findings WHERE repo_url = ?"
        params: list[Any] = [repo_url]
        if cwe:
            query += " AND cwe = ?"
            params.append(cwe)
        if file:
            query += " AND file = ?"
            params.append(file)
        if exclude_session_id:
            query += " AND (campaign_session_id IS NULL OR campaign_session_id != ?)"
            params.append(exclude_session_id)
        query += " ORDER BY discovered_at DESC LIMIT 200"
        try:
            rows = self._conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            logger.debug("Historical query failed", exc_info=True)
            return []

    def is_known(self, finding: Finding, repo_url: str) -> bool:
        """Check if a finding with this file+line+cwe already exists."""
        file_path = finding.get("file")
        line = finding.get("line_number")
        cwe = finding.get("cwe", "")
        if not file_path or not cwe:
            return False
        try:
            row = self._conn.execute(
                "SELECT 1 FROM findings WHERE repo_url = ? AND file = ? AND line_number = ? AND cwe = ? LIMIT 1",
                (repo_url, file_path, line, cwe),
            ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False
