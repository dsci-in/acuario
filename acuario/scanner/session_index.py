"""A tiny index mapping audit session ids to their on-disk results directory.

Results are written relative to wherever ``acuario audit`` ran (usually next to
the target app), while ``historical_findings.db`` only retains findings - so a
later ``inspect`` / ``eval`` run from a different directory could not locate the
full artifacts (lab logs, transcripts).  This index records each session's
output directory at audit time so those commands can resolve it regardless of
the current working directory.

Stored at ``~/.acuario/scanner/session_paths.json``.  Every access is
best-effort and never raises into the pipeline; a missing or corrupt index
simply degrades to the previous behaviour (cwd default, then the DB fallback).
"""

from __future__ import annotations

import json
from pathlib import Path

from acuario.core.config import acuario_home


def _index_path() -> Path:
    return acuario_home() / "scanner" / "session_paths.json"


def _load() -> dict:
    try:
        data = json.loads(_index_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def record_session_path(session_id: str, session_dir) -> None:
    """Upsert ``session_id -> absolute results dir``.  Best-effort; never raises."""
    try:
        if not session_id:
            return
        path = _index_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = _load()
        data[str(session_id)] = str(Path(session_dir).resolve())
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)  # atomic swap
    except Exception:
        pass


def lookup_session_path(session_id: str) -> Path | None:
    """The recorded results dir for a session, if it is still on disk."""
    try:
        raw = _load().get(str(session_id))
        if not raw:
            return None
        p = Path(raw)
        return p if p.exists() else None
    except Exception:
        return None
