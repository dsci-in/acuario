"""Non-destructive same-locus finding de-duplication.

The analyzer re-hunts a file several times (band promotion, critic leads,
cross-file follow-ups) and the semantic clusterer under-merges, so the raw
findings list can carry the SAME bug at one file:line several times under
slightly different finding_type / CWE labels (e.g. identity.py:39 as
auth_bypass x3 + broken_authentication). That inflates the headline counts and
makes the report repetitive.

This module marks those duplicates WITHOUT deleting anything: every finding and
id stays in the list, so ``inspect fix <id>``, ``--resume --findings <id>``,
the historical DB, and the per-session exploit transcripts all keep resolving.
Only the report rendering and the headline counts treat a non-primary as an
alias of its primary.

A primary is the highest-evidence, then highest-severity member of a locus, so
an exploited / verified finding is never hidden behind a weaker duplicate.

Guard: a locus carrying two or more DISTINCT concrete ``primitive_type`` values
(ignoring ``unknown`` / empty) is left split - genuinely different bugs on the
same line are not merged.
"""

from __future__ import annotations

from .state import EVIDENCE_LEVELS, Finding

_EVIDENCE_RANK = {level: idx for idx, level in enumerate(EVIDENCE_LEVELS)}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_PATH_PREFIXES = ("/app/", "/repo/", "/workspace/", "/code/")


def _clear_marker(f: Finding, key: str) -> None:
    """Remove a dedup marker from a Finding (kept in ``extra``) or plain dict.

    Finding has no ``pop``; unknown keys live in its public ``extra`` dict.
    """
    extra = getattr(f, "extra", None)
    if isinstance(extra, dict):
        extra.pop(key, None)
    elif isinstance(f, dict):
        f.pop(key, None)


def _norm_file(path: str) -> str:
    p = (path or "").strip()
    for pre in _PATH_PREFIXES:
        if p.startswith(pre):
            p = p[len(pre) :]
    return p.lstrip("/")


def _severity(f: Finding) -> str:
    return (f.get("severity_verified") or f.get("severity") or "info").lower()


def _primary_sort_key(f: Finding) -> tuple[int, int, int, int, int]:
    """Rank a finding for primary selection - larger wins.

    Highest evidence, then severity, then a verified / exploited finding, then
    the most detailed description as a final deterministic tiebreak.
    """
    return (
        _EVIDENCE_RANK.get(f.get("evidence_level", "suspicion"), 0),
        _SEVERITY_RANK.get(_severity(f), 0),
        1 if f.get("verified") is True else 0,
        1 if f.get("exploit_success") is True else 0,
        len(str(f.get("description") or "")),
    )


def annotate_duplicate_loci(findings: list[Finding]) -> int:
    """Mark same-locus duplicate findings in place. Returns the dup count.

    Sets ``duplicate_of`` (the primary's id) on each non-primary, and records
    ``alias_ids`` + ``alias_labels`` on the primary for the report's "also
    reported as" note. Idempotent: any prior markers are cleared first so a
    resume re-run recomputes cleanly.
    """
    for f in findings:
        for _key in ("duplicate_of", "alias_ids", "alias_labels"):
            _clear_marker(f, _key)

    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        nfile = _norm_file(str(f.get("file", "")))
        line = f.get("line_number", None)
        if not nfile or line in (None, "", "?"):
            # No resolvable locus - leave the finding as its own primary.
            continue
        groups.setdefault((nfile, str(line)), []).append(f)

    dup_count = 0
    for members in groups.values():
        if len(members) < 2:
            continue

        # Guard: 2+ distinct concrete primitives at one locus => different
        # bugs; sub-group by primitive so they stay separate primaries.
        real_prims = {
            p for f in members if (p := (f.get("primitive_type") or "").strip()) and p != "unknown"
        }
        if len(real_prims) >= 2:
            subgroups: dict[str, list[Finding]] = {}
            for f in members:
                prim = (f.get("primitive_type") or "").strip() or "unknown"
                subgroups.setdefault(prim, []).append(f)
            clusters = list(subgroups.values())
        else:
            clusters = [members]

        for cluster in clusters:
            if len(cluster) < 2:
                continue
            primary = max(cluster, key=_primary_sort_key)
            aliases = [f for f in cluster if f is not primary]
            primary["alias_ids"] = [str(a.get("id", "")) for a in aliases]
            primary["alias_labels"] = sorted(
                {str(a.get("finding_type") or a.get("cwe") or "?") for a in aliases}
            )
            pid = str(primary.get("id", ""))
            for a in aliases:
                a["duplicate_of"] = pid
                dup_count += 1
    return dup_count


def primaries(findings: list[Finding]) -> list[Finding]:
    """The findings that are not aliases of another (``duplicate_of`` unset)."""
    return [f for f in findings if not f.get("duplicate_of")]
