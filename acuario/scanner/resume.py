"""Resume a crashed `acuario audit` run from its persisted findings.

When `acuario audit` crashes, the analyzer's findings are already in
``~/.acuario/scanner/historical_findings.db``. This module pulls them
back out and runs the remaining stages (reviewer + reporter), giving
the same end-state the original run would have produced - without
re-doing the multi-hour analyzer work.

P2: findings are now persisted **incrementally as each file completes**
(``HuntPoolConfig.on_file_complete`` → ``ingest_campaign``), not just in
one batch at end-of-pool. So a crash *mid-pool* - at file 30 of 50, nine
hours in - leaves all 30 completed files' findings in the DB, and
``--resume`` recovers and finishes them instead of restarting from zero.
(It does not re-hunt the 20 files that never ran before the crash; it
salvages the expensive work already done and completes the pipeline.)

Invoked from the CLI via ``acuario audit --resume <session-id>``.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, cast

from acuario.llm.retry_policy import KIND_RATE_LIMITED, KIND_TRANSIENT, classify_error

if TYPE_CHECKING:
    from acuario.findings.types import Finding
    from acuario.scanner.validator import ValidatorVerdict

logger = logging.getLogger(__name__)


def load_findings_from_db(db_path: Path, session_id: str) -> tuple[list[dict], str]:
    """Read all findings persisted under ``session_id``.

    Returns ``(findings, repo_url)``. Findings are returned as plain
    dicts in the shape the rest of the scanner pipeline consumes,
    plus the ``reviewed_at`` and ``review_revision`` columns that
    track the reviewer-verdict state across resume runs.
    """
    # Lazily ensure the schema migrations are applied before we read,
    # so older DBs gain the reviewed_at / review_revision columns.
    from .historical_findings_db import HistoricalFindingsDB

    HistoricalFindingsDB(db_path).close()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.execute(
        "SELECT * FROM findings WHERE campaign_session_id = ? ORDER BY discovered_at",
        (session_id,),
    )
    findings: list[dict] = []
    repo_url = ""
    for row in cur:
        d = dict(row)
        d["verified"] = bool(d.get("verified", 0))
        repo_url = d.get("repo_url") or repo_url
        d.pop("discovered_at", None)
        d.pop("campaign_session_id", None)
        findings.append(d)
    conn.close()
    return findings, repo_url


async def _reverify_findings(
    findings: list[dict],
    repo_path: Path,
    cli_config_section: dict | None,
) -> tuple[list[dict], list[dict]]:
    """Run the reviewer over ``findings`` using the configured LLM provider.

    Serial execution: one finding at a time. The two-layer retry strategy
    (per-finding attempts + outer multi-pass) handles transient Ollama
    or network blips without losing findings.
    """
    from acuario.providers.env import resolve_llm_endpoint
    from acuario.providers.manager import ProviderManager
    from acuario.scanner.validator import Validator, apply_validator_verdict

    endpoint = resolve_llm_endpoint(
        cli_model=None,
        cli_base_url=None,
        cli_api_key=None,
        config_provider=cli_config_section or None,
    )
    pm = ProviderManager.for_endpoint(endpoint)
    # The validator expects a native AsyncLLMClient (with `aask_text`),
    # not the LangChain-shaped object that get_llm() returns.
    try:
        reviewer_llm = pm.get_native_client("reviewer")
    except Exception:
        logger.exception("Failed to build native LLM client for reviewer task")
        reviewer_llm = None

    if reviewer_llm is None:
        logger.warning("No reviewer LLM available; skipping verification")
        return [], findings

    val = Validator(reviewer_llm, gate_threshold="suspicion")

    # Two-layer retry strategy:
    #   1. Per-finding inner retry - handles brief network blips inline
    #      (5 attempts, exponential backoff 1/2/4/8/16s - up to ~31s wait).
    #   2. Outer multi-pass - after the first pass, any finding that still
    #      did not get a verdict (i.e. exhausted its inner retries) gets
    #      re-attempted in a follow-up pass. Repeats until every finding
    #      has a verdict or a pass produces zero new verdicts (real
    #      sustained outage, not transient).
    PER_FINDING_ATTEMPTS = 5
    MAX_OUTER_PASSES = 3

    async def _validate_with_retry(finding: dict, file_content: str) -> ValidatorVerdict:
        """Inner retry - handles one finding through transient blips.

        Uses the shared retry classifier (M1) so request errors - a
        deterministic 4xx the server rejects on the same body - fail fast
        instead of burning all PER_FINDING_ATTEMPTS, while genuine transient
        connectivity blips still get retried.
        """
        last_exc: BaseException | None = None
        for attempt in range(1, PER_FINDING_ATTEMPTS + 1):
            try:
                return await val.avalidate(cast("Finding", finding), file_content=file_content)
            except BaseException as exc:
                last_exc = exc
                kind = classify_error(exc)
                retryable = kind in (KIND_RATE_LIMITED, KIND_TRANSIENT)
                if not retryable or attempt == PER_FINDING_ATTEMPTS:
                    raise
                backoff = min(2 ** (attempt - 1), 16)
                logger.info(
                    "Transient error on %s (attempt %d/%d); retry in %ds",
                    finding.get("id"),
                    attempt,
                    PER_FINDING_ATTEMPTS,
                    backoff,
                )
                await asyncio.sleep(backoff)
        if last_exc:
            raise last_exc
        raise RuntimeError("retry loop exited without value")

    # `pending` tracks findings that still don't have a verdict.
    # Findings the reviewer rejects deliberately (verdict came through but
    # said "not verified") stay rejected - we don't retry those, that's a
    # legitimate review decision.
    pending: list[dict] = list(findings)

    for pass_num in range(1, MAX_OUTER_PASSES + 1):
        total = len(pending)
        if pass_num > 1:
            logger.info(
                "Retry pass %d/%d: re-reviewing %d findings (serial)",
                pass_num,
                MAX_OUTER_PASSES,
                total,
            )
        else:
            logger.info("Pass %d: reviewing %d findings (serial)", pass_num, total)

        next_pending: list[dict] = []
        verdicts_this_pass = 0

        for i, finding in enumerate(pending, start=1):
            fid = finding.get("id", "")
            try:
                file_content = ""
                try:
                    fp = repo_path / (finding.get("file") or "")
                    if fp.is_file():
                        file_content = fp.read_text(errors="replace")
                except Exception:
                    pass

                verdict = await _validate_with_retry(finding, file_content)
                apply_validator_verdict(
                    cast("Finding", finding),
                    verdict,
                    session_id=fid + f"-pass{pass_num}",
                    discoverer_severity=finding.get("severity"),
                )
                verdicts_this_pass += 1
                logger.info(
                    "Pass %d - verdict %d/%d for %s (verified=%s)",
                    pass_num,
                    i,
                    total,
                    fid,
                    bool(finding.get("verified")),
                )
            except BaseException:
                logger.warning(
                    "Pass %d - no verdict %d/%d for %s after %d attempts; will retry in next pass",
                    pass_num,
                    i,
                    total,
                    fid,
                    PER_FINDING_ATTEMPTS,
                    exc_info=True,
                )
                next_pending.append(finding)

        logger.info(
            "Pass %d complete: %d verdicts this pass, %d still pending",
            pass_num,
            verdicts_this_pass,
            len(next_pending),
        )

        if not next_pending:
            logger.info("All findings have a verdict - retry loop done")
            break

        if verdicts_this_pass == 0:
            logger.warning(
                "Pass %d produced zero verdicts - remote service likely "
                "down. Stopping retry loop with %d still un-verdicted.",
                pass_num,
                len(next_pending),
            )
            pending = next_pending
            break

        pending = next_pending

    verified = [f for f in findings if f.get("verified")]
    rejected = [f for f in findings if not f.get("verified")]
    return verified, rejected


_EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
}


def _langs_from_findings(findings: list) -> list[str]:
    """Best-effort language set from the findings' file extensions."""
    import os

    langs = set()
    for f in findings:
        ext = os.path.splitext(str(f.get("file", "")))[1].lower()
        if ext in _EXT_LANG:
            langs.add(_EXT_LANG[ext])
    return sorted(langs)


async def _run_exploit_on_resume(
    verified: list,
    repo_path: Path,
    session_id: str,
    out_dir: Path,
    db: Path,
    cli_config_section: dict | None,
    finding_ids: list[str] | None,
) -> None:
    """Run the shared exploit stage on the re-verified findings during resume.

    Mutates ``verified`` findings in place with exploit verdicts (the reporter
    then reflects them). Builds the exploit LLM + analyzer sandbox the same way
    the full runner does. With ``finding_ids`` the exploit stage targets only
    those findings (evidence gate bypassed, see exploit_stage.select_exploit_targets).
    """
    import os

    from acuario.providers.env import resolve_llm_endpoint
    from acuario.providers.manager import ProviderManager
    from acuario.sandbox.analyzer_sandbox import AnalyzerSandbox
    from acuario.scanner.exploit_stage import run_exploit_stage

    endpoint = resolve_llm_endpoint(
        cli_model=None,
        cli_base_url=None,
        cli_api_key=None,
        config_provider=cli_config_section or None,
    )
    pm = ProviderManager.for_endpoint(endpoint)
    try:
        exploit_llm = pm.get_native_client("exploit_dev")
    except Exception:
        logger.exception("Failed to build native LLM client for exploit_dev task")
        exploit_llm = None
    if exploit_llm is None:
        logger.warning("No exploit_dev LLM available; skipping exploit stage on resume")
        return

    langs = _langs_from_findings(verified)
    exploit_mode = bool({"c", "cpp", "rust"} & set(langs))
    sandbox_manager = None
    try:
        mgr = AnalyzerSandbox(
            repo_path=str(repo_path),
            languages=langs,
            deep_agent_mode=True,
            exploit_agent_mode=exploit_mode,
        )
        mgr.build_image()
        sandbox_manager = mgr
    except Exception:
        logger.warning(
            "AnalyzerSandbox unavailable; exploit stage will use the static fallback",
            exc_info=True,
        )

    project = os.path.basename(str(repo_path).rstrip("/")) or "target"
    outcome = await run_exploit_stage(
        verified=verified,
        repo_path=str(repo_path),
        exploit_dev_llm=exploit_llm,
        sandbox_manager=sandbox_manager,
        sandbox_factory=None,
        findings_pool=None,
        session_id=session_id,
        budget_band="standard",
        output_dir=str(out_dir),
        project_name=project,
        enable_sandbox_snapshots=True,
        enable_ptrace_monitor=True,
        exploit_compose=True,
        historical_db_path=db,
        persist_to_db=True,
        finding_ids=finding_ids,
    )
    logger.info(
        "[exploit] resume exploit stage complete: eligible=%d attempted=%d "
        "forced_below_gate=%d exploited=%d",
        outcome.eligible_count,
        outcome.attempted,
        outcome.forced_below_gate,
        len(outcome.exploited),
    )


def resume_session(
    session_id: str,
    *,
    repo_path: Path | str | None = None,
    output_dir: Path | str | None = None,
    db_path: Path | str | None = None,
    verify: bool = True,
    force_review: bool = False,
    formats: list[str] | None = None,
    cli_config_section: dict | None = None,
    run_exploit: bool = False,
    finding_ids: list[str] | None = None,
) -> dict[str, str]:
    """Resume a crashed audit session and write its reports.

    Args:
        session_id: Session id of the crashed run (e.g. ``sh-718e5885``).
        repo_path: Path to the audited repository (used only to read
            file content for the reviewer pass). Defaults to cwd.
        output_dir: Where to write reports. Defaults to
            ``~/.acuario/results/scanner/``.
        db_path: Override path to the historical-findings DB.
        verify: If True (default), re-run the reviewer pass before
            rendering. If False, render the raw analyzer output as-is
            (faster but flags every finding as unverified).
        formats: Report formats to write (default: SARIF + Markdown + JSON).
        cli_config_section: The active provider section from
            ``~/.acuario/config.yaml``, only needed when ``verify=True``.

    Returns:
        Mapping of format → output file path, including the manifest.
    """
    from acuario.core.config import acuario_home
    from acuario.scanner.reporter import write_scanner_report

    db = Path(db_path) if db_path else acuario_home() / "scanner" / "historical_findings.db"
    if not db.exists():
        raise FileNotFoundError(f"Historical-findings DB not found at {db}")

    if output_dir:
        out_dir = Path(output_dir)
    else:
        # Resolve the audit's own results dir the same way audit/inspect/eval do,
        # so `report` lands beside the audit's artifacts instead of a separate
        # ~/.acuario/results copy. Prefer the recorded session path (works from any
        # cwd); the recorded path is the session dir (…/scanner/<id>) and the
        # reporter re-appends <id>, so hand back its parent. Otherwise fall back to
        # the default results base - cwd-relative (./results/scanner) in a dev
        # checkout, ~/.acuario/results on an installed copy - exactly as `audit`.
        from acuario.core.config import default_results_dir
        from acuario.scanner.session_index import lookup_session_path

        recorded = lookup_session_path(session_id)
        out_dir = (
            recorded.parent
            if recorded is not None
            else Path(default_results_dir("scanner"))
        )
    out_dir.mkdir(parents=True, exist_ok=True)

    repo_path = Path(repo_path or ".").resolve()

    logger.info("Loading findings for session %s from %s", session_id, db)
    findings, repo_url = load_findings_from_db(db, session_id)
    if not findings:
        raise ValueError(f"No findings found for session {session_id}")
    logger.info("Loaded %d findings (repo=%s)", len(findings), repo_url or "unknown")

    verified: list[dict]
    rejected: list[dict]
    if verify:
        # Idempotent resume: only re-review findings that have NOT
        # reached a verdict yet (reviewed_at IS NULL). Findings the
        # reviewer already decided - positive OR negative - are left
        # alone. This is what stops the dice-rolling problem where
        # repeated --resume calls kept flipping borderline findings
        # to verified=True. Use --force-review to override.
        if force_review:
            to_review = list(findings)
            already_judged = []
            logger.info(
                "Force-review mode: re-reviewing all %d findings "
                "(this WILL overwrite prior verdicts)",
                len(to_review),
            )
        else:
            to_review = [f for f in findings if f.get("reviewed_at") is None]
            already_judged = [f for f in findings if f.get("reviewed_at") is not None]
            if already_judged:
                logger.info(
                    "%d findings have a verdict from a prior run "
                    "(skipping); reviewing %d still un-judged",
                    len(already_judged),
                    len(to_review),
                )
            else:
                logger.info(
                    "Re-running reviewer on %d findings (LLM-bound)",
                    len(to_review),
                )
        verified_new, rejected_new = asyncio.run(
            _reverify_findings(to_review, repo_path, cli_config_section)
        )
        # Combine fresh verdicts with the already-judged findings.
        # The already-judged group is split by their saved verdict.
        verified = verified_new + [f for f in already_judged if f.get("verified")]
        rejected = rejected_new + [f for f in already_judged if not f.get("verified")]
        logger.info(
            "Verification complete: %d verified, %d rejected",
            len(verified),
            len(rejected),
        )
        # Stamp every freshly-judged finding (positive OR negative).
        # mark_reviewed() bumps review_revision and sets reviewed_at,
        # so the next --resume run will skip these unless --force-review
        # is passed. Findings in `already_judged` were skipped this run,
        # so we don't re-stamp them.
        from .historical_findings_db import HistoricalFindingsDB

        hdb = HistoricalFindingsDB(db)
        try:
            for f in verified_new:
                hdb.mark_reviewed(
                    f.get("id", ""), verified=True, evidence_level=f.get("evidence_level")
                )
            for f in rejected_new:
                hdb.mark_reviewed(
                    f.get("id", ""), verified=False, evidence_level=f.get("evidence_level")
                )
        finally:
            hdb.close()
    else:
        logger.info(
            "Skipping reviewer pass (use --verify to re-run it). "
            "Findings will keep their original analyzer status."
        )
        verified = [f for f in findings if f.get("verified")]
        rejected = [f for f in findings if not f.get("verified")]

    # Optional exploit stage: re-run the exploit-development stage on the
    # re-verified findings (or a named subset), skipping the multi-hour analyze.
    # The reviewer pass above re-derives evidence, so the automatic gate sees
    # fresh eligibility; a named --findings subset bypasses the gate with a warning.
    if run_exploit:
        try:
            asyncio.run(
                _run_exploit_on_resume(
                    verified,
                    repo_path,
                    session_id,
                    out_dir,
                    db,
                    cli_config_section,
                    finding_ids,
                )
            )
        except Exception:
            logger.warning("Exploit stage on resume failed (continuing to report)", exc_info=True)

    # mark same-locus duplicates before the report, exactly as the full
    # run does, so a resumed report and its counts match a fresh run.
    from acuario.scanner.dedup import annotate_duplicate_loci

    annotate_duplicate_loci(cast("list[Finding]", findings))

    formats = formats or ["sarif", "markdown", "json", "pdf"]
    paths = write_scanner_report(
        output_dir=str(out_dir),
        session_id=session_id,
        repo_url=repo_url or "(unknown)",
        findings=cast("list[Finding]", findings),
        verified_findings=cast("list[Finding]", verified),
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},  # unknown post-recovery
        formats=formats,
    )
    return paths
