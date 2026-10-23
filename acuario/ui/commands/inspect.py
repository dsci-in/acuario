"""Inspect subcommand - interactive REPL for chatting with a past audit session.

Usage
-----
    acuario inspect <session-id>

Commands (typed at the ``>`` prompt)
-------------------------------------
    list [--severity critical|high|medium|low]
        List findings in the session, optionally filtered by severity.

    show <finding-id>
        Show full detail for one finding (description, code snippet, evidence).

    why <finding-id>
        Ask the LLM to explain the reasoning chain behind a finding.

    skeptic <finding-id>
        Show the skeptic's verdict for this finding - was it accepted or refuted?
        If refuted findings are available in skeptic_refuted.jsonl, surface them.

    critic <session-id>
        Show the reflective critic's low-confidence leads for the session.

    orchestrator <session-id>
        Show the cross-file plans the orchestrator emitted and which led to findings.

    debate <finding-id>
        Replay the analyzer↔skeptic debate for a refuted finding.

    fix <finding-id>
        Ask the LLM to emit a unified-diff patch suggestion.
        **Read-only**: the diff is printed to screen only, never applied to source.

    exploit <finding-id>
        Print the exploit transcript and PoC string (if --exploit was used in the audit).

    related <finding-id>
        Show sibling findings from the same findings-pool cluster.

    help
        Print this help text.

    quit / exit / q
        Exit the inspector.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from rich.console import Group
from rich.constrain import Constrain
from rich.text import Text

from acuario.findings.types import canonical_findings
from acuario.ui import theme

#: A finding detail view is capped to this column width so it stays readable and
#: does not sprawl edge-to-edge on a wide terminal.
_DETAIL_WIDTH = 100
#: The REPL `help` table is capped to this width for the same reason.
_HELP_WIDTH = 96

PROMPT = "\n> "
INDENT = "  "

# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------


_INSPECT_EPILOG = """\
Opens an interactive REPL over a finished audit. Inside it:
  triage / list          findings, ranked or filtered
  show <n|id>            full detail for a finding      why / fix   LLM explanations
  .. (or 0)             go up one level                 q           quit
A session whose results directory is gone is loaded from the findings DB.
Type `help` in the REPL for the full command glossary.
"""


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "inspect",
        help="Interactive REPL - chat with a past audit session",
        epilog=_INSPECT_EPILOG,
    )
    parser.add_argument(
        "session_id",
        help="Audit session id (see `acuario history` for available ids)",
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Override the results directory (default: auto-detected)",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle(cli, args):
    # Standalone entry: there is no hub above, so back and quit both just exit.
    open_session(cli, args.session_id, args.results_dir, from_hub=False)


def _resolve_results_dir(results_dir: str | None) -> str:
    if results_dir is not None:
        return results_dir
    try:
        from acuario.core.config import default_results_dir

        return default_results_dir("scanner")
    except Exception:
        return "./results/scanner"


def _load_findings_from_db(session_id: str) -> list[dict] | None:
    """Findings for a session read straight from ``historical_findings.db``.

    Lets the inspector open a session whose on-disk results directory is gone
    (cleaned up, or written elsewhere with --output-dir) - the DB retains every
    finding.  Returns the finding dicts, or None when the DB or session is
    absent.  Columns map 1:1 to the finding shape the views expect.
    """
    import sqlite3

    from acuario.core.config import acuario_home

    db_path = acuario_home() / "scanner" / "historical_findings.db"
    if not db_path.exists():
        return None
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE campaign_session_id = ? "
            "ORDER BY severity, file, line_number",
            (session_id,),
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not rows:
        return None
    findings: list[dict] = []
    for r in rows:
        d = {k: r[k] for k in r.keys()}
        d["verified"] = bool(r["verified"])  # sqlite stores 0/1
        findings.append(d)
    return findings


def open_session(
    cli, session_id: str, results_dir: str | None = None, *, from_hub: bool = False
) -> str:
    """Resolve and run the inspector for one session.

    Returns the REPL's navigation signal: ``"quit"`` (exit the tool) or
    ``"back"`` (pop up to the caller).  Prefers the on-disk results directory
    (full artifacts); when it is gone, falls back to the findings in the
    historical DB so the session is still browsable; only when neither exists
    does it report back so a hub (``acuario history``) can re-list.
    """
    # Resolution order: an explicit --results-dir, else the path recorded at
    # audit time (works from any cwd), else the cwd default, else the DB.
    if results_dir is not None:
        session_dir = Path(results_dir) / session_id
    else:
        from acuario.scanner.session_index import lookup_session_path

        recorded = lookup_session_path(session_id)
        session_dir = recorded if recorded is not None else Path(_resolve_results_dir(None)) / session_id

    db_findings = None
    if not session_dir.exists():
        db_findings = _load_findings_from_db(session_id)
        if db_findings is None:
            msg = theme.error("No inspectable results for session ")
            msg.append(str(session_id), style="ident")
            cli.console.print(msg)
            cli.console.print(
                theme.muted(f"Looked in {session_dir} and the findings DB; nothing found.")
            )
            return "back"

    inspector = AuditInspector(
        session_id=session_id,
        session_dir=session_dir,
        cli=cli,
        from_hub=from_hub,
        db_findings=db_findings,
    )
    return inspector.run()


# ---------------------------------------------------------------------------
# Inspector class
# ---------------------------------------------------------------------------


class AuditInspector:
    """Interactive REPL over a completed audit session's artifacts."""

    def __init__(
        self,
        session_id: str,
        session_dir: Path,
        cli: Any,
        *,
        from_hub: bool = False,
        db_findings: list[dict] | None = None,
    ):
        self.session_id = session_id
        self.session_dir = session_dir
        self.cli = cli
        # True when launched from the `acuario history` hub: back (`..`/`0`) pops
        # up to the session list; standalone, there is no hub so it just exits.
        self._from_hub = from_hub
        # Findings sourced from the historical DB when no results dir exists on
        # disk - the session is still browsable (list/triage/show), while the
        # lab artifacts (skeptic/critic/transcripts) degrade to "not recorded".
        self._db_findings = db_findings
        self._findings: list[dict] = []
        self._findings_by_id: dict[str, dict] = {}
        self._skeptic_refuted: list[dict] = []
        self._skeptic_log_by_id: dict[str, dict] = {}
        self._critic_leads: list[dict] = []
        self._orchestrator_plans: list[dict] = []
        self._loaded = False
        # Selection context: the current finding, and the last listing shown
        # (so a finding can be picked by row number and acted on without an id).
        self._current: dict | None = None
        self._last_list: list[dict] = []
        # Command dispatch table (name -> handler taking the arg list).
        self._handlers: dict[str, Any] = {
            "help": self._cmd_help,
            "list": self._cmd_list,
            "show": self._cmd_show,
            "why": self._cmd_why,
            "skeptic": self._cmd_skeptic,
            "critic": self._cmd_critic,
            "orchestrator": self._cmd_orchestrator,
            "debate": self._cmd_debate,
            "fix": self._cmd_fix,
            "exploit": self._cmd_exploit,
            "related": self._cmd_related,
            "next": self._cmd_next,
            "prev": self._cmd_prev,
            "n": self._cmd_next,
            "p": self._cmd_prev,
            "triage": self._cmd_triage,
            "top": self._cmd_triage,
        }

    # ------------------------------------------------------------------
    # REPL loop
    # ------------------------------------------------------------------

    def run(self) -> str:
        """Run the REPL and return a navigation signal: ``"quit"`` (exit the
        tool) or ``"back"`` (pop up to the hub)."""
        self._load_artifacts()
        self.cli.console.print()
        # Breadcrumb: history ▸ <session> when launched from the hub.
        crumb = Text()
        if self._from_hub:
            crumb.append("history ", style="muted")
            crumb.append(theme.glyph("arrow", console=self.cli.console), style="faint")
            crumb.append(" ", style="muted")
        crumb.append("inspect", style="accent.strong")
        crumb.append("  session ", style="muted")
        crumb.append(self.session_id, style="ident")
        self.cli.console.print(crumb)
        verified_n = sum(1 for f in self._findings if f.get("verified"))
        src = " · from history DB" if self._db_findings is not None else ""
        noun = "finding" if len(self._findings) == 1 else "findings"
        self.cli.console.print(
            theme.muted(f"  {len(self._findings)} {noun} loaded ({verified_n} verified){src}")
        )
        if self._db_findings is not None:
            self.cli.console.print(
                theme.muted("  (results directory gone; lab artifacts unavailable; findings are intact)")
            )
        self.cli.console.print(self._hint_line())

        while True:
            try:
                raw = self._read_line()
            except (EOFError, KeyboardInterrupt):
                self.cli.console.print()
                self.cli.console.print(theme.muted("Exiting inspector."))
                return "quit"

            line = raw.strip()
            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()
            rest = parts[1:]

            if cmd in ("quit", "exit", "q"):
                if not self._from_hub:
                    self.cli.console.print(theme.muted("Exiting inspector."))
                return "quit"

            # Universal up-one-level: a selected finding pops to the session top;
            # otherwise pop to the hub (or exit, standalone).
            if cmd in ("back", "..", "0"):
                if self._current is not None:
                    self._current = None
                    self.cli.console.print(theme.muted("← back to the session"))
                    continue
                return "back"

            try:
                handler = self._handlers.get(cmd)
                if handler is not None:
                    handler(rest)
                    continue

                # Bare token: a row number or an id/prefix means `show <token>`
                # (keyword commands are matched first, so they are never shadowed).
                if not rest and self._candidates(parts[0]):
                    self._cmd_show([parts[0]])
                    continue
            except Exception as exc:  # noqa: BLE001
                # A single command (or a render) must never tear down the whole
                # interactive session - degrade to a message and keep going.
                self.cli.console.print(
                    f"[danger]command failed:[/danger] {theme.escape(str(exc))}"
                )
                continue

            # Built as a Text (not markup): the typed command is free input, so a
            # value like `[/]` must render verbatim instead of crashing the parser
            # and tearing down the whole session (this print is outside the guard).
            unknown = theme.error("Unknown command ")
            unknown.append(repr(cmd))
            unknown.append(". Type ", style="muted")
            unknown.append("help", style="accent")
            unknown.append(" for available commands", style="muted")
            self.cli.console.print(unknown)

    def _hint_line(self) -> Text:
        """The one-line command hint under the header, including the back/quit
        navigation affordance so there is always a visible way up and out."""
        t = theme.muted("  ")
        for label in ("triage", "help"):
            t.append(label, style="accent")
            t.append(" · ", style="faint")
        if self._from_hub:
            t.append("..", style="accent")
            t.append(" back · ", style="muted")
        t.append("q", style="accent")
        t.append(" quit", style="muted")
        return t

    def _prompt_str(self) -> str:
        """The input prompt, reflecting the current selection if one is set."""
        if self._current is not None:
            fid = self._current.get("id", "?")
            sev = (self._current.get("severity") or "?").upper()[:4]
            return f"\n[{sev} {fid}] > "
        return PROMPT

    def _read_line(self) -> str:
        """Read one line from stdin, using prompt_toolkit if available."""
        prompt_text = self._prompt_str()
        try:
            from prompt_toolkit import prompt as _pt_prompt

            return _pt_prompt(prompt_text)
        except ImportError:
            sys.stdout.write(prompt_text)
            sys.stdout.flush()
            return sys.stdin.readline()

    # ------------------------------------------------------------------
    # Artifact loading
    # ------------------------------------------------------------------

    def _load_artifacts(self) -> None:
        if self._loaded:
            return

        # DB-backed session (no results dir on disk): use the findings pulled from
        # historical_findings.db and skip the file-based artifact loading; the lab
        # streams stay empty, so lab commands report "nothing recorded".
        if self._db_findings is not None:
            self._findings = self._db_findings
            self._findings_by_id = {f.get("id", ""): f for f in self._findings if f.get("id")}
            self._loaded = True
            return

        # Primary findings (findings.json)
        findings_path = self.session_dir / "findings.json"
        if findings_path.exists():
            try:
                raw = json.loads(findings_path.read_text())
                if isinstance(raw, list):
                    self._findings = raw
                elif isinstance(raw, dict) and "findings" in raw:
                    self._findings = raw["findings"]
            except Exception:
                pass

        # Fall back to findings_pool.jsonl
        if not self._findings:
            pool_path = self.session_dir / "findings_pool.jsonl"
            if pool_path.exists():
                try:
                    for line in pool_path.read_text().splitlines():
                        line = line.strip()
                        if line:
                            self._findings.append(json.loads(line))
                except Exception:
                    pass

        # Variant-loop entries are pattern-match suspicions the 4-axis reviewer
        # rejects at ~100% (a default-OFF stage; "0/97 historical verified yield").
        # They are ingested into neither historical_findings.db nor `history`, and
        # ~2/3 point at the scanner's own results artifacts (findings_pool.jsonl /
        # rejected_findings.jsonl) instead of real source. Drop them so this on-disk
        # path shows the same canonical finding set as the DB-backed path.
        self._findings = canonical_findings(self._findings)

        self._findings_by_id = {f.get("id", ""): f for f in self._findings if f.get("id")}

        # Skeptic-refuted findings
        refuted_path = self.session_dir / "skeptic_refuted.jsonl"
        if refuted_path.exists():
            try:
                for line in refuted_path.read_text().splitlines():
                    line = line.strip()
                    if line:
                        self._skeptic_refuted.append(json.loads(line))
            except Exception:
                pass

        # Skeptic verdicts (skeptic_log.jsonl: one reasoned entry per judged finding)
        skeptic_log = self.session_dir / "skeptic_log.jsonl"
        if skeptic_log.exists():
            try:
                for line in skeptic_log.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    fid = entry.get("finding_id")
                    if fid:
                        self._skeptic_log_by_id[fid] = entry
            except Exception:
                pass

        # Critic leads (tagged discovered_by="critic" in findings)
        self._critic_leads = [f for f in self._findings if f.get("discovered_by") == "critic"]

        # Orchestrator plans (orchestrator_log.jsonl; the manifest field is legacy/absent)
        orch_log = self.session_dir / "orchestrator_log.jsonl"
        if orch_log.exists():
            try:
                for line in orch_log.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    self._orchestrator_plans.extend(entry.get("plans", []))
            except Exception:
                pass
        if not self._orchestrator_plans:
            manifest_path = self.session_dir / "manifest.json"
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text())
                    self._orchestrator_plans = manifest.get("orchestrator_plans", [])
                except Exception:
                    pass

        self._loaded = True

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    #: REPL command reference, grouped. Command syntax carries brackets, so every
    #: cell is field-wrapped (never markup-parsed) when the table is built.
    _HELP_GROUPS = (
        ("Browse", (
            ("triage [N | all]", "Findings ranked by priority (severity, evidence, confidence); top 15 by default. Alias: top."),
            ("list [--severity ...] [--sort ...] [--all]", "List findings (top 25; --all for every row). --plain for grep-friendly rows, --ids-only for one id per line."),
            ("show <id>", "Full detail and validation for a finding (also sets the selection)."),
            ("<row#> | <id-fragment>", "Shortcut for show: a number from the last list, or any part of an id."),
            ("next | prev  (n | p)", "Move the selection through the last list."),
            ("related <id>", "Sibling findings from the same cluster, or same file + CWE."),
        )),
        ("Explain (calls the LLM)", (
            ("why <id>", "Explanation of the reasoning chain, rendered as Markdown."),
            ("fix <id>", "Unified-diff suggestion. Read-only; never writes to source."),
        )),
        ("Lab", (
            ("skeptic <id>", "The skeptic gate verdict (accepted / refuted) and its reasoning."),
            ("debate <id>", "Replay the analyzer / skeptic debate for a refuted finding."),
            ("critic", "Reflective-critic low-confidence leads."),
            ("orchestrator", "Cross-file hunt plans the orchestrator emitted."),
            ("exploit <id>", "Exploit transcript and PoC string, if available."),
        )),
        ("Navigate", (
            (".. | 0 | back", "Up one level: clear the selected finding, else return to the history hub."),
            ("help", "Show this table."),
            ("q | quit | exit", "Leave the inspector."),
        )),
    )

    def _cmd_help(self, args: list[str] | None = None) -> None:
        console = self.cli.console
        table = theme.framed_table(["COMMAND", "WHAT IT DOES"], title="Inspector commands", kind="info")
        table.columns[0].style = "accent"
        table.columns[0].no_wrap = True
        for i, (group, cmds) in enumerate(self._HELP_GROUPS):
            if i:
                table.add_row(theme.field(""), theme.field(""))  # blank spacer between groups
            table.add_row(theme.field(group, style="accent.strong"), theme.field(""))
            for cmd, desc in cmds:
                table.add_row(theme.field("  " + cmd, style="ident"), theme.field(desc, style="muted"))
        console.print()
        console.print(Constrain(table, min(console.width, _HELP_WIDTH)))

    def _cmd_list(self, args: list[str]) -> None:
        severity_filter: str | None = None
        plain = False
        ids_only = False
        show_all = False
        sort_mode = "severity"
        it = iter(args)
        for a in it:
            if a == "--severity":
                severity_filter = next(it, None)
            elif a == "--plain":
                plain = True
            elif a == "--ids-only":
                ids_only = True
            elif a == "--all":
                show_all = True
            elif a == "--sort":
                sort_mode = next(it, None) or "severity"

        findings = self._findings
        if severity_filter:
            # Validate the *user-supplied* filter against the known labels + aliases
            # first: theme.normalize_severity folds anything unknown to "info" (right
            # for rendering a finding's own severity, wrong for a filter - it would
            # silently turn a typo like `--severity criticl` into `--severity info`).
            key = str(severity_filter).strip().lower()
            if key not in theme.SEVERITIES and key not in theme._SEVERITY_ALIASES:
                self.cli.console.print(
                    theme.error(
                        f"unknown severity {severity_filter!r} "
                        f"(try: {', '.join(theme.SEVERITY_ORDER)})"
                    )
                )
                return
            # Normalize both sides (via the kit) so the filter agrees with the
            # canonicalized severity labels shown in the table / plain output -
            # e.g. `--severity crit` matches findings recorded as "critical".
            want = theme.normalize_severity(severity_filter)
            findings = [f for f in findings if theme.normalize_severity(f.get("severity")) == want]

        if not findings:
            self.cli.console.print(theme.muted("No findings match."))
            return

        if sort_mode == "rank":
            ordered = sorted(findings, key=_rank_score, reverse=True)
        else:
            ordered = sorted(findings, key=lambda x: _severity_rank(x.get("severity", "")))
        self._set_last_list(ordered)

        if ids_only:
            for f in ordered:
                self.cli.console.print(theme.field(f.get("id", "?") or "?"))
            return

        if plain:
            for i, f in enumerate(ordered, 1):
                spec = theme.resolve_severity(f.get("severity", ""))
                row = Text()
                row.append(f"  {i:>3}  ", style="faint")
                row.append(f"[{spec.label}]", style=spec.style)  # literal brackets, themed
                if f.get("verified"):
                    row.append(" ✓", style="success")
                if f.get("discovered_by") == "critic":
                    row.append(" (critic)", style="warn")
                row.append("  ")
                row.append(f.get("id", "?") or "?", style="ident")
                row.append(f"  {f.get('file', '?')}:{f.get('line_number', '?')}", style="path")
                row.append(f"  {f.get('cwe', '') or ''}  {(f.get('description', '') or '')[:60]}")
                self.cli.console.print(row)
            return

        # Cap the framed table so a 189-finding session doesn't flood the screen
        # (triage already caps to 15); --plain / --ids-only above stay uncapped for
        # piping, and _set_last_list(ordered) keeps the FULL list so `show 40` /
        # next / prev still resolve past the 25 shown rows.
        shown = ordered if show_all else ordered[:25]
        caption = f"{len(ordered)} finding(s)"
        if severity_filter:
            caption += f" · {theme.normalize_severity(severity_filter)}"
        self.cli.console.print(self._findings_table(shown, title="Findings", caption=caption))
        self.cli.console.print(self._flag_legend())
        if len(shown) < len(ordered):
            hint = Text(f"  +{len(ordered) - len(shown)} more · ", style="muted")
            hint.append("list --all", style="ident")
            hint.append(" · ", style="muted")
            hint.append("list --severity <sev>", style="ident")
            self.cli.console.print(hint)

    def _findings_table(
        self, findings: list[dict], *, title: str = "Findings", caption: str | None = None
    ) -> Any:
        # Framed "destination" table (the surface you land on and scan): the
        # flags cell is built from constants and every free-text cell is wrapped
        # in theme.field / severity_cell, so a bracket in an id / path /
        # description renders verbatim instead of being markup-parsed (which would
        # crash the render and, via the REPL loop, the whole session).  Glyphs are
        # routed through theme.glyph so they ASCII-fold on non-UTF-8 terminals.
        console = self.cli.console
        table = theme.framed_table(
            ["#", "SEV", "", "ID", "FILE:LINE", "CWE", "DESC"],
            title=title,
            caption=caption,
            kind="info",
        )
        table.columns[0].justify = "right"
        table.columns[0].style = "faint"
        table.columns[2].no_wrap = True
        table.columns[3].style = "ident"
        table.columns[4].style = "path"
        # DESC (the only long column) is the one allowed to wrap; the fixed columns
        # keep their natural width.  On a wide terminal each finding is one line; on
        # a narrow one DESC wraps rather than crushing the severity badge / id.
        for i, f in enumerate(findings, 1):
            flags = Text()
            if f.get("verified"):
                flags.append(theme.glyph("accept", console=console), style="success")
            if f.get("discovered_by") == "critic":
                flags.append("c", style="warn")
            if _efield(f, "exploit_transcript_path"):
                flags.append(theme.glyph("exploit", console=console), style="sev.critical")
            table.add_row(
                theme.field(str(i)),
                theme.severity_cell(f.get("severity", ""), console=console),
                flags,
                theme.field(f.get("id", "?") or "?"),
                theme.field(f"{f.get('file', '?')}:{f.get('line_number', '?')}", style="path"),
                theme.field((str(f.get("cwe") or "").split(":", 1)[0])[:12]),
                theme.field(_truncate_desc(f.get("description", "") or "", 60)),
            )
        return table

    def _flag_legend(self) -> Text:
        """One-line key for the flag column under the triage / list tables."""
        console = self.cli.console
        legend = Text("  ")
        legend.append(theme.glyph("accept", console=console), style="success")
        legend.append(" verified", style="muted")
        legend.append("    ")
        legend.append(theme.glyph("exploit", console=console), style="sev.critical")
        legend.append(" exploited", style="muted")
        legend.append("    ")
        legend.append("c", style="warn")
        legend.append(" critic", style="muted")
        return legend

    def _cmd_triage(self, args: list[str] | None = None) -> None:
        if not self._findings:
            self.cli.console.print(theme.muted("No findings loaded."))
            return
        ranked = sorted(self._findings, key=_rank_score, reverse=True)
        limit = 15
        if args:
            if args[0] == "all":
                limit = len(ranked)
            elif args[0].isdigit():
                limit = max(1, int(args[0]))
        top = ranked[:limit]
        self._set_last_list(top)
        caption = f"top {len(top)} of {len(ranked)} by priority (severity, evidence, confidence)"
        self.cli.console.print(self._findings_table(top, title="Triage", caption=caption))
        self.cli.console.print(self._flag_legend())

    def _cmd_show(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        # Finding free text (description, snippet, evidence, even the id) is
        # attacker/LLM-influenced and must never be parsed as Rich markup - a
        # route like `[/admin]` or a regex `[/x]` would otherwise crash the render
        # (and, via the REPL loop, the whole session).  It is carried only through
        # the Text-based kit helpers (kv_table / section_rule / field), which never
        # parse markup, so every value renders verbatim.
        console = self.cli.console
        fid = finding.get("id", "?")
        header = theme.accent("Finding ")
        header.append(str(fid), style="ident")

        body: list[Any] = [header]
        rows: list[tuple[str, Any]] = []
        for key in (
            "severity",
            "cwe",
            "file",
            "line_number",
            "evidence_level",
            "verified",
        ):
            val = finding.get(key)
            if val is None:
                continue
            # Severity reads as the CVD-safe badge (shape + LABEL + colour) used
            # everywhere else; verified reads as a glyph, not a raw Python bool.
            if key == "severity":
                cell = theme.severity_badge(str(val), console=console)
            elif key == "verified":
                cell = theme.line("✓ yes", style="success") if val else theme.line("✗ no", style="danger")
            else:
                cell = theme.field(str(val))
            rows.append((key, cell))
        if rows:
            body.append(theme.kv_table(rows))

        description = finding.get("description")
        if description is not None:
            body.append(theme.section_rule("description"))
            body.append(theme.field(str(description)))

        snippet = finding.get("code_snippet") or finding.get("snippet")
        if snippet:
            body.append(theme.section_rule("code snippet"))
            body.append(theme.field(str(snippet), style="muted"))

        evidence = finding.get("evidence_details") or finding.get("crash_evidence")
        if evidence:
            body.append(theme.section_rule("evidence"))
            body.append(theme.field(str(evidence)[:500], style="muted"))

        body.extend(self._validation_renderables(finding))

        # Cap the detail to a readable column so it does not sprawl edge-to-edge
        # on a wide terminal (long section rules, over-wide description lines).
        console.print()
        console.print(Constrain(Group(*body), min(console.width, _DETAIL_WIDTH)))

    def _validation_renderables(self, finding: dict) -> list[Any]:
        """The verifier debate / validator axes block as renderables (so the
        caller can print them inside the width-capped detail group)."""
        console = self.cli.console
        pro = finding.get("verifier_pro_argument")
        counter = finding.get("verifier_counter_argument")
        tie = finding.get("verifier_tie_breaker")
        axes = _efield(finding, "validator_axes")

        out: list[Any] = [theme.section_rule("validation")]

        if not (pro or counter or tie or axes):
            # Unvalidated finding (~half of them): surface whatever signal exists.
            bits = []
            sk = self._skeptic_log_by_id.get(finding.get("id", ""))
            if sk and sk.get("verdict"):
                bits.append(f"skeptic={sk['verdict']}")
            if finding.get("evidence_level"):
                bits.append(f"evidence={finding['evidence_level']}")
            note = f" ({', '.join(bits)})" if bits else ""
            out.append(theme.muted(f"  not validated{note}"))
            return out

        # Labels are constants; the pro/counter/tie-breaker bodies and the axis
        # rationales are LLM free text (they routinely cite bracketed routes like
        # `[/login]`), so each is appended to a Text and never markup-parsed.  The
        # pass/fail marks route through theme.glyph so they ASCII-fold on a
        # non-UTF-8 terminal.
        for label, value, style in (
            ("pro: ", pro, "success"),
            ("counter: ", counter, "warn"),
            ("tie-breaker: ", tie, "accent"),
        ):
            if value:
                row = Text("  ")
                row.append(label, style=style)
                row.append(str(value))
                out.append(row)
        if isinstance(axes, dict):
            for axis, detail in axes.items():
                if not isinstance(detail, dict):
                    continue
                conf = detail.get("confidence", "")
                rationale = (detail.get("rationale") or "")[:200]
                row = Text("  ")
                if detail.get("passed"):
                    row.append(theme.glyph("accept", console=console) + " ", style="success")
                else:
                    row.append(theme.glyph("refute", console=console) + " ", style="danger")
                row.append(str(axis), style="ident")
                row.append(f" ({conf}): ")
                row.append(str(rationale))
                out.append(row)
        return out

    def _cmd_why(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        llm = self._get_llm()
        if llm is None:
            return

        fid = finding.get("id", "?")

        trajectory_text = self._load_trajectory(fid)
        prompt = _build_why_prompt(finding, trajectory_text)
        try:
            text = self._ask_llm(
                llm,
                "You are a security analysis assistant.",
                prompt,
                status=f"Explaining {fid}…",
            )
        except Exception as exc:
            err = theme.error("LLM error: ")
            err.append(str(exc))
            self.cli.console.print(err)
            return

        from rich.markdown import Markdown

        # Frame the LLM explanation in a themed panel.  The Markdown renderable
        # carries the rich formatting; the title is a Text (never markup-parsed),
        # so a bracket in the finding id renders verbatim.
        console = self.cli.console
        console.print()
        panel = theme.panel(Markdown(text), title=f"Why {fid}", kind="info")
        console.print(Constrain(panel, min(console.width, _DETAIL_WIDTH)))

    def _cmd_skeptic(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        fid = finding.get("id", "?")

        # Primary source: skeptic_log.jsonl - a reasoned verdict per judged finding.
        entry = self._skeptic_log_by_id.get(fid)
        if entry:
            verdict = (entry.get("verdict") or "").lower()
            reasoning = entry.get("reasoning") or "(no reasoning recorded)"
            sfid = theme.escape(str(fid))
            if verdict in ("refuted", "accepted"):
                # theme.success / theme.error already prepend the ✓ / ✗ mark.
                style = theme.error if verdict == "refuted" else theme.success
                line = style(f"Skeptic {verdict} ")
                line.append(str(fid), style="ident")  # raw id: Text.append never markup-parses
                self.cli.console.print()
                self.cli.console.print(line)
            else:
                self.cli.console.print(
                    f"\n[warn]~ Skeptic {theme.escape(verdict or 'verdict')}[/warn] {sfid}"
                )
            self.cli.console.print(
                f"  [dim]Reasoning:[/dim] {theme.escape(str(reasoning))}",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )
            return

        # Fallback: explicit refutations file (skeptic_refuted.jsonl).
        refuted_entry = next(
            (r for r in self._skeptic_refuted if r.get("id") == fid or r.get("finding_id") == fid),
            None,
        )
        if refuted_entry:
            reason = (
                refuted_entry.get("skeptic_reasoning")
                or refuted_entry.get("refutation_reason")
                or refuted_entry.get("reason", "no reason recorded")
            )
            code_ref = refuted_entry.get("code_reference", "")
            self.cli.console.print(
                f"\n[danger]✗ Skeptic refuted[/danger] {theme.escape(str(fid))}"
                f"\n  Reason: {theme.escape(str(reason))}",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )
            if code_ref:
                self.cli.console.print(f"  Code reference: {theme.escape(str(code_ref))}")
            return

        self.cli.console.print()
        ok = theme.success("Skeptic accepted ")  # theme.success already prepends ✓
        ok.append(str(fid), style="ident")
        self.cli.console.print(ok)
        self.cli.console.print(
            theme.muted("  (No skeptic log entry recorded; finding entered the pool.)")
        )

    def _cmd_critic(self, args: list[str] | None = None) -> None:
        if not self._critic_leads:
            self.cli.console.print(
                theme.muted(
                    "No reflective-critic leads for this session "
                    "(this run had no critic stage)."
                )
            )
            return

        caption = f"{len(self._critic_leads)} low-confidence lead(s)"
        self.cli.console.print(
            self._findings_table(
                self._critic_leads, title="Reflective critic leads", caption=caption
            )
        )

    def _cmd_orchestrator(self, args: list[str] | None = None) -> None:
        console = self.cli.console
        if not self._orchestrator_plans:
            console.print(theme.muted("No orchestrator plans recorded for this session."))
            return

        caption = f"{len(self._orchestrator_plans)} cross-file plan(s)"
        table = theme.framed_table(
            ["#", "FOCUS", "FILES", "RATIONALE", "LED TO"],
            title="Cross-file orchestrator plans",
            caption=caption,
            kind="info",
        )
        table.columns[0].justify = "right"
        table.columns[0].style = "faint"
        for i, plan in enumerate(self._orchestrator_plans, 1):
            files = plan.get("files", [])
            led_to = plan.get("findings_from_plan", [])
            table.add_row(
                theme.field(str(i)),
                theme.field(str(plan.get("hunt_focus", "") or "")),
                theme.field(", ".join(str(x) for x in files)),
                theme.field(str(plan.get("rationale", "") or "")),
                theme.field(", ".join(str(x) for x in led_to)),
            )
        console.print(Constrain(table, min(console.width, _DETAIL_WIDTH)))

    def _cmd_debate(self, args: list[str]) -> None:
        """Replay the analyzer↔skeptic debate for a refuted finding."""
        # Resolve quietly: a debated finding may have been refuted out of the main
        # list, so fall through to the debate_log lookup below instead of printing
        # a spurious "Finding not found".
        matches = self._candidates(args[0]) if args else []
        finding = matches[0] if len(matches) == 1 else None
        fid = finding.get("id", "?") if finding else (args[0] if args else "?")

        entry = None
        debate_path = self.session_dir / "debate_log.jsonl"
        if debate_path.is_file():
            try:
                with debate_path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        rec = json.loads(line)
                        if rec.get("finding_id") == fid:
                            entry = rec  # keep the last (most recent) for this id
            except Exception:
                entry = None

        if entry is None:
            self.cli.console.print(
                f"[dim]No debate recorded for {theme.escape(str(fid))} "
                "(the skeptic either accepted it or it wasn't refuted).[/dim]"
            )
            return

        self.cli.console.print(f"\n[bold]Debate - {theme.escape(str(fid))}[/bold]")
        self.cli.console.print(
            f"  [danger]Skeptic refutation:[/danger] {theme.escape(str(entry.get('refutation', '')))}",
            width=min(self.cli.console.width, _DETAIL_WIDTH),
        )
        if entry.get("conceded"):
            self.cli.console.print("  [warn]Analyst conceded[/warn] - refutation stands.")
        else:
            self.cli.console.print(
                f"  [accent]Analyst rebuttal:[/accent] {theme.escape(str(entry.get('rebuttal', '')))}",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )
        fv = entry.get("final_verdict", "?")
        glyph = (
            "[success]overturned → reinstated[/success]"
            if entry.get("reinstated")
            else f"[danger]{theme.escape(str(fv))}[/danger]"
        )
        final = theme.muted("  Skeptic final: ")
        final.append_text(theme.markup(str(glyph)))
        self.cli.console.print(final)
        if entry.get("reasoning"):
            self.cli.console.print(
                f"    {theme.escape(str(entry.get('reasoning')))}",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )

    def _cmd_fix(self, args: list[str]) -> None:
        """Ask the LLM for a unified-diff patch suggestion.

        Strictly read-only: the diff is printed to screen only, never written
        to any file.
        """
        finding = self._resolve_finding(args)
        if finding is None:
            return

        llm = self._get_llm()
        if llm is None:
            return

        fid = finding.get("id", "?")
        self.cli.console.print(
            theme.warn(
                "Read-only suggestion: the diff is printed to screen only; "
                "nothing is written to source."
            )
        )

        snippet = finding.get("code_snippet") or finding.get("snippet", "")
        prompt = _build_fix_prompt(finding, snippet)
        try:
            text = self._ask_llm(
                llm,
                "You are a security analysis assistant.",
                prompt,
                status=f"Drafting fix for {fid}…",
            )
        except Exception as exc:
            err = theme.error("LLM error: ")
            err.append(str(exc))
            self.cli.console.print(err)
            return

        from rich.syntax import Syntax

        # Frame the syntax-highlighted diff in a themed panel; the title is a Text
        # (never markup-parsed), so a bracket in the finding id renders verbatim.
        diff = Syntax(_strip_code_fences(text), "diff", theme="ansi_dark")
        console = self.cli.console
        console.print()
        panel = theme.panel(diff, title=f"Suggested fix for {fid}  ·  read-only diff", kind="info")
        console.print(Constrain(panel, min(console.width, _DETAIL_WIDTH)))

    def _cmd_exploit(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        fid = finding.get("id", "?")

        # Look for exploit transcript in the session directory
        exploit_dir = self.session_dir / "exploits" / _safe_id(fid)
        transcript_path = exploit_dir / "transcript.jsonl"

        poc = finding.get("poc") or finding.get("exploit")
        exploit_result = finding.get("exploit_result", {}) or {}

        self.cli.console.print(f"\n[bold]Exploit summary for {theme.escape(str(fid))}:[/bold]")
        if exploit_result:
            success = exploit_result.get("success", False)
            impact = exploit_result.get("impact", "none")
            notes = exploit_result.get("notes", "")
            status = "[success]SUCCESS[/success]" if success else "[danger]FAILED[/danger]"
            self.cli.console.print(
                f"  status: {status}  impact: {theme.escape(str(impact))}\n"
                f"  notes: {theme.escape(str(notes)[:200])}",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )
        elif poc:
            poc_s = str(poc)
            poc_preview = poc_s[:200] + ("…" if len(poc_s) > 200 else "")
            self.cli.console.print(
                f"  PoC: {theme.escape(poc_preview)}",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )
        else:
            success = _efield(finding, "exploit_success")
            blocked_by = _efield(finding, "exploit_blocked_by")
            attempted = (
                success is not None
                or bool(blocked_by)
                or _efield(finding, "exploit_transcript_path") is not None
                or _efield(finding, "exploit_cost_usd") is not None
            )
            if attempted and not success:
                line = "  [danger]Exploit attempted - did not succeed.[/danger]"
                if blocked_by:
                    line += f" [dim]Blocked by: {theme.escape(str(blocked_by)[:200])}[/dim]"
                self.cli.console.print(line)
            else:
                self.cli.console.print(
                    "  [dim]No exploit attempted. "
                    "Run `acuario audit --exploit` to attempt exploitation.[/dim]"
                )

        meta = []
        cost = _efield(finding, "exploit_cost_usd")
        duration = _efield(finding, "exploit_duration_seconds")
        bypassed = _efield(finding, "exploit_mitigations_bypassed")
        if cost is not None:
            meta.append(f"cost ${float(cost):.4f}")
        if duration is not None:
            meta.append(f"{duration}s")
        if bypassed:
            meta.append(f"bypassed: {', '.join(str(m) for m in bypassed)}")
        if meta:
            self.cli.console.print(
                f"  [dim]{theme.escape(' · '.join(str(m) for m in meta))}[/dim]",
                width=min(self.cli.console.width, _DETAIL_WIDTH),
            )

        if transcript_path.exists():
            tp = theme.muted("Transcript: ")
            tp.append(str(transcript_path), style="path")  # free-text path, never markup
            self.cli.console.print()
            self.cli.console.print(tp)
            lines = transcript_path.read_text().splitlines()
            self.cli.console.print(theme.muted(f"{len(lines)} trajectory steps in transcript."))

    def _cmd_related(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        fid = finding.get("id", "?")
        cluster_id = finding.get("cluster_id") or finding.get("cluster")
        file_ = finding.get("file", "")
        cwe = finding.get("cwe", "")

        related: list[dict] = []
        if cluster_id:
            related = [
                f
                for f in self._findings
                if (f.get("cluster_id") or f.get("cluster")) == cluster_id and f.get("id") != fid
            ]

        # Fall back: same file + same CWE
        if not related:
            related = [
                f
                for f in self._findings
                if f.get("file") == file_ and f.get("cwe") == cwe and f.get("id") != fid
            ]

        if not related:
            self.cli.console.print(theme.muted(f"No related findings for {fid}."))
            return

        # Same framed findings table as list / triage, for a consistent surface.
        scope = "same cluster" if cluster_id else "same file + CWE"
        self.cli.console.print(
            self._findings_table(
                related, title=f"Related to {fid}", caption=f"{len(related)} finding(s) · {scope}"
            )
        )
        self.cli.console.print(self._flag_legend())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cmd_next(self, args: list[str] | None = None) -> None:
        self._step(1)

    def _cmd_prev(self, args: list[str] | None = None) -> None:
        self._step(-1)

    def _step(self, delta: int) -> None:
        listing = self._active_list()
        if not listing:
            self.cli.console.print(theme.muted("No findings to navigate."))
            return
        cur_id = self._current.get("id") if self._current else None
        idx = next((i for i, f in enumerate(listing) if f.get("id") == cur_id), None)
        if idx is None:
            idx = 0 if delta > 0 else len(listing) - 1
        else:
            idx = max(0, min(idx + delta, len(listing) - 1))
        self._current = listing[idx]
        self._cmd_show([])

    def _set_last_list(self, findings: list[dict]) -> None:
        """Record the last listing so findings can be picked by row number."""
        self._last_list = list(findings)

    def _active_list(self) -> list[dict]:
        """The listing row numbers resolve against: the last `list`/`triage`
        shown, or - before either has run - all findings, so `show 1` / `next`
        work the moment a session opens instead of needing a `list` first."""
        return self._last_list or self._findings

    def _candidates(self, token: str) -> list[dict]:
        """Resolve a token to candidate findings, with no console output.

        Precedence: a pure integer in range of the last listing is that row
        (1-based); otherwise an exact id, then prefix/substring matches.
        """
        listing = self._active_list()
        if token.isdigit() and listing:
            idx = int(token)
            if 1 <= idx <= len(listing):
                return [listing[idx - 1]]
        exact = self._findings_by_id.get(token)
        if exact is not None:
            return [exact]
        return [
            f for fkey, f in self._findings_by_id.items() if fkey.startswith(token) or token in fkey
        ]

    def _resolve_finding(self, args: list[str]) -> dict | None:
        # No token: act on the current selection, if one is set.
        if not args:
            if self._current is not None:
                return self._current
            self.cli.console.print(
                theme.error("finding id required (or select one with `show <id>` first).")
            )
            return None

        token = args[0]
        # A bare integer (incl 0 / negative) is a row number, never an id
        # substring: an out-of-range row reports the valid range instead of
        # falling into loose matching (`0` would substring-match dozens of ids).
        if token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
            listing = self._active_list()
            if listing and not (1 <= int(token) <= len(listing)):
                self.cli.console.print(
                    theme.warn(f"Row {token} out of range; rows are 1-{len(listing)}.")
                )
                return None
        matches = self._candidates(token)
        if len(matches) == 1:
            self._current = matches[0]
            return self._current
        if len(matches) > 1:
            self.cli.console.print(
                theme.warn(f"Ambiguous id {token!r}, {len(matches)} matches. Be more specific.")
            )
            for m in matches[:5]:
                self.cli.console.print(theme.line(f"  {m.get('id')}"))
            return None
        nf = theme.error("Finding not found: ")
        nf.append(repr(token))
        self.cli.console.print(nf)
        self.cli.console.print(theme.muted("Use `list` to see available findings."))
        return None

    def _ask_llm(self, llm: Any, system: str, user: str, status: str) -> str:
        """Run a blocking LLM call and return its text.

        Shows a spinner on an interactive terminal; falls back to a plain status
        line when stdout is not a TTY (piped/captured), so it never garbles
        non-interactive output.
        """
        import asyncio

        def _call() -> str:
            return _extract_text(asyncio.run(llm.aask_text(system=system, user=user)))

        if sys.stdout.isatty():
            with self.cli.console.status(f"[dim]{status}[/dim]"):
                return _call()
        self.cli.console.print(theme.muted(str(status)))
        return _call()

    def _get_llm(self) -> Any | None:
        try:
            from acuario.providers import ProviderManager, resolve_llm_endpoint

            endpoint = resolve_llm_endpoint(
                config_provider=self.cli.config.get_provider_section() or None
            )
            return ProviderManager.for_endpoint(endpoint).get_native_client("inspect")
        except Exception as exc:
            err = theme.error("Could not initialise LLM provider: ")
            err.append(str(exc))
            self.cli.console.print(err)
            self.cli.console.print(
                theme.muted("Set provider env vars (e.g. ACUARIO_PROVIDER) to enable LLM commands.")
            )
            return None

    def _load_trajectory(self, finding_id: str) -> str:
        """Try to load a trajectory file for the given finding."""
        # Trajectory dirs are stored alongside the session
        traj_dir = self.session_dir.parent.parent / "trajectories"
        pattern = f"*{_safe_id(finding_id)}*"
        candidates = list(traj_dir.glob(pattern)) if traj_dir.exists() else []

        # Also check inside session dir
        candidates += list(self.session_dir.glob(f"**/{_safe_id(finding_id)}*/transcript.jsonl"))

        for path in candidates[:1]:
            if path.is_dir():
                t = path / "transcript.jsonl"
                if t.exists():
                    return t.read_text()[:4000]
            elif path.is_file():
                return path.read_text()[:4000]
        return ""


# ---------------------------------------------------------------------------
# LLM prompt builders
# ---------------------------------------------------------------------------


def _build_why_prompt(finding: dict, trajectory: str) -> str:
    fid = finding.get("id", "?")
    file_ = finding.get("file", "?")
    line = finding.get("line_number", "?")
    cwe = finding.get("cwe", "")
    desc = finding.get("description", "")
    snippet = finding.get("code_snippet") or finding.get("snippet", "")
    evidence = finding.get("evidence_details") or finding.get("crash_evidence", "")

    parts = [
        "You are explaining why a security finding was reported during a code audit.",
        f"\nFinding ID: {fid}",
        f"File: {file_}:{line}  CWE: {cwe}",
        f"Description: {desc}",
    ]
    if snippet:
        parts.append(f"\nCode snippet:\n```\n{snippet[:800]}\n```")
    if evidence:
        parts.append(f"\nEvidence: {str(evidence)[:400]}")
    if trajectory:
        parts.append(f"\nAnalysis trajectory (excerpt):\n{trajectory[:2000]}")
    parts.append(
        "\nIn plain English (2-4 sentences), explain why this is a real vulnerability, "
        "what the exploitability path is, and why the evidence supports this conclusion."
    )
    return "\n".join(parts)


def _build_fix_prompt(finding: dict, snippet: str) -> str:
    fid = finding.get("id", "?")
    file_ = finding.get("file", "?")
    line = finding.get("line_number", "?")
    cwe = finding.get("cwe", "")
    desc = finding.get("description", "")

    return (
        f"You are a security engineer suggesting a minimal fix for a confirmed vulnerability.\n\n"
        f"Finding: {fid}\nFile: {file_}:{line}\nCWE: {cwe}\nDescription: {desc}\n"
        + (f"\nVulnerable code:\n```\n{snippet[:800]}\n```\n" if snippet else "")
        + "\nProvide a minimal unified-diff patch (--- / +++ format) that fixes this vulnerability "
        "without changing unrelated logic. Output only the diff, no prose. "
        "This is a read-only suggestion - it will be displayed to the developer, not applied automatically."
    )


def _truncate_desc(text: str, limit: int) -> str:
    """Cap a description at ``limit`` chars with a trailing ellipsis.

    Breaks at the last word boundary inside the kept span, but never drops a
    long unbroken token (falls back to a hard cut), so the table never shows a
    mid-word slice with no "more" signal.
    """
    if len(text) <= limit:
        return text
    head = text[:limit].rstrip()
    cut = head.rfind(" ")
    if cut > 0:
        head = head[:cut].rstrip()
    return head + "…"


def _efield(finding: dict, key: str, default: Any = None) -> Any:
    """Read a finding field, falling back to its ``extra`` dict.

    Fields such as ``validator_axes`` and ``exploit_*`` live only under
    ``extra`` in the plain dicts inspect loads from ``findings.json``.
    """
    val = finding.get(key)
    if val is not None:
        return val
    extra = finding.get("extra")
    if isinstance(extra, dict):
        return extra.get(key, default)
    return default


def _strip_code_fences(text: Any) -> str:
    """Drop a leading/trailing ``` fence if the LLM wrapped the diff in one."""
    if not isinstance(text, str):
        return str(text)
    stripped = text.strip()
    if not stripped.startswith("```"):
        return text
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)


def _extract_text(response: Any) -> str:
    """Extract the text of a native ChatResponse (the why/fix LLM replies)."""
    if isinstance(response, str):
        return response
    try:
        from acuario.llm.native import response_text

        return response_text(response)
    except Exception:
        return str(response)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity.lower(), 5)


# Evidence ladder (weakest -> strongest); mirrors acuario.findings.types.EvidenceLevel.
_EVIDENCE_LADDER = (
    "suspicion",
    "static_corroboration",
    "parameter_anomaly",
    "timing_confirmed",
    "crash_reproduced",
    "root_cause_explained",
    "assumption_broken",
    "exploit_demonstrated",
    "key_material_recovered",
    "patch_validated",
)
_CONFIDENCE_SCORE = {"high": 2, "medium": 1, "low": 0}


def _rank_score(finding: dict) -> int:
    """Deterministic triage priority - higher means review it sooner.

    Transparent and overridable: severity dominates, then evidence strength,
    then confidence, with bonuses for verified and exploit-demonstrated findings.
    """
    sev_score = 4 - min(_severity_rank(finding.get("severity", "")), 4)  # critical=4 .. info=0
    ev = (finding.get("evidence_level") or "").lower()
    ev_score = _EVIDENCE_LADDER.index(ev) if ev in _EVIDENCE_LADDER else 0
    conf_score = _CONFIDENCE_SCORE.get((finding.get("confidence") or "").lower(), 0)
    verified = 3 if finding.get("verified") else 0
    exploited = 5 if _efield(finding, "exploit_transcript_path") else 0
    return sev_score * 100 + ev_score * 5 + conf_score * 2 + verified + exploited


def _severity_color(severity: str) -> str:
    """Theme style name for a severity (e.g. ``"sev.high"``), from the shared kit.

    Kept as a thin wrapper so existing ``f"[{_severity_color(s)}]...[/...]"`` call
    sites resolve against the one themed palette instead of hard-coded colours.
    """
    return theme.severity_style(severity)


def _safe_id(finding_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", finding_id).strip("._") or "unknown"
