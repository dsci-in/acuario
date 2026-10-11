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
import textwrap
from pathlib import Path
from typing import Any

PROMPT = "\n> "
INDENT = "  "

# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "inspect",
        help="Interactive REPL - chat with a past audit session",
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
    session_id = args.session_id
    results_dir = args.results_dir

    if results_dir is None:
        try:
            from acuario.core.config import default_results_dir

            results_dir = default_results_dir("scanner")
        except Exception:
            results_dir = "./results/scanner"

    session_dir = Path(results_dir) / session_id
    if not session_dir.exists():
        cli.console.print(
            f"[red]Session directory not found:[/red] {session_dir}\n"
            "[dim]Tip: run `acuario history` to list available sessions.[/dim]"
        )
        return

    inspector = AuditInspector(session_id=session_id, session_dir=session_dir, cli=cli)
    inspector.run()


# ---------------------------------------------------------------------------
# Inspector class
# ---------------------------------------------------------------------------


class AuditInspector:
    """Interactive REPL over a completed audit session's artifacts."""

    def __init__(self, session_id: str, session_dir: Path, cli: Any):
        self.session_id = session_id
        self.session_dir = session_dir
        self.cli = cli
        self._findings: list[dict] = []
        self._findings_by_id: dict[str, dict] = {}
        self._skeptic_refuted: list[dict] = []
        self._critic_leads: list[dict] = []
        self._orchestrator_plans: list[dict] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # REPL loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._load_artifacts()
        self.cli.console.print(
            f"\n[bold cyan]Acuario inspect[/bold cyan] · session [bold]{self.session_id}[/bold]"
        )
        self.cli.console.print(
            f"  {len(self._findings)} findings loaded  "
            f"({sum(1 for f in self._findings if f.get('verified'))} verified)\n"
            "[dim]Type [bold]help[/bold] for commands, [bold]quit[/bold] to exit.[/dim]"
        )

        while True:
            try:
                raw = self._read_line()
            except (EOFError, KeyboardInterrupt):
                self.cli.console.print("\n[dim]Exiting inspector.[/dim]")
                break

            line = raw.strip()
            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()
            rest = parts[1:]

            if cmd in ("quit", "exit", "q"):
                self.cli.console.print("[dim]Exiting inspector.[/dim]")
                break
            elif cmd == "help":
                self._cmd_help()
            elif cmd == "list":
                self._cmd_list(rest)
            elif cmd == "show":
                self._cmd_show(rest)
            elif cmd == "why":
                self._cmd_why(rest)
            elif cmd == "skeptic":
                self._cmd_skeptic(rest)
            elif cmd == "critic":
                self._cmd_critic()
            elif cmd == "orchestrator":
                self._cmd_orchestrator()
            elif cmd == "debate":
                self._cmd_debate(rest)
            elif cmd == "fix":
                self._cmd_fix(rest)
            elif cmd == "exploit":
                self._cmd_exploit(rest)
            elif cmd == "related":
                self._cmd_related(rest)
            else:
                self.cli.console.print(
                    f"[red]Unknown command:[/red] {cmd!r}  "
                    "[dim](type [bold]help[/bold] for available commands)[/dim]"
                )

    def _read_line(self) -> str:
        """Read one line from stdin, using prompt_toolkit if available."""
        try:
            from prompt_toolkit import prompt as _pt_prompt

            return _pt_prompt(PROMPT)
        except ImportError:
            sys.stdout.write(PROMPT)
            sys.stdout.flush()
            return sys.stdin.readline()

    # ------------------------------------------------------------------
    # Artifact loading
    # ------------------------------------------------------------------

    def _load_artifacts(self) -> None:
        if self._loaded:
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

        # Critic leads (tagged discovered_by="critic" in findings)
        self._critic_leads = [f for f in self._findings if f.get("discovered_by") == "critic"]

        # Orchestrator plans (manifest.json field)
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

    def _cmd_help(self) -> None:
        self.cli.console.print(
            textwrap.dedent("""\
            [bold]Available commands[/bold]

              [cyan]list[/cyan] [--severity critical|high|medium|low]
                  List findings, optionally filtered by severity.

              [cyan]show[/cyan] <finding-id>
                  Full detail for a finding.

              [cyan]why[/cyan] <finding-id>
                  LLM explanation of the reasoning chain.

              [cyan]skeptic[/cyan] <finding-id>
                  Show the skeptic gate verdict for this finding.

              [cyan]critic[/cyan]
                  Show all reflective-critic low-confidence leads.

              [cyan]orchestrator[/cyan]
                  Show cross-file plans emitted by the orchestrator.

              [cyan]debate[/cyan] <finding-id>
                  Replay the analyzer↔skeptic debate (O2) for a refuted finding

              [cyan]fix[/cyan] <finding-id>
                  LLM-generated unified-diff suggestion (read-only - never writes source).

              [cyan]exploit[/cyan] <finding-id>
                  Exploit transcript and PoC string (if available).

              [cyan]related[/cyan] <finding-id>
                  Sibling findings from the same cluster.

              [cyan]help[/cyan]      Print this help.
              [cyan]quit[/cyan]      Exit the inspector.
            """)
        )

    def _cmd_list(self, args: list[str]) -> None:
        severity_filter: str | None = None
        it = iter(args)
        for a in it:
            if a == "--severity":
                severity_filter = next(it, None)

        findings = self._findings
        if severity_filter:
            findings = [
                f for f in findings if f.get("severity", "").lower() == severity_filter.lower()
            ]

        if not findings:
            self.cli.console.print("[dim]No findings match.[/dim]")
            return

        for f in sorted(findings, key=lambda x: _severity_rank(x.get("severity", ""))):
            fid = f.get("id", "?")
            sev = f.get("severity", "?").upper()
            file_ = f.get("file", "?")
            line = f.get("line_number", "?")
            cwe = f.get("cwe", "")
            desc = f.get("description", "")[:60]
            color = _severity_color(f.get("severity", ""))
            verified_mark = " [green]✓[/green]" if f.get("verified") else ""
            critic_mark = " [yellow](critic)[/yellow]" if f.get("discovered_by") == "critic" else ""
            self.cli.console.print(
                f"  [{color}][{sev}][/{color}]{verified_mark}{critic_mark}  "
                f"[bold]{fid}[/bold]  {file_}:{line}  {cwe}  {desc}"
            )

    def _cmd_show(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        fid = finding.get("id", "?")
        self.cli.console.print(f"\n[bold]Finding: {fid}[/bold]")
        for key in (
            "severity",
            "cwe",
            "file",
            "line_number",
            "evidence_level",
            "verified",
            "discovered_by",
            "description",
        ):
            val = finding.get(key)
            if val is not None:
                self.cli.console.print(f"  {key:<20} {val}")

        snippet = finding.get("code_snippet") or finding.get("snippet")
        if snippet:
            self.cli.console.print("\n[dim]── code snippet ──[/dim]")
            self.cli.console.print(f"[dim]{snippet}[/dim]")

        evidence = finding.get("evidence_details") or finding.get("crash_evidence")
        if evidence:
            self.cli.console.print("\n[dim]── evidence ──[/dim]")
            self.cli.console.print(f"[dim]{str(evidence)[:500]}[/dim]")

    def _cmd_why(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        llm = self._get_llm()
        if llm is None:
            return

        fid = finding.get("id", "?")
        self.cli.console.print(f"[dim]Asking LLM to explain {fid}…[/dim]")

        # Load trajectory if available
        trajectory_text = self._load_trajectory(fid)

        prompt = _build_why_prompt(finding, trajectory_text)
        try:
            import asyncio

            response = asyncio.run(
                llm.aask_text(
                    system="You are a security analysis assistant.",
                    user=prompt,
                )
            )
            text = _extract_text(response)
            self.cli.console.print(f"\n[bold]Why {fid}:[/bold]")
            self.cli.console.print(textwrap.fill(text, width=88))
        except Exception as exc:
            self.cli.console.print(f"[red]LLM error:[/red] {exc}")

    def _cmd_skeptic(self, args: list[str]) -> None:
        finding = self._resolve_finding(args)
        if finding is None:
            return

        fid = finding.get("id", "?")

        # Check if finding appears in skeptic_refuted.jsonl
        refuted_entry = next(
            (r for r in self._skeptic_refuted if r.get("id") == fid or r.get("finding_id") == fid),
            None,
        )

        if refuted_entry:
            reason = refuted_entry.get("refutation_reason") or refuted_entry.get(
                "reason", "no reason recorded"
            )
            code_ref = refuted_entry.get("code_reference", "")
            self.cli.console.print(f"\n[red]✗ Skeptic refuted[/red] {fid}\n  Reason: {reason}")
            if code_ref:
                self.cli.console.print(f"  Code reference: {code_ref}")
        else:
            # Check if the finding carries a skeptic verdict inline
            verdict = finding.get("skeptic_verdict", "")
            skeptic_reason = finding.get("skeptic_reason", "")
            # A finding flagged "uncertain" passed the gate but the skeptic
            # had unrefuted doubt - surface that rather than a clean accept.
            if finding.get("skeptic_flag") == "uncertain":
                doubt = finding.get("skeptic_doubt", "") or skeptic_reason
                self.cli.console.print(
                    f"\n[yellow]~ Skeptic uncertain[/yellow] {fid}\n"
                    f"  Doubt (not a code-cited refutation, so it passed through): {doubt}"
                )
            elif verdict == "refuted":
                self.cli.console.print(
                    f"\n[red]✗ Skeptic refuted[/red] {fid}\n  Reason: {skeptic_reason}"
                )
            else:
                self.cli.console.print(
                    f"\n[green]✓ Skeptic accepted[/green] {fid}\n"
                    "  (Skeptic gate failed to produce a valid refutation - "
                    "finding entered the pool.)"
                )

    def _cmd_critic(self) -> None:
        if not self._critic_leads:
            self.cli.console.print(
                "[dim]No critic leads in this session "
                '(none tagged discovered_by=\\"critic\\" in findings.json).[/dim]'
            )
            return

        self.cli.console.print(
            f"\n[bold]Reflective critic leads[/bold] - "
            f"{len(self._critic_leads)} low-confidence lead(s):"
        )
        for lead in self._critic_leads:
            fid = lead.get("id", "?")
            file_ = lead.get("file", "?")
            line = lead.get("line_number", "?")
            desc = lead.get("description", "")[:80]
            verified = " [green]✓ verified[/green]" if lead.get("verified") else ""
            self.cli.console.print(f"  [yellow]{fid}[/yellow]  {file_}:{line}  {desc}{verified}")

    def _cmd_orchestrator(self) -> None:
        if not self._orchestrator_plans:
            self.cli.console.print(
                "[dim]No orchestrator plans found "
                "(none recorded in manifest.json orchestrator_plans field).[/dim]"
            )
            return

        self.cli.console.print(
            f"\n[bold]Cross-file orchestrator plans[/bold] - "
            f"{len(self._orchestrator_plans)} plan(s):"
        )
        for i, plan in enumerate(self._orchestrator_plans, 1):
            files = plan.get("files", [])
            focus = plan.get("hunt_focus", "")
            rationale = plan.get("rationale", "")
            led_to = plan.get("findings_from_plan", [])
            self.cli.console.print(
                f"\n  [cyan]Plan {i}[/cyan]  focus: {focus}\n"
                f"  files: {', '.join(files)}\n"
                f"  rationale: {rationale}"
            )
            if led_to:
                self.cli.console.print(f"  led to findings: {', '.join(led_to)}")

    def _cmd_debate(self, args: list[str]) -> None:
        """Replay the analyzer↔skeptic debate for a refuted finding."""
        finding = self._resolve_finding(args)
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
                f"[dim]No debate recorded for {fid} "
                "(the skeptic either accepted it or it wasn't refuted).[/dim]"
            )
            return

        self.cli.console.print(f"\n[bold]Debate - {fid}[/bold]")
        self.cli.console.print(f"  [red]Skeptic refutation:[/red] {entry.get('refutation', '')}")
        if entry.get("conceded"):
            self.cli.console.print("  [yellow]Analyst conceded[/yellow] - refutation stands.")
        else:
            self.cli.console.print(f"  [cyan]Analyst rebuttal:[/cyan] {entry.get('rebuttal', '')}")
        fv = entry.get("final_verdict", "?")
        glyph = (
            "[green]overturned → reinstated[/green]"
            if entry.get("reinstated")
            else f"[red]{fv}[/red]"
        )
        self.cli.console.print(f"  [bold]Skeptic final:[/bold] {glyph}")
        if entry.get("reasoning"):
            self.cli.console.print(f"    {entry.get('reasoning')}")

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
        self.cli.console.print(f"[dim]Asking LLM for fix suggestion for {fid}…[/dim]")
        self.cli.console.print(
            "[bold yellow]Note:[/bold yellow] This is a read-only suggestion. "
            "The diff is printed to screen only - nothing is written to source."
        )

        snippet = finding.get("code_snippet") or finding.get("snippet", "")
        prompt = _build_fix_prompt(finding, snippet)

        try:
            import asyncio

            response = asyncio.run(
                llm.aask_text(
                    system="You are a security analysis assistant.",
                    user=prompt,
                )
            )
            text = _extract_text(response)
            self.cli.console.print(f"\n[bold]Suggested fix for {fid}[/bold] (read-only diff):\n")
            self.cli.console.print(text)
        except Exception as exc:
            self.cli.console.print(f"[red]LLM error:[/red] {exc}")

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

        self.cli.console.print(f"\n[bold]Exploit summary for {fid}:[/bold]")
        if exploit_result:
            success = exploit_result.get("success", False)
            impact = exploit_result.get("impact", "none")
            notes = exploit_result.get("notes", "")
            status = "[green]SUCCESS[/green]" if success else "[red]FAILED[/red]"
            self.cli.console.print(f"  status: {status}  impact: {impact}\n  notes: {notes[:200]}")
        elif poc:
            self.cli.console.print(f"  PoC: {poc[:200]}")
        else:
            self.cli.console.print(
                "  [dim]No exploit result recorded. "
                "Run `acuario audit --exploit` to attempt exploitation.[/dim]"
            )

        if transcript_path.exists():
            self.cli.console.print(f"\n[dim]Transcript: {transcript_path}[/dim]")
            lines = transcript_path.read_text().splitlines()
            self.cli.console.print(f"[dim]{len(lines)} trajectory steps in transcript.[/dim]")

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
            self.cli.console.print(f"[dim]No related findings found for {fid}.[/dim]")
            return

        self.cli.console.print(
            f"\n[bold]Related findings[/bold] for {fid} "
            f"({'same cluster' if cluster_id else 'same file+CWE'}):"
        )
        for rel in related:
            rid = rel.get("id", "?")
            rsev = rel.get("severity", "?").upper()
            rfile = rel.get("file", "?")
            rline = rel.get("line_number", "?")
            rdesc = rel.get("description", "")[:60]
            color = _severity_color(rel.get("severity", ""))
            self.cli.console.print(
                f"  [{color}][{rsev}][/{color}]  [bold]{rid}[/bold]  {rfile}:{rline}  {rdesc}"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_finding(self, args: list[str]) -> dict | None:
        if not args:
            self.cli.console.print("[red]Error:[/red] finding id required.")
            return None
        fid = args[0]
        finding = self._findings_by_id.get(fid)
        if finding is None:
            # Fuzzy: prefix match
            matches = [
                f for fkey, f in self._findings_by_id.items() if fkey.startswith(fid) or fid in fkey
            ]
            if len(matches) == 1:
                finding = matches[0]
            elif len(matches) > 1:
                self.cli.console.print(
                    f"[yellow]Ambiguous id prefix '{fid}' - "
                    f"{len(matches)} matches. Be more specific.[/yellow]"
                )
                for m in matches[:5]:
                    self.cli.console.print(f"  {m.get('id')}")
                return None
            else:
                self.cli.console.print(
                    f"[red]Finding not found:[/red] {fid!r}\n"
                    "[dim]Use `list` to see available findings.[/dim]"
                )
                return None
        return finding

    def _get_llm(self) -> Any | None:
        try:
            from acuario.providers import ProviderManager, resolve_llm_endpoint

            endpoint = resolve_llm_endpoint(
                config_provider=self.cli.config.get_provider_section() or None
            )
            return ProviderManager.for_endpoint(endpoint).get_native_client("inspect")
        except Exception as exc:
            self.cli.console.print(
                f"[red]Could not initialise LLM provider:[/red] {exc}\n"
                "[dim]Set provider env vars (e.g. ACUARIO_PROVIDER) to enable LLM commands.[/dim]"
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


def _extract_text(response: Any) -> str:
    """Extract text from an LLM response object."""
    if hasattr(response, "content"):
        content = response.content
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    return block.get("text", "")
                if hasattr(block, "text"):
                    return block.text
        if isinstance(content, str):
            return content
    if isinstance(response, str):
        return response
    return str(response)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity.lower(), 5)


def _severity_color(severity: str) -> str:
    return {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }.get(severity.lower(), "white")


def _safe_id(finding_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", finding_id).strip("._") or "unknown"
