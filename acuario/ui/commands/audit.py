"""Audit CLI subcommand - runs the Acuario source-code vulnerability pipeline."""

import logging
import os
import resource
import sys


def _raise_fd_limit() -> None:
    """Raise the soft file-descriptor limit before any sandbox / LLM clients spawn.

    Default Ubuntu ``ulimit -n`` is 1024, which the audit pipeline blows past
    after ~80 sandbox starts (each Docker exec/put_archive call holds an FD).
    Bumping to 65536 (or the hard cap, whichever is lower) eliminates ~80% of
    the historical "Too many open files" crashes mid-run.

    Non-fatal on platforms or environments where ``resource.setrlimit`` is
    forbidden (e.g. some CI sandboxes); the run will still go, just with the
    smaller default and `--max-parallel` capping concurrency.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65536, hard) if hard != resource.RLIM_INFINITY else 65536
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (OSError, ValueError):
        pass  # non-fatal; concurrency caps still apply


def _format_budget(budget: float) -> str:
    if budget <= 0:
        return "unlimited"
    return f"${budget:.2f}"


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "audit",
        help="Source-code security audit",
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Git URL or local path to a repository (default: current directory). "
        "Optional when using --resume.",
    )
    parser.add_argument(
        "--resume",
        metavar="SESSION_ID",
        default=None,
        dest="resume_session_id",
        help="Resume a crashed audit run from its persisted findings. "
        "Skips the analyzer pool and runs the reviewer + reporter "
        "on findings already saved to the historical DB. "
        "Transient network errors are auto-retried (5 attempts per "
        "finding, then up to 3 outer re-passes). Findings that "
        "have already received a verdict from a prior resume are "
        "skipped - re-running --resume is idempotent. Pair with "
        "--no-verify to skip the reviewer pass entirely, or with "
        "--force-review to re-review even findings that already "
        "have a verdict.",
    )
    parser.add_argument(
        "--force-review",
        action="store_true",
        default=False,
        dest="force_review",
        help="With --resume, re-review findings even if they already "
        "have a saved verdict. Bumps the per-finding review_revision "
        "counter. Use this only when you want to compare reviewer "
        "verdicts across runs - be aware that LLM non-determinism "
        "means borderline findings may flip-flop.",
    )
    parser.add_argument("--branch", default="main", help="Git branch to clone (default: main)")
    parser.add_argument(
        "--local-path", metavar="PATH", help="Use this local path instead of cloning"
    )
    parser.add_argument(
        "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Hunt depth (default: standard)",
    )
    parser.add_argument(
        "--agent-mode",
        choices=["auto", "constrained", "deep"],
        default="auto",
        dest="agent_mode",
        help="Agent mode: 'auto' derives from --depth, 'constrained' forces legacy "
        "9-tool analyzer, 'deep' forces full-shell agent (default: auto)",
    )
    parser.add_argument(
        "--prompt-mode",
        choices=["unconstrained", "specialist"],
        default="unconstrained",
        dest="prompt_mode",
        help="Prompt mode: 'unconstrained' uses a simple discovery prompt "
        "(default), 'specialist' uses legacy prescriptive checklists",
    )
    parser.add_argument(
        "--campaign-hint",
        default=None,
        dest="campaign_hint",
        metavar="OBJECTIVE",
        help="Campaign objective hint, e.g. 'bugs reachable from unauthenticated remote input'",
    )
    parser.add_argument(
        "--exploit",
        action="store_true",
        default=False,
        dest="exploit_mode",
        help="Instruct analyzers to write exploits for found vulnerabilities",
    )
    parser.add_argument(
        "--findings",
        default=None,
        dest="exploit_findings",
        metavar="ID[,ID...]",
        help=(
            "With --resume --exploit, restrict the exploit stage to these "
            "finding ids (comma-separated). Named findings bypass the evidence "
            "gate (each below-gate one is force-exploited with a warning)."
        ),
    )
    parser.add_argument(
        "--starting-band",
        choices=["fast", "standard", "deep"],
        default=None,
        dest="starting_band",
        help="Override starting band for all runs (default: auto from --depth)",
    )
    parser.add_argument(
        "--redundancy",
        type=int,
        default=None,
        metavar="N",
        help="Override redundancy count for high-ranked files (default: auto from priority)",
    )
    parser.add_argument(
        "--shard-entry-points",
        action="store_true",
        default=False,
        dest="shard_entry_points",
        help="Shard agents by function-level entry point for high-ranked files "
        "(auto-enabled at --depth deep)",
    )
    parser.add_argument(
        "--min-shard-rank",
        type=int,
        default=4,
        dest="min_shard_rank",
        metavar="N",
        help="Minimum file rank for entry-point sharding (default: 4)",
    )
    parser.add_argument(
        "--subsystem-hunt",
        action="store_true",
        default=False,
        dest="subsystem_hunt",
        help="Enable cross-subsystem analyzing after per-file hunts. "
        "Auto-identifies subsystems from ranked files.",
    )
    parser.add_argument(
        "--subsystem",
        action="append",
        default=[],
        metavar="PATH",
        dest="subsystem_paths",
        help="Manually specify a subsystem directory to hunt (repeatable). "
        "Implies --subsystem-hunt. Example: --subsystem net/ipv4/",
    )
    parser.add_argument(
        "--no-per-file-hunt",
        action="store_true",
        default=False,
        dest="no_per_file_hunt",
        help="Skip per-file analyzing; only run subsystem hunts.",
    )
    parser.add_argument(
        "--seed-corpus",
        default=None,
        dest="seed_corpus",
        metavar="PATH",
        help="Path to a local seed corpus directory",
    )
    parser.add_argument(
        "--seed-cves",
        action="store_true",
        default=False,
        dest="seed_cves",
        help="Auto-extract CVE history from git log as seed context",
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=0.0,
        metavar="USD",
        help="Max dollars to spend (default: unlimited; 0 = unlimited)",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=1,
        help="Max concurrent analyzer agents in the pool. The reviewer, "
        "variant loop, exploit-dev, and stability stages always run "
        "serially regardless. Default: 1 (fully serial). Bump higher "
        "when running against a backend with continuous batching "
        "(vLLM, Anthropic, OpenRouter, …) - e.g. --max-parallel 8.",
    )
    parser.add_argument(
        "--max-llm-concurrency",
        type=int,
        default=0,
        help="M6: override the per-LLM-client request cap (in-flight "
        "requests to the model endpoint). 0 = use the built-in defaults "
        "(8 general, 4 prioritizer, 15 for openai_resp). A multi-GPU "
        "self-hosted vLLM box can usually sustain 24-32; raise this to "
        "convert that headroom into throughput. Clamped to 64.",
    )
    parser.add_argument(
        "--warm-container-pool",
        action="store_true",
        help="N4: reuse a pool of pre-warmed sandbox containers across files "
        "instead of cold-spawning one per file (saves the per-file docker-run "
        "start). Each container is reset to a pristine git state between files; "
        "any container that can't be verified clean is dropped and replaced, so "
        "it never leaks state. Off by default - the per-file-spawn path is the "
        "guaranteed-fresh baseline.",
    )
    parser.add_argument(
        "--tier-split",
        default="70/25/5",
        help="Budget split A/B/C as percentages "
        "(default: 70/25/5; e.g. 60/30/10 for more propagation audits)",
    )
    parser.add_argument(
        "--skip-tier-c",
        action="store_true",
        help="Disable Tier C propagation audits (faster, misses root-cause-in-boring-files bugs)",
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Skip the independent-context reviewer pass"
    )
    parser.add_argument(
        "--no-adversarial",
        action="store_true",
        help="Disable adversarial reviewer (use the simpler v0.1 prompt)",
    )
    parser.add_argument(
        "--adversarial-threshold",
        default="static_corroboration",
        choices=[
            "suspicion",
            "static_corroboration",
            "crash_reproduced",
            "root_cause_explained",
            "always",
        ],
        help="Minimum evidence level to spend adversarial-reviewer "
        'budget on. "always" disables the gate; default is '
        "static_corroboration.",
    )
    parser.add_argument(
        "--validator-mode",
        choices=["v1", "v2"],
        default="v2",
        dest="validator_mode",
        help="Validation mode: v1 (legacy reviewer) or v2 (4-axis validator, default).",
    )
    parser.add_argument(
        "--recalibrate-severity",
        action="store_true",
        help="O6: deterministically cap a verified finding's severity from the "
        "4-axis confidences (e.g. TRIGGERABLE passed only at low confidence → "
        "cap at high). Rule-based, no extra LLM call. Off by default; the "
        "analyzer's claimed severity is preserved otherwise.",
    )
    parser.add_argument(
        "--skeptic-shadow-mode",
        action="store_true",
        help="O8: run the skeptic in shadow mode - it logs its verdicts but "
        "does NOT gate (every finding passes through to the validator). Lets "
        "you measure the skeptic's false-negative rate against the validator "
        "as ground truth. Writes calibration.jsonl. Off by default.",
    )
    parser.add_argument("--no-exploit", action="store_true", help="Skip the exploit-triage pass")
    parser.add_argument(
        "--exploit-budget",
        choices=["standard", "deep", "campaign"],
        default=None,
        dest="exploit_budget",
        help="Exploit development budget band (default: auto from --depth). "
        "standard=$25/1hr, deep=$200/4hr, campaign=$2000/12hr.",
    )
    parser.add_argument(
        "--variant-loop",
        action="store_true",
        help="Enable the variant analyzer loop (v0.3 compounding sibling-bug "
        "search). Off by default (O9): historically 0 verified findings and the "
        "source of the ~8h single-call stall.",
    )
    parser.add_argument(
        "--no-sca",
        action="store_true",
        help="Skip the SCA vulnerable-dependency scan (C1: package.json + "
        "lockfiles matched against a bundled offline advisory set). On by default.",
    )
    parser.add_argument(
        "--no-mechanism-memory", action="store_true", help="Skip cross-run mechanism memory (v0.3)"
    )
    parser.add_argument(
        "--mechanism-recall-k",
        type=int,
        default=3,
        metavar="N",
        help=(
            "Top-K prior mechanisms recalled per file and injected into the "
            "analyzer prompt (lab/A1). Clamped to [0, 10]. 0 disables recall "
            "without disabling mechanism *recording*. Default: 3."
        ),
    )
    parser.add_argument(
        "--no-cross-file-context",
        action="store_true",
        help=(
            "Disable cross-file context pre-seeding (lab/A4). When enabled "
            "(default), each analyzer receives callers, callees, and prior "
            "findings for its file before specialist instructions."
        ),
    )
    parser.add_argument(
        "--no-skeptic-gate",
        action="store_true",
        help=(
            "Disable the skeptic gate (lab/B1). When enabled (default), each "
            "finding is challenged by an adversarial agent before entering the "
            "pool. Refuted findings are logged to skeptic_refuted.jsonl."
        ),
    )
    parser.add_argument(
        "--no-debate",
        action="store_true",
        help=(
            "Disable the analyzer↔skeptic debate round (O2). When enabled "
            "(default), every finding the skeptic REFUTES gets one analyst "
            "rebuttal; if the skeptic is convinced, the finding is reinstated "
            "(advisory - the validator still judges it). The exchange is "
            "written to debate_log.jsonl. Improves recall at a small extra "
            "LLM cost; disable to keep the skeptic's refutations final."
        ),
    )
    parser.add_argument(
        "--no-critic",
        action="store_true",
        help=(
            "Disable the reflective critic (lab/B2). When enabled (default), "
            "one extra LLM call fires after each analyzer session asking "
            "'what did you miss?' Leads are tagged discovered_by=critic."
        ),
    )
    parser.add_argument(
        "--no-orchestrator",
        action="store_true",
        help=(
            "Disable the cross-file orchestrator (lab/B3). When enabled "
            "(default), one LLM call after the analyzer pool emits cross-file "
            "investigation plans for shared-state and boundary violations."
        ),
    )
    parser.add_argument(
        "--no-stability-check",
        action="store_true",
        help="Skip the PoC stability verification (Stage 2.5)",
    )
    parser.add_argument(
        "--no-findings-pool",
        action="store_true",
        help="Disable the shared findings pool (dedup + cross-agent queries)",
    )
    parser.add_argument(
        "--gvisor",
        action="store_true",
        help="Use the gVisor (runsc) runtime for stronger container "
        "isolation. Falls back to the default Docker runtime with a warning "
        "if runsc isn't installed on the host.",
    )
    parser.add_argument(
        "--strict-sandbox",
        action="store_true",
        help="N5: add networking syscalls (socket/connect/bind/…) to the "
        "analyzer sandbox's seccomp denylist for defense-in-depth. Off by "
        "default - a deep analyzer may legitimately run a target server on "
        "loopback to confirm a bug. The sandbox is network-isolated either "
        "way (network_mode=none, cap_drop=ALL).",
    )
    parser.add_argument(
        "--encrypt-artifacts",
        action="store_true",
        help="Enable encrypted artifact storage",
    )
    parser.add_argument(
        "--no-behavior-monitor",
        action="store_true",
        help="Disable behavioral monitoring (regex post-hoc + ptrace real-time)",
    )
    parser.add_argument(
        "--no-sandbox-snapshots",
        action="store_true",
        help=(
            "Disable docker-commit checkpoint/rollback around exploit attempts "
            "(C1).  Default: snapshots are enabled when the daemon supports commit."
        ),
    )
    parser.add_argument(
        "--no-exploit-compose",
        action="store_true",
        help=(
            "Disable host-orchestrated `docker compose up` for multi-service exploit "
            "targets.  Default: when a compose file and the compose CLI are present, "
            "the app stack is brought up on an internal-only network so exploits run "
            "against a live multi-service instance; disabling forces the single-process "
            "loopback launch + fail-fast static-PoC path."
        ),
    )
    parser.add_argument(
        "--no-ptrace-monitor",
        action="store_true",
        help=(
            "Disable the ptrace/strace real-time syscall monitor (C2).  When "
            "set, only the regex behavior monitor runs.  Default: ptrace tries "
            "to attach and falls back to regex when strace is unavailable."
        ),
    )
    parser.add_argument(
        "--model", default=None, help="Override all role models with one model name"
    )
    parser.add_argument(
        "--base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible API base URL. Point at OpenRouter, Ollama "
        "(http://localhost:11434/v1), LM Studio (http://localhost:1234/v1), "
        "vLLM, Together, Groq, etc. Overrides ANTHROPIC_API_KEY for this run. "
        "Also settable via the ACUARIO_BASE_URL env var.",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API key for the --base-url endpoint. Also settable via the "
        "ACUARIO_API_KEY env var. Use any placeholder for fully-local "
        "endpoints like Ollama / LM Studio that ignore it.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: ./results/scanner or ~/.acuario/results/scanner)",
    )
    parser.add_argument(
        "--format",
        nargs="+",
        choices=["sarif", "markdown", "json", "pdf", "all"],
        default=["all"],
        help="Output formats to write (default: all, which includes a native PDF)",
    )
    return parser


def handle(cli, args):
    """Run the scanner pipeline."""
    # Raise the OS file-descriptor cap before anything else fires up - the
    # Docker sandbox + the genai-pyo3 reqwest client both consume FDs at a
    # rate that exhausts the 1024 default after a few dozen findings.
    _raise_fd_limit()

    from ...core.config import default_results_dir
    from ...providers import ProviderManager, resolve_llm_endpoint
    from ...scanner.pool import TierBudget
    from ...scanner.runner import ScanRunner

    if args.output_dir is None:
        args.output_dir = default_results_dir("scanner")

    # Set up console logging with the narration formatter so glyphs and stage
    # prefixes render consistently on the console and in audit.log.
    # basicConfig is called first to install a StreamHandler; we then replace
    # its formatter with the NarrationFormatter (level-aware variant).
    logging.basicConfig(level=logging.INFO, force=True)
    from ...ui.narration import AuditNarrator as _AN

    # Enable color + stage banners + auxiliary-line indentation
    # on the console, but auto-disable color when the output isn't a TTY
    # (e.g. piped to file or tee).  NO_COLOR env honoring lives in the
    # formatter itself.
    _is_tty = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
    _console_fmt = _AN.get_log_formatter(
        colorize=_is_tty,
        banner_on_stage_change=True,
        indent_auxiliary_stages=True,
    )
    for _h in logging.getLogger().handlers:
        if isinstance(_h, logging.StreamHandler) and not isinstance(_h, logging.FileHandler):
            _h.setFormatter(_console_fmt)
            try:
                _h.stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
            except (AttributeError, TypeError):
                pass  # stream may not support reconfigure (e.g. redirected pipe)

    # Resume path: skip the entire analyzer pipeline, load saved findings
    # from the historical DB, run the reviewer + reporter on them.
    if getattr(args, "resume_session_id", None):
        from ...scanner.resume import resume_session

        session_id = args.resume_session_id
        cli.console.print(f"[bold cyan]Resuming audit session {session_id}[/bold cyan]")
        try:
            _exploit_findings_raw = getattr(args, "exploit_findings", None)
            _finding_ids = (
                [s.strip() for s in _exploit_findings_raw.split(",") if s.strip()]
                if _exploit_findings_raw
                else None
            )
            paths = resume_session(
                session_id=session_id,
                repo_path=args.repo if args.repo != "." else None,
                output_dir=args.output_dir,
                verify=not getattr(args, "no_verify", False),
                force_review=getattr(args, "force_review", False),
                cli_config_section=cli.config.get_provider_section() or None,
                run_exploit=getattr(args, "exploit_mode", False),
                finding_ids=_finding_ids,
            )
        except FileNotFoundError as exc:
            cli.console.print(f"[red]{exc}[/red]")
            return
        except ValueError as exc:
            cli.console.print(f"[red]{exc}[/red]")
            cli.console.print(
                "[dim]Tip: list available sessions with "
                "`acuario history` or check "
                "`~/.acuario/scanner/historical_findings.db`.[/dim]"
            )
            return
        cli.console.print("\n[bold green]Resume complete[/bold green]")
        for fmt, path in paths.items():
            cli.console.print(f"  [bold]{fmt:10s}[/bold]  {path}")
        return

    # Resolve the LLM endpoint once at the top of the command.
    # CLI > env > ~/.acuario/config.yaml > ANTHROPIC_API_KEY default.
    endpoint = resolve_llm_endpoint(
        cli_model=args.model,
        cli_base_url=getattr(args, "base_url", None),
        cli_api_key=getattr(args, "api_key", None),
        config_provider=cli.config.get_provider_section() or None,
    )
    cli.console.print(f"[dim]LLM endpoint: {endpoint.describe()}[/dim]")
    provider_manager = ProviderManager.for_endpoint(endpoint)

    # Tell the CostTracker which mode to operate in. Self-hosted endpoints
    # (Ollama, vLLM, LM Studio, anything on localhost / RFC1918) charge
    # nothing per token; the tracker accumulates token totals + reference
    # quotes (current frontier flagships, see CostTracker.REF_*_MODEL) instead
    # of bogus dollar figures derived from the default-Sonnet pricing fallback.
    from ...observability.telemetry import CostTracker

    _tracker = CostTracker()
    _tracker.set_endpoint(
        provider=endpoint.provider,
        base_url=endpoint.base_url,
        model=endpoint.model,
    )
    # Arm the cost-limit primitive from --budget so is_over_limit() is
    # meaningful on commercial endpoints. (On self-hosted runs paid cost stays
    # $0, so the per-tier/per-band budget caps remain the effective control.)
    if getattr(args, "budget", 0.0) and args.budget > 0:
        _tracker.cost_limit = float(args.budget)

    # Parse tier-split
    try:
        a, b, c = (int(x) / 100.0 for x in args.tier_split.split("/"))
    except ValueError:
        cli.console.print(
            f"[red]Error: --tier-split must be three integers like '70/25/5', got '{args.tier_split}'[/red]"
        )
        sys.exit(1)

    if args.skip_tier_c:
        # Redistribute Tier C allocation into A
        a += c
        c = 0.0

    try:
        tier_budget = TierBudget(
            tier_a_fraction=a,
            tier_b_fraction=b,
            tier_c_fraction=c,
        )
    except ValueError as e:
        cli.console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    formats = args.format
    if "all" in formats:
        formats = ["sarif", "markdown", "json", "pdf"]

    if args.no_per_file_hunt and not args.subsystem_hunt and not args.subsystem_paths:
        cli.console.print(
            "[red]Error: --no-per-file-hunt requires --subsystem-hunt or --subsystem[/red]"
        )
        sys.exit(1)

    # Canonicalise the repo identifier so local-path scans get a stable,
    # unique key in the historical-findings DB. Relative paths like "."
    # would otherwise collide across projects and pull dedup hits from
    # unrelated codebases. Git URLs (anything with a scheme or @) are
    # left as-is - they're already unique.
    _repo_id = args.repo
    if _repo_id and "://" not in _repo_id and not _repo_id.startswith("git@"):
        if os.path.isdir(_repo_id):
            _repo_id = os.path.abspath(_repo_id)

    # Surface the per-LLM-client concurrency override to ProviderManager
    # via the env var it reads (_native_concurrency_for_task). Setting it here
    # keeps the knob a single source of truth whether the user passes the flag
    # or exports the env var directly.
    if getattr(args, "max_llm_concurrency", 0):
        os.environ["ACUARIO_MAX_LLM_CONCURRENCY"] = str(args.max_llm_concurrency)

    runner = ScanRunner(
        repo_url=_repo_id,
        branch=args.branch,
        local_path=args.local_path,
        depth=args.depth,
        budget_usd=args.budget,
        max_parallel=args.max_parallel,
        tier_budget=tier_budget,
        output_dir=args.output_dir,
        output_formats=formats,
        no_verify=args.no_verify,
        no_exploit=args.no_exploit,
        exploit_compose=not getattr(args, "no_exploit_compose", False),
        exploit_budget=args.exploit_budget,
        adversarial_verifier=not args.no_adversarial,
        adversarial_threshold=(
            None if args.adversarial_threshold == "always" else args.adversarial_threshold
        ),
        validator_mode=args.validator_mode,
        recalibrate_severity=getattr(args, "recalibrate_severity", False),
        skeptic_shadow_mode=getattr(args, "skeptic_shadow_mode", False),
        enable_variant_loop=getattr(args, "variant_loop", False),
        enable_sca=not getattr(args, "no_sca", False),
        enable_mechanism_memory=not args.no_mechanism_memory,
        mechanism_recall_k=int(getattr(args, "mechanism_recall_k", 3)),
        enable_cross_file_context=not getattr(args, "no_cross_file_context", False),
        enable_skeptic_gate=not getattr(args, "no_skeptic_gate", False),
        enable_debate=not getattr(args, "no_debate", False),
        enable_critic=not getattr(args, "no_critic", False),
        enable_orchestrator=not getattr(args, "no_orchestrator", False),
        enable_stability_verification=not args.no_stability_check,
        model_override=args.model,
        provider_manager=provider_manager,
        agent_mode=args.agent_mode,
        prompt_mode=args.prompt_mode,
        campaign_hint=args.campaign_hint,
        exploit_mode=args.exploit_mode,
        starting_band=args.starting_band,
        redundancy_override=args.redundancy,
        shard_entry_points=True if args.shard_entry_points else None,
        min_shard_rank=args.min_shard_rank,
        enable_findings_pool=not args.no_findings_pool,
        enable_subsystem_hunt=args.subsystem_hunt or bool(args.subsystem_paths),
        subsystem_paths=args.subsystem_paths or None,
        no_per_file_hunt=args.no_per_file_hunt,
        enable_behavior_monitor=not getattr(args, "no_behavior_monitor", False),
        enable_sandbox_snapshots=not getattr(args, "no_sandbox_snapshots", False),
        enable_ptrace_monitor=not getattr(args, "no_ptrace_monitor", False),
        enable_warm_pool=getattr(args, "warm_container_pool", False),
        strict_seccomp=getattr(args, "strict_sandbox", False),
        gvisor_runtime="runsc" if getattr(args, "gvisor", False) else None,
    )

    from ...ui.narration import AuditNarrator

    _narrator = AuditNarrator(cli.console)
    _narrator.print_header(
        session_id=runner.session_id,
        target=str(args.repo),
        depth=args.depth,
        endpoint_label=endpoint.describe(),
        budget_label=_format_budget(args.budget),
        lab_flags={
            "skeptic": not getattr(args, "no_skeptic_gate", False),
            "critic": not getattr(args, "no_critic", False),
            "orchestrator": not getattr(args, "no_orchestrator", False),
            "sandbox_snapshots": not getattr(args, "no_sandbox_snapshots", False),
            "ptrace_monitor": (
                not getattr(args, "no_ptrace_monitor", False)
                and not getattr(args, "no_behavior_monitor", False)
            ),
        },
    )

    # Add a FileHandler so the full INFO/WARNING log is saved alongside the
    # report - useful for post-run debugging without having to re-run.
    import pathlib

    _session_log_dir = pathlib.Path(args.output_dir) / runner.session_id
    _session_log_dir.mkdir(parents=True, exist_ok=True)
    _log_file_path = _session_log_dir / "audit.log"
    _file_handler = logging.FileHandler(_log_file_path, encoding="utf-8")
    _file_handler.setFormatter(AuditNarrator.get_log_formatter(for_file=True))
    _file_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(_file_handler)

    try:
        result = runner.run()
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Audit cancelled by user[/yellow]")
        sys.exit(130)
    except (ValueError, RuntimeError) as exc:
        cli.console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)
    finally:
        # Flush and detach the per-session FileHandler so it doesn't leak
        # into subsequent commands if the process is reused.
        logging.getLogger().removeHandler(_file_handler)
        _file_handler.close()

    # --- End-of-run summary via narrator -----------------------------------
    from ...ui.narration import LabStats

    _lab_stats = LabStats(
        skeptic_accepted=getattr(result, "skeptic_accepted", 0),
        skeptic_refuted=getattr(result, "skeptic_refuted", 0),
        critic_leads=getattr(result, "critic_leads", 0),
        critic_verified=getattr(result, "critic_verified", 0),
        orchestrator_plans=getattr(result, "orchestrator_plans", 0),
        orchestrator_findings=getattr(result, "orchestrator_findings", 0),
        snapshot_cycles=getattr(result, "snapshot_cycles", 0),
        ptrace_events=getattr(result, "ptrace_events", 0),
    )
    _narrator.print_summary(
        result=result,
        log_file_path=str(_log_file_path),
        lab_stats=_lab_stats,
    )

    sys.exit(result.exit_code)
