# Architecture

Acuario is a **single-pipeline** source-code auditor. The core pipeline
is one command - `acuario audit` - wired together from a small set of
well-defined components. (The CLI ships other subcommands too, e.g.
`acuario history` and `acuario report`.)

## High-level pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│                          acuario audit                               │
│                                                                      │
│ preprocessor → prioritizer → analyzer pool → reviewer → variant loop*│
│                                  │                                   │
│                          ┌───────┴────────┐                          │
│                          ▼                ▼                          │
│               exploit-dev (default)   stability check                │
│                          │                                           │
│                      └──────────► reporter (SARIF + MD + JSON + PDF) │
└──────────────────────────────────────────────────────────────────────┘
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       ▼                           ▼                           ▼
  Docker sandbox             LLM provider             Findings DB
  (analyzer + PoC run)       (genai-pyo3 native)      (sqlite)
```

`*` variant loop is opt-in (`--variant-loop`, off by default).

After exploit-dev, a deterministic **SCA** pass (`--no-sca` to skip) scans
dependencies for known-vulnerable versions and feeds its findings straight into
the report; a `calibration.jsonl` agreement log (skeptic vs validator vs exploit
outcome) is written alongside the report.

## Stages

### 1. Preprocessor (`acuario/scanner/preprocessor.py`)

Static-pattern scan of the repo: regex-based vulnerability hints
(SQL injection, hardcoded secrets, dangerous functions, etc.) plus
file enumeration with priority hints (entry-point files,
authentication code, etc.). Optional taint analysis and call-graph
construction (via tree-sitter) feed into the prioritizer.

**No LLM** - runs in milliseconds.

### 2. Prioritizer (`acuario/scanner/prioritizer.py`)

LLM ranks the enumerated files by attack surface - which files are
most likely to contain bugs given the project's structure, the
preprocessor's hints, and the entry points. Outputs a tier-A/B/C
split (default 70%/25%/5% of the budget).

### 3. Analyzer pool (`acuario/scanner/pool.py` + `acuario/scanner/analyzer.py`)

For each file, an analyzer agent runs inside a Docker sandbox container.
The default set is the full 9-tool set - the agent can discover,
compile, and actually run/fuzz code in the sandbox:

- discovery: `read_source_file`, `list_source_tree`, `grep_source`,
  `find_callers`
- analysis: `compile_file`, `run_with_sanitizer`, `write_test_case`,
  `fuzz_harness`
- reporting: `record_finding` - register a vulnerability into the run state

(deep / full-shell mode adds more tools via `build_deep_agent_tools`.)

The agent is given the file content + preprocessor hints and runs a
ReAct loop until it either records all findings it can substantiate
or hits its per-file budget cap. The pool runs `--max-parallel` agents
concurrently. Tier-A files default to multiple agents per file
(redundancy) for robustness.

The analyzer's tool set lives at `acuario/agent/tools/hunt/`.

### 4. Reviewer / 4-axis validator (`acuario/scanner/validator.py`, `reviewer.py`)

The reviewer pass runs **serially** - one finding at a time - to
avoid compounding the file-descriptor pressure that the analyzer pool
already creates with its sandbox containers. For each finding, the
reviewer evaluates four independent axes:

- **REAL** - does the bug actually exist as described?
- **TRIGGERABLE** - can it be reached from realistic input?
- **IMPACTFUL** - what's the security consequence?
- **GENERAL** - is this a class of bug or a one-off?

Findings that pass all four axes are marked `verified=1`. Each verdict
is stamped into the historical DB (`reviewed_at`, `review_revision`)
so subsequent `--resume` calls skip already-judged findings.

### 5. Variant loop (opt-in via `--variant-loop`) (`acuario/scanner/variant_loop.py`)

**Off by default** (historically 0 verified findings, and the source
of a multi-hour single-call stall) - enable with `--variant-loop`.

For each verified finding, ask the LLM for a lexical `grep_regex` (a
single-line regex) plus a semantic description from the finding's
signature, then scan the codebase line-by-line with that regex.
Each match becomes a new suspicion-level finding linked back to the
parent.

### 6. Exploit-dev (runs by default; disable with `--no-exploit`) (`acuario/scanner/exploit_dev.py`)

For verified findings with `crash_reproduced` or higher evidence, an
exploit-dev agent generates a working PoC, runs it inside the sandbox
against the source/binary, and captures the output. Successful PoCs
upgrade the finding's `evidence_level` to `exploit_demonstrated`.

This stage runs **by default** on `crash_reproduced`+ findings; pass
`--no-exploit` to skip it. The separate `--exploit` flag is unrelated
to this stage - it instructs the per-file analyzers to attempt writing
exploits during the analysis phase itself.

The PoC is stored in the finding's `poc` and `crash_evidence` fields
- **never written to the source tree**. Acuario doesn't patch.

**Live hosting (`acuario/sandbox/apphost.py`).** For a *live* PoC the target
app is stood up on a per-target, egress-free `--internal` network and the
exploit sandbox joins it by `network_mode`, probing services by Docker DNS.
A pluggable `AppHost` resolver picks the first tier that fits:

1. `acuario.host.yml` recipe (explicit override; see `docs/acuario.host.yml.example`)
2. `docker-compose.yml` (multi-service stack)
3. a root `Dockerfile` (built + run as one service)
4. an auto-detected stack (Python / Node) - a Dockerfile is synthesized

A database sidecar (postgres / mysql / mssql) is provisioned - schema + seed
loaded, connection env injected - when a `schema.sql` is detected or the recipe
declares one. Every host implements the same `up()` / `reset()` (clean state
per finding) / `down()` lifecycle, all time-bounded. If nothing can be stood up
(an unknown stack, or a Windows-only runtime such as ASP.NET/IIS), the stage
falls back to a **static PoC** rather than failing the run.

### 7. Stability check (`acuario/scanner/stability.py`)

For exploit-confirmed findings, replay the PoC across multiple fresh
sandbox containers (configurable runs-per-container) to confirm the
bug is reproducible, not a one-off race. Classifies findings as
stable / flaky / unreliable.

### 8. Software composition analysis (SCA) (`acuario/scanner/sca.py`)

Runs by default after exploit-dev (`--no-sca` to skip). The LLM hunt reads
*code*, not manifests, so vulnerable dependencies get reasoned about but rarely
emitted as findings. SCA closes that deterministically: parse the npm manifests
+ lockfiles, resolve exact installed versions, and match them against a bundled
**offline** advisory snapshot - one finding per (package, CVE/advisory). These
enter the verified set directly, bypassing the skeptic / validator (a dependency
CVE has no in-code trace to gate on). A finding fires **only** on an exact
resolved version inside a vulnerable range; loose semver without a lockfile is
skipped, never guessed. Offline curated seed (npm today), expandable, no network
fetch.

### 9. Reporter (`acuario/scanner/reporter.py`)

Writes the report formats plus a manifest to the results directory -
`./results/scanner/<session-id>/` in a dev/git checkout,
`~/.acuario/results/scanner/<session-id>/` for an installed package:

- `findings.sarif` - IDE / code scanning (GitHub, IntelliJ); enriched with
  `security-severity`, CWE tags + `helpUri`, and stable `partialFingerprints`
  so alerts are ranked and tracked across scans
- `report.md` - human narrative; a two-column Severity Breakdown (Total /
  Verified) and per-finding details, over unique locations (same-locus
  duplicates folded into one primary with an "also reported as" note)
- `report.pdf` - a native, paginated, print-ready rendering (reportlab, no
  system deps) of the same substance as `report.md`
- `findings.json` - flat JSON for scripting (keeps every finding, incl.
  duplicates, marked with `duplicate_of`)
- `manifest.json` - counts (raw + unique) + spend summary
- `calibration.jsonl` - per-finding agreement log joining the skeptic verdict,
  the validator verdict, and the exploit outcome, so a run yields
  severity/confidence-vs-ground-truth data with no annotation labor

## Lab subsystem (`acuario/lab/`)

The lab subsystem adds multi-agent collaboration, snapshottable sandboxes, and
real-time syscall monitoring on top of the core audit pipeline.

### Updated pipeline with lab agents

```
preprocessor → prioritizer
                   │
                   ▼
         analyzer pool → [recall] → [context] → ◐ engage <file>
                                                  ● complete → N findings
                                                  [critic] reflective pass
                   │
                   ▼
         skeptic gate (per-finding adversarial challenge)
           ✓ accept → findings pool
           ✗ refute → skeptic_refuted.jsonl
                   │
                   ▼
         findings pool ◄── critic leads (discovered_by="critic")
                   │
                   ▼
         cross-file orchestrator → subsystem hunter pool (auto-executed)
                   │                          findings tagged subsystem_source
                   ▼
            reviewer → reporter → team_discussion.md
                   │
         (if --exploit):
         exploit-dev  ◇ snapshot → ▸ ptrace wraps each exec → run PoC
                      ◇ rollback on failure
```

### Lab agents

- **`acuario/lab/agents/skeptic.py`** - `SkepticGate` runs between the analyzer
  pool and the findings pool.  Must produce a concrete refutation before a finding
  enters.  Sees the finding, a source snippet, and a cross-file context block.
  Persists every decision (accept + refute) to `skeptic_log.jsonl`.  Default: on.
  Toggle: `--no-skeptic-gate`.
- **`acuario/lab/agents/critic.py`** - `ReflectiveCritic` runs after each analyzer
  session, concurrently with the next dispatch.  Sees the analyzer's trajectory
  summary, existing findings, the source file (up to 12 KB), and the cross-file
  context block.  Emits low-confidence leads tagged `discovered_by="critic"`.
  The lead-to-`Finding` conversion auto-extracts a `code_snippet` from the
  source file.  Persists prompt + response + leads to `critic_log.jsonl`.
  Default: on.  Toggle: `--no-critic`.
- **`acuario/lab/agents/orchestrator.py`** - `CrossFileOrchestrator` runs once
  after the per-file pool.  Reads pool + callgraph + a structural map of every
  in-scope file (definitions, calls, callers, internal deps - not just topology),
  emits up to five `SubsystemPlan` objects.  Plans **auto-execute** as a
  follow-up subsystem-hunter pass; emitted findings are tagged with
  `subsystem_source="orchestrator"` and `subsystem_plan_id`.  Persists every
  emission to `orchestrator_log.jsonl`.  Default: on.  Toggle: `--no-orchestrator`.
- **`acuario/lab/agents/_retry.py`** - shared transient-error retry helper used
  by all three agents.  Wraps each agent's LLM call with up to 3 outer
  attempts on parse-recoverable failures (empty body, malformed JSON), on top
  of the LLM transport layer's 6-attempt rate-limit / network retry.

### Lab sandbox

- **`acuario/lab/sandbox/snapshot.py`** - `SandboxSnapshotter` wraps
  `SandboxContainer`.  API: `snapshot(label)`, `revert_to(handle)`,
  `cleanup_snapshots()`.  Used by `exploit_dev.py` for hypothesis branching.
  Toggle: `--no-sandbox-snapshots`.
- **`acuario/lab/sandbox/behavior.py`** - `PtraceBehaviorMonitor` uses
  **per-command instrumentation**: when attached to a `SandboxContainer`,
  every `container.exec()` call wraps its argv with
  `strace -f -e trace=… -o /scratch/<id>.log -- <cmd>`, then reads the trace
  back and emits one `BehaviorEvent` per tracked syscall to
  `behavior_events.jsonl`.  This works where the earlier "attach `strace -p 1`"
  approach did not - PID 1 inside the container is `sleep infinity`, and the
  agent's exec'd subprocesses run in separate process trees.  Falls back to
  the regex monitor (`acuario/scanner/behavior_monitor.py`, tagged
  `[behavior]` in logs) when `strace` is unavailable inside the container.
  Toggle: `--no-ptrace-monitor`.

### Other v2 artifacts

- **`team_discussion.md`** - generated by
  `acuario/scanner/team_discussion_report.py` after every audit.  Aggregates
  every agent's reasoning on every finding into one Markdown file:
  per-finding sections show analyzer thoughts, skeptic verdict + reasoning,
  critic origin, reviewer 4-axis verdict, and exploit-dev outcome.  Reads
  the per-agent JSONL logs without truncation.
- **Findings-pool deduplication** - `FindingsPool.add()` collapses
  identical `(file, line, cwe)` entries into one cluster representative.
  Duplicate records produced by redundant analyzer runs are dropped rather
  than inflating the finding count.  Useful fields (`code_snippet`,
  `description`, `poc`) backfill onto the representative if it was missing
  them.

### Reading an audit run

The narration module (`acuario/ui/narration.py`) owns the run-surface vocabulary:

- **Run-start header box** - session id, target, lab flags, pipeline map.
- **Stage banners** - `══════════ stage: skeptic gate ══════════` between phases
  (console-only; not in `audit.log`).
- **`audit.log` vocabulary** - `[stage] glyph message` format (grep-friendly):
  - `◐` engage · `●` complete · `✓` accept · `✗` refute · `▸` event · `◇` checkpoint · `⚠` alert
- **End-of-run summary** - labeled blocks: INVESTIGATION / LAB / LLM / OUTPUTS /
  TOP FINDINGS / NEXT.

See [`docs/lab.md`](lab.md) for the detailed lab walkthrough.

---

## Sandbox layer (`acuario/sandbox/`)

The analyzer + exploit-dev + stability stages all run inside disposable
Docker containers (`acuario-scanner:<image-id>`). Each container:

- Has the audited workspace mounted at `/workspace` (read-only by
  default; `/scratch` is writable for the agent)
- Runs without network by default
- Has a configurable seccomp profile
- Is torn down at the end of each per-file analyzer run

Containers are spun up by a `sandbox_factory` callable that returns
a `SandboxContainer`. `AnalyzerSandbox` wraps the factory with
behavior monitoring (it watches for unexpected file paths or network
attempts and surfaces them as warnings).

## LLM layer (`acuario/llm/`)

`AsyncLLMClient` (`acuario/llm/native.py`) is the native Rust-backed
client over `genai-pyo3`. It speaks every major provider:

- Anthropic (`anthropic`)
- OpenAI (`openai` for chat/completions, `openai_resp` for the
  Responses API)
- OpenRouter, Together, Groq, Fireworks, DeepSeek, LM Studio, vLLM,
  any custom (`openai`)
- Ollama (`ollama` adapter, no `/v1` shim required)
- MiniMax (`anthropic`-compatible endpoint at api.minimax.io)

Per-task routing is supported: see [providers.md](providers.md) for
the YAML config that routes `prioritizer` to a small fast model and
`analyzer` to a big one.

The genai-pyo3 client is **cached per `AsyncLLMClient` instance** so
we don't rebuild reqwest clients (and exhaust TLS / CA-cert FDs) on
every call. This was the root cause of an earlier crash class.

## Persistence

- `~/.acuario/config.yaml` - provider settings
- `~/.acuario/scanner/historical_findings.db` - sqlite store of all
  past findings, keyed by `(repo_url, campaign_session_id)`. Powers
  `acuario history`, `acuario report`, and `--resume`.
- `~/.acuario/scanner/trajectories/<session>-<file>/` - per-file
  agent transcripts (debug / replay use only)
- `./results/scanner/<session-id>/` (dev/git checkout) or
  `~/.acuario/results/scanner/<session-id>/` (installed package) -
  rendered reports

## Resume mechanism (`acuario/scanner/resume.py`)

The audit pipeline persists findings to the historical DB **as the
analyzer pool finishes**, before the reviewer/exploit-dev/reporter
stages run. If anything later crashes (LLM panic, FD exhaustion,
host reboot), the analyzer's expensive work is already saved.

`acuario audit --resume <session-id>`:

1. Reads the saved findings from the DB
2. Re-runs the reviewer pass on findings without a verdict
3. Renders the report

The reviewer is serial with a two-layer retry strategy:

- **Per-finding inner retry**: 5 attempts with exponential backoff
  (1s → 2s → 4s → 8s → 16s) on transient-error markers
  (`web stream error`, `connection reset`, `timed out`, …).
- **Outer multi-pass**: after the first pass, any finding that still
  didn't get a verdict is re-attempted in a follow-up pass. Up to 3
  outer passes; stops early if a pass produces zero new verdicts
  (the LLM service is genuinely down, not transient).

Idempotent: findings with a saved verdict are skipped. `--force-review`
bypasses the skip and bumps the per-finding `review_revision`.
