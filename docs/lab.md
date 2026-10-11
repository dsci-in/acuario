# The Acuario Lab

Acuario runs a *multi-agent security research team* inside a snapshottable laboratory
environment.  This page explains how the lab works, why each component exists, and
how they wire into the audit pipeline.

## What the lab is and why

Acuario's lab subsystem (`acuario/lab/`) is the coordination layer that sits above
the per-file analyzer pipeline.  It introduces:

| Capability | Lab component |
|---|---|
| Adversarial precision filter | Skeptic gate - every finding must survive a refutation attempt before entering the pool |
| Reflective recall pass | Reflective critic - one extra call per session: "what paths did you skip?" |
| Cross-file investigation planning | Cross-file orchestrator - reads the pool + callgraph + structural map, emits multi-file hunt plans that auto-execute |
| Hypothesis branching in exploit-dev | Sandbox snapshotter - Docker-commit checkpoints allow rollback between exploit variants |
| Real syscall observation | Ptrace monitor - wraps every container exec with strace, captures actual kernel events |
| Aggregated agent debate per finding | `team_discussion.md` - a single report with every agent's reasoning on every finding |
| Post-audit session exploration | `acuario inspect` - interactive REPL over a completed audit's artifacts |

---

## 1. Skeptic gate (`acuario/lab/agents/skeptic.py`)

**Role:** Inserted between the analyzer pool and the findings pool.  For every
analyzer-emitted finding, the skeptic must produce one concrete refutation - a
specific code reference, a contradicting precondition, or a demonstrated bypass of
the claimed attack path - before the finding can enter the pool.  If the skeptic
fails to refute within its budget, the finding is accepted.

**Adversarial by construction:** The skeptic doesn't ask "is this valid?" - it asks
"prove this is *not* a bug."  This is the highest-precision lift per LOC of any
change in the lab, because it fires on every finding.

**Three-way verdict (O1):** A refutation only kills a finding when it cites the
*specific code* that makes it a false positive (the exact sanitizer call, the
parameterized query, the access-control check on the reachable path). A doubt
that rests on a general assumption - "the framework probably escapes this",
"this is usually called from trusted code" - is recorded as **uncertain**, and
the finding **passes through flagged** (`skeptic_flag=uncertain`) for the
validator to weigh, rather than being silently dropped. This directly attacks
over-refutation: a hand-wave can no longer kill a true positive. Each verdict
also carries a `confidence` (0.0-1.0).

**Shadow mode (O8):** `--skeptic-shadow-mode` runs the skeptic for its verdicts
but never gates - every finding passes to the validator, which becomes ground
truth for the skeptic's refutations. The run writes `calibration.jsonl` joining
each finding's skeptic verdict, validator verdict, and exploit outcome, so the
skeptic's false-negative rate is measurable without any hand-labeling.

**Inputs:** the finding, a source snippet around the bug (up to 4 KB), and a
cross-file context block (direct callers, direct callees, prior findings on
the same file from past audits, up to 3 KB).  The skeptic does not see the
analyzer's reasoning trail - that's deliberate, so it forms its own view
without anchoring to the analyzer's conclusion.

**Outputs:**
- Accepted findings flow into the findings pool as normal.
- Every skeptic decision (accept and refute) is persisted to
  `skeptic_log.jsonl` with the full prompt, the raw LLM response, the
  parsed verdict, and the reasoning - no truncation.
- Refuted findings additionally land in `skeptic_refuted.jsonl` for backwards
  compatibility with older `acuario inspect` flows.

**Retry:** transient LLM errors retry up to six times at the LLM transport
layer with exponential backoff; parse-recoverable failures (empty body,
malformed JSON) get an additional three outer attempts before the gate
fails open and accepts the finding.

**Toggle:** `--no-skeptic-gate` disables it (default: on).

**Example refutation (in `audit.log`):**
```
[skeptic] ✗ refute analyzer-1d1e8bb5 (input sanitised at call site, line 47)
[skeptic] ✓ accept analyzer-086a5448
```

---

## 2. Reflective critic (`acuario/lab/agents/critic.py`)

**Role:** After an analyzer's ReAct loop terminates, one additional LLM call fires:
*"You analyzed file X and produced these findings.  Read your own trajectory.  What
would a skeptic say you missed?  Any code paths you didn't follow?"*

Findings the critic emits are tagged `discovered_by="critic"` and enter the pool at
`evidence_level="suspicion"`.  They still go through the normal validator and skeptic
flows, so noise is filtered before findings are accepted.

**Inputs:** the trajectory summary (up to 1.5 KB), the analyzer's existing
findings on this file (first 30), a source snippet of the file (up to 12 KB),
and a cross-file context block (up to 3 KB).  Having the actual source +
callers/callees makes the critic significantly more accurate - without them
it speculates from the trajectory alone.

**Outputs:**
- Each lead is converted into a `Finding` and run through the skeptic gate.
- The lead-to-`Finding` conversion auto-extracts a code snippet from the
  source file around the lead's line, so critic-discovered findings show
  real code in reports rather than empty placeholders.
- Every reflection (prompt, raw response, parsed leads, elapsed time)
  persists to `critic_log.jsonl`.

**Why it matters:**  Closes the analyzer-tunnel-vision gap cheaply (one extra call per
file, concurrent with the next dispatch - the pipeline is not serialized).

**Toggle:** `--no-critic` disables it (default: on).

**Inspecting critic leads:**
```
acuario inspect <session>
> critic
  [analyzer-bbbb0002]  app/comments.php:17  XSS in comment rendering  (critic)
```

---

## 3. Cross-file orchestrator (`acuario/lab/agents/orchestrator.py`)

**Role:** Runs once per audit after the initial per-file analyzer pool completes.
Reads the findings pool + callgraph + a structural map of every in-scope file
and emits *investigation plans*:
```json
{
  "files": ["app/login.php", "app/session.php"],
  "hunt_focus": "shared session-token contract",
  "rationale": "Both files read SESSION_TOKEN without validating its origin"
}
```

**Structural map (not just topology):** for every file in scope, the orchestrator
sees the list of function/class definitions with line numbers, the file's
outgoing calls, its callers, and which files in the project define names this
file calls.  That's a "map of the codebase" rather than only the top-N caller
counts - and it scales linearly with project size at a few dozen tokens per
file.

**Auto-execution:** when the orchestrator emits plans, the subsystem-hunt
phase is automatically enabled (you do not need `--subsystem-hunt`).  Each
plan converts to a `SubsystemTarget` and runs as a real multi-file analyzer
session via the existing `build_subsystem_hunter_agent` path.  Findings the
hunt surfaces are tagged with `subsystem_source="orchestrator"` and
`subsystem_plan_id=<plan-id>` so they trace back to the originating plan in
`findings.json` and `team_discussion.md`.

**Outputs:** every plan emission (prompt, raw response, parsed plans,
elapsed time) persists to `orchestrator_log.jsonl`.

**Why it matters:**  Addresses Acuario's #1 architectural weakness (per-file myopia).
Most LLM-audit tools have no cross-file reasoning at all.

**Toggle:** `--no-orchestrator` disables it (default: on).

**Inspecting orchestrator plans:**
```
acuario inspect <session>
> orchestrator
  Plan 1  focus: shared auth bypass
  files: app/login.php, app/session.php
  rationale: ...
  led to findings: analyzer-cccc0003
```

---

## 4. Sandbox snapshotter (`acuario/lab/sandbox/snapshot.py`)

**Role:** Wraps `SandboxContainer` to add Docker-commit-based checkpoint/rollback.
Before each exploit attempt, the agent commits the container's filesystem state to an
intermediate image.  On a failed hypothesis it reverts to that image, restoring the
pre-attempt state instantly, then tries a different variant.

**Why it matters:** Today every failed exploit attempt tears down and rebuilds a
sandbox from scratch.  With snapshotting, hypothesis branching is fast (reuse the
compiled binary, pre-installed dependencies) and clean (no contamination from the
failed attempt).

**Wire-in point:** `acuario/scanner/exploit_dev.py::AgenticExploiter.aattempt()` -
snapshots before each attempt, reverts on failure, cleans up intermediate images at
audit end.

**Log vocabulary:**
```
[lab/sandbox] ◇ snapshot 'pre-exploit' → acuario-snap-session:abc123
[lab/sandbox] ◇ rollback to snapshot 'pre-exploit' (acuario-snap-session:abc123)
[lab/sandbox] cleaned up 3 snapshot image(s)
```

**Flag:** `--no-sandbox-snapshots` disables it.  Default: on when the Docker
daemon supports `commit`.  The flag pairs with `--no-ptrace-monitor` for runs
that want the baseline sandbox behavior for comparison.

---

## 5. Ptrace behavior monitor (`acuario/lab/sandbox/behavior.py`)

**Role:** Replaces the post-hoc regex monitor (`behavior_monitor.py`) as the
primary behavior-auditing layer.  Streams real kernel syscall events to
`results/scanner/<session>/behavior_events.jsonl`.

**Why it matters:** The regex monitor scans agent *output* after the fact - it
catches things like `curl` or `wget` appearing in a transcript.  It cannot catch a
bare `open("/etc/passwd", O_RDONLY)` call because there's no shell command to grep.
The ptrace monitor sees the actual kernel call.

**How it works:** the monitor uses **per-command instrumentation**, not an
attach-to-init daemon.  When attached to a `SandboxContainer`, every call to
`container.exec()` gets transparently wrapped:

```
strace -f -e trace=<set> -o /scratch/_ptrace_<id>.log -- <original_argv>
```

The wrapped command runs as normal; the trace file is read back via a
separate non-instrumented `cat`, parsed, and one structured event is emitted
per tracked syscall.  This works where the original "attach `strace -p 1`"
approach did not - PID 1 inside a sandbox is `sleep infinity`, and the
agent's `docker exec` commands run in separate process trees that strace
cannot follow without per-command instrumentation.

**Tracked syscalls:** `open`, `openat`, `openat2`, `execve`, `execveat`, `connect`,
`socket`, `mount`, `pivot_root`, and relatives.

**Severity classification:**
- `critical`: `mount`, `pivot_root` - container escape indicators
- `warning`: `execve`, `connect`, paths under `/etc/`, `/proc/self/`, `/proc/1/`
- `info`: all other tracked syscalls

This mapping is a starting point, not flat: an `execve` of a staged binary
(paths under `/scratch`, `/tmp`, `/var/tmp`, `/dev/shm`) is escalated to
`critical`, while a routine tool exec and a benign `/etc/` read (e.g.
`ld.so.cache`, `hosts`, `resolv.conf`) are demoted to `info`.

**Image dependency:** `strace` is pre-installed in every sandbox image via
`COMMON_APT_PACKAGES` (see `acuario/sandbox/builders.py`).  Custom images
that drop the package will trigger the fallback path.

**Scratch writability dependency (operational note):** the per-command wrap
writes its trace file to `/scratch/_ptrace_<id>.log` inside the container.
`/scratch` is bind-mounted from a host tempdir under `/tmp/acuario-scratch-*`.
`AnalyzerSandbox.spawn()` chmods this tempdir to `0o777` so the container's
user can write into it regardless of whether the Docker daemon is configured
with `userns-remap`.  Without this chmod the strace command silently fails
with `Permission denied`, no trace file lands, and `behavior_events.jsonl`
stays at zero bytes despite `ptrace_monitor.start()` reporting `ok`.  The
diagnostic line `[lab/sandbox] ptrace_monitor.start() → ok (session=…)` in
`audit.log` lets you confirm the monitor attached; the corresponding
`[ptrace] ◇ monitor stopped - N events captured` line tells you whether the
wrap actually produced events.

**Fallback:** When `strace` is unavailable inside the container - older
images, custom builds, daemon configurations that block exec - the
monitor's startup probe returns `False` and the regex behavior monitor
takes over.  The regex fallback is tagged `[behavior]` in the audit log;
real syscall events use `[ptrace]`, so a reviewer can tell at a glance
which monitor produced an alert.

**Log vocabulary:**
```
[ptrace] ▸ monitor activated for session exploit-abc123
[ptrace] ⚠ openat(/etc/passwd) in session exploit-abc123 [warning]
[ptrace] ◇ monitor stopped - 7 events captured for session exploit-abc123
[lab/sandbox] ⚠ ptrace unavailable, regex monitor remains the fallback
```

**Flag:** `--no-ptrace-monitor` disables just the syscall layer;
`--no-behavior-monitor` disables both monitors together.

**Analyzer sessions (N2).** The monitor isn't exploit-dev-only anymore. In
**deep** mode (deep depth only), each analyzer sandbox is also
strace-wrapped, and its compile/run syscalls stream to a separate
`analyzer_behavior_events.jsonl` in the session directory. This gives syscall
visibility during the analysis phase - useful for spotting sandbox-escape or
privilege-escalation behavior while the agent is still investigating, not just
during exploitation. It degrades the same way: if strace can't attach, the
analyzer just runs unwrapped. Respects `--no-ptrace-monitor`.

---

## 6. Live-app dynamic validation (`acuario/sandbox/app_harness.py`)

**Role:** Turn "this looks like SQLi" into "I sent this request and the
response leaked a row." For web-application findings, the strongest possible
evidence is a real HTTP request against a *running* instance - not a static
argument from source. The `AppHarness` launches the target app **inside the
existing exploit-dev sandbox** and lets the agent probe it.

Why it stays safe: a `--network none` container still has a working loopback
interface, so a server started by one `docker exec` is reachable at
`127.0.0.1:<port>` from another `docker exec` in the same container - with
zero outbound connectivity. The harness never relaxes the network isolation.

Three tools join the exploit-dev tool set:

| Tool | What it does |
|---|---|
| `launch_app` | Auto-detects the launch recipe (PHP `php -S`, Django `manage.py runserver`, Flask, FastAPI/uvicorn, Node) or takes an explicit `command`; starts it detached and waits until it answers. |
| `http_request` | Sends a method/path/headers/body request over loopback and returns the parsed status, headers, and body - the primary evidence tool for web bugs. |
| `read_app_log` | Tails the app's stdout/stderr - stack traces and SQL errors your payload triggered are often the clearest confirmation. |

A response that demonstrably misbehaves (a leaked row, a reflected payload, a
200 on a protected route) is recorded as the exploit and lifts the finding to
`exploit_demonstrated` honestly. The server is killed (process-group `kill`)
when the exploit session ends.

PHP support: the build detector now recognizes `composer.json` / `.php` file
mixes and maps them to a `php:8.2-cli` image (which ships `php -S`), so PHP
targets - common in the test corpora - launch out of the box.

---

## Sandbox isolation tiers

Every sandbox container runs with `network_mode="none"`, `cap_drop=["ALL"]`
(which removes `NET_RAW` and every other capability), a `pids_limit`, memory
and CPU caps, and a seccomp profile. On top of that baseline:

| Tier | How to enable | What it adds |
|---|---|---|
| **Default** | (always on) | Allow-by-default seccomp that blocks host-escape syscalls (`mount`, `pivot_root`, `kexec_*`, `unshare`, `setns`, …). The analyzer can still open loopback sockets - a deep analyzer may run a target server to confirm a bug. |
| **Strict** | `--strict-sandbox` | Adds networking syscalls (`socket`, `connect`, `bind`, `listen`, `accept`) to the analyzer denylist - defense-in-depth for running untrusted target code. Off by default because it forecloses loopback dynamic testing. The exploit-dev / live-app harness keeps sockets regardless (it probes over loopback). |
| **gVisor** | `--gvisor` | Runs containers under the gVisor (`runsc`) runtime - a user-space kernel that intercepts syscalls, a far stronger boundary than namespaces alone. Falls back to the default Docker runtime with a warning if `runsc` isn't installed, so the flag is safe to leave on. |

---

## 7. Team discussion report (`acuario/scanner/team_discussion_report.py`)

**Role:** Aggregates every lab agent's reasoning on every finding into a
single Markdown artifact: `results/scanner/<session>/team_discussion.md`.
Generated automatically after every audit, alongside `report.md`, `report.pdf`,
and the SARIF / JSON outputs. (The raw ptrace syscall trace it embeds renders as
a collapsed code block, not a table, so the document stays fast to open.)

**Why it matters:** `report.md` is the verdict - severity, CWE, evidence
level.  `team_discussion.md` is the deliberation - for each finding, the
analyzer's reasoning chain, the skeptic's verdict and reasoning, the
critic's origin notes when applicable, the reviewer's 4-axis verdict with
rationales, and the exploit-dev outcome when `--exploit` was on.  Long
analyzer reasoning chains wrap in collapsed `<details>` blocks so the
file stays scannable without sacrificing content.

**Inputs** (read from disk after the run, not from in-memory state):
- `findings.json` for the verified + unverified findings
- `skeptic_log.jsonl` / `critic_log.jsonl` / `orchestrator_log.jsonl` for
  per-agent prompts and responses
- Analyzer trajectories under `~/.acuario/scanner/trajectories/`
- `exploits/<id>/transcript.jsonl` for exploit-dev outcomes
- `behavior_events.jsonl` for the ptrace events section

**Full content, no truncation:** the per-agent JSONL logs are written without
caps, and the renderer emits the full content of every excerpt.  The earlier
practice of clipping LLM responses to a few hundred chars made the report
look complete while quietly hiding the bulk of the agent's reasoning;
that's gone.

---

## 8. How the lab agents wire into the audit pipeline

The full pipeline with lab insertions:

```
preprocessor → prioritizer
                   │
                   ▼
         ┌─── analyzer pool ───────────────────────────────────┐
         │  For each file:                                      │
         │   [recall] inject prior mechanisms into prompt       │
         │   [context] pre-seed with callers, imports, history  │
         │   ◐ engage <file>                                    │
         │   ● complete → N findings                            │
         │   [critic] reflective pass on trajectory             │
         └─────────────────────────────────────────────────────┘
                   │
                   ▼
         ┌─── skeptic gate ────────┐
         │  For each finding:      │
         │   ✓ accept → pool       │
         │   ✗ refute → jsonl      │
         └─────────────────────────┘
                   │
                   ▼
           findings pool ◄── critic leads (discovered_by="critic")
                   │
                   ▼
         ┌─── cross-file orchestrator ──────────────┐
         │   reads pool + callgraph + structural map │
         │   emits N subsystem plans                 │
         └──────────────────────────────────────────┘
                   │
                   ▼
         ┌─── subsystem hunter pool ────────────────┐
         │   auto-runs orchestrator plans           │
         │   findings tagged subsystem_source=      │
         │   "orchestrator" + plan_id                │
         └──────────────────────────────────────────┘
                   │
                   ▼
            reviewer → reporter → team_discussion.md
                   │
         (if --exploit):
         ┌─── exploit-dev ─────────────────────────┐
         │   ◇ snapshot pre-exploit                 │
         │   ▸ ptrace wraps every container exec    │
         │   run PoC agent                          │
         │   ◇ rollback on failure                  │
         └─────────────────────────────────────────┘
```

The diagram shows the skeptic gate, per-finding debate, and reflective critic
as discrete boxes for readability, but they don't run as a monolithic
post-pool phase: each runs **per-file inside the analyzer pool** as a detached
task off the dispatch path, and the results are joined at a barrier before the
findings pool moves on.

The `[ptrace]` monitor wraps each command issued inside the exploit-dev
sandbox; the `[behavior]` regex monitor scans agent transcripts.

---

## 9. Reading an audit run with lab agents active

When lab agents are enabled, `audit.log` contains lines like:

```
[analyze:surface] ◐ engage app3/cart.php
[recall] ▸ injected 3 prior mechanisms into app3/cart.php prompt
[context] ▸ pre-seeded app3/cart.php with 7 callers, 3 imports
[analyze:surface] ● app3/cart.php → 4 findings ($1.88)
[critic] ▸ added 2 low-confidence leads from app3/cart.php trajectory
[skeptic] ✓ accept analyzer-1d1e8bb5
[skeptic] ✗ refute analyzer-X (reason: input sanitised at call site, line 47)
[orchestrate] ▸ emitted 3 subsystem plans from findings pool
[orchestrate] ▸ auto-enabling subsystem hunt to execute 3 plan(s)
[review] ✓ analyzer-1d1e8bb5 (1/81)
[review] ✗ analyzer-Y (2/81) insufficient evidence
[ptrace] ▸ monitor activated for session exploit-1d1e8bb5
[ptrace] ⚠ openat(/etc/passwd) in exploit-1d1e8bb5 [warning]
```

Note the tier labels are `surface` (tier A - entry-point / high-attack-surface
files), `depth` (tier B - deeper internals), and `trace` (tier C - low-priority
coverage) rather than raw A / B / C.  The internal tier letters are
unchanged; only the display labels were renamed for readability.

The glyph vocabulary:

| Glyph | Meaning |
|---|---|
| `◐` | Engage - investigation starting |
| `●` | Complete - investigation finished |
| `✓` | Accept / verified |
| `✗` | Refute / rejected |
| `▸` | Event |
| `◇` | Checkpoint (snapshot / rollback) |
| `⚠` | Alert |

The stage prefixes also tell you which monitor produced an alert:
`[ptrace]` is the syscall-level observer; `[behavior]` is the regex
transcript scanner.

See also `acuario inspect --help` for the glossary in the REPL.
