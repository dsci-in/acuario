# Acuario

```
 █████╗  ██████╗██╗   ██╗ █████╗ ██████╗ ██╗ ██████╗
██╔══██╗██╔════╝██║   ██║██╔══██╗██╔══██╗██║██╔═══██╗
███████║██║     ██║   ██║███████║██████╔╝██║██║   ██║
██╔══██║██║     ██║   ██║██╔══██║██╔══██╗██║██║   ██║
██║  ██║╚██████╗╚██████╔╝██║  ██║██║  ██║██║╚██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝
    Multi AI Agent Source Code Auditing Sandbox
```

**Multi AI Agent Source Code Auditing Sandbox.** Built on `genai-pyo3`,
a native Rust-backed LLM runtime that speaks every major provider -
Anthropic, OpenAI, OpenRouter, Ollama, LM Studio, vLLM, Together, Groq,
DeepSeek, MiniMax, or any OpenAI-compatible endpoint.

Acuario does one thing: **find vulnerabilities in source code**, with
sandboxed analyzer agents, an adversarial reviewer, optional
proof-of-concept generation, deterministic dependency (SCA) scanning, and
resumable runs that survive crashes.

- **Source-code audit** - a per-file LLM analyzer agent runs inside a
  Docker sandbox, calls a small tool set (read / search / record),
  and produces findings. An adversarial reviewer runs a 4-axis
  validation pass to weed out false positives. SARIF + Markdown + JSON
  + a native PDF report drop into `./results/scanner/<session-id>/` (a git checkout) or
  `~/.acuario/results/scanner/<session-id>/` (an installed package).
- **Exploit confirmation** (default; disable with `--no-exploit`) - for
  verified, crash-reproduced findings an exploit-dev agent generates a PoC
  and **runs it inside the sandbox**, capturing the output as evidence and
  upgrading the finding's evidence level when the PoC actually triggers the
  bug. (The separate `--exploit` flag tells the per-file analyzers to
  attempt exploit-writing during the hunt.)
- **Resumable runs** - `acuario audit --resume <session-id>` picks
  up from a saved state after any crash (network drop, sandbox FD
  exhaustion, host reboot).
- **Real-cost transparency** - runs on self-hosted endpoints (Ollama,
  vLLM, LM Studio) report `$0.00` paid plus a "what this would have
  cost on current frontier models (Claude Opus / OpenAI GPT-class)"
  reference quote. Commercial APIs show real billing.

---

## The Acuario lab

Acuario is architected as a **multi-agent security research lab**.  The audit pipeline
coordinates a team of specialist agents, each with a defined role, operating inside
sandboxes that can checkpoint and roll back - rather than a single analyst reading
files in sequence.

### Coordinated agent team (`acuario/lab/agents/`)

Three agents collaborate around the core audit pipeline:

- **Skeptic gate** - adversarial agent inserted between the analyzer pool and the
  findings pool.  Must produce a concrete refutation (a specific code reference,
  a contradicting precondition) before any finding enters the pool.  Fires on every
  finding; adversarial by construction.  Sees the finding, a source snippet, and
  a cross-file context block (callers / callees / prior findings).  Every
  decision - accept and refute - is persisted to `skeptic_log.jsonl` with the
  full prompt and raw LLM response.
- **Reflective critic** - after each analyzer session concludes, one extra LLM call
  asks *"read your own trajectory - what did you miss?"*  Sees the analyzer's
  existing findings, the source file, and the cross-file context.  Leads enter the
  pool tagged `discovered_by="critic"` at low confidence, then go through the normal
  validator/skeptic flow.  The lead-to-`Finding` conversion auto-extracts a code
  snippet from the source file, so critic findings show real code rather than
  placeholders.  Runs concurrently with the next file dispatch; no pipeline
  serialization.
- **Cross-file orchestrator** - reads the findings pool, the call graph, and a
  structural map of every in-scope file (definitions, calls, callers, internal
  deps) after the per-file pass.  Emits structured investigation plans for
  shared-state and boundary bugs.  Plans **auto-execute** as a follow-up
  subsystem-hunter pass; resulting findings are tagged with
  `subsystem_source="orchestrator"` and the plan ID so they trace back to the
  originating plan in `findings.json`.

### Snapshottable sandbox (`acuario/lab/sandbox/`)

The `SandboxSnapshotter` wraps `SandboxContainer` to add Docker-commit checkpoints.
Before each exploit attempt the agent snapshots the container state; on a failed
hypothesis it reverts instantly - enabling multi-hypothesis exploration without
paying the sandbox rebuild cost for each variant.

The `PtraceBehaviorMonitor` captures real syscalls via per-command
instrumentation: when attached to the sandbox, every `container.exec()` call
is wrapped with `strace -f -e trace=… -o /scratch/<id>.log -- <argv>`, and
the resulting trace is read back and emitted to `behavior_events.jsonl`.
This catches syscalls the regex `[behavior]` monitor cannot - a bare
`open("/etc/passwd")` issued by the agent leaves a real syscall event even
when nothing about it shows up in the agent's transcript.  Falls back to the
regex monitor when `strace` is unavailable inside the sandbox image.

### `team_discussion.md` - the multi-agent debate report

Every audit also writes `team_discussion.md` - a single Markdown artifact
that aggregates every agent's reasoning on every finding.  Per-finding
sections show the analyzer's reasoning chain (collapsed in long sessions
so the file stays scannable), the skeptic's verdict and full reasoning,
the critic's origin notes when applicable, the reviewer's 4-axis verdict
with rationales, and the exploit-dev outcome when `--exploit` was on.
No content is truncated.

### `acuario inspect` - interactive session explorer

```
acuario inspect audit-3eff431d
> list --severity critical
> show analyzer-1d1e8bb5
> why analyzer-1d1e8bb5      # LLM explains the reasoning chain
> skeptic analyzer-1d1e8bb5  # accepted or refuted, and why
> critic                     # reflective-critic leads for this session
> orchestrator               # cross-file plans and the findings they surfaced
> fix analyzer-1d1e8bb5      # read-only unified-diff suggestion
> exploit analyzer-1d1e8bb5  # PoC transcript and impact
> related analyzer-1d1e8bb5  # sibling findings from the same cluster
```

See [`docs/lab.md`](docs/lab.md) for the full lab walkthrough.

**Authorized use only.** Acuario is a dual-use offensive-security
tool. Run it only against code you own or have explicit written
authorization to audit. Operators are responsible for scope, legal
authorization, and disclosure.

---

## Setup - get to a first audit in five steps

Everything below this line is one linear flow. No need to open another
doc to reach a green audit run.

### 1. Requirements

**System packages** - install these before the install step below:

- **Python 3.10+**
- **git** - the scanner clones and reads the target repository
- **ripgrep** (`rg`) - the analyzer's fast code-search tool (required)
- **Docker Engine + the Compose v2 plugin** - the analyzer and exploit-dev
  agents run inside disposable sandbox containers, and the live-exploit stage
  brings target apps up with `docker compose`. The Compose plugin is a
  **separate package** from the engine on most distros (`docker.io` /
  `docker-ce` alone does **not** include it).
- Optional: **`gh`** (for `--auto-pr` / `--github-checks`), **`gdb`**
  (in-sandbox debugging)

```bash
# Debian / Ubuntu
sudo apt install -y git ripgrep docker.io docker-compose-v2
sudo usermod -aG docker "$USER"    # log out / back in so the group applies

# macOS (Homebrew) - Docker Desktop bundles Compose v2
brew install git ripgrep
brew install --cask docker
```

- **An LLM endpoint** - one of:
  - An Anthropic / OpenAI / OpenRouter / Together / Groq / DeepSeek API key
  - A local Ollama / LM Studio / vLLM server you control
  - Any OpenAI-compatible endpoint (the wizard has a "custom" preset)

After installing, run `acuario doctor` - it verifies Python, your LLM
credentials, the Docker daemon, `docker compose`, and the external CLI tools
(git, ripgrep, gh, gdb).

### 2. Install

```bash
git clone https://github.com/dsci-in/acuario.git
cd acuario

# `uv` is recommended - it reads pyproject.toml + uv.lock and builds
# the locked environment under .venv/. No Rust toolchain needed -
# genai-pyo3 ships as prebuilt wheels.
uv sync --all-extras
source .venv/bin/activate     # fish: source .venv/bin/activate.fish

acuario --version             # 2.0.0
```

If you don't have `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Or use plain pip (no lock-file pinning):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

### 3. Configure your LLM provider

Run the interactive wizard. It picks a preset, prompts for credentials,
runs an optional live test, and persists to `~/.acuario/config.yaml`.

```bash
acuario setup
```

The menu lists Anthropic, OpenRouter, Ollama, LM Studio, vLLM, OpenAI
(Chat / Responses / OAuth), Together, Groq, Fireworks, DeepSeek,
MiniMax, plus a custom OpenAI-compatible catch-all. For local servers
(Ollama / vLLM / LM Studio) the wizard auto-fetches the model list from
your endpoint so you can pick by number instead of typing model names.

### 4. Verify your environment

```bash
acuario doctor
```

Doctor checks Python version, your LLM credentials, Docker daemon
reachability + the `docker compose` plugin, external CLI tools
(git, ripgrep, gh, gdb), filesystem
permissions on `~/.acuario/`, and network reachability to your LLM
endpoint. Green-yellow-red glyphs per check.

### 5. Run your first audit

Point `audit` at a local folder, an absolute path, or a remote git URL.

```bash
# Fast pass - static patterns + LLM prioritizer only (no analyzer pool).
acuario audit . --depth quick

# Real audit - full pipeline (analyzer pool + 4-axis reviewer + exploit-dev).
acuario audit . --depth standard

# Same, but also have the analyzers attempt exploit-writing during the hunt.
acuario audit . --depth standard --exploit

# Audit a GitHub repo (Acuario clones it).
acuario audit https://github.com/example/project --depth standard
```

That's it - you're auditing.

---

## What the depths actually do

| Depth      | Stages run                                                                                          | Cost on commercial APIs |
|------------|-----------------------------------------------------------------------------------------------------|------------------------|
| `quick`    | Preprocessor + LLM prioritizer + static patterns (no analyzer pool / sandbox).                      | ~free (prioritizer)    |
| `standard` | + LLM analyzer pool, 4-axis reviewer, taint + reachability, mechanism memory, exploit-dev. **Default.** | ~$10-50 (Claude Sonnet) |
| `deep`     | + entry-point sharding, deeper promotion bands, analyzer ptrace monitoring.                          | higher                 |

Exploit-dev (sandboxed PoC generation on crash-reproduced findings) runs by
default; disable it with `--no-exploit`. The variant loop is opt-in via
`--variant-loop`. The separate `--exploit` flag makes the analyzers attempt
exploit-writing during the hunt.

For **live** PoCs the target app is stood up on an isolated, egress-free network
so the exploit agent can hit it by service DNS. It is hosted from - in order - an
`acuario.host.yml` recipe, a `docker-compose.yml`, a root `Dockerfile`, or an
auto-detected stack (Python / Node), with a database sidecar provisioned when a
schema is detected or the recipe asks. An app that can't be stood up (e.g. a
Windows/.NET runtime, or an unknown stack) falls back to a static PoC without
failing the run.

## Where the results land

Every audit writes to `~/.acuario/results/scanner/<session-id>/`:

| File                       | Audience                                              |
|----------------------------|-------------------------------------------------------|
| `findings.sarif`           | IDE integration (VS Code, IntelliJ, GitHub Code Scanning) |
| `report.md`                | Human-readable report                                 |
| `report.pdf`               | Paginated, print-ready report (same substance as `report.md`) |
| `findings.json`            | Programmatic / scripting consumers                    |
| `manifest.json`            | Counts, repo URL, tokens, real cost + reference quote |
| `team_discussion.md`       | Multi-agent debate per finding (full reasoning, no truncation; per-plan findings attributed back to their orchestrator plan) |
| `skeptic_log.jsonl`        | Every skeptic decision with full prompt + LLM response |
| `critic_log.jsonl`         | Every reflective-critic reflection with prompt + leads |
| `orchestrator_log.jsonl`   | Cross-file plan emissions with full reasoning          |
| `calibration.jsonl`        | Skeptic vs validator vs exploit-outcome agreement log (accuracy tuning) |
| `behavior_events.jsonl`    | Real syscall events from `[ptrace]` per-command strace wrap |
| `exploits/<id>/`           | Per-finding ReAct transcripts when `--exploit` is on  |

The CLI summary at the end of each run shows tokens consumed, cost
paid (real for commercial APIs, $0 for self-hosted), and reference
quotes against current frontier models (Claude Opus / OpenAI GPT-class)
when running locally.

## Inspecting past audits

```bash
acuario history                  # list every saved audit session
acuario history --repo Project1  # filter by repo path
acuario report <session-id>      # re-render reports (no LLM)
acuario report <session-id> --verify   # also re-run the reviewer
acuario sessions                 # alias of `history`
```

## Resuming a crashed run

If an audit dies mid-run (network blip, FD pressure, host reboot),
its findings are already persisted. Pick up where it stopped:

```bash
acuario audit --resume <session-id>            # full reviewer + reporter
acuario audit --resume <session-id> --no-verify  # skip reviewer (~30s)
```

The serial verifier + auto-retry handles transient network errors;
each `--resume` is idempotent.

---

## Architecture at a glance

<p align="center">
  <img src="docs/assets/architecture.png"
       alt="Acuario audit pipeline data-flow: a codebase (local dir or git repo) flows through preprocess and prioritize into a tiered, sandboxed hunt pool with an embedded adversarial lab, then cross-file and subsystem hunting, 4-axis verification, sandboxed exploit-dev, and a SARIF/Markdown/JSON/PDF report; a cross-run memory store persists results and feeds prior findings back into the next run's hunt pool."
       width="960">
</p>

<p align="center"><sub>The audited <code>acuario audit</code> pipeline. Exploit-dev runs by default (disable with <code>--no-exploit</code>); the variant loop is opt-in (<code>--variant-loop</code>). The sandbox defaults to runc + <code>net=none</code>; gVisor, ptrace monitoring, and warm pools are opt-in.</sub></p>

The analyzer agent's tool set lives under `acuario.agent.tools.hunt.*`
and runs inside the sandbox during `acuario audit`. The CLI surface
is the audit pipeline plus eight utility commands: `setup`, `doctor`,
`config`, `history`, `report`, `sessions`, `inspect`, `eval`. See
[`docs/architecture.md`](docs/architecture.md) for the full pipeline,
sandbox lifecycle, and the reviewer's 4-axis check.

## Going deeper

The README above is everything you need to run the tool. The docs
below are reference material for advanced workflows and provider
specifics - read them when you need them, not as a precondition.

| Doc                                              | What it covers                                                                                          |
|--------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| [`docs/quickstart.md`](docs/quickstart.md)       | Advanced workflows beyond first run - env-var setup, per-task routing, troubleshooting, common scenarios |
| [`docs/providers.md`](docs/providers.md)         | Per-provider recipes: Ollama, vLLM, OpenRouter, Anthropic, OpenAI, LM Studio, Together, Groq, DeepSeek  |
| [`docs/cli.md`](docs/cli.md)                     | Every flag for every command                                                                            |
| [`docs/architecture.md`](docs/architecture.md)   | Pipeline internals, sandbox lifecycle, reviewer's 4-axis check, resume mechanism                        |

## Development

```bash
uv sync --all-extras
source .venv/bin/activate
pytest -q
ruff check acuario/ tests/
ruff format --check acuario/ tests/
mypy --follow-imports=silent acuario/findings acuario/scanner \
    acuario/capabilities.py acuario/agent/tools acuario/core
```

## Acknowledgements

Acuario incorporates MIT-licensed code originally authored by **Eric Hartford**
(see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)), and its design is
foundationally inspired by **Anthropic's Glasswing**. Our thanks to both.

## License

Acuario is free software, licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE). Run
`acuario --license` to print the notice in your terminal.

You are free to use, study, modify, and share it. If you run a modified
version as a network service, section 13 requires you to offer your users its
source.

Acuario is a research project. We also have some non-binding requests about
naming, attribution, and commercial use - see [`COPYRIGHT`](COPYRIGHT). They
are preferences, not licence conditions.

Copyright (C) 2026 Data Security Council of India.
