# CLI reference

Acuario ships nine commands. The headline is `acuario audit`; the
others handle credentials, environment health, and inspecting past
runs. `inspect` and `eval` are developer-facing commands.

```
acuario [-h] [-V] [--license] {setup,doctor,config,audit,history,report,sessions,inspect,eval} ...
```

Every subcommand supports `-h` / `--help` for flag-level details.
This page is the hand-written complement that groups commands by
workflow and explains the non-obvious flags.

## Global flags

- `-h`, `--help` - top-level or per-subcommand help
- `acuario help [command]` - the same help, git-style (`acuario help` for the
  overview, `acuario help audit` for one command)
- `-V`, `--version` - prints `acuario 2.0.0`
- `--license` - prints the AGPL legal notice (copyright, no-warranty, redistribution terms) and exits

## Global env vars

- `ANTHROPIC_API_KEY` - Anthropic direct credential (default LLM path)
- `ACUARIO_BASE_URL` - OpenAI-compatible endpoint override (OpenRouter,
  Ollama, LM Studio, vLLM, Together, Groq, …)
- `ACUARIO_API_KEY` - credential for the `ACUARIO_BASE_URL` endpoint
- `ACUARIO_MODEL` - model name for the endpoint
- `ACUARIO_HOME` - override the runtime data dir (default `~/.acuario/`)
- `NO_COLOR` - disable all colour (output stays plain; severity still reads
  via its shape + label). Colour is also dropped automatically when stdout
  is not a TTY (piped / CI), so logs and `--plain` / `--ids-only` output are
  clean to parse.
- `FORCE_COLOR` - keep colour even when the output is redirected

---

## `audit` - source-code security audit

```bash
acuario audit <repo_url_or_path>
  [--depth quick|standard|deep]      # default: standard
  [--branch BRANCH]                  # default: main
  [--local-path PATH]                # use a local checkout instead of cloning
  [--budget USD]                     # default: unlimited
  [--max-parallel N]                 # default: 1 (fully serial) - caps only the analyzer pool; reviewer/verifier and later stages always run serially
  [--tier-split A/B/C]               # default: 70/25/5
  [--skip-tier-c]                    # drop the lowest-priority tier
  [--no-verify]                      # skip the adversarial reviewer pass
  [--exploit]                        # generate + run PoCs in the sandbox
  [--no-exploit]                     # skip the exploit-dev stage
  [--exploit-budget standard|deep|campaign]  # default: auto from --depth
  [--variant-loop]                   # enable variant pattern loop (off by default)
  [--no-mechanism-memory]            # skip cross-run mechanism store
  [--no-stability-check]             # skip PoC stability replay
  [--no-sca]                         # skip the deterministic dependency (SCA) scan
  [--no-findings-pool]               # disable cross-agent dedup pool
  [--gvisor]                         # use gVisor runtime for sandboxes
  [--encrypt-artifacts]              # currently a no-op - parsed but not yet wired
  [--no-behavior-monitor]            # disable behavioral monitoring
  [--starting-band fast|standard|deep]
  [--redundancy N]                   # agents per tier-A file
  [--shard-entry-points]             # function-level sharding for big files
  [--min-shard-rank N]               # default: 4
  [--subsystem-hunt]                 # cross-subsystem analysis pass
  [--subsystem PATH]                 # repeatable; manually specify subsystems
  [--no-per-file-hunt]               # only run subsystem hunts
  [--seed-corpus PATH]               # local seed-corpus dir
  [--seed-cves]                      # extract CVE history from git log
  [--validator-mode v1|v2]           # default: v2 (4-axis)
  [--no-adversarial]                 # use the simpler v0.1 reviewer prompt
  [--adversarial-threshold LEVEL]    # min evidence to spend reviewer budget
  [--agent-mode auto|constrained|deep]
  [--prompt-mode unconstrained|specialist]
  [--campaign-hint OBJECTIVE]        # e.g. "bugs reachable from remote input"
  [--resume SESSION_ID]              # resume a crashed run (see below)
  [--force-review]                   # with --resume, re-review even saved verdicts
  [--model MODEL]                    # override per-task model selection
  [--base-url URL]                   # OpenAI-compatible endpoint
  [--api-key KEY]                    # credential for --base-url
  [--output-dir DIR]                 # default: ./results/scanner (git checkout) or ~/.acuario/results/scanner (installed package)
  [--format sarif markdown json pdf all]   # default: all (includes a native PDF)
  [--no-dashboard]                   # disable the live progress dashboard
```

### Live progress dashboard

On an interactive terminal the run shows a live dashboard pinned below the
scrolling log: the current pipeline stage, a running findings tally (with
CVD-safe severity badges) and verified count, elapsed time, and a spend /
budget meter. It is **on by default**; `--no-dashboard`, `NO_COLOR`, or a
non-TTY (piped / CI) fall back to the plain streaming log - so scripted and
CI runs are unchanged. The dashboard only reads run state; the scan itself
is identical either way.

### Depth comparison

| Depth      | What runs                                                             |
|------------|-----------------------------------------------------------------------|
| `quick`    | Static patterns + preprocessor. **No LLM.** Free, instant.            |
| `standard` | + LLM analyzer pool, adversarial reviewer, taint, mechanism memory. **Default.** |
| `deep`     | + Heavier sharding + redundancy. Highest-fidelity, expensive.         |

### Exploit confirmation

The exploit-dev/PoC stage runs **by default** (disable it with
`--no-exploit`). For each qualifying finding, an exploit-dev agent
generates a PoC, runs it inside the sandbox, and captures the output as
evidence. PoCs are stored in the finding's `poc` and `crash_evidence`
fields - they're never written to your source tree. Successful PoCs
upgrade the finding's `evidence_level` to `exploit_demonstrated`.

`--exploit` is a separate flag: it instructs the per-file analyzers to
attempt writing exploits during the hunt itself, distinct from the
default exploit-dev stage above.

### Software Composition Analysis (SCA)

Runs **by default** after exploit-dev (disable with `--no-sca`). Independent of
the LLM hunt: the analyzer reads *code*, not manifests, so vulnerable
dependencies were reasoned about but rarely emitted as findings. SCA closes that
deterministically - it parses npm dependency manifests + lockfiles, resolves the
exact installed versions, and matches them against a bundled **offline** advisory
snapshot, emitting one finding per (package, CVE/advisory). SCA findings enter
the verified set directly, bypassing the skeptic / validator (a dependency CVE
has no in-code trace to adjudicate, and gating it would corrupt the sound
refute-rate statistics). Discipline: a finding fires **only** on an exact
resolved version (from a lockfile or an exact pin) that falls inside a vulnerable
range; loose semver without a lockfile is skipped, never guessed - a false "you
are vulnerable" is worse than a miss. The advisory set is a curated offline seed
(npm-focused today), meant to be expanded; there is no network fetch.

### Resume (`--resume`)

Recover from any mid-run crash:

```bash
# Continue: load saved findings, run reviewer + reporter, write reports
acuario audit --resume <session-id>

# Faster: re-render reports without the reviewer pass
acuario audit --resume <session-id> --no-verify

# Re-review even findings that already have a verdict
acuario audit --resume <session-id> --force-review
```

Resume is **idempotent** - findings whose verdict has been saved
(`reviewed_at IS NOT NULL` in the historical DB) are skipped on
subsequent re-runs. The serial reviewer + 5-attempt-per-finding +
3-outer-pass retry strategy means transient network errors auto-recover.

---

## `setup` - interactive provider wizard

```bash
acuario setup                              # menu-driven
acuario setup --provider openrouter        # skip the menu
acuario setup --provider ollama --no-test  # skip the live-invoke test
acuario setup -y                           # skip confirmations
acuario init                               # alias
```

Walks through LLM backend selection, credential entry, optional
connection testing, and persistence to `~/.acuario/config.yaml`.
Currently lists, among others, Anthropic, OpenRouter, Ollama, LM Studio,
vLLM, OpenAI, OpenAI Responses API, OpenAI OAuth, Together, Groq,
Fireworks, DeepSeek, MiniMax, and a "custom OpenAI-compatible" catch-all.

The wizard offers to store credentials as `${ENV_VAR}` references
(pulled from the shell at runtime) instead of literal secrets, so
the YAML never contains an api_key value.

---

## `doctor` - environment health check

```bash
acuario doctor                       # full probe + live LLM test
acuario doctor --skip-llm-invoke     # skip the test prompt
acuario doctor --json                # machine-readable for CI
```

Checks Python version, acuario version, LLM provider resolution,
filesystem (`~/.acuario/` writable, config valid), Docker daemon
reachability, external CLI tools (git, ripgrep, gh, gdb), optional
Python extras (genai-pyo3, playwright, fastapi, chromadb), and
network reachability to the configured LLM endpoint.

Exit code 0 when every check is `ok`/`warn`, 1 when anything is `err`.

---

## `config` - show / edit config

```bash
acuario config                       # print the current config
acuario config --show-provider       # resolved LLM endpoint + source
acuario config --set-provider \
    base_url=https://openrouter.ai/api/v1 \
    api_key='${OPENROUTER_API_KEY}' \
    model=anthropic/claude-opus-5    # persists to ~/.acuario/config.yaml
```

---

## `history` - browse past audit sessions

```bash
acuario history                      # interactive hub, newest first
acuario history --repo Project1      # filter by repo path / URL
acuario history --limit 20           # cap the list to the 20 most recent
acuario history --ids-only           # one session id per line, for piping
```

Reads from `~/.acuario/scanner/historical_findings.db` - the same sqlite store
the audit pipeline writes to.

On a terminal, `history` is an **interactive hub**: sessions are numbered and
paged 15 at a time. Type a number (a leading `#` is fine) to open that audit in
`inspect`; `/text` filters by repo or id, `n` / `p` page through a long list,
and `q` quits. Piped or `--ids-only` output stays plain for scripting.

---

## `report` - render reports for a saved session

```bash
acuario report <session-id>          # re-emit SARIF + Markdown + JSON + PDF (no LLM)
acuario report <session-id> --verify # also re-run the reviewer pass first
acuario report <session-id> --output-dir /tmp/acuario-reports
```

Wraps the same `resume_session()` primitive as `audit --resume`; with
`--verify` off (the default for `report`) it just reads the saved DB
state and emits the report files in seconds.

---

## `sessions` - alias of `history`

```bash
acuario sessions                     # same output as `acuario history`
acuario sessions --repo Project1 --limit 20
```

A thin alias of `history` - same flags (`--repo`, `--ids-only`, `--limit`),
same interactive hub, same handler.

---

## `inspect` - interactive session explorer (REPL)

```bash
acuario inspect <session-id>
acuario inspect <session-id> --results-dir /path/to/results/scanner
```

Opens a prompt for chatting with a finished audit. It loads the saved
findings plus the lab logs (skeptic, critic, orchestrator, debate) and
lets you triage, drill in, and ask the LLM to explain or patch a finding.
Output is plain when piped or under `NO_COLOR`, so the REPL also works in
scripts (`printf 'triage\nquit\n' | acuario inspect <id>`).

Commands at the `>` prompt:

**Browse**

- `triage [N|all]` - findings ranked by priority (severity, then evidence
  strength, then confidence; verified and exploited findings float up).
  Defaults to the top 15. Alias: `top`.
- `list [--severity critical|high|medium|low] [--sort severity|rank]` -
  list findings. `--plain` prints grep-friendly rows (no table),
  `--ids-only` prints one finding id per line for piping.
- `show <finding-id>` - full detail for a finding (fields, code snippet,
  evidence, and the validator's pro/counter/tie-breaker + 4-axis verdict).
  Also sets the current selection.
- `<row#>` or `<id-prefix>` - a bare row number from the last listing, or
  an id prefix, is a shortcut for `show`.
- `next` / `prev` (`n` / `p`) - step the selection through the last list.

**Explain** (these call the LLM)

- `why <finding-id>` - explanation of the reasoning chain, rendered as
  Markdown.
- `fix <finding-id>` - a suggested unified-diff patch, rendered as a diff.
  Read-only: it never writes to your source tree.
- `related <finding-id>` - sibling findings from the same cluster (or, as
  a fallback, the same file + CWE).

**Lab**

- `skeptic <finding-id>` - the skeptic gate verdict (accepted / refuted)
  and its reasoning.
- `debate <finding-id>` - replay the analyzer↔skeptic debate for a
  refuted finding.
- `critic` - reflective-critic low-confidence leads for the session.
- `orchestrator` - cross-file hunt plans the orchestrator emitted and the
  findings they surfaced.
- `exploit <finding-id>` - the exploit transcript and PoC string, if the
  audit ran the exploit-dev stage.

**Navigate**

- `back` (`..` / `0`) - up one level: clears the selected finding, or returns
  to the `acuario history` hub when you entered from there.
- `help` prints the command list; `quit` (or `exit`, `q`) leaves the REPL.

Row numbers work the moment a session opens - `show 1` resolves against all
findings before you have run `list` or `triage`. If a session's results
directory has been moved or cleaned up, `inspect` loads its findings from the
`historical_findings.db` instead (lab logs are then unavailable, but the
findings are intact), so anything listed in `history` stays openable.

---

## `eval` - quality scoreboard for a session

```bash
acuario eval <session-id>                        # proxy-metric scoreboard
acuario eval <session-id> --compare <session-id> # delta between two runs
acuario eval <session-id> --annotations ann.json # true precision from labels
acuario eval <session-id> --format json          # machine-readable
acuario eval <session-id> --results-dir PATH
```

A developer-facing scoreboard over a finished audit. Without labels it
reports proxy metrics (counts by severity/evidence, verified vs refuted
rates, exploit outcomes); `--compare` shows the delta against a second
session. Supply `--annotations` - a JSON map of `finding_id -> {"label":
"TP"|"FP"}` - to compute true precision instead of proxies.

On a terminal the scoreboard renders with the theme (a framed by-source table
with colour-banded rates, plus kv-tables); piped or redirected output
(`acuario eval <id> > report.md`) stays raw Markdown. `--format json` writes
machine-readable JSON to stdout.
