# Beyond the first audit

> **You should already have `acuario audit` working.** If you haven't,
> the [README](https://github.com/dsci-in/acuario#readme) walks you from `git clone` to a green run
> in five steps. This page is the companion: scenarios, env-var
> alternatives to the wizard, per-task model routing, troubleshooting,
> and the resume / inspect workflows in more depth.

## Configure without the wizard (env vars + config file)

`acuario setup` is the easiest path. If you'd rather configure
manually - for CI, scripting, or because you already know the values
- Acuario reads three sources in this precedence:

1. **CLI flags** - `--base-url`, `--api-key`, `--model` on `acuario audit`
2. **Env vars** - `ACUARIO_BASE_URL`, `ACUARIO_API_KEY`, `ACUARIO_MODEL`
3. **Config file** - `~/.acuario/config.yaml`, written by `acuario setup`
   or `acuario config --set-provider`
4. **Anthropic-direct fallback** - `ANTHROPIC_API_KEY`, used only when
   none of the above resolve a provider

Examples:

```bash
# Anthropic direct
export ANTHROPIC_API_KEY=sk-ant-...

# Any OpenAI-compatible endpoint
export ACUARIO_BASE_URL=https://openrouter.ai/api/v1
export ACUARIO_API_KEY=$OPENROUTER_API_KEY
export ACUARIO_MODEL=anthropic/claude-opus-5

# Or persist it to ~/.acuario/config.yaml
acuario config --set-provider \
    base_url=https://openrouter.ai/api/v1 \
    api_key='${OPENROUTER_API_KEY}' \
    model=anthropic/claude-opus-5
```

`'${OPENROUTER_API_KEY}'` (with single quotes) writes the literal
`${OPENROUTER_API_KEY}` reference to the YAML - Acuario expands it
at runtime, so the secret never lives in the file.

Inspect the resolved configuration anytime:

```bash
acuario config --show-provider
```

See [`providers.md`](providers.md) for backend-specific recipes:
Ollama, vLLM, LM Studio, Together, Groq, DeepSeek, MiniMax, OpenAI
direct, plus per-task model routing (e.g. small model for the
prioritizer, big model for the analyzer, a third for the reviewer
to maintain cross-provider independence).

## What the depth flag actually changes

```bash
acuario audit . --depth quick      # static patterns only
acuario audit . --depth standard   # default - full LLM pipeline
```

| Stage                | `quick` | `standard` |
|----------------------|:-------:|:----------:|
| Static-pattern scan  | ✅      | ✅         |
| File enumeration     | ✅      | ✅         |
| LLM prioritizer      | ✅ *     | ✅         |
| LLM analyzer pool    | -       | ✅         |
| 4-axis reviewer      | -       | ✅         |
| Variant loop         | -       | ✅         |
| Taint propagation    | -       | ✅         |
| Mechanism memory     | -       | ✅         |
| Stability check      | -       | ✅ (when `--exploit` is on) |
| Dependency scan (SCA)| -       | ✅ (`--no-sca` to skip)     |

\* `quick` still runs the LLM prioritizer when an endpoint is
configured; it skips only the analyzer pool and sandbox stages.

`quick` is for CI gates and smoke checks - runs in seconds, no
Docker. `standard` is the default for real audits.

## Generate working PoCs (`--exploit`)

For verified findings, the exploit-dev agent generates a
proof-of-concept and **runs it inside the sandbox** to confirm
exploitability. Successful PoCs upgrade the finding's
`evidence_level` to `exploit_demonstrated`.

```bash
acuario audit /path/to/your/project --depth standard --exploit
```

Each exploit-dev session writes a full ReAct transcript to
`~/.acuario/results/scanner/<session-id>/exploits/<finding-id>/transcript.jsonl`.
The transcript records every tool call (`read_file`, `execute`,
`write_file`), tool result, and the agent's reasoning between calls.
The agent's final verdict - primitive achieved, impact, success
flag - is in the last `tool_call` event with `fn_name=record_exploit_result`.

Quick way to scan one transcript:

```bash
python3 -c "
import json
for line in open('transcript.jsonl'):
    e = json.loads(line)
    if e.get('event') == 'tool_call' and e['tool_call'].get('fn_name') == 'record_exploit_result':
        a = e['tool_call']['fn_arguments']
        print(f'success: {a.get(\"success\")}')
        print(f'impact:  {a.get(\"impact\")}')
        print(f'notes:   {(a.get(\"notes\") or \"\")[:300]}')
"
```

## Resume a crashed audit

If an audit dies mid-run (network blip, sandbox FD pressure, host
reboot), the analyzer's findings are already persisted to
`~/.acuario/scanner/historical_findings.db`. You don't have to redo
the multi-hour analyzer work - just resume:

```bash
# Continue from where it stopped: load saved findings, run the
# reviewer on them, write the full report.
acuario audit --resume <session-id>

# Skip the reviewer pass and write reports as-is (~30 seconds).
acuario audit --resume <session-id> --no-verify
```

The serial verifier + auto-retry path means transient network errors
self-heal across re-runs. Each `--resume` is idempotent - findings
that already have a verdict are skipped.

Find a session ID:

```bash
acuario history
# or directly from the historical DB
sqlite3 ~/.acuario/scanner/historical_findings.db \
  "SELECT campaign_session_id, COUNT(*) FROM findings GROUP BY campaign_session_id"
```

## Inspect past audits

On a terminal `acuario history` is an interactive hub: sessions are numbered,
you open one by typing its number (into `inspect`), `/text` filters, `n` / `p`
page, and `..` inside `inspect` steps back to the list. For scripting, the same
command piped or with `--ids-only` stays plain.

```bash
acuario history                            # interactive hub
acuario history --repo Project1 --limit 10 # filter + cap, non-interactively
acuario history --ids-only                 # session ids only, for piping
acuario inspect <session-id>               # open one directly
acuario report <session-id>                # re-render reports (no LLM)
acuario report <session-id> --verify       # also re-run the reviewer
```

A session whose results directory has moved is still openable - `inspect` falls
back to the findings database.

## Reading the cost summary

The CLI summary at the end of each audit shows different things
depending on whether you're on a self-hosted or commercial endpoint.

**Self-hosted (Ollama / vLLM / LM Studio)** - real cost is `$0` (your
GPU + electricity, not USD per token), so the report shows token
totals plus reference quotes against frontier APIs:

```
Tokens used:  input=17,432,109   output=543,201   total=17,975,310
Cost paid:    $0.00  (self-hosted)
Reference (same workload on current frontier APIs):
    Anthropic Claude Opus 5.5:   ~$80.59
    Anthropic Claude Fable 5.1:  ~$201.48
    OpenAI GPT-6 Astra:          ~$201.48
    OpenAI GPT-5.6 Sol:          ~$103.46
```

(The exact model lineup is defined once in `CostTracker.REFERENCE_MODELS` and
priced from the run's token totals, so the report and terminal never disagree.)

**Commercial API (Anthropic / OpenAI / OpenRouter / etc.)** - shows
real billing with per-tier breakdown:

```
Tokens used:  input=2,109,432   output=312,847   total=2,422,279
Cost paid:    $43.92
    Per tier: A=$36.42  B=$7.21  C=$0.29
```

The same numbers also land in `~/.acuario/results/scanner/<session-id>/manifest.json`
under `cost_summary`, and in the `report.md` "LLM usage" section.

## Troubleshooting

**Audit runs forever / appears stuck.** The analyzer agent does many
ReAct loops per file; with a small local model + a remote endpoint,
each step can be slow. Check Ollama's `api/ps` to confirm the model
is actively serving:

```bash
curl -s http://<gpu-host>:11434/api/ps | python3 -m json.tool
```

If `expires_at` is in the future, the model is loaded and processing.
For more visibility tail the logs in the audit terminal - the analyzer
prints one line per file completion.

**`Web stream error`** in the log. Usually a transient connectivity
blip to the LLM endpoint; the auto-retry layer recovers most of these.
If a finding ends up in `rejected_findings.jsonl` for that reason,
re-run `acuario audit --resume <session-id>` to give it another pass.

**Sandbox / FD-related crashes.** The runner bumps the file-descriptor
limit at startup, but if your host has a hard cap below 1024, sandboxed
analyzer work can still hit `EMFILE`. Raise it system-wide:

```bash
ulimit -Hn 65536
ulimit -n 65536
```

**The same finding shows up 2-3 times in the report.** Tier-A files
get analyzed by N agents in parallel for robustness (redundancy
defaults to a rank-based 1/2/3 by file priority) plus a band
promotion = up to 3 runs. Pass `--redundancy 1` to get unique
findings only:

```bash
acuario audit . --depth standard --redundancy 1
```

## What's in `~/.acuario/`

```
~/.acuario/
├── config.yaml                          ← LLM provider config (you write this)
└── scanner/
    ├── historical_findings.db           ← all findings across all runs
    └── trajectories/                    ← per-analyzer ReAct trace dumps
```

Plus your audit results, in whichever directory you ran from:

```
results/scanner/<session-id>/
├── findings.sarif       ← IDE / code-scanning (ranked: security-severity, CWE, fingerprints)
├── report.md            ← human-readable
├── report.pdf           ← paginated, print-ready (same substance as report.md)
├── findings.json        ← scripting
├── manifest.json        ← summary + token / cost detail
├── findings_pool.jsonl  ← dedup state (cross-agent)
├── rejected_findings.jsonl  ← what the reviewer dropped
└── exploits/<id>/       ← per-finding exploit-dev transcripts (when --exploit)
```

---

## Chat with your audit (`acuario inspect`)

After a run completes, `acuario inspect` opens an interactive REPL over the session's
artifacts - no LLM required for most commands (only `why` and `fix` make an LLM call):

```bash
acuario inspect audit-3eff431d
```

```
> list --severity critical
  [CRITICAL] ✓  analyzer-1d1e8bb5  app3/cart.php:13     CWE-352  CSRF on state-changing POST
  [CRITICAL] ✓  analyzer-086a5448  app3/admin/export.php:17  CWE-78  Command injection via template

> show analyzer-1d1e8bb5
  severity             critical
  cwe                  CWE-352
  file                 app3/cart.php
  line_number          13
  evidence_level       crash_reproduced
  verified             True
  description          CSRF on state-changing POST actions
  ── code snippet ──
  if ($_POST['action'] == 'delete') { ...

> why analyzer-1d1e8bb5
  (LLM reads trajectory + source, explains reasoning in plain English)

> skeptic analyzer-1d1e8bb5
  ✓ Skeptic accepted analyzer-1d1e8bb5
  (Skeptic gate failed to produce a valid refutation - finding entered the pool.)

> critic
  Reflective critic leads - 3 low-confidence lead(s):
  analyzer-bbbb0002  app3/comments.php:17  XSS in comment rendering

> fix analyzer-1d1e8bb5
  Note: This is a read-only suggestion - nothing is written to source.
  --- a/app3/cart.php
  +++ b/app3/cart.php
  ...

> orchestrator
  Cross-file orchestrator plans - 2 plan(s):
  Plan 1  focus: shared session-token contract
  files: app3/cart.php, app3/session.php

> ..        # step back a level (or back to the `history` hub); `q` quits
```

A bare row number (e.g. `show 1`) works immediately, before any `list`. Full
command list: `help` inside the REPL, or `acuario inspect --help`.

---

## How the lab agents tune precision and recall

By default, every audit run has three lab agents active.  Here's what to look for
in `audit.log` to see their impact:

### Skeptic gate - precision

```bash
grep "\[skeptic\]" results/scanner/<session>/audit.log
```

```
[skeptic] ✓ accept analyzer-1d1e8bb5
[skeptic] ✗ refute analyzer-X (reason: input sanitised at call site, line 47)
```

The ratio of `refute` to `accept` lines is your precision filter in action.  A large
number of refutations on a run with many low-quality findings is the skeptic doing its
job.  Inspect the refuted findings with `acuario inspect <session> > skeptic <id>`.

### Reflective critic - recall

```bash
grep "\[critic\]" results/scanner/<session>/audit.log
```

```
[critic] ▸ added 2 low-confidence leads from app3/cart.php trajectory
```

These leads appear in `findings.json` with `discovered_by="critic"`.  If they pass the
skeptic and reviewer they surface as real findings the analyzer would have missed.

### Cross-file orchestrator - cross-boundary recall

```bash
grep "\[orchestrate\]" results/scanner/<session>/audit.log
```

```
[orchestrate] ▸ emitted 3 subsystem plans from findings pool
```

Plans trigger a second analyzer pool pass targeting multi-file contracts.  Findings from
these passes carry `subsystem_source="orchestrator"` (plus `subsystem_name` and
`subsystem_plan_id`) in `findings.json`.

### Trust calibration (skeptic three-way, recalibration, evidence honesty)

The verification chain reports what it actually knows, not its first guess:

- **Skeptic three-way** - a finding is only dropped when the skeptic cites the
  *specific code* that refutes it. A doubt resting on a general assumption
  ("the framework probably escapes this") is marked **uncertain** and passes
  through flagged, so a hand-wave can't kill a true positive. The flag and the
  doubt show up on the finding and in `report.md`.
- **`--recalibrate-severity`** - deterministically caps a verified finding's
  severity from the 4-axis confidences (e.g. TRIGGERABLE passed only at low
  confidence → cap at high). The analyzer's original claim is preserved
  alongside, with the rule that adjusted it. Rule-based, no extra LLM call.
- **Evidence honesty** - an unreliable PoC (reproduces <50% of the time) is
  kept but its evidence is demoted (`crash_reproduced → static_corroboration`)
  with a reason, instead of being silently dropped or overstating
  reproducibility. A verified bug whose exploit was *attempted but blocked*
  records `exploit_blocked_by` ("verified; blocked by ASLR") rather than
  leaving a gap.
- **`--skeptic-shadow-mode`** - run the skeptic for its verdicts without
  gating; the validator becomes ground truth and the run writes
  `calibration.jsonl` (skeptic verdict × validator verdict × exploit outcome
  per finding), so you can measure the skeptic's false-negative rate.

### Tuning flags

| Flag | Effect |
|---|---|
| `--no-skeptic-gate` | Disable skeptic (faster, lower precision) |
| `--no-critic` | Disable reflective critic (faster, lower recall) |
| `--no-orchestrator` | Disable cross-file orchestrator (plans no longer auto-run) |
| `--recalibrate-severity` | Cap verified severities from the 4-axis confidences (O6) |
| `--skeptic-shadow-mode` | Skeptic logs verdicts but doesn't gate; writes calibration.jsonl (O8) |
| `--warm-container-pool` | Reuse pre-warmed sandbox containers across files (N4) |
| `--strict-sandbox` | Add network syscalls to the analyzer seccomp denylist (N5) |
| `--gvisor` | Run sandboxes under gVisor when available (falls back gracefully) |
| `--max-llm-concurrency N` | Raise the per-client in-flight request cap (M6) |
| `--no-sandbox-snapshots` | Disable Docker-commit checkpoint/rollback during exploit-dev |
| `--no-ptrace-monitor` | Disable just the syscall-level monitor (regex monitor still runs) |
| `--no-behavior-monitor` | Disable both ptrace and regex sandbox monitors |

### The team-discussion report

Every audit also writes `results/scanner/<session>/team_discussion.md` - a
single Markdown artifact that aggregates the analyzer's reasoning, the
skeptic's verdict and reasoning, critic origin notes, the reviewer's
4-axis verdict, and exploit-dev outcome for every finding.  Useful when
you want to share an audit's complete deliberation with someone who
doesn't have shell access to your machine.

```bash
less results/scanner/<session>/team_discussion.md
# or open in your editor; long analyzer chains wrap in <details> blocks
```

---

## Next

- [**CLI reference**](cli.md) - every flag across every command.
- [**LLM providers**](providers.md) - Ollama, OpenRouter, Anthropic,
  OpenAI, LM Studio, vLLM, Together, Groq, DeepSeek, MiniMax.
- [**Architecture**](architecture.md) - pipeline internals, sandbox
  lifecycle, reviewer's 4-axis check, resume mechanism.
- [**Lab walkthrough**](lab.md) - deep dive into all lab agents and sandbox features.
