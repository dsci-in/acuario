# Acuario tests

This directory holds the unit and integration tests for Acuario.  As of
v2.0.0 the suite is **1657 tests** spread across **~69 test modules**.

## Running the suite

The repo uses `uv` for environment management.  From the repo root:

```bash
# Full suite (recommended before any commit)
pytest -q

# With coverage
pytest -q --cov=acuario

# Single module
pytest -q tests/test_scanner_runner.py

# Single test, with -x to stop on first failure
pytest -x tests/test_lab_skeptic.py::TestSkepticGate::test_refute_drops_finding

# Faster local runs - filter by keyword
pytest -q -k variant_loop
```

CI runs the full suite on every PR via `.github/workflows/`.

## How the modules are organised

Tests are grouped by the layer of the codebase they exercise.

### Pipeline core (`tests/test_scanner_*`)

The audit pipeline - preprocessor, prioritizer, analyzer pool, reviewer,
variant loop, subsystem hunter, mechanism memory, exploit-dev,
stability, reporter, runner orchestration.

Key modules:

- `test_scanner_runner.py` - top-level `ScanRunner` orchestration:
  quick / standard depth, exit-code behaviour, output-path stability,
  pipeline status coverage across all stages.
- `test_scanner_pool_budget.py` - analyzer pool budget enforcement,
  tier-A/B/C allocation, parallel dispatch.
- `test_scanner_reviewer.py` - 4-axis validator (REAL / TRIGGERABLE /
  IMPACTFUL / GENERAL) and the adversarial steel-man prompt.
- `test_scanner_variant_loop.py` - variant-pattern generation, the L1
  skeptic-gate integration that drops pattern-only false positives.
- `test_scanner_subsystem.py` - orchestrator-driven follow-up hunts and
  per-plan finding attribution.
- `test_scanner_reporter_polish.py` - `report.md` formatting
  (executive summary, severity table, dedup section, LAB activity).
- `test_scanner_prioritizer.py`, `test_scanner_preprocessor.py`,
  `test_scanner_callgraph.py`, `test_scanner_evidence_levels.py`,
  `test_scanner_taint.py`, `test_scanner_tiering.py`,
  `test_scanner_stability.py`, `test_scanner_mechanism_memory.py`,
  `test_scanner_fuzz_harness_tool.py`, `test_scanner_v02_seams.py`,
  `test_scanner_analyzer.py`, `test_scanner_exploit_dev.py`.

### Lab subsystem (`tests/test_lab_*`)

The multi-agent layer that sits above the per-file analyzer pipeline.

- `test_lab_skeptic.py` - `SkepticGate` adversarial refutation, persist
  to `skeptic_log.jsonl`, accept / refute verdict shape.
- `test_lab_critic.py` - `ReflectiveCritic` post-ReAct pass, lead
  extraction, `code_snippet` backfill from the source file.
- `test_lab_orchestrator.py` - `CrossFileOrchestrator` plan emission,
  `SubsystemPlan.to_subsystem_target()` round-trip, structural-map
  summary format.
- `test_lab_sandbox_snapshot.py` - Docker-commit snapshot / revert
  round-trip used by exploit-dev hypothesis branching.
- `test_lab_sandbox_behavior.py` - `PtraceBehaviorMonitor`
  per-command `strace` wrap, trace-text parsing, event classification.
- `test_l5_l6_diagnostics.py` - guard tests for the L5 / L6 diagnostic
  log strings; fails loudly if a refactor accidentally drops those
  diagnostic log lines.

### Sandbox layer (`tests/test_sandbox_*`, `tests/test_hunter_sandbox.py`)

The Docker container abstraction.

- `test_sandbox_container.py` - `SandboxContainer` lifecycle (start /
  exec / stop / cleanup), exec error handling.
- `test_sandbox_msan_variants.py` - `AnalyzerSandbox` per-variant image
  builds (ASan+UBSan / MSan), tmpfs scratch chmod (L6 fix).
- `test_sandbox_writable_workspace.py` - writable-workspace mount
  behaviour for exploit-dev sandboxes.
- `test_hunter_sandbox.py` - analyzer-tool integration with
  `HunterContext`.
- `test_kali_docker.py` - additional sandbox-variant test.

### Findings + dedup (`tests/test_findings_*`)

- `test_findings_pool.py` - `FindingsPool.add()` fast-path dedup,
  evidence-level merging, exact-match short-circuit.
- `test_findings_unified.py` - `Finding` dataclass round-tripping,
  legacy dict ↔ dataclass bridge, `extra:` field stuffing.

### UI + reports (`tests/test_ui_*`, `tests/test_team_discussion_report.py`)

- `test_team_discussion_report.py` - `team_discussion.md` rendering:
  per-plan finding attribution (L8), skeptic reasoning blocks,
  variable-length code fences for nested LLM responses.
- `test_ui_narration.py` - terminal narration vocabulary
  (`[stage] glyph message`), end-of-run summary, ASCII fallback.
- `test_ui_inspect.py` - `acuario inspect` REPL subcommands:
  `list` / `show` / `why` / `skeptic` / `critic` / `orchestrator` /
  `fix` (read-only) / `exploit` / `related`.

### Provider + LLM (`tests/test_providers*`, `tests/test_*compat.py`)

- `test_providers.py` - provider-preset wizard, model-list
  auto-fetch for local endpoints.
- `test_providers_env.py` - environment-variable overrides.
- `test_minimax_compat.py` - Anthropic-compatible endpoint at
  api.minimax.io.
- `test_openai_oauth.py` - OAuth flow for OpenAI Responses API.
- `test_unconstrained_prompt.py` - unconstrained-analyzer prompt
  variant.

### Setup, doctor, observability

- `test_setup_and_doctor.py` - `acuario setup` wizard and
  `acuario doctor` health checks.
- `test_observability.py`, `test_telemetry.py`, `test_event_bus.py`,
  `test_event_payloads.py`, `test_events.py` - telemetry + event-bus
  contracts.
- `test_skills.py`, `test_self_security.py`, `test_guardrails.py`,
  `test_remediation.py` - guardrail and self-security checks.
- `test_audit.py`, `test_analysis.py`, `test_auth.py`,
  `test_payloads.py`, `test_scoring.py` - legacy network-audit modules.
- `test_band_promotion.py`, `test_parallel*.py` - analyzer pool's
  fast → standard → deep band promotion logic.
- `test_military_features.py`, `test_exploiters.py` - additional
  exploitation modules.

## Fixtures (`tests/fixtures/`)

Tests that need a real-looking input tree (rather than a `tmp_path`
synthesised in-test) read from `tests/fixtures/`.

| Fixture | Purpose |
|---|---|
| `vuln_samples/c_heap_overflow/` | Synthetic C heap overflow - exercises the `crash_reproduced` evidence-level path |
| `vuln_samples/c_propagation/` | Synthetic C `memcpy` length-confusion across two source files - exercises cross-file context |
| `vuln_samples/py_sqli/` | Tiny Python file mixing a parameterised query with an f-string SQLi - exercises the static-pattern preprocessor |
| `vuln_samples/taint_samples/` | Inputs for taint-propagation tests |

Every fixture is synthetic code written for testing - none of these
contain real customer code, real credentials, or sensitive material.

## Writing new tests

- Match the naming convention `test_<module>.py` (mirroring the source
  layout where possible).
- Use `tmp_path` for filesystem isolation; never write to the host
  outside of `pytest`-managed fixtures.
- For tests that need an LLM, mock `AsyncLLMClient.aask` / `aask_text`
  with `unittest.mock.AsyncMock` (see `tests/test_lab_skeptic.py` for
  the canonical pattern).
- For tests that need a sandbox, prefer mocking the `docker` SDK
  rather than spawning real containers - see
  `tests/test_sandbox_container.py::mock_docker`.
- New behaviour should land with at least one test that fails without
  the change and passes with it.

See `CONTRIBUTING.md` at the repo root for the full PR checklist
(linter / formatter / type checker requirements).
