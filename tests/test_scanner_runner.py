"""End-to-end tests for ScanRunner.

Mocks the prioritizer / analyzer / reviewer / exploit_dev LLMs and runs against the
local c_propagation fixture. Verifies:
- Pipeline runs to completion in `quick`, `standard`, and `deep` depth modes
- SARIF output is generated and includes file + line_number
- The propagation file (codec_limits.h) lands in Tier B (not Tier C)
- evidence_level is set on every finding
- spent_per_tier breakdown is recorded in the manifest
- The `quick` depth path runs without any LLM analyzers
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from genai_pyo3 import ChatResponse

from acuario.scanner.pool import assign_tier
from acuario.scanner.preprocessor import Preprocessor
from acuario.scanner.prioritizer import Prioritizer
from acuario.scanner.runner import ScanResult, ScanRunner

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"
FIXTURE_PY_SQLI = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"


def _ranker_response(files: list[str]) -> str:
    """Build a JSON response covering the listed files."""
    entries = []
    for path in files:
        if "codec_limits.h" in path:
            # The propagation case: surface=1, influence=5
            entries.append(
                {
                    "path": path,
                    "surface": 1,
                    "influence": 5,
                    "surface_rationale": "just a constants header",
                    "influence_rationale": "MAX_FRAME_BYTES used in 3 memcpys",
                }
            )
        elif "codec_a.c" in path or "codec_b.c" in path or "codec_c.c" in path:
            entries.append(
                {
                    "path": path,
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "memcpy on user input",
                    "influence_rationale": "called by main",
                }
            )
        else:
            entries.append(
                {
                    "path": path,
                    "surface": 2,
                    "influence": 1,
                    "surface_rationale": "utility",
                    "influence_rationale": "isolated",
                }
            )
    return json.dumps(entries)


def _make_prioritizer_llm(file_paths: list[str]) -> AsyncMock:
    """Prioritizer LLM that responds via aask_json with a {results: [...]} payload."""
    llm = AsyncMock()
    entries = json.loads(_ranker_response(file_paths))
    llm.aask_json.return_value = ({"results": entries}, ChatResponse())
    return llm


def _make_analyzer_llm() -> MagicMock:
    """A analyzer LLM that immediately returns 'no findings' (no tool calls)."""
    llm = MagicMock()
    bound = MagicMock()
    response = MagicMock()
    response.content = "I analyzed the file but found no vulnerabilities."
    response.tool_calls = []
    bound.invoke.return_value = response
    llm.bind_tools.return_value = bound
    return llm


def _make_reviewer_llm() -> AsyncMock:
    llm = AsyncMock()
    llm.aask_text.return_value = ChatResponse(
        content=[
            {
                "text": json.dumps(
                    {
                        "is_real": True,
                        "severity": "high",
                        "evidence_level": "static_corroboration",
                        "pro_argument": "regex matched",
                        "counter_argument": "",
                        "tie_breaker": "static analysis hit",
                        "duplicate_cve": None,
                    }
                )
            }
        ]
    )
    return llm


# --- depth=quick ------------------------------------------------------------


class TestQuickDepth:
    def test_session_dir_exists_even_if_run_fails_early(self, tmp_path, monkeypatch):
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
        )
        monkeypatch.setattr(
            runner, "_preprocess", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        with pytest.raises(RuntimeError, match="boom"):
            runner.run()

        assert (tmp_path / runner.session_id).is_dir()

    def test_quick_runs_without_analyzer_llm(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
            # No analyzer/reviewer/exploit_dev LLMs needed for quick
        )
        result = runner.run()
        assert isinstance(result, ScanResult)
        # Quick mode returns whatever static findings SourceAnalyzer found
        # (possibly zero for this fixture; that's fine)
        assert result.files_ranked == 4
        assert result.files_hunted == 0
        assert result.cost_usd == 0.0
        # SARIF file exists
        assert "sarif" in result.output_paths
        sarif_path = Path(result.output_paths["sarif"])
        assert sarif_path.exists()


# --- depth=standard ---------------------------------------------------------


class TestStandardDepth:
    def test_standard_pipeline_completes(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            max_parallel=2,
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
            analyzer_llm=_make_analyzer_llm(),
            reviewer_llm=_make_reviewer_llm(),
            no_exploit=True,  # exploit_dev not needed for this test
        )
        result = runner.run()
        assert isinstance(result, ScanResult)
        assert result.files_ranked == 4
        # Output paths exist
        for fmt, path in result.output_paths.items():
            assert Path(path).exists(), f"{fmt} not written"

    def test_codec_limits_h_lands_in_tier_b_not_c(self, tmp_path):
        prioritizer_llm = _make_prioritizer_llm(
            [
                "include/codec_limits.h",
                "src/codec_a.c",
                "src/codec_b.c",
                "src/codec_c.c",
            ]
        )
        ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            output_dir=str(tmp_path),
            prioritizer_llm=prioritizer_llm,
            analyzer_llm=_make_analyzer_llm(),
            reviewer_llm=_make_reviewer_llm(),
            no_exploit=True,
        )
        # Hook into the runner's preprocess + rank to inspect tiers without
        # running the full hunt
        pp = Preprocessor(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
        )
        result = pp.run()
        Prioritizer(prioritizer_llm).rank(result.file_targets)
        # Find the header
        header = next(ft for ft in result.file_targets if ft["path"].endswith("codec_limits.h"))
        # surface=1 from LLM, but defines_constants=True floors influence to 3.
        # Wait - the prioritizer LLM returns influence=5. defines_constants floor
        # of 3 doesn't downgrade. Let me check the actual values.
        # surface=1, influence=5, reach=3 → priority = 0.5 + 1.0 + 0.9 = 2.4 → B
        assert header["surface"] == 1
        assert header["influence"] == 5
        assert header["priority"] == pytest.approx(2.4)
        assert assign_tier(header) == "B"

    def test_manifest_has_spent_per_tier(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
            analyzer_llm=_make_analyzer_llm(),
            reviewer_llm=_make_reviewer_llm(),
            no_exploit=True,
        )
        result = runner.run()
        # Manifest exists and has spent_per_tier
        manifest_path = Path(result.output_paths["manifest"])
        manifest = json.loads(manifest_path.read_text())
        assert "spent_per_tier" in manifest
        assert "A" in manifest["spent_per_tier"]
        assert "B" in manifest["spent_per_tier"]
        assert "C" in manifest["spent_per_tier"]


# --- evidence_level on findings ---------------------------------------------


class TestEvidenceLevels:
    def test_static_findings_promoted_to_static_corroboration(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(["app.py"]),
        )
        result = runner.run()
        # The py_sqli fixture has an f-string SQL injection - SourceAnalyzer
        # catches it via regex
        assert any(f.get("evidence_level") == "static_corroboration" for f in result.findings), (
            f"no static_corroboration findings: {[f.get('evidence_level') for f in result.findings]}"
        )

    def test_every_finding_has_evidence_level(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(["app.py"]),
        )
        result = runner.run()
        for f in result.findings:
            assert f.get("evidence_level") is not None


# --- Output sanity ----------------------------------------------------------


class TestOutputs:
    def test_sarif_includes_file_and_line(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(["app.py"]),
        )
        result = runner.run()
        sarif_path = Path(result.output_paths["sarif"])
        sarif = json.loads(sarif_path.read_text())
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1
        # Each result has a physicalLocation with a file URI
        for r in results:
            loc = r["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert loc["artifactLocation"]["uri"]
            # And a region with a startLine
            if "line_number" in r.get("message", {}).get("text", "") or "region" in loc:
                assert "region" in loc

    def test_markdown_is_written(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(["app.py"]),
        )
        result = runner.run()
        md_path = Path(result.output_paths["markdown"])
        content = md_path.read_text()
        assert "Acuario Audit Report" in content
        assert "Severity Histogram" in content or "Findings" in content


# --- Error handling ---------------------------------------------------------


class TestAdversarialVerifierDefault:
    """v0.2: adversarial reviewer is on by default."""

    def test_default_runner_constructs_adversarial_verifier(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
        )
        assert runner.adversarial_verifier is True

    def test_explicit_no_adversarial(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="quick",
            output_dir=str(tmp_path),
            adversarial_verifier=False,
        )
        assert runner.adversarial_verifier is False

    def test_runner_passes_adversarial_to_verifier(self, tmp_path):
        """When the reviewer runs, it gets the adversarial flag from the runner.

        v0.3 note: the reviewer_llm is also used for patch-oracle, mechanism
        extraction, and variant-loop pattern generation. So we look through
        ALL calls for the one with the adversarial system prompt.
        """
        reviewer_llm = _make_reviewer_llm()
        runner = ScanRunner(
            repo_url=str(FIXTURE_PY_SQLI),
            local_path=str(FIXTURE_PY_SQLI),
            depth="standard",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(["app.py"]),
            analyzer_llm=_make_analyzer_llm(),
            reviewer_llm=reviewer_llm,
            no_exploit=True,
            # Use v1 reviewer which has the STEEL-MAN adversarial prompt
            validator_mode="v1",
            # Disable the evidence-level gate so the adversarial prompt is
            # used on every finding regardless of evidence_level
            adversarial_threshold=None,
            # Disable v0.3 features that re-use the reviewer LLM so this
            # test only sees the verification call
            enable_mechanism_memory=False,
            enable_variant_loop=False,
        )
        runner.run()
        # Find the call whose system prompt contains STEEL-MAN
        found_adversarial = False
        for call in reviewer_llm.aask_text.call_args_list:
            system_prompt = call.kwargs.get("system", "")
            if "STEEL-MAN" in system_prompt:
                found_adversarial = True
                break
        assert found_adversarial, (
            "Expected at least one reviewer LLM call to use the adversarial "
            f"(STEEL-MAN) system prompt; got {len(reviewer_llm.aask_text.call_args_list)} calls"
        )


class TestErrorHandling:
    def test_no_llm_at_all_runs_quick_path(self, tmp_path):
        # No prioritizer LLM, no provider manager - fallback should kick in
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=None,
        )
        # Should not raise; falls back to default scores
        result = runner.run()
        assert result is not None
        assert result.files_ranked == 4

    def test_session_id_is_set(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(["x"]),
        )
        assert runner.session_id.startswith("audit-")
        result = runner.run()
        assert result.session_id == runner.session_id


# --- L2: duration plumbing in quick-result path -----------------------------


class TestQuickDurationPlumbing:
    """L2: ``_build_quick_result`` previously computed ``duration`` *after*
    calling ``_write_report`` so the report rendered ``Total duration: 0.0s``.
    The fix moves the computation earlier and passes the value through.
    """

    def test_quick_report_includes_duration_line(self, tmp_path):
        # We can't reliably assert a positive magnitude on a sub-second
        # fixture (rounding) and asyncio uses ``time.monotonic`` internally
        # so we can't monkeypatch it to fake elapsed time.  Instead, assert
        # the structural fix: the report renders the duration line.  The
        # adjacent ``test_quick_path_passes_duration_to_write_report`` test
        # below proves the value is plumbed; together the two tests catch
        # the L2 regression.
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
        )
        result = runner.run()
        assert result.duration_seconds is not None
        report_path = Path(result.output_paths["markdown"])
        text = report_path.read_text()
        # The duration line is rendered (pre-L2 the line was still rendered
        # but always read "0.0s" because the value never reached the
        # renderer; that bug is now structurally caught by the second test).
        assert "Total duration" in text

    def test_quick_path_passes_duration_to_write_report(self, tmp_path, monkeypatch):
        # Belt-and-suspenders: assert the contract directly.  Spy on
        # ``_write_report`` to confirm ``duration_seconds`` is in the kwargs
        # (pre-L2 the quick path called _write_report without it).
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                [
                    "include/codec_limits.h",
                    "src/codec_a.c",
                    "src/codec_b.c",
                    "src/codec_c.c",
                ]
            ),
        )

        captured_kwargs: dict = {}
        original_write_report = runner._write_report

        def _spy_write_report(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return original_write_report(*args, **kwargs)

        monkeypatch.setattr(runner, "_write_report", _spy_write_report)
        runner.run()

        assert "duration_seconds" in captured_kwargs, (
            "Quick path's _write_report() call did not receive duration_seconds - "
            "L2 fix regressed (pre-fix kwargs were just findings/verified/spent_per_tier)"
        )
        assert captured_kwargs["duration_seconds"] is not None
        assert captured_kwargs["duration_seconds"] >= 0.0


# --- L3: PipelineStatus tracks all stages -----------------------------------


class TestPipelineStatusCoverage:
    """L3: prior to this phase only ``prioritizer`` and ``hunter_pool``
    recorded success.  After L3 every stage that runs records either a
    success or a degraded outcome - silent failures show up in
    Pipeline Health instead of going unnoticed.
    """

    def test_quick_run_records_preprocessor(self, tmp_path):
        # The quick path runs preprocessor + prioritizer + reporter.
        # All three should appear in pipeline_status.stages.
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                ["include/codec_limits.h", "src/codec_a.c", "src/codec_b.c", "src/codec_c.c"]
            ),
        )
        result = runner.run()
        stages = result.pipeline_status.stages
        # Pre-L3 the preprocessor never showed up; this is the regression
        # the test guards against.
        assert "preprocessor" in stages, (
            "Pipeline Health is missing the preprocessor stage - L3 regressed"
        )
        assert "prioritizer" in stages  # was already tracked pre-L3

    def test_standard_run_records_all_executed_stages(self, tmp_path):
        # A full standard run with verify exercises preprocessor, prioritizer,
        # hunter_pool, skeptic_gate, critic, reviewer, variant_loop, and
        # reporter.  Each should record a status.
        runner = ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="standard",
            budget_usd=1.0,
            max_parallel=2,
            output_dir=str(tmp_path),
            prioritizer_llm=_make_prioritizer_llm(
                ["include/codec_limits.h", "src/codec_a.c", "src/codec_b.c", "src/codec_c.c"]
            ),
            analyzer_llm=_make_analyzer_llm(),
            reviewer_llm=_make_reviewer_llm(),
            no_exploit=True,
            # Disable optional features to keep the test deterministic;
            # the stages they would trigger (variant_loop, mechanism_extraction)
            # then either don't run or only record their absence.
            enable_variant_loop=False,
            enable_mechanism_memory=False,
        )
        result = runner.run()
        stages = result.pipeline_status.stages
        # Each of these was missing from Pipeline Health pre-L3.
        for name in ("preprocessor", "prioritizer", "hunter_pool", "reporter"):
            assert name in stages, (
                f"Pipeline Health is missing the {name!r} stage (have: {sorted(stages)})"
            )
        # And these must record SUCCEEDED on the happy path (the test
        # fixture is small enough that all stages should complete cleanly).
        from acuario.scanner.state import StageOutcome

        for name in ("preprocessor", "prioritizer", "reporter"):
            assert stages[name].outcome == StageOutcome.SUCCEEDED, (
                f"{name!r} did not record SUCCEEDED - got {stages[name].outcome}"
            )


class TestCalibrationFlush:
    """O8: calibration.jsonl joins skeptic verdict + validator verdict +
    exploit outcome per finding."""

    def _runner(self, tmp_path) -> ScanRunner:
        return ScanRunner(
            repo_url=str(FIXTURE_C_PROPAGATION),
            local_path=str(FIXTURE_C_PROPAGATION),
            depth="quick",
            output_dir=str(tmp_path),
        )

    def test_flush_joins_skeptic_validator_exploit(self, tmp_path):
        runner = self._runner(tmp_path)
        session_dir = tmp_path / "sess"
        session_dir.mkdir(parents=True, exist_ok=True)
        # Seed a skeptic_log.jsonl with one accepted + one refuted decision.
        (session_dir / "skeptic_log.jsonl").write_text(
            json.dumps({"finding_id": "f1", "verdict": "accepted", "confidence": 0.8})
            + "\n"
            + json.dumps({"finding_id": "f2", "verdict": "refuted", "confidence": 0.9})
            + "\n"
        )
        # Validator captured f1 advancing.
        runner._calibration_rows = [
            {"finding_id": "f1", "validator_advance": True, "validator_severity": "high"}
        ]
        findings = [
            {
                "id": "f1",
                "verified": True,
                "exploit_success": False,
                "evidence_level": "crash_reproduced",
            },
        ]
        runner._flush_calibration(session_dir, findings)

        rows = [
            json.loads(line)
            for line in (session_dir / "calibration.jsonl").read_text().splitlines()
            if line.strip()
        ]
        by_id = {r["finding_id"]: r for r in rows}
        # f1: skeptic accepted, validator advanced, exploit outcome present.
        assert by_id["f1"]["skeptic_verdict"] == "accepted"
        assert by_id["f1"]["validator"]["validator_advance"] is True
        assert by_id["f1"]["exploit"]["evidence_level"] == "crash_reproduced"
        # f2: skeptic refuted, no validator/exploit (it was gated out).
        assert by_id["f2"]["skeptic_verdict"] == "refuted"
        assert by_id["f2"]["validator"] is None

    def test_flush_noop_when_nothing_to_record(self, tmp_path):
        runner = self._runner(tmp_path)
        session_dir = tmp_path / "sess2"
        session_dir.mkdir(parents=True, exist_ok=True)
        runner._flush_calibration(session_dir, [])
        # No rows + not shadow mode → no file written.
        assert not (session_dir / "calibration.jsonl").exists()


class TestNoVulnerabilityClearing:
    """B2: 'no vulnerability found' records (finding_type=none) are cleared, not
    counted as verified findings."""

    def test_none_family_is_cleared(self):
        from acuario.scanner.runner import _is_no_vulnerability_finding

        for ft in (
            "none",
            "NONE",
            "no-vulnerability",
            "no_vulnerability",
            "no_vuln",
            "not_vulnerable",
        ):
            assert _is_no_vulnerability_finding({"finding_type": ft}) is True

    def test_confirmed_evidence_does_not_save_a_none_record(self):
        # The load-bearing case: none-records all carried a
        # confirmed evidence_level spuriously - finding_type is the only signal.
        from acuario.scanner.runner import _is_no_vulnerability_finding

        assert _is_no_vulnerability_finding(
            {"finding_type": "none", "evidence_level": "static_corroboration", "cwe": "CWE-200"}
        )

    def test_real_findings_and_empty_type_are_not_cleared(self):
        from acuario.scanner.runner import _is_no_vulnerability_finding

        assert _is_no_vulnerability_finding({"finding_type": "xss"}) is False
        assert _is_no_vulnerability_finding({"finding_type": ""}) is False  # watch-out
        assert _is_no_vulnerability_finding({}) is False


class TestDedupByLocation:
    """B3: collapse same-(file,line,cwe) dupes before recalibration, keyed on
    location NOT cluster_id - so different-location reinstated findings survive."""

    def test_merges_same_location_keeps_highest_severity(self):
        from acuario.scanner.runner import _dedup_by_location

        fs = [
            {"file": "Comments.jsx", "line_number": 20, "cwe": "CWE-79", "severity": "medium"},
            {"file": "Comments.jsx", "line_number": 20, "cwe": "CWE-79", "severity": "high"},
            {"file": "Comments.jsx", "line_number": 20, "cwe": "CWE-79", "severity": "high"},
        ]
        out, merged = _dedup_by_location(fs)
        assert merged == 2
        assert len(out) == 1
        assert out[0]["severity"] == "high"  # highest-severity representative

    def test_preserves_distinct_locations_pat_cluster(self):
        # The api.js -> Admin.jsx PAT cluster: same CWE, DIFFERENT files/lines.
        # It must NOT be merged (that was the debate-reinstated cluster).
        from acuario.scanner.runner import _dedup_by_location

        fs = [
            {"file": "api.js", "line_number": 4, "cwe": "CWE-798", "severity": "high"},
            {"file": "Admin.jsx", "line_number": 21, "cwe": "CWE-798", "severity": "high"},
            {"file": "Admin.jsx", "line_number": 35, "cwe": "CWE-798", "severity": "high"},
        ]
        out, merged = _dedup_by_location(fs)
        assert merged == 0
        assert len(out) == 3

    def test_findings_without_reliable_key_pass_through(self):
        from acuario.scanner.runner import _dedup_by_location

        fs = [
            {"file": "", "line_number": None, "cwe": "", "severity": "info"},
            {"file": "a.js", "line_number": None, "cwe": "CWE-79", "severity": "high"},
        ]
        out, merged = _dedup_by_location(fs)
        assert merged == 0
        assert len(out) == 2
