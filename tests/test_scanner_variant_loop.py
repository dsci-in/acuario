"""Tests for the v0.3 Variant Analyzer Loop.

The variant loop compounds finding density within a single run by turning
each verified finding into a search pattern and re-feeding matches as
suspicion-level variant findings.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

from genai_pyo3 import ChatResponse

from acuario.scanner.runner import ScanRunner
from acuario.scanner.variant_loop import (
    VariantLoop,
    VariantLoopConfig,
    VariantLoopResult,
    VariantPattern,
    VariantPatternGenerator,
    VariantSearcher,
)

if TYPE_CHECKING:
    # Used only as string forward-ref annotations on the helper factories
    # below; the concrete classes are imported lazily inside the helpers.
    from acuario.findings.types import Finding
    from acuario.scanner.variant_loop import VariantSeed

FIXTURE_C_PROPAGATION = Path(__file__).parent / "fixtures" / "vuln_samples" / "c_propagation"


def _mock_llm(payload: dict) -> AsyncMock:
    llm = AsyncMock()
    llm.aask_text.return_value = ChatResponse(content=[{"text": json.dumps(payload)}])
    return llm


def _run(coro):
    return asyncio.run(coro)


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "analyzer-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "cwe": "CWE-787",
        "severity": "high",
        "description": "memcpy overflow",
        "code_snippet": "memcpy(frame, input, input_len);",
        "evidence_level": "crash_reproduced",
    }
    base.update(kwargs)
    return base


# --- VariantPatternGenerator -----------------------------------------------


class TestVariantPatternGenerator:
    def test_basic_generation(self):
        llm = _mock_llm(
            {
                "grep_regex": r"memcpy\s*\([^)]*len[^)]*\)",
                "semantic_description": "memcpy with length variable",
            }
        )
        gen = VariantPatternGenerator(llm)
        pattern = _run(gen.agenerate(_make_finding()))
        assert pattern is not None
        assert "memcpy" in pattern.grep_regex
        assert "memcpy" in pattern.semantic_description

    def test_invalid_response_returns_none(self):
        llm = AsyncMock()
        llm.aask_text.return_value = ChatResponse(content=[{"text": "no json here"}])
        gen = VariantPatternGenerator(llm)
        assert _run(gen.agenerate(_make_finding())) is None

    def test_llm_exception_returns_none(self):
        llm = AsyncMock()
        llm.aask_text.side_effect = Exception("rate limited")
        gen = VariantPatternGenerator(llm)
        assert _run(gen.agenerate(_make_finding())) is None

    def test_pattern_gen_caps_max_tokens(self):
        """O-AF: the pattern-gen call is token-capped (tiny JSON output)."""
        llm = _mock_llm({"grep_regex": "memcpy", "semantic_description": "memcpy call"})
        gen = VariantPatternGenerator(llm)
        _run(gen.agenerate(_make_finding()))
        assert llm.aask_text.call_args.kwargs["max_tokens"] == 500

    def test_pattern_gen_times_out_returns_none(self, monkeypatch):
        """O-AF: a hung endpoint is bounded by the wall-clock timeout (the
        ~8h stall class), returning None instead of stalling the loop."""
        import acuario.scanner.variant_loop as vl

        monkeypatch.setattr(vl, "_VARIANT_LLM_TIMEOUT_S", 0.05)
        llm = AsyncMock()

        async def _slow(*args, **kwargs):
            await asyncio.sleep(0.5)
            return ChatResponse(content=[{"text": "{}"}])

        llm.aask_text.side_effect = _slow
        gen = VariantPatternGenerator(llm)
        assert _run(gen.agenerate(_make_finding())) is None


# --- VariantSearcher --------------------------------------------------------


class TestVariantSearcher:
    def test_search_finds_memcpy_matches(self):
        """The c_propagation fixture has memcpy calls in 3 codec files."""
        searcher = VariantSearcher()
        pattern = VariantPattern(
            grep_regex=r"memcpy",
            semantic_description="memcpy call",
        )
        # Source finding is on codec_a.c:9 - searcher should skip that exact line
        source = _make_finding(file="src/codec_a.c", line_number=9, id="origin")
        matches = searcher.search(str(FIXTURE_C_PROPAGATION), pattern, source)
        # Expect memcpy in codec_b.c and codec_c.c (at least - not codec_a.c:9)
        match_files = {m.file for m in matches}
        assert "src/codec_b.c" in match_files
        assert "src/codec_c.c" in match_files
        # codec_a.c:9 (the source) is excluded
        for m in matches:
            assert not (m.file == "src/codec_a.c" and m.line_number == 9)

    def test_search_invalid_regex_returns_empty(self):
        searcher = VariantSearcher()
        pattern = VariantPattern(
            grep_regex=r"[invalid(",
            semantic_description="broken regex",
        )
        assert searcher.search(str(FIXTURE_C_PROPAGATION), pattern, _make_finding()) == []

    def test_search_empty_regex_returns_empty(self):
        searcher = VariantSearcher()
        pattern = VariantPattern(grep_regex="", semantic_description="empty")
        assert searcher.search(str(FIXTURE_C_PROPAGATION), pattern, _make_finding()) == []

    def test_search_respects_max_per_pattern(self):
        """The searcher caps matches per pattern to keep results sane."""
        searcher = VariantSearcher()
        searcher.MAX_MATCHES_PER_PATTERN = 2  # tiny cap for the test
        pattern = VariantPattern(grep_regex=r".", semantic_description="all")
        matches = searcher.search(str(FIXTURE_C_PROPAGATION), pattern, _make_finding())
        assert len(matches) <= 2


# --- VariantLoop orchestration ---------------------------------------------


class TestVariantLoop:
    def test_run_once_generates_seeds(self):
        llm = _mock_llm(
            {
                "grep_regex": r"memcpy",
                "semantic_description": "memcpy variant",
            }
        )
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))
        verified = [_make_finding(file="src/codec_a.c", line_number=9)]
        result = _run(loop.arun_once(verified, str(FIXTURE_C_PROPAGATION)))

        assert isinstance(result, VariantLoopResult)
        assert result.patterns_generated == 1
        assert result.matches_found >= 2  # codec_b and codec_c
        assert result.iterations == 1
        for seed in result.seeds:
            assert seed.original_finding["id"] == "analyzer-abc"
            assert "A similar pattern" in seed.message
            assert seed.match.source_finding_id == "analyzer-abc"

    def test_run_once_respects_already_seen(self):
        """Locations in already_seen_locations should not generate seeds."""
        llm = _mock_llm(
            {
                "grep_regex": r"memcpy",
                "semantic_description": "memcpy variant",
            }
        )
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))

        # Pre-claim codec_b.c lines 6-10
        already_seen = {("src/codec_b.c", i) for i in range(1, 15)}
        result = _run(
            loop.arun_once(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
                already_seen_locations=already_seen,
            )
        )
        for seed in result.seeds:
            assert seed.match.file != "src/codec_b.c"

    def test_run_once_with_no_verified_findings(self):
        llm = _mock_llm({"grep_regex": "x", "semantic_description": "x"})
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))
        result = _run(loop.arun_once([], str(FIXTURE_C_PROPAGATION)))
        assert result.seeds == []
        assert result.patterns_generated == 0

    def test_run_once_caps_matches_per_finding(self):
        llm = _mock_llm({"grep_regex": r".", "semantic_description": "any"})
        config = VariantLoopConfig(max_variants_per_finding=2)
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm), config=config)
        result = _run(
            loop.arun_once(
                [_make_finding()],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        # Each verified finding contributes at most `max_variants_per_finding` seeds
        assert len(result.seeds) <= 2

    def test_pattern_gen_failure_is_per_finding(self):
        """If pattern generation fails for one finding, others still run."""
        llm = AsyncMock()
        llm.aask_text.side_effect = [
            Exception("rate limited"),  # first finding fails
            ChatResponse(
                content=[
                    {"text": json.dumps({"grep_regex": "memcpy", "semantic_description": "ok"})}
                ]
            ),  # second succeeds
        ]
        loop = VariantLoop(pattern_gen=VariantPatternGenerator(llm))
        result = _run(
            loop.arun_once(
                [
                    _make_finding(id="f1", file="src/codec_a.c", line_number=9),
                    _make_finding(id="f2", file="src/codec_b.c", line_number=5),
                ],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        # Only one pattern generated (the second succeeded)
        assert result.patterns_generated == 1


# --- Runner integration ----------------------------------------------------


class TestMultiIterationDriver:
    """v0.4: VariantLoop.run() drives multiple iterations until fixpoint."""

    def test_run_single_iteration_when_no_seeds_found(self):
        """If the first pass finds nothing, the loop terminates after 1 iteration."""
        # Regex doesn't match anything in the fixture
        llm = _mock_llm(
            {
                "grep_regex": "xyzzy_never_matches",
                "semantic_description": "nothing",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=5),
        )
        result = _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        # 1 iteration, fixpoint reached
        assert result.iterations == 1
        assert result.seeds == []
        # Pattern was generated once
        assert result.patterns_generated == 1

    def test_run_stops_after_empty_iteration(self):
        """Second iteration produces no new seeds → loop stops at 2."""
        # Already-seen dict grows each iteration; once the regex exhausts
        # everything new, the next pass returns zero seeds.
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=5),
        )
        result = _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        # First pass finds variants; second pass finds nothing (already_seen
        # now includes them). Stops at 2.
        assert result.iterations == 2
        assert result.matches_found >= 2  # from the first pass

    def test_run_respects_max_iterations_cap(self):
        """max_iterations hard-cap the loop."""
        # Return a pattern that always matches something
        llm = _mock_llm({"grep_regex": "memcpy", "semantic_description": "memcpy"})

        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(
                max_iterations=1,
                stop_on_empty_iteration=False,  # force the cap to matter
            ),
        )
        result = _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        assert result.iterations == 1

    def test_run_with_reverify_callback_compounds(self):
        """When reverify_callback returns new findings, the next pass uses them."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=3),
        )

        # reverify_callback turns seeds into "verified" findings with new IDs
        reverify_calls = []

        def reverify(seeds):
            reverify_calls.append(len(seeds))
            # Return a new finding at a fresh file so the NEXT pass can look
            # for variants of the NEW finding rather than the original.
            return [
                _make_finding(
                    id=f"reverified-{len(reverify_calls)}",
                    file="src/codec_b.c",
                    line_number=100 + len(reverify_calls),
                )
            ]

        _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
                reverify_callback=reverify,
            )
        )
        # At least one reverify call (the first iteration found seeds)
        assert len(reverify_calls) >= 1

    def test_run_reverify_callback_empty_result_stops_loop(self):
        """If reverify returns [], the next iteration has no input → stop."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "memcpy",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=5),
        )

        def reverify(seeds):
            return []  # nothing survived re-verification

        result = _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
                reverify_callback=reverify,
            )
        )
        # The first pass generated a pattern; reverify returned [] so the
        # loop stopped after 1 iteration.
        assert result.iterations == 1

    def test_run_per_iteration_callback_fires(self):
        """per_iteration_callback should fire after each run_once pass."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "x",
            }
        )
        callback_calls = []
        config = VariantLoopConfig(
            max_iterations=2,
            stop_on_empty_iteration=False,
            per_iteration_callback=lambda r: callback_calls.append(r),
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=config,
        )
        _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        assert len(callback_calls) == 2
        # Each callback receives a VariantLoopResult
        for r in callback_calls:
            assert isinstance(r, VariantLoopResult)

    def test_run_aggregates_seeds_across_iterations(self):
        """The returned VariantLoopResult sums seeds across passes."""
        llm = _mock_llm(
            {
                "grep_regex": "memcpy",
                "semantic_description": "x",
            }
        )
        loop = VariantLoop(
            pattern_gen=VariantPatternGenerator(llm),
            config=VariantLoopConfig(max_iterations=3),
        )
        result = _run(
            loop.arun(
                [_make_finding(file="src/codec_a.c", line_number=9)],
                str(FIXTURE_C_PROPAGATION),
            )
        )
        # Total patterns_generated should equal iterations (one per pass)
        assert result.patterns_generated == result.iterations


class TestRunnerVariantLoopIntegration:
    def test_runner_initializes_with_variant_loop_enabled(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            enable_variant_loop=True,
        )
        assert runner.enable_variant_loop is True

    def test_variant_loop_can_be_disabled(self, tmp_path):
        runner = ScanRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            enable_variant_loop=False,
        )
        assert runner.enable_variant_loop is False


# --- L1: variant skeptic gate ------------------------------------------------


def _make_parent_finding() -> Finding:
    """A minimal verified-finding-like object the variant loop hands to
    ``_gate_variant_seeds``.  Only the attributes the helper reads matter."""
    from acuario.scanner.state import Finding as _F

    return _F(
        id="analyzer-deadbeef",
        finding_type="memcpy_overflow",
        file="src/codec_a.c",
        line_number=9,
        cwe="CWE-787",
        severity="high",
        description="memcpy with user-controlled length",
        code_snippet="memcpy(frame, input, input_len);",
        evidence_level="crash_reproduced",
        related_cve="",
    )


def _make_variant_seed(
    file: str = "src/codec_b.c",
    line_number: int = 42,
    matched_text: str = "memcpy(out, src, n);",
    description: str = "memcpy with size from user input",
) -> VariantSeed:
    from acuario.scanner.variant_loop import (
        VariantMatch,
        VariantPattern,
        VariantSeed,
    )

    pattern = VariantPattern(
        grep_regex=r"memcpy\s*\(",
        semantic_description=description,
    )
    match = VariantMatch(
        file=file,
        line_number=line_number,
        matched_text=matched_text,
        source_finding_id="analyzer-deadbeef",
        pattern=pattern,
    )
    return VariantSeed(
        original_finding=_make_parent_finding(),
        match=match,
        message=f"Variant of analyzer-deadbeef at {file}:{line_number}",
    )


class _StubSkeptic:
    """Stand-in for SkepticGate whose ``ascreen`` returns a queued verdict.

    Simpler than mocking SkepticGate end-to-end - we only need the
    ``ascreen(finding, source_snippet, cross_file_context)`` contract.
    """

    def __init__(self, verdicts):
        from acuario.lab.agents.skeptic import SkepticVerdict

        self._verdicts: list = []
        for v in verdicts:
            if isinstance(v, str):
                self._verdicts.append(
                    SkepticVerdict(
                        verdict=v,
                        reasoning="stub",
                        finding_id="",
                        file="",
                        line_number=0,
                    )
                )
            else:
                # treat as Exception class/instance to be raised
                self._verdicts.append(v)
        self.calls: list[tuple] = []

    async def ascreen(self, finding, source_snippet="", cross_file_context=""):
        self.calls.append((finding, source_snippet, cross_file_context))
        item = self._verdicts.pop(0)
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, type) and issubclass(item, BaseException):
            raise item("stub raise")
        return item


class TestVariantSkepticGate:
    """L1: ``ScanRunner._gate_variant_seeds`` should refute pattern-match
    variants at the skeptic before they pollute the findings pool."""

    def _runner(self, tmp_path) -> ScanRunner:
        return ScanRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            enable_variant_loop=True,
        )

    def test_skeptic_none_accepts_all_variants(self, tmp_path):
        # When the skeptic gate is disabled (None), every seed becomes a
        # variant finding - preserves the legacy pre-L1 behaviour.
        runner = self._runner(tmp_path)
        seeds = [_make_variant_seed(line_number=i) for i in (10, 20, 30)]
        findings, accepted, refuted = _run(runner._gate_variant_seeds(seeds, skeptic_gate=None))
        assert len(findings) == 3
        assert all(f.get("discovered_by") == "variant_loop" for f in findings)
        assert accepted == 0  # No gate = no decisions to count
        assert refuted == 0

    def test_skeptic_refuting_drops_variant(self, tmp_path):
        # A single seed refuted by the skeptic should yield no variant.
        runner = self._runner(tmp_path)
        skeptic = _StubSkeptic(["refuted"])
        findings, accepted, refuted = _run(
            runner._gate_variant_seeds([_make_variant_seed()], skeptic_gate=skeptic)
        )
        assert findings == []
        assert accepted == 0
        assert refuted == 1
        # ascreen received the right source_snippet (the matched text)
        assert len(skeptic.calls) == 1
        _, snippet, ctx = skeptic.calls[0]
        assert snippet == "memcpy(out, src, n);"
        assert ctx == ""  # variants pass empty cross-file context

    def test_skeptic_accepting_keeps_variant(self, tmp_path):
        runner = self._runner(tmp_path)
        skeptic = _StubSkeptic(["accepted"])
        findings, accepted, refuted = _run(
            runner._gate_variant_seeds([_make_variant_seed()], skeptic_gate=skeptic)
        )
        assert len(findings) == 1
        assert accepted == 1
        assert refuted == 0
        assert findings[0].get("evidence_level") == "suspicion"
        assert findings[0].get("related_finding_id") == "analyzer-deadbeef"

    def test_skeptic_mixed_verdicts_split_correctly(self, tmp_path):
        # 3 seeds: refuted, accepted, refuted - only one survives.
        runner = self._runner(tmp_path)
        seeds = [
            _make_variant_seed(file="a.c", line_number=1),
            _make_variant_seed(file="b.c", line_number=2),
            _make_variant_seed(file="c.c", line_number=3),
        ]
        skeptic = _StubSkeptic(["refuted", "accepted", "refuted"])
        findings, accepted, refuted = _run(runner._gate_variant_seeds(seeds, skeptic_gate=skeptic))
        assert len(findings) == 1
        assert findings[0].get("file") == "b.c"
        assert accepted == 1
        assert refuted == 2

    def test_skeptic_exception_fails_open(self, tmp_path):
        # ascreen raising should NOT drop the variant - the existing
        # SkepticGate is fail-open and runner.py mirrors that contract.
        runner = self._runner(tmp_path)
        skeptic = _StubSkeptic([RuntimeError("transient LLM error")])
        findings, accepted, refuted = _run(
            runner._gate_variant_seeds([_make_variant_seed()], skeptic_gate=skeptic)
        )
        assert len(findings) == 1
        assert accepted == 1  # Counted as accepted (fail-open)
        assert refuted == 0

    def test_empty_seeds_returns_empty(self, tmp_path):
        runner = self._runner(tmp_path)
        skeptic = _StubSkeptic([])
        findings, accepted, refuted = _run(runner._gate_variant_seeds([], skeptic_gate=skeptic))
        assert findings == []
        assert accepted == 0
        assert refuted == 0
        assert skeptic.calls == []  # Never invoked
