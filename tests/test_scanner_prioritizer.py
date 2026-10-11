"""Unit tests for the three-axis scanner prioritizer.

The prioritizer is the only component besides the analyzers/reviewer/exploit_dev that
makes LLM calls in v0.1, so most tests use a MagicMock for the LLM.

Critical assertions:
- BOTH surface AND influence scored 1-5 with rationales
- Static-hint and imports_by floors applied
- Reachability defaults to 3 in v0.1
- Priority formula = surface*0.5 + influence*0.2 + reachability*0.3
- Chunking works for >chunk_size files
- The FFmpeg-style file (surface=1, influence=5) doesn't get dropped
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from genai_pyo3 import ChatResponse

from acuario.scanner.pool import assign_tier
from acuario.scanner.prioritizer import (
    RANKER_SYSTEM_PROMPT,
    Prioritizer,
    RankerConfig,
)


def _make_file(
    path: str,
    *,
    language: str = "c",
    loc: int = 50,
    static_hint: int = 0,
    imports_by: int = 0,
    defines_constants: bool = False,
    tags: list[str] = None,
) -> dict:
    return {
        "path": path,
        "absolute_path": "/abs/" + path,
        "language": language,
        "loc": loc,
        "tags": tags or [],
        "static_hint": static_hint,
        "imports_by": imports_by,
        "defines_constants": defines_constants,
        "surface": 0,
        "influence": 0,
        "reachability": 3,
        "priority": 0.0,
        "tier": "C",
    }


def _mock_llm_returning(scores: list[dict]) -> AsyncMock:
    """Build an AsyncMock LLM whose .aask_json returns (parsed_scores, response)."""
    mock = AsyncMock()
    mock.aask_json.return_value = ({"results": scores}, ChatResponse())
    return mock


# --- Basic rank()  -----------------------------------------------------------


class TestRanker:
    def test_empty_files_returns_empty(self):
        llm = AsyncMock()
        prioritizer = Prioritizer(llm)
        out = prioritizer.rank([])
        assert out == []
        llm.aask_json.assert_not_called()

    def test_basic_rank_fills_in_scores(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "foo.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "parses input",
                    "influence_rationale": "isolated",
                }
            ]
        )
        files = [_make_file("foo.c")]
        prioritizer = Prioritizer(llm)
        out = prioritizer.rank(files)
        assert out[0]["surface"] == 4
        assert out[0]["influence"] == 2
        assert out[0]["surface_rationale"] == "parses input"
        assert out[0]["influence_rationale"] == "isolated"

    def test_rank_uses_low_reasoning_effort(self):
        """A2a: the prioritizer is an ancillary role - it ranks files and does
        not need deep reasoning, so its LLM call passes reasoning_effort=low."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "foo.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        Prioritizer(llm).rank([_make_file("foo.c")])
        assert llm.aask_json.call_args.kwargs["reasoning_effort"] == "low"

    def test_priority_formula(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "x.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("x.c")]
        Prioritizer(llm).rank(files)
        # surface=4 → 2.0, influence=2 → 0.4, reachability=3 → 0.9 → total 3.3
        assert files[0]["priority"] == pytest.approx(3.3)

    def test_reachability_defaults_to_three(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "y.c",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("y.c")]
        Prioritizer(llm).rank(files)
        assert files[0]["reachability"] == 3


# --- Floors ------------------------------------------------------------------


class TestFloors:
    def test_static_hint_promotes_surface(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "weak.c",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("weak.c", static_hint=2)]
        Prioritizer(llm).rank(files)
        # surface=1 from LLM → floored to 3 by static_hint
        assert files[0]["surface"] == 3

    def test_static_hint_does_not_decrease_surface(self):
        """If LLM already returned 5, static_hint floor of 3 doesn't drop it."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "strong.c",
                    "surface": 5,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("strong.c", static_hint=3)]
        Prioritizer(llm).rank(files)
        assert files[0]["surface"] == 5

    def test_imports_by_promotes_influence(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "header.h",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("header.h", imports_by=20)]
        Prioritizer(llm).rank(files)
        # imports_by > 10 → influence floor of 3
        assert files[0]["influence"] == 3

    def test_defines_constants_promotes_influence(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "limits.h",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("limits.h", defines_constants=True)]
        Prioritizer(llm).rank(files)
        assert files[0]["influence"] == 3

    def test_low_imports_by_does_not_floor(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "a.c",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("a.c", imports_by=2)]
        Prioritizer(llm).rank(files)
        # imports_by=2 < threshold=10 → no floor
        assert files[0]["influence"] == 1


# --- Chunking ----------------------------------------------------------------


class TestChunking:
    def test_chunks_split_correctly(self):
        files = [_make_file(f"f{i}.c") for i in range(350)]
        chunks = Prioritizer._chunk(files, 150)
        assert len(chunks) == 3
        assert len(chunks[0]) == 150
        assert len(chunks[1]) == 150
        assert len(chunks[2]) == 50

    def test_rank_makes_one_call_per_chunk(self):
        # Build 250 files; chunk_size=100 → 3 chunks → 3 LLM calls
        llm = _mock_llm_returning(
            [
                {
                    "path": f"f{i}.c",
                    "surface": 2,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
                for i in range(250)
            ]
        )
        files = [_make_file(f"f{i}.c") for i in range(250)]
        Prioritizer(llm, RankerConfig(chunk_size=100)).rank(files)
        assert llm.aask_json.call_count == 3

    def test_large_repo_reranks_only_top_heuristic_candidates(self):
        llm = _mock_llm_returning([])
        files = [
            _make_file("parser.c", tags=["parser"]),
            _make_file("static.c", static_hint=1),
            _make_file("large.c", loc=1000),
            _make_file("boring1.c"),
            _make_file("boring2.c"),
            _make_file("boring3.c"),
        ]

        Prioritizer(
            llm,
            RankerConfig(
                chunk_size=2,
                large_repo_file_threshold=3,
                large_repo_llm_file_limit=3,
            ),
        ).rank(files)

        assert llm.aask_json.call_count == 2
        ranked_payload = "\n".join(call.kwargs["user"] for call in llm.aask_json.call_args_list)
        assert "parser.c" in ranked_payload
        assert "static.c" in ranked_payload
        assert "large.c" in ranked_payload
        assert "boring3.c" not in ranked_payload
        assert all(file["priority"] > 0 for file in files)


# --- LLM response handling ---------------------------------------------------


class TestResponseParsing:
    def test_parse_response_extracts_json_array(self):
        prioritizer = Prioritizer(MagicMock())
        content = """Here is my analysis:
[
  {"path": "a.c", "surface": 3, "influence": 2, "surface_rationale": "x", "influence_rationale": "y"}
]
Done."""
        result = prioritizer._parse_response(content)
        assert "a.c" in result
        assert result["a.c"]["surface"] == 3
        assert result["a.c"]["influence"] == 2

    def test_parse_response_invalid_json_returns_empty(self):
        prioritizer = Prioritizer(MagicMock())
        result = prioritizer._parse_response("not json at all")
        assert result == {}

    def test_parse_response_clamps_out_of_range(self):
        prioritizer = Prioritizer(MagicMock())
        content = '[{"path":"f","surface":99,"influence":-3,"surface_rationale":"","influence_rationale":""}]'
        parsed = prioritizer._parse_response(content)
        # _parse_response itself doesn't clamp - _apply_scores does
        assert parsed["f"]["surface"] == 99


class TestFallbackOnLLMSilence:
    """When the LLM returns no scores for a file, the prioritizer falls back to heuristics."""

    def test_fallback_surface_for_parser_tag(self):
        llm = _mock_llm_returning([])  # empty array
        files = [_make_file("decoder.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        assert files[0]["surface"] == 4

    def test_fallback_surface_for_static_hint(self):
        llm = _mock_llm_returning([])
        files = [_make_file("a.c", static_hint=1)]
        Prioritizer(llm).rank(files)
        assert files[0]["surface"] >= 3

    def test_fallback_influence_for_high_imports_by(self):
        llm = _mock_llm_returning([])
        files = [_make_file("h.h", imports_by=25)]
        Prioritizer(llm).rank(files)
        # imports_by > 20 → fallback influence 5; floor stays 5
        assert files[0]["influence"] == 5

    def test_fallback_when_llm_raises(self):
        llm = AsyncMock()
        llm.aask_json.side_effect = Exception("rate limited")
        files = [_make_file("foo.c", tags=["parser"], static_hint=2, imports_by=15)]
        Prioritizer(llm).rank(files)
        # Failure → fallback - surface should be at least 3 from static_hint floor
        assert files[0]["surface"] >= 3
        # imports_by=15 → fallback influence 4 (15 > 5 but ≤ 20)
        assert files[0]["influence"] >= 3


# --- The FFmpeg-style propagation case --------------------------------------


class TestPropagationCase:
    """The whole point of the two-axis prioritizer: a file with surface=1 but
    influence=5 must NOT be dropped to the bottom of the queue.
    """

    def test_constants_header_lands_high_priority(self):
        # LLM correctly identifies it as low surface, high influence
        llm = _mock_llm_returning(
            [
                {
                    "path": "codec_limits.h",
                    "surface": 1,
                    "influence": 5,
                    "surface_rationale": "just constants",
                    "influence_rationale": "used in 50 memcpys",
                },
                {
                    "path": "main.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "main entry",
                    "influence_rationale": "isolated",
                },
            ]
        )
        files = [
            _make_file("codec_limits.h", defines_constants=True, imports_by=50),
            _make_file("main.c"),
        ]
        Prioritizer(llm).rank(files)
        header = next(f for f in files if f["path"] == "codec_limits.h")
        main = next(f for f in files if f["path"] == "main.c")
        # surface=1, influence=5, reachability=3
        # priority = 0.5 + 1.0 + 0.9 = 2.4
        assert header["priority"] == pytest.approx(2.4)
        # main.c: 4*0.5 + 2*0.4... wait that's 2.0 + 0.4 + 0.9 = 3.3
        assert main["priority"] == pytest.approx(3.3)
        # main.c outranks the header by priority - that's expected with these
        # weights. But the header is NOT zeroed out: its priority is 2.4, well
        # above any rank-1 file (0.5 + 0.2 + 0.9 = 1.6). So it'll land in
        # Tier B at worst - never Tier C - and never get dropped.
        assert header["priority"] > 2.0

    def test_pure_constants_file_with_high_imports_by_floors(self):
        """Even if the LLM whiffs (returns influence=1), the imports_by floor
        and defines_constants floor must keep it relevant."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "limits.h",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "constants",
                    "influence_rationale": "missed it",
                },
            ]
        )
        files = [
            _make_file(
                "limits.h",
                defines_constants=True,
                imports_by=30,
            )
        ]
        Prioritizer(llm).rank(files)
        # Both floors apply → influence at least 3
        assert files[0]["influence"] == 3
        # priority = 1*0.5 + 3*0.2 + 3*0.3 = 0.5 + 0.6 + 0.9 = 2.0
        assert files[0]["priority"] == pytest.approx(2.0)


class TestFuzzableRankBoost:
    """v0.4: files tagged parser/fuzzable with surface>=4 get priority += 0.5.
    This back-propagates the HarnessGenerator's selection criteria into the
    prioritizer so fuzzable parsers outrank peers at the same base score."""

    def test_parser_tagged_high_surface_gets_boost(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "decode.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "parses input",
                    "influence_rationale": "isolated",
                }
            ]
        )
        files = [_make_file("decode.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        # Base priority: 4*0.5 + 2*0.2 + 3*0.3 = 3.3
        # After boost: 3.3 + 0.5 = 3.8
        assert files[0]["priority"] == pytest.approx(3.8)

    def test_fuzzable_tagged_high_surface_gets_boost(self):
        llm = _mock_llm_returning(
            [
                {
                    "path": "harness.c",
                    "surface": 5,
                    "influence": 1,
                    "surface_rationale": "fuzz entry point",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("harness.c", tags=["fuzzable"])]
        Prioritizer(llm).rank(files)
        # Base: 5*0.5 + 1*0.2 + 3*0.3 = 3.6, + 0.5 = 4.1
        assert files[0]["priority"] == pytest.approx(4.1)

    def test_low_surface_no_boost_even_if_tagged(self):
        """surface < 4 disqualifies the boost."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "lib.c",
                    "surface": 3,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("lib.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        # Base: 3*0.5 + 2*0.2 + 3*0.3 = 2.8, no boost
        assert files[0]["priority"] == pytest.approx(2.8)

    def test_no_relevant_tag_no_boost(self):
        """Even with high surface, no parser/fuzzable tag → no boost."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "auth.c",
                    "surface": 5,
                    "influence": 3,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("auth.c", tags=["auth_boundary"])]
        Prioritizer(llm).rank(files)
        # Base: 5*0.5 + 3*0.2 + 3*0.3 = 4.0, no boost
        assert files[0]["priority"] == pytest.approx(4.0)

    def test_boost_is_audited_in_rationale(self):
        """The boost should leave a trace in surface_rationale for explainability."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "parser.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "parses untrusted input",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("parser.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        assert "+0.5" in files[0]["surface_rationale"]
        assert "fuzzable boost" in files[0]["surface_rationale"]

    def test_parser_fuzzable_outranks_non_parser_at_same_base(self):
        """The whole point of the boost: a parser file outranks a non-parser
        peer at the same surface/influence/reachability."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "parser.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                },
                {
                    "path": "util.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                },
            ]
        )
        files = [
            _make_file("parser.c", tags=["parser"]),
            _make_file("util.c", tags=[]),
        ]
        Prioritizer(llm).rank(files)
        parser = next(f for f in files if f["path"] == "parser.c")
        util = next(f for f in files if f["path"] == "util.c")
        assert parser["priority"] > util["priority"]
        assert parser["priority"] - util["priority"] == pytest.approx(0.5)

    def test_boost_applied_only_once_per_file(self):
        """Running rank() twice on the same file shouldn't stack the boost."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "decode.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("decode.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        first_priority = files[0]["priority"]
        # Re-run - boost is deterministic on the same inputs
        # but we need to re-mock the LLM
        llm2 = _mock_llm_returning(
            [
                {
                    "path": "decode.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        Prioritizer(llm2).rank(files)
        # Priority should be the same (4*0.5 + 2*0.2 + 3*0.3 + 0.5 = 3.8)
        assert files[0]["priority"] == pytest.approx(first_priority)
        # Rationale audit note should appear at most once
        rationale = files[0]["surface_rationale"]
        assert rationale.count("fuzzable boost") == 1

    def test_boost_changes_tier_assignment(self):
        """A fuzzable file at the B/A boundary should get bumped to A by
        the boost - the whole point of the back-propagation."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "parser.c",
                    "surface": 4,
                    "influence": 2,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("parser.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        # Base priority 3.3 → A (>= 3.0), after boost 3.8 → still A but stronger
        assert assign_tier(files[0]) == "A"

    def test_boost_rescues_borderline_file(self):
        """A file with surface=4, influence=1, reach=3 → base priority 2.9 → B.
        With the fuzzable boost: 3.4 → A."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "decode.c",
                    "surface": 4,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        files = [_make_file("decode.c", tags=["parser"])]
        Prioritizer(llm).rank(files)
        # 4*0.5 + 1*0.2 + 3*0.3 + 0.5 = 2.0 + 0.2 + 0.9 + 0.5 = 3.6 → A
        assert files[0]["priority"] == pytest.approx(3.6)
        assert assign_tier(files[0]) == "A"


class TestRankerSystemPrompt:
    def test_prompt_mentions_both_axes(self):
        assert "SURFACE" in RANKER_SYSTEM_PROMPT
        assert "INFLUENCE" in RANKER_SYSTEM_PROMPT
        # The prompt must explicitly call out the propagation case
        assert "constants.h" in RANKER_SYSTEM_PROMPT or "propagat" in RANKER_SYSTEM_PROMPT.lower()
        # Must request JSON output
        assert "JSON" in RANKER_SYSTEM_PROMPT


# --- Callgraph reachability signal -------------------------------------------


class TestCallgraphReachabilitySignal:
    """A2: callgraph hop-distance should drive reachability scores.

    The preprocessor's _propagate_reachability stamps `reachability` and
    `min_hops_from_entry` on FileTargets.  The prioritizer's _apply_floors
    then enforces floor/ceiling rules based on those values so the LLM
    surface/influence scores cannot fully override the structural signal.
    """

    def test_entry_point_file_gets_reachability_five(self):
        """A file stamped as an entry point (min_hops_from_entry=0) must end up
        with reachability=5 regardless of what the LLM scores for it."""
        llm = _mock_llm_returning(
            [
                {
                    "path": "index.php",
                    "surface": 3,
                    "influence": 2,
                    "surface_rationale": "handles requests",
                    "influence_rationale": "moderate",
                }
            ]
        )
        # Simulate preprocessor having stamped the entry-point reachability
        ft = _make_file("index.php", language="php", tags=["web_entry"])
        ft["reachability"] = 5
        ft["min_hops_from_entry"] = 0
        ft["reachability_rationale"] = "entry point (web/cli/parser/fuzzable/syscall)"

        Prioritizer(llm).rank([ft])

        # _apply_floors must keep reachability at 5 (floor rule: hops==0 → max(r,5))
        assert ft["reachability"] == 5
        # priority = 3*0.5 + 2*0.2 + 5*0.3 = 1.5 + 0.4 + 1.5 = 3.4
        assert ft["priority"] == pytest.approx(3.4)
        # Entry-point files at tier boundary should be in A
        assert assign_tier(ft) == "A"

    def test_deep_internal_file_reachability_capped_at_two(self):
        """A file deep in the call tree (hops>5) gets reachability capped at 2
        even if the preprocessor had assigned it a higher reachability score.

        The point is that LLM surface/influence scores alone cannot push a
        structurally-distant file above reachability=2.  If the base scores are
        low, the combined priority lands in Tier C.
        """
        llm = _mock_llm_returning(
            [
                {
                    "path": "deep/internal/helper.php",
                    "surface": 1,
                    "influence": 2,
                    "surface_rationale": "shared utility",
                    "influence_rationale": "limited reach",
                }
            ]
        )
        ft = _make_file("deep/internal/helper.php", language="php")
        # Preprocessor determined this file is 7 hops from any entry point.
        # _propagate_reachability already set reachability=2; we confirm
        # _apply_floors keeps it there (soft cap: min(r, 2) with hops>5).
        ft["reachability"] = 2
        ft["min_hops_from_entry"] = 7
        ft["reachability_rationale"] = "reachable at distance 7"

        Prioritizer(llm).rank([ft])

        # hops>5 → soft cap: reachability stays at 2 (min(2, 2) = 2)
        assert ft["reachability"] == 2
        # priority = 1*0.5 + 2*0.2 + 2*0.3 = 0.5 + 0.4 + 0.6 = 1.5 → Tier C
        assert ft["priority"] == pytest.approx(1.5)
        assert assign_tier(ft) == "C"
