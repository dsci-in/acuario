"""Tests for the SkepticGate lab agent (lab/B1)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from acuario.findings.types import Finding
from acuario.lab.agents.skeptic import SkepticGate


def _make_finding(**kw) -> Finding:
    defaults = dict(
        id="f-test",
        file="src/auth.php",
        line_number=42,
        finding_type="sql_injection",
        cwe="CWE-89",
        severity="high",
        description="Unparameterized query constructed from user input",
        code_snippet="$q = \"SELECT * FROM users WHERE id='\" . $_GET['id'] . \"'\";",
        evidence_level="static_corroboration",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _mock_llm_verdict(verdict_text: str) -> AsyncMock:
    mock = AsyncMock()
    resp = MagicMock()
    resp.first_text.return_value = verdict_text
    mock.achat.return_value = resp
    return mock


# --- SkepticVerdict parsing ---------------------------------------------------


class TestSkepticVerdictParsing:
    def test_parse_accepted_json(self):
        text = '{"verdict": "accepted", "reasoning": "no mitigations visible"}'
        verdict, reasoning, _conf = SkepticGate._parse_verdict(text)
        assert verdict == "accepted"
        assert reasoning == "no mitigations visible"

    def test_parse_refuted_json(self):
        text = '{"verdict": "refuted", "reasoning": "prepared statements used at line 18"}'
        verdict, reasoning, _conf = SkepticGate._parse_verdict(text)
        assert verdict == "refuted"
        assert "prepared" in reasoning

    def test_parse_garbage_defaults_to_accepted(self):
        verdict, reasoning, _conf = SkepticGate._parse_verdict("this is not json at all")
        assert verdict == "accepted"

    def test_parse_refuted_regex_fallback(self):
        text = 'Verdict: {"verdict": "refuted", "reasoning": "input validated at line 5"}'
        verdict, _, _conf = SkepticGate._parse_verdict(text)
        assert verdict == "refuted"

    def test_parse_invalid_verdict_value_defaults_to_accepted(self):
        text = '{"verdict": "maybe", "reasoning": "not sure"}'
        verdict, _, _conf = SkepticGate._parse_verdict(text)
        assert verdict == "accepted"

    def test_parse_uncertain_json(self):
        # O1: three-way verdict - the framework-assumption case.
        text = (
            '{"verdict": "uncertain", "confidence": 0.3, '
            '"reasoning": "the framework probably escapes this but I cannot see where"}'
        )
        verdict, reasoning, conf = SkepticGate._parse_verdict(text)
        assert verdict == "uncertain"
        assert conf == 0.3
        assert "framework" in reasoning

    def test_parse_confidence_clamped(self):
        text = '{"verdict": "refuted", "confidence": 5.0, "reasoning": "sanitized at line 7"}'
        _v, _r, conf = SkepticGate._parse_verdict(text)
        assert conf == 1.0

    def test_parse_uncertain_default_confidence_is_low(self):
        text = '{"verdict": "uncertain", "reasoning": "general assumption, no code cited here"}'
        _v, _r, conf = SkepticGate._parse_verdict(text)
        assert conf == 0.4


# --- SkepticGate.ascreen ------------------------------------------------------


class TestSkepticGateScreen:
    @pytest.mark.asyncio
    async def test_no_llm_always_accepts(self):
        gate = SkepticGate(llm=None)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        assert verdict.verdict == "accepted"
        assert gate.accepted_count == 1
        assert gate.refuted_count == 0

    @pytest.mark.asyncio
    async def test_llm_accepted_verdict(self):
        llm = _mock_llm_verdict('{"verdict": "accepted", "reasoning": "no bypass"}')
        gate = SkepticGate(llm=llm)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        assert verdict.verdict == "accepted"
        assert gate.accepted_count == 1

    @pytest.mark.asyncio
    async def test_llm_refuted_verdict(self):
        llm = _mock_llm_verdict(
            '{"verdict": "refuted", "reasoning": "PDO prepared statements used at line 12"}'
        )
        gate = SkepticGate(llm=llm)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        assert verdict.verdict == "refuted"
        assert gate.refuted_count == 1
        assert gate.accepted_count == 0

    @pytest.mark.asyncio
    async def test_llm_error_is_fail_open(self):
        llm = AsyncMock()
        llm.achat.side_effect = RuntimeError("connection reset")
        gate = SkepticGate(llm=llm)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        # Fail-open → accepted even on error
        assert verdict.verdict == "accepted"
        assert gate.accepted_count == 1

    @pytest.mark.asyncio
    async def test_uncertain_passes_through_with_flag(self):
        # O1: an uncertain verdict must NOT drop the finding - it passes
        # through flagged so the validator weighs it.
        llm = _mock_llm_verdict(
            '{"verdict": "uncertain", "confidence": 0.3, '
            '"reasoning": "the ORM probably parameterizes but I cannot see it"}'
        )
        gate = SkepticGate(llm=llm)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        assert verdict.verdict == "uncertain"
        assert gate.uncertain_count == 1
        assert gate.refuted_count == 0
        # The finding is stamped so downstream consumers can see the doubt.
        assert f.get("skeptic_flag") == "uncertain"
        assert "ORM" in (f.get("skeptic_doubt") or "")

    @pytest.mark.asyncio
    async def test_shadow_mode_logs_but_does_not_gate(self, tmp_path: Path):
        # O8: in shadow mode a "refuted" finding still passes through (returned
        # verdict is accepted), but the skeptic_log records the TRUE verdict.
        llm = _mock_llm_verdict('{"verdict": "refuted", "reasoning": "param query at line 5"}')
        gate = SkepticGate(llm=llm, output_dir=tmp_path, shadow_mode=True)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        # Caller sees "accepted" → finding is admitted, not gated.
        assert verdict.verdict == "accepted"
        # But the log captured the real "refuted" decision for calibration.
        log = (tmp_path / "skeptic_log.jsonl").read_text().strip()
        record = json.loads(log)
        assert record["verdict"] == "refuted"
        # Review fix: the finding is stamped with the would-be doubt so the
        # validator/report keep the calibration signal shadow mode collects.
        assert f.get("skeptic_flag") == "would-refute"
        assert "param query" in (f.get("skeptic_doubt") or "")

    @pytest.mark.asyncio
    async def test_shadow_mode_uncertain_stamps_flag(self, tmp_path: Path):
        # Review fix: an uncertain verdict in shadow mode must stamp
        # skeptic_flag="uncertain" (was lost on the early return).
        llm = _mock_llm_verdict(
            '{"verdict": "uncertain", "reasoning": "framework maybe escapes this"}'
        )
        gate = SkepticGate(llm=llm, output_dir=tmp_path, shadow_mode=True)
        f = _make_finding()
        verdict = await gate.ascreen(f)
        assert verdict.verdict == "accepted"  # not gated
        assert f.get("skeptic_flag") == "uncertain"

    @pytest.mark.asyncio
    async def test_batch_keeps_uncertain_findings(self):
        # O1: ascreen_batch drops only "refuted"; "uncertain" survives.
        call = 0

        async def mock_achat(**kwargs):
            nonlocal call
            call += 1
            resp = MagicMock()
            if call == 1:
                resp.first_text.return_value = (
                    '{"verdict": "refuted", "reasoning": "param query line 5"}'
                )
            else:
                resp.first_text.return_value = (
                    '{"verdict": "uncertain", "reasoning": "framework maybe handles it"}'
                )
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm)
        findings = [_make_finding(id="f0"), _make_finding(id="f1")]
        accepted, verdicts = await gate.ascreen_batch(findings)
        # refuted f0 dropped; uncertain f1 kept.
        assert [f["id"] for f in accepted] == ["f1"]
        assert verdicts[0].verdict == "refuted"
        assert verdicts[1].verdict == "uncertain"

    @pytest.mark.asyncio
    async def test_fail_open_is_counted(self):
        # M3: a dead skeptic LLM must not be silent - the fail-open count
        # makes the precision risk visible to Pipeline Health.
        llm = AsyncMock()
        llm.achat.side_effect = RuntimeError("connection reset")
        gate = SkepticGate(llm=llm)
        assert gate.fail_open_count == 0
        await gate.ascreen(_make_finding(id="f1"))
        await gate.ascreen(_make_finding(id="f2"))
        assert gate.fail_open_count == 2

    @pytest.mark.asyncio
    async def test_fail_open_count_stays_zero_on_clean_verdicts(self):
        llm = _mock_llm_verdict('{"verdict": "accepted", "reasoning": "ok"}')
        gate = SkepticGate(llm=llm)
        await gate.ascreen(_make_finding())
        assert gate.fail_open_count == 0


class TestDebateRound:
    """O2: analyzer↔skeptic debate over refuted findings."""

    def _verdict(self, fid="f1"):
        from acuario.lab.agents.skeptic import SkepticVerdict

        return SkepticVerdict(
            verdict="refuted",
            reasoning="the ORM parameterizes this query",
            finding_id=fid,
            file="src/db.py",
            line_number=42,
        )

    @pytest.mark.asyncio
    async def test_rebuttal_overturns_and_reinstates(self):
        # analyst rebuts (no concede) -> skeptic overturns -> finding reinstated.
        seq = [
            '{"concede": false, "rebuttal": "raw f-string at line 42, no ORM here"}',
            '{"final_verdict": "overturned", "reasoning": "concrete code I missed"}',
        ]
        it = iter(seq)

        async def mock_achat(**kwargs):
            resp = MagicMock()
            resp.first_text.return_value = next(it)
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm)
        f = _make_finding(id="f1")
        reinstated = await gate.adebate_batch([(f, self._verdict("f1"))])
        assert [x["id"] for x in reinstated] == ["f1"]
        assert gate.debate_overturned_count == 1
        assert f.get("debate_overturned") is True

    @pytest.mark.asyncio
    async def test_concede_keeps_finding_refuted(self):
        # analyst concedes -> no second call -> not reinstated.
        async def mock_achat(**kwargs):
            resp = MagicMock()
            resp.first_text.return_value = '{"concede": true, "rebuttal": ""}'
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm)
        f = _make_finding(id="f1")
        reinstated = await gate.adebate_batch([(f, self._verdict("f1"))])
        assert reinstated == []
        assert gate.debate_upheld_count == 1

    @pytest.mark.asyncio
    async def test_skeptic_upholds_after_rebuttal(self):
        seq = [
            '{"concede": false, "rebuttal": "I think it is exploitable"}',
            '{"final_verdict": "upheld", "reasoning": "still just a guess, no code cited"}',
        ]
        it = iter(seq)

        async def mock_achat(**kwargs):
            resp = MagicMock()
            resp.first_text.return_value = next(it)
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm)
        f = _make_finding(id="f1")
        reinstated = await gate.adebate_batch([(f, self._verdict("f1"))])
        assert reinstated == []
        assert gate.debate_upheld_count == 1

    @pytest.mark.asyncio
    async def test_debate_log_written(self, tmp_path):
        seq = [
            '{"concede": false, "rebuttal": "raw query at line 42"}',
            '{"final_verdict": "overturned", "reasoning": "valid point"}',
        ]
        it = iter(seq)

        async def mock_achat(**kwargs):
            resp = MagicMock()
            resp.first_text.return_value = next(it)
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm, output_dir=tmp_path)
        await gate.adebate_batch([(_make_finding(id="f1"), self._verdict("f1"))])
        log = tmp_path / "debate_log.jsonl"
        assert log.exists()
        rec = json.loads(log.read_text().strip())
        assert rec["finding_id"] == "f1"
        assert rec["reinstated"] is True

    @pytest.mark.asyncio
    async def test_no_llm_is_noop(self):
        gate = SkepticGate(llm=None)
        reinstated = await gate.adebate_batch([(_make_finding(), self._verdict())])
        assert reinstated == []

    @pytest.mark.asyncio
    async def test_failed_debate_is_counted(self):
        # Review fix: a debate that errors out (None outcome) must increment a
        # failure counter, not vanish silently from the tallies.
        llm = AsyncMock()
        llm.achat.side_effect = RuntimeError("connection reset")
        gate = SkepticGate(llm=llm)
        reinstated = await gate.adebate_batch([(_make_finding(id="f1"), self._verdict("f1"))])
        assert reinstated == []
        assert gate._debate_failed == 1
        assert gate._debate_overturned == 0
        assert gate._debate_upheld == 0
        assert "failed" in gate.summary()

    @pytest.mark.asyncio
    async def test_refuted_written_to_file(self, tmp_path: Path):
        llm = _mock_llm_verdict('{"verdict": "refuted", "reasoning": "sanitized at line 7"}')
        gate = SkepticGate(llm=llm, output_dir=tmp_path)
        f = _make_finding()
        await gate.ascreen(f)

        refuted_path = tmp_path / "skeptic_refuted.jsonl"
        assert refuted_path.exists()
        record = json.loads(refuted_path.read_text().strip())
        assert record["finding_id"] == "f-test"
        assert "sanitized" in record["skeptic_reasoning"]

    @pytest.mark.asyncio
    async def test_accepted_not_written_to_file(self, tmp_path: Path):
        llm = _mock_llm_verdict('{"verdict": "accepted", "reasoning": "looks bad"}')
        gate = SkepticGate(llm=llm, output_dir=tmp_path)
        f = _make_finding()
        await gate.ascreen(f)

        refuted_path = tmp_path / "skeptic_refuted.jsonl"
        assert not refuted_path.exists()


# --- SkepticGate.ascreen_batch -----------------------------------------------


class TestSkepticGateBatch:
    @pytest.mark.asyncio
    async def test_batch_filters_refuted(self):
        call_count = 0

        async def mock_achat(**kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            # Refute the first finding, accept the rest
            if call_count == 1:
                resp.first_text.return_value = (
                    '{"verdict": "refuted", "reasoning": "prepared stmt at 5"}'
                )
            else:
                resp.first_text.return_value = '{"verdict": "accepted", "reasoning": "ok"}'
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm)

        findings = [_make_finding(id=f"f-{i}") for i in range(3)]
        accepted, verdicts = await gate.ascreen_batch(findings)

        assert len(accepted) == 2
        assert len(verdicts) == 3
        assert verdicts[0].verdict == "refuted"
        assert verdicts[1].verdict == "accepted"

    @pytest.mark.asyncio
    async def test_batch_passes_per_file_cross_file_context(self):
        # M2: ascreen_batch must thread per-file cross_file_context into each
        # screen so batched findings get the same context the serial path gave.
        seen_contexts: list[str] = []

        async def mock_achat(**kwargs):
            user_msg = kwargs["messages"][0].content
            seen_contexts.append(user_msg)
            resp = MagicMock()
            resp.first_text.return_value = '{"verdict": "accepted", "reasoning": "ok"}'
            return resp

        llm = AsyncMock()
        llm.achat = mock_achat
        gate = SkepticGate(llm=llm)

        findings = [
            _make_finding(id="f-a", file="a.py"),
            _make_finding(id="f-b", file="b.py"),
        ]
        contexts = {"a.py": "CALLER_OF_A_MARKER", "b.py": "CALLER_OF_B_MARKER"}
        accepted, verdicts = await gate.ascreen_batch(findings, cross_file_contexts=contexts)

        assert len(accepted) == 2
        blob = "\n".join(seen_contexts)
        assert "CALLER_OF_A_MARKER" in blob
        assert "CALLER_OF_B_MARKER" in blob

    @pytest.mark.asyncio
    async def test_summary_string(self):
        gate = SkepticGate(llm=None)
        f1 = _make_finding(id="f1")
        f2 = _make_finding(id="f2")
        await gate.ascreen(f1)
        await gate.ascreen(f2)
        s = gate.summary()
        assert "accepted 2" in s
        assert "refuted 0" in s


def test_skeptic_system_prompt_has_per_value_credential_clause():
    """D1/O-W: per-value credential disposition + anchored formats + the
    server-enforcement bar, WITHOUT a high-entropy-hex refutation lever."""
    from acuario.lab.agents.skeptic import _SKEPTIC_SYSTEM

    low = " ".join(_SKEPTIC_SYSTEM.split()).lower()  # collapse line wraps
    # Anchored credential formats - a value in these is real regardless of framing.
    for anchor in ("ghp_", "akia", "private key", "eyj"):
        assert anchor in low, anchor
    # Per-value disposition, not a blanket mock-refute.
    assert "per-value" in low or "each secret value" in low
    # Server-enforcement bar.
    assert "assert server-side enforcement only if" in low
    # The high-entropy-hex anchor is explicitly struck, not used as a lever.
    assert "entropy alone proves nothing" in low
