"""Tests for the ReflectiveCritic lab agent (lab/B2)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from acuario.lab.agents.critic import ReflectiveCritic


def _mock_llm(response_text: str) -> AsyncMock:
    mock = AsyncMock()
    resp = MagicMock()
    resp.first_text.return_value = response_text
    mock.achat.return_value = resp
    return mock


# --- CriticLead parsing -------------------------------------------------------


class TestCriticLeadParsing:
    def test_parse_valid_json_array(self):
        text = """
[
  {
    "file": "src/login.php",
    "line_number": 17,
    "cwe": "CWE-79",
    "finding_type": "xss",
    "description": "User input reflected without escaping in error message",
    "confidence": "low"
  }
]
"""
        leads = ReflectiveCritic._parse_leads(text, "src/login.php")
        assert len(leads) == 1
        assert leads[0].cwe == "CWE-79"
        assert leads[0].finding_type == "xss"
        assert leads[0].discovered_by == "critic"

    def test_parse_empty_array(self):
        leads = ReflectiveCritic._parse_leads("[]", "src/foo.php")
        assert leads == []

    def test_parse_garbage_returns_empty(self):
        leads = ReflectiveCritic._parse_leads("not json at all", "src/bar.php")
        assert leads == []

    def test_parse_caps_at_five_leads(self):
        items = [
            {
                "file": f"src/f{i}.php",
                "line_number": i,
                "cwe": "CWE-89",
                "finding_type": "sqli",
                "description": f"finding {i}",
            }
            for i in range(10)
        ]
        import json

        text = json.dumps(items)
        leads = ReflectiveCritic._parse_leads(text, "src/f0.php")
        assert len(leads) == 5

    def test_parse_uses_fallback_file_when_missing(self):
        text = '[{"line_number": 5, "cwe": "CWE-352", "finding_type": "csrf", "description": "d"}]'
        leads = ReflectiveCritic._parse_leads(text, "src/default.php")
        # file field was absent → should fall back to the passed file_path
        assert leads[0].file == "src/default.php"


# --- ReflectiveCritic.areflect -----------------------------------------------


class TestReflectiveCriticReflect:
    @pytest.mark.asyncio
    async def test_no_llm_returns_empty(self):
        critic = ReflectiveCritic(llm=None)
        leads = await critic.areflect(
            file_path="src/auth.php",
            existing_findings=[],
        )
        assert leads == []
        assert critic.sessions_reflected == 0

    @pytest.mark.asyncio
    async def test_llm_returns_leads(self):
        response_json = """
[
  {
    "file": "src/auth.php",
    "line_number": 22,
    "cwe": "CWE-284",
    "finding_type": "broken_access_control",
    "description": "Admin check bypassed via role parameter manipulation",
    "confidence": "low"
  }
]
"""
        critic = ReflectiveCritic(llm=_mock_llm(response_json))
        leads = await critic.areflect(
            file_path="src/auth.php",
            existing_findings=[],
            trajectory_summary="Agent investigated SQL injection only.",
        )
        assert len(leads) == 1
        assert leads[0].discovered_by == "critic"
        assert leads[0].confidence == "low"
        assert critic.sessions_reflected == 1
        assert critic.leads_total == 1

    @pytest.mark.asyncio
    async def test_llm_error_returns_empty(self):
        llm = AsyncMock()
        llm.achat.side_effect = RuntimeError("timeout")
        critic = ReflectiveCritic(llm=llm)
        leads = await critic.areflect(
            file_path="src/cart.php",
            existing_findings=[],
        )
        assert leads == []
        assert critic.sessions_reflected == 0

    @pytest.mark.asyncio
    async def test_summary_string(self):
        critic = ReflectiveCritic(
            llm=_mock_llm('[{"file":"f","cwe":"X","finding_type":"y","description":"d"}]')
        )
        await critic.areflect("src/f.php", [])
        s = critic.summary()
        assert "1 sessions reflected" in s
        assert "1 leads" in s
