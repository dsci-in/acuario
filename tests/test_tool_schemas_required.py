"""M1 defensive: every object-typed tool schema must carry a 'required' key.

The self-hosted vLLM/minijinja chat-template path can choke when a tool's
parameter schema omits "required" (the template iterates it). JSON Schema
treats a missing "required" as an empty list, so adding "required": [] is a
semantic no-op that keeps strict renderers happy. This test locks that in
across every tool set so a future tool can't silently reintroduce the gap.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from acuario.agent.tools.hunt.deep_agent import build_deep_agent_tools
from acuario.agent.tools.hunt.exploit_tools import build_exploit_agent_tools


def _ctx():
    ctx = MagicMock()
    ctx.findings_pool = None
    return ctx


def _tool_sets():
    ctx = _ctx()
    finding = {"id": "x", "file": "a.php", "line_number": 1, "cwe": "CWE-89"}
    sets = {
        "deep": build_deep_agent_tools(ctx),
        "exploit": build_exploit_agent_tools(ctx, finding),
    }
    # hunter / propagation sets live behind the package __init__ exports.
    try:
        from acuario.agent.tools.hunt import (
            build_hunter_tools,
            build_propagation_auditor_tools,
        )

        sets["hunter"] = build_hunter_tools(ctx)
        sets["propagation"] = build_propagation_auditor_tools(ctx)
    except Exception:  # pragma: no cover - import shape varies
        pass
    return sets


@pytest.mark.parametrize("set_name", ["deep", "exploit", "hunter", "propagation"])
def test_every_object_schema_has_required(set_name):
    sets = _tool_sets()
    if set_name not in sets:
        pytest.skip(f"{set_name} tool set not available")
    offenders = [
        t.name
        for t in sets[set_name]
        if isinstance(t.schema, dict)
        and t.schema.get("type") == "object"
        and "required" not in t.schema
    ]
    assert offenders == [], f"{set_name} tools missing top-level 'required': {offenders}"
