"""Tests for the CostTracker telemetry module."""

from acuario.observability.telemetry import CostSummary, CostTracker, ToolUsage


def _reset_tracker():
    """Reset the CostTracker singleton for test isolation."""
    CostTracker._instance = None


class TestToolUsage:
    def test_defaults(self):
        tu = ToolUsage(name="nmap")
        assert tu.name == "nmap"
        assert tu.calls == 0
        assert tu.total_duration_ms == 0


class TestCostSummary:
    def test_fields(self):
        cs = CostSummary(
            input_tokens=100,
            output_tokens=50,
            total_cost_usd=0.01,
            tool_calls=3,
            by_tool={},
        )
        assert cs.input_tokens == 100
        assert cs.total_cost_usd == 0.01


class TestCostTracker:
    def setup_method(self):
        _reset_tracker()

    def teardown_method(self):
        _reset_tracker()

    def test_singleton(self):
        t1 = CostTracker()
        t2 = CostTracker()
        assert t1 is t2

    def test_initial_state(self):
        t = CostTracker()
        assert t.input_tokens == 0
        assert t.output_tokens == 0
        assert t.total_cost_usd == 0.0
        assert t.tool_calls == 0
        assert t.by_tool == {}
        assert t.cost_limit is None

    def test_record_llm_call_sonnet(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        # Cost = (1000 * 3.0 + 500 * 15.0) / 1_000_000 = (3000 + 7500) / 1M = 0.0105
        assert t.input_tokens == 1000
        assert t.output_tokens == 500
        assert abs(t.total_cost_usd - 0.0105) < 1e-6

    def test_record_llm_call_opus(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-opus-5-5")
        # Cost = (1000 * 4.0 + 500 * 20.0) / 1_000_000 = (4000 + 10000) / 1M = 0.014
        assert abs(t.total_cost_usd - 0.014) < 1e-6

    def test_record_llm_call_haiku(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-haiku-4-5")
        # Cost = (1000 * 0.80 + 500 * 4.0) / 1_000_000 = (800 + 2000) / 1M = 0.0028
        assert abs(t.total_cost_usd - 0.0028) < 1e-6

    def test_unknown_model_uses_sonnet_pricing(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "unknown-model")
        assert abs(t.total_cost_usd - 0.0105) < 1e-6

    def test_cumulative_calls(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        t.record_llm_call(2000, 1000, "claude-sonnet-4-6")
        assert t.input_tokens == 3000
        assert t.output_tokens == 1500

    def test_per_agent_attribution(self):
        # P4: record_llm_call(task=...) accumulates per-agent token + cost.
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6", task="analyzer")
        t.record_llm_call(200, 100, "claude-sonnet-4-6", task="analyzer")
        t.record_llm_call(50, 20, "claude-sonnet-4-6", task="skeptic")
        assert set(t.by_agent) == {"analyzer", "skeptic"}
        assert t.by_agent["analyzer"]["calls"] == 2
        assert t.by_agent["analyzer"]["input_tokens"] == 1200
        assert t.by_agent["analyzer"]["output_tokens"] == 600
        assert t.by_agent["skeptic"]["calls"] == 1
        # ref_cost_usd always accumulates (Opus rate) even on self-hosted $0 runs.
        assert t.by_agent["analyzer"]["ref_cost_usd"] > 0

    def test_per_agent_skipped_without_task(self):
        t = CostTracker()
        t.record_llm_call(100, 50, "claude-sonnet-4-6")  # no task
        assert t.by_agent == {}

    def test_self_hosted_agent_paid_cost_zero_but_ref_nonzero(self):
        t = CostTracker()
        t.set_endpoint(provider="vllm", base_url="http://192.168.1.5:8000/v1", model="qwen")
        t.record_llm_call(1000, 500, "qwen", task="analyzer")
        assert t.by_agent["analyzer"]["cost_usd"] == 0.0
        assert t.by_agent["analyzer"]["ref_cost_usd"] > 0

    def test_reset_clears_by_agent(self):
        t = CostTracker()
        t.record_llm_call(100, 50, "claude-sonnet-4-6", task="analyzer")
        t.reset()
        assert t.by_agent == {}

    def test_record_tool_call(self):
        t = CostTracker()
        t.record_tool_call("scan_ports", 150)
        t.record_tool_call("scan_ports", 200)
        t.record_tool_call("detect_os", 50)
        assert t.tool_calls == 3
        assert t.by_tool["scan_ports"].calls == 2
        assert t.by_tool["scan_ports"].total_duration_ms == 350
        assert t.by_tool["detect_os"].calls == 1

    def test_get_summary(self):
        t = CostTracker()
        t.record_llm_call(100, 50, "claude-sonnet-4-6")
        t.record_tool_call("nmap", 100)
        summary = t.get_summary()
        assert isinstance(summary, CostSummary)
        assert summary.input_tokens == 100
        assert summary.output_tokens == 50
        assert summary.tool_calls == 1
        assert "nmap" in summary.by_tool

    def test_is_over_limit_no_limit(self):
        t = CostTracker()
        t.record_llm_call(1000000, 500000, "claude-opus-4-6")
        assert not t.is_over_limit()

    def test_is_over_limit_under(self):
        t = CostTracker()
        t.cost_limit = 1.0
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        assert not t.is_over_limit()

    def test_is_over_limit_exceeded(self):
        t = CostTracker()
        t.cost_limit = 0.001
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        assert t.is_over_limit()

    def test_reset(self):
        t = CostTracker()
        t.record_llm_call(1000, 500, "claude-sonnet-4-6")
        t.record_tool_call("nmap", 100)
        t.reset()
        assert t.input_tokens == 0
        assert t.output_tokens == 0
        assert t.total_cost_usd == 0.0
        assert t.tool_calls == 0
        assert t.by_tool == {}

    def test_pricing_table(self):
        # Operational defaults the tool bills against must stay priced.
        assert "claude-sonnet-4-6" in CostTracker.PRICING
        assert "claude-haiku-4-5" in CostTracker.PRICING
        # Every frontier reference model must have a rate to quote against.
        for model, _label in CostTracker.REFERENCE_MODELS:
            assert model in CostTracker.PRICING
        for model, prices in CostTracker.PRICING.items():
            assert "input" in prices
            assert "output" in prices
            assert prices["input"] > 0
            assert prices["output"] > 0

    def test_reference_quotes_cover_frontier_lineup(self):
        # The displayed comparison prices each REFERENCE_MODELS entry from the
        # run's token totals; labels and figures come from one source.
        quotes = CostTracker.reference_quotes(1_000_000, 1_000_000)
        assert len(quotes) == len(CostTracker.REFERENCE_MODELS)
        labels = [label for label, _ in quotes]
        assert labels == [label for _, label in CostTracker.REFERENCE_MODELS]
        assert all(usd > 0 for _, usd in quotes)
