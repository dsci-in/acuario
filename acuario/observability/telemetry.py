"""Cost tracking and telemetry for Acuario LLM usage.

Tracks two parallel cost figures:

- ``total_cost_usd``  - what you ACTUALLY paid. For commercial APIs this is the
  bill at the provider's published rate. For self-hosted endpoints (Ollama,
  vLLM, LM Studio, custom local) this stays at $0 - there is no bill.

- ``reference_cost_*_usd`` - what the same tokens WOULD HAVE COST on a
  commercial frontier API. Two reference quotes are kept: Anthropic Claude
  Opus 4.7 and OpenAI GPT-5.4. Useful for stage demos / cost-comparison
  reports - "this audit on Ollama generated 17M tokens; the same workload
  via Claude Opus would have cost ~$268."

The ``set_endpoint`` method tells the tracker which mode to use; it must be
called once at audit start before any LLM call records.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from urllib.parse import urlparse

from acuario.core.events import EventBus, EventType


@dataclass
class ToolUsage:
    """Tracks usage statistics for a single tool."""

    name: str
    calls: int = 0
    total_duration_ms: int = 0


@dataclass
class CostSummary:
    """Snapshot of current cost and usage metrics."""

    input_tokens: int
    output_tokens: int
    total_cost_usd: float
    tool_calls: int
    by_tool: dict[str, ToolUsage]
    # Reference quotes - what the same token totals would have cost on
    # commercial frontier APIs. Always populated; the runner / reporter
    # decides whether to surface them based on `is_self_hosted`.
    reference_cost_opus_usd: float = 0.0
    reference_cost_gpt_usd: float = 0.0
    is_self_hosted: bool = False
    endpoint_label: str = ""


class CostTracker:
    """Singleton that tracks LLM token usage, costs, and tool call metrics.

    Thread-safe via an internal lock.
    """

    _instance: CostTracker | None = None
    _lock_cls = threading.Lock  # used only for singleton creation

    # Per-million-token prices (USD). Kept deliberately lean. The lineup churns
    # fast, so verify against the providers' official pricing when touching
    # this. Rates current as of 2026-09.
    PRICING: dict[str, dict[str, float]] = {
        # Operational models the tool actually bills against (task defaults +
        # sub-task models). These must stay so commercial-run cost tracking is
        # accurate - they are not just decoration for the reference quotes.
        "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
        "claude-haiku-4-5": {"input": 0.80, "output": 4.0},
        "gpt-4o": {"input": 2.5, "output": 10.0},
        # Current frontier flagships - the reference-quote set.
        "claude-opus-5-5": {"input": 4.0, "output": 20.0},
        "claude-fable-5-1": {"input": 10.0, "output": 50.0},
        "gpt-6-astra": {"input": 10.0, "output": 50.0},
        "gpt-5.6-sol": {"input": 5.0, "output": 30.0},
    }

    _DEFAULT_MODEL = "claude-sonnet-4-6"

    # Reference models the per-call accumulators (reference_cost_opus_usd /
    # reference_cost_gpt_usd) price against, kept for the machine-readable
    # cost_summary / manifest.
    REF_OPUS_MODEL = "claude-opus-5-5"
    REF_GPT_MODEL = "gpt-6-astra"

    # The frontier models shown in the "what this run would have cost on a
    # commercial API" comparison in the report and terminal. Single source of
    # truth for that display so a model name can never drift from its rate.
    # Kept lean and current; each is priced from PRICING against the run's
    # token totals. Verify the lineup + rates against the providers' official
    # pricing when updating.
    REFERENCE_MODELS: tuple[tuple[str, str], ...] = (
        ("claude-opus-5-5", "Anthropic Claude Opus 5.5"),
        ("claude-fable-5-1", "Anthropic Claude Fable 5.1"),
        ("gpt-6-astra", "OpenAI GPT-6 Astra"),
        ("gpt-5.6-sol", "OpenAI GPT-5.6 Sol"),
    )

    # Hostname / IP prefixes that mean "this is the user's own infrastructure".
    # Used to classify endpoints as self-hosted even when the provider
    # adapter is a generic "openai" (vLLM, SGLang, custom proxies, etc.).
    _LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    _PRIVATE_IP_PREFIXES = (
        "192.168.",
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
    )
    _SELF_HOSTED_ADAPTERS = {"ollama", "lmstudio", "vllm"}

    def __new__(cls) -> CostTracker:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._lock = threading.Lock()
        self.input_tokens: int = 0
        self.output_tokens: int = 0
        self.total_cost_usd: float = 0.0
        self.reference_cost_opus_usd: float = 0.0
        self.reference_cost_gpt_usd: float = 0.0
        self.tool_calls: int = 0
        self.by_tool: dict[str, ToolUsage] = {}
        self.cost_limit: float | None = None
        # per-agent token + cost attribution. Keyed by the pipeline role
        # (analyzer / reviewer / skeptic / critic / orchestrator / exploit_dev
        # / prioritizer / …). Lets the report show which agent earns its spend.
        self.by_agent: dict[str, dict[str, float]] = {}
        # Endpoint mode - set by the audit handler at startup. When
        # is_self_hosted is True, total_cost_usd stays at $0 for every
        # call and only the reference quotes accumulate.
        self.is_self_hosted: bool = False
        self.endpoint_label: str = ""
        self._initialized = True

    # ------------------------------------------------------------------
    # Endpoint classification (called once at audit start)
    # ------------------------------------------------------------------

    @classmethod
    def is_self_hosted_endpoint(cls, provider: str | None = "", base_url: str | None = "") -> bool:
        """Decide whether an endpoint is self-hosted.

        Self-hosted = no real money changes hands per token. Detected via:
          - a known local-only adapter (``ollama``, ``lmstudio``, ``vllm``), or
          - a base URL whose hostname is loopback or in an RFC1918 range.

        Returns False on ambiguous input (no base_url AND no provider) so
        we don't accidentally hide costs for a real cloud API call.
        """
        if (provider or "").lower() in cls._SELF_HOSTED_ADAPTERS:
            return True
        if not base_url:
            return False
        host = (urlparse(base_url).hostname or "").lower()
        if host in cls._LOCAL_HOSTS:
            return True
        return any(host.startswith(p) for p in cls._PRIVATE_IP_PREFIXES)

    def set_endpoint(
        self,
        *,
        provider: str | None = "",
        base_url: str | None = "",
        model: str = "",
    ) -> None:
        """Tell the tracker which endpoint the audit will use.

        Call this once at the top of ``audit.py::handle()`` after the
        endpoint is resolved. Subsequent ``record_llm_call`` invocations
        will route real cost to $0 (self-hosted) or to the model's rate
        (commercial), and always accumulate both reference quotes.
        """
        with self._lock:
            self.is_self_hosted = self.is_self_hosted_endpoint(provider, base_url)
            label_parts = [model] if model else []
            if provider:
                label_parts.append(f"via {provider}")
            self.endpoint_label = " ".join(label_parts).strip() or "unknown"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def _quote(cls, input_tokens: int, output_tokens: int, model: str) -> float:
        """Per-call USD cost at the rates registered for ``model``.

        Falls back to default Sonnet pricing for unknown models. Always
        returns a finite float (even for zero tokens or unknown model).
        """
        pricing = cls.PRICING.get(model, cls.PRICING[cls._DEFAULT_MODEL])
        return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000

    @classmethod
    def reference_quotes(cls, input_tokens: int, output_tokens: int) -> list[tuple[str, float]]:
        """``(label, usd)`` for each frontier model in ``REFERENCE_MODELS``.

        Drives the "what this run would have cost on a commercial API"
        comparison shown in the report and terminal, priced from the run's
        token totals so the report never disagrees with the rate table.
        """
        return [
            (label, cls._quote(input_tokens, output_tokens, model))
            for model, label in cls.REFERENCE_MODELS
        ]

    def record_llm_call(
        self, input_tokens: int, output_tokens: int, model: str, task: str = ""
    ) -> None:
        """Record token usage for a single LLM call and update running counters.

        Behaviour depends on the tracker's endpoint mode (set via
        ``set_endpoint``):
          - self-hosted: ``total_cost_usd`` stays at $0; both reference
            quotes accumulate at frontier-API rates.
          - commercial: ``total_cost_usd`` accumulates at the in-use
            model's rate; reference quotes also accumulate (so the report
            can still show "vs Opus" / "vs GPT-5.4" if useful).

        Tokens always accumulate regardless of mode.
        """
        actual_cost = (
            0.0
            if self.is_self_hosted
            else self._quote(
                input_tokens,
                output_tokens,
                model,
            )
        )
        opus_cost = self._quote(input_tokens, output_tokens, self.REF_OPUS_MODEL)
        gpt_cost = self._quote(input_tokens, output_tokens, self.REF_GPT_MODEL)

        with self._lock:
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.total_cost_usd += actual_cost
            self.reference_cost_opus_usd += opus_cost
            self.reference_cost_gpt_usd += gpt_cost
            # per-agent attribution. On self-hosted runs actual_cost is $0,
            # so we also track the reference (Opus-rate) cost as a relative
            # "how expensive is this agent" signal that's meaningful even when
            # no money changes hands.
            if task:
                slot = self.by_agent.setdefault(
                    task,
                    {
                        "input_tokens": 0.0,
                        "output_tokens": 0.0,
                        "cost_usd": 0.0,
                        "ref_cost_usd": 0.0,
                        "calls": 0.0,
                    },
                )
                slot["input_tokens"] += input_tokens
                slot["output_tokens"] += output_tokens
                slot["cost_usd"] += actual_cost
                slot["ref_cost_usd"] += opus_cost
                slot["calls"] += 1

        try:
            EventBus.emit(
                EventType.COST_UPDATE,
                {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost": actual_cost,
                    "total_cost_usd": self.total_cost_usd,
                    "reference_cost_opus_usd": self.reference_cost_opus_usd,
                    "reference_cost_gpt_usd": self.reference_cost_gpt_usd,
                    "model": model,
                    "is_self_hosted": self.is_self_hosted,
                },
            )
        except Exception:
            pass  # telemetry should never break the caller

    def record_tool_call(self, tool_name: str, duration_ms: int) -> None:
        """Record a tool invocation and its wall-clock duration."""
        with self._lock:
            self.tool_calls += 1
            if tool_name not in self.by_tool:
                self.by_tool[tool_name] = ToolUsage(name=tool_name)
            usage = self.by_tool[tool_name]
            usage.calls += 1
            usage.total_duration_ms += duration_ms

    def get_summary(self) -> CostSummary:
        """Return a point-in-time snapshot of all tracked metrics."""
        with self._lock:
            return CostSummary(
                input_tokens=self.input_tokens,
                output_tokens=self.output_tokens,
                total_cost_usd=self.total_cost_usd,
                tool_calls=self.tool_calls,
                by_tool=dict(self.by_tool),
                reference_cost_opus_usd=self.reference_cost_opus_usd,
                reference_cost_gpt_usd=self.reference_cost_gpt_usd,
                is_self_hosted=self.is_self_hosted,
                endpoint_label=self.endpoint_label,
            )

    def is_over_limit(self) -> bool:
        """Return ``True`` if a cost limit is set and the current spend exceeds it."""
        with self._lock:
            if self.cost_limit is None:
                return False
            return self.total_cost_usd > self.cost_limit

    def reset(self) -> None:
        """Reset all counters to their initial state."""
        with self._lock:
            self.input_tokens = 0
            self.output_tokens = 0
            self.total_cost_usd = 0.0
            self.reference_cost_opus_usd = 0.0
            self.reference_cost_gpt_usd = 0.0
            self.tool_calls = 0
            self.by_tool = {}
            self.by_agent = {}
            self.is_self_hosted = False
            self.endpoint_label = ""
