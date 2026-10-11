"""Per-analyzer sandbox context and sanitizer-variant routing.

`HunterContext` is the mutable state passed to every per-analyzer tool
builder (discovery/analysis/reporting). It owns the primary
SandboxContainer plus a cache of sanitizer-variant containers so that
an MSan analyzer can transparently spawn a second image without the
caller tracking it.

This file holds ONLY the context dataclass and the argument parser for
the `sanitizer_variant` tool argument. All tool builders live in
sibling modules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import cast

from acuario.sandbox.container import SandboxContainer
from acuario.scanner.state import Finding

logger = logging.getLogger(__name__)


@dataclass
class HunterContext:
    """Per-analyzer mutable context. Closured into every tool for state access."""

    repo_path: str  # absolute host path
    sandbox: SandboxContainer | None = None  # primary sandbox; set by hunt loop
    findings: list[Finding] = field(default_factory=list)
    file_path: str | None = None  # the file this analyzer is scoped to
    session_id: str | None = None
    specialist: str = "general"  # "general" | "memory_safety" | "logic_auth" | "propagation"
    seeded_crash: dict | None = None  # from harness generator
    # MSan variant support: a AnalyzerSandbox manager so tools can
    # spawn alternative-sanitizer containers (e.g. MSan) on demand.
    # Variant containers are cached in `variant_sandboxes` and torn down
    # at analyzer cleanup time.
    sandbox_manager: object | None = None  # AnalyzerSandbox (avoiding circular import)
    variant_sandboxes: dict = field(default_factory=dict)  # {variant_key: SandboxContainer}
    default_sanitizers: tuple = ("asan", "ubsan")
    findings_pool: object | None = None  # FindingsPool (avoiding circular import)
    trajectory_dir: object | None = None  # Path override for transcript output
    exploit_result: object | None = None  # ExploiterResult slot for exploit agent
    elaboration_result: object | None = None  # ElaborationResult slot for elaboration agent
    # live-app dynamic-validation harness, lazily created by the launch_app
    # tool and reused by http_request / read_app_log within one exploit session.
    app_harness: object | None = None  # acuario.sandbox.app_harness.AppHarness
    # fail-fast: count failed launch_app attempts within one exploit session
    # so the agent pivots to a static PoC instead of retrying into the per-session
    # wait_for backstop (an observed 9-retry / ~1h-idle failure mode).
    launch_failures: int = 0
    max_launch_failures: int = 2
    # compose harness: when the exploit target is a host-orchestrated
    # docker-compose app, the runner seeds these so the agent probes services by
    # DNS over the shared internal network instead of launching a process on
    # 127.0.0.1. `compose` is a ComposeBringUp (typed as object to avoid a
    # circular import); empty entry_base_url means "not a compose target".
    compose: object | None = None  # acuario.sandbox.compose.ComposeBringUp
    entry_base_url: str = ""  # resolved front door, e.g. http://bff:4000
    service_urls: dict = field(default_factory=dict)  # {service_name: base_url}
    # cross-file context pre-seed.  Built by the pool dispatcher and
    # injected into the analyzer prompt as a "Known cross-file context" block.
    # Empty string means the pool didn't compute it (e.g., no callgraph).
    cross_file_context: str = ""

    def get_sandbox_for_variant(
        self,
        sanitizer_variant: list[str] | None = None,
    ) -> SandboxContainer | None:
        """Return the SandboxContainer for the requested sanitizer variant.

        - variant=None or matches default → returns self.sandbox (fast path)
        - different variant → spawns from self.sandbox_manager and caches
        - no manager → returns self.sandbox (degraded: the variant is ignored)
        """
        if sanitizer_variant is None:
            return self.sandbox
        chosen = list(sanitizer_variant)
        # If the default variant is requested, reuse the primary sandbox
        if sorted(chosen) == sorted(self.default_sanitizers):
            return self.sandbox
        key = "+".join(sorted(chosen))
        cached = self.variant_sandboxes.get(key)
        if cached is not None:
            return cast(SandboxContainer, cached)
        # Need to spawn a new variant container
        if self.sandbox_manager is None:
            # No manager - degrade to the primary sandbox
            logger.debug(
                "variant=%s requested but no sandbox_manager; using primary",
                chosen,
            )
            return self.sandbox
        try:
            sb = self.sandbox_manager.spawn(  # type: ignore[attr-defined]
                session_id=self.session_id,
                variant=chosen,
            )
        except Exception:
            logger.warning("Failed to spawn variant sandbox %s", chosen, exc_info=True)
            return self.sandbox
        self.variant_sandboxes[key] = sb
        return cast(SandboxContainer, sb)

    def cleanup_variants(self) -> None:
        """Stop every cached variant container. Call when the analyzer finishes."""
        for sb in self.variant_sandboxes.values():
            try:
                sb.stop()
            except Exception:
                logger.debug("cleanup_variants stop failed", exc_info=True)
        self.variant_sandboxes.clear()


def _parse_variant_arg(sanitizer_variant: str) -> list[str] | None:
    """Translate the `sanitizer_variant` tool arg into a sanitizer list.

    Accepts:
        "" or None     → None (use the primary default sandbox)
        "msan"          → ["msan"]
        "asan,ubsan"    → ["asan", "ubsan"]
        "asan+ubsan"    → ["asan", "ubsan"]
    """
    if not sanitizer_variant:
        return None
    parts = [p.strip().lower() for p in sanitizer_variant.replace("+", ",").split(",") if p.strip()]
    return parts or None
