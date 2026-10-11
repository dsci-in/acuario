"""Sandbox primitives for scanner and other source-code-aware agent flows.

Distinct from acuario/agent/tools/kali_docker_tool.py - that tool is
attack-focused (approval gates, apt-get install, network access). The sandbox
primitives here are isolation-focused: no network, read-only mounts, resource
limits, and sanitizer-instrumented build images.
"""

from .analyzer_sandbox import AnalyzerSandbox
from .builders import BuildRecipe, BuildSystemDetector
from .container import ExecResult, SandboxConfig, SandboxContainer
from .registry import ContainerRegistry

__all__ = [
    "ContainerRegistry",
    "ExecResult",
    "SandboxConfig",
    "SandboxContainer",
    "BuildRecipe",
    "BuildSystemDetector",
    "AnalyzerSandbox",
]
