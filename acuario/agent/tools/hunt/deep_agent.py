"""Deep agent mode tools: execute, read_file, write_file.

Replaces the constrained 9-tool analyzer set with 3 primitives that give
the model full-shell access inside the sandbox container. The model
uses the same tools a human researcher would - gcc, gdb, strace, make,
etc. - all via ``execute()``.

Model-side reasoning is captured natively via rust-genai's
`capture_reasoning_content=True` on every chat request; the analyzer
transcript logs `ChatResponse.reasoning_content` alongside the
visible text, so there's no explicit `think()` scratchpad tool -
native reasoning is strictly richer than a model-callable no-op.
"""

from __future__ import annotations

import logging
import shlex

from acuario.llm import NativeToolSpec

from .pool_query import build_pool_query_tools
from .reporting import build_reporting_tools
from .sandbox import HunterContext

logger = logging.getLogger(__name__)

_OUTPUT_CAP = 100_000  # 100 KB cap on stdout/stderr per execute call


def _cap_output(text: str, label: str = "output") -> str:
    if len(text) <= _OUTPUT_CAP:
        return text
    return text[:_OUTPUT_CAP] + f"\n\n[{label} truncated at {_OUTPUT_CAP} bytes]"


def build_deep_agent_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Build the deep agent tool set: execute, read_file, write_file,
    plus the shared reporting + findings-pool tools.
    """

    def execute(command: str = "", timeout: int = 300, **_: object) -> dict:
        # Soft-fail when the LLM forgets arguments.  Smaller models
        # like qwen3.6-coder occasionally call ``execute()`` with empty
        # kwargs.  Returning a string error lets the agent self-correct
        # on the next step; raising TypeError aborts the whole analyzer
        # turn and the file gets dropped.
        if not command:
            return {"error": "execute requires a 'command' argument (non-empty string)"}
        if ctx.sandbox is None:
            return {"error": "no sandbox available"}
        # Coerce timeout to int - the LLM occasionally passes "300" instead.
        try:
            timeout = int(timeout) if not isinstance(timeout, int) else timeout
        except (TypeError, ValueError):
            timeout = 300
        result = ctx.sandbox.exec(str(command), timeout=timeout)
        return {
            "exit_code": result.exit_code,
            "stdout": _cap_output(result.stdout, "stdout"),
            "stderr": _cap_output(result.stderr, "stderr"),
            "timed_out": result.timed_out,
            "duration_seconds": round(result.duration_seconds, 2),
        }

    def read_file(
        path: str = "",
        offset: int = 0,
        limit: int = 2000,
        **_: object,
    ) -> str:
        # Soft-fail + coerce numeric args from strings.  The LLM
        # sometimes passes offset/limit as strings, which raised
        # "'<' not supported between instances of 'str' and 'int'".
        # Coerce defensively so the file is still read.
        if not path:
            return "error: read_file requires a 'path' argument"
        try:
            offset = int(offset) if not isinstance(offset, int) else offset
        except (TypeError, ValueError):
            offset = 0
        try:
            limit = int(limit) if not isinstance(limit, int) else limit
        except (TypeError, ValueError):
            limit = 2000
        if ctx.sandbox is None:
            return "error: no sandbox available"
        start = offset + 1
        end = offset + limit
        # A plain `sed ... | cat -n` numbers output starting from 1
        # regardless of offset - a analyzer asking for lines 101-150
        # would get back "line 1..line 50" and then reason about the
        # wrong line numbers when reporting findings. Use awk with NR
        # directly so the emitted line numbers match the file.
        cmd = (
            f"awk -v s={start} -v e={end} "
            f"'NR>=s && NR<=e {{ printf \"%6d\\t%s\\n\", NR, $0 }}' "
            f"{shlex.quote(path)}"
        )
        result = ctx.sandbox.exec(cmd, timeout=30)
        if result.exit_code != 0:
            return f"error reading {path}: {result.stderr.strip()}"
        return result.stdout

    def write_file(path: str = "", contents: str = "", **_: object) -> str:
        # Soft-fail when the LLM forgets arguments. Smaller models like
        # qwen3.6 occasionally call `write_file()` with empty kwargs;
        # raising TypeError aborts the analyzer's whole turn. We'd
        # rather return an error string so the agent can self-correct.
        if not path:
            return "error: write_file requires a 'path' argument"
        if ctx.sandbox is None:
            return "error: no sandbox available"
        ctx.sandbox.exec(f"mkdir -p $(dirname {shlex.quote(path)})", timeout=10)
        ctx.sandbox.write_file(path, contents.encode("utf-8"))
        return f"Wrote {len(contents)} bytes to {path}"

    reporting_tools = build_reporting_tools(ctx)

    return [
        NativeToolSpec(
            name="execute",
            description=(
                "Run a shell command inside the sandbox container. "
                "Use for compilation, debugging, running tests, etc."
            ),
            schema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 300).",
                        "default": 300,
                    },
                },
                "required": ["command"],
            },
            handler=execute,
        ),
        NativeToolSpec(
            name="read_file",
            description="Read lines from a file in the container.",
            schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path in the container.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Line offset (0-based, default 0).",
                        "default": 0,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max lines to return (default 2000).",
                        "default": 2000,
                    },
                },
                "required": ["path"],
            },
            handler=read_file,
        ),
        NativeToolSpec(
            name="write_file",
            description="Write contents to a file in the container. Creates parent directories.",
            schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path in the container.",
                    },
                    "contents": {
                        "default": "",
                        "type": "string",
                        "description": "File contents to write.",
                    },
                },
                "required": ["path"],
            },
            handler=write_file,
        ),
        *reporting_tools,
        *(build_pool_query_tools(ctx) if ctx.findings_pool is not None else []),
    ]
