"""Live-app dynamic validation harness.

The static analyzer reads code; the exploit-dev agent has historically reasoned
about exploitability from source plus compiled C PoCs. But most real targets -
and most of Acuario's corpora - are *web apps*, where the strongest possible
evidence that a bug is real is an HTTP request against a **running instance**
that demonstrably misbehaves (a SQLi that dumps a row, an auth bypass that
returns 200 on a protected route, a reflected XSS echoed verbatim).

``AppHarness`` launches the target application *inside the existing sandbox
container* and lets the agent probe it over the container's own loopback
interface. This keeps ``network_mode="none"`` intact - a ``--network none``
container still has a working ``lo``, so a process started by ``docker exec``
can reach ``127.0.0.1:<port>`` of a server started by another ``docker exec`` in
the same container, with zero outside connectivity.

Design:
- The server is launched **detached** (``setsid ... &``) with stdout/stderr to
  a log under ``/scratch`` so the launching exec returns immediately and the
  server survives the exec session (reparented to the container init).
- Health is polled *inside* a single ``sh -c`` loop so the host event loop
  never blocks and the exec timeout bounds the wait.
- HTTP probes shell out to ``curl -i`` inside the container; the response
  (status line, headers, body) is parsed back into a ``HttpResult``.

This is duck-typed on the sandbox: anything exposing ``exec(command, timeout=)``
returning an object with ``exit_code`` / ``stdout`` / ``stderr`` works, so the
harness is unit-testable without a real Docker daemon.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Bounded so a chatty endpoint can't blow up the transcript / agent context.
_MAX_BODY_CHARS = 16_000
_DEFAULT_PORT = 8000


@dataclass
class LaunchRecipe:
    """How to start a target app inside the sandbox."""

    kind: str  # "php" | "django" | "flask" | "fastapi" | "node" | "custom"
    command: str  # the server command (cd is added by the harness)
    port: int = _DEFAULT_PORT
    workdir: str = "/workspace"
    note: str = ""


@dataclass
class HttpResult:
    """Parsed result of an in-sandbox HTTP probe."""

    ok: bool
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    raw: str = ""

    def summary(self) -> str:
        if not self.ok:
            return f"request failed: {self.error}"
        head = f"HTTP {self.status_code}"
        ct = self.headers.get("content-type", "")
        if ct:
            head += f" ({ct})"
        return f"{head}\n{self.body[:2000]}"


class AppHarness:
    """Launch a web-app target in the sandbox and probe it over loopback."""

    def __init__(
        self,
        sandbox: Any,
        *,
        workdir: str = "/workspace",
        scratch: str = "/scratch",
        base_url: str | None = None,
    ) -> None:
        self._sb = sandbox
        self._workdir = workdir
        self._scratch = scratch
        self._log_path = f"{scratch}/app_harness.log"
        self._pid: str | None = None
        self._port: int | None = None
        self._recipe: LaunchRecipe | None = None
        # Compose mode: when set, the app is already running as a host-orchestrated
        # multi-service stack reachable over the shared internal network by service
        # DNS (e.g. http://bff:4000). launch() then only probes readiness, and
        # request() targets this base URL instead of the container's own loopback.
        self._base_url: str | None = base_url

    # --- detection ----------------------------------------------------------

    def detect_launch(self, port: int = _DEFAULT_PORT) -> LaunchRecipe | None:
        """Heuristically pick a launch recipe from files in the workspace.

        Priority favors the unambiguous framework entry points. Returns None
        when nothing recognizable is found - the agent can still launch
        explicitly via the ``launch_app`` tool with an exact command.
        """
        exists = self._file_exists

        # Django - the most unambiguous signal.
        if exists("manage.py"):
            return LaunchRecipe(
                kind="django",
                command=f"python manage.py runserver 127.0.0.1:{port} --noreload",
                port=port,
                note="Django manage.py runserver",
            )

        # PHP - built-in dev server. Prefer a public/ docroot when present.
        if exists("public/index.php"):
            return LaunchRecipe(
                kind="php",
                command=f"php -S 127.0.0.1:{port} -t public",
                port=port,
                note="php -S with public/ docroot",
            )
        if exists("index.php") or exists("composer.json"):
            return LaunchRecipe(
                kind="php",
                command=f"php -S 127.0.0.1:{port}",
                port=port,
                note="php -S at repo root",
            )

        # FastAPI / uvicorn - try the common module:attr names.
        for mod in ("main", "app", "server"):
            if exists(f"{mod}.py") and self._file_contains(f"{mod}.py", "FastAPI"):
                return LaunchRecipe(
                    kind="fastapi",
                    command=f"uvicorn {mod}:app --host 127.0.0.1 --port {port}",
                    port=port,
                    note=f"uvicorn {mod}:app",
                )

        # Flask - app.py / wsgi.py.
        for mod in ("app", "wsgi", "application"):
            if exists(f"{mod}.py") and self._file_contains(f"{mod}.py", "Flask"):
                return LaunchRecipe(
                    kind="flask",
                    command=(f"FLASK_APP={mod} flask run --host 127.0.0.1 --port {port}"),
                    port=port,
                    note=f"flask run ({mod})",
                )

        # Node - a server entry point.
        for entry in ("server.js", "index.js", "app.js"):
            if exists(entry):
                return LaunchRecipe(
                    kind="node",
                    command=f"node {entry}",
                    port=port,
                    note=f"node {entry}",
                )

        return None

    def detect_app_class(self) -> str:
        """Classify the target: 'server' (a launch recipe exists), 'spa'
        (a client-side build with no server), or 'unknown'.

        Conservative on purpose. Only 'spa' when there is a package.json
        with a build step AND a SPA framework AND NO server recipe AND NO
        server-side dependency - so a real server app is never mislabeled and
        denied its live-launch evidence. A SPA has nothing to launch and no
        offline browser runtime (no jsdom under network_mode=none), so the
        exploiter should build a static PoC rather than attempt a doomed launch.
        """
        if self.detect_launch() is not None:
            return "server"
        if not self._file_exists("package.json"):
            return "unknown"
        has_build = self._file_contains("package.json", '"build"')
        has_spa = any(
            self._file_contains("package.json", fw)
            for fw in ("react", "vue", "@angular", "svelte", "preact", "vite", "solid-js")
        )
        has_server = any(
            self._file_contains("package.json", dep)
            for dep in ("express", "koa", "fastify", "@hapi", "next", "nuxt", "@nestjs", "restify")
        )
        if has_build and has_spa and not has_server:
            return "spa"
        return "unknown"

    # --- lifecycle ----------------------------------------------------------

    def launch(self, recipe: LaunchRecipe | None = None, *, timeout: int = 40) -> bool:
        """Background-launch the app and wait until it answers on its port.

        Returns True when the server responds to an HTTP probe (any status
        code counts as "up"), False otherwise. Idempotent-ish: a second call
        relaunches (the caller should ``stop()`` first if changing recipes).
        """
        # Compose / base_url mode: the stack is already up on the internal
        # network; "launch" is just a bounded readiness probe against the entry
        # URL (no process is started inside this container).
        if self._base_url:
            return self._probe_ready(self._base_url, timeout)
        recipe = recipe or self.detect_launch()
        if recipe is None:
            logger.info("[harness] no launch recipe detected; app not started")
            return False
        # Stop any previously-launched server before relaunching. Without this a
        # second launch() overwrites self._pid and orphans the prior process,
        # which keeps holding the port so the retry's readiness probe fails too
        # (the prior retry loop left one server process per attempt).
        if self._pid:
            self.stop()
        self._recipe = recipe
        self._port = recipe.port

        # Detached launch: setsid makes the server a session/group leader so
        # it survives the exec session and can be killed as a group later.
        # < /dev/null prevents it from blocking on stdin.
        launch_cmd = (
            f"cd {shlex.quote(recipe.workdir or self._workdir)} && "
            f"setsid {recipe.command} > {shlex.quote(self._log_path)} 2>&1 < /dev/null & "
            f"echo $!"
        )
        res = self._sb.exec(["sh", "-c", launch_cmd], timeout=15)
        pid = (getattr(res, "stdout", "") or "").strip().splitlines()
        self._pid = pid[-1].strip() if pid else None
        logger.info(
            "[harness] launching %s on 127.0.0.1:%d (pid=%s)",
            recipe.kind,
            recipe.port,
            self._pid or "?",
        )

        # Poll for readiness entirely inside one exec so the host loop never
        # blocks; the exec timeout is the hard ceiling.
        attempts = max(1, timeout * 2)  # ~0.5s cadence
        probe = (
            f"for i in $(seq 1 {attempts}); do "
            f'code=$(curl -s -o /dev/null -w "%{{http_code}}" '
            f"http://127.0.0.1:{recipe.port}/ 2>/dev/null); "
            f'if [ -n "$code" ] && [ "$code" != "000" ]; then echo "UP:$code"; exit 0; fi; '
            f"sleep 0.5; done; echo DOWN; exit 1"
        )
        hc = self._sb.exec(["sh", "-c", probe], timeout=timeout + 5)
        out = (getattr(hc, "stdout", "") or "").strip()
        up = out.startswith("UP:")
        if up:
            logger.info("[harness] %s ready (%s)", recipe.kind, out)
        else:
            logger.warning(
                "[harness] %s did not come up on port %d; see %s",
                recipe.kind,
                recipe.port,
                self._log_path,
            )
        return up

    def request(
        self,
        path: str = "/",
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int = 20,
    ) -> HttpResult:
        """Probe the running app over loopback and return a parsed response."""
        if self._base_url:
            base = self._base_url.rstrip("/")
        elif self._port is not None:
            base = f"http://127.0.0.1:{self._port}"
        else:
            return HttpResult(ok=False, status_code=None, error="app not launched")

        if not path.startswith("/"):
            path = "/" + path
        url = f"{base}{path}"
        argv = ["curl", "-s", "-i", "-m", str(timeout), "-X", method.upper()]
        for k, v in (headers or {}).items():
            argv += ["-H", f"{k}: {v}"]
        if body is not None:
            argv += ["--data-binary", body]
        argv.append(url)

        res = self._sb.exec(argv, timeout=timeout + 5)
        if getattr(res, "exit_code", -1) != 0 and not getattr(res, "stdout", ""):
            return HttpResult(
                ok=False,
                status_code=None,
                error=(getattr(res, "stderr", "") or "curl failed").strip()[:500],
            )
        return self._parse_curl_i(getattr(res, "stdout", "") or "")

    def read_log(self, tail: int = 200) -> str:
        """Return the last ``tail`` lines of the app's stdout/stderr log."""
        res = self._sb.exec(
            ["sh", "-c", f"tail -n {int(tail)} {shlex.quote(self._log_path)} 2>/dev/null || true"],
            timeout=15,
        )
        return (getattr(res, "stdout", "") or "").rstrip()

    def _probe_ready(self, base_url: str, timeout: int = 40) -> bool:
        """Bounded readiness probe against an already-running service (base_url mode).

        Polls the entry URL from INSIDE the sandbox until it answers or the
        timeout elapses; any HTTP status counts as "up". The --internal compose
        network is unreachable from the host, so this probe must run in-sandbox.
        """
        attempts = max(1, timeout * 2)  # ~0.5s cadence
        url = base_url.rstrip("/") + "/"
        probe = (
            f"for i in $(seq 1 {attempts}); do "
            f'code=$(curl -s -o /dev/null -w "%{{http_code}}" {shlex.quote(url)} 2>/dev/null); '
            f'if [ -n "$code" ] && [ "$code" != "000" ]; then echo "UP:$code"; exit 0; fi; '
            f"sleep 0.5; done; echo DOWN; exit 1"
        )
        hc = self._sb.exec(["sh", "-c", probe], timeout=timeout + 5)
        out = (getattr(hc, "stdout", "") or "").strip()
        up = out.startswith("UP:")
        if up:
            logger.info("[harness] compose target ready at %s (%s)", base_url, out)
        else:
            logger.warning("[harness] compose target did not answer at %s", base_url)
        return up

    def stop(self) -> None:
        """Best-effort teardown: kill the server's process group."""
        if not self._pid:
            return
        try:
            # Negative PID targets the process group (setsid made pid==pgid).
            # SIGTERM first, then a SIGKILL fallback after a short grace period:
            # a server that ignores SIGTERM would otherwise keep holding the
            # port, and when this container is reused from the warm pool the
            # next file's launch_app would fail with the port still bound.
            pid = self._pid
            self._sb.exec(
                [
                    "sh",
                    "-c",
                    f"kill -TERM -{pid} 2>/dev/null; kill -TERM {pid} 2>/dev/null; "
                    f"sleep 0.5; "
                    f"kill -KILL -{pid} 2>/dev/null; kill -KILL {pid} 2>/dev/null; true",
                ],
                timeout=10,
            )
        except Exception:
            logger.debug("[harness] stop() failed", exc_info=True)
        finally:
            self._pid = None
            self._port = None

    # --- internals ----------------------------------------------------------

    def _file_exists(self, rel: str) -> bool:
        path = f"{self._workdir}/{rel}"
        try:
            res = self._sb.exec(["test", "-e", path], timeout=10)
            return getattr(res, "exit_code", 1) == 0
        except Exception:
            return False

    def _file_contains(self, rel: str, needle: str) -> bool:
        path = f"{self._workdir}/{rel}"
        try:
            res = self._sb.exec(
                ["sh", "-c", f"grep -ql {shlex.quote(needle)} {shlex.quote(path)}"],
                timeout=10,
            )
            return getattr(res, "exit_code", 1) == 0
        except Exception:
            return False

    @staticmethod
    def _parse_curl_i(raw: str) -> HttpResult:
        """Parse ``curl -i`` output (status line + headers + blank + body).

        Handles multiple header blocks (redirect chains / 100-continue) by
        keeping the LAST status line and its headers, which is what the client
        actually received.
        """
        if not raw:
            return HttpResult(ok=False, status_code=None, error="empty response")

        # Split header blocks from body. curl -i emits CRLF line endings.
        normalized = raw.replace("\r\n", "\n")
        # The header/body boundary is the first blank line AFTER the last
        # status line. Find all status-line positions.
        status_positions = [m.start() for m in re.finditer(r"(?m)^HTTP/\d\.\d \d{3}", normalized)]
        if not status_positions:
            # No recognizable status line - treat the whole thing as body.
            return HttpResult(
                ok=True,
                status_code=None,
                body=normalized[:_MAX_BODY_CHARS],
                raw=raw[:_MAX_BODY_CHARS],
            )

        last_block = normalized[status_positions[-1] :]
        head, _, body = last_block.partition("\n\n")
        lines = head.split("\n")
        status_line = lines[0]
        m = re.match(r"HTTP/\d\.\d (\d{3})", status_line)
        status_code = int(m.group(1)) if m else None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return HttpResult(
            ok=True,
            status_code=status_code,
            headers=headers,
            body=body[:_MAX_BODY_CHARS],
            raw=raw[:_MAX_BODY_CHARS],
        )
