"""Host-orchestrated docker-compose harness for the live exploit stage.

The single-process ``AppHarness`` launches one server inside the exploit sandbox
over loopback. That cannot stand up a real multi-service app (e.g. a
mysql + python api + node bff + nginx web): the sibling services are never
started, and under ``network_mode=none`` they are unreachable anyway. This
module brings the app's OWN docker-compose stack up on the HOST, on a per-target
internal-only network (no internet or host egress), and lets the exploit sandbox
join that network so the exploit agent can probe services by their compose DNS
names (``http://bff:4000`` and so on).

Everything here runs host-side against the host ``docker`` / ``docker compose``
CLI (the sandbox has no docker socket, and cannot run compose itself). Every
subprocess call is time-bounded so a stuck bring-up fails fast to the static-PoC
path instead of idling the agent's per-session backstop. The subprocess runner
is injectable, so the pure logic - detection, spec parsing, entry resolution,
the transformed compose file, and command construction - is unit-testable
without a Docker daemon.

Isolation: the per-target network is created with ``--internal`` (no gateway /
no NAT), so both the app services and the joined exploit sandbox have zero route
to the internet or the host, while Docker's embedded DNS still resolves service
names on the user-defined network. Build and image pull happen daemon-side
(before the internal-only runtime), so build-time egress does not weaken the
runtime isolation.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Compose files at the repo root, in the priority docker/Compose itself uses.
_COMPOSE_FILENAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)

# Container ports that read as a web front door, best first.
_WEB_PORTS = (80, 8080, 3000, 8000, 4000, 5000, 8888)

# A subprocess runner returns (returncode, stdout, stderr). Injectable for tests.
Runner = Callable[[list, int], "tuple[int, str, str]"]


def _default_runner(argv: list, timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", f"timed out after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


# --- detection --------------------------------------------------------------


def detect_compose(repo_path: str) -> ComposeSpec | None:
    """Return a ComposeSpec if a compose file sits at the repo root, else None."""
    for name in _COMPOSE_FILENAMES:
        path = os.path.join(repo_path, name)
        if os.path.isfile(path):
            try:
                return ComposeSpec.from_file(path)
            except Exception:
                logger.debug("[compose] failed to parse %s", path, exc_info=True)
                return None
    return None


def resolve_compose_cli(runner: Runner | None = None) -> list | None:
    """Return the compose CLI invocation prefix, or None if none is available.

    Prefers Compose v2 (``docker compose``); falls back to v1
    (``docker-compose``). Both are probed with a bounded ``version`` call.
    """
    run = runner or _default_runner
    try:
        rc, _out, _err = run(["docker", "compose", "version"], 10)
        if rc == 0:
            return ["docker", "compose"]
    except Exception:
        logger.debug("[compose] `docker compose version` probe failed", exc_info=True)
    try:
        rc, _out, _err = run(["docker-compose", "version"], 10)
        if rc == 0:
            return ["docker-compose"]
    except Exception:
        logger.debug("[compose] `docker-compose version` probe failed", exc_info=True)
    return None


# --- spec -------------------------------------------------------------------


@dataclass
class ServiceSpec:
    """A single compose service, reduced to what the harness needs."""

    name: str
    build_context: str = ""  # repo-relative dir of `build:`, "" for image-only
    image: str = ""
    container_ports: list = field(default_factory=list)  # ints, container side
    expose: list = field(default_factory=list)  # ints
    has_build: bool = False

    def primary_port(self) -> int | None:
        for p in self.container_ports:
            return p
        for p in self.expose:
            return p
        return None


@dataclass
class ComposeSpec:
    """Parsed docker-compose file, reduced to what the harness needs."""

    file_path: str
    services: dict = field(default_factory=dict)  # name -> ServiceSpec
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str) -> ComposeSpec:
        import yaml

        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        services: dict = {}
        for name, sdef in (raw.get("services") or {}).items():
            sdef = sdef or {}
            build = sdef.get("build")
            build_context = ""
            has_build = False
            if isinstance(build, str):
                build_context = _norm_context(build)
                has_build = True
            elif isinstance(build, dict):
                build_context = _norm_context(str(build.get("context", "")))
                has_build = True
            container_ports = []
            for entry in sdef.get("ports", []) or []:
                cp = _container_port(entry)
                if cp is not None:
                    container_ports.append(cp)
            expose = []
            for entry in sdef.get("expose", []) or []:
                cp = _container_port(entry)
                if cp is not None:
                    expose.append(cp)
            services[name] = ServiceSpec(
                name=name,
                build_context=build_context,
                image=str(sdef.get("image", "") or ""),
                container_ports=container_ports,
                expose=expose,
                has_build=has_build,
            )
        return cls(file_path=path, services=services, raw=raw)

    def resolve_entry(self, finding_file: str) -> str:
        """Best base_url (``http://<service>:<port>``) for a finding's file.

        Finding-first: the service whose ``build.context`` (or its own name) is a
        path prefix of the finding's file. Falls back to a web-port front door.
        Returns "" when no service has a usable http port.
        """
        ff = _norm_context(finding_file or "")
        if ff:
            best: ServiceSpec | None = None
            best_len = -1
            for svc in self.services.values():
                ctx = svc.build_context or svc.name
                if ctx and (ff == ctx or ff.startswith(ctx + "/")):
                    if len(ctx) > best_len:
                        best, best_len = svc, len(ctx)
            if best is not None:
                port = best.primary_port()
                if port is not None:
                    return f"http://{best.name}:{port}"
        # Fallback: the front-door service (a well-known web port).
        front = self._front_door()
        if front is not None:
            port = front.primary_port()
            if port is not None:
                return f"http://{front.name}:{port}"
        return ""

    def _front_door(self) -> ServiceSpec | None:
        for wp in _WEB_PORTS:
            for svc in self.services.values():
                if wp in svc.container_ports or wp in svc.expose:
                    return svc
        # else the first service that exposes any port
        for svc in self.services.values():
            if svc.primary_port() is not None:
                return svc
        return None

    def service_urls(self) -> dict:
        """{service_name: http base_url} for every service with a usable port."""
        out: dict = {}
        for name, svc in self.services.items():
            port = svc.primary_port()
            if port is not None:
                out[name] = f"http://{name}:{port}"
        return out


def _norm_context(value: str) -> str:
    """Normalize a build context / file path to a clean repo-relative dir path."""
    v = (value or "").strip().strip("/")
    if v.startswith("./"):
        v = v[2:]
    return v.strip("/")


def _container_port(entry: Any) -> int | None:
    """Extract the CONTAINER-side port from a compose ``ports``/``expose`` entry.

    Handles ``"4000"``, ``"3000:80"``, ``"127.0.0.1:4000:4000"``, ``"8000/tcp"``,
    ``"4000-4005:4000-4005"`` (first of range), and the long dict form
    ``{target: 80, published: 3000}``.
    """
    if isinstance(entry, dict):
        target = entry.get("target")
        try:
            return int(target)
        except (TypeError, ValueError):
            return None
    s = str(entry).split("/")[0]  # drop /tcp|/udp
    parts = s.split(":")
    cand = parts[-1]  # container side is always last
    cand = cand.split("-")[0]  # first port of a range
    try:
        return int(cand)
    except ValueError:
        return None


# --- orchestration ----------------------------------------------------------


@dataclass
class ComposeBringUp:
    """Result of an up() attempt (also used as launch_app's readiness signal)."""

    ok: bool
    network_name: str = ""
    project: str = ""
    service_urls: dict = field(default_factory=dict)
    entry_default: str = ""
    reason: str = ""


class ComposeOrchestrator:
    """Host-side lifecycle for a compose app on a per-target internal network.

    Usage (once per target, wrapping the eligible-findings loop):

        with ComposeOrchestrator(spec, repo_path, cli, session_id=sid) as orch:
            for finding in eligible:
                orch.reset()                 # clean state per finding
                ... exploit sandbox joins orch.network_name ...

    ``up()`` (via ``__enter__``) creates the internal network, builds and pulls
    images (daemon-side egress), and starts the stack on the internal network.
    ``reset()`` recreates the container stack for clean state. ``down()`` (via
    ``__exit__``) tears the stack down and removes the network. Every step is
    bounded so nothing can idle the agent's per-session backstop.
    """

    def __init__(
        self,
        spec: ComposeSpec,
        repo_path: str,
        cli: list,
        *,
        session_id: str | None = None,
        runner: Runner | None = None,
        build_timeout: int = 1800,
        up_timeout: int = 600,
        down_timeout: int = 120,
        network_internal: bool = True,
    ) -> None:
        self.spec = spec
        self.repo_path = os.path.abspath(repo_path)
        self.cli = list(cli)
        self._run = runner or _default_runner
        self._build_timeout = build_timeout
        self._up_timeout = up_timeout
        self._down_timeout = down_timeout
        self._network_internal = network_internal
        # Env forced for the build subprocess: disable Bake so the build does not
        # require the `docker buildx` CLI plugin (see _build_argv).
        self._build_env = {"COMPOSE_BAKE": "false"}
        token = (session_id or uuid.uuid4().hex)[:12]
        self.uid = token
        self.project = f"acuario-exploit-{token}"
        self.network_name = f"acuario-exploit-net-{token}"
        self._resolved_file: str | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self.service_urls: dict = spec.service_urls()
        self._bringup = ComposeBringUp(ok=False, reason="not started")

    # -- properties consumed by exploit_tools / exploit_dev ------------------

    @property
    def ok(self) -> bool:
        return self._bringup.ok

    @property
    def reason(self) -> str:
        return self._bringup.reason

    @property
    def entry_default(self) -> str:
        return self._bringup.entry_default

    def resolve_entry(self, finding_file: str) -> str:
        return self.spec.resolve_entry(finding_file) or self._bringup.entry_default

    # -- lifecycle -----------------------------------------------------------

    def _compose_argv(self, *args: str) -> list:
        base = list(self.cli) + ["-p", self.project]
        if self._resolved_file:
            base += ["-f", self._resolved_file]
        return base + list(args)

    def _write_resolved_file(self) -> str:
        """Write a single self-contained compose file pinned to the internal net.

        The stack is brought up from ONLY this file (no `-f` merge), so there is
        no list-concatenation surprise: every service is pinned to the internal
        network and its host ``ports`` are stripped (nothing re-exposes on host
        loopback, and no egress-capable ``<project>_default`` network is created).
        All other fields (build, environment, volumes, depends_on, healthcheck,
        command) pass through unchanged.
        """
        import copy

        import yaml

        doc = copy.deepcopy(self.spec.raw) or {}
        doc.setdefault("services", {})
        for _name, sdef in doc["services"].items():
            if not isinstance(sdef, dict):
                continue
            sdef.pop("ports", None)  # no host publishing
            sdef["networks"] = [self.network_name]
            # This file is written to a temp dir, but docker/compose resolves
            # relative host-side paths (build context, bind-mount sources,
            # env_file) against the COMPOSE FILE'S directory. Left relative they
            # would point into the temp dir and fail ("unable to prepare context:
            # path .../api not found"). Rewrite them absolute against repo_path.
            self._absolutize_paths(sdef)
        # Externalize the network we create ourselves; drop any project-defined
        # networks so services land only on the internal net.
        doc["networks"] = {self.network_name: {"external": True}}
        self._tmpdir = tempfile.TemporaryDirectory(prefix="acuario-compose-")
        path = os.path.join(self._tmpdir.name, "acuario-resolved.yml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False)
        self._resolved_file = path
        return path

    def _absolutize_paths(self, sdef: dict) -> None:
        """Rewrite a service's relative host-side paths absolute against repo_path.

        The resolved compose file is written to a temp dir, so build contexts,
        bind-mount sources and env_file entries that were relative to the repo
        root must be made absolute or compose resolves them against the temp dir.
        Named volumes (a bare token, no path separator) are left untouched.
        """
        repo = self.repo_path
        build = sdef.get("build")
        if isinstance(build, str):
            sdef["build"] = _abs(repo, build)
        elif isinstance(build, dict):
            ctx = build.get("context")
            if isinstance(ctx, str) and ctx:
                build["context"] = _abs(repo, ctx)
        vols = sdef.get("volumes")
        if isinstance(vols, list):
            sdef["volumes"] = [_abs_volume(repo, v) for v in vols]
        ef = sdef.get("env_file")
        if isinstance(ef, str):
            sdef["env_file"] = _abs(repo, ef)
        elif isinstance(ef, list):
            sdef["env_file"] = [_abs(repo, e) if isinstance(e, str) else e for e in ef]

    def _build_argv(self) -> list:
        """Compose ``build`` argv, prefixed with the env that disables Bake.

        Compose v2 defaults to building via Bake, which needs the ``docker
        buildx`` CLI plugin; hosts without buildx fail ("Docker Compose is
        configured to build using Bake, but buildx isn't installed"). Forcing
        ``COMPOSE_BAKE=false`` uses compose's classic daemon-side build, which
        does not require the buildx plugin. Egress during build is intentional.
        """
        env_prefix = ["env"] + [f"{k}={v}" for k, v in self._build_env.items()]
        return env_prefix + self._compose_argv("build")

    def _fail(self, reason: str) -> ComposeBringUp:
        logger.warning("[compose] bring-up failed: %s", reason)
        self._bringup = ComposeBringUp(
            ok=False, network_name=self.network_name, project=self.project, reason=reason
        )
        return self._bringup

    def up(self) -> ComposeBringUp:
        """Create the internal network, build/pull, and start the stack."""
        # 1. internal network (idempotent-ish: tolerate "already exists").
        net_argv = ["docker", "network", "create"]
        if self._network_internal:
            net_argv.append("--internal")
        net_argv += [
            "--label",
            "com.acuario.kind=exploit-compose",
            "--label",
            f"com.acuario.session={self.uid}",
            self.network_name,
        ]
        rc, _out, err = self._run(net_argv, 60)
        if rc != 0 and "already exists" not in (err or "").lower():
            return self._fail(f"network create failed: {err.strip()[:300]}")

        # 2. self-contained resolved compose file pinned to the internal net.
        try:
            self._write_resolved_file()
        except Exception as exc:  # pragma: no cover - defensive
            return self._fail(f"could not write resolved compose file: {exc}")

        # 3. build (daemon-side egress) then start offline on the internal net.
        rc, _out, err = self._run(self._build_argv(), self._build_timeout)
        if rc != 0:
            self.down()
            return self._fail(f"compose build failed: {_tail(err)}")
        rc, _out, err = self._run(
            self._compose_argv("up", "-d", "--no-build", "--wait"), self._up_timeout
        )
        if rc != 0:
            self.down()
            return self._fail(f"compose up failed: {_tail(err)}")

        entry = self.spec.resolve_entry("")  # generic front door
        self._bringup = ComposeBringUp(
            ok=True,
            network_name=self.network_name,
            project=self.project,
            service_urls=dict(self.service_urls),
            entry_default=entry,
            reason="",
        )
        logger.info(
            "[compose] stack up on %s (project=%s, services=%s)",
            self.network_name,
            self.project,
            ",".join(self.service_urls) or "?",
        )
        return self._bringup

    def reset(self) -> bool:
        """Recreate the container stack for clean state (restart per finding).

        Drops named volumes so init scripts (schema/seed) re-run, then starts
        again on the same internal network. Best-effort: returns False on error.
        """
        if not self._resolved_file:
            return False
        rc, _o, err = self._run(
            self._compose_argv("down", "-v", "--remove-orphans", "--timeout", "10"),
            self._down_timeout,
        )
        if rc != 0:
            logger.warning("[compose] reset down failed: %s", _tail(err))
        rc, _o, err = self._run(
            self._compose_argv("up", "-d", "--no-build", "--wait"), self._up_timeout
        )
        if rc != 0:
            logger.warning("[compose] reset up failed: %s", _tail(err))
            return False
        return True

    def logs(self, service: str | None = None, tail: int = 200) -> str:
        """Return recent compose logs (host-side) for the stack or one service."""
        if not self._resolved_file:
            return ""
        args = ["logs", "--no-color", "--tail", str(int(tail))]
        if service:
            args.append(service)
        rc, out, err = self._run(self._compose_argv(*args), 60)
        return out if rc == 0 else (err or "")

    def down(self) -> None:
        """Tear the stack down and remove the internal network. Idempotent.

        Uses ``--rmi local`` so the per-service images compose built for this
        run (auto-named ``<project>-<service>``, no custom tag) are removed too.
        Without it those images accumulate one set per audit. This is the
        FINAL teardown; ``reset()`` (per-finding restart) deliberately omits
        ``--rmi`` so the stack rebuilds are cheap between findings.
        """
        if self._resolved_file:
            self._run(
                self._compose_argv(
                    "down", "-v", "--rmi", "local", "--remove-orphans", "--timeout", "10"
                ),
                self._down_timeout,
            )
        # Best-effort network removal (external nets are not removed by compose).
        self._run(["docker", "network", "rm", self.network_name], 30)
        if self._tmpdir is not None:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None
        self._resolved_file = None

    def __enter__(self) -> ComposeOrchestrator:
        self.up()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.down()
        return False


def _tail(text: str, n: int = 400) -> str:
    return (text or "").strip()[-n:]


def _abs(repo: str, p: str) -> str:
    """Absolutize a host-side path against repo unless it is already absolute."""
    p = (p or "").strip()
    if not p or os.path.isabs(p):
        return p
    return os.path.normpath(os.path.join(repo, p))


def _is_bind_source(src: str) -> bool:
    """A bind-mount source is path-like; a bare token is a named volume."""
    return bool(src) and ("/" in src or src.startswith("."))


def _abs_volume(repo: str, entry: Any) -> Any:
    """Absolutize a bind-mount source in a compose ``volumes`` entry.

    Handles the short ``"src:dst[:mode]"`` string and the long
    ``{type: bind, source: ./x, target: /y}`` dict; leaves named volumes and
    already-absolute sources unchanged.
    """
    if isinstance(entry, dict):
        if entry.get("type", "bind") == "bind":
            src = entry.get("source")
            if isinstance(src, str) and _is_bind_source(src) and not os.path.isabs(src):
                entry = dict(entry)
                entry["source"] = _abs(repo, src)
        return entry
    parts = str(entry).split(":")
    if len(parts) >= 2 and _is_bind_source(parts[0]) and not os.path.isabs(parts[0]):
        parts[0] = _abs(repo, parts[0])
        return ":".join(parts)
    return entry
