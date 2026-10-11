"""Pluggable application hosting for the live exploit stage.

The exploit stage needs a running instance of the target app on a per-target,
egress-free ``--internal`` network so the exploit sandbox can join it by
``network_mode`` and probe services by Docker DNS. Historically the only way to
stand an app up was a ``docker-compose.yml`` shipped by the target
(``ComposeOrchestrator``). This module generalizes that into an ``AppHost``
contract with several tiers, so apps without a compose file can still be hosted:

    Tier 0  compose        - docker-compose.yml            (ComposeOrchestrator)
    Tier 1  dockerfile     - a Dockerfile at the repo root (DockerfileAppHost)
    Tier 2  auto-detect    - synthesized from the stack     (SynthesizedAppHost)
    Tier 2.5 host-recipe   - acuario.host.yml user hint     (RecipeAppHost)
    Tier 3  static         - nothing stands up -> static PoC (existing fallback)

Everything downstream of the exploit stage consumes only the small duck-typed
surface below, so a new tier is an addition, not a rewrite. The contract an
``AppHost`` must satisfy (read side + lifecycle):

    ok: bool                     reason: str
    network_name: str            service_urls: dict[str, str]  {dns: "http://dns:port"}
    entry_default: str           resolve_entry(finding_file) -> str
    logs(service=None, tail=200) -> str
    up() -> object   (once per target; sets ok/network_name/service_urls/entry)
    reset() -> bool  (per finding; clean app state)
    down() -> None   (guaranteed teardown; idempotent)

All subprocess calls are time-bounded via the injectable ``Runner`` (reused from
compose) so a stuck stand-up fails fast to the static-PoC path.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .compose import (
    ComposeOrchestrator,
    Runner,
    _default_runner,
    _tail,
    detect_compose,
    resolve_compose_cli,
)

logger = logging.getLogger(__name__)

# Container ports that read as a web front door, best first (mirrors compose).
_WEB_PORTS = (80, 8080, 3000, 8000, 4000, 5000, 8888)
_DEFAULT_PORT = 8000

# Per-dialect DB sidecar defaults (image, port, container env). Kept lean to the
# dialects the target apps here use; extend as needed. Passwords are lab creds
# for a throwaway, network-isolated container - never production secrets.
_DB_DEFAULTS: dict[str, dict] = {
    "postgres": {
        "image": "postgres:16",
        "port": 5432,
        "env": {"POSTGRES_USER": "acuario", "POSTGRES_PASSWORD": "acuario", "POSTGRES_DB": "app"},
    },
    "mysql": {
        "image": "mysql:8",
        "port": 3306,
        "env": {
            "MYSQL_ROOT_PASSWORD": "acuario",
            "MYSQL_DATABASE": "app",
            "MYSQL_USER": "acuario",
            "MYSQL_PASSWORD": "acuario",
        },
    },
    "mssql": {
        "image": "mcr.microsoft.com/mssql/server:2022-latest",
        "port": 1433,
        "env": {"ACCEPT_EULA": "Y", "MSSQL_SA_PASSWORD": "Acuario!Pass1"},
    },
}


@dataclass
class DbSidecar:
    """A database container to stand up next to the app on the internal net.

    ``connection_env`` is injected into the APP container so it can reach the DB
    at ``<alias>:<port>``. For auto-detection those are best-effort common var
    names; the acuario.host.yml recipe lets a user specify exact ones.
    """

    dialect: str  # postgres | mysql | mssql
    image: str = ""
    alias: str = "db"
    port: int = 0
    env: dict = field(default_factory=dict)
    schema_path: str = ""  # absolute host path to a schema .sql (loaded first)
    seed_path: str = ""  # absolute host path to a seed .sql (loaded after schema)
    connection_env: dict = field(default_factory=dict)

    def with_defaults(self) -> DbSidecar:
        d = _DB_DEFAULTS.get(self.dialect, {})
        if not self.image:
            self.image = d.get("image", "")
        if not self.port:
            self.port = d.get("port", 0)
        merged = dict(d.get("env", {}))
        merged.update(self.env)
        self.env = merged
        if not self.connection_env:
            self.connection_env = _default_connection_env(self)
        return self


def _default_connection_env(db: DbSidecar) -> dict:
    """Best-effort common connection env vars an app might read."""
    env = db.env
    if db.dialect == "postgres":
        user = env.get("POSTGRES_USER", "postgres")
        pw = env.get("POSTGRES_PASSWORD", "")
        name = env.get("POSTGRES_DB", "postgres")
        url = f"postgresql://{user}:{pw}@{db.alias}:{db.port}/{name}"
    elif db.dialect == "mysql":
        user = env.get("MYSQL_USER", "root")
        pw = env.get("MYSQL_PASSWORD", env.get("MYSQL_ROOT_PASSWORD", ""))
        name = env.get("MYSQL_DATABASE", "app")
        url = f"mysql://{user}:{pw}@{db.alias}:{db.port}/{name}"
    elif db.dialect == "mssql":
        user, pw, name = "sa", env.get("MSSQL_SA_PASSWORD", ""), "master"
        url = f"mssql://{user}:{pw}@{db.alias}:{db.port}/{name}"
    else:
        user = pw = name = ""
        url = ""
    return {
        "DATABASE_URL": url,
        "DB_HOST": db.alias,
        "DB_PORT": str(db.port),
        "DB_NAME": name,
        "DB_USER": user,
        "DB_PASSWORD": pw,
    }


def _db_ready_argv(container: str, db: DbSidecar) -> list:
    env = db.env
    if db.dialect == "postgres":
        return [
            "docker",
            "exec",
            container,
            "pg_isready",
            "-U",
            env.get("POSTGRES_USER", "postgres"),
            "-d",
            env.get("POSTGRES_DB", "postgres"),
        ]
    if db.dialect == "mysql":
        return [
            "docker",
            "exec",
            container,
            "mysqladmin",
            "ping",
            "-h",
            "127.0.0.1",
            "-uroot",
            f"-p{env.get('MYSQL_ROOT_PASSWORD', '')}",
            "--silent",
        ]
    if db.dialect == "mssql":
        p = env.get("MSSQL_SA_PASSWORD", "")
        return [
            "docker",
            "exec",
            container,
            "sh",
            "-lc",
            f"/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P '{p}' -Q 'SELECT 1' "
            f"2>/dev/null || /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P '{p}' -Q 'SELECT 1'",
        ]
    return ["docker", "exec", container, "true"]


def _db_load_argv(container: str, db: DbSidecar, remote: str) -> list | None:
    env = db.env
    if db.dialect == "postgres":
        return [
            "docker",
            "exec",
            "-e",
            f"PGPASSWORD={env.get('POSTGRES_PASSWORD', '')}",
            container,
            "psql",
            "-U",
            env.get("POSTGRES_USER", "postgres"),
            "-d",
            env.get("POSTGRES_DB", "postgres"),
            "-f",
            remote,
        ]
    if db.dialect == "mysql":
        return [
            "docker",
            "exec",
            container,
            "sh",
            "-lc",
            f"mysql -uroot -p'{env.get('MYSQL_ROOT_PASSWORD', '')}' "
            f"{env.get('MYSQL_DATABASE', '')} < {remote}",
        ]
    if db.dialect == "mssql":
        p = env.get("MSSQL_SA_PASSWORD", "")
        return [
            "docker",
            "exec",
            container,
            "sh",
            "-lc",
            f"/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P '{p}' -i {remote} "
            f"|| /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P '{p}' -i {remote}",
        ]
    return None


@runtime_checkable
class AppHost(Protocol):
    """The surface the exploit stage + agent depend on. ComposeOrchestrator and
    DockerfileAppHost both satisfy it structurally."""

    network_name: str
    service_urls: dict

    @property
    def ok(self) -> bool: ...
    @property
    def reason(self) -> str: ...
    @property
    def entry_default(self) -> str: ...
    def resolve_entry(self, finding_file: str) -> str: ...
    def logs(self, service: str | None = None, tail: int = 200) -> str: ...
    def up(self) -> object: ...
    def reset(self) -> bool: ...
    def down(self) -> None: ...


# --- detection --------------------------------------------------------------


def detect_dockerfile(repo_path: str) -> str | None:
    """Return the path to a root-level Dockerfile, else None.

    Only the repo root is considered (a Dockerfile deeper in the tree usually
    belongs to one service of a larger app and needs compose to wire it).
    """
    for name in ("Dockerfile", "dockerfile"):
        path = os.path.join(repo_path, name)
        if os.path.isfile(path):
            return path
    return None


def _docker_available(runner: Runner) -> bool:
    try:
        rc, _o, _e = runner(["docker", "version"], 10)
        return rc == 0
    except Exception:
        logger.debug("[apphost] `docker version` probe failed", exc_info=True)
        return False


def _parse_expose_port(dockerfile_path: str) -> int:
    """Pick a port from the Dockerfile's EXPOSE lines (web-ish first), else default."""
    ports: list[int] = []
    try:
        with open(dockerfile_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*EXPOSE\s+(.+)", line, re.IGNORECASE)
                if not m:
                    continue
                for tok in m.group(1).split():
                    num = tok.split("/", 1)[0].strip()
                    if num.isdigit():
                        ports.append(int(num))
    except Exception:
        logger.debug("[apphost] failed reading EXPOSE from %s", dockerfile_path, exc_info=True)
    if not ports:
        return _DEFAULT_PORT
    for web in _WEB_PORTS:
        if web in ports:
            return web
    return ports[0]


# --- Tier 1: single Dockerfile ----------------------------------------------


class DockerfileAppHost:
    """Host an app defined by a single root-level Dockerfile.

    Builds the image (daemon-side egress, BuildKit disabled so no buildx plugin
    is required), runs one container on a fresh ``--internal`` network with a
    stable DNS alias (``app``), and exposes it to the exploit agent as
    ``service_urls={"app": "http://app:<port>"}``. Satisfies the ``AppHost``
    contract so it drops into the exploit stage wherever ComposeOrchestrator did.
    """

    #: DNS alias the exploit agent probes on the internal net.
    SERVICE_ALIAS = "app"

    def __init__(
        self,
        repo_path: str,
        dockerfile_path: str,
        *,
        session_id: str | None = None,
        runner: Runner | None = None,
        port: int | None = None,
        db: DbSidecar | None = None,
        app_env: dict | None = None,
        build_timeout: int = 1800,
        up_timeout: int = 600,
        down_timeout: int = 120,
        db_ready_timeout: int = 300,
        network_internal: bool = True,
    ):
        self.repo_path = os.path.abspath(repo_path)
        self.dockerfile_path = os.path.abspath(dockerfile_path)
        self._run = runner or _default_runner
        self._build_timeout = build_timeout
        self._up_timeout = up_timeout
        self._down_timeout = down_timeout
        self._db_ready_timeout = db_ready_timeout
        self._network_internal = network_internal
        self._db = db.with_defaults() if db is not None else None
        self._app_env = dict(app_env or {})
        self._db_started = False
        self._port = port or _parse_expose_port(self.dockerfile_path)

        import uuid

        token = (session_id or uuid.uuid4().hex)[:12]
        self.uid = token
        # Same naming scheme as compose so cleanup/watcher patterns still match.
        self.project = f"acuario-exploit-{token}"
        self.network_name = f"acuario-exploit-net-{token}"
        self._image_tag = f"{self.project}-app:latest"
        self._container = f"{self.project}-app"
        self._db_container = f"{self.project}-db"
        self.service_urls: dict = {self.SERVICE_ALIAS: f"http://{self.SERVICE_ALIAS}:{self._port}"}

        self._ok = False
        self._reason = "not started"
        self._entry = self.service_urls[self.SERVICE_ALIAS]
        self._started = False

    # -- properties (AppHost read side) --------------------------------------

    @property
    def ok(self) -> bool:
        return self._ok

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def entry_default(self) -> str:
        return self._entry

    def resolve_entry(self, finding_file: str) -> str:
        # Single service: every finding shares the one front door.
        return self._entry

    # -- lifecycle -----------------------------------------------------------

    def _fail(self, reason: str) -> DockerfileAppHost:
        self._ok = False
        self._reason = reason
        logger.warning("[apphost] dockerfile host not up: %s", reason)
        self.down()
        return self

    def _build_argv(self) -> list:
        # DOCKER_BUILDKIT=0 forces the classic daemon builder so the build does
        # not require the `docker buildx` plugin (same rationale as compose's
        # COMPOSE_BAKE=false).
        return [
            "env",
            "DOCKER_BUILDKIT=0",
            "docker",
            "build",
            "-t",
            self._image_tag,
            "-f",
            self.dockerfile_path,
            self.repo_path,
        ]

    def _wait_running(self) -> bool:
        """Poll until the container is running (and, if it declares a healthcheck,
        healthy), or it crashes / times out. Bounded by up_timeout."""
        deadline = time.monotonic() + self._up_timeout
        while time.monotonic() < deadline:
            rc, out, _e = self._run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{.State.Running}}|{{.State.Health.Status}}",
                    self._container,
                ],
                20,
            )
            state = (out or "").strip()
            running, _, health = state.partition("|")
            if running != "true":
                # Crashed on boot - surface the tail as the reason.
                return False
            if health in ("", "<no value>", "healthy", "none"):
                # No healthcheck (or already healthy): a running container is
                # good enough; the agent's own readiness probe confirms HTTP.
                return True
            if health == "unhealthy":
                return False
            time.sleep(2)  # health == "starting"
        return False

    # -- app + db run helpers ------------------------------------------------

    def _run_app_argv(self) -> list:
        argv = [
            "docker",
            "run",
            "-d",
            "--name",
            self._container,
            "--network",
            self.network_name,
            "--network-alias",
            self.SERVICE_ALIAS,
            "--label",
            f"com.acuario.session={self.uid}",
        ]
        env = dict(self._app_env)
        if self._db is not None:
            env.update(self._db.connection_env)  # let the app reach the DB
        for k, v in env.items():
            argv += ["-e", f"{k}={v}"]
        argv.append(self._image_tag)
        return argv

    def _start_app(self) -> tuple[int, str]:
        rc, _o, err = self._run(self._run_app_argv(), self._up_timeout)
        if rc == 0:
            self._started = True
        return rc, err

    def _up_db(self) -> bool:
        """Run the DB container, wait until it accepts connections, load schema+seed."""
        db = self._db
        argv = [
            "docker",
            "run",
            "-d",
            "--name",
            self._db_container,
            "--network",
            self.network_name,
            "--network-alias",
            db.alias,
            "--label",
            f"com.acuario.session={self.uid}",
        ]
        for k, v in db.env.items():
            argv += ["-e", f"{k}={v}"]
        argv.append(db.image)
        rc, _o, err = self._run(argv, self._up_timeout)
        if rc != 0:
            self._reason = f"db run failed: {_tail(err)}"
            return False
        self._db_started = True
        if not self._wait_db_ready():
            self._reason = "db did not become ready"
            return False
        if db.schema_path and not self._load_sql(db.schema_path):
            self._reason = "db schema load failed"
            return False
        if db.seed_path and not self._load_sql(db.seed_path):
            self._reason = "db seed load failed"
            return False
        return True

    def _wait_db_ready(self) -> bool:
        deadline = time.monotonic() + self._db_ready_timeout
        argv = _db_ready_argv(self._db_container, self._db)
        while time.monotonic() < deadline:
            rc, _o, _e = self._run(argv, 30)
            if rc == 0:
                return True
            time.sleep(3)
        return False

    def _load_sql(self, host_path: str) -> bool:
        if not os.path.isfile(host_path):
            logger.warning("[apphost] sql file not found: %s", host_path)
            return False
        remote = "/acuario_load.sql"
        rc, _o, err = self._run(["docker", "cp", host_path, f"{self._db_container}:{remote}"], 120)
        if rc != 0:
            logger.warning("[apphost] docker cp sql failed: %s", _tail(err))
            return False
        load_argv = _db_load_argv(self._db_container, self._db, remote)
        if load_argv is None:
            logger.warning("[apphost] no SQL loader for dialect %s", self._db.dialect)
            return False
        rc, _o, err = self._run(load_argv, 300)
        if rc != 0:
            logger.warning("[apphost] sql load failed: %s", _tail(err))
            return False
        return True

    def up(self) -> DockerfileAppHost:
        if not _docker_available(self._run):
            return self._fail("docker CLI not available")

        # 1. internal network (egress-free; DNS still resolves).
        net_argv = ["docker", "network", "create"]
        if self._network_internal:
            net_argv.append("--internal")
        net_argv += [
            "--label",
            "com.acuario.kind=exploit-dockerfile",
            "--label",
            f"com.acuario.session={self.uid}",
            self.network_name,
        ]
        rc, _o, err = self._run(net_argv, 60)
        if rc != 0 and "already exists" not in (err or "").lower():
            return self._fail(f"network create failed: {(err or '').strip()[:300]}")

        # 2. build the app image (daemon-side egress allowed).
        rc, _o, err = self._run(self._build_argv(), self._build_timeout)
        if rc != 0:
            return self._fail(f"docker build failed: {_tail(err)}")

        # 3. DB sidecar first (so the app can connect at startup).
        if self._db is not None and not self._up_db():
            return self._fail(self._reason)

        # 4. run the app on the internal net (with any DB connection env).
        rc, err = self._start_app()
        if rc != 0:
            return self._fail(f"docker run failed: {_tail(err)}")

        # 5. readiness.
        if not self._wait_running():
            return self._fail(f"container did not become ready: {_tail(self.logs(tail=40))}")

        self._ok = True
        self._reason = ""
        logger.info(
            "[apphost] dockerfile stack up on %s (container=%s, url=%s, db=%s)",
            self.network_name,
            self._container,
            self._entry,
            self._db.dialect if self._db else "none",
        )
        return self

    def reset(self) -> bool:
        """Recreate the app (and DB, if any) from images for clean per-finding
        state (no rebuild). Best-effort."""
        if not self._started:
            return False
        if self._db is not None:
            # Fresh DB container + reload schema/seed for clean data state.
            self._run(["docker", "rm", "-f", self._db_container], 60)
            self._db_started = False
            if not self._up_db():
                logger.warning("[apphost] db reset failed: %s", self._reason)
                return False
        self._run(["docker", "rm", "-f", self._container], 60)
        rc, err = self._start_app()
        if rc != 0:
            logger.warning("[apphost] app reset run failed: %s", _tail(err))
            return False
        return self._wait_running()

    def logs(self, service: str | None = None, tail: int = 200) -> str:
        if not self._started:
            return ""
        target = self._db_container if service == "db" and self._db else self._container
        rc, out, err = self._run(["docker", "logs", "--tail", str(int(tail)), target], 60)
        return out if rc == 0 else (err or "")

    def down(self) -> None:
        """Remove the app + DB containers, the built image, and the network.
        Idempotent."""
        self._run(["docker", "rm", "-f", self._container], self._down_timeout)
        if self._db is not None:
            self._run(["docker", "rm", "-f", self._db_container], self._down_timeout)
        self._run(["docker", "rmi", "-f", self._image_tag], self._down_timeout)
        self._run(["docker", "network", "rm", self.network_name], 30)
        self._started = False
        self._db_started = False

    def __enter__(self) -> DockerfileAppHost:
        self.up()
        return self

    def __exit__(self, *exc) -> None:
        self.down()


# --- Tier 2: auto-detected stack (synthesized Dockerfile) -------------------
#
# Honest scope: this synthesizes a runnable image for the highest-confidence
# single-service stacks (Python and Node) where the start command + port can be
# inferred reliably. Anything else returns None and defers to the acuario.host.yml
# hint (Tier 2.5) or the static-PoC fallback. Apps that need a database get one
# via the DB sidecar; a synthesized app with an unmet external
# dependency will simply read NOT ready and fall back.


def _exists(root: str, name: str) -> bool:
    return os.path.isfile(os.path.join(root, name))


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def _py_module_for(root: str, needle: str, candidates: tuple[str, ...]) -> str | None:
    """First candidate .py at root whose content mentions ``needle`` (e.g. Flask)."""
    for name in candidates:
        p = os.path.join(root, name)
        if os.path.isfile(p) and needle in _read_text(p):
            return name[:-3]  # strip .py -> module name
    return None


_DF_TEMPLATE = "FROM {base}\nWORKDIR /app\nCOPY . /app\n{install}{env}EXPOSE {port}\nCMD {cmd}\n"


def _synth_python(root: str) -> tuple[str, int] | None:
    port = 8000
    install = ""
    if _exists(root, "requirements.txt"):
        install = "RUN pip install --no-cache-dir -r requirements.txt\n"
    elif _exists(root, "pyproject.toml") or _exists(root, "setup.py"):
        install = "RUN pip install --no-cache-dir .\n"

    env = ""
    # Framework detection -> a 0.0.0.0-bound start command (loopback binds are
    # unreachable from the exploit sandbox on the shared network).
    if _exists(root, "manage.py"):
        cmd = f"python manage.py runserver 0.0.0.0:{port}"
    elif mod := _py_module_for(root, "FastAPI", ("main.py", "app.py", "server.py")):
        install += "RUN pip install --no-cache-dir uvicorn\n"
        cmd = f"uvicorn {mod}:app --host 0.0.0.0 --port {port}"
    elif mod := _py_module_for(root, "Flask", ("app.py", "wsgi.py", "application.py")):
        install += "RUN pip install --no-cache-dir flask\n"
        env = f"ENV FLASK_APP={mod}\n"
        cmd = f"flask run --host 0.0.0.0 --port {port}"
    elif _exists(root, "app.py"):
        cmd = "python app.py"
    elif _exists(root, "main.py"):
        cmd = "python main.py"
    else:
        return None  # can't infer how to start -> defer

    text = _DF_TEMPLATE.format(
        base="python:3.12-slim", install=install, env=env, port=port, cmd=cmd
    )
    return text, port


def _synth_node(root: str) -> tuple[str, int] | None:
    if not _exists(root, "package.json"):
        return None
    port = 3000
    install = "RUN npm ci\n" if _exists(root, "package-lock.json") else "RUN npm install\n"
    # Node apps conventionally honor PORT/HOST env; set both for reachability.
    env = f"ENV PORT={port}\nENV HOST=0.0.0.0\n"
    cmd: str | None = None
    try:
        pkg = json.loads(_read_text(os.path.join(root, "package.json")) or "{}")
        if isinstance(pkg.get("scripts"), dict) and pkg["scripts"].get("start"):
            cmd = "npm start"
    except Exception:
        pass
    if cmd is None:
        for entry in ("server.js", "index.js", "app.js"):
            if _exists(root, entry):
                cmd = f"node {entry}"
                break
    if cmd is None:
        return None
    text = _DF_TEMPLATE.format(base="node:20-slim", install=install, env=env, port=port, cmd=cmd)
    return text, port


def synthesize_dockerfile(repo_path: str) -> tuple[str, int] | None:
    """Best-effort synthesized (Dockerfile text, port) for a single-service app,
    or None when the stack/start can't be inferred confidently."""
    for synth in (_synth_python, _synth_node):
        try:
            result = synth(repo_path)
        except Exception:
            logger.debug("[apphost] synth probe failed", exc_info=True)
            result = None
        if result:
            return result
    return None


_SCHEMA_CANDIDATES = ("database/schema.sql", "db/schema.sql", "sql/schema.sql", "schema.sql")
_SEED_CANDIDATES = ("database/seed.sql", "db/seed.sql", "sql/seed.sql", "seed.sql")


def _infer_sql_dialect(text: str) -> str:
    t = text.lower()
    if "identity(" in t or "nvarchar" in t or "\ngo\n" in t or "[dbo]" in t or "dbo." in t:
        return "mssql"
    if "auto_increment" in t or "engine=" in t or "`" in text:
        return "mysql"
    if "serial" in t or "returning" in t or "::" in text or "pg_" in t:
        return "postgres"
    return "postgres"  # sensible default


def detect_db_need(repo_path: str) -> DbSidecar | None:
    """Best-effort: if the repo ships a schema .sql, provision a matching DB
    sidecar (dialect inferred from the SQL). Heuristic - the connection env is a
    common-name guess; acuario.host.yml lets a user specify it exactly.
    """
    schema = None
    for rel in _SCHEMA_CANDIDATES:
        p = os.path.join(repo_path, rel)
        if os.path.isfile(p):
            schema = p
            break
    if schema is None:
        for d in ("database", "db", "sql", "migrations"):
            dpath = os.path.join(repo_path, d)
            if os.path.isdir(dpath):
                sqls = sorted(f for f in os.listdir(dpath) if f.lower().endswith(".sql"))
                if sqls:
                    schema = os.path.join(dpath, sqls[0])
                    break
    if schema is None:
        return None
    dialect = _infer_sql_dialect(_read_text(schema))
    seed = ""
    for rel in _SEED_CANDIDATES:
        p = os.path.join(repo_path, rel)
        if os.path.isfile(p) and os.path.abspath(p) != os.path.abspath(schema):
            seed = os.path.abspath(p)
            break
    logger.info("[apphost] db need detected: %s (schema=%s)", dialect, os.path.basename(schema))
    return DbSidecar(dialect=dialect, schema_path=os.path.abspath(schema), seed_path=seed)


class SynthesizedAppHost(DockerfileAppHost):
    """Host an app with no Dockerfile by synthesizing one from its stack.

    Reuses DockerfileAppHost's build/run/readiness/reset/teardown by writing the
    synthesized Dockerfile to a private temp dir and pointing the build at it
    (context stays the repo). Owns and cleans that temp dir.
    """

    def __init__(
        self,
        repo_path: str,
        dockerfile_text: str,
        port: int,
        *,
        session_id: str | None = None,
        runner: Runner | None = None,
        db: DbSidecar | None = None,
        app_env: dict | None = None,
    ):
        self._synth_dir = tempfile.TemporaryDirectory(prefix="acuario-synthdf-")
        df_path = os.path.join(self._synth_dir.name, "Dockerfile")
        with open(df_path, "w", encoding="utf-8") as fh:
            fh.write(dockerfile_text)
        super().__init__(
            repo_path,
            df_path,
            session_id=session_id,
            runner=runner,
            port=port,
            db=db,
            app_env=app_env,
        )

    def down(self) -> None:
        super().down()
        if self._synth_dir is not None:
            try:
                self._synth_dir.cleanup()
            except Exception:
                pass
            self._synth_dir = None


# --- Tier 2.5: acuario.host.yml recipe (explicit user override) -------------

_HOST_RECIPE_FILES = ("acuario.host.yml", "acuario.host.yaml")


@dataclass
class HostRecipe:
    """A user-authored run recipe (acuario.host.yml) - the reliable escape hatch
    for anything auto-detection can't stand up. Either point at a Dockerfile, or
    give base_image + install + start so a Dockerfile is synthesized."""

    dockerfile: str = ""  # repo-relative path to a Dockerfile
    base_image: str = ""
    install: list = field(default_factory=list)  # RUN lines
    start: str = ""  # the container start command (bind 0.0.0.0)
    port: int = 0
    env: dict = field(default_factory=dict)  # app env (injected via -e)
    db: DbSidecar | None = None


def detect_host_recipe(repo_path: str) -> HostRecipe | None:
    """Parse acuario.host.yml at the repo root, or None if absent/unusable."""
    path = None
    for name in _HOST_RECIPE_FILES:
        p = os.path.join(repo_path, name)
        if os.path.isfile(p):
            path = p
            break
    if path is None:
        return None
    import yaml

    try:
        raw = yaml.safe_load(_read_text(path)) or {}
    except Exception:
        logger.warning("[apphost] failed to parse %s", path, exc_info=True)
        return None
    if not isinstance(raw, dict):
        return None

    build = raw.get("build") if isinstance(raw.get("build"), dict) else {}

    def _abs(rel: str) -> str:
        return os.path.abspath(os.path.join(repo_path, rel)) if rel else ""

    db = None
    dbraw = raw.get("database")
    if isinstance(dbraw, dict) and dbraw.get("dialect"):
        db = DbSidecar(
            dialect=str(dbraw.get("dialect", "")),
            image=str(dbraw.get("image", "")),
            alias=str(dbraw.get("alias", "db")),
            port=int(dbraw.get("port", 0) or 0),
            env={str(k): str(v) for k, v in (dbraw.get("env") or {}).items()},
            schema_path=_abs(str(dbraw.get("schema", ""))),
            seed_path=_abs(str(dbraw.get("seed", ""))),
            connection_env={str(k): str(v) for k, v in (dbraw.get("connection_env") or {}).items()},
        )

    recipe = HostRecipe(
        dockerfile=str(build.get("dockerfile", "")),
        base_image=str(build.get("base_image", "")),
        install=[str(c) for c in (build.get("install") or [])],
        start=str(raw.get("start", "")),
        port=int(raw.get("port", 0) or 0),
        env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        db=db,
    )
    if not recipe.dockerfile and not recipe.start:
        logger.warning("[apphost] %s has neither build.dockerfile nor start; ignoring", path)
        return None
    return recipe


class RecipeAppHost(DockerfileAppHost):
    """Host an app from an acuario.host.yml recipe: use its Dockerfile, or
    synthesize one from base_image + install + start. DB + env come from the
    recipe, so the wiring is exact rather than guessed."""

    def __init__(
        self,
        repo_path: str,
        recipe: HostRecipe,
        *,
        session_id: str | None = None,
        runner: Runner | None = None,
    ):
        self._synth_dir = None
        repo_abs = os.path.abspath(repo_path)
        if recipe.dockerfile:
            df_path = os.path.join(repo_abs, recipe.dockerfile)
            port = recipe.port or _parse_expose_port(df_path)
        else:
            port = recipe.port or _DEFAULT_PORT
            install = "".join(f"RUN {c}\n" for c in recipe.install)
            text = _DF_TEMPLATE.format(
                base=recipe.base_image or "debian:12-slim",
                install=install,
                env="",
                port=port,
                cmd=recipe.start,
            )
            self._synth_dir = tempfile.TemporaryDirectory(prefix="acuario-recipedf-")
            df_path = os.path.join(self._synth_dir.name, "Dockerfile")
            with open(df_path, "w", encoding="utf-8") as fh:
                fh.write(text)
        super().__init__(
            repo_abs,
            df_path,
            session_id=session_id,
            runner=runner,
            port=port,
            db=recipe.db,
            app_env=recipe.env,
        )

    def down(self) -> None:
        super().down()
        if self._synth_dir is not None:
            try:
                self._synth_dir.cleanup()
            except Exception:
                pass
            self._synth_dir = None


# --- resolver ---------------------------------------------------------------


def resolve_app_host(
    repo_path: str,
    *,
    session_id: str | None = None,
    runner: Runner | None = None,
    enable_compose: bool = True,
) -> AppHost | None:
    """Return the first hostable tier for ``repo_path``, or None for static PoC.

    Order: acuario.host.yml recipe (explicit override) -> compose (Tier 0) ->
    Dockerfile (Tier 1) -> auto-detected stack (Tier 2). A DB sidecar is attached
    to the Dockerfile/stack tiers when a schema .sql is detected. None means
    nothing is hostable and findings fall back to the static-PoC path.
    """
    run = runner or _default_runner

    # An explicit acuario.host.yml is a deliberate override; it wins over
    # auto-detection so a user can teach Acuario exactly how to run their app.
    recipe = detect_host_recipe(repo_path)
    if recipe is not None:
        if _docker_available(run):
            logger.info("[apphost] acuario.host.yml recipe -> RecipeAppHost")
            return RecipeAppHost(repo_path, recipe, session_id=session_id, runner=runner)
        logger.warning("[apphost] acuario.host.yml present but docker CLI unavailable")

    if enable_compose:
        try:
            spec = detect_compose(repo_path)
            cli = resolve_compose_cli(run) if spec else None
            if spec and cli:
                return ComposeOrchestrator(spec, repo_path, cli, session_id=session_id)
            if spec and not cli:
                logger.warning(
                    "[apphost] compose app detected but no `docker compose` CLI; "
                    "trying other tiers / falling back to static PoC"
                )
        except Exception:
            logger.debug("[apphost] compose detection failed (non-fatal)", exc_info=True)

    # A schema.sql (etc.) means the app likely needs a database; provision a
    # matching sidecar for the Dockerfile/synthesized tiers (best-effort).
    db = detect_db_need(repo_path)

    dockerfile = detect_dockerfile(repo_path)
    if dockerfile:
        if _docker_available(run):
            logger.info("[apphost] root Dockerfile detected -> DockerfileAppHost")
            return DockerfileAppHost(
                repo_path, dockerfile, session_id=session_id, runner=runner, db=db
            )
        logger.warning("[apphost] Dockerfile detected but docker CLI unavailable")

    synth = synthesize_dockerfile(repo_path)
    if synth:
        if _docker_available(run):
            logger.info("[apphost] no Dockerfile; synthesized stack image -> SynthesizedAppHost")
            return SynthesizedAppHost(
                repo_path, synth[0], synth[1], session_id=session_id, runner=runner, db=db
            )
        logger.warning("[apphost] stack detected but docker CLI unavailable")

    return None
