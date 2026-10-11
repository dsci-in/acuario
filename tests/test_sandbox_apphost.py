"""Tests for the pluggable AppHost hosting (Stage A: Dockerfile tier + resolver)."""

from __future__ import annotations

from pathlib import Path

from acuario.sandbox.apphost import (
    DockerfileAppHost,
    _parse_expose_port,
    detect_dockerfile,
    resolve_app_host,
)
from acuario.sandbox.compose import ComposeOrchestrator


class FakeRunner:
    """Argv-pattern-driven runner. Records calls; returns canned (rc, out, err)."""

    def __init__(self, rules=None, default=(0, "", "")):
        self.rules = rules or []
        self.default = default
        self.calls: list[list] = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        joined = " ".join(str(a) for a in argv)
        for needle, result in self.rules:
            if needle in joined:
                return result
        return self.default

    def joined(self):
        return [" ".join(str(a) for a in c) for c in self.calls]


def _ready_runner(extra_rules=None):
    # docker available + net create + build + run all succeed; inspect => running.
    rules = [
        ("docker version", (0, "Docker version 27", "")),
        ("network create", (0, "netid", "")),
        ("env DOCKER_BUILDKIT=0 docker build", (0, "built", "")),
        ("docker run -d", (0, "cid", "")),
        ("docker inspect", (0, "true|<no value>", "")),
    ]
    if extra_rules:
        rules = extra_rules + rules
    return FakeRunner(rules)


# --- detection --------------------------------------------------------------


def test_detect_dockerfile_root_only(tmp_path: Path):
    assert detect_dockerfile(str(tmp_path)) is None
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    assert detect_dockerfile(str(tmp_path)) == str(tmp_path / "Dockerfile")


def test_parse_expose_prefers_web_port(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM x\nEXPOSE 9000\nEXPOSE 8080/tcp\n")
    assert _parse_expose_port(str(df)) == 8080  # web-ish beats 9000
    df.write_text("FROM x\nEXPOSE 9000\n")
    assert _parse_expose_port(str(df)) == 9000
    df.write_text("FROM x\n")
    assert _parse_expose_port(str(df)) == 8000  # default


# --- DockerfileAppHost lifecycle -------------------------------------------


def _host(tmp_path: Path, runner, port=None) -> DockerfileAppHost:
    df = tmp_path / "Dockerfile"
    if not df.exists():
        df.write_text("FROM python:3.12\nEXPOSE 5000\nCMD python -m http.server 5000\n")
    return DockerfileAppHost(
        str(tmp_path), str(df), session_id="sess1234abcd", runner=runner, port=port
    )


def test_up_success_builds_runs_and_exposes_service(tmp_path: Path):
    runner = _ready_runner()
    host = _host(tmp_path, runner)
    host.up()
    assert host.ok is True
    assert host.service_urls == {"app": "http://app:5000"}
    assert host.entry_default == "http://app:5000"
    assert host.resolve_entry("anything.py") == "http://app:5000"
    calls = runner.joined()
    assert any("network create --internal" in c for c in calls)
    assert any("env DOCKER_BUILDKIT=0 docker build" in c for c in calls)
    assert any("docker run -d --name acuario-exploit-sess1234abcd-app" in c for c in calls)
    assert any("--network-alias app" in c for c in calls)


def test_up_fails_on_build_error(tmp_path: Path):
    runner = _ready_runner(extra_rules=[("docker build", (1, "", "boom: missing base image"))])
    host = _host(tmp_path, runner)
    host.up()
    assert host.ok is False
    assert "build failed" in host.reason
    # down() ran (rm/rmi/network rm attempted)
    assert any("network rm" in c for c in runner.joined())


def test_up_fails_when_container_not_running(tmp_path: Path):
    runner = _ready_runner(extra_rules=[("docker inspect", (0, "false|<no value>", ""))])
    host = _host(tmp_path, runner)
    host.up()
    assert host.ok is False
    assert "did not become ready" in host.reason


def test_reset_recreates_container(tmp_path: Path):
    runner = _ready_runner()
    host = _host(tmp_path, runner)
    host.up()
    runner.calls.clear()
    assert host.reset() is True
    calls = runner.joined()
    assert any("rm -f acuario-exploit-sess1234abcd-app" in c for c in calls)
    assert any("docker run -d" in c for c in calls)
    # reset must NOT rebuild the image
    assert not any("docker build" in c for c in calls)


def test_down_removes_container_image_and_network(tmp_path: Path):
    runner = _ready_runner()
    host = _host(tmp_path, runner)
    host.up()
    runner.calls.clear()
    host.down()
    calls = runner.joined()
    assert any("rm -f acuario-exploit-sess1234abcd-app" in c for c in calls)
    assert any("rmi -f acuario-exploit-sess1234abcd-app:latest" in c for c in calls)
    assert any("network rm acuario-exploit-net-sess1234abcd" in c for c in calls)


def test_docker_unavailable_fails_cleanly(tmp_path: Path):
    runner = FakeRunner([("docker version", (127, "", "not found"))])
    host = _host(tmp_path, runner)
    host.up()
    assert host.ok is False
    assert "docker CLI not available" in host.reason


# --- resolver ---------------------------------------------------------------


def test_resolver_prefers_compose(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - '8000:8000'\n"
    )
    runner = FakeRunner([("docker compose version", (0, "v2", ""))])
    host = resolve_app_host(str(tmp_path), session_id="s", runner=runner)
    assert isinstance(host, ComposeOrchestrator)


def test_resolver_falls_back_to_dockerfile(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nEXPOSE 8000\n")
    runner = FakeRunner(
        [
            ("docker compose version", (1, "", "no compose")),
            ("docker version", (0, "ok", "")),
        ]
    )
    host = resolve_app_host(str(tmp_path), session_id="s", runner=runner)
    assert isinstance(host, DockerfileAppHost)


def test_resolver_returns_none_when_nothing_hostable(tmp_path: Path):
    runner = FakeRunner([("docker version", (0, "ok", ""))])
    assert resolve_app_host(str(tmp_path), session_id="s", runner=runner) is None


def test_resolver_dockerfile_needs_docker(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    runner = FakeRunner(
        [
            ("docker compose version", (1, "", "")),
            ("docker version", (127, "", "not found")),
        ]
    )
    assert resolve_app_host(str(tmp_path), session_id="s", runner=runner) is None


# --- Stage B: synthesized (auto-detected) hosting ---------------------------

from acuario.sandbox.apphost import (  # noqa: E402
    SynthesizedAppHost,
    synthesize_dockerfile,
)


def test_synth_flask(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    text, port = synthesize_dockerfile(str(tmp_path))
    assert port == 8000
    assert "pip install --no-cache-dir -r requirements.txt" in text
    assert "ENV FLASK_APP=app" in text
    assert "flask run --host 0.0.0.0 --port 8000" in text


def test_synth_fastapi(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("fastapi\n")
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    text, _ = synthesize_dockerfile(str(tmp_path))
    assert "uvicorn main:app --host 0.0.0.0 --port 8000" in text
    assert "pip install --no-cache-dir uvicorn" in text


def test_synth_django(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("django\n")
    (tmp_path / "manage.py").write_text("# django manage\n")
    text, _ = synthesize_dockerfile(str(tmp_path))
    assert "python manage.py runserver 0.0.0.0:8000" in text


def test_synth_node_start_script(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"scripts": {"start": "node srv.js"}}')
    text, port = synthesize_dockerfile(str(tmp_path))
    assert port == 3000
    assert "npm start" in text
    assert "ENV PORT=3000" in text and "ENV HOST=0.0.0.0" in text


def test_synth_node_entry_file(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "server.js").write_text("require('http')")
    text, _ = synthesize_dockerfile(str(tmp_path))
    assert "node server.js" in text


def test_synth_returns_none_when_unknown(tmp_path: Path):
    (tmp_path / "README.md").write_text("just docs")
    assert synthesize_dockerfile(str(tmp_path)) is None


def test_resolver_falls_back_to_synth(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "app.py").write_text("from flask import Flask\napp=Flask(__name__)\n")
    runner = FakeRunner(
        [
            ("docker compose version", (1, "", "")),
            ("docker version", (0, "ok", "")),
        ]
    )
    host = resolve_app_host(str(tmp_path), session_id="s", runner=runner)
    assert isinstance(host, SynthesizedAppHost)


def test_synth_host_up_and_down_cleans_tempdir(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "app.py").write_text("from flask import Flask\napp=Flask(__name__)\n")
    text, port = synthesize_dockerfile(str(tmp_path))
    runner = _ready_runner()
    host = SynthesizedAppHost(str(tmp_path), text, port, session_id="sess1234abcd", runner=runner)
    synth_dir = host._synth_dir.name
    assert Path(synth_dir, "Dockerfile").exists()
    host.up()
    assert host.ok is True
    assert host.service_urls == {"app": "http://app:8000"}
    host.down()
    assert not Path(synth_dir).exists()  # temp dir cleaned


# --- Stage C1: DB sidecar + auto-detection ----------------------------------

from acuario.sandbox.apphost import DbSidecar, detect_db_need  # noqa: E402


def test_db_sidecar_with_defaults():
    db = DbSidecar(dialect="postgres").with_defaults()
    assert db.image == "postgres:16"
    assert db.port == 5432
    assert db.env["POSTGRES_USER"] == "acuario"
    assert db.connection_env["DB_HOST"] == "db"
    assert db.connection_env["DATABASE_URL"].startswith("postgresql://")


def test_detect_db_need_dialects(tmp_path: Path):
    d = tmp_path / "database"
    d.mkdir()
    (d / "schema.sql").write_text("CREATE TABLE t (id INT IDENTITY(1,1));\nGO\n")
    assert detect_db_need(str(tmp_path)).dialect == "mssql"
    (d / "schema.sql").write_text("CREATE TABLE t (id INT AUTO_INCREMENT) ENGINE=InnoDB;")
    assert detect_db_need(str(tmp_path)).dialect == "mysql"
    (d / "schema.sql").write_text("CREATE TABLE t (id SERIAL PRIMARY KEY);")
    assert detect_db_need(str(tmp_path)).dialect == "postgres"


def test_detect_db_need_none(tmp_path: Path):
    assert detect_db_need(str(tmp_path)) is None


def test_detect_db_need_finds_seed(tmp_path: Path):
    d = tmp_path / "database"
    d.mkdir()
    (d / "schema.sql").write_text("CREATE TABLE t (id SERIAL);")
    (d / "seed.sql").write_text("INSERT INTO t VALUES (1);")
    db = detect_db_need(str(tmp_path))
    assert db.schema_path.endswith("schema.sql")
    assert db.seed_path.endswith("seed.sql")


def test_dockerfile_host_with_db_up_and_wires_conn_env(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nEXPOSE 8000\n")
    d = tmp_path / "database"
    d.mkdir()
    (d / "schema.sql").write_text("CREATE TABLE t (id SERIAL);")
    (d / "seed.sql").write_text("INSERT INTO t VALUES (1);")
    db = detect_db_need(str(tmp_path))
    runner = _ready_runner()
    host = DockerfileAppHost(
        str(tmp_path), str(tmp_path / "Dockerfile"), session_id="sess1234abcd", runner=runner, db=db
    )
    host.up()
    assert host.ok is True
    calls = runner.joined()
    assert any("docker run -d --name acuario-exploit-sess1234abcd-db" in c for c in calls)
    assert any("docker cp" in c for c in calls)  # schema + seed copied in
    assert any("-e DATABASE_URL=postgresql://" in c for c in calls)  # app got conn env
    assert any("--name acuario-exploit-sess1234abcd-app" in c for c in calls)


def test_dockerfile_host_db_not_ready_fails(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM x\nEXPOSE 8000\n")
    runner = _ready_runner(extra_rules=[("pg_isready", (1, "", "starting"))])
    host = DockerfileAppHost(
        str(tmp_path),
        str(tmp_path / "Dockerfile"),
        session_id="sess1234abcd",
        runner=runner,
        db=DbSidecar(dialect="postgres"),
        db_ready_timeout=1,
    )
    host.up()
    assert host.ok is False
    assert "db did not become ready" in host.reason


def test_down_removes_db_container(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM x\nEXPOSE 8000\n")
    runner = _ready_runner()
    host = DockerfileAppHost(
        str(tmp_path),
        str(tmp_path / "Dockerfile"),
        session_id="sess1234abcd",
        runner=runner,
        db=DbSidecar(dialect="mysql"),
    )
    host.up()
    runner.calls.clear()
    host.down()
    assert any("rm -f acuario-exploit-sess1234abcd-db" in c for c in runner.joined())


def test_resolver_attaches_db(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "app.py").write_text("from flask import Flask\napp=Flask(__name__)\n")
    d = tmp_path / "database"
    d.mkdir()
    (d / "schema.sql").write_text("CREATE TABLE t (id SERIAL);")
    runner = FakeRunner(
        [
            ("docker compose version", (1, "", "")),
            ("docker version", (0, "ok", "")),
        ]
    )
    host = resolve_app_host(str(tmp_path), session_id="s", runner=runner)
    assert isinstance(host, SynthesizedAppHost)
    assert host._db is not None and host._db.dialect == "postgres"


# --- Stage C2: acuario.host.yml recipe --------------------------------------

from acuario.sandbox.apphost import (  # noqa: E402
    RecipeAppHost,
    detect_host_recipe,
)

_RECIPE_SYNTH = """\
build:
  base_image: python:3.12-slim
  install:
    - pip install -r requirements.txt
start: "uvicorn main:app --host 0.0.0.0 --port 8000"
port: 8000
env:
  SECRET_KEY: dev
database:
  dialect: postgres
  schema: database/schema.sql
  seed: database/seed.sql
  connection_env:
    DATABASE_URL: "postgresql://app:app@db:5432/app"
"""


def test_detect_host_recipe_full(tmp_path: Path):
    (tmp_path / "acuario.host.yml").write_text(_RECIPE_SYNTH)
    (tmp_path / "database").mkdir()
    (tmp_path / "database" / "schema.sql").write_text("CREATE TABLE t (id SERIAL);")
    r = detect_host_recipe(str(tmp_path))
    assert r.base_image == "python:3.12-slim"
    assert r.install == ["pip install -r requirements.txt"]
    assert r.start.startswith("uvicorn")
    assert r.port == 8000
    assert r.env == {"SECRET_KEY": "dev"}
    assert r.db is not None and r.db.dialect == "postgres"
    assert r.db.schema_path.endswith("database/schema.sql")
    assert r.db.connection_env["DATABASE_URL"] == "postgresql://app:app@db:5432/app"


def test_detect_host_recipe_none(tmp_path: Path):
    assert detect_host_recipe(str(tmp_path)) is None


def test_detect_host_recipe_invalid_ignored(tmp_path: Path):
    (tmp_path / "acuario.host.yml").write_text("port: 8000\n")  # no dockerfile, no start
    assert detect_host_recipe(str(tmp_path)) is None


def test_recipe_host_synth_up_wires_env_and_db(tmp_path: Path):
    (tmp_path / "acuario.host.yml").write_text(_RECIPE_SYNTH)
    (tmp_path / "database").mkdir()
    (tmp_path / "database" / "schema.sql").write_text("CREATE TABLE t (id SERIAL);")
    (tmp_path / "database" / "seed.sql").write_text("INSERT INTO t VALUES (1);")
    r = detect_host_recipe(str(tmp_path))
    runner = _ready_runner()
    host = RecipeAppHost(str(tmp_path), r, session_id="sess1234abcd", runner=runner)
    synth_dir = host._synth_dir.name
    host.up()
    assert host.ok is True
    assert host.service_urls == {"app": "http://app:8000"}
    calls = runner.joined()
    assert (
        any("python:3.12-slim" in c for c in calls) is False
    )  # base is in the Dockerfile, not argv
    assert any("docker run -d --name acuario-exploit-sess1234abcd-db" in c for c in calls)
    assert any("-e SECRET_KEY=dev" in c for c in calls)
    assert any("-e DATABASE_URL=postgresql://app:app@db:5432/app" in c for c in calls)
    host.down()
    assert not Path(synth_dir).exists()


def test_recipe_host_dockerfile_mode(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nEXPOSE 7000\n")
    (tmp_path / "acuario.host.yml").write_text(
        "build:\n  dockerfile: Dockerfile\nstart: ignored\nport: 7000\n"
    )
    r = detect_host_recipe(str(tmp_path))
    runner = _ready_runner()
    host = RecipeAppHost(str(tmp_path), r, session_id="sess1234abcd", runner=runner)
    assert host._synth_dir is None  # uses the real Dockerfile
    host.up()
    assert host.ok is True
    assert host.service_urls == {"app": "http://app:7000"}


def test_resolver_recipe_wins_over_compose(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - '8000:8000'\n"
    )
    (tmp_path / "acuario.host.yml").write_text(_RECIPE_SYNTH)
    (tmp_path / "database").mkdir()
    (tmp_path / "database" / "schema.sql").write_text("CREATE TABLE t (id SERIAL);")
    runner = FakeRunner(
        [
            ("docker compose version", (0, "v2", "")),
            ("docker version", (0, "ok", "")),
        ]
    )
    host = resolve_app_host(str(tmp_path), session_id="s", runner=runner)
    assert isinstance(host, RecipeAppHost)
