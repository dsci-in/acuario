"""Tests for the host-orchestrated compose exploit harness (acuario/sandbox/compose.py).

All duck-typed: an injectable subprocess runner stands in for the docker /
docker compose CLI, so nothing here touches a real daemon.
"""

from __future__ import annotations

import os
import textwrap

import yaml

from acuario.sandbox.compose import (
    ComposeOrchestrator,
    ComposeSpec,
    _container_port,
    detect_compose,
    resolve_compose_cli,
)

# A multi-service compose file: mysql db + python api + node bff + nginx web.
MULTISERVICE_COMPOSE = textwrap.dedent(
    """
    services:
      db:
        image: mysql:8.0
        ports:
          - "127.0.0.1:3306:3306"
        healthcheck:
          test: ["CMD", "mysqladmin", "ping"]
      api:
        build: ./api
        ports:
          - "127.0.0.1:8000:8000"
        depends_on:
          db:
            condition: service_healthy
      bff:
        build: ./bff
        ports:
          - "127.0.0.1:4000:4000"
        depends_on:
          - api
      web:
        build: ./web
        ports:
          - "127.0.0.1:3000:80"
        depends_on:
          - bff
    volumes:
      app_mysql:
    """
).strip()


class FakeRunner:
    """Records argv calls; returns a forced rc when a substring matches."""

    def __init__(self, rc_map=None, default_rc=0):
        self.calls: list[tuple[list, int]] = []
        self.rc_map = rc_map or {}
        self.default_rc = default_rc

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        joined = " ".join(argv)
        for key, rc in self.rc_map.items():
            if key in joined:
                return (rc, "", f"forced rc {rc}")
        return (self.default_rc, "ok", "")

    def joined_calls(self) -> list[str]:
        return [" ".join(argv) for argv, _t in self.calls]


def _write(tmp_path, name: str, content: str) -> str:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return str(tmp_path)


# --- detection --------------------------------------------------------------


class TestDetectCompose:
    def test_detects_docker_compose_yml(self, tmp_path):
        _write(tmp_path, "docker-compose.yml", MULTISERVICE_COMPOSE)
        spec = detect_compose(str(tmp_path))
        assert spec is not None
        assert set(spec.services) == {"db", "api", "bff", "web"}

    def test_none_when_absent(self, tmp_path):
        assert detect_compose(str(tmp_path)) is None

    def test_priority_prefers_compose_yaml(self, tmp_path):
        # compose.yaml wins over docker-compose.yml
        _write(tmp_path, "docker-compose.yml", "services: {a: {image: x}}")
        _write(tmp_path, "compose.yaml", MULTISERVICE_COMPOSE)
        spec = detect_compose(str(tmp_path))
        assert set(spec.services) == {"db", "api", "bff", "web"}


# --- spec parsing / entry resolution ----------------------------------------


class TestComposeSpec:
    def test_parse_build_context_and_ports(self, tmp_path):
        _write(tmp_path, "docker-compose.yml", MULTISERVICE_COMPOSE)
        spec = detect_compose(str(tmp_path))
        assert spec.services["bff"].build_context == "bff"
        assert spec.services["bff"].container_ports == [4000]
        assert spec.services["web"].container_ports == [80]  # "3000:80" -> 80
        assert spec.services["db"].has_build is False
        assert spec.services["api"].has_build is True

    def test_resolve_entry_finding_first(self, tmp_path):
        _write(tmp_path, "docker-compose.yml", MULTISERVICE_COMPOSE)
        spec = detect_compose(str(tmp_path))
        assert spec.resolve_entry("bff/src/index.js") == "http://bff:4000"
        assert spec.resolve_entry("api/app/main.py") == "http://api:8000"

    def test_resolve_entry_fallback_front_door(self, tmp_path):
        _write(tmp_path, "docker-compose.yml", MULTISERVICE_COMPOSE)
        spec = detect_compose(str(tmp_path))
        # A file that maps to no service -> the web front door (port 80).
        assert spec.resolve_entry("README.md") == "http://web:80"

    def test_service_urls(self, tmp_path):
        _write(tmp_path, "docker-compose.yml", MULTISERVICE_COMPOSE)
        spec = detect_compose(str(tmp_path))
        urls = spec.service_urls()
        assert urls["bff"] == "http://bff:4000"
        assert urls["api"] == "http://api:8000"
        assert urls["web"] == "http://web:80"
        assert urls["db"] == "http://db:3306"

    def test_empty_when_no_ports(self, tmp_path):
        _write(tmp_path, "docker-compose.yml", "services: {solo: {build: ./solo}}")
        spec = detect_compose(str(tmp_path))
        assert spec.resolve_entry("solo/x.py") == ""
        assert spec.service_urls() == {}


class TestContainerPort:
    def test_variants(self):
        assert _container_port("4000:4000") == 4000
        assert _container_port("127.0.0.1:4000:4000") == 4000
        assert _container_port("8000") == 8000
        assert _container_port("3000:80") == 80
        assert _container_port("8000/tcp") == 8000
        assert _container_port("4000-4005:4000-4005") == 4000
        assert _container_port({"target": 80, "published": 3000}) == 80
        assert _container_port("notaport") is None


# --- CLI resolution ---------------------------------------------------------


class TestResolveComposeCli:
    def test_prefers_v2(self):
        runner = FakeRunner()  # everything rc=0
        assert resolve_compose_cli(runner) == ["docker", "compose"]

    def test_falls_back_to_v1(self):
        # v2 `docker compose version` fails, v1 `docker-compose version` works
        runner = FakeRunner(rc_map={"docker compose version": 1})
        assert resolve_compose_cli(runner) == ["docker-compose"]

    def test_none_when_absent(self):
        runner = FakeRunner(rc_map={"docker compose version": 127, "docker-compose version": 127})
        assert resolve_compose_cli(runner) is None


# --- orchestrator lifecycle (command construction) --------------------------


class TestOrchestrator:
    def _spec(self, tmp_path) -> ComposeSpec:
        _write(tmp_path, "docker-compose.yml", MULTISERVICE_COMPOSE)
        return detect_compose(str(tmp_path))

    def test_up_happy_path(self, tmp_path):
        spec = self._spec(tmp_path)
        runner = FakeRunner()
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="sess1234abcd", runner=runner
        )
        bringup = orch.up()
        assert bringup.ok is True and orch.ok is True
        calls = runner.joined_calls()
        # internal network created with labels
        assert any("network create" in c and "--internal" in c for c in calls)
        assert any("com.acuario.kind=exploit-compose" in c for c in calls)
        # build then offline up --wait
        assert any(c.endswith("build") for c in calls)
        assert any("up -d --no-build --wait" in c for c in calls)
        # resolved compose file: ports stripped, every service pinned to the net,
        # top-level network external.
        doc = yaml.safe_load(open(orch._resolved_file, encoding="utf-8"))
        for name, sdef in doc["services"].items():
            assert "ports" not in sdef, f"{name} still publishes ports"
            assert sdef["networks"] == [orch.network_name]
        assert doc["networks"][orch.network_name]["external"] is True
        orch.down()

    def test_resolved_file_absolutizes_build_context(self, tmp_path):
        # The resolved file is written to a temp dir, so relative build contexts
        # must be rewritten absolute against the repo or compose fails to find
        # them ("unable to prepare context: path .../api not found").
        spec = self._spec(tmp_path)
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=FakeRunner()
        )
        orch.up()
        doc = yaml.safe_load(open(orch._resolved_file, encoding="utf-8"))
        for name in ("api", "bff", "web"):
            ctx = doc["services"][name]["build"]
            # build was a plain string; stays a string, now absolute + existing repo root
            assert os.path.isabs(ctx), f"{name} build context not absolute: {ctx}"
            assert ctx == os.path.join(str(tmp_path), name)
        orch.down()

    def test_build_forces_compose_bake_false(self, tmp_path):
        # The build subprocess must disable Bake so it does not require the
        # `docker buildx` CLI plugin (absent on the test host).
        spec = self._spec(tmp_path)
        runner = FakeRunner()
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=runner
        )
        orch.up()
        build_calls = [c for c in runner.joined_calls() if c.rstrip().endswith("build")]
        assert build_calls, "no build call recorded"
        assert all(c.startswith("env COMPOSE_BAKE=false ") for c in build_calls), build_calls
        # non-build compose calls are NOT env-prefixed
        up_calls = [c for c in runner.joined_calls() if "up -d --no-build" in c]
        assert up_calls and all(not c.startswith("env ") for c in up_calls)
        orch.down()

    def test_resolved_file_absolutizes_relative_volume_and_env_file(self, tmp_path):
        compose = textwrap.dedent(
            """
            services:
              api:
                build: ./api
                env_file: ./api/.env
                volumes:
                  - ./db/seed.sql:/docker-entrypoint-initdb.d/seed.sql:ro
                  - namedvol:/var/lib/data
            volumes:
              namedvol:
            """
        ).strip()
        _write(tmp_path, "docker-compose.yml", compose)
        spec = detect_compose(str(tmp_path))
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=FakeRunner()
        )
        orch.up()
        api = yaml.safe_load(open(orch._resolved_file, encoding="utf-8"))["services"]["api"]
        assert api["env_file"] == os.path.join(str(tmp_path), "api/.env")
        vols = api["volumes"]
        bind = os.path.join(str(tmp_path), "db/seed.sql")
        assert any(str(v).startswith(bind + ":") for v in vols), vols
        # named volume left untouched
        assert any(str(v) == "namedvol:/var/lib/data" for v in vols), vols
        orch.down()

    def test_up_build_failure_is_ok_false(self, tmp_path):
        spec = self._spec(tmp_path)
        runner = FakeRunner(rc_map={"build": 1})
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="sess1234abcd", runner=runner
        )
        bringup = orch.up()
        assert bringup.ok is False
        assert "build failed" in bringup.reason
        # teardown attempted (network rm) after the failure
        assert any("network rm" in c for c in runner.joined_calls())

    def test_up_network_create_failure(self, tmp_path):
        spec = self._spec(tmp_path)
        runner = FakeRunner(rc_map={"network create": 1})
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=runner
        )
        bringup = orch.up()
        assert bringup.ok is False
        assert "network create failed" in bringup.reason

    def test_network_create_already_exists_is_tolerated(self, tmp_path):
        spec = self._spec(tmp_path)

        class R(FakeRunner):
            def __call__(self, argv, timeout):
                self.calls.append((list(argv), timeout))
                if "network create" in " ".join(argv):
                    return (1, "", "Error response from daemon: network ... already exists")
                return (0, "ok", "")

        orch = ComposeOrchestrator(spec, str(tmp_path), ["docker", "compose"], runner=R())
        assert orch.up().ok is True
        orch.down()

    def test_reset_recreates_stack(self, tmp_path):
        spec = self._spec(tmp_path)
        runner = FakeRunner()
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=runner
        )
        orch.up()
        runner.calls.clear()
        assert orch.reset() is True
        calls = runner.joined_calls()
        assert any("down -v --remove-orphans" in c for c in calls)
        assert any("up -d --no-build --wait" in c for c in calls)
        orch.down()

    def test_down_removes_network(self, tmp_path):
        spec = self._spec(tmp_path)
        runner = FakeRunner()
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=runner
        )
        orch.up()
        runner.calls.clear()
        orch.down()
        calls = runner.joined_calls()
        # Final teardown also removes the images compose built (--rmi local) so
        # per-service build images don't accumulate one set per audit.
        assert any("down -v --rmi local --remove-orphans" in c for c in calls)
        assert any(f"network rm {orch.network_name}" in c for c in calls)

    def test_reset_keeps_images_but_down_removes_them(self, tmp_path):
        # reset() (per-finding restart) must NOT pass --rmi (cheap rebuilds);
        # only the final down() removes images.
        spec = self._spec(tmp_path)
        runner = FakeRunner()
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=runner
        )
        orch.up()
        runner.calls.clear()
        orch.reset()
        assert not any("--rmi" in c for c in runner.joined_calls())
        runner.calls.clear()
        orch.down()
        assert any("--rmi local" in c for c in runner.joined_calls())

    def test_deterministic_names_from_session(self, tmp_path):
        spec = self._spec(tmp_path)
        orch = ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="abcdef123456xyz"
        )
        assert orch.project == "acuario-exploit-abcdef123456"
        assert orch.network_name == "acuario-exploit-net-abcdef123456"

    def test_context_manager(self, tmp_path):
        spec = self._spec(tmp_path)
        runner = FakeRunner()
        with ComposeOrchestrator(
            spec, str(tmp_path), ["docker", "compose"], session_id="s", runner=runner
        ) as orch:
            assert orch.ok is True
        # after __exit__, network rm was issued
        assert any("network rm" in c for c in runner.joined_calls())
