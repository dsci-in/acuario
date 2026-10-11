"""Tests for the live-app dynamic-validation harness (N1).

The harness is duck-typed on the sandbox, so a recording fake stands in for a
real Docker container - every assertion checks the commands the harness builds
and how it parses curl output, with no daemon involved.
"""

from __future__ import annotations

from dataclasses import dataclass

from acuario.sandbox.app_harness import AppHarness, HttpResult, LaunchRecipe


@dataclass
class _Exec:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


class FakeSandbox:
    """Records exec calls and replays scripted responses.

    ``responder`` maps a substring of the joined command to an _Exec result;
    the first matching substring wins. Unmatched commands return exit 0 empty.
    """

    def __init__(self, responder=None, existing_files=None):
        self.calls: list[list[str]] = []
        self._responder = responder or {}
        self._existing = set(existing_files or [])

    def exec(self, command, timeout=None, **kw):
        argv = command if isinstance(command, list) else ["sh", "-c", command]
        self.calls.append(argv)
        joined = " ".join(argv)

        # test -e <path> → file-existence checks for detection
        if argv[:1] == ["test"] and "-e" in argv:
            path = argv[-1]
            rel = path.split("/workspace/", 1)[-1]
            return _Exec(exit_code=0 if rel in self._existing else 1)

        for needle, result in self._responder.items():
            if needle in joined:
                return result
        return _Exec(exit_code=0, stdout="")


class TestDetectLaunch:
    def test_detects_django(self):
        sb = FakeSandbox(existing_files={"manage.py"})
        h = AppHarness(sb)
        recipe = h.detect_launch(port=8000)
        assert recipe is not None
        assert recipe.kind == "django"
        assert "manage.py runserver 127.0.0.1:8000" in recipe.command

    def test_detects_php_public_docroot(self):
        sb = FakeSandbox(existing_files={"public/index.php"})
        h = AppHarness(sb)
        recipe = h.detect_launch()
        assert recipe is not None
        assert recipe.kind == "php"
        assert "-t public" in recipe.command

    def test_detects_php_root(self):
        sb = FakeSandbox(existing_files={"index.php"})
        h = AppHarness(sb)
        recipe = h.detect_launch()
        assert recipe is not None and recipe.kind == "php"

    def test_no_recipe_when_nothing_recognized(self):
        sb = FakeSandbox(existing_files=set())
        h = AppHarness(sb)
        assert h.detect_launch() is None

    def test_node_entry_point(self):
        sb = FakeSandbox(existing_files={"server.js"})
        h = AppHarness(sb)
        recipe = h.detect_launch()
        assert recipe is not None and recipe.kind == "node"
        assert "node server.js" in recipe.command


class TestLaunch:
    def test_launch_reports_up_on_http_code(self):
        sb = FakeSandbox(
            responder={
                "echo $!": _Exec(exit_code=0, stdout="4242\n"),
                "seq 1": _Exec(exit_code=0, stdout="UP:200\n"),
            },
            existing_files={"index.php"},
        )
        h = AppHarness(sb)
        assert h.launch() is True
        assert h._port == 8000  # noqa: SLF001 - asserting internal readiness state
        # The detached launch must use setsid and redirect to the scratch log.
        launch_calls = [" ".join(c) for c in sb.calls if "setsid" in " ".join(c)]
        assert launch_calls and "/scratch/app_harness.log" in launch_calls[0]

    def test_launch_reports_down_when_never_ready(self):
        sb = FakeSandbox(
            responder={
                "echo $!": _Exec(exit_code=0, stdout="4242\n"),
                "seq 1": _Exec(exit_code=1, stdout="DOWN\n"),
            },
        )
        h = AppHarness(sb)
        recipe = LaunchRecipe(kind="custom", command="php -S 127.0.0.1:8000", port=8000)
        assert h.launch(recipe) is False

    def test_launch_returns_false_without_recipe(self):
        sb = FakeSandbox(existing_files=set())
        h = AppHarness(sb)
        assert h.launch() is False


class TestRequest:
    def _launched(self, request_stdout: str) -> AppHarness:
        sb = FakeSandbox(
            responder={
                "echo $!": _Exec(exit_code=0, stdout="1\n"),
                "seq 1": _Exec(exit_code=0, stdout="UP:200\n"),
                "curl -s -i": _Exec(exit_code=0, stdout=request_stdout),
            },
        )
        h = AppHarness(sb)
        h.launch(LaunchRecipe(kind="custom", command="x", port=8000))
        return h

    def test_request_parses_status_and_body(self):
        raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: php\r\n\r\n<b>admin</b> row leaked"
        h = self._launched(raw)
        res = h.request("/search?q=1' OR '1'='1")
        assert res.ok is True
        assert res.status_code == 200
        assert res.headers["content-type"] == "text/html"
        assert "row leaked" in res.body

    def test_request_keeps_last_status_block_on_redirect_chain(self):
        raw = (
            "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
            'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
        )
        h = self._launched(raw)
        res = h.request("/")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/json"

    def test_request_before_launch_is_error(self):
        sb = FakeSandbox()
        h = AppHarness(sb)
        res = h.request("/")
        assert res.ok is False
        assert "not launched" in res.error

    def test_request_builds_method_headers_body(self):
        h = self._launched("HTTP/1.1 200 OK\r\n\r\nok")
        h.request(
            "/login",
            method="post",
            headers={"Cookie": "s=1"},
            body="user=admin",
        )
        curl_calls = [c for c in h._sb.calls if c[:1] == ["curl"]]  # noqa: SLF001
        assert curl_calls
        argv = curl_calls[-1]
        assert "-X" in argv and "POST" in argv
        assert "-H" in argv and "Cookie: s=1" in argv
        assert "--data-binary" in argv and "user=admin" in argv


class TestParse:
    def test_parse_no_status_line_is_body_only(self):
        res = AppHarness._parse_curl_i("just some text, no HTTP line")
        assert res.ok is True
        assert res.status_code is None
        assert "just some text" in res.body

    def test_parse_empty(self):
        res = AppHarness._parse_curl_i("")
        assert res.ok is False


class TestStop:
    def test_stop_kills_process_group(self):
        sb = FakeSandbox(
            responder={
                "echo $!": _Exec(exit_code=0, stdout="9999\n"),
                "seq 1": _Exec(exit_code=0, stdout="UP:200\n"),
            },
        )
        h = AppHarness(sb)
        h.launch(LaunchRecipe(kind="custom", command="x", port=8000))
        h.stop()
        kill_calls = [" ".join(c) for c in sb.calls if "kill" in " ".join(c)]
        assert kill_calls and "-9999" in kill_calls[-1]
        assert h._port is None  # noqa: SLF001


def test_http_result_summary():
    r = HttpResult(
        ok=True, status_code=500, headers={"content-type": "text/html"}, body="SQL error"
    )
    s = r.summary()
    assert "HTTP 500" in s and "SQL error" in s
    bad = HttpResult(ok=False, status_code=None, error="connection refused")
    assert "connection refused" in bad.summary()


# --- N1 enablers: PHP image/recipe detection + exploit-tool wiring -----------


class TestPhpBuilderSupport:
    def test_composer_json_detects_php(self, tmp_path):
        from acuario.sandbox.builders import BuildSystemDetector

        (tmp_path / "composer.json").write_text("{}")
        recipe = BuildSystemDetector.detect(str(tmp_path))
        assert recipe.primary_language == "php"
        assert "php" in recipe.base_image

    def test_php_file_mix_detects_php(self, tmp_path):
        from acuario.sandbox.builders import BuildSystemDetector

        (tmp_path / "index.php").write_text("<?php echo 1;")
        (tmp_path / "db.php").write_text("<?php echo 2;")
        recipe = BuildSystemDetector.detect(str(tmp_path))
        assert recipe.primary_language == "php"

    def test_php_image_in_defaults(self):
        from acuario.sandbox.builders import DEFAULT_BASE_IMAGES

        assert DEFAULT_BASE_IMAGES["php"].startswith("php:")


class TestExploitToolWiring:
    def test_exploit_tools_include_harness_tools(self):
        from unittest.mock import MagicMock

        from acuario.agent.tools.hunt.exploit_tools import build_exploit_agent_tools

        ctx = MagicMock()
        ctx.findings_pool = None
        finding = {"id": "f1", "file": "app.php", "line_number": 3, "cwe": "CWE-89"}
        names = {t.name for t in build_exploit_agent_tools(ctx, finding)}
        assert {"launch_app", "http_request", "read_app_log"} <= names
        assert "record_exploit_result" in names

    def test_http_request_rejects_non_dict_headers_json(self):
        # Review fix: valid JSON that is not an object (e.g. a list) must
        # return an error, not silently send the request with no headers.
        from unittest.mock import MagicMock

        from acuario.agent.tools.hunt.exploit_tools import build_app_harness_tools

        # A harness stub that is "launched" (port set) and records requests.
        harness = MagicMock()
        harness._port = 8000
        sent = {}

        def _request(path, **kw):
            sent["called"] = True
            r = MagicMock()
            r.summary.return_value = "HTTP 200"
            return r

        harness.request.side_effect = _request

        ctx = MagicMock()
        ctx.app_harness = harness
        tools = {t.name: t for t in build_app_harness_tools(ctx)}
        http = tools["http_request"].handler

        # valid JSON list → rejected, request never sent
        out = http(path="/x", headers="[1, 2, 3]")
        assert "JSON OBJECT" in out
        assert "called" not in sent

        # valid JSON object → accepted, request sent
        http(path="/x", headers='{"Cookie": "s=1"}')
        assert sent.get("called") is True


class _ContainsSandbox:
    """Fake sandbox that models `test -e` existence AND `grep` containment,
    so detect_app_class's file-content checks resolve correctly (the shared
    FakeSandbox returns exit 0 for any unmatched grep, which would falsely
    report every dependency as present)."""

    def __init__(self, existing=None, contains=None):
        self._existing = set(existing or [])
        self._contains = set(contains or [])

    def exec(self, command, timeout=None, **kw):
        argv = command if isinstance(command, list) else ["sh", "-c", command]
        joined = " ".join(argv)
        if argv[:1] == ["test"] and "-e" in argv:
            rel = argv[-1].split("/workspace/", 1)[-1]
            return _Exec(exit_code=0 if rel in self._existing else 1)
        if "grep" in joined:
            return _Exec(exit_code=0 if any(n in joined for n in self._contains) else 1)
        return _Exec(exit_code=0)


class TestDetectAppClass:
    def test_server_when_launch_recipe_exists(self):
        h = AppHarness(FakeSandbox(existing_files={"manage.py"}))
        assert h.detect_app_class() == "server"

    def test_spa_build_plus_framework_no_server(self):
        sb = _ContainsSandbox(existing={"package.json"}, contains={'"build"', "react"})
        assert AppHarness(sb).detect_app_class() == "spa"

    def test_not_spa_when_a_server_dep_is_present(self):
        # Conservative: a build + framework + express means it may be server-
        # rendered; never deny it a live launch by mislabeling it SPA.
        sb = _ContainsSandbox(existing={"package.json"}, contains={'"build"', "react", "express"})
        assert AppHarness(sb).detect_app_class() == "unknown"

    def test_unknown_without_package_json(self):
        assert AppHarness(_ContainsSandbox(existing=set())).detect_app_class() == "unknown"

    def test_not_spa_without_build_step(self):
        sb = _ContainsSandbox(existing={"package.json"}, contains={"react"})  # no "build"
        assert AppHarness(sb).detect_app_class() == "unknown"
