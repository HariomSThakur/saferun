from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.middleware.trustedhost import TrustedHostMiddleware

from saferun.checks.static import run_static_check
from saferun.config import Settings
from saferun.models import DetectedProject, PlannedCheck
import saferun.runner.session as sandbox


class SecretScannerTests(unittest.TestCase):
    def test_ignores_environment_references_and_placeholders_but_finds_literals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="saferun-secret-test-", dir=Path.cwd()) as temp:
            root = Path(temp)
            (root / "cases.txt").write_text(
                "\n".join(
                    [
                        'password = os.environ.get("DB_PASSWORD")',
                        "API_KEY = process.env.SERVICE_KEY",
                        '{"password": "your_password_here"}',
                        '{"password": "tR9$unique-password-value-731"}',
                        '{"aws_secret_access_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012345678"}',
                        'DATABASE_URL = "postgres://service:longPass_98@db.internal/app"',
                        'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
                    ]
                ),
                encoding="utf-8",
            )
            check = PlannedCheck("secrets.scan", "Likely secret scan", True, "", "static")

            result = run_static_check(check, root, DetectedProject())

        self.assertEqual(result.status, "failed")
        self.assertEqual(
            {item["kind"] for item in result.evidence},
            {"Credential assignment", "AWS secret key", "Database URL credentials"},
        )
        self.assertEqual(len(result.evidence), 3)
        self.assertNotIn("tR9$unique-password-value-731", json.dumps(result.to_dict()))
        self.assertEqual(
            {item["confidence"] for item in result.evidence}, {"medium", "high"}
        )


class TrustedHostTests(unittest.TestCase):
    def test_accepts_loopback_and_rejects_foreign_hosts(self) -> None:
        async def response_status(host: str) -> int:
            messages = []

            async def app(scope, receive, send):
                await send({"type": "http.response.start", "status": 204, "headers": []})

            middleware = TrustedHostMiddleware(
                app, allowed_hosts=["localhost", "127.0.0.1", "[::1]"]
            )
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "headers": [(b"host", host.encode())],
                "server": ("127.0.0.1", 8000),
                "client": ("127.0.0.1", 1),
                "root_path": "",
            }

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                messages.append(message)

            await middleware(scope, receive, send)
            return next(
                message["status"]
                for message in messages
                if message["type"] == "http.response.start"
            )

        self.assertEqual(asyncio.run(response_status("localhost:8000")), 204)
        self.assertEqual(asyncio.run(response_status("attacker.example")), 400)


class SandboxSetupBoundaryTests(unittest.TestCase):
    def test_project_paths_are_added_only_after_network_disconnect(self) -> None:
        cases = [
            ("python", "python.tests", None),
            (
                "node",
                "node.test",
                '{"name":"demo","scripts":{"test":"node --test"}}',
            ),
        ]
        for ecosystem, check_id, manifest in cases:
            with self.subTest(ecosystem=ecosystem):
                with tempfile.TemporaryDirectory(
                    prefix="saferun-runner-test-", dir=Path.cwd()
                ) as temp:
                    root = Path(temp)
                    if manifest:
                        (root / "package.json").write_text(manifest, encoding="utf-8")
                    calls: list[list[str]] = []

                    def bounded_command(args, timeout, output_limit):
                        calls.append(args)
                        output = "{}" if "inspect" in args else ""
                        return 0, output, False

                    settings = Settings(data_dir=root / "data")
                    with (
                        patch.object(sandbox, "_docker_executable", return_value="docker-stub"),
                        patch.object(sandbox, "_ensure_image", return_value=(True, "")),
                        patch.object(sandbox, "_bounded_command", side_effect=bounded_command),
                    ):
                        session = sandbox.start_sandbox_session(
                            root,
                            DetectedProject(),
                            settings,
                            "a" * 32,
                            ecosystem,
                            {check_id},
                        )
                        self.assertTrue(session.ready, session.message)
                        disconnect_index = next(
                            index
                            for index, args in enumerate(calls)
                            if args[1:3] == ["network", "disconnect"]
                        )
                        setup_calls = calls[:disconnect_index]
                        self.assertTrue(
                            all(
                                "--workdir" in args
                                and args[args.index("--workdir") + 1] == "/tmp"
                                for args in setup_calls
                                if len(args) > 1 and args[1] == "exec"
                            )
                        )
                        run_args = calls[0]
                        self.assertEqual(run_args[run_args.index("--workdir") + 1], "/tmp")
                        self.assertFalse(
                            any(
                                value.startswith(
                                    ("PYTHONPATH=", "NODE_PATH=", "PATH=/deps/project")
                                )
                                for value in run_args
                            )
                        )
                        if ecosystem == "python":
                            self.assertIn("-I", calls[1])
                            self.assertIn("-I", calls[2])
                        else:
                            self.assertFalse(
                                any("npm install" in " ".join(args) for args in setup_calls),
                                "A package-free Node project must not contact npm during setup.",
                            )
                            self.assertNotIn(
                                "node_modules/.bin",
                                " ".join(value for args in setup_calls for value in args),
                            )

                        check = PlannedCheck(check_id, check_id, True, "", "sandbox")
                        code, _, timed_out, reason = sandbox.run_in_sandbox(
                            check, root, DetectedProject(), session, settings
                        )
                        self.assertEqual((code, timed_out, reason), (0, False, ""))
                        self.assertTrue(
                            any(
                                value in {
                                    "PYTHONPATH=/deps/python:/deps/project",
                                    "NODE_PATH=/deps/project/node_modules",
                                }
                                for value in calls[-1]
                            )
                        )


if __name__ == "__main__":
    unittest.main()
