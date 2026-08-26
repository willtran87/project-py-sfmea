from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from pysfmea.sandbox_policy import resolve_sandbox_engine, sandbox_command


class SandboxPolicyTests(unittest.TestCase):
    def test_engine_resolution_is_allowlisted_and_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "auto, docker, or podman"):
            resolve_sandbox_engine("shell")
        with mock.patch("pysfmea.sandbox_policy.shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "no Docker or Podman"):
                resolve_sandbox_engine("auto")
        with mock.patch(
            "pysfmea.sandbox_policy.shutil.which",
            side_effect=lambda value: "/usr/bin/podman" if value == "podman" else None,
        ):
            self.assertEqual(resolve_sandbox_engine("auto"), "/usr/bin/podman")

    def test_command_validation_rejects_unsafe_or_unbounded_inputs(self) -> None:
        base = {
            "engine_path": "/usr/bin/docker",
            "container_name": "sfmea-test",
            "repository": Path("/repo"),
            "evidence_directory": Path("/evidence"),
            "image": "python:3.14",
            "command_argv": ["pytest"],
            "cpus": 1.0,
            "memory_mb": 512,
            "pids_limit": 128,
        }
        for field, value, message in (
            ("image", "bad image", "image reference"),
            ("cpus", 0.0, "CPU limit"),
            ("memory_mb", 64, "memory limit"),
            ("pids_limit", 2, "process limit"),
            ("command_argv", [], "command argv"),
            ("command_argv", ["bad\x00arg"], "command argv"),
        ):
            case = {**base, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                sandbox_command(**case)  # type: ignore[arg-type]

    def test_docker_and_podman_commands_enforce_policy_and_sandbox_marker(self) -> None:
        common = {
            "container_name": "sfmea-test",
            "repository": Path("/repo"),
            "evidence_directory": Path("/evidence"),
            "image": "python:3.14",
            "command_argv": ["python", "-m", "pytest"],
            "cpus": 1.0,
            "memory_mb": 512,
            "pids_limit": 128,
        }
        docker = sandbox_command(engine_path="/usr/bin/docker", **common)
        podman = sandbox_command(
            engine_path="/usr/bin/podman",
            **{**common, "command_argv": ["python", "check.py"]},
        )
        self.assertIn("--pull", docker)
        self.assertIn("never", docker)
        self.assertIn("--pull=never", podman)
        self.assertIn("no-new-privileges:true", docker)
        self.assertIn("no-new-privileges", podman)
        self.assertIn("PYSFMEA_APPROVED_SANDBOX=1", docker)
        self.assertIn("--junitxml=/evidence/junit.xml", docker)
        self.assertNotIn("--junitxml=/evidence/junit.xml", podman)


if __name__ == "__main__":
    unittest.main()
