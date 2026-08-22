from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.pull_request import analyze_pull_request, verify_pull_request_analysis
from pysfmea.schemas import schema_document


@unittest.skipUnless(shutil.which("git"), "Git is required")
class PullRequestAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self._git("init")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Test Reviewer")
        source = self.repo / "service.py"
        source.write_text("def fetch():\n    return 1\n", encoding="utf-8")
        self._git("add", "service.py")
        self._git("commit", "-m", "base")
        self.base = self._git("rev-parse", "HEAD")
        source.write_text(
            "def fetch(client):\n    return client.get('/status')\n", encoding="utf-8"
        )
        self._git("add", "service.py")
        self._git("commit", "-m", "head")
        self.head = self._git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def test_exact_commits_create_bound_bundle_without_mutating_worktree(self) -> None:
        before = self._git("status", "--porcelain=v1")
        output = self.root / "pr-review"

        result = analyze_pull_request(
            self.repo, base=self.base, head=self.head, output=output
        )

        self.assertEqual(result, output)
        self.assertEqual(self._git("status", "--porcelain=v1"), before)
        receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("pull-request-analysis")).validate(receipt)
        self.assertEqual(receipt["base"]["commit"], self.base)
        self.assertEqual(receipt["head"]["commit"], self.head)
        self.assertFalse(receipt["security"]["repository_code_executed"])
        for name in (
            "base-analysis.json",
            "head-analysis.json",
            "differential-analysis.json",
            "base-report.html",
            "head-report.html",
        ):
            self.assertIn(name, receipt["artifacts"])
            self.assertTrue((output / name).is_file())
        verification = verify_pull_request_analysis(output)
        Draft202012Validator(
            schema_document("pull-request-analysis-verification")
        ).validate(verification)
        self.assertTrue(verification["valid"])
        self.assertTrue(all(verification["checks"].values()))
        command_output = io.StringIO()
        with contextlib.redirect_stdout(command_output):
            status = main(["pr-verify", str(output), "--json"])
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(command_output.getvalue())["valid"])

        diff_path = output / "differential-analysis.json"
        diff_path.write_text("{}", encoding="utf-8")
        rejected = verify_pull_request_analysis(output)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["artifact_integrity"])
        self.assertFalse(rejected["checks"]["differential_regeneration"])

    def test_rejects_option_like_refs_and_existing_destination(self) -> None:
        with self.assertRaisesRegex(ValueError, "base ref"):
            analyze_pull_request(
                self.repo,
                base="--help",
                head=self.head,
                output=self.root / "invalid",
            )
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaises(FileExistsError):
            analyze_pull_request(
                self.repo, base=self.base, head=self.head, output=existing
            )

        unavailable = verify_pull_request_analysis(self.root / "missing-bundle")
        self.assertFalse(unavailable["valid"])
        Draft202012Validator(
            schema_document("pull-request-analysis-verification")
        ).validate(unavailable)


if __name__ == "__main__":
    unittest.main()
