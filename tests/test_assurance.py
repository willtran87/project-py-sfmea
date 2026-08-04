from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance import (
    export_assurance_register,
    export_pytest_scaffold,
    refresh_assurance_register,
    review_obligation,
)
from pysfmea.execution import (
    import_execution_evidence,
    register_test_implementation,
    review_execution_evidence,
    run_sandbox_execution,
    sandbox_command,
)
from pysfmea.cli import main
from pysfmea.html_report import build_html_report_data, export_html_report
from pysfmea.report import export_review_package, verify_review_package
from pysfmea.scanner import scan_repository
from pysfmea.store import load_analysis, merge_rescan, save_analysis
from pysfmea.validation import validate_analysis


class AssuranceRegisterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def divide(value):\n    return 100 / value\n\n"
            "def publish(client, payload):\n    return client.send(payload)\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_every_finding_gets_a_stable_automation_ready_obligation(self) -> None:
        obligations = self.analysis["assurance"]["obligations"]
        active = [
            item
            for item in self.analysis["items"]
            if item.get("source_status", "active") == "active"
        ]
        self.assertEqual(len(obligations), len(active))
        self.assertEqual(
            {value["finding_id"] for value in obligations},
            {value["id"] for value in active},
        )
        obligation = obligations[0]
        self.assertTrue(obligation["acceptance_criteria"])
        self.assertTrue(obligation["oracles"])
        self.assertEqual(
            obligation["automation"]["execution_policy"],
            "approved_sandbox_required",
        )
        self.assertEqual(
            obligation["automation"]["implementation_status"], "not_implemented"
        )
        self.assertEqual(obligation["evidence_status"], "missing")
        original_ids = [value["id"] for value in obligations]
        refresh_assurance_register(self.analysis, self.analysis["assurance"])
        self.assertEqual(
            original_ids,
            [value["id"] for value in self.analysis["assurance"]["obligations"]],
        )

    def test_register_exports_cli_scaffold_html_and_package(self) -> None:
        json_path = export_assurance_register(
            self.analysis, self.root / "assurance.json", format="json"
        )
        csv_path = export_assurance_register(
            self.analysis, self.root / "assurance.csv", format="csv"
        )
        markdown_path = export_assurance_register(
            self.analysis, self.root / "assurance.md", format="markdown"
        )
        self.assertTrue(json.loads(json_path.read_text(encoding="utf-8"))["obligations"])
        with csv_path.open(encoding="utf-8-sig", newline="") as handle:
            self.assertTrue(list(csv.DictReader(handle)))
        self.assertIn(
            "Executable assurance checklist",
            markdown_path.read_text(encoding="utf-8"),
        )

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "assurance",
                        str(analysis_path),
                        "--format",
                        "json",
                    ]
                ),
                0,
            )
        self.assertTrue((self.root / "analysis.assurance.json").is_file())

        scaffold = export_pytest_scaffold(
            self.analysis, self.root / "assurance-tests", limit=2
        )
        manifest = json.loads(
            (scaffold / "assurance-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["obligations"]), 2)
        generated_test = (scaffold / "test_sfmea_assurance.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("pytest.fail", generated_test)
        self.assertNotIn("pytest.skip", generated_test)

        payload = build_html_report_data(self.analysis)
        self.assertEqual(
            payload["assurance"]["summary"]["active_obligations"],
            len(self.analysis["items"]),
        )
        report = export_html_report(self.analysis, self.root / "report.html")
        document = report.read_text(encoding="utf-8")
        self.assertIn('data-view="assurance"', document)
        self.assertIn("Executable assurance checklist", document)

        package = export_review_package(self.analysis, self.root / "package")
        self.assertTrue((package / "assurance-register.json").is_file())
        self.assertTrue(verify_review_package(package)["valid"])

    def test_review_is_preserved_and_privileged_states_are_guarded(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        with self.assertRaisesRegex(ValueError, "cannot directly set"):
            review_obligation(
                self.analysis,
                obligation["id"],
                status="verified",
                reviewer="Morgan",
                rationale="A test passed.",
            )
        review_obligation(
            self.analysis,
            obligation["id"],
            status="verification_planned",
            reviewer="Morgan",
            rationale="The acceptance criteria are ready for implementation.",
            owner="Riley",
        )
        path = self.root / "analysis.json"
        save_analysis(path, self.analysis)
        loaded = load_analysis(path)
        retained = next(
            value
            for value in loaded["assurance"]["obligations"]
            if value["id"] == obligation["id"]
        )
        self.assertEqual(retained["assurance_status"], "verification_planned")
        self.assertEqual(retained["review"]["owner"], "Riley")

        merged = merge_rescan(loaded, scan_repository(self.root))
        retained = next(
            value
            for value in merged["assurance"]["obligations"]
            if value["id"] == obligation["id"]
        )
        self.assertEqual(retained["assurance_status"], "verification_planned")

    def test_validation_rejects_missing_and_unsupported_assurance(self) -> None:
        obligation = self.analysis["assurance"]["obligations"].pop()
        findings = validate_analysis(self.analysis)["findings"]
        self.assertIn(
            "assurance.obligation_cardinality",
            {value["rule_id"] for value in findings},
        )
        self.analysis["assurance"]["obligations"].append(obligation)
        obligation["assurance_status"] = "verified"
        obligation["evidence_status"] = "missing"
        findings = validate_analysis(self.analysis)["findings"]
        self.assertIn(
            "assurance.unsupported_verification",
            {value["rule_id"] for value in findings},
        )

    def test_sandbox_command_has_mandatory_isolation_controls(self) -> None:
        command = sandbox_command(
            engine_path="docker",
            container_name="pysfmea-exec-test",
            repository=self.root,
            evidence_directory=self.root / "evidence",
            image="approved@sha256:" + "a" * 64,
            command_argv=["python", "-m", "pytest", "tests/test_assurance.py", "-q"],
            cpus=1.0,
            memory_mb=512,
            pids_limit=64,
        )
        self.assertIn("none", command[command.index("--network") + 1 :])
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("ALL", command)
        self.assertIn("65534:65534", command)
        self.assertIn("--pull", command)
        self.assertIn("never", command)
        self.assertIn("--entrypoint", command)
        self.assertEqual(command[command.index("--entrypoint") + 1], "python")
        self.assertIn("--junitxml=/evidence/junit.xml", command)

    def test_execution_evidence_requires_independent_criterion_review(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        test_path = self.root / "test_assurance_control.py"
        test_path.write_text(
            "def test_control():\n    assert True\n", encoding="utf-8"
        )
        register_test_implementation(
            self.analysis,
            obligation["id"],
            test_path=test_path.name,
            author="Implementation Agent",
            origin="llm_generated",
        )

        def fake_command(**kwargs: object) -> list[str]:
            evidence = Path(str(kwargs["evidence_directory"]))
            junit = (
                '<testsuite tests="1" failures="0" errors="0" skipped="0" time="0.1">'
                '<testcase name="test_control" time="0.1"/></testsuite>'
            )
            source = (
                "from pathlib import Path; "
                f"Path({str(evidence / 'junit.xml')!r}).write_text({junit!r}, encoding='utf-8'); "
                "print('failure stimulus and assertions executed')"
            )
            return [sys.executable, "-c", source]

        recorded_vcs = self.analysis["project"]["baseline"].get("vcs", {})
        with (
            mock.patch("pysfmea.execution._resolve_engine", return_value="fake-docker"),
            mock.patch(
                "pysfmea.execution._git_state", return_value=recorded_vcs
            ),
            mock.patch(
                "pysfmea.execution.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=0, stdout="sha256:approved-image\n", stderr=""
                ),
            ),
            mock.patch("pysfmea.execution.sandbox_command", side_effect=fake_command),
        ):
            execution = run_sandbox_execution(
                self.analysis,
                obligation["id"],
                image="approved@sha256:" + "b" * 64,
                initiated_by="Execution Agent",
                evidence_root=self.root / "evidence",
                approved=True,
                allow_dirty=True,
                timeout_seconds=30,
            )
        self.assertEqual(execution["status"], "passed")
        self.assertEqual(execution["result"]["junit"]["tests"], 1)
        self.assertEqual(len(execution["artifacts"]), 3)
        self.assertEqual(obligation["evidence_status"], "collected_unreviewed")

        criterion_results = {
            index: "pass"
            for index, _value in enumerate(
                obligation["acceptance_criteria"], start=1
            )
        }
        with self.assertRaisesRegex(ValueError, "independent"):
            review_execution_evidence(
                self.analysis,
                execution["id"],
                reviewer="Execution Agent",
                decision="sufficient",
                rationale="Self-review is prohibited.",
                stimulus_observed=True,
                criterion_results=criterion_results,
            )
        review = review_execution_evidence(
            self.analysis,
            execution["id"],
            reviewer="Independent Reviewer",
            decision="sufficient",
            rationale="The stimulus was observed and every pre-existing criterion is supported.",
            stimulus_observed=True,
            criterion_results=criterion_results,
        )
        self.assertTrue(review["artifact_integrity_valid"])
        self.assertEqual(obligation["evidence_status"], "sufficient")
        self.assertEqual(obligation["assurance_status"], "verified")
        rules = {value["rule_id"] for value in validate_analysis(self.analysis)["findings"]}
        self.assertNotIn("assurance.unsupported_verification", rules)

    def test_external_evidence_is_copied_hashed_idempotent_and_unreviewed(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        test_path = self.root / "test_external_control.py"
        test_path.write_text("def test_control():\n    assert True\n", encoding="utf-8")
        source = self.root / "ci-evidence"
        source.mkdir()
        log = source / "pytest.log"
        log.write_text("1 passed; failure stimulus observed\n", encoding="utf-8")
        manifest = {
            "schema_version": "1.0",
            "baseline_id": self.analysis["project"]["baseline"]["id"],
            "repository_revision": self.analysis["project"]["baseline"]
            .get("vcs", {})
            .get("revision", ""),
            "repository_dirty": False,
            "test": {
                "path": test_path.name,
                "sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
            },
            "command_argv": ["python", "-m", "pytest", test_path.name, "-q"],
            "status": "passed",
            "exit_code": 0,
            "environment": {"python": "3.11", "runner": "approved-ci"},
            "artifacts": [
                {
                    "kind": "execution_log",
                    "path": log.name,
                    "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                }
            ],
        }
        manifest_path = source / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        execution = import_execution_evidence(
            self.analysis,
            obligation["id"],
            manifest_path=manifest_path,
            evidence_root=self.root / "managed-evidence",
            initiated_by="CI Import Agent",
        )
        repeated = import_execution_evidence(
            self.analysis,
            obligation["id"],
            manifest_path=manifest_path,
            evidence_root=self.root / "managed-evidence",
            initiated_by="CI Import Agent",
        )
        self.assertEqual(execution["id"], repeated["id"])
        self.assertEqual(execution["execution_mode"], "external_import")
        self.assertEqual(execution["import_trust"], "externally_supplied_unattested")
        self.assertEqual(len(self.analysis["assurance"]["executions"]), 1)
        self.assertEqual(obligation["evidence_status"], "collected_unreviewed")
        copied = Path(execution["evidence_directory"]) / "artifact-001-execution_log.log"
        self.assertEqual(copied.read_bytes(), log.read_bytes())
        statement = Path(execution["evidence_directory"]) / "execution.json"
        saved = json.loads(statement.read_text(encoding="utf-8"))
        saved["status"] = "failed"
        statement.write_text(json.dumps(saved), encoding="utf-8")
        criteria = {
            index: "pass"
            for index, _value in enumerate(obligation["acceptance_criteria"], start=1)
        }
        with self.assertRaisesRegex(ValueError, "intact artifacts"):
            review_execution_evidence(
                self.analysis,
                execution["id"],
                reviewer="Independent Reviewer",
                decision="sufficient",
                rationale="This should fail because the execution statement was changed.",
                stimulus_observed=True,
                criterion_results=criteria,
            )


if __name__ == "__main__":
    unittest.main()
