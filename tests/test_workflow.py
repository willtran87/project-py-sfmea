from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance import export_pytest_scaffold
from pysfmea.cli import main
from pysfmea.config import load_config, write_config_template
from pysfmea.html_report import export_html_report
from pysfmea.integrity import verify_run_manifest_integrity
from pysfmea.report import (
    REVIEW_PACKAGE_FILES,
    REVIEW_PACKAGE_SCHEMA_FILES,
    export_review_archive,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis, update_item_review
from pysfmea.workflow import WORKFLOW_STATUS_FORMAT, workflow_status


class WorkflowStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "app.py").write_text(
            "def authorize(actor, request):\n    return bool(actor and request)\n",
            encoding="utf-8",
        )
        self.config_path = self.root / "sfmea.toml"
        write_config_template(self.config_path)
        source = self.config_path.read_text(encoding="utf-8")
        source = source.replace("Example Python System", "Authorization Service")
        source = source.replace(
            "Example unacceptable system condition", "Unauthorized operation"
        )
        source = source.replace("Example reviewer", "Safety Reviewer")
        source = source.replace("Example team", "Assurance Team")
        source = source.replace("src/example/payment.py", "app.py")
        source = source.replace("src/example/refund.py", "app.py")
        self.config_path.write_text(source, encoding="utf-8")
        self.analysis_path = self.root / "sfmea-analysis.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _scan(self) -> dict:
        config, _ = load_config(self.config_path)
        analysis = scan_repository(self.root, config=config)
        save_analysis(self.analysis_path, analysis)
        return analysis

    def test_status_moves_from_ready_to_scan_to_engineering_review(self) -> None:
        before = workflow_status(self.root)
        self.assertEqual(before["format"], WORKFLOW_STATUS_FORMAT)
        self.assertEqual(before["stage"], "ready_to_scan")
        self.assertTrue(before["readiness"]["ready"])
        self.assertFalse(before["analysis"]["exists"])
        self.assertEqual(before["next_actions"][0]["id"], "scan_repository")
        self.assertEqual(
            [gate["id"] for gate in before["handoff_gates"]],
            [
                "repository_ready",
                "analysis_available",
                "validation_clear",
                "findings_reviewed",
                "revalidation_clear",
                "assurance_plan_ready",
                "report_current",
                "package_current",
            ],
        )
        before_gates = {gate["id"]: gate for gate in before["handoff_gates"]}
        self.assertTrue(before_gates["repository_ready"]["passed"])
        self.assertFalse(before_gates["analysis_available"]["passed"])
        self.assertEqual(
            before_gates["analysis_available"]["remediation_action_id"],
            "scan_repository",
        )
        self.assertEqual(
            before["handoff_gate_summary"],
            {"total": 8, "passed": 1, "blocked": 7},
        )
        self.assertEqual(
            before["ready_for_handoff"],
            before["handoff_gate_summary"]["blocked"] == 0,
        )
        available_actions = {action["id"] for action in before["next_actions"]}
        for gate in before["handoff_gates"]:
            if not gate["passed"]:
                self.assertIn(gate["remediation_action_id"], available_actions)

    def test_public_cli_scan_publishes_an_integrity_valid_final_manifest(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pysfmea",
                "scan",
                str(self.root),
                "--config",
                str(self.config_path),
                "--fresh",
                "--output",
                str(self.analysis_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        analysis = load_analysis(self.analysis_path)
        verification = verify_run_manifest_integrity(analysis)
        self.assertTrue(verification["valid"], verification["failures"])
        settings = analysis["project"]["settings"]
        self.assertEqual(settings["config_file"], str(self.config_path.resolve()))
        self.assertEqual(settings["analysis_serialization"], "compact")
        self.assertEqual(
            len(self.analysis_path.read_text(encoding="utf-8").splitlines()), 1
        )
        self.assertGreater(settings["fact_cache"]["run"]["misses"], 0)
        self.assertEqual(settings["fact_cache"]["output"]["status"], "published")
        self.assertFalse(analysis["run_manifest"]["cache"]["used"])
        self.assertGreater(analysis["run_manifest"]["cache"]["entries_recomputed"], 0)
        self.assertIsNot(
            analysis["run_manifest"]["tool"]["settings"],
            settings,
        )

        warm = subprocess.run(
            [
                sys.executable,
                "-m",
                "pysfmea",
                "scan",
                str(self.root),
                "--config",
                str(self.config_path),
                "--fresh",
                "--output",
                str(self.analysis_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(warm.returncode, 0, warm.stderr)
        self.assertIn("Fact cache: hits=", warm.stdout)
        warmed_analysis = load_analysis(self.analysis_path)
        self.assertGreater(
            warmed_analysis["project"]["settings"]["fact_cache"]["run"]["hits"], 0
        )
        self.assertTrue(warmed_analysis["run_manifest"]["cache"]["used"])
        self.assertGreater(
            warmed_analysis["run_manifest"]["cache"]["entries_reused"], 0
        )
        self.assertTrue(verify_run_manifest_integrity(warmed_analysis)["valid"])

    def test_public_cli_requires_explicit_discovery_only_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "app.py").write_text(
                "def run(value):\n    return value\n", encoding="utf-8"
            )
            output = repository / "analysis.json"
            command = [
                sys.executable,
                "-m",
                "pysfmea",
                "scan",
                str(repository),
                "--fresh",
                "--output",
                str(output),
            ]
            refused = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(refused.returncode, 2)
            self.assertIn("--allow-ungoverned", refused.stderr)
            self.assertFalse(output.exists())

            allowed = subprocess.run(
                [*command, "--allow-ungoverned"],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            self.assertIn("DISCOVERY ONLY", allowed.stdout)
            analysis = load_analysis(output)
            self.assertEqual(
                analysis["project"]["settings"]["governance_mode"],
                "discovery_only",
            )
            self.assertIn(
                "UngovernedScan",
                {warning.get("type") for warning in analysis["warnings"]},
            )
            self.assertTrue(verify_run_manifest_integrity(analysis)["valid"])

        analysis = self._scan()
        after = workflow_status(self.root)
        self.assertEqual(after["stage"], "engineering_review")
        self.assertEqual(
            after["analysis"]["baseline_id"],
            analysis["project"]["baseline"]["id"],
        )
        self.assertGreater(after["analysis"]["counts"]["unreviewed"], 0)
        self.assertEqual(after["artifacts"]["html_report"]["status"], "missing")
        self.assertIn(
            "review_findings", [value["id"] for value in after["next_actions"]]
        )
        available_actions = {action["id"] for action in after["next_actions"]}
        for gate in after["handoff_gates"]:
            if not gate["passed"]:
                self.assertIn(gate["remediation_action_id"], available_actions)

    def test_read_only_scan_never_writes_inside_target_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            repository = workspace / "repository"
            repository.mkdir()
            source = repository / "app.py"
            source.write_text(
                "def run(value):\n    return value\n", encoding="utf-8"
            )
            before = {
                path.relative_to(repository).as_posix(): path.read_bytes()
                for path in repository.rglob("*")
                if path.is_file()
            }
            output = workspace / "external-artifacts" / "analysis.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "scan",
                        str(repository),
                        "--allow-ungoverned",
                        "--read-only",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(status, 0)
            after = {
                path.relative_to(repository).as_posix(): path.read_bytes()
                for path in repository.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
            self.assertNotIn(".artifacts", {path.name for path in repository.iterdir()})
            analysis = load_analysis(output)
            settings = analysis["project"]["settings"]
            self.assertEqual(settings["repository_mutation_policy"], "read_only")
            self.assertFalse(settings["fact_cache"]["enabled"])
            self.assertEqual(settings["fact_cache"]["output"]["status"], "disabled")
            self.assertIn("prohibited by --read-only", stdout.getvalue())
            self.assertTrue(verify_run_manifest_integrity(analysis)["valid"])

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rejected = main(
                    [
                        "scan",
                        str(repository),
                        "--allow-ungoverned",
                        "--read-only",
                        "--output",
                        str(repository / "analysis.json"),
                    ]
                )
            self.assertEqual(rejected, 2)
            self.assertIn("outside the scanned repository", stderr.getvalue())
            self.assertFalse((repository / "analysis.json").exists())

    def test_read_only_scan_can_publish_an_explicit_external_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            repository = workspace / "repository"
            repository.mkdir()
            (repository / "app.py").write_text(
                "def run(value):\n    return value\n", encoding="utf-8"
            )
            before = {
                path.relative_to(repository).as_posix(): path.read_bytes()
                for path in repository.rglob("*")
                if path.is_file()
            }
            output = workspace / "external-artifacts" / "analysis.json"
            cache = workspace / "external-cache" / "facts.json"

            status = main(
                [
                    "scan",
                    str(repository),
                    "--allow-ungoverned",
                    "--read-only",
                    "--output",
                    str(output),
                    "--cache",
                    str(cache),
                ]
            )

            self.assertEqual(status, 0)
            self.assertTrue(output.is_file())
            self.assertTrue(cache.is_file())
            after = {
                path.relative_to(repository).as_posix(): path.read_bytes()
                for path in repository.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
            settings = load_analysis(output)["project"]["settings"]
            self.assertEqual(settings["repository_mutation_policy"], "read_only")
            self.assertTrue(settings["fact_cache"]["enabled"])
            self.assertEqual(settings["fact_cache"]["output"]["status"], "published")

    def test_unreconciled_inventory_summary_blocks_handoff(self) -> None:
        analysis = self._scan()
        analysis["repository_inventory"]["summary"]["files"] += 1
        save_analysis(self.analysis_path, analysis)

        status = workflow_status(self.root)
        validation_gate = next(
            gate for gate in status["handoff_gates"] if gate["id"] == "validation_clear"
        )
        self.assertFalse(validation_gate["passed"])
        self.assertGreaterEqual(validation_gate["evidence"]["error_count"], 1)
        self.assertEqual(validation_gate["remediation_action_id"], "validate_analysis")
        self.assertIn(
            "validate_analysis", {action["id"] for action in status["next_actions"]}
        )
        self.assertFalse(status["ready_for_handoff"])

    def test_artifact_freshness_integrity_and_exact_binding(self) -> None:
        analysis = self._scan()
        report = self.root / "sfmea-report.html"
        package = self.root / "authorization-review-package.zip"
        export_html_report(analysis, report)
        export_review_archive(
            analysis,
            package,
            source_analysis=self.analysis_path,
            portable=True,
        )
        older_than_analysis = self.analysis_path.stat().st_mtime - 10
        os.utime(report, (older_than_analysis, older_than_analysis))
        os.utime(package, (older_than_analysis, older_than_analysis))
        current = workflow_status(self.root)
        self.assertEqual(current["artifacts"]["html_report"]["status"], "current")
        self.assertEqual(
            current["artifacts"]["html_report"]["binding"]["status"], "matched"
        )
        self.assertTrue(
            current["artifacts"]["html_report"]["binding"]["checks"][
                "payload_integrity"
            ]
        )
        self.assertTrue(
            current["artifacts"]["html_report"]["binding"]["checks"][
                "document_integrity"
            ]
        )
        self.assertEqual(
            current["artifacts"]["html_report"]["binding"]["integrity_scope"],
            "document_and_payload",
        )
        self.assertEqual(current["artifacts"]["review_package"]["status"], "current")
        current_gates = {gate["id"]: gate for gate in current["handoff_gates"]}
        self.assertTrue(current_gates["report_current"]["passed"])
        self.assertTrue(current_gates["package_current"]["passed"])
        self.assertTrue(current["artifacts"]["review_package"]["integrity"]["valid"])
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
                "evidence_catalog_projection_v1",
                "guidance_traceability_projection_v1",
                "interchange_artifacts_projection_v1",
                "package_provenance_projection_v1",
                "review_views_projection_v1",
                "sfta_projection_v1",
            ],
        )
        self.assertTrue(current["artifacts"]["review_package"]["binding"]["valid"])
        self.assertEqual(
            current["artifacts"]["review_package"]["binding"]["status"],
            "matched",
        )
        self.assertFalse(current["artifacts"]["review_package"]["timestamp_current"])
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["checked_files"],
            len(REVIEW_PACKAGE_FILES | REVIEW_PACKAGE_SCHEMA_FILES),
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["schema_catalog"][
                "valid"
            ]
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["analysis_diagnostics"][
                "valid"
            ]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["analysis_diagnostics"][
                "artifact_count"
            ],
            5,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"][
                "guidance_traceability"
            ]["valid"]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"][
                "guidance_traceability"
            ]["artifact_count"],
            2,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["sfta_projection"][
                "valid"
            ]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["sfta_projection"][
                "artifact_count"
            ],
            2,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["evidence_catalog"][
                "valid"
            ]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["evidence_catalog"][
                "artifact_count"
            ],
            1,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"][
                "interchange_artifacts"
            ]["valid"]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"][
                "interchange_artifacts"
            ]["artifact_count"],
            2,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["analysis_structure"][
                "valid"
            ]
        )
        self.assertGreater(
            current["artifacts"]["review_package"]["integrity"]["analysis_structure"][
                "node_count"
            ],
            0,
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["analysis_structure"][
                "limits"
            ],
            {"max_nodes": 3_000_000, "max_depth": 100},
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["review_views"]["valid"]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["review_views"][
                "artifact_count"
            ],
            10,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["package_provenance"][
                "valid"
            ]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["package_provenance"][
                "artifact_count"
            ],
            2,
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["assurance_work_queue"][
                "valid"
            ]
        )
        self.assertEqual(
            current["artifacts"]["review_package"]["integrity"]["assurance_work_queue"][
                "status"
            ],
            "matched",
        )
        self.assertTrue(
            current["artifacts"]["review_package"]["integrity"]["assurance_register"][
                "valid"
            ]
        )
        self.assertTrue(
            all(
                current["artifacts"]["review_package"]["integrity"][
                    "assurance_register"
                ]["checks"].values()
            )
        )
        self.assertIn("does not establish", current["notice"])
        Draft202012Validator(schema_document("workflow-status")).validate(current)

        report_text = report.read_text(encoding="utf-8")
        report.write_text(
            report_text.replace(
                '"name":"Authorization Service"',
                '"name":"Authorization Servicf"',
                1,
            ),
            encoding="utf-8",
        )
        report_tampered = workflow_status(self.root)
        self.assertEqual(
            report_tampered["artifacts"]["html_report"]["status"], "invalid"
        )
        self.assertFalse(
            report_tampered["artifacts"]["html_report"]["binding"]["checks"][
                "payload_integrity"
            ]
        )
        self.assertFalse(
            report_tampered["artifacts"]["html_report"]["binding"]["checks"][
                "document_integrity"
            ]
        )
        export_html_report(analysis, report)

        analysis["items"][0]["review"]["notes"] = "Current governed review changed."
        save_analysis(self.analysis_path, analysis)
        newer = self.analysis_path.stat().st_mtime + 2
        os.utime(package, (newer, newer))
        os.utime(report, (newer, newer))
        mismatched = workflow_status(self.root)
        self.assertEqual(mismatched["artifacts"]["html_report"]["status"], "mismatched")
        self.assertFalse(
            mismatched["artifacts"]["html_report"]["binding"]["checks"][
                "analysis_state"
            ]
        )
        report_action = next(
            value
            for value in mismatched["next_actions"]
            if value["id"] == "refresh_report"
        )
        self.assertIn(f'-o "{report}"', report_action["command"])
        self.assertEqual(
            mismatched["artifacts"]["review_package"]["status"], "mismatched"
        )
        self.assertTrue(mismatched["artifacts"]["review_package"]["integrity"]["valid"])
        self.assertFalse(mismatched["artifacts"]["review_package"]["binding"]["valid"])
        self.assertFalse(
            mismatched["artifacts"]["review_package"]["binding"]["checks"][
                "analysis_state"
            ]
        )

        with zipfile.ZipFile(package) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        contents["summary.json"] += b"tampered\n"
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in contents.items():
                archive.writestr(name, raw)
        invalid = workflow_status(self.root)
        self.assertEqual(invalid["artifacts"]["review_package"]["status"], "invalid")
        self.assertFalse(invalid["artifacts"]["review_package"]["integrity"]["valid"])
        self.assertIn(
            "refresh_package", [value["id"] for value in invalid["next_actions"]]
        )
        package_action = next(
            value
            for value in invalid["next_actions"]
            if value["id"] == "refresh_package"
        )
        self.assertIn(f'-o "{package}"', package_action["command"])
        self.assertIn("--force", package_action["command"])

        export_html_report(analysis, report)
        older = self.analysis_path.stat().st_mtime - 10
        os.utime(report, (older, older))
        exact = workflow_status(self.root)
        self.assertEqual(exact["artifacts"]["html_report"]["status"], "current")
        self.assertFalse(exact["artifacts"]["html_report"]["timestamp_current"])
        self.assertNotIn(
            "refresh_report", [value["id"] for value in exact["next_actions"]]
        )

    def test_cli_text_and_json_outputs_are_actionable(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as text_output:
            result = main(["status", str(self.root)])
        self.assertEqual(result, 0)
        self.assertIn("Workflow stage: ready to scan", text_output.getvalue())
        self.assertIn("Handoff gates: passed=1/8, blocked=7", text_output.getvalue())
        self.assertIn("[BLOCKED] Governed analysis available", text_output.getvalue())
        self.assertIn("Next actions:", text_output.getvalue())
        self.assertIn("sfmea scan", text_output.getvalue())

        with contextlib.redirect_stdout(io.StringIO()):
            result = main(["status", str(self.root), "--require-handoff-ready"])
        self.assertEqual(result, 1)

        with contextlib.redirect_stdout(io.StringIO()) as json_output:
            result = main(["status", str(self.root), "--json"])
        self.assertEqual(result, 0)
        payload = json.loads(json_output.getvalue())
        self.assertEqual(payload["format"], WORKFLOW_STATUS_FORMAT)
        self.assertEqual(payload["stage"], "ready_to_scan")
        self.assertEqual(payload["handoff_gate_summary"]["total"], 8)
        self.assertEqual(len(payload["handoff_gates"]), 8)

    def test_status_exposes_assurance_planning_progress_and_action(self) -> None:
        analysis = self._scan()
        item = analysis["items"][0]
        item["review"]["disposition"] = "accepted"
        save_analysis(self.analysis_path, analysis)

        result = workflow_status(self.root)
        assurance = result["analysis"]["counts"]["assurance"]
        self.assertEqual(assurance["active_obligations"], len(analysis["items"]))
        self.assertEqual(assurance["applicable_findings"], 1)
        self.assertEqual(assurance["planning_pending"], 1)
        self.assertFalse(assurance["gates"]["plan_ready"])
        action = next(
            value
            for value in result["next_actions"]
            if value["id"] == "review_assurance_plan"
        )
        self.assertIn("--format markdown", action["command"])
        self.assertIn("sfmea-analysis-assurance.md", action["command"])

    def test_status_discovers_and_verifies_optional_assurance_scaffold(self) -> None:
        analysis = self._scan()
        scaffold = export_pytest_scaffold(
            analysis,
            self.root / "assurance-tests",
            limit=1,
            disposition="all",
        )

        current = workflow_status(self.root)
        artifact = current["artifacts"]["assurance_scaffold"]
        self.assertEqual(artifact["status"], "current")
        self.assertTrue(artifact["integrity"]["valid"])
        self.assertTrue(artifact["binding"]["valid"])
        self.assertEqual(artifact["generated_files_changed"], 0)
        self.assertNotIn(
            "verify_assurance_scaffold",
            {value["id"] for value in current["next_actions"]},
        )

        generated_test = scaffold / "test_sfmea_assurance.py"
        generated_test.write_text(
            generated_test.read_text(encoding="utf-8") + "\n# implementation draft\n",
            encoding="utf-8",
        )
        implemented = workflow_status(self.root)
        self.assertEqual(
            implemented["artifacts"]["assurance_scaffold"]["status"], "current"
        )
        self.assertEqual(
            implemented["artifacts"]["assurance_scaffold"]["generated_files_changed"],
            1,
        )
        with contextlib.redirect_stdout(io.StringIO()) as status_output:
            self.assertEqual(main(["status", str(self.root)]), 0)
        self.assertIn("assurance scaffold: current", status_output.getvalue())
        self.assertIn("generated changes=1", status_output.getvalue())
        self.assertIn("contract changes=0", status_output.getvalue())

        analysis["items"][0]["review"]["notes"] = "Current analysis changed."
        save_analysis(self.analysis_path, analysis)
        advanced = workflow_status(self.root)
        advanced_artifact = advanced["artifacts"]["assurance_scaffold"]
        self.assertEqual(advanced_artifact["status"], "current")
        self.assertTrue(advanced_artifact["binding"]["valid"])
        self.assertEqual(advanced_artifact["binding"]["status"], "contracts_current")
        self.assertNotIn(
            "verify_assurance_scaffold",
            {value["id"] for value in advanced["next_actions"]},
        )
        with contextlib.redirect_stdout(io.StringIO()) as advanced_output:
            self.assertEqual(main(["status", str(self.root)]), 0)
        self.assertIn("binding=contracts_current", advanced_output.getvalue())

        update_item_review(
            analysis,
            analysis["items"][0]["id"],
            {"end_effect": "The selected verification contract changed."},
        )
        save_analysis(self.analysis_path, analysis)
        stale = workflow_status(self.root)
        stale_artifact = stale["artifacts"]["assurance_scaffold"]
        self.assertEqual(stale_artifact["status"], "mismatched")
        self.assertFalse(stale_artifact["binding"]["valid"])
        self.assertEqual(stale_artifact["contract_change_summary"]["changed"], 1)
        action = next(
            value
            for value in stale["next_actions"]
            if value["id"] == "verify_assurance_scaffold"
        )
        self.assertIn("assurance-scaffold-verify", action["command"])
        self.assertIn(str(scaffold), action["command"])

        manifest_path = scaffold / "assurance-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["selection"]["scope"] = "tampered"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        invalid = workflow_status(self.root)
        invalid_artifact = invalid["artifacts"]["assurance_scaffold"]
        self.assertEqual(invalid_artifact["status"], "invalid")
        self.assertFalse(invalid_artifact["integrity"]["valid"])

    def test_status_offers_and_executes_safe_scaffold_refresh(self) -> None:
        analysis = self._scan()
        scaffold = export_pytest_scaffold(
            analysis,
            self.root / "assurance-tests",
            limit=1,
            disposition="all",
            queue_id="refreshable-queue",
            owner="Assurance Team",
        )
        update_item_review(
            analysis,
            analysis["items"][0]["id"],
            {"end_effect": "The selected verification contract changed."},
        )
        save_analysis(self.analysis_path, analysis)

        stale = workflow_status(self.root)
        action = next(
            value
            for value in stale["next_actions"]
            if value["id"] == "refresh_assurance_scaffold"
        )
        self.assertIn("assurance-scaffold-refresh", action["command"])
        self.assertIn(str(scaffold), action["command"])

        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                main(
                    [
                        "assurance-scaffold-refresh",
                        str(self.analysis_path),
                        str(scaffold),
                    ]
                ),
                0,
            )
        self.assertIn("refreshable-queue", output.getvalue())
        refreshed = workflow_status(self.root)
        self.assertEqual(
            refreshed["artifacts"]["assurance_scaffold"]["status"], "current"
        )
        self.assertNotIn(
            "refresh_assurance_scaffold",
            {value["id"] for value in refreshed["next_actions"]},
        )

    def test_status_routes_an_empty_selection_to_retirement_review(self) -> None:
        analysis = self._scan()
        finding = analysis["items"][0]
        update_item_review(
            analysis,
            finding["id"],
            {"disposition": "accepted", "reviewer": "Finding Reviewer"},
        )
        save_analysis(self.analysis_path, analysis)
        scaffold = export_pytest_scaffold(
            analysis,
            self.root / "assurance-tests",
            limit=1,
            queue_id="completed-queue",
        )
        update_item_review(
            analysis,
            finding["id"],
            {"disposition": "rejected", "reviewer": "Finding Reviewer"},
        )
        save_analysis(self.analysis_path, analysis)

        status = workflow_status(self.root)
        artifact = status["artifacts"]["assurance_scaffold"]
        self.assertEqual(artifact["lifecycle"], "retirement_candidate")
        self.assertEqual(artifact["current_selection"]["obligation_count"], 0)
        actions = {value["id"]: value for value in status["next_actions"]}
        self.assertNotIn("refresh_assurance_scaffold", actions)
        action = actions["archive_empty_assurance_scaffold"]
        self.assertIn("assurance-scaffold-archive", action["command"])
        self.assertIn(str(scaffold), action["command"])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["status", str(self.root)]), 0)
        self.assertIn("selected now=0", output.getvalue())
        self.assertIn("lifecycle=retirement candidate", output.getvalue())

        with contextlib.redirect_stdout(io.StringIO()) as archive_output:
            self.assertEqual(
                main(
                    [
                        "assurance-scaffold-archive",
                        str(self.analysis_path),
                        str(scaffold),
                    ]
                ),
                0,
            )
        self.assertIn("completed-queue", archive_output.getvalue())
        self.assertFalse(scaffold.exists())
        after_archive = workflow_status(self.root)
        self.assertNotIn("assurance_scaffold", after_archive["artifacts"])

    def test_assurance_plan_is_an_explicit_handoff_gate(self) -> None:
        self._scan()
        synthetic_counts = {
            "components": 1,
            "active_findings": 1,
            "unreviewed": 0,
            "accepted": 1,
            "rejected": 0,
            "revalidation_required": 0,
            "by_disposition": {"accepted": 1},
            "by_status": {"in_review": 1},
            "review_percent": 100.0,
            "validation": {"error": 0, "warning": 0, "information": 0},
            "assurance": {
                "active_obligations": 1,
                "applicable_findings": 1,
                "planning_pending": 1,
                "planning_percent": 0.0,
                "implemented_tests": 0,
                "recorded_executions": 0,
                "verified_obligations": 0,
                "gates": {"plan_ready": False},
            },
        }
        with (
            mock.patch(
                "pysfmea.workflow.repository_readiness",
                return_value={
                    "ready": True,
                    "counts": {
                        "error": 0,
                        "warning": 0,
                        "information": 0,
                        "pass": 1,
                    },
                },
            ),
            mock.patch(
                "pysfmea.workflow._analysis_counts", return_value=synthetic_counts
            ),
        ):
            result = workflow_status(self.root)
        self.assertEqual(result["stage"], "assurance_planning")
        self.assertFalse(result["ready_for_handoff"])
        assurance_gate = next(
            gate
            for gate in result["handoff_gates"]
            if gate["id"] == "assurance_plan_ready"
        )
        self.assertFalse(assurance_gate["passed"])
        self.assertEqual(assurance_gate["evidence"]["planning_pending"], 1)
        self.assertEqual(
            assurance_gate["remediation_action_id"], "review_assurance_plan"
        )
        self.assertIn(
            "review_assurance_plan", [value["id"] for value in result["next_actions"]]
        )

    def test_status_accepts_an_explicit_nonstandard_scaffold_path(self) -> None:
        analysis = self._scan()
        update_item_review(
            analysis,
            analysis["items"][0]["id"],
            {"disposition": "accepted", "reviewer": "Finding Reviewer"},
        )
        save_analysis(self.analysis_path, analysis)
        custom_scaffold = self.root / "review-queues" / "payments"

        missing = workflow_status(
            self.root,
            assurance_scaffold_path=custom_scaffold,
        )
        self.assertEqual(missing["paths"]["assurance_scaffold"], str(custom_scaffold))
        self.assertEqual(
            missing["artifacts"]["assurance_scaffold"]["status"], "missing"
        )
        create_action = next(
            value
            for value in missing["next_actions"]
            if value["id"] == "create_assurance_scaffold"
        )
        self.assertIn(str(custom_scaffold), create_action["command"])

        export_pytest_scaffold(
            analysis,
            custom_scaffold,
            queue_id="payments",
            owner="Payments Assurance",
            purpose="Payment subsystem hardening",
        )
        explicit = workflow_status(
            self.root,
            assurance_scaffold_path=custom_scaffold,
        )
        self.assertEqual(
            explicit["artifacts"]["assurance_scaffold"]["status"], "current"
        )
        second_scaffold = self.root / "review-queues" / "platform"
        multiple = workflow_status(
            self.root,
            assurance_scaffold_path=[
                custom_scaffold,
                second_scaffold,
                custom_scaffold,
            ],
        )
        self.assertEqual(len(multiple["assurance_scaffolds"]), 2)
        self.assertEqual(
            multiple["artifacts"]["assurance_scaffold"]["path"],
            str(custom_scaffold),
        )
        self.assertEqual(multiple["assurance_scaffolds"][1]["status"], "missing")
        second_action = next(
            value
            for value in multiple["next_actions"]
            if value["id"] == "create_assurance_scaffold_2"
        )
        self.assertIn(str(second_scaffold), second_action["command"])
        with contextlib.redirect_stdout(io.StringIO()) as json_output:
            self.assertEqual(
                main(
                    [
                        "status",
                        str(self.root),
                        "--assurance-scaffold",
                        str(custom_scaffold),
                        "--assurance-scaffold",
                        str(second_scaffold),
                        "--json",
                    ]
                ),
                0,
            )
        payload = json.loads(json_output.getvalue())
        self.assertEqual(
            payload["artifacts"]["assurance_scaffold"]["path"],
            str(custom_scaffold),
        )
        self.assertEqual(len(payload["assurance_scaffolds"]), 2)
        self.assertEqual(
            payload["paths"]["assurance_scaffolds"],
            [str(custom_scaffold), str(second_scaffold)],
        )

        export_pytest_scaffold(
            analysis,
            second_scaffold,
            queue_id="platform",
            owner="Platform Assurance",
            purpose="Platform integration hardening",
        )
        overlapping = workflow_status(
            self.root,
            assurance_scaffold_path=[custom_scaffold, second_scaffold],
        )
        portfolio = overlapping["assurance_scaffold_portfolio"]
        self.assertEqual(portfolio["format"], "pysfmea-assurance-scaffold-portfolio-1")
        self.assertEqual(portfolio["queue_count"], 2)
        self.assertEqual(portfolio["current_queues"], 2)
        self.assertEqual(portfolio["coverage_percent"], 100.0)
        self.assertEqual(portfolio["uncovered_accepted_obligations"], 0)
        self.assertEqual(portfolio["duplicate_assignment_count"], 1)
        self.assertEqual(portfolio["unowned_current_queues"], 0)
        self.assertEqual(portfolio["duplicate_queue_id_count"], 0)
        self.assertEqual(
            portfolio["duplicate_assignments"][0]["scaffold_paths"],
            [str(custom_scaffold), str(second_scaffold)],
        )
        self.assertEqual(
            [
                value["owner"]
                for value in portfolio["duplicate_assignments"][0]["queues"]
            ],
            ["Payments Assurance", "Platform Assurance"],
        )
        overlap_action = next(
            value
            for value in overlapping["next_actions"]
            if value["id"] == "review_assurance_scaffold_overlap"
        )
        self.assertIn("--json", overlap_action["command"])
        with contextlib.redirect_stdout(io.StringIO()) as text_output:
            self.assertEqual(
                main(
                    [
                        "status",
                        str(self.root),
                        "--assurance-scaffold",
                        str(custom_scaffold),
                        "--assurance-scaffold",
                        str(second_scaffold),
                    ]
                ),
                0,
            )
        self.assertIn("accepted coverage=100.0%", text_output.getvalue())
        self.assertIn("overlaps=1", text_output.getvalue())
        self.assertIn("unowned=0", text_output.getvalue())
        self.assertIn("duplicate queue IDs=0", text_output.getvalue())

        update_item_review(
            analysis,
            analysis["items"][1]["id"],
            {"disposition": "accepted", "reviewer": "Finding Reviewer"},
        )
        save_analysis(self.analysis_path, analysis)
        uncovered = workflow_status(
            self.root,
            assurance_scaffold_path=[custom_scaffold, second_scaffold],
        )["assurance_scaffold_portfolio"]
        self.assertEqual(uncovered["current_queues"], 0)
        self.assertEqual(uncovered["accepted_pending_obligations"], 2)
        self.assertEqual(uncovered["uncovered_accepted_obligations"], 2)
        self.assertEqual(uncovered["coverage_percent"], 0.0)

    def test_root_and_artifacts_layout_is_auto_discovered(self) -> None:
        artifacts = self.root / ".artifacts"
        artifacts.mkdir()
        relocated_config = artifacts / "sfmea.toml"
        self.config_path.replace(relocated_config)
        self.config_path = relocated_config
        relocated_analysis = artifacts / "sfmea-analysis.json"
        self.analysis_path = relocated_analysis
        self._scan()

        result = workflow_status(self.root)
        self.assertEqual(result["paths"]["configuration"], str(relocated_config))
        self.assertEqual(result["paths"]["analysis"], str(relocated_analysis))
        self.assertTrue(result["analysis"]["exists"])


if __name__ == "__main__":
    unittest.main()
