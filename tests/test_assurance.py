from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pysfmea.assurance as assurance_module
import pysfmea.execution as execution_module
from pysfmea.assurance import (
    archive_pytest_scaffold,
    assurance_progress,
    assurance_work_queue,
    export_assurance_register,
    export_pytest_scaffold,
    refresh_assurance_register,
    refresh_pytest_scaffold,
    review_obligation,
    verify_assurance_work_queue,
    verify_assurance_work_queue_file,
    verify_pytest_scaffold,
)
from pysfmea.cli import main
from pysfmea.execution import (
    import_execution_evidence,
    register_test_implementation,
    review_execution_evidence,
    run_sandbox_execution,
    sandbox_command,
)
from pysfmea.html_report import build_html_report_data, export_html_report
from pysfmea.report import (
    analysis_state_sha256,
    export_review_package,
    verify_review_package,
)
from pysfmea.scanner import scan_repository
from pysfmea.store import load_analysis, merge_rescan, save_analysis, update_item_review
from pysfmea.validation import validate_analysis
from pysfmea.version import __version__


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

    def test_work_queue_verifies_integrity_binding_projection_and_cli(self) -> None:
        self.analysis["items"][0]["review"]["disposition"] = "accepted"
        save_analysis(self.root / "analysis.json", self.analysis)
        self.analysis = load_analysis(self.root / "analysis.json")
        queue = assurance_work_queue(self.analysis)
        queue_path = self.root / "assurance-work.json"
        queue_path.write_text(json.dumps(queue), encoding="utf-8")

        standalone = verify_assurance_work_queue_file(queue_path)
        self.assertTrue(standalone["valid"])
        self.assertEqual(standalone["status"], "valid_binding_not_checked")
        self.assertIsNone(standalone["checks"]["analysis_state"])

        matched = verify_assurance_work_queue_file(queue_path, analysis=self.analysis)
        self.assertTrue(matched["valid"])
        self.assertEqual(matched["status"], "matched")
        self.assertTrue(all(matched["checks"].values()))
        self.assertEqual(
            matched["verifier"],
            {"name": "PySFMEA", "version": __version__},
        )

        canonical_text = json.dumps(queue, separators=(",", ":"))
        queue_path.write_text(
            '{"format":"ambiguous",' + canonical_text[1:], encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            verify_assurance_work_queue_file(queue_path)
        for value in ("NaN", "1e9999"):
            with self.subTest(non_finite=value):
                queue_path.write_text(
                    '{"numeric_probe":' + value + "," + canonical_text[1:],
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "non-finite number"):
                    verify_assurance_work_queue_file(queue_path)
        queue_path.write_text(canonical_text, encoding="utf-8")
        with mock.patch("pysfmea.assurance.MAX_ASSURANCE_WORK_QUEUE_JSON_NODES", 2):
            with self.assertRaisesRegex(ValueError, "2-node JSON structure limit"):
                verify_assurance_work_queue_file(queue_path)
        with mock.patch(
            "pysfmea.json_ingestion._same_file_identity", side_effect=[True, False]
        ):
            with self.assertRaisesRegex(
                ValueError, "changed during bounded consumption"
            ):
                verify_assurance_work_queue_file(queue_path)
        queue_path.write_text(canonical_text, encoding="utf-8")

        older_producer = json.loads(json.dumps(queue))
        older_producer["generator"]["version"] = "0.46.0"
        older_content = dict(older_producer)
        older_content.pop("integrity")
        older_producer["integrity"]["content_sha256"] = hashlib.sha256(
            json.dumps(
                older_content,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        cross_version = verify_assurance_work_queue(
            older_producer, analysis=self.analysis
        )
        self.assertTrue(cross_version["valid"])
        self.assertTrue(cross_version["checks"]["semantic_projection"])

        tampered = json.loads(json.dumps(queue))
        tampered["items"][0]["component"] = "forged.component"
        rejected = verify_assurance_work_queue(tampered, analysis=self.analysis)
        self.assertFalse(rejected["valid"])
        self.assertIn("content_integrity", rejected["failed_checks"])

        content = dict(tampered)
        content.pop("integrity")
        tampered["integrity"]["content_sha256"] = hashlib.sha256(
            json.dumps(
                content,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        forged = verify_assurance_work_queue(tampered, analysis=self.analysis)
        self.assertTrue(forged["checks"]["content_integrity"])
        self.assertTrue(forged["checks"]["structure"])
        self.assertFalse(forged["checks"]["semantic_projection"])
        self.assertFalse(forged["valid"])

        invalid_lifecycle = json.loads(json.dumps(queue))
        invalid_lifecycle["items"][0]["next_action_id"] = "none"
        content = dict(invalid_lifecycle)
        content.pop("integrity")
        invalid_lifecycle["integrity"]["content_sha256"] = hashlib.sha256(
            json.dumps(
                content,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        invalid = verify_assurance_work_queue(invalid_lifecycle)
        self.assertTrue(invalid["checks"]["content_integrity"])
        self.assertFalse(invalid["checks"]["structure"])
        self.assertEqual(invalid["status"], "invalid")

        stale_analysis = json.loads(json.dumps(self.analysis))
        stale_analysis["project"]["baseline"]["id"] = "new-baseline"
        stale = verify_assurance_work_queue(queue, analysis=stale_analysis)
        self.assertFalse(stale["checks"]["baseline"])
        self.assertFalse(stale["checks"]["analysis_state"])
        self.assertEqual(stale["status"], "mismatched")

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "assurance-work-verify",
                    str(queue_path),
                    "--analysis",
                    str(self.root / "missing-analysis.json"),
                    "--json",
                ]
            )
        self.assertEqual(exit_code, 2)
        self.assertEqual(
            json.loads(stdout.getvalue())["errors"][0]["code"],
            "analysis.load_failed",
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "assurance-work-verify",
                    str(queue_path),
                    "--analysis",
                    str(self.root / "analysis.json"),
                    "--json",
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(json.loads(stdout.getvalue())["valid"])

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
        work_path = export_assurance_register(
            self.analysis, self.root / "assurance-work.json", format="work-json"
        )
        json_payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertTrue(json_payload["obligations"])
        self.assertIn("planning_percent", json_payload["progress"])
        self.assertEqual(
            json_payload["work_queue"]["format"],
            "pysfmea-assurance-work-queue-2",
        )
        work_payload = json.loads(work_path.read_text(encoding="utf-8"))
        self.assertTrue(csv_path.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertEqual(work_payload, json_payload["work_queue"])
        self.assertNotIn("obligations", work_payload)
        self.assertEqual(
            work_payload["binding"]["analysis_state_sha256"],
            analysis_state_sha256(self.analysis),
        )
        self.assertEqual(work_payload["integrity"]["algorithm"], "sha256")
        with csv_path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            self.assertTrue(
                {
                    "control_review_questions",
                    "direct_callers",
                    "static_upstream_paths",
                    "cascade_path_inventory_complete",
                    "cascade_path_inventory_emitted",
                    "cascade_path_inventory_limitations",
                    "cascade_notice",
                    "work_state",
                    "automation_eligible",
                    "next_action_id",
                    "work_blockers",
                }
                <= set(reader.fieldnames or [])
            )
            self.assertTrue(list(reader))
        self.assertIn(
            "Executable assurance checklist",
            markdown_path.read_text(encoding="utf-8"),
        )
        self.assertIn("Planning:", markdown_path.read_text(encoding="utf-8"))
        self.assertIn("Work state", markdown_path.read_text(encoding="utf-8"))

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
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "assurance",
                        str(analysis_path),
                        "--format",
                        "work-json",
                    ]
                ),
                0,
            )
        self.assertTrue((self.root / "analysis.assurance-work.json").is_file())

        scaffold = export_pytest_scaffold(
            self.analysis,
            self.root / "assurance-tests",
            limit=2,
            disposition="all",
        )
        manifest_path = scaffold / "assurance-manifest.json"
        original_manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(original_manifest_text)
        canonical_manifest = dict(manifest)
        manifest_sha256 = canonical_manifest.pop("manifest_sha256")
        self.assertEqual(manifest["format"], "pysfmea-pytest-assurance-scaffold-7")
        self.assertEqual(
            manifest_sha256,
            hashlib.sha256(
                json.dumps(
                    canonical_manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(
            manifest["binding"]["analysis_state_sha256"],
            analysis_state_sha256(self.analysis),
        )
        self.assertEqual(
            manifest["binding"]["analysis_schema_version"],
            self.analysis["schema_version"],
        )
        self.assertEqual(
            manifest["binding"]["scaffold_contracts_sha256"],
            hashlib.sha256(
                json.dumps(
                    manifest["contract_snapshot"],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(len(manifest["obligations"]), 2)
        self.assertEqual(manifest["selection"]["limit"], 2)
        self.assertRegex(manifest["queue"]["id"], r"^QUEUE-[A-F0-9]{12}$")
        test_path = scaffold / "test_sfmea_assurance.py"
        generated_test = test_path.read_text(encoding="utf-8")
        self.assertIn("pytest.fail", generated_test)
        self.assertNotIn("pytest.skip", generated_test)
        runtime_path = scaffold / "sfmea_assurance_runtime.py"
        generated_runtime = runtime_path.read_text(encoding="utf-8")
        sys.path.insert(0, str(scaffold))
        self.addCleanup(
            lambda: sys.path.remove(str(scaffold))
            if str(scaffold) in sys.path
            else None
        )
        self.assertIn("failed its SHA-256 integrity check", generated_runtime)
        self.assertIn('path.open("rb")', generated_runtime)
        self.assertIn("MAX_MANIFEST_BYTES + 1", generated_runtime)
        self.assertIn("regular non-symbolic-link file", generated_runtime)
        self.assertNotIn('.read_text(encoding="utf-8")', generated_runtime)
        property_test = (scaffold / "test_sfmea_generated_properties.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("from hypothesis import", property_test)
        self.assertIn("assert_observation", property_test)
        self.assertNotIn("pytest.skip", property_test)
        self.assertIn(
            "raise NotImplementedError",
            (scaffold / "sfmea_assurance_adapters.py").read_text(encoding="utf-8"),
        )
        self.assertEqual(manifest["test_designs"]["summary"]["property_designs"], 2)
        self.assertEqual(manifest["test_designs"]["summary"]["contract_designs"], 0)
        self.assertEqual(
            manifest["binding"]["test_designs_sha256"],
            manifest["test_designs"]["content_sha256"],
        )
        for name in manifest["generated_files"]:
            self.assertEqual(
                manifest["generated_files"][name]["sha256"],
                hashlib.sha256((scaffold / name).read_bytes()).hexdigest(),
            )
        self.assertFalse(
            any(
                value.name.startswith(scaffold.name + ".")
                and value.name.endswith(".tmp")
                for value in scaffold.parent.iterdir()
            )
        )
        verification = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["status"], "matched")
        self.assertEqual(
            verification["format"], "pysfmea-assurance-scaffold-verification-6"
        )
        self.assertTrue(verification["checks"]["test_designs"])
        self.assertTrue(verification["checks"]["test_designs_sha256"])
        self.assertEqual(
            verification["obligation_ids"],
            [value["id"] for value in manifest["obligations"]],
        )
        self.assertEqual(verification["queue"], manifest["queue"])
        with contextlib.redirect_stdout(io.StringIO()) as verification_output:
            self.assertEqual(
                main(
                    [
                        "assurance-scaffold-verify",
                        str(analysis_path),
                        str(scaffold),
                        "--json",
                    ]
                ),
                0,
            )
        self.assertTrue(json.loads(verification_output.getvalue())["valid"])
        manifest["selection"]["scope"] = "tampered"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "integrity check"):
            runpy.run_path(str(test_path))
        tampered = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(tampered["valid"])
        self.assertEqual(tampered["status"], "invalid")
        self.assertFalse(tampered["checks"]["manifest_integrity"])

        runtime_path.write_text(
            generated_runtime.replace(
                "MAX_MANIFEST_BYTES = 64 * 1024 * 1024",
                "MAX_MANIFEST_BYTES = 10",
                1,
            ),
            encoding="utf-8",
        )
        sys.modules.pop("sfmea_assurance_runtime", None)
        with self.assertRaisesRegex(RuntimeError, "10-byte collection limit"):
            runpy.run_path(str(test_path))
        runtime_path.write_text(generated_runtime, encoding="utf-8")
        sys.modules.pop("sfmea_assurance_runtime", None)

        manifest_path.write_bytes(b"\xff\xfe")
        sys.modules.pop("sfmea_assurance_runtime", None)
        with self.assertRaisesRegex(RuntimeError, "valid bounded UTF-8 JSON"):
            runpy.run_path(str(test_path))
        manifest_path.write_text(
            '{"format":"ambiguous",' + original_manifest_text[1:],
            encoding="utf-8",
        )
        sys.modules.pop("sfmea_assurance_runtime", None)
        with self.assertRaisesRegex(RuntimeError, "unambiguous objects"):
            runpy.run_path(str(test_path))
        rejected_manifest = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(rejected_manifest["valid"])
        self.assertTrue(
            any(
                "duplicate object key" in finding["message"]
                for finding in rejected_manifest["findings"]
            )
        )
        manifest_path.write_text(
            '{"numeric_probe":1e9999,' + original_manifest_text[1:],
            encoding="utf-8",
        )
        sys.modules.pop("sfmea_assurance_runtime", None)
        with self.assertRaisesRegex(RuntimeError, "finite numbers"):
            runpy.run_path(str(test_path))
        manifest_path.write_text("[]", encoding="utf-8")
        sys.modules.pop("sfmea_assurance_runtime", None)
        with self.assertRaisesRegex(RuntimeError, "root must be an object"):
            runpy.run_path(str(test_path))
        manifest_path.write_text(original_manifest_text, encoding="utf-8")
        sys.modules.pop("sfmea_assurance_runtime", None)
        with mock.patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "regular non-symbolic-link"):
                runpy.run_path(str(test_path))

        malformed = json.loads(original_manifest_text)
        malformed["obligations"] = None
        malformed.pop("manifest_sha256")
        malformed["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                malformed,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        manifest_path.write_text(json.dumps(malformed), encoding="utf-8")
        sys.modules.pop("sfmea_assurance_runtime", None)
        with self.assertRaisesRegex(RuntimeError, "no valid obligation list"):
            runpy.run_path(str(test_path))
        malformed_result = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(malformed_result["valid"])
        self.assertFalse(malformed_result["checks"]["obligations"])
        manifest_path.write_text(original_manifest_text, encoding="utf-8")

        cli_scaffold = self.root / "owned-assurance-tests"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "assurance-scaffold",
                        str(analysis_path),
                        "-o",
                        str(cli_scaffold),
                        "--disposition",
                        "all",
                        "--limit",
                        "1",
                        "--queue-id",
                        "payments-critical",
                        "--owner",
                        "Payments Assurance",
                        "--purpose",
                        "Critical payment failure hardening",
                    ]
                ),
                0,
            )
        cli_manifest = json.loads(
            (cli_scaffold / "assurance-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            cli_manifest["queue"],
            {
                "id": "payments-critical",
                "owner": "Payments Assurance",
                "purpose": "Critical payment failure hardening",
            },
        )

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
        self.assertTrue((package / "assurance-work.json").is_file())
        package_verification = verify_review_package(package)
        self.assertTrue(package_verification["valid"])
        self.assertEqual(
            package_verification["assurance_work_queue"]["status"], "matched"
        )

    def test_register_export_uses_safe_prior_preserving_publication(self) -> None:
        destination = self.root / "assurance.json"
        destination.write_text("trusted previous register\n", encoding="utf-8")

        with mock.patch(
            "pysfmea.file_publication.os.replace",
            side_effect=OSError("injected publication failure"),
        ):
            with self.assertRaisesRegex(ValueError, "could not be published safely"):
                export_assurance_register(self.analysis, destination, format="json")

        self.assertEqual(
            destination.read_text(encoding="utf-8"),
            "trusted previous register\n",
        )
        self.assertFalse(list(self.root.glob(".assurance.json.*.tmp")))

        directory = self.root / "assurance-directory"
        directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file path"):
            export_assurance_register(self.analysis, directory, format="work-json")

    def test_scaffold_synthesizes_bounded_property_designs_and_rejects_overclaim(
        self,
    ) -> None:
        annotated_root = self.root / "annotated"
        annotated_root.mkdir()
        (annotated_root / "calculation.py").write_text(
            "def calculate(count: int, enabled: bool, name: str, "
            "values: list[int], options: dict[str, int], maybe: int | None) -> float:\n"
            "    return float(count) if enabled and name else 0.0\n",
            encoding="utf-8",
        )
        analysis = scan_repository(annotated_root)
        property_obligation = next(
            value
            for value in analysis["assurance"]["obligations"]
            if value["verification_method"] == "property_test"
        )
        scaffold = export_pytest_scaffold(
            analysis,
            self.root / "property-synthesis",
            scope=property_obligation["id"],
            limit=1,
            disposition="all",
        )
        manifest_path = scaffold / "assurance-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        design = manifest["test_designs"]["property_tests"][0]
        strategy_by_name = {
            value["name"]: value["strategy"] for value in design["parameters"]
        }
        self.assertEqual(strategy_by_name["count"]["kind"], "integers")
        self.assertEqual(strategy_by_name["enabled"]["kind"], "booleans")
        self.assertEqual(strategy_by_name["name"]["kind"], "text")
        self.assertEqual(strategy_by_name["values"]["kind"], "lists")
        self.assertEqual(strategy_by_name["options"]["kind"], "dictionaries")
        self.assertEqual(strategy_by_name["maybe"]["kind"], "one_of")
        self.assertTrue(design["oracles"])
        self.assertTrue(design["acceptance_criteria"])
        self.assertEqual(design["adapter_status"], "project_implementation_required")
        self.assertTrue(verify_pytest_scaffold(analysis, scaffold)["valid"])
        executed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "test_sfmea_generated_properties.py",
                "-q",
            ],
            cwd=scaffold,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(executed.returncode, 0)
        self.assertIn("NotImplementedError", executed.stdout + executed.stderr)
        self.assertIn(property_obligation["id"], executed.stdout + executed.stderr)

        design["parameters"][0]["strategy"]["kind"] = "text"
        design_projection = dict(manifest["test_designs"])
        design_projection.pop("content_sha256")
        forged_design_digest = hashlib.sha256(
            json.dumps(
                design_projection,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        manifest["test_designs"]["content_sha256"] = forged_design_digest
        manifest["binding"]["test_designs_sha256"] = forged_design_digest
        manifest.pop("manifest_sha256")
        manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        rejected = verify_pytest_scaffold(analysis, scaffold)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["test_designs_sha256"])

    def test_scaffold_synthesizes_fail_visible_contract_cases(self) -> None:
        analysis = json.loads(json.dumps(self.analysis))
        obligation = analysis["assurance"]["obligations"][0]
        obligation["verification_method"] = "contract_test"
        analysis["context"]["contracts"] = [
            {
                "id": "CONTRACT-EXAMPLE",
                "path": "openapi.json",
                "kind": "openapi",
                "bytes": 128,
                "sha256": "a" * 64,
                "operations": [f"POST /{obligation['component']}"],
                "data_types": ["Request", "Response"],
            }
        ]
        scaffold = export_pytest_scaffold(
            analysis,
            self.root / "contract-synthesis",
            scope=obligation["id"],
            limit=1,
            disposition="all",
        )
        manifest = json.loads(
            (scaffold / "assurance-manifest.json").read_text(encoding="utf-8")
        )
        design = manifest["test_designs"]["contract_tests"][0]
        self.assertEqual(
            design["binding_status"], "static_candidate_match_requires_review"
        )
        self.assertEqual(
            {value["kind"] for value in design["cases"]},
            {
                "conforming_exchange",
                "missing_required_input",
                "malformed_input",
                "incompatible_response",
                "declared_error_exchange",
            },
        )
        self.assertTrue(verify_pytest_scaffold(analysis, scaffold)["valid"])
        for source in scaffold.glob("*.py"):
            compile(source.read_text(encoding="utf-8"), str(source), "exec")

        sys.path.insert(0, str(scaffold))
        try:
            sys.modules.pop("sfmea_assurance_runtime", None)
            sys.modules.pop("sfmea_assurance_adapters", None)
            with self.assertRaisesRegex(NotImplementedError, obligation["id"]):
                namespace = runpy.run_path(
                    str(scaffold / "test_sfmea_generated_contracts.py")
                )
                namespace["test_sfmea_generated_contract"](
                    design,
                    design["cases"][0],
                )
        finally:
            if str(scaffold) in sys.path:
                sys.path.remove(str(scaffold))
            sys.modules.pop("sfmea_assurance_runtime", None)
            sys.modules.pop("sfmea_assurance_adapters", None)

        analysis["context"]["contracts"] = [
            {
                "id": f"CONTRACT-{index}",
                "path": f"unrelated-{index}.json",
                "kind": "json_schema",
                "bytes": 64,
                "sha256": str(index) * 64,
                "operations": [f"unrelated_operation_{index}"],
                "data_types": [],
            }
            for index in (1, 2)
        ]
        unresolved_scaffold = export_pytest_scaffold(
            analysis,
            self.root / "unresolved-contract-synthesis",
            scope=obligation["id"],
            limit=1,
            disposition="all",
        )
        unresolved_manifest = json.loads(
            (unresolved_scaffold / "assurance-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        unresolved = unresolved_manifest["test_designs"]["contract_tests"][0]
        self.assertEqual(unresolved["binding_status"], "unresolved")
        self.assertEqual(unresolved["contracts"], [])
        self.assertEqual(unresolved["cases"][0]["kind"], "establish_contract_binding")

    def test_scaffold_publication_cleans_staging_after_failure(self) -> None:
        destination = self.root / "assurance-tests"
        with mock.patch(
            "pysfmea.assurance.os.replace", side_effect=OSError("publish failed")
        ):
            with self.assertRaisesRegex(OSError, "publish failed"):
                export_pytest_scaffold(
                    self.analysis,
                    destination,
                    limit=1,
                    disposition="all",
                )

        self.assertFalse(destination.exists())
        self.assertFalse(
            any(
                value.name.startswith(destination.name + ".")
                and value.name.endswith(".tmp")
                for value in destination.parent.iterdir()
            )
        )

    def test_scaffold_queue_metadata_is_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "queue ID"):
            export_pytest_scaffold(
                self.analysis,
                self.root / "invalid-id",
                disposition="all",
                queue_id="invalid queue id",
            )
        with self.assertRaisesRegex(ValueError, "owner"):
            export_pytest_scaffold(
                self.analysis,
                self.root / "invalid-owner",
                disposition="all",
                owner="line one\nline two",
            )

    def test_scaffold_refresh_preserves_identity_edits_and_previous_publication(
        self,
    ) -> None:
        scaffold = export_pytest_scaffold(
            self.analysis,
            self.root / "assurance-tests",
            disposition="all",
            limit=1,
            queue_id="core-hardening",
            owner="Core Assurance",
            purpose="Core failure hardening",
        )
        self.analysis["items"][0]["review"]["notes"] = "Unrelated review update."
        with mock.patch(
            "pysfmea.assurance._read_assurance_json_object",
            wraps=assurance_module._read_assurance_json_object,
        ) as bounded_reads:
            refresh_pytest_scaffold(self.analysis, scaffold)
        self.assertEqual(bounded_reads.call_count, 2)
        refreshed = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(refreshed["valid"])
        self.assertEqual(refreshed["status"], "matched")
        self.assertEqual(
            refreshed["queue"],
            {
                "id": "core-hardening",
                "owner": "Core Assurance",
                "purpose": "Core failure hardening",
            },
        )

        manifest_path = scaffold / "assurance-manifest.json"
        preserved_manifest_bytes = manifest_path.read_bytes()
        verified_manifest = json.loads(preserved_manifest_bytes)
        raced_manifest = json.loads(json.dumps(verified_manifest))
        raced_manifest["queue"]["owner"] = "Concurrent Queue Owner"
        raced_manifest.pop("manifest_sha256")
        raced_manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                raced_manifest,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        with mock.patch(
            "pysfmea.assurance._read_assurance_json_object",
            side_effect=[verified_manifest, raced_manifest],
        ) as bounded_reads:
            with self.assertRaisesRegex(ValueError, "changed after guarded refresh"):
                refresh_pytest_scaffold(self.analysis, scaffold)
        self.assertEqual(bounded_reads.call_count, 2)
        self.assertEqual(manifest_path.read_bytes(), preserved_manifest_bytes)
        self.assertFalse(
            any(
                value.name.startswith(scaffold.name + ".")
                and value.name.endswith(".tmp")
                for value in scaffold.parent.iterdir()
            )
        )

        self.analysis["items"][0]["review"]["notes"] = "Another review update."
        original_replace = os.replace
        replace_calls = 0

        def fail_new_publication(
            source: str | os.PathLike, destination: str | os.PathLike
        ) -> None:
            nonlocal replace_calls
            replace_calls += 1
            if replace_calls == 2:
                raise OSError("publish failed")
            original_replace(source, destination)

        with mock.patch(
            "pysfmea.assurance.os.replace", side_effect=fail_new_publication
        ):
            with self.assertRaisesRegex(OSError, "publish failed"):
                refresh_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue((scaffold / "assurance-manifest.json").is_file())
        self.assertTrue(
            verify_pytest_scaffold(self.analysis, scaffold)["checks"][
                "manifest_integrity"
            ]
        )
        self.assertFalse(
            any(value.name.endswith(".backup") for value in scaffold.parent.iterdir())
        )

        generated_test = scaffold / "test_sfmea_assurance.py"
        generated_test.write_text(
            generated_test.read_text(encoding="utf-8") + "\n# implementation work\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "edited or removed"):
            refresh_pytest_scaffold(self.analysis, scaffold)
        self.assertIn("implementation work", generated_test.read_text(encoding="utf-8"))

    def test_scaffold_verifier_bounds_every_consumed_artifact(self) -> None:
        scaffold = export_pytest_scaffold(
            self.analysis,
            self.root / "bounded-assurance-tests",
            limit=1,
            disposition="all",
        )
        manifest_path = scaffold / "assurance-manifest.json"
        manifest_bytes = manifest_path.read_bytes()

        with mock.patch(
            "pysfmea.assurance.MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES",
            len(manifest_bytes) - 1,
        ):
            oversized_manifest = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(oversized_manifest["valid"])
        manifest_errors = [
            value["message"]
            for value in oversized_manifest["findings"]
            if value["rule_id"] == "scaffold.manifest_unreadable"
        ]
        self.assertEqual(len(manifest_errors), 1)
        self.assertIn("verification limit", manifest_errors[0])

        manifest_path.write_bytes(b"\xff\xfe")
        invalid_utf8 = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(invalid_utf8["valid"])
        self.assertIn(
            "not valid UTF-8 JSON",
            next(
                value["message"]
                for value in invalid_utf8["findings"]
                if value["rule_id"] == "scaffold.manifest_unreadable"
            ),
        )
        manifest_path.write_bytes(manifest_bytes)

        with mock.patch(
            "pysfmea.assurance.MAX_ASSURANCE_SCAFFOLD_GENERATED_FILE_BYTES",
            10,
        ):
            oversized_generated = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(oversized_generated["valid"])
        self.assertTrue(
            all(value["exists"] for value in oversized_generated["generated_files"])
        )
        self.assertTrue(
            all(
                not value["unchanged_from_generated"]
                for value in oversized_generated["generated_files"]
            )
        )
        generated_errors = [
            value["message"]
            for value in oversized_generated["findings"]
            if value["rule_id"] == "scaffold.generated_file_unreadable"
        ]
        self.assertEqual(
            len(generated_errors),
            len(json.loads(manifest_bytes)["generated_files"]),
        )
        self.assertTrue(
            all("10-byte verification limit" in value for value in generated_errors)
        )

        retirement_path = scaffold / "retirement-record.json"
        retirement_path.write_bytes(b"x" * (len(manifest_bytes) + 1))
        with mock.patch(
            "pysfmea.assurance.MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES",
            len(manifest_bytes),
        ):
            oversized_retirement = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(oversized_retirement["retirement"]["present"])
        self.assertFalse(oversized_retirement["retirement"]["valid"])
        self.assertFalse(oversized_retirement["valid"])
        retirement_path.unlink()

        with mock.patch("pysfmea.assurance.os.path.lexists", return_value=True):
            broken_link = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(broken_link["retirement"]["present"])
        self.assertFalse(broken_link["retirement"]["valid"])
        self.assertIn(
            "scaffold.retirement_record",
            {value["rule_id"] for value in broken_link["findings"]},
        )

    def test_scaffold_archive_preserves_a_retirement_record_atomically(self) -> None:
        finding = self.analysis["items"][0]
        update_item_review(
            self.analysis,
            finding["id"],
            {"disposition": "accepted", "reviewer": "Finding Reviewer"},
        )
        scaffold = export_pytest_scaffold(
            self.analysis,
            self.root / "assurance-tests",
            limit=1,
            queue_id="completed-queue",
            owner="Assurance Team",
        )
        with self.assertRaisesRegex(ValueError, "retirement candidate"):
            archive_pytest_scaffold(self.analysis, scaffold)

        update_item_review(
            self.analysis,
            finding["id"],
            {"disposition": "rejected", "reviewer": "Finding Reviewer"},
        )
        manifest_path = scaffold / "assurance-manifest.json"
        verified_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        raced_manifest = json.loads(json.dumps(verified_manifest))
        raced_manifest["queue"]["owner"] = "Concurrent Archive Owner"
        raced_manifest.pop("manifest_sha256")
        raced_manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                raced_manifest,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        with mock.patch(
            "pysfmea.assurance._read_assurance_json_object",
            side_effect=[verified_manifest, raced_manifest],
        ) as bounded_reads:
            with self.assertRaisesRegex(ValueError, "changed after guarded archive"):
                archive_pytest_scaffold(self.analysis, scaffold)
        self.assertEqual(bounded_reads.call_count, 2)
        self.assertTrue(scaffold.is_dir())
        self.assertFalse((scaffold / "retirement-record.json").exists())

        with mock.patch(
            "pysfmea.assurance.os.replace", side_effect=OSError("archive failed")
        ):
            with self.assertRaisesRegex(OSError, "archive failed"):
                archive_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(scaffold.is_dir())
        self.assertFalse((scaffold / "retirement-record.json").exists())

        with mock.patch(
            "pysfmea.assurance._read_assurance_json_object",
            wraps=assurance_module._read_assurance_json_object,
        ) as bounded_reads:
            archived = archive_pytest_scaffold(self.analysis, scaffold)
        self.assertEqual(bounded_reads.call_count, 2)
        self.assertFalse(scaffold.exists())
        self.assertEqual(archived.parent.name, ".sfmea-archive")
        record = json.loads(
            (archived / "retirement-record.json").read_text(encoding="utf-8")
        )
        supplied_digest = record.pop("record_sha256")
        actual_digest = hashlib.sha256(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(supplied_digest, actual_digest)
        self.assertEqual(record["queue"]["id"], "completed-queue")
        self.assertEqual(
            record["reason"], "selection_no_longer_matches_pending_obligations"
        )
        archived_verification = verify_pytest_scaffold(self.analysis, archived)
        self.assertEqual(archived_verification["lifecycle"], "archived")
        self.assertTrue(archived_verification["checks"]["manifest_integrity"])
        self.assertTrue(archived_verification["checks"]["retirement_record"])
        self.assertTrue(archived_verification["retirement"]["valid"])
        with self.assertRaisesRegex(ValueError, "archived queues are immutable"):
            refresh_pytest_scaffold(self.analysis, archived)

        retirement_path = archived / "retirement-record.json"
        retirement_path.write_text(
            retirement_path.read_text(encoding="utf-8").replace(
                "selection_no_longer_matches_pending_obligations",
                "tampered_retirement_reason",
                1,
            ),
            encoding="utf-8",
        )
        tampered = verify_pytest_scaffold(self.analysis, archived)
        self.assertFalse(tampered["checks"]["retirement_record"])
        self.assertEqual(tampered["status"], "invalid")

    def test_scaffold_verifier_distinguishes_implementation_edits_from_staleness(
        self,
    ) -> None:
        scaffold = export_pytest_scaffold(
            self.analysis,
            self.root / "assurance-tests",
            limit=1,
            disposition="all",
        )
        test_path = scaffold / "test_sfmea_assurance.py"
        test_path.write_text(
            test_path.read_text(encoding="utf-8") + "\n# implementation draft\n",
            encoding="utf-8",
        )
        edited = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(edited["valid"])
        self.assertEqual(edited["status"], "matched")
        self.assertIn(
            "scaffold.generated_file_changed",
            {value["rule_id"] for value in edited["findings"]},
        )

        self.analysis["items"][0]["review"]["notes"] = "Governed state changed."
        advanced = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(advanced["valid"])
        self.assertEqual(advanced["status"], "contracts_current")
        self.assertFalse(advanced["checks"]["analysis_state_sha256"])
        self.assertTrue(advanced["checks"]["scaffold_contracts_sha256"])
        self.assertIn(
            "scaffold.analysis_state_advanced",
            {value["rule_id"] for value in advanced["findings"]},
        )

        update_item_review(
            self.analysis,
            self.analysis["items"][0]["id"],
            {"end_effect": "The verification contract has materially changed."},
        )
        stale = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(stale["valid"])
        self.assertEqual(stale["status"], "mismatched")
        self.assertFalse(stale["checks"]["scaffold_contracts_sha256"])
        self.assertEqual(stale["contract_change_summary"]["changed"], 1)
        self.assertIn("contract_sha256", stale["contract_changes"][0]["changed_fields"])

    def test_progress_and_scaffolds_follow_accepted_engineering_decisions(self) -> None:
        initial = assurance_progress(self.analysis)
        self.assertEqual(initial["applicable_findings"], 0)
        self.assertIsNone(initial["planning_percent"])
        self.assertTrue(initial["gates"]["plan_ready"])
        self.assertEqual(assurance_work_queue(self.analysis)["summary"]["total"], 0)
        with self.assertRaisesRegex(ValueError, "disposition='accepted'"):
            export_pytest_scaffold(self.analysis, self.root / "premature-tests")

        item = self.analysis["items"][0]
        update_item_review(
            self.analysis,
            item["id"],
            {
                "disposition": "accepted",
                "reviewer": "Finding Reviewer",
                "next_higher_effect": "The containing service rejects the operation.",
                "end_effect": "The system remains within its approved boundary.",
                "prevention_controls": ["Input invariant enforcement"],
                "required_safe_state": "Operation rejected with no committed side effect.",
            },
        )
        obligation = next(
            value
            for value in self.analysis["assurance"]["obligations"]
            if value["finding_id"] == item["id"]
        )
        self.assertEqual(obligation["planning_gaps"], [])
        pending = assurance_progress(self.analysis)
        self.assertEqual(pending["applicable_findings"], 1)
        self.assertEqual(pending["planning_pending"], 1)
        self.assertFalse(pending["gates"]["plan_ready"])
        pending_work = assurance_work_queue(self.analysis)
        self.assertEqual(pending_work["items"][0]["state"], "plan_review_required")
        self.assertFalse(pending_work["items"][0]["automation_eligible"])
        self.assertIn(
            "named assurance-plan reviewer is missing",
            pending_work["items"][0]["blockers"],
        )

        review_obligation(
            self.analysis,
            obligation["id"],
            status="verification_planned",
            reviewer="Assurance Planner",
            rationale="The accepted finding requires the recorded off-nominal test.",
        )
        planned = assurance_progress(self.analysis)
        self.assertTrue(planned["gates"]["plan_ready"])
        self.assertEqual(planned["implementation_pending"], 1)
        planned_work = assurance_work_queue(self.analysis)
        self.assertEqual(planned_work["items"][0]["state"], "ready_for_implementation")
        self.assertTrue(planned_work["items"][0]["automation_eligible"])
        self.assertEqual(planned["work_queue"]["implementation_ready"], 1)

        scaffold = export_pytest_scaffold(
            self.analysis, self.root / "accepted-tests", limit=10
        )
        manifest = json.loads(
            (scaffold / "assurance-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["selection"]["disposition"], "accepted")
        self.assertEqual(
            [value["id"] for value in manifest["obligations"]], [obligation["id"]]
        )
        obligation["automation"]["implementation_status"] = "implemented"
        execution_work = assurance_work_queue(self.analysis)
        self.assertEqual(execution_work["items"][0]["state"], "ready_for_execution")
        self.assertEqual(
            assurance_progress(self.analysis)["work_queue"]["execution_ready"], 1
        )
        with self.assertRaisesRegex(ValueError, "no pending"):
            export_pytest_scaffold(self.analysis, self.root / "no-pending-tests")
        included = export_pytest_scaffold(
            self.analysis,
            self.root / "implemented-tests",
            include_implemented=True,
        )
        self.assertTrue((included / "assurance-manifest.json").is_file())

        execution = {
            "id": "EXEC-WORK-QUEUE",
            "obligation_id": obligation["id"],
            "status": "failed",
            "reviews": [],
        }
        self.analysis["assurance"]["executions"].append(execution)
        self.assertEqual(
            assurance_work_queue(self.analysis)["items"][0]["state"],
            "execution_remediation_required",
        )
        execution["status"] = "passed"
        self.assertEqual(
            assurance_work_queue(self.analysis)["items"][0]["state"],
            "evidence_review_required",
        )
        obligation["evidence_status"] = "partial"
        self.assertEqual(
            assurance_work_queue(self.analysis)["items"][0]["state"],
            "evidence_remediation_required",
        )
        obligation["evidence_status"] = "sufficient"
        obligation["assurance_status"] = "verified"
        resolved = assurance_work_queue(self.analysis)["items"][0]
        self.assertEqual(resolved["state"], "resolved")
        self.assertFalse(resolved["actionable"])
        self.assertEqual(resolved["next_action_id"], "none")

    def test_scaffold_verifier_detects_newly_selected_obligations(self) -> None:
        first, second = self.analysis["items"][:2]
        update_item_review(
            self.analysis,
            first["id"],
            {"disposition": "accepted", "reviewer": "Finding Reviewer"},
        )
        scaffold = export_pytest_scaffold(
            self.analysis,
            self.root / "accepted-tests",
        )
        initial = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertTrue(initial["valid"])
        self.assertEqual(initial["contract_change_summary"]["current"], 1)
        self.assertEqual(initial["current_selection"]["obligation_count"], 1)
        self.assertEqual(initial["lifecycle"], "active")

        update_item_review(
            self.analysis,
            second["id"],
            {"disposition": "accepted", "reviewer": "Finding Reviewer"},
        )
        expanded = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(expanded["valid"])
        self.assertEqual(expanded["status"], "mismatched")
        self.assertEqual(expanded["contract_change_summary"]["added"], 1)
        self.assertEqual(expanded["contract_changes"][0]["status"], "added")
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                main(
                    [
                        "assurance-scaffold-verify",
                        str(analysis_path),
                        str(scaffold),
                    ]
                ),
                1,
            )
        self.assertIn("added=1", output.getvalue())
        self.assertIn(
            expanded["contract_changes"][0]["obligation_id"], output.getvalue()
        )

        for item in (first, second):
            update_item_review(
                self.analysis,
                item["id"],
                {"disposition": "rejected", "reviewer": "Finding Reviewer"},
            )
        empty = verify_pytest_scaffold(self.analysis, scaffold)
        self.assertFalse(empty["valid"])
        self.assertEqual(empty["current_selection"]["obligation_count"], 0)
        self.assertEqual(empty["lifecycle"], "retirement_candidate")
        self.assertEqual(empty["contract_change_summary"]["removed"], 1)

    def test_finding_contract_change_reopens_assurance_evidence(self) -> None:
        item = self.analysis["items"][0]
        obligation = next(
            value
            for value in self.analysis["assurance"]["obligations"]
            if value["finding_id"] == item["id"]
        )
        obligation["planning_gaps"] = []
        review_obligation(
            self.analysis,
            obligation["id"],
            status="verification_planned",
            reviewer="Assurance Planner",
            rationale="The verification contract is ready.",
        )
        obligation["evidence_status"] = "sufficient"
        previous_digest = obligation["provenance"]["contract_sha256"]

        update_item_review(
            self.analysis,
            item["id"],
            {
                "end_effect": "A newly reviewed system consequence.",
                "reviewer": "Finding Reviewer",
            },
        )
        refreshed = next(
            value
            for value in self.analysis["assurance"]["obligations"]
            if value["finding_id"] == item["id"]
        )
        self.assertNotEqual(refreshed["provenance"]["contract_sha256"], previous_digest)
        self.assertEqual(refreshed["assurance_status"], "reopened")
        self.assertEqual(refreshed["evidence_status"], "stale")
        self.assertIn(
            "verification contract changed", refreshed["history"][-1]["reason"]
        )

    def test_closed_obligation_always_requires_named_approval(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        obligation["assurance_status"] = "closed"
        obligation["evidence_status"] = "sufficient"
        obligation["review"].update(
            {
                "reviewer": "Evidence Reviewer",
                "rationale": "Evidence was reviewed.",
                "acceptance_approved_by": "",
            }
        )
        self.analysis["assurance"]["obligations"][-1]["assurance_status"] = "candidate"
        rules = {
            value["rule_id"] for value in validate_analysis(self.analysis)["findings"]
        }
        self.assertIn("assurance.unapproved_closure", rules)

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

    def test_planning_review_cannot_overwrite_evidence_controlled_states(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        obligation["assurance_status"] = "verified"
        obligation["evidence_status"] = "sufficient"
        with self.assertRaisesRegex(ValueError, "evidence-controlled"):
            review_obligation(
                self.analysis,
                obligation["id"],
                status="candidate",
                reviewer="Planner",
                rationale="Attempt to downgrade verified evidence.",
            )
        review_obligation(
            self.analysis,
            obligation["id"],
            status="residual_risk_review",
            reviewer="Planner",
            rationale="Verification is sufficient; evaluate the residual risk.",
        )
        self.assertEqual(obligation["assurance_status"], "residual_risk_review")

        obligation["assurance_status"] = "partially_verified"
        with self.assertRaisesRegex(ValueError, "evidence- or approval-controlled"):
            review_obligation(
                self.analysis,
                obligation["id"],
                status="verification_planned",
                reviewer="Planner",
                rationale="Attempt to overwrite evidence-derived progress.",
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
        user_index = command.index("--user")
        self.assertRegex(command[user_index + 1], r"^\d+:\d+$")
        self.assertIn("--pull", command)
        self.assertIn("never", command)
        self.assertIn("--entrypoint", command)
        self.assertEqual(command[command.index("--entrypoint") + 1], "python")
        self.assertIn("--junitxml=/evidence/junit.xml", command)

    def test_junit_summary_rejects_entity_expansion(self) -> None:
        junit = self.root / "junit.xml"
        junit.write_text(
            '<!DOCTYPE testsuite [<!ENTITY x "expanded">]>'
            '<testsuite tests="1" failures="0" errors="0" skipped="0" '
            'time="0.1" name="&x;"/>',
            encoding="utf-8",
        )
        self.assertEqual(execution_module._junit_summary(junit), {"parse_error": True})

    def test_execution_evidence_requires_independent_criterion_review(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        test_path = self.root / "test_assurance_control.py"
        test_path.write_text("def test_control():\n    assert True\n", encoding="utf-8")
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
            mock.patch("pysfmea.execution._git_state", return_value=recorded_vcs),
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
            for index, _value in enumerate(obligation["acceptance_criteria"], start=1)
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
        rules = {
            value["rule_id"] for value in validate_analysis(self.analysis)["findings"]
        }
        self.assertNotIn("assurance.unsupported_verification", rules)

    def test_external_evidence_import_is_bounded_link_safe_and_transactional(
        self,
    ) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        test_path = self.root / "test_external_boundary.py"
        test_path.write_text("def test_control():\n    assert True\n", encoding="utf-8")
        source = self.root / "external-boundary"
        source.mkdir()
        log = source / "pytest.log"
        log.write_text("bounded external execution evidence\n", encoding="utf-8")
        manifest = {
            "schema_version": "1.0",
            "baseline_id": self.analysis["project"]["baseline"]["id"],
            "repository_revision": self.analysis["project"]["baseline"]
            .get("vcs", {})
            .get("revision", ""),
            "test": {
                "path": test_path.name,
                "sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
            },
            "command_argv": ["python", "-m", "pytest", test_path.name],
            "status": "passed",
            "artifacts": [
                {
                    "kind": "execution_log",
                    "path": log.name,
                    "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                }
            ],
        }
        manifest_path = source / "manifest.json"
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)
        evidence_root = self.root / "managed-boundary-evidence"
        original_analysis = json.loads(json.dumps(self.analysis))

        with mock.patch(
            "pysfmea.execution.MAX_IMPORT_MANIFEST_BYTES",
            10,
        ):
            with self.assertRaisesRegex(ValueError, "10-byte consumption limit"):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )
        manifest_path.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "valid bounded UTF-8 JSON"):
            import_execution_evidence(
                self.analysis,
                obligation["id"],
                manifest_path=manifest_path,
                evidence_root=evidence_root,
                initiated_by="Boundary Importer",
            )
        manifest_path.write_bytes(manifest_bytes)
        duplicate_manifest = (
            '{"schema_version":"ambiguous",' + manifest_bytes.decode("utf-8")[1:]
        ).encode("utf-8")
        manifest_path.write_bytes(duplicate_manifest)
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            import_execution_evidence(
                self.analysis,
                obligation["id"],
                manifest_path=manifest_path,
                evidence_root=evidence_root,
                initiated_by="Boundary Importer",
            )
        for value in ("NaN", "1e9999"):
            with self.subTest(non_finite=value):
                manifest_path.write_text(
                    '{"numeric_probe":'
                    + value
                    + ","
                    + manifest_bytes.decode("utf-8")[1:],
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "non-finite number"):
                    import_execution_evidence(
                        self.analysis,
                        obligation["id"],
                        manifest_path=manifest_path,
                        evidence_root=evidence_root,
                        initiated_by="Boundary Importer",
                    )
        manifest_path.write_bytes(manifest_bytes)
        with mock.patch(
            "pysfmea.json_ingestion._same_file_identity", side_effect=[True, False]
        ):
            with self.assertRaisesRegex(
                ValueError, "changed during bounded consumption"
            ):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )
        with mock.patch(
            "pysfmea.json_ingestion._is_symbolic_link_mode", return_value=True
        ):
            with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )

        def artifact_link_only(path: Path) -> bool:
            return path.name == log.name

        with mock.patch(
            "pysfmea.execution.Path.is_symlink",
            autospec=True,
            side_effect=artifact_link_only,
        ):
            with self.assertRaisesRegex(
                ValueError, "artifact 1 path is missing or unsafe"
            ):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )
        with mock.patch(
            "pysfmea.execution.MAX_IMPORTED_ARTIFACT_BYTES",
            10,
        ):
            with self.assertRaisesRegex(ValueError, "10-byte consumption limit"):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )
        with mock.patch(
            "pysfmea.execution._copy_file_bounded",
            side_effect=ValueError("artifact changed during bounded copy"),
        ):
            with self.assertRaisesRegex(ValueError, "bounded copy"):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )
        self.assertEqual(self.analysis, original_analysis)
        self.assertFalse(evidence_root.exists() and any(evidence_root.iterdir()))

        with mock.patch(
            "pysfmea.execution._record_collected_execution",
            side_effect=RuntimeError("recording failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "recording failed"):
                import_execution_evidence(
                    self.analysis,
                    obligation["id"],
                    manifest_path=manifest_path,
                    evidence_root=evidence_root,
                    initiated_by="Boundary Importer",
                )
        self.assertEqual(self.analysis, original_analysis)
        self.assertFalse(evidence_root.exists() and any(evidence_root.iterdir()))

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
        copied = (
            Path(execution["evidence_directory"]) / "artifact-001-execution_log.log"
        )
        self.assertEqual(copied.read_bytes(), log.read_bytes())
        statement = Path(execution["evidence_directory"]) / "execution.json"
        saved = json.loads(statement.read_text(encoding="utf-8"))
        saved["status"] = "failed"
        statement.write_text(json.dumps(saved), encoding="utf-8")
        criteria = {
            index: "pass"
            for index, _value in enumerate(obligation["acceptance_criteria"], start=1)
        }
        with mock.patch("pysfmea.execution.MAX_IMPORT_MANIFEST_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "intact artifacts"):
                review_execution_evidence(
                    self.analysis,
                    execution["id"],
                    reviewer="Independent Reviewer",
                    decision="sufficient",
                    rationale="Managed evidence must remain consumption bounded.",
                    stimulus_observed=True,
                    criterion_results=criteria,
                )
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
