from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.evidence_onboarding import (
    _apply_selected,
    onboard_evidence,
    verify_evidence_onboarding_receipt,
    verify_evidence_onboarding_receipt_file,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis


class EvidenceOnboardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "app.py").write_text(
            "def run(value: int) -> int:\n    return value + 1\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)
        self.coverage = self.root / "coverage.json"
        self.coverage.write_text(
            json.dumps(
                {
                    "meta": {"version": "7.10", "branch_coverage": True},
                    "files": {
                        "app.py": {
                            "executed_lines": [1, 2],
                            "missing_lines": [],
                            "executed_branches": [],
                            "missing_branches": [],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.trace = self.root / "runtime-trace.json"
        self.trace.write_text(
            json.dumps(
                {
                    "spans": [
                        {
                            "trace_id": "trace-1",
                            "span_id": "span-1",
                            "name": "run",
                            "start_time": "1",
                            "end_time": "11",
                            "attributes": {"sfmea.component": "run"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_plan_validates_full_import_without_mutating_source(self) -> None:
        original = copy.deepcopy(self.analysis)
        updated, receipt, queue = onboard_evidence(
            self.analysis,
            self.root,
            coverage_json=self.coverage,
            runtime_traces=[(self.trace, "smoke scenario")],
        )

        self.assertEqual(self.analysis, original)
        self.assertEqual(receipt["mode"], "validated_plan")
        self.assertEqual(receipt["summary"]["selected"], 2)
        self.assertEqual(receipt["summary"]["validated"], 2)
        self.assertEqual(receipt["summary"]["coverage_components"], 0)
        self.assertEqual(receipt["summary"]["runtime_imports"], 0)
        self.assertEqual(receipt["summary"]["prospective"]["coverage_components"], 1)
        self.assertEqual(receipt["summary"]["prospective"]["runtime_imports"], 1)
        self.assertTrue(receipt["queue_verification"]["valid"])
        self.assertEqual(
            queue["integrity"]["content_sha256"],
            receipt["result_binding"]["assurance_work_queue_sha256"],
        )
        Draft202012Validator(schema_document("evidence-onboarding-receipt")).validate(
            receipt
        )
        verification = verify_evidence_onboarding_receipt(receipt, analysis=updated)
        self.assertTrue(verification["valid"])
        Draft202012Validator(
            schema_document("evidence-onboarding-receipt-verification")
        ).validate(verification)

    def test_apply_is_bound_deduplicated_and_tamper_evident(self) -> None:
        updated, receipt, _queue = onboard_evidence(
            self.analysis,
            self.root,
            coverage_json=self.coverage,
            runtime_traces=[(self.trace, "smoke scenario")],
            apply=True,
        )

        self.assertEqual(receipt["mode"], "applied")
        self.assertEqual(receipt["summary"]["imported"], 2)
        self.assertTrue(updated["components"][0]["coverage"])
        self.assertEqual(len(updated["runtime_evidence"]["imports"]), 1)
        self.assertEqual(
            receipt["result_binding"]["analysis_state_sha256"],
            canonical_json_sha256(updated),
        )
        duplicate, duplicate_receipt, _queue = onboard_evidence(
            updated,
            self.root,
            coverage_json=self.coverage,
            runtime_traces=[(self.trace, "smoke scenario")],
            apply=True,
        )
        self.assertEqual(duplicate_receipt["summary"]["duplicates"], 2)
        self.assertEqual(len(duplicate["runtime_evidence"]["imports"]), 1)

        tampered = copy.deepcopy(receipt)
        tampered["summary"]["imported"] = 99
        self.assertFalse(verify_evidence_onboarding_receipt(tampered)["valid"])
        rehashed = copy.deepcopy(receipt)
        rehashed["summary"]["prospective"]["runtime_imports"] = 99
        rehashed.pop("content_sha256")
        rehashed["content_sha256"] = canonical_json_sha256(rehashed)
        rejected = verify_evidence_onboarding_receipt(rehashed)
        self.assertTrue(rejected["checks"]["content_integrity"])
        self.assertFalse(rejected["checks"]["summary_reconciliation"])
        self.assertFalse(rejected["valid"])

    def test_apply_requires_evidence_and_exact_repository(self) -> None:
        self.coverage.unlink()
        with self.assertRaisesRegex(ValueError, "at least one"):
            onboard_evidence(
                self.analysis,
                self.root,
                use_discovered_coverage=False,
                apply=True,
            )
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        with self.assertRaisesRegex(ValueError, "differs"):
            onboard_evidence(self.analysis, unrelated)

    def test_external_execution_manifest_is_fully_validated_before_apply(self) -> None:
        obligation = self.analysis["assurance"]["obligations"][0]
        test_path = self.root / "test_external.py"
        test_path.write_text("def test_external():\n    assert True\n", encoding="utf-8")
        external = self.root / "external"
        external.mkdir()
        log = external / "pytest.log"
        log.write_text("one passing test\n", encoding="utf-8")
        manifest = external / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
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
            ),
            encoding="utf-8",
        )

        planned, plan, _queue = onboard_evidence(
            self.analysis,
            self.root,
            use_discovered_coverage=False,
            execution_manifests=[(obligation["id"], manifest)],
            initiated_by="CI Importer",
        )
        self.assertEqual(planned, self.analysis)
        self.assertEqual(plan["selected_evidence"][0]["status"], "validated")
        self.assertNotIn(
            "evidence_directory", plan["selected_evidence"][0]["result"]
        )
        self.assertEqual(plan["summary"]["prospective"]["assurance"]["executions"], 1)

        updated, receipt, _queue = onboard_evidence(
            self.analysis,
            self.root,
            use_discovered_coverage=False,
            execution_manifests=[(obligation["id"], manifest)],
            initiated_by="CI Importer",
            evidence_root=self.root / "managed-evidence",
            apply=True,
        )
        self.assertEqual(receipt["selected_evidence"][0]["status"], "imported")
        self.assertEqual(len(updated["assurance"]["executions"]), 1)
        evidence_directory = Path(
            updated["assurance"]["executions"][0]["evidence_directory"]
        )
        self.assertTrue(evidence_directory.is_dir())

    def test_failed_multi_import_removes_only_new_managed_directories(self) -> None:
        managed = self.root / "managed"
        retained = managed / "existing-evidence"
        retained.mkdir(parents=True)
        selected = [
            {
                "kind": "execution_manifest",
                "subject_id": f"OBLIGATION-{index}",
                "label": "",
                "path": str(self.root / f"manifest-{index}.json"),
                "bytes": 1,
                "sha256": str(index) * 64,
            }
            for index in (1, 2)
        ]
        calls = 0

        def fake_import(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("second import rejected")
            created = managed / "EXEC-NEW"
            created.mkdir(parents=True)
            imported_analysis = _args[0]
            assert isinstance(imported_analysis, dict)
            imported_analysis["assurance"]["executions"].append({"id": "EXEC-NEW"})
            return {
                "id": "EXEC-NEW",
                "evidence_directory": str(created),
                "artifacts": [],
            }

        with mock.patch(
            "pysfmea.evidence_onboarding.import_execution_evidence",
            side_effect=fake_import,
        ):
            with self.assertRaisesRegex(ValueError, "second import"):
                _apply_selected(
                    copy.deepcopy(self.analysis),
                    selected,
                    initiated_by="Importer",
                    evidence_root=managed,
                )
        self.assertFalse((managed / "EXEC-NEW").exists())
        self.assertTrue(retained.is_dir())

    def test_cli_applies_and_publishes_receipt_and_queue(self) -> None:
        source = self.root / "analysis.json"
        destination = self.root / "analysis-with-evidence.json"
        receipt = self.root / "receipt.json"
        queue = self.root / "work-queue.json"
        save_analysis(source, self.analysis)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                [
                    "evidence-onboard",
                    str(source),
                    str(self.root),
                    "--coverage-json",
                    str(self.coverage),
                    "--runtime-trace",
                    str(self.trace),
                    "--apply",
                    "--output-analysis",
                    str(destination),
                    "--receipt",
                    str(receipt),
                    "--work-queue",
                    str(queue),
                ]
            )
        self.assertEqual(result, 0)
        self.assertIn("No repository code was executed", output.getvalue())
        persisted = load_analysis(destination)
        receipt_document = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertTrue(
            verify_evidence_onboarding_receipt(
                receipt_document, analysis=persisted
            )["valid"]
        )
        self.assertTrue(queue.is_file())
        verdict_path = self.root / "onboarding-verification.json"
        with contextlib.redirect_stdout(io.StringIO()):
            verify_result = main(
                [
                    "evidence-onboard-verify",
                    str(receipt),
                    "--analysis",
                    str(destination),
                    "--output",
                    str(verdict_path),
                ]
            )
        self.assertEqual(verify_result, 0)
        file_verification = verify_evidence_onboarding_receipt_file(
            receipt, analysis=persisted
        )
        self.assertTrue(file_verification["valid"])
        Draft202012Validator(
            schema_document("evidence-onboarding-receipt-verification")
        ).validate(json.loads(verdict_path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
