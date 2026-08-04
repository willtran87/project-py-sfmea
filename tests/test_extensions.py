from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.config import write_config_template
from pysfmea.discovery import (
    OpenAICompatibleProvider,
    deterministic_summary,
    discover_suggestions,
    evaluate_candidates,
    evidence_packets,
    review_suggestion,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.readiness import repository_readiness
from pysfmea.report import (
    REVIEW_PACKAGE_SCHEMA_FILES,
    export_review_archive,
    export_review_package,
    verify_review_package,
)
from pysfmea.runtime import import_runtime_trace
from pysfmea.scanner import scan_repository
from pysfmea.schemas import REVIEW_PACKAGE_VERIFICATION_FORMAT, schema_document
from pysfmea.signing import sign_review_package, verify_review_signature
from pysfmea.store import load_analysis, merge_rescan, save_analysis
from pysfmea.visuals import (
    coverage_metrics,
    export_coverage,
    export_sequence,
    export_traceability,
    sequence_model,
    traceability_model,
)


class StaticProvider:
    name = "test-provider"
    model = "test-model"

    def generate(self, payload: dict[str, Any], *, task: str) -> dict[str, Any]:
        component_id = payload["component"]["evidence_id"]
        return {
            "suggestions": [
                {
                    "failure_class": "security",
                    "guideword": "Bypass",
                    "failure_mode": "The authorization boundary permits an unauthorized operation.",
                    "trigger": "A crafted request reaches the entrypoint.",
                    "causes": ["Authorization is evaluated after the protected operation."],
                    "local_effect": "The operation executes without a valid authorization decision.",
                    "next_higher_effect": "The service exposes a protected capability.",
                    "possible_end_effects": ["Protected data or operations may be exposed."],
                    "prevention_controls": [],
                    "detection_controls": [],
                    "recommended_actions": ["Enforce authorization before side effects."],
                    "evidence_ids": [component_id],
                    "citation_ids": ["NIST-SP-800-218-PW.7"],
                    "uncertainties": ["The external identity contract was not supplied."],
                    "questions": ["Where is authorization enforced?"],
                    "confidence": "medium",
                }
            ]
        }


class UnsafeProvider(StaticProvider):
    def generate(self, payload: dict[str, Any], *, task: str) -> dict[str, Any]:
        result = super().generate(payload, task=task)
        result["suggestions"][0]["severity"] = 10
        return result


class UnknownCitationProvider(StaticProvider):
    def generate(self, payload: dict[str, Any], *, task: str) -> dict[str, Any]:
        result = super().generate(payload, task=task)
        result["suggestions"][0]["citation_ids"] = ["NASA-INVENTED-CLAUSE"]
        return result


class ExtensionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def validate(value):\n    return bool(value)\n\n"
            "def charge(value):\n    return value * 2\n\n"
            "def checkout(value):\n    validate(value)\n    return charge(value)\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(
            self.root,
            config={
                "requirements": [
                    {
                        "id": "REQ-1",
                        "text": "Process valid requests.",
                        "source": "SRS",
                        "hazards": ["HZ-1"],
                    }
                ],
                "hazards": [
                    {
                        "id": "HZ-1",
                        "description": "Incorrect transaction",
                        "end_effect": "A transaction is processed incorrectly.",
                    }
                ],
                "component_mappings": [
                    {
                        "pattern": "service.py:checkout",
                        "requirements": ["REQ-1"],
                        "hazards": ["HZ-1"],
                    }
                ],
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_sequence_traceability_and_coverage_exports(self) -> None:
        model = sequence_model(self.analysis, "service.py:checkout")
        labels = [value["label"] for value in model["interactions"]]
        self.assertEqual(labels[:2], ["validate", "charge"])
        sequence_path = export_sequence(
            self.analysis, self.root / "sequence.md", "service.py:checkout"
        )
        self.assertIn("sequenceDiagram", sequence_path.read_text(encoding="utf-8"))
        trace = traceability_model(self.analysis)
        self.assertTrue(any(edge["kind"] == "may_contribute_to" for edge in trace["edges"]))
        self.assertTrue(any(edge["kind"] == "mitigates" for edge in trace["edges"]))
        self.assertIn(
            "flowchart LR",
            export_traceability(self.analysis, self.root / "trace.md").read_text(
                encoding="utf-8"
            ),
        )
        bounded = sequence_model(
            self.analysis, "service.py:checkout", max_interactions=1
        )
        self.assertEqual(len(bounded["interactions"]), 1)
        self.assertTrue(bounded["truncated"])
        self.assertIn("max_interactions", bounded["truncation_reasons"])

    def test_repository_readiness_guides_pre_scan_setup(self) -> None:
        missing = repository_readiness(self.root)
        self.assertFalse(missing["ready"])
        self.assertTrue(
            any(check["id"] == "configuration.file" for check in missing["checks"])
        )
        write_config_template(self.root / "sfmea.toml")
        unchanged_template = repository_readiness(self.root)
        self.assertFalse(unchanged_template["ready"])
        self.assertTrue(
            any(
                check["id"] == "configuration.example_template"
                for check in unchanged_template["checks"]
            )
        )
        config_path = self.root / "sfmea.toml"
        configured = (
            config_path.read_text(encoding="utf-8")
            .replace("Example Python System", "Checkout Service")
            .replace("Example unacceptable system condition", "Incorrect checkout")
            .replace("Example reviewer", "Jordan Lee")
            .replace("src/example/", "")
        )
        config_path.write_text(configured, encoding="utf-8")
        ready = repository_readiness(self.root)
        self.assertTrue(ready["ready"])
        self.assertGreater(ready["counts"]["pass"], 0)

    def test_traceability_namespaces_catalog_ids(self) -> None:
        analysis = scan_repository(
            self.root,
            config={
                "hazards": [{"id": "SHARED", "description": "Hazard"}],
                "requirements": [
                    {"id": "SHARED", "text": "Requirement", "hazards": ["SHARED"]}
                ],
            },
        )
        model = traceability_model(analysis)
        shared = [node for node in model["nodes"] if node.get("reference_id") == "SHARED"]
        self.assertEqual({node["kind"] for node in shared}, {"requirement", "hazard"})
        self.assertEqual(len({node["id"] for node in shared}), 2)
        metrics = coverage_metrics(self.analysis)
        self.assertEqual(metrics["requirements"]["coverage_percent"], 100.0)
        self.assertIn(
            "SFMEA analysis coverage",
            export_coverage(self.analysis, self.root / "coverage.md").read_text(
                encoding="utf-8"
            ),
        )

    def test_runtime_trace_import_adds_observed_sequence_edges(self) -> None:
        trace_path = self.root / "trace.json"
        trace_path.write_text(
            json.dumps(
                {
                    "spans": [
                        {"trace_id": "T1", "span_id": "S1", "name": "checkout"},
                        {
                            "trace_id": "T1",
                            "span_id": "S2",
                            "parent_span_id": "S1",
                            "name": "charge",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        record = import_runtime_trace(self.analysis, trace_path, label="checkout test")
        self.assertEqual(record["mapped_span_count"], 2)
        model = sequence_model(self.analysis, "service.py:checkout")
        self.assertTrue(
            any(value["evidence"] == "observed_runtime" for value in model["interactions"])
        )
        history_count = len(self.analysis["history"])
        duplicate = import_runtime_trace(self.analysis, trace_path, label="duplicate")
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(len(self.analysis["runtime_evidence"]["imports"]), 1)
        self.assertEqual(len(self.analysis["history"]), history_count)
        self.assertEqual(self.analysis["summary"]["runtime_mapped_spans"], 2)

    def test_review_package_is_complete_and_manifested(self) -> None:
        destination = self.root / "review-package"
        result = export_review_package(
            self.analysis,
            destination,
            source_analysis=self.root / "analysis.json",
        )
        manifest = json.loads((result / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["analysis_state_sha256"]), 64)
        names = {value["path"] for value in manifest["files"]}
        self.assertTrue(
            {
                "analysis.json",
                "worksheet.csv",
                "worksheet.md",
                "inventory.md",
                "architecture.md",
                "traceability.md",
                "coverage.md",
                "audit.csv",
                "validation.json",
                "summary.json",
                "README.md",
            }.issubset(names)
        )
        self.assertTrue(REVIEW_PACKAGE_SCHEMA_FILES.issubset(names))
        self.assertEqual(manifest["schema_catalog"]["schema_count"], 12)
        self.assertEqual(
            manifest["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
            ],
        )
        self.assertIn("assurance-work.json", names)
        Draft202012Validator(schema_document("review-package-manifest")).validate(
            manifest
        )
        with self.assertRaisesRegex(ValueError, "not empty"):
            export_review_package(self.analysis, destination)
        unexpected = destination / "reviewer-notes.txt"
        unexpected.write_text("preserve me", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unrecognized files"):
            export_review_package(self.analysis, destination, overwrite=True)
        self.assertEqual(unexpected.read_text(encoding="utf-8"), "preserve me")
        unexpected.unlink()
        refreshed = export_review_package(self.analysis, destination, overwrite=True)
        self.assertTrue((refreshed / "manifest.json").is_file())
        self.assertFalse(
            any(path.name.startswith(f".{destination.name}.tmp-") for path in self.root.iterdir())
        )

        historical_profiles = (
            (
                {
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                },
                32,
            ),
            (
                {
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                },
                34,
            ),
            (
                {
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                },
                36,
            ),
            (
                {
                    "detached-signature",
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                },
                37,
            ),
            (
                {
                    "detached-signature",
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                    "workflow-status",
                },
                38,
            ),
            (
                {
                    "assurance-work-queue",
                    "detached-signature",
                    "diagram",
                    "diagram-bundle",
                    "diagram-bundle-verification",
                    "html-report-verification",
                    "review-package-manifest",
                    "review-package-verification",
                    "schema-bundle-verification",
                    "schema-catalog",
                    "workflow-status",
                },
                39,
            ),
        )
        for index, (retained_names, expected_files) in enumerate(
            historical_profiles, start=1
        ):
            compatible = export_review_package(
                self.analysis,
                self.root / f"compatible-package-{index}",
                source_analysis=self.root / "analysis.json",
            )
            catalog_path = compatible / "schema-catalog.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            catalog["schemas"] = [
                entry
                for entry in catalog["schemas"]
                if entry["name"] in retained_names
            ]
            retained_files = {
                "schema-catalog.json",
                *(entry["filename"] for entry in catalog["schemas"]),
            }
            for filename in REVIEW_PACKAGE_SCHEMA_FILES - retained_files:
                (compatible / filename).unlink()
            catalog_path.write_text(
                json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            manifest_path = compatible / "manifest.json"
            compatible_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            compatible_manifest["files"] = [
                entry
                for entry in compatible_manifest["files"]
                if entry["path"] not in REVIEW_PACKAGE_SCHEMA_FILES
                or entry["path"] in retained_files
            ]
            catalog_raw = catalog_path.read_bytes()
            catalog_entry = next(
                entry
                for entry in compatible_manifest["files"]
                if entry["path"] == "schema-catalog.json"
            )
            catalog_entry["bytes"] = len(catalog_raw)
            catalog_entry["sha256"] = hashlib.sha256(catalog_raw).hexdigest()
            compatible_manifest["schema_catalog"].update(
                {
                    "canonical_sha256": canonical_json_sha256(catalog),
                    "schema_count": len(retained_names),
                }
            )
            manifest_path.write_text(
                json.dumps(compatible_manifest, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            compatible_verification = verify_review_package(compatible)
            self.assertTrue(compatible_verification["valid"])
            self.assertEqual(
                compatible_verification["checked_files"], expected_files
            )

        pre_diagnostics_analysis = copy.deepcopy(self.analysis)
        pre_diagnostics_analysis["generator"]["version"] = "0.49.0"
        pre_diagnostics = export_review_package(
            pre_diagnostics_analysis,
            self.root / "pre-diagnostics-package",
            source_analysis=self.root / "analysis.json",
        )
        pre_diagnostics_manifest_path = pre_diagnostics / "manifest.json"
        pre_diagnostics_manifest = json.loads(
            pre_diagnostics_manifest_path.read_text(encoding="utf-8")
        )
        pre_diagnostics_manifest["exporter"]["version"] = "0.49.0"
        pre_diagnostics_manifest["capabilities"].remove(
            "analysis_diagnostics_projection_v1"
        )
        pre_diagnostics_manifest_path.write_text(
            json.dumps(pre_diagnostics_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        pre_diagnostics_verification = verify_review_package(pre_diagnostics)
        self.assertTrue(pre_diagnostics_verification["valid"])
        self.assertEqual(
            pre_diagnostics_verification["capabilities"],
            ["assurance_register_projection", "assurance_work_queue_projection"],
        )
        self.assertEqual(pre_diagnostics_verification["analysis_diagnostics"], {})

        legacy = export_review_package(
            self.analysis,
            self.root / "legacy-package",
            source_analysis=self.root / "analysis.json",
        )
        legacy_manifest_path = legacy / "manifest.json"
        legacy_manifest = json.loads(legacy_manifest_path.read_text(encoding="utf-8"))
        legacy_manifest.pop("schema_catalog")
        legacy_manifest.pop("capabilities")
        legacy_analysis_path = legacy / "analysis.json"
        legacy_analysis = json.loads(
            legacy_analysis_path.read_text(encoding="utf-8")
        )
        legacy_analysis["generator"]["version"] = "0.46.0"
        legacy_analysis_path.write_text(
            json.dumps(legacy_analysis, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        legacy_manifest["exporter"]["version"] = "0.46.0"
        legacy_manifest["analysis_generator"] = legacy_analysis["generator"]
        legacy_manifest["analysis_state_sha256"] = canonical_json_sha256(
            legacy_analysis
        )
        legacy_manifest["files"] = [
            value
            for value in legacy_manifest["files"]
            if value["path"] not in REVIEW_PACKAGE_SCHEMA_FILES
            and value["path"] != "assurance-work.json"
        ]
        legacy_analysis_raw = legacy_analysis_path.read_bytes()
        legacy_analysis_entry = next(
            value
            for value in legacy_manifest["files"]
            if value["path"] == "analysis.json"
        )
        legacy_analysis_entry["bytes"] = len(legacy_analysis_raw)
        legacy_analysis_entry["sha256"] = hashlib.sha256(
            legacy_analysis_raw
        ).hexdigest()
        legacy_manifest_path.write_text(
            json.dumps(legacy_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        for filename in REVIEW_PACKAGE_SCHEMA_FILES:
            (legacy / filename).unlink()
        (legacy / "assurance-work.json").unlink()
        legacy_verification = verify_review_package(legacy)
        self.assertTrue(legacy_verification["valid"])
        self.assertEqual(legacy_verification["checked_files"], 26)
        self.assertEqual(legacy_verification["schema_catalog"], {})
        self.assertEqual(legacy_verification["assurance_work_queue"], {})

        legacy_archive = self.root / "legacy-package.zip"
        with zipfile.ZipFile(
            legacy_archive, "w", compression=zipfile.ZIP_DEFLATED
        ) as bundle:
            for path in legacy.iterdir():
                bundle.write(path, path.name)
        legacy_archive_verification = verify_review_package(legacy_archive)
        self.assertTrue(legacy_archive_verification["valid"])
        self.assertEqual(legacy_archive_verification["checked_files"], 26)

        self.analysis["project"]["settings"]["config_file"] = str(
            self.root / "sfmea.toml"
        )
        self.analysis["runtime_evidence"]["imports"] = [
            {
                "source": str(self.root / "runtime" / "trace.json"),
                "mapped_span_count": 0,
                "unmapped_span_count": 0,
            }
        ]
        portable = export_review_package(
            self.analysis,
            self.root / "portable-package",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        snapshot = json.loads((portable / "analysis.json").read_text(encoding="utf-8"))
        portable_manifest = json.loads(
            (portable / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(snapshot["project"]["root"], ".")
        self.assertEqual(snapshot["project"]["settings"]["config_file"], "sfmea.toml")
        self.assertEqual(
            snapshot["runtime_evidence"]["imports"][0]["source"], "trace.json"
        )
        self.assertEqual(portable_manifest["source_analysis"], "analysis.json")
        self.assertTrue(portable_manifest["portable"])
        self.assertEqual(self.analysis["project"]["root"], str(self.root))

    def test_review_package_verification_rejects_tampering_and_unsafe_content(self) -> None:
        destination = export_review_package(
            self.analysis,
            self.root / "verified-package",
            source_analysis=self.root / "analysis.json",
        )
        verified = verify_review_package(destination)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["checked_files"], 40)
        self.assertEqual(
            verified["verification_format"], REVIEW_PACKAGE_VERIFICATION_FORMAT
        )
        Draft202012Validator(schema_document("review-package-verification")).validate(
            verified
        )
        self.assertTrue(verified["schema_catalog"]["valid"])
        self.assertEqual(
            verified["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
            ],
        )
        self.assertTrue(all(verified["schema_catalog"]["checks"].values()))
        self.assertTrue(verified["analysis_diagnostics"]["valid"])
        self.assertEqual(verified["analysis_diagnostics"]["artifact_count"], 5)
        self.assertTrue(all(verified["analysis_diagnostics"]["checks"].values()))
        self.assertTrue(verified["assurance_work_queue"]["valid"])
        self.assertEqual(verified["assurance_work_queue"]["status"], "matched")
        self.assertTrue(
            all(verified["assurance_work_queue"]["checks"].values())
        )
        self.assertTrue(verified["assurance_register"]["valid"])
        self.assertTrue(all(verified["assurance_register"]["checks"].values()))
        self.assertEqual(
            verified["binding"]["analysis_state_sha256"],
            json.loads(
                (destination / "manifest.json").read_text(encoding="utf-8")
            )["analysis_state_sha256"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify-package", str(destination), "--json"]), 0)
        human_output = io.StringIO()
        with contextlib.redirect_stdout(human_output):
            self.assertEqual(main(["verify-package", str(destination)]), 0)
        self.assertIn(
            "Schema catalog: valid=True, schemas=12", human_output.getvalue()
        )
        self.assertIn(
            "Assurance work queue: valid=True, status=matched",
            human_output.getvalue(),
        )
        self.assertIn(
            "Assurance register: valid=True, obligations=",
            human_output.getvalue(),
        )
        self.assertIn(
            "Analysis diagnostics: valid=True, artifacts=5",
            human_output.getvalue(),
        )
        self.assertIn(
            "Capabilities: analysis_diagnostics_projection_v1, "
            "assurance_register_projection, assurance_work_queue_projection",
            human_output.getvalue(),
        )

        queue_path = destination / "assurance-work.json"
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        queue["notice"] += " Rewritten after packaging."
        queue_content = dict(queue)
        queue_content.pop("integrity")
        queue["integrity"]["content_sha256"] = canonical_json_sha256(
            queue_content
        )
        queue_path.write_text(
            json.dumps(queue, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        queue_raw = queue_path.read_bytes()
        queue_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "assurance-work.json"
        )
        queue_entry["bytes"] = len(queue_raw)
        queue_entry["sha256"] = hashlib.sha256(queue_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        queue_tampered = verify_review_package(destination)
        queue_rules = {value["rule_id"] for value in queue_tampered["findings"]}
        self.assertFalse(queue_tampered["valid"])
        self.assertIn("package.assurance_work_queue_invalid", queue_rules)
        self.assertNotIn("package.checksum_mismatch", queue_rules)
        self.assertTrue(
            queue_tampered["assurance_work_queue"]["checks"]["content_integrity"]
        )
        self.assertFalse(
            queue_tampered["assurance_work_queue"]["checks"]["semantic_projection"]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        register_path = destination / "assurance-register.json"
        register = json.loads(register_path.read_text(encoding="utf-8"))
        register["notice"] += " Rewritten after packaging."
        register_path.write_text(
            json.dumps(register, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        register_raw = register_path.read_bytes()
        register_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "assurance-register.json"
        )
        register_entry["bytes"] = len(register_raw)
        register_entry["sha256"] = hashlib.sha256(register_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        register_tampered = verify_review_package(destination)
        register_rules = {
            value["rule_id"] for value in register_tampered["findings"]
        }
        self.assertFalse(register_tampered["valid"])
        self.assertIn("package.assurance_register_invalid", register_rules)
        self.assertNotIn("package.checksum_mismatch", register_rules)
        self.assertFalse(
            register_tampered["assurance_register"]["checks"][
                "semantic_projection"
            ]
        )
        self.assertTrue(register_tampered["assurance_work_queue"]["valid"])

        export_review_package(self.analysis, destination, overwrite=True)

        validation_path = destination / "validation.json"
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["counts"]["warning"] += 1
        validation_path.write_text(
            json.dumps(validation, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        validation_raw = validation_path.read_bytes()
        validation_entry = next(
            value
            for value in manifest["files"]
            if value["path"] == "validation.json"
        )
        validation_entry["bytes"] = len(validation_raw)
        validation_entry["sha256"] = hashlib.sha256(validation_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        diagnostics_tampered = verify_review_package(destination)
        diagnostics_rules = {
            value["rule_id"] for value in diagnostics_tampered["findings"]
        }
        self.assertFalse(diagnostics_tampered["valid"])
        self.assertIn("package.analysis_diagnostics_invalid", diagnostics_rules)
        self.assertNotIn("package.checksum_mismatch", diagnostics_rules)
        self.assertFalse(
            diagnostics_tampered["analysis_diagnostics"]["checks"]["validation"]
        )
        self.assertTrue(
            diagnostics_tampered["analysis_diagnostics"]["checks"]["summary"]
        )

        export_review_package(self.analysis, destination, overwrite=True)

        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.pop("capabilities")
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        undeclared = verify_review_package(destination)
        self.assertFalse(undeclared["valid"])
        self.assertIn(
            "package.capabilities_missing",
            {value["rule_id"] for value in undeclared["findings"]},
        )
        self.assertTrue(undeclared["assurance_work_queue"]["valid"])

        export_review_package(self.analysis, destination, overwrite=True)

        schema_path = destination / "pysfmea-diagram.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["title"] = "Tampered schema title"
        schema_path.write_text(
            json.dumps(schema, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        schema_tampered = verify_review_package(destination)
        Draft202012Validator(schema_document("review-package-verification")).validate(
            schema_tampered
        )
        schema_rules = {value["rule_id"] for value in schema_tampered["findings"]}
        self.assertIn("package.checksum_mismatch", schema_rules)
        self.assertIn("package.schema.digest", schema_rules)

        export_review_package(self.analysis, destination, overwrite=True)

        summary_path = destination / "summary.json"
        summary_path.write_text(
            summary_path.read_text(encoding="utf-8") + "tampered\n",
            encoding="utf-8",
        )
        tampered = verify_review_package(destination)
        tampered_rules = {value["rule_id"] for value in tampered["findings"]}
        self.assertFalse(tampered["valid"])
        self.assertIn("package.checksum_mismatch", tampered_rules)
        self.assertIn("package.size_mismatch", tampered_rules)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify-package", str(destination)]), 1)

        missing = verify_review_package(self.root / "missing-review-package.zip")
        self.assertFalse(missing["valid"])
        Draft202012Validator(schema_document("review-package-verification")).validate(
            missing
        )

        export_review_package(self.analysis, destination, overwrite=True)
        unexpected = destination / "reviewer-notes.txt"
        unexpected.write_text("not manifested\n", encoding="utf-8")
        extra = verify_review_package(destination)
        self.assertIn(
            "package.file_unexpected",
            {value["rule_id"] for value in extra["findings"]},
        )
        unexpected.unlink()

        unexpected_directory = destination / "nested-content"
        unexpected_directory.mkdir()
        nested_file = unexpected_directory / "do-not-traverse.txt"
        nested_file.write_text("unexpected\n", encoding="utf-8")
        nested = verify_review_package(destination)
        self.assertIn(
            "package.entry_type",
            {value["rule_id"] for value in nested["findings"]},
        )
        nested_file.unlink()
        unexpected_directory.rmdir()

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["bytes"] = 100_000_001
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        oversized = verify_review_package(destination)
        self.assertIn(
            "package.file_limit",
            {value["rule_id"] for value in oversized["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["files"][:6]:
            entry["bytes"] = 90_000_000
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        excessive_total = verify_review_package(destination)
        self.assertIn(
            "package.total_limit",
            {value["rule_id"] for value in excessive_total["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"].extend(
            dict(manifest["files"][0]) for _ in range(61)
        )
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        excessive_entries = verify_review_package(destination)
        self.assertIn(
            "package.file_list_invalid",
            {value["rule_id"] for value in excessive_entries["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["path"] = "../escape.txt"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        unsafe = verify_review_package(destination)
        self.assertIn(
            "package.path_unsafe",
            {value["rule_id"] for value in unsafe["findings"]},
        )

        export_review_package(self.analysis, destination, overwrite=True)
        analysis_path = destination / "analysis.json"
        snapshot = json.loads(analysis_path.read_text(encoding="utf-8"))
        snapshot["generator"] = {"name": "different-generator", "version": "999"}
        analysis_path.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        raw = analysis_path.read_bytes()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        analysis_entry = next(
            value for value in manifest["files"] if value["path"] == "analysis.json"
        )
        analysis_entry["bytes"] = len(raw)
        analysis_entry["sha256"] = hashlib.sha256(raw).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        provenance = verify_review_package(destination)
        provenance_rules = {value["rule_id"] for value in provenance["findings"]}
        self.assertIn("package.provenance_mismatch", provenance_rules)
        self.assertIn("package.analysis_state_digest_mismatch", provenance_rules)

    def test_review_archive_is_atomic_and_safely_verified(self) -> None:
        archive = export_review_archive(
            self.analysis,
            self.root / "review-package.zip",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        verified = verify_review_package(archive)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["container"], "zip")
        self.assertEqual(verified["checked_files"], 40)
        self.assertTrue(verified["schema_catalog"]["valid"])
        self.assertEqual(
            verified["capabilities"],
            [
                "analysis_diagnostics_projection_v1",
                "assurance_register_projection",
                "assurance_work_queue_projection",
            ],
        )
        self.assertTrue(verified["assurance_work_queue"]["valid"])
        self.assertTrue(verified["analysis_diagnostics"]["valid"])
        self.assertTrue(verified["assurance_register"]["valid"])
        self.assertTrue(
            verified["assurance_work_queue"]["path"].endswith(
                "review-package.zip!/assurance-work.json"
            )
        )
        self.assertNotIn(
            ".pysfmea-verify-",
            verified["assurance_work_queue"]["path"],
        )
        self.assertEqual(len(verified["archive_sha256"]), 64)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(
                set(bundle.namelist()),
                {
                    "analysis.json",
                    "assurance-register.csv",
                    "assurance-register.json",
                    "assurance-work.json",
                    "assurance-register.md",
                    "architecture.md",
                    "audit.csv",
                    "coverage.md",
                    "citations.json",
                    "evidence-catalog.json",
                    "sfta.json",
                    "sfta-gaps.csv",
                    "findings.sarif",
                    "components.cdx.json",
                    "run-manifest.json",
                    "system-context.json",
                    "repository-inventory.json",
                    "adapter-runs.json",
                    "guidance-traceability.csv",
                    "guidance-traceability.json",
                    "inventory.md",
                    "manifest.json",
                    "README.md",
                    "schema-catalog.json",
                    "pysfmea-detached-signature.schema.json",
                    "pysfmea-diagram.schema.json",
                    "pysfmea-diagram-bundle.schema.json",
                    "pysfmea-diagram-bundle-verification.schema.json",
                    "pysfmea-html-report-verification.schema.json",
                    "pysfmea-schema-bundle-verification.schema.json",
                    "pysfmea-schema-catalog.schema.json",
                    "pysfmea-review-package-manifest.schema.json",
                    "pysfmea-review-package-verification.schema.json",
                    "pysfmea-workflow-status.schema.json",
                    "pysfmea-assurance-work-queue.schema.json",
                    "pysfmea-assurance-work-queue-verification.schema.json",
                    "summary.json",
                    "traceability.md",
                    "validation.json",
                    "worksheet.csv",
                    "worksheet.md",
                },
            )
            contents = {name: bundle.read(name) for name in bundle.namelist()}
        with self.assertRaisesRegex(ValueError, "already exists"):
            export_review_archive(self.analysis, archive)

        contents["summary.json"] += b"tampered\n"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, raw in contents.items():
                bundle.writestr(name, raw)
        tampered = verify_review_package(archive)
        self.assertFalse(tampered["valid"])
        self.assertIn(
            "package.checksum_mismatch",
            {value["rule_id"] for value in tampered["findings"]},
        )

        refreshed = export_review_archive(
            self.analysis,
            archive,
            overwrite=True,
        )
        self.assertTrue(verify_review_package(refreshed)["valid"])

        malicious = self.root / "unsafe.zip"
        with zipfile.ZipFile(malicious, "w") as bundle:
            bundle.writestr("../escape.txt", "must not escape")
        unsafe = verify_review_package(malicious)
        self.assertFalse(unsafe["valid"])
        self.assertIn(
            "package.archive_path_unsafe",
            {value["rule_id"] for value in unsafe["findings"]},
        )
        self.assertFalse((self.root / "escape.txt").exists())

        duplicate = self.root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as bundle:
                bundle.writestr("analysis.json", "first")
                bundle.writestr("analysis.json", "second")
        duplicated = verify_review_package(duplicate)
        self.assertIn(
            "package.archive_entry_duplicate",
            {value["rule_id"] for value in duplicated["findings"]},
        )

        symlink = self.root / "symlink.zip"
        link_info = zipfile.ZipInfo("analysis.json")
        link_info.create_system = 3
        link_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(symlink, "w") as bundle:
            bundle.writestr(link_info, "outside.json")
        linked = verify_review_package(symlink)
        self.assertIn(
            "package.archive_entry_type",
            {value["rule_id"] for value in linked["findings"]},
        )

        bomb = self.root / "ratio-limit.zip"
        with zipfile.ZipFile(
            bomb, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as bundle:
            bundle.writestr("analysis.json", b"0" * 2_000_000)
        limited = verify_review_package(bomb)
        self.assertIn(
            "package.archive_ratio_limit",
            {value["rule_id"] for value in limited["findings"]},
        )

    @unittest.skipUnless(
        importlib.util.find_spec("cryptography"), "optional signing dependency unavailable"
    )
    def test_detached_signature_authenticates_package_and_claims(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        private_path = self.root / "signing-private.pem"
        public_path = self.root / "signing-public.pem"
        private_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"test-passphrase"),
            )
        )
        public_path.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        archive = export_review_archive(
            self.analysis,
            self.root / "signed-review.zip",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        signature_path = sign_review_package(
            archive,
            private_path,
            "Quality Engineering Release",
            passphrase=b"test-passphrase",
        )
        verified = verify_review_signature(archive, signature_path, public_path)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["signature"]["valid"])
        self.assertEqual(
            verified["signature"]["signer"], "Quality Engineering Release"
        )
        self.assertTrue(
            verified["signature"]["key_fingerprint"].startswith("sha256:")
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "verify-package",
                        str(archive),
                        "--signature",
                        str(signature_path),
                        "--public-key",
                        str(public_path),
                        "--json",
                    ]
                ),
                0,
            )
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "verify-package",
                        str(archive),
                        "--signature",
                        str(signature_path),
                    ]
                ),
                2,
            )
        with self.assertRaisesRegex(ValueError, "already exists"):
            sign_review_package(archive, private_path, "Duplicate")

        other_private = Ed25519PrivateKey.generate()
        other_public = self.root / "other-public.pem"
        other_public.write_bytes(
            other_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        wrong_key = verify_review_signature(archive, signature_path, other_public)
        self.assertIn(
            "signature.key_mismatch",
            {value["rule_id"] for value in wrong_key["findings"]},
        )

        envelope = json.loads(signature_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("detached-signature")).validate(envelope)
        original = json.dumps(envelope, indent=2) + "\n"
        envelope["statement"]["signer"] = "Impersonated signer"
        signature_path.write_text(
            json.dumps(envelope, indent=2) + "\n", encoding="utf-8"
        )
        modified = verify_review_signature(archive, signature_path, public_path)
        self.assertIn(
            "signature.verification_failed",
            {value["rule_id"] for value in modified["findings"]},
        )
        signature_path.write_text(original, encoding="utf-8")

        second_archive = export_review_archive(
            self.analysis,
            self.root / "second-review.zip",
            source_analysis=self.root / "analysis.json",
            portable=True,
        )
        replayed = verify_review_signature(second_archive, signature_path, public_path)
        self.assertIn(
            "signature.subject_mismatch",
            {value["rule_id"] for value in replayed["findings"]},
        )

        directory = export_review_package(
            self.analysis,
            self.root / "unsigned-directory",
        )
        with self.assertRaisesRegex(ValueError, "outside the package directory"):
            sign_review_package(
                directory,
                private_path,
                "Invalid destination",
                destination=directory / "signature.json",
                passphrase=b"test-passphrase",
            )

    def test_provider_rejects_spoofed_loopback_and_embedded_credentials(self) -> None:
        payload = {"component": {"evidence_id": "CMP-1"}}
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            OpenAICompatibleProvider(
                "http://localhost.evil.example/v1/chat/completions", "model"
            ).generate(payload, task="test")
        with self.assertRaisesRegex(ValueError, "embedded credentials"):
            OpenAICompatibleProvider(
                "https://user:secret@example.com/v1/chat/completions", "model"
            ).generate(payload, task="test")

    def test_grounded_suggestion_review_and_baseline_invalidation(self) -> None:
        self.analysis["guidance"]["active_profiles"] = ["core_sfmea", "security"]
        created = discover_suggestions(
            self.analysis,
            StaticProvider(),
            scope="service.py:checkout",
            limit=1,
        )
        self.assertEqual(len(created), 1)
        self.assertEqual(self.analysis["summary"]["suggestions"]["proposed"], 1)
        self.assertNotIn("severity", created[0]["content"])
        self.assertEqual(
            created[0]["proposed_citation_ids"], ["NIST-SP-800-218-PW.7"]
        )
        reviewed = review_suggestion(
            self.analysis,
            created[0]["id"],
            decision="accept",
            reviewer="Jordan",
            rationale="Credible authorization boundary failure.",
        )
        self.assertEqual(reviewed["status"], "accepted")
        materialized = next(
            item
            for item in self.analysis["items"]
            if item["id"] == reviewed["materialized_item_id"]
        )
        self.assertEqual(materialized["review"]["disposition"], "unreviewed")
        self.assertEqual(materialized["scanner"]["rule_id"], "machine_suggestion")
        self.assertEqual(
            materialized["scanner"]["citations"][0]["status"], "reviewer_accepted"
        )
        persisted_path = self.root / "accepted-citation.json"
        save_analysis(persisted_path, self.analysis)
        persisted = load_analysis(persisted_path)
        persisted_item = next(
            item
            for item in persisted["items"]
            if item["id"] == reviewed["materialized_item_id"]
        )
        self.assertTrue(
            any(
                citation["citation_id"] == "NIST-SP-800-218-PW.7"
                and citation["status"] == "reviewer_accepted"
                for citation in persisted_item["scanner"]["citations"]
            )
        )

        proposed = discover_suggestions(
            self.analysis,
            StaticProvider(),
            scope="service.py:charge",
            limit=1,
        )[0]
        (self.root / "service.py").write_text(
            (self.root / "service.py").read_text(encoding="utf-8") + "\n# baseline change\n",
            encoding="utf-8",
        )
        merged = merge_rescan(self.analysis, scan_repository(self.root))
        stale = next(value for value in merged["suggestions"] if value["id"] == proposed["id"])
        self.assertEqual(stale["status"], "stale")
        retained = next(
            item for item in merged["items"] if item["id"] == reviewed["materialized_item_id"]
        )
        self.assertEqual(retained["source_change"], "manual")
        self.assertEqual(retained["source_status"], "active")

    def test_machine_discovery_rejects_invented_guidance_citation(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown guidance IDs"):
            discover_suggestions(
                self.analysis,
                UnknownCitationProvider(),
                scope="service.py:checkout",
                limit=1,
            )

    def test_framework_metadata_summary_and_evaluation_hook(self) -> None:
        (self.root / "api.py").write_text(
            "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
            "@router.post('/checkout')\ndef endpoint(value):\n    return value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        endpoint = next(value for value in analysis["components"] if value["qualname"] == "endpoint")
        self.assertIn("fastapi", endpoint["frameworks"])
        self.assertIn("http_route", endpoint["entrypoint_types"])
        summary = deterministic_summary(analysis)
        self.assertGreater(summary["counts"]["failure_modes"], 0)
        expected = {
            "cases": [
                {"component": "endpoint", "rule_id": "functional.omission"}
            ]
        }
        result = evaluate_candidates(analysis, expected)
        self.assertEqual(result["recall"], 1.0)

        (self.root / "other.py").write_text(
            "def endpoint(value):\n    return value\n", encoding="utf-8"
        )
        ambiguous = scan_repository(self.root)
        with self.assertRaisesRegex(ValueError, "ambiguous across sources"):
            evaluate_candidates(ambiguous, expected)
        expected["cases"][0]["source"] = "api.py"
        source_aware = evaluate_candidates(ambiguous, expected)
        self.assertEqual(source_aware["matched"], 1)
        self.assertEqual(source_aware["missing"], [])

    def test_openapi_and_protobuf_contracts_become_analysis_elements(self) -> None:
        (self.root / "openapi.json").write_text(
            json.dumps(
                {
                    "openapi": "3.1.0",
                    "paths": {"/payments": {"post": {"responses": {"200": {}}}}},
                    "components": {"schemas": {"Payment": {"type": "object"}}},
                }
            ),
            encoding="utf-8",
        )
        (self.root / "payments.proto").write_text(
            "syntax = \"proto3\";\nmessage Payment {}\nservice Billing { rpc Charge(Payment) returns (Payment); }\n",
            encoding="utf-8",
        )
        analysis = scan_repository(
            self.root,
            config={
                "hazards": [
                    {
                        "id": "HZ-CONTRACT",
                        "description": "Payment request is misinterpreted.",
                        "end_effect": "A payment is processed incorrectly.",
                        "severity": 8,
                    }
                ],
                "requirements": [
                    {"id": "REQ-CONTRACT", "text": "Maintain API compatibility."}
                ],
                "system_interfaces": [
                    {"id": "IF-PAY", "source": "Client", "target": "Payment API"}
                ],
                "component_mappings": [
                    {
                        "pattern": "openapi.json:Interface contract *",
                        "subsystem": "Payments",
                        "requirements": ["REQ-CONTRACT"],
                        "hazards": ["HZ-CONTRACT"],
                        "interfaces": ["IF-PAY"],
                    }
                ],
            },
        )
        self.assertEqual(len(analysis["context"]["contracts"]), 2)
        contract_items = [
            item
            for item in analysis["items"]
            if item["scanner"]["rule_id"] == "interface.contract_compatibility"
        ]
        self.assertEqual(len(contract_items), 2)
        evidence = " ".join(contract_items[0]["scanner"]["evidence"])
        self.assertTrue("POST /payments" in evidence or "Charge" in evidence)
        openapi_item = next(
            item for item in contract_items if item["source"]["path"] == "openapi.json"
        )
        self.assertEqual(openapi_item["review"]["requirement"], "REQ-CONTRACT")
        self.assertEqual(openapi_item["review"]["linked_hazards"], ["HZ-CONTRACT"])
        self.assertEqual(openapi_item["review"]["severity"], 8)
        openapi_component = next(
            component
            for component in analysis["components"]
            if component["id"] == openapi_item["component_id"]
        )
        self.assertEqual(openapi_component["interface_ids"], ["IF-PAY"])
        self.assertEqual(openapi_component["subsystems"], ["Payments"])

    def test_model_cannot_generate_decision_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "prohibited decision fields"):
            discover_suggestions(
                self.analysis,
                UnsafeProvider(),
                scope="service.py:checkout",
                limit=1,
            )

    def test_evidence_packets_redact_common_secret_shapes(self) -> None:
        self.analysis["context"]["project"]["operating_context"] = (
            "API_KEY=super-secret-value and Bearer abc.def.ghi"
        )
        packet = evidence_packets(
            self.analysis, scope="service.py:checkout", limit=1
        )[0]
        serialized = json.dumps(packet)
        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("abc.def.ghi", serialized)
        self.assertIn("[REDACTED]", serialized)


if __name__ == "__main__":
    unittest.main()
