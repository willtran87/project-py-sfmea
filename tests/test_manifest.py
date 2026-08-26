from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.adapters import adapter_registry_snapshot
from pysfmea.integrity import canonical_json_sha256, verify_run_manifest_integrity
from pysfmea.manifest import current_audit_manifest
from pysfmea.scanner import scan_repository
from pysfmea.validation import validate_analysis


class RunManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "service.py").write_text(
            "def execute(value):\n    return value\n", encoding="utf-8"
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_registry_publishes_typed_capabilities_health_and_isolation(self) -> None:
        registry = adapter_registry_snapshot(self.analysis)
        self.assertEqual(registry["schema_version"], "pysfmea-adapter-registry-1")
        self.assertGreaterEqual(registry["summary"]["total"], 16)
        self.assertEqual(len(registry["registry_sha256"]), 64)
        identifiers = {value["id"] for value in registry["adapters"]}
        self.assertIn("assurance.container_runner", identifiers)
        self.assertIn("export.json_schema_catalog", identifiers)
        runner = next(
            value
            for value in registry["adapters"]
            if value["id"] == "assurance.container_runner"
        )
        self.assertEqual(runner["isolation"], "approved_disposable_container")
        self.assertEqual(runner["trust_level"], "observed")
        coverage = next(
            value for value in registry["adapters"] if value["id"] == "coverage.py_json"
        )
        self.assertEqual(coverage["health"]["status"], "not_configured")
        schema_exporter = next(
            value
            for value in registry["adapters"]
            if value["id"] == "export.json_schema_catalog"
        )
        self.assertEqual(schema_exporter["trust_level"], "deterministic")
        self.assertEqual(schema_exporter["output_schema"], "json-schema-draft-2020-12")

    def test_scan_manifest_is_canonical_and_package_audit_is_separate(self) -> None:
        manifest = self.analysis["run_manifest"]
        self.assertEqual(manifest["schema_version"], "pysfmea-run-manifest-1")
        self.assertEqual(
            manifest["repository"]["baseline_id"],
            self.analysis["project"]["baseline"]["id"],
        )
        supplied = manifest["manifest_sha256"]
        canonical = dict(manifest)
        canonical.pop("manifest_sha256")
        actual = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(supplied, actual)
        self.assertFalse(manifest["commands"][0]["repository_code_executed"])
        audit = current_audit_manifest(self.analysis)
        self.assertEqual(audit["scan_manifest"]["id"], manifest["id"])
        self.assertIn("review_decisions", audit)
        self.assertIn("test_executions", audit)
        self.assertNotIn("generated_at", manifest["resolved_inputs"])
        integrity = verify_run_manifest_integrity(self.analysis)
        self.assertTrue(integrity["valid"], integrity["failures"])
        self.assertTrue(all(integrity["checks"].values()))

    def test_manifest_tampering_and_rehashed_false_bindings_fail_closed(self) -> None:
        timestamp_tampered = copy.deepcopy(self.analysis)
        timestamp_tampered["run_manifest"]["created_at"] = "2030-01-01T00:00:00+00:00"
        timestamp_result = verify_run_manifest_integrity(timestamp_tampered)
        self.assertFalse(timestamp_result["valid"])
        self.assertFalse(timestamp_result["checks"]["content_integrity"])
        self.assertFalse(timestamp_result["checks"]["timestamp_binding"])
        self.assertFalse(timestamp_result["checks"]["identity_binding"])

        rebound = copy.deepcopy(self.analysis)
        manifest = rebound["run_manifest"]
        manifest["resolved_inputs"]["source_digest"] = "0" * 64
        manifest["resolved_inputs_sha256"] = canonical_json_sha256(
            manifest["resolved_inputs"]
        )
        canonical = dict(manifest)
        canonical.pop("manifest_sha256")
        manifest["manifest_sha256"] = canonical_json_sha256(canonical)
        rebound_result = verify_run_manifest_integrity(rebound)
        self.assertTrue(rebound_result["checks"]["content_integrity"])
        self.assertTrue(rebound_result["checks"]["resolved_inputs_integrity"])
        self.assertFalse(rebound_result["checks"]["resolved_inputs_binding"])
        rules = {
            finding["rule_id"] for finding in validate_analysis(rebound)["findings"]
        }
        self.assertIn("run_manifest.resolved_inputs_binding", rules)

    def test_manifest_verifier_contains_malformed_nested_claims(self) -> None:
        malformed = copy.deepcopy(self.analysis)
        malformed["project"]["baseline"]["vcs"] = None
        malformed["guidance"]["profiles"] = None
        malformed["guidance"]["sources"] = None
        malformed["run_manifest"]["resolved_inputs"] = None
        result = verify_run_manifest_integrity(malformed)
        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["resolved_inputs_shape"])
        self.assertIn(
            "run_manifest.resolved_inputs_shape",
            {failure["code"] for failure in result["failures"]},
        )


if __name__ == "__main__":
    unittest.main()
