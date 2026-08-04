from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.adapters import adapter_registry_snapshot
from pysfmea.manifest import current_audit_manifest
from pysfmea.scanner import scan_repository


class RunManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
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


if __name__ == "__main__":
    unittest.main()
