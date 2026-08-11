from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.integrity import canonical_json_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.sdk import PLUGIN_MANIFEST_FORMAT, validate_manifest
from pysfmea.sdk.host import (
    export_plugin_run,
    run_plugin,
    verify_plugin_run,
    verify_plugin_run_file,
)
from pysfmea.store import load_analysis, save_analysis


class PluginSdkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "sample.py").write_text(
            "def calculate(value):\n    return value + 1\n", encoding="utf-8"
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_reference_plugin_runs_with_bound_observation_receipt(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        self.analysis = load_analysis(analysis_path)
        manifest = (
            Path(__file__).parents[1] / "examples" / "plugins" / "reference_plugin.json"
        )
        manifest_document = json.loads(manifest.read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("plugin-manifest")).validate(
            manifest_document
        )
        request = {
            "format": "pysfmea-plugin-request-1",
            "sdk_api": "1.0",
            "plugin_id": manifest_document["id"],
            "capability": "analyze",
            "analysis_binding": {
                "baseline_id": self.analysis["project"]["baseline"]["id"],
                "analysis_state_sha256": canonical_json_sha256(self.analysis),
            },
            "analysis": self.analysis,
            "authority": "Return observations only.",
        }
        Draft202012Validator(schema_document("plugin-request")).validate(request)
        result = run_plugin(manifest, self.analysis)
        Draft202012Validator(schema_document("plugin-run")).validate(result)
        self.assertEqual(result["format"], "pysfmea-plugin-run-1")
        self.assertEqual(result["plugin"]["id"], "org.pysfmea.reference.inventory")
        self.assertEqual(len(result["observations"]), 1)
        self.assertFalse(result["execution"]["os_sandbox"])
        self.assertEqual(
            result["analysis_binding"]["baseline_id"],
            self.analysis["project"]["baseline"]["id"],
        )
        verification = verify_plugin_run(
            result, analysis=self.analysis, manifest_source=manifest
        )
        response = {
            "format": "pysfmea-plugin-response-1",
            "plugin_id": manifest_document["id"],
            "observations": result["observations"],
        }
        Draft202012Validator(schema_document("plugin-response")).validate(response)
        Draft202012Validator(schema_document("plugin-run-verification")).validate(
            verification
        )
        self.assertTrue(verification["valid"])
        self.assertTrue(all(value is not False for value in verification["checks"].values()))

        run_path = export_plugin_run(result, self.root / "plugin-run.json")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "plugin-run-verify",
                    str(run_path),
                    "--analysis",
                    str(analysis_path),
                    "--manifest",
                    str(manifest),
                    "--json",
                ]
            )
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(output.getvalue())["valid"])

        result["observations"][0]["message"] = "tampered"
        rejected = verify_plugin_run(
            result, analysis=self.analysis, manifest_source=manifest
        )
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["content_integrity"])

    def test_manifest_rejects_incompatible_api_and_unknown_fields(self) -> None:
        manifest = {
            "format": PLUGIN_MANIFEST_FORMAT,
            "id": "org.example.plugin",
            "name": "Example",
            "version": "1.0.0",
            "sdk_api": "2.0",
            "command": ["{python}", "plugin.py"],
            "capabilities": ["analyze"],
            "deterministic": True,
            "timeout_seconds": 10,
            "trust": "third_party",
        }
        with self.assertRaisesRegex(ValueError, "host supports"):
            validate_manifest(manifest, path=self.root / "manifest.json")
        manifest["sdk_api"] = "1.0"
        manifest["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            validate_manifest(manifest, path=self.root / "manifest.json")

    def test_host_rejects_identity_spoofing(self) -> None:
        plugin = self.root / "plugin.py"
        plugin.write_text(
            "import json,sys\n"
            "request=json.load(sys.stdin)\n"
            "json.dump({'format':'pysfmea-plugin-response-1',"
            "'plugin_id':'org.attacker.plugin','observations':[]},sys.stdout)\n",
            encoding="utf-8",
        )
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "format": PLUGIN_MANIFEST_FORMAT,
                    "id": "org.example.plugin",
                    "name": "Example",
                    "version": "1.0.0",
                    "sdk_api": "1.0",
                    "command": ["{python}", "plugin.py"],
                    "capabilities": ["analyze"],
                    "deterministic": True,
                    "timeout_seconds": 10,
                    "trust": "third_party",
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            run_plugin(manifest, self.analysis)

    def test_missing_run_returns_schema_backed_rejection(self) -> None:
        rejected = verify_plugin_run_file(
            self.root / "missing.json", analysis=self.analysis
        )
        self.assertFalse(rejected["valid"])
        Draft202012Validator(schema_document("plugin-run-verification")).validate(
            rejected
        )


if __name__ == "__main__":
    unittest.main()
