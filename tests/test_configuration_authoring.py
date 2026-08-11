from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.config import load_config
from pysfmea.configuration_authoring import (
    CONFIGURATION_AUTHORING_APPLY_RECEIPT_FORMAT,
    apply_configuration_authoring,
    configuration_authoring_draft,
    seal_configuration_authoring_draft,
    verify_configuration_authoring_file,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.model import stable_id
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis
from pysfmea.workflow import workflow_status


class ConfigurationAuthoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "app.py").write_text(
            "import os\n"
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n\n"
            "def mapped(value):\n"
            "    return value\n\n"
            "def unmapped(value):\n"
            "    return value\n\n"
            "def configured():\n"
            "    return os.getenv('SERVICE_MODE')\n\n"
            "@router.get('/internal/health')\n"
            "def health():\n"
            "    return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        self.config_path = self.root / "sfmea.toml"
        self.config_path.write_text(
            "[project]\n"
            'name = "Configuration authoring fixture"\n'
            "\n[analysis]\n"
            'guidance_profiles = ["core_sfmea"]\n'
            "\n[[hazards]]\n"
            'id = "HZ-1"\n'
            'description = "Incorrect service behavior"\n'
            'end_effect = "Mission degradation"\n'
            "severity = 7\n"
            "\n[[requirements]]\n"
            'id = "REQ-1"\n'
            'text = "The service shall preserve valid behavior."\n'
            'source = "System specification"\n'
            'hazards = ["HZ-1"]\n'
            "\n[[system_interfaces]]\n"
            'id = "IF-1"\n'
            'source = "Service"\n'
            'target = "Client"\n'
            'description = "Service API"\n'
            "\n[[component_mappings]]\n"
            'pattern = "app.py:mapped"\n'
            'subsystem = "Service"\n'
            'requirements = ["REQ-1"]\n'
            'hazards = ["HZ-1"]\n'
            'interfaces = ["IF-1"]\n',
            encoding="utf-8",
        )
        self.config, _path = load_config(self.config_path)
        self.analysis = scan_repository(self.root, config=self.config)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _approved_draft(self) -> dict[str, object]:
        raw = self.config_path.read_bytes()
        draft = configuration_authoring_draft(self.analysis, self.config, raw)
        selected = {"guidance": False, "architecture": False, "interface": False}
        for entry in draft["entries"]:
            kind = entry["kind"]
            if selected[kind]:
                continue
            if kind == "guidance":
                entry["proposal"].update(
                    {
                        "citation_id": "NASA-SWEHB-8.05-DATA-EVENTS",
                        "relationship": "supports_review_question",
                        "strength": "direct",
                    }
                )
            elif kind == "architecture":
                if entry["proposal"]["component_id"] == "":
                    continue
            elif kind == "interface":
                if entry["proposal"]["side"] != "server":
                    continue
                entry["proposal"]["decision"] = "intentional_backend_only"
            entry["action"] = "apply"
            entry["review"] = {
                "status": "approved",
                "reviewer": "Independent reviewer",
                "rationale": f"Reviewed the exact {kind} proposal against the governed context.",
                "reviewed_at": "2026-08-09",
            }
            selected[kind] = True
        self.assertTrue(all(selected.values()))
        return draft

    def test_seal_verify_and_apply_publishes_valid_reusable_configuration(self) -> None:
        analysis_path = self.root / "sfmea-analysis.json"
        save_analysis(analysis_path, self.analysis)
        self.analysis = load_analysis(analysis_path)
        draft_path = self.root / "configuration-authoring-draft.json"
        sealed_path = self.root / "configuration-authoring.json"
        output_path = self.root / "sfmea-refined.toml"
        draft_path.write_text(
            json.dumps(self._approved_draft(), indent=2) + "\n", encoding="utf-8"
        )
        Draft202012Validator(schema_document("configuration-authoring-draft")).validate(
            json.loads(draft_path.read_text(encoding="utf-8"))
        )

        seal_configuration_authoring_draft(
            draft_path,
            self.analysis,
            self.config_path,
            sealed_path,
        )
        verdict = verify_configuration_authoring_file(
            sealed_path,
            analysis=self.analysis,
            config_source=self.config_path,
        )
        self.assertTrue(verdict["valid"])
        Draft202012Validator(
            schema_document("configuration-authoring-verification")
        ).validate(verdict)
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("configuration-authoring")).validate(
            sealed
        )
        status = workflow_status(self.root)
        self.assertTrue(status["artifacts"]["configuration_authoring"]["current"])
        self.assertIn(
            "apply_configuration_authoring",
            {value["id"] for value in status["next_actions"]},
        )
        published, receipt = apply_configuration_authoring(
            self.analysis,
            sealed,
            self.config_path,
            output_path,
        )

        self.assertEqual(published, output_path)
        self.assertEqual(receipt["format"], CONFIGURATION_AUTHORING_APPLY_RECEIPT_FORMAT)
        self.assertEqual(receipt["guidance_mappings"], 1)
        self.assertEqual(receipt["component_mappings"], 1)
        self.assertEqual(receipt["interface_dispositions"], 1)
        Draft202012Validator(
            schema_document("configuration-authoring-apply-receipt")
        ).validate(receipt)
        updated, _path = load_config(output_path)
        self.assertEqual(len(updated["guidance_rule_mappings"]), 1)
        self.assertEqual(len(updated["component_mappings"]), 2)
        self.assertEqual(len(updated["interface_dispositions"]), 1)
        rescanned = scan_repository(self.root, config=updated)
        self.assertEqual(
            rescanned["interface_reconciliation"]["summary"]["applied_dispositions"],
            1,
        )
        self.assertEqual(
            rescanned["guidance"]["project_mapping_application"]["applied"], 1
        )
        preserved = output_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "destination already exists"):
            apply_configuration_authoring(
                self.analysis,
                sealed,
                self.config_path,
                output_path,
            )
        self.assertEqual(output_path.read_bytes(), preserved)
        source_before = self.config_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "publish to a new file"):
            apply_configuration_authoring(
                self.analysis,
                sealed,
                self.config_path,
                self.config_path,
            )
        self.assertEqual(self.config_path.read_bytes(), source_before)
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        with self.assertRaisesRegex(ValueError, "written beside the source"):
            apply_configuration_authoring(
                self.analysis,
                sealed,
                self.config_path,
                elsewhere / "sfmea.toml",
            )

    def test_rejects_unreviewed_apply_tamper_and_configuration_drift(self) -> None:
        draft = self._approved_draft()
        selected = next(value for value in draft["entries"] if value["action"] == "apply")
        selected["review"]["reviewer"] = ""
        draft_path = self.root / "invalid-draft.json"
        sealed_path = self.root / "sealed.json"
        draft_path.write_text(json.dumps(draft) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "approved named review"):
            seal_configuration_authoring_draft(
                draft_path, self.analysis, self.config_path, sealed_path
            )

        draft_path.write_text(
            json.dumps(self._approved_draft()) + "\n", encoding="utf-8"
        )
        seal_configuration_authoring_draft(
            draft_path, self.analysis, self.config_path, sealed_path
        )
        tampered = json.loads(sealed_path.read_text(encoding="utf-8"))
        tampered["summary"]["applied"] += 1
        sealed_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        self.assertFalse(verify_configuration_authoring_file(sealed_path)["valid"])

        seal_configuration_authoring_draft(
            draft_path, self.analysis, self.config_path, sealed_path
        )
        semantically_tampered = json.loads(sealed_path.read_text(encoding="utf-8"))
        deferred = next(
            value
            for value in semantically_tampered["entries"]
            if value["action"] == "defer"
        )
        deferred["proposal"]["unsupported"] = True
        semantically_tampered.pop("content_sha256")
        semantically_tampered["content_sha256"] = canonical_json_sha256(
            semantically_tampered
        )
        sealed_path.write_text(
            json.dumps(semantically_tampered) + "\n", encoding="utf-8"
        )
        semantic_verdict = verify_configuration_authoring_file(
            sealed_path,
            analysis=self.analysis,
            config_source=self.config_path,
        )
        self.assertFalse(semantic_verdict["valid"])
        self.assertFalse(semantic_verdict["checks"]["configuration_semantics"])

        seal_configuration_authoring_draft(
            draft_path, self.analysis, self.config_path, sealed_path
        )
        self.config_path.write_text(
            self.config_path.read_text(encoding="utf-8") + "\n# changed\n",
            encoding="utf-8",
        )
        verdict = verify_configuration_authoring_file(
            sealed_path,
            analysis=self.analysis,
            config_source=self.config_path,
        )
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["configuration_binding"])

    def test_cli_round_trip_publishes_configuration_and_receipt(self) -> None:
        analysis_path = self.root / "analysis.json.gz"
        draft_path = self.root / "draft.json"
        sealed_path = self.root / "sealed.json"
        output_path = self.root / "sfmea-reviewed.toml"
        receipt_path = self.root / "receipt.json"
        save_analysis(analysis_path, self.analysis, compact=True)
        draft_path.write_text(
            json.dumps(self._approved_draft()) + "\n", encoding="utf-8"
        )

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "config-authoring-seal",
                        str(draft_path),
                        "--analysis",
                        str(analysis_path),
                        "--config",
                        str(self.config_path),
                        "-o",
                        str(sealed_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "config-authoring-apply",
                        str(analysis_path),
                        str(sealed_path),
                        "--config",
                        str(self.config_path),
                        "-o",
                        str(output_path),
                        "--receipt",
                        str(receipt_path),
                    ]
                ),
                0,
            )
        self.assertTrue(output_path.is_file())
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["component_mappings"], 1)

    def test_prior_activation_review_prefills_exact_architecture_proposal(self) -> None:
        initial = configuration_authoring_draft(
            self.analysis, self.config, self.config_path.read_bytes()
        )
        architecture = next(
            value for value in initial["entries"] if value["kind"] == "architecture"
        )
        component_id = architecture["proposal"]["component_id"]
        self.analysis["activation"] = {
            "decision_history": [
                {
                    "id": "ACTIVATION-DECISION-1",
                    "kind": "architecture",
                    "subject_id": stable_id("ACTIVATION-ARCH", component_id),
                    "decision": "accepted",
                    "reviewer": "Architecture authority",
                    "rationale": "The component belongs to the proposed subsystem and traces.",
                    "recorded_at": "2026-08-09T12:00:00Z",
                }
            ]
        }

        updated = configuration_authoring_draft(
            self.analysis, self.config, self.config_path.read_bytes()
        )
        prefilled = next(
            value
            for value in updated["entries"]
            if value["kind"] == "architecture"
            and value["proposal"]["component_id"] == component_id
        )
        self.assertEqual(prefilled["action"], "apply")
        self.assertEqual(prefilled["review"]["status"], "approved")
        self.assertEqual(prefilled["review"]["reviewer"], "Architecture authority")


if __name__ == "__main__":
    unittest.main()
