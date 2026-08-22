from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.activation import (
    ACTIVATION_APPLY_RECEIPT_FORMAT,
    ACTIVATION_WORKSPACE_FORMAT,
    activation_records_template,
    activation_workspace,
    apply_activation_workspace,
    import_activation_records,
    record_activation_assignment,
    record_activation_decision,
    verify_activation_workspace_file,
)
from pysfmea.activation import (
    test_attribution as build_test_attribution,
)
from pysfmea.cli import main
from pysfmea.integrity import canonical_json_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis


class ActivationWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "app.py").write_text(
            "def publish(value):\n    return value\n", encoding="utf-8"
        )
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_app.py").write_text(
            "from app import publish\n\ndef test_publish():\n    assert publish(1) == 1\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(
            self.root,
            config={"scan": {"test_evidence_include": ["tests/**"]}},
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_test_attribution_explains_static_mapping(self) -> None:
        result = build_test_attribution(
            self.analysis, self.root, ["tests/test_app.py"]
        )

        self.assertEqual(result["format"], "pysfmea-test-attribution-1")
        self.assertEqual(result["summary"]["tests"], 1)
        self.assertNotEqual(result["tests"][0]["status"], "unmapped")
        self.assertTrue(result["tests"][0]["component_matches"])
        self.assertIn("module_import", result["tests"][0]["component_matches"][0]["reasons"])

    def test_workspace_records_verifies_and_applies_exact_finding_decision(self) -> None:
        workspace = activation_workspace(self.analysis, self.root)
        self.assertEqual(workspace["format"], ACTIVATION_WORKSPACE_FORMAT)
        self.assertTrue(workspace["queues"]["finding_reviews"])
        Draft202012Validator(schema_document("activation-workspace")).validate(
            workspace
        )
        workspace_path = self.root / "activation.json"
        workspace_path.write_text(
            json.dumps(workspace, indent=2) + "\n", encoding="utf-8"
        )
        finding_id = workspace["queues"]["finding_reviews"][0]["id"]

        record_activation_assignment(
            workspace_path,
            kind="finding",
            subject_id=finding_id,
            assignee="Safety reviewer",
            due_date="2026-08-31",
        )
        record_activation_decision(
            workspace_path,
            kind="finding",
            subject_id=finding_id,
            decision="needs_information",
            reviewer="Independent Reviewer",
            rationale="System-level effect and operational context are still missing.",
        )
        verification = verify_activation_workspace_file(
            workspace_path, analysis=self.analysis
        )
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["status"], "matched")
        self.assertEqual(verification["decision_count"], 1)
        assigned = json.loads(workspace_path.read_text(encoding="utf-8"))[
            "assignments"
        ][0]
        self.assertEqual(assigned["assignee"], "Safety reviewer")
        Draft202012Validator(
            schema_document("activation-workspace-verification")
        ).validate(verification)
        updated, receipt = apply_activation_workspace(
            self.analysis,
            json.loads(workspace_path.read_text(encoding="utf-8")),
        )

        reviewed = next(value for value in updated["items"] if value["id"] == finding_id)
        self.assertEqual(reviewed["review"]["disposition"], "needs_information")
        self.assertEqual(reviewed["review"]["reviewer"], "Independent Reviewer")
        self.assertEqual(receipt["format"], ACTIVATION_APPLY_RECEIPT_FORMAT)
        self.assertEqual(receipt["finding_reviews_applied"], 1)
        Draft202012Validator(schema_document("activation-apply-receipt")).validate(
            receipt
        )
        self.assertEqual(self.analysis["items"][0]["review"]["disposition"], "unreviewed")

    def test_named_consolidation_creates_canonical_group_without_removing_members(self) -> None:
        (self.root / "app.py").write_text(
            "def publish_one(value):\n    return value\n\n"
            "def publish_two(value):\n    return value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        workspace = activation_workspace(analysis, self.root)
        candidate = workspace["queues"]["finding_consolidations"][0]
        workspace_path = self.root / "consolidation-activation.json"
        workspace_path.write_text(json.dumps(workspace) + "\n", encoding="utf-8")

        record_activation_decision(
            workspace_path,
            kind="consolidation",
            subject_id=candidate["id"],
            decision="consolidate",
            reviewer="Independent SFMEA reviewer",
            rationale=(
                "The members have the same failure mechanism, effects, control needs, "
                "hazard treatment, and evidence expectations; retain one review anchor."
            ),
        )
        decided = json.loads(workspace_path.read_text(encoding="utf-8"))
        updated, receipt = apply_activation_workspace(analysis, decided)

        registry = updated["finding_consolidation"]
        self.assertEqual(registry["summary"]["canonical_groups"], 1)
        self.assertEqual(registry["summary"]["source_findings_removed"], 0)
        record = registry["records"][0]
        self.assertEqual(record["member_finding_ids"], candidate["member_finding_ids"])
        self.assertEqual(record["canonical_finding_id"], candidate["canonical_finding_id"])
        self.assertEqual(len(updated["items"]), len(analysis["items"]))
        members = {
            value["id"]: value
            for value in updated["items"]
            if value["id"] in candidate["member_finding_ids"]
        }
        self.assertEqual(set(members), set(candidate["member_finding_ids"]))
        self.assertEqual(
            members[candidate["canonical_finding_id"]]["consolidation"]["role"],
            "canonical",
        )
        self.assertTrue(
            all(
                value["review"]["disposition"] == "unreviewed"
                for value in members.values()
            )
        )
        self.assertEqual(receipt["finding_consolidations_applied"], 1)
        Draft202012Validator(schema_document("activation-apply-receipt")).validate(
            receipt
        )

    def test_consolidation_candidate_tamper_and_retain_separate_are_safe(self) -> None:
        (self.root / "app.py").write_text(
            "def publish_one(value):\n    return value\n\n"
            "def publish_two(value):\n    return value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        workspace = activation_workspace(analysis, self.root)
        candidate = workspace["queues"]["finding_consolidations"][0]
        workspace_path = self.root / "consolidation-activation.json"
        workspace_path.write_text(json.dumps(workspace) + "\n", encoding="utf-8")

        record_activation_decision(
            workspace_path,
            kind="consolidation",
            subject_id=candidate["id"],
            decision="retain_separate",
            reviewer="SFMEA reviewer",
            rationale="The members require different effect and verification conclusions.",
        )
        decided = json.loads(workspace_path.read_text(encoding="utf-8"))
        updated, receipt = apply_activation_workspace(analysis, decided)
        self.assertNotIn("finding_consolidation", updated)
        self.assertEqual(receipt["finding_consolidations_applied"], 0)

        tampered = activation_workspace(analysis, self.root)
        tampered["queues"]["finding_consolidations"][0][
            "canonical_finding_id"
        ] = tampered["queues"]["finding_consolidations"][0][
            "member_finding_ids"
        ][1]
        tampered.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(tampered)
        workspace_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        verdict = verify_activation_workspace_file(workspace_path, analysis=analysis)
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["consolidation_candidate_binding"])

    def test_workspace_refuses_tamper_stale_binding_and_unknown_subject(self) -> None:
        workspace = activation_workspace(self.analysis, self.root)
        path = self.root / "activation.json"
        path.write_text(json.dumps(workspace) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "no decisions"):
            apply_activation_workspace(self.analysis, workspace)

        with self.assertRaisesRegex(ValueError, "unknown finding"):
            record_activation_decision(
                path,
                kind="finding",
                subject_id="SFMEA-UNKNOWN",
                decision="accepted",
                reviewer="Reviewer",
                rationale="Reviewed exact source and system behavior.",
            )
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["repository"] = "changed"
        path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        self.assertFalse(verify_activation_workspace_file(path)["valid"])

        clean = activation_workspace(self.analysis, self.root)
        changed = json.loads(json.dumps(self.analysis))
        changed["project"]["name"] = "different"
        path.write_text(json.dumps(clean) + "\n", encoding="utf-8")
        verdict = verify_activation_workspace_file(path, analysis=changed)
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["analysis_binding"])

    def test_interface_decisions_use_the_subject_specific_queue_vocabulary(self) -> None:
        (self.root / "routes.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/backend-only')\n"
            "def backend_only():\n"
            "    return {}\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        workspace = activation_workspace(analysis, self.root)
        server_id = workspace["queues"]["interfaces"]["servers"][0]["id"]
        path = self.root / "interface-activation.json"
        path.write_text(json.dumps(workspace) + "\n", encoding="utf-8")

        record_activation_decision(
            path,
            kind="interface",
            subject_id=server_id,
            decision="intentional_backend_only",
            reviewer="Interface reviewer",
            rationale="This endpoint intentionally serves operational tooling only.",
        )
        self.assertTrue(verify_activation_workspace_file(path)["valid"])
        with self.assertRaisesRegex(ValueError, "invalid interface decision"):
            record_activation_decision(
                path,
                kind="interface",
                subject_id=server_id,
                decision="confirmed_compatible",
                reviewer="Interface reviewer",
                rationale="This client-only choice is invalid for a server route.",
            )

    def test_cli_activation_round_trip_publishes_receipt(self) -> None:
        analysis_path = self.root / "analysis.json"
        workspace_path = self.root / "activation.json"
        output_path = self.root / "updated.json"
        receipt_path = self.root / "receipt.json"
        save_analysis(analysis_path, self.analysis)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "activate-init",
                        str(analysis_path),
                        str(self.root),
                        "-o",
                        str(workspace_path),
                    ]
                ),
                0,
            )
        workspace = json.loads(workspace_path.read_text(encoding="utf-8"))
        finding_id = workspace["queues"]["finding_reviews"][0]["id"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "activate-decide",
                        str(workspace_path),
                        "finding",
                        finding_id,
                        "rejected",
                        "--reviewer",
                        "Reviewer",
                        "--rationale",
                        "The candidate is not credible in this operating context.",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "activate-apply",
                        str(analysis_path),
                        str(workspace_path),
                        "-o",
                        str(output_path),
                        "--receipt",
                        str(receipt_path),
                    ]
                ),
                0,
            )
        self.assertEqual(
            next(
                value
                for value in load_analysis(output_path)["items"]
                if value["id"] == finding_id
            )["review"]["disposition"],
            "rejected",
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "applied")
        self.assertRegex(receipt["result_analysis_state_sha256"], r"^[0-9a-f]{64}$")

    def test_bulk_records_import_is_bound_transactional_and_schema_backed(self) -> None:
        workspace = activation_workspace(self.analysis, self.root)
        workspace_path = self.root / "activation.json"
        records_path = self.root / "records.json"
        workspace_path.write_text(json.dumps(workspace) + "\n", encoding="utf-8")
        finding_id = workspace["queues"]["finding_reviews"][0]["id"]
        records = activation_records_template(workspace)
        records["assignments"] = [
            {
                "kind": "finding",
                "subject_id": finding_id,
                "assignee": "Reviewer",
                "due_date": "2026-09-01",
            }
        ]
        records["decisions"] = [
            {
                "kind": "finding",
                "subject_id": finding_id,
                "decision": "needs_information",
                "reviewer": "Reviewer",
                "rationale": "The operating mode and worst credible effect need confirmation.",
            }
        ]
        Draft202012Validator(schema_document("activation-records")).validate(records)
        records_path.write_text(json.dumps(records) + "\n", encoding="utf-8")

        result, receipt = import_activation_records(workspace_path, records_path)

        self.assertEqual(result, workspace_path.resolve())
        self.assertEqual(receipt["assignments_imported"], 1)
        self.assertEqual(receipt["decisions_imported"], 1)
        Draft202012Validator(
            schema_document("activation-records-import-receipt")
        ).validate(receipt)
        imported = json.loads(workspace_path.read_text(encoding="utf-8"))
        self.assertEqual(imported["summary"]["assigned_items"], 1)
        self.assertEqual(imported["summary"]["recorded_decisions"], 1)

        stale_records = activation_records_template(imported)
        stale_records["workspace_binding"]["content_sha256"] = "0" * 64
        records_path.write_text(json.dumps(stale_records) + "\n", encoding="utf-8")
        before = workspace_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "exact current workspace"):
            import_activation_records(workspace_path, records_path)
        self.assertEqual(workspace_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
