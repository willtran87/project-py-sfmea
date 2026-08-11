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
from pysfmea.store import load_analysis, save_analysis
from pysfmea.synthesis import (
    SYNTHESIS_FORMAT,
    apply_synthesis_workspace,
    build_synthesis_workspace,
    seal_synthesis_workspace,
    suggestion_relationships,
    verify_synthesis_apply_receipt_file,
    verify_synthesis_workspace,
    verify_synthesis_workspace_file,
)


class SynthesisWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def fetch():\n    return request_remote()\n", encoding="utf-8"
        )
        self.analysis = scan_repository(self.root)
        component = self.analysis["components"][0]
        existing = self.analysis["items"][0]
        existing["review"]["failure_mode"] = "remote service is available"
        self.analysis["suggestions"] = [
            {
                "id": "SUG-TEST",
                "component_id": component["id"],
                "component_reference": (
                    f"{component['source']['path']}:{component['qualname']}"
                ),
                "origin": "machine_suggestion",
                "status": "proposed",
                "content": {
                    "failure_class": "response",
                    "guideword": "Unavailable",
                    "failure_mode": "remote service is unavailable",
                    "trigger": "dependency outage",
                    "causes": ["network interruption"],
                    "local_effect": "request fails",
                    "next_higher_effect": "workflow is unavailable",
                    "possible_end_effects": ["mission task may be delayed"],
                    "prevention_controls": [],
                    "detection_controls": [],
                    "recommended_actions": ["test timeout behavior"],
                },
                "evidence_ids": [component["id"]],
                "proposed_citation_ids": [],
                "uncertainties": ["runtime behavior not observed"],
                "questions": ["what timeout applies?"],
                "confidence": "medium",
                "provenance": {},
                "reviewer": "",
                "review_rationale": "",
                "materialized_item_id": "",
                "history": [],
            }
        ]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_relationships_detect_opposed_claims(self) -> None:
        result = suggestion_relationships(self.analysis)
        self.assertTrue(result["contradictions"])
        self.assertEqual(
            result["contradictions"][0]["classification"],
            "lexical_contradiction_review_required",
        )

    def test_edit_seal_verify_and_apply_is_human_controlled(self) -> None:
        workspace = build_synthesis_workspace(self.analysis)
        Draft202012Validator(schema_document("synthesis-workspace-draft")).validate(
            workspace
        )
        entry = workspace["entries"][0]
        entry["proposed_content"]["local_effect"] = "bounded request failure"
        entry["decision"] = "accept"
        entry["reviewer"] = "safety-reviewer"
        entry["rationale"] = "Source evidence supports a bounded request failure."
        path = self.root / "synthesis.json"
        path.write_text(json.dumps(workspace), encoding="utf-8")
        seal_synthesis_workspace(path)
        sealed = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(sealed["format"], SYNTHESIS_FORMAT)
        Draft202012Validator(schema_document("synthesis-workspace")).validate(sealed)
        verification = verify_synthesis_workspace(sealed, self.analysis)
        Draft202012Validator(
            schema_document("synthesis-workspace-verification")
        ).validate(verification)
        self.assertTrue(verification["valid"])

        receipt = apply_synthesis_workspace(self.analysis, sealed)
        Draft202012Validator(schema_document("synthesis-apply-receipt")).validate(
            receipt
        )

        self.assertEqual(receipt["applied_suggestion_ids"], ["SUG-TEST"])
        suggestion = self.analysis["suggestions"][0]
        self.assertEqual(suggestion["status"], "accepted")
        self.assertEqual(suggestion["content"]["local_effect"], "bounded request failure")
        self.assertTrue(
            any(value["event"] == "human_synthesis_edit" for value in suggestion["history"])
        )

    def test_verifier_rejects_stale_or_tampered_workspace(self) -> None:
        workspace = build_synthesis_workspace(self.analysis)
        workspace["format"] = SYNTHESIS_FORMAT
        workspace.pop("content_sha256")
        workspace["content_sha256"] = canonical_json_sha256(workspace)
        self.analysis["suggestions"][0]["content"]["trigger"] = "changed"
        result = verify_synthesis_workspace(workspace, self.analysis)
        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["analysis_binding"])

    def test_resealed_immutable_context_and_missing_file_are_rejected(self) -> None:
        workspace = build_synthesis_workspace(self.analysis)
        workspace["format"] = SYNTHESIS_FORMAT
        workspace["entries"][0]["evidence_ids"] = ["fabricated-evidence"]
        workspace.pop("content_sha256")
        workspace["content_sha256"] = canonical_json_sha256(workspace)
        rejected = verify_synthesis_workspace(workspace, self.analysis)
        self.assertFalse(rejected["valid"])
        self.assertTrue(rejected["checks"]["structure"])
        self.assertFalse(rejected["checks"]["analysis_binding"])

        unavailable = verify_synthesis_workspace_file(
            self.root / "missing.json", self.analysis
        )
        self.assertFalse(unavailable["valid"])
        Draft202012Validator(
            schema_document("synthesis-workspace-verification")
        ).validate(unavailable)

    def test_synthesis_workspace_final_link_is_rejected(self) -> None:
        workspace_path = self.root / "workspace.json"
        workspace_path.write_text(
            json.dumps(build_synthesis_workspace(self.analysis)), encoding="utf-8"
        )
        linked_workspace = self.root / "linked-workspace.json"
        try:
            linked_workspace.symlink_to(workspace_path)
        except OSError:
            self.skipTest("symbolic links are unavailable on this platform")

        with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
            seal_synthesis_workspace(linked_workspace)

        verdict = verify_synthesis_workspace_file(linked_workspace, self.analysis)
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["path"], str(linked_workspace))
        Draft202012Validator(
            schema_document("synthesis-workspace-verification")
        ).validate(verdict)

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        seal_synthesis_workspace(workspace_path)
        before = analysis_path.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(["synthesis-apply", str(analysis_path), str(linked_workspace)]),
                2,
            )
        self.assertEqual(analysis_path.read_bytes(), before)

    def test_cli_apply_publishes_bound_receipt(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        source_analysis_path = self.root / "source-analysis.json"
        source_state_sha256 = canonical_json_sha256(load_analysis(analysis_path))
        workspace = build_synthesis_workspace(self.analysis)
        workspace["entries"][0].update(
            {
                "decision": "reject",
                "reviewer": "safety-reviewer",
                "rationale": "The claim is not supported by the retained evidence.",
            }
        )
        workspace_path = self.root / "workspace.json"
        workspace_path.write_text(json.dumps(workspace), encoding="utf-8")
        seal_synthesis_workspace(workspace_path)
        receipt_path = self.root / "apply-receipt.json"

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "synthesis-apply",
                    str(analysis_path),
                    str(workspace_path),
                    "--receipt",
                    str(receipt_path),
                    "--source-snapshot",
                    str(source_analysis_path),
                ]
            )

        self.assertEqual(status, 0)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("synthesis-apply-receipt")).validate(
            receipt
        )
        result_analysis = load_analysis(analysis_path)
        self.assertEqual(
            receipt["source_analysis_state_sha256"], source_state_sha256
        )
        self.assertEqual(
            receipt["result_analysis_state_sha256"],
            canonical_json_sha256(result_analysis),
        )
        self.assertEqual(result_analysis["suggestions"][0]["status"], "rejected")
        self.assertIn(str(receipt_path), output.getvalue())

        integrity = verify_synthesis_apply_receipt_file(receipt_path)
        self.assertTrue(integrity["valid"])
        self.assertFalse(integrity["reconciled"])
        self.assertEqual(integrity["mode"], "integrity_only")

        verification_path = self.root / "apply-verification.json"
        verified = main(
            [
                "synthesis-apply-verify",
                str(receipt_path),
                "--source-analysis",
                str(source_analysis_path),
                "--workspace",
                str(workspace_path),
                "--result-analysis",
                str(analysis_path),
                "--output",
                str(verification_path),
            ]
        )
        self.assertEqual(verified, 0)
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["reconciled"])
        self.assertEqual(verification["mode"], "complete")
        self.assertTrue(all(verification["checks"].values()))
        Draft202012Validator(
            schema_document("synthesis-apply-receipt-verification")
        ).validate(verification)

        result_analysis["suggestions"][0]["review_rationale"] = "changed"
        save_analysis(analysis_path, result_analysis)
        stale = verify_synthesis_apply_receipt_file(
            receipt_path,
            source_analysis_path=source_analysis_path,
            workspace_path=workspace_path,
            result_analysis_path=analysis_path,
        )
        self.assertFalse(stale["valid"])
        self.assertFalse(stale["reconciled"])
        self.assertFalse(stale["checks"]["result_analysis_binding"])

    def test_apply_receipt_verifier_rejects_missing_and_partial_inputs(self) -> None:
        missing = verify_synthesis_apply_receipt_file(
            self.root / "missing-receipt.json"
        )
        self.assertFalse(missing["valid"])
        Draft202012Validator(
            schema_document("synthesis-apply-receipt-verification")
        ).validate(missing)

        receipt_path = self.root / "receipt.json"
        receipt_path.write_text("{}", encoding="utf-8")
        partial = verify_synthesis_apply_receipt_file(
            receipt_path, source_analysis_path=self.root / "source.json"
        )
        self.assertFalse(partial["valid"])
        self.assertFalse(partial["reconciled"])
        self.assertEqual(partial["mode"], "incomplete_bindings")
        Draft202012Validator(
            schema_document("synthesis-apply-receipt-verification")
        ).validate(partial)

    def test_cli_apply_refuses_to_overwrite_source_snapshot(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        original_analysis = analysis_path.read_bytes()
        workspace_path = self.root / "workspace.json"
        workspace_path.write_text(
            json.dumps(build_synthesis_workspace(self.analysis)), encoding="utf-8"
        )
        seal_synthesis_workspace(workspace_path)
        receipt_path = self.root / "apply-receipt.json"
        source_snapshot_path = self.root / "source-analysis.json"
        sentinel = b"existing governed evidence\n"
        source_snapshot_path.write_bytes(sentinel)

        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = main(
                [
                    "synthesis-apply",
                    str(analysis_path),
                    str(workspace_path),
                    "--receipt",
                    str(receipt_path),
                    "--source-snapshot",
                    str(source_snapshot_path),
                ]
            )

        self.assertEqual(status, 2)
        self.assertIn("source snapshot already exists", error.getvalue())
        self.assertEqual(source_snapshot_path.read_bytes(), sentinel)
        self.assertEqual(analysis_path.read_bytes(), original_analysis)
        self.assertFalse(receipt_path.exists())


if __name__ == "__main__":
    unittest.main()
