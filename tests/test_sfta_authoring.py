from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.sfta_authoring import (
    SFTA_AUTHORING_APPLY_RECEIPT_FORMAT,
    SFTA_AUTHORING_DRAFT_FORMAT,
    SFTA_AUTHORING_FORMAT,
    apply_sfta_authoring,
    seal_sfta_authoring_draft,
    sfta_authoring_draft,
    verify_sfta_authoring_file,
)
from pysfmea.store import load_analysis, save_analysis


class SftaAuthoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "service.py").write_text(
            "def process(value):\n    return value\n", encoding="utf-8"
        )
        self.analysis = scan_repository(
            self.root,
            config={
                "hazards": [
                    {
                        "id": "HZ-LOSS",
                        "description": "Required service is lost",
                        "end_effect": "Mission operation cannot complete",
                        "severity": 8,
                    }
                ]
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _approved_draft(self) -> dict[str, object]:
        draft = sfta_authoring_draft(self.analysis)
        entry = draft["entries"][0]
        entry["action"] = "replace"
        entry["review"] = {
            "status": "approved",
            "reviewer": "Independent safety reviewer",
            "rationale": "The preliminary structure is suitable for controlled decomposition.",
        }
        return draft

    def test_draft_seal_verify_and_apply_is_exact_and_transactional(self) -> None:
        draft = self._approved_draft()
        self.assertEqual(draft["format"], SFTA_AUTHORING_DRAFT_FORMAT)
        Draft202012Validator(schema_document("sfta-authoring-draft")).validate(draft)
        draft_path = self.root / "draft.json"
        sealed_path = self.root / "sealed.json"
        draft_path.write_text(json.dumps(draft) + "\n", encoding="utf-8")

        seal_sfta_authoring_draft(draft_path, self.analysis, sealed_path)
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        self.assertEqual(sealed["format"], SFTA_AUTHORING_FORMAT)
        Draft202012Validator(schema_document("sfta-authoring")).validate(sealed)
        verdict = verify_sfta_authoring_file(sealed_path, analysis=self.analysis)
        self.assertTrue(verdict["valid"])
        self.assertEqual(verdict["status"], "matched")
        Draft202012Validator(schema_document("sfta-authoring-verification")).validate(
            verdict
        )

        updated, receipt = apply_sfta_authoring(self.analysis, sealed)
        self.assertEqual(receipt["format"], SFTA_AUTHORING_APPLY_RECEIPT_FORMAT)
        Draft202012Validator(schema_document("sfta-authoring-apply-receipt")).validate(
            receipt
        )
        self.assertEqual(receipt["replacement_hazards"], ["HZ-LOSS"])
        self.assertEqual(receipt["qualitative_cut_sets"], 1)
        tree = updated["sfta"]["trees"][0]
        self.assertEqual(tree["logic_status"], "approved_for_qualitative_cut_sets")
        self.assertEqual(tree["cut_set_analysis"]["status"], "computed")
        self.assertEqual(tree["cut_set_analysis"]["cut_set_count"], 1)
        review = updated["sfta_authoring"]["history"][-1]["reviews"][0]
        self.assertRegex(review["definition_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            updated["sfta"]["reconciliation"]["summary"]["explicit_trees"], 1
        )
        self.assertEqual(
            updated["sfta"]["reconciliation"]["summary"]["placeholder_trees"], 0
        )
        self.assertEqual(
            self.analysis["sfta"]["reconciliation"]["summary"]["placeholder_trees"],
            1,
        )

    def test_seal_rejects_missing_review_stale_binding_and_invalid_logic(self) -> None:
        draft = sfta_authoring_draft(self.analysis)
        draft["entries"][0]["action"] = "replace"
        draft_path = self.root / "draft.json"
        draft_path.write_text(json.dumps(draft) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "requires approved review"):
            seal_sfta_authoring_draft(
                draft_path, self.analysis, self.root / "sealed.json"
            )

        approved = self._approved_draft()
        approved["analysis_binding"]["analysis_state_sha256"] = "0" * 64
        draft_path.write_text(json.dumps(approved) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exact analysis state"):
            seal_sfta_authoring_draft(
                draft_path, self.analysis, self.root / "sealed.json"
            )

        invalid = self._approved_draft()
        definition = invalid["entries"][0]["definition"]
        definition["events"][0]["inputs"] = [definition["events"][0]["id"]]
        draft_path.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cycle"):
            seal_sfta_authoring_draft(
                draft_path, self.analysis, self.root / "sealed.json"
            )

    def test_cli_round_trip_publishes_updated_analysis_and_receipt(self) -> None:
        analysis_path = self.root / "analysis.json"
        draft_path = self.root / "draft.json"
        sealed_path = self.root / "sealed.json"
        updated_path = self.root / "updated.json"
        receipt_path = self.root / "receipt.json"
        save_analysis(analysis_path, self.analysis)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "sfta-authoring-init",
                        str(analysis_path),
                        "-o",
                        str(draft_path),
                    ]
                ),
                0,
            )
        draft = json.loads(draft_path.read_text(encoding="utf-8"))
        draft["entries"][0]["action"] = "replace"
        draft["entries"][0]["review"] = {
            "status": "approved",
            "reviewer": "Reviewer",
            "rationale": "Reviewed preliminary software contribution structure.",
        }
        draft_path.write_text(json.dumps(draft) + "\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "sfta-authoring-seal",
                        str(draft_path),
                        "--analysis",
                        str(analysis_path),
                        "-o",
                        str(sealed_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "sfta-authoring-apply",
                        str(analysis_path),
                        str(sealed_path),
                        "-o",
                        str(updated_path),
                        "--receipt",
                        str(receipt_path),
                    ]
                ),
                0,
            )
        updated = load_analysis(updated_path)
        self.assertEqual(
            updated["sfta"]["reconciliation"]["summary"]["explicit_trees"], 1
        )
        self.assertEqual(
            json.loads(receipt_path.read_text(encoding="utf-8"))["status"],
            "applied",
        )


if __name__ == "__main__":
    unittest.main()
