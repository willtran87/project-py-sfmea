from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance_case import (
    ASSURANCE_CASE_FORMAT,
    assurance_case,
    export_assurance_case,
    verify_assurance_case,
    verify_assurance_case_file,
)
from pysfmea.cli import main
from pysfmea.conformance import (
    CONFORMANCE_CATALOG_FORMAT,
    CONFORMANCE_WORKSPACE_FORMAT,
    assess_objective,
    conformance_workspace,
    export_conformance_workspace,
    standards_catalog,
    verify_conformance_workspace,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.slsa import (
    export_slsa_provenance,
    slsa_provenance_statement,
    verify_slsa_provenance,
)
from pysfmea.store import save_analysis


class IndustryAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "subject.py").write_text(
            "def divide(total: float, count: int) -> float:\n"
            "    return total / count\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)
        self.analysis_path = self.root / "analysis.json"
        save_analysis(self.analysis_path, self.analysis)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_catalog_is_content_addressed_schema_valid_and_license_explicit(
        self,
    ) -> None:
        catalog = standards_catalog()
        self.assertEqual(catalog["format"], CONFORMANCE_CATALOG_FORMAT)
        self.assertGreaterEqual(len(catalog["profiles"]), 20)
        self.assertTrue(
            any(
                profile["access"] == "licensed_normative_text_required"
                for profile in catalog["profiles"]
            )
        )
        profile_ids = {profile["id"] for profile in catalog["profiles"]}
        self.assertIn("iec-60812-2018", profile_ids)
        self.assertIn("sae-j1739-202605", profile_ids)
        self.assertIn("nist-ai-600-1-llm", profile_ids)
        self.assertIn("aiag-vda-fmea-2019", profile_ids)
        self.assertIn("sae-arp4754b-arp4761a", profile_ids)
        self.assertIn("iso-12207-2026", profile_ids)
        self.assertIn("openssf-osps-2026-02-19", profile_ids)
        self.assertIn("medical-14971-62304-81001", profile_ids)
        Draft202012Validator(schema_document("standards-catalog")).validate(catalog)

    def test_conformance_requires_evidence_and_reconciles_all_objectives(self) -> None:
        workspace = conformance_workspace(
            self.analysis,
            ["nist-ssdf-1.1"],
            system="example service",
            lifecycle_phase="verification",
            applicability_basis="organization adopted NIST SSDF",
            authority="software assurance board",
            generated_at="2026-08-27T12:00:00+00:00",
        )
        self.assertEqual(workspace["format"], CONFORMANCE_WORKSPACE_FORMAT)
        initial = verify_conformance_workspace(workspace, analysis=self.analysis)
        self.assertTrue(initial["valid"])
        self.assertFalse(initial["assessment_complete"])
        with self.assertRaisesRegex(ValueError, "evidence"):
            assess_objective(
                workspace,
                "SSDF-PO",
                applicability="applicable",
                status="satisfied",
                rationale="controls reviewed",
                reviewer="reviewer@example.test",
                evidence_refs=[],
            )
        for objective in [
            item["id"] for item in workspace["profiles"][0]["objectives"]
        ]:
            workspace = assess_objective(
                workspace,
                objective,
                applicability="applicable",
                status="satisfied",
                rationale="The adopted practice was reviewed against controlled evidence.",
                reviewer="reviewer@example.test",
                evidence_refs=[f"evidence://{objective}"],
                reviewed_at="2026-08-27T13:00:00+00:00",
            )
        verdict = verify_conformance_workspace(workspace, analysis=self.analysis)
        self.assertTrue(verdict["valid"])
        self.assertTrue(verdict["assessment_complete"])
        self.assertTrue(verdict["conformance_supported"])
        Draft202012Validator(schema_document("conformance-workspace")).validate(
            workspace
        )
        Draft202012Validator(schema_document("conformance-verification")).validate(
            verdict
        )
        tampered = copy.deepcopy(workspace)
        tampered["profiles"][0]["objectives"][0]["status"] = "not_satisfied"
        self.assertFalse(verify_conformance_workspace(tampered)["valid"])

    def test_assurance_case_exposes_defeaters_and_rejects_graph_tampering(self) -> None:
        case = assurance_case(
            self.analysis,
            self.analysis_path,
            generated_at="2026-08-27T14:00:00+00:00",
        )
        self.assertEqual(case["format"], ASSURANCE_CASE_FORMAT)
        self.assertFalse(case["summary"]["top_claim_status"] == "supported")
        self.assertGreater(case["summary"]["open_defeaters"], 0)
        verdict = verify_assurance_case(case, analysis=self.analysis)
        self.assertTrue(verdict["valid"])
        self.assertFalse(verdict["decision_ready"])
        Draft202012Validator(schema_document("assurance-case")).validate(case)
        Draft202012Validator(schema_document("assurance-case-verification")).validate(
            verdict
        )
        tampered = copy.deepcopy(case)
        tampered["relationships"][0]["target"] = "C-NOT-FOUND"
        tampered.pop("content_sha256")
        from pysfmea.integrity import canonical_json_sha256

        tampered["content_sha256"] = canonical_json_sha256(tampered)
        rejected = verify_assurance_case(tampered)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["relationship_integrity"])

    def test_cli_round_trip_is_exact_analysis_bound(self) -> None:
        workspace_path = self.root / "conformance.json"
        case_path = self.root / "assurance-case.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "conformance-init",
                        str(self.analysis_path),
                        "--profile",
                        "iec-60812-2018",
                        "--system",
                        "example service",
                        "--phase",
                        "verification",
                        "--basis",
                        "project-selected method",
                        "--authority",
                        "software assurance board",
                        "-o",
                        str(workspace_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "conformance-verify",
                        str(workspace_path),
                        "--analysis",
                        str(self.analysis_path),
                        "--json",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "assurance-case",
                        str(self.analysis_path),
                        "--conformance",
                        str(workspace_path),
                        "-o",
                        str(case_path),
                    ]
                ),
                0,
            )
        case = json.loads(case_path.read_text(encoding="utf-8"))
        self.assertIn("C-CONFORMANCE", {claim["id"] for claim in case["claims"]})
        self.assertTrue(
            verify_assurance_case_file(case_path, analysis=self.analysis)["valid"]
        )
        export_assurance_case(case, case_path)
        export_conformance_workspace(
            json.loads(workspace_path.read_text(encoding="utf-8")), workspace_path
        )

    def test_slsa_provenance_is_standard_shaped_and_exact_subject_bound(self) -> None:
        statement = slsa_provenance_statement(
            self.analysis,
            self.analysis_path,
            generated_at="2026-08-27T15:00:00+00:00",
        )
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(statement["predicateType"], "https://slsa.dev/provenance/v1")
        verdict = verify_slsa_provenance(
            statement,
            analysis=self.analysis,
            analysis_path=self.analysis_path,
        )
        self.assertTrue(verdict["valid"])
        Draft202012Validator(schema_document("slsa-provenance")).validate(statement)
        Draft202012Validator(schema_document("slsa-provenance-verification")).validate(
            verdict
        )
        tampered = copy.deepcopy(statement)
        tampered["subject"][0]["digest"]["sha256"] = "0" * 64
        self.assertFalse(
            verify_slsa_provenance(
                tampered,
                analysis=self.analysis,
                analysis_path=self.analysis_path,
            )["valid"]
        )
        output = self.root / "analysis.intoto.jsonl"
        export_slsa_provenance(statement, output)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "provenance-verify",
                        str(output),
                        "--analysis",
                        str(self.analysis_path),
                        "--json",
                    ]
                ),
                0,
            )


if __name__ == "__main__":
    unittest.main()
