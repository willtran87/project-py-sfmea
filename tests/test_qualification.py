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
from jsonschema.exceptions import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.benchmark_assurance import (
    BENCHMARK_PROTOCOL_FORMAT,
    benchmark_assessment,
    verify_benchmark_assessment,
    verify_benchmark_assessment_file,
)
from pysfmea.cli import main
from pysfmea.conformance import assess_objective, conformance_workspace
from pysfmea.discovery import evaluate_candidates, load_evaluation_spec
from pysfmea.integrity import canonical_json_sha256
from pysfmea.program import verify_assurance_program
from pysfmea.qualification import (
    QUALIFICATION_CAMPAIGN_MANIFEST_FORMAT,
    build_qualification_campaign,
    qualification_validation_cohorts,
    verify_qualification_campaign,
    verify_qualification_campaign_file,
)
from pysfmea.qualification_report import (
    QUALIFICATION_REPORT_FORMAT,
    export_qualification_report,
    verify_qualification_report_file,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis
from pysfmea.tool_qualification import (
    assess_tool_qualification_objective,
    tool_qualification_dossier,
    verify_tool_qualification_dossier,
    verify_tool_qualification_dossier_file,
)


class QualificationCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "service.py").write_text(
            "def perform(value):\n"
            "    return value\n\n"
            "def check_circuit_breaker(circuit_open):\n"
            "    if circuit_open:\n"
            "        return False\n"
            "    return True\n",
            encoding="utf-8",
        )
        self.analysis_path = self.root / "analysis.json"
        save_analysis(self.analysis_path, scan_repository(self.root))
        analysis = load_analysis(self.analysis_path)
        cases = [
            {
                "source": item["source"]["path"],
                "component": item["component"]["qualname"],
                "rule_id": item["scanner"]["rule_id"],
            }
            for item in analysis["items"]
            if item["source"]["path"] == "service.py"
        ]
        semantic_item = next(
            item for item in analysis["items"] if item["source"]["path"] == "service.py"
        )
        self.corpus = {
            "schema_version": "pysfmea-golden-corpus-1",
            "name": "Independent service corpus",
            "purpose": "Measure exact candidate detection on a retained repository.",
            "scope": ["service.py:*"],
            "cases": cases,
            "control_scope": ["service.py:*"],
            "control_cases": [
                {
                    "source": "service.py",
                    "component": "check_circuit_breaker",
                    "kind": "circuit_breaker",
                    "roles": ["admission_guard"],
                }
            ],
            "semantic_cases": [
                {
                    "source": semantic_item["source"]["path"],
                    "component": semantic_item["component"]["qualname"],
                    "rule_id": semantic_item["scanner"]["rule_id"],
                    "expect": {
                        "failure_mode": semantic_item["review"]["failure_mode"],
                        "confidence": semantic_item["scanner"]["confidence"],
                    },
                }
            ],
            "governance": {
                "independent": True,
                "repositories": ["retained/service-a"],
                "labeled_by": "Independent labeler",
                "approved_by": "Validation authority",
                "approval_date": "2026-08-09",
            },
        }
        self.corpus_path = self.root / "corpus.json"
        self.evaluation_path = self.root / "evaluation.json"
        self._write_corpus_and_evaluation(analysis)
        self.manifest = {
            "format": QUALIFICATION_CAMPAIGN_MANIFEST_FORMAT,
            "id": "CAMPAIGN-1",
            "title": "Representative scanner qualification",
            "purpose": "Aggregate exact retained scanner evaluations.",
            "governance": {
                "independent": True,
                "labeled_by": "Campaign benchmark team",
                "approved_by": "Independent assurance authority",
                "approval_date": "2026-08-09",
                "selection_method": "Risk-stratified repository sampling.",
                "representativeness_rationale": (
                    "The retained service exercises the declared framework and domain."
                ),
            },
            "thresholds": {
                "minimum_repositories": 1,
                "minimum_frameworks": 1,
                "minimum_domains": 1,
                "minimum_expected_findings": 1,
                "minimum_finding_recall": 1.0,
                "minimum_finding_precision": 1.0,
                "require_call_cases": False,
                "minimum_call_recall": 0.0,
                "minimum_call_precision": 0.0,
                "require_control_cases": True,
                "minimum_control_negative_components_per_repository": 1,
                "minimum_control_recall": 1.0,
                "minimum_control_precision": 1.0,
                "require_semantic_cases": True,
                "minimum_semantic_recall": 1.0,
                "minimum_semantic_precision": 1.0,
            },
            "repositories": [
                {
                    "id": "service-a",
                    "analysis": self.analysis_path.name,
                    "corpus": self.corpus_path.name,
                    "evaluation": self.evaluation_path.name,
                    "frameworks": ["plain-python"],
                    "domains": ["workflow"],
                    "selection_rationale": "Small deterministic repository fixture.",
                }
            ],
        }
        self.manifest_path = self.root / "qualification-manifest.json"
        self._write_json(self.manifest_path, self.manifest)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def _write_corpus_and_evaluation(self, analysis: dict[str, object]) -> None:
        self._write_json(self.corpus_path, self.corpus)
        loaded = load_evaluation_spec(self.corpus_path)
        self._write_json(
            self.evaluation_path,
            evaluate_candidates(analysis, loaded),
        )

    def test_build_verify_and_public_schemas(self) -> None:
        result = build_qualification_campaign(self.manifest_path)
        self.assertTrue(result["eligible_for_independent_review"])
        self.assertEqual(result["summary"]["repository_count"], 1)
        self.assertEqual(result["features"]["finding_detection"]["recall"], 1.0)
        self.assertIsNone(result["checks"]["call_cases_present"])
        self.assertTrue(result["checks"]["control_cases_present"])
        self.assertTrue(result["checks"]["control_negative_population"])
        self.assertEqual(result["features"]["control_detection"]["recall"], 1.0)
        self.assertEqual(result["features"]["control_detection"]["precision"], 1.0)
        self.assertEqual(
            result["features"]["control_detection"]["evaluated_components"], 2
        )

    def test_independent_benchmark_protocol_adds_statistical_and_holdout_gates(
        self,
    ) -> None:
        result = build_qualification_campaign(self.manifest_path)
        result_path = self.root / "qualification-result.json"
        self._write_json(result_path, result)
        protocol = {
            "format": BENCHMARK_PROTOCOL_FORMAT,
            "id": "BENCHMARK-1",
            "title": "Pre-registered independent scanner benchmark",
            "pre_registered_at": "2026-08-01T00:00:00+00:00",
            "pre_registration_evidence_ref": "registry://benchmark/BENCHMARK-1",
            "governance": {
                "protocol_owner": "Benchmark protocol owner",
                "label_authority": "Independent label authority",
                "approval_authority": "Tool qualification authority",
                "independence_basis": "The label and approval authorities are organizationally independent of scanner development.",
            },
            "design": {
                "frozen_before_execution": True,
                "blinded_holdout": True,
                "minimum_holdout_repositories": 1,
                "holdout_repository_ids": ["service-a"],
                "selection_method": "Risk-stratified sampling frozen before scanner execution.",
                "represented_populations": ["plain Python workflow service"],
                "excluded_populations": ["native extension modules"],
            },
            "statistics": {
                "confidence_level": 0.95,
                "minimum_lower_bounds": {
                    name: 0.0
                    for name in (
                        "finding_recall",
                        "finding_precision",
                        "call_recall",
                        "call_precision",
                        "control_recall",
                        "control_precision",
                        "semantic_recall",
                        "semantic_precision",
                    )
                },
                "minimum_cohen_kappa": 0.8,
            },
            "reviewer_agreement": {
                "both_positive": 8,
                "primary_only": 0,
                "secondary_only": 0,
                "both_negative": 8,
                "adjudication_evidence_ref": "evidence://benchmark/adjudication",
            },
            "requalification_triggers": [
                "scanner_or_rule_change",
                "python_or_dependency_change",
                "benchmark_or_label_change",
                "llm_model_prompt_or_policy_change",
                "intended_environment_change",
                "new_or_changed_known_anomaly",
            ],
        }
        protocol_path = self.root / "benchmark-protocol.json"
        self._write_json(protocol_path, protocol)
        assessment = benchmark_assessment(
            protocol_path,
            result_path,
            self.manifest_path,
            generated_at="2026-08-27T12:00:00+00:00",
        )
        self.assertTrue(verify_benchmark_assessment(assessment)["valid"])
        self.assertFalse(assessment["summary"]["passed"])
        assessment_path = self.root / "benchmark-assessment.json"
        self._write_json(assessment_path, assessment)
        exact = verify_benchmark_assessment_file(
            assessment_path,
            protocol_source=protocol_path,
            qualification_result_source=result_path,
            qualification_manifest_source=self.manifest_path,
        )
        self.assertTrue(exact["valid"])
        self.assertTrue(exact["checks"]["source_regeneration"])
        Draft202012Validator(
            schema_document("independent-benchmark-assessment")
        ).validate(assessment)
        Draft202012Validator(
            schema_document("independent-benchmark-verification")
        ).validate(exact)
        tampered = copy.deepcopy(assessment)
        tampered["statistics"]["confidence_intervals"]["finding_recall"]["lower"] = 1.0
        tampered["content_sha256"] = canonical_json_sha256(
            {key: value for key, value in tampered.items() if key != "content_sha256"}
        )
        self.assertFalse(verify_benchmark_assessment(tampered)["valid"])

        conformance = conformance_workspace(
            load_analysis(self.analysis_path),
            ["nist-ssdf-1.1"],
            system="qualification fixture",
            lifecycle_phase="verification",
            applicability_basis="approved qualification plan",
            authority="Tool qualification authority",
            generated_at="2026-08-27T12:30:00+00:00",
        )
        for objective in [
            item["id"] for item in conformance["profiles"][0]["objectives"]
        ]:
            conformance = assess_objective(
                conformance,
                objective,
                applicability="applicable",
                status="satisfied",
                rationale="The objective is supported by controlled fixture evidence.",
                reviewer="Conformance reviewer",
                evidence_refs=[f"evidence://{objective}"],
                reviewed_at="2026-08-27T12:45:00+00:00",
            )
        conformance_path = self.root / "conformance.json"
        self._write_json(conformance_path, conformance)
        anomaly_path = self.root / "known-anomalies.json"
        self._write_json(
            anomaly_path,
            {"format": "pysfmea-known-anomaly-register-1", "anomalies": []},
        )
        dossier = tool_qualification_dossier(
            load_analysis(self.analysis_path),
            self.analysis_path,
            assessment_path,
            conformance_path,
            anomaly_path,
            intended_use="Generate review candidates and assurance evidence for Python repositories.",
            reliance="Authorized reviewers do not eliminate required verification based solely on scanner output.",
            qualification_basis="Project-selected DO-330-aligned organizational process.",
            tool_classification="TQL-5 candidate",
            intended_environment="CPython 3.13 on the controlled Windows qualification host.",
            classification_authority="Tool qualification authority",
            generated_at="2026-08-27T13:00:00+00:00",
        )
        self.assertTrue(verify_tool_qualification_dossier(dossier)["valid"])
        self.assertFalse(
            dossier["summary"]["eligible_for_authorized_qualification_decision"]
        )
        dossier_path = self.root / "tool-qualification-dossier.json"
        self._write_json(dossier_path, dossier)
        dossier_verdict = verify_tool_qualification_dossier_file(
            dossier_path,
            analysis_source=self.analysis_path,
            benchmark_assessment_source=assessment_path,
            conformance_workspace_source=conformance_path,
            anomaly_register_source=anomaly_path,
        )
        self.assertTrue(dossier_verdict["valid"])
        self.assertTrue(dossier_verdict["checks"]["source_bindings"])
        Draft202012Validator(schema_document("tool-qualification-dossier")).validate(
            dossier
        )
        Draft202012Validator(
            schema_document("tool-qualification-verification")
        ).validate(dossier_verdict)

        cli_assessment_path = self.root / "cli-benchmark-assessment.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "benchmark-assess",
                        str(protocol_path),
                        str(result_path),
                        str(self.manifest_path),
                        "-o",
                        str(cli_assessment_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "benchmark-verify",
                        str(cli_assessment_path),
                        "--protocol",
                        str(protocol_path),
                        "--qualification-result",
                        str(result_path),
                        "--qualification-manifest",
                        str(self.manifest_path),
                        "--json",
                    ]
                ),
                0,
            )
        cli_dossier_path = self.root / "cli-tool-qualification.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "tool-qualification-init",
                        str(self.analysis_path),
                        "--benchmark",
                        str(cli_assessment_path),
                        "--conformance",
                        str(conformance_path),
                        "--anomalies",
                        str(anomaly_path),
                        "--intended-use",
                        "Controlled screening",
                        "--reliance",
                        "Human review remains mandatory",
                        "--basis",
                        "Approved qualification plan",
                        "--classification",
                        "TQL decision pending",
                        "--environment",
                        "Controlled CPython baseline",
                        "--authority",
                        "Tool qualification authority",
                        "-o",
                        str(cli_dossier_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "tool-qualification-assess",
                        str(cli_dossier_path),
                        "TQ-CLASSIFY",
                        "--applicability",
                        "applicable",
                        "--status",
                        "satisfied",
                        "--rationale",
                        "Approved classification record",
                        "--reviewer",
                        "Independent reviewer",
                        "--evidence-ref",
                        "record://classification",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "tool-qualification-verify",
                        str(cli_dossier_path),
                        "--analysis",
                        str(self.analysis_path),
                        "--benchmark",
                        str(cli_assessment_path),
                        "--conformance",
                        str(conformance_path),
                        "--anomalies",
                        str(anomaly_path),
                        "--json",
                    ]
                ),
                0,
            )
        for objective in [item["id"] for item in dossier["objectives"]]:
            dossier = assess_tool_qualification_objective(
                dossier,
                objective,
                applicability="applicable",
                status="satisfied",
                rationale="The controlled dossier evidence was independently reviewed.",
                reviewer="Qualification reviewer",
                evidence_refs=[f"evidence://qualification/{objective}"],
                reviewed_at="2026-08-27T13:30:00+00:00",
            )
        self.assertTrue(verify_tool_qualification_dossier(dossier)["valid"])
        self.assertFalse(
            dossier["summary"]["eligible_for_authorized_qualification_decision"]
        )
        tampered_dossier = copy.deepcopy(dossier)
        tampered_dossier["objectives"][0]["title"] = "weakened objective"
        tampered_dossier["content_sha256"] = canonical_json_sha256(
            {
                key: value
                for key, value in tampered_dossier.items()
                if key != "content_sha256"
            }
        )
        self.assertFalse(verify_tool_qualification_dossier(tampered_dossier)["valid"])
        malformed_dossier = copy.deepcopy(dossier)
        malformed_dossier["bindings"]["analysis"] = None
        self.assertFalse(verify_tool_qualification_dossier(malformed_dossier)["valid"])
        malformed_dossier = copy.deepcopy(dossier)
        malformed_dossier["objectives"] = [1]
        self.assertFalse(verify_tool_qualification_dossier(malformed_dossier)["valid"])
        self.assertEqual(
            result["features"]["control_detection"]["positive_components"], 1
        )
        self.assertEqual(
            result["features"]["control_detection"]["negative_components"], 1
        )

        result_path = self.root / "qualification-result.json"
        self._write_json(result_path, result)
        complete = verify_qualification_campaign_file(
            result_path, manifest=self.manifest_path
        )
        integrity = verify_qualification_campaign_file(result_path)
        self.assertTrue(complete["valid"])
        self.assertTrue(complete["reconciled"])
        self.assertTrue(complete["eligible_for_independent_review"])
        self.assertTrue(integrity["valid"])
        self.assertFalse(integrity["reconciled"])

        artifacts = {
            "qualification-campaign-manifest": self.manifest,
            "qualification-campaign-result": result,
            "qualification-campaign-verification": complete,
        }
        for name, artifact in artifacts.items():
            Draft202012Validator(schema_document(name)).validate(artifact)

    def test_cli_build_verify_and_eligibility_gate(self) -> None:
        result_path = self.root / "qualification-result.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            build_exit = main(
                [
                    "qualification-build",
                    str(self.manifest_path),
                    "-o",
                    str(result_path),
                    "--require-eligible",
                ]
            )
        self.assertEqual(build_exit, 0)
        self.assertTrue(result_path.exists())
        self.assertIn("missing_cases=0", stdout.getvalue())
        self.assertIn("mismatched_claims=0", stdout.getvalue())

        verification_path = self.root / "qualification-verification.json"
        with contextlib.redirect_stdout(io.StringIO()):
            verify_exit = main(
                [
                    "qualification-verify",
                    str(result_path),
                    "--manifest",
                    str(self.manifest_path),
                    "--require-eligible",
                    "-o",
                    str(verification_path),
                ]
            )
            integrity_exit = main(
                [
                    "qualification-verify",
                    str(result_path),
                    "--integrity-only",
                ]
            )
        self.assertEqual(verify_exit, 0)
        self.assertEqual(integrity_exit, 0)
        self.assertTrue(json.loads(verification_path.read_text())["reconciled"])

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            missing_manifest_exit = main(["qualification-verify", str(result_path)])
        self.assertEqual(missing_manifest_exit, 2)
        self.assertIn("--manifest is required", stderr.getvalue())

    def test_program_init_imports_exact_reconciled_campaign_cohorts(self) -> None:
        result = build_qualification_campaign(self.manifest_path)
        result_path = self.root / "qualification-result.json"
        self._write_json(result_path, result)
        program_path = self.root / "assurance-program.json"

        incomplete_program_path = self.root / "incomplete-program.json"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            incomplete_exit = main(
                [
                    "program-init",
                    "--analysis",
                    f"service-a={self.analysis_path}",
                    "--qualification-result",
                    str(result_path),
                    "-o",
                    str(incomplete_program_path),
                ]
            )
        self.assertEqual(incomplete_exit, 2)
        self.assertFalse(incomplete_program_path.exists())
        self.assertIn("must be supplied together", stderr.getvalue())

        cohorts = qualification_validation_cohorts(
            result_path,
            self.manifest_path,
            program_destination=program_path,
        )
        self.assertEqual(len(cohorts), 1)
        self.assertEqual(cohorts[0]["matched_count"], cohorts[0]["case_count"])
        self.assertEqual(
            cohorts[0]["evaluation_result_artifact"]["path"],
            self.evaluation_path.name,
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "program-init",
                    "--analysis",
                    f"service-a={self.analysis_path}",
                    "--qualification-result",
                    str(result_path),
                    "--qualification-manifest",
                    str(self.manifest_path),
                    "-o",
                    str(program_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("qualification cohorts imported=1", stdout.getvalue())
        program = json.loads(program_path.read_text(encoding="utf-8"))
        self.assertEqual(program["validation_cohorts"], cohorts)
        verification = verify_assurance_program(program_path)
        self.assertEqual(verification["validation"]["cohorts"], 1)
        self.assertEqual(verification["validation"]["verified_evaluation_artifacts"], 1)
        self.assertFalse(
            any(
                finding["code"].startswith("validation.evaluation_artifact_")
                for finding in verification["findings"]
            )
        )

    def test_self_contained_report_is_navigable_bound_and_schema_valid(self) -> None:
        result = build_qualification_campaign(self.manifest_path)
        result_path = self.root / "qualification-result.json"
        report_path = self.root / "qualification-report.html"
        self._write_json(result_path, result)
        export_qualification_report(
            result_path,
            self.manifest_path,
            report_path,
            title='Qualification <review> "campaign"',
        )
        document = report_path.read_text(encoding="utf-8")
        self.assertIn(f'content="{QUALIFICATION_REPORT_FORMAT}"', document)
        self.assertIn("Skip to report content", document)
        self.assertIn('class="skip skip-link"', document)
        self.assertIn('aria-label="Report sections"', document)
        self.assertIn('scope="col"', document)
        self.assertEqual(document.count('<caption class="sr-only">'), 10)
        self.assertIn("prefers-reduced-motion", document)
        self.assertIn("@media print", document)
        self.assertIn("Control components positive / negative", document)
        self.assertIn("positive and negative evaluated components", document)
        self.assertIn("Semantic-output qualification", document)
        self.assertIn("Accuracy by output field", document)
        self.assertIn("Observed semantic drift", document)
        self.assertIn("mismatched semantic claims", document)
        self.assertIn('id="semanticDiagnosticSearch"', document)
        self.assertIn('id="semanticDiagnosticNext"', document)
        self.assertIn("Search drift", document)
        self.assertIn("No retained semantic drift examples", document)
        self.assertIn("Qualification &lt;review&gt; &quot;campaign&quot;", document)
        self.assertNotIn('Qualification <review> "campaign"', document)

        standalone = verify_qualification_report_file(report_path)
        complete = verify_qualification_report_file(
            report_path, result_source=result_path
        )
        self.assertTrue(standalone["valid"])
        self.assertFalse(standalone["reconciled"])
        self.assertTrue(complete["reconciled"])
        Draft202012Validator(
            schema_document("qualification-report-verification")
        ).validate(standalone)
        Draft202012Validator(
            schema_document("qualification-report-verification")
        ).validate(complete)

        verification_path = self.root / "qualification-report-verification.json"
        with contextlib.redirect_stdout(io.StringIO()):
            report_exit = main(
                [
                    "qualification-report",
                    str(result_path),
                    "--manifest",
                    str(self.manifest_path),
                    "-o",
                    str(self.root / "cli-report.html"),
                ]
            )
            verify_exit = main(
                [
                    "qualification-report-verify",
                    str(report_path),
                    "--result",
                    str(result_path),
                    "-o",
                    str(verification_path),
                ]
            )
        self.assertEqual(report_exit, 0)
        self.assertEqual(verify_exit, 0)
        self.assertTrue(json.loads(verification_path.read_text())["reconciled"])

        tampered_path = self.root / "tampered-report.html"
        tampered_path.write_text(
            document.replace("Qualification overview", "Approved qualification", 1),
            encoding="utf-8",
        )
        tampered = verify_qualification_report_file(tampered_path)
        self.assertFalse(tampered["valid"])
        self.assertFalse(tampered["checks"]["document_integrity"])

        stale_result = copy.deepcopy(result)
        stale_result["campaign"]["title"] = "Changed result"
        stale_unsigned = copy.deepcopy(stale_result)
        stale_unsigned.pop("content_sha256")
        stale_result["content_sha256"] = canonical_json_sha256(stale_unsigned)
        stale_path = self.root / "stale-result.json"
        self._write_json(stale_path, stale_result)
        stale_verdict = verify_qualification_report_file(
            report_path, result_source=stale_path
        )
        self.assertTrue(stale_verdict["valid"])
        self.assertFalse(stale_verdict["reconciled"])
        self.assertFalse(stale_verdict["checks"]["result_binding"])

    def test_tampering_and_stale_evaluation_receive_no_credit(self) -> None:
        result = build_qualification_campaign(self.manifest_path)
        tampered = copy.deepcopy(result)
        tampered["summary"]["domain_count"] = 99
        unsigned = copy.deepcopy(tampered)
        unsigned.pop("content_sha256")
        tampered["content_sha256"] = canonical_json_sha256(unsigned)
        verdict = verify_qualification_campaign(tampered)
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["semantic_consistency"])

        malformed = copy.deepcopy(result)
        malformed["repositories"][0]["selection_rationale"] = ""
        malformed_unsigned = copy.deepcopy(malformed)
        malformed_unsigned.pop("content_sha256")
        malformed["content_sha256"] = canonical_json_sha256(malformed_unsigned)
        malformed_verdict = verify_qualification_campaign(malformed)
        self.assertFalse(malformed_verdict["valid"])
        self.assertFalse(malformed_verdict["checks"]["structure"])

        evaluation = json.loads(self.evaluation_path.read_text(encoding="utf-8"))
        evaluation["actual"] += 1
        self._write_json(self.evaluation_path, evaluation)
        with self.assertRaisesRegex(ValueError, "does not exactly regenerate"):
            build_qualification_campaign(self.manifest_path)

    def test_governance_and_required_feature_gates_are_explicit(self) -> None:
        self.corpus["governance"]["independent"] = False
        self._write_corpus_and_evaluation(load_analysis(self.analysis_path))
        self.manifest["thresholds"]["require_call_cases"] = True
        self._write_json(self.manifest_path, self.manifest)

        result = build_qualification_campaign(self.manifest_path)
        self.assertFalse(result["eligible_for_independent_review"])
        self.assertFalse(result["checks"]["independent_corpora"])
        self.assertFalse(result["checks"]["call_cases_present"])
        self.assertEqual(result["status"], "qualification_evidence_incomplete")
        Draft202012Validator(schema_document("qualification-campaign-result")).validate(
            result
        )

        result_path = self.root / "negative-result.json"
        self._write_json(result_path, result)
        with self.assertRaisesRegex(ValueError, "independently governed corpus"):
            qualification_validation_cohorts(
                result_path,
                self.manifest_path,
                program_destination=self.root / "program.json",
            )
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main(
                [
                    "qualification-verify",
                    str(result_path),
                    "--manifest",
                    str(self.manifest_path),
                    "--require-eligible",
                ]
            )
        self.assertEqual(exit_code, 1)

    def test_semantic_drift_blocks_campaign_eligibility_and_is_segmented(self) -> None:
        current = self.corpus["semantic_cases"][0]["expect"]["confidence"]
        self.corpus["semantic_cases"][0]["expect"]["confidence"] = (
            "low" if current != "low" else "high"
        )
        self._write_corpus_and_evaluation(load_analysis(self.analysis_path))
        self._write_json(self.manifest_path, self.manifest)

        result = build_qualification_campaign(self.manifest_path)

        self.assertFalse(result["eligible_for_independent_review"])
        self.assertFalse(result["checks"]["semantic_recall"])
        self.assertFalse(result["checks"]["semantic_precision"])
        self.assertFalse(result["checks"]["semantic_population_recall"])
        self.assertFalse(result["checks"]["semantic_population_precision"])
        self.assertEqual(result["features"]["semantic_output"]["matched"], 0)
        self.assertEqual(result["by_semantic_field"]["confidence"]["matched"], 0)
        self.assertEqual(
            result["by_semantic_rule"][self.corpus["semantic_cases"][0]["rule_id"]][
                "matched"
            ],
            0,
        )
        diagnostics = result["repositories"][0]["semantic_diagnostics"]
        self.assertEqual(diagnostics["missing_count"], 0)
        self.assertEqual(diagnostics["mismatch_count"], 1)
        self.assertEqual(diagnostics["examples_omitted"], 0)
        self.assertEqual(diagnostics["examples"][0]["kind"], "mismatch")
        self.assertEqual(diagnostics["examples"][0]["field"], "confidence")
        self.assertEqual(result["summary"]["semantic_missing_cases"], 0)
        self.assertEqual(result["summary"]["semantic_mismatched_claims"], 1)
        Draft202012Validator(schema_document("qualification-campaign-result")).validate(
            result
        )
        malformed = copy.deepcopy(result)
        malformed["repositories"][0]["semantic_diagnostics"]["examples"][0][
            "actual"
        ] = None
        with self.assertRaises(ValidationError):
            Draft202012Validator(
                schema_document("qualification-campaign-result")
            ).validate(malformed)

    def test_required_negative_control_population_cannot_receive_precision_credit(
        self,
    ) -> None:
        self.corpus["control_scope"] = ["service.py:check_circuit_breaker"]
        self._write_corpus_and_evaluation(load_analysis(self.analysis_path))

        result = build_qualification_campaign(self.manifest_path)

        self.assertEqual(
            result["features"]["control_detection"]["negative_components"], 0
        )
        self.assertFalse(result["checks"]["control_negative_population"])
        self.assertFalse(result["eligible_for_independent_review"])

    def test_manifest_rejects_escape_duplicate_identity_and_unknown_fields(
        self,
    ) -> None:
        escaped = copy.deepcopy(self.manifest)
        escaped["repositories"][0]["analysis"] = "../analysis.json"
        self._write_json(self.manifest_path, escaped)
        with self.assertRaisesRegex(ValueError, "escapes"):
            build_qualification_campaign(self.manifest_path)

        duplicated = copy.deepcopy(self.manifest)
        duplicated["repositories"].append(copy.deepcopy(duplicated["repositories"][0]))
        self._write_json(self.manifest_path, duplicated)
        with self.assertRaisesRegex(ValueError, "IDs must be unique"):
            build_qualification_campaign(self.manifest_path)

        unknown = copy.deepcopy(self.manifest)
        unknown["unreviewed_override"] = True
        self._write_json(self.manifest_path, unknown)
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            build_qualification_campaign(self.manifest_path)

    def test_reused_artifacts_and_masked_weak_segments_receive_no_credit(self) -> None:
        duplicate_analysis = self.root / "analysis-copy.json"
        duplicate_corpus = self.root / "corpus-copy.json"
        duplicate_evaluation = self.root / "evaluation-copy.json"
        duplicate_analysis.write_bytes(self.analysis_path.read_bytes())
        duplicate_corpus.write_bytes(self.corpus_path.read_bytes())
        duplicate_evaluation.write_bytes(self.evaluation_path.read_bytes())
        duplicate_manifest = copy.deepcopy(self.manifest)
        duplicate_manifest["repositories"].append(
            {
                **copy.deepcopy(duplicate_manifest["repositories"][0]),
                "id": "service-copy",
                "analysis": duplicate_analysis.name,
                "corpus": duplicate_corpus.name,
                "evaluation": duplicate_evaluation.name,
            }
        )
        self._write_json(self.manifest_path, duplicate_manifest)
        with self.assertRaisesRegex(ValueError, "reuses one analysis artifact"):
            build_qualification_campaign(self.manifest_path)

        second_source = self.root / "worker_b.py"
        second_source.write_text(
            "def dispatch(value):\n    return value\n", encoding="utf-8"
        )
        second_analysis_path = self.root / "analysis-b.json"
        save_analysis(second_analysis_path, scan_repository(self.root))
        second_analysis = load_analysis(second_analysis_path)
        second_cases = [
            {
                "source": item["source"]["path"],
                "component": item["component"]["qualname"],
                "rule_id": item["scanner"]["rule_id"],
            }
            for item in second_analysis["items"]
            if item["source"]["path"] == second_source.name
        ]
        second_cases.append(
            {
                "source": second_source.name,
                "component": "dispatch",
                "rule_id": "synthetic.missed-mode",
            }
        )
        second_corpus = {
            **copy.deepcopy(self.corpus),
            "name": "Independent weak-segment corpus",
            "scope": ["worker_b.py:*"],
            "cases": second_cases,
            "governance": {
                **copy.deepcopy(self.corpus["governance"]),
                "repositories": ["retained/service-b"],
            },
        }
        second_corpus_path = self.root / "corpus-b.json"
        second_evaluation_path = self.root / "evaluation-b.json"
        self._write_json(second_corpus_path, second_corpus)
        second_evaluation = evaluate_candidates(
            second_analysis, load_evaluation_spec(second_corpus_path)
        )
        self._write_json(second_evaluation_path, second_evaluation)
        segmented = copy.deepcopy(self.manifest)
        segmented["thresholds"]["minimum_finding_recall"] = 0.0
        segmented["repositories"].append(
            {
                "id": "service-b",
                "analysis": second_analysis_path.name,
                "corpus": second_corpus_path.name,
                "evaluation": second_evaluation_path.name,
                "frameworks": ["worker-framework"],
                "domains": ["background-jobs"],
                "selection_rationale": "Independent lower-performing segment.",
            }
        )
        self._write_json(self.manifest_path, segmented)
        preliminary = build_qualification_campaign(self.manifest_path)
        global_recall = preliminary["features"]["finding_detection"]["recall"]
        weak_recall = preliminary["repositories"][1]["features"]["finding_detection"][
            "recall"
        ]
        self.assertGreater(global_recall, weak_recall)
        threshold = round((global_recall + weak_recall) / 2, 4)
        segmented["thresholds"]["minimum_finding_recall"] = threshold
        self._write_json(self.manifest_path, segmented)
        result = build_qualification_campaign(self.manifest_path)
        self.assertGreaterEqual(
            result["features"]["finding_detection"]["recall"], threshold
        )
        self.assertFalse(result["checks"]["repository_finding_recall"])
        self.assertFalse(result["checks"]["framework_finding_recall"])
        self.assertFalse(result["eligible_for_independent_review"])

    def test_missing_result_returns_schema_backed_rejection(self) -> None:
        verdict = verify_qualification_campaign_file(self.root / "missing.json")
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["mode"], "rejected")
        Draft202012Validator(
            schema_document("qualification-campaign-verification")
        ).validate(verdict)
        report_verdict = verify_qualification_report_file(
            self.root / "missing-report.html"
        )
        self.assertFalse(report_verdict["valid"])
        Draft202012Validator(
            schema_document("qualification-report-verification")
        ).validate(report_verdict)


if __name__ == "__main__":
    unittest.main()
