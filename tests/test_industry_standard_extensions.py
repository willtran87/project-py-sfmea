from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.benchmark_report_v2 import (
    export_benchmark_v2_report,
    verify_benchmark_v2_report_file,
)
from pysfmea.benchmark_v2 import (
    BENCHMARK_OBSERVATIONS_V2_FORMAT,
    BENCHMARK_PROTOCOL_V2_FORMAT,
    REQUALIFICATION_TRIGGERS_V2,
    benchmark_v2_assessment,
    export_benchmark_v2_assessment,
    seal_benchmark_v2_source,
    verify_benchmark_v2_assessment_file,
)
from pysfmea.conformance import standards_catalog
from pysfmea.csaf import export_csaf, verify_csaf_file
from pysfmea.dependability import (
    dependability_assessment,
    dependability_authoring_template,
    export_dependability_assessment,
    export_dependability_authoring,
    seal_dependability_authoring,
    verify_dependability_assessment_file,
)
from pysfmea.industry_exchange import export_exchange
from pysfmea.integrity import canonical_json_sha256
from pysfmea.interoperability_validation import (
    export_independent_roundtrip_evidence,
    export_normative_schema_validation,
    independent_roundtrip_evidence,
    normative_schema_validation,
    verify_independent_roundtrip_evidence_file,
    verify_normative_schema_validation_file,
)
from pysfmea.lifecycle_model import (
    export_lifecycle_model,
    import_lifecycle_model,
    verify_lifecycle_model_file,
)
from pysfmea.safety_lifecycle import (
    export_safety_lifecycle_assessment,
    export_safety_lifecycle_authoring,
    safety_lifecycle_assessment,
    safety_lifecycle_authoring_template,
    seal_safety_lifecycle_authoring,
    verify_safety_lifecycle_assessment_file,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.slsa import (
    SLSA_BUILD_TYPE,
    SLSA_BUILDER_ID,
    export_slsa_provenance,
    slsa_provenance_statement,
)
from pysfmea.slsa_policy import (
    export_slsa_policy_assessment,
    export_slsa_trust_policy,
    export_slsa_verification_observation,
    seal_slsa_trust_policy,
    seal_slsa_verification_observation,
    slsa_policy_assessment,
    slsa_trust_policy_template,
    slsa_verification_observation_template,
    verify_slsa_policy_assessment_file,
)


def _seal(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result["content_sha256"] = canonical_json_sha256(result)
    return result


class IndustryStandardExtensionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "service.py").write_text(
            "def deliver(value: int) -> int:\n    return value + 1\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_catalog_includes_interoperability_quality_and_dependability_profiles(self) -> None:
        identifiers = {profile["id"] for profile in standards_catalog()["profiles"]}
        self.assertGreaterEqual(len(identifiers), 61)
        self.assertTrue(
            {
                "omg-sysml-2-2025",
                "oasis-oslc-lifecycle-2022",
                "iec-61882-2016",
                "iec-61078-2016",
                "iec-61165-2006",
                "iso-5055-25023-quality-measurement",
                "ieee-1012-2024",
                "oasis-csaf-2-0",
                "iso-15026-2-2022",
                "iso-5338-2023",
                "iso-42005-2025",
                "iso-pas-8800-2024",
                "ul-4600-edition-3",
                "iso-25040-2024",
                "ieee-1633-2016",
                "owasp-asvs-5-0",
                "iso-27034-1-2011",
                "nist-ai-rmf-1-0",
                "iso-24029-robustness",
                "automotive-spice-4-0",
                "faa-do-326a-ed-202a",
                "iec-82304-1-2016",
                "iso-17025-2017",
                "first-cvss-4-0",
                "mit-stpa-cast",
            }.issubset(identifiers)
        )

    def test_safety_lifecycle_and_common_cause_workbench(self) -> None:
        self.analysis["context"]["hazards"] = [
            {"id": "HZ-1", "description": "Service unavailable", "end_effect": "Mission delay", "severity_category": "major"}
        ]
        authoring = safety_lifecycle_authoring_template(
            self.analysis, authority="system-safety-authority", generated_at="2026-08-28T10:00:00+00:00"
        )
        for stage in authoring["stages"]:
            stage.update({"status": "approved", "rationale": "Lifecycle evidence reviewed for the exact baseline.", "reviewer": "independent-safety-reviewer", "reviewed_at": "2026-08-28", "evidence_refs": [f"evidence://safety/{stage['stage'].lower()}"]})
        hazard = authoring["hazards"][0]
        hazard.update({
            "classification_rationale": "Project hazard classification reviewed.",
            "safety_objectives": ["Prevent loss of required service."],
            "allocated_requirement_ids": ["REQ-SAFE-1"],
            "verification_refs": ["evidence://verification/safe-1"],
            "residual_risk_disposition": "accepted",
            "decision_authority": "system-safety-authority",
            "decision_rationale": "Acceptance is limited to the declared operating context.",
        })
        authoring["assumptions"] = ["The declared system boundary is controlled."]
        authoring["operational_feedback"].update(
            {
                "review_period": "2026-Q3",
                "authority": "operations-safety-reviewer",
                "evidence_refs": ["evidence://operations/incident-register-review"],
            }
        )
        authoring_path = self.root / "safety-authoring.json"
        export_safety_lifecycle_authoring(authoring, authoring_path)
        seal_safety_lifecycle_authoring(self.analysis, authoring_path, authoring_path)
        assessment = safety_lifecycle_assessment(
            self.analysis, authoring_path, generated_at="2026-08-28T11:00:00+00:00"
        )
        self.assertTrue(assessment["summary"]["complete"])
        Draft202012Validator(schema_document("safety-lifecycle-assessment")).validate(assessment)
        output = self.root / "safety-assessment.json"
        export_safety_lifecycle_assessment(assessment, output)
        verdict = verify_safety_lifecycle_assessment_file(output, analysis=self.analysis, authoring_source=authoring_path)
        self.assertTrue(verdict["valid"], verdict["errors"])

    def test_slsa_1_2_deny_by_default_policy(self) -> None:
        analysis_path = self.root / "analysis.json"
        analysis_path.write_text(json.dumps(self.analysis), encoding="utf-8")
        provenance = slsa_provenance_statement(self.analysis, analysis_path, generated_at="2026-08-28T12:00:00+00:00")
        provenance_path = self.root / "provenance.json"
        export_slsa_provenance(provenance, provenance_path)
        policy = slsa_trust_policy_template(authority="supply-chain-authority", generated_at="2026-08-28T12:00:00+00:00")
        policy["trusted_builders"] = [SLSA_BUILDER_ID]
        policy["trusted_signer_identities"] = ["https://example.test/workflow/main"]
        policy["allowed_build_types"] = [SLSA_BUILD_TYPE]
        policy["allowed_source_repositories"] = ["https://example.test/repository"]
        policy["policy_evidence_refs"] = ["evidence://policy/approval"]
        policy_path = self.root / "slsa-policy.json"
        export_slsa_trust_policy(policy, policy_path)
        seal_slsa_trust_policy(policy_path, policy_path)
        observation = slsa_verification_observation_template(verifier="independent-verifier", generated_at="2026-08-28T12:00:00+00:00")
        observation.update({
            "verification_tool": "cosign", "verification_tool_version": "verified-version",
            "signature_verified": True, "signer_identity": "https://example.test/workflow/main",
            "verification_evidence_ref": "evidence://signature/receipt", "hosted_build": True,
            "isolated_builds": True, "ephemeral_environment": True, "parameterless_rebuild": True,
            "source_repository": "https://example.test/repository", "source_two_party_reviewed": True,
            "source_provenance_verified": True, "source_history_retained": True,
            "evidence_refs": ["evidence://builder/controls"],
        })
        observation_path = self.root / "slsa-observation.json"
        export_slsa_verification_observation(observation, observation_path)
        seal_slsa_verification_observation(observation_path, observation_path)
        assessment = slsa_policy_assessment(provenance_path, policy_path, observation_path, generated_at="2026-08-28T13:00:00+00:00")
        self.assertTrue(assessment["summary"]["passed"])
        self.assertEqual(assessment["levels"]["build_track_achieved"], 3)
        self.assertEqual(assessment["levels"]["source_track_achieved"], 2)
        Draft202012Validator(schema_document("slsa-policy-assessment")).validate(assessment)
        output = self.root / "slsa-assessment.json"
        export_slsa_policy_assessment(assessment, output)
        verdict = verify_slsa_policy_assessment_file(output, provenance_source=provenance_path, policy_source=policy_path, observation_source=observation_path)
        self.assertTrue(verdict["valid"], verdict["errors"])

    def test_normative_json_schema_receipt_and_independent_roundtrip(self) -> None:
        artifact = self.root / "artifact.json"
        schema = self.root / "schema.json"
        artifact.write_text('{"name":"project","version":1}\n', encoding="utf-8")
        schema.write_text(
            json.dumps(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "$id": "https://standards.example.test/schema.json",
                    "type": "object",
                    "required": ["name", "version"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "version": {"type": "integer", "minimum": 1},
                    },
                    "additionalProperties": False,
                }
            ),
            encoding="utf-8",
        )
        receipt = normative_schema_validation(
            artifact,
            schema,
            schema_kind="json-schema",
            standard_name="Test exchange standard",
            standard_edition="1.0",
            normative_schema_uri="https://standards.example.test/schema.json",
            generated_at="2026-08-27T12:00:00+00:00",
        )
        self.assertTrue(receipt["outcome"]["valid"])
        Draft202012Validator(schema_document("normative-schema-validation")).validate(
            receipt
        )
        receipt_path = self.root / "schema-receipt.json"
        export_normative_schema_validation(receipt, receipt_path)
        self.assertTrue(
            verify_normative_schema_validation_file(
                receipt_path, artifact_source=artifact, schema_source=schema
            )["schema_valid"]
        )

        reexport = self.root / "receiver-export.json"
        reexport.write_bytes(artifact.read_bytes())
        observation = self.root / "roundtrip-observation.json"
        observation.write_text(
            json.dumps(
                {
                    "receiver_name": "Independent Lifecycle Tool",
                    "receiver_version": "7.4",
                    "receiver_vendor": "Example Vendor",
                    "operator": "independent-validator@example.test",
                    "independence_basis": "Separate reporting line and no scanner implementation role.",
                    "import_succeeded": True,
                    "import_evidence_ref": "evidence://receiver/import-log",
                    "reexport_artifact": str(reexport),
                    "identity_preserved": True,
                    "relationships_preserved": True,
                    "extensions_preserved": True,
                    "differences": [],
                    "comparison_evidence_ref": "evidence://receiver/comparison",
                }
            ),
            encoding="utf-8",
        )
        roundtrip = independent_roundtrip_evidence(
            receipt_path,
            observation,
            generated_at="2026-08-27T13:00:00+00:00",
        )
        self.assertTrue(roundtrip["passed"])
        Draft202012Validator(schema_document("independent-roundtrip-evidence")).validate(
            roundtrip
        )
        roundtrip_path = self.root / "roundtrip.json"
        export_independent_roundtrip_evidence(roundtrip, roundtrip_path)
        verdict = verify_independent_roundtrip_evidence_file(
            roundtrip_path,
            validation_receipt_source=receipt_path,
            observation_source=observation,
            reexport_source=reexport,
        )
        self.assertTrue(verdict["valid"], verdict["errors"])
        artifact.write_text('{"name":"changed","version":1}', encoding="utf-8")
        self.assertFalse(
            verify_normative_schema_validation_file(
                receipt_path, artifact_source=artifact, schema_source=schema
            )["valid"]
        )

    def test_reqif_sysml_and_oslc_lifecycle_bridges_regenerate(self) -> None:
        reqif = self.root / "analysis.reqif"
        export_exchange("reqif", self.analysis, reqif, generated_at="2026-08-27T12:00:00+00:00")
        reqif_model = import_lifecycle_model(
            "reqif", reqif, analysis=self.analysis, generated_at="2026-08-27T13:00:00+00:00"
        )
        reqif_output = self.root / "reqif-model.json"
        export_lifecycle_model(reqif_model, reqif_output)
        Draft202012Validator(schema_document("lifecycle-model")).validate(reqif_model)
        self.assertTrue(
            verify_lifecycle_model_file(
                reqif_output, lifecycle_source=reqif, analysis=self.analysis
            )["valid"]
        )

        component = self.analysis["components"][0]
        sysml = self.root / "sysml.json"
        sysml.write_text(
            json.dumps(
                {
                    "elements": [
                        {
                            "@id": "req-1",
                            "@type": "RequirementUsage",
                            "declaredName": "Response correctness",
                            "pysfmea:componentId": component["id"],
                        },
                        {
                            "@id": "verify-1",
                            "@type": "VerificationCaseUsage",
                            "declaredName": "Boundary verification",
                        },
                        {
                            "@id": "rel-1",
                            "@type": "VerificationRelationship",
                            "source": {"@id": "verify-1"},
                            "target": {"@id": "req-1"},
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        sysml_model = import_lifecycle_model("sysml2-json", sysml, analysis=self.analysis)
        self.assertEqual(sysml_model["summary"]["code_links"], 1)
        self.assertEqual(sysml_model["summary"]["relationships"], 1)

        oslc = self.root / "oslc.json"
        oslc.write_text(
            json.dumps(
                {
                    "@graph": [
                        {
                            "@id": "https://lifecycle.example.test/requirements/1",
                            "@type": "oslc_rm:Requirement",
                            "dcterms:title": "Response correctness",
                            "oslc_rm:validatedBy": {
                                "@id": "https://lifecycle.example.test/tests/1"
                            },
                        },
                        {
                            "@id": "https://lifecycle.example.test/tests/1",
                            "@type": "oslc_qm:TestCase",
                            "dcterms:title": "Boundary verification",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        oslc_model = import_lifecycle_model("oslc-jsonld", oslc)
        self.assertEqual(oslc_model["summary"]["entities"], 2)
        self.assertEqual(oslc_model["summary"]["relationships"], 1)

    def test_repository_clustered_benchmark_v2_is_exactly_reproducible(self) -> None:
        thresholds = {
            "propagation_paths": {
                "minimum_recall_lower": 0.5,
                "minimum_precision_lower": 0.5,
            },
            "timing_contracts": {
                "minimum_recall_lower": 0.5,
                "minimum_precision_lower": 0.5,
            },
        }
        protocol = _seal(
            {
                "format": BENCHMARK_PROTOCOL_V2_FORMAT,
                "id": "benchmark-v2-test",
                "title": "Independent repository-clustered benchmark",
                "pre_registered_at": "2026-08-27T00:00:00+00:00",
                "pre_registration_evidence_ref": "registry://benchmark-v2-test",
                "governance": {
                    "protocol_owner": "protocol-owner",
                    "label_authority": "label-authority",
                    "approval_authority": "approval-authority",
                    "independence_basis": "Distinct organizations and reporting lines.",
                },
                "design": {
                    "frozen_before_execution": True,
                    "blinded_holdout": True,
                    "minimum_repositories": 3,
                    "selection_method": "Pre-registered risk-stratified selection.",
                    "represented_populations": ["service"],
                    "excluded_populations": ["native extension"],
                    "strata_fields": ["framework", "size"],
                    "minimum_repositories_per_stratum": 1,
                },
                "statistics": {
                    "confidence_level": 0.95,
                    "bootstrap_replicates": 200,
                    "bootstrap_seed": "published-seed-2026",
                    "metric_thresholds": thresholds,
                    "minimum_krippendorff_alpha": 0.8,
                    "minimum_calibration_samples": 6,
                    "maximum_brier_score": 0.1,
                    "maximum_expected_calibration_error": 0.2,
                },
                "power_analysis": {
                    "method": "pre-registered repository-cluster simulation",
                    "alpha": 0.05,
                    "target_power": 0.8,
                    "minimum_effect_size": 0.2,
                    "required_repositories": 3,
                    "evidence_ref": "evidence://power-analysis/1",
                },
                "requalification_triggers": sorted(REQUALIFICATION_TRIGGERS_V2),
            }
        )
        metric = {
            "true_positive": 20,
            "false_positive": 0,
            "false_negative": 0,
            "true_negative": 20,
        }
        repositories = []
        for index, framework in enumerate(("plain", "async", "data"), start=1):
            repositories.append(
                {
                    "id": f"repo-{index}",
                    "source_ref": f"evidence://repo/{index}",
                    "strata": {"framework": [framework], "size": ["small"]},
                    "metrics": {
                        "propagation_paths": copy.deepcopy(metric),
                        "timing_contracts": copy.deepcopy(metric),
                    },
                    "predictions": [
                        {"confidence": 0.95, "outcome": True},
                        {"confidence": 0.05, "outcome": False},
                    ],
                }
            )
        observations = _seal(
            {
                "format": BENCHMARK_OBSERVATIONS_V2_FORMAT,
                "protocol_id": "benchmark-v2-test",
                "sealed_at": "2026-08-27T01:00:00+00:00",
                "labeling_completed_at": "2026-08-27T02:00:00+00:00",
                "repositories": repositories,
                "rating_items": [
                    {
                        "id": f"rating-{index}",
                        "ratings": {"reviewer-a": state, "reviewer-b": state},
                        "adjudication_ref": f"evidence://rating/{index}",
                    }
                    for index, state in enumerate((True, False, True, False), start=1)
                ],
            }
        )
        protocol_path = self.root / "protocol-v2.json"
        observations_path = self.root / "observations-v2.json"
        protocol["content_sha256"] = "0" * 64
        observations["content_sha256"] = "0" * 64
        protocol_path.write_text(json.dumps(protocol), encoding="utf-8")
        observations_path.write_text(json.dumps(observations), encoding="utf-8")
        seal_benchmark_v2_source(protocol_path, protocol_path)
        seal_benchmark_v2_source(
            observations_path, observations_path, protocol_source=protocol_path
        )
        result = benchmark_v2_assessment(
            protocol_path,
            observations_path,
            generated_at="2026-08-27T03:00:00+00:00",
        )
        self.assertTrue(result["summary"]["passed"])
        Draft202012Validator(
            schema_document("independent-benchmark-assessment-v2")
        ).validate(result)
        output = self.root / "benchmark-v2.json"
        export_benchmark_v2_assessment(result, output)
        verdict = verify_benchmark_v2_assessment_file(
            output,
            protocol_source=protocol_path,
            observations_source=observations_path,
        )
        self.assertTrue(verdict["valid"], verdict["errors"])
        self.assertTrue(verdict["passed"])
        report = self.root / "benchmark-v2.html"
        export_benchmark_v2_report(output, report, title="Controlled benchmark")
        report_verdict = verify_benchmark_v2_report_file(
            report, assessment_source=output
        )
        self.assertTrue(report_verdict["valid"], report_verdict["errors"])
        Draft202012Validator(
            schema_document("independent-benchmark-report-verification-v2")
        ).validate(report_verdict)

    def test_hazop_rbd_and_markov_assessment(self) -> None:
        authoring = dependability_authoring_template(
            self.analysis,
            authority="dependability-authority",
            generated_at="2026-08-27T10:00:00+00:00",
        )
        authoring["assumptions"] = [
            "Rates are homogeneous over the one-hour mission and independently reviewed."
        ]
        for node in authoring["hazop"]["nodes"]:
            node["design_intent"] = "Return the specified output within the declared timing contract."
            node["deviations"] = [
                {
                    "parameter": parameter,
                    "guideword": guideword,
                    "deviation": f"{guideword} {parameter}",
                    "causes": ["Injected component fault"],
                    "effects": ["Specified service objective is not met"],
                    "safeguards": ["Independent acceptance oracle"],
                    "recommendations": ["Retain fault-injection evidence"],
                    "evidence_refs": ["evidence://hazop/review"],
                    "status": "reviewed",
                }
                for parameter in node["parameters"]
                for guideword in authoring["hazop"]["guidewords"]
            ]
        block = authoring["rbd"]["blocks"][0]
        block["reliability"] = 0.99
        authoring["rbd"]["success_criterion"] = "The delivery function returns a valid result."
        authoring["rbd"]["top_gate_id"] = block["id"]
        authoring["markov_models"] = [
            {
                "id": "service-state-model",
                "title": "Service failure and restoration",
                "mission_time_hours": 1.0,
                "initial_state": "operational",
                "states": ["operational", "failed"],
                "transitions": [
                    {
                        "source": "operational",
                        "target": "failed",
                        "rate_per_hour": 0.01,
                        "evidence_ref": "evidence://rates/failure",
                    },
                    {
                        "source": "failed",
                        "target": "operational",
                        "rate_per_hour": 1.0,
                        "evidence_ref": "evidence://rates/repair",
                    },
                ],
                "source_ref": "service.py:deliver",
            }
        ]
        authoring_path = self.root / "dependability-authoring.json"
        export_dependability_authoring(authoring, authoring_path)
        seal_dependability_authoring(self.analysis, authoring_path, authoring_path)
        result = dependability_assessment(
            self.analysis,
            authoring_path,
            generated_at="2026-08-27T11:00:00+00:00",
        )
        self.assertTrue(result["summary"]["complete"])
        Draft202012Validator(schema_document("dependability-assessment")).validate(
            result
        )
        self.assertAlmostEqual(result["rbd"]["top_success_probability"], 0.99)
        self.assertEqual(result["rbd"]["block_measures"][0]["birnbaum_importance"], 1.0)
        self.assertAlmostEqual(
            sum(result["markov_models"][0]["state_probabilities"].values()), 1.0
        )
        output = self.root / "dependability-assessment.json"
        export_dependability_assessment(result, output)
        verdict = verify_dependability_assessment_file(
            output, analysis=self.analysis, authoring_source=authoring_path
        )
        self.assertTrue(verdict["valid"], verdict["errors"])
        self.assertTrue(verdict["complete"])

    def test_csaf_projection_uses_only_governed_vex_status(self) -> None:
        decisions = {
            "format": "pysfmea-vex-decisions-1",
            "authority": "product-security-authority",
            "issued_at": "2026-08-27T16:00:00+00:00",
            "vulnerabilities": [
                {
                    "id": "CVE-2099-0001",
                    "source_name": "NVD",
                    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                    "response": [],
                    "detail": "The affected entry point is not reachable in the exact baseline.",
                    "affected_refs": ["project"],
                    "evidence_refs": ["evidence://security/reachability-review"],
                }
            ],
        }
        decisions_path = self.root / "vex-decisions.json"
        decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
        output = self.root / "advisory.csaf.json"
        export_csaf(self.analysis, decisions_path, output)
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["document"]["csaf_version"], "2.0")
        self.assertEqual(
            document["vulnerabilities"][0]["product_status"]["known_not_affected"],
            ["CSAFPID-PYSFMEA-PROJECT"],
        )
        verdict = verify_csaf_file(output, self.analysis, decisions_path)
        self.assertTrue(verdict["valid"], verdict["errors"])
        Draft202012Validator(schema_document("csaf-verification")).validate(verdict)


if __name__ == "__main__":
    unittest.main()
