from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.integrity import canonical_json_sha256
from pysfmea.json_ingestion import BoundedJsonDocument
from pysfmea.llm_quality import project_llm_quality_corpus
from pysfmea.program import (
    PROGRAM_FORMAT,
    ProgramReportPublicationError,
    _program_report_verification_contract,
    _program_verification_payload_contract,
    build_program_template,
    export_program_report_verification,
    export_program_verification,
    program_verification_html,
    program_verification_markdown,
    seal_program,
    seal_program_file,
    verify_assurance_program,
    verify_program_report_file,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis


class AssuranceProgramTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.analysis_paths: list[Path] = []
        self.analyses: list[dict[str, object]] = []
        for name in ("orders", "payments"):
            repository = self.root / name
            repository.mkdir()
            (repository / "service.py").write_text(
                f"def {name}_operation(value):\n    return value\n",
                encoding="utf-8",
            )
            analysis = scan_repository(repository)
            path = repository / "sfmea-analysis.json"
            save_analysis(path, analysis)
            self.analysis_paths.append(path)
            self.analyses.append(analysis)
        self.program_path = self.root / "program.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _valid_program(self) -> dict[str, object]:
        program = build_program_template(
            [
                ("orders", self.analysis_paths[0]),
                ("payments", self.analysis_paths[1]),
            ],
            destination=self.program_path,
            name="Checkout assurance program",
        )
        orders_component = self.analyses[0]["components"][0]["id"]
        payments_component = self.analyses[1]["components"][0]["id"]
        program["relationships"] = [
            {
                "id": "REL-CHECKOUT-PAYMENT",
                "kind": "calls",
                "source": {
                    "repository_id": "orders",
                    "component_id": orders_component,
                },
                "target": {
                    "repository_id": "payments",
                    "component_id": payments_component,
                },
                "temporal": {
                    "deadline_ms": 500,
                    "timeout_ms": 450,
                    "retry_limit": 1,
                    "ordering": "request before authorization response",
                    "clock": "monotonic",
                },
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "open_state_timeout_ms": 1_000,
                    "half_open_max_calls": 1,
                    "recovery_deadline_ms": 2_000,
                },
            }
        ]
        requirements = [
            {
                "id": "REQ-CHECKOUT-001",
                "text": "Checkout shall fail safely when authorization is unavailable.",
                "repository_ids": ["orders", "payments"],
                "hazard_ids": [],
                "finding_ids": [],
            }
        ]
        program["requirements_sources"] = [
            {
                "id": "JAMA-CHECKOUT",
                "provider": "Jama",
                "revision": "42",
                "retrieved_at": "2026-08-05T00:00:00+00:00",
                "source_uri": "https://requirements.example/items/checkout",
                "content_sha256": canonical_json_sha256(requirements),
                "requirements": requirements,
            }
        ]
        artifact = self.root / "timing-evidence.json"
        artifact.write_text('{"observed_max_ms":325}\n', encoding="utf-8")
        program["external_evidence"] = [
            {
                "id": "EVID-TIMING-001",
                "technique": "chaos",
                "status": "passed",
                "repository_ids": ["orders", "payments"],
                "relationship_ids": ["REL-CHECKOUT-PAYMENT"],
                "finding_ids": [],
                "producer": "CI runner",
                "reviewer": "Independent safety reviewer",
                "metrics": {
                    "observed_max_ms": 325,
                    "circuit_breaker_opened": True,
                    "half_open_recovered": True,
                    "recovery_time_ms": 1_500,
                },
                "artifact": {
                    "path": artifact.name,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                },
            }
        ]
        evaluation_result = {
            "format": "pysfmea-evaluation-result-1",
            "verifier": {"name": "PySFMEA", "version": "0.59.0"},
            "corpus": {
                "content_sha256": "a" * 64,
                "case_count": 100,
                "call_case_count": 40,
                "semantic_case_count": 10,
            },
            "expected": 100,
            "actual": 100,
            "matched": 91,
            "recall": 0.91,
            "precision": 0.91,
            "missing": [{"case": index} for index in range(9)],
            "unexpected": [{"case": index} for index in range(9)],
            "metrics": {
                "duplicate_count": 0,
                "unsupported_verification_claims": [],
            },
            "call_resolution": {
                "enabled": True,
                "expected": 40,
                "actual": 40,
                "matched": 36,
                "recall": 0.9,
                "precision": 0.9,
                "missing": [{"case": index} for index in range(4)],
                "unexpected": [{"case": index} for index in range(4)],
            },
            "semantic_output": {
                "enabled": True,
                "expected": 10,
                "actual": 10,
                "matched": 9,
                "recall": 0.9,
                "precision": 0.9,
                "missing": [{"case": 1}],
                "mismatches": [],
            },
        }
        evaluation_artifact = self.root / "evaluation-result.json"
        evaluation_artifact.write_text(
            json.dumps(evaluation_result, indent=2) + "\n", encoding="utf-8"
        )
        program["validation_cohorts"] = [
            {
                "id": "COHORT-EXTERNAL-1",
                "repository": "independently-labelled-service",
                "framework": "FastAPI",
                "corpus_sha256": "a" * 64,
                "case_count": 100,
                "recall": 0.91,
                "precision": 0.91,
                "matched_count": 91,
                "actual_matched_count": 91,
                "actual_count": 100,
                "evaluation_result_format": "pysfmea-evaluation-result-1",
                "evaluation_result_sha256": canonical_json_sha256(evaluation_result),
                "evaluation_verifier_version": "0.59.0",
                "evaluation_result_artifact": {
                    "path": evaluation_artifact.name,
                    "sha256": hashlib.sha256(
                        evaluation_artifact.read_bytes()
                    ).hexdigest(),
                },
                "call_case_count": 40,
                "call_resolution_recall": 0.9,
                "call_resolution_precision": 0.9,
                "call_matched_count": 36,
                "call_actual_matched_count": 36,
                "call_actual_count": 40,
                "semantic_case_count": 10,
                "semantic_output_recall": 0.9,
                "semantic_output_precision": 0.9,
                "semantic_matched_count": 9,
                "semantic_actual_matched_count": 9,
                "semantic_actual_count": 10,
                "independent_reviewed": True,
                "producer": "Benchmark team",
                "reviewer": "Independent validation authority",
            }
        ]
        llm_corpus = {
            "schema_version": "pysfmea-llm-quality-corpus-2",
            "name": "Independent LLM quality corpus",
            "purpose": "Verify grounded and cited failure-mode summaries.",
            "subject": {
                "provider": "local",
                "model": "review-model",
                "prompt_version": "3",
            },
            "samples": [
                {
                    "id": f"S-{index + 1}",
                    "grounded": index < 49,
                    "citations_correct": index < 48,
                    "claim_count": 2,
                    "unsupported_claim_count": 0,
                }
                for index in range(50)
            ],
        }
        llm_corpus_artifact = self.root / "llm-quality-corpus.json"
        llm_corpus_artifact.write_text(
            json.dumps(llm_corpus, indent=2) + "\n", encoding="utf-8"
        )
        llm_projection = project_llm_quality_corpus(llm_corpus)
        program["llm_evaluations"] = [
            {
                "id": "LLM-EVAL-1",
                "provider": "local",
                "model": "review-model",
                "prompt_version": "3",
                "sample_count": 50,
                "grounding": 0.98,
                "citation_accuracy": 0.96,
                "unsupported_claim_rate": 0.0,
                "grounded_sample_count": 49,
                "citation_correct_sample_count": 48,
                "claim_count": 100,
                "unsupported_claim_count": 0,
                "corpus_sha256": hashlib.sha256(
                    llm_corpus_artifact.read_bytes()
                ).hexdigest(),
                "evidence_fingerprint_sha256": llm_projection.evidence_fingerprint_sha256,
                "corpus_format": "pysfmea-llm-quality-corpus-2",
                "subject_bound": True,
                "corpus_artifact": {
                    "path": llm_corpus_artifact.name,
                    "sha256": hashlib.sha256(
                        llm_corpus_artifact.read_bytes()
                    ).hexdigest(),
                },
                "independent_reviewed": True,
                "producer": "Model evaluation team",
                "reviewer": "Independent AI assurance authority",
            }
        ]
        program["quality_gates"] = {
            "min_validation_repositories": 1,
            "require_independent_validation": True,
            "min_recall": 0.8,
            "min_precision": 0.8,
            "require_count_backed_validation": True,
            "require_evaluation_result_artifacts": True,
            "min_micro_recall": 0.8,
            "min_micro_precision": 0.8,
            "min_call_resolution_recall": 0.8,
            "min_call_resolution_precision": 0.8,
            "min_micro_call_resolution_recall": 0.8,
            "min_micro_call_resolution_precision": 0.8,
            "min_semantic_output_recall": 0.8,
            "min_semantic_output_precision": 0.8,
            "min_micro_semantic_output_recall": 0.8,
            "min_micro_semantic_output_precision": 0.8,
            "require_temporal_evidence": True,
            "require_resilience_evidence": True,
            "min_llm_samples": 25,
            "require_independent_llm_evaluation": True,
            "require_llm_count_backing": True,
            "require_llm_corpus_artifacts": True,
            "require_llm_subject_binding": True,
            "min_llm_grounding": 0.9,
            "min_llm_citation_accuracy": 0.9,
            "max_llm_unsupported_claim_rate": 0.02,
        }
        program["governance"] = {
            "required_roles": ["software", "safety"],
            "independent_evidence_review": True,
            "require_program_approval": True,
            "approvals": [
                {
                    "subject_kind": "program",
                    "subject_id": "Checkout assurance program",
                    "reviewer": "Software authority",
                    "role": "software",
                    "decision": "approved",
                    "at": "2026-08-05T01:00:00+00:00",
                },
                {
                    "subject_kind": "program",
                    "subject_id": "Checkout assurance program",
                    "reviewer": "Safety authority",
                    "role": "safety",
                    "decision": "approved",
                    "at": "2026-08-05T01:05:00+00:00",
                },
            ],
        }
        program["created_at"] = "2026-08-05T00:00:00+00:00"
        return seal_program(program)

    def _write_program(self, program: dict[str, object]) -> Path:
        self.program_path.write_text(
            json.dumps(program, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return self.program_path

    def test_verifies_federated_program_evidence_timing_quality_and_governance(
        self,
    ) -> None:
        self._write_program(self._valid_program())
        result = verify_assurance_program(self.program_path)
        self.assertTrue(result["valid"], result["findings"])
        Draft202012Validator(schema_document("assurance-program")).validate(
            json.loads(self.program_path.read_text(encoding="utf-8"))
        )
        Draft202012Validator(
            schema_document("assurance-program-verification")
        ).validate(result)
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["summary"]["bound_repositories"], 2)
        self.assertEqual(result["summary"]["requirements"], 1)
        self.assertEqual(result["relationships"][0]["temporal_status"], "supported")
        self.assertEqual(result["relationships"][0]["resilience_status"], "supported")
        self.assertEqual(result["summary"]["trusted_evidence"], 1)
        self.assertEqual(result["summary"]["verified_evidence"], 1)
        self.assertEqual(result["summary"]["duplicate_evidence"], 0)
        self.assertEqual(result["summary"]["approvals"], 2)
        self.assertEqual(result["summary"]["validated_approvals"], 2)
        self.assertEqual(result["summary"]["credited_program_approvals"], 2)
        self.assertEqual(result["summary"]["conflicting_program_roles"], [])
        self.assertEqual(result["validation"]["macro_recall"], 0.91)
        self.assertEqual(result["validation"]["credited_cohorts"], 1)
        self.assertEqual(result["validation"]["duplicate_evidence"], 0)
        self.assertEqual(result["validation"]["micro_recall"], 0.91)
        self.assertEqual(result["validation"]["micro_precision"], 0.91)
        self.assertEqual(result["validation"]["count_backed_cohorts"], 1)
        self.assertEqual(result["validation"]["verified_evaluation_artifacts"], 1)
        self.assertGreater(result["validation"]["evaluation_artifact_bytes"], 0)
        self.assertEqual(result["validation"]["macro_call_resolution_recall"], 0.9)
        self.assertEqual(result["validation"]["micro_call_resolution_recall"], 0.9)
        self.assertEqual(result["validation"]["call_cases"], 40)
        self.assertEqual(result["validation"]["semantic_cases"], 10)
        self.assertEqual(result["validation"]["macro_semantic_output_recall"], 0.9)
        self.assertEqual(result["validation"]["micro_semantic_output_precision"], 0.9)
        self.assertEqual(result["llm_quality"]["samples"], 50)
        self.assertEqual(result["llm_quality"]["credited_evaluations"], 1)
        self.assertEqual(result["llm_quality"]["duplicate_evidence"], 0)
        self.assertEqual(result["llm_quality"]["count_backed_evaluations"], 1)
        self.assertEqual(result["llm_quality"]["verified_corpus_artifacts"], 1)
        self.assertEqual(result["llm_quality"]["subject_bound_evaluations"], 1)
        self.assertEqual(
            result["llm_quality"]["semantic_fingerprinted_evaluations"], 1
        )
        self.assertEqual(result["llm_quality"]["claim_count"], 100)
        self.assertEqual(result["llm_quality"]["aggregation_method"], "count-backed")
        markdown = program_verification_markdown(result)
        self.assertIn("**VALID**", markdown)
        self.assertIn("Micro recall / precision: 0.91 / 0.91", markdown)
        self.assertIn("Semantic-output cohorts: 1 (count-backed: 1; exact cases: 10)", markdown)
        self.assertIn("Micro semantic-output recall / precision: 0.9 / 0.9", markdown)
        self.assertIn("Credited validation cohorts: 1 of 1", markdown)
        self.assertIn("Count-backed cohorts: 1 of 1", markdown)
        self.assertIn("Verified evaluation artifacts: 1 of 1", markdown)
        self.assertIn("Verified / credited / duplicate evidence: 1 / 1 / 0", markdown)
        self.assertIn("Validated approvals: 2 / 2", markdown)
        self.assertIn("Credited program approvals: 2", markdown)
        self.assertIn("Conflicting program roles: none", markdown)
        self.assertIn("LLM aggregation: count-backed", markdown)
        self.assertIn("Credited LLM evaluations: 1 of 1", markdown)
        self.assertIn("Verified LLM corpus artifacts: 1 of 1", markdown)
        self.assertIn("Subject-bound LLM evaluations: 1 of 1", markdown)
        self.assertIn("Semantically fingerprinted LLM evaluations: 1 of 1", markdown)
        self.assertIn("REL-CHECKOUT-PAYMENT", markdown)
        html = program_verification_html(result)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Checkout assurance program", html)
        self.assertIn("REL-CHECKOUT-PAYMENT", html)
        self.assertIn("System topology", html)
        self.assertIn('role="img"', html)
        self.assertIn("Severity", html)
        self.assertIn("micro recall", html)
        self.assertIn("count-backed cohorts", html)
        self.assertIn("micro semantic-output recall", html)
        self.assertIn("credited validation cohorts", html)
        self.assertIn("duplicate validation evidence", html)
        self.assertIn("verified evaluation artifacts", html)
        self.assertIn("verified LLM corpus artifacts", html)
        self.assertIn("subject-bound LLM evaluations", html)
        self.assertIn("semantic LLM fingerprints", html)
        self.assertIn("credited LLM evaluations", html)
        self.assertIn("validated approvals", html)
        self.assertIn("program approvals", html)
        self.assertIn("conflicting roles", html)
        self.assertIn("duplicate LLM evidence", html)
        self.assertIn("LLM aggregation", html)
        self.assertNotIn("https://", html)

    def test_duplicate_validation_corpus_is_rejected_without_metric_credit(
        self,
    ) -> None:
        program = self._valid_program()
        duplicate = copy.deepcopy(program["validation_cohorts"][0])
        duplicate["id"] = "COHORT-EXTERNAL-DUPLICATE"
        duplicate["repository"] = "claimed-second-repository"
        program["validation_cohorts"].append(duplicate)
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)

        self.assertFalse(result["valid"])
        self.assertIn(
            "validation.duplicate_corpus_evidence",
            {value["code"] for value in result["findings"]},
        )
        self.assertEqual(result["validation"]["cohorts"], 2)
        self.assertEqual(result["validation"]["credited_cohorts"], 1)
        self.assertEqual(result["validation"]["duplicate_evidence"], 1)
        self.assertEqual(result["validation"]["repositories"], 1)
        self.assertEqual(result["validation"]["cases"], 100)
        self.assertEqual(result["validation"]["micro_recall"], 0.91)

    def test_duplicate_llm_corpus_is_rejected_without_sample_credit(self) -> None:
        program = self._valid_program()
        duplicate = copy.deepcopy(program["llm_evaluations"][0])
        duplicate["id"] = "LLM-EVAL-DUPLICATE"
        original_path = self.root / "llm-quality-corpus.json"
        duplicate_corpus = json.loads(original_path.read_text(encoding="utf-8"))
        duplicate_corpus["name"] = "Repackaged metadata"
        duplicate_corpus["purpose"] = "Same labels in a different order"
        duplicate_corpus["samples"].reverse()
        duplicate_path = self.root / "llm-quality-corpus-repackaged.json"
        duplicate_path.write_text(
            json.dumps(duplicate_corpus, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        duplicate_digest = hashlib.sha256(duplicate_path.read_bytes()).hexdigest()
        self.assertNotEqual(duplicate_digest, duplicate["corpus_sha256"])
        duplicate["corpus_sha256"] = duplicate_digest
        duplicate["corpus_artifact"] = {
            "path": duplicate_path.name,
            "sha256": duplicate_digest,
        }
        program["llm_evaluations"].append(duplicate)
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)

        self.assertFalse(result["valid"])
        self.assertIn(
            "llm.duplicate_corpus_evidence",
            {value["code"] for value in result["findings"]},
        )
        self.assertEqual(result["llm_quality"]["evaluations"], 2)
        self.assertEqual(result["llm_quality"]["credited_evaluations"], 1)
        self.assertEqual(result["llm_quality"]["duplicate_evidence"], 1)
        self.assertEqual(result["llm_quality"]["samples"], 50)
        self.assertEqual(result["llm_quality"]["claim_count"], 100)
        self.assertEqual(result["llm_quality"]["grounding"], 0.98)

    def test_rejects_stale_analysis_deadline_failure_and_nonindependent_evidence(
        self,
    ) -> None:
        program = self._valid_program()
        program["external_evidence"][0]["reviewer"] = "CI runner"
        program["external_evidence"][0]["metrics"]["observed_max_ms"] = 700
        program = seal_program(program)
        self._write_program(program)
        changed = load_analysis(self.analysis_paths[0])
        changed["summary"]["warnings"] += 1
        save_analysis(self.analysis_paths[0], changed)

        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("repository.binding_mismatch", codes)
        self.assertIn("relationship.deadline_violated", codes)
        self.assertIn("governance.evidence_independence", codes)

    def test_template_defaults_expose_missing_external_validation_and_approval(
        self,
    ) -> None:
        program = build_program_template(
            [("orders", self.analysis_paths[0])],
            destination=self.program_path,
        )
        self.assertEqual(program["format"], PROGRAM_FORMAT)
        self._write_program(program)
        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("validation.repository_count", codes)
        self.assertIn("governance.program_approval", codes)
        self.assertIn("governance.roles", codes)

    def test_malformed_nested_references_fail_closed_without_traceback(self) -> None:
        program = self._valid_program()
        program["external_evidence"][0]["repository_ids"] = None
        program["governance"]["required_roles"] = "safety"
        self._write_program(seal_program(program))
        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("evidence.reference_array", codes)
        self.assertIn("governance.required_roles", codes)
        self.assertEqual(result["summary"]["verified_evidence"], 0)
        self.assertEqual(result["summary"]["trusted_evidence"], 0)

    def test_unknown_subjects_weak_quality_and_incomplete_temporal_contract_are_blocked(
        self,
    ) -> None:
        program = self._valid_program()
        program["relationships"][0]["temporal"].pop("clock")
        program["requirements_sources"][0]["requirements"][0]["finding_ids"] = [
            "FM-UNKNOWN"
        ]
        requirements = program["requirements_sources"][0]["requirements"]
        program["requirements_sources"][0]["content_sha256"] = canonical_json_sha256(
            requirements
        )
        program["external_evidence"][0]["finding_ids"] = ["FM-UNKNOWN"]
        program["validation_cohorts"][0]["recall"] = 0.2
        program["validation_cohorts"][0]["call_resolution_recall"] = 0.2
        program["llm_evaluations"][0]["unsupported_claim_rate"] = 0.5
        program["governance"]["approvals"][0]["subject_kind"] = "evidence"
        program["governance"]["approvals"][0]["subject_id"] = "EVID-UNKNOWN"
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("relationship.temporal_contract_incomplete", codes)
        self.assertIn("requirements.unknown_finding", codes)
        self.assertIn("evidence.unknown_finding", codes)
        self.assertIn("validation.recall", codes)
        self.assertIn("validation.call_resolution_recall", codes)
        self.assertIn("llm.unsupported_claim_rate", codes)
        self.assertIn("governance.unknown_subject", codes)
        self.assertEqual(result["summary"]["validated_approvals"], 1)
        self.assertEqual(result["summary"]["credited_program_approvals"], 1)
        self.assertEqual(result["summary"]["approved_roles"], ["safety"])

    def test_call_resolution_cohort_contract_fails_closed(self) -> None:
        mutations = (
            (
                lambda cohort: cohort.pop("call_resolution_precision"),
                "validation.call_metric_missing",
            ),
            (
                lambda cohort: cohort.update({"call_case_count": 0}),
                "validation.call_metric_without_cases",
            ),
            (
                lambda cohort: cohort.update({"call_case_count": -1}),
                "validation.call_case_count",
            ),
        )
        for mutation, expected_code in mutations:
            with self.subTest(expected_code=expected_code):
                program = self._valid_program()
                mutation(program["validation_cohorts"][0])
                self._write_program(seal_program(program))
                result = verify_assurance_program(self.program_path)
                self.assertFalse(result["valid"])
                self.assertIn(
                    expected_code,
                    {value["code"] for value in result["findings"]},
                )

    def test_count_backed_metrics_fail_closed_when_claims_do_not_reconcile(
        self,
    ) -> None:
        program = self._valid_program()
        program["validation_cohorts"][0]["recall"] = 0.92
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("validation.metric_reconciliation", codes)
        self.assertIn("validation.count_backing", codes)

    def test_evaluation_artifact_bytes_and_projected_claims_are_verified(self) -> None:
        program = self._valid_program()
        artifact_path = self.root / "evaluation-result.json"
        artifact_path.write_text(
            artifact_path.read_text(encoding="utf-8") + " ", encoding="utf-8"
        )
        self._write_program(seal_program(program))
        tampered = verify_assurance_program(self.program_path)
        self.assertIn(
            "validation.evaluation_artifact_digest",
            {value["code"] for value in tampered["findings"]},
        )

        program = self._valid_program()
        evaluation = json.loads(artifact_path.read_text(encoding="utf-8"))
        evaluation["verifier"]["version"] = "forged-version"
        artifact_path.write_text(
            json.dumps(evaluation, indent=2) + "\n", encoding="utf-8"
        )
        cohort = program["validation_cohorts"][0]
        cohort["evaluation_result_artifact"]["sha256"] = hashlib.sha256(
            artifact_path.read_bytes()
        ).hexdigest()
        cohort["evaluation_result_sha256"] = canonical_json_sha256(evaluation)
        self._write_program(seal_program(program))
        forged = verify_assurance_program(self.program_path)
        self.assertIn(
            "validation.evaluation_artifact_claims",
            {value["code"] for value in forged["findings"]},
        )

    def test_evaluation_artifact_aggregate_limit_fails_closed(self) -> None:
        program = self._valid_program()
        self._write_program(program)
        with patch("pysfmea.program.MAX_TOTAL_EVALUATION_BYTES", 1):
            result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["validation"]["evaluation_artifact_bytes"], 0)
        self.assertIn(
            "validation.evaluation_artifact_rejected",
            {value["code"] for value in result["findings"]},
        )

    def test_reconciliation_preserves_distinct_recall_and_precision_numerators(
        self,
    ) -> None:
        program = self._valid_program()
        cohort = program["validation_cohorts"][0]
        cohort.update(
            {
                "recall": 0.9,
                "precision": 0.8,
                "matched_count": 90,
                "actual_matched_count": 80,
                "actual_count": 100,
            }
        )
        cohort.pop("evaluation_result_artifact")
        program["quality_gates"]["require_evaluation_result_artifacts"] = False
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertTrue(result["valid"], result["findings"])
        self.assertEqual(result["validation"]["micro_recall"], 0.9)
        self.assertEqual(result["validation"]["micro_precision"], 0.8)

    def test_micro_gate_weights_large_cohorts_by_observed_counts(self) -> None:
        program = self._valid_program()
        program["quality_gates"]["require_evaluation_result_artifacts"] = False
        program["validation_cohorts"].append(
            {
                "id": "COHORT-EXTERNAL-2",
                "repository": "large-independent-service",
                "framework": "Django",
                "corpus_sha256": "d" * 64,
                "case_count": 900,
                "recall": 0.5,
                "precision": 0.5,
                "matched_count": 450,
                "actual_matched_count": 450,
                "actual_count": 900,
                "evaluation_result_format": "pysfmea-evaluation-result-1",
                "evaluation_result_sha256": "e" * 64,
                "evaluation_verifier_version": "0.59.0",
                "independent_reviewed": True,
                "producer": "External benchmark team",
                "reviewer": "External safety authority",
            }
        )
        program["quality_gates"]["min_recall"] = 0.7
        program["quality_gates"]["min_precision"] = 0.7
        program["quality_gates"]["min_micro_recall"] = 0.6
        program["quality_gates"]["min_micro_precision"] = 0.6
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertEqual(result["validation"]["macro_recall"], 0.705)
        self.assertEqual(result["validation"]["micro_recall"], 0.541)
        codes = {value["code"] for value in result["findings"]}
        self.assertNotIn("validation.recall", codes)
        self.assertIn("validation.micro_recall", codes)
        self.assertIn("validation.micro_precision", codes)

    def test_llm_claim_rate_is_aggregated_by_claim_count(self) -> None:
        program = self._valid_program()
        program["quality_gates"]["require_llm_corpus_artifacts"] = False
        program["quality_gates"]["require_llm_subject_binding"] = False
        program["quality_gates"]["max_llm_unsupported_claim_rate"] = 0.1
        program["llm_evaluations"].append(
            {
                "id": "LLM-EVAL-2",
                "provider": "local",
                "model": "review-model-2",
                "prompt_version": "3",
                "sample_count": 10,
                "grounding": 1.0,
                "citation_accuracy": 1.0,
                "unsupported_claim_rate": 0.5,
                "grounded_sample_count": 10,
                "citation_correct_sample_count": 10,
                "claim_count": 900,
                "unsupported_claim_count": 450,
                "corpus_sha256": "d" * 64,
                "independent_reviewed": True,
                "producer": "Second model team",
                "reviewer": "Second assurance authority",
            }
        )
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertEqual(result["llm_quality"]["unsupported_claim_rate"], 0.45)
        self.assertEqual(result["llm_quality"]["claim_count"], 1_000)
        self.assertIn(
            "llm.unsupported_claim_rate",
            {value["code"] for value in result["findings"]},
        )

    def test_llm_corpus_artifact_bytes_and_claims_are_verified(self) -> None:
        program = self._valid_program()
        artifact_path = self.root / "llm-quality-corpus.json"
        artifact_path.write_text(
            artifact_path.read_text(encoding="utf-8") + " ", encoding="utf-8"
        )
        self._write_program(seal_program(program))
        tampered = verify_assurance_program(self.program_path)
        self.assertIn(
            "llm.corpus_artifact_digest",
            {value["code"] for value in tampered["findings"]},
        )

        program = self._valid_program()
        corpus = json.loads(artifact_path.read_text(encoding="utf-8"))
        corpus["samples"][0]["grounded"] = False
        artifact_path.write_text(json.dumps(corpus) + "\n", encoding="utf-8")
        evaluation = program["llm_evaluations"][0]
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        evaluation["corpus_sha256"] = digest
        evaluation["corpus_artifact"]["sha256"] = digest
        self._write_program(seal_program(program))
        forged = verify_assurance_program(self.program_path)
        self.assertIn(
            "llm.corpus_artifact_claims",
            {value["code"] for value in forged["findings"]},
        )

    def test_llm_corpus_aggregate_limit_fails_closed(self) -> None:
        program = self._valid_program()
        self._write_program(program)
        with patch("pysfmea.program.MAX_TOTAL_LLM_CORPUS_BYTES", 1):
            result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["llm_quality"]["corpus_artifact_bytes"], 0)
        self.assertIn(
            "llm.corpus_artifact_rejected",
            {value["code"] for value in result["findings"]},
        )

    def test_legacy_llm_corpus_is_replayable_but_not_subject_bound(self) -> None:
        program = self._valid_program()
        artifact_path = self.root / "llm-quality-corpus.json"
        corpus = json.loads(artifact_path.read_text(encoding="utf-8"))
        corpus["schema_version"] = "pysfmea-llm-quality-corpus-1"
        corpus.pop("subject")
        artifact_path.write_text(json.dumps(corpus) + "\n", encoding="utf-8")
        evaluation = program["llm_evaluations"][0]
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        evaluation["corpus_sha256"] = digest
        evaluation["corpus_artifact"]["sha256"] = digest
        evaluation["corpus_format"] = "pysfmea-llm-quality-corpus-1"
        evaluation["subject_bound"] = False
        evaluation.pop("evidence_fingerprint_sha256")
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertEqual(result["llm_quality"]["verified_corpus_artifacts"], 1)
        self.assertEqual(result["llm_quality"]["subject_bound_evaluations"], 0)
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("llm.subject_binding", codes)
        self.assertNotIn("llm.corpus_artifact_claims", codes)

    def test_legacy_cohort_remains_compatible_when_count_gate_is_disabled(self) -> None:
        program = self._valid_program()
        cohort = program["validation_cohorts"][0]
        for field in (
            "matched_count",
            "actual_matched_count",
            "actual_count",
            "evaluation_result_format",
            "evaluation_result_sha256",
            "evaluation_verifier_version",
            "evaluation_result_artifact",
            "call_matched_count",
            "call_actual_matched_count",
            "call_actual_count",
        ):
            cohort.pop(field)
        for field in (
            "require_count_backed_validation",
            "require_evaluation_result_artifacts",
            "min_micro_recall",
            "min_micro_precision",
            "min_micro_call_resolution_recall",
            "min_micro_call_resolution_precision",
        ):
            program["quality_gates"].pop(field)
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertTrue(result["valid"], result["findings"])
        self.assertEqual(result["validation"]["count_backed_cohorts"], 0)
        self.assertIsNone(result["validation"]["micro_recall"])

    def test_legacy_llm_record_remains_compatible_when_new_gates_are_disabled(
        self,
    ) -> None:
        program = self._valid_program()
        evaluation = program["llm_evaluations"][0]
        for field in (
            "grounded_sample_count",
            "citation_correct_sample_count",
            "claim_count",
            "unsupported_claim_count",
            "evidence_fingerprint_sha256",
            "corpus_artifact",
            "corpus_format",
            "subject_bound",
        ):
            evaluation.pop(field)
        program["quality_gates"].pop("require_llm_count_backing")
        program["quality_gates"].pop("require_llm_corpus_artifacts")
        program["quality_gates"].pop("require_llm_subject_binding")
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertTrue(result["valid"], result["findings"])
        self.assertEqual(
            result["llm_quality"]["aggregation_method"], "legacy-sample-weighted"
        )
        self.assertTrue(_program_verification_payload_contract(result))
        Draft202012Validator(
            schema_document("assurance-program-verification")
        ).validate(result)

    def test_evidence_digest_and_html_content_are_safe(self) -> None:
        program = self._valid_program()
        program["name"] = "<script>alert('program')</script>"
        program["external_evidence"][0]["artifact"]["sha256"] = "0" * 64
        self._write_program(seal_program(program))
        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        self.assertIn(
            "evidence.artifact_digest",
            {value["code"] for value in result["findings"]},
        )
        self.assertEqual(result["summary"]["trusted_evidence"], 0)
        self.assertEqual(result["relationships"][0]["temporal_status"], "unverified")
        self.assertEqual(result["relationships"][0]["resilience_status"], "unverified")
        self.assertIn(
            "relationship.temporal_evidence_missing",
            {value["code"] for value in result["findings"]},
        )
        html = program_verification_html(result)
        self.assertNotIn("<script>alert('program')</script>", html)
        self.assertIn("&lt;script&gt;", html)

        output = self.root / "program-report.html"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "program-verify",
                    str(self.program_path),
                    "--format",
                    "html",
                    "-o",
                    str(output),
                ]
            )
        self.assertEqual(exit_code, 1)
        self.assertTrue(
            output.read_text(encoding="utf-8").startswith("<!doctype html>")
        )

    def test_program_html_report_is_self_verifying_and_exactly_program_bound(
        self,
    ) -> None:
        self._write_program(self._valid_program())
        output = self.root / "program-report.html"
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main(
                [
                    "program-verify",
                    str(self.program_path),
                    "--format",
                    "html",
                    "-o",
                    str(output),
                ]
            )
        self.assertEqual(exit_code, 0)

        standalone = verify_program_report_file(output)
        self.assertTrue(standalone["valid"], standalone)
        self.assertTrue(_program_report_verification_contract(standalone))
        self.assertEqual(
            standalone["artifact_sha256"], hashlib.sha256(output.read_bytes()).hexdigest()
        )
        self.assertEqual(standalone["status"], "valid_binding_not_checked")
        self.assertTrue(standalone["assurance_valid"])
        self.assertIsNone(standalone["checks"]["program_content"])
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(standalone)

        matched = verify_program_report_file(
            output,
            program=self.program_path,
            expected_sha256=standalone["artifact_sha256"],
        )
        self.assertTrue(matched["valid"], matched)
        self.assertEqual(matched["status"], "matched")
        self.assertTrue(matched["artifact_binding_requested"])
        self.assertTrue(matched["artifact_binding_checked"])
        self.assertTrue(matched["checks"]["artifact_identity"])
        self.assertTrue(all(value is True for value in matched["checks"].values()))
        report_validator = Draft202012Validator(
            schema_document("assurance-program-report-verification")
        )
        report_validator.validate(matched)
        self.assertTrue(_program_report_verification_contract(matched))
        contradictions = []
        contradiction = copy.deepcopy(matched)
        contradiction["valid"] = False
        contradictions.append(contradiction)
        contradiction = copy.deepcopy(matched)
        contradiction["binding_checked"] = False
        contradictions.append(contradiction)
        contradiction = copy.deepcopy(matched)
        contradiction["current"].pop("verifier")
        contradictions.append(contradiction)
        contradiction = copy.deepcopy(standalone)
        contradiction["current"] = {"program_path": "unrequested.json"}
        contradictions.append(contradiction)
        contradiction = copy.deepcopy(matched)
        contradiction.pop("artifact_sha256")
        contradictions.append(contradiction)
        contradiction = copy.deepcopy(matched)
        contradiction["artifact_sha256"] = ""
        contradictions.append(contradiction)
        for contradiction in contradictions:
            self.assertFalse(report_validator.is_valid(contradiction))
            self.assertFalse(_program_report_verification_contract(contradiction))
        artifact_mismatch = verify_program_report_file(
            output,
            expected_sha256="0" * 64,
        )
        self.assertFalse(artifact_mismatch["valid"])
        self.assertEqual(artifact_mismatch["status"], "invalid")
        self.assertTrue(artifact_mismatch["artifact_binding_checked"])
        self.assertFalse(artifact_mismatch["checks"]["artifact_identity"])
        report_validator.validate(artifact_mismatch)
        self.assertTrue(_program_report_verification_contract(artifact_mismatch))
        relocated_program = self.root / "relocated" / "program.json"
        relocated_program.parent.mkdir()
        relocated_program.write_bytes(self.program_path.read_bytes())
        for analysis_path in self.analysis_paths:
            relocated_analysis = relocated_program.parent / analysis_path.relative_to(
                self.root
            )
            relocated_analysis.parent.mkdir(parents=True)
            relocated_analysis.write_bytes(analysis_path.read_bytes())
        for artifact in (
            "timing-evidence.json",
            "evaluation-result.json",
            "llm-quality-corpus.json",
        ):
            (relocated_program.parent / artifact).write_bytes(
                (self.root / artifact).read_bytes()
            )
        relocated = verify_program_report_file(output, program=relocated_program)
        self.assertTrue(relocated["valid"], relocated)
        self.assertEqual(relocated["status"], "matched")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    [
                        "program-report-verify",
                        str(output),
                        "--program",
                        str(self.program_path),
                    ]
                ),
                0,
            )
        self.assertIn("MATCHED", stdout.getvalue())
        self.assertIn("Exact program binding: matched", stdout.getvalue())

        receipt_path = self.root / "program-report-verification.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            receipt_exit = main(
                [
                    "program-report-verify",
                    str(output),
                    "--program",
                    str(self.program_path),
                    "--expect-sha256",
                    standalone["artifact_sha256"],
                    "--output",
                    str(receipt_path),
                ]
            )
        self.assertEqual(receipt_exit, 0)
        persisted_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertTrue(persisted_receipt["valid"])
        self.assertTrue(persisted_receipt["checks"]["artifact_identity"])
        report_validator.validate(persisted_receipt)
        self.assertIn("Exported assurance program report verification", stdout.getvalue())

        report_before_collision = output.read_bytes()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            collision_exit = main(
                [
                    "program-report-verify",
                    str(output),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(collision_exit, 2)
        self.assertIn("destination must differ", stderr.getvalue())
        self.assertEqual(output.read_bytes(), report_before_collision)

        program_before_collision = self.program_path.read_bytes()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            program_collision_exit = main(
                [
                    "program-report-verify",
                    str(output),
                    "--program",
                    str(self.program_path),
                    "--output",
                    str(self.program_path),
                ]
            )
        self.assertEqual(program_collision_exit, 2)
        self.assertEqual(self.program_path.read_bytes(), program_before_collision)

        receipt_path.write_text("prior receipt", encoding="utf-8")
        verified_result = verify_program_report_file(
            output, program=self.program_path
        )

        def replace_receipt_during_verification(*args: object, **kwargs: object) -> dict:
            receipt_path.write_text("concurrent receipt", encoding="utf-8")
            return verified_result

        stderr = io.StringIO()
        with patch(
            "pysfmea.cli.verify_program_report_file",
            side_effect=replace_receipt_during_verification,
        ), contextlib.redirect_stderr(stderr):
            race_exit = main(
                [
                    "program-report-verify",
                    str(output),
                    "--output",
                    str(receipt_path),
                ]
            )
        self.assertEqual(race_exit, 2)
        self.assertIn("destination changed", stderr.getvalue())
        self.assertEqual(
            receipt_path.read_text(encoding="utf-8"), "concurrent receipt"
        )
        self.assertFalse(
            list(self.root.glob(".program-report-verification.json.*.tmp"))
        )

        report_bytes = output.read_bytes()
        output.write_bytes(
            report_bytes.replace(
                b"Executive assurance state", b"Rewritten assurance state", 1
            )
        )
        tampered = verify_program_report_file(output, program=self.program_path)
        self.assertFalse(tampered["valid"])
        self.assertNotEqual(
            tampered["artifact_sha256"], standalone["artifact_sha256"]
        )
        self.assertEqual(
            tampered["artifact_sha256"], hashlib.sha256(output.read_bytes()).hexdigest()
        )
        self.assertEqual(tampered["status"], "invalid")
        self.assertFalse(tampered["checks"]["document_integrity"])
        self.assertTrue(tampered["checks"]["payload_integrity"])
        tampered_receipt = self.root / "tampered-program-report-verification.json"
        with contextlib.redirect_stdout(io.StringIO()):
            tampered_exit = main(
                [
                    "program-report-verify",
                    str(output),
                    "--output",
                    str(tampered_receipt),
                ]
            )
        self.assertEqual(tampered_exit, 1)
        persisted_tampered = json.loads(
            tampered_receipt.read_text(encoding="utf-8")
        )
        self.assertFalse(persisted_tampered["valid"])
        report_validator.validate(persisted_tampered)

        output.write_bytes(report_bytes)
        changed_program = self._valid_program()
        changed_program["purpose"] = "Changed after report generation."
        self._write_program(seal_program(changed_program))
        stale = verify_program_report_file(output, program=self.program_path)
        self.assertFalse(stale["valid"])
        self.assertEqual(stale["status"], "mismatched")
        self.assertFalse(stale["checks"]["program_content"])
        self.assertFalse(stale["checks"]["program_verification"])
        report_validator.validate(stale)

    def test_program_report_cli_and_unsafe_input_return_public_verdict(self) -> None:
        missing = self.root / "missing-report.html"
        rejected = verify_program_report_file(missing, program=self.program_path)
        self.assertFalse(rejected["valid"])
        self.assertEqual(rejected["artifact_sha256"], "")
        self.assertEqual(rejected["status"], "invalid")
        self.assertFalse(rejected["binding_checked"])
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(rejected)
        self.assertTrue(_program_report_verification_contract(rejected))
        pinned_missing = verify_program_report_file(
            missing, expected_sha256="0" * 64
        )
        self.assertTrue(pinned_missing["artifact_binding_requested"])
        self.assertFalse(pinned_missing["artifact_binding_checked"])
        self.assertIsNone(pinned_missing["checks"]["artifact_identity"])
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(pinned_missing)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "program-report-verify",
                    str(missing),
                    "--program",
                    str(self.program_path),
                    "--json",
                ]
            )
        self.assertEqual(exit_code, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload["format"],
            "pysfmea-assurance-program-report-verification-1",
        )

        self._write_program(self._valid_program())
        valid_report = self.root / "pinned-report.html"
        valid_report.write_bytes(
            program_verification_html(
                verify_assurance_program(self.program_path)
            ).encode("utf-8")
        )
        expected_digest = hashlib.sha256(valid_report.read_bytes()).hexdigest()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            pinned_exit = main(
                [
                    "program-report-verify",
                    str(valid_report),
                    "--expect-sha256",
                    expected_digest,
                    "--json",
                ]
            )
        pinned = json.loads(stdout.getvalue())
        self.assertEqual(pinned_exit, 0)
        self.assertTrue(pinned["checks"]["artifact_identity"])
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(pinned)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            mismatch_exit = main(
                [
                    "program-report-verify",
                    str(valid_report),
                    "--expect-sha256",
                    "0" * 64,
                    "--json",
                ]
            )
        mismatch = json.loads(stdout.getvalue())
        self.assertEqual(mismatch_exit, 1)
        self.assertFalse(mismatch["valid"])
        self.assertFalse(mismatch["checks"]["artifact_identity"])
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(mismatch)

        malformed_pin = verify_program_report_file(
            valid_report, expected_sha256="not-a-digest"
        )
        self.assertFalse(malformed_pin["valid"])
        self.assertTrue(malformed_pin["artifact_binding_requested"])
        self.assertFalse(malformed_pin["artifact_binding_checked"])
        self.assertIsNone(malformed_pin["checks"]["artifact_identity"])
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(malformed_pin)

        invalid_utf8 = self.root / "invalid-report.html"
        invalid_utf8.write_bytes(b"\xff")
        invalid_encoding = verify_program_report_file(invalid_utf8)
        self.assertFalse(invalid_encoding["valid"])
        self.assertIn("UTF-8", invalid_encoding["errors"][0]["message"])
        self.assertEqual(invalid_encoding["bytes"], 1)
        self.assertEqual(
            invalid_encoding["artifact_sha256"], hashlib.sha256(b"\xff").hexdigest()
        )
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(invalid_encoding)

        self._write_program(self._valid_program())
        result = verify_assurance_program(self.program_path)
        report = program_verification_html(result)
        format_meta = (
            '<meta name="pysfmea-program-report-format" '
            'content="pysfmea-assurance-program-report-1">'
        )
        duplicate_metadata = self.root / "duplicate-metadata.html"
        duplicate_metadata.write_text(
            report.replace(format_meta, format_meta + format_meta, 1),
            encoding="utf-8",
        )
        duplicate = verify_program_report_file(duplicate_metadata)
        self.assertFalse(duplicate["valid"])
        self.assertFalse(duplicate["checks"]["metadata_unique"])

        payload_start = report.index(
            '<script id="program-verification-data" type="application/json">'
        ) + len('<script id="program-verification-data" type="application/json">')
        payload_end = report.index("</script>", payload_start)
        malformed_payload = self.root / "malformed-payload.html"
        malformed_payload.write_text(
            report[:payload_start] + "{" + report[payload_end:],
            encoding="utf-8",
        )
        malformed = verify_program_report_file(malformed_payload)
        self.assertFalse(malformed["valid"])
        self.assertFalse(malformed["checks"]["payload_json"])
        self.assertFalse(malformed["checks"]["payload_contract"])
        self.assertIsNone(malformed["assurance_valid"])

    def test_program_report_rejects_self_consistent_semantic_contradictions(
        self,
    ) -> None:
        self._write_program(self._valid_program())
        result = verify_assurance_program(self.program_path)
        self.assertTrue(result["valid"], result["findings"])

        def unexplained_failed_check(value: dict[str, object]) -> None:
            value["checks"]["validation"] = False
            value["valid"] = False

        def moved_error_namespace(value: dict[str, object]) -> None:
            value["checks"]["relationships"] = False
            value["valid"] = False
            value["counts"]["errors"] = 1
            value["findings"].append(
                {
                    "code": "validation.forged_failure",
                    "level": "error",
                    "message": "A validation error cannot explain relationship failure.",
                    "location": "validation_cohorts",
                }
            )

        def misplaced_deadline_finding(value: dict[str, object]) -> None:
            relationship = value["relationships"][0]
            relationship["temporal_status"] = "violated"
            relationship["observed_max_ms"] = relationship["deadline_ms"] + 1
            value["checks"]["relationships"] = False
            value["valid"] = False
            value["counts"]["errors"] = 1
            value["findings"].append(
                {
                    "code": "relationship.deadline_violated",
                    "level": "error",
                    "message": "The finding is attached to the wrong relationship.",
                    "location": "relationships.UNRELATED",
                }
            )

        def invented_finding_namespace(value: dict[str, object]) -> None:
            value["valid"] = False
            value["counts"]["errors"] = 1
            value["findings"].append(
                {
                    "code": "forged.failure",
                    "level": "error",
                    "message": "An invented producer namespace is not trustworthy.",
                    "location": "forged",
                }
            )

        def hidden_timing_overrun(value: dict[str, object]) -> None:
            relationship = value["relationships"][0]
            relationship["temporal_status"] = "unverified"
            relationship["observed_max_ms"] = relationship["deadline_ms"] + 1
            value["checks"]["relationships"] = False
            value["valid"] = False
            value["counts"]["errors"] = 1
            value["findings"].append(
                {
                    "code": "relationship.temporal_evidence_missing",
                    "level": "error",
                    "message": "An observed overrun cannot remain unverified.",
                    "location": f"relationships.{relationship['id']}",
                }
            )

        def impossible_validation_population(value: dict[str, object]) -> None:
            value["validation"]["cases"] = 0

        def relabeled_llm_aggregation(value: dict[str, object]) -> None:
            value["llm_quality"]["aggregation_method"] = "legacy-sample-weighted"
            value["llm_quality"]["claim_count"] = None
            value["llm_quality"]["unsupported_claim_count"] = None

        def forged_llm_claim_rate(value: dict[str, object]) -> None:
            current = value["llm_quality"]["unsupported_claim_rate"]
            value["llm_quality"]["unsupported_claim_rate"] = (
                0.5 if current != 0.5 else 0.25
            )

        mutations = (
            unexplained_failed_check,
            moved_error_namespace,
            misplaced_deadline_finding,
            invented_finding_namespace,
            hidden_timing_overrun,
            impossible_validation_population,
            relabeled_llm_aggregation,
            forged_llm_claim_rate,
            lambda value: value["checks"].update({"invented_check": True}),
            lambda value: value["summary"].update(
                {"relationships": value["summary"]["relationships"] + 1}
            ),
            lambda value: value["summary"].update(
                {"conflicting_program_roles": ["forged"]}
            ),
            lambda value: value["summary"].update(
                {
                    "bound_repositories": value["summary"]["bound_repositories"]
                    - 1
                }
            ),
            lambda value: value["summary"].update(
                {"evidence_statuses": {"not_run": 1}}
            ),
            lambda value: value["summary"].update({"duplicate_evidence": 1}),
            lambda value: value["summary"].update(
                {
                    "validated_approvals": value["summary"][
                        "validated_approvals"
                    ]
                    - 1
                }
            ),
            lambda value: value["relationships"][0].update(
                {"unexpected_projection": True}
            ),
            lambda value: value["relationships"][0].update(
                {"observed_max_ms": None}
            ),
            lambda value: value["relationships"][0].update(
                {"temporal_status": "violated"}
            ),
            lambda value: value["relationships"][0].update(
                {"observed_recovery_ms": None}
            ),
            lambda value: value["relationships"][0].update(
                {"endpoints_valid": False}
            ),
            lambda value: value["validation"].update(
                {"credited_cohorts": value["validation"]["cohorts"] + 1}
            ),
            lambda value: value["llm_quality"].update(
                {
                    "unsupported_claim_count": value["llm_quality"]["claim_count"]
                    + 1
                }
            ),
            lambda value: value["program"].update({"content_sha256": ""}),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                contradictory = copy.deepcopy(result)
                mutation(contradictory)
                report = self.root / f"self-consistent-contradiction-{index}.html"
                with patch(
                    "pysfmea.program._program_verification_payload_contract",
                    return_value=True,
                ):
                    forged_html = program_verification_html(contradictory)
                report.write_bytes(forged_html.encode("utf-8"))

                verdict = verify_program_report_file(report)

                self.assertFalse(verdict["valid"])
                self.assertFalse(verdict["checks"]["payload_contract"])
                self.assertTrue(verdict["checks"]["payload_integrity"])
                self.assertTrue(
                    verdict["checks"]["verification_result_integrity"]
                )
                self.assertTrue(verdict["checks"]["document_integrity"])

        program_schema = Draft202012Validator(
            schema_document("assurance-program-verification")
        )
        for field in ("observed_max_ms", "observed_recovery_ms"):
            with self.subTest(schema_field=field):
                contradictory = copy.deepcopy(result)
                contradictory["relationships"][0][field] = None
                self.assertFalse(program_schema.is_valid(contradictory))
        missing_evidence = copy.deepcopy(result)
        missing_evidence["relationships"][0]["evidence_ids"] = []
        self.assertFalse(program_schema.is_valid(missing_evidence))

    def test_program_report_accepts_closed_early_rejection_payload(self) -> None:
        rejected_program = self.root / "invalid-root-program.json"
        rejected_program.write_text("[]\n", encoding="utf-8")
        result = verify_assurance_program(rejected_program)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checks"], {"input": True, "format": False})
        report = self.root / "invalid-root-program-report.html"
        report.write_bytes(program_verification_html(result).encode("utf-8"))

        verdict = verify_program_report_file(report)

        self.assertTrue(verdict["valid"], verdict)
        self.assertFalse(verdict["assurance_valid"])
        self.assertTrue(verdict["checks"]["payload_contract"])
        Draft202012Validator(
            schema_document("assurance-program-verification")
        ).validate(result)

        invalid_program = self._valid_program()
        invalid_program["external_evidence"][0]["artifact"]["sha256"] = "0" * 64
        self._write_program(invalid_program)
        full_result = verify_assurance_program(self.program_path)
        self.assertFalse(full_result["valid"])
        report.write_bytes(program_verification_html(full_result).encode("utf-8"))

        full_verdict = verify_program_report_file(report)

        self.assertTrue(full_verdict["valid"], full_verdict)
        self.assertFalse(full_verdict["assurance_valid"])
        self.assertTrue(full_verdict["checks"]["payload_contract"])
        Draft202012Validator(
            schema_document("assurance-program-verification")
        ).validate(full_result)

    def test_program_report_publication_json_is_schema_backed_and_assurance_aware(
        self,
    ) -> None:
        self._write_program(self._valid_program())
        output = self.root / "published-program-report.html"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "program-verify",
                    str(self.program_path),
                    "--format",
                    "html",
                    "--output",
                    str(output),
                    "--publication-json",
                ]
            )
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(receipt["valid"])
        self.assertEqual(
            receipt["artifact_sha256"], hashlib.sha256(output.read_bytes()).hexdigest()
        )
        self.assertTrue(receipt["assurance_valid"])
        self.assertEqual(receipt["status"], "matched")
        self.assertEqual(
            receipt["publication"],
            {
                "status": "published",
                "phase": "complete",
                "destination_existed": False,
                "prior_destination_preserved": False,
            },
        )
        validator = Draft202012Validator(
            schema_document("assurance-program-report-verification")
        )
        validator.validate(receipt)
        self.assertTrue(_program_report_verification_contract(receipt))
        contradiction = copy.deepcopy(receipt)
        contradiction["publication"]["status"] = "not_published"
        contradiction["publication"]["phase"] = "publication"
        contradiction["publication"]["prior_destination_preserved"] = False
        self.assertFalse(validator.is_valid(contradiction))
        self.assertFalse(_program_report_verification_contract(contradiction))

        program = self._valid_program()
        program["external_evidence"][0]["artifact"]["sha256"] = "0" * 64
        self._write_program(seal_program(program))
        not_ready_output = self.root / "not-ready-program-report.html"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "program-verify",
                    str(self.program_path),
                    "--format",
                    "html",
                    "--output",
                    str(not_ready_output),
                    "--publication-json",
                ]
            )
        not_ready = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertTrue(not_ready["valid"])
        self.assertFalse(not_ready["assurance_valid"])
        self.assertEqual(not_ready["publication"]["status"], "published")
        validator.validate(not_ready)
        self.assertTrue(_program_report_verification_contract(not_ready))

    def test_program_report_publication_json_preserves_prior_on_failure(self) -> None:
        self._write_program(self._valid_program())
        output = self.root / "preserved-program-report.html"
        output.write_text("trusted prior report", encoding="utf-8")
        stdout = io.StringIO()
        with patch(
            "pysfmea.program.program_verification_html",
            side_effect=RuntimeError("renderer detail must not escape"),
        ), contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    "program-verify",
                    str(self.program_path),
                    "--format",
                    "html",
                    "--output",
                    str(output),
                    "--publication-json",
                ]
            )
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertFalse(receipt["valid"])
        self.assertEqual(receipt["publication"]["status"], "not_published")
        self.assertEqual(receipt["publication"]["phase"], "generation")
        self.assertTrue(receipt["publication"]["destination_existed"])
        self.assertTrue(receipt["publication"]["prior_destination_preserved"])
        self.assertNotIn("renderer detail", stdout.getvalue())
        self.assertEqual(output.read_text(encoding="utf-8"), "trusted prior report")
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(receipt)
        self.assertTrue(_program_report_verification_contract(receipt))

        original_program = self.program_path.read_bytes()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            collision_exit = main(
                [
                    "program-verify",
                    str(self.program_path),
                    "--format",
                    "html",
                    "--output",
                    str(self.program_path),
                    "--publication-json",
                ]
            )
        collision = json.loads(stdout.getvalue())
        self.assertEqual(collision_exit, 2)
        self.assertEqual(collision["publication"]["phase"], "input_validation")
        self.assertTrue(collision["publication"]["prior_destination_preserved"])
        self.assertEqual(self.program_path.read_bytes(), original_program)
        Draft202012Validator(
            schema_document("assurance-program-report-verification")
        ).validate(collision)
        self.assertTrue(_program_report_verification_contract(collision))

        result = verify_assurance_program(self.program_path)
        report = program_verification_html(result)
        payload_start = report.index(
            '<script id="program-verification-data" type="application/json">'
        ) + len('<script id="program-verification-data" type="application/json">')
        payload_end = report.index("</script>", payload_start)
        empty_payload = self.root / "empty-payload.html"
        empty_payload.write_text(
            report[:payload_start] + "{}" + report[payload_end:],
            encoding="utf-8",
        )
        empty = verify_program_report_file(empty_payload)
        self.assertFalse(empty["valid"])
        self.assertTrue(empty["checks"]["payload_json"])
        self.assertFalse(empty["checks"]["payload_contract"])
        self.assertFalse(empty["checks"]["payload_binding"])
        self.assertFalse(empty["assurance_valid"])

        document_meta_start = report.index(
            '<meta name="pysfmea-program-report-document-sha256"'
        )
        document_meta_end = report.index("\n", document_meta_start) + 1
        missing_document_metadata = self.root / "missing-document-metadata.html"
        missing_document_metadata.write_text(
            report[:document_meta_start] + report[document_meta_end:],
            encoding="utf-8",
        )
        missing_metadata = verify_program_report_file(missing_document_metadata)
        self.assertFalse(missing_metadata["valid"])
        self.assertFalse(missing_metadata["checks"]["metadata_complete"])
        self.assertFalse(missing_metadata["checks"]["metadata_unique"])
        self.assertFalse(missing_metadata["checks"]["document_integrity"])

        payload_block = report[
            report.rfind("<script", 0, payload_start) : payload_end + len("</script>")
        ]
        duplicate_payload = self.root / "duplicate-payload.html"
        duplicate_payload.write_text(
            report[:payload_end]
            + "</script>"
            + payload_block
            + report[payload_end + len("</script>") :],
            encoding="utf-8",
        )
        repeated = verify_program_report_file(duplicate_payload)
        self.assertFalse(repeated["valid"])
        self.assertFalse(repeated["checks"]["payload_present"])
        self.assertFalse(repeated["checks"]["payload_json"])

    def test_program_report_payload_contract_rejects_each_wrong_top_level_type(
        self,
    ) -> None:
        self._write_program(self._valid_program())
        result = verify_assurance_program(self.program_path)
        self.assertTrue(_program_verification_payload_contract(result))
        replacements = {
            "format": "wrong-format",
            "verifier": [],
            "program": [],
            "valid": 1,
            "checks": [],
            "counts": [],
            "summary": [],
            "relationships": {},
            "validation": [],
            "llm_quality": [],
            "findings": {},
            "notice": [],
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                candidate = copy.deepcopy(result)
                candidate[field] = replacement
                self.assertFalse(_program_verification_payload_contract(candidate))

        nested_mutations: list[tuple[str, object]] = []
        candidate = copy.deepcopy(result)
        candidate["verifier"]["unexpected"] = True
        nested_mutations.append(("verifier fields", candidate))
        candidate = copy.deepcopy(result)
        candidate["program"]["content_sha256"] = "A" * 64
        nested_mutations.append(("program digest", candidate))
        candidate = copy.deepcopy(result)
        candidate["checks"]["integrity"] = "passed"
        nested_mutations.append(("check state", candidate))
        candidate = copy.deepcopy(result)
        candidate["counts"]["errors"] = True
        nested_mutations.append(("boolean count", candidate))
        candidate = copy.deepcopy(result)
        candidate["relationships"] = ["not an object"]
        nested_mutations.append(("relationship record", candidate))
        candidate = copy.deepcopy(result)
        candidate["findings"].append(
            {
                "code": "invalid.finding",
                "level": "critical",
                "message": "Invalid level.",
                "location": "program",
            }
        )
        nested_mutations.append(("finding record", candidate))
        candidate = copy.deepcopy(result)
        candidate["counts"]["warnings"] += 1
        nested_mutations.append(("finding count reconciliation", candidate))
        candidate = copy.deepcopy(result)
        candidate["valid"] = not candidate["valid"]
        nested_mutations.append(("validity reconciliation", candidate))
        candidate = copy.deepcopy(result)
        candidate["notice"] = ""
        nested_mutations.append(("empty notice", candidate))
        for label, candidate in nested_mutations:
            with self.subTest(label=label):
                self.assertFalse(_program_verification_payload_contract(candidate))

        contradictory_result = copy.deepcopy(result)
        contradictory_result["summary"]["relationships"] += 1
        for renderer in (program_verification_markdown, program_verification_html):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaisesRegex(ValueError, "closed contract"):
                    renderer(contradictory_result)
        for output_format, suffix in (
            ("json", ".json"),
            ("markdown", ".md"),
            ("html", ".html"),
        ):
            with self.subTest(output_format=output_format):
                destination = self.root / f"preserved-invalid-verdict{suffix}"
                destination.write_text("trusted prior", encoding="utf-8")
                expected_error = (
                    ProgramReportPublicationError
                    if output_format == "html"
                    else ValueError
                )
                with self.assertRaisesRegex(expected_error, "closed contract") as raised:
                    export_program_verification(
                        contradictory_result,
                        destination,
                        format=output_format,
                    )
                if output_format == "html":
                    self.assertEqual(raised.exception.phase, "input_validation")
                self.assertEqual(
                    destination.read_text(encoding="utf-8"), "trusted prior"
                )
                self.assertFalse(
                    list(self.root.glob(f".{destination.name}.*.tmp"))
                )

        json_output = export_program_verification(
            result, self.root / "program-verification.json", format="json"
        )
        markdown_output = export_program_verification(
            result, self.root / "program-verification.md", format="markdown"
        )
        self.assertEqual(
            json.loads(json_output.read_text(encoding="utf-8")), result
        )
        self.assertIn(
            "# System assurance program verification",
            markdown_output.read_text(encoding="utf-8"),
        )
        substituted_program_verdict = self.root / "substituted-program-verdict.json"
        substituted_program_verdict.write_text(
            "trusted prior verdict", encoding="utf-8"
        )
        with patch(
            "pysfmea.program.load_bounded_json_document",
            return_value=BoundedJsonDocument(
                path=substituted_program_verdict,
                value={"format": "substituted-program-verdict"},
                raw=b"{}",
            ),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "staged assurance program verification verification failed",
            ):
                export_program_verification(
                    result, substituted_program_verdict, format="json"
                )
        self.assertEqual(
            substituted_program_verdict.read_text(encoding="utf-8"),
            "trusted prior verdict",
        )
        self.assertFalse(
            list(self.root.glob(".substituted-program-verdict.json.*.tmp"))
        )
        receipt_source = self.root / "receipt-source-program-report.html"
        receipt_source.write_bytes(program_verification_html(result).encode("utf-8"))
        report_receipt = verify_program_report_file(receipt_source)
        self.assertTrue(_program_report_verification_contract(report_receipt))
        malformed_contract_receipt = self.root / "malformed-contract-receipt.json"
        malformed_contract_receipt.write_text(
            "trusted prior receipt", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "violates its closed contract"):
            export_program_report_verification(result, malformed_contract_receipt)
        self.assertEqual(
            malformed_contract_receipt.read_text(encoding="utf-8"),
            "trusted prior receipt",
        )
        self.assertFalse(
            list(self.root.glob(".malformed-contract-receipt.json.*.tmp"))
        )
        bounded_receipt = self.root / "bounded-program-report-receipt.json"
        bounded_receipt.write_text("trusted prior receipt", encoding="utf-8")
        with patch("pysfmea.program.MAX_PROGRAM_REPORT_VERIFICATION_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds the 1-byte"):
                export_program_report_verification(report_receipt, bounded_receipt)
        self.assertEqual(
            bounded_receipt.read_text(encoding="utf-8"), "trusted prior receipt"
        )
        substituted_receipt = self.root / "substituted-program-report-receipt.json"
        substituted_receipt.write_text("trusted prior receipt", encoding="utf-8")
        with patch(
            "pysfmea.program.load_bounded_json_document",
            return_value=BoundedJsonDocument(
                path=substituted_receipt,
                value={"format": "substituted-staged-receipt"},
                raw=b"{}",
            ),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "staged assurance program report verification receipt verification failed",
            ):
                export_program_report_verification(report_receipt, substituted_receipt)
        self.assertEqual(
            substituted_receipt.read_text(encoding="utf-8"),
            "trusted prior receipt",
        )
        self.assertFalse(
            list(self.root.glob(".substituted-program-report-receipt.json.*.tmp"))
        )

        non_finite_receipt = self.root / "non-finite-program-report-receipt.json"
        non_finite_receipt.write_text("trusted prior receipt", encoding="utf-8")
        non_finite_result = copy.deepcopy(report_receipt)
        non_finite_result["unexpected_metric"] = float("nan")
        with self.assertRaisesRegex(
            ValueError,
            "violates its closed contract",
        ):
            export_program_report_verification(
                non_finite_result, non_finite_receipt
            )
        self.assertEqual(
            non_finite_receipt.read_text(encoding="utf-8"),
            "trusted prior receipt",
        )
        self.assertFalse(
            list(self.root.glob(".non-finite-program-report-receipt.json.*.tmp"))
        )
        with self.assertRaisesRegex(ValueError, "must be json, markdown, or html"):
            export_program_verification(
                result, self.root / "program-verification.txt", format="text"
            )
        original_program = self.program_path.read_bytes()
        with self.assertRaisesRegex(
            ProgramReportPublicationError,
            "destination must differ from the assurance program file",
        ) as collision:
            export_program_verification(result, self.program_path, format="html")
        self.assertEqual(collision.exception.phase, "input_validation")
        self.assertEqual(self.program_path.read_bytes(), original_program)

        preserved_report = self.root / "preserved-program-report.html"
        preserved_report.write_text("trusted prior report", encoding="utf-8")
        with patch(
            "pysfmea.program.verify_program_report_file",
            return_value={"valid": False},
        ):
            with self.assertRaisesRegex(
                ValueError, "staged assurance program report verification failed"
            ):
                export_program_verification(
                    result, preserved_report, format="html"
                )
        self.assertEqual(
            preserved_report.read_text(encoding="utf-8"), "trusted prior report"
        )
        self.assertFalse(
            list(self.root.glob(".preserved-program-report.html.*.tmp"))
        )

        substituted_report = self.root / "substituted-program-report.html"
        substituted_report.write_text("trusted prior report", encoding="utf-8")
        altered_result = copy.deepcopy(result)
        altered_result["notice"] = "Internally valid but not the requested verdict."
        altered_html = program_verification_html(altered_result)
        altered_standalone = self.root / "altered-standalone.html"
        altered_standalone.write_bytes(altered_html.encode("utf-8"))
        self.assertTrue(verify_program_report_file(altered_standalone)["valid"])
        with patch(
            "pysfmea.program.program_verification_html",
            return_value=altered_html,
        ):
            with self.assertRaisesRegex(
                ValueError, "staged assurance program report verification failed"
            ):
                export_program_verification(
                    result, substituted_report, format="html"
                )
        self.assertEqual(
            substituted_report.read_text(encoding="utf-8"),
            "trusted prior report",
        )
        self.assertFalse(
            list(self.root.glob(".substituted-program-report.html.*.tmp"))
        )

    def test_unrun_or_failed_evidence_cannot_support_timing_or_resilience(self) -> None:
        program = self._valid_program()
        program["external_evidence"][0]["status"] = "not_run"
        self._write_program(seal_program(program))

        unrun = verify_assurance_program(self.program_path)
        self.assertFalse(unrun["valid"])
        self.assertEqual(unrun["summary"]["trusted_evidence"], 0)
        self.assertEqual(unrun["relationships"][0]["temporal_status"], "unverified")
        self.assertIn(
            "evidence.incomplete",
            {value["code"] for value in unrun["findings"]},
        )

        program = self._valid_program()
        program["external_evidence"][0]["status"] = "failed"
        self._write_program(seal_program(program))
        failed = verify_assurance_program(self.program_path)
        self.assertFalse(failed["valid"])
        self.assertIn(
            "evidence.failed", {value["code"] for value in failed["findings"]}
        )

    def test_duplicate_external_evidence_claims_are_verified_but_not_credited(self) -> None:
        program = self._valid_program()
        duplicate = copy.deepcopy(program["external_evidence"][0])
        duplicate["id"] = "EVID-TIMING-DUPLICATE"
        program["external_evidence"].append(duplicate)
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)

        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["external_evidence"])
        self.assertIn(
            "evidence.duplicate_claim",
            {finding["code"] for finding in result["findings"]},
        )
        self.assertEqual(result["summary"]["external_evidence"], 2)
        self.assertEqual(result["summary"]["verified_evidence"], 2)
        self.assertEqual(result["summary"]["trusted_evidence"], 1)
        self.assertEqual(result["summary"]["duplicate_evidence"], 1)
        self.assertEqual(
            result["relationships"][0]["evidence_ids"], ["EVID-TIMING-001"]
        )
        self.assertTrue(_program_verification_payload_contract(result))
        Draft202012Validator(
            schema_document("assurance-program-verification")
        ).validate(result)

    def test_circuit_breaker_violation_and_unrelated_role_approval_are_blocked(
        self,
    ) -> None:
        program = self._valid_program()
        program["external_evidence"][0]["metrics"]["half_open_recovered"] = False
        program["external_evidence"][0]["metrics"]["recovery_time_ms"] = 2_500
        program["governance"]["approvals"][1]["subject_kind"] = "evidence"
        program["governance"]["approvals"][1]["subject_id"] = "EVID-TIMING-001"
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["relationships"][0]["resilience_status"], "violated")
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("relationship.circuit_breaker_violated", codes)
        self.assertIn("governance.roles", codes)

    def test_identity_timestamp_boolean_and_closed_nested_contracts_fail_closed(
        self,
    ) -> None:
        program = self._valid_program()
        program["created_at"] = "2026-08-05"
        program["purpose"] = "assurance\u202eprogram"
        program["quality_gates"]["require_temporal_evidence"] = "yes"
        program["validation_cohorts"][0]["reviewer"] = "Benchmark team"
        program["llm_evaluations"][0]["reviewer"] = "Model evaluation team"
        program["governance"]["approvals"][1]["reviewer"] = "Software authority"
        program["governance"]["approvals"][1]["unexpected"] = True
        program["governance"]["approvals"].append(
            {
                "subject_kind": "program",
                "subject_id": "Checkout assurance program",
                "reviewer": "Software dissent authority",
                "role": "software",
                "decision": "rejected",
                "at": "2026-08-05T01:10:00+00:00",
            }
        )
        program["external_evidence"][0]["unexpected"] = True
        self._write_program(seal_program(program))

        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["valid"])
        codes = {value["code"] for value in result["findings"]}
        self.assertIn("program.timestamp", codes)
        self.assertIn("program.metadata", codes)
        self.assertIn("program.boolean_value", codes)
        self.assertIn("validation.independence_identity", codes)
        self.assertIn("llm.independence_identity", codes)
        self.assertIn("governance.roles", codes)
        self.assertNotIn("governance.role_independence", codes)
        self.assertIn("governance.role_decision_conflict", codes)
        self.assertIn("governance.program_approval", codes)
        self.assertNotIn("governance.program_rejected", codes)
        self.assertIn("governance.approval_unknown_fields", codes)
        self.assertEqual(result["summary"]["approvals"], 3)
        self.assertEqual(result["summary"]["validated_approvals"], 2)
        self.assertEqual(result["summary"]["credited_program_approvals"], 0)
        self.assertEqual(result["summary"]["approved_roles"], [])
        self.assertEqual(result["summary"]["conflicting_program_roles"], ["software"])
        self.assertIn("evidence.unknown_fields", codes)
        self.assertEqual(result["summary"]["trusted_evidence"], 0)
        self.assertEqual(result["relationships"][0]["temporal_status"], "unverified")

    def test_invalid_approval_records_receive_no_governance_credit(self) -> None:
        mutations = (
            (lambda approval: approval.update({"reviewer": ""}), "governance.approval_identity"),
            (lambda approval: approval.update({"role": "software authority"}), "governance.approval_identity"),
            (lambda approval: approval.update({"at": "2026-08-05"}), "governance.approval_timestamp"),
            (lambda approval: approval.update({"at": "2026-08-04T23:59:59+00:00"}), "governance.approval_predates_program"),
            (lambda approval: approval.update({"unexpected": True}), "governance.approval_unknown_fields"),
            (lambda approval: approval.update({"subject_id": "unknown"}), "governance.unknown_subject"),
        )
        for index, (mutation, expected_code) in enumerate(mutations):
            with self.subTest(index=index, expected_code=expected_code):
                program = self._valid_program()
                mutation(program["governance"]["approvals"][0])
                self._write_program(seal_program(program))

                result = verify_assurance_program(self.program_path)

                self.assertFalse(result["valid"])
                self.assertIn(
                    expected_code,
                    {finding["code"] for finding in result["findings"]},
                )
                self.assertEqual(result["summary"]["approvals"], 2)
                self.assertEqual(result["summary"]["validated_approvals"], 1)
                self.assertEqual(result["summary"]["credited_program_approvals"], 1)
                self.assertEqual(result["summary"]["approved_roles"], ["safety"])
                self.assertTrue(result["summary"]["program_approval"])
                self.assertTrue(_program_verification_payload_contract(result))

    def test_required_approval_roles_are_bounded_identifiers_and_unique(self) -> None:
        mutations = (
            lambda roles: roles.append(""),
            lambda roles: roles.append("software assurance"),
            lambda roles: roles.append("SOFTWARE"),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                program = self._valid_program()
                mutation(program["governance"]["required_roles"])
                self._write_program(seal_program(program))

                result = verify_assurance_program(self.program_path)

                self.assertFalse(result["valid"])
                self.assertIn(
                    "governance.required_roles",
                    {finding["code"] for finding in result["findings"]},
                )
                self.assertEqual(result["summary"]["required_roles"], ["safety", "software"])
                self.assertTrue(_program_verification_payload_contract(result))

    def test_finding_references_are_repository_qualified(self) -> None:
        program = self._valid_program()
        finding_id = self.analyses[0]["items"][0]["id"]
        qualified = f"orders:{finding_id}"
        requirement = program["requirements_sources"][0]["requirements"][0]
        requirement["finding_ids"] = [qualified]
        program["requirements_sources"][0]["content_sha256"] = canonical_json_sha256(
            program["requirements_sources"][0]["requirements"]
        )
        program["external_evidence"][0]["finding_ids"] = [qualified]
        self._write_program(seal_program(program))
        qualified_result = verify_assurance_program(self.program_path)
        self.assertTrue(qualified_result["valid"], qualified_result["findings"])

        requirement["finding_ids"] = [finding_id]
        program["requirements_sources"][0]["content_sha256"] = canonical_json_sha256(
            program["requirements_sources"][0]["requirements"]
        )
        program["external_evidence"][0]["finding_ids"] = [finding_id]
        self._write_program(seal_program(program))
        unqualified_result = verify_assurance_program(self.program_path)
        codes = {value["code"] for value in unqualified_result["findings"]}
        self.assertIn("requirements.unknown_finding", codes)
        self.assertIn("evidence.unknown_finding", codes)

    def test_markdown_escapes_relationship_table_delimiters(self) -> None:
        program = self._valid_program()
        program["relationships"][0]["id"] = "REL|PIPE"
        program["external_evidence"][0]["relationship_ids"] = ["REL|PIPE"]
        self._write_program(seal_program(program))
        result = verify_assurance_program(self.program_path)
        self.assertTrue(result["valid"], result["findings"])
        self.assertIn("REL\\|PIPE", program_verification_markdown(result))

    def test_aggregate_rejected_artifact_is_not_reused_from_cache(self) -> None:
        program = self._valid_program()
        duplicate = json.loads(json.dumps(program["external_evidence"][0]))
        duplicate["id"] = "EVID-TIMING-002"
        program["external_evidence"].append(duplicate)
        self._write_program(seal_program(program))

        with patch("pysfmea.program.MAX_TOTAL_EVIDENCE_BYTES", 1):
            result = verify_assurance_program(self.program_path)

        self.assertFalse(result["valid"])
        self.assertEqual(result["summary"]["trusted_evidence"], 0)
        self.assertEqual(result["summary"]["evidence_bytes"], 0)
        rejected = [
            value
            for value in result["findings"]
            if value["code"] == "evidence.artifact_rejected"
        ]
        self.assertEqual(len(rejected), 2)

    def test_integrity_and_cli_lifecycle(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            created = main(
                [
                    "program-init",
                    "--analysis",
                    f"orders={self.analysis_paths[0]}",
                    "-o",
                    str(self.program_path),
                ]
            )
        self.assertEqual(created, 0)
        program = json.loads(self.program_path.read_text(encoding="utf-8"))
        program["purpose"] = "Intentional edit requiring resealing."
        self._write_program(program)
        result = verify_assurance_program(self.program_path)
        self.assertFalse(result["checks"]["integrity"])
        seal_program_file(self.program_path)
        resealed = verify_assurance_program(self.program_path)
        self.assertTrue(resealed["checks"]["integrity"])

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                ["program-verify", str(self.program_path), "--format", "json"]
            )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["format"], "pysfmea-assurance-program-verification-1")

    def test_human_cli_surfaces_semantic_validation_metrics(self) -> None:
        self._write_program(self._valid_program())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["program-verify", str(self.program_path)])
        self.assertEqual(exit_code, 0)
        self.assertIn("semantic_cases=10", stdout.getvalue())
        self.assertIn("semantic_micro_recall=0.9", stdout.getvalue())

    def test_duplicate_key_and_unsafe_input_return_structured_rejection(self) -> None:
        self.program_path.write_text(
            '{"format":"pysfmea-assurance-program-1","format":"duplicate"}',
            encoding="utf-8",
        )
        duplicate = verify_assurance_program(self.program_path)
        self.assertFalse(duplicate["valid"])
        self.assertEqual(duplicate["checks"], {"input": False})

        directory = self.root / "directory"
        directory.mkdir()
        unsafe = verify_assurance_program(directory)
        self.assertFalse(unsafe["valid"])
        self.assertEqual(unsafe["findings"][0]["code"], "program.input_rejected")


if __name__ == "__main__":
    unittest.main()
