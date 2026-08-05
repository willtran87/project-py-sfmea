from __future__ import annotations

import contextlib
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
from pysfmea.program import (
    PROGRAM_FORMAT,
    build_program_template,
    program_verification_html,
    program_verification_markdown,
    seal_program,
    seal_program_file,
    verify_assurance_program,
)
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import load_analysis, save_analysis


class AssuranceProgramTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
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
        program["validation_cohorts"] = [
            {
                "id": "COHORT-EXTERNAL-1",
                "repository": "independently-labelled-service",
                "framework": "FastAPI",
                "corpus_sha256": "a" * 64,
                "case_count": 100,
                "recall": 0.91,
                "precision": 0.94,
                "independent_reviewed": True,
                "producer": "Benchmark team",
                "reviewer": "Independent validation authority",
            }
        ]
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
                "corpus_sha256": "b" * 64,
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
            "require_temporal_evidence": True,
            "require_resilience_evidence": True,
            "min_llm_samples": 25,
            "require_independent_llm_evaluation": True,
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
        return seal_program(program)

    def _write_program(self, program: dict[str, object]) -> Path:
        self.program_path.write_text(
            json.dumps(program, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return self.program_path

    def test_verifies_federated_program_evidence_timing_quality_and_governance(self) -> None:
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
        self.assertEqual(result["validation"]["macro_recall"], 0.91)
        self.assertEqual(result["llm_quality"]["samples"], 50)
        markdown = program_verification_markdown(result)
        self.assertIn("**VALID**", markdown)
        self.assertIn("REL-CHECKOUT-PAYMENT", markdown)
        html = program_verification_html(result)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Checkout assurance program", html)
        self.assertIn("REL-CHECKOUT-PAYMENT", html)
        self.assertIn("System topology", html)
        self.assertIn('role="img"', html)
        self.assertIn("Severity", html)
        self.assertNotIn("https://", html)

    def test_rejects_stale_analysis_deadline_failure_and_nonindependent_evidence(self) -> None:
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

    def test_template_defaults_expose_missing_external_validation_and_approval(self) -> None:
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
        self.assertIn("program.invalid_reference_array", codes)
        self.assertIn("governance.required_roles", codes)

    def test_unknown_subjects_weak_quality_and_incomplete_temporal_contract_are_blocked(self) -> None:
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
        self.assertIn("llm.unsupported_claim_rate", codes)
        self.assertIn("governance.unknown_subject", codes)

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
        self.assertTrue(output.read_text(encoding="utf-8").startswith("<!doctype html>"))

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

    def test_circuit_breaker_violation_and_unrelated_role_approval_are_blocked(self) -> None:
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

    def test_identity_timestamp_boolean_and_closed_nested_contracts_fail_closed(self) -> None:
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
        self.assertIn("governance.role_independence", codes)
        self.assertIn("governance.program_rejected", codes)
        self.assertIn("governance.approval_unknown_fields", codes)
        self.assertIn("evidence.unknown_fields", codes)
        self.assertEqual(result["summary"]["trusted_evidence"], 0)
        self.assertEqual(result["relationships"][0]["temporal_status"], "unverified")

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
