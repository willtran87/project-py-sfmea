from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.assurance import refresh_assurance_register
from pysfmea.cli import main
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import save_analysis
from pysfmea.test_generation import (
    RecordedTestGenerationProvider,
    apply_test_proposal,
    build_test_generation_packet,
    create_test_proposal,
    generation_readiness,
    stage_test_proposal,
    validate_test_generation_response,
    verify_test_proposal,
    verify_test_proposal_apply_receipt,
    verify_test_proposal_stage,
)


class _FailIfCalledProvider:
    name = "must-not-run"
    model = "must-not-run"

    def generate(self, payload: dict[str, object], *, task: str) -> dict[str, object]:
        raise AssertionError("the provider must not run for an ineligible obligation")


class _RepairingProvider:
    name = "repairing-provider"
    model = "qualification-fixture"

    def __init__(self, valid: dict[str, object]) -> None:
        self.valid = valid
        self.requests: list[dict[str, object]] = []

    def generate(self, payload: dict[str, object], *, task: str) -> dict[str, object]:
        self.requests.append(payload)
        return {} if len(self.requests) == 1 else self.valid


class GovernedTestGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "subject.py").write_text(
            "def divide(value: int) -> float:\n    return 100 / value\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)
        self.obligation = next(
            value
            for value in self.analysis["assurance"]["obligations"]
            if value["component"] == "divide"
        )
        self.obligation = self._accept(self.analysis, self.obligation)

    def _accept(
        self, analysis: dict[str, object], obligation: dict[str, object]
    ) -> dict[str, object]:
        finding = next(
            value
            for value in analysis["items"]  # type: ignore[index]
            if value["id"] == obligation["finding_id"]
        )
        finding["review"].update(
            {
                "disposition": "accepted",
                "reviewer": "Verification Engineer",
                "disposition_rationale": "Reviewed the complete assurance contract.",
                "end_effect": "An incorrect system output is produced.",
                "next_higher_effect": "The caller receives an incorrect numeric result.",
                "requirement": "REQ-NUMERIC-001",
                "severity": 3,
                "severity_rationale": "The effect is bounded in this fixture.",
                "prevention_controls": ["Input constraints and an independent numeric oracle."],
                "required_safe_state": "Reject invalid numeric input.",
                "degraded_behavior": "No degraded numeric result is permitted.",
                "recovery_behavior": "The caller retries with valid input.",
            }
        )
        refresh_assurance_register(analysis, analysis["assurance"])  # type: ignore[arg-type,index]
        return next(
            value
            for value in analysis["assurance"]["obligations"]  # type: ignore[index]
            if value["finding_id"] == finding["id"]
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _response(self, packet: dict[str, object]) -> dict[str, object]:
        obligation = packet["obligation"]
        assert isinstance(obligation, dict)
        automation = obligation["automation"]
        assert isinstance(automation, dict)
        test_name = str(automation["proposed_test_name"])
        path = str(automation["proposed_test_path"])
        content = (
            "from subject import divide\n\n\n"
            f"def {test_name}():\n"
            "    observed = divide(2)\n"
            "    assert observed == 50\n"
        )
        oracles = obligation["oracles"]
        criteria = obligation["acceptance_criteria"]
        assert isinstance(oracles, list)
        assert isinstance(criteria, list)
        return {
            "decision": "proposed",
            "rationale": "Exercise the analyzed calculation with an exact numeric oracle.",
            "files": [
                {
                    "path": path,
                    "content": content,
                    "purpose": "Implement the exact assurance obligation.",
                }
            ],
            "oracle_mappings": [
                {"index": index, "assertion_reference": f"{test_name}: observed == 50"}
                for index in range(1, len(oracles) + 1)
            ],
            "criterion_mappings": [
                {"index": index, "assertion_reference": f"{test_name}: observed == 50"}
                for index in range(1, len(criteria) + 1)
            ],
            "assumptions": ["The accepted obligation defines 2 as an adequate stimulus."],
            "unresolved_questions": [],
        }

    def test_packet_is_exact_source_bound_and_bounded(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        self.assertTrue(packet["generation_eligibility"]["eligible"])
        self.assertEqual(packet["allowed_changes"]["paths"], [
            self.obligation["automation"]["proposed_test_path"]
        ])
        source = packet["source_context"][0]
        self.assertEqual(source["path"], "subject.py")
        self.assertEqual(
            source["content"],
            (self.root / "subject.py").read_bytes().decode("utf-8"),
        )
        self.assertEqual(len(source["sha256"]), 64)
        self.assertLess(len(json.dumps(packet).encode("utf-8")), 2_000_000)

    def test_potential_embedded_secret_blocks_provider_egress(self) -> None:
        secret_root = self.root / "secret-repository"
        secret_root.mkdir()
        (secret_root / "subject.py").write_text(
            'password = "not-a-real-secret-value"\n\n'
            "def divide(value: int) -> float:\n    return 100 / value\n",
            encoding="utf-8",
        )
        analysis = scan_repository(secret_root)
        obligation = next(
            value
            for value in analysis["assurance"]["obligations"]
            if value["component"] == "divide"
        )
        obligation = self._accept(analysis, obligation)
        packet = build_test_generation_packet(analysis, obligation["id"])
        self.assertFalse(packet["generation_eligibility"]["eligible"])
        self.assertIn(
            "potential embedded secret",
            " ".join(packet["generation_eligibility"]["blocking_reasons"]),
        )
        proposal = create_test_proposal(
            analysis, obligation["id"], _FailIfCalledProvider()
        )
        self.assertEqual(proposal["response"]["decision"], "refused")

    def test_cli_dry_run_offline_replay_and_verification(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        obligation_id = self.obligation["id"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                main(
                    [
                        "assurance-test-generate",
                        str(analysis_path),
                        obligation_id,
                        "--dry-run",
                    ]
                ),
                0,
            )
        packet = json.loads(output.getvalue())
        self.assertEqual(packet["binding"]["obligation_id"], obligation_id)

        response_path = self.root / "recorded-response.json"
        response_path.write_text(
            json.dumps(self._response(packet)), encoding="utf-8"
        )
        proposal_path = self.root / "offline-proposal.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "assurance-test-generate",
                        str(analysis_path),
                        obligation_id,
                        "--response-file",
                        str(response_path),
                        "-o",
                        str(proposal_path),
                    ]
                ),
                0,
            )
        proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        self.assertEqual(proposal["response"]["decision"], "proposed")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["assurance-test-proposal-verify", str(proposal_path)]), 0
            )
        stage_path = self.root.parent / f"{self.root.name}-cli-stage"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "assurance-test-stage",
                        str(proposal_path),
                        "--analysis",
                        str(analysis_path),
                        "-o",
                        str(stage_path),
                    ]
                ),
                0,
            )
        with contextlib.redirect_stdout(io.StringIO()) as stage_output:
            self.assertEqual(
                main(
                    [
                        "assurance-test-stage-verify",
                        str(stage_path),
                        str(proposal_path),
                        "--analysis",
                        str(analysis_path),
                        "--json",
                    ]
                ),
                0,
            )
        self.assertTrue(json.loads(stage_output.getvalue())["valid"])
        receipt_path = self.root / "cli-apply-receipt.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "assurance-test-apply",
                        str(stage_path),
                        str(proposal_path),
                        "--analysis",
                        str(analysis_path),
                        "--reviewer",
                        "CLI Reviewer",
                        "--rationale",
                        "Reviewed the exact generated source and mappings.",
                        "--approve",
                        "--receipt",
                        str(receipt_path),
                    ]
                ),
                0,
            )
        with contextlib.redirect_stdout(io.StringIO()) as apply_output:
            self.assertEqual(
                main(
                    [
                        "assurance-test-apply-verify",
                        str(receipt_path),
                        str(proposal_path),
                        "--analysis",
                        str(analysis_path),
                        "--json",
                    ]
                ),
                0,
            )
        self.assertTrue(json.loads(apply_output.getvalue())["valid"])
        with contextlib.redirect_stdout(io.StringIO()) as readiness_output:
            self.assertEqual(
                main(
                    [
                        "assurance-test-readiness",
                        str(receipt_path),
                        str(proposal_path),
                        "--analysis",
                        str(analysis_path),
                        "--json",
                    ]
                ),
                1,
            )
        self.assertEqual(json.loads(readiness_output.getvalue())["passed_gates"], 2)
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(
                main(
                    [
                        "assurance-test-generate",
                        str(analysis_path),
                        obligation_id,
                        "--endpoint",
                        "https://llm.invalid/v1/chat/completions",
                        "--model",
                        "test-model",
                        "-o",
                        str(self.root / "must-not-exist.json"),
                    ]
                ),
                2,
            )
        self.assertIn("approve-source-egress", error.getvalue())

    def test_proposal_verifies_and_stages_without_mutating_repository(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        proposal = create_test_proposal(
            self.analysis,
            self.obligation["id"],
            RecordedTestGenerationProvider(self._response(packet)),
        )
        verification = verify_test_proposal(proposal, self.analysis)
        self.assertTrue(verification["valid"], verification)
        self.assertTrue(verification["implementation_ready"])
        Draft202012Validator(schema_document("assurance-test-proposal")).validate(
            proposal
        )
        Draft202012Validator(
            schema_document("assurance-test-proposal-verification")
        ).validate(verification)
        destination = self.root.parent / f"{self.root.name}-staged"
        staged = stage_test_proposal(proposal, self.analysis, destination)
        test_path = staged / self.obligation["automation"]["proposed_test_path"]
        self.assertTrue(test_path.is_file())
        self.assertFalse(
            (self.root / self.obligation["automation"]["proposed_test_path"]).exists()
        )
        manifest = json.loads(
            (staged / "pysfmea-test-proposal-stage.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(
            schema_document("assurance-test-proposal-stage")
        ).validate(manifest)
        self.assertEqual(manifest["status"], "staged_unreviewed")
        self.assertEqual(manifest["proposal_id"], proposal["id"])
        stage_verification = verify_test_proposal_stage(
            staged, proposal, self.analysis
        )
        self.assertTrue(stage_verification["valid"], stage_verification)
        Draft202012Validator(
            schema_document("assurance-test-proposal-stage-verification")
        ).validate(stage_verification)

        receipt_path = self.root.parent / f"{self.root.name}-apply-receipt.json"
        receipt = apply_test_proposal(
            staged,
            proposal,
            self.analysis,
            reviewer="Safety Reviewer",
            rationale="The exact source and all obligation mappings were reviewed.",
            approved=True,
            receipt_path=receipt_path,
        )
        self.assertEqual(receipt["status"], "applied_unregistered")
        Draft202012Validator(
            schema_document("assurance-test-proposal-apply-receipt")
        ).validate(receipt)
        self.assertTrue(
            (self.root / self.obligation["automation"]["proposed_test_path"]).is_file()
        )
        self.assertEqual(json.loads(receipt_path.read_text()), receipt)
        with self.assertRaisesRegex(ValueError, "destination already exists"):
            apply_test_proposal(
                staged,
                proposal,
                self.analysis,
                reviewer="Second Reviewer",
                rationale="A duplicate publication must be refused.",
                approved=True,
                receipt_path=self.root.parent / f"{self.root.name}-duplicate.json",
            )
        receipt_verification = verify_test_proposal_apply_receipt(
            receipt, proposal, self.analysis
        )
        self.assertTrue(receipt_verification["valid"], receipt_verification)
        Draft202012Validator(
            schema_document("assurance-test-proposal-apply-receipt-verification")
        ).validate(receipt_verification)
        readiness = generation_readiness(proposal, receipt, self.analysis)
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["passed_gates"], 2)
        Draft202012Validator(
            schema_document("assurance-test-generation-readiness")
        ).validate(readiness)
        self.obligation["automation"].update(
            {
                "implementation_status": "implemented",
                "implementation_origin": "llm_generated",
                "implemented_test_path": receipt["file"]["path"],
                "test_sha256": receipt["file"]["sha256"],
            }
        )
        execution = {
            "id": "EXEC-QUALIFIED",
            "obligation_id": self.obligation["id"],
            "baseline_id": receipt["baseline_id"],
            "test": {"sha256": receipt["file"]["sha256"]},
            "status": "passed",
            "initiated_by": "Execution Operator",
            "stimulus_observed": True,
            "acceptance_criteria": [
                {"index": index, "text": text, "result": "pass"}
                for index, text in enumerate(
                    self.obligation["acceptance_criteria"], start=1
                )
            ],
            "reviews": [
                {
                    "reviewer": "Independent Reviewer",
                    "decision": "sufficient",
                    "artifact_integrity_valid": True,
                    "baseline_current": True,
                }
            ],
        }
        self.analysis["assurance"]["executions"].append(execution)
        self.obligation["executions"].append(execution["id"])
        ready = generation_readiness(proposal, receipt, self.analysis)
        self.assertTrue(ready["ready"], ready)
        self.assertEqual(ready["passed_gates"], 7)

        tampered_receipt = copy.deepcopy(receipt)
        tampered_receipt["review"]["reviewer"] = ""
        self.assertFalse(
            verify_test_proposal_apply_receipt(
                tampered_receipt, proposal, self.analysis
            )["valid"]
        )

    def test_stage_tampering_and_unapproved_application_fail_closed(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        proposal = create_test_proposal(
            self.analysis,
            self.obligation["id"],
            RecordedTestGenerationProvider(self._response(packet)),
        )
        with self.assertRaisesRegex(ValueError, "outside the analyzed repository"):
            stage_test_proposal(proposal, self.analysis, self.root / "unsafe-stage")
        occupied = self.root.parent / f"{self.root.name}-occupied-stage"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must be empty"):
            stage_test_proposal(proposal, self.analysis, occupied)
        missing_stage = verify_test_proposal_stage(
            self.root.parent / "missing-stage", proposal, self.analysis
        )
        self.assertFalse(missing_stage["valid"])
        self.assertTrue(missing_stage["errors"])
        staged = stage_test_proposal(
            proposal, self.analysis, self.root.parent / f"{self.root.name}-tamper-stage"
        )
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            apply_test_proposal(
                staged,
                proposal,
                self.analysis,
                reviewer="Reviewer",
                rationale="Reviewed exact bytes.",
                approved=False,
                receipt_path=self.root.parent / "unapproved.json",
            )
        staged_test = staged / self.obligation["automation"]["proposed_test_path"]
        staged_test.write_text("def test_tampered():\n    assert True\n", encoding="utf-8")
        verification = verify_test_proposal_stage(staged, proposal, self.analysis)
        self.assertFalse(verification["valid"])
        self.assertFalse(verification["checks"]["file_integrity"])

    def test_ineligible_obligation_is_refused_without_provider_invocation(self) -> None:
        self.obligation["planning_gaps"] = ["system effect remains undefined"]
        proposal = create_test_proposal(
            self.analysis, self.obligation["id"], _FailIfCalledProvider()
        )
        self.assertEqual(proposal["response"]["decision"], "refused")
        self.assertEqual(proposal["producer"]["provider"], "pysfmea-policy")
        self.assertTrue(verify_test_proposal(proposal, self.analysis)["valid"])

    def test_accepted_finding_with_validation_error_cannot_reach_provider(self) -> None:
        finding = next(
            value
            for value in self.analysis["items"]
            if value["id"] == self.obligation["finding_id"]
        )
        finding["review"]["reviewer"] = ""
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        self.assertFalse(packet["generation_eligibility"]["eligible"])
        self.assertIn(
            "review.missing_reviewer",
            " ".join(packet["generation_eligibility"]["blocking_reasons"]),
        )
        proposal = create_test_proposal(
            self.analysis, self.obligation["id"], _FailIfCalledProvider()
        )
        self.assertEqual(proposal["response"]["decision"], "refused")

    def test_bounded_repair_exposes_only_validator_feedback(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        provider = _RepairingProvider(self._response(packet))
        proposal = create_test_proposal(
            self.analysis,
            self.obligation["id"],
            provider,
            max_attempts=2,
        )
        self.assertEqual(len(provider.requests), 2)
        self.assertEqual(
            provider.requests[1]["attempt_context"]["prior_validation_errors"],  # type: ignore[index]
            ["test-generation response must match the closed root contract"],
        )
        self.assertTrue(proposal["generation"]["repair_performed"])
        self.assertEqual(proposal["generation"]["attempts_used"], 2)
        self.assertFalse(proposal["generation"]["attempt_records"][0]["accepted"])
        self.assertTrue(verify_test_proposal(proposal, self.analysis)["valid"])

    def test_response_rejects_unsafe_or_non_exercising_source(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        production_edit = self._response(packet)
        production_edit["files"][0]["path"] = "subject.py"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "allowlist"):
            validate_test_generation_response(production_edit, packet)

        no_target = self._response(packet)
        test_name = self.obligation["automation"]["proposed_test_name"]
        no_target["files"][0]["content"] = (  # type: ignore[index]
            f"def {test_name}():\n    observed = 50\n    assert observed == 50\n"
        )
        with self.assertRaisesRegex(ValueError, "analyzed target"):
            validate_test_generation_response(no_target, packet)

        shell = self._response(packet)
        shell["files"][0]["content"] = (  # type: ignore[index]
            "import subprocess\nfrom subject import divide\n\n"
            f"def {test_name}():\n"
            "    subprocess.run(['whoami'])\n"
            "    assert divide(2) == 50\n"
        )
        with self.assertRaisesRegex(ValueError, "network or shell"):
            validate_test_generation_response(shell, packet)

    def test_closed_response_and_source_contract_rejection_matrix(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        test_name = self.obligation["automation"]["proposed_test_name"]

        def rejected(change: object, message: str) -> None:
            response = self._response(packet)
            assert callable(change)
            change(response)
            with self.assertRaisesRegex(ValueError, message):
                validate_test_generation_response(response, packet)

        rejected(lambda value: value.update(decision="unknown"), "decision")
        rejected(lambda value: value.update(rationale=42), "rationale")
        rejected(lambda value: value.update(assumptions="none"), "bounded array")
        rejected(lambda value: value.update(files="test.py"), "at most one")
        rejected(lambda value: value.update(files=[]), "requires one file")
        rejected(
            lambda value: value["files"][0].update(extra=True),  # type: ignore[index]
            "closed file contract",
        )
        rejected(
            lambda value: value["files"][0].update(content=42),  # type: ignore[index]
            "content must be text",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=f"def {test_name}(:\n    assert divide(2) == 50\n"
            ),
            "valid Python syntax",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content="def helper():\n    assert divide(2) == 50\n"
            ),
            "pytest test",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=f"def {test_name}():\n    divide(2)\n"
            ),
            "explicit assertions",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=f"def {test_name}():\n    pass\n    assert divide(2) == 50\n"
            ),
            "pass placeholders",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=(
                    f"def {test_name}():\n"
                    "    raise NotImplementedError()\n"
                    "    assert divide(2) == 50\n"
                )
            ),
            "NotImplementedError",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=(
                    "import pytest\n"
                    f"def {test_name}():\n"
                    "    pytest.skip('no')\n"
                    "    assert divide(2) == 50\n"
                )
            ),
            "skip or xfail",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=f"def {test_name}():\n    assert True\n    divide(2)\n"
            ),
            "assert True",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=(
                    f"def {test_name}():\n"
                    "    exec('value = 1')\n"
                    "    assert divide(2) == 50\n"
                )
            ),
            "dynamic or shell",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content=f"def {test_name}():\n    assert divide(2) == 50  # TODO\n"
            ),
            "placeholder text",
        )
        rejected(
            lambda value: value["files"][0].update(  # type: ignore[index]
                content="x" * 300_000
            ),
            "256 KB",
        )
        rejected(
            lambda value: value.update(oracle_mappings=[]),
            "every indexed contract entry",
        )
        rejected(
            lambda value: value["oracle_mappings"][0].update(index=999),  # type: ignore[index]
            "outside the contract",
        )
        rejected(
            lambda value: value["oracle_mappings"][0].update(extra=True),  # type: ignore[index]
            "closed mapping contract",
        )

        refused = self._response(packet)
        refused.update(decision="refused", unresolved_questions=["Need an oracle."])
        with self.assertRaisesRegex(ValueError, "must not contain"):
            validate_test_generation_response(refused, packet)
        refused.update(files=[], oracle_mappings=[], criterion_mappings=[])
        refused["unresolved_questions"] = []
        with self.assertRaisesRegex(ValueError, "unresolved questions"):
            validate_test_generation_response(refused, packet)

        for attempts in (0, 4, True):
            with self.assertRaisesRegex(ValueError, "attempts"):
                create_test_proposal(
                    self.analysis,
                    self.obligation["id"],
                    _FailIfCalledProvider(),
                    max_attempts=attempts,  # type: ignore[arg-type]
                )
        with self.assertRaisesRegex(ValueError, "unsupported task"):
            RecordedTestGenerationProvider({}).generate(packet, task="discovery")

    def test_verification_rejects_tampering_and_analysis_drift(self) -> None:
        packet = build_test_generation_packet(self.analysis, self.obligation["id"])
        proposal = create_test_proposal(
            self.analysis,
            self.obligation["id"],
            RecordedTestGenerationProvider(self._response(packet)),
        )
        extra = copy.deepcopy(proposal)
        extra["unexpected"] = True
        self.assertFalse(verify_test_proposal(extra, self.analysis)["valid"])

        changed = copy.deepcopy(self.analysis)
        changed["project"]["name"] = "changed"
        self.assertFalse(verify_test_proposal(proposal, changed)["valid"])


if __name__ == "__main__":
    unittest.main()
