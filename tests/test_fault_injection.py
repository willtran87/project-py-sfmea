from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator, ValidationError

import pysfmea.fault_injection as fault_module
from pysfmea.cli import main
from pysfmea.fault_injection import (
    assert_fault_injection_result,
    build_fault_injection_plan,
    complete_fault_injection_plan,
    execute_fault_injection_plan,
    fault_injection_plugin_catalog,
    load_fault_injection_plan,
    recommended_fault_plugins,
    verify_fault_injection_plan,
)
from pysfmea.integrity import canonical_json_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document
from pysfmea.store import save_analysis


def _install_fixture_module() -> types.ModuleType:
    fixture = types.ModuleType("pysfmea_fault_fixture")

    def dependency() -> object:
        return {"status": "normal"}

    def subject() -> object:
        try:
            return fixture.dependency()  # type: ignore[attr-defined]
        except TimeoutError:
            return {"status": "degraded"}

    def subject_without_dependency() -> object:
        return {"status": "false-pass"}

    async def async_dependency() -> object:
        return {"status": "normal"}

    async def async_subject() -> object:
        try:
            return await fixture.async_dependency()  # type: ignore[attr-defined]
        except TimeoutError:
            return {"status": "async-degraded"}

    fixture.dependency = dependency  # type: ignore[attr-defined]
    fixture.subject = subject  # type: ignore[attr-defined]
    fixture.subject_without_dependency = subject_without_dependency  # type: ignore[attr-defined]
    fixture.async_dependency = async_dependency  # type: ignore[attr-defined]
    fixture.async_subject = async_subject  # type: ignore[attr-defined]
    sys.modules[fixture.__name__] = fixture
    return fixture


class FaultInjectionPluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _install_fixture_module()
        self.obligation = {
            "id": "VO-1",
            "finding_id": "FM-1",
            "baseline_id": "BASE-1",
            "rule_id": "resilience.circuit_breaker_recovery",
            "failure_class": "timing",
            "verification_method": "fault_injection_test",
            "provenance": {"contract_sha256": "a" * 64},
        }

    def tearDown(self) -> None:
        sys.modules.pop(self.fixture.__name__, None)

    def execute(self, plan: dict[str, object]) -> dict[str, object]:
        with patch.dict("os.environ", {"PYSFMEA_APPROVED_SANDBOX": "1"}):
            return execute_fault_injection_plan(plan, obligation=self.obligation)

    def test_catalog_recommendation_and_non_executable_starter(self) -> None:
        catalog = fault_injection_plugin_catalog()
        self.assertEqual(
            {value["id"] for value in catalog},
            {
                "builtin.raise-exception.v1",
                "builtin.return-value.v1",
                "builtin.sequence.v1",
            },
        )
        self.assertEqual(
            recommended_fault_plugins(self.obligation),
            ["builtin.sequence.v1", "builtin.raise-exception.v1"],
        )
        plan = build_fault_injection_plan(self.obligation)
        self.assertEqual(plan["status"], "binding_required")
        verification = verify_fault_injection_plan(plan, obligation=self.obligation)
        Draft202012Validator(schema_document("fault-injection-plan")).validate(plan)
        Draft202012Validator(
            schema_document("fault-injection-plan-verification")
        ).validate(verification)
        self.assertFalse(verification["valid"])
        self.assertTrue(verification["checks"]["content_integrity"])
        self.assertTrue(verification["checks"]["binding"])
        self.assertFalse(verification["checks"]["ready"])
        with self.assertRaisesRegex(ValueError, "complete governed obligation"):
            build_fault_injection_plan(
                {**self.obligation, "provenance": {}},
                plugin_id="builtin.raise-exception.v1",
            )

    def test_exception_plugin_proves_stimulus_and_degraded_behavior(self) -> None:
        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.raise-exception.v1"
        )
        case = {
            "subject": "pysfmea_fault_fixture:subject",
            "patch_target": "pysfmea_fault_fixture.dependency",
            "args": [],
            "kwargs": {},
            "fault": {"exception": "TimeoutError", "message": "dependency timed out"},
            "expected": {
                "outcomes": [{"outcome": "returns", "value": {"status": "degraded"}}]
            },
        }
        completed = complete_fault_injection_plan(
            plan, case, obligation=self.obligation
        )
        verification = verify_fault_injection_plan(
            completed, obligation=self.obligation
        )
        Draft202012Validator(schema_document("fault-injection-plan")).validate(
            completed
        )
        Draft202012Validator(
            schema_document("fault-injection-plan-verification")
        ).validate(verification)
        self.assertTrue(verification["valid"])
        result = self.execute(completed)
        self.assertTrue(result["stimulus_observed"])
        self.assertEqual(result["patch_calls"], 1)
        self.assertEqual(result["observations"][0]["value"], {"status": "degraded"})

    def test_return_and_sequence_plugins_execute_explicit_cases(self) -> None:
        cases = {
            "builtin.return-value.v1": {
                "fault": {"value": {"status": "malformed"}},
                "expected": {
                    "outcomes": [
                        {"outcome": "returns", "value": {"status": "malformed"}}
                    ]
                },
            },
            "builtin.sequence.v1": {
                "fault": {
                    "events": [
                        {"kind": "raise", "exception": "TimeoutError"},
                        {"kind": "return", "value": {"status": "recovered"}},
                    ]
                },
                "expected": {
                    "outcomes": [
                        {"outcome": "returns", "value": {"status": "degraded"}},
                        {"outcome": "returns", "value": {"status": "recovered"}},
                    ]
                },
            },
        }
        for plugin_id, plugin_case in cases.items():
            with self.subTest(plugin=plugin_id):
                plan = build_fault_injection_plan(self.obligation, plugin_id=plugin_id)
                case = {
                    "subject": "pysfmea_fault_fixture:subject",
                    "patch_target": "pysfmea_fault_fixture.dependency",
                    "args": [],
                    "kwargs": {},
                    **plugin_case,
                }
                result = self.execute(
                    complete_fault_injection_plan(
                        plan, case, obligation=self.obligation
                    )
                )
                self.assertTrue(result["stimulus_observed"])
                self.assertEqual(result["patch_calls"], len(result["observations"]))

    def test_async_subject_and_duration_oracle_execute_in_sandbox(self) -> None:
        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.raise-exception.v1"
        )
        case = {
            "subject": "pysfmea_fault_fixture:async_subject",
            "patch_target": "pysfmea_fault_fixture.async_dependency",
            "args": [],
            "kwargs": {},
            "fault": {"exception": "TimeoutError"},
            "expected": {
                "outcomes": [
                    {
                        "outcome": "returns",
                        "value": {"status": "async-degraded"},
                        "max_duration_ms": 5_000,
                    }
                ]
            },
        }
        result = self.execute(
            complete_fault_injection_plan(plan, case, obligation=self.obligation)
        )
        self.assertGreaterEqual(result["observations"][0]["elapsed_ms"], 0)

    def test_false_pass_and_unsupported_exception_are_rejected(self) -> None:
        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.raise-exception.v1"
        )
        case = {
            "subject": "pysfmea_fault_fixture:subject_without_dependency",
            "patch_target": "pysfmea_fault_fixture.dependency",
            "args": [],
            "kwargs": {},
            "fault": {"exception": "TimeoutError"},
            "expected": {
                "outcomes": [{"outcome": "returns", "value": {"status": "false-pass"}}]
            },
        }
        completed = complete_fault_injection_plan(
            plan, case, obligation=self.obligation
        )
        with self.assertRaisesRegex(AssertionError, "stimulus was not observed"):
            self.execute(completed)
        bad = json.loads(json.dumps(case))
        bad["fault"]["exception"] = "SystemExit"
        with self.assertRaisesRegex(ValueError, "injected exception must be one of"):
            complete_fault_injection_plan(plan, bad, obligation=self.obligation)

    def test_closed_policy_binding_and_host_execution_are_enforced(self) -> None:
        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.raise-exception.v1"
        )
        case = {
            "subject": "package.service.module:Client.call",
            "patch_target": "package.service.module.dependency",
            "args": [],
            "kwargs": {},
            "fault": {"exception": "TimeoutError"},
            "expected": {"outcomes": [{"outcome": "returns", "value": None}]},
        }
        completed = complete_fault_injection_plan(
            plan, case, obligation=self.obligation
        )
        self.assertTrue(
            verify_fault_injection_plan(completed, obligation=self.obligation)["valid"]
        )
        self.assertFalse(verify_fault_injection_plan(completed)["valid"])
        with self.assertRaisesRegex(PermissionError, "approved sandbox"):
            execute_fault_injection_plan(completed, obligation=self.obligation)

        unsafe = json.loads(json.dumps(completed))
        unsafe["execution"]["network"] = "allowed"
        unsafe["unexpected"] = True
        unsafe.pop("integrity")
        unsafe["integrity"] = {
            "algorithm": "sha256",
            "content_sha256": canonical_json_sha256(unsafe),
        }
        verification = verify_fault_injection_plan(
            unsafe, obligation=self.obligation
        )
        self.assertFalse(verification["valid"])
        self.assertFalse(verification["checks"]["contract"])
        self.assertFalse(verification["checks"]["execution_policy"])

        with self.assertRaisesRegex(ValueError, "starter fails"):
            complete_fault_injection_plan(
                unsafe, case, obligation=self.obligation
            )

        wrong_obligation = {**self.obligation, "id": "VO-DIFFERENT"}
        mismatch = verify_fault_injection_plan(
            completed, obligation=wrong_obligation
        )
        self.assertIn(
            "fault_plan.binding_mismatch",
            {value["code"] for value in mismatch["findings"]},
        )
        with self.assertRaisesRegex(ValueError, "starter fails"):
            complete_fault_injection_plan(
                plan, case, obligation=wrong_obligation
            )

        tampered = json.loads(json.dumps(completed))
        tampered["notice"] = "changed without updating integrity"
        integrity_verdict = verify_fault_injection_plan(
            tampered, obligation=self.obligation
        )
        self.assertIn(
            "fault_plan.integrity_invalid",
            {value["code"] for value in integrity_verdict["findings"]},
        )
        for field, value, code in (
            ("format", "pysfmea-fault-injection-plan-0", "fault_plan.format_invalid"),
            ("plugin", {"id": "unknown", "recommended_plugin_ids": []}, "fault_plan.plugin_invalid"),
        ):
            invalid = json.loads(json.dumps(completed))
            invalid[field] = value
            invalid.pop("integrity")
            invalid["integrity"] = {
                "algorithm": "sha256",
                "content_sha256": canonical_json_sha256(invalid),
            }
            verdict = verify_fault_injection_plan(
                invalid, obligation=self.obligation
            )
            self.assertIn(code, {item["code"] for item in verdict["findings"]})
        unhashable_plugin = json.loads(json.dumps(completed))
        unhashable_plugin["plugin"]["recommended_plugin_ids"] = [{}]
        unhashable_plugin.pop("integrity")
        unhashable_plugin["integrity"] = {
            "algorithm": "sha256",
            "content_sha256": canonical_json_sha256(unhashable_plugin),
        }
        self.assertFalse(
            verify_fault_injection_plan(
                unhashable_plugin, obligation=self.obligation
            )["checks"]["plugin"]
        )
        with self.assertRaisesRegex(ValueError, "binding_required starter"):
            complete_fault_injection_plan(
                completed, case, obligation=self.obligation
            )

    def test_contract_rejects_state_metadata_and_outcome_ambiguity(self) -> None:
        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.return-value.v1"
        )
        case = {
            "subject": "pysfmea_fault_fixture:subject",
            "patch_target": "pysfmea_fault_fixture.dependency",
            "args": [],
            "kwargs": {},
            "fault": {"value": None},
            "expected": {
                "outcomes": [
                    {
                        "outcome": "returns",
                        "value": None,
                        "exception_type": "TimeoutError",
                    }
                ]
            },
        }
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            complete_fault_injection_plan(
                plan, case, obligation=self.obligation
            )

        invalid_state = json.loads(json.dumps(plan))
        invalid_state["completed_at"] = "2026-08-05T00:00:00Z"
        invalid_state.pop("integrity")
        invalid_state["integrity"] = {
            "algorithm": "sha256",
            "content_sha256": canonical_json_sha256(invalid_state),
        }
        verification = verify_fault_injection_plan(
            invalid_state, obligation=self.obligation
        )
        self.assertFalse(verification["checks"]["contract"])
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema_document("fault-injection-plan")).validate(
                invalid_state
            )

    def test_duration_contract_rejects_invalid_bounds_and_failed_oracles(self) -> None:
        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.return-value.v1"
        )
        case = {
            "subject": "pysfmea_fault_fixture:subject",
            "patch_target": "pysfmea_fault_fixture.dependency",
            "args": [],
            "kwargs": {},
            "fault": {"value": None},
            "expected": {
                "outcomes": [
                    {
                        "outcome": "returns",
                        "value": None,
                        "min_duration_ms": 10,
                        "max_duration_ms": 1,
                    }
                ]
            },
        }
        with self.assertRaisesRegex(ValueError, "duration bounds are inverted"):
            complete_fault_injection_plan(plan, case, obligation=self.obligation)
        case["expected"]["outcomes"][0]["min_duration_ms"] = 10_000
        case["expected"]["outcomes"][0]["max_duration_ms"] = 20_000
        with self.assertRaisesRegex(AssertionError, "minimum duration"):
            assert_fault_injection_result(
                case,
                {
                    "plugin_id": "builtin.return-value.v1",
                    "stimulus_observed": True,
                    "patch_calls": 1,
                    "observations": [
                        {"outcome": "returns", "value": None, "elapsed_ms": 1.0}
                    ],
                },
            )

    def test_adversarial_case_and_result_boundaries_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite JSON-compatible"):
            fault_module._json_bytes({object()})
        with self.assertRaisesRegex(ValueError, "encoded limit"):
            fault_module._json_bytes("x" * (fault_module.MAX_CASE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "string keys"):
            fault_module._mapping({1: "value"}, label="record")

        self.fixture.not_callable = 1  # type: ignore[attr-defined]
        with self.assertRaisesRegex(ValueError, "does not resolve to a callable"):
            fault_module._resolve_subject("pysfmea_fault_fixture:not_callable")
        with self.assertRaisesRegex(ValueError, "500 characters"):
            fault_module._exception(
                {"exception": "TimeoutError", "message": "x" * 501}
            )
        with self.assertRaisesRegex(ValueError, "requires value"):
            fault_module._event_side_effect({"kind": "return"})
        with self.assertRaisesRegex(ValueError, "must be raise or return"):
            fault_module._event_side_effect({"kind": "pause"})

        invalid_outcomes = (
            ({"outcomes": []}, "one record"),
            ({"outcomes": [{"outcome": "unknown"}]}, "returns or raises"),
            (
                {"outcomes": [{"outcome": "raises", "exception_type": "KeyError"}]},
                "allowed exception_type",
            ),
            (
                {"outcomes": [{"outcome": "returns", "min_duration_ms": True}]},
                "finite non-negative",
            ),
        )
        for expected, message in invalid_outcomes:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError, message
            ):
                fault_module._expected_outcomes({"expected": expected}, 1)

        case = {
            "expected": {
                "outcomes": [
                    {"outcome": "raises", "exception_type": "TimeoutError"}
                ]
            }
        }
        result = {
            "plugin_id": "builtin.raise-exception.v1",
            "stimulus_observed": True,
            "patch_calls": 1,
            "observations": [
                {
                    "outcome": "raises",
                    "exception_type": "ValueError",
                    "elapsed_ms": 0.0,
                }
            ],
        }
        with self.assertRaisesRegex(AssertionError, "exception type"):
            assert_fault_injection_result(case, result)
        case["expected"]["outcomes"][0]["exception_type"] = "ValueError"
        case["expected"]["outcomes"][0]["max_duration_ms"] = 0
        result["observations"][0]["elapsed_ms"] = 1.0
        with self.assertRaisesRegex(AssertionError, "maximum duration"):
            assert_fault_injection_result(case, result)

        plan = build_fault_injection_plan(
            self.obligation, plugin_id="builtin.raise-exception.v1"
        )
        with patch.dict("os.environ", {"PYSFMEA_APPROVED_SANDBOX": "1"}):
            with self.assertRaisesRegex(ValueError, "not complete"):
                execute_fault_injection_plan(plan, obligation=self.obligation)

        with tempfile.TemporaryDirectory() as directory:
            invalid_root = Path(directory) / "array.json"
            invalid_root.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "plan root"):
                load_fault_injection_plan(invalid_root)
            with self.assertRaisesRegex(ValueError, "case root"):
                fault_module.load_fault_injection_case(invalid_root)

    def test_cli_exports_and_verifies_bound_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def call(client):\n    return client.send()\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            analysis_path = root / "analysis.json"
            save_analysis(analysis_path, analysis)
            obligation_id = analysis["assurance"]["obligations"][0]["id"]
            plan_path = root / "fault-plan.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "assurance-fault-plan",
                            str(analysis_path),
                            obligation_id,
                            "-o",
                            str(plan_path),
                            "--plugin",
                            "builtin.raise-exception.v1",
                        ]
                    ),
                    0,
                )
            loaded = load_fault_injection_plan(plan_path)
            self.assertEqual(loaded["binding"]["obligation_id"], obligation_id)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "assurance-fault-verify",
                            str(plan_path),
                            "--analysis",
                            str(analysis_path),
                            "--json",
                        ]
                    ),
                    1,
                )
            self.assertEqual(
                json.loads(output.getvalue())["status"], "binding_required"
            )
            case_path = root / "fault-case.json"
            case_path.write_text(
                json.dumps(
                    {
                        "subject": "service:call",
                        "patch_target": "service.client",
                        "args": [None],
                        "kwargs": {},
                        "fault": {"exception": "TimeoutError"},
                        "expected": {
                            "outcomes": [
                                {
                                    "outcome": "raises",
                                    "exception_type": "TimeoutError",
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            ready_path = root / "ready-fault-plan.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "assurance-fault-complete",
                            str(plan_path),
                            str(case_path),
                            "--analysis",
                            str(analysis_path),
                            "-o",
                            str(ready_path),
                        ]
                    ),
                    0,
                )
            pytest_path = root / "test_generated_fault.py"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "assurance-fault-scaffold",
                            str(ready_path),
                            "--analysis",
                            str(analysis_path),
                            "-o",
                            str(pytest_path),
                        ]
                    ),
                    0,
                )
            self.assertIn(
                "execute_fault_injection_plan",
                pytest_path.read_text(encoding="utf-8"),
            )


@settings(max_examples=40, deadline=None)
@given(st.dictionaries(st.text(max_size=12), st.integers(), max_size=8))
def test_return_value_plugin_preserves_finite_json_values(
    value: dict[str, int],
) -> None:
    fixture = _install_fixture_module()
    try:
        obligation = {
            "id": "VO-PROPERTY",
            "finding_id": "FM-PROPERTY",
            "baseline_id": "BASE",
            "rule_id": "interface.contract_compatibility",
            "failure_class": "data",
            "verification_method": "contract_test",
            "provenance": {"contract_sha256": "b" * 64},
        }
        plan = build_fault_injection_plan(
            obligation, plugin_id="builtin.return-value.v1"
        )
        case = {
            "subject": "pysfmea_fault_fixture:subject",
            "patch_target": "pysfmea_fault_fixture.dependency",
            "args": [],
            "kwargs": {},
            "fault": {"value": value},
            "expected": {"outcomes": [{"outcome": "returns", "value": value}]},
        }
        with patch.dict("os.environ", {"PYSFMEA_APPROVED_SANDBOX": "1"}):
            result = execute_fault_injection_plan(
                complete_fault_injection_plan(plan, case, obligation=obligation),
                obligation=obligation,
            )
        assert_fault_injection_result(case, result)
        assert result["observations"][0]["value"] == value
    finally:
        sys.modules.pop(fixture.__name__, None)
