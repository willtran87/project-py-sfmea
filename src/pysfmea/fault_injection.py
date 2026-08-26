"""Governed, explicitly bound fault-injection plugins for assurance tests.

Scanning never imports or executes the analyzed repository.  This module is used only
from engineer-authored tests or the approved sandbox execution workflow.  Generated
plans remain non-executable until a reviewer supplies explicit subject, patch, fault,
and expected-outcome bindings.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import inspect
import json
import math
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from unittest import mock

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .interfaces import FaultInjectionPlugin, FaultInjectionResult, FaultObservation
from .json_ingestion import load_bounded_json_file
from .model import stable_id, utc_now
from .version import __version__

FAULT_INJECTION_PLAN_FORMAT = "pysfmea-fault-injection-plan-1"
FAULT_INJECTION_PLAN_VERIFICATION_FORMAT = "pysfmea-fault-injection-plan-verification-1"
MAX_FAULT_PLAN_BYTES = 1_000_000
MAX_FAULT_PLAN_DEPTH = 50
MAX_FAULT_PLAN_NODES = 50_000
MAX_CASE_BYTES = 64_000
MAX_INVOCATIONS = 32
_SUBJECT_PATTERN = re.compile(
    r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$"
)
_PATCH_PATTERN = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_EXCEPTIONS: dict[str, type[Exception]] = {
    "ConnectionError": ConnectionError,
    "OSError": OSError,
    "RuntimeError": RuntimeError,
    "TimeoutError": TimeoutError,
    "ValueError": ValueError,
}
FAULT_SANDBOX_ENV = "PYSFMEA_APPROVED_SANDBOX"
_PLAN_FIELDS = {
    "format",
    "id",
    "status",
    "generated_at",
    "completed_at",
    "generator",
    "binding",
    "plugin",
    "case",
    "execution",
    "notice",
    "integrity",
}


def _json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError(
            "fault-injection case must contain finite JSON-compatible values"
        ) from exc
    if len(encoded) > MAX_CASE_BYTES:
        raise ValueError(
            f"fault-injection case exceeds the {MAX_CASE_BYTES}-byte encoded limit"
        )
    return encoded


def _mapping(value: object, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return cast(Mapping[str, Any], value)


def _resolve_subject(reference: str) -> Any:
    if not _SUBJECT_PATTERN.fullmatch(reference):
        raise ValueError(
            "subject must use the explicit module.path:qualified.callable format"
        )
    module_name, qualname = reference.split(":", 1)
    value: Any = importlib.import_module(module_name)
    for segment in qualname.split("."):
        value = getattr(value, segment)
    if not callable(value):
        raise ValueError("fault-injection subject does not resolve to a callable")
    return value


def _exception(event: Mapping[str, Any]) -> Exception:
    name = str(event.get("exception", ""))
    exception_type = _EXCEPTIONS.get(name)
    if exception_type is None:
        raise ValueError(
            "injected exception must be one of: " + ", ".join(sorted(_EXCEPTIONS))
        )
    message = str(event.get("message", "injected fault"))
    if len(message) > 500:
        raise ValueError("injected exception message exceeds 500 characters")
    return exception_type(message)


def _event_side_effect(event: Mapping[str, Any]) -> Any:
    kind = str(event.get("kind", ""))
    if kind == "raise":
        return _exception(event)
    if kind == "return":
        if "value" not in event:
            raise ValueError("return fault event requires value")
        _json_bytes(event["value"])
        return copy.deepcopy(event["value"])
    raise ValueError("fault event kind must be raise or return")


def _expected_outcomes(
    case: Mapping[str, Any], invocations: int
) -> list[Mapping[str, Any]]:
    expected = _mapping(case.get("expected"), label="expected outcome")
    raw = expected.get("outcomes")
    if not isinstance(raw, list) or len(raw) != invocations:
        raise ValueError("expected.outcomes must contain one record per invocation")
    outcomes: list[Mapping[str, Any]] = []
    for value in raw:
        outcome = _mapping(value, label="expected outcome record")
        kind = str(outcome.get("outcome", ""))
        if kind not in {"returns", "raises"}:
            raise ValueError("expected outcome must be returns or raises")
        allowed = {"outcome", "min_duration_ms", "max_duration_ms"}
        allowed.add("value" if kind == "returns" else "exception_type")
        unknown = set(outcome) - allowed
        if unknown:
            raise ValueError(
                "expected outcome contains unsupported fields: "
                + ", ".join(sorted(unknown))
            )
        if (
            kind == "raises"
            and str(outcome.get("exception_type", "")) not in _EXCEPTIONS
        ):
            raise ValueError(
                "expected raised outcome requires an allowed exception_type"
            )
        if kind == "returns" and "value" in outcome:
            _json_bytes(outcome["value"])
        minimum = outcome.get("min_duration_ms")
        maximum = outcome.get("max_duration_ms")
        for label, bound in (("min_duration_ms", minimum), ("max_duration_ms", maximum)):
            if bound is not None and (
                not isinstance(bound, (int, float))
                or isinstance(bound, bool)
                or not math.isfinite(bound)
                or bound < 0
            ):
                raise ValueError(f"expected {label} must be a finite non-negative number")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ValueError("expected duration bounds are inverted")
        outcomes.append(outcome)
    return outcomes


def _observation(
    value: Any = None, *, error: Exception | None = None, elapsed_ms: float
) -> FaultObservation:
    if error is not None:
        return {
            "outcome": "raises",
            "exception_type": type(error).__name__,
            "message": str(error)[:500],
            "elapsed_ms": elapsed_ms,
        }
    _json_bytes(value)
    return {
        "outcome": "returns",
        "value": copy.deepcopy(value),
        "elapsed_ms": elapsed_ms,
    }


async def _await_value(value: Any) -> Any:
    return await value


def _settle(value: Any) -> Any:
    if not inspect.isawaitable(value):
        return value
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_await_value(value))
    raise RuntimeError(
        "async fault subjects require a synchronous approved-sandbox test entrypoint"
    )


@dataclass(frozen=True)
class _BuiltinFaultPlugin:
    id: str
    version: str
    title: str
    fault_kinds: tuple[str, ...]

    def _events(self, case: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        fault = _mapping(case.get("fault"), label="fault")
        if self.id == "builtin.raise-exception.v1":
            return [{"kind": "raise", **dict(fault)}]
        if self.id == "builtin.return-value.v1":
            if "value" not in fault:
                raise ValueError("return-value plugin requires fault.value")
            return [{"kind": "return", "value": copy.deepcopy(fault["value"])}]
        raw_events = fault.get("events")
        if not isinstance(raw_events, list) or not raw_events:
            raise ValueError("sequence plugin requires a non-empty fault.events array")
        if len(raw_events) > MAX_INVOCATIONS:
            raise ValueError(
                f"sequence plugin exceeds the {MAX_INVOCATIONS}-invocation limit"
            )
        return [_mapping(value, label="fault event") for value in raw_events]

    def validate(self, case: Mapping[str, Any]) -> None:
        allowed = {"subject", "patch_target", "args", "kwargs", "fault", "expected"}
        unknown = set(case) - allowed
        if unknown:
            raise ValueError(
                "fault-injection case contains unsupported fields: "
                + ", ".join(sorted(unknown))
            )
        subject = str(case.get("subject", ""))
        patch_target = str(case.get("patch_target", ""))
        if not _SUBJECT_PATTERN.fullmatch(subject):
            raise ValueError(
                "subject must use the explicit module.path:qualified.callable format"
            )
        if not _PATCH_PATTERN.fullmatch(patch_target):
            raise ValueError("patch_target must be a dotted import attribute")
        args = case.get("args", [])
        kwargs = case.get("kwargs", {})
        if not isinstance(args, list):
            raise ValueError("case args must be an array")
        _mapping(kwargs, label="case kwargs")
        events = self._events(case)
        for event in events:
            _event_side_effect(event)
        _expected_outcomes(case, len(events))
        _json_bytes(case)

    def execute(self, case: Mapping[str, Any]) -> FaultInjectionResult:
        self.validate(case)
        subject = _resolve_subject(str(case["subject"]))
        args = cast(list[Any], case.get("args", []))
        kwargs = dict(_mapping(case.get("kwargs", {}), label="case kwargs"))
        events = self._events(case)
        side_effects = [_event_side_effect(value) for value in events]
        observations: list[FaultObservation] = []
        with mock.patch(
            str(case["patch_target"]), side_effect=side_effects
        ) as injected:
            for _event in events:
                started = time.perf_counter_ns()
                try:
                    value = _settle(subject(*args, **kwargs))
                    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
                    observations.append(_observation(value, elapsed_ms=elapsed_ms))
                except Exception as exc:  # test evidence records application exceptions
                    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
                    observations.append(_observation(error=exc, elapsed_ms=elapsed_ms))
        return {
            "plugin_id": self.id,
            "stimulus_observed": injected.call_count > 0,
            "patch_calls": injected.call_count,
            "observations": observations,
        }


_PLUGINS: tuple[FaultInjectionPlugin, ...] = (
    _BuiltinFaultPlugin(
        "builtin.raise-exception.v1",
        "1",
        "Dependency exception or timeout",
        ("dependency_failure", "timeout", "unavailable"),
    ),
    _BuiltinFaultPlugin(
        "builtin.return-value.v1",
        "1",
        "Malformed, stale, partial, or degraded dependency result",
        ("malformed_result", "partial_result", "stale_result", "degraded_result"),
    ),
    _BuiltinFaultPlugin(
        "builtin.sequence.v1",
        "1",
        "Controlled failure/recovery sequence",
        ("circuit_breaker", "retry", "recovery", "ordering"),
    ),
)
_PLUGIN_BY_ID = {plugin.id: plugin for plugin in _PLUGINS}


def fault_injection_plugin_catalog() -> list[dict[str, Any]]:
    """Return deterministic metadata for every built-in executable plugin."""

    return [
        {
            "id": plugin.id,
            "version": plugin.version,
            "title": plugin.title,
            "fault_kinds": list(plugin.fault_kinds),
            "execution_policy": "approved_sandbox_required",
            "network_policy": "deny_by_default",
        }
        for plugin in _PLUGINS
    ]


def recommended_fault_plugins(obligation: Mapping[str, Any]) -> list[str]:
    """Select conservative plugin candidates without claiming test adequacy."""

    method = str(obligation.get("verification_method", ""))
    rule_id = str(obligation.get("rule_id", ""))
    failure_class = str(obligation.get("failure_class", ""))
    if rule_id.startswith("resilience.circuit_breaker_"):
        return ["builtin.sequence.v1", "builtin.raise-exception.v1"]
    if method in {"fault_injection_test", "concurrency_test", "stress_test"}:
        return ["builtin.raise-exception.v1", "builtin.sequence.v1"]
    if method in {"contract_test", "integration_test", "security_test"}:
        return ["builtin.return-value.v1", "builtin.raise-exception.v1"]
    if failure_class in {"data", "calculation"}:
        return ["builtin.return-value.v1"]
    return []


def _starter_case(plugin_id: str) -> dict[str, Any]:
    common: dict[str, Any] = {
        "subject": "",
        "patch_target": "",
        "args": [],
        "kwargs": {},
    }
    if plugin_id == "builtin.return-value.v1":
        return {
            **common,
            "fault": {"value": None},
            "expected": {"outcomes": [{"outcome": "returns", "value": None}]},
        }
    if plugin_id == "builtin.sequence.v1":
        return {
            **common,
            "fault": {
                "events": [
                    {
                        "kind": "raise",
                        "exception": "TimeoutError",
                        "message": "injected",
                    },
                    {"kind": "return", "value": None},
                ]
            },
            "expected": {
                "outcomes": [
                    {"outcome": "returns", "value": None},
                    {"outcome": "returns", "value": None},
                ]
            },
        }
    return {
        **common,
        "fault": {"exception": "TimeoutError", "message": "injected"},
        "expected": {"outcomes": [{"outcome": "returns", "value": None}]},
    }


def _obligation_contract_sha256(obligation: Mapping[str, Any]) -> str:
    provenance = obligation.get("provenance")
    if not isinstance(provenance, dict):
        return ""
    return str(provenance.get("contract_sha256", ""))


def build_fault_injection_plan(
    obligation: Mapping[str, Any], *, plugin_id: str = ""
) -> dict[str, Any]:
    """Create a non-executable, obligation-bound plugin plan for explicit completion."""

    recommended = recommended_fault_plugins(obligation)
    selected = plugin_id or (recommended[0] if recommended else "")
    if selected not in _PLUGIN_BY_ID:
        raise ValueError(
            "fault-injection plugin must be one of: " + ", ".join(sorted(_PLUGIN_BY_ID))
        )
    binding = {
        "obligation_id": str(obligation.get("id", "")),
        "finding_id": str(obligation.get("finding_id", "")),
        "baseline_id": str(obligation.get("baseline_id", "")),
        "contract_sha256": _obligation_contract_sha256(obligation),
    }
    if (
        not all(binding[name] for name in ("obligation_id", "finding_id", "baseline_id"))
        or re.fullmatch(r"[0-9a-f]{64}", binding["contract_sha256"]) is None
    ):
        raise ValueError(
            "fault-injection planning requires a complete governed obligation binding"
        )
    plan: dict[str, Any] = {
        "format": FAULT_INJECTION_PLAN_FORMAT,
        "id": stable_id(
            "FIPLAN",
            str(obligation.get("id", "")),
            selected,
            _obligation_contract_sha256(obligation),
        ),
        "status": "binding_required",
        "generated_at": utc_now(),
        "generator": {"name": "PySFMEA", "version": __version__},
        "binding": binding,
        "plugin": {
            "id": selected,
            "recommended_plugin_ids": recommended,
        },
        "case": _starter_case(selected),
        "execution": {
            "policy": "approved_sandbox_required",
            "network": "deny_by_default",
            "scanner_execution": False,
        },
        "notice": (
            "Complete the explicit subject, patch target, injected fault, and expected outcomes; "
            "set status to ready; validate the plan; then execute only from a governed test in "
            "the approved sandbox. A passing plugin result is evidence awaiting independent review."
        ),
    }
    plan["integrity"] = {
        "algorithm": "sha256",
        "content_sha256": canonical_json_sha256(plan),
    }
    return plan


def verify_fault_injection_plan(
    plan: Mapping[str, Any], *, obligation: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Verify the closed plan contract, policy, integrity, and exact obligation binding."""

    supplied = dict(plan)
    integrity = supplied.pop("integrity", None)
    checks: dict[str, bool | None] = {
        "format": plan.get("format") == FAULT_INJECTION_PLAN_FORMAT,
        "contract": False,
        "content_integrity": False,
        "plugin": False,
        "case": False,
        "execution_policy": False,
        "binding": False if obligation is not None else None,
        "ready": plan.get("status") == "ready",
    }
    findings: list[dict[str, str]] = []
    if not checks["format"]:
        findings.append(
            {
                "code": "fault_plan.format_invalid",
                "message": "Plan format is not a supported PySFMEA fault-plan contract.",
            }
        )
    unknown = set(plan) - _PLAN_FIELDS
    missing = (_PLAN_FIELDS - {"completed_at"}) - set(plan)
    generator = plan.get("generator")
    binding = plan.get("binding")
    execution = plan.get("execution")
    completed_valid = (
        isinstance(plan.get("completed_at"), str)
        and bool(str(plan.get("completed_at", "")).strip())
        if checks["ready"] is True
        else "completed_at" not in plan
    )
    checks["contract"] = bool(
        not unknown
        and not missing
        and plan.get("status") in {"binding_required", "ready"}
        and isinstance(plan.get("id"), str)
        and bool(str(plan.get("id", "")).strip())
        and isinstance(plan.get("generated_at"), str)
        and bool(str(plan.get("generated_at", "")).strip())
        and isinstance(plan.get("notice"), str)
        and bool(str(plan.get("notice", "")).strip())
        and isinstance(generator, dict)
        and set(generator) == {"name", "version"}
        and generator.get("name") == "PySFMEA"
        and isinstance(generator.get("version"), str)
        and bool(generator.get("version"))
        and isinstance(binding, dict)
        and set(binding)
        == {"obligation_id", "finding_id", "baseline_id", "contract_sha256"}
        and all(
            isinstance(binding.get(name), str) and bool(binding.get(name))
            for name in ("obligation_id", "finding_id", "baseline_id")
        )
        and re.fullmatch(
            r"[0-9a-f]{64}", str(binding.get("contract_sha256", ""))
        )
        is not None
        and completed_valid
    )
    if not checks["contract"]:
        findings.append(
            {
                "code": "fault_plan.contract_invalid",
                "message": "Plan fields, provenance, binding, or completion metadata violate the closed contract.",
            }
        )
    checks["execution_policy"] = bool(
        isinstance(execution, dict)
        and set(execution) == {"policy", "network", "scanner_execution"}
        and execution.get("policy") == "approved_sandbox_required"
        and execution.get("network") == "deny_by_default"
        and execution.get("scanner_execution") is False
    )
    if not checks["execution_policy"]:
        findings.append(
            {
                "code": "fault_plan.execution_policy_invalid",
                "message": "Fault plans require the approved sandbox, denied network, and disabled scanner execution.",
            }
        )
    if isinstance(integrity, dict):
        try:
            checks["content_integrity"] = bool(
                set(integrity) == {"algorithm", "content_sha256"}
                and integrity.get("algorithm") == "sha256"
                and integrity.get("content_sha256")
                == canonical_json_sha256(supplied)
            )
        except (RecursionError, TypeError, ValueError):
            checks["content_integrity"] = False
    if not checks["content_integrity"]:
        findings.append(
            {
                "code": "fault_plan.integrity_invalid",
                "message": "Plan content does not match its closed SHA-256 integrity declaration.",
            }
        )
    plugin_record = plan.get("plugin")
    plugin_id = (
        str(plugin_record.get("id", "")) if isinstance(plugin_record, dict) else ""
    )
    plugin = _PLUGIN_BY_ID.get(plugin_id)
    recommended_ids = (
        plugin_record.get("recommended_plugin_ids", [])
        if isinstance(plugin_record, dict)
        else []
    )
    checks["plugin"] = bool(
        plugin is not None
        and isinstance(plugin_record, dict)
        and set(plugin_record) == {"id", "recommended_plugin_ids"}
        and isinstance(recommended_ids, list)
        and all(isinstance(value, str) for value in recommended_ids)
        and len(recommended_ids) <= 3
        and len(set(recommended_ids)) == len(recommended_ids)
        and all(value in _PLUGIN_BY_ID for value in recommended_ids)
    )
    if not checks["plugin"]:
        findings.append(
            {
                "code": "fault_plan.plugin_invalid",
                "message": "Plan plugin metadata is unknown, ambiguous, or outside the built-in catalog.",
            }
        )
    if plugin is not None and checks["ready"]:
        try:
            plugin.validate(_mapping(plan.get("case"), label="fault-injection case"))
            checks["case"] = True
        except ValueError as exc:
            findings.append({"code": "fault_plan.case_invalid", "message": str(exc)})
    elif not checks["ready"]:
        findings.append(
            {
                "code": "fault_plan.binding_required",
                "message": "Plan is intentionally non-executable until explicit bindings are completed.",
            }
        )
    if obligation is not None:
        checks["binding"] = bool(
            isinstance(binding, dict)
            and binding.get("obligation_id") == obligation.get("id")
            and binding.get("finding_id") == obligation.get("finding_id")
            and binding.get("baseline_id") == obligation.get("baseline_id")
            and binding.get("contract_sha256")
            == _obligation_contract_sha256(obligation)
        )
        if not checks["binding"]:
            findings.append(
                {
                    "code": "fault_plan.binding_mismatch",
                    "message": "Plan binding does not exactly match the governed obligation provenance.",
                }
            )
    else:
        findings.append(
            {
                "code": "fault_plan.binding_unchecked",
                "message": "Exact obligation binding requires the governed analysis obligation.",
            }
        )
    required_checks = [
        "format",
        "contract",
        "content_integrity",
        "plugin",
        "case",
        "execution_policy",
        "binding",
        "ready",
    ]
    valid = all(checks[name] is True for name in required_checks)
    return {
        "format": FAULT_INJECTION_PLAN_VERIFICATION_FORMAT,
        "valid": valid,
        "status": "ready"
        if valid
        else "binding_required"
        if not checks["ready"]
        else "invalid",
        "checks": checks,
        "findings": findings,
        "plugin_id": plugin_id,
        "verified_at": utc_now(),
        "verifier": {"name": "PySFMEA", "version": __version__},
    }


def execute_fault_injection_plan(
    plan: Mapping[str, Any], *, obligation: Mapping[str, Any]
) -> FaultInjectionResult:
    """Execute one valid explicit plan from engineer-authored sandbox test code."""

    if os.environ.get(FAULT_SANDBOX_ENV) != "1":
        raise PermissionError(
            f"fault injection requires {FAULT_SANDBOX_ENV}=1 from the approved sandbox runner"
        )
    verification = verify_fault_injection_plan(plan, obligation=obligation)
    if not verification["valid"]:
        raise ValueError("fault-injection plan is not complete, valid, and ready")
    plugin_id = str(plan["plugin"]["id"])
    plugin = _PLUGIN_BY_ID[plugin_id]
    case = _mapping(plan.get("case"), label="fault-injection case")
    result = plugin.execute(case)
    assert_fault_injection_result(case, result)
    return result


def assert_fault_injection_result(
    case: Mapping[str, Any], result: FaultInjectionResult
) -> None:
    """Reject false-pass injection paths and mismatched explicit observations."""

    if not result["stimulus_observed"] or result["patch_calls"] < 1:
        raise AssertionError(
            "fault stimulus was not observed by the configured patch target"
        )
    expected = _expected_outcomes(case, len(result["observations"]))
    for index, (wanted, observed) in enumerate(
        zip(expected, result["observations"], strict=True), start=1
    ):
        if wanted.get("outcome") != observed.get("outcome"):
            raise AssertionError(f"fault invocation {index} outcome did not match")
        if wanted.get("outcome") == "raises" and wanted.get(
            "exception_type"
        ) != observed.get("exception_type"):
            raise AssertionError(
                f"fault invocation {index} exception type did not match"
            )
        if (
            wanted.get("outcome") == "returns"
            and "value" in wanted
            and wanted.get("value") != observed.get("value")
        ):
            raise AssertionError(f"fault invocation {index} return value did not match")
        elapsed = float(observed.get("elapsed_ms", -1))
        minimum = wanted.get("min_duration_ms")
        maximum = wanted.get("max_duration_ms")
        if minimum is not None and elapsed < float(minimum):
            raise AssertionError(
                f"fault invocation {index} completed before its minimum duration"
            )
        if maximum is not None and elapsed > float(maximum):
            raise AssertionError(
                f"fault invocation {index} exceeded its maximum duration"
            )


def export_fault_injection_plan(
    obligation: Mapping[str, Any], destination: str | Path, *, plugin_id: str = ""
) -> Path:
    """Atomically publish a deterministic, obligation-bound starter plan."""

    plan = build_fault_injection_plan(obligation, plugin_id=plugin_id)
    target = Path(destination).expanduser().absolute()
    atomic_publish_text(
        target,
        json.dumps(plan, indent=2, ensure_ascii=False) + "\n",
        label="fault-injection plan",
    )
    return target


def load_fault_injection_plan(source: str | Path) -> dict[str, Any]:
    """Load one strict, bounded, identity-stable plan file."""

    _path, value, _size = load_bounded_json_file(
        Path(source).expanduser().absolute(),
        label="fault-injection plan",
        max_bytes=MAX_FAULT_PLAN_BYTES,
        max_depth=MAX_FAULT_PLAN_DEPTH,
        max_nodes=MAX_FAULT_PLAN_NODES,
    )
    if not isinstance(value, dict):
        raise ValueError("fault-injection plan root must be an object")
    return cast(dict[str, Any], value)


def load_fault_injection_case(source: str | Path) -> dict[str, Any]:
    """Load one bounded engineer-authored fault case."""

    _path, value, _size = load_bounded_json_file(
        Path(source).expanduser().absolute(),
        label="fault-injection case",
        max_bytes=MAX_CASE_BYTES,
        max_depth=MAX_FAULT_PLAN_DEPTH,
        max_nodes=MAX_FAULT_PLAN_NODES,
    )
    if not isinstance(value, dict):
        raise ValueError("fault-injection case root must be an object")
    return cast(dict[str, Any], value)


def complete_fault_injection_plan(
    plan: Mapping[str, Any],
    case: Mapping[str, Any],
    *,
    obligation: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a ready plan after validating explicit engineer-supplied bindings."""

    starter = verify_fault_injection_plan(plan, obligation=obligation)
    protected_checks = (
        "format",
        "contract",
        "content_integrity",
        "plugin",
        "execution_policy",
        "binding",
    )
    if not all(starter["checks"][name] is True for name in protected_checks):
        raise ValueError(
            "fault-injection starter fails its contract, integrity, policy, or binding checks"
        )
    if plan.get("status") != "binding_required":
        raise ValueError("fault-injection completion requires a binding_required starter plan")
    plugin_record = _mapping(plan.get("plugin"), label="plugin")
    plugin_id = str(plugin_record.get("id", ""))
    plugin = _PLUGIN_BY_ID.get(plugin_id)
    if plugin is None:
        raise ValueError("fault-injection plan references an unknown plugin")
    plugin.validate(case)
    completed = copy.deepcopy(dict(plan))
    completed.pop("integrity", None)
    completed["status"] = "ready"
    completed["case"] = copy.deepcopy(dict(case))
    completed["completed_at"] = utc_now()
    completed["integrity"] = {
        "algorithm": "sha256",
        "content_sha256": canonical_json_sha256(completed),
    }
    return completed


def export_completed_fault_injection_plan(
    plan: Mapping[str, Any],
    case: Mapping[str, Any],
    obligation: Mapping[str, Any],
    destination: str | Path,
) -> Path:
    """Validate and atomically publish a ready, exactly bound fault plan."""

    completed = complete_fault_injection_plan(plan, case, obligation=obligation)
    verification = verify_fault_injection_plan(completed, obligation=obligation)
    if not verification["valid"]:
        codes = ", ".join(value["code"] for value in verification["findings"])
        raise ValueError(f"completed fault-injection plan is invalid: {codes or 'checks failed'}")
    target = Path(destination).expanduser().absolute()
    atomic_publish_text(
        target,
        json.dumps(completed, indent=2, ensure_ascii=False) + "\n",
        label="completed fault-injection plan",
    )
    return target


def export_fault_injection_pytest(
    plan: Mapping[str, Any],
    obligation: Mapping[str, Any],
    destination: str | Path,
) -> Path:
    """Publish a deterministic pytest bridge for the approved sandbox runner."""

    verification = verify_fault_injection_plan(plan, obligation=obligation)
    if not verification["valid"]:
        raise ValueError("fault-injection pytest requires a valid exactly bound ready plan")
    plan_json = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    obligation_json = json.dumps(
        obligation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    content = (
        '"""Generated PySFMEA fault-injection bridge; run only in the approved sandbox."""\n\n'
        "import json\n\n"
        "from pysfmea.fault_injection import execute_fault_injection_plan\n\n"
        f"PLAN = json.loads({plan_json!r})\n"
        f"OBLIGATION = json.loads({obligation_json!r})\n\n"
        "def test_pysfmea_bound_fault_injection() -> None:\n"
        "    result = execute_fault_injection_plan(PLAN, obligation=OBLIGATION)\n"
        "    assert result['stimulus_observed'] is True\n"
    )
    target = Path(destination).expanduser().absolute()
    atomic_publish_text(target, content, label="fault-injection pytest bridge")
    return target
