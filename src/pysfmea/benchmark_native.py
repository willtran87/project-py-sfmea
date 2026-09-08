"""Native, exact-byte normalization for supported external benchmark result formats."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any

from .benchmark_source_health import _ADAPTER_MODE
from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .harbor_results import trial_observation
from .json_ingestion import load_bounded_file_snapshot, parse_bounded_json_bytes
from .model import utc_now

NATIVE_BENCHMARK_FORMAT = "pysfmea-native-benchmark-normalization-1"
NATIVE_BENCHMARK_VERIFICATION_FORMAT = (
    "pysfmea-native-benchmark-normalization-verification-1"
)
MAX_BYTES = 100 * 1024 * 1024
OUTCOMES = {"success", "failure", "incomplete", "error", "not_reported"}


def _bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "pass", "passed", "positive"}:
        return True
    if text in {"0", "false", "no", "fail", "failed", "negative"}:
        return False
    raise ValueError(f"{label} is not a recognized boolean")


def _number(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    result = float(value)
    if not result == result or result in {float("inf"), float("-inf")}:
        raise ValueError("benchmark metric must be finite")
    return result


def _record(
    identifier: Any,
    *,
    expected: Any = None,
    predicted: Any = None,
    passed: Any = None,
    resolved: Any = None,
    coverage: Any = None,
    mutation: Any = None,
    outcome: Any = None,
) -> dict[str, Any]:
    outcome_value = "not_reported" if outcome in {None, ""} else str(outcome).strip()
    if outcome_value not in OUTCOMES:
        raise ValueError("benchmark outcome is not recognized")
    return {
        "case_id": bounded_text(identifier, "benchmark case id"),
        "expected_label": None
        if expected is None
        else ("positive" if _bool(expected, "expected label") else "negative"),
        "predicted_label": None
        if predicted is None
        else ("positive" if _bool(predicted, "predicted label") else "negative"),
        "passed": None if passed is None else _bool(passed, "passed"),
        "resolved": None if resolved is None else _bool(resolved, "resolved"),
        "coverage_delta": _number(coverage),
        "mutation_score": _number(mutation),
        "outcome": outcome_value,
    }


def _optional_text(value: Any, label: str) -> str | None:
    if value is None or value == "":
        return None
    return bounded_text(value, label)


def _source_context(suite_id: str, raw: bytes) -> dict[str, str | None]:
    context: dict[str, str | None] = {
        "benchmark_month": None,
        "repository": None,
        "platform": None,
        "image": None,
        "harness_version": None,
        "evaluator": None,
    }
    if suite_id != "swe-bench-live":
        return context
    value = parse_bounded_json_bytes(
        raw,
        label="SWE-bench Live result metadata",
        max_bytes=MAX_BYTES,
        max_depth=100,
        max_nodes=5_000_000,
    )
    if not isinstance(value, dict):
        return context
    aliases = {
        "benchmark_month": ("benchmark_month", "month", "evaluation_month"),
        "repository": ("repository", "repo"),
        "platform": ("platform", "runtime_platform"),
        "image": ("image", "container_image"),
        "harness_version": ("harness_version", "runner_version"),
        "evaluator": ("evaluator", "evaluation_authority"),
    }
    for target, names in aliases.items():
        source_value = next((value[name] for name in names if name in value), None)
        context[target] = _optional_text(source_value, f"SWE-bench Live {target}")
    return context


def _rows(suite_id: str, raw: bytes) -> list[dict[str, Any]]:
    mode = _ADAPTER_MODE.get(suite_id, "contract-only")
    if mode == "contract-only" or mode == "direct":
        raise ValueError(
            f"{suite_id} does not declare a native external-result adapter"
        )
    values: Any
    if mode == "native-csv":
        values = list(
            csv.DictReader(io.StringIO(raw.decode("utf-8-sig", errors="strict")))
        )
    elif mode == "native-json":
        value = parse_bounded_json_bytes(
            raw,
            label="native benchmark JSON",
            max_bytes=MAX_BYTES,
            max_depth=100,
            max_nodes=5_000_000,
        )
        if suite_id == "swe-bench-live" and isinstance(value, dict):
            states = (
                ("success_ids", True),
                ("failure_ids", False),
                ("incomplete_ids", None),
                ("error_ids", None),
            )
            values = []
            for field, resolved in states:
                identifiers = value.get(field, [])
                if not isinstance(identifiers, list):
                    raise ValueError(f"SWE-bench Live {field} must be an array")
                values.extend(
                    {
                        "instance_id": identifier,
                        "resolved": resolved,
                        "outcome": field.removesuffix("_ids"),
                    }
                    for identifier in identifiers
                )
        elif suite_id == "swe-polybench-verified-python" and isinstance(value, dict):
            container = value.get("results", value.get("cases", value))
            if isinstance(container, dict):
                values = [
                    {
                        "instance_id": identifier,
                        **(
                            result if isinstance(result, dict) else {"resolved": result}
                        ),
                    }
                    for identifier, result in container.items()
                ]
            else:
                values = container
        else:
            values = (
                value.get("results", value.get("cases", []))
                if isinstance(value, dict)
                else value
            )
    else:
        values = [
            json.loads(line)
            for line in raw.decode("utf-8", errors="strict").splitlines()
            if line.strip()
        ]
    if (
        not isinstance(values, list)
        or not values
        or len(values) > 1_000_000
        or not all(isinstance(item, dict) for item in values)
    ):
        raise ValueError("native benchmark result population is invalid")
    normalized = []
    for item in values:
        if suite_id == "terminal-bench-2":
            trial = trial_observation(item)
            normalized.append(_record(trial["case_id"], passed=trial["passed"], resolved=trial["resolved"], outcome=trial["outcome"]))
        elif suite_id == "owasp-benchmark-python":
            normalized.append(
                _record(
                    item.get("testCaseName") or item.get("test_case") or item.get("id"),
                    expected=item.get("realVulnerability", item.get("expected")),
                    predicted=item.get("toolFound", item.get("predicted")),
                )
            )
        elif suite_id == "idoft-python":
            project = item.get("Project URL") or item.get("project_url")
            revision = item.get("SHA Detected") or item.get("sha_detected")
            test_name = item.get(
                "Pytest Test Name (PathToFile::TestClass::TestMethod or PathToFile::TestMethod)"
            ) or item.get("test_name")
            if not project or not revision or not test_name:
                raise ValueError(
                    "IDoFT row lacks project, detected revision, or test name"
                )
            normalized.append(
                _record(
                    f"{project}@{revision}::{test_name}",
                    expected=True,
                )
            )
        elif suite_id in {
            "tdd-bench-verified",
            "swe-bench-verified",
            "swe-bench-live",
        }:
            normalized.append(
                _record(
                    item.get("instance_id") or item.get("task_id") or item.get("id"),
                    passed=item.get("passed", item.get("resolved")),
                    resolved=item.get("resolved"),
                    outcome=item.get("outcome")
                    if suite_id == "swe-bench-live"
                    else None,
                )
            )
        elif suite_id == "swe-polybench-verified-python":
            identifier = (
                item.get("instance_id") or item.get("task_id") or item.get("id")
            )
            if not identifier:
                raise ValueError("SWE-PolyBench result lacks an instance id")
            resolved = item.get("resolved")
            if resolved is None and isinstance(item.get("report"), dict):
                resolved = item["report"].get("resolved")
            normalized.append(_record(identifier, passed=resolved, resolved=resolved))
        elif suite_id == "agentdojo":
            identifier = item.get("case_id") or item.get("id")
            if not identifier:
                parts = [
                    item.get("suite_name"),
                    item.get("user_task_id"),
                    item.get("attack_type") or "none",
                    item.get("injection_task_id") or "none",
                ]
                if not all(parts[:2]):
                    raise ValueError(
                        "AgentDojo result lacks suite and user-task identity"
                    )
                identifier = "/".join(str(part) for part in parts)
            if "utility" not in item or "security" not in item:
                raise ValueError(
                    "AgentDojo result lacks distinct utility and security outcomes"
                )
            normalized.append(
                _record(
                    identifier,
                    passed=item["security"],
                    resolved=item["utility"],
                )
            )
        elif suite_id == "testgeneval":
            normalized.append(
                _record(
                    item.get("task_id") or item.get("instance_id") or item.get("id"),
                    passed=item.get("passed"),
                    coverage=item.get("coverage_delta"),
                    mutation=item.get("mutation_score"),
                )
            )
        else:
            raise ValueError(f"no native normalizer is implemented for {suite_id}")
    return normalized


def normalize_native_benchmark(
    source: str | Path,
    *,
    suite_id: str,
    suite_revision: str,
    authority: str,
) -> dict[str, Any]:
    snapshot = load_bounded_file_snapshot(
        source, label="native benchmark output", max_bytes=MAX_BYTES
    )
    cases = _rows(suite_id, snapshot.raw)
    if len({item["case_id"] for item in cases}) != len(cases):
        raise ValueError("native benchmark case ids must be unique")
    result = seal(
        {
            "format": NATIVE_BENCHMARK_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "native benchmark authority"),
            "suite": {
                "id": suite_id,
                "revision": bounded_text(suite_revision, "suite revision"),
                "adapter_mode": _ADAPTER_MODE.get(suite_id, "contract-only"),
            },
            "source": {
                "name": snapshot.path.name,
                "bytes": snapshot.size,
                "sha256": hashlib.sha256(snapshot.raw).hexdigest(),
                "context": _source_context(suite_id, snapshot.raw),
            },
            "cases": cases,
            "summary": {
                "cases": len(cases),
                "classification_cases": sum(
                    item["expected_label"] is not None
                    and item["predicted_label"] is not None
                    for item in cases
                ),
                "execution_cases": sum(item["passed"] is not None for item in cases),
                "resolved_cases": sum(item["resolved"] is True for item in cases),
                "outcomes": {
                    outcome: sum(item["outcome"] == outcome for item in cases)
                    for outcome in sorted(OUTCOMES)
                },
            },
            "claim_boundary": "Normalization preserves exact source identity and translates only declared native fields. It is not executable benchmark evidence until joined with pinned corpus, runner, environment, ground truth, and per-case evidence through the governed observation workflow.",
        }
    )
    if not verify_native_benchmark(result)["valid"]:
        raise ValueError("native benchmark normalization failed internal verification")
    return result


def _summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cases": len(cases),
        "classification_cases": sum(
            item.get("expected_label") is not None
            and item.get("predicted_label") is not None
            for item in cases
        ),
        "execution_cases": sum(item.get("passed") is not None for item in cases),
        "resolved_cases": sum(item.get("resolved") is True for item in cases),
        "outcomes": {
            outcome: sum(item.get("outcome") == outcome for item in cases)
            for outcome in sorted(OUTCOMES)
        },
    }


def _structure(value: dict[str, Any]) -> bool:
    try:
        cases = value["cases"]
        case_fields = {
            "case_id",
            "expected_label",
            "predicted_label",
            "passed",
            "resolved",
            "coverage_delta",
            "mutation_score",
            "outcome",
        }
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "suite",
                "source",
                "cases",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(value["suite"]) == {"id", "revision", "adapter_mode"}
            and value["suite"]["adapter_mode"]
            == _ADAPTER_MODE.get(value["suite"]["id"], "contract-only")
            and value["suite"]["adapter_mode"] not in {"contract-only", "direct"}
            and set(value["source"]) == {"name", "bytes", "sha256", "context"}
            and isinstance(value["source"]["name"], str)
            and bool(value["source"]["name"])
            and isinstance(value["source"]["bytes"], int)
            and value["source"]["bytes"] > 0
            and bool(re.fullmatch(r"[0-9a-f]{64}", value["source"]["sha256"]))
            and set(value["source"]["context"])
            == {
                "benchmark_month",
                "repository",
                "platform",
                "image",
                "harness_version",
                "evaluator",
            }
            and all(
                item is None or (isinstance(item, str) and bool(item))
                for item in value["source"]["context"].values()
            )
            and isinstance(cases, list)
            and 0 < len(cases) <= 1_000_000
            and len({item.get("case_id") for item in cases}) == len(cases)
            and all(
                isinstance(item, dict)
                and set(item) == case_fields
                and isinstance(item["case_id"], str)
                and bool(item["case_id"])
                and item["expected_label"] in {None, "positive", "negative"}
                and item["predicted_label"] in {None, "positive", "negative"}
                and (item["passed"] is None or isinstance(item["passed"], bool))
                and (item["resolved"] is None or isinstance(item["resolved"], bool))
                and item["outcome"] in OUTCOMES
                and all(
                    item[name] is None
                    or (
                        isinstance(item[name], (int, float))
                        and not isinstance(item[name], bool)
                        and item[name] == item[name]
                    )
                    for name in ("coverage_delta", "mutation_score")
                )
                for item in cases
            )
            and value["summary"] == _summary(cases)
        )
    except (KeyError, TypeError):
        return False


def verify_native_benchmark(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="native benchmark normalization",
            format_value=NATIVE_BENCHMARK_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("native benchmark normalization fields are invalid")
    return seal(
        {
            "format": NATIVE_BENCHMARK_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "eligible_for_observation_join": integrity and structure,
            "checks": {
                "content_integrity": integrity,
                "native_mapping_and_reconciliation": structure,
            },
            "errors": errors,
            "notice": "Eligibility permits a governed join to evidence-backed observations; it is not benchmark execution evidence.",
        }
    )


def export_native_benchmark(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_native_benchmark(value)["valid"]:
        raise ValueError("native benchmark normalization is invalid")
    return publish_json(value, destination)


def verify_native_benchmark_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_native_benchmark(
            load_json(source, label="native benchmark normalization")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": NATIVE_BENCHMARK_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_observation_join": False,
                "checks": {
                    "content_integrity": False,
                    "native_mapping_and_reconciliation": False,
                },
                "errors": [str(exc)],
                "notice": "Native benchmark verification failed closed.",
            }
        )
