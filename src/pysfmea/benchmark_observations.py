"""Case-level benchmark observations for scanners and LLM-generated tests."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import load_json, publish_json, seal, verify_seal
from .model import utc_now

BENCHMARK_OBSERVATIONS_FORMAT = "pysfmea-benchmark-observations-2"
BENCHMARK_OBSERVATIONS_VERIFICATION_FORMAT = (
    "pysfmea-benchmark-observations-verification-1"
)
LABELS = {"positive", "negative", "unknown"}
MAX_CASES = 100_000
MAX_ATTEMPTS_PER_CASE = 100


def _finite(
    value: Any, *, minimum: float | None = None, maximum: float | None = None
) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    number = float(value)
    return (
        math.isfinite(number)
        and (minimum is None or number >= minimum)
        and (maximum is None or number <= maximum)
    )


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 6) if values else None


def _summary(cases: list[dict[str, Any]], repetitions: int) -> dict[str, Any]:
    attempts = [attempt for case in cases for attempt in case["attempts"]]
    first = [case["attempts"][0] for case in cases]
    pass_at_1 = sum(bool(item["passed"]) for item in first)
    pass_at_k = sum(
        any(bool(item["passed"]) for item in case["attempts"][:repetitions])
        for case in cases
    )
    resolved = [
        bool(item["resolved"]) for item in first if item["resolved"] is not None
    ]
    coverage = [
        float(item["coverage_delta"])
        for item in attempts
        if item["coverage_delta"] is not None
    ]
    mutation = [
        float(item["mutation_score"])
        for item in attempts
        if item["mutation_score"] is not None
    ]
    confusion = {
        "true_positive": 0,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 0,
    }
    for case in cases:
        expected = case["expected_label"]
        predicted = case["predicted_label"]
        if "unknown" in {expected, predicted}:
            continue
        key = (
            "true_positive"
            if expected == predicted == "positive"
            else "true_negative"
            if expected == predicted == "negative"
            else "false_positive"
            if expected == "negative"
            else "false_negative"
        )
        confusion[key] += 1
    tp, fp, fn, tn = (
        confusion[name]
        for name in (
            "true_positive",
            "false_positive",
            "false_negative",
            "true_negative",
        )
    )
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    case_count = len(cases)
    attempt_count = len(attempts)
    return {
        "cases": case_count,
        "attempts": attempt_count,
        "repetitions": repetitions,
        "pass_at_1": round(pass_at_1 / case_count, 6) if case_count else None,
        "pass_at_k": round(pass_at_k / case_count, 6) if case_count else None,
        "resolved_rate": round(sum(resolved) / len(resolved), 6) if resolved else None,
        "mean_coverage_delta": _mean(coverage),
        "mean_mutation_score": _mean(mutation),
        "flaky_attempt_rate": round(
            sum(bool(item["flaky"]) for item in attempts) / attempt_count, 6
        )
        if attempt_count
        else None,
        "unsafe_oracle_rate": round(
            sum(bool(item["unsafe_oracle"]) for item in attempts) / attempt_count, 6
        )
        if attempt_count
        else None,
        "mean_latency_ms": _mean([float(item["latency_ms"]) for item in attempts]),
        "input_tokens": sum(int(item["input_tokens"]) for item in attempts),
        "output_tokens": sum(int(item["output_tokens"]) for item in attempts),
        "cost_usd": round(sum(float(item["cost_usd"]) for item in attempts), 6),
        "errors": sum(item["error"] is not None for item in attempts),
        "classification": {
            **confusion,
            "precision": round(precision, 6) if precision is not None else None,
            "recall": round(recall, 6) if recall is not None else None,
            "specificity": round(specificity, 6) if specificity is not None else None,
            "f1": round(f1, 6) if f1 is not None else None,
        },
    }


def _attempt_valid(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {
            "passed",
            "resolved",
            "coverage_delta",
            "mutation_score",
            "flaky",
            "unsafe_oracle",
            "latency_ms",
            "input_tokens",
            "output_tokens",
            "cost_usd",
            "error",
            "output_sha256",
            "test_artifact_sha256",
            "environment_sha256",
            "output_evidence_ref",
            "test_artifact_evidence_ref",
            "environment_evidence_ref",
            "execution_evidence_ref",
            "coverage_evidence_ref",
            "mutation_evidence_ref",
        }
        and isinstance(value["passed"], bool)
        and (value["resolved"] is None or isinstance(value["resolved"], bool))
        and (
            value["coverage_delta"] is None
            or _finite(value["coverage_delta"], minimum=-1, maximum=1)
        )
        and (
            value["mutation_score"] is None
            or _finite(value["mutation_score"], minimum=0, maximum=1)
        )
        and isinstance(value["flaky"], bool)
        and isinstance(value["unsafe_oracle"], bool)
        and _finite(value["latency_ms"], minimum=0)
        and isinstance(value["input_tokens"], int)
        and not isinstance(value["input_tokens"], bool)
        and value["input_tokens"] >= 0
        and isinstance(value["output_tokens"], int)
        and not isinstance(value["output_tokens"], bool)
        and value["output_tokens"] >= 0
        and _finite(value["cost_usd"], minimum=0)
        and (value["error"] is None or isinstance(value["error"], str))
        and all(
            isinstance(value[name], str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", value[name]))
            for name in ("output_sha256", "test_artifact_sha256", "environment_sha256")
        )
        and all(
            isinstance(value[name], str) and bool(value[name].strip())
            for name in (
                "execution_evidence_ref",
                "output_evidence_ref",
                "test_artifact_evidence_ref",
                "environment_evidence_ref",
                "coverage_evidence_ref",
                "mutation_evidence_ref",
            )
        )
    )


def benchmark_observations(
    *,
    suite_id: str,
    suite_revision: str,
    suite_sha256: str,
    runner_image: str,
    runner_command: list[str],
    cases: list[dict[str, Any]],
    repetitions: int,
    authority: str,
    model: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Validate and seal raw case observations with recomputed aggregate metrics."""

    value = {
        "format": BENCHMARK_OBSERVATIONS_FORMAT,
        "generated_at": generated_at or utc_now(),
        "suite": {
            "id": suite_id,
            "revision": suite_revision,
            "snapshot_sha256": suite_sha256,
        },
        "runner": {"image": runner_image, "command": list(runner_command)},
        "model": model,
        "authority": authority,
        "repetitions": repetitions,
        "cases": cases,
        "summary": _summary(cases, repetitions),
        "claim_boundary": "Metrics are recomputed from exact case observations whose inputs, ground truth, outputs, generated tests, environments, and execution evidence are content-addressed. Dataset representativeness, label correctness, provider identity, and independent authority remain externally reviewable evidence.",
    }
    result = seal(value)
    verdict = verify_benchmark_observations(result)
    if not verdict["valid"]:
        raise ValueError(
            "benchmark observations are invalid: " + "; ".join(verdict["errors"])
        )
    return result


def _structure(value: dict[str, Any]) -> bool:
    try:
        cases = value["cases"]
        repetitions = value["repetitions"]
        suite = value["suite"]
        runner = value["runner"]
        model = value["model"]
        if not (
            set(value)
            == {
                "format",
                "generated_at",
                "suite",
                "runner",
                "model",
                "authority",
                "repetitions",
                "cases",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(suite) == {"id", "revision", "snapshot_sha256"}
            and re.fullmatch(r"[0-9a-f]{64}", suite["snapshot_sha256"])
            and set(runner) == {"image", "command"}
            and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", runner["image"])
            and isinstance(runner["command"], list)
            and runner["command"]
            and all(isinstance(item, str) and item for item in runner["command"])
            and isinstance(repetitions, int)
            and not isinstance(repetitions, bool)
            and 1 <= repetitions <= MAX_ATTEMPTS_PER_CASE
            and isinstance(cases, list)
            and 0 < len(cases) <= MAX_CASES
            and isinstance(value["authority"], str)
            and bool(value["authority"].strip())
        ):
            return False
        if model is not None and not (
            isinstance(model, dict)
            and set(model)
            == {"provider", "name", "version", "prompt_sha256", "temperature", "seed"}
            and re.fullmatch(r"[0-9a-f]{64}", str(model["prompt_sha256"]))
            and _finite(model["temperature"], minimum=0, maximum=2)
            and isinstance(model["seed"], int)
            and all(
                isinstance(model[name], str) and model[name].strip()
                for name in ("provider", "name", "version")
            )
        ):
            return False
        identifiers: list[str] = []
        for case in cases:
            if not isinstance(case, dict) or set(case) != {
                "id",
                "repository_id",
                "input_sha256",
                "input_evidence_ref",
                "ground_truth_sha256",
                "ground_truth_evidence_ref",
                "expected_label",
                "predicted_label",
                "attempts",
            }:
                return False
            identifiers.append(case["id"])
            if not (
                isinstance(case["id"], str)
                and case["id"]
                and isinstance(case["repository_id"], str)
                and case["repository_id"]
                and re.fullmatch(r"[0-9a-f]{64}", str(case["input_sha256"]))
                and isinstance(case["input_evidence_ref"], str)
                and bool(case["input_evidence_ref"].strip())
                and re.fullmatch(r"[0-9a-f]{64}", str(case["ground_truth_sha256"]))
                and isinstance(case["ground_truth_evidence_ref"], str)
                and bool(case["ground_truth_evidence_ref"].strip())
                and case["expected_label"] in LABELS
                and case["predicted_label"] in LABELS
                and isinstance(case["attempts"], list)
                and len(case["attempts"]) == repetitions
                and all(_attempt_valid(item) for item in case["attempts"])
            ):
                return False
        return len(identifiers) == len(set(identifiers))
    except (KeyError, TypeError):
        return False


def verify_benchmark_observations(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark observations",
            format_value=BENCHMARK_OBSERVATIONS_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("benchmark observation fields are invalid")
    reconciliation = bool(
        structure
        and checked["summary"] == _summary(checked["cases"], checked["repetitions"])
    )
    if structure and not reconciliation:
        errors.append("benchmark observation summary does not reconcile")
    valid = integrity and structure and reconciliation
    return seal(
        {
            "format": BENCHMARK_OBSERVATIONS_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_execution_receipt": valid,
            "checks": {
                "content_integrity": integrity,
                "closed_case_structure": structure,
                "metric_reconciliation": reconciliation,
            },
            "errors": errors,
            "notice": "This verifies case accounting and metric computation; independent labels, suite provenance, and model/provider evidence remain separately governed.",
        }
    )


def verify_benchmark_observations_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_benchmark_observations(
            load_json(source, label="benchmark observations")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_OBSERVATIONS_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_execution_receipt": False,
                "checks": {
                    "content_integrity": False,
                    "closed_case_structure": False,
                    "metric_reconciliation": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark observation verification failed closed.",
            }
        )


def seal_benchmark_observations(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="benchmark observations")
    value.pop("content_sha256", None)
    value["summary"] = _summary(value["cases"], value["repetitions"])
    result = seal(value)
    if not verify_benchmark_observations(result)["valid"]:
        raise ValueError("benchmark observations are invalid")
    return publish_json(result, destination)


def export_benchmark_observations(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_benchmark_observations(value)["valid"]:
        raise ValueError("benchmark observations are internally invalid")
    return publish_json(value, destination)
