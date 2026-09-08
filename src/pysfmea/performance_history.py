"""Comparable longitudinal scanner-performance evidence and release ratchets."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now

PERFORMANCE_HISTORY_FORMAT = "pysfmea-performance-history-1"
PERFORMANCE_HISTORY_VERIFICATION_FORMAT = "pysfmea-performance-history-verification-1"
PERFORMANCE_RECEIPT_FORMAT = "pysfmea-scan-performance-2"
MAX_RECEIPTS = 1_000


def _performance_receipt(source: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    document = load_bounded_json_document(
        source,
        label="performance receipt",
        max_bytes=64 * 1024 * 1024,
        max_depth=100,
        max_nodes=2_000_000,
    )
    value = document.value
    if not isinstance(value, dict) or value.get("format") != PERFORMANCE_RECEIPT_FORMAT:
        raise ValueError("performance receipt format is invalid")
    unsigned = dict(value)
    claimed = unsigned.pop("content_sha256", "")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", str(claimed))
        or canonical_json_sha256(unsigned) != claimed
    ):
        raise ValueError("performance receipt content digest does not match")
    generated_at = bounded_text(
        value.get("generated_at", ""), "performance receipt generated time"
    )
    environment = value.get("environment")
    repository = value.get("repository")
    summary = value.get("summary")
    tool = value.get("tool")
    measurement_policy = value.get("measurement_policy")
    if not isinstance(environment, dict):
        raise ValueError("performance receipt environment is invalid")
    if not isinstance(repository, dict):
        raise ValueError("performance receipt repository is invalid")
    if not isinstance(summary, dict):
        raise ValueError("performance receipt summary is invalid")
    if not isinstance(tool, dict):
        raise ValueError("performance receipt core fields are invalid")
    if measurement_policy is None:
        measurement_policy = {
            "legacy_receipt": True,
            "warmup_runs": 0,
            "process_model": "unspecified",
            "process_isolation": False,
        }
    if not isinstance(measurement_policy, dict):
        raise ValueError("performance receipt measurement policy is invalid")
    baseline_ids = repository.get("baseline_ids")
    if (
        not isinstance(baseline_ids, list)
        or len(baseline_ids) != 1
        or not baseline_ids[0]
    ):
        raise ValueError("performance receipt must bind one stable repository baseline")
    comparable_environment = {
        name: environment.get(name)
        for name in (
            "python",
            "implementation",
            "platform",
            "machine",
            "processor",
            "logical_cpu_count",
        )
    }
    population = {
        name: repository.get(name)
        for name in (
            "inventory_files",
            "inventory_bytes",
            "source_snapshot_files",
            "source_snapshot_bytes",
            "components",
            "candidates",
        )
    }
    for name in ("median_seconds", "p95_seconds", "maximum_peak_traced_bytes"):
        if (
            not isinstance(summary.get(name), (int, float))
            or isinstance(summary.get(name), bool)
            or summary[name] < 0
        ):
            raise ValueError(f"performance receipt {name} is invalid")
    source_binding = {
        "reference": str(document.path),
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "content_sha256": claimed,
    }
    observation = {
        "generated_at": generated_at,
        "tool_version": bounded_text(
            tool.get("version", ""), "performance tool version"
        ),
        "repository_baseline_id": str(baseline_ids[0]),
        "environment": comparable_environment,
        "population": population,
        "median_seconds": float(summary["median_seconds"]),
        "p95_seconds": float(summary["p95_seconds"]),
        "maximum_peak_traced_bytes": int(summary["maximum_peak_traced_bytes"]),
        "maximum_process_peak_rss_bytes": summary.get("maximum_process_peak_rss_bytes"),
        "coefficient_of_variation_percent": float(
            summary.get("coefficient_of_variation_percent", 0.0)
        ),
        "fact_reuse_enabled": bool(summary.get("fact_reuse_enabled", False)),
        "measurement_policy": measurement_policy,
        "source": source_binding,
    }
    return value, observation


def _percent_change(current: float, baseline: float) -> float:
    if baseline == 0:
        return 0.0 if current == 0 else 100.0
    return round((current - baseline) / baseline * 100.0, 3)


def performance_history(
    receipts: Iterable[str | Path],
    *,
    authority: str,
    maximum_runtime_regression_percent: float = 10.0,
    maximum_memory_regression_percent: float = 10.0,
    minimum_observations: int = 3,
) -> dict[str, Any]:
    paths = list(receipts)
    if not 2 <= len(paths) <= MAX_RECEIPTS:
        raise ValueError(
            f"performance history requires between 2 and {MAX_RECEIPTS} receipts"
        )
    if (
        not isinstance(minimum_observations, int)
        or isinstance(minimum_observations, bool)
        or minimum_observations < 2
    ):
        raise ValueError("minimum performance observations must be at least two")
    for label, value in (
        ("runtime", maximum_runtime_regression_percent),
        ("memory", maximum_memory_regression_percent),
    ):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"maximum {label} regression must be non-negative")
    observations = [_performance_receipt(path)[1] for path in paths]
    observations.sort(key=lambda item: (item["generated_at"], item["source"]["sha256"]))
    environments = {canonical_json_sha256(item["environment"]) for item in observations}
    populations = {canonical_json_sha256(item["population"]) for item in observations}
    baselines = {item["repository_baseline_id"] for item in observations}
    reuse_modes = {item["fact_reuse_enabled"] for item in observations}
    policies = {
        canonical_json_sha256(item["measurement_policy"]) for item in observations
    }
    comparable = (
        len(environments)
        == len(populations)
        == len(baselines)
        == len(reuse_modes)
        == len(policies)
        == 1
    )
    baseline = observations[0]
    current = observations[-1]
    runtime_change = _percent_change(
        current["median_seconds"], baseline["median_seconds"]
    )
    memory_change = _percent_change(
        float(current["maximum_peak_traced_bytes"]),
        float(baseline["maximum_peak_traced_bytes"]),
    )
    checks = {
        "minimum_observations": len(observations) >= minimum_observations,
        "comparable_environment_and_population": comparable,
        "runtime_regression": runtime_change <= maximum_runtime_regression_percent,
        "memory_regression": memory_change <= maximum_memory_regression_percent,
    }
    return seal(
        {
            "format": PERFORMANCE_HISTORY_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "performance history authority"),
            "policy": {
                "minimum_observations": minimum_observations,
                "maximum_runtime_regression_percent": float(
                    maximum_runtime_regression_percent
                ),
                "maximum_memory_regression_percent": float(
                    maximum_memory_regression_percent
                ),
                "comparison_basis": "first-to-latest exact comparable receipt",
            },
            "observations": observations,
            "comparison": {
                "baseline_content_sha256": baseline["source"]["content_sha256"],
                "current_content_sha256": current["source"]["content_sha256"],
                "runtime_change_percent": runtime_change,
                "memory_change_percent": memory_change,
            },
            "checks": checks,
            "summary": {
                "observations": len(observations),
                "comparable": comparable,
                "passed": all(checks.values()),
            },
            "notice": "A passing history establishes non-regression only for the exact repository population, environment, measurement policy, and cache mode represented by its bound receipts.",
        }
    )


def verify_performance_history(
    value: dict[str, Any], *, receipts: Iterable[str | Path] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    valid = False
    passed = False
    try:
        checked = verify_seal(
            value, label="performance history", format_value=PERFORMANCE_HISTORY_FORMAT
        )
        expected = {
            "format",
            "generated_at",
            "authority",
            "policy",
            "observations",
            "comparison",
            "checks",
            "summary",
            "notice",
            "content_sha256",
        }
        if set(checked) != expected:
            raise ValueError("performance history fields are invalid")
        policy = checked["policy"]
        if not isinstance(policy, dict) or set(policy) != {
            "minimum_observations",
            "maximum_runtime_regression_percent",
            "maximum_memory_regression_percent",
            "comparison_basis",
        }:
            raise ValueError("performance history policy is invalid")
        if (
            not isinstance(policy["minimum_observations"], int)
            or isinstance(policy["minimum_observations"], bool)
            or policy["minimum_observations"] < 2
            or policy["comparison_basis"] != "first-to-latest exact comparable receipt"
        ):
            raise ValueError("performance history policy semantics are invalid")
        for name in (
            "maximum_runtime_regression_percent",
            "maximum_memory_regression_percent",
        ):
            if (
                not isinstance(policy[name], (int, float))
                or isinstance(policy[name], bool)
                or policy[name] < 0
            ):
                raise ValueError("performance history regression threshold is invalid")
        observations = checked["observations"]
        if (
            not isinstance(observations, list)
            or not 2 <= len(observations) <= MAX_RECEIPTS
        ):
            raise ValueError("performance history observation population is invalid")
        source_hashes = [
            item.get("source", {}).get("sha256")
            for item in observations
            if isinstance(item, dict)
        ]
        if (
            len(source_hashes) != len(observations)
            or len(source_hashes) != len(set(source_hashes))
            or not all(
                re.fullmatch(r"[0-9a-f]{64}", str(item)) for item in source_hashes
            )
        ):
            raise ValueError(
                "performance history source bindings are invalid or duplicated"
            )
        if receipts is not None:
            supplied = [_performance_receipt(path)[1] for path in receipts]
            supplied.sort(
                key=lambda item: (item["generated_at"], item["source"]["sha256"])
            )
            if supplied != observations:
                raise ValueError(
                    "performance history does not bind the exact supplied receipts"
                )
        environments = {
            canonical_json_sha256(item["environment"]) for item in observations
        }
        populations = {
            canonical_json_sha256(item["population"]) for item in observations
        }
        baselines = {item["repository_baseline_id"] for item in observations}
        reuse_modes = {item["fact_reuse_enabled"] for item in observations}
        policies = {
            canonical_json_sha256(item["measurement_policy"]) for item in observations
        }
        comparable = (
            len(environments)
            == len(populations)
            == len(baselines)
            == len(reuse_modes)
            == len(policies)
            == 1
        )
        baseline = observations[0]
        current = observations[-1]
        runtime_change = _percent_change(
            float(current["median_seconds"]), float(baseline["median_seconds"])
        )
        memory_change = _percent_change(
            float(current["maximum_peak_traced_bytes"]),
            float(baseline["maximum_peak_traced_bytes"]),
        )
        expected_comparison = {
            "baseline_content_sha256": baseline["source"]["content_sha256"],
            "current_content_sha256": current["source"]["content_sha256"],
            "runtime_change_percent": runtime_change,
            "memory_change_percent": memory_change,
        }
        if checked["comparison"] != expected_comparison:
            raise ValueError("performance history comparison does not reconcile")
        expected_checks = {
            "minimum_observations",
            "comparable_environment_and_population",
            "runtime_regression",
            "memory_regression",
        }
        checks = checked["checks"]
        if (
            not isinstance(checks, dict)
            or set(checks) != expected_checks
            or not all(type(item) is bool for item in checks.values())
        ):
            raise ValueError("performance history checks are invalid")
        recomputed_checks = {
            "minimum_observations": len(observations) >= policy["minimum_observations"],
            "comparable_environment_and_population": comparable,
            "runtime_regression": runtime_change
            <= policy["maximum_runtime_regression_percent"],
            "memory_regression": memory_change
            <= policy["maximum_memory_regression_percent"],
        }
        if checks != recomputed_checks:
            raise ValueError("performance history checks do not reconcile")
        passed = all(checks.values())
        if checked["summary"] != {
            "observations": len(observations),
            "comparable": checks["comparable_environment_and_population"],
            "passed": passed,
        }:
            raise ValueError("performance history summary does not reconcile")
        valid = True
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
    return seal(
        {
            "format": PERFORMANCE_HISTORY_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_release_gate": valid and passed,
            "checks": {
                "content_integrity_and_structure": valid,
                "policy_passed": valid and passed,
            },
            "errors": errors,
            "notice": "Verification confirms history integrity and declared non-regression policy only.",
        }
    )


def export_performance_history(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_performance_history(value)["valid"]:
        raise ValueError("performance history is invalid")
    return publish_json(value, destination)


def verify_performance_history_file(
    source: str | Path, *, receipts: Iterable[str | Path] | None = None
) -> dict[str, Any]:
    try:
        value = load_bounded_json_document(
            source,
            label="performance history",
            max_bytes=64 * 1024 * 1024,
            max_depth=100,
            max_nodes=2_000_000,
        ).value
        if not isinstance(value, dict):
            raise ValueError("performance history root must be an object")
        return verify_performance_history(value, receipts=receipts)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": PERFORMANCE_HISTORY_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_release_gate": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "policy_passed": False,
                },
                "errors": [str(exc)],
                "notice": "Performance-history verification failed closed.",
            }
        )
