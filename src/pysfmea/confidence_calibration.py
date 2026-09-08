"""Deterministic confidence calibration for benchmarked findings and test proposals."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .model import utc_now

CONFIDENCE_CALIBRATION_FORMAT = "pysfmea-confidence-calibration-1"
CONFIDENCE_CALIBRATION_VERIFICATION_FORMAT = (
    "pysfmea-confidence-calibration-verification-1"
)
MAX_OBSERVATIONS = 1_000_000


def _finite(value: Any, minimum: float = 0, maximum: float = 1) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and minimum <= float(value) <= maximum
    )


def _wilson(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [round(max(0, center - margin), 6), round(min(1, center + margin), 6)]


def _metrics(observations: list[dict[str, Any]], bins: int) -> dict[str, Any]:
    count = len(observations)
    brier = sum(
        (float(item["confidence"]) - int(item["outcome"])) ** 2 for item in observations
    )
    calibration_bins: list[dict[str, Any]] = []
    ece = 0.0
    for index in range(bins):
        lower, upper = index / bins, (index + 1) / bins
        members = [
            item
            for item in observations
            if lower <= float(item["confidence"]) < upper
            or (index == bins - 1 and float(item["confidence"]) == 1)
        ]
        if not members:
            continue
        average = sum(float(item["confidence"]) for item in members) / len(members)
        correct = sum(bool(item["outcome"]) for item in members)
        accuracy = correct / len(members)
        ece += len(members) / count * abs(accuracy - average)
        calibration_bins.append(
            {
                "lower": round(lower, 6),
                "upper": round(upper, 6),
                "count": len(members),
                "mean_confidence": round(average, 6),
                "accuracy": round(accuracy, 6),
                "accuracy_wilson_95": _wilson(correct, len(members)),
            }
        )
    ordered = sorted(
        observations, key=lambda item: (-float(item["confidence"]), item["id"])
    )
    risk_coverage = []
    for retained in sorted({1, len(ordered), *range(10, len(ordered) + 1, 10)}):
        retained = min(retained, len(ordered))
        prefix = ordered[:retained]
        errors = sum(not bool(item["outcome"]) for item in prefix)
        risk_coverage.append(
            {
                "coverage": round(retained / count, 6),
                "retained": retained,
                "threshold": round(float(prefix[-1]["confidence"]), 6),
                "selective_risk": round(errors / retained, 6),
            }
        )
    correct = sum(bool(item["outcome"]) for item in observations)
    return {
        "count": count,
        "accuracy": round(correct / count, 6),
        "accuracy_wilson_95": _wilson(correct, count),
        "brier_score": round(brier / count, 6),
        "expected_calibration_error": round(ece, 6),
        "bins": calibration_bins,
        "risk_coverage": risk_coverage,
    }


def confidence_calibration(
    observations: list[dict[str, Any]],
    *,
    subject_id: str,
    subject_sha256: str,
    authority: str,
    bins: int = 10,
) -> dict[str, Any]:
    if not 2 <= bins <= 100:
        raise ValueError("calibration bins must be between 2 and 100")
    if not observations or len(observations) > MAX_OBSERVATIONS:
        raise ValueError("calibration requires one to 1,000,000 observations")
    normalized: list[dict[str, Any]] = []
    for item in observations:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "confidence",
            "outcome",
            "stratum",
            "evidence_ref",
        }:
            raise ValueError("calibration observation fields are invalid")
        if not _finite(item["confidence"]) or not isinstance(item["outcome"], bool):
            raise ValueError(
                "confidence must be finite in [0,1] and outcome must be boolean"
            )
        normalized.append(
            {
                "id": bounded_text(item["id"], "calibration observation id"),
                "confidence": float(item["confidence"]),
                "outcome": bool(item["outcome"]),
                "stratum": bounded_text(item["stratum"], "calibration stratum"),
                "evidence_ref": bounded_text(
                    item["evidence_ref"], "calibration evidence ref"
                ),
            }
        )
    if len({item["id"] for item in normalized}) != len(normalized):
        raise ValueError("calibration observation ids must be unique")
    if not re.fullmatch(r"[0-9a-f]{64}", subject_sha256):
        raise ValueError("calibration subject digest must be SHA-256")
    strata: set[str] = {str(item["stratum"]) for item in normalized}
    by_stratum = {
        name: _metrics([item for item in normalized if item["stratum"] == name], bins)
        for name in sorted(strata)
    }
    result = seal(
        {
            "format": CONFIDENCE_CALIBRATION_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "calibration authority"),
            "subject": {
                "id": bounded_text(subject_id, "calibration subject id"),
                "content_sha256": subject_sha256,
            },
            "policy": {"bins": bins, "confidence_level": 0.95},
            "observations": normalized,
            "metrics": _metrics(normalized, bins),
            "by_stratum": by_stratum,
            "claim_boundary": "Calibration measures agreement between declared confidence and supplied reviewed outcomes. It does not validate the outcome oracle, sample representativeness, independence, or operational safety.",
        }
    )
    if not verify_confidence_calibration(result)["valid"]:
        raise ValueError("confidence calibration failed internal verification")
    return result


def _structure(value: dict[str, Any]) -> bool:
    try:
        observations = value["observations"]
        bins = value["policy"]["bins"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "subject",
                "policy",
                "observations",
                "metrics",
                "by_stratum",
                "claim_boundary",
                "content_sha256",
            }
            and set(value["subject"]) == {"id", "content_sha256"}
            and bool(re.fullmatch(r"[0-9a-f]{64}", value["subject"]["content_sha256"]))
            and set(value["policy"]) == {"bins", "confidence_level"}
            and 2 <= bins <= 100
            and value["policy"]["confidence_level"] == 0.95
            and isinstance(observations, list)
            and 0 < len(observations) <= MAX_OBSERVATIONS
            and all(
                isinstance(item, dict)
                and set(item)
                == {"id", "confidence", "outcome", "stratum", "evidence_ref"}
                and _finite(item["confidence"])
                and isinstance(item["outcome"], bool)
                and all(
                    isinstance(item[name], str) and item[name]
                    for name in ("id", "stratum", "evidence_ref")
                )
                for item in observations
            )
            and len({item["id"] for item in observations}) == len(observations)
        )
    except (KeyError, TypeError):
        return False


def verify_confidence_calibration(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="confidence calibration",
            format_value=CONFIDENCE_CALIBRATION_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    reconciliation = False
    if structure:
        observations, bins = checked["observations"], checked["policy"]["bins"]
        strata: set[str] = {str(item["stratum"]) for item in observations}
        expected_strata = {
            name: _metrics(
                [item for item in observations if item["stratum"] == name], bins
            )
            for name in sorted(strata)
        }
        reconciliation = (
            checked["metrics"] == _metrics(observations, bins)
            and checked["by_stratum"] == expected_strata
        )
    if not structure:
        errors.append("confidence-calibration fields are invalid")
    if structure and not reconciliation:
        errors.append("confidence-calibration metrics do not reconcile")
    return seal(
        {
            "format": CONFIDENCE_CALIBRATION_VERIFICATION_FORMAT,
            "valid": integrity and structure and reconciliation,
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "metric_and_stratum_reconciliation": reconciliation,
            },
            "errors": errors,
            "notice": "Verification recalculates calibration metrics; it does not establish oracle quality or independence.",
        }
    )


def export_confidence_calibration(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_confidence_calibration(value)["valid"]:
        raise ValueError("confidence calibration is invalid")
    return publish_json(value, destination)


def verify_confidence_calibration_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_confidence_calibration(
            load_json(source, label="confidence calibration")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": CONFIDENCE_CALIBRATION_VERIFICATION_FORMAT,
                "valid": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "metric_and_stratum_reconciliation": False,
                },
                "errors": [str(exc)],
                "notice": "Confidence-calibration verification failed closed.",
            }
        )
