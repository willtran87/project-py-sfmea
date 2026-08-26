"""Data-model helpers kept deliberately dependency-free."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "0.6"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def preserve_unchanged_generated_at(
    previous: object, current: dict[str, object]
) -> dict[str, object]:
    """Keep derived-artifact provenance stable when its governed content is unchanged."""

    if not isinstance(previous, dict):
        return current
    previous_generated_at = previous.get("generated_at")
    if not isinstance(previous_generated_at, str) or not previous_generated_at:
        return current
    previous_content = {
        key: value for key, value in previous.items() if key != "generated_at"
    }
    current_content = {
        key: value for key, value in current.items() if key != "generated_at"
    }
    if previous_content == current_content:
        current["generated_at"] = previous_generated_at
    return current


def stable_id(prefix: str, *parts: str, size: int = 12) -> str:
    material = "\x1f".join(parts).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:size].upper()
    return f"{prefix}-{digest}"


def empty_review() -> dict[str, Any]:
    """Fields owned by the reviewer and preserved across rescans."""

    return {
        "disposition": "unreviewed",
        "disposition_rationale": "",
        "status": "draft",
        "requirement": "",
        "linked_hazards": [],
        "function": "",
        "failure_mode": "",
        "trigger": "",
        "operational_mode": "",
        "operational_state": "",
        "required_safe_state": "",
        "degraded_behavior": "",
        "recovery_behavior": "",
        "causes": [],
        "local_effect": "",
        "next_higher_effect": "",
        "end_effect": "",
        "severity": None,
        "severity_category": "",
        "severity_rationale": "",
        "occurrence": None,
        "occurrence_rationale": "",
        "detection": None,
        "detection_rationale": "",
        "prevention_controls": [],
        "detection_controls": [],
        "recommended_actions": [],
        "actions_taken": [],
        "verification_evidence": [],
        "post_action_severity": None,
        "post_action_severity_category": "",
        "post_action_severity_rationale": "",
        "post_action_occurrence": None,
        "post_action_occurrence_rationale": "",
        "post_action_detection": None,
        "post_action_detection_rationale": "",
        "residual_risk": "",
        "owner": "",
        "target_date": "",
        "approved_by": "",
        "approval_date": "",
        "reviewer": "",
        "revalidation_required": False,
        "validated_fingerprint": "",
        "validated_context_fingerprint": "",
        "validated_analysis_context_fingerprint": "",
        "validated_baseline_id": "",
        "validated_at": "",
        "notes": "",
    }


def calculate_rpn(item: dict[str, Any], *, post_action: bool = False) -> int | None:
    review = item.get("review", {})
    prefix = "post_action_" if post_action else ""
    values = [
        review.get(prefix + "severity"),
        review.get(prefix + "occurrence"),
        review.get(prefix + "detection"),
    ]
    if all(
        isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 10
        for value in values
    ):
        return int(values[0]) * int(values[1]) * int(values[2])
    return None


def validate_rating(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("ratings must be blank or an integer from 1 through 10")
    rating = int(value)
    if not 1 <= rating <= 10:
        raise ValueError("ratings must be blank or an integer from 1 through 10")
    return rating
