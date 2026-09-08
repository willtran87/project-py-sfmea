"""NIST SP 500-268/270-style source-analysis evaluation evidence."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .model import utc_now

SAMATE_SOURCE_FORMAT = "pysfmea-samate-assessment-source-1"
SAMATE_ASSESSMENT_FORMAT = "pysfmea-samate-assessment-1"
SAMATE_VERIFICATION_FORMAT = "pysfmea-samate-assessment-verification-1"
LABELS = {"positive", "negative"}


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value))
        and value != "0" * 64
    )


def _capability(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {
            "languages",
            "weakness_classes",
            "input_forms",
            "output_semantics",
            "environment",
            "limitations",
        }
        and isinstance(value["languages"], list)
        and 0 < len(value["languages"]) <= 100
        and all(isinstance(item, str) and item.strip() for item in value["languages"])
        and isinstance(value["weakness_classes"], list)
        and len(value["weakness_classes"]) <= 10_000
        and all(
            isinstance(item, str) and item.strip() for item in value["weakness_classes"]
        )
        and isinstance(value["input_forms"], list)
        and 0 < len(value["input_forms"]) <= 100
        and all(isinstance(item, str) and item.strip() for item in value["input_forms"])
        and isinstance(value["output_semantics"], str)
        and bool(value["output_semantics"].strip())
        and isinstance(value["environment"], str)
        and isinstance(value["limitations"], list)
        and len(value["limitations"]) <= 1_000
        and all(isinstance(item, str) and item.strip() for item in value["limitations"])
    )


def _plan(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {
            "suite_id",
            "suite_revision",
            "suite_sha256",
            "tool_version",
            "tool_sha256",
            "normalization_policy_ref",
            "exclusion_policy",
            "pre_registration_ref",
        }
        and all(isinstance(value[name], str) for name in value)
        and len(value["suite_sha256"]) == 64
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["suite_sha256"]))
        and len(value["tool_sha256"]) == 64
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["tool_sha256"]))
    )


def _governance(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {
            "protocol_owner",
            "execution_operator",
            "label_authority",
            "approval_authority",
            "independence_basis",
        }
        and all(isinstance(item, str) and item.strip() for item in value.values())
    )


def _source_structure(value: dict[str, Any]) -> bool:
    required = {
        "format",
        "generated_at",
        "authority",
        "capability_claim",
        "test_plan",
        "governance",
        "cases",
        "claim_boundary",
        "content_sha256",
    }
    if (
        set(value) != required
        or not isinstance(value.get("cases"), list)
        or len(value["cases"]) > 1_000_000
    ):
        return False
    if (
        not _capability(value["capability_claim"])
        or not _plan(value["test_plan"])
        or not _governance(value["governance"])
    ):
        return False
    try:
        for item in value["cases"]:
            if not isinstance(item, dict):
                return False
            _case(item)
    except (TypeError, ValueError):
        return False
    identifiers = [item["id"] for item in value["cases"]]
    return len(identifiers) == len(set(identifiers))


def samate_source_template(*, authority: str) -> dict[str, Any]:
    return seal(
        {
            "format": SAMATE_SOURCE_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "SAMATE source authority"),
            "capability_claim": {
                "languages": ["Python"],
                "weakness_classes": [],
                "input_forms": ["Python source"],
                "output_semantics": "Candidate findings with source coordinates, rule identity, confidence, evidence, and claim limitations.",
                "environment": "unassigned",
                "limitations": [],
            },
            "test_plan": {
                "suite_id": "unassigned",
                "suite_revision": "unassigned",
                "suite_sha256": "0" * 64,
                "tool_version": "unassigned",
                "tool_sha256": "0" * 64,
                "normalization_policy_ref": "unassigned",
                "exclusion_policy": "unassigned",
                "pre_registration_ref": "unassigned",
            },
            "governance": {
                "protocol_owner": authority,
                "execution_operator": "unassigned",
                "label_authority": "unassigned",
                "approval_authority": "unassigned",
                "independence_basis": "unassigned",
            },
            "cases": [],
            "claim_boundary": "Populate exact suite, tool, labels, locations, evidence, exclusions, and distinct authorities before assessment. This template is not a completed NIST evaluation.",
        }
    )


def _case(value: dict[str, Any]) -> None:
    fields = {
        "id",
        "weakness_id",
        "expected_label",
        "predicted_label",
        "expected_locations",
        "reported_locations",
        "excluded",
        "exclusion_rationale",
        "input_evidence_ref",
        "label_evidence_ref",
        "output_evidence_ref",
    }
    if (
        set(value) != fields
        or value["expected_label"] not in LABELS
        or value["predicted_label"] not in LABELS
    ):
        raise ValueError("SAMATE case fields or labels are invalid")
    for name in (
        "id",
        "weakness_id",
        "input_evidence_ref",
        "label_evidence_ref",
        "output_evidence_ref",
    ):
        bounded_text(value[name], f"SAMATE case {name}")
    for name in ("expected_locations", "reported_locations"):
        if (
            not isinstance(value[name], list)
            or len(value[name]) > 10_000
            or not all(isinstance(item, str) and item.strip() for item in value[name])
        ):
            raise ValueError(f"SAMATE case {name} is invalid")
    if (
        not isinstance(value["excluded"], bool)
        or not isinstance(value["exclusion_rationale"], str)
        or (value["excluded"] and not value["exclusion_rationale"].strip())
    ):
        raise ValueError("SAMATE case exclusion accounting is invalid")


def _interval(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def _metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    included = [item for item in cases if not item["excluded"]]
    tp = sum(
        item["expected_label"] == item["predicted_label"] == "positive"
        for item in included
    )
    tn = sum(
        item["expected_label"] == item["predicted_label"] == "negative"
        for item in included
    )
    fp = sum(
        item["expected_label"] == "negative" and item["predicted_label"] == "positive"
        for item in included
    )
    fn = sum(
        item["expected_label"] == "positive" and item["predicted_label"] == "negative"
        for item in included
    )
    localized = sum(
        item["expected_locations"]
        and bool(set(item["expected_locations"]) & set(item["reported_locations"]))
        for item in included
        if item["expected_label"] == "positive"
    )
    positives = tp + fn
    precision_total = tp + fp
    return {
        "population": len(cases),
        "included": len(included),
        "excluded": len(cases) - len(included),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "precision": round(tp / precision_total, 6) if precision_total else None,
        "recall": round(tp / positives, 6) if positives else None,
        "specificity": round(tn / (tn + fp), 6) if tn + fp else None,
        "recall_95_percent_wilson": _interval(tp, positives),
        "precision_95_percent_wilson": _interval(tp, precision_total),
        "positive_localization_rate": round(localized / positives, 6)
        if positives
        else None,
    }


def _complete_source(value: dict[str, Any]) -> bool:
    if not _source_structure(value):
        return False
    plan = value["test_plan"]
    governance = value["governance"]
    roles = [
        governance[name]
        for name in (
            "protocol_owner",
            "execution_operator",
            "label_authority",
            "approval_authority",
        )
    ]
    return bool(
        value["cases"]
        and value["capability_claim"]["weakness_classes"]
        and all(
            plan[name] != "unassigned"
            for name in (
                "suite_id",
                "suite_revision",
                "tool_version",
                "normalization_policy_ref",
                "exclusion_policy",
                "pre_registration_ref",
            )
        )
        and all(_digest(plan[name]) for name in ("suite_sha256", "tool_sha256"))
        and all(role != "unassigned" for role in roles)
        and len(set(roles)) == len(roles)
        and governance["independence_basis"] != "unassigned"
    )


def samate_assessment(source: dict[str, Any]) -> dict[str, Any]:
    checked = verify_seal(
        source, label="SAMATE source", format_value=SAMATE_SOURCE_FORMAT
    )
    if not _source_structure(checked):
        raise ValueError(
            "SAMATE source structure, fields, cases, or identities are invalid"
        )
    weakness = {
        key: _metrics([item for item in checked["cases"] if item["weakness_id"] == key])
        for key in sorted({item["weakness_id"] for item in checked["cases"]})
    }
    result = seal(
        {
            "format": SAMATE_ASSESSMENT_FORMAT,
            "generated_at": utc_now(),
            "source_sha256": checked["content_sha256"],
            "capability_claim": checked["capability_claim"],
            "test_plan": checked["test_plan"],
            "governance": checked["governance"],
            "metrics": _metrics(checked["cases"]),
            "by_weakness": weakness,
            "case_ledger": checked["cases"],
            "eligible_for_external_conclusion": _complete_source(checked),
            "claim_boundary": "Metrics follow the supplied SP 500-268 capability claim and SP 500-270-style test plan. Eligibility means the evidence package is complete enough for external review; it does not authenticate labels, establish representativeness, qualify the tool, or grant NIST endorsement or certification.",
        }
    )
    if not verify_samate_assessment(result)["valid"]:
        raise ValueError("SAMATE assessment failed internal verification")
    return result


def verify_samate_assessment(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    integrity = structure = reconciliation = False
    try:
        checked = verify_seal(
            value, label="SAMATE assessment", format_value=SAMATE_ASSESSMENT_FORMAT
        )
        required = {
            "format",
            "generated_at",
            "source_sha256",
            "capability_claim",
            "test_plan",
            "governance",
            "metrics",
            "by_weakness",
            "case_ledger",
            "eligible_for_external_conclusion",
            "claim_boundary",
            "content_sha256",
        }
        if (
            set(checked) != required
            or not _digest(checked["source_sha256"])
            or not isinstance(checked["case_ledger"], list)
            or not _capability(checked["capability_claim"])
            or not _plan(checked["test_plan"])
            or not _governance(checked["governance"])
        ):
            raise ValueError("SAMATE assessment fields are invalid")
        for item in checked["case_ledger"]:
            _case(item)
        expected_by = {
            key: _metrics(
                [item for item in checked["case_ledger"] if item["weakness_id"] == key]
            )
            for key in sorted({item["weakness_id"] for item in checked["case_ledger"]})
        }
        eligibility = bool(
            checked["case_ledger"]
            and checked["capability_claim"]["weakness_classes"]
            and all(
                checked["test_plan"][name] != "unassigned"
                for name in (
                    "suite_id",
                    "suite_revision",
                    "tool_version",
                    "normalization_policy_ref",
                    "exclusion_policy",
                    "pre_registration_ref",
                )
            )
            and all(
                _digest(checked["test_plan"][name])
                for name in ("suite_sha256", "tool_sha256")
            )
            and len(
                set(
                    checked["governance"][name]
                    for name in (
                        "protocol_owner",
                        "execution_operator",
                        "label_authority",
                        "approval_authority",
                    )
                )
            )
            == 4
            and all(
                checked["governance"][name] != "unassigned"
                for name in (
                    "protocol_owner",
                    "execution_operator",
                    "label_authority",
                    "approval_authority",
                    "independence_basis",
                )
            )
        )
        reconciliation = (
            checked["metrics"] == _metrics(checked["case_ledger"])
            and checked["by_weakness"] == expected_by
            and checked["eligible_for_external_conclusion"] is eligibility
        )
        if not reconciliation:
            errors.append("SAMATE metrics do not reconcile to the case ledger")
        integrity = structure = True
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
    valid = integrity and structure and reconciliation and not errors
    return seal(
        {
            "format": SAMATE_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_external_conclusion": bool(
                valid and value.get("eligible_for_external_conclusion")
            ),
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "case_and_metric_reconciliation": reconciliation,
            },
            "errors": errors,
            "notice": "Verification establishes deterministic evaluation accounting, not label truth, laboratory independence, qualification, endorsement, or certification.",
        }
    )


def seal_samate_source(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="SAMATE source")
    value.pop("content_sha256", None)
    result = seal(value)
    samate_assessment(result)
    return publish_json(result, destination)


def export_samate_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def verify_samate_assessment_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_samate_assessment(load_json(source, label="SAMATE assessment"))
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": SAMATE_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_external_conclusion": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "case_and_metric_reconciliation": False,
                },
                "errors": [str(exc)],
                "notice": "SAMATE assessment verification failed closed.",
            }
        )
