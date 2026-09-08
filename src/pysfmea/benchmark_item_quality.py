"""Independent, case-level quality audits for governed benchmark populations."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .benchmark_case_inventory import (
    BENCHMARK_CASE_INVENTORY_FORMAT,
    verify_benchmark_case_inventory,
)
from .benchmark_native import verify_native_benchmark
from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_json_document
from .model import utc_now

BENCHMARK_ITEM_QUALITY_FORMAT = "pysfmea-benchmark-item-quality-1"
BENCHMARK_ITEM_QUALITY_VERIFICATION_FORMAT = (
    "pysfmea-benchmark-item-quality-verification-1"
)
MAX_BYTES = 100 * 1024 * 1024
DISPOSITIONS = {"accepted", "excluded", "remediation_required"}
CRITERION_STATUSES = {"pass", "fail", "not_applicable"}
CRITERIA = (
    "requirements_complete",
    "oracle_valid",
    "hidden_tests_reasonable",
    "coverage_adequate",
    "mutation_adequate",
    "harness_reproducible",
    "ambiguity_resolved",
    "gold_patch_valid",
    "regression_tests_valid",
)
CORE_CRITERIA = {
    "requirements_complete",
    "oracle_valid",
    "hidden_tests_reasonable",
    "harness_reproducible",
    "ambiguity_resolved",
}


def _document(source: str | Path, label: str) -> tuple[Any, dict[str, Any]]:
    document = load_bounded_json_document(
        Path(source).expanduser().resolve(),
        label=label,
        max_bytes=MAX_BYTES,
        max_depth=160,
        max_nodes=3_000_000,
    )
    return document.value, {
        "name": Path(source).name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "content_sha256": (
            str(document.value.get("content_sha256", ""))
            if isinstance(document.value, dict)
            else ""
        ),
    }


def _review_item(value: dict[str, Any], authority: str) -> dict[str, Any]:
    case_id = bounded_text(value.get("case_id"), "benchmark audit case id")
    disposition = str(value.get("disposition", "")).strip()
    if disposition not in DISPOSITIONS:
        raise ValueError(f"{case_id}: benchmark audit disposition is invalid")
    criteria = value.get("criteria")
    if not isinstance(criteria, dict) or set(criteria) != set(CRITERIA):
        raise ValueError(f"{case_id}: benchmark audit criteria must be complete")
    normalized_criteria = {}
    for name in CRITERIA:
        criterion = criteria[name]
        if not isinstance(criterion, dict) or set(criterion) != {
            "status",
            "rationale",
            "evidence_refs",
        }:
            raise ValueError(f"{case_id}: {name} criterion is invalid")
        status = str(criterion.get("status", "")).strip()
        if status not in CRITERION_STATUSES:
            raise ValueError(f"{case_id}: {name} status is invalid")
        rationale = bounded_text(
            criterion.get("rationale"), f"{case_id} {name} rationale"
        )
        refs = criterion.get("evidence_refs")
        if (
            not isinstance(refs, list)
            or not refs
            or len(refs) > 100
            or not all(isinstance(item, str) and item.strip() for item in refs)
        ):
            raise ValueError(f"{case_id}: {name} requires evidence references")
        normalized_criteria[name] = {
            "status": status,
            "rationale": rationale,
            "evidence_refs": list(dict.fromkeys(item.strip() for item in refs)),
        }
    reviewers = value.get("reviewers")
    if (
        not isinstance(reviewers, list)
        or len(reviewers) < 2
        or len(reviewers) > 20
        or not all(isinstance(item, str) and item.strip() for item in reviewers)
    ):
        raise ValueError(f"{case_id}: at least two reviewers are required")
    reviewer_values = list(dict.fromkeys(item.strip() for item in reviewers))
    if len(reviewer_values) < 2:
        raise ValueError(f"{case_id}: reviewers must be distinct")
    if authority.casefold() in {item.casefold() for item in reviewer_values}:
        raise ValueError(f"{case_id}: audit authority cannot review its own items")
    exclusion_reason = bounded_text(
        value.get("exclusion_reason", ""),
        f"{case_id} exclusion reason",
        allow_empty=True,
    )
    if disposition == "excluded" and not exclusion_reason:
        raise ValueError(f"{case_id}: excluded items require a reason")
    notes = bounded_text(
        value.get("notes", ""), f"{case_id} audit notes", allow_empty=True
    )
    statuses = {name: item["status"] for name, item in normalized_criteria.items()}
    criteria_passed = bool(
        all(statuses[name] == "pass" for name in CORE_CRITERIA)
        and "fail" not in statuses.values()
    )
    if disposition == "accepted" and not criteria_passed:
        raise ValueError(f"{case_id}: accepted item does not pass its quality criteria")
    if disposition == "remediation_required" and "fail" not in statuses.values():
        raise ValueError(
            f"{case_id}: remediation requires at least one failed criterion"
        )
    return {
        "case_id": case_id,
        "disposition": disposition,
        "criteria": normalized_criteria,
        "criteria_passed": criteria_passed,
        "reviewers": reviewer_values,
        "exclusion_reason": exclusion_reason,
        "notes": notes,
    }


def benchmark_item_quality_audit(
    normalization_source: str | Path,
    reviews_source: str | Path,
    *,
    authority: str,
    max_exclusion_rate: float = 0.05,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Audit every normalized benchmark case without manufacturing review evidence."""

    if not isinstance(max_exclusion_rate, (int, float)) or isinstance(
        max_exclusion_rate, bool
    ):
        raise TypeError("maximum exclusion rate must be numeric")
    max_exclusion_rate = float(max_exclusion_rate)
    if not 0 <= max_exclusion_rate <= 1:
        raise ValueError("maximum exclusion rate must be between zero and one")
    normalization, normalization_binding = _document(
        normalization_source, "benchmark case population"
    )
    population_valid = False
    if isinstance(normalization, dict):
        if normalization.get("format") == BENCHMARK_CASE_INVENTORY_FORMAT:
            population_valid = verify_benchmark_case_inventory(normalization)[
                "eligible_for_item_review"
            ]
        else:
            population_valid = verify_native_benchmark(normalization)[
                "eligible_for_observation_join"
            ]
    if not population_valid:
        raise ValueError("benchmark case population is invalid")
    review_document, review_binding = _document(
        reviews_source, "benchmark item reviews"
    )
    reviews = (
        review_document.get("reviews")
        if isinstance(review_document, dict)
        else review_document
    )
    if not isinstance(reviews, list) or not reviews:
        raise ValueError("benchmark item reviews must be a non-empty array")
    owner = bounded_text(authority, "benchmark item-quality authority")
    items = [_review_item(item, owner) for item in reviews if isinstance(item, dict)]
    if len(items) != len(reviews):
        raise ValueError("every benchmark review must be an object")
    source_ids = [item["case_id"] for item in normalization["cases"]]
    review_ids = [item["case_id"] for item in items]
    if len(set(review_ids)) != len(review_ids) or set(source_ids) != set(review_ids):
        raise ValueError("benchmark reviews must exactly account for normalized cases")
    ordered = {item["case_id"]: item for item in items}
    items = [ordered[case_id] for case_id in source_ids]
    accepted = sum(item["disposition"] == "accepted" for item in items)
    excluded = sum(item["disposition"] == "excluded" for item in items)
    remediation = sum(item["disposition"] == "remediation_required" for item in items)
    exclusion_rate = excluded / len(items)
    passed = bool(
        accepted > 0
        and remediation == 0
        and accepted + excluded == len(items)
        and exclusion_rate <= max_exclusion_rate
    )
    result = seal(
        {
            "format": BENCHMARK_ITEM_QUALITY_FORMAT,
            "generated_at": generated_at or utc_now(),
            "authority": owner,
            "suite": dict(normalization["suite"]),
            "policy": {
                "minimum_reviewers": 2,
                "max_exclusion_rate": max_exclusion_rate,
                "required_core_criteria": sorted(CORE_CRITERIA),
                "population_accounting": "exact",
            },
            "sources": {
                "normalization": normalization_binding,
                "reviews": review_binding,
            },
            "items": items,
            "summary": {
                "items": len(items),
                "accepted": accepted,
                "excluded": excluded,
                "remediation_required": remediation,
                "exclusion_rate": exclusion_rate,
                "passed": passed,
            },
            "claim_boundary": (
                "Passing establishes complete, independently reviewed case-quality accounting "
                "for the exact normalized population. It does not prove reviewer competence, "
                "ground-truth correctness, representativeness, benchmark execution, or tool qualification. "
                "The population may be a native-result normalization or an exact governed case inventory."
            ),
        }
    )
    if not verify_benchmark_item_quality(result)["valid"]:
        raise ValueError("benchmark item-quality audit failed internal verification")
    return result


def _digest(value: Any, *, allow_empty: bool = False) -> bool:
    return bool(
        isinstance(value, str)
        and ((allow_empty and not value) or re.fullmatch(r"[0-9a-f]{64}", value))
    )


def _binding(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == {"name", "bytes", "sha256", "content_sha256"}
        and isinstance(value["name"], str)
        and bool(value["name"])
        and isinstance(value["bytes"], int)
        and not isinstance(value["bytes"], bool)
        and value["bytes"] > 0
        and _digest(value["sha256"])
        and _digest(value["content_sha256"], allow_empty=True)
    )


def _structure(value: dict[str, Any]) -> bool:
    try:
        items = value["items"]
        summary = value["summary"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "suite",
                "policy",
                "sources",
                "items",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and isinstance(value["generated_at"], str)
            and bool(value["generated_at"])
            and isinstance(value["authority"], str)
            and bool(value["authority"])
            and set(value["suite"]) == {"id", "revision", "adapter_mode"}
            and set(value["policy"])
            == {
                "minimum_reviewers",
                "max_exclusion_rate",
                "required_core_criteria",
                "population_accounting",
            }
            and value["policy"]["minimum_reviewers"] == 2
            and value["policy"]["required_core_criteria"] == sorted(CORE_CRITERIA)
            and value["policy"]["population_accounting"] == "exact"
            and isinstance(value["policy"]["max_exclusion_rate"], (int, float))
            and 0 <= value["policy"]["max_exclusion_rate"] <= 1
            and set(value["sources"]) == {"normalization", "reviews"}
            and all(_binding(item) for item in value["sources"].values())
            and isinstance(items, list)
            and bool(items)
            and len({item.get("case_id") for item in items}) == len(items)
            and all(_item_structure(item, value["authority"]) for item in items)
            and summary == _summary(items, value["policy"]["max_exclusion_rate"])
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"])
        )
    except (KeyError, TypeError):
        return False


def _item_structure(item: Any, authority: str) -> bool:
    if not isinstance(item, dict) or set(item) != {
        "case_id",
        "disposition",
        "criteria",
        "criteria_passed",
        "reviewers",
        "exclusion_reason",
        "notes",
    }:
        return False
    criteria = item["criteria"]
    statuses = {}
    valid = bool(
        isinstance(item["case_id"], str)
        and bool(item["case_id"])
        and item["disposition"] in DISPOSITIONS
        and isinstance(criteria, dict)
        and set(criteria) == set(CRITERIA)
        and isinstance(item["reviewers"], list)
        and len(set(item["reviewers"])) >= 2
        and authority.casefold()
        not in {str(name).casefold() for name in item["reviewers"]}
        and all(isinstance(name, str) and name for name in item["reviewers"])
        and isinstance(item["exclusion_reason"], str)
        and isinstance(item["notes"], str)
    )
    if not valid:
        return False
    for name, criterion in criteria.items():
        if not isinstance(criterion, dict) or set(criterion) != {
            "status",
            "rationale",
            "evidence_refs",
        }:
            return False
        statuses[name] = criterion["status"]
        if not (
            criterion["status"] in CRITERION_STATUSES
            and isinstance(criterion["rationale"], str)
            and bool(criterion["rationale"])
            and isinstance(criterion["evidence_refs"], list)
            and bool(criterion["evidence_refs"])
            and all(isinstance(ref, str) and ref for ref in criterion["evidence_refs"])
        ):
            return False
    criteria_passed = all(statuses[name] == "pass" for name in CORE_CRITERIA) and (
        "fail" not in statuses.values()
    )
    return bool(
        item["criteria_passed"] is criteria_passed
        and (item["disposition"] != "accepted" or criteria_passed)
        and (item["disposition"] != "excluded" or item["exclusion_reason"])
        and (
            item["disposition"] != "remediation_required" or "fail" in statuses.values()
        )
    )


def _summary(items: list[dict[str, Any]], max_exclusion_rate: float) -> dict[str, Any]:
    accepted = sum(item["disposition"] == "accepted" for item in items)
    excluded = sum(item["disposition"] == "excluded" for item in items)
    remediation = sum(item["disposition"] == "remediation_required" for item in items)
    exclusion_rate = excluded / len(items)
    return {
        "items": len(items),
        "accepted": accepted,
        "excluded": excluded,
        "remediation_required": remediation,
        "exclusion_rate": exclusion_rate,
        "passed": bool(
            accepted > 0
            and remediation == 0
            and accepted + excluded == len(items)
            and exclusion_rate <= max_exclusion_rate
        ),
    }


def verify_benchmark_item_quality(
    value: dict[str, Any],
    *,
    normalization_source: str | Path | None = None,
    reviews_source: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark item-quality audit",
            format_value=BENCHMARK_ITEM_QUALITY_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("benchmark item-quality audit fields do not reconcile")
    replay: bool | None = None
    if normalization_source is not None or reviews_source is not None:
        replay = False
        if (
            normalization_source is not None
            and reviews_source is not None
            and structure
        ):
            try:
                replayed = benchmark_item_quality_audit(
                    normalization_source,
                    reviews_source,
                    authority=checked["authority"],
                    max_exclusion_rate=checked["policy"]["max_exclusion_rate"],
                    generated_at=checked["generated_at"],
                )
                replay = replayed == value
            except (OSError, TypeError, ValueError):
                replay = False
        if not replay:
            errors.append("benchmark item-quality audit does not exactly replay")
    valid = integrity and structure and replay is not False
    passed = bool(valid and checked.get("summary", {}).get("passed"))
    return seal(
        {
            "format": BENCHMARK_ITEM_QUALITY_VERIFICATION_FORMAT,
            "valid": valid,
            "passed": passed,
            "eligible_for_benchmark_claim": passed and replay is True,
            "checks": {
                "content_integrity": integrity,
                "closed_population_and_policy": structure,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": (
                "Claim eligibility requires a passing audit and exact replay from both source "
                "artifacts. It remains review evidence, not certification or ground-truth proof."
            ),
        }
    )


def export_benchmark_item_quality(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_benchmark_item_quality(value)["valid"]:
        raise ValueError("benchmark item-quality audit is invalid")
    return publish_json(value, destination)


def verify_benchmark_item_quality_file(
    source: str | Path,
    *,
    normalization_source: str | Path | None = None,
    reviews_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        value, _ = _document(source, "benchmark item-quality audit")
        if not isinstance(value, dict):
            raise ValueError("benchmark item-quality audit must contain an object")
        return verify_benchmark_item_quality(
            value,
            normalization_source=normalization_source,
            reviews_source=reviews_source,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_ITEM_QUALITY_VERIFICATION_FORMAT,
                "valid": False,
                "passed": False,
                "eligible_for_benchmark_claim": False,
                "checks": {
                    "content_integrity": False,
                    "closed_population_and_policy": False,
                    "exact_source_replay": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark item-quality verification failed closed.",
            }
        )
