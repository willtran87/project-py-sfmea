"""Deterministic interlaboratory benchmark-proficiency assessment evidence.

The workflow is inspired by ISO/IEC 17043 and ISO 13528 concepts, but it is
deliberately non-normative: PySFMEA does not reproduce either publication and
cannot accredit a provider or certify a participant.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .model import utc_now

BENCHMARK_PROFICIENCY_SOURCE_FORMAT = "pysfmea-benchmark-proficiency-source-1"
BENCHMARK_PROFICIENCY_ASSESSMENT_FORMAT = "pysfmea-benchmark-proficiency-assessment-1"
BENCHMARK_PROFICIENCY_VERIFICATION_FORMAT = (
    "pysfmea-benchmark-proficiency-verification-1"
)


def benchmark_proficiency_template(*, authority: str) -> dict[str, Any]:
    owner = bounded_text(authority, "proficiency provider")
    return seal(
        {
            "format": BENCHMARK_PROFICIENCY_SOURCE_FORMAT,
            "generated_at": utc_now(),
            "scheme": {
                "id": "unassigned",
                "round": "unassigned",
                "scope": "Python SFMEA benchmark proficiency",
            },
            "authorities": {
                "provider": owner,
                "technical_reviewer": "unassigned",
                "approval_authority": "unassigned",
            },
            "policy": {
                "minimum_participants": 2,
                "minimum_organizations": 2,
                "z_warning_limit": 2.0,
                "z_action_limit": 3.0,
                "minimum_qualitative_agreement": 1.0,
            },
            "items": [],
            "participants": [],
            "claim_boundary": (
                "This editable source supports deterministic proficiency scoring. "
                "It is not ISO/IEC 17043 accreditation, ISO 13528 conformity, "
                "certification, or proof of benchmark representativeness."
            ),
        }
    )


def _finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _source_structure(value: dict[str, Any]) -> bool:
    try:
        scheme = value["scheme"]
        authorities = value["authorities"]
        policy = value["policy"]
        items = value["items"]
        participants = value["participants"]
        item_ids = [item["id"] for item in items]
        participant_ids = [item["id"] for item in participants]
        item_fields = {
            "id",
            "kind",
            "assigned_value",
            "proficiency_standard_deviation",
            "homogeneous",
            "stable",
            "evidence_refs",
        }
        result_fields = {"item_id", "value", "evidence_ref"}
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "scheme",
                "authorities",
                "policy",
                "items",
                "participants",
                "claim_boundary",
                "content_sha256",
            }
            and set(scheme) == {"id", "round", "scope"}
            and all(
                isinstance(scheme[name], str) and scheme[name].strip()
                for name in scheme
            )
            and set(authorities)
            == {"provider", "technical_reviewer", "approval_authority"}
            and all(
                isinstance(authorities[name], str) and authorities[name].strip()
                for name in authorities
            )
            and set(policy)
            == {
                "minimum_participants",
                "minimum_organizations",
                "z_warning_limit",
                "z_action_limit",
                "minimum_qualitative_agreement",
            }
            and isinstance(policy["minimum_participants"], int)
            and not isinstance(policy["minimum_participants"], bool)
            and policy["minimum_participants"] >= 2
            and isinstance(policy["minimum_organizations"], int)
            and not isinstance(policy["minimum_organizations"], bool)
            and policy["minimum_organizations"] >= 2
            and _finite_number(policy["z_warning_limit"])
            and _finite_number(policy["z_action_limit"])
            and 0 < policy["z_warning_limit"] < policy["z_action_limit"]
            and _finite_number(policy["minimum_qualitative_agreement"])
            and 0 <= policy["minimum_qualitative_agreement"] <= 1
            and isinstance(items, list)
            and len(items) <= 100_000
            and len(item_ids) == len(set(item_ids))
            and all(
                isinstance(item, dict)
                and set(item) == item_fields
                and isinstance(item["id"], str)
                and bool(item["id"].strip())
                and item["kind"] in {"quantitative", "qualitative"}
                and (
                    (
                        item["kind"] == "quantitative"
                        and _finite_number(item["assigned_value"])
                        and _finite_number(item["proficiency_standard_deviation"])
                        and item["proficiency_standard_deviation"] > 0
                    )
                    or (
                        item["kind"] == "qualitative"
                        and isinstance(item["assigned_value"], str)
                        and bool(item["assigned_value"].strip())
                        and item["proficiency_standard_deviation"] is None
                    )
                )
                and isinstance(item["homogeneous"], bool)
                and isinstance(item["stable"], bool)
                and isinstance(item["evidence_refs"], list)
                and bool(item["evidence_refs"])
                and len(item["evidence_refs"]) == len(set(item["evidence_refs"]))
                and all(
                    isinstance(ref, str) and ref.strip()
                    for ref in item["evidence_refs"]
                )
                for item in items
            )
            and isinstance(participants, list)
            and len(participants) <= 100_000
            and len(participant_ids) == len(set(participant_ids))
            and all(
                isinstance(participant, dict)
                and set(participant) == {"id", "organization", "results"}
                and isinstance(participant["id"], str)
                and bool(participant["id"].strip())
                and isinstance(participant["organization"], str)
                and bool(participant["organization"].strip())
                and isinstance(participant["results"], list)
                and {result["item_id"] for result in participant["results"]}
                == set(item_ids)
                and len(participant["results"]) == len(item_ids)
                and all(
                    isinstance(result, dict)
                    and set(result) == result_fields
                    and result["item_id"] in set(item_ids)
                    and isinstance(result["evidence_ref"], str)
                    and bool(result["evidence_ref"].strip())
                    and (
                        _finite_number(result["value"])
                        if items[item_ids.index(result["item_id"])]["kind"]
                        == "quantitative"
                        else isinstance(result["value"], str)
                        and bool(result["value"].strip())
                    )
                    for result in participant["results"]
                )
                for participant in participants
            )
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"].strip())
        )
    except (KeyError, TypeError, ValueError):
        return False


def _assessment(
    source: dict[str, Any], *, generated_at: str | None = None
) -> dict[str, Any]:
    if not _source_structure(source):
        raise ValueError("benchmark proficiency source structure is invalid")
    policy = source["policy"]
    item_by_id = {item["id"]: item for item in source["items"]}
    ledger: list[dict[str, Any]] = []
    for participant in source["participants"]:
        outcomes = []
        for result in participant["results"]:
            item = item_by_id[result["item_id"]]
            if item["kind"] == "quantitative":
                z_score = round(
                    (result["value"] - item["assigned_value"])
                    / item["proficiency_standard_deviation"],
                    12,
                )
                absolute = abs(z_score)
                status = (
                    "action"
                    if absolute >= policy["z_action_limit"]
                    else "warning"
                    if absolute >= policy["z_warning_limit"]
                    else "satisfactory"
                )
                outcomes.append(
                    {
                        "item_id": item["id"],
                        "kind": item["kind"],
                        "z_score": z_score,
                        "agreement": None,
                        "status": status,
                    }
                )
            else:
                agreement = result["value"] == item["assigned_value"]
                outcomes.append(
                    {
                        "item_id": item["id"],
                        "kind": item["kind"],
                        "z_score": None,
                        "agreement": agreement,
                        "status": "satisfactory" if agreement else "action",
                    }
                )
        ledger.append(
            {
                "participant_id": participant["id"],
                "organization": participant["organization"],
                "outcomes": outcomes,
                "passed": bool(outcomes)
                and all(item["status"] == "satisfactory" for item in outcomes),
            }
        )
    organizations = {item["organization"].casefold() for item in source["participants"]}
    authorities = [value.casefold() for value in source["authorities"].values()]
    authority_separation = "unassigned" not in authorities and len(authorities) == len(
        set(authorities)
    )
    qualitative = [
        outcome["agreement"]
        for participant in ledger
        for outcome in participant["outcomes"]
        if outcome["kind"] == "qualitative"
    ]
    qualitative_agreement = (
        sum(value is True for value in qualitative) / len(qualitative)
        if qualitative
        else 1.0
    )
    checks = {
        "authority_separation": authority_separation,
        "participant_population": len(ledger) >= policy["minimum_participants"],
        "organization_population": len(organizations)
        >= policy["minimum_organizations"],
        "assigned_value_evidence": bool(source["items"]),
        "item_homogeneity": bool(source["items"])
        and all(item["homogeneous"] for item in source["items"]),
        "item_stability": bool(source["items"])
        and all(item["stable"] for item in source["items"]),
        "qualitative_agreement": qualitative_agreement
        >= policy["minimum_qualitative_agreement"],
        "all_participants_satisfactory": bool(ledger)
        and all(item["passed"] for item in ledger),
    }
    return seal(
        {
            "format": BENCHMARK_PROFICIENCY_ASSESSMENT_FORMAT,
            "generated_at": generated_at or utc_now(),
            "source_sha256": source["content_sha256"],
            "scheme": source["scheme"],
            "authorities": source["authorities"],
            "policy": policy,
            "participant_ledger": ledger,
            "checks": checks,
            "summary": {
                "items": len(source["items"]),
                "participants": len(ledger),
                "organizations": len(organizations),
                "satisfactory_participants": sum(item["passed"] for item in ledger),
                "qualitative_agreement": round(qualitative_agreement, 12),
                "passed": all(checks.values()),
            },
            "claim_boundary": (
                "Passing means the supplied results satisfy this declared deterministic "
                "scheme only. It is not accreditation, certification, regulatory approval, "
                "or a claim that the corpus is representative."
            ),
        }
    )


def assess_benchmark_proficiency(source: dict[str, Any]) -> dict[str, Any]:
    verify_seal(
        source,
        label="benchmark proficiency source",
        format_value=BENCHMARK_PROFICIENCY_SOURCE_FORMAT,
    )
    return _assessment(source)


def verify_benchmark_proficiency(
    value: dict[str, Any], *, source: dict[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark proficiency assessment",
            format_value=BENCHMARK_PROFICIENCY_ASSESSMENT_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = bool(
        isinstance(checked, dict)
        and set(checked)
        == {
            "format",
            "generated_at",
            "source_sha256",
            "scheme",
            "authorities",
            "policy",
            "participant_ledger",
            "checks",
            "summary",
            "claim_boundary",
            "content_sha256",
        }
        and isinstance(checked.get("checks"), dict)
        and set(checked.get("checks", {}))
        == {
            "authority_separation",
            "participant_population",
            "organization_population",
            "assigned_value_evidence",
            "item_homogeneity",
            "item_stability",
            "qualitative_agreement",
            "all_participants_satisfactory",
        }
        and isinstance(checked.get("summary"), dict)
        and isinstance(checked.get("participant_ledger"), list)
    )
    if not structure:
        errors.append("benchmark proficiency assessment structure is invalid")
    replay: bool | None = None
    if source is not None:
        try:
            verify_seal(
                source,
                label="benchmark proficiency source",
                format_value=BENCHMARK_PROFICIENCY_SOURCE_FORMAT,
            )
            replay = _assessment(source, generated_at=checked["generated_at"]) == value
        except (KeyError, TypeError, ValueError):
            replay = False
        if not replay:
            errors.append(
                "benchmark proficiency assessment does not exactly replay from source"
            )
    valid = integrity and structure and replay is not False
    passed = bool(
        valid
        and checked.get("summary", {}).get("passed")
        and all(checked.get("checks", {}).values())
    )
    return seal(
        {
            "format": BENCHMARK_PROFICIENCY_VERIFICATION_FORMAT,
            "valid": valid,
            "passed": passed,
            "eligible_for_qualification_input": passed and replay is True,
            "checks": {
                "content_integrity": integrity,
                "closed_structure": structure,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": "Eligibility requires exact source replay and is only an input to an authorized qualification decision.",
        }
    )


def seal_benchmark_proficiency_source(
    source: str | Path, destination: str | Path
) -> Path:
    value = load_json(source, label="benchmark proficiency source")
    value.pop("content_sha256", None)
    result = seal(value)
    verify_seal(
        result,
        label="benchmark proficiency source",
        format_value=BENCHMARK_PROFICIENCY_SOURCE_FORMAT,
    )
    if not _source_structure(result):
        raise ValueError("benchmark proficiency source structure is invalid")
    return publish_json(result, destination)


def export_benchmark_proficiency(
    value: dict[str, Any], destination: str | Path
) -> Path:
    return publish_json(value, destination)


def assess_benchmark_proficiency_file(
    source: str | Path, destination: str | Path
) -> Path:
    return publish_json(
        assess_benchmark_proficiency(
            load_json(source, label="benchmark proficiency source")
        ),
        destination,
    )


def verify_benchmark_proficiency_file(
    source: str | Path, *, scheme_source: str | Path | None = None
) -> dict[str, Any]:
    try:
        assessment = load_json(source, label="benchmark proficiency assessment")
        scheme = (
            load_json(scheme_source, label="benchmark proficiency source")
            if scheme_source
            else None
        )
        return verify_benchmark_proficiency(assessment, source=scheme)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_PROFICIENCY_VERIFICATION_FORMAT,
                "valid": False,
                "passed": False,
                "eligible_for_qualification_input": False,
                "checks": {
                    "content_integrity": False,
                    "closed_structure": False,
                    "exact_source_replay": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark proficiency verification failed closed.",
            }
        )
