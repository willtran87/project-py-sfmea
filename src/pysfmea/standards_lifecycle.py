"""Governed standards-revision review and reapproval evidence."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .conformance import standards_catalog
from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .model import utc_now

STANDARDS_LIFECYCLE_FORMAT = "pysfmea-standards-lifecycle-1"
STANDARDS_LIFECYCLE_VERIFICATION_FORMAT = "pysfmea-standards-lifecycle-verification-1"
DISPOSITIONS = {
    "unreviewed",
    "current",
    "revised",
    "withdrawn",
    "superseded",
    "unknown",
}


def _iso(value: str) -> datetime | None:
    if value == "unassigned":
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _summary(reviews: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    now = _iso(generated_at)
    counts = {name: 0 for name in sorted(DISPOSITIONS)}
    overdue = 0
    complete = 0
    changed = 0
    for review in reviews:
        counts[review["disposition"]] += 1
        complete += int(
            review["reviewer"] != "unassigned"
            and review["source_evidence_ref"] != "unassigned"
            and _iso(review["observed_at"]) is not None
            and _iso(review["next_review_at"]) is not None
            and review["disposition"] != "unreviewed"
        )
        due = _iso(review["next_review_at"])
        overdue += int(now is not None and due is not None and due < now)
        changed += int(review["disposition"] in {"revised", "withdrawn", "superseded"})
    return {
        "profiles": len(reviews),
        "complete_reviews": complete,
        "overdue_reviews": overdue,
        "changed_sources": changed,
        "by_disposition": counts,
    }


def standards_lifecycle_template(
    *, authority: str, generated_at: str | None = None
) -> dict[str, Any]:
    """Create a closed review ledger bound to the exact built-in catalog."""

    catalog = standards_catalog()
    created = generated_at or utc_now()
    reviews = [
        {
            "profile_id": profile["id"],
            "catalog_edition": profile["edition"],
            "catalog_status": profile["status"],
            "observed_edition": "unassigned",
            "observed_status": "unassigned",
            "disposition": "unreviewed",
            "observed_at": "unassigned",
            "next_review_at": "unassigned",
            "source_evidence_ref": "unassigned",
            "reviewer": "unassigned",
            "reapproval_refs": [],
            "notes": "",
        }
        for profile in catalog["profiles"]
    ]
    return seal(
        {
            "format": STANDARDS_LIFECYCLE_FORMAT,
            "generated_at": created,
            "authority": bounded_text(authority, "standards lifecycle authority"),
            "catalog": {
                "version": catalog["version"],
                "content_sha256": catalog["content_sha256"],
            },
            "reviews": reviews,
            "summary": _summary(reviews, created),
            "claim_boundary": "This ledger records accountable metadata review against publisher evidence. It does not reproduce licensed requirements, determine applicability, or establish conformity.",
        }
    )


def _structure(value: dict[str, Any]) -> bool:
    try:
        catalog = standards_catalog()
        expected_profiles = {
            profile["id"]: (profile["edition"], profile["status"])
            for profile in catalog["profiles"]
        }
        reviews = value["reviews"]
        generated = _iso(value["generated_at"])
        if not (
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "catalog",
                "reviews",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and value["catalog"]
            == {
                "version": catalog["version"],
                "content_sha256": catalog["content_sha256"],
            }
            and generated is not None
            and isinstance(reviews, list)
            and len(reviews) == len(expected_profiles)
        ):
            return False
        identifiers: list[str] = []
        for review in reviews:
            if not isinstance(review, dict) or set(review) != {
                "profile_id",
                "catalog_edition",
                "catalog_status",
                "observed_edition",
                "observed_status",
                "disposition",
                "observed_at",
                "next_review_at",
                "source_evidence_ref",
                "reviewer",
                "reapproval_refs",
                "notes",
            }:
                return False
            identifier = review["profile_id"]
            identifiers.append(identifier)
            if (
                identifier not in expected_profiles
                or (review["catalog_edition"], review["catalog_status"])
                != expected_profiles[identifier]
                or review["disposition"] not in DISPOSITIONS
                or not all(
                    isinstance(review[name], str)
                    for name in (
                        "observed_edition",
                        "observed_status",
                        "observed_at",
                        "next_review_at",
                        "source_evidence_ref",
                        "reviewer",
                        "notes",
                    )
                )
                or not isinstance(review["reapproval_refs"], list)
                or len(review["reapproval_refs"]) != len(set(review["reapproval_refs"]))
                or not all(
                    isinstance(item, str) and item and item != "unassigned"
                    for item in review["reapproval_refs"]
                )
            ):
                return False
            observed = _iso(review["observed_at"])
            next_review = _iso(review["next_review_at"])
            if review["disposition"] != "unreviewed" and (
                observed is None
                or next_review is None
                or generated is None
                or observed > generated
                or next_review <= observed
                or review["source_evidence_ref"] == "unassigned"
                or review["reviewer"] == "unassigned"
                or review["observed_edition"] == "unassigned"
                or review["observed_status"] == "unassigned"
            ):
                return False
            if review["disposition"] == "current" and (
                review["observed_edition"] != review["catalog_edition"]
                or review["observed_status"] != review["catalog_status"]
            ):
                return False
            if (
                review["disposition"] in {"revised", "withdrawn", "superseded"}
                and not review["reapproval_refs"]
            ):
                return False
        return bool(
            len(identifiers) == len(set(identifiers))
            and set(identifiers) == set(expected_profiles)
            and value["summary"] == _summary(reviews, value["generated_at"])
        )
    except (KeyError, TypeError):
        return False


def verify_standards_lifecycle(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="standards lifecycle", format_value=STANDARDS_LIFECYCLE_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append(
            "standards lifecycle fields, catalog binding, or summary are invalid"
        )
    complete = bool(
        structure
        and checked["summary"]["complete_reviews"] == checked["summary"]["profiles"]
        and checked["summary"]["overdue_reviews"] == 0
        and checked["summary"]["changed_sources"] == 0
        and checked["summary"]["by_disposition"]["current"]
        == checked["summary"]["profiles"]
    )
    if structure and not complete:
        errors.append(
            "standards lifecycle review is incomplete, overdue, or requires reapproval"
        )
    return seal(
        {
            "format": STANDARDS_LIFECYCLE_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "eligible_as_current_catalog_evidence": integrity
            and structure
            and complete,
            "checks": {
                "content_integrity": integrity,
                "exact_catalog_binding_and_structure": structure,
                "complete_current_review": complete,
            },
            "errors": errors,
            "notice": "Eligibility establishes current reviewed metadata only; normative interpretation and conformity remain external authority decisions.",
        }
    )


def seal_standards_lifecycle(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="standards lifecycle")
    value.pop("content_sha256", None)
    value["summary"] = _summary(value["reviews"], value["generated_at"])
    result = seal(value)
    if not verify_standards_lifecycle(result)["valid"]:
        raise ValueError("standards lifecycle source is invalid")
    return publish_json(result, destination)


def verify_standards_lifecycle_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_standards_lifecycle(
            load_json(source, label="standards lifecycle")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": STANDARDS_LIFECYCLE_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_as_current_catalog_evidence": False,
                "checks": {
                    "content_integrity": False,
                    "exact_catalog_binding_and_structure": False,
                    "complete_current_review": False,
                },
                "errors": [str(exc)],
                "notice": "Standards-lifecycle verification failed closed.",
            }
        )


def export_standards_lifecycle(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_standards_lifecycle(value)["valid"]:
        raise ValueError("standards lifecycle artifact is internally invalid")
    return publish_json(value, destination)
