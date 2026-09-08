"""Non-normative watchlist for relevant standards still under development."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .governed_artifact import load_json, publish_json, seal, verify_seal
from .model import utc_now

STANDARDS_WATCHLIST_FORMAT = "pysfmea-standards-watchlist-1"
STANDARDS_WATCHLIST_VERIFICATION_FORMAT = "pysfmea-standards-watchlist-verification-1"

WATCHLIST = [
    {
        "id": "nist-ai-200-2-tevv-athlon",
        "title": "NIST AI 200-2 TEVV-Athlon framework for evaluating AI systems",
        "development_stage": "initial_public_draft",
        "official_url": "https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems",
        "potential_impact": "extensible TEVV design for machine-learning, language, multimodal, and agentic systems; evaluation context, measurement, evidence, uncertainty, and lifecycle governance",
    },
    {
        "id": "iso-iec-42007",
        "title": "ISO/IEC 42007 AI conformity-assessment scheme framework",
        "development_stage": "DIS",
        "official_url": "https://www.iso.org/standard/89967.html",
        "potential_impact": "DIS stage 40.20 AI conformity-assessment scheme governance, certification-scheme design, impartiality, evidence, surveillance, and claim boundaries",
    },
    {
        "id": "iso-17065-edition-2",
        "title": "ISO/IEC 17065 product, process, and service certification revision",
        "development_stage": "FDIS",
        "official_url": "https://www.iso.org/standard/94443.html",
        "potential_impact": "certification-body impartiality, process, decision, surveillance, and claim-boundary governance",
    },
    {
        "id": "ieee-828-revision",
        "title": "IEEE 828 configuration-management revision",
        "development_stage": "active_PAR",
        "official_url": "https://standards.ieee.org/ieee/828/10549/",
        "potential_impact": "configuration identification, change control, release engineering, status accounting, and CM plans",
    },
    {
        "id": "iso-ts-23485",
        "title": "ISO/TS 23485 guidance for applying ISO 13485",
        "development_stage": "CD",
        "official_url": "https://www.iso.org/standard/90565.html",
        "potential_impact": "medical-device QMS implementation guidance and evidence interpretation",
    },
    {
        "id": "iso-15939-revision",
        "title": "ISO/IEC/IEEE 15939 measurement-process revision",
        "development_stage": "DIS",
        "official_url": "https://www.iso.org/committee/45086/x/catalogue/",
        "potential_impact": "measurement information needs, validity, analysis, and governance controls",
    },
    {
        "id": "iso-29119-8",
        "title": "ISO/IEC/IEEE 29119-8 model-based testing",
        "development_stage": "FDIS",
        "official_url": "https://www.iso.org/committee/45086/x/catalogue/",
        "potential_impact": "model-derived test generation and coverage evidence",
    },
    {
        "id": "iso-29119-15",
        "title": "ISO/IEC/IEEE 29119-15 static testing",
        "development_stage": "CD",
        "official_url": "https://www.iso.org/committee/45086/x/catalogue/",
        "potential_impact": "static-analysis process, evidence, and reporting controls",
    },
    {
        "id": "spdx-3",
        "title": "ISO/IEC 5962 SPDX 3.0 revision",
        "development_stage": "DIS",
        "official_url": "https://www.iso.org/committee/45086/x/catalogue/",
        "potential_impact": "software and AI supply-chain evidence exchange",
    },
    {
        "id": "iso-5055-3",
        "title": "ISO/IEC 5055-3 automated source-code quality measures",
        "development_stage": "DIS",
        "official_url": "https://www.iso.org/committee/45086/x/catalogue/",
        "potential_impact": "automated source-code structural quality measurement",
    },
]


def standards_watchlist() -> dict[str, Any]:
    return seal(
        {
            "format": STANDARDS_WATCHLIST_FORMAT,
            "generated_at": utc_now(),
            "items": WATCHLIST,
            "policy": {
                "normative_use": "prohibited_until_published_and_adopted",
                "review_trigger": "publisher stage, edition, or publication change",
                "catalog_action": "create a new stable profile id after accountable review; never repurpose an existing profile",
            },
            "claim_boundary": "Watchlist entries are planning signals, not adopted standards profiles or normative requirements. Development stage and content can change before publication.",
        }
    )


def verify_standards_watchlist(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="standards watchlist", format_value=STANDARDS_WATCHLIST_FORMAT
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
            "items",
            "policy",
            "claim_boundary",
            "content_sha256",
        }
        and checked.get("items") == WATCHLIST
        and checked.get("policy", {}).get("normative_use")
        == "prohibited_until_published_and_adopted"
    )
    if not structure:
        errors.append(
            "standards watchlist does not match the governed development inventory"
        )
    return seal(
        {
            "format": STANDARDS_WATCHLIST_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "checks": {"content_integrity": integrity, "governed_inventory": structure},
            "errors": errors,
            "notice": "A valid watchlist remains non-normative and cannot support conformance claims.",
        }
    )


def export_standards_watchlist(destination: str | Path) -> Path:
    return publish_json(standards_watchlist(), destination)


def verify_standards_watchlist_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_standards_watchlist(
            load_json(source, label="standards watchlist")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": STANDARDS_WATCHLIST_VERIFICATION_FORMAT,
                "valid": False,
                "checks": {"content_integrity": False, "governed_inventory": False},
                "errors": [str(exc)],
                "notice": "Standards-watchlist verification failed closed.",
            }
        )
