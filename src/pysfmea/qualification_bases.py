"""Governed navigation packs for selecting a tool-qualification basis.

The packs map PySFMEA's generic dossier objectives to recognizable lifecycle
data categories. They do not reproduce licensed requirements or decide a tool
classification.
"""

from __future__ import annotations

import copy
from typing import Any

from .integrity import canonical_json_sha256

QUALIFICATION_BASES_FORMAT = "pysfmea-tool-qualification-bases-1"

_COMMON = {
    "TQ-CLASSIFY": "intended use, reliance, failure consequence, and classification decision",
    "TQ-TOR": "tool operational requirements",
    "TQ-TQP": "qualification or validation plan",
    "TQ-TVP": "verification procedures and traceability",
    "TQ-TVR": "verification results and independent review",
    "TQ-CONFIG": "configuration, environment, build, and provenance index",
    "TQ-ANOMALY": "known-problem and operational-limitation record",
    "TQ-TQAS": "accomplishment or validation summary",
    "TQ-REQUALIFY": "change impact and requalification criteria",
}


def _pack(
    identifier: str,
    title: str,
    publisher: str,
    edition: str,
    reference_url: str,
    classification_questions: list[str],
    tailoring_notes: list[str],
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "publisher": publisher,
        "edition": edition,
        "reference_url": reference_url,
        "access": "licensed_normative_text_required",
        "classification_authority_required": True,
        "classification_questions": classification_questions,
        "objective_crosswalk": [
            {"objective_id": objective, "evidence_category": category}
            for objective, category in _COMMON.items()
        ],
        "tailoring_notes": tailoring_notes,
    }


QUALIFICATION_BASIS_PACKS: tuple[dict[str, Any], ...] = (
    _pack(
        "do-330-2011-aligned",
        "DO-330/ED-215 tool qualification navigation pack",
        "RTCA and EUROCAE",
        "DO-330 / ED-215, 2011",
        "https://www.faa.gov/documentLibrary/media/Advisory_Circular/AC_20-115D.pdf",
        [
            "Can an erroneous tool output fail to be detected by other lifecycle processes?",
            "Does the tool automate, reduce, or eliminate a process required by the selected airborne-software basis?",
            "What software level, tool criteria, and resulting TQL are approved for each operational use?",
        ],
        [
            "Use the approved airborne-software planning and tool-use analysis to select the criteria and TQL.",
            "Retain operational requirements, qualification data, configuration, anomalies, and accomplishment evidence for the exact baseline.",
        ],
    ),
    _pack(
        "iso-26262-8-2018-aligned",
        "ISO 26262-8:2018 software-tool confidence navigation pack",
        "ISO",
        "ISO 26262-8:2018",
        "https://www.iso.org/standard/68392.html",
        [
            "What is the possibility that a tool malfunction can introduce or fail to detect an error?",
            "What confidence exists that the tool error will be prevented or detected in the development process?",
            "What Tool Impact, Tool Error Detection, Tool Confidence Level, ASIL context, and qualification methods are approved?",
        ],
        [
            "Perform the confidence evaluation separately for each use case and environment.",
            "Select qualification methods and rigor from the licensed normative basis and approved safety plan.",
        ],
    ),
    _pack(
        "iec-61508-3-2010-aligned",
        "IEC 61508-3:2010 software-tool and translator navigation pack",
        "IEC",
        "IEC 61508-3:2010",
        "https://webstore.iec.ch/en/publication/5515",
        [
            "Can the tool directly or indirectly contribute to executable safety-related code or verification evidence?",
            "What tool class, SIL context, failure-detection measures, prior-use evidence, and validation are approved?",
            "Are tool versions, configurations, translators, libraries, environments, and known failures controlled?",
        ],
        [
            "Treat classification and required confidence as project safety decisions, not scanner outputs.",
            "Reconcile tool validation, operational constraints, configuration, anomalies, and change impact for the exact qualified use.",
        ],
    ),
)


def qualification_bases_catalog() -> dict[str, Any]:
    content: dict[str, Any] = {
        "format": QUALIFICATION_BASES_FORMAT,
        "packs": [copy.deepcopy(pack) for pack in QUALIFICATION_BASIS_PACKS],
        "notice": (
            "Original navigation summaries only. Obtain and apply the licensed normative "
            "edition, approved tailoring, and authorized classification decision. A pack is "
            "not a qualification certificate or compliance claim."
        ),
    }
    content["content_sha256"] = canonical_json_sha256(content)
    return content
