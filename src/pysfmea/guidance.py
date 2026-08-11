"""Versioned public guidance and machine-readable SFMEA traceability mappings."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from .integrity import verify_run_manifest_integrity
from .json_ingestion import load_bounded_json_document

GUIDANCE_SCHEMA_VERSION = "1.1"
GUIDANCE_CATALOG_VERSION = "2026.08.05"
GUIDANCE_RETRIEVED_AT = "2026-08-05"
MAX_ORGANIZATIONAL_GUIDANCE_PACK_BYTES = 5_000_000
MAX_ORGANIZATIONAL_GUIDANCE_PACK_DEPTH = 100
MAX_ORGANIZATIONAL_GUIDANCE_PACK_NODES = 250_000

RELATIONSHIP_TYPES = {
    "methodology_basis",
    "failure_taxonomy",
    "process_expectation",
    "hazard_traceability",
    "verification_expectation",
    "security_taxonomy",
    "supports_review_question",
}
MAPPING_STRENGTHS = {"direct", "supporting", "contextual"}
APPLICABILITY_TYPES = {
    "general_methodological",
    "legacy_methodological",
    "nasa_program_or_contract",
    "faa_commercial_space",
    "faa_airworthiness",
    "security_relevant",
    "organizational",
}

DEFAULT_GUIDANCE_PROFILES = ["core_sfmea"]

GUIDELINE_PROFILES: list[dict[str, Any]] = [
    {
        "id": "core_sfmea",
        "title": "Core public SFMEA methodology",
        "status": "default",
        "source_ids": ["NASA-SWEHB-8.05", "NASA-GB-8719.13"],
        "applicability": "General software failure-mode analysis; project-specific tailoring is still required.",
        "risk_semantics": "Severity follows the credible end effect. Occurrence and detection are not inferred from code metrics.",
        "verification_semantics": "Candidate controls and tests require objective evidence and qualified human review.",
        "tailoring": "Default profile. Record system boundary, lifecycle phase, ground rules, hazards, requirements, and the approved risk scale.",
        "compliance_claim": False,
    },
    {
        "id": "nasa_assurance",
        "title": "NASA software assurance and safety",
        "status": "optional",
        "source_ids": [
            "NASA-SWEHB-8.05",
            "NASA-GB-8719.13",
            "NASA-STD-8739.8B",
            "NASA-NPR-7150.2D",
        ],
        "applicability": "NASA programs, projects, contracts, or organizations that explicitly adopt the cited requirements.",
        "risk_semantics": "Use the governing NASA/project classification, hazard, and risk processes; the scanner does not assign compliance status.",
        "verification_semantics": "Trace hazard contributions and controls to requirements and independent verification evidence when applicable.",
        "tailoring": "Select only after the governing program documents, software classification, assurance scope, and approved tailoring are known.",
        "compliance_claim": False,
    },
    {
        "id": "faa_commercial_space",
        "title": "FAA commercial-space computing system safety",
        "status": "optional",
        "source_ids": ["FAA-AC-450.141-1A"],
        "applicability": "Commercial launch or reentry work using AC 450.141-1A as an accepted means of compliance or engineering reference.",
        "risk_semantics": "Apply the operator's approved system-safety and computing-system criticality processes.",
        "verification_semantics": "Verification depth and independence are proportional to criticality; trace requirements to objective evidence.",
        "tailoring": "Confirm the applicable 14 CFR part, license basis, accepted means of compliance, and any FAA-approved alternative before use.",
        "compliance_claim": False,
    },
    {
        "id": "faa_airworthiness",
        "title": "FAA airborne software development assurance",
        "status": "optional",
        "source_ids": ["FAA-AC-20-115D"],
        "applicability": "Airborne software approval contexts that adopt AC 20-115D and the applicable RTCA/EUROCAE material.",
        "risk_semantics": "Software level and certification objectives come from the approved aircraft/system safety process, not from SFMEA screening priority.",
        "verification_semantics": "Lifecycle objectives, change impact analysis, life-cycle data, and tool qualification are certification-context concerns.",
        "tailoring": "Licensed RTCA/EUROCAE standards are not bundled. Coordinate interpretation with the certification authority and approved plans.",
        "compliance_claim": False,
    },
    {
        "id": "security",
        "title": "Secure software assurance",
        "status": "optional",
        "source_ids": ["NIST-SP-800-218", "MITRE-CWE"],
        "applicability": "Findings with a defensible security consequence or secure-development objective.",
        "risk_semantics": "Security weakness and vulnerability ratings remain distinct from SFMEA severity and risk acceptance.",
        "verification_semantics": "Use reproducible security analysis, remediation, and root-cause evidence.",
        "tailoring": "Select the applicable SSDF practices and CWE release; do not force a CWE mapping where evidence is insufficient.",
        "compliance_claim": False,
    },
    {
        "id": "legacy_reference",
        "title": "Legacy FAA launch/reentry methodology reference",
        "status": "optional_legacy",
        "source_ids": ["FAA-RLV-SCS-2006"],
        "applicability": "Historical methodology only; not a current regulatory basis.",
        "risk_semantics": "Use only as a taxonomy/worksheet reference and defer to current governing risk criteria.",
        "verification_semantics": "Historical examples do not establish current acceptance evidence.",
        "tailoring": "Keep visibly marked legacy and never present it as current FAA guidance.",
        "compliance_claim": False,
    },
]


GUIDANCE_DOCUMENTS: list[dict[str, Any]] = [
    {
        "id": "NASA-SWEHB-8.05",
        "publisher": "NASA",
        "title": "NASA Software Engineering Handbook: SW Failure Modes and Effects Analysis",
        "version": "D",
        "status": "active",
        "published_at": "2020-04-20",
        "url": "https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis",
        "use": "Bottom-up SFMEA process; software data, event, interface, timing, propagation, detection, corrective-action, and change-impact guidance.",
        "applicability": "general_methodological",
        "access": "public",
    },
    {
        "id": "FAA-RLV-SCS-2006",
        "publisher": "Federal Aviation Administration",
        "title": "Guide to Reusable Launch and Reentry Vehicle Software and Computing System Safety",
        "version": "1.0",
        "status": "legacy",
        "published_at": "2006-07-01",
        "url": "https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf",
        "status_url": "https://www.faa.gov/space/licenses/legacy-regulations",
        "use": "Legacy commercial-space methodology: software-specific FMEA procedure, failure classifications, effects, controls, and worksheet examples.",
        "applicability": "legacy_methodological",
        "access": "public",
    },
    {
        "id": "NASA-GB-8719.13",
        "publisher": "NASA",
        "title": "NASA Software Safety Guidebook",
        "version": "Baseline",
        "status": "legacy_method_reference",
        "published_at": "2004-03-31",
        "url": "https://standards.nasa.gov/sites/default/files/standards/NASA/Baseline/0/nasa-gb-871913.pdf",
        "use": "Detailed public software-safety analysis reference, including bottom-up SFMEA, top-down SFTA, and data/event failure tables.",
        "applicability": "legacy_methodological",
        "access": "public",
        "artifact": {
            "media_type": "application/pdf",
            "bytes": 2553832,
            "sha256": "d4742a244ac188fc656715fdb051ea09fed4eda2cd13d850a7f018f7899402c9",
            "digest_scope": "exact downloaded response body",
        },
    },
    {
        "id": "FAA-AC-450.141-1A",
        "publisher": "Federal Aviation Administration",
        "title": "Computing System Safety",
        "version": "AC 450.141-1A",
        "status": "active",
        "published_at": "2021-08-16",
        "url": "https://www.faa.gov/documentLibrary/media/Advisory_Circular/AC_450.141-1A_Computing_System_Safety_20210816_v1_%28002%29.pdf",
        "status_url": "https://www.faa.gov/regulations_policies/advisory_circulars/index.cfm/go/document.information/documentNumber/450.141-1A",
        "use": "Current FAA commercial-space computing-system safety guidance, including SFMEA, SFTA, criticality-proportional verification, independence, and evidence traceability.",
        "applicability": "faa_commercial_space",
        "access": "public",
        "artifact": {
            "media_type": "application/pdf",
            "bytes": 1057433,
            "sha256": "5592dfa7515c578729504615ee679ee745165143a46ec073c53549f20e26cb0a",
            "digest_scope": "exact downloaded response body",
        },
    },
    {
        "id": "FAA-AC-20-115D",
        "publisher": "Federal Aviation Administration",
        "title": "Airborne Software Development Assurance Using EUROCAE ED-12() and RTCA DO-178()",
        "version": "AC 20-115D",
        "status": "active",
        "published_at": "2017-07-21",
        "url": "https://www.faa.gov/documentLibrary/media/Advisory_Circular/AC_20-115D.pdf",
        "status_url": "https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D",
        "use": "Airworthiness development-assurance context for lifecycle objectives and data, change impact analysis, and tool qualification; not a generic SFMEA rule source.",
        "applicability": "faa_airworthiness",
        "access": "public_with_licensed_normative_references",
        "artifact": {
            "media_type": "application/pdf",
            "bytes": 511369,
            "sha256": "5597a1af49c872a1a843c05601742ddcc8e8a190642f31e3cb9ce8e0dc63d91e",
            "digest_scope": "exact downloaded response body",
        },
    },
    {
        "id": "NASA-STD-8739.8B",
        "publisher": "NASA",
        "title": "Software Assurance and Software Safety Standard",
        "version": "B",
        "status": "active",
        "published_at": "2022-09-08",
        "url": "https://standards.nasa.gov/sites/default/files/standards/NASA/B/0/NASA-STD-87398-Revision-B_1.pdf",
        "use": "Software safety, hazard contribution, requirements traceability, assurance, and verification expectations for applicable NASA work.",
        "applicability": "nasa_program_or_contract",
        "access": "public",
    },
    {
        "id": "NASA-NPR-7150.2D",
        "publisher": "NASA",
        "title": "NASA Software Engineering Requirements",
        "version": "D",
        "status": "active",
        "published_at": "2022-03-08",
        "url": "https://nodis3.gsfc.nasa.gov/displayDir.cfm?c=7150&s=2D&t=NPR",
        "use": "NASA lifecycle requirements for safety-critical software, bidirectional traceability, testing, configuration management, and defect management.",
        "applicability": "nasa_program_or_contract",
        "access": "public",
    },
    {
        "id": "NIST-SP-800-218",
        "publisher": "NIST",
        "title": "Secure Software Development Framework (SSDF) Version 1.1",
        "version": "1.1",
        "status": "active",
        "published_at": "2022-02-03",
        "url": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "use": "Optional secure-development, vulnerability remediation, and root-cause profile for security-relevant findings.",
        "applicability": "security_relevant",
        "access": "public",
    },
    {
        "id": "MITRE-CWE",
        "publisher": "MITRE",
        "title": "Common Weakness Enumeration",
        "version": "4.20",
        "status": "active",
        "published_at": "",
        "url": "https://cwe.mitre.org/",
        "use": "Optional, versioned weakness taxonomy for findings with a defensible security mapping.",
        "applicability": "security_relevant",
        "access": "public",
    },
    {
        "id": "IEC-60812-2018",
        "publisher": "IEC",
        "title": "IEC 60812:2018 Failure modes and effects analysis (FMEA and FMECA)",
        "version": "2018",
        "status": "active",
        "published_at": "2018-08-01",
        "url": "https://webstore.iec.ch/en/publication/26359",
        "use": "General FMEA framework. Clause text and semantic mappings are not bundled because the standard is licensed.",
        "applicability": "general_methodological",
        "access": "licensed",
    },
]


def _attach_source_integrity(records: list[dict[str, Any]]) -> None:
    """Bind every catalog source record to a stable canonical digest."""

    for record in records:
        record.setdefault(
            "quotation_policy",
            "Locator and concise paraphrase only; verify the official source before making an assurance or compliance decision.",
        )
        canonical = {
            key: value for key, value in record.items() if key != "record_sha256"
        }
        record["record_sha256"] = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


_attach_source_integrity(GUIDANCE_DOCUMENTS)


def _citation(
    citation_id: str,
    source_id: str,
    section: str,
    heading: str,
    summary: str,
    *,
    page: str = "",
    applicability: str,
    url: str = "",
) -> dict[str, Any]:
    value = {
        "id": citation_id,
        "source_id": source_id,
        "locator": {"section": section, "heading": heading, "page": page},
        "summary": summary,
        "applicability": applicability,
        "retrieved_at": GUIDANCE_RETRIEVED_AT,
    }
    if url:
        value["url"] = url
    anchor_material = {
        "source_id": source_id,
        "locator": value["locator"],
        "summary": summary,
    }
    value["locator_summary_sha256"] = hashlib.sha256(
        json.dumps(anchor_material, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    value["record_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return value


GUIDANCE_CITATIONS: list[dict[str, Any]] = [
    _citation(
        "NASA-SWEHB-8.05-PROCESS",
        "NASA-SWEHB-8.05",
        "3",
        "Process Introduction",
        "Defines system boundary and functional diagrams, then identifies item and interface failure modes, consequences, detection, corrective actions, change impacts, and unresolved issues.",
        applicability="general_methodological",
    ),
    _citation(
        "NASA-SWEHB-8.05-EFFECTS",
        "NASA-SWEHB-8.05",
        "1.1 and 5.4",
        "Terminology; Start at the Bottom",
        "Classifies failure effects as local, next-higher-level, and end effects and traces propagation upward through the system.",
        applicability="general_methodological",
    ),
    _citation(
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "NASA-SWEHB-8.05",
        "5.3, 10.3, and 10.4",
        "Possible Failure Modes; Data Table; Events Table",
        "Covers missing, wrong, out-of-range, overwritten, or out-of-sequence data and halt, omission, incorrect logic, timing, and ordering event faults.",
        applicability="general_methodological",
    ),
    _citation(
        "NASA-SWEHB-8.05-DETECTION",
        "NASA-SWEHB-8.05",
        "7",
        "Detection and Compensation",
        "Calls for failure-detection methods and compensating provisions to be identified and evaluated.",
        applicability="general_methodological",
    ),
    _citation(
        "NASA-SWEHB-8.05-CHANGE",
        "NASA-SWEHB-8.05",
        "8 and 9",
        "Design Changes; Impacts of Corrective Changes",
        "Calls for corrective actions and evaluation of their effects on design, function, performance, process, and other software.",
        applicability="general_methodological",
    ),
    _citation(
        "NASA-GB-8719.13-6.6.8-SFMEA",
        "NASA-GB-8719.13",
        "6.6.8",
        "Software Failure Modes and Effects Analysis",
        "Describes a bottom-up SFMEA that identifies software failure modes, causes, local and higher-level effects, detection, mitigation, and hazard relationships.",
        page="123-132",
        applicability="legacy_methodological",
    ),
    _citation(
        "NASA-GB-8719.13-6.6.7-SFTA",
        "NASA-GB-8719.13",
        "6.6.7",
        "Software Fault Tree Analysis",
        "Describes top-down fault-tree analysis of software contributions to system hazards and emphasizes tracing credible causal paths.",
        page="120-123",
        applicability="legacy_methodological",
    ),
    _citation(
        "NASA-GB-8719.13-D.4.8-DATA-EVENTS",
        "NASA-GB-8719.13",
        "Appendix D.4.8",
        "SFMEA Data and Events Tables",
        "Provides structured prompts for data failures such as wrong, missing, out-of-range, overwritten, or out-of-sequence values and event failures such as omission, incorrect logic, timing, or order.",
        page="333-336",
        applicability="legacy_methodological",
    ),
    _citation(
        "FAA-AC-450.141-1A-B.1.1-SFMEA",
        "FAA-AC-450.141-1A",
        "Appendix B.1.1",
        "Software Failure Modes and Effects Analysis",
        "Defines an SFMEA procedure covering the computing system boundary, software elements and interfaces, failure modes and causes, local and system effects, controls, and derived requirements.",
        page="48-52",
        applicability="faa_commercial_space",
    ),
    _citation(
        "FAA-AC-450.141-1A-B.1.2-TAXONOMY",
        "FAA-AC-450.141-1A",
        "Appendix B.1.2, Table B-1",
        "Example Classification of Software and Computing System Errors",
        "Provides direct calculation, data, interface, logic/control, timing, and other generalized software and computing-system failure classifications for SFMEA screening.",
        page="49-51",
        applicability="faa_commercial_space",
    ),
    _citation(
        "FAA-AC-450.141-1A-B.2-SFTA",
        "FAA-AC-450.141-1A",
        "Appendix B.2",
        "Software Fault Tree Analysis",
        "Describes top-down analysis of software contributions to hazardous top events using logical combinations and traceable contributing events.",
        page="55-59",
        applicability="faa_commercial_space",
    ),
    _citation(
        "FAA-AC-450.141-1A-7.3.1-INDEPENDENCE",
        "FAA-AC-450.141-1A",
        "7.3.1",
        "Independent Verification and Validation",
        "Calls for safety-critical computing-system verification and validation by personnel with appropriate independence from the development organization.",
        page="21",
        applicability="faa_commercial_space",
    ),
    _citation(
        "FAA-AC-450.141-1A-8.2.4-TRACE",
        "FAA-AC-450.141-1A",
        "8.2.4",
        "Verification Evidence Traceability",
        "Calls for computing-system requirements to be traced to validation and verification evidence.",
        page="23",
        applicability="faa_commercial_space",
    ),
    _citation(
        "FAA-AC-20-115D-6-LIFECYCLE",
        "FAA-AC-20-115D",
        "6",
        "Acceptable Means of Compliance",
        "Recognizes the applicable ED-12C/DO-178C objectives and software life-cycle data as an acceptable airborne-software development-assurance basis.",
        page="3-4",
        applicability="faa_airworthiness",
    ),
    _citation(
        "FAA-AC-20-115D-9.B.4-CHANGE",
        "FAA-AC-20-115D",
        "9.b(4)",
        "Software Change Impact Analysis",
        "Calls for change impact analysis, appropriate verification of affected software, and summarization of the resulting evidence in the certification context.",
        page="9",
        applicability="faa_airworthiness",
    ),
    _citation(
        "FAA-AC-20-115D-10-TOOLS",
        "FAA-AC-20-115D",
        "10",
        "Tool Qualification",
        "Identifies tool qualification as a development-assurance concern and points to DO-330 objectives when a tool's output is relied upon without otherwise required verification.",
        page="10-12",
        applicability="faa_airworthiness",
    ),
    _citation(
        "FAA-RLV-SCS-2006-B.1-PROCEDURE",
        "FAA-RLV-SCS-2006",
        "Appendix B.1",
        "Software Failure Modes and Effects Analysis",
        "Defines an SFMEA procedure covering system definition, elements, failure modes, causes, local and system effects, controls, requirements, and worksheet documentation.",
        page="36-37",
        applicability="legacy_methodological",
    ),
    _citation(
        "FAA-RLV-SCS-2006-B.1-TAXONOMY",
        "FAA-RLV-SCS-2006",
        "Appendix B.1, Table 1",
        "Example classification of software and computing system errors",
        "Provides calculation, data, interface, logic/control, timing, and related software fault and failure classifications.",
        page="37-39",
        applicability="legacy_methodological",
    ),
    _citation(
        "FAA-RLV-SCS-2006-B.1-WORKSHEET",
        "FAA-RLV-SCS-2006",
        "Appendix B.1, Table 2",
        "Example Software and Computing System FMEA worksheet",
        "Relates software elements, failure modes, causes, local effects, system effects or hazards, and risk-mitigation measures.",
        page="40-42",
        applicability="legacy_methodological",
    ),
    _citation(
        "FAA-RLV-SCS-2006-5.3-TRACEABILITY",
        "FAA-RLV-SCS-2006",
        "5.3",
        "Configuration Management and Control",
        "Calls for baselines and traceability and for changes to software and system-safety documentation to be tracked across the lifecycle.",
        page="20-21",
        applicability="legacy_methodological",
    ),
    _citation(
        "NASA-STD-8739.8B-4.2-SAFETY-CRITICAL",
        "NASA-STD-8739.8B",
        "4.2",
        "Safety-Critical Software Determination",
        "Connects safety-critical software to hazard analysis when software causes, controls, mitigates, detects, reports, or responds to a hazardous condition.",
        page="20",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NASA-STD-8739.8B-3.7.1-TRACE",
        "NASA-STD-8739.8B",
        "Table 1, NPR 7150.2 section 3.7.1, task 4",
        "Software assurance and software safety requirements mapping",
        "Calls for traceability between software requirements and hazards with software contributions.",
        page="30",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NASA-STD-8739.8B-A.1.1-COMMON-MODE",
        "NASA-STD-8739.8B",
        "Appendix A.1.1",
        "Software Contributions to Hazards",
        "Calls for hazard analysis to consider software as a hazard cause or control and to consider software common-mode failures.",
        page="62",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NASA-STD-8739.8B-A.1.4-CAUSES",
        "NASA-STD-8739.8B",
        "Appendix A.1.4, Table 2",
        "Software causes in hazard analysis",
        "Lists data, interface, communication, validation, timing, logic, and resource conditions to consider as potential software hazard causes.",
        page="62-66",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NASA-STD-8739.8B-4.4.2.20-TRACE",
        "NASA-STD-8739.8B",
        "4.4.2.20",
        "IV&V hazard traceability",
        "Calls for known software-based hazard causes, contributors, and controls to be identified, documented, and traced to project requirements.",
        page="57",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NASA-STD-8739.8B-4.4.2.46-TEST",
        "NASA-STD-8739.8B",
        "4.4.2.46",
        "Independent testing of hazardous requirements",
        "Calls for independent testing of software requirements that trace to hazardous events, causes, or mitigation techniques.",
        page="60",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NASA-NPR-7150.2D-3.12-TRACEABILITY",
        "NASA-NPR-7150.2D",
        "3.12",
        "Software Bi-Directional Traceability",
        "Defines lifecycle expectations for bidirectional traceability according to applicable software classification.",
        applicability="nasa_program_or_contract",
    ),
    _citation(
        "NIST-SP-800-218-PW.7",
        "NIST-SP-800-218",
        "PW.7",
        "Review and/or Analyze Human-Readable Code",
        "Recommends code review or analysis to identify vulnerabilities and verify compliance with security requirements.",
        page="14-15",
        applicability="security_relevant",
    ),
    _citation(
        "NIST-SP-800-218-RV.3",
        "NIST-SP-800-218",
        "RV.3",
        "Analyze Vulnerabilities to Identify Their Root Causes",
        "Recommends root-cause analysis and process improvement to reduce recurrence of vulnerabilities.",
        page="18-19",
        applicability="security_relevant",
    ),
    _citation(
        "MITRE-CWE-20",
        "MITRE-CWE",
        "CWE-20",
        "Improper Input Validation",
        "Classifies insufficient validation of input properties needed for safe and correct processing.",
        applicability="security_relevant",
        url="https://cwe.mitre.org/data/definitions/20.html",
    ),
    _citation(
        "MITRE-CWE-400",
        "MITRE-CWE",
        "CWE-400",
        "Uncontrolled Resource Consumption",
        "Classifies failure to control allocation or maintenance of a limited resource, enabling exhaustion or denial of service.",
        applicability="security_relevant",
        url="https://cwe.mitre.org/data/definitions/400.html",
    ),
    _citation(
        "MITRE-CWE-703",
        "MITRE-CWE",
        "CWE-703",
        "Improper Check or Handling of Exceptional Conditions",
        "Classifies failures to detect or correctly handle exceptional conditions that alter expected behavior.",
        applicability="security_relevant",
        url="https://cwe.mitre.org/data/definitions/703.html",
    ),
    _citation(
        "MITRE-CWE-862",
        "MITRE-CWE",
        "CWE-862",
        "Missing Authorization",
        "Classifies absence of an authorization check when an actor attempts to access a resource or perform an action.",
        applicability="security_relevant",
        url="https://cwe.mitre.org/data/definitions/862.html",
    ),
    _citation(
        "MITRE-CWE-918",
        "MITRE-CWE",
        "CWE-918",
        "Server-Side Request Forgery",
        "Classifies server-side requests whose destination or request components can be influenced without sufficient validation and policy enforcement.",
        applicability="security_relevant",
        url="https://cwe.mitre.org/data/definitions/918.html",
    ),
]


def _mapping(
    selector: str,
    citation_id: str,
    relationship: str,
    rationale: str,
    *,
    strength: str = "direct",
    profile_ids: list[str] | None = None,
) -> dict[str, Any]:
    if profile_ids is None:
        citation = next(
            value for value in GUIDANCE_CITATIONS if value["id"] == citation_id
        )
        profile_ids = [
            profile["id"]
            for profile in GUIDELINE_PROFILES
            if citation["source_id"] in profile["source_ids"]
        ]
    value = {
        "id": "MAP-"
        + hashlib.sha256(
            f"{selector}\x1f{citation_id}\x1f{relationship}".encode("utf-8")
        )
        .hexdigest()[:12]
        .upper(),
        "rule_selector": selector,
        "citation_id": citation_id,
        "relationship": relationship,
        "rationale": rationale,
        "strength": strength,
        "profile_ids": profile_ids,
        "created_by": "curated",
        "mapping_version": GUIDANCE_CATALOG_VERSION,
        "review_status": "maintainer_curated",
        "reviewed_at": GUIDANCE_RETRIEVED_AT,
        "independent_approval": False,
        "review_basis": "Exact locator plus bounded paraphrase; official source applicability remains project-reviewed.",
    }
    value["record_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return value


GUIDANCE_RULE_MAPPINGS: list[dict[str, Any]] = [
    _mapping(
        "functional.*",
        "NASA-SWEHB-8.05-PROCESS",
        "process_expectation",
        "Functional failure candidates implement the item-failure review step.",
    ),
    _mapping(
        "functional.*",
        "FAA-RLV-SCS-2006-B.1-PROCEDURE",
        "failure_taxonomy",
        "The FAA procedure considers functional software failures and their causes and effects.",
        strength="supporting",
    ),
    _mapping(
        "data.*",
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "failure_taxonomy",
        "The rule reviews documented bad-data manifestations.",
    ),
    _mapping(
        "data.*",
        "FAA-RLV-SCS-2006-B.1-TAXONOMY",
        "failure_taxonomy",
        "The FAA table includes data and representation fault classes.",
    ),
    _mapping(
        "data.invalid_input",
        "NASA-STD-8739.8B-A.1.4-CAUSES",
        "hazard_traceability",
        "The NASA hazard-cause table includes range and input/output validity faults.",
        strength="supporting",
    ),
    _mapping(
        "calculation.*",
        "FAA-RLV-SCS-2006-B.1-TAXONOMY",
        "failure_taxonomy",
        "The FAA classification includes equation, operand, sign, precision, convergence, overflow, and underflow faults.",
    ),
    _mapping(
        "logic.*",
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "failure_taxonomy",
        "The events table includes incorrect logic, omission, and ordering faults.",
    ),
    _mapping(
        "logic.*",
        "FAA-RLV-SCS-2006-B.1-TAXONOMY",
        "failure_taxonomy",
        "The FAA classification includes logic and control faults.",
    ),
    _mapping(
        "state.*",
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "failure_taxonomy",
        "State-transition faults are reviewed as incorrect, omitted, duplicated, or out-of-order events.",
        strength="supporting",
    ),
    _mapping(
        "interface.*",
        "NASA-SWEHB-8.05-PROCESS",
        "process_expectation",
        "NASA's procedure explicitly calls for interface failure modes.",
    ),
    _mapping(
        "interface.*",
        "FAA-RLV-SCS-2006-B.1-TAXONOMY",
        "failure_taxonomy",
        "The FAA classification includes calls, parameters, messages, and interface resolution faults.",
    ),
    _mapping(
        "storage.*",
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "failure_taxonomy",
        "Stored, overwritten, missing, duplicated, and incompatible data are within the documented data review.",
    ),
    _mapping(
        "configuration.*",
        "NASA-SWEHB-8.05-PROCESS",
        "process_expectation",
        "Configuration assumptions and component behavior require explicit analysis.",
        strength="contextual",
    ),
    _mapping(
        "process.*",
        "FAA-RLV-SCS-2006-B.1-PROCEDURE",
        "process_expectation",
        "External-process failure is analyzed through element, cause, effect, and mitigation fields.",
        strength="contextual",
    ),
    _mapping(
        "environment.*",
        "NASA-SWEHB-8.05-CHANGE",
        "process_expectation",
        "Environment and dependency changes require impact review and reanalysis.",
        strength="supporting",
    ),
    _mapping(
        "hardware.*",
        "NASA-STD-8739.8B-A.1.1-COMMON-MODE",
        "hazard_traceability",
        "Software must be considered as a cause or control within system hazard analysis.",
        strength="supporting",
    ),
    _mapping(
        "timing.*",
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "failure_taxonomy",
        "The NASA events table includes wrong-time and out-of-sequence behavior.",
    ),
    _mapping(
        "resilience.circuit_breaker_*",
        "NASA-SWEHB-8.05-PROCESS",
        "process_expectation",
        "Circuit-breaker candidates are analyzed as software controls with explicit failure modes, causes, propagated effects, and derived verification needs.",
    ),
    _mapping(
        "resilience.circuit_breaker_*",
        "NASA-SWEHB-8.05-DETECTION",
        "verification_expectation",
        "A detected containment mechanism is not credited until its detection, compensating, and recovery behavior is supported by objective evidence.",
    ),
    _mapping(
        "resilience.circuit_breaker_recovery",
        "NASA-SWEHB-8.05-DATA-EVENTS",
        "failure_taxonomy",
        "Cooldown and half-open recovery are reviewed for wrong-time and out-of-sequence behavior.",
    ),
    _mapping(
        "timing.*",
        "FAA-RLV-SCS-2006-B.1-TAXONOMY",
        "failure_taxonomy",
        "The FAA classification includes timing and sequencing faults.",
    ),
    _mapping(
        "detection.*",
        "NASA-SWEHB-8.05-DETECTION",
        "process_expectation",
        "The rule prompts review of detection methods and compensating provisions.",
    ),
    _mapping(
        "resource.*",
        "NASA-STD-8739.8B-A.1.4-CAUSES",
        "hazard_traceability",
        "The NASA cause table includes overload and resource-related communication failure conditions.",
        strength="supporting",
    ),
    _mapping(
        "common_cause.*",
        "NASA-STD-8739.8B-A.1.1-COMMON-MODE",
        "hazard_traceability",
        "The guidance explicitly calls for consideration of software common-mode failures.",
    ),
    _mapping(
        "*",
        "NASA-SWEHB-8.05-EFFECTS",
        "methodology_basis",
        "Every candidate is reviewed using local, next-higher-level, and end-effect propagation.",
        strength="contextual",
    ),
    _mapping(
        "*",
        "FAA-RLV-SCS-2006-B.1-WORKSHEET",
        "methodology_basis",
        "The worksheet structure relates candidates to causes, effects, hazards, and mitigations.",
        strength="contextual",
    ),
    _mapping(
        "functional.*",
        "NASA-GB-8719.13-6.6.8-SFMEA",
        "methodology_basis",
        "The guidebook's bottom-up SFMEA method reviews functional failure causes and propagated effects.",
        strength="supporting",
    ),
    _mapping(
        "data.*",
        "NASA-GB-8719.13-D.4.8-DATA-EVENTS",
        "failure_taxonomy",
        "The guidebook data table provides structured bad-data failure prompts.",
        strength="supporting",
    ),
    _mapping(
        "logic.*",
        "NASA-GB-8719.13-D.4.8-DATA-EVENTS",
        "failure_taxonomy",
        "The guidebook events table provides logic, omission, timing, and sequence prompts.",
        strength="supporting",
    ),
    _mapping(
        "timing.*",
        "NASA-GB-8719.13-D.4.8-DATA-EVENTS",
        "failure_taxonomy",
        "The guidebook events table includes wrong-time and out-of-sequence behavior.",
        strength="supporting",
    ),
    _mapping(
        "*",
        "NASA-GB-8719.13-6.6.7-SFTA",
        "hazard_traceability",
        "Bottom-up candidates should be reconciled with top-down hazard causal paths.",
        strength="contextual",
    ),
    _mapping(
        "functional.*",
        "FAA-AC-450.141-1A-B.1.1-SFMEA",
        "methodology_basis",
        "The current commercial-space guidance directly defines an SFMEA procedure for system elements, potential failure modes, causes, effects, controls, requirements, and worksheet documentation.",
    ),
    _mapping(
        "calculation.*",
        "FAA-AC-450.141-1A-B.1.2-TAXONOMY",
        "failure_taxonomy",
        "Table B-1 directly identifies calculation failure classifications including equations, operands, operators, sign, precision, convergence, overflow, and underflow.",
    ),
    _mapping(
        "data.*",
        "FAA-AC-450.141-1A-B.1.2-TAXONOMY",
        "failure_taxonomy",
        "Table B-1 directly identifies data failure classifications for SFMEA screening.",
    ),
    _mapping(
        "interface.*",
        "FAA-AC-450.141-1A-B.1.2-TAXONOMY",
        "failure_taxonomy",
        "Table B-1 directly identifies interface failure classifications for SFMEA screening.",
    ),
    _mapping(
        "logic.*",
        "FAA-AC-450.141-1A-B.1.2-TAXONOMY",
        "failure_taxonomy",
        "Table B-1 directly identifies logic and control failure classifications for SFMEA screening.",
    ),
    _mapping(
        "timing.*",
        "FAA-AC-450.141-1A-B.1.2-TAXONOMY",
        "failure_taxonomy",
        "Table B-1 directly identifies timing and sequencing failure classifications for SFMEA screening.",
    ),
    _mapping(
        "*",
        "FAA-AC-450.141-1A-B.2-SFTA",
        "hazard_traceability",
        "Candidate failure modes can support top-down reconciliation with software fault-tree events.",
        strength="contextual",
    ),
    _mapping(
        "*",
        "FAA-AC-450.141-1A-7.3.1-INDEPENDENCE",
        "verification_expectation",
        "Safety-critical verification evidence may require organizational independence under the selected commercial-space profile.",
        strength="contextual",
    ),
    _mapping(
        "*",
        "FAA-AC-450.141-1A-8.2.4-TRACE",
        "verification_expectation",
        "Requirements should be traceable to validation and verification evidence under the selected commercial-space profile.",
        strength="contextual",
    ),
    _mapping(
        "*",
        "FAA-AC-20-115D-6-LIFECYCLE",
        "process_expectation",
        "In the selected airworthiness profile, findings are assurance inputs and do not replace applicable lifecycle objectives or life-cycle data.",
        strength="contextual",
    ),
    _mapping(
        "*",
        "FAA-AC-20-115D-9.B.4-CHANGE",
        "verification_expectation",
        "Resolved findings and corrective changes require scoped impact analysis and verification in the selected airworthiness profile.",
        strength="contextual",
    ),
    _mapping(
        "*",
        "FAA-AC-20-115D-10-TOOLS",
        "verification_expectation",
        "Reliance on unverified analysis-tool output may create a separate qualification concern in the selected airworthiness profile.",
        strength="contextual",
    ),
    _mapping(
        "data.invalid_input",
        "MITRE-CWE-20",
        "security_taxonomy",
        "The scanner prompt overlaps the CWE input-validation weakness class when a security consequence is credible.",
        strength="supporting",
    ),
    _mapping(
        "resource.*",
        "MITRE-CWE-400",
        "security_taxonomy",
        "The scanner prompt overlaps uncontrolled consumption of bounded resources.",
        strength="supporting",
    ),
    _mapping(
        "detection.masked_failure",
        "MITRE-CWE-703",
        "security_taxonomy",
        "Broad or silent failure handling overlaps improper exceptional-condition handling.",
        strength="supporting",
    ),
    _mapping(
        "process.uncontrolled_failure",
        "MITRE-CWE-703",
        "security_taxonomy",
        "Unchecked subprocess failure states overlap improper exceptional-condition handling.",
        strength="supporting",
    ),
    _mapping(
        "domain.cross_scope_access",
        "MITRE-CWE-862",
        "security_taxonomy",
        "The project rule explicitly reviews missing or insufficient authorization across a resource scope.",
        strength="direct",
    ),
    _mapping(
        "domain.outbound_rebinding",
        "MITRE-CWE-918",
        "security_taxonomy",
        "The project rule explicitly reviews attacker-influenced server-side request destinations and rebinding behavior.",
        strength="direct",
    ),
    _mapping(
        "domain.*",
        "NIST-SP-800-218-PW.7",
        "process_expectation",
        "Security-relevant project rules should be reviewed or analyzed against the applicable security requirements.",
        strength="contextual",
    ),
    _mapping(
        "domain.*",
        "NIST-SP-800-218-RV.3",
        "verification_expectation",
        "Accepted security-relevant findings should feed evidence-backed root-cause and recurrence-prevention review.",
        strength="contextual",
    ),
]


def _selector_matches(selector: str, rule_id: str) -> bool:
    if selector == "*":
        return True
    if selector.endswith(".*"):
        return rule_id.startswith(selector[:-1])
    return selector == rule_id


def validate_guidance_catalog() -> None:
    """Raise when the built-in catalog contains an invalid or invented reference."""

    source_ids = [source["id"] for source in GUIDANCE_DOCUMENTS]
    profile_ids = [profile["id"] for profile in GUIDELINE_PROFILES]
    citation_ids = [citation["id"] for citation in GUIDANCE_CITATIONS]
    mapping_ids = [mapping["id"] for mapping in GUIDANCE_RULE_MAPPINGS]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("guidance source IDs must be unique")
    if len(profile_ids) != len(set(profile_ids)):
        raise ValueError("guidance profile IDs must be unique")
    if len(citation_ids) != len(set(citation_ids)):
        raise ValueError("guidance citation IDs must be unique")
    if len(mapping_ids) != len(set(mapping_ids)):
        raise ValueError("guidance mapping IDs must be unique")
    if unknown := sorted(
        {citation["source_id"] for citation in GUIDANCE_CITATIONS} - set(source_ids)
    ):
        raise ValueError(
            "guidance citations reference unknown sources: " + ", ".join(unknown)
        )
    if unknown := sorted(
        {mapping["citation_id"] for mapping in GUIDANCE_RULE_MAPPINGS}
        - set(citation_ids)
    ):
        raise ValueError(
            "guidance mappings reference unknown citations: " + ", ".join(unknown)
        )
    for mapping in GUIDANCE_RULE_MAPPINGS:
        if mapping["relationship"] not in RELATIONSHIP_TYPES:
            raise ValueError(
                f"invalid guidance relationship: {mapping['relationship']}"
            )
        if mapping["strength"] not in MAPPING_STRENGTHS:
            raise ValueError(
                f"invalid guidance mapping strength: {mapping['strength']}"
            )
        if unknown := sorted(set(mapping.get("profile_ids", [])) - set(profile_ids)):
            raise ValueError(
                "guidance mapping references unknown profiles: " + ", ".join(unknown)
            )
        if not mapping.get("profile_ids"):
            raise ValueError(
                f"guidance mapping has no applicable profile: {mapping['id']}"
            )
        if mapping.get("review_status") != "maintainer_curated":
            raise ValueError(
                f"guidance mapping lacks maintainer review state: {mapping['id']}"
            )
        material = {
            key: value for key, value in mapping.items() if key != "record_sha256"
        }
        expected = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if mapping.get("record_sha256") != expected:
            raise ValueError(f"guidance mapping digest mismatch: {mapping['id']}")
    for citation in GUIDANCE_CITATIONS:
        if citation["applicability"] not in APPLICABILITY_TYPES:
            raise ValueError(
                f"invalid guidance applicability: {citation['applicability']}"
            )
        anchor_material = {
            "source_id": citation["source_id"],
            "locator": citation["locator"],
            "summary": citation["summary"],
        }
        expected_anchor = hashlib.sha256(
            json.dumps(anchor_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if citation.get("locator_summary_sha256") != expected_anchor:
            raise ValueError(
                f"guidance citation locator digest mismatch: {citation['id']}"
            )
        citation_material = {
            key: value for key, value in citation.items() if key != "record_sha256"
        }
        expected_record = hashlib.sha256(
            json.dumps(citation_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if citation.get("record_sha256") != expected_record:
            raise ValueError(
                f"guidance citation record digest mismatch: {citation['id']}"
            )
    for source in GUIDANCE_DOCUMENTS:
        if source["applicability"] not in APPLICABILITY_TYPES:
            raise ValueError(f"invalid source applicability: {source['applicability']}")
        if len(str(source.get("record_sha256", ""))) != 64:
            raise ValueError(
                f"guidance source lacks a canonical digest: {source['id']}"
            )
        source_material = {
            key: value for key, value in source.items() if key != "record_sha256"
        }
        expected_source = hashlib.sha256(
            json.dumps(source_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if source.get("record_sha256") != expected_source:
            raise ValueError(f"guidance source record digest mismatch: {source['id']}")
    for profile in GUIDELINE_PROFILES:
        if unknown := sorted(set(profile["source_ids"]) - set(source_ids)):
            raise ValueError(
                f"guidance profile {profile['id']} references unknown sources: "
                + ", ".join(unknown)
            )


validate_guidance_catalog()


_CITATIONS_BY_ID = {citation["id"]: citation for citation in GUIDANCE_CITATIONS}
_SOURCES_BY_ID = {source["id"]: source for source in GUIDANCE_DOCUMENTS}


def normalize_profile_ids(
    profile_ids: list[str] | None, catalog: dict[str, Any] | None = None
) -> list[str]:
    """Validate, deduplicate, and deterministically order a profile selection."""

    selected = DEFAULT_GUIDANCE_PROFILES if profile_ids is None else profile_ids
    if not isinstance(selected, list) or not all(
        isinstance(value, str) for value in selected
    ):
        raise ValueError("guidance profiles must be an array of strings")
    profiles = (catalog or {}).get("profiles", GUIDELINE_PROFILES)
    known = {profile["id"] for profile in profiles}
    if unknown := sorted(set(selected) - known):
        raise ValueError("unknown guidance profile(s): " + ", ".join(unknown))
    if not selected:
        raise ValueError("at least one guidance profile is required")
    return list(dict.fromkeys(selected))


def citations_for_rule(
    rule_id: str,
    profile_ids: list[str] | None = None,
    *,
    catalog: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return curated, typed citation links inherited by one scanner rule."""

    active_profiles = normalize_profile_ids(profile_ids, catalog)
    mappings = (catalog or {}).get("rule_mappings", GUIDANCE_RULE_MAPPINGS)
    citations_by_id = {
        value["id"]: value
        for value in (catalog or {}).get("citations", GUIDANCE_CITATIONS)
    }
    links: list[dict[str, Any]] = []
    for mapping in mappings:
        if mapping.get("review_status") == "independent_rejected":
            continue
        if not _selector_matches(mapping["rule_selector"], rule_id):
            continue
        matched_profiles = [
            value for value in active_profiles if value in mapping["profile_ids"]
        ]
        if not matched_profiles:
            continue
        citation = citations_by_id[mapping["citation_id"]]
        links.append(
            {
                "citation_id": citation["id"],
                "source_id": citation["source_id"],
                "relationship": mapping["relationship"],
                "strength": mapping["strength"],
                "applicability": citation["applicability"],
                "via_rule_id": rule_id,
                "mapping_id": mapping["id"],
                "mapping_record_sha256": mapping.get("record_sha256", ""),
                "mapping_review_status": mapping.get("review_status", "unreviewed"),
                "mapping_independent_approval": bool(
                    mapping.get("independent_approval", False)
                ),
                "profile_ids": matched_profiles,
                "status": "curated",
            }
        )
    return links


def guidance_bundle(
    profile_ids: list[str] | None = None,
    *,
    organizational_packs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the complete immutable-in-practice catalog as detached JSON data."""

    core = {
        "schema_version": GUIDANCE_SCHEMA_VERSION,
        "catalog_version": GUIDANCE_CATALOG_VERSION,
        "retrieved_at": GUIDANCE_RETRIEVED_AT,
        "sources": GUIDANCE_DOCUMENTS,
        "profiles": GUIDELINE_PROFILES,
        "citations": GUIDANCE_CITATIONS,
        "rule_mappings": GUIDANCE_RULE_MAPPINGS,
    }
    bundle = copy.deepcopy(core)
    pack_records = []
    for pack in organizational_packs or []:
        _merge_organizational_pack(bundle, pack)
        pack_records.append(copy.deepcopy(pack["provenance"]))
    if pack_records:
        bundle["organizational_packs"] = pack_records
        core = {
            key: bundle[key]
            for key in (
                "schema_version",
                "catalog_version",
                "retrieved_at",
                "sources",
                "profiles",
                "citations",
                "rule_mappings",
                "organizational_packs",
            )
        }
    active_profiles = normalize_profile_ids(profile_ids, bundle)
    bundle["catalog_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    bundle["active_profiles"] = active_profiles
    bundle["selection_sha256"] = hashlib.sha256(
        json.dumps(active_profiles, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return bundle


def selected_guidance_sources(
    profile_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return detached source records applicable to the selected profiles."""

    active_profiles = normalize_profile_ids(profile_ids)
    source_ids = {
        source_id
        for profile in GUIDELINE_PROFILES
        if profile["id"] in active_profiles
        for source_id in profile["source_ids"]
    }
    return copy.deepcopy(
        [source for source in GUIDANCE_DOCUMENTS if source["id"] in source_ids]
    )


def selected_sources_from_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Return sources selected by a resolved built-in/organizational catalog."""

    active_profiles = normalize_profile_ids(bundle.get("active_profiles"), bundle)
    source_ids = {
        source_id
        for profile in bundle.get("profiles", [])
        if profile.get("id") in active_profiles
        for source_id in profile.get("source_ids", [])
    }
    return copy.deepcopy(
        [
            source
            for source in bundle.get("sources", [])
            if source.get("id") in source_ids
        ]
    )


def load_organizational_guidance_pack(path: str | Path) -> dict[str, Any]:
    """Load and strictly validate a local organizational guidance pack."""

    try:
        document = load_bounded_json_document(
            path,
            label="organizational guidance pack",
            max_bytes=MAX_ORGANIZATIONAL_GUIDANCE_PACK_BYTES,
            max_depth=MAX_ORGANIZATIONAL_GUIDANCE_PACK_DEPTH,
            max_nodes=MAX_ORGANIZATIONAL_GUIDANCE_PACK_NODES,
        )
    except ValueError as exc:
        message = str(exc)
        if message == (
            "organizational guidance pack exceeds the "
            f"{MAX_ORGANIZATIONAL_GUIDANCE_PACK_BYTES}-byte limit"
        ):
            raise ValueError(
                "organizational guidance pack exceeds the "
                f"{MAX_ORGANIZATIONAL_GUIDANCE_PACK_BYTES}-byte safety limit"
            ) from exc
        raise
    source_path = document.path
    payload = document.value
    raw = document.raw
    if not isinstance(payload, dict):
        raise ValueError("organizational guidance pack root must be an object")
    allowed = {"schema_version", "profile", "sources", "citations", "rule_mappings"}
    if unknown := set(payload) - allowed:
        raise ValueError(
            "unknown organizational guidance pack field(s): "
            + ", ".join(sorted(unknown))
        )
    if payload.get("schema_version") != "pysfmea-organizational-guidance-pack-1":
        raise ValueError("unsupported organizational guidance pack schema")
    profile = payload.get("profile")
    sources = payload.get("sources")
    citations = payload.get("citations")
    mappings = payload.get("rule_mappings")
    if not isinstance(profile, dict):
        raise ValueError("organizational guidance pack profile must be an object")
    if (
        not isinstance(sources, list)
        or not isinstance(citations, list)
        or not isinstance(mappings, list)
    ):
        raise ValueError(
            "organizational guidance pack sources, citations, and rule_mappings must be arrays"
        )
    required_profile = {
        "id",
        "title",
        "status",
        "applicability",
        "risk_semantics",
        "verification_semantics",
        "tailoring",
        "compliance_claim",
    }
    if missing := required_profile - set(profile):
        raise ValueError(
            "organizational profile missing field(s): " + ", ".join(sorted(missing))
        )
    if not isinstance(profile.get("id"), str) or not profile["id"].startswith("org."):
        raise ValueError("organizational profile id must start with 'org.'")
    for field in required_profile - {"compliance_claim"}:
        if not isinstance(profile.get(field), str) or not profile[field].strip():
            raise ValueError(
                f"organizational profile {field} must be a non-empty string"
            )
    if profile.get("compliance_claim") is not False:
        raise ValueError(
            "organizational guidance packs cannot assert a compliance claim"
        )
    required_source = {
        "id",
        "publisher",
        "title",
        "version",
        "status",
        "published_at",
        "url",
        "official_source",
        "scope",
        "use",
        "access",
        "quote_policy",
    }
    source_ids: set[str] = set()
    for index, source in enumerate(sources, start=1):
        if not isinstance(source, dict):
            raise ValueError(f"organizational source {index} must be an object")
        if missing := required_source - set(source):
            raise ValueError(
                f"organizational source {index} missing field(s): "
                + ", ".join(sorted(missing))
            )
        source_id = source.get("id")
        if not isinstance(source_id, str) or not source_id.startswith("ORG-"):
            raise ValueError("organizational source ids must start with 'ORG-'")
        if source_id in source_ids:
            raise ValueError(f"duplicate organizational source id: {source_id}")
        for field in required_source - {"id"}:
            if not isinstance(source.get(field), str) or not source[field].strip():
                raise ValueError(
                    f"organizational source {source_id} {field} must be a non-empty string"
                )
        artifact = source.get("artifact")
        if artifact is not None:
            if not isinstance(artifact, dict):
                raise ValueError(
                    f"organizational source {source_id} artifact must be an object"
                )
            digest = artifact.get("sha256", "")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(
                    character not in "0123456789abcdefABCDEF" for character in digest
                )
            ):
                raise ValueError(
                    f"organizational source {source_id} artifact requires a SHA-256 digest"
                )
        source_ids.add(source_id)
        source["applicability"] = "organizational"
        material = {
            key: value for key, value in source.items() if key != "record_sha256"
        }
        source["record_sha256"] = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    citation_ids: set[str] = set()
    for index, citation in enumerate(citations, start=1):
        if not isinstance(citation, dict):
            raise ValueError(f"organizational citation {index} must be an object")
        required = {"id", "source_id", "locator", "summary"}
        if missing := required - set(citation):
            raise ValueError(
                f"organizational citation {index} missing field(s): "
                + ", ".join(sorted(missing))
            )
        citation_id = citation.get("id")
        if not isinstance(citation_id, str) or not citation_id.startswith("ORG-CIT-"):
            raise ValueError("organizational citation ids must start with 'ORG-CIT-'")
        if citation_id in citation_ids:
            raise ValueError(f"duplicate organizational citation id: {citation_id}")
        if citation.get("source_id") not in source_ids:
            raise ValueError(
                f"organizational citation {citation_id} references an unknown source"
            )
        if (
            not isinstance(citation.get("summary"), str)
            or not citation["summary"].strip()
        ):
            raise ValueError(
                f"organizational citation {citation_id} summary must be a non-empty string"
            )
        locator = citation.get("locator")
        if not isinstance(locator, dict) or not (
            str(locator.get("section", "")).strip()
            or str(locator.get("heading", "")).strip()
        ):
            raise ValueError(
                f"organizational citation {citation_id} requires an exact locator"
            )
        citation["applicability"] = "organizational"
        anchor_material = {
            "source_id": citation["source_id"],
            "locator": citation["locator"],
            "summary": citation["summary"],
        }
        citation["locator_summary_sha256"] = hashlib.sha256(
            json.dumps(anchor_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        citation_material = {
            key: value for key, value in citation.items() if key != "record_sha256"
        }
        citation["record_sha256"] = hashlib.sha256(
            json.dumps(citation_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        citation_ids.add(citation_id)
    for index, mapping in enumerate(mappings, start=1):
        if not isinstance(mapping, dict):
            raise ValueError(f"organizational rule mapping {index} must be an object")
        required = {"id", "rule_selector", "citation_id", "relationship", "strength"}
        if missing := required - set(mapping):
            raise ValueError(
                f"organizational rule mapping {index} missing field(s): "
                + ", ".join(sorted(missing))
            )
        if mapping.get("citation_id") not in citation_ids:
            raise ValueError(
                f"organizational mapping {mapping.get('id')} references an unknown citation"
            )
        if mapping.get("relationship") not in RELATIONSHIP_TYPES:
            raise ValueError(
                f"organizational mapping {mapping.get('id')} has an invalid relationship"
            )
        if mapping.get("strength") not in MAPPING_STRENGTHS:
            raise ValueError(
                f"organizational mapping {mapping.get('id')} has an invalid strength"
            )
        if not isinstance(mapping.get("id"), str) or not mapping["id"].startswith(
            "ORG-MAP-"
        ):
            raise ValueError("organizational mapping ids must start with 'ORG-MAP-'")
        if (
            not isinstance(mapping.get("rule_selector"), str)
            or not mapping["rule_selector"].strip()
        ):
            raise ValueError(
                f"organizational mapping {mapping.get('id')} requires a rule selector"
            )
        mapping["profile_ids"] = [profile["id"]]
        mapping.setdefault("created_by", "organizational_pack")
        mapping.setdefault("mapping_version", str(profile.get("id", "organizational")))
        review = mapping.get("review")
        if review is None:
            mapping["review_status"] = "organization_supplied"
            mapping["reviewed_at"] = ""
            mapping["independent_approval"] = False
            mapping["review_basis"] = (
                "Organization-supplied mapping; approval authority is external to PySFMEA."
            )
        else:
            if not isinstance(review, dict):
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} review must be an object"
                )
            review_fields = {
                "decision",
                "producer",
                "reviewer",
                "authority",
                "reviewed_at",
                "expires_at",
                "source_revision",
                "rationale",
            }
            if unknown := set(review) - review_fields:
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} review contains unsupported "
                    "fields: " + ", ".join(sorted(unknown))
                )
            required_review = review_fields - {"expires_at"}
            if missing := required_review - set(review):
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} review missing field(s): "
                    + ", ".join(sorted(missing))
                )
            for field in required_review | {"expires_at"}:
                value = review.get(field, "")
                if not isinstance(value, str) or len(value) > 4096:
                    raise ValueError(
                        f"organizational mapping {mapping.get('id')} review {field} must be "
                        "a bounded string"
                    )
                if field != "expires_at" and not value.strip():
                    raise ValueError(
                        f"organizational mapping {mapping.get('id')} review {field} must be "
                        "non-empty"
                    )
            decision = review["decision"].strip()
            if decision not in {"approved", "rejected"}:
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} review decision is unsupported"
                )
            if (
                review["producer"].strip().casefold()
                == review["reviewer"].strip().casefold()
            ):
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} independent review requires "
                    "distinct producer and reviewer identities"
                )
            try:
                date.fromisoformat(review["reviewed_at"].strip())
                if review.get("expires_at", "").strip():
                    date.fromisoformat(review["expires_at"].strip())
            except ValueError as exc:
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} review dates must use YYYY-MM-DD"
                ) from exc
            citation = next(
                value for value in citations if value["id"] == mapping["citation_id"]
            )
            source = next(
                value for value in sources if value["id"] == citation["source_id"]
            )
            if review["source_revision"].strip() != source["version"]:
                raise ValueError(
                    f"organizational mapping {mapping.get('id')} review source_revision does "
                    "not match its governed source version"
                )
            review.setdefault("expires_at", "")
            review_material = {
                key: review.get(key, "") for key in sorted(review_fields)
            }
            review["record_sha256"] = hashlib.sha256(
                json.dumps(
                    review_material, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            mapping["review_status"] = f"independent_{decision}"
            mapping["reviewed_at"] = review["reviewed_at"].strip()
            mapping["independent_approval"] = decision == "approved"
            mapping["review_basis"] = review["rationale"].strip()
        mapping_material = {
            key: value for key, value in mapping.items() if key != "record_sha256"
        }
        mapping["record_sha256"] = hashlib.sha256(
            json.dumps(mapping_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    all_ids = [
        profile["id"],
        *(value["id"] for value in sources),
        *(value["id"] for value in citations),
        *(value["id"] for value in mappings),
    ]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("organizational guidance pack IDs must be globally unique")
    profile["source_ids"] = sorted(source_ids)
    payload["provenance"] = {
        "path": source_path.name,
        "source_location": "local_explicit_input",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "profile_id": profile["id"],
    }
    return payload


def _merge_organizational_pack(bundle: dict[str, Any], pack: dict[str, Any]) -> None:
    existing = {
        value.get("id")
        for field in ("profiles", "sources", "citations", "rule_mappings")
        for value in bundle.get(field, [])
    }
    incoming = [
        pack["profile"],
        *pack["sources"],
        *pack["citations"],
        *pack["rule_mappings"],
    ]
    collisions = sorted(
        str(value.get("id")) for value in incoming if value.get("id") in existing
    )
    if collisions:
        raise ValueError(
            "organizational guidance IDs collide with the resolved catalog: "
            + ", ".join(collisions)
        )
    bundle["profiles"].append(copy.deepcopy(pack["profile"]))
    bundle["sources"].extend(copy.deepcopy(pack["sources"]))
    bundle["citations"].extend(copy.deepcopy(pack["citations"]))
    bundle["rule_mappings"].extend(copy.deepcopy(pack["rule_mappings"]))


def analysis_guidance_profiles(analysis: dict[str, Any]) -> list[str]:
    """Resolve the persisted selection without silently enabling extra authorities."""

    embedded = analysis.get("guidance", {})
    if isinstance(embedded, dict) and isinstance(embedded.get("active_profiles"), list):
        return normalize_profile_ids(embedded["active_profiles"], embedded)
    configured = (
        analysis.get("context", {}).get("analysis", {}).get("guidance_profiles")
    )
    return normalize_profile_ids(configured)


def apply_guidance_applicability(
    bundle: dict[str, Any], decisions: list[dict[str, Any]] | None
) -> dict[str, Any]:
    """Attach project-owned profile-selection evidence to a catalog projection."""

    active_profiles = [
        value
        for value in bundle.get("active_profiles", [])
        if isinstance(value, str)
    ]
    preserved = copy.deepcopy(decisions or [])
    decided_profiles = {
        value.get("profile_id")
        for value in preserved
        if isinstance(value, dict) and isinstance(value.get("profile_id"), str)
    }
    bundle["applicability_decisions"] = preserved
    bundle["applicability_summary"] = {
        "active_profiles": len(active_profiles),
        "decided_profiles": len(decided_profiles & set(active_profiles)),
        "missing_profile_ids": sorted(set(active_profiles) - decided_profiles),
        "notice": (
            "Profile selection is a tool input until a named project authority records an "
            "applicability decision."
        ),
    }
    return bundle


def apply_project_guidance_mappings(
    bundle: dict[str, Any], mappings: list[dict[str, Any]] | None
) -> dict[str, Any]:
    """Attach named project-reviewed mappings to built-in source records.

    These relationships are project configuration, not changes to the shipped
    catalog and not independent regulatory approval. Configuration validation
    restricts them to known built-in citations and closed relationship types.
    """

    supplied = copy.deepcopy(mappings or [])
    citations = {
        str(value.get("id", "")): value
        for value in bundle.get("citations", [])
        if isinstance(value, dict)
    }
    profiles = [
        value for value in bundle.get("profiles", []) if isinstance(value, dict)
    ]
    existing = {
        (
            str(value.get("rule_selector", "")),
            str(value.get("citation_id", "")),
            str(value.get("relationship", "")),
            str(value.get("strength", "")),
        )
        for value in bundle.get("rule_mappings", [])
        if isinstance(value, dict)
    }
    applied: list[str] = []
    shadowed: list[str] = []
    for configured in supplied:
        selector = str(configured.get("rule_selector", ""))
        citation_id = str(configured.get("citation_id", ""))
        relationship = str(configured.get("relationship", ""))
        strength = str(configured.get("strength", ""))
        identity = (selector, citation_id, relationship, strength)
        mapping_id = "PROJECT-MAP-" + hashlib.sha256(
            "\x1f".join(
                (
                    selector,
                    citation_id,
                    relationship,
                    strength,
                    str(configured.get("reviewed_by", "")),
                    str(configured.get("effective_date", "")),
                )
            ).encode("utf-8")
        ).hexdigest()[:12].upper()
        if identity in existing:
            shadowed.append(mapping_id)
            continue
        citation = citations[citation_id]
        source_id = str(citation.get("source_id", ""))
        profile_ids = [
            str(profile.get("id", ""))
            for profile in profiles
            if source_id in profile.get("source_ids", [])
        ]
        value: dict[str, Any] = {
            "id": mapping_id,
            "rule_selector": selector,
            "citation_id": citation_id,
            "relationship": relationship,
            "rationale": str(configured.get("rationale", "")),
            "strength": strength,
            "profile_ids": profile_ids,
            "created_by": "project_configuration",
            "mapping_version": "project-reviewed-1",
            "review_status": "project_reviewed",
            "reviewed_at": str(configured.get("effective_date", "")),
            "independent_approval": False,
            "review_basis": (
                f"Named project review by {configured.get('reviewed_by', '')}; "
                "regulatory applicability and independent approval remain external."
            ),
        }
        value["record_sha256"] = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        bundle.setdefault("rule_mappings", []).append(value)
        existing.add(identity)
        applied.append(mapping_id)
    bundle["project_mapping_application"] = {
        "configured": len(supplied),
        "applied": len(applied),
        "shadowed_by_existing_mapping": len(shadowed),
        "mapping_ids": applied,
        "shadowed_mapping_ids": shadowed,
        "authority": (
            "named_project_mapping_review_not_independent_approval_or_compliance"
        ),
    }
    return bundle


def ensure_guidance_traceability(
    analysis: dict[str, Any], *, refresh: bool = False
) -> dict[str, Any]:
    """Add missing guidance data or refresh scanner-owned mappings explicitly."""

    active_profiles = analysis_guidance_profiles(analysis)
    existing_bundle = analysis.get("guidance", {})
    if refresh or not isinstance(analysis.get("guidance"), dict):
        if isinstance(existing_bundle, dict) and existing_bundle.get(
            "organizational_packs"
        ):
            analysis["guidance"] = existing_bundle
        else:
            analysis["guidance"] = guidance_bundle(active_profiles)
    resolved_bundle = analysis.get("guidance", {})
    if isinstance(resolved_bundle, dict):
        configured_decisions = analysis.get("context", {}).get(
            "guidance_applicability"
        )
        if not isinstance(configured_decisions, list):
            configured_decisions = existing_bundle.get("applicability_decisions", [])
        apply_guidance_applicability(resolved_bundle, configured_decisions)
        configured_mappings = analysis.get("context", {}).get(
            "guidance_rule_mappings", []
        )
        if not isinstance(configured_mappings, list):
            configured_mappings = []
        apply_project_guidance_mappings(resolved_bundle, configured_mappings)
    methodology = analysis.setdefault("methodology", {})
    if refresh:
        methodology["basis"] = selected_sources_from_bundle(resolved_bundle)
    else:
        methodology.setdefault("basis", selected_sources_from_bundle(resolved_bundle))
    methodology.setdefault("notice", METHODOLOGY_NOTICE)
    methodology.setdefault("review_checklist", copy.deepcopy(REVIEW_CHECKLIST))
    for item in analysis.get("items", []):
        scanner = item.get("scanner")
        if isinstance(scanner, dict):
            if refresh:
                inherited = citations_for_rule(
                    str(scanner.get("rule_id", "")),
                    active_profiles,
                    catalog=resolved_bundle,
                )
                retained = [
                    link
                    for link in scanner.get("citations", [])
                    if isinstance(link, dict)
                    and link.get("status") in {"proposed", "reviewer_accepted"}
                    and link.get("citation_id")
                    in {
                        value.get("id")
                        for value in resolved_bundle.get("citations", [])
                    }
                ]
                seen = {
                    (link.get("citation_id"), link.get("relationship"))
                    for link in inherited
                }
                scanner["citations"] = [
                    *inherited,
                    *(
                        link
                        for link in retained
                        if (link.get("citation_id"), link.get("relationship"))
                        not in seen
                    ),
                ]
            else:
                scanner.setdefault(
                    "citations",
                    citations_for_rule(
                        str(scanner.get("rule_id", "")),
                        active_profiles,
                        catalog=resolved_bundle,
                    ),
                )
    return analysis


def mapping_review_expiry_audit(
    analysis: dict[str, Any],
    *,
    bundle: dict[str, Any] | None = None,
    active_profiles: list[str] | None = None,
) -> dict[str, Any]:
    """Audit mapping-review expiry against a reproducible analysis timestamp."""

    resolved_bundle = (
        bundle if isinstance(bundle, dict) else analysis.get("guidance", {})
    )
    if not isinstance(resolved_bundle, dict):
        resolved_bundle = {}
    profiles = (
        active_profiles
        if active_profiles is not None
        else analysis_guidance_profiles(analysis)
    )
    audit_date: date | None = None
    for candidate in (
        analysis.get("run_manifest", {}).get("created_at", ""),
        analysis.get("project", {}).get("scanned_at", ""),
        resolved_bundle.get("retrieved_at", ""),
        GUIDANCE_RETRIEVED_AT,
    ):
        try:
            audit_date = date.fromisoformat(str(candidate).strip()[:10])
            break
        except (TypeError, ValueError):
            continue
    if (
        audit_date is None
    ):  # pragma: no cover - the module constant is valid by contract
        audit_date = date(1970, 1, 1)
    active_profile_set = set(profiles)
    expired: list[str] = []
    invalid: list[str] = []
    for mapping in resolved_bundle.get("rule_mappings", []):
        if not isinstance(mapping, dict):
            continue
        profile_ids = mapping.get("profile_ids", [])
        if not isinstance(profile_ids, list) or not active_profile_set.intersection(
            str(value) for value in profile_ids
        ):
            continue
        review = mapping.get("review")
        if not isinstance(review, dict) or review.get("decision") != "approved":
            continue
        expires_at = str(review.get("expires_at", "")).strip()
        if not expires_at:
            continue
        try:
            expiry = date.fromisoformat(expires_at)
        except ValueError:
            invalid.append(str(mapping.get("id", "")))
            continue
        if expiry < audit_date:
            expired.append(str(mapping.get("id", "")))
    manifest_integrity = verify_run_manifest_integrity(analysis)
    timestamp_integrity = manifest_integrity["checks"].get(
        "timestamp_binding", False
    ) and manifest_integrity["checks"].get("content_integrity", False)
    return {
        "audit_as_of": audit_date.isoformat(),
        "timestamp_source": (
            "run_manifest.created_at"
            if analysis.get("run_manifest", {}).get("created_at")
            else "persisted_analysis_fallback"
        ),
        "timestamp_integrity": "verified" if timestamp_integrity else "invalid",
        "expired_mapping_review_ids": sorted(expired),
        "invalid_mapping_review_expiry_ids": sorted(invalid),
    }


def guidance_traceability(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build source-to-rule-to-finding relationships for programmatic export."""

    active_profiles = analysis_guidance_profiles(analysis)
    embedded = analysis.get("guidance", {})
    bundle = (
        copy.deepcopy(embedded)
        if isinstance(embedded, dict)
        else guidance_bundle(active_profiles)
    )
    active_mappings = [
        mapping
        for mapping in bundle.get("rule_mappings", [])
        if isinstance(mapping, dict)
        and set(mapping.get("profile_ids", [])) & set(active_profiles)
    ]
    mapping_review_states = Counter(
        str(mapping.get("review_status", "unreviewed")) for mapping in active_mappings
    )
    mapping_integrity_failures = 0
    unverifiable_legacy_mappings = 0
    review_integrity_failures = 0
    invalid_mapping_ids: set[str] = set()
    for mapping in active_mappings:
        material = {
            key: value for key, value in mapping.items() if key != "record_sha256"
        }
        expected = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        recorded = mapping.get("record_sha256")
        if not recorded:
            unverifiable_legacy_mappings += 1
            invalid_mapping_ids.add(str(mapping.get("id", "")))
        elif recorded != expected:
            mapping_integrity_failures += 1
            invalid_mapping_ids.add(str(mapping.get("id", "")))
        review = mapping.get("review")
        if isinstance(review, dict):
            review_material = {
                key: value for key, value in review.items() if key != "record_sha256"
            }
            expected_review = hashlib.sha256(
                json.dumps(
                    review_material, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            if review.get("record_sha256") != expected_review:
                review_integrity_failures += 1
                invalid_mapping_ids.add(str(mapping.get("id", "")))
    review_expiry = mapping_review_expiry_audit(
        analysis,
        bundle=bundle,
        active_profiles=active_profiles,
    )
    expired_mapping_ids = set(review_expiry["expired_mapping_review_ids"])
    review_timestamp_valid = review_expiry["timestamp_integrity"] == "verified"
    citations_by_id = {value.get("id") for value in bundle.get("citations", [])}
    active = [
        item
        for item in analysis.get("items", [])
        if item.get("source_status", "active") == "active"
    ]
    finding_links: list[dict[str, Any]] = []
    cited_items: set[str] = set()
    used_citations: Counter[str] = Counter()
    used_sources: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    strengths: Counter[str] = Counter()
    relationships: Counter[str] = Counter()
    directly_cited_items: set[str] = set()
    supporting_only_items: set[str] = set()
    contextual_only_items: set[str] = set()
    direct_rules: set[str] = set()
    for item in active:
        scanner = item.get("scanner", {})
        rule_id = str(scanner.get("rule_id", ""))
        links = scanner.get("citations")
        if not isinstance(links, list):
            links = citations_for_rule(rule_id, active_profiles, catalog=bundle)
        normalized_links = [
            link
            for link in links
            if isinstance(link, dict) and link.get("citation_id") in citations_by_id
        ]
        if normalized_links:
            cited_items.add(str(item.get("id", "")))
        finding_strengths = {str(link.get("strength", "")) for link in normalized_links}
        strongest = (
            "direct"
            if "direct" in finding_strengths
            else "supporting"
            if "supporting" in finding_strengths
            else "contextual"
            if "contextual" in finding_strengths
            else "uncited"
        )
        finding_id = str(item.get("id", ""))
        if strongest == "direct":
            directly_cited_items.add(finding_id)
            direct_rules.add(rule_id)
        elif strongest == "supporting":
            supporting_only_items.add(finding_id)
        elif strongest == "contextual":
            contextual_only_items.add(finding_id)
        rules[rule_id] += 1
        for link in normalized_links:
            used_citations[str(link["citation_id"])] += 1
            used_sources[str(link["source_id"])] += 1
            strengths[str(link.get("strength", "unknown"))] += 1
            relationships[str(link.get("relationship", "unknown"))] += 1
        finding_links.append(
            {
                "finding_id": item.get("id", ""),
                "component_id": item.get("component_id", ""),
                "component": item.get("component", {}).get("qualname", ""),
                "source": item.get("source", {}),
                "rule_id": rule_id,
                "failure_class": scanner.get("failure_class", ""),
                "strongest_mapping": strongest,
                "citations": copy.deepcopy(normalized_links),
            }
        )
    total = len(active)
    total_citation_uses = sum(used_citations.values())
    broadly_reused_citations = {
        citation_id: uses
        for citation_id, uses in used_citations.items()
        if total and uses / total >= 0.8
    }
    bundle.update(
        {
            "finding_links": finding_links,
            "mapping_governance": {
                "active_mappings": len(active_mappings),
                "review_statuses": dict(sorted(mapping_review_states.items())),
                "independently_approved_mappings": sum(
                    bool(mapping.get("independent_approval", False))
                    and review_timestamp_valid
                    for mapping in active_mappings
                ),
                "effective_independently_approved_mappings": sum(
                    bool(mapping.get("independent_approval", False))
                    and str(mapping.get("id", "")) not in expired_mapping_ids
                    and str(mapping.get("id", "")) not in invalid_mapping_ids
                    for mapping in active_mappings
                ),
                "review_audit_as_of": review_expiry["audit_as_of"],
                "review_audit_timestamp_source": review_expiry["timestamp_source"],
                "review_audit_timestamp_integrity": review_expiry[
                    "timestamp_integrity"
                ],
                "expired_mapping_reviews": len(expired_mapping_ids),
                "expired_mapping_review_ids": sorted(expired_mapping_ids),
                "invalid_mapping_review_expiries": len(
                    review_expiry["invalid_mapping_review_expiry_ids"]
                ),
                "mapping_integrity_failures": mapping_integrity_failures,
                "review_integrity_failures": review_integrity_failures,
                "unverifiable_legacy_mappings": unverifiable_legacy_mappings,
                "rejected_mappings": sum(
                    mapping.get("review_status") == "independent_rejected"
                    for mapping in active_mappings
                ),
                "notice": (
                    "Maintainer curation is not independent regulatory approval; projects must "
                    "approve applicability and mapping strength under their own authority. "
                    "Mappings without record digests are retained as legacy-unverifiable rather "
                    "than being misreported as integrity failures. Approval effectiveness is "
                    "audited against the persisted analysis timestamp, not the viewer's clock."
                ),
            },
            "coverage": {
                "active_findings": total,
                "cited_findings": len(cited_items),
                "uncited_findings": total - len(cited_items),
                "directly_cited_findings": len(directly_cited_items),
                "supporting_only_findings": len(supporting_only_items),
                "contextual_only_findings": len(contextual_only_items),
                "finding_coverage_percent": round(len(cited_items) * 100 / total, 1)
                if total
                else 100.0,
                "direct_finding_coverage_percent": round(
                    len(directly_cited_items) * 100 / total, 1
                )
                if total
                else 100.0,
                "used_citations": len(used_citations),
                "used_sources": len(used_sources),
                "total_citation_uses": total_citation_uses,
                "average_citations_per_finding": round(
                    total_citation_uses / total, 2
                )
                if total
                else 0.0,
                "broadly_reused_citations": dict(
                    sorted(broadly_reused_citations.items())
                ),
                "broadly_reused_citation_count": len(
                    broadly_reused_citations
                ),
                "specificity_notice": (
                    "Coverage counts methodology, supporting, and contextual mappings. Broadly "
                    "reused citations apply to at least 80% of active findings and must not be "
                    "read as finding-specific regulatory applicability."
                ),
                "findings_by_rule": dict(sorted(rules.items())),
                "rules_with_direct_mapping": sorted(direct_rules),
                "rules_without_direct_mapping": sorted(set(rules) - direct_rules),
                "uses_by_mapping_strength": dict(sorted(strengths.items())),
                "uses_by_relationship": dict(sorted(relationships.items())),
                "uses_by_citation": dict(sorted(used_citations.items())),
                "uses_by_source": dict(sorted(used_sources.items())),
            },
            "notice": (
                "Guidance relationships explain methodology and review relevance. They do not "
                "prove a defect, establish regulatory applicability, or demonstrate compliance."
            ),
        }
    )
    return bundle


GUIDANCE_SOURCES: list[dict[str, Any]] = copy.deepcopy(GUIDANCE_DOCUMENTS)


METHODOLOGY_NOTICE = (
    "Scanner output is a set of candidate failure modes, not an approved FMEA. "
    "Guidance citations describe methodology or review relevance and are not findings "
    "of noncompliance. Severity must be based on the credible end effect. Occurrence and "
    "detection, when used, require project-defined scales and evidence. Complexity, dependency "
    "count, and test-file presence are screening signals and are not substituted for S/O/D "
    "ratings. Qualified people must review scope, effects, controls, ratings, actions, "
    "applicability, and residual risk."
)


REVIEW_CHECKLIST = [
    "Confirm the component's intended function and requirement.",
    "Decide whether the candidate is a credible failure mode in the defined scope.",
    "Trace local effect to the next-higher level and the system/end effect.",
    "Identify specific causes, including data, logic, interface, timing, and state faults.",
    "Record existing prevention and detection controls with objective evidence.",
    "Review each guidance citation for applicability; do not treat relevance as noncompliance.",
    "Apply the project's documented rating scales; do not infer severity from code metrics.",
    "Define actions, owners, verification evidence, and closure criteria.",
    "After a design change, rescan and confirm that no new failure path was introduced.",
]


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    "__pycache__",
}
