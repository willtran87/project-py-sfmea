"""Versioned public guidance and machine-readable SFMEA traceability mappings."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from typing import Any


GUIDANCE_SCHEMA_VERSION = "1.1"
GUIDANCE_CATALOG_VERSION = "2026.08.04"
GUIDANCE_RETRIEVED_AT = "2026-08-04"

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

GUIDELINE_PROFILES = [
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


GUIDANCE_DOCUMENTS = [
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
        canonical = {key: value for key, value in record.items() if key != "record_sha256"}
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
    value["record_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return value


GUIDANCE_CITATIONS = [
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
        citation = next(value for value in GUIDANCE_CITATIONS if value["id"] == citation_id)
        profile_ids = [
            profile["id"]
            for profile in GUIDELINE_PROFILES
            if citation["source_id"] in profile["source_ids"]
        ]
    return {
        "id": "MAP-" + hashlib.sha256(
            f"{selector}\x1f{citation_id}\x1f{relationship}".encode("utf-8")
        ).hexdigest()[:12].upper(),
        "rule_selector": selector,
        "citation_id": citation_id,
        "relationship": relationship,
        "rationale": rationale,
        "strength": strength,
        "profile_ids": profile_ids,
        "created_by": "curated",
        "mapping_version": GUIDANCE_CATALOG_VERSION,
    }


GUIDANCE_RULE_MAPPINGS = [
    _mapping("functional.*", "NASA-SWEHB-8.05-PROCESS", "process_expectation", "Functional failure candidates implement the item-failure review step."),
    _mapping("functional.*", "FAA-RLV-SCS-2006-B.1-PROCEDURE", "failure_taxonomy", "The FAA procedure considers functional software failures and their causes and effects.", strength="supporting"),
    _mapping("data.*", "NASA-SWEHB-8.05-DATA-EVENTS", "failure_taxonomy", "The rule reviews documented bad-data manifestations."),
    _mapping("data.*", "FAA-RLV-SCS-2006-B.1-TAXONOMY", "failure_taxonomy", "The FAA table includes data and representation fault classes."),
    _mapping("data.invalid_input", "NASA-STD-8739.8B-A.1.4-CAUSES", "hazard_traceability", "The NASA hazard-cause table includes range and input/output validity faults.", strength="supporting"),
    _mapping("calculation.*", "FAA-RLV-SCS-2006-B.1-TAXONOMY", "failure_taxonomy", "The FAA classification includes equation, operand, sign, precision, convergence, overflow, and underflow faults."),
    _mapping("logic.*", "NASA-SWEHB-8.05-DATA-EVENTS", "failure_taxonomy", "The events table includes incorrect logic, omission, and ordering faults."),
    _mapping("logic.*", "FAA-RLV-SCS-2006-B.1-TAXONOMY", "failure_taxonomy", "The FAA classification includes logic and control faults."),
    _mapping("state.*", "NASA-SWEHB-8.05-DATA-EVENTS", "failure_taxonomy", "State-transition faults are reviewed as incorrect, omitted, duplicated, or out-of-order events.", strength="supporting"),
    _mapping("interface.*", "NASA-SWEHB-8.05-PROCESS", "process_expectation", "NASA's procedure explicitly calls for interface failure modes."),
    _mapping("interface.*", "FAA-RLV-SCS-2006-B.1-TAXONOMY", "failure_taxonomy", "The FAA classification includes calls, parameters, messages, and interface resolution faults."),
    _mapping("storage.*", "NASA-SWEHB-8.05-DATA-EVENTS", "failure_taxonomy", "Stored, overwritten, missing, duplicated, and incompatible data are within the documented data review."),
    _mapping("configuration.*", "NASA-SWEHB-8.05-PROCESS", "process_expectation", "Configuration assumptions and component behavior require explicit analysis.", strength="contextual"),
    _mapping("process.*", "FAA-RLV-SCS-2006-B.1-PROCEDURE", "process_expectation", "External-process failure is analyzed through element, cause, effect, and mitigation fields.", strength="contextual"),
    _mapping("environment.*", "NASA-SWEHB-8.05-CHANGE", "process_expectation", "Environment and dependency changes require impact review and reanalysis.", strength="supporting"),
    _mapping("hardware.*", "NASA-STD-8739.8B-A.1.1-COMMON-MODE", "hazard_traceability", "Software must be considered as a cause or control within system hazard analysis.", strength="supporting"),
    _mapping("timing.*", "NASA-SWEHB-8.05-DATA-EVENTS", "failure_taxonomy", "The NASA events table includes wrong-time and out-of-sequence behavior."),
    _mapping("timing.*", "FAA-RLV-SCS-2006-B.1-TAXONOMY", "failure_taxonomy", "The FAA classification includes timing and sequencing faults."),
    _mapping("detection.*", "NASA-SWEHB-8.05-DETECTION", "process_expectation", "The rule prompts review of detection methods and compensating provisions."),
    _mapping("resource.*", "NASA-STD-8739.8B-A.1.4-CAUSES", "hazard_traceability", "The NASA cause table includes overload and resource-related communication failure conditions.", strength="supporting"),
    _mapping("common_cause.*", "NASA-STD-8739.8B-A.1.1-COMMON-MODE", "hazard_traceability", "The guidance explicitly calls for consideration of software common-mode failures."),
    _mapping("*", "NASA-SWEHB-8.05-EFFECTS", "methodology_basis", "Every candidate is reviewed using local, next-higher-level, and end-effect propagation.", strength="contextual"),
    _mapping("*", "FAA-RLV-SCS-2006-B.1-WORKSHEET", "methodology_basis", "The worksheet structure relates candidates to causes, effects, hazards, and mitigations.", strength="contextual"),
    _mapping("functional.*", "NASA-GB-8719.13-6.6.8-SFMEA", "methodology_basis", "The guidebook's bottom-up SFMEA method reviews functional failure causes and propagated effects.", strength="supporting"),
    _mapping("data.*", "NASA-GB-8719.13-D.4.8-DATA-EVENTS", "failure_taxonomy", "The guidebook data table provides structured bad-data failure prompts.", strength="supporting"),
    _mapping("logic.*", "NASA-GB-8719.13-D.4.8-DATA-EVENTS", "failure_taxonomy", "The guidebook events table provides logic, omission, timing, and sequence prompts.", strength="supporting"),
    _mapping("timing.*", "NASA-GB-8719.13-D.4.8-DATA-EVENTS", "failure_taxonomy", "The guidebook events table includes wrong-time and out-of-sequence behavior.", strength="supporting"),
    _mapping("*", "NASA-GB-8719.13-6.6.7-SFTA", "hazard_traceability", "Bottom-up candidates should be reconciled with top-down hazard causal paths.", strength="contextual"),
    _mapping("functional.*", "FAA-AC-450.141-1A-B.1.1-SFMEA", "methodology_basis", "The current commercial-space guidance defines a software FMEA procedure for elements, interfaces, causes, effects, controls, and requirements.", strength="supporting"),
    _mapping("interface.*", "FAA-AC-450.141-1A-B.1.1-SFMEA", "failure_taxonomy", "The procedure explicitly includes computing-system interfaces.", strength="supporting"),
    _mapping("*", "FAA-AC-450.141-1A-B.2-SFTA", "hazard_traceability", "Candidate failure modes can support top-down reconciliation with software fault-tree events.", strength="contextual"),
    _mapping("*", "FAA-AC-450.141-1A-7.3.1-INDEPENDENCE", "verification_expectation", "Safety-critical verification evidence may require organizational independence under the selected commercial-space profile.", strength="contextual"),
    _mapping("*", "FAA-AC-450.141-1A-8.2.4-TRACE", "verification_expectation", "Requirements should be traceable to validation and verification evidence under the selected commercial-space profile.", strength="contextual"),
    _mapping("*", "FAA-AC-20-115D-6-LIFECYCLE", "process_expectation", "In the selected airworthiness profile, findings are assurance inputs and do not replace applicable lifecycle objectives or life-cycle data.", strength="contextual"),
    _mapping("*", "FAA-AC-20-115D-9.B.4-CHANGE", "verification_expectation", "Resolved findings and corrective changes require scoped impact analysis and verification in the selected airworthiness profile.", strength="contextual"),
    _mapping("*", "FAA-AC-20-115D-10-TOOLS", "verification_expectation", "Reliance on unverified analysis-tool output may create a separate qualification concern in the selected airworthiness profile.", strength="contextual"),
    _mapping("data.invalid_input", "MITRE-CWE-20", "security_taxonomy", "The scanner prompt overlaps the CWE input-validation weakness class when a security consequence is credible.", strength="supporting"),
    _mapping("resource.*", "MITRE-CWE-400", "security_taxonomy", "The scanner prompt overlaps uncontrolled consumption of bounded resources.", strength="supporting"),
    _mapping("detection.masked_failure", "MITRE-CWE-703", "security_taxonomy", "Broad or silent failure handling overlaps improper exceptional-condition handling.", strength="supporting"),
    _mapping("process.uncontrolled_failure", "MITRE-CWE-703", "security_taxonomy", "Unchecked subprocess failure states overlap improper exceptional-condition handling.", strength="supporting"),
    _mapping("domain.cross_scope_access", "MITRE-CWE-862", "security_taxonomy", "The project rule explicitly reviews missing or insufficient authorization across a resource scope.", strength="direct"),
    _mapping("domain.outbound_rebinding", "MITRE-CWE-918", "security_taxonomy", "The project rule explicitly reviews attacker-influenced server-side request destinations and rebinding behavior.", strength="direct"),
    _mapping("domain.*", "NIST-SP-800-218-PW.7", "process_expectation", "Security-relevant project rules should be reviewed or analyzed against the applicable security requirements.", strength="contextual"),
    _mapping("domain.*", "NIST-SP-800-218-RV.3", "verification_expectation", "Accepted security-relevant findings should feed evidence-backed root-cause and recurrence-prevention review.", strength="contextual"),
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
        raise ValueError("guidance citations reference unknown sources: " + ", ".join(unknown))
    if unknown := sorted(
        {mapping["citation_id"] for mapping in GUIDANCE_RULE_MAPPINGS}
        - set(citation_ids)
    ):
        raise ValueError("guidance mappings reference unknown citations: " + ", ".join(unknown))
    for mapping in GUIDANCE_RULE_MAPPINGS:
        if mapping["relationship"] not in RELATIONSHIP_TYPES:
            raise ValueError(f"invalid guidance relationship: {mapping['relationship']}")
        if mapping["strength"] not in MAPPING_STRENGTHS:
            raise ValueError(f"invalid guidance mapping strength: {mapping['strength']}")
        if unknown := sorted(set(mapping.get("profile_ids", [])) - set(profile_ids)):
            raise ValueError("guidance mapping references unknown profiles: " + ", ".join(unknown))
        if not mapping.get("profile_ids"):
            raise ValueError(f"guidance mapping has no applicable profile: {mapping['id']}")
    for citation in GUIDANCE_CITATIONS:
        if citation["applicability"] not in APPLICABILITY_TYPES:
            raise ValueError(f"invalid guidance applicability: {citation['applicability']}")
    for source in GUIDANCE_DOCUMENTS:
        if source["applicability"] not in APPLICABILITY_TYPES:
            raise ValueError(f"invalid source applicability: {source['applicability']}")
        if len(str(source.get("record_sha256", ""))) != 64:
            raise ValueError(f"guidance source lacks a canonical digest: {source['id']}")
    for profile in GUIDELINE_PROFILES:
        if unknown := sorted(set(profile["source_ids"]) - set(source_ids)):
            raise ValueError(
                f"guidance profile {profile['id']} references unknown sources: "
                + ", ".join(unknown)
            )


validate_guidance_catalog()


_CITATIONS_BY_ID = {citation["id"]: citation for citation in GUIDANCE_CITATIONS}
_SOURCES_BY_ID = {source["id"]: source for source in GUIDANCE_DOCUMENTS}


def normalize_profile_ids(profile_ids: list[str] | None) -> list[str]:
    """Validate, deduplicate, and deterministically order a profile selection."""

    selected = DEFAULT_GUIDANCE_PROFILES if profile_ids is None else profile_ids
    if not isinstance(selected, list) or not all(isinstance(value, str) for value in selected):
        raise ValueError("guidance profiles must be an array of strings")
    known = {profile["id"] for profile in GUIDELINE_PROFILES}
    if unknown := sorted(set(selected) - known):
        raise ValueError("unknown guidance profile(s): " + ", ".join(unknown))
    if not selected:
        raise ValueError("at least one guidance profile is required")
    return list(dict.fromkeys(selected))


def citations_for_rule(
    rule_id: str, profile_ids: list[str] | None = None
) -> list[dict[str, Any]]:
    """Return curated, typed citation links inherited by one scanner rule."""

    active_profiles = normalize_profile_ids(profile_ids)
    links: list[dict[str, Any]] = []
    for mapping in GUIDANCE_RULE_MAPPINGS:
        if not _selector_matches(mapping["rule_selector"], rule_id):
            continue
        matched_profiles = [
            value for value in active_profiles if value in mapping["profile_ids"]
        ]
        if not matched_profiles:
            continue
        citation = _CITATIONS_BY_ID[mapping["citation_id"]]
        links.append(
            {
                "citation_id": citation["id"],
                "source_id": citation["source_id"],
                "relationship": mapping["relationship"],
                "strength": mapping["strength"],
                "applicability": citation["applicability"],
                "via_rule_id": rule_id,
                "mapping_id": mapping["id"],
                "profile_ids": matched_profiles,
                "status": "curated",
            }
        )
    return links


def guidance_bundle(profile_ids: list[str] | None = None) -> dict[str, Any]:
    """Return the complete immutable-in-practice catalog as detached JSON data."""

    active_profiles = normalize_profile_ids(profile_ids)
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
    bundle["catalog_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    bundle["active_profiles"] = active_profiles
    bundle["selection_sha256"] = hashlib.sha256(
        json.dumps(active_profiles, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return bundle


def selected_guidance_sources(profile_ids: list[str] | None = None) -> list[dict[str, Any]]:
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


def analysis_guidance_profiles(analysis: dict[str, Any]) -> list[str]:
    """Resolve the persisted selection without silently enabling extra authorities."""

    embedded = analysis.get("guidance", {})
    if isinstance(embedded, dict) and isinstance(embedded.get("active_profiles"), list):
        return normalize_profile_ids(embedded["active_profiles"])
    configured = analysis.get("context", {}).get("analysis", {}).get("guidance_profiles")
    return normalize_profile_ids(configured)


def ensure_guidance_traceability(
    analysis: dict[str, Any], *, refresh: bool = False
) -> dict[str, Any]:
    """Add missing guidance data or refresh scanner-owned mappings explicitly."""

    active_profiles = analysis_guidance_profiles(analysis)
    if refresh or not isinstance(analysis.get("guidance"), dict):
        analysis["guidance"] = guidance_bundle(active_profiles)
    methodology = analysis.setdefault("methodology", {})
    if refresh:
        methodology["basis"] = selected_guidance_sources(active_profiles)
    else:
        methodology.setdefault("basis", selected_guidance_sources(active_profiles))
    methodology.setdefault("notice", METHODOLOGY_NOTICE)
    methodology.setdefault("review_checklist", copy.deepcopy(REVIEW_CHECKLIST))
    for item in analysis.get("items", []):
        scanner = item.get("scanner")
        if isinstance(scanner, dict):
            if refresh:
                inherited = citations_for_rule(
                    str(scanner.get("rule_id", "")), active_profiles
                )
                retained = [
                    link
                    for link in scanner.get("citations", [])
                    if isinstance(link, dict)
                    and link.get("status") in {"proposed", "reviewer_accepted"}
                    and link.get("citation_id") in _CITATIONS_BY_ID
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
                    citations_for_rule(str(scanner.get("rule_id", "")), active_profiles),
                )
    return analysis


def guidance_traceability(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build source-to-rule-to-finding relationships for programmatic export."""

    active_profiles = analysis_guidance_profiles(analysis)
    bundle = guidance_bundle(active_profiles)
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
    for item in active:
        scanner = item.get("scanner", {})
        rule_id = str(scanner.get("rule_id", ""))
        links = scanner.get("citations")
        if not isinstance(links, list):
            links = citations_for_rule(rule_id, active_profiles)
        normalized_links = [
            link
            for link in links
            if isinstance(link, dict) and link.get("citation_id") in _CITATIONS_BY_ID
        ]
        if normalized_links:
            cited_items.add(str(item.get("id", "")))
        rules[rule_id] += 1
        for link in normalized_links:
            used_citations[str(link["citation_id"])] += 1
            used_sources[str(link["source_id"])] += 1
        finding_links.append(
            {
                "finding_id": item.get("id", ""),
                "component_id": item.get("component_id", ""),
                "component": item.get("component", {}).get("qualname", ""),
                "source": item.get("source", {}),
                "rule_id": rule_id,
                "failure_class": scanner.get("failure_class", ""),
                "citations": copy.deepcopy(normalized_links),
            }
        )
    total = len(active)
    bundle.update(
        {
            "finding_links": finding_links,
            "coverage": {
                "active_findings": total,
                "cited_findings": len(cited_items),
                "uncited_findings": total - len(cited_items),
                "finding_coverage_percent": round(len(cited_items) * 100 / total, 1)
                if total
                else 100.0,
                "used_citations": len(used_citations),
                "used_sources": len(used_sources),
                "findings_by_rule": dict(sorted(rules.items())),
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


GUIDANCE_SOURCES = copy.deepcopy(GUIDANCE_DOCUMENTS)


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
