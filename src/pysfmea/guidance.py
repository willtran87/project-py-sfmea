"""Versioned public guidance and machine-readable SFMEA traceability mappings."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from typing import Any


GUIDANCE_SCHEMA_VERSION = "1.0"
GUIDANCE_CATALOG_VERSION = "2026.08.03"
GUIDANCE_RETRIEVED_AT = "2026-08-03"

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
    "security_relevant",
}


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


def _citation(
    citation_id: str,
    source_id: str,
    section: str,
    heading: str,
    summary: str,
    *,
    page: str = "",
    applicability: str,
) -> dict[str, Any]:
    value = {
        "id": citation_id,
        "source_id": source_id,
        "locator": {"section": section, "heading": heading, "page": page},
        "summary": summary,
        "applicability": applicability,
        "retrieved_at": GUIDANCE_RETRIEVED_AT,
    }
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
]


def _mapping(
    selector: str,
    citation_id: str,
    relationship: str,
    rationale: str,
    *,
    strength: str = "direct",
) -> dict[str, Any]:
    return {
        "id": "MAP-" + hashlib.sha256(
            f"{selector}\x1f{citation_id}\x1f{relationship}".encode("utf-8")
        ).hexdigest()[:12].upper(),
        "rule_selector": selector,
        "citation_id": citation_id,
        "relationship": relationship,
        "rationale": rationale,
        "strength": strength,
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
    citation_ids = [citation["id"] for citation in GUIDANCE_CITATIONS]
    mapping_ids = [mapping["id"] for mapping in GUIDANCE_RULE_MAPPINGS]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("guidance source IDs must be unique")
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
    for citation in GUIDANCE_CITATIONS:
        if citation["applicability"] not in APPLICABILITY_TYPES:
            raise ValueError(f"invalid guidance applicability: {citation['applicability']}")


validate_guidance_catalog()


_CITATIONS_BY_ID = {citation["id"]: citation for citation in GUIDANCE_CITATIONS}
_SOURCES_BY_ID = {source["id"]: source for source in GUIDANCE_DOCUMENTS}


def citations_for_rule(rule_id: str) -> list[dict[str, Any]]:
    """Return curated, typed citation links inherited by one scanner rule."""

    links: list[dict[str, Any]] = []
    for mapping in GUIDANCE_RULE_MAPPINGS:
        if not _selector_matches(mapping["rule_selector"], rule_id):
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
                "status": "curated",
            }
        )
    return links


def guidance_bundle() -> dict[str, Any]:
    """Return the complete immutable-in-practice catalog as detached JSON data."""

    core = {
        "schema_version": GUIDANCE_SCHEMA_VERSION,
        "catalog_version": GUIDANCE_CATALOG_VERSION,
        "retrieved_at": GUIDANCE_RETRIEVED_AT,
        "sources": GUIDANCE_DOCUMENTS,
        "citations": GUIDANCE_CITATIONS,
        "rule_mappings": GUIDANCE_RULE_MAPPINGS,
    }
    bundle = copy.deepcopy(core)
    bundle["catalog_sha256"] = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return bundle


def ensure_guidance_traceability(
    analysis: dict[str, Any], *, refresh: bool = False
) -> dict[str, Any]:
    """Add missing guidance data or refresh scanner-owned mappings explicitly."""

    if refresh or not isinstance(analysis.get("guidance"), dict):
        analysis["guidance"] = guidance_bundle()
    methodology = analysis.setdefault("methodology", {})
    if refresh:
        methodology["basis"] = copy.deepcopy(GUIDANCE_SOURCES)
    else:
        methodology.setdefault("basis", copy.deepcopy(GUIDANCE_SOURCES))
    methodology.setdefault("notice", METHODOLOGY_NOTICE)
    methodology.setdefault("review_checklist", copy.deepcopy(REVIEW_CHECKLIST))
    for item in analysis.get("items", []):
        scanner = item.get("scanner")
        if isinstance(scanner, dict):
            if refresh:
                inherited = citations_for_rule(str(scanner.get("rule_id", "")))
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
                    "citations", citations_for_rule(str(scanner.get("rule_id", "")))
                )
    return analysis


def guidance_traceability(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build source-to-rule-to-finding relationships for programmatic export."""

    bundle = guidance_bundle()
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
            links = citations_for_rule(rule_id)
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
