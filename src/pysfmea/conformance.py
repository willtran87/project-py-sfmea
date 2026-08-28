"""Governed, analysis-bound standards conformance workspaces.

The catalog deliberately records public metadata and original PySFMEA objective
summaries.  It does not reproduce licensed standards or turn a tool verdict into
certification, regulatory approval, or organizational risk acceptance.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .report import analysis_state_sha256

CONFORMANCE_CATALOG_FORMAT = "pysfmea-standards-catalog-1"
CONFORMANCE_WORKSPACE_FORMAT = "pysfmea-conformance-workspace-1"
CONFORMANCE_VERIFICATION_FORMAT = "pysfmea-conformance-verification-1"
CONFORMANCE_CATALOG_VERSION = "2026.08.27"
MAX_CONFORMANCE_BYTES = 10_000_000
MAX_CONFORMANCE_OBJECTIVES = 500
MAX_CONFORMANCE_TEXT = 20_000

APPLICABILITY = {"applicable", "not_applicable", "undetermined"}
ASSESSMENT_STATUSES = {
    "unassessed",
    "satisfied",
    "partially_satisfied",
    "not_satisfied",
    "not_applicable",
}


def _objective(
    identifier: str, title: str, locator: str, evidence: list[str]
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "reference_locator": locator,
        "expected_evidence": evidence,
    }


_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "id": "iec-60812-2018",
        "title": "IEC 60812:2018 FMEA/FMECA",
        "publisher": "IEC",
        "edition": "2018",
        "status": "current",
        "reference_url": "https://webstore.iec.ch/en/publication/26359",
        "access": "licensed_normative_text_required",
        "scope": "Planning, performing, documenting, maintaining, and reviewing FMEA/FMECA.",
        "objectives": [
            _objective(
                "IEC60812-SCOPE",
                "Define analysis purpose, boundary, assumptions, ground rules, and acceptance authority.",
                "planning and tailoring",
                ["approved scope", "system context", "tailoring record"],
            ),
            _objective(
                "IEC60812-STRUCTURE",
                "Establish functions, components, interfaces, operating states, and hierarchy before evaluating failures.",
                "system structure and functions",
                ["architecture", "interface inventory", "operating-state model"],
            ),
            _objective(
                "IEC60812-MODES",
                "Identify credible failure modes for functions, data, timing, interfaces, resources, and controls.",
                "failure-mode identification",
                ["reviewed failure-mode register", "coverage record"],
            ),
            _objective(
                "IEC60812-EFFECTS",
                "Trace local, next-higher, end, and dependent or cascading effects.",
                "failure effects",
                ["effect chains", "system boundary review"],
            ),
            _objective(
                "IEC60812-CAUSES",
                "Record credible causes, existing prevention controls, and detection controls without inventing occurrence evidence.",
                "causes and controls",
                ["cause rationale", "control evidence"],
            ),
            _objective(
                "IEC60812-EVALUATION",
                "Apply an approved risk-evaluation method and keep automated screening distinct from engineering ratings.",
                "risk evaluation",
                ["approved scale", "reviewed ratings", "risk rationale"],
            ),
            _objective(
                "IEC60812-ACTIONS",
                "Assign actions, owners, acceptance criteria, verification methods, and residual-risk review.",
                "treatment and follow-up",
                ["action register", "test evidence", "approval record"],
            ),
            _objective(
                "IEC60812-MAINTENANCE",
                "Maintain configuration, change impact, review history, anomalies, and analysis currency.",
                "documentation and maintenance",
                ["baseline identity", "change history", "review record"],
            ),
        ],
    },
    {
        "id": "sae-j1739-202605",
        "title": "SAE J1739_202605 FMEA",
        "publisher": "SAE International",
        "edition": "J1739_202605",
        "status": "stabilized_2026-05-08",
        "reference_url": "https://saemobilus.sae.org/standards/j1739_202605-potential-failure-mode-effects-analysis-fmea-including-design-fmea-supplemental-fmea-msr-process-fmea",
        "access": "licensed_normative_text_required",
        "scope": "DFMEA, supplemental FMEA-MSR, and PFMEA process and records.",
        "objectives": [
            _objective(
                "J1739-PLAN",
                "Define FMEA scope, team, inputs, assumptions, and customer-specific requirements.",
                "FMEA planning",
                ["scope approval", "team record", "input baseline"],
            ),
            _objective(
                "J1739-ANALYZE",
                "Relate functions, requirements, failure modes, effects, causes, and controls in the selected FMEA type.",
                "analysis records",
                ["reviewed FMEA records", "requirements trace"],
            ),
            _objective(
                "J1739-RATE",
                "Use organization-approved rating criteria and preserve the basis for each rating.",
                "rating criteria and worksheets",
                ["licensed criteria reference", "rating rationale"],
            ),
            _objective(
                "J1739-ACTION",
                "Prioritize and track risk-reduction actions using the adopted licensed method.",
                "action prioritization",
                ["action-priority source", "action closure evidence"],
            ),
            _objective(
                "J1739-DEVIATION",
                "Document rationale and authorized agreement for deviations from the adopted process.",
                "deviation control",
                ["deviation record", "customer or authority approval"],
            ),
        ],
    },
    {
        "id": "faa-airborne-do178c-do330",
        "title": "FAA AC 20-115D / DO-178C / DO-330 assurance profile",
        "publisher": "FAA with RTCA/EUROCAE normative material",
        "edition": "AC 20-115D",
        "status": "active",
        "reference_url": "https://www.faa.gov/documentLibrary/media/Advisory_Circular/AC_20-115D.pdf",
        "access": "public_ac_with_licensed_normative_text_required",
        "scope": "Airborne software lifecycle objectives and applicable tool qualification.",
        "objectives": [
            _objective(
                "FAA-PLANS",
                "Identify the approved certification basis, software level, lifecycle plans, standards, and authorized tailoring.",
                "AC 20-115D lifecycle planning",
                ["certification plan", "software level basis", "approved standards"],
            ),
            _objective(
                "FAA-TRACE",
                "Maintain bidirectional traceability among system safety inputs, software requirements, design, code, verification, and anomalies.",
                "DO-178C lifecycle data",
                ["trace matrix", "verification records", "problem reports"],
            ),
            _objective(
                "FAA-INDEPENDENCE",
                "Apply the verification independence required by the approved software level and plans.",
                "DO-178C objective independence",
                ["role assignments", "independent review record"],
            ),
            _objective(
                "FAA-CHANGE",
                "Perform configuration control, change impact analysis, regression verification, and lifecycle-data maintenance.",
                "AC 20-115D change management",
                ["configuration index", "change impact", "regression evidence"],
            ),
            _objective(
                "FAA-TOOL",
                "Determine whether tool qualification is required and, when applicable, satisfy the approved DO-330 qualification criteria.",
                "AC 20-115D tool qualification",
                [
                    "tool criteria determination",
                    "TOR",
                    "qualification plan and results",
                    "anomaly record",
                ],
            ),
        ],
    },
    {
        "id": "iec-61508-3-2010",
        "title": "IEC 61508-3:2010 safety-related software",
        "publisher": "IEC",
        "edition": "2010",
        "status": "current",
        "reference_url": "https://webstore.iec.ch/en/publication/5517",
        "access": "licensed_normative_text_required",
        "scope": "Software safety lifecycle for E/E/PE safety-related systems.",
        "objectives": [
            _objective(
                "IEC61508-LIFECYCLE",
                "Define and control the software safety lifecycle, responsibilities, competence, and required independence.",
                "software safety lifecycle",
                ["safety plan", "competence record", "independence record"],
            ),
            _objective(
                "IEC61508-REQUIREMENTS",
                "Derive, validate, trace, and maintain software safety requirements from allocated safety functions and integrity constraints.",
                "software safety requirements",
                ["requirements baseline", "validation and trace evidence"],
            ),
            _objective(
                "IEC61508-ARCH",
                "Use architecture and design measures appropriate to systematic capability and fault control.",
                "architecture and design",
                ["architecture rationale", "fault-control evidence"],
            ),
            _objective(
                "IEC61508-VERIFY",
                "Plan and execute verification, integration, validation, modification, and regression activities.",
                "verification and validation",
                ["verification plan", "test results", "validation record"],
            ),
            _objective(
                "IEC61508-TOOLS",
                "Control support tools and qualify or justify them according to their potential impact.",
                "support tools",
                [
                    "tool inventory",
                    "impact classification",
                    "validation or qualification evidence",
                ],
            ),
        ],
    },
    {
        "id": "iso-26262-6-2018",
        "title": "ISO 26262-6:2018 automotive software",
        "publisher": "ISO",
        "edition": "2018",
        "status": "published_revision_planned",
        "reference_url": "https://www.iso.org/standard/68388.html",
        "access": "licensed_normative_text_required",
        "scope": "Product development at the software level for road vehicles.",
        "objectives": [
            _objective(
                "ISO26262-REQ",
                "Specify and verify software safety requirements with ASIL, allocation, interfaces, and traceability.",
                "software safety requirements",
                ["ASIL basis", "requirements and trace matrix"],
            ),
            _objective(
                "ISO26262-ARCH",
                "Develop and verify software architecture including freedom-from-interference and dependent-failure considerations where applicable.",
                "software architectural design",
                ["architecture", "interference and dependency analysis"],
            ),
            _objective(
                "ISO26262-UNIT",
                "Apply unit design, implementation, verification, and coverage methods appropriate to the assigned integrity.",
                "software unit development",
                ["coding-standard evidence", "unit verification", "coverage"],
            ),
            _objective(
                "ISO26262-INTEGRATION",
                "Verify software integration, interfaces, timing, resources, and safety mechanisms.",
                "software integration and testing",
                [
                    "integration tests",
                    "timing and resource evidence",
                    "fault injection",
                ],
            ),
            _objective(
                "ISO26262-QUAL",
                "Control tool confidence, software-component qualification, and configuration evidence when applicable.",
                "supporting processes",
                [
                    "tool confidence analysis",
                    "component qualification",
                    "configuration baseline",
                ],
            ),
        ],
    },
    {
        "id": "nist-ssdf-1.1",
        "title": "NIST SP 800-218 Secure Software Development Framework",
        "publisher": "NIST",
        "edition": "1.1",
        "status": "final",
        "reference_url": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "access": "public",
        "scope": "Secure software development practices integrated into the SDLC.",
        "objectives": [
            _objective(
                "SSDF-PO",
                "Prepare the organization with defined security requirements, roles, environments, and supporting toolchains.",
                "PO practices",
                ["security requirements", "roles", "toolchain controls"],
            ),
            _objective(
                "SSDF-PS",
                "Protect software, source, credentials, build inputs, releases, and provenance from unauthorized change.",
                "PS practices",
                ["access control", "signed provenance", "release integrity"],
            ),
            _objective(
                "SSDF-PW",
                "Produce well-secured software using threat modeling, review, analysis, testing, dependency control, and secure defaults.",
                "PW practices",
                ["threat model", "SAST and tests", "dependency evidence"],
            ),
            _objective(
                "SSDF-RV",
                "Identify, remediate, disclose, and prevent recurrence of vulnerabilities with measured root-cause feedback.",
                "RV practices",
                [
                    "vulnerability records",
                    "root-cause analysis",
                    "remediation evidence",
                ],
            ),
        ],
    },
    {
        "id": "iso-25010-29119",
        "title": "ISO/IEC 25010:2023 and ISO/IEC/IEEE 29119-2:2021 quality and testing",
        "publisher": "ISO/IEC/IEEE",
        "edition": "25010:2023 / 29119-2:2021",
        "status": "current",
        "reference_url": "https://www.iso.org/standard/78176.html",
        "access": "licensed_normative_text_required",
        "scope": "Product-quality requirements and governed test processes.",
        "objectives": [
            _objective(
                "QUALITY-MODEL",
                "Select applicable product-quality characteristics and measurable acceptance criteria.",
                "ISO/IEC 25010 product quality model",
                ["quality model tailoring", "measures and thresholds"],
            ),
            _objective(
                "TEST-GOV",
                "Establish test governance, organizational policy, plans, monitoring, completion, and reusable testware.",
                "ISO/IEC/IEEE 29119-2 test processes",
                ["test policy", "test plan", "completion report"],
            ),
            _objective(
                "TEST-DESIGN",
                "Derive tests and oracles using documented techniques with requirements and risk traceability.",
                "test design and implementation",
                ["test design specification", "oracle rationale", "trace matrix"],
            ),
            _objective(
                "TEST-EVAL",
                "Evaluate test effectiveness, independence, anomalies, coverage, mutation resistance, and residual limitations.",
                "test evaluation",
                ["test results", "coverage", "mutation results", "limitations"],
            ),
        ],
    },
    {
        "id": "nist-ai-600-1-llm",
        "title": "NIST AI 600-1 generative-AI governance for LLM-assisted assurance",
        "publisher": "NIST",
        "edition": "2024",
        "status": "current_profile",
        "reference_url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
        "access": "public",
        "scope": "Governance, measurement, and risk treatment for LLM-generated analysis or tests.",
        "objectives": [
            _objective(
                "LLM-GOVERN",
                "Define authorized use, accountability, human approval, data handling, incident response, and prohibited autonomous actions.",
                "Govern",
                ["AI use policy", "role and approval records", "incident process"],
            ),
            _objective(
                "LLM-PROVENANCE",
                "Record model/provider identity, parameters, prompt/template, inputs, retrieved evidence, outputs, and transformations.",
                "content provenance",
                ["generation manifest", "content digests", "retention policy"],
            ),
            _objective(
                "LLM-EVALUATE",
                "Pre-deployment-test correctness, confabulation, citation fidelity, security, privacy, nondeterminism, and benchmark contamination.",
                "Measure",
                [
                    "independent evaluation",
                    "red-team results",
                    "repeatability evidence",
                ],
            ),
            _objective(
                "LLM-ORACLES",
                "Independently verify generated test oracles, fault sensitivity, non-triviality, and absence of implementation mirroring.",
                "human-AI configuration and information integrity",
                ["oracle review", "mutation evidence", "negative controls"],
            ),
            _objective(
                "LLM-EXECUTE",
                "Use least-privilege sandbox execution and require human promotion before generated code can affect trusted branches or assurance claims.",
                "Manage",
                ["sandbox policy", "execution receipt", "promotion approval"],
            ),
        ],
    },
)


def standards_catalog() -> dict[str, Any]:
    """Return the deterministic, content-addressed profile catalog."""

    result = {
        "format": CONFORMANCE_CATALOG_FORMAT,
        "version": CONFORMANCE_CATALOG_VERSION,
        "profiles": copy.deepcopy(list(_PROFILES)),
        "authority": "public_metadata_and_original_objective_summaries_not_normative_text",
        "notice": (
            "Apply only profiles adopted by the project authority. Licensed standards must "
            "be consulted directly; this catalog does not establish conformance."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def _profile_by_id(identifier: str) -> dict[str, Any]:
    for profile in _PROFILES:
        if profile["id"] == identifier:
            return copy.deepcopy(profile)
    choices = ", ".join(profile["id"] for profile in _PROFILES)
    raise ValueError(
        f"unknown standards profile {identifier!r}; choose one of: {choices}"
    )


def _analysis_binding(analysis: dict[str, Any]) -> dict[str, str]:
    return {
        "baseline_id": str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        ),
        "analysis_schema_version": str(analysis.get("schema_version", "")),
        "analysis_state_sha256": analysis_state_sha256(analysis),
    }


def _summary(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    objectives = [item for profile in profiles for item in profile["objectives"]]
    counts = {status: 0 for status in sorted(ASSESSMENT_STATUSES)}
    applicability = {status: 0 for status in sorted(APPLICABILITY)}
    for item in objectives:
        counts[item["status"]] += 1
        applicability[item["applicability"]] += 1
    applicable = [item for item in objectives if item["applicability"] == "applicable"]
    complete = (
        bool(applicable)
        and all(item["status"] != "unassessed" for item in applicable)
        and applicability["undetermined"] == 0
    )
    supported = complete and all(item["status"] == "satisfied" for item in applicable)
    return {
        "profiles": len(profiles),
        "objectives": len(objectives),
        "by_applicability": applicability,
        "by_status": counts,
        "assessment_complete": complete,
        "conformance_supported": supported,
        "blocking_objective_ids": [
            item["id"]
            for item in objectives
            if item["applicability"] == "undetermined"
            or (item["applicability"] == "applicable" and item["status"] != "satisfied")
        ],
    }


def conformance_workspace(
    analysis: dict[str, Any],
    profile_ids: list[str],
    *,
    system: str,
    lifecycle_phase: str,
    applicability_basis: str,
    authority: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not profile_ids:
        raise ValueError("at least one standards profile is required")
    if len(profile_ids) != len(set(profile_ids)):
        raise ValueError("standards profiles must not contain duplicates")
    for label, value in {
        "system": system,
        "lifecycle_phase": lifecycle_phase,
        "applicability_basis": applicability_basis,
        "authority": authority,
    }.items():
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > MAX_CONFORMANCE_TEXT
        ):
            raise ValueError(f"{label} must be non-empty bounded text")
    profiles = []
    for profile_id in profile_ids:
        profile = _profile_by_id(profile_id)
        profile["objectives"] = [
            {
                **objective,
                "applicability": "undetermined",
                "status": "unassessed",
                "rationale": "",
                "evidence_refs": [],
                "reviewer": "",
                "reviewed_at": "",
            }
            for objective in profile["objectives"]
        ]
        profiles.append(profile)
    workspace: dict[str, Any] = {
        "format": CONFORMANCE_WORKSPACE_FORMAT,
        "generated_at": generated_at or utc_now(),
        "catalog": {
            "version": CONFORMANCE_CATALOG_VERSION,
            "content_sha256": standards_catalog()["content_sha256"],
        },
        "scope": {
            "system": system.strip(),
            "lifecycle_phase": lifecycle_phase.strip(),
            "applicability_basis": applicability_basis.strip(),
            "authority": authority.strip(),
        },
        "binding": _analysis_binding(analysis),
        "profiles": profiles,
        "summary": {},
        "claim": "No certification, regulatory approval, or organizational conformance is asserted by this workspace.",
        "content_sha256": "",
    }
    workspace["summary"] = _summary(workspace["profiles"])
    workspace["content_sha256"] = _workspace_digest(workspace)
    return workspace


def _workspace_digest(workspace: dict[str, Any]) -> str:
    content = copy.deepcopy(workspace)
    content.pop("content_sha256", None)
    return canonical_json_sha256(content)


def load_conformance_workspace(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="standards conformance workspace",
        max_bytes=MAX_CONFORMANCE_BYTES,
        max_depth=60,
        max_nodes=500_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("standards conformance workspace must be a JSON object")
    return document.value


def assess_objective(
    workspace: dict[str, Any],
    objective_id: str,
    *,
    applicability: str,
    status: str,
    rationale: str,
    reviewer: str,
    evidence_refs: list[str],
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    """Return a newly sealed workspace with one governed assessment decision."""

    if applicability not in APPLICABILITY:
        raise ValueError("unsupported objective applicability")
    if status not in ASSESSMENT_STATUSES:
        raise ValueError("unsupported objective assessment status")
    if applicability == "not_applicable" and status != "not_applicable":
        raise ValueError("not-applicable objectives must use not_applicable status")
    if applicability == "undetermined" and status != "unassessed":
        raise ValueError("undetermined objectives must remain unassessed")
    if applicability == "applicable" and status == "not_applicable":
        raise ValueError("applicable objectives cannot use not_applicable status")
    if status == "satisfied" and not evidence_refs:
        raise ValueError("satisfied objectives require at least one evidence reference")
    if status != "unassessed" and (not rationale.strip() or not reviewer.strip()):
        raise ValueError("assessed objectives require rationale and reviewer")
    if any(
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_CONFORMANCE_TEXT
        for value in evidence_refs
    ):
        raise ValueError("evidence references must be non-empty bounded text")
    result = copy.deepcopy(workspace)
    matches = [
        objective
        for profile in result.get("profiles", [])
        for objective in profile.get("objectives", [])
        if objective.get("id") == objective_id
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous objective ID: {objective_id}")
    objective = matches[0]
    objective.update(
        {
            "applicability": applicability,
            "status": status,
            "rationale": rationale.strip(),
            "evidence_refs": list(
                dict.fromkeys(value.strip() for value in evidence_refs)
            ),
            "reviewer": reviewer.strip(),
            "reviewed_at": (reviewed_at or utc_now()) if status != "unassessed" else "",
        }
    )
    result["generated_at"] = utc_now()
    result["summary"] = _summary(result["profiles"])
    result["content_sha256"] = _workspace_digest(result)
    verification = verify_conformance_workspace(result)
    if not verification["valid"]:
        raise ValueError(
            "updated conformance workspace is invalid: "
            + "; ".join(verification["errors"])
        )
    return result


def verify_conformance_workspace(
    workspace: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    checks: dict[str, bool | None] = {
        "closed_structure": True,
        "content_integrity": False,
        "catalog_binding": False,
        "profile_integrity": False,
        "assessment_semantics": False,
        "summary_reconciliation": False,
        "analysis_binding": None,
    }
    required = {
        "format",
        "generated_at",
        "catalog",
        "scope",
        "binding",
        "profiles",
        "summary",
        "claim",
        "content_sha256",
    }
    if (
        set(workspace) != required
        or workspace.get("format") != CONFORMANCE_WORKSPACE_FORMAT
    ):
        checks["closed_structure"] = False
        errors.append("workspace fields or format do not match conformance format 1")
    checks["content_integrity"] = bool(
        re.fullmatch(r"[0-9a-f]{64}", str(workspace.get("content_sha256", "")))
        and workspace.get("content_sha256") == _workspace_digest(workspace)
    )
    if not checks["content_integrity"]:
        errors.append("workspace content digest does not match")
    catalog = workspace.get("catalog")
    current_catalog = standards_catalog()
    checks["catalog_binding"] = bool(
        isinstance(catalog, dict)
        and catalog.get("version") == CONFORMANCE_CATALOG_VERSION
        and catalog.get("content_sha256") == current_catalog["content_sha256"]
    )
    if not checks["catalog_binding"]:
        errors.append("workspace standards catalog is missing, stale, or altered")
    profiles = workspace.get("profiles")
    seen_profiles: set[str] = set()
    seen_objectives: set[str] = set()
    profile_integrity = isinstance(profiles, list) and 0 < len(profiles) <= len(
        _PROFILES
    )
    semantic = profile_integrity
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict) or not isinstance(profile.get("id"), str):
                profile_integrity = False
                semantic = False
                continue
            identifier = profile["id"]
            try:
                expected = _profile_by_id(identifier)
            except ValueError:
                profile_integrity = False
                continue
            if identifier in seen_profiles:
                profile_integrity = False
            seen_profiles.add(identifier)
            fixed_fields = {
                key: expected[key] for key in expected if key != "objectives"
            }
            if any(profile.get(key) != value for key, value in fixed_fields.items()):
                profile_integrity = False
            expected_objectives = {item["id"]: item for item in expected["objectives"]}
            objectives = profile.get("objectives")
            if not isinstance(objectives, list) or len(objectives) != len(
                expected_objectives
            ):
                profile_integrity = False
                semantic = False
                continue
            for objective in objectives:
                if not isinstance(objective, dict):
                    profile_integrity = False
                    semantic = False
                    continue
                objective_id = str(objective.get("id", ""))
                expected_objective = expected_objectives.get(objective_id)
                if objective_id in seen_objectives or expected_objective is None:
                    profile_integrity = False
                seen_objectives.add(objective_id)
                if expected_objective and any(
                    objective.get(key) != value
                    for key, value in expected_objective.items()
                ):
                    profile_integrity = False
                applicability = objective.get("applicability")
                status = objective.get("status")
                rationale = objective.get("rationale")
                reviewer = objective.get("reviewer")
                evidence = objective.get("evidence_refs")
                reviewed_at_value = objective.get("reviewed_at")
                valid_record = (
                    applicability in APPLICABILITY
                    and status in ASSESSMENT_STATUSES
                    and isinstance(rationale, str)
                    and isinstance(reviewer, str)
                    and isinstance(reviewed_at_value, str)
                    and isinstance(evidence, list)
                    and len(evidence) <= 1_000
                    and all(
                        isinstance(value, str)
                        and 0 < len(value) <= MAX_CONFORMANCE_TEXT
                        for value in evidence
                    )
                )
                rationale_text = rationale if isinstance(rationale, str) else ""
                reviewer_text = reviewer if isinstance(reviewer, str) else ""
                valid_record = valid_record and not (
                    (applicability == "not_applicable" and status != "not_applicable")
                    or (applicability == "undetermined" and status != "unassessed")
                    or (applicability == "applicable" and status == "not_applicable")
                    or (status == "satisfied" and not evidence)
                    or (
                        status != "unassessed"
                        and (
                            not rationale_text.strip()
                            or not reviewer_text.strip()
                            or not reviewed_at_value
                        )
                    )
                )
                semantic = semantic and valid_record
    checks["profile_integrity"] = profile_integrity
    checks["assessment_semantics"] = semantic
    if not profile_integrity:
        errors.append("profiles or objectives do not match the governed catalog")
    if not semantic:
        errors.append(
            "objective applicability, status, rationale, reviewer, or evidence semantics are invalid"
        )
    try:
        expected_summary = _summary(profiles if isinstance(profiles, list) else [])
    except (KeyError, TypeError, ValueError):
        expected_summary = None
    checks["summary_reconciliation"] = (
        expected_summary is not None and workspace.get("summary") == expected_summary
    )
    if not checks["summary_reconciliation"]:
        errors.append("workspace summary does not reconcile with objective records")
    if analysis is not None:
        checks["analysis_binding"] = workspace.get("binding") == _analysis_binding(
            analysis
        )
        if not checks["analysis_binding"]:
            errors.append("workspace does not match the supplied analysis state")
    valid = all(value is not False for value in checks.values())
    summary_value = workspace.get("summary")
    summary: dict[str, Any] = summary_value if isinstance(summary_value, dict) else {}
    return {
        "format": CONFORMANCE_VERIFICATION_FORMAT,
        "valid": valid,
        "assessment_complete": bool(valid and summary.get("assessment_complete")),
        "conformance_supported": bool(valid and summary.get("conformance_supported")),
        "checks": checks,
        "errors": errors,
        "profile_ids": sorted(seen_profiles),
        "objective_count": len(seen_objectives),
        "content_sha256": str(workspace.get("content_sha256", "")),
        "notice": "A valid or fully satisfied workspace is evidence for authorized review; it is not certification, regulatory approval, or risk acceptance.",
    }


def export_conformance_workspace(
    workspace: dict[str, Any], destination: str | Path
) -> Path:
    return atomic_publish_text(
        destination,
        json.dumps(workspace, indent=2, ensure_ascii=False) + "\n",
        label="standards conformance workspace",
    )


def verify_conformance_workspace_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        workspace = load_conformance_workspace(source)
        return {
            "path": str(Path(source).expanduser().resolve()),
            **verify_conformance_workspace(workspace, analysis=analysis),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": CONFORMANCE_VERIFICATION_FORMAT,
            "valid": False,
            "assessment_complete": False,
            "conformance_supported": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "catalog_binding": False,
                "profile_integrity": False,
                "assessment_semantics": False,
                "summary_reconciliation": False,
                "analysis_binding": None if analysis is None else False,
            },
            "errors": [str(exc)],
            "profile_ids": [],
            "objective_count": 0,
            "content_sha256": "",
            "notice": "The conformance workspace could not be safely verified.",
        }
