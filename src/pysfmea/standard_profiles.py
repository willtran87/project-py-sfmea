"""Current optional standards profiles for the governed conformance catalog.

Every objective is an original navigation summary. Licensed normative text,
project tailoring, interpretations, and conformity decisions remain external.
"""

from __future__ import annotations

from typing import Any


def _objective(
    identifier: str, title: str, locator: str, evidence: list[str]
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "reference_locator": locator,
        "expected_evidence": evidence,
    }


ADDITIONAL_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "id": "aiag-vda-fmea-2019",
        "title": "AIAG & VDA FMEA Handbook, 1st Edition",
        "publisher": "AIAG and VDA",
        "edition": "2019 with controlled errata",
        "status": "current_licensed_industry_method",
        "reference_url": "https://www.aiag.org/training-and-resources/manuals/details/FMEAAV-1",
        "access": "licensed_normative_text_and_rating_tables_required",
        "scope": "Seven-step DFMEA, PFMEA, and supplemental FMEA-MSR workflow.",
        "objectives": [
            _objective(
                "AIVDA-PLAN",
                "Establish purpose, scope, boundaries, team, assumptions, lessons learned, and project plan.",
                "step 1 planning and preparation",
                [
                    "approved scope",
                    "team record",
                    "project plan",
                    "lessons-learned inputs",
                ],
            ),
            _objective(
                "AIVDA-STRUCTURE",
                "Build a reviewed structure tree or network at the analysis level and adjacent levels.",
                "step 2 structure analysis",
                ["structure tree", "interface and boundary review"],
            ),
            _objective(
                "AIVDA-FUNCTION",
                "Relate requirements and measurable functions across the reviewed structure.",
                "step 3 function analysis",
                ["function network", "requirements trace"],
            ),
            _objective(
                "AIVDA-FAILURE",
                "Relate failure effects, failure modes, and causes in failure chains.",
                "step 4 failure analysis",
                ["failure network", "effect and cause rationale"],
            ),
            _objective(
                "AIVDA-RISK",
                "Apply the controlled severity, occurrence, detection, monitoring, and Action Priority criteria for the selected FMEA type.",
                "step 5 risk analysis and licensed tables",
                [
                    "licensed criteria identity",
                    "reviewed ratings",
                    "Action Priority result",
                ],
            ),
            _objective(
                "AIVDA-OPTIMIZE",
                "Assign preventive or detective actions, owners, deadlines, status, effectiveness evidence, and residual ratings.",
                "step 6 optimization",
                ["action register", "completion evidence", "residual-risk decision"],
            ),
            _objective(
                "AIVDA-RESULTS",
                "Communicate results, limitations, open high-priority actions, and management acceptance using the adopted report views.",
                "step 7 results documentation",
                ["results report", "management review", "open-action disposition"],
            ),
        ],
    },
    {
        "id": "sae-arp4754b-arp4761a",
        "title": "SAE ARP4754B / ARP4761A aircraft and system assurance",
        "publisher": "SAE International with EUROCAE counterparts",
        "edition": "ARP4754B and ARP4761A (2023)",
        "status": "current",
        "reference_url": "https://saemobilus.sae.org/standards/arp4761a-guidelines-conducting-safety-assessment-process-civil-aircraft-systems-equipment",
        "access": "licensed_normative_text_required",
        "scope": "Aircraft and system development assurance, safety assessment, allocation, and common-cause analysis.",
        "objectives": [
            _objective(
                "ARP-SCOPE",
                "Define aircraft and system boundaries, operational context, certification basis, plans, and development-assurance level strategy.",
                "development and safety-assessment planning",
                ["approved plans", "system context", "assurance-level basis"],
            ),
            _objective(
                "ARP-FHA",
                "Identify functions, failure conditions, operational effects, classifications, and safety objectives through aircraft and system FHA.",
                "AFHA and SFHA",
                [
                    "functional hazard assessments",
                    "classification rationale",
                    "safety objectives",
                ],
            ),
            _objective(
                "ARP-PSSA",
                "Allocate safety requirements and development assurance through a preliminary architecture and safety assessment.",
                "PASA and PSSA",
                ["allocated requirements", "preliminary architecture", "PSSA evidence"],
            ),
            _objective(
                "ARP-SSA",
                "Verify the implemented architecture and lifecycle evidence satisfy allocated safety requirements.",
                "ASA and SSA",
                ["verification results", "SSA", "requirements closure"],
            ),
            _objective(
                "ARP-CCA",
                "Evaluate common mode, common cause, zonal, and particular risks without assuming independence from separation alone.",
                "common-cause analyses",
                ["CCA set", "independence rationale", "mitigation evidence"],
            ),
            _objective(
                "ARP-TRACE",
                "Maintain bidirectional traceability from failure conditions and safety objectives through allocated software requirements and verification evidence.",
                "safety data integration",
                [
                    "cross-level trace matrix",
                    "change-impact record",
                    "open problem reports",
                ],
            ),
        ],
    },
    {
        "id": "iso-12207-2026",
        "title": "ISO/IEC/IEEE 12207:2026 software life cycle processes",
        "publisher": "ISO, IEC, and IEEE",
        "edition": "2026",
        "status": "current",
        "reference_url": "https://www.iso.org/standard/90219.html",
        "access": "licensed_normative_text_required",
        "scope": "Software acquisition, supply, development, operation, maintenance, and disposal processes.",
        "objectives": [
            _objective(
                "12207-AGREEMENT",
                "Define acquisition, supply, stakeholder, acceptance, and responsibility agreements for the software system or service.",
                "agreement processes",
                ["agreement baseline", "acceptance criteria", "responsibility matrix"],
            ),
            _objective(
                "12207-ORGANIZATION",
                "Provide lifecycle models, infrastructure, portfolio, quality, knowledge, and human-resource enablement.",
                "organizational project-enabling processes",
                [
                    "lifecycle model",
                    "quality plan",
                    "competence and infrastructure evidence",
                ],
            ),
            _objective(
                "12207-MANAGEMENT",
                "Plan, assess, control, measure, assure, decide, manage risk, and manage information and configuration.",
                "technical management processes",
                [
                    "project plan",
                    "risk register",
                    "measurement record",
                    "configuration index",
                ],
            ),
            _objective(
                "12207-TECHNICAL",
                "Trace stakeholder needs through requirements, architecture, design, implementation, integration, verification, validation, transition, operation, maintenance, and disposal.",
                "technical processes",
                [
                    "lifecycle trace",
                    "verification and validation evidence",
                    "transition and maintenance records",
                ],
            ),
            _objective(
                "12207-TAILOR",
                "Document the selected lifecycle, tailoring decisions, omissions, rationale, authority, and effects on required outcomes.",
                "application and tailoring",
                ["tailoring record", "outcome coverage", "authorized deviations"],
            ),
        ],
    },
    {
        "id": "iso-330xx-process-assessment",
        "title": "ISO/IEC 330xx software process assessment",
        "publisher": "ISO and IEC",
        "edition": "33002/33004 with TS 33010:2023 and TS 33061:2021",
        "status": "current_family_subject_to_selected_parts",
        "reference_url": "https://committee.iso.org/sites/jtc1sc7/home/projects/flagship-standards/isoiec-33000-family.html",
        "access": "licensed_normative_text_required",
        "scope": "Evidence-based process capability assessment and software lifecycle assessment models.",
        "objectives": [
            _objective(
                "330XX-SCOPE",
                "Predefine the assessment purpose, scope, class, process model, sponsors, participants, constraints, and intended use.",
                "assessment planning",
                [
                    "assessment plan",
                    "selected process model",
                    "scope and sampling rationale",
                ],
            ),
            _objective(
                "330XX-COMPETENCE",
                "Establish assessor competence, responsibilities, independence expectations, and conflict controls.",
                "assessment roles and competence",
                ["assessor competence record", "independence declaration"],
            ),
            _objective(
                "330XX-EVIDENCE",
                "Collect and retain objective evidence sufficient to rate process outcomes and attributes.",
                "evidence collection and validation",
                ["evidence index", "sampling record", "interview and artifact notes"],
            ),
            _objective(
                "330XX-RATE",
                "Apply the selected measurement framework consistently and preserve the basis for every rating.",
                "process attribute rating",
                ["rating record", "process outcome trace", "review resolution"],
            ),
            _objective(
                "330XX-REPORT",
                "Report results, limitations, nonconformities, improvement opportunities, and assessment validity without overstating maturity.",
                "assessment reporting",
                [
                    "assessment report",
                    "limitations",
                    "approval and distribution record",
                ],
            ),
        ],
    },
    {
        "id": "openssf-osps-2026-02-19",
        "title": "OpenSSF Open Source Project Security Baseline",
        "publisher": "Open Source Security Foundation",
        "edition": "2026.02.19",
        "status": "current_public_baseline",
        "reference_url": "https://baseline.openssf.org/versions/2026-02-19.html",
        "access": "public",
        "scope": "Tiered minimum security controls for open-source project governance and delivery.",
        "objectives": [
            _objective(
                "OSPS-ACCESS",
                "Protect authoritative project resources, privileged actions, and identities with appropriate authentication and least privilege.",
                "access control category",
                [
                    "repository settings evidence",
                    "privilege review",
                    "MFA enforcement evidence",
                ],
            ),
            _objective(
                "OSPS-BUILD",
                "Protect build and release workflows, dependencies, provenance, and published artifacts from unauthorized modification.",
                "build and release category",
                ["pinned workflow", "provenance", "release integrity evidence"],
            ),
            _objective(
                "OSPS-DOCUMENT",
                "Publish security, contribution, governance, support, and vulnerability-reporting information appropriate to project maturity.",
                "documentation and governance categories",
                [
                    "security policy",
                    "governance record",
                    "support and contribution documentation",
                ],
            ),
            _objective(
                "OSPS-QUALITY",
                "Use automated tests, reviews, static analysis, and change controls to detect regressions and unsafe changes.",
                "quality category",
                ["required checks", "test evidence", "review protection"],
            ),
            _objective(
                "OSPS-VULNERABILITY",
                "Operate vulnerability intake, coordinated response, remediation, advisory, and supported-version processes.",
                "vulnerability management category",
                [
                    "intake process",
                    "advisory records",
                    "remediation and disclosure evidence",
                ],
            ),
        ],
    },
    {
        "id": "iso-42001-23894-ai-governance",
        "title": "ISO/IEC 42001:2023 and ISO/IEC 23894:2023 AI governance",
        "publisher": "ISO and IEC",
        "edition": "2023",
        "status": "current",
        "reference_url": "https://www.iso.org/standard/42001",
        "access": "licensed_normative_text_required",
        "scope": "AI management system and risk-management governance for LLM-assisted assurance.",
        "objectives": [
            _objective(
                "AIMS-CONTEXT",
                "Define organizational context, interested parties, AI system inventory, scope, policy, roles, and accountability.",
                "AI management system context and leadership",
                ["AIMS scope", "AI inventory", "policy and accountable roles"],
            ),
            _objective(
                "AIMS-RISK",
                "Identify, analyze, evaluate, treat, and monitor AI risks and opportunities using documented criteria.",
                "AI risk management",
                [
                    "AI risk register",
                    "impact assessment",
                    "treatment and residual-risk decisions",
                ],
            ),
            _objective(
                "AIMS-LIFECYCLE",
                "Govern data, models, prompts, suppliers, human oversight, documentation, operation, change, and retirement.",
                "AI system lifecycle controls",
                [
                    "lineage records",
                    "supplier controls",
                    "human-oversight design",
                    "change history",
                ],
            ),
            _objective(
                "AIMS-MEASURE",
                "Measure model and system performance, safety, security, fairness, transparency, robustness, and limitations in context.",
                "performance evaluation",
                [
                    "evaluation protocol",
                    "retained results",
                    "limitations and monitoring thresholds",
                ],
            ),
            _objective(
                "AIMS-IMPROVE",
                "Audit, review, correct, and continually improve the AI management system and deployed controls.",
                "internal audit, management review, and improvement",
                ["audit evidence", "management review", "corrective-action closure"],
            ),
        ],
    },
    {
        "id": "nist-ssdf-800-218a-genai",
        "title": "NIST SP 800-218A SSDF Community Profile for Generative AI",
        "publisher": "NIST",
        "edition": "SP 800-218A (2024, updated 2025)",
        "status": "current_public",
        "reference_url": "https://csrc.nist.gov/pubs/sp/800/218/a/final",
        "access": "public",
        "scope": "Secure development practices for generative-AI and dual-use foundation-model systems.",
        "objectives": [
            _objective(
                "SSDF-AI-PREPARE",
                "Prepare people, policy, environments, provenance, suppliers, and risk models for secure AI development and use.",
                "PO community-profile additions",
                [
                    "AI security plan",
                    "threat model",
                    "supplier and provenance controls",
                ],
            ),
            _objective(
                "SSDF-AI-PROTECT",
                "Protect models, weights, data, prompts, secrets, development environments, and release artifacts.",
                "PS community-profile additions",
                ["access controls", "asset inventory", "integrity and leakage tests"],
            ),
            _objective(
                "SSDF-AI-PRODUCE",
                "Evaluate abuse, poisoning, evasion, prompt injection, unsafe output, privacy, and supply-chain risks before release.",
                "PW community-profile additions",
                ["adversarial evaluation", "release criteria", "model and system card"],
            ),
            _objective(
                "SSDF-AI-RESPOND",
                "Monitor, disclose, respond to, learn from, and prevent recurrence of AI vulnerabilities and incidents.",
                "RV community-profile additions",
                [
                    "monitoring record",
                    "incident process",
                    "corrective and preventive actions",
                ],
            ),
        ],
    },
    {
        "id": "iso-21434-21448-automotive",
        "title": "ISO/SAE 21434:2021 cybersecurity and ISO 21448:2022 SOTIF",
        "publisher": "ISO and SAE International",
        "edition": "2021 and 2022",
        "status": "current_subject_to_systematic_review",
        "reference_url": "https://www.iso.org/standard/70918.html",
        "access": "licensed_normative_text_required",
        "scope": "Automotive cybersecurity engineering and safety of intended functionality.",
        "objectives": [
            _objective(
                "AUTO-CYBER",
                "Govern lifecycle cybersecurity, assets, threat scenarios, impact, attack paths, risk treatment, verification, operations, and supply-chain interfaces.",
                "ISO/SAE 21434 lifecycle",
                [
                    "cybersecurity plan",
                    "TARA",
                    "cybersecurity case",
                    "supplier agreements",
                ],
            ),
            _objective(
                "AUTO-SOTIF-SCOPE",
                "Define intended functionality, operating domain, functional insufficiencies, foreseeable misuse, triggering conditions, and acceptance criteria.",
                "ISO 21448 specification and analysis",
                ["item definition", "scenario taxonomy", "acceptance criteria"],
            ),
            _objective(
                "AUTO-SOTIF-EVALUATE",
                "Evaluate known and unknown hazardous scenarios using analysis, simulation, testing, field evidence, and residual-risk arguments.",
                "ISO 21448 verification and validation",
                ["scenario coverage", "V&V results", "residual-risk rationale"],
            ),
            _objective(
                "AUTO-INTEGRATE",
                "Keep functional safety, SOTIF, cybersecurity, software, supplier, and change-impact evidence connected without conflating their claims.",
                "cross-discipline integration",
                [
                    "integrated trace",
                    "interaction analysis",
                    "change-impact assessment",
                ],
            ),
        ],
    },
    {
        "id": "medical-14971-62304-81001",
        "title": "ISO 14971 / IEC 62304 / IEC 81001-5-1 medical software",
        "publisher": "ISO and IEC",
        "edition": "ISO 14971:2019; IEC 62304:2006+A1:2015; IEC 81001-5-1:2021 with interpretations",
        "status": "current_subject_to_applicable_jurisdiction",
        "reference_url": "https://www.iso.org/standard/72704.html",
        "access": "licensed_normative_text_required",
        "scope": "Medical-device risk management, software lifecycle, and health-software security.",
        "objectives": [
            _objective(
                "MED-RISK",
                "Define intended use, reasonably foreseeable misuse, hazards, hazardous situations, harms, risk criteria, controls, benefit-risk decisions, and lifecycle monitoring.",
                "ISO 14971 risk-management process",
                [
                    "risk-management plan",
                    "hazard trace",
                    "risk controls",
                    "risk-management report",
                ],
            ),
            _objective(
                "MED-SOFTWARE",
                "Classify software safety, plan and perform development, architecture, detailed design, implementation, integration, testing, release, maintenance, risk management, configuration, and problem resolution.",
                "IEC 62304 lifecycle processes",
                [
                    "software plan",
                    "safety classification",
                    "traceability",
                    "release and maintenance records",
                ],
            ),
            _objective(
                "MED-SECURITY",
                "Apply secure product lifecycle activities to health software and retain post-market vulnerability and update evidence.",
                "IEC 81001-5-1 security lifecycle",
                [
                    "security plan",
                    "threat model",
                    "security verification",
                    "post-market process",
                ],
            ),
            _objective(
                "MED-TRACE",
                "Maintain traceability among requirements, hazards, software items, causes, controls, verification, anomalies, and post-production information.",
                "integrated medical software evidence",
                ["risk trace matrix", "anomaly evaluation", "post-production review"],
            ),
        ],
    },
    {
        "id": "en-50716-2023-rail",
        "title": "EN 50716:2023 railway software development",
        "publisher": "CEN-CENELEC",
        "edition": "2023",
        "status": "current",
        "reference_url": "https://www.dinmedia.de/en/standard/bs-en-50716/375765007",
        "access": "licensed_normative_text_required",
        "scope": "Railway software lifecycle, safety integrity, verification, validation, and assurance evidence.",
        "objectives": [
            _objective(
                "RAIL-PLAN",
                "Establish software scope, safety integrity, lifecycle, organization, competence, independence, quality, configuration, and verification plans.",
                "software planning and organization",
                [
                    "software quality and safety plans",
                    "competence and independence records",
                ],
            ),
            _objective(
                "RAIL-DEVELOP",
                "Trace requirements through architecture, design, implementation, integration, verification, validation, and acceptance using techniques suitable for the integrity level.",
                "software development lifecycle",
                ["lifecycle trace", "technique selection rationale", "V&V results"],
            ),
            _objective(
                "RAIL-SUPPORT",
                "Control configuration, tools, components, change, anomalies, maintenance, deployment, and archival evidence.",
                "support and maintenance processes",
                [
                    "configuration index",
                    "tool and component evidence",
                    "change and anomaly records",
                ],
            ),
            _objective(
                "RAIL-ASSESS",
                "Provide complete, reviewable evidence for authorized safety assessment without treating automated analysis as approval.",
                "assessment and acceptance",
                ["safety case evidence", "assessment findings", "acceptance record"],
            ),
        ],
    },
    {
        "id": "iec-62443-4-1-2018",
        "title": "IEC 62443-4-1:2018 secure product development lifecycle",
        "publisher": "IEC",
        "edition": "2018",
        "status": "current",
        "reference_url": "https://webstore.iec.ch/en/publication/33615",
        "access": "licensed_normative_text_required",
        "scope": "Secure development lifecycle for industrial automation and control-system products.",
        "objectives": [
            _objective(
                "62443-PROCESS",
                "Operate a governed secure-development process with roles, competence, scope, quality, suppliers, and records.",
                "security management",
                [
                    "secure lifecycle process",
                    "role and competence evidence",
                    "supplier controls",
                ],
            ),
            _objective(
                "62443-REQUIREMENTS",
                "Derive, review, trace, and maintain security requirements from threat models and product context.",
                "security requirements and design",
                ["threat model", "security requirements", "secure-design review"],
            ),
            _objective(
                "62443-IMPLEMENT",
                "Apply secure implementation, verification, vulnerability testing, component control, and defect-management practices.",
                "secure implementation and verification",
                [
                    "implementation controls",
                    "security tests",
                    "defect and component records",
                ],
            ),
            _objective(
                "62443-MAINTAIN",
                "Manage security issues, updates, disclosure, product defense, and end-of-support communications throughout the supported lifecycle.",
                "security issue and update management",
                [
                    "vulnerability process",
                    "update evidence",
                    "security guidance",
                    "support policy",
                ],
            ),
        ],
    },
    {
        "id": "iec-61511-process-safety",
        "title": "IEC 61511 process-industry functional safety",
        "publisher": "IEC",
        "edition": "IEC 61511-1:2016+A1:2017 and current series",
        "status": "current_series",
        "reference_url": "https://webstore.iec.ch/en/publication/5527",
        "access": "licensed_normative_text_required",
        "scope": "Safety instrumented systems and application-program lifecycle in process industries.",
        "objectives": [
            _objective(
                "61511-HAZARD",
                "Perform hazard and risk assessment, allocate risk reduction, and specify safety instrumented functions and integrity requirements.",
                "hazard assessment and safety requirements",
                [
                    "hazard assessment",
                    "SIF allocation",
                    "safety requirements specification",
                ],
            ),
            _objective(
                "61511-LIFECYCLE",
                "Plan, design, implement, integrate, validate, operate, maintain, modify, and decommission the safety instrumented system under functional-safety management.",
                "safety lifecycle",
                [
                    "lifecycle plan",
                    "application-program evidence",
                    "validation and operation records",
                ],
            ),
            _objective(
                "61511-INDEPENDENCE",
                "Establish competence, verification, validation, assessment, and independence appropriate to the claimed integrity and lifecycle activity.",
                "management and assurance",
                [
                    "competence record",
                    "verification evidence",
                    "functional-safety assessment",
                ],
            ),
            _objective(
                "61511-CHANGE",
                "Control bypasses, overrides, incidents, proof tests, maintenance, modifications, and revalidation using retained operational evidence.",
                "operation, maintenance, and modification",
                [
                    "operational history",
                    "proof-test evidence",
                    "change and revalidation record",
                ],
            ),
        ],
    },
)
