"""Complementary governance, evaluation, usability, and continuity profiles.

The objective text is original navigation guidance.  It is intentionally not a
copy of licensed normative requirements.  Projects must retain controlled
copies, tailoring decisions, and evidence approved by their own authorities.
"""

from __future__ import annotations

from typing import Any


def _objective(
    identifier: str, title: str, locator: str, *evidence: str
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "reference_locator": locator,
        "expected_evidence": list(evidence),
    }


def _profile(
    identifier: str,
    title: str,
    publisher: str,
    edition: str,
    url: str,
    scope: str,
    objectives: list[dict[str, Any]],
    *,
    access: str = "licensed_normative_text_required",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "publisher": publisher,
        "edition": edition,
        "status": "current",
        "reference_url": url,
        "access": access,
        "scope": scope,
        "objectives": objectives,
    }


GOVERNANCE_STANDARD_PROFILES: tuple[dict[str, Any], ...] = (
    _profile(
        "nist-csf-2-0",
        "NIST Cybersecurity Framework 2.0",
        "NIST",
        "2.0 (2024)",
        "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20",
        "Organization-wide cybersecurity governance and outcomes across Govern, Identify, Protect, Detect, Respond, and Recover.",
        [
            _objective("CSF-GOVERN", "Establish cybersecurity context, strategy, policy, roles, oversight, risk appetite, supply-chain governance, and accountable decisions.", "GOVERN function", "governance charter", "risk strategy", "role and supply-chain records"),
            _objective("CSF-IDENTIFY", "Inventory assets, services, software, data, dependencies, vulnerabilities, threats, impacts, and prioritized risks.", "IDENTIFY function", "asset and dependency inventory", "risk register", "prioritization record"),
            _objective("CSF-PROTECT-DETECT", "Implement and verify safeguards, secure engineering, access, data, platform, resilience, monitoring, and adverse-event detection.", "PROTECT and DETECT functions", "control evidence", "monitoring coverage", "detection validation"),
            _objective("CSF-RESPOND-RECOVER", "Prepare, exercise, execute, communicate, learn from, and improve incident response, restoration, and recovery.", "RESPOND and RECOVER functions", "response and recovery plans", "exercise evidence", "lessons and improvements"),
        ],
        access="public_guidance",
    ),
    _profile(
        "iso-27001-27002-27005",
        "ISO/IEC 27001, 27002, and 27005 information-security management",
        "ISO and IEC",
        "27001:2022, 27002:2022, and 27005:2022; applicable amendments",
        "https://www.iso.org/standard/iso-iec-27000-family",
        "Information-security management system, controls, and risk-management lifecycle.",
        [
            _objective("ISMS-CONTEXT", "Define organizational context, interested parties, scope, leadership, policy, responsibilities, and information-security objectives.", "ISMS context, leadership, and planning", "ISMS scope", "policy and objectives", "role assignments"),
            _objective("ISMS-RISK", "Apply repeatable risk identification, analysis, evaluation, treatment, acceptance, and residual-risk review using approved criteria.", "information-security risk assessment and treatment", "risk methodology", "risk register", "treatment and acceptance records"),
            _objective("ISMS-CONTROLS", "Select, tailor, implement, operate, and trace justified organizational, people, physical, and technological controls.", "statement of applicability and control guidance", "statement of applicability", "control design and operating evidence"),
            _objective("ISMS-EVALUATE", "Measure performance, conduct independent audits and management reviews, control nonconformities, and continually improve the ISMS.", "performance evaluation and improvement", "metrics", "audit and management-review records", "corrective actions"),
        ],
    ),
    _profile(
        "iso-27701-2025",
        "ISO/IEC 27701:2025 privacy information management system",
        "ISO and IEC",
        "2025, edition 2",
        "https://www.iso.org/standard/27701",
        "Standalone privacy information management requirements and guidance for PII controllers and processors.",
        [
            _objective("PIMS-SCOPE", "Define privacy context, PII processing roles, scope, interested parties, obligations, objectives, authority, and governance interfaces.", "PIMS context and leadership", "PIMS scope", "PII role inventory", "obligation register"),
            _objective("PIMS-RISK", "Assess privacy risks and impacts across collection, use, sharing, retention, transfer, rights, incidents, and disposal.", "privacy risk assessment and treatment", "data-flow inventory", "privacy impact and risk records", "treatment decisions"),
            _objective("PIMS-CONTROLS", "Implement and verify controller, processor, supplier, transparency, rights, minimization, retention, security, and breach controls.", "controller and processor controls", "control evidence", "supplier agreements", "rights and incident records"),
            _objective("PIMS-IMPROVE", "Monitor measures, complaints, changes, incidents, audits, nonconformities, management review, and continual improvement.", "performance evaluation and improvement", "privacy metrics", "audit evidence", "corrective-action history"),
        ],
    ),
    _profile(
        "iso-29147-30111",
        "ISO/IEC 29147:2018 vulnerability disclosure and ISO/IEC 30111:2019 vulnerability handling",
        "ISO and IEC",
        "29147:2018 and 30111:2019; revisions in progress",
        "https://www.iso.org/standard/72311.html",
        "Coordinated vulnerability intake, triage, remediation, disclosure, communication, and lifecycle learning.",
        [
            _objective("VULN-INTAKE", "Publish authenticated reporting channels and policy; acknowledge, protect, deduplicate, track, and communicate reported vulnerabilities.", "vulnerability disclosure intake", "disclosure policy", "reporting channel evidence", "case records"),
            _objective("VULN-ANALYZE", "Reproduce, validate, scope, prioritize, coordinate, and assess safety, security, privacy, dependency, and exploitability impact.", "vulnerability handling analysis", "reproduction evidence", "affected-product inventory", "risk decision"),
            _objective("VULN-REMEDIATE", "Develop, review, test, release, monitor, and roll back remediations with configuration, advisory, and downstream coordination evidence.", "remediation development and release", "fix and regression evidence", "release and rollback records"),
            _objective("VULN-DISCLOSE", "Coordinate disclosure timing and content, credit reporters, communicate affected versions and mitigations, and retain post-case learning.", "coordinated disclosure", "advisory", "coordination record", "post-case review"),
        ],
    ),
    _profile(
        "iso-15408-18045-2026",
        "ISO/IEC 15408 and ISO/IEC 18045:2026 IT security evaluation",
        "ISO and IEC",
        "15408 parts 1-5:2026 and 18045:2026",
        "https://www.iso.org/standard/18045",
        "Common Criteria security targets, functional and assurance requirements, evaluation evidence, activities, and verdicts.",
        [
            _objective("CC-SCOPE", "Define the target of evaluation, boundary, environment, assets, threats, organizational policies, assumptions, and exact configuration.", "security target introduction and security problem definition", "security target", "TOE and configuration inventory"),
            _objective("CC-OBJECTIVES", "Derive security objectives and trace functional and assurance requirements to threats, policies, assumptions, interfaces, and dependencies.", "security objectives and requirements", "rationale and trace matrix", "requirements baseline"),
            _objective("CC-EVIDENCE", "Produce controlled development, guidance, lifecycle, testing, vulnerability-analysis, configuration, and delivery evidence for the selected assurance package.", "security assurance components", "evaluation evidence index", "test and vulnerability-analysis results"),
            _objective("CC-EVALUATE", "Execute applicable ISO/IEC 18045 evaluator activities, record observations and verdicts, resolve findings, and bind results to the exact evaluated configuration.", "evaluation methodology and activities", "evaluation work units", "observation reports", "evaluation technical report"),
        ],
    ),
    _profile(
        "iso-9241-210-171",
        "ISO 9241-210 human-centred design and ISO 9241-171:2025 software accessibility",
        "ISO",
        "9241-210:2019 and 9241-171:2025",
        "https://www.iso.org/standard/86308.html",
        "Human-centred lifecycle, context of use, user requirements, evaluated designs, usability, and accessible software.",
        [
            _objective("HCD-PLAN", "Plan iterative human-centred activities, responsibilities, competence, representative participation, accessibility, evidence, and acceptance criteria.", "human-centred design planning", "HCD plan", "participant and competence rationale"),
            _objective("HCD-CONTEXT", "Understand users, tasks, goals, environments, assistive technologies, constraints, hazards, and reasonably foreseeable use and misuse.", "context-of-use analysis", "user and task research", "context model", "use-related risk inputs"),
            _objective("HCD-DESIGN", "Specify measurable user and accessibility requirements and iteratively produce design solutions traceable to them.", "user requirements and design solutions", "requirements", "design rationale", "accessibility trace"),
            _objective("HCD-EVALUATE", "Evaluate effectiveness, efficiency, satisfaction, accessibility, errors, recovery, and safety with representative users and retain limitations.", "user-centred evaluation", "study protocol", "task observations", "analysis and improvement record"),
        ],
    ),
    _profile(
        "iec-62366-1",
        "IEC 62366-1 medical-device usability engineering",
        "IEC",
        "2015 with amendment 1:2020; verify applicable consolidated edition",
        "https://webstore.iec.ch/en/publication/21863",
        "Safety-related usability engineering for medical devices, user interfaces, use errors, formative evaluation, and validation.",
        [
            _objective("MEDUSE-SCOPE", "Define intended users, uses, environments, user-interface characteristics, safety-related characteristics, known use problems, and critical tasks.", "use specification and user-interface safety characteristics", "use specification", "critical-task and known-problem analysis"),
            _objective("MEDUSE-RISK", "Identify foreseeable use errors, hazardous situations, task sequences, risk controls, residual risks, and links to the product risk-management file.", "use-related risk analysis", "use-error analysis", "risk-control traceability"),
            _objective("MEDUSE-FORMATIVE", "Perform iterative formative evaluations using justified participants, scenarios, methods, observations, findings, and design changes.", "formative evaluation", "evaluation plans and results", "design-change history"),
            _objective("MEDUSE-VALIDATE", "Conduct summative usability validation of critical tasks and risk controls under representative conditions and resolve unexplained failures.", "usability validation", "validation protocol", "raw observations", "final report"),
        ],
    ),
    _profile(
        "iso-22301-2019",
        "ISO 22301:2019 business continuity management system",
        "ISO",
        "2019 with amendment 1:2024; revision in progress",
        "https://www.iso.org/standard/75106.html",
        "Organizational continuity planning, impact analysis, strategies, procedures, exercises, recovery, and improvement.",
        [
            _objective("BCMS-CONTEXT", "Define continuity scope, interested parties, obligations, leadership, policy, objectives, roles, dependencies, and risk criteria.", "BCMS context, leadership, and planning", "BCMS scope", "policy and objectives", "dependency inventory"),
            _objective("BCMS-IMPACT", "Perform business-impact and risk assessment; define prioritized activities, maximum tolerable disruption, recovery objectives, and resource needs.", "business-impact analysis and risk assessment", "BIA", "recovery objectives", "risk register"),
            _objective("BCMS-STRATEGY", "Implement continuity strategies, response structure, communications, procedures, recovery capabilities, supplier arrangements, and controlled plans.", "business continuity strategies and solutions", "continuity and recovery plans", "supplier and communication evidence"),
            _objective("BCMS-EXERCISE", "Exercise and evaluate continuity capabilities, monitor measures, audit, review incidents and changes, correct deficiencies, and improve.", "exercise programme and performance evaluation", "exercise results", "audit and review evidence", "corrective actions"),
        ],
    ),
    _profile(
        "iso-42006-2025",
        "ISO/IEC 42006:2025 certification bodies auditing AI management systems",
        "ISO and IEC",
        "2025",
        "https://www.iso.org/standard/42006",
        "Competence, consistency, impartiality, audit, and certification controls for bodies certifying ISO/IEC 42001 AI management systems.",
        [
            _objective("AICB-IMPARTIAL", "Define certification scope, legal responsibility, impartiality threats, governance, confidentiality, liability, and separation from prohibited consultancy.", "certification-body structural requirements", "impartiality analysis", "governance and conflict records"),
            _objective("AICB-COMPETENCE", "Establish and retain competence criteria and authorization for application review, audit teams, technical review, certification decisions, and sector-specific AI risks.", "competence requirements", "competence matrix", "authorization and monitoring records"),
            _objective("AICB-AUDIT", "Plan and conduct evidence-based ISO/IEC 42001 audits with suitable duration, sampling, stage, surveillance, recertification, multisite, and change controls.", "audit-process requirements", "audit programme", "plans, working papers, and findings"),
            _objective("AICB-DECIDE", "Separate audit and certification decisions, resolve nonconformities, control certificates, appeals, complaints, records, and public information.", "certification decision and management-system requirements", "independent review", "decision record", "appeal and complaint evidence"),
        ],
    ),
    _profile(
        "faa-do-333-formal-methods",
        "FAA-recognized DO-333 formal methods supplement",
        "FAA and RTCA/EUROCAE",
        "DO-333 / ED-216 recognized by FAA AC 20-115D",
        "https://www.faa.gov/documentLibrary/media/Advisory_Circular/AC_20-115D.pdf",
        "Use of formal methods as part of airborne software verification with controlled models, soundness arguments, coverage, tools, and lifecycle evidence.",
        [
            _objective("FORMAL-PLAN", "Define the lifecycle objectives addressed by formal methods, notation, semantics, assumptions, limitations, personnel, independence, tools, and complementary verification.", "formal-methods planning and applicability", "formal methods plan", "objective-credit matrix", "independence rationale"),
            _objective("FORMAL-MODEL", "Control requirements, models, properties, abstractions, environmental assumptions, configuration, transformations, and traceability to software and tests.", "formal models and properties", "model and property baseline", "trace matrix", "assumption register"),
            _objective("FORMAL-VERIFY", "Retain reproducible proof or counterexample results, coverage evidence, soundness and consistency review, anomalies, and required object-code correlation.", "formal verification evidence", "proof and counterexample artifacts", "coverage and review results"),
            _objective("FORMAL-TOOLS", "Classify and qualify tools when their output eliminates, reduces, or automates required verification without independent checking.", "formal-method tool qualification", "tool classification", "qualification data", "known-anomaly record"),
        ],
        access="public_faa_guidance_and_licensed_normative_text_required",
    ),
    _profile(
        "nist-sp-800-53-53a-r5",
        "NIST SP 800-53 Rev. 5 controls and SP 800-53A Rev. 5 assessment procedures",
        "NIST",
        "Revision 5, including current updates",
        "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "Risk-based security and privacy control selection, implementation, assessment, authorization, and continuous monitoring.",
        [
            _objective("NIST53-TAILOR", "Select and tailor applicable controls and enhancements from a documented risk, mission, legal, and system context.", "SP 800-53 control catalog and tailoring guidance", "control baseline", "tailoring rationale", "applicability record"),
            _objective("NIST53-IMPLEMENT", "Trace control objectives to implemented technical, operational, and management mechanisms and responsible parties.", "SP 800-53 control families", "control implementation statements", "architecture and configuration evidence"),
            _objective("NIST53-ASSESS", "Plan and perform appropriate examine, interview, and test procedures with defined depth, coverage, evidence, and findings.", "SP 800-53A assessment procedures", "assessment plan", "objective evidence", "assessment results"),
            _objective("NIST53-MONITOR", "Resolve deficiencies, authorize residual risk, and continuously monitor control effectiveness and material change.", "authorization and continuous-monitoring use", "POA&M", "risk acceptance", "monitoring evidence"),
        ],
        access="public_guidance",
    ),
    _profile(
        "nist-sp-800-160-v1r1",
        "NIST SP 800-160 Volume 1 Revision 1 systems security engineering",
        "NIST",
        "Volume 1 Revision 1 (2022)",
        "https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final",
        "Lifecycle systems security engineering, trustworthy-system design, assurance, and evidence across system concepts through disposal.",
        [
            _objective("SSE-CONTEXT", "Establish mission, stakeholder, loss, asset, threat, trustworthiness, assurance, and lifecycle context.", "systems security engineering context", "problem definition", "stakeholder and loss analysis"),
            _objective("SSE-ARCH", "Apply security design principles and loss-driven requirements across architecture, interfaces, dependencies, and enabling systems.", "architecture and design processes", "security architecture", "requirements and interface trace"),
            _objective("SSE-EVIDENCE", "Develop an evidence-backed assurance argument that addresses uncertainty, assumptions, emergent behavior, and residual risk.", "assurance and trustworthiness concepts", "assurance case", "verification and validation evidence"),
            _objective("SSE-LIFECYCLE", "Maintain security decisions, configuration, monitoring, change impact, sustainment, and disposal evidence through the lifecycle.", "technical and technical-management processes", "lifecycle records", "change and risk decisions"),
        ],
        access="public_guidance",
    ),
    _profile(
        "nist-sp-800-161-r1",
        "NIST SP 800-161 Revision 1 cyber supply chain risk management",
        "NIST",
        "Revision 1, including current updates",
        "https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final",
        "Cybersecurity supply-chain governance, criticality, supplier risk, acquisition, provenance, monitoring, incident response, and improvement.",
        [
            _objective("C-SCRM-GOVERN", "Define accountable C-SCRM strategy, policy, roles, risk appetite, information sharing, and integration with enterprise risk.", "C-SCRM governance", "strategy and policy", "roles and risk criteria"),
            _objective("C-SCRM-ASSESS", "Inventory critical products, services, suppliers, dependencies, provenance, threats, vulnerabilities, and concentration risks.", "criticality and risk assessment", "supplier and dependency inventory", "risk assessment"),
            _objective("C-SCRM-CONTROL", "Specify, contract, verify, and monitor supply-chain requirements across acquisition, build, delivery, operation, and disposal.", "C-SCRM controls and acquisition", "supplier requirements", "SBOM and provenance", "monitoring evidence"),
            _objective("C-SCRM-RESPOND", "Coordinate supplier incidents, vulnerability response, continuity, recovery, lessons, and reassessment after material change.", "response and improvement", "incident and continuity plans", "exercise and corrective-action records"),
        ],
        access="public_guidance",
    ),
    _profile(
        "nistir-8397",
        "NISTIR 8397 minimum standards for developer verification of software",
        "NIST",
        "2021",
        "https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software",
        "Threat modeling, automated testing, static analysis, review, fuzzing, scanning, dependency review, and evidence-backed developer verification.",
        [
            _objective("DV-PLAN", "Select risk-appropriate verification techniques and define coverage, independence, tools, configurations, acceptance, and retained evidence.", "recommended verification techniques", "verification plan", "tool and acceptance rationale"),
            _objective("DV-STATIC", "Perform review and automated static, secret, dependency, structural, and historical defect analysis with governed triage.", "code-based verification techniques", "tool outputs", "triage and disposition evidence"),
            _objective("DV-DYNAMIC", "Perform requirements-based, black-box, regression, negative, web, and fuzz testing under representative and isolated conditions.", "test-based verification techniques", "test and fuzz results", "coverage and environment evidence"),
            _objective("DV-IMPROVE", "Track escaped defects, false positives, weaknesses, technique effectiveness, and changes to continuously improve verification.", "verification programme improvement", "metrics and trend evidence", "corrective actions"),
        ],
        access="public_guidance",
    ),
    _profile(
        "owasp-samm-v2",
        "OWASP Software Assurance Maturity Model",
        "OWASP Foundation",
        "Version 2",
        "https://owaspsamm.org/model/",
        "Measurable software-assurance maturity across governance, design, implementation, verification, and operations.",
        [
            _objective("SAMM-GOVERN", "Define strategy, metrics, policy, education, and accountable assurance governance appropriate to business risk.", "Governance business functions", "roadmap and metrics", "policy and training evidence"),
            _objective("SAMM-DESIGN", "Perform threat assessment, security requirements, and architecture assessment for material systems and changes.", "Design business functions", "threat models", "security requirements", "architecture review"),
            _objective("SAMM-IMPLEMENT-VERIFY", "Control builds and dependencies, deploy securely, review code, perform security testing, and manage findings.", "Implementation and Verification business functions", "build provenance", "review and test evidence", "finding dispositions"),
            _objective("SAMM-OPERATE", "Manage incidents, environments, operational defenses, defects, and improvement using measured outcomes.", "Operations business functions", "incident and environment evidence", "defect metrics", "improvement plan"),
        ],
        access="public_guidance",
    ),
    _profile(
        "iso-iec-20246-2017",
        "ISO/IEC 20246:2017 work product reviews",
        "ISO and IEC",
        "2017",
        "https://www.iso.org/standard/67407.html",
        "Planned, accountable, evidence-based reviews of requirements, design, code, tests, safety analyses, and other work products.",
        [
            _objective("REVIEW-PLAN", "Define review purpose, scope, entry and exit criteria, roles, competence, independence, methods, and schedule.", "review planning", "review plan", "role and competence evidence"),
            _objective("REVIEW-PREPARE", "Baseline review material, identify applicable criteria, distribute inputs, and retain individual preparation evidence.", "review preparation", "baseline and checklist", "preparation records"),
            _objective("REVIEW-EXECUTE", "Identify, classify, record, disposition, and trace issues and decisions without losing minority or unresolved views.", "review execution", "issue log", "decision and trace records"),
            _objective("REVIEW-CLOSE", "Verify actions, satisfy exit criteria, report measures, approve closure, and improve the review process.", "review closure and improvement", "action verification", "closure report", "review metrics"),
        ],
    ),
    _profile(
        "iec-62443-3-3",
        "IEC 62443-3-3 system security requirements and security levels",
        "IEC",
        "2013; verify applicable edition and amendments",
        "https://webstore.iec.ch/en/publication/7033",
        "Industrial automation and control system zones, conduits, foundational requirements, system requirements, and target security levels.",
        [
            _objective("IACS-ZONES", "Define system under consideration, assets, zones, conduits, interfaces, operational environment, threat assumptions, and target security levels.", "system definition and security levels", "zone and conduit model", "risk and target-level rationale"),
            _objective("IACS-REQUIRE", "Allocate applicable foundational and system security requirements to zones, conduits, components, people, and procedures.", "foundational and system requirements", "requirement allocation", "architecture and responsibility trace"),
            _objective("IACS-VERIFY", "Verify identification, use control, integrity, confidentiality, restricted flow, event response, and availability capabilities under representative conditions.", "system requirement verification", "security test evidence", "configuration and monitoring evidence"),
            _objective("IACS-MAINTAIN", "Control exceptions, compensating measures, vulnerabilities, patches, remote access, incidents, backups, recovery, and reassessment.", "operation and residual-risk evidence", "exception and patch records", "incident and recovery evidence"),
        ],
    ),
)
