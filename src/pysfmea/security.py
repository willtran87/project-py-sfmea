"""Versioned service threat model and residual-risk register."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .version import __version__


def service_threat_model() -> dict[str, Any]:
    threats = [
        (
            "TM-01",
            "Repository evidence substitution",
            "tampering",
            "Bounded regular non-link reads, identity reconciliation, exact-byte hashes, and manifest binding.",
        ),
        (
            "TM-02",
            "Path traversal or unsafe publication target",
            "tampering",
            "Repository containment checks plus destination-state-checked atomic publication.",
        ),
        (
            "TM-03",
            "Repository code execution during static scan",
            "execution",
            "AST and bounded lexical parsing; scan adapters declare in-process non-execution isolation.",
        ),
        (
            "TM-04",
            "Malicious JSON/XML/TOML or archive resource exhaustion",
            "denial_of_service",
            "Byte, depth, node, record, member, and aggregate limits with strict decoders.",
        ),
        (
            "TM-05",
            "Prompt injection or evidence exfiltration through LLM use",
            "information_disclosure",
            "Explicit provider invocation, bounded redacted evidence packets, schema-constrained output, and prohibited decision fields.",
        ),
        (
            "TM-06",
            "Unauthorized review or risk decision",
            "elevation_of_privilege",
            "Named reviewer/rationale workflows, exact-state binding, role separation, and no automatic approval semantics.",
        ),
        (
            "TM-07",
            "Tampered report, package, receipt, or schema bundle",
            "tampering",
            "Canonical digests, exact regeneration, verifier provenance, downgrade protection, and optional signatures.",
        ),
        (
            "TM-08",
            "Unsafe test or fault-injection execution",
            "execution",
            "Explicit sandbox policy, pinned image identity, resource/network controls, and separate evidence review.",
        ),
        (
            "TM-09",
            "Review service exposure or session misuse",
            "spoofing",
            "Loopback-first operation, deployment authentication/TLS requirement, bounded requests, and atomic state writes.",
        ),
        (
            "TM-10",
            "Denial of service from repository/report scale",
            "denial_of_service",
            "Traversal and projection limits, cache bounds, runtime/memory budgets, compact profiles, and browser gates.",
        ),
    ]
    threat_records = [
        {
            "id": identifier,
            "scenario": scenario,
            "class": threat_class,
            "controls": controls,
            "verification": "Retain the applicable test, CI, verifier, or operational configuration receipt.",
            "status": "mitigated_with_residual_risk",
        }
        for identifier, scenario, threat_class, controls in threats
    ]
    residual = [
        {
            "id": "RR-01",
            "threat_ids": ["TM-03", "TM-04", "TM-10"],
            "risk": "Parser defects or pathological inputs can still exhaust native/process resources or trigger a dependency vulnerability.",
            "owner": "Product security maintainer",
            "treatment": "Maintain dependency audit, adversarial corpus, process/container limits, and incident response.",
            "review_trigger": "Parser/dependency change, security advisory, or budget regression.",
            "acceptance_authority": "Deploying organization",
        },
        {
            "id": "RR-02",
            "threat_ids": ["TM-05"],
            "risk": "Redaction is pattern-based and a configured remote model receives selected evidence.",
            "owner": "Deploying data owner",
            "treatment": "Use local inference or disable LLM features for restricted data; review provider retention and access policy.",
            "review_trigger": "Provider, model, prompt, data classification, or redaction change.",
            "acceptance_authority": "Deploying data owner",
        },
        {
            "id": "RR-03",
            "threat_ids": ["TM-08", "TM-09"],
            "risk": "Networked review service or sandbox execution expands the attack surface beyond offline scanning.",
            "owner": "Deploying service owner",
            "treatment": "Require authenticated TLS reverse proxy, least privilege, network isolation, logging, backups, and environment-specific penetration testing.",
            "review_trigger": "Non-loopback binding, multi-user deployment, sandbox policy, or infrastructure change.",
            "acceptance_authority": "Deploying service owner",
        },
        {
            "id": "RR-04",
            "threat_ids": ["TM-06", "TM-07"],
            "risk": "Local identities and unsigned artifacts do not by themselves establish organizational identity or non-repudiation.",
            "owner": "Assurance process owner",
            "treatment": "Integrate enterprise identity, access control, durable audit storage, and signing-key governance.",
            "review_trigger": "Regulated handoff, external reliance, or identity/signing policy change.",
            "acceptance_authority": "Assurance process owner",
        },
    ]
    material = {
        "format": "pysfmea-service-threat-model-1",
        "tool_version": __version__,
        "scope": "PySFMEA static scanner, offline artifacts, optional review service, LLM provider boundary, and sandbox execution boundary.",
        "assets": [
            "repository source and configuration",
            "analysis findings and decisions",
            "guidance and evidence",
            "credentials and provider data",
            "signed/review artifacts",
        ],
        "trust_boundaries": [
            "repository filesystem",
            "artifact publication filesystem",
            "browser/review-service client",
            "optional model provider",
            "optional execution sandbox",
            "CI and signing environment",
        ],
        "threats": threat_records,
        "residual_risks": residual,
        "deployment_minimums": [
            "Bind locally unless an authenticated TLS reverse proxy is configured.",
            "Run as a dedicated least-privilege identity with repository/output allowlists.",
            "Keep model credentials out of analysis artifacts and logs.",
            "Keep sandbox networking disabled unless an approved test requires it.",
            "Retain backups, audit receipts, dependency SBOM/audit evidence, and incident contacts.",
        ],
        "review_policy": {
            "cadence": "at least annually and on every listed trigger",
            "required_roles": [
                "product security maintainer",
                "deploying service/data owner",
                "assurance process owner",
            ],
            "authority": "risk acceptance remains with the deploying organization",
        },
        "non_claims": [
            "penetration_test",
            "formal_security_proof",
            "deployment_authorization",
            "identity_provider_integration",
            "automatic_residual_risk_acceptance",
        ],
    }
    return {**material, "content_sha256": canonical_json_sha256(material)}


def export_service_threat_model(
    destination: str | Path, *, format: str = "json"
) -> Path:
    model = service_threat_model()
    if format == "json":
        rendered = json.dumps(model, indent=2, ensure_ascii=False) + "\n"
    elif format == "markdown":
        lines = [
            "# PySFMEA service threat model",
            "",
            model["scope"],
            "",
            "## Threat register",
            "",
        ]
        lines.extend(
            f"- **{value['id']} / {value['class']}**: {value['scenario']} Controls: {value['controls']}"
            for value in model["threats"]
        )
        lines.extend(["", "## Residual-risk register", ""])
        lines.extend(
            f"- **{value['id']}**: {value['risk']} Owner: {value['owner']}. Treatment: {value['treatment']} Acceptance: {value['acceptance_authority']}."
            for value in model["residual_risks"]
        )
        lines.extend(["", f"Model SHA-256: `{model['content_sha256']}`", ""])
        rendered = "\n".join(lines)
    else:
        raise ValueError("threat-model format must be json or markdown")
    return atomic_publish_text(destination, rendered, label="service threat model")
