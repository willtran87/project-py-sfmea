"""Standards-oriented interchange exports and reproducible analysis differencing."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from .model import stable_id, utc_now
from .version import __version__


def sarif_document(analysis: dict[str, Any]) -> dict[str, Any]:
    """Return SARIF 2.1.0 screening results without claiming confirmed defects."""

    active = [
        value
        for value in analysis.get("items", [])
        if value.get("source_status", "active") == "active"
    ]
    rule_ids = sorted({str(value.get("scanner", {}).get("rule_id", "manual")) for value in active})
    rules = []
    for rule_id in rule_ids:
        example = next(value for value in active if value.get("scanner", {}).get("rule_id") == rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "_"),
                "shortDescription": {"text": str(example.get("scanner", {}).get("guideword", rule_id))},
                "fullDescription": {
                    "text": "SFMEA screening rule that generates a candidate for qualified engineering review."
                },
                "help": {"text": str(example.get("scanner", {}).get("failure_mode", ""))},
                "properties": {
                    "precision": "medium",
                    "tags": ["sfmea", "screening", str(example.get("scanner", {}).get("failure_class", ""))],
                },
            }
        )
    results = []
    for item in active:
        scanner = item.get("scanner", {})
        review = item.get("review", {})
        source = item.get("source", {})
        priority = str(scanner.get("screening_priority", "low"))
        level = "warning" if review.get("disposition") == "accepted" and priority == "high" else "note"
        results.append(
            {
                "ruleId": str(scanner.get("rule_id", "manual")),
                "level": level,
                "message": {
                    "text": str(review.get("failure_mode") or scanner.get("failure_mode", "SFMEA candidate"))
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(source.get("path", "")), "uriBaseId": "%SRCROOT%"},
                            "region": {
                                "startLine": max(1, int(source.get("line", 1) or 1)),
                                "endLine": max(1, int(source.get("end_line", source.get("line", 1)) or 1)),
                            },
                        },
                        "logicalLocations": [
                            {"fullyQualifiedName": str(item.get("component", {}).get("qualname", ""))}
                        ],
                    }
                ],
                "partialFingerprints": {"pysfmeaFindingId": str(item.get("id", ""))},
                "properties": {
                    "pysfmeaCandidate": True,
                    "screeningPriority": priority,
                    "failureClass": str(scanner.get("failure_class", "")),
                    "disposition": str(review.get("disposition", "unreviewed")),
                    "hazardIds": list(review.get("linked_hazards", [])),
                    "citationIds": list(scanner.get("citation_ids", [])),
                    "baselineId": analysis.get("project", {}).get("baseline", {}).get("id", ""),
                    "notice": "Candidate screening result; not a confirmed defect or compliance determination.",
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PySFMEA",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Will-A-W/project-py-sfmea",
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": analysis.get("project", {}).get("baseline", {}).get("id", "")
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "./"}
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not bool(analysis.get("warnings")),
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": str(value.get("message", value))}}
                            for value in analysis.get("warnings", [])[:100]
                        ],
                    }
                ],
            }
        ],
    }


def cyclonedx_document(analysis: dict[str, Any]) -> dict[str, Any]:
    """Return a CycloneDX 1.6 inventory of declared dependencies and hashed manifests."""

    project_name = str(analysis.get("project", {}).get("name", "python-project"))
    baseline_id = str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
    components = []
    for dependency in analysis.get("context", {}).get("dependencies", []):
        name = str(dependency.get("name", "unknown"))
        specification = str(dependency.get("specification", ""))
        is_manifest = name.startswith("manifest:")
        component: dict[str, Any] = {
            "type": "file" if is_manifest else "library",
            "bom-ref": stable_id("DEP", name, specification, str(dependency.get("source", ""))),
            "name": name.removeprefix("manifest:"),
            "properties": [
                {"name": "pysfmea:declared-specification", "value": specification},
                {"name": "pysfmea:declaration-source", "value": str(dependency.get("source", ""))},
                {"name": "pysfmea:resolution-status", "value": "declared-not-resolved"},
            ],
        }
        if is_manifest and specification.startswith("sha256:"):
            component["hashes"] = [{"alg": "SHA-256", "content": specification[7:]}]
        components.append(component)
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'pysfmea:{project_name}:{baseline_id}')}",
        "version": 1,
        "metadata": {
            "timestamp": utc_now(),
            "tools": {"components": [{"type": "application", "name": "PySFMEA", "version": __version__}]},
            "component": {
                "type": "application",
                "bom-ref": "project",
                "name": project_name,
                "version": baseline_id or "unversioned",
                "properties": [
                    {"name": "pysfmea:inventory-scope", "value": "declared dependencies only"},
                    {"name": "pysfmea:resolution-notice", "value": "Versions and transitive dependencies are not resolved unless present in scanned manifests."},
                ],
            },
        },
        "components": components,
        "dependencies": [{"ref": "project", "dependsOn": [value["bom-ref"] for value in components]}],
    }


def _item_state(item: dict[str, Any]) -> dict[str, Any]:
    review = item.get("review", {})
    scanner = item.get("scanner", {})
    return {
        "failure_mode": review.get("failure_mode") or scanner.get("failure_mode", ""),
        "trigger": review.get("trigger") or scanner.get("trigger", ""),
        "causes": review.get("causes", []),
        "local_effect": review.get("local_effect", ""),
        "next_higher_effect": review.get("next_higher_effect", ""),
        "end_effect": review.get("end_effect", ""),
        "severity": review.get("severity"),
        "severity_category": review.get("severity_category", ""),
        "prevention_controls": review.get("prevention_controls", []),
        "detection_controls": review.get("detection_controls", []),
        "linked_hazards": review.get("linked_hazards", []),
        "requirement": review.get("requirement", ""),
        "disposition": review.get("disposition", ""),
        "status": review.get("status", ""),
        "citation_ids": scanner.get("citation_ids", []),
        "source_fingerprint": scanner.get("source_fingerprint", ""),
    }


def differential_analysis(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two canonical runs and enumerate risk/evidence-relevant changes."""

    old = {value.get("id"): value for value in previous.get("items", []) if value.get("source_status", "active") == "active"}
    new = {value.get("id"): value for value in current.get("items", []) if value.get("source_status", "active") == "active"}
    changed = []
    for finding_id in sorted(set(old) & set(new)):
        before = _item_state(old[finding_id])
        after = _item_state(new[finding_id])
        fields = {
            key: {"before": before[key], "after": after[key]}
            for key in before
            if before[key] != after[key]
        }
        if fields:
            changed.append({"finding_id": finding_id, "fields": fields})
    old_assumptions = previous.get("context", {}).get("project", {}).get("assumptions", [])
    new_assumptions = current.get("context", {}).get("project", {}).get("assumptions", [])
    previous_dependencies = previous.get("context", {}).get("dependencies", [])
    current_dependencies = current.get("context", {}).get("dependencies", [])
    old_obligations = {value.get("finding_id"): value for value in previous.get("assurance", {}).get("obligations", [])}
    new_obligations = {value.get("finding_id"): value for value in current.get("assurance", {}).get("obligations", [])}
    invalidated = []
    for finding_id in sorted(set(old_obligations) & set(new_obligations)):
        before = old_obligations[finding_id]
        after = new_obligations[finding_id]
        if before.get("evidence_status") == "sufficient" and after.get("evidence_status") != "sufficient":
            invalidated.append(
                {
                    "finding_id": finding_id,
                    "previous_obligation_id": before.get("id", ""),
                    "current_obligation_id": after.get("id", ""),
                    "reason": "Previously sufficient evidence is no longer sufficient for the current run.",
                }
            )
    return {
        "schema_version": "pysfmea-diff-1",
        "generated_at": utc_now(),
        "previous_baseline_id": previous.get("project", {}).get("baseline", {}).get("id", ""),
        "current_baseline_id": current.get("project", {}).get("baseline", {}).get("id", ""),
        "summary": {
            "new_findings": len(set(new) - set(old)),
            "removed_findings": len(set(old) - set(new)),
            "changed_findings": len(changed),
            "invalidated_verifications": len(invalidated),
            "assumptions_changed": old_assumptions != new_assumptions,
            "dependency_baseline_changed": previous_dependencies != current_dependencies,
            "configuration_changed": previous.get("project", {}).get("baseline", {}).get("config_digest") != current.get("project", {}).get("baseline", {}).get("config_digest"),
        },
        "new_findings": sorted(set(new) - set(old)),
        "removed_findings": sorted(set(old) - set(new)),
        "changed_findings": changed,
        "invalidated_verifications": invalidated,
        "assumptions": {"before": old_assumptions, "after": new_assumptions},
        "notice": "Differences are change indicators for impact review; absence of a reported change does not prove behavioral equivalence.",
    }


def export_json_document(document: dict[str, Any], destination: str | Path) -> Path:
    target = Path(destination).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target
