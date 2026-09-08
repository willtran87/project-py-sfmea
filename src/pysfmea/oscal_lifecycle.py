"""Governed OSCAL 1.2.3 assessment planning and remediation projections.

The generated documents intentionally use a conservative supported subset.  They retain
an exact PySFMEA analysis binding, but normative schema validation and receiving-tool
interoperability remain separate evidence activities.
"""

from __future__ import annotations

import copy
import re
import uuid
from pathlib import Path
from typing import Any, Callable

from .governed_artifact import bounded_text, load_json, publish_json, seal
from .model import utc_now
from .report import analysis_state_sha256

OSCAL_VERSION = "1.2.3"
OSCAL_ASSESSMENT_PLAN_SCHEMA = "https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_assessment-plan_schema.json"
OSCAL_POAM_SCHEMA = (
    "https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_poam_schema.json"
)
OSCAL_AP_VERIFICATION_FORMAT = "pysfmea-oscal-assessment-plan-verification-1"
OSCAL_POAM_VERIFICATION_FORMAT = "pysfmea-oscal-poam-verification-1"
_NAMESPACE = uuid.UUID("7bcd5c2b-b1f4-5af4-a9e4-b173b7c57e4b")


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, "\0".join(parts)))


def _text(value: Any, fallback: str) -> str:
    return (
        bounded_text(value, "OSCAL lifecycle text")
        if isinstance(value, str) and value.strip()
        else fallback
    )


def _metadata(
    analysis: dict[str, Any], *, authority: str, title: str, timestamp: str
) -> tuple[dict[str, Any], str]:
    digest = analysis_state_sha256(analysis)
    actor = bounded_text(authority, "OSCAL authority")
    party_uuid = _uuid("party", actor)
    return (
        {
            "title": bounded_text(title, "OSCAL title"),
            "last-modified": timestamp,
            "version": digest[:12],
            "oscal-version": OSCAL_VERSION,
            "props": [
                {"name": "pysfmea-analysis-state-sha256", "value": digest},
                {
                    "name": "pysfmea-baseline-id",
                    "value": str(
                        analysis.get("project", {}).get("baseline", {}).get("id", "")
                    ),
                },
            ],
            "roles": [{"id": "assessment-authority", "title": "Assessment authority"}],
            "parties": [{"uuid": party_uuid, "type": "organization", "name": actor}],
            "responsible-parties": [
                {"role-id": "assessment-authority", "party-uuids": [party_uuid]}
            ],
        },
        party_uuid,
    )


def _active_findings(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    values = analysis.get("findings", analysis.get("failure_modes", []))
    if not isinstance(values, list):
        return []
    return [
        item
        for item in values
        if isinstance(item, dict)
        and str(item.get("status", "open")).lower()
        not in {"closed", "resolved", "accepted"}
    ]


def oscal_assessment_plan(
    analysis: dict[str, Any],
    *,
    authority: str,
    ssp_href: str,
    title: str = "PySFMEA software assurance assessment plan",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create a deterministic, analysis-bound OSCAL Assessment Plan subset."""

    timestamp = generated_at or utc_now()
    metadata, party_uuid = _metadata(
        analysis, authority=authority, title=title, timestamp=timestamp
    )
    digest = analysis_state_sha256(analysis)
    activities: list[dict[str, Any]] = []
    tasks: list[dict[str, Any]] = []
    component_ids = {
        str(item.get("component_id") or item.get("source_component_id") or "unmapped")
        for item in _active_findings(analysis)
    }
    if not component_ids:
        component_ids = {
            str(item.get("id"))
            for item in analysis.get("components", [])
            if isinstance(item, dict) and item.get("id")
        }
    for component_id in sorted(component_ids):
        activity_uuid = _uuid("activity", digest, component_id)
        task_uuid = _uuid("task", digest, component_id)
        activities.append(
            {
                "uuid": activity_uuid,
                "title": f"Assess component {component_id}",
                "description": "Examine static analysis evidence and test the applicable failure-mode controls.",
                "props": [{"name": "pysfmea-component-id", "value": component_id}],
                "responsible-roles": [
                    {"role-id": "assessment-authority", "party-uuids": [party_uuid]}
                ],
            }
        )
        tasks.append(
            {
                "uuid": task_uuid,
                "type": "action",
                "title": f"Execute assessment for {component_id}",
                "associated-activities": [
                    {
                        "activity-uuid": activity_uuid,
                        "subjects": [
                            {
                                "type": "component",
                                "include-subjects": [
                                    {
                                        "subject-uuid": _uuid(
                                            "component-subject", digest, component_id
                                        ),
                                        "type": "component",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
    return {
        "$schema": OSCAL_ASSESSMENT_PLAN_SCHEMA,
        "assessment-plan": {
            "uuid": _uuid("assessment-plan", digest, timestamp, title, ssp_href),
            "metadata": metadata,
            "import-ssp": {"href": bounded_text(ssp_href, "OSCAL SSP reference")},
            "local-definitions": {"activities": activities},
            "reviewed-controls": {"control-selections": [{"include-all": {}}]},
            "assessment-subjects": [{"type": "component", "include-all": {}}],
            "tasks": tasks,
        },
    }


def oscal_poam(
    analysis: dict[str, Any],
    *,
    authority: str,
    ssp_href: str,
    title: str = "PySFMEA plan of action and milestones",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Project open SFMEA findings into a conservative OSCAL POA&M subset."""

    timestamp = generated_at or utc_now()
    metadata, party_uuid = _metadata(
        analysis, authority=authority, title=title, timestamp=timestamp
    )
    digest = analysis_state_sha256(analysis)
    observations: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    for index, finding in enumerate(_active_findings(analysis)):
        identifier = _text(finding.get("id"), f"finding-{index + 1}")
        title_value = _text(
            finding.get("title") or finding.get("failure_mode"), identifier
        )
        description = _text(
            finding.get("effect")
            or finding.get("local_effect")
            or finding.get("description"),
            "Potential software failure effect requires engineering review.",
        )
        component_id = _text(
            finding.get("component_id") or finding.get("source_component_id"),
            "unmapped",
        )
        observation_uuid = _uuid("observation", digest, identifier)
        risk_uuid = _uuid("risk", digest, identifier)
        observations.append(
            {
                "uuid": observation_uuid,
                "title": title_value,
                "description": description,
                "props": [
                    {"name": "pysfmea-finding-id", "value": identifier},
                    {"name": "pysfmea-component-id", "value": component_id},
                ],
                "methods": ["EXAMINE"],
                "types": ["finding"],
                "origins": [{"actors": [{"type": "party", "actor-uuid": party_uuid}]}],
                "collected": timestamp,
            }
        )
        risks.append(
            {
                "uuid": risk_uuid,
                "title": title_value,
                "description": description,
                "statement": f"If {title_value.lower()}, then {description}",
                "status": "open",
                "origins": [{"actors": [{"type": "party", "actor-uuid": party_uuid}]}],
                "related-observations": [{"observation-uuid": observation_uuid}],
                "props": [{"name": "pysfmea-finding-id", "value": identifier}],
            }
        )
        items.append(
            {
                "uuid": _uuid("poam-item", digest, identifier),
                "title": f"Remediate {title_value}",
                "description": "Plan, implement, independently verify, and authorize the disposition of this exact finding.",
                "props": [
                    {"name": "pysfmea-finding-id", "value": identifier},
                    {"name": "pysfmea-component-id", "value": component_id},
                ],
                "related-observations": [{"observation-uuid": observation_uuid}],
                "related-risks": [{"risk-uuid": risk_uuid}],
                "remarks": "Owner, milestones, resources, due dates, and risk acceptance remain authority-controlled fields.",
            }
        )
    return {
        "$schema": OSCAL_POAM_SCHEMA,
        "plan-of-action-and-milestones": {
            "uuid": _uuid("poam", digest, timestamp, title, ssp_href),
            "metadata": metadata,
            "import-ssp": {"href": bounded_text(ssp_href, "OSCAL SSP reference")},
            "system-id": {
                "identifier-type": "https://github.com/willtran87/project-py-sfmea/baseline",
                "id": str(
                    analysis.get("project", {})
                    .get("baseline", {})
                    .get("id", digest[:12])
                ),
            },
            "local-definitions": {
                "remarks": "PySFMEA finding identities are retained in props."
            },
            "observations": observations,
            "risks": risks,
            "poam-items": items,
        },
    }


def _digest_from(value: dict[str, Any], root_name: str) -> str | None:
    try:
        matches = [
            item.get("value")
            for item in value[root_name]["metadata"]["props"]
            if isinstance(item, dict)
            and item.get("name") == "pysfmea-analysis-state-sha256"
        ]
        return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None
    except (KeyError, TypeError):
        return None


def _verify(
    value: dict[str, Any],
    *,
    analysis: dict[str, Any] | None,
    root_name: str,
    schema: str,
    format_value: str,
    regenerate: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    errors: list[str] = []
    digest = _digest_from(value, root_name)
    try:
        root = value[root_name]
        metadata = root["metadata"]
        structure = bool(
            set(value) == {"$schema", root_name}
            and value["$schema"] == schema
            and isinstance(root.get("uuid"), str)
            and metadata.get("oscal-version") == OSCAL_VERSION
            and re.fullmatch(r"[0-9a-f]{64}", digest or "")
            and isinstance(root.get("import-ssp", {}).get("href"), str)
        )
        if root_name == "assessment-plan":
            structure = (
                structure
                and isinstance(root.get("tasks"), list)
                and isinstance(
                    root.get("local-definitions", {}).get("activities"), list
                )
            )
        else:
            counts = [
                len(root.get(name, []))
                for name in ("observations", "risks", "poam-items")
            ]
            structure = structure and len(set(counts)) == 1
    except (KeyError, TypeError):
        structure = False
    if not structure:
        errors.append(f"OSCAL {root_name} supported subset is invalid")
    binding: bool | None = None
    regeneration: bool | None = None
    if analysis is not None:
        binding = digest == analysis_state_sha256(analysis)
        if not binding:
            errors.append("OSCAL document does not bind the exact analysis state")
        if structure:
            try:
                root = value[root_name]
                metadata = root["metadata"]
                expected = regenerate(
                    analysis,
                    authority=metadata["parties"][0]["name"],
                    title=metadata["title"],
                    ssp_href=root["import-ssp"]["href"],
                    generated_at=metadata["last-modified"],
                )
                regeneration = expected == value
                if not regeneration:
                    errors.append("OSCAL document does not exactly regenerate")
            except (KeyError, TypeError, ValueError):
                regeneration = False
                errors.append("OSCAL regeneration inputs are invalid")
    valid = structure and binding is not False and regeneration is not False
    return seal(
        {
            "format": format_value,
            "valid": valid,
            "ready_for_normative_validation": valid,
            "checks": {
                "supported_subset": structure,
                "analysis_binding": binding,
                "exact_regeneration": regeneration,
            },
            "errors": errors,
            "notice": "Validate the exact document against the official NIST OSCAL schema and an independent receiving implementation before relying on interchange.",
        }
    )


def verify_oscal_assessment_plan(
    value: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    return _verify(
        value,
        analysis=analysis,
        root_name="assessment-plan",
        schema=OSCAL_ASSESSMENT_PLAN_SCHEMA,
        format_value=OSCAL_AP_VERIFICATION_FORMAT,
        regenerate=oscal_assessment_plan,
    )


def verify_oscal_poam(
    value: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    return _verify(
        value,
        analysis=analysis,
        root_name="plan-of-action-and-milestones",
        schema=OSCAL_POAM_SCHEMA,
        format_value=OSCAL_POAM_VERIFICATION_FORMAT,
        regenerate=oscal_poam,
    )


def _verify_file(
    source: str | Path,
    *,
    analysis: dict[str, Any] | None,
    verifier: Callable[..., dict[str, Any]],
    label: str,
    format_value: str,
) -> dict[str, Any]:
    try:
        return verifier(load_json(source, label=label), analysis=analysis)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": format_value,
                "valid": False,
                "ready_for_normative_validation": False,
                "checks": {
                    "supported_subset": False,
                    "analysis_binding": False if analysis is not None else None,
                    "exact_regeneration": False if analysis is not None else None,
                },
                "errors": [str(exc)],
                "notice": f"{label} verification failed closed.",
            }
        )


def verify_oscal_assessment_plan_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    return _verify_file(
        source,
        analysis=analysis,
        verifier=verify_oscal_assessment_plan,
        label="OSCAL Assessment Plan",
        format_value=OSCAL_AP_VERIFICATION_FORMAT,
    )


def verify_oscal_poam_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    return _verify_file(
        source,
        analysis=analysis,
        verifier=verify_oscal_poam,
        label="OSCAL POA&M",
        format_value=OSCAL_POAM_VERIFICATION_FORMAT,
    )


def export_oscal_assessment_plan(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_oscal_assessment_plan(value)["valid"]:
        raise ValueError("OSCAL Assessment Plan document is internally invalid")
    return publish_json(copy.deepcopy(value), destination)


def export_oscal_poam(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_oscal_poam(value)["valid"]:
        raise ValueError("OSCAL POA&M document is internally invalid")
    return publish_json(copy.deepcopy(value), destination)
