"""Resolved, auditable system context for an SFMEA analysis run."""

from __future__ import annotations

import hashlib
import json
from typing import Any

CONTEXT_FIELDS: tuple[tuple[str, str, bool], ...] = (
    ("purpose", "System purpose or mission outcome", True),
    ("mission", "Mission or service objective", False),
    ("boundary", "Analysis boundary and exclusions", True),
    ("operating_context", "Operating context and environment", True),
    ("operational_modes", "Operational modes", False),
    ("system_states", "Relevant system states", False),
    ("must_work_functions", "Functions that must work", False),
    ("must_not_work_functions", "Functions that must not occur", False),
    ("safe_states", "Required safe states", False),
    ("degraded_states", "Permitted degraded states", False),
    ("interfaces", "External and internal interfaces", False),
    ("human_interactions", "Human and operator interactions", False),
    ("timing_constraints", "Timing constraints", False),
    ("resource_constraints", "Resource constraints", False),
    ("deployment_environments", "Deployment environments", False),
    ("criticality", "System criticality classification", False),
    ("assumptions", "Analysis assumptions", False),
    ("exclusions", "Explicit analysis exclusions", False),
)


def _present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return value is not None


def build_system_context(config: dict[str, Any]) -> dict[str, Any]:
    """Build a context-completeness record without blocking an incomplete scan."""

    project = config.get("project", {})
    list_fields = {
        "operational_modes",
        "system_states",
        "must_work_functions",
        "must_not_work_functions",
        "safe_states",
        "degraded_states",
        "interfaces",
        "human_interactions",
        "timing_constraints",
        "resource_constraints",
        "deployment_environments",
        "assumptions",
        "exclusions",
    }
    resolved: dict[str, Any] = {
        field: project.get(field, [] if field in list_fields else "")
        for field, _, _ in CONTEXT_FIELDS
    }
    resolved.update(
        {
            "stakeholders": list(project.get("stakeholders", [])),
            "hazards": list(config.get("hazards", [])),
            "system_interfaces": list(config.get("system_interfaces", [])),
            "critical_functions": list(config.get("critical_functions", [])),
            "fault_tolerance_assumptions": list(
                config.get("analysis", {}).get("fault_tolerance_assumptions", [])
            ),
            "guidance_profiles": list(
                config.get("analysis", {}).get("guidance_profiles", [])
            ),
        }
    )
    field_records = []
    missing_required: list[str] = []
    missing_recommended: list[str] = []
    unresolved_questions: list[str] = []
    for field, label, required in CONTEXT_FIELDS:
        present = _present(resolved.get(field))
        field_records.append(
            {
                "field": field,
                "label": label,
                "required": required,
                "status": "provided" if present else "unresolved",
                "provenance": f"configuration.project.{field}",
            }
        )
        if not present:
            target = missing_required if required else missing_recommended
            target.append(field)
            unresolved_questions.append(f"What is the approved {label.lower()}?")

    provided = sum(record["status"] == "provided" for record in field_records)
    completeness = round(100 * provided / len(field_records), 1) if field_records else 100.0
    if missing_required:
        status = "insufficient"
    elif missing_recommended:
        status = "partial"
    else:
        status = "complete"
    limitations = []
    if missing_required:
        limitations.append(
            "Required system context is incomplete; generated failure effects and risk framing "
            "must not be treated as sufficient for approval."
        )
    if missing_recommended:
        limitations.append(
            "Unresolved contextual fields constrain mode-, state-, timing-, resource-, and "
            "safe-state-specific coverage."
        )
    material = {
        "resolved": resolved,
        "fields": field_records,
        "status": status,
        "completeness_percent": completeness,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "unresolved_questions": unresolved_questions,
        "limitations": limitations,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "pysfmea-system-context-1",
        **material,
        "context_sha256": digest,
    }
