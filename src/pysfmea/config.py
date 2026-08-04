"""Project-specific SFMEA configuration and template generation."""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "project": {
        "name": "",
        "purpose": "",
        "boundary": "",
        "operating_context": "",
        "stakeholders": [],
        "interfaces": [],
        "assumptions": [],
    },
    "analysis": {
        "phase": "detailed_design",
        "revision": "",
        "ground_rules": [],
        "included_failure_classes": [
            "functional",
            "data",
            "interface",
            "timing",
            "logic",
            "calculation",
            "environment",
            "resource",
            "detection",
            "hardware",
            "custom",
            "common_cause",
        ],
        "excluded_failure_classes": [],
        "fault_tolerance_assumptions": [],
        "guidance_profiles": ["core_sfmea"],
    },
    "scan": {
        "include_private": True,
        "include_tests": False,
        "include_nested": True,
        "exclude": [],
        "focus": [],
        "coverage_json": "",
    },
    "risk": {
        "method": "severity_only",
        "severity_categories": [],
        "severity_guidance": "Rate the credible system/end effect using the applicable organizational scale.",
        "occurrence_guidance": "Define whether occurrence means fault presence, activation likelihood, or observed frequency.",
        "detection_guidance": "Rate the effectiveness of existing prevention and detection controls using objective evidence.",
        "acceptance_policy": "Risk acceptance requires authorized human review; scanner priority is not a risk rating.",
    },
    "quality": {
        "require_project_context": True,
        "require_reviewer_for_decision": True,
        "require_rejection_rationale": True,
        "require_requirement_for_accepted": True,
        "require_hazard_for_accepted": False,
        "require_severity_for_accepted": True,
        "require_local_effect_for_accepted": True,
        "require_next_higher_effect_for_accepted": True,
        "require_causes_for_accepted": True,
        "require_rating_rationales": True,
        "require_controls_for_accepted": True,
        "require_action_description_for_action": True,
        "require_owner_for_action": True,
        "require_target_date_for_action": True,
        "require_verification_for_verified": True,
        "require_approval_for_closed": True,
        "require_actions_taken_for_closed": True,
        "require_post_action_assessment_for_closed": True,
        "approval_severity_threshold": 8,
        "approval_severity_categories": [],
        "unreviewed_level": "error",
        "scan_warning_level": "error",
    },
    "hazards": [],
    "fault_trees": [],
    "requirements": [],
    "component_mappings": [],
    "system_interfaces": [],
    "reviewers": [],
    "common_causes": [],
    "critical_functions": [],
    "custom_rules": [],
}

RESERVED_SCANNER_RULE_IDS = {
    "functional.omission",
    "functional.incorrect",
    "data.invalid_input",
    "data.model_contract",
    "data.serialization",
    "calculation.precision_or_range",
    "logic.condition_or_sequence",
    "state.invalid_transition",
    "interface.unavailable",
    "interface.bad_response",
    "interface.internal_contract",
    "interface.contract_compatibility",
    "storage.partial_or_corrupt",
    "configuration.missing_or_wrong",
    "process.uncontrolled_failure",
    "environment.runtime_incompatibility",
    "environment.dependency_drift",
    "hardware.abnormal_response",
    "timing.order_or_race",
    "timing.late_or_early",
    "detection.masked_failure",
    "resource.exhaustion",
    "manual",
}


CONFIG_TEMPLATE = '''# PySFMEA project configuration
# Edit this file before the first governed scan. Blank values are allowed.

[project]
name = "Example Python System"
purpose = "Describe what the system must accomplish."
boundary = "Describe what is inside and outside this analysis."
operating_context = "Describe users, deployment, modes, loads, and environmental assumptions."
stakeholders = ["End user", "Operator"]
interfaces = ["External API", "Database"]
assumptions = ["External identity provider is available"]

[analysis]
phase = "detailed_design" # requirements, architecture, detailed_design, implementation, operations
revision = "Draft A"
ground_rules = [
  "Analyze the worst credible effect for each failure mode.",
  "Trace failures across documented software and external interfaces."
]
included_failure_classes = ["functional", "data", "interface", "timing", "logic", "calculation", "environment", "resource", "detection", "hardware", "custom", "common_cause"]
excluded_failure_classes = []
fault_tolerance_assumptions = ["No single software control is credited as independent redundancy."]
guidance_profiles = ["core_sfmea"] # Optional: nasa_assurance, faa_commercial_space, faa_airworthiness, security, legacy_reference

[scan]
include_private = true
include_tests = false
include_nested = true
exclude = ["migrations/**", "generated/**"]
# When non-empty, only matching path:qualified-name components are analyzed.
focus = []
# Optional coverage.py JSON path, relative to this file.
coverage_json = ""

[risk]
method = "severity_only" # severity_only or sod_rpn
severity_categories = [] # Example: ["minor", "major", "hazardous", "catastrophic"]
severity_guidance = "Rate the credible system/end effect using the approved project scale."
occurrence_guidance = "Document the project's interpretation and supporting evidence."
detection_guidance = "Rate existing controls, not planned actions or test-file presence."
acceptance_policy = "High-severity effects require named approval regardless of RPN."

[quality]
require_project_context = true
require_reviewer_for_decision = true
require_rejection_rationale = true
require_requirement_for_accepted = true
require_hazard_for_accepted = false
require_severity_for_accepted = true
require_local_effect_for_accepted = true
require_next_higher_effect_for_accepted = true
require_causes_for_accepted = true
require_rating_rationales = true
require_controls_for_accepted = true
require_action_description_for_action = true
require_owner_for_action = true
require_target_date_for_action = true
require_verification_for_verified = true
require_approval_for_closed = true
require_actions_taken_for_closed = true
require_post_action_assessment_for_closed = true
approval_severity_threshold = 8
approval_severity_categories = [] # Categories requiring named closure approval
unreviewed_level = "error" # error, warning, or information
scan_warning_level = "error"

[[hazards]]
id = "HZ-001"
description = "Example unacceptable system condition"
end_effect = "Describe the consequence to the user, mission, safety, data, or service."
severity = 10

# Optional formal top-down Software Fault Tree. Gates and events are explicit
# engineering inputs; PySFMEA does not infer logical sufficiency from code links.
[[fault_trees]]
id = "SFTA-HZ-001"
hazard = "HZ-001"
top_event_id = "TOP-HZ-001"
top_event = "Example unacceptable system condition occurs"
description = "Preliminary software contribution tree"
assumptions = ["External hardware contributions are analyzed separately"]
gates = [
  { id = "G-LOSS-OR-CORRUPT", type = "OR", description = "Required service is lost or produces unsafe output", inputs = ["EV-OMISSION", "EV-CORRUPTION"] }
]
events = [
  { id = "TOP-HZ-001", type = "top", description = "Example unacceptable system condition occurs", inputs = ["G-LOSS-OR-CORRUPT"] },
  { id = "EV-OMISSION", type = "basic", description = "Critical software function is omitted", component_patterns = ["src/example/payment.py:*"], failure_mode_patterns = ["*omitted*"] },
  { id = "EV-CORRUPTION", type = "undeveloped", description = "Output is corrupted before use", component_patterns = ["src/example/payment.py:*"] }
]

[[requirements]]
id = "REQ-001"
text = "The system shall perform the example critical function safely."
source = "System requirements specification"
hazards = ["HZ-001"]

[[component_mappings]]
pattern = "src/example/payment.py:*"
subsystem = "Transaction processing"
requirements = ["REQ-001"]
hazards = ["HZ-001"]
interfaces = ["IF-001"]

[[system_interfaces]]
id = "IF-001"
source = "Transaction processing"
target = "External payment provider"
description = "Payment authorization request and response"
data = ["Amount", "Currency", "Authorization result"]
assumptions = ["Responses are authenticated and version compatible"]

[[reviewers]]
name = "Example reviewer"
role = "Software engineer"
organization = "Example team"

[[common_causes]]
id = "CC-001"
description = "One shared configuration or dependency causes multiple critical functions to fail together."
component_patterns = ["src/example/payment.py:*", "src/example/refund.py:*"]
hazards = ["HZ-001"]
requirements = ["REQ-001"]
causes = ["Shared dependency defect", "Common configuration error"]
controls = ["Independent validation", "Diverse fallback where required"]

[[critical_functions]]
# Pattern matches a POSIX-style relative path followed by a colon and qualified name.
pattern = "src/example/payment.py:*"
rationale = "Financial transaction boundary"
hazards = ["HZ-001"]

# Add domain-specific failure prompts where generic software guidewords are insufficient.
[[custom_rules]]
id = "domain.duplicate_transaction"
failure_class = "logic"
pattern = "src/example/payment.py:*"
guideword = "Duplicate action"
failure_mode = "The payment operation is applied more than once for one authorized request."
trigger = "A retry or duplicate message follows an ambiguous completion response."
local_effect = "The transaction is recorded or submitted more than once."
causes = ["Non-idempotent retry", "Duplicate event delivery"]
actions = ["Use an idempotency key", "Test ambiguous completion and replay"]
confidence = "project"
'''


def load_config(path: str | Path | None) -> tuple[dict[str, Any], Path | None]:
    if path is None:
        return normalize_config({}), None
    config_path = Path(path).expanduser().resolve()
    with config_path.open("rb") as handle:
        supplied = tomllib.load(handle)
    config = normalize_config(supplied)
    coverage_path = config["scan"].get("coverage_json", "")
    if coverage_path:
        candidate = Path(coverage_path)
        if not candidate.is_absolute():
            config["scan"]["coverage_json"] = str((config_path.parent / candidate).resolve())
    return config, config_path


def normalize_config(supplied: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge and validate a programmatic configuration against the public schema."""

    if supplied is None:
        supplied = {}
    if not isinstance(supplied, dict):
        raise ValueError("configuration root must be a TOML table")
    _reject_unknown_fields(supplied)
    config = copy.deepcopy(DEFAULT_CONFIG)
    for section in ("project", "analysis", "scan", "risk", "quality"):
        value = supplied.get(section, {})
        if not isinstance(value, dict):
            raise ValueError(f"[{section}] must be a TOML table")
        config[section].update(value)
    for section in (
        "hazards",
        "fault_trees",
        "requirements",
        "component_mappings",
        "system_interfaces",
        "reviewers",
        "common_causes",
        "critical_functions",
        "custom_rules",
    ):
        value = supplied.get(section, [])
        if not isinstance(value, list) or not all(isinstance(entry, dict) for entry in value):
            raise ValueError(f"[[{section}]] entries must be TOML tables")
        config[section] = value
    _validate_config(config)
    return config


def _reject_unknown_fields(supplied: dict[str, Any]) -> None:
    table_fields = {
        "project": {
            "name",
            "purpose",
            "boundary",
            "operating_context",
            "stakeholders",
            "interfaces",
            "assumptions",
        },
        "analysis": {
            "phase",
            "revision",
            "ground_rules",
            "included_failure_classes",
            "excluded_failure_classes",
            "fault_tolerance_assumptions",
            "guidance_profiles",
        },
        "scan": {
            "include_private",
            "include_tests",
            "include_nested",
            "exclude",
            "focus",
            "coverage_json",
        },
        "risk": {
            "method",
            "severity_categories",
            "severity_guidance",
            "occurrence_guidance",
            "detection_guidance",
            "acceptance_policy",
        },
        "quality": set(DEFAULT_CONFIG["quality"]),
    }
    array_fields = {
        "hazards": {"id", "description", "end_effect", "severity", "severity_category"},
        "fault_trees": {
            "id",
            "hazard",
            "top_event_id",
            "top_event",
            "description",
            "assumptions",
            "gates",
            "events",
        },
        "requirements": {"id", "text", "source", "hazards"},
        "component_mappings": {
            "pattern",
            "subsystem",
            "requirements",
            "hazards",
            "interfaces",
        },
        "system_interfaces": {
            "id",
            "source",
            "target",
            "description",
            "data",
            "assumptions",
        },
        "reviewers": {"name", "role", "organization"},
        "common_causes": {
            "id",
            "description",
            "component_patterns",
            "hazards",
            "requirements",
            "causes",
            "controls",
        },
        "critical_functions": {"pattern", "rationale", "hazards"},
        "custom_rules": {
            "id",
            "failure_class",
            "pattern",
            "guideword",
            "failure_mode",
            "trigger",
            "local_effect",
            "causes",
            "actions",
            "confidence",
        },
    }
    allowed_sections = set(table_fields) | set(array_fields)
    unknown_sections = set(supplied) - allowed_sections
    if unknown_sections:
        raise ValueError("unknown configuration section(s): " + ", ".join(sorted(unknown_sections)))
    for section, allowed in table_fields.items():
        value = supplied.get(section)
        if isinstance(value, dict):
            unknown = set(value) - allowed
            if unknown:
                raise ValueError(
                    f"unknown [{section}] field(s): " + ", ".join(sorted(unknown))
                )
    for section, allowed in array_fields.items():
        for index, value in enumerate(supplied.get(section, []) or []):
            if isinstance(value, dict):
                unknown = set(value) - allowed
                if unknown:
                    raise ValueError(
                        f"unknown [[{section}]] field(s) at entry {index + 1}: "
                        + ", ".join(sorted(unknown))
                    )


def write_config_template(path: str | Path, *, overwrite: bool = False) -> Path:
    destination = Path(path).expanduser().resolve()
    if destination.exists() and not overwrite:
        raise ValueError(f"configuration already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(CONFIG_TEMPLATE, encoding="utf-8", newline="\n")
    return destination


def _validate_config(config: dict[str, Any]) -> None:
    project = config["project"]
    for field in ("name", "purpose", "boundary", "operating_context"):
        if not isinstance(project.get(field), str):
            raise ValueError(f"project.{field} must be a string")
    for field in ("stakeholders", "interfaces", "assumptions"):
        if not isinstance(project.get(field), list) or not all(
            isinstance(entry, str) for entry in project[field]
        ):
            raise ValueError(f"project.{field} must be an array of strings")
    analysis = config["analysis"]
    if analysis.get("phase") not in {
        "requirements",
        "architecture",
        "detailed_design",
        "implementation",
        "operations",
    }:
        raise ValueError("analysis.phase is not a supported lifecycle phase")
    if not isinstance(analysis.get("revision"), str):
        raise ValueError("analysis.revision must be a string")
    for field in (
        "ground_rules",
        "included_failure_classes",
        "excluded_failure_classes",
        "fault_tolerance_assumptions",
        "guidance_profiles",
    ):
        if not isinstance(analysis.get(field), list) or not all(
            isinstance(entry, str) for entry in analysis[field]
        ):
            raise ValueError(f"analysis.{field} must be an array of strings")
    from .guidance import normalize_profile_ids

    normalize_profile_ids(analysis["guidance_profiles"])
    overlap = set(analysis["included_failure_classes"]) & set(
        analysis["excluded_failure_classes"]
    )
    if overlap:
        raise ValueError(
            "analysis failure classes cannot be both included and excluded: "
            + ", ".join(sorted(overlap))
        )
    scan = config["scan"]
    for field in ("include_private", "include_tests", "include_nested"):
        if not isinstance(scan.get(field), bool):
            raise ValueError(f"scan.{field} must be true or false")
    if not isinstance(scan.get("coverage_json"), str):
        raise ValueError("scan.coverage_json must be a string path")
    for field in ("exclude", "focus"):
        if not isinstance(scan.get(field), list) or not all(
            isinstance(entry, str) for entry in scan[field]
        ):
            raise ValueError(f"scan.{field} must be an array of glob strings")
    risk = config["risk"]
    if risk.get("method") not in {"severity_only", "sod_rpn"}:
        raise ValueError("risk.method must be 'severity_only' or 'sod_rpn'")
    for field in (
        "severity_guidance",
        "occurrence_guidance",
        "detection_guidance",
        "acceptance_policy",
    ):
        if not isinstance(risk.get(field), str):
            raise ValueError(f"risk.{field} must be a string")
    categories = risk.get("severity_categories", [])
    if not isinstance(categories, list) or not all(isinstance(value, str) for value in categories):
        raise ValueError("risk.severity_categories must be an array of strings")
    if len(categories) != len(set(categories)):
        raise ValueError("risk.severity_categories must not contain duplicates")
    quality = config["quality"]
    for field in (
        "require_project_context",
        "require_reviewer_for_decision",
        "require_rejection_rationale",
        "require_requirement_for_accepted",
        "require_hazard_for_accepted",
        "require_severity_for_accepted",
        "require_local_effect_for_accepted",
        "require_next_higher_effect_for_accepted",
        "require_causes_for_accepted",
        "require_rating_rationales",
        "require_controls_for_accepted",
        "require_action_description_for_action",
        "require_owner_for_action",
        "require_target_date_for_action",
        "require_verification_for_verified",
        "require_approval_for_closed",
        "require_actions_taken_for_closed",
        "require_post_action_assessment_for_closed",
    ):
        if not isinstance(quality.get(field), bool):
            raise ValueError(f"quality.{field} must be true or false")
    threshold = quality.get("approval_severity_threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 10:
        raise ValueError("quality.approval_severity_threshold must be from 1 through 10")
    approval_categories = quality.get("approval_severity_categories", [])
    if not isinstance(approval_categories, list) or not all(
        isinstance(value, str) for value in approval_categories
    ):
        raise ValueError("quality.approval_severity_categories must be an array of strings")
    unknown_approval_categories = set(approval_categories) - set(categories)
    if unknown_approval_categories:
        raise ValueError(
            "quality approval categories are not in risk.severity_categories: "
            + ", ".join(sorted(unknown_approval_categories))
        )
    if quality.get("unreviewed_level") not in {"error", "warning", "information"}:
        raise ValueError("quality.unreviewed_level must be error, warning, or information")
    if quality.get("scan_warning_level") not in {"error", "warning", "information"}:
        raise ValueError("quality.scan_warning_level must be error, warning, or information")

    hazard_ids: set[str] = set()
    for hazard in config["hazards"]:
        hazard_id = hazard.get("id")
        if not isinstance(hazard_id, str) or not hazard_id.strip():
            raise ValueError("each hazard requires a non-empty id")
        if hazard_id in hazard_ids:
            raise ValueError(f"duplicate hazard id: {hazard_id}")
        hazard_ids.add(hazard_id)
        for field in ("description", "end_effect"):
            if field in hazard and not isinstance(hazard[field], str):
                raise ValueError(f"hazard {hazard_id} {field} must be a string")
        severity = hazard.get("severity")
        if severity is not None and (
            isinstance(severity, bool)
            or not isinstance(severity, int)
            or not 1 <= severity <= 10
        ):
            raise ValueError(f"hazard {hazard_id} severity must be an integer from 1 through 10")
        severity_category = hazard.get("severity_category", "")
        if not isinstance(severity_category, str):
            raise ValueError(f"hazard {hazard_id} severity_category must be a string")
        if severity_category and severity_category not in categories:
            raise ValueError(
                f"hazard {hazard_id} severity_category is not in risk.severity_categories"
            )
    tree_ids: set[str] = set()
    for tree in config["fault_trees"]:
        tree_id = tree.get("id")
        if not isinstance(tree_id, str) or not tree_id:
            raise ValueError("each fault_trees entry requires a non-empty id")
        if tree_id in tree_ids:
            raise ValueError(f"duplicate fault tree id: {tree_id}")
        tree_ids.add(tree_id)
        hazard_id = tree.get("hazard")
        if hazard_id not in hazard_ids:
            raise ValueError(f"fault tree {tree_id} references unknown hazard: {hazard_id}")
        for field in ("top_event_id", "top_event"):
            if not isinstance(tree.get(field), str) or not tree[field]:
                raise ValueError(f"fault tree {tree_id} requires {field}")
        if not isinstance(tree.get("description", ""), str):
            raise ValueError(f"fault tree {tree_id} description must be a string")
        assumptions = tree.get("assumptions", [])
        if not isinstance(assumptions, list) or not all(
            isinstance(value, str) for value in assumptions
        ):
            raise ValueError(f"fault tree {tree_id} assumptions must be an array of strings")
        gates = tree.get("gates", [])
        events = tree.get("events", [])
        if not isinstance(gates, list) or not all(isinstance(value, dict) for value in gates):
            raise ValueError(f"fault tree {tree_id} gates must be an array of tables")
        if not isinstance(events, list) or not all(isinstance(value, dict) for value in events):
            raise ValueError(f"fault tree {tree_id} events must be an array of tables")
        nodes: dict[str, list[str]] = {}
        for gate in gates:
            unknown = set(gate) - {"id", "type", "description", "inputs", "k"}
            if unknown:
                raise ValueError(
                    f"fault tree {tree_id} gate has unknown fields: "
                    + ", ".join(sorted(unknown))
                )
            gate_id = gate.get("id")
            gate_type = gate.get("type")
            if not isinstance(gate_id, str) or not gate_id:
                raise ValueError(f"fault tree {tree_id} gate requires an id")
            if gate_type not in {"AND", "OR", "VOTE", "INHIBIT"}:
                raise ValueError(f"fault tree {tree_id} gate {gate_id} has invalid type")
            inputs = gate.get("inputs", [])
            if not isinstance(inputs, list) or len(inputs) < 2 or not all(
                isinstance(value, str) and value for value in inputs
            ):
                raise ValueError(
                    f"fault tree {tree_id} gate {gate_id} requires at least two input ids"
                )
            if gate_type == "VOTE" and (
                isinstance(gate.get("k"), bool)
                or not isinstance(gate.get("k"), int)
                or not 1 <= gate["k"] <= len(inputs)
            ):
                raise ValueError(f"fault tree {tree_id} VOTE gate {gate_id} requires valid k")
            if not isinstance(gate.get("description", ""), str):
                raise ValueError(f"fault tree {tree_id} gate {gate_id} description must be a string")
            if gate_id in nodes:
                raise ValueError(f"fault tree {tree_id} has duplicate node id: {gate_id}")
            nodes[gate_id] = inputs
        event_types = {"top", "intermediate", "basic", "undeveloped", "external", "conditioning"}
        for event in events:
            unknown = set(event) - {
                "id",
                "type",
                "description",
                "inputs",
                "component_patterns",
                "failure_mode_patterns",
                "finding_ids",
                "evidence",
                "assumptions",
            }
            if unknown:
                raise ValueError(
                    f"fault tree {tree_id} event has unknown fields: "
                    + ", ".join(sorted(unknown))
                )
            event_id = event.get("id")
            if not isinstance(event_id, str) or not event_id:
                raise ValueError(f"fault tree {tree_id} event requires an id")
            if event.get("type") not in event_types:
                raise ValueError(f"fault tree {tree_id} event {event_id} has invalid type")
            if not isinstance(event.get("description"), str) or not event["description"]:
                raise ValueError(f"fault tree {tree_id} event {event_id} requires a description")
            inputs = event.get("inputs", [])
            if not isinstance(inputs, list) or not all(
                isinstance(value, str) and value for value in inputs
            ):
                raise ValueError(f"fault tree {tree_id} event {event_id} inputs must be strings")
            for field in (
                "component_patterns",
                "failure_mode_patterns",
                "finding_ids",
                "evidence",
                "assumptions",
            ):
                values = event.get(field, [])
                if not isinstance(values, list) or not all(
                    isinstance(value, str) for value in values
                ):
                    raise ValueError(
                        f"fault tree {tree_id} event {event_id} {field} must be strings"
                    )
            if event_id in nodes:
                raise ValueError(f"fault tree {tree_id} has duplicate node id: {event_id}")
            nodes[event_id] = inputs
        top_event_id = tree["top_event_id"]
        event_by_id = {str(value.get("id")): value for value in events}
        if top_event_id not in event_by_id or event_by_id[top_event_id].get("type") != "top":
            raise ValueError(
                f"fault tree {tree_id} top_event_id must identify an event of type top"
            )
        for node_id, inputs in nodes.items():
            unknown_inputs = set(inputs) - set(nodes)
            if unknown_inputs:
                raise ValueError(
                    f"fault tree {tree_id} node {node_id} references unknown inputs: "
                    + ", ".join(sorted(unknown_inputs))
                )
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError(f"fault tree {tree_id} contains a cycle at {node_id}")
            if node_id in visited:
                return
            visiting.add(node_id)
            for child in nodes[node_id]:
                visit(child)
            visiting.remove(node_id)
            visited.add(node_id)

        visit(top_event_id)
    requirement_ids: set[str] = set()
    for requirement in config["requirements"]:
        requirement_id = requirement.get("id")
        if not isinstance(requirement_id, str) or not requirement_id:
            raise ValueError("each requirement requires a non-empty id")
        if requirement_id in requirement_ids:
            raise ValueError(f"duplicate requirement id: {requirement_id}")
        requirement_ids.add(requirement_id)
        for field in ("text", "source"):
            if field in requirement and not isinstance(requirement[field], str):
                raise ValueError(f"requirement {requirement_id} {field} must be a string")
        linked = requirement.get("hazards", [])
        if not isinstance(linked, list) or not all(isinstance(value, str) for value in linked):
            raise ValueError(f"requirement {requirement_id} hazards must be an array of strings")
        unknown = set(linked) - hazard_ids
        if unknown:
            raise ValueError(
                f"requirement {requirement_id} references unknown hazards: "
                + ", ".join(sorted(unknown))
            )
    for mapping in config["component_mappings"]:
        if not isinstance(mapping.get("pattern"), str) or not mapping["pattern"]:
            raise ValueError("each component_mappings entry requires a pattern")
        if not isinstance(mapping.get("subsystem", ""), str):
            raise ValueError("component_mappings subsystem must be a string")
        for field, known in (("requirements", requirement_ids), ("hazards", hazard_ids)):
            linked = mapping.get(field, [])
            if not isinstance(linked, list) or not all(isinstance(value, str) for value in linked):
                raise ValueError(f"component_mappings {field} must be an array of strings")
            unknown = set(linked) - known
            if unknown:
                raise ValueError(
                    f"component mapping {mapping['pattern']!r} references unknown {field}: "
                    + ", ".join(sorted(unknown))
                )
        interfaces = mapping.get("interfaces", [])
        if not isinstance(interfaces, list) or not all(
            isinstance(value, str) for value in interfaces
        ):
            raise ValueError("component_mappings interfaces must be an array of strings")
    interface_ids: set[str] = set()
    for interface in config["system_interfaces"]:
        interface_id = interface.get("id")
        if not isinstance(interface_id, str) or not interface_id:
            raise ValueError("each system_interfaces entry requires a non-empty id")
        if interface_id in interface_ids:
            raise ValueError(f"duplicate system interface id: {interface_id}")
        interface_ids.add(interface_id)
        for field in ("source", "target", "description"):
            if not isinstance(interface.get(field, ""), str):
                raise ValueError(f"system interface {interface_id} {field} must be a string")
        for field in ("data", "assumptions"):
            value = interface.get(field, [])
            if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
                raise ValueError(f"system interface {interface_id} {field} must be an array of strings")
    for mapping in config["component_mappings"]:
        unknown = set(mapping.get("interfaces", [])) - interface_ids
        if unknown:
            raise ValueError(
                f"component mapping {mapping['pattern']!r} references unknown interfaces: "
                + ", ".join(sorted(unknown))
            )
    reviewer_names: set[str] = set()
    for reviewer in config["reviewers"]:
        if not isinstance(reviewer.get("name"), str) or not reviewer["name"]:
            raise ValueError("each reviewers entry requires a name")
        if reviewer["name"] in reviewer_names:
            raise ValueError(f"duplicate reviewer name: {reviewer['name']}")
        reviewer_names.add(reviewer["name"])
        for field in ("role", "organization"):
            if not isinstance(reviewer.get(field, ""), str):
                raise ValueError(f"reviewer {reviewer['name']} {field} must be a string")
    common_cause_ids: set[str] = set()
    for common_cause in config["common_causes"]:
        common_cause_id = common_cause.get("id")
        if not isinstance(common_cause_id, str) or not common_cause_id:
            raise ValueError("each common_causes entry requires a non-empty id")
        if common_cause_id in common_cause_ids:
            raise ValueError(f"duplicate common cause id: {common_cause_id}")
        common_cause_ids.add(common_cause_id)
        if not isinstance(common_cause.get("description"), str) or not common_cause["description"]:
            raise ValueError(f"common cause {common_cause_id} requires a description")
        patterns = common_cause.get("component_patterns", [])
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            raise ValueError(
                f"common cause {common_cause_id} component_patterns must be a non-empty array"
            )
        for field, known in (("hazards", hazard_ids), ("requirements", requirement_ids)):
            values = common_cause.get(field, [])
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError(f"common cause {common_cause_id} {field} must be an array")
            unknown = set(values) - known
            if unknown:
                raise ValueError(
                    f"common cause {common_cause_id} references unknown {field}: "
                    + ", ".join(sorted(unknown))
                )
        for field in ("causes", "controls"):
            values = common_cause.get(field, [])
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError(f"common cause {common_cause_id} {field} must be an array")
    for entry in config["critical_functions"]:
        if not isinstance(entry.get("pattern"), str) or not entry["pattern"]:
            raise ValueError("each critical_functions entry requires a pattern")
        linked = entry.get("hazards", [])
        if not isinstance(linked, list) or not all(isinstance(value, str) for value in linked):
            raise ValueError("critical_functions hazards must be an array of strings")
        if "rationale" in entry and not isinstance(entry["rationale"], str):
            raise ValueError("critical_functions rationale must be a string")
        unknown = set(linked) - hazard_ids
        if unknown:
            raise ValueError(
                f"critical function pattern {entry['pattern']!r} references unknown hazards: "
                + ", ".join(sorted(unknown))
            )
    rule_ids: set[str] = set()
    for rule in config["custom_rules"]:
        required = {"id", "pattern", "guideword", "failure_mode"}
        missing = [field for field in required if not isinstance(rule.get(field), str) or not rule[field]]
        if missing:
            raise ValueError("custom rule missing: " + ", ".join(sorted(missing)))
        if rule["id"] in rule_ids:
            raise ValueError(f"duplicate custom rule id: {rule['id']}")
        if rule["id"] in RESERVED_SCANNER_RULE_IDS:
            raise ValueError(f"custom rule id is reserved by the scanner: {rule['id']}")
        rule_ids.add(rule["id"])
        for field in ("causes", "actions"):
            value = rule.get(field, [])
            if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
                raise ValueError(f"custom rule {rule['id']} {field} must be an array of strings")
        for field in ("trigger", "local_effect", "confidence", "failure_class"):
            if field in rule and not isinstance(rule[field], str):
                raise ValueError(f"custom rule {rule['id']} {field} must be a string")
    known_failure_classes = set(DEFAULT_CONFIG["analysis"]["included_failure_classes"])
    known_failure_classes.update(
        rule.get("failure_class") or "custom" for rule in config["custom_rules"]
    )
    for field in ("included_failure_classes", "excluded_failure_classes"):
        values = analysis[field]
        if len(values) != len(set(values)):
            raise ValueError(f"analysis.{field} must not contain duplicates")
        unknown = set(values) - known_failure_classes
        if unknown:
            raise ValueError(
                f"analysis.{field} contains unknown failure classes: "
                + ", ".join(sorted(unknown))
            )
