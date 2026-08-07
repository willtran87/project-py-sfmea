"""Actionable, machine-readable diagnostics for a completed SFMEA analysis."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .guidance import guidance_traceability
from .repository_inventory import derive_repository_inventory_summary
from .validation import validate_analysis

DIAGNOSTICS_FORMAT = "pysfmea-analysis-diagnostics-1"


def _percent(numerator: int, denominator: int) -> float:
    return round(100 * numerator / denominator, 1) if denominator else 100.0


def _top(counter: Counter[str], limit: int = 15) -> list[dict[str, Any]]:
    return [
        {"value": value, "count": count}
        for value, count in counter.most_common(limit)
    ]


def analysis_diagnostics(analysis: dict[str, Any]) -> dict[str, Any]:
    """Return bounded reconciliation, workload, evidence, and next-action diagnostics."""

    inventory = analysis.get("repository_inventory", {})
    entries = inventory.get("entries", []) if isinstance(inventory, dict) else []
    entries = [value for value in entries if isinstance(value, dict)]
    summary = derive_repository_inventory_summary(inventory) or {}
    items = [
        value
        for value in analysis.get("items", [])
        if isinstance(value, dict) and value.get("source_status", "active") == "active"
    ]
    components = [
        value for value in analysis.get("components", []) if isinstance(value, dict)
    ]
    code_components = [
        value
        for value in components
        if str(value.get("source", {}).get("path", "")).casefold().endswith(".py")
    ]
    run_by_id = {
        str(value.get("adapter_id", "")): value
        for value in analysis.get("adapter_runs", {}).get("runs", [])
        if isinstance(value, dict)
    }
    dependencies = [
        value
        for value in analysis.get("context", {}).get("dependencies", [])
        if isinstance(value, dict)
    ]
    contracts = [
        value
        for value in analysis.get("context", {}).get("contracts", [])
        if isinstance(value, dict)
    ]
    expected_contributions = {
        "python.repository_discoverer": {
            str(value.get("path", "")) for value in entries if value.get("path")
        },
        "python.ast_parser": {
            str(value.get("path", ""))
            for value in entries
            if value.get("status") == "analyzed" and value.get("path")
        },
        "web.language_boundary_indexer": {
            str(value.get("path", ""))
            for value in entries
            if isinstance(value.get("boundary_facts"), dict) and value.get("path")
        },
        "python.dependency_inventory": {
            "dependency:"
            + str(value.get("source", ""))
            + ":"
            + str(value.get("name", ""))
            for value in dependencies
            if value.get("name")
        },
        "contracts.local_schema": {
            str(value.get("id") or value.get("path") or value.get("source") or "")
            for value in contracts
            if value.get("id") or value.get("path") or value.get("source")
        },
    }
    for item in items:
        finding_id = str(item.get("id", ""))
        for adapter_id in item.get("scanner", {}).get("adapter_ids", []):
            if adapter_id in expected_contributions and finding_id:
                expected_contributions[adapter_id].add(finding_id)
    accounting_checks: list[dict[str, Any]] = []
    for adapter_id, expected in expected_contributions.items():
        run = run_by_id.get(adapter_id, {})
        observed = {
            str(value)
            for value in run.get("contribution_entity_ids", [])
            if isinstance(value, str)
        }
        missing = sorted(expected - observed)
        unexpected = sorted(observed - expected)
        accounting_checks.append(
            {
                "id": f"adapter.{adapter_id}.contributions",
                "status": "pass" if not missing and not unexpected else "error",
                "adapter_id": adapter_id,
                "expected_entities": len(expected),
                "observed_entities": len(observed),
                "missing_entities": missing[:100],
                "missing_entities_omitted": max(0, len(missing) - 100),
                "unexpected_entities": unexpected[:100],
                "unexpected_entities_omitted": max(0, len(unexpected) - 100),
                "message": (
                    "Observed adapter contributions cover the governed source projection."
                    if not missing and not unexpected
                    else "The adapter ledger differs from the governed entity projection."
                ),
            }
        )

    validation = validate_analysis(analysis)
    validation_rules = Counter(
        str(value.get("rule_id", ""))
        for value in validation.get("findings", [])
        if isinstance(value, dict)
    )
    priorities = Counter(
        str(value.get("scanner", {}).get("screening_priority", "unrated"))
        for value in items
    )
    families = {
        (
            str(value.get("component_id", "")),
            str(value.get("scanner", {}).get("failure_class", "unclassified")),
        )
        for value in items
    }
    unreviewed = sum(
        value.get("review", {}).get("disposition", "unreviewed") == "unreviewed"
        for value in items
    )
    with_tests = sum(bool(value.get("test_references")) for value in code_components)
    with_coverage = sum(
        isinstance(value.get("coverage"), dict) for value in code_components
    )
    with_mapping = sum(
        bool(
            value.get("mapping_context")
            or value.get("subsystems")
            or value.get("requirement_ids")
            or value.get("interface_ids")
        )
        for value in code_components
    )
    runtime_imports = len(analysis.get("runtime_evidence", {}).get("imports", []))
    external_call_candidates = sum(
        len(value.get("external_call_candidates", []))
        for value in code_components
        if isinstance(value.get("external_call_candidates", []), list)
    )
    circuit_breaker_controls = sum(
        control.get("kind") == "circuit_breaker"
        for value in code_components
        for control in value.get("detected_controls", [])
        if isinstance(control, dict)
    )
    assurance = analysis.get("assurance", {}).get("summary", {})
    interface_reconciliation = analysis.get("interface_reconciliation", {})
    interface_summary = (
        interface_reconciliation.get("summary", {})
        if isinstance(interface_reconciliation, dict)
        else {}
    )
    guidance = guidance_traceability(analysis)
    guidance_coverage = guidance.get("coverage", {})
    path_hotspots = Counter(
        str(value.get("source", {}).get("path", "")) for value in items
    )
    component_hotspots = Counter(
        str(value.get("component", {}).get("qualname", "")) for value in items
    )
    module_initialization = sum(
        value.get("component", {}).get("qualname") == "<module initialization>"
        for value in items
    )
    actions: list[dict[str, str]] = []

    def action(action_id: str, priority: str, reason: str, command: str) -> None:
        actions.append(
            {
                "id": action_id,
                "priority": priority,
                "reason": reason,
                "command": command,
            }
        )

    accounting_errors = sum(
        value["status"] == "error" for value in accounting_checks
    )
    if accounting_errors:
        action(
            "repair_adapter_accounting",
            "P0",
            f"{accounting_errors} adapter contribution projection(s) are inconsistent.",
            "rescan with the current PySFMEA version before relying on provenance",
        )
    system_context = analysis.get("system_context", {})
    if system_context.get("status") != "complete":
        action(
            "govern_system_context",
            "P0",
            "System context is incomplete and limits effect and hazard interpretation.",
            "sfmea doctor REPOSITORY",
        )
    if unreviewed:
        action(
            "triage_review_families",
            "P0",
            f"{unreviewed} findings remain unreviewed across {len(families)} families.",
            "sfmea queue ANALYSIS --limit 1000",
        )
    if not with_coverage:
        action(
            "import_coverage",
            "P1",
            "No component has coverage.py evidence.",
            "sfmea scan REPOSITORY --coverage-json coverage.json",
        )
    if not with_tests:
        action(
            "index_test_sources",
            "P1",
            "No eligible Python component has a textual reference from indexed test sources.",
            "review scan exclusions and retain test directories as evidence even when tests are not analyzed as components",
        )
    if not runtime_imports:
        action(
            "import_runtime_trace",
            "P1",
            "No runtime trace is available to corroborate static relationships or timing.",
            "sfmea trace-import ANALYSIS runtime-trace.json",
        )
    if with_mapping < len(code_components):
        action(
            "map_architecture",
            "P1",
            f"{len(code_components) - with_mapping} eligible Python components lack a subsystem, requirement, hazard, or interface mapping.",
            "complete component_mappings and system_interfaces in sfmea.toml",
        )
    if interface_summary.get("unmatched_client_endpoints"):
        action(
            "review_cross_stack_interfaces",
            "P1",
            f"{interface_summary['unmatched_client_endpoints']} web-client endpoint candidates have no exact Python route match.",
            "review interface_reconciliation in the analysis or HTML report",
        )
    if assurance.get("planning_gaps"):
        action(
            "resolve_assurance_planning",
            "P1",
            f"{assurance.get('planning_gaps')} obligations require effect/control definition.",
            "sfmea assurance-work ANALYSIS",
        )
    if guidance_coverage.get("direct_finding_coverage_percent", 100.0) < 100:
        action(
            "review_guidance_specificity",
            "P2",
            "Some findings have only supporting or contextual guidance mappings.",
            "sfmea citations ANALYSIS --format json",
        )

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    actions.sort(key=lambda value: (priority_order.get(value["priority"], 9), value["id"]))
    return {
        "format": DIAGNOSTICS_FORMAT,
        "status": (
            "invalid_accounting"
            if accounting_errors
            else "action_required"
            if actions
            else "ready"
        ),
        "accounting": {
            "valid": not accounting_errors,
            "checks": accounting_checks,
            "adapter_statuses": dict(
                sorted(
                    Counter(
                        str(value.get("status", "unknown"))
                        for value in run_by_id.values()
                    ).items()
                )
            ),
        },
        "coverage": summary.get("coverage_dimensions", {}),
        "workload": {
            "components": len(components),
            "active_findings": len(items),
            "review_families": len(families),
            "family_reduction_percent": _percent(len(items) - len(families), len(items)),
            "unreviewed": unreviewed,
            "priorities": dict(sorted(priorities.items())),
            "module_initialization_findings": module_initialization,
            "top_paths": _top(path_hotspots),
            "top_components": _top(component_hotspots),
        },
        "evidence": {
            "eligible_python_components": len(code_components),
            "components_with_test_references": with_tests,
            "test_reference_coverage_percent": _percent(
                with_tests, len(code_components)
            ),
            "components_with_coverage": with_coverage,
            "coverage_evidence_percent": _percent(
                with_coverage, len(code_components)
            ),
            "runtime_imports": runtime_imports,
            "external_call_candidates": external_call_candidates,
            "circuit_breaker_controls": circuit_breaker_controls,
            "components_with_governed_mappings": with_mapping,
            "mapping_coverage_percent": _percent(with_mapping, len(code_components)),
            "assurance": assurance,
        },
        "interfaces": interface_reconciliation,
        "guidance": {
            "finding_coverage_percent": guidance_coverage.get(
                "finding_coverage_percent", 0.0
            ),
            "direct_finding_coverage_percent": guidance_coverage.get(
                "direct_finding_coverage_percent", 0.0
            ),
            "rules_without_direct_mapping": guidance_coverage.get(
                "rules_without_direct_mapping", []
            ),
            "broadly_reused_citations": guidance_coverage.get(
                "broadly_reused_citations", {}
            ),
        },
        "validation": {
            "counts": validation.get("counts", {}),
            "top_rules": _top(validation_rules),
        },
        "performance": analysis.get("project", {}).get("settings", {}).get(
            "scan_telemetry", {}
        ),
        "recommended_actions": actions,
        "notice": (
            "Diagnostics prioritize tool accounting, review workload, and missing evidence. "
            "They do not establish hazard completeness, regulatory applicability, or approval."
        ),
    }
