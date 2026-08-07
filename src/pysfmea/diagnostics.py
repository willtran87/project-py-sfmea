"""Actionable, machine-readable diagnostics for a completed SFMEA analysis."""

from __future__ import annotations

from collections import Counter
from math import ceil
from typing import Any

from .guidance import guidance_traceability
from .repository_inventory import derive_repository_inventory_summary
from .validation import validate_analysis

DIAGNOSTICS_FORMAT = "pysfmea-analysis-diagnostics-1"


def _percent(numerator: int, denominator: int) -> float:
    return round(100 * numerator / denominator, 1) if denominator else 100.0


def _top(counter: Counter[str], limit: int = 15) -> list[dict[str, Any]]:
    return [
        {"value": value, "count": count} for value, count in counter.most_common(limit)
    ]


def _looks_like_test_glob(value: str) -> bool:
    parts = value.replace("\\", "/").casefold().split("/")
    return any(part in {"test", "tests"} or part.startswith("test") for part in parts)


def _looks_like_web_glob(value: str) -> bool:
    lowered = value.replace("\\", "/").casefold()
    return any(token in lowered for token in ("frontend", "client", "web", "ui"))


def _bounded_int(value: Any, default: int, *, minimum: int = 1) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= minimum
        else default
    )


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


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
    family_counts = Counter(
        (
            str(value.get("component_id", "")),
            str(value.get("scanner", {}).get("failure_class", "unclassified")),
        )
        for value in items
    )
    family_priorities: Counter[str] = Counter()
    family_representatives: dict[tuple[str, str], dict[str, Any]] = {}
    priority_rank = {"high": 0, "medium": 1, "low": 2, "manual": 3}
    for item in items:
        key = (
            str(item.get("component_id", "")),
            str(item.get("scanner", {}).get("failure_class", "unclassified")),
        )
        current = family_representatives.get(key)
        if current is None or priority_rank.get(
            str(item.get("scanner", {}).get("screening_priority", "manual")), 9
        ) < priority_rank.get(
            str(current.get("scanner", {}).get("screening_priority", "manual")), 9
        ):
            family_representatives[key] = item
    family_priorities.update(
        str(value.get("scanner", {}).get("screening_priority", "manual"))
        for value in family_representatives.values()
    )
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
    accounting_errors = sum(value["status"] == "error" for value in accounting_checks)
    settings = analysis.get("project", {}).get("settings", {})
    test_evidence_analysis = settings.get("test_evidence_analysis", {})
    if not isinstance(test_evidence_analysis, dict):
        test_evidence_analysis = {}
    exclude_patterns = [
        value for value in settings.get("exclude", []) if isinstance(value, str)
    ]
    test_evidence_includes = [
        value
        for value in settings.get("test_evidence_include", [])
        if isinstance(value, str)
    ]
    boundary_evidence_includes = [
        value
        for value in settings.get("boundary_evidence_include", [])
        if isinstance(value, str)
    ]
    excluded_test_globs = [
        value for value in exclude_patterns if _looks_like_test_glob(value)
    ]
    excluded_web_globs = [
        value for value in exclude_patterns if _looks_like_web_glob(value)
    ]
    evidence_scope_conflicts: list[dict[str, Any]] = []
    if excluded_test_globs and not test_evidence_includes and not with_tests:
        evidence_scope_conflicts.append(
            {
                "kind": "test_evidence_hidden_by_semantic_exclusion",
                "excluded_patterns": excluded_test_globs,
                "suggested_config": {"scan.test_evidence_include": excluded_test_globs},
                "notice": "The suggestion must be reviewed; it does not include tests as analyzed components.",
            }
        )
    if (
        excluded_web_globs
        and not boundary_evidence_includes
        and not interface_summary.get("client_endpoint_candidates")
    ):
        evidence_scope_conflicts.append(
            {
                "kind": "web_boundary_hidden_by_semantic_exclusion",
                "excluded_patterns": excluded_web_globs,
                "suggested_config": {
                    "scan.boundary_evidence_include": excluded_web_globs
                },
                "notice": "The suggestion enables bounded JS/TS boundary indexing only.",
            }
        )
    warning_budget = _bounded_int(settings.get("diagnostic_warning_budget"), 25_000)
    per_rule_budget = _bounded_int(settings.get("diagnostic_per_rule_budget"), 10_000)
    validation_counts = validation.get("counts", {})
    warning_total = _bounded_int(validation_counts.get("warning"), 0, minimum=0)
    over_budget_rules = {
        rule_id: count
        for rule_id, count in validation_rules.items()
        if count > per_rule_budget
    }
    findings_by_rule: dict[str, list[dict[str, Any]]] = {}
    for finding in validation.get("findings", []):
        if isinstance(finding, dict):
            findings_by_rule.setdefault(str(finding.get("rule_id", "")), []).append(
                finding
            )
    validation_aggregates: list[dict[str, Any]] = []
    for rule_id, count in validation_rules.most_common():
        matching = findings_by_rule.get(rule_id, [])
        affected_items = {
            str(value.get("item_id", "")) for value in matching if value.get("item_id")
        }
        validation_aggregates.append(
            {
                "rule_id": rule_id,
                "count": count,
                "levels": dict(
                    sorted(
                        Counter(
                            str(value.get("level", "unknown")) for value in matching
                        ).items()
                    )
                ),
                "affected_items": len(affected_items),
                "sample_item_ids": sorted(affected_items)[:10],
                "sample_item_ids_omitted": max(0, len(affected_items) - 10),
                "over_budget": count > per_rule_budget,
            }
        )
    queue_limit = _bounded_int(settings.get("review_queue_max_total"), 1_000)
    queue_batches = ceil(len(families) / queue_limit) if families else 0
    priority_starvation_risk = bool(
        family_priorities.get("high", 0) >= queue_limit
        and (family_priorities.get("medium", 0) or family_priorities.get("low", 0))
    )
    family_samples = []
    for key, count in family_counts.most_common(25):
        representative = family_representatives[key]
        family_samples.append(
            {
                "component_id": key[0],
                "failure_class": key[1],
                "size": count,
                "representative_finding_id": representative.get("id", ""),
                "priority": representative.get("scanner", {}).get(
                    "screening_priority", "manual"
                ),
                "path": representative.get("source", {}).get("path", ""),
            }
        )
    semantic_percent = float(
        summary.get("coverage_dimensions", {})
        .get("python_semantic", {})
        .get("percent", 0.0)
        or 0.0
    )
    mapping_percent = _percent(with_mapping, len(code_components))
    test_percent = _percent(with_tests, len(code_components))
    coverage_percent = _percent(with_coverage, len(code_components))
    guidance_percent = float(
        guidance_coverage.get("direct_finding_coverage_percent", 0.0) or 0.0
    )
    interface_score = 100.0
    if interface_summary.get("server_routes"):
        interface_score = _percent(
            int(interface_summary.get("matched_server_routes", 0)),
            int(interface_summary.get("server_routes", 0)),
        )
    evidence_score = round(
        (test_percent + coverage_percent + (100.0 if runtime_imports else 0.0)) / 3,
        1,
    )
    scalability_score = 100.0
    if warning_total > warning_budget:
        scalability_score -= 30
    if over_budget_rules:
        scalability_score -= 30
    if priority_starvation_risk:
        scalability_score -= 20
    if summary.get("truncated"):
        scalability_score -= 20
    qualification_domains: list[tuple[str, float, str]] = [
        (
            "bounded_static_discovery",
            semantic_percent,
            "Python semantic inventory coverage",
        ),
        (
            "architecture_traceability",
            mapping_percent,
            "Governed component mapping coverage",
        ),
        (
            "corroborating_evidence",
            evidence_score,
            "Test, coverage, and runtime evidence coverage",
        ),
        (
            "cross_stack_interfaces",
            interface_score,
            "Static server-route reconciliation coverage",
        ),
        (
            "guidance_specificity",
            guidance_percent,
            "Direct finding-to-guidance mapping coverage",
        ),
        (
            "provenance_accounting",
            100.0 if not accounting_errors else 0.0,
            "Adapter contribution accounting",
        ),
        (
            "review_scalability",
            max(0.0, scalability_score),
            "Configured diagnostic and queue budgets",
        ),
    ]
    qualification = {
        "authority": "diagnostic_readiness_score_not_tool_qualification_or_regulatory_approval",
        "overall_score": round(
            sum(value[1] for value in qualification_domains)
            / len(qualification_domains),
            1,
        ),
        "domains": [
            {
                "id": domain_id,
                "score": round(score, 1),
                "grade": _grade(score),
                "basis": basis,
                "status": "strong"
                if score >= 90
                else "attention"
                if score >= 70
                else "gap",
            }
            for domain_id, score, basis in qualification_domains
        ],
    }
    qualification["overall_grade"] = _grade(
        float(qualification["overall_score"])
    )
    telemetry = settings.get("scan_telemetry", {})
    phase_seconds = (
        telemetry.get("phases_seconds", {}) if isinstance(telemetry, dict) else {}
    )
    slowest_phase_values = sorted(
        (
            (str(phase), float(seconds))
            for phase, seconds in phase_seconds.items()
            if isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
        ),
        key=lambda value: value[1],
        reverse=True,
    )[:5]
    slowest_phases = [
        {"phase": phase, "seconds": seconds} for phase, seconds in slowest_phase_values
    ]
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
    if warning_total > warning_budget or over_budget_rules:
        action(
            "reduce_diagnostic_repetition",
            "P0",
            f"Validation produced {warning_total} warnings; {len(over_budget_rules)} rule families exceed the configured per-rule budget.",
            "triage validation.aggregates and govern repetitive families before item-level review",
        )
    if priority_starvation_risk:
        action(
            "reserve_cross_priority_sampling",
            "P0",
            "High-priority families can consume the entire configured queue projection.",
            "run separate sfmea queue projections for --minimum-priority high, medium, and low",
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
    if evidence_scope_conflicts:
        action(
            "resolve_evidence_scope_conflicts",
            "P1",
            f"{len(evidence_scope_conflicts)} semantic exclusion(s) likely hide bounded corroborating evidence.",
            "review evidence_scope.conflicts and add only approved evidence include globs to sfmea.toml",
        )
    if not runtime_imports:
        action(
            "import_runtime_trace",
            "P1",
            "No runtime trace is available to corroborate static relationships or timing.",
            "sfmea trace-import ANALYSIS runtime-trace.json",
        )
    if with_tests and not test_evidence_analysis.get("dimensions", {}).get(
        "fault_injection_or_resilience", {}
    ).get("files", 0):
        action(
            "strengthen_failure_path_tests",
            "P2",
            "Indexed tests contain no static fault-injection or resilience-test signal.",
            "implement assurance obligations with injected dependency, timing, overload, and recovery failures",
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
    actions.sort(
        key=lambda value: (priority_order.get(value["priority"], 9), value["id"])
    )
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
            "family_reduction_percent": _percent(
                len(items) - len(families), len(items)
            ),
            "unreviewed": unreviewed,
            "priorities": dict(sorted(priorities.items())),
            "family_priorities": dict(sorted(family_priorities.items())),
            "findings_per_component": round(len(items) / len(components), 2)
            if components
            else 0.0,
            "findings_per_family": round(len(items) / len(families), 2)
            if families
            else 0.0,
            "queue_projection": {
                "configured_limit": queue_limit,
                "estimated_family_batches": queue_batches,
                "priority_starvation_risk": priority_starvation_risk,
                "recommended_reserved_slots": {
                    "high": max(1, round(queue_limit * 0.8)),
                    "medium": max(1, round(queue_limit * 0.15)),
                    "low": max(1, round(queue_limit * 0.05)),
                },
            },
            "largest_families": family_samples,
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
            "static_test_evidence_analysis": test_evidence_analysis,
            "components_with_coverage": with_coverage,
            "coverage_evidence_percent": _percent(with_coverage, len(code_components)),
            "runtime_imports": runtime_imports,
            "external_call_candidates": external_call_candidates,
            "circuit_breaker_controls": circuit_breaker_controls,
            "components_with_governed_mappings": with_mapping,
            "mapping_coverage_percent": _percent(with_mapping, len(code_components)),
            "assurance": assurance,
        },
        "evidence_scope": {
            "semantic_exclusions": exclude_patterns,
            "test_evidence_includes": test_evidence_includes,
            "boundary_evidence_includes": boundary_evidence_includes,
            "conflicts": evidence_scope_conflicts,
            "authority": "configuration_diagnostic_not_automatic_scope_expansion",
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
            "counts": validation_counts,
            "top_rules": _top(validation_rules),
            "aggregates": validation_aggregates,
            "budgets": {
                "warning_limit": warning_budget,
                "per_rule_limit": per_rule_budget,
                "warning_limit_exceeded": warning_total > warning_budget,
                "over_budget_rules": dict(sorted(over_budget_rules.items())),
            },
        },
        "qualification": qualification,
        "performance": {
            "telemetry": telemetry,
            "slowest_phases": slowest_phases,
            "scale_profile": {
                "repository_files": summary.get("files", 0),
                "python_components": len(code_components),
                "active_findings": len(items),
                "validation_findings": sum(
                    value
                    for value in validation_counts.values()
                    if isinstance(value, int)
                ),
                "inventory_truncated": bool(inventory.get("truncated")),
                "review_batches": queue_batches,
            },
            "ratchet_baseline": {
                "total_seconds": telemetry.get("total_seconds")
                if isinstance(telemetry, dict)
                else None,
                "notice": "Store this projection with representative-repository CI results and fail only against an approved tolerance.",
            },
        },
        "recommended_actions": actions,
        "notice": (
            "Diagnostics prioritize tool accounting, review workload, and missing evidence. "
            "They do not establish hazard completeness, regulatory applicability, or approval."
        ),
    }
