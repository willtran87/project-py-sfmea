"""Typed capability registry for deterministic analyzers, providers, and exporters."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

AdapterCategory = Literal[
    "discoverer",
    "parser",
    "analyzer",
    "graph_provider",
    "evidence_provider",
    "guideline_pack",
    "planner",
    "execution_provider",
    "diagram_renderer",
    "exporter",
    "llm_provider",
]
TrustLevel = Literal["deterministic", "heuristic", "observed", "human_supplied", "model_generated"]


@dataclass(frozen=True)
class AdapterDescriptor:
    id: str
    category: AdapterCategory
    version: str
    capabilities: tuple[str, ...]
    input_schema: str
    output_schema: str
    trust_level: TrustLevel
    lifecycle: str = "stable"
    isolation: str = "in_process_no_repository_execution"
    deterministic: bool = True


BUILTIN_ADAPTERS = (
    AdapterDescriptor("python.repository_discoverer", "discoverer", "1", ("python_source", "test_inventory", "bounded_walk", "symlink_rejection"), "repository-path-1", "repository-inventory-1", "deterministic"),
    AdapterDescriptor("python.ast_parser", "parser", "1", ("functions", "methods", "classes", "lambdas", "module_initialization"), "python-source-1", "python-ast-facts-1", "deterministic"),
    AdapterDescriptor("python.failure_rule_analyzer", "analyzer", "2", ("guideword_screening", "failure_taxonomy", "source_localization"), "python-ast-facts-1", "sfmea-candidates-1", "heuristic"),
    AdapterDescriptor("human.manual_finding", "analyzer", "1", ("reviewer_authored_failure_mode", "human_provenance"), "reviewer-input-1", "sfmea-candidates-1", "human_supplied"),
    AdapterDescriptor("python.control_flow_analyzer", "analyzer", "1", ("branching", "ordering", "state_transition_signals"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.data_flow_signals", "analyzer", "1", ("input_boundaries", "serialization", "persistence", "calculation_signals"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.interface_analyzer", "analyzer", "1", ("external_calls", "internal_contracts", "storage_interfaces", "hardware_interfaces"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.concurrency_analyzer", "analyzer", "1", ("async_operations", "task_creation", "timing_and_ordering"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.resilience_control_analyzer", "analyzer", "1", ("circuit_breaker_roles", "state_machine", "trip_threshold", "cooldown_clock", "isolation_key", "fallback_contract"), "python-ast-facts-1", "detected-resilience-control-1", "heuristic"),
    AdapterDescriptor("repository.configuration_analyzer", "analyzer", "1", ("environment_access", "configuration_failure", "runtime_compatibility"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.security_boundary_analyzer", "analyzer", "1", ("subprocess_boundaries", "masked_failures", "untrusted_input_signals"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.complexity_analyzer", "analyzer", "1", ("complexity", "loops", "resource_exhaustion_signals"), "python-ast-facts-1", "normalized-finding-contributions-1", "heuristic"),
    AdapterDescriptor("python.call_graph", "graph_provider", "1", ("static_calls", "transitive_upstream_impact", "ordered_calls"), "python-ast-facts-1", "static-call-graph-1", "heuristic"),
    AdapterDescriptor("python.dependency_inventory", "analyzer", "1", ("declared_dependencies", "manifest_hashes", "included_requirements"), "repository-inventory-1", "dependency-inventory-1", "deterministic"),
    AdapterDescriptor("contracts.local_schema", "analyzer", "1", ("openapi", "swagger", "json_schema", "protobuf"), "repository-inventory-1", "interface-contract-inventory-1", "deterministic"),
    AdapterDescriptor("coverage.py_json", "evidence_provider", "1", ("line_coverage", "branch_coverage", "function_mapping"), "coveragepy-json", "coverage-evidence-1", "observed"),
    AdapterDescriptor("runtime.json_trace", "evidence_provider", "1", ("simple_spans", "opentelemetry_spans", "observed_edges"), "runtime-trace-json-1", "runtime-evidence-1", "observed"),
    AdapterDescriptor("guidance.curated_registry", "guideline_pack", "1", ("versioned_sources", "exact_locators", "typed_rule_mappings"), "guidance-pack-1", "guidance-traceability-1", "human_supplied"),
    AdapterDescriptor("assurance.deterministic_planner", "planner", "1", ("verification_obligations", "stimuli", "oracles", "acceptance_criteria"), "sfmea-analysis-0.6", "assurance-register-1", "deterministic"),
    AdapterDescriptor("assurance.container_runner", "execution_provider", "1", ("docker", "podman", "bounded_capture", "artifact_hashing"), "assurance-obligation-1", "execution-evidence-1", "observed", isolation="approved_disposable_container", deterministic=False),
    AdapterDescriptor("hazard.sfta", "analyzer", "1", ("fault_tree_validation", "sfmea_correlation", "coverage_gaps"), "fault-tree-config-1", "sfta-1", "deterministic"),
    AdapterDescriptor("diagram.inline_svg", "diagram_renderer", "1", ("directed_graph", "flow", "sequence", "traceability", "cause_effect", "state"), "pysfmea-diagram-1", "self-contained-svg", "deterministic"),
    AdapterDescriptor("export.sarif", "exporter", "1", ("sarif_2_1_0",), "sfmea-analysis-0.6", "sarif-2.1.0", "deterministic"),
    AdapterDescriptor("export.cyclonedx", "exporter", "1", ("cyclonedx_1_6", "declared_inventory"), "dependency-inventory-1", "cyclonedx-1.6", "deterministic"),
    AdapterDescriptor("llm.openai_compatible", "llm_provider", "1", ("grounded_discovery", "grounded_summary", "schema_constrained_output"), "evidence-packet-2", "model-suggestion-2", "model_generated", lifecycle="optional", isolation="remote_explicit_opt_in", deterministic=False),
)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _contribution_adapters(item: dict[str, Any]) -> list[str]:
    scanner = item.get("scanner", {})
    rule_id = str(scanner.get("rule_id", ""))
    failure_class = str(scanner.get("failure_class", ""))
    if rule_id == "manual":
        return ["human.manual_finding"]
    adapters = {"python.failure_rule_analyzer"}
    if failure_class in {"data", "calculation"} or rule_id.startswith(("data.", "storage.")):
        adapters.add("python.data_flow_signals")
    if failure_class in {"interface", "hardware"} or rule_id.startswith(
        ("interface.", "hardware.")
    ):
        adapters.add("python.interface_analyzer")
    if failure_class == "timing" or rule_id.startswith("timing."):
        adapters.add("python.concurrency_analyzer")
    if failure_class in {"logic", "functional"} or rule_id.startswith(
        ("logic.", "state.", "functional.")
    ):
        adapters.add("python.control_flow_analyzer")
    if failure_class == "environment" or rule_id.startswith(
        ("configuration.", "environment.")
    ):
        adapters.add("repository.configuration_analyzer")
    if failure_class == "detection" or rule_id.startswith(
        ("detection.", "process.")
    ):
        adapters.add("python.security_boundary_analyzer")
    if failure_class == "resource" or rule_id.startswith("resource."):
        adapters.add("python.complexity_analyzer")
    if rule_id == "environment.dependency_drift":
        adapters.add("python.dependency_inventory")
    if rule_id == "interface.contract_compatibility":
        adapters.add("contracts.local_schema")
    if failure_class == "common_cause":
        adapters.add("hazard.sfta")
    if rule_id.startswith("resilience.circuit_breaker_"):
        adapters.add("python.resilience_control_analyzer")
    return sorted(adapters)


def annotate_adapter_contributions(analysis: dict[str, Any]) -> None:
    """Attach stable, many-to-one analyzer provenance to normalized findings."""

    for item in analysis.get("items", []):
        scanner = item.setdefault("scanner", {})
        adapters = _contribution_adapters(item)
        scanner["adapter_id"] = "python.failure_rule_analyzer"
        scanner["adapter_ids"] = adapters


def build_adapter_run_ledger(analysis: dict[str, Any]) -> dict[str, Any]:
    """Record which adapters ran and the exact normalized entities they contributed."""

    annotate_adapter_contributions(analysis)
    contributions: dict[str, list[str]] = {}
    for item in analysis.get("items", []):
        for adapter_id in item.get("scanner", {}).get("adapter_ids", []):
            contributions.setdefault(adapter_id, []).append(str(item.get("id", "")))
    inventory = analysis.get("repository_inventory", {})
    parsed_count = inventory.get("summary", {}).get("by_status", {}).get("analyzed", 0)
    static_runs = {
        "python.repository_discoverer": [
            value.get("path", "") for value in inventory.get("entries", [])
        ],
        "python.ast_parser": [
            value.get("path", "")
            for value in inventory.get("entries", [])
            if value.get("status") == "analyzed"
        ],
        "python.call_graph": [
            value.get("id", "")
            for value in analysis.get("components", [])
            if value.get("calls") or value.get("called_by")
        ],
        "guidance.curated_registry": [
            value.get("id", "") for value in analysis.get("guidance", {}).get("citations", [])
        ],
        "assurance.deterministic_planner": [
            value.get("id", "")
            for value in analysis.get("assurance", {}).get("obligations", [])
        ],
        "hazard.sfta": [
            value.get("id", "") for value in analysis.get("sfta", {}).get("trees", [])
        ],
    }
    for adapter_id, entity_ids in static_runs.items():
        contributions.setdefault(adapter_id, []).extend(str(value) for value in entity_ids if value)
    coverage_configured = bool(
        analysis.get("project", {}).get("settings", {}).get("coverage_json")
    )
    runtime_imported = bool(analysis.get("runtime_evidence", {}).get("imports"))
    runs = []
    input_digest = _digest(
        {
            "baseline": analysis.get("project", {}).get("baseline", {}).get("id", ""),
            "inventory": inventory.get("inventory_sha256", ""),
        }
    )
    for descriptor in BUILTIN_ADAPTERS:
        entity_ids = sorted(set(contributions.get(descriptor.id, [])))
        status = "completed"
        reason = "Adapter completed and its normalized contribution set is recorded."
        if descriptor.id == "coverage.py_json" and not coverage_configured:
            status, reason = "not_configured", "No coverage.py JSON input was supplied."
        elif descriptor.id == "runtime.json_trace" and not runtime_imported:
            status, reason = "not_configured", "No runtime trace was imported."
        elif descriptor.category in {"execution_provider", "diagram_renderer", "exporter", "llm_provider"}:
            status, reason = "not_invoked", "Capability is available but is not part of the deterministic scan stage."
        elif descriptor.id == "python.ast_parser" and not parsed_count:
            status, reason = "completed_no_results", "No selected Python source was successfully parsed."
        elif not entity_ids and descriptor.id not in {
            "python.failure_rule_analyzer",
            "python.repository_discoverer",
            "python.ast_parser",
            "guidance.curated_registry",
            "assurance.deterministic_planner",
            "hazard.sfta",
        }:
            status, reason = "completed_no_results", "Adapter ran but produced no normalized contribution for this repository."
        output_material = {
            "adapter_id": descriptor.id,
            "entity_ids": entity_ids,
            "status": status,
        }
        runs.append(
            {
                "schema_version": "pysfmea-adapter-run-1",
                "adapter_id": descriptor.id,
                "adapter_version": descriptor.version,
                "status": status,
                "reason": reason,
                "input_sha256": input_digest,
                "output_sha256": _digest(output_material),
                "contribution_count": len(entity_ids),
                "contribution_entity_ids": entity_ids,
                "trust_level": descriptor.trust_level,
                "deterministic": descriptor.deterministic,
                "isolation": descriptor.isolation,
                "diagnostics": [],
            }
        )
    material = {"runs": runs}
    return {
        "schema_version": "pysfmea-adapter-run-ledger-1",
        **material,
        "ledger_sha256": _digest(material),
        "summary": {
            "total": len(runs),
            "completed": sum(value["status"] == "completed" for value in runs),
            "completed_no_results": sum(
                value["status"] == "completed_no_results" for value in runs
            ),
            "not_configured": sum(value["status"] == "not_configured" for value in runs),
            "not_invoked": sum(value["status"] == "not_invoked" for value in runs),
            "finding_contributors": len(
                {
                    adapter_id
                    for item in analysis.get("items", [])
                    for adapter_id in item.get("scanner", {}).get("adapter_ids", [])
                }
            ),
        },
    }


def adapter_registry_snapshot(analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a versioned health/capability snapshot for the resolved run."""

    analysis = analysis or {}
    coverage_available = bool(analysis.get("project", {}).get("settings", {}).get("coverage_json"))
    runtime_available = bool(analysis.get("runtime_evidence", {}).get("imports"))
    run_by_id = {
        value.get("adapter_id"): value
        for value in analysis.get("adapter_runs", {}).get("runs", [])
    }
    records = []
    for descriptor in BUILTIN_ADAPTERS:
        record = asdict(descriptor)
        record["capabilities"] = list(descriptor.capabilities)
        health = "available"
        reason = "Built-in capability available."
        if descriptor.id == "coverage.py_json" and not coverage_available:
            health, reason = "not_configured", "No coverage.py JSON input was supplied."
        elif descriptor.id == "runtime.json_trace" and not runtime_available:
            health, reason = "not_configured", "No runtime trace was imported."
        elif descriptor.id == "llm.openai_compatible":
            health, reason = "not_invoked", "Model use requires an explicit provider call."
        run = run_by_id.get(descriptor.id)
        if run:
            run_status = str(run.get("status", "unknown"))
            health = "available" if run_status.startswith("completed") else run_status
            reason = str(run.get("reason", reason))
            record["last_run"] = {
                "status": run_status,
                "contribution_count": run.get("contribution_count", 0),
                "input_sha256": run.get("input_sha256", ""),
                "output_sha256": run.get("output_sha256", ""),
            }
        record["health"] = {"status": health, "reason": reason}
        records.append(record)
    material = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema_version": "pysfmea-adapter-registry-1",
        "adapters": records,
        "registry_sha256": hashlib.sha256(material).hexdigest(),
        "summary": {
            "total": len(records),
            "available": sum(value["health"]["status"] == "available" for value in records),
            "not_configured": sum(value["health"]["status"] == "not_configured" for value in records),
            "not_invoked": sum(value["health"]["status"] == "not_invoked" for value in records),
            "deterministic": sum(value["deterministic"] for value in records),
        },
    }
