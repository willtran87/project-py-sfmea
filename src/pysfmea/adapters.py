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
    AdapterDescriptor("python.call_graph", "graph_provider", "1", ("static_calls", "transitive_upstream_impact", "ordered_calls"), "python-ast-facts-1", "static-call-graph-1", "heuristic"),
    AdapterDescriptor("python.dependency_inventory", "analyzer", "1", ("declared_dependencies", "manifest_hashes", "included_requirements"), "repository-inventory-1", "dependency-inventory-1", "deterministic"),
    AdapterDescriptor("contracts.local_schema", "analyzer", "1", ("openapi", "swagger", "json_schema", "protobuf"), "repository-inventory-1", "interface-contract-inventory-1", "deterministic"),
    AdapterDescriptor("coverage.py_json", "evidence_provider", "1", ("line_coverage", "branch_coverage", "function_mapping"), "coveragepy-json", "coverage-evidence-1", "observed"),
    AdapterDescriptor("runtime.json_trace", "evidence_provider", "1", ("simple_spans", "opentelemetry_spans", "observed_edges"), "runtime-trace-json-1", "runtime-evidence-1", "observed"),
    AdapterDescriptor("guidance.curated_registry", "guideline_pack", "1", ("versioned_sources", "exact_locators", "typed_rule_mappings"), "guidance-pack-1", "guidance-traceability-1", "human_supplied"),
    AdapterDescriptor("assurance.deterministic_planner", "planner", "1", ("verification_obligations", "stimuli", "oracles", "acceptance_criteria"), "sfmea-analysis-0.5", "assurance-register-1", "deterministic"),
    AdapterDescriptor("assurance.container_runner", "execution_provider", "1", ("docker", "podman", "bounded_capture", "artifact_hashing"), "assurance-obligation-1", "execution-evidence-1", "observed", isolation="approved_disposable_container", deterministic=False),
    AdapterDescriptor("hazard.sfta", "analyzer", "1", ("fault_tree_validation", "sfmea_correlation", "coverage_gaps"), "fault-tree-config-1", "sfta-1", "deterministic"),
    AdapterDescriptor("diagram.inline_svg", "diagram_renderer", "1", ("directed_graph", "flow", "sequence", "traceability", "cause_effect", "state"), "pysfmea-diagram-1", "self-contained-svg", "deterministic"),
    AdapterDescriptor("export.sarif", "exporter", "1", ("sarif_2_1_0",), "sfmea-analysis-0.5", "sarif-2.1.0", "deterministic"),
    AdapterDescriptor("export.cyclonedx", "exporter", "1", ("cyclonedx_1_6", "declared_inventory"), "dependency-inventory-1", "cyclonedx-1.6", "deterministic"),
    AdapterDescriptor("llm.openai_compatible", "llm_provider", "1", ("grounded_discovery", "grounded_summary", "schema_constrained_output"), "evidence-packet-2", "model-suggestion-2", "model_generated", lifecycle="optional", isolation="remote_explicit_opt_in", deterministic=False),
)


def adapter_registry_snapshot(analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a versioned health/capability snapshot for the resolved run."""

    analysis = analysis or {}
    coverage_available = bool(analysis.get("project", {}).get("settings", {}).get("coverage_json"))
    runtime_available = bool(analysis.get("runtime_evidence", {}).get("imports"))
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
