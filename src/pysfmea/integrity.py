"""Canonical hashing primitives shared by governed PySFMEA artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .model import stable_id

MAX_GOVERNED_JSON_DEPTH = 100
MAX_GOVERNED_JSON_NODES = 2_000_000


def canonical_json_sha256(value: Any) -> str:
    """Hash JSON-compatible data using the project's canonical UTF-8 encoding."""

    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def verify_run_manifest_integrity(analysis: dict[str, Any]) -> dict[str, Any]:
    """Verify the scan manifest digest and its reproducibility bindings."""

    checks: dict[str, bool] = {}
    failures: list[dict[str, str]] = []

    def check(name: str, passed: bool, message: str) -> None:
        checks[name] = passed
        if not passed:
            failures.append(
                {
                    "code": f"run_manifest.{name}",
                    "message": message,
                    "field": "run_manifest",
                }
            )

    manifest = analysis.get("run_manifest")
    shape_valid = (
        isinstance(manifest, dict)
        and manifest.get("schema_version") == "pysfmea-run-manifest-1"
    )
    check(
        "shape",
        shape_valid,
        "The run manifest is missing or uses an unsupported structure.",
    )
    if not shape_valid or not isinstance(manifest, dict):
        return {"valid": False, "checks": checks, "failures": failures}

    supplied_digest = manifest.get("manifest_sha256")
    canonical_manifest = dict(manifest)
    canonical_manifest.pop("manifest_sha256", None)
    check(
        "content_integrity",
        isinstance(supplied_digest, str)
        and len(supplied_digest) == 64
        and supplied_digest == canonical_json_sha256(canonical_manifest),
        "The run manifest content does not match its declared SHA-256 digest.",
    )

    resolved_inputs = manifest.get("resolved_inputs")
    inputs_shape_valid = isinstance(resolved_inputs, dict)
    check(
        "resolved_inputs_shape",
        inputs_shape_valid,
        "The run manifest resolved_inputs field must be an object.",
    )
    if inputs_shape_valid and isinstance(resolved_inputs, dict):
        check(
            "resolved_inputs_integrity",
            manifest.get("resolved_inputs_sha256")
            == canonical_json_sha256(resolved_inputs),
            "The resolved input claims do not match their declared SHA-256 digest.",
        )
    else:
        checks["resolved_inputs_integrity"] = False

    project = analysis.get("project", {})
    project = project if isinstance(project, dict) else {}
    baseline = project.get("baseline", {})
    baseline = baseline if isinstance(baseline, dict) else {}
    vcs = baseline.get("vcs", {})
    vcs = vcs if isinstance(vcs, dict) else {}
    context = analysis.get("context", {})
    context = context if isinstance(context, dict) else {}
    guidance = analysis.get("guidance", {})
    guidance = guidance if isinstance(guidance, dict) else {}
    inventory = analysis.get("repository_inventory", {})
    inventory = inventory if isinstance(inventory, dict) else {}
    system_context = analysis.get("system_context", {})
    system_context = system_context if isinstance(system_context, dict) else {}
    adapter_runs = analysis.get("adapter_runs", {})
    adapter_runs = adapter_runs if isinstance(adapter_runs, dict) else {}
    adapters = manifest.get("adapters", {})
    adapters = adapters if isinstance(adapters, dict) else {}

    expected_inputs: dict[str, str] = {
        "source_digest": str(baseline.get("source_digest", "")),
        "configuration_digest": str(baseline.get("config_digest", "")),
        "guidance_catalog_sha256": str(guidance.get("catalog_sha256", "")),
        "adapter_registry_sha256": str(adapters.get("registry_sha256", "")),
        "dependency_inventory_sha256": canonical_json_sha256(
            context.get("dependencies", [])
        ),
        "contract_inventory_sha256": canonical_json_sha256(
            context.get("contracts", [])
        ),
        "repository_inventory_sha256": str(inventory.get("inventory_sha256", "")),
        "system_context_sha256": str(system_context.get("context_sha256", "")),
        "adapter_run_ledger_sha256": str(adapter_runs.get("ledger_sha256", "")),
    }
    for field in ("source_snapshot_sha256", "test_evidence_snapshot_sha256"):
        if baseline.get(field):
            expected_inputs[field] = str(baseline[field])
    settings = project.get("settings", {})
    settings = settings if isinstance(settings, dict) else {}
    coverage_evidence = settings.get("coverage_evidence")
    if isinstance(coverage_evidence, dict) and coverage_evidence.get("sha256"):
        expected_inputs["coverage_json_sha256"] = str(coverage_evidence["sha256"])
    check(
        "resolved_inputs_binding",
        inputs_shape_valid and resolved_inputs == expected_inputs,
        "The run manifest resolved inputs do not match the governed analysis inputs.",
    )

    repository = manifest.get("repository", {})
    repository = repository if isinstance(repository, dict) else {}
    portable = manifest.get("portable_redaction")
    portable_valid = (
        isinstance(portable, dict)
        and portable.get("applied") is True
        and portable.get("fields") == ["repository.root"]
        and isinstance(portable.get("source_manifest_sha256"), str)
        and len(str(portable.get("source_manifest_sha256"))) == 64
    )
    root_matches = repository.get("root") == project.get("root")
    if portable_valid:
        root_matches = root_matches and repository.get("root") == "."
    check(
        "repository_binding",
        root_matches
        and repository.get("baseline_id") == baseline.get("id")
        and repository.get("revision") == vcs.get("revision", "")
        and repository.get("dirty") == vcs.get("dirty"),
        "The run manifest repository identity does not match the governed analysis baseline.",
    )
    created_at = str(manifest.get("created_at", ""))
    check(
        "timestamp_binding",
        bool(created_at) and created_at == str(project.get("scanned_at", "")),
        "The run manifest creation time does not match the persisted scan time.",
    )
    check(
        "identity_binding",
        manifest.get("id") == stable_id("RUN", str(baseline.get("id", "")), created_at),
        "The run manifest ID does not match its baseline and creation time.",
    )
    tool = manifest.get("tool", {})
    tool = tool if isinstance(tool, dict) else {}
    check(
        "schema_binding",
        tool.get("name") == "PySFMEA"
        and tool.get("analysis_schema_version") == analysis.get("schema_version"),
        "The run manifest tool/schema declaration does not match the analysis.",
    )

    active_profiles = guidance.get("active_profiles", [])
    active_profiles = active_profiles if isinstance(active_profiles, list) else []
    profiles = guidance.get("profiles", [])
    profiles = profiles if isinstance(profiles, list) else []
    source_ids = {
        str(source_id)
        for profile in profiles
        if isinstance(profile, dict) and profile.get("id") in active_profiles
        for source_id in (
            profile.get("source_ids", [])
            if isinstance(profile.get("source_ids", []), list)
            else []
        )
        if isinstance(source_id, str)
    }
    expected_guidance_sources = []
    sources = guidance.get("sources", [])
    sources = sources if isinstance(sources, list) else []
    for source in sources:
        if not isinstance(source, dict) or source.get("id") not in source_ids:
            continue
        artifact = source.get("artifact", {})
        artifact = artifact if isinstance(artifact, dict) else {}
        expected_guidance_sources.append(
            {
                "id": source.get("id", ""),
                "version": source.get("version", ""),
                "record_sha256": source.get("record_sha256", ""),
                "artifact_sha256": artifact.get("sha256", ""),
            }
        )
    manifest_guidance = manifest.get("guidance", {})
    manifest_guidance = manifest_guidance if isinstance(manifest_guidance, dict) else {}
    check(
        "guidance_binding",
        manifest_guidance
        == {
            "catalog_version": guidance.get("catalog_version", ""),
            "catalog_sha256": guidance.get("catalog_sha256", ""),
            "active_profiles": active_profiles,
            "selection_sha256": guidance.get("selection_sha256", ""),
            "sources": expected_guidance_sources,
        },
        "The run manifest guidance snapshot does not match the governed guidance catalog.",
    )
    check(
        "adapter_binding",
        inputs_shape_valid
        and isinstance(resolved_inputs, dict)
        and resolved_inputs.get("adapter_registry_sha256")
        == adapters.get("registry_sha256"),
        "The run manifest adapter registry is not bound to the resolved input declaration.",
    )
    commands = manifest.get("commands", [])
    check(
        "execution_claim",
        isinstance(commands, list)
        and bool(commands)
        and isinstance(commands[0], dict)
        and commands[0].get("operation") == "static_scan"
        and commands[0].get("repository_code_executed") is False,
        "The run manifest does not preserve the static-scan non-execution claim.",
    )
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "failures": failures,
    }


def bounded_json_structure_metrics(
    value: Any,
    *,
    max_depth: int = MAX_GOVERNED_JSON_DEPTH,
    max_nodes: int = MAX_GOVERNED_JSON_NODES,
) -> dict[str, int | bool]:
    """Measure JSON-compatible structure iteratively and stop at the node bound."""

    node_count = 0
    observed_depth = 0
    depth_within_limit = True
    node_within_limit = True
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        node_count += 1
        observed_depth = max(observed_depth, depth)
        if depth > max_depth:
            depth_within_limit = False
        if node_count > max_nodes:
            node_within_limit = False
            break
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return {
        "node_count": node_count,
        "max_depth": observed_depth,
        "depth_within_limit": depth_within_limit,
        "node_within_limit": node_within_limit,
    }
