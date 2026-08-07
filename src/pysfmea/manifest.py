"""Resolved analysis-run manifests for reproducibility and audit."""

from __future__ import annotations

import copy
import hashlib
import json
import platform
import sys
from typing import Any

from .adapters import adapter_registry_snapshot
from .guidance import analysis_guidance_profiles, guidance_bundle
from .model import stable_id, utc_now
from .version import __version__

GROUNDED_DISCOVERY_PROMPT_VERSION = "sfmea-grounded-discovery-3"


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def create_run_manifest(
    analysis: dict[str, Any], *, tool_version: str | None = None
) -> dict[str, Any]:
    """Create the immutable resolved manifest for a completed deterministic scan."""

    producer_version = tool_version or __version__
    baseline = analysis.get("project", {}).get("baseline", {})
    settings = copy.deepcopy(analysis.get("project", {}).get("settings", {}))
    registry = adapter_registry_snapshot(analysis)
    guidance_profiles = analysis_guidance_profiles(analysis)
    embedded_guidance = analysis.get("guidance")
    guidance = (
        embedded_guidance
        if isinstance(embedded_guidance, dict) and embedded_guidance.get("catalog_sha256")
        else guidance_bundle(guidance_profiles)
    )
    inputs = {
        "source_digest": baseline.get("source_digest", ""),
        "configuration_digest": baseline.get("config_digest", ""),
        "guidance_catalog_sha256": guidance.get("catalog_sha256", ""),
        "adapter_registry_sha256": registry.get("registry_sha256", ""),
        "dependency_inventory_sha256": _digest(
            analysis.get("context", {}).get("dependencies", [])
        ),
        "contract_inventory_sha256": _digest(
            analysis.get("context", {}).get("contracts", [])
        ),
        "repository_inventory_sha256": analysis.get("repository_inventory", {}).get(
            "inventory_sha256", ""
        ),
        "system_context_sha256": analysis.get("system_context", {}).get(
            "context_sha256", ""
        ),
        "adapter_run_ledger_sha256": analysis.get("adapter_runs", {}).get(
            "ledger_sha256", ""
        ),
    }
    source_snapshot_sha256 = baseline.get("source_snapshot_sha256")
    if source_snapshot_sha256:
        inputs["source_snapshot_sha256"] = str(source_snapshot_sha256)
    test_evidence_snapshot_sha256 = baseline.get("test_evidence_snapshot_sha256")
    if test_evidence_snapshot_sha256:
        inputs["test_evidence_snapshot_sha256"] = str(
            test_evidence_snapshot_sha256
        )
    coverage_evidence = (
        analysis.get("project", {}).get("settings", {}).get("coverage_evidence")
    )
    if isinstance(coverage_evidence, dict) and coverage_evidence.get("sha256"):
        inputs["coverage_json_sha256"] = str(coverage_evidence["sha256"])
    created_at = str(analysis.get("project", {}).get("scanned_at") or utc_now())
    manifest: dict[str, Any] = {
        "schema_version": "pysfmea-run-manifest-1",
        "id": stable_id("RUN", str(baseline.get("id", "")), created_at),
        "created_at": created_at,
        "repository": {
            "root": str(analysis.get("project", {}).get("root", "")),
            "baseline_id": str(baseline.get("id", "")),
            "revision": str(baseline.get("vcs", {}).get("revision", "")),
            "dirty": baseline.get("vcs", {}).get("dirty"),
        },
        "resolved_inputs": inputs,
        "resolved_inputs_sha256": _digest(inputs),
        "tool": {
            "name": "PySFMEA",
            "version": producer_version,
            "analysis_schema_version": analysis.get("schema_version", ""),
            "settings": copy.deepcopy(settings),
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "executable_name": sys.executable.rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
        },
        "guidance": {
            "catalog_version": guidance.get("catalog_version", ""),
            "catalog_sha256": guidance.get("catalog_sha256", ""),
            "active_profiles": guidance_profiles,
            "selection_sha256": guidance.get("selection_sha256", ""),
            "sources": [
                {
                    "id": value.get("id", ""),
                    "version": value.get("version", ""),
                    "record_sha256": value.get("record_sha256", ""),
                    "artifact_sha256": value.get("artifact", {}).get("sha256", ""),
                }
                for value in guidance.get("sources", [])
                if any(
                    value.get("id") in profile.get("source_ids", [])
                    for profile in guidance.get("profiles", [])
                    if profile.get("id") in guidance_profiles
                )
            ],
        },
        "adapters": registry,
        "models": [],
        "prompts": [{"role": "grounded_discovery", "version": GROUNDED_DISCOVERY_PROMPT_VERSION, "invoked": False}],
        "commands": [
            {
                "operation": "static_scan",
                "repository_code_executed": False,
                "exit_code": 0,
                "settings": copy.deepcopy(settings),
            }
        ],
        "events": [
            {"sequence": 1, "at": created_at, "event": "scan_completed", "baseline_id": baseline.get("id", "")}
        ],
        "cache": {"used": False, "entries_reused": 0},
        "review_decisions": [],
        "waivers": [],
        "risk_acceptances": [],
        "notice": "This manifest records resolved analysis inputs and execution provenance; it does not establish certification, completeness, or approval.",
    }
    manifest["manifest_sha256"] = _digest(manifest)
    return manifest


def current_audit_manifest(
    analysis: dict[str, Any],
    *,
    generated_at: str | None = None,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a package-time audit view without mutating the immutable scan manifest."""

    scan_manifest = analysis.get("run_manifest") or create_run_manifest(
        analysis, tool_version=tool_version
    )
    reviews = []
    waivers = []
    risk_acceptances = []
    for item in analysis.get("items", []):
        review = item.get("review", {})
        if review.get("reviewed_at") or review.get("disposition") != "unreviewed":
            decision = {
                "finding_id": item.get("id", ""),
                "disposition": review.get("disposition", ""),
                "status": review.get("status", ""),
                "reviewer": review.get("reviewer", ""),
                "reviewed_at": review.get("reviewed_at", ""),
                "rationale": review.get("disposition_rationale", ""),
            }
            reviews.append(decision)
            if review.get("status") == "closed" and not review.get("actions_taken"):
                waivers.append(decision)
            if review.get("approved_by"):
                risk_acceptances.append(
                    {
                        "finding_id": item.get("id", ""),
                        "approved_by": review.get("approved_by", ""),
                        "approval_date": review.get("approval_date", ""),
                        "residual_severity": review.get("post_action_severity"),
                        "residual_severity_category": review.get("post_action_severity_category", ""),
                    }
                )
    executions = [
        {
            "id": value.get("id", ""),
            "status": value.get("status", ""),
            "ended_at": value.get("ended_at", ""),
            "manifest_sha256": value.get("execution_manifest_sha256", ""),
            "review_ids": [review.get("id", "") for review in value.get("reviews", [])],
        }
        for value in analysis.get("assurance", {}).get("executions", [])
    ]
    result = {
        "schema_version": "pysfmea-current-audit-manifest-1",
        "generated_at": generated_at or utc_now(),
        "scan_manifest": scan_manifest,
        "review_decisions": reviews,
        "waivers": waivers,
        "risk_acceptances": risk_acceptances,
        "test_executions": executions,
        "ordered_history": analysis.get("history", []),
    }
    result["manifest_sha256"] = _digest(result)
    return result
