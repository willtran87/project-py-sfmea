"""Governed, closed-loop activation workflows for an SFMEA analysis.

The enhancement workbench explains what remains.  This module turns the
highest-value queues into an editable, integrity-bound work package and applies
reviewed decisions without executing repository code or inferring approval.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any

from .diagnostics import analysis_diagnostics
from .enhancements import enhancement_workbench, evidence_preflight
from .file_publication import atomic_publish_text, inspect_artifact_destination
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id, utc_now
from .store import update_item_review

ACTIVATION_WORKSPACE_FORMAT = "pysfmea-activation-workspace-1"
ACTIVATION_VERIFICATION_FORMAT = "pysfmea-activation-workspace-verification-1"
ACTIVATION_APPLY_RECEIPT_FORMAT = "pysfmea-activation-apply-receipt-1"
ACTIVATION_RECORDS_FORMAT = "pysfmea-activation-records-1"
MAX_ACTIVATION_BYTES = 50_000_000
MAX_ACTIVATION_DEPTH = 100
MAX_ACTIVATION_NODES = 3_000_000
MAX_TEST_SOURCE_BYTES = 2_000_000
MAX_ATTRIBUTION_COMPONENTS = 250
MAX_ATTRIBUTION_TESTS = 5_000
MAX_ATTRIBUTION_MATCHES = 25_000
MAX_ACTIVATION_FINDINGS = 50_000

DECISION_CHOICES: dict[str, frozenset[str]] = {
    "finding": frozenset({"accepted", "rejected", "needs_information"}),
    "consolidation": frozenset(
        {"consolidate", "retain_separate", "needs_information"}
    ),
    "guidance": frozenset(
        {"map_direct", "supporting_only", "not_applicable", "needs_source"}
    ),
    "sfta": frozenset({"authoring_planned", "deferred", "needs_information"}),
    "architecture": frozenset({"accepted", "rejected", "needs_information"}),
    "interface": frozenset(
        {
            "confirmed_compatible",
            "deployment_prefix_or_proxy",
            "generated_or_external_server",
            "test_only",
            "confirmed_mismatch",
            "intentional_backend_only",
            "external_or_generated_client",
            "deprecated_or_unreachable",
            "missing_client_coverage",
            "needs_information",
        }
    ),
}


def _finding_consolidation_contract(item: dict[str, Any]) -> dict[str, Any]:
    """Return the review-significant finding fields used by a candidate group."""

    scanner = item.get("scanner", {})
    review = item.get("review", {})
    component = item.get("component", {})
    source = item.get("source", component.get("source", {}))
    return {
        "id": str(item.get("id", "")),
        "component_id": str(component.get("id", "")),
        "source": {
            "path": str(source.get("path", "")),
            "line": int(source.get("line", 0) or 0),
        },
        "rule_id": str(scanner.get("rule_id", "")),
        "failure_class": str(scanner.get("failure_class", "")),
        "failure_mode": str(
            review.get("failure_mode") or scanner.get("failure_mode", "")
        ),
        "causes": [str(value) for value in review.get("causes", [])],
        "local_effects": [str(value) for value in review.get("local_effects", [])],
        "next_effects": [str(value) for value in review.get("next_effects", [])],
        "end_effects": [str(value) for value in review.get("end_effects", [])],
        "linked_hazards": sorted(
            str(value) for value in review.get("linked_hazards", [])
        ),
        "recommended_actions": [
            str(value) for value in review.get("recommended_actions", [])
        ],
        "citation_ids": sorted(
            str(value.get("id", ""))
            for value in item.get("citations", [])
            if isinstance(value, dict) and value.get("id")
        ),
    }


def _finding_consolidation_queue(
    analysis: dict[str, Any], clusters: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Project complete multi-member clusters for explicit human adjudication."""

    items = {
        str(value.get("id", "")): value
        for value in analysis.get("items", [])
        if isinstance(value, dict)
        and value.get("source_status", "active") == "active"
        and value.get("id")
    }
    candidates: list[dict[str, Any]] = []
    for cluster in clusters:
        member_ids = [str(value) for value in cluster.get("members", []) if value]
        if (
            len(member_ids) < 2
            or int(cluster.get("members_omitted", 0) or 0) != 0
            or int(cluster.get("finding_count", 0) or 0) != len(member_ids)
            or len(member_ids) != len(set(member_ids))
            or any(identifier not in items for identifier in member_ids)
            or any(items[identifier].get("consolidation") for identifier in member_ids)
        ):
            continue
        canonical_id = str(cluster.get("representative_finding_id", ""))
        if canonical_id not in member_ids:
            continue
        contracts = [_finding_consolidation_contract(items[value]) for value in member_ids]
        candidates.append(
            {
                "id": stable_id("CONSOLIDATION-CANDIDATE", str(cluster.get("id", ""))),
                "cluster_id": str(cluster.get("id", "")),
                "canonical_finding_id": canonical_id,
                "member_finding_ids": member_ids,
                "member_count": len(member_ids),
                "member_contract_sha256": canonical_json_sha256(contracts),
                "semantic_basis": {
                    key: str(cluster.get(key, ""))
                    for key in (
                        "rule_id",
                        "failure_class",
                        "shared_cause",
                        "shared_action",
                        "hazard",
                        "source_area",
                    )
                },
                "decision_choices": sorted(DECISION_CHOICES["consolidation"]),
                "review_requirements": [
                    "Confirm that failure mode, causes, effects, controls, citations, and recommended actions can be governed as one review unit.",
                    "Record retain_separate whenever any member needs an independent disposition, evidence conclusion, action, or hazard treatment.",
                    "The canonical finding is a navigation and governance anchor; every source finding remains authoritative and individually addressable.",
                ],
                "authority": "deterministic_candidate_requires_named_semantic_equivalence_review",
            }
        )
    return candidates


def _analysis_binding(analysis: dict[str, Any]) -> dict[str, str]:
    baseline = analysis.get("project", {}).get("baseline", {})
    return {
        "baseline_id": str(baseline.get("id", "")),
        "repository_sha256": str(baseline.get("repository_sha256", "")),
        "analysis_state_sha256": canonical_json_sha256(analysis),
    }


def _safe_test_facts(root: Path, relative: str) -> tuple[set[str], set[str], str]:
    """Read one regular test source and return imports, names, and a diagnostic."""

    candidate = root / Path(relative)
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return set(), set(), "not_a_regular_file"
        size = candidate.stat().st_size
        if size > MAX_TEST_SOURCE_BYTES:
            return set(), set(), "source_exceeds_2mb_limit"
        raw = candidate.read_bytes()
        if len(raw) != size or len(raw) > MAX_TEST_SOURCE_BYTES:
            return set(), set(), "source_changed_or_exceeded_limit"
        source = raw.decode("utf-8-sig")
        tree = ast.parse(source, filename=relative)
    except UnicodeDecodeError:
        return set(), set(), "source_is_not_utf8"
    except (OSError, SyntaxError):
        return set(), set(), "source_could_not_be_parsed"
    imports: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            names.add(node.id if isinstance(node, ast.Name) else node.attr)
    return imports, names, "parsed"


def test_attribution(
    analysis: dict[str, Any], repository: str | Path, test_files: list[str]
) -> dict[str, Any]:
    """Explain whether and how discovered tests can be attributed to components."""

    root = Path(os.path.abspath(Path(repository).expanduser()))
    components: list[dict[str, Any]] = [
        value for value in analysis.get("components", []) if isinstance(value, dict)
    ]
    components_by_module_prefix: dict[str, list[str]] = defaultdict(list)
    components_by_module: dict[str, list[str]] = defaultdict(list)
    components_by_module_leaf: dict[str, list[str]] = defaultdict(list)
    components_by_symbol: dict[str, list[str]] = defaultdict(list)
    for component in components:
        source = component.get("source", {})
        source_path = str(source.get("path", "")).replace("\\", "/")
        module = source_path.removesuffix(".py").replace("/", ".")
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        component_id = str(component.get("id", ""))
        if not component_id:
            continue
        qualname = str(component.get("qualname", component.get("name", "")))
        components_by_module[module].append(component_id)
        components_by_module_leaf[module.rsplit(".", 1)[-1]].append(component_id)
        components_by_symbol[qualname.rsplit(".", 1)[-1]].append(component_id)
        module_parts = module.split(".")
        for index in range(1, len(module_parts) + 1):
            components_by_module_prefix[".".join(module_parts[:index])].append(
                component_id
            )
    records: list[dict[str, Any]] = []
    embedded_matches = 0
    unique_test_files = sorted(dict.fromkeys(test_files))
    for relative in unique_test_files[:MAX_ATTRIBUTION_TESTS]:
        imports, names, diagnostic = _safe_test_facts(root, relative)
        conventional = Path(relative).stem
        if conventional.startswith("test_"):
            conventional = conventional[5:]
        elif conventional.endswith("_test"):
            conventional = conventional[:-5]
        matches: dict[str, set[str]] = defaultdict(set)
        for imported in imports:
            for component_id in components_by_module_prefix.get(imported, []):
                matches[component_id].add("module_import")
            parts = imported.split(".")
            for index in range(1, len(parts) + 1):
                for component_id in components_by_module.get(
                    ".".join(parts[:index]), []
                ):
                    matches[component_id].add("module_import")
        module_candidates = set(matches)
        for component_id in components_by_module_leaf.get(conventional, []):
            matches[component_id].add("test_filename_convention")
        for name in names:
            for component_id in components_by_symbol.get(name, []):
                if not module_candidates or component_id in module_candidates:
                    matches[component_id].add("referenced_symbol")
        # Prefer the strongest available evidence. A module import alone can
        # legitimately name hundreds of callables; a referenced symbol or a
        # conventional module-specific test name is the more useful review lead.
        reason_weight = {
            "referenced_symbol": 3,
            "test_filename_convention": 2,
            "module_import": 1,
        }
        strongest = max(
            (
                max(reason_weight[reason] for reason in reasons)
                for reasons in matches.values()
            ),
            default=0,
        )
        if strongest:
            matches = {
                identifier: reasons
                for identifier, reasons in matches.items()
                if max(reason_weight[reason] for reason in reasons) == strongest
            }
        component_matches = [
            {"component_id": identifier, "reasons": sorted(reasons)}
            for identifier, reasons in sorted(matches.items())
        ]
        total_component_matches = len(component_matches)
        if diagnostic != "parsed":
            status = "unreadable"
        elif not total_component_matches:
            status = "unmapped"
        elif total_component_matches == 1:
            status = "mapped"
        else:
            status = "ambiguous"
        remaining_match_budget = max(0, MAX_ATTRIBUTION_MATCHES - embedded_matches)
        component_matches = component_matches[
            : min(MAX_ATTRIBUTION_COMPONENTS, remaining_match_budget)
        ]
        embedded_matches += len(component_matches)
        omitted = max(0, total_component_matches - len(component_matches))
        records.append(
            {
                "test_path": relative,
                "status": status,
                "parse_status": diagnostic,
                "imports": sorted(imports)[:250],
                "component_matches": component_matches,
                "component_matches_omitted": omitted,
                "review_required": status != "mapped",
                "authority": "static_attribution_candidate_not_test_effectiveness_evidence",
            }
        )
    counts: dict[str, int] = {
        name: sum(record["status"] == name for record in records)
        for name in ("mapped", "ambiguous", "unmapped", "unreadable")
    }
    return {
        "format": "pysfmea-test-attribution-1",
        "summary": {
            "discovered_tests": len(unique_test_files),
            "tests": len(records),
            "tests_omitted": max(0, len(unique_test_files) - len(records)),
            "truncated": len(unique_test_files) > len(records),
            "component_matches_embedded": embedded_matches,
            "component_matches_truncated": any(
                record["component_matches_omitted"] for record in records
            ),
            **counts,
        },
        "tests": records,
        "method": "bounded_ast_import_symbol_and_filename_attribution",
        "limitations": [
            "Static attribution does not prove that a test executes a component.",
            "Fixtures, parametrization, dynamic imports, plugins, and subprocess tests may require runtime evidence.",
            "Ambiguous matches require explicit project mapping before evidence credit.",
            f"Attribution is bounded to {MAX_ATTRIBUTION_TESTS:,} test files per workspace.",
            f"Attribution embeds at most {MAX_ATTRIBUTION_MATCHES:,} component matches per workspace.",
        ],
    }


def _finding_review_queue(
    analysis: dict[str, Any], campaign: dict[str, Any]
) -> list[dict[str, Any]]:
    item_by_id = {
        str(value.get("id", "")): value
        for value in analysis.get("items", [])
        if isinstance(value, dict)
    }
    units: list[dict[str, Any]] = []
    seen: set[str] = set()
    for batch in campaign.get("batches", []):
        if not isinstance(batch, dict):
            continue
        for unit in batch.get("units", []):
            if not isinstance(unit, dict):
                continue
            finding_id = str(unit.get("id", ""))
            if not finding_id or finding_id in seen or finding_id not in item_by_id:
                continue
            seen.add(finding_id)
            item = item_by_id[finding_id]
            review = item.get("review", {})
            units.append(
                {
                    "id": finding_id,
                    "kind": str(unit.get("kind", "finding")),
                    "parent_id": str(unit.get("parent_id", "")),
                    "rule_id": str(item.get("scanner", {}).get("rule_id", "")),
                    "priority": str(
                        item.get("scanner", {}).get("screening_priority", "")
                    ),
                    "component": str(item.get("component", {}).get("qualname", "")),
                    "source": item.get("source", {}),
                    "failure_mode": str(
                        review.get("failure_mode")
                        or item.get("scanner", {}).get("failure_mode", "")
                    ),
                    "current_disposition": str(review.get("disposition", "unreviewed")),
                }
            )
    remaining = [
        item
        for identifier, item in item_by_id.items()
        if identifier not in seen and item.get("source_status") != "removed"
    ]
    priority_order = {"high": 0, "medium": 1, "low": 2}
    remaining.sort(
        key=lambda item: (
            priority_order.get(
                str(item.get("scanner", {}).get("screening_priority", "")), 9
            ),
            str(item.get("source", {}).get("path", "")),
            str(item.get("id", "")),
        )
    )
    for item in remaining:
        if len(units) >= MAX_ACTIVATION_FINDINGS:
            break
        review = item.get("review", {})
        units.append(
            {
                "id": str(item.get("id", "")),
                "kind": "complete_register",
                "parent_id": "",
                "rule_id": str(item.get("scanner", {}).get("rule_id", "")),
                "priority": str(
                    item.get("scanner", {}).get("screening_priority", "")
                ),
                "component": str(item.get("component", {}).get("qualname", "")),
                "source": item.get("source", {}),
                "failure_mode": str(
                    review.get("failure_mode")
                    or item.get("scanner", {}).get("failure_mode", "")
                ),
                "current_disposition": str(
                    review.get("disposition", "unreviewed")
                ),
            }
        )
    return units[:MAX_ACTIVATION_FINDINGS]


def _queue_ids(workspace: dict[str, Any]) -> dict[str, set[str]]:
    return {kind: set(values) for kind, values in _queue_id_values(workspace).items()}


def _subject_decision_choices(
    workspace: dict[str, Any], kind: str, subject_id: str
) -> frozenset[str]:
    if kind != "interface":
        return DECISION_CHOICES.get(kind, frozenset())
    queues = workspace.get("queues", {})
    for side in ("servers", "clients"):
        for value in queues.get("interfaces", {}).get(side, []):
            if not isinstance(value, dict) or str(value.get("id", "")) != subject_id:
                continue
            choices = value.get("suggested_dispositions", [])
            if isinstance(choices, list):
                return frozenset(
                    str(choice)
                    for choice in choices
                    if str(choice) in DECISION_CHOICES["interface"]
                )
    return frozenset()


def _queue_id_values(workspace: dict[str, Any]) -> dict[str, list[str]]:
    queues = workspace.get("queues", {})
    return {
        "finding": [
            str(value.get("id", ""))
            for value in queues.get("finding_reviews", [])
            if isinstance(value, dict)
        ],
        "consolidation": [
            str(value.get("id", ""))
            for value in queues.get("finding_consolidations", [])
            if isinstance(value, dict)
        ],
        "guidance": [
            str(value.get("rule_id", ""))
            for value in queues.get("guidance", [])
            if isinstance(value, dict)
        ],
        "sfta": [
            str(value.get("id", value.get("tree_id", "")))
            for value in queues.get("sfta", [])
            if isinstance(value, dict)
        ],
        "architecture": [
            str(value.get("id", ""))
            for value in queues.get("architecture", [])
            if isinstance(value, dict)
        ],
        "interface": [
            str(value.get("id", ""))
            for side in ("servers", "clients")
            for value in queues.get("interfaces", {}).get(side, [])
            if isinstance(value, dict)
        ],
    }


def activation_workspace(
    analysis: dict[str, Any], repository: str | Path
) -> dict[str, Any]:
    """Build one editable, state-bound closure workspace."""

    diagnostics = analysis_diagnostics(analysis)
    preflight = evidence_preflight(analysis, repository, diagnostics=diagnostics)
    workbench = enhancement_workbench(analysis, diagnostics=diagnostics)
    campaign = workbench.get("review_campaign", {})
    consolidation_records = _finding_consolidation_queue(
        analysis,
        [
            value
            for value in workbench.get("review_clusters", [])
            if isinstance(value, dict)
        ],
    )
    guidance = workbench.get("guidance_specificity_program", {})
    sfta_queue = workbench.get("sfta_queue", {})
    sfta_records: list[dict[str, Any]] = []
    for tree in analysis.get("sfta", {}).get("trees", []):
        if not isinstance(tree, dict):
            continue
        source = str(tree.get("source", ""))
        if source == "explicit_configuration":
            continue
        sfta_records.append(
            {
                "id": str(tree.get("id", "")),
                "hazard_id": str(tree.get("hazard_id", "")),
                "top_event": str(tree.get("top_event", "")),
                "source": source or "undeveloped",
            }
        )
    if not sfta_records:
        for value in sfta_queue.get("top_down_uncovered_events", []):
            if isinstance(value, dict):
                identifier = str(value.get("tree_id") or value.get("event_id") or "")
                if identifier:
                    sfta_records.append({"id": identifier, **value})
    interface_queue = workbench.get("interface_disposition_queue", {})
    finding_records = _finding_review_queue(analysis, campaign)
    active_findings = sum(
        isinstance(value, dict) and value.get("source_status") != "removed"
        for value in analysis.get("items", [])
    )
    architecture_records = []
    for value in workbench.get("architecture_mapping_queue", {}).get(
        "proposals", []
    ):
        if not isinstance(value, dict):
            continue
        component_id = str(value.get("component_id", ""))
        architecture_records.append(
            {
                "id": stable_id("ACTIVATION-ARCH", component_id)
                if component_id
                else "",
                **value,
            }
        )
    material: dict[str, Any] = {
        "format": ACTIVATION_WORKSPACE_FORMAT,
        "created_at": utc_now(),
        "analysis_binding": _analysis_binding(analysis),
        "repository": str(preflight.get("repository", Path(repository).absolute())),
        "summary": {
            "finding_reviews": len(finding_records),
            "finding_reviews_omitted": max(0, active_findings - len(finding_records)),
            "finding_consolidation_candidates": len(consolidation_records),
            "finding_consolidation_members": sum(
                int(value["member_count"]) for value in consolidation_records
            ),
            "guidance_dispositions": len(guidance.get("closure_queue", [])),
            "sfta_authoring_items": len(sfta_records),
            "architecture_dispositions": len(architecture_records),
            "interface_dispositions": len(interface_queue.get("servers", []))
            + len(interface_queue.get("clients", [])),
            "recorded_decisions": 0,
            "assigned_items": 0,
        },
        "evidence_onboarding": {
            "preflight": preflight,
            "test_attribution": test_attribution(
                analysis,
                repository,
                list(preflight.get("discovery", {}).get("test_files", [])),
            ),
            "state_machine": workbench.get("evidence_onboarding", {}),
            "scope_patch": workbench.get("scope_patch", {}),
            "next_actions": preflight.get("ordered_actions", []),
        },
        "queues": {
            "finding_reviews": finding_records,
            "finding_consolidations": consolidation_records,
            "calibration": campaign.get("calibration_samples", []),
            "guidance": guidance.get("closure_queue", []),
            "guidance_overbreadth": guidance.get("overbroad_citations", []),
            "sfta": sfta_records,
            "architecture": architecture_records,
            "interfaces": {
                "servers": interface_queue.get("servers", []),
                "clients": interface_queue.get("clients", []),
            },
        },
        "decisions": [],
        "assignments": [],
        "workflow": [
            {"step": 1, "action": "Review evidence onboarding diagnostics and repair scope or evidence inputs."},
            {"step": 2, "action": "Assign and review finding representatives, calibration samples, and complete consolidation candidates."},
            {"step": 3, "action": "Record explicit consolidation, guidance, SFTA, architecture, and interface dispositions."},
            {"step": 4, "action": "Verify the workspace against the unchanged source analysis."},
            {"step": 5, "action": "Apply finding reviews and approved canonical review groups; route approved SFTA and configuration inputs through their dedicated authoring workflows before rescanning."},
        ],
        "guardrails": [
            "No repository code is executed by this workspace.",
            "Each decision applies only to its exact subject; cluster members are never implicitly disposed.",
            "Consolidation never removes a finding or propagates the canonical finding disposition to its members.",
            "A consolidation decision is valid only for a complete state-bound candidate membership list.",
            "Non-finding decisions are retained as governed review records and do not alter scanner rules or claim compliance.",
            "The workspace must match the exact source analysis state before application.",
        ],
        "authority": "human_review_work_package_not_engineering_approval_compliance_or_evidence_credit",
    }
    material["content_sha256"] = canonical_json_sha256(material)
    return material


def export_activation_workspace(
    analysis: dict[str, Any], repository: str | Path, destination: str | Path
) -> Path:
    expected_destination = inspect_artifact_destination(
        destination, label="activation workspace"
    )
    workspace = activation_workspace(analysis, repository)
    if not _verify_value(workspace, analysis=analysis)["valid"]:
        raise RuntimeError("generated activation workspace failed internal verification")
    return atomic_publish_text(
        destination,
        json.dumps(workspace, indent=2, ensure_ascii=False) + "\n",
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        expected_destination=expected_destination,
        staged_verifier=lambda path: verify_activation_workspace_file(
            path, analysis=analysis
        )["valid"]
        is True,
    )


def activation_records_template(workspace: dict[str, Any]) -> dict[str, Any]:
    """Return a small, workspace-bound bulk assignment/decision import template."""

    verification = _verify_value(workspace)
    if not verification["valid"]:
        raise ValueError("activation workspace is invalid")
    return {
        "format": ACTIVATION_RECORDS_FORMAT,
        "workspace_binding": {
            "content_sha256": str(workspace.get("content_sha256", "")),
            "analysis_state_sha256": str(
                workspace.get("analysis_binding", {}).get(
                    "analysis_state_sha256", ""
                )
            ),
        },
        "decision_choices": {
            kind: sorted(values) for kind, values in sorted(DECISION_CHOICES.items())
        },
        "assignments": [],
        "decisions": [],
        "instructions": [
            "Copy exact kind and subject_id values from the activation workspace queues.",
            "Assignments require assignee and may include due_date in YYYY-MM-DD form.",
            "Decisions require an allowed decision, named reviewer, and non-empty rationale.",
            "Import is all-or-nothing and refuses a workspace changed after this template was exported.",
        ],
        "authority": "bulk_review_input_template_not_disposition_or_approval",
    }


def export_activation_records_template(
    workspace: dict[str, Any], destination: str | Path
) -> Path:
    expected_destination = inspect_artifact_destination(
        destination, label="activation records template"
    )
    template = activation_records_template(workspace)

    def staged_valid(path: Path) -> bool:
        try:
            document = load_bounded_json_document(
                path,
                label="activation records template",
                max_bytes=MAX_ACTIVATION_BYTES,
                max_depth=MAX_ACTIVATION_DEPTH,
                max_nodes=MAX_ACTIVATION_NODES,
            )
        except ValueError:
            return False
        return bool(document.value == template)

    return atomic_publish_text(
        destination,
        json.dumps(template, indent=2, ensure_ascii=False) + "\n",
        label="activation records template",
        max_bytes=MAX_ACTIVATION_BYTES,
        expected_destination=expected_destination,
        staged_verifier=staged_valid,
    )


def import_activation_records(
    workspace_source: str | Path, records_source: str | Path
) -> tuple[Path, dict[str, Any]]:
    """All-or-nothing bulk import of assignments and decisions."""

    expected_destination = inspect_artifact_destination(
        workspace_source, label="activation workspace"
    )
    workspace_document = load_bounded_json_document(
        workspace_source,
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        max_depth=MAX_ACTIVATION_DEPTH,
        max_nodes=MAX_ACTIVATION_NODES,
    )
    workspace = workspace_document.value
    verification = _verify_value(workspace)
    if not verification["valid"]:
        raise ValueError("activation workspace is invalid before bulk import")
    records_document = load_bounded_json_document(
        records_source,
        label="activation records",
        max_bytes=MAX_ACTIVATION_BYTES,
        max_depth=MAX_ACTIVATION_DEPTH,
        max_nodes=MAX_ACTIVATION_NODES,
    )
    records = records_document.value
    if not isinstance(records, dict) or records.get("format") != ACTIVATION_RECORDS_FORMAT:
        raise ValueError("activation records format is missing or unsupported")
    binding = records.get("workspace_binding", {})
    if not isinstance(binding, dict) or binding != {
        "content_sha256": workspace.get("content_sha256", ""),
        "analysis_state_sha256": workspace.get("analysis_binding", {}).get(
            "analysis_state_sha256", ""
        ),
    }:
        raise ValueError("activation records do not match the exact current workspace")
    incoming_assignments = records.get("assignments", [])
    incoming_decisions = records.get("decisions", [])
    if (
        not isinstance(incoming_assignments, list)
        or not isinstance(incoming_decisions, list)
        or not all(isinstance(value, dict) for value in incoming_assignments)
        or not all(isinstance(value, dict) for value in incoming_decisions)
    ):
        raise ValueError("activation assignments and decisions must be lists of objects")
    if len(incoming_assignments) + len(incoming_decisions) > 50_000:
        raise ValueError("activation bulk import exceeds the 50,000-record limit")
    ids = _queue_ids(workspace)
    assignment_keys: set[tuple[str, str]] = set()
    decision_keys: set[tuple[str, str]] = set()
    normalized_assignments: list[dict[str, str]] = []
    normalized_decisions: list[dict[str, str]] = []
    imported_at = utc_now()
    for index, value in enumerate(incoming_assignments, start=1):
        kind = str(value.get("kind", "")).strip()
        subject_id = str(value.get("subject_id", "")).strip()
        assignee = str(value.get("assignee", "")).strip()
        due_date = str(value.get("due_date", "")).strip()
        key = (kind, subject_id)
        if key in assignment_keys:
            raise ValueError(f"activation assignment {index} duplicates {kind}:{subject_id}")
        assignment_keys.add(key)
        if kind not in DECISION_CHOICES or subject_id not in ids.get(kind, set()):
            raise ValueError(f"activation assignment {index} targets an unknown subject")
        if not assignee:
            raise ValueError(f"activation assignment {index} requires assignee")
        if due_date:
            try:
                date.fromisoformat(due_date)
            except ValueError as exc:
                raise ValueError(
                    f"activation assignment {index} due date must use YYYY-MM-DD"
                ) from exc
        normalized_assignments.append(
            {
                "id": stable_id("ACTIVATION-ASSIGNMENT", kind, subject_id, assignee),
                "kind": kind,
                "subject_id": subject_id,
                "assignee": assignee,
                "due_date": due_date,
                "assigned_at": imported_at,
            }
        )
    for index, value in enumerate(incoming_decisions, start=1):
        kind = str(value.get("kind", "")).strip()
        subject_id = str(value.get("subject_id", "")).strip()
        choice = str(value.get("decision", "")).strip()
        reviewer = str(value.get("reviewer", "")).strip()
        rationale = str(value.get("rationale", "")).strip()
        key = (kind, subject_id)
        if key in decision_keys:
            raise ValueError(f"activation decision {index} duplicates {kind}:{subject_id}")
        decision_keys.add(key)
        if kind not in DECISION_CHOICES or subject_id not in ids.get(kind, set()):
            raise ValueError(f"activation decision {index} targets an unknown subject")
        if choice not in _subject_decision_choices(workspace, kind, subject_id):
            raise ValueError(f"activation decision {index} is not allowed for {kind}")
        if not reviewer or not rationale:
            raise ValueError(
                f"activation decision {index} requires reviewer and rationale"
            )
        normalized_decisions.append(
            {
                "id": stable_id(
                    "ACTIVATION-DECISION",
                    kind,
                    subject_id,
                    choice,
                    reviewer,
                    rationale,
                ),
                "kind": kind,
                "subject_id": subject_id,
                "decision": choice,
                "reviewer": reviewer,
                "rationale": rationale,
                "recorded_at": imported_at,
            }
        )
    updated = copy.deepcopy(workspace)
    updated["assignments"] = [
        value
        for value in updated.get("assignments", [])
        if (str(value.get("kind", "")), str(value.get("subject_id", "")))
        not in assignment_keys
    ] + normalized_assignments
    updated["decisions"] = [
        value
        for value in updated.get("decisions", [])
        if (str(value.get("kind", "")), str(value.get("subject_id", "")))
        not in decision_keys
    ] + normalized_decisions
    updated["assignments"].sort(
        key=lambda value: (str(value["kind"]), str(value["subject_id"]))
    )
    updated["decisions"].sort(
        key=lambda value: (str(value["kind"]), str(value["subject_id"]))
    )
    updated.setdefault("summary", {})["assigned_items"] = len(
        updated["assignments"]
    )
    updated["summary"]["recorded_decisions"] = len(updated["decisions"])
    updated.pop("content_sha256", None)
    updated["content_sha256"] = canonical_json_sha256(updated)
    final_verification = _verify_value(updated)
    if not final_verification["valid"]:
        raise RuntimeError("bulk activation records failed post-import verification")
    result = atomic_publish_text(
        workspace_document.path,
        json.dumps(updated, indent=2, ensure_ascii=False) + "\n",
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        expected_destination=expected_destination,
        staged_verifier=lambda path: verify_activation_workspace_file(path)["valid"]
        is True,
    )
    receipt = {
        "format": "pysfmea-activation-records-import-receipt-1",
        "status": "imported",
        "workspace": str(result),
        "records_sha256": hashlib.sha256(records_document.raw).hexdigest(),
        "assignments_imported": len(normalized_assignments),
        "decisions_imported": len(normalized_decisions),
        "result_workspace_sha256": str(updated["content_sha256"]),
        "authority": "transactional_import_receipt_not_decision_approval",
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return result, receipt


def _verify_value(
    value: Any, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    checks: dict[str, bool] = {}

    def check(name: str, passed: bool, code: str, message: str) -> None:
        checks[name] = passed
        if not passed:
            findings.append({"code": code, "message": message})

    shape = isinstance(value, dict)
    check("object_shape", shape, "activation.invalid_shape", "Workspace root must be an object.")
    if not shape:
        return {
            "format": ACTIVATION_VERIFICATION_FORMAT,
            "valid": False,
            "status": "invalid",
            "analysis_checked": analysis is not None,
            "checks": checks,
            "decision_count": 0,
            "assignment_count": 0,
            "findings": findings,
            "notice": "The workspace root was rejected before semantic processing.",
        }
    check(
        "format",
        value.get("format") == ACTIVATION_WORKSPACE_FORMAT,
        "activation.unsupported_format",
        "Workspace format is unsupported.",
    )
    supplied = value.get("content_sha256")
    canonical = dict(value)
    canonical.pop("content_sha256", None)
    check(
        "content_integrity",
        isinstance(supplied, str) and supplied == canonical_json_sha256(canonical),
        "activation.content_mismatch",
        "Workspace content differs from its declared digest.",
    )
    id_values = _queue_id_values(value)
    ids = {kind: set(values) for kind, values in id_values.items()}
    check(
        "queue_identifiers",
        all("" not in values for values in ids.values()),
        "activation.queue_identifier_missing",
        "Every queued subject must have a non-empty identifier.",
    )
    check(
        "queue_identifier_uniqueness",
        all(len(values) == len(set(values)) for values in id_values.values()),
        "activation.duplicate_queue_identifier",
        "Queued subject identifiers must be unique within each decision kind.",
    )
    consolidation_candidates = value.get("queues", {}).get(
        "finding_consolidations", []
    )
    consolidation_structure = isinstance(consolidation_candidates, list) and all(
        isinstance(candidate, dict)
        and set(candidate)
        == {
            "id",
            "cluster_id",
            "canonical_finding_id",
            "member_finding_ids",
            "member_count",
            "member_contract_sha256",
            "semantic_basis",
            "decision_choices",
            "review_requirements",
            "authority",
        }
        and isinstance(candidate.get("member_finding_ids"), list)
        and len(candidate["member_finding_ids"]) >= 2
        and len(candidate["member_finding_ids"])
        == len(set(str(member) for member in candidate["member_finding_ids"]))
        == int(candidate.get("member_count", 0) or 0)
        and candidate.get("canonical_finding_id")
        in candidate.get("member_finding_ids", [])
        and isinstance(candidate.get("member_contract_sha256"), str)
        and len(candidate["member_contract_sha256"]) == 64
        and candidate.get("decision_choices")
        == sorted(DECISION_CHOICES["consolidation"])
        and isinstance(candidate.get("semantic_basis"), dict)
        and isinstance(candidate.get("review_requirements"), list)
        and bool(candidate.get("authority"))
        for candidate in consolidation_candidates
    )
    check(
        "consolidation_candidate_structure",
        consolidation_structure,
        "activation.invalid_consolidation_candidate",
        "Every consolidation candidate must be complete, closed, and internally consistent.",
    )
    decisions = value.get("decisions", [])
    structure = isinstance(decisions, list) and all(
        isinstance(decision, dict) for decision in decisions
    )
    check(
        "decision_structure",
        structure,
        "activation.invalid_decisions",
        "Decisions must be a list of objects.",
    )
    decision_ids: list[str] = []
    decision_semantics = structure
    if structure:
        for decision in decisions:
            kind = str(decision.get("kind", ""))
            subject_id = str(decision.get("subject_id", ""))
            choice = str(decision.get("decision", ""))
            identifier = str(decision.get("id", ""))
            decision_ids.append(identifier)
            if (
                kind not in DECISION_CHOICES
                or subject_id not in ids.get(kind, set())
                or choice not in _subject_decision_choices(value, kind, subject_id)
                or not str(decision.get("reviewer", "")).strip()
                or not str(decision.get("rationale", "")).strip()
                or not identifier
            ):
                decision_semantics = False
    check(
        "decision_semantics",
        bool(decision_semantics),
        "activation.invalid_decision",
        "Every decision must target a queued subject and include an allowed choice, reviewer, rationale, and ID.",
    )
    check(
        "decision_uniqueness",
        len(decision_ids) == len(set(decision_ids))
        and len({(str(d.get("kind")), str(d.get("subject_id"))) for d in decisions})
        == len(decision_ids),
        "activation.duplicate_decision",
        "A subject may have only one current decision.",
    )
    assignments = value.get("assignments", [])
    assignment_structure = isinstance(assignments, list) and all(
        isinstance(assignment, dict) for assignment in assignments
    )
    check(
        "assignment_structure",
        assignment_structure,
        "activation.invalid_assignments",
        "Assignments must be a list of objects.",
    )
    assignment_semantics = assignment_structure
    assignment_keys: list[tuple[str, str]] = []
    if assignment_structure:
        for assignment in assignments:
            kind = str(assignment.get("kind", ""))
            subject_id = str(assignment.get("subject_id", ""))
            due_date = str(assignment.get("due_date", ""))
            assignment_keys.append((kind, subject_id))
            try:
                if due_date:
                    date.fromisoformat(due_date)
            except ValueError:
                assignment_semantics = False
            if (
                kind not in DECISION_CHOICES
                or subject_id not in ids.get(kind, set())
                or not str(assignment.get("id", ""))
                or not str(assignment.get("assignee", "")).strip()
            ):
                assignment_semantics = False
    check(
        "assignment_semantics",
        bool(assignment_semantics),
        "activation.invalid_assignment",
        "Every assignment must target a queued subject and include an assignee, valid optional due date, and ID.",
    )
    check(
        "assignment_uniqueness",
        len(assignment_keys) == len(set(assignment_keys)),
        "activation.duplicate_assignment",
        "A subject may have only one current assignment.",
    )
    if analysis is not None:
        binding = value.get("analysis_binding", {})
        expected = _analysis_binding(analysis)
        check(
            "analysis_binding",
            binding == expected,
            "activation.analysis_mismatch",
            "Workspace does not match the exact supplied analysis state.",
        )
        expected_workbench = enhancement_workbench(analysis)
        expected_consolidations = _finding_consolidation_queue(
            analysis,
            [
                candidate
                for candidate in expected_workbench.get("review_clusters", [])
                if isinstance(candidate, dict)
            ],
        )
        check(
            "consolidation_candidate_binding",
            consolidation_candidates == expected_consolidations,
            "activation.consolidation_candidate_mismatch",
            "Consolidation candidates do not exactly regenerate from the supplied analysis.",
        )
    valid = all(checks.values())
    return {
        "format": ACTIVATION_VERIFICATION_FORMAT,
        "valid": valid,
        "status": "matched" if valid and analysis is not None else "internally_valid" if valid else "invalid",
        "analysis_checked": analysis is not None,
        "checks": checks,
        "decision_count": len(decisions) if isinstance(decisions, list) else 0,
        "assignment_count": len(assignments) if isinstance(assignments, list) else 0,
        "findings": findings,
        "notice": "Verification proves workspace integrity and state binding; it does not approve any decision.",
    }


def verify_activation_workspace_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="activation workspace",
            max_bytes=MAX_ACTIVATION_BYTES,
            max_depth=MAX_ACTIVATION_DEPTH,
            max_nodes=MAX_ACTIVATION_NODES,
        )
    except ValueError as exc:
        return {
            "format": ACTIVATION_VERIFICATION_FORMAT,
            "valid": False,
            "status": "invalid",
            "source": str(Path(source).absolute()),
            "analysis_checked": analysis is not None,
            "checks": {"bounded_ingestion": False},
            "decision_count": 0,
            "assignment_count": 0,
            "findings": [{"code": "activation.ingestion_failed", "message": str(exc)}],
            "notice": "The workspace was rejected before semantic processing.",
        }
    result = _verify_value(document.value, analysis=analysis)
    result["source"] = str(document.path)
    result["source_bytes"] = document.size
    result["source_sha256"] = hashlib.sha256(document.raw).hexdigest()
    return result


def record_activation_decision(
    source: str | Path,
    *,
    kind: str,
    subject_id: str,
    decision: str,
    reviewer: str,
    rationale: str,
) -> Path:
    """Transactionally add or replace one explicit workspace decision."""

    expected_destination = inspect_artifact_destination(
        source, label="activation workspace"
    )
    document = load_bounded_json_document(
        source,
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        max_depth=MAX_ACTIVATION_DEPTH,
        max_nodes=MAX_ACTIVATION_NODES,
    )
    value = document.value
    verification = _verify_value(value)
    if not verification["valid"]:
        raise ValueError("activation workspace is invalid before decision update")
    kind = kind.strip()
    subject_id = subject_id.strip()
    decision = decision.strip()
    reviewer = reviewer.strip()
    rationale = rationale.strip()
    if kind not in DECISION_CHOICES:
        raise ValueError("unknown activation decision kind")
    if subject_id not in _queue_ids(value)[kind]:
        raise ValueError(f"unknown {kind} activation subject: {subject_id}")
    allowed = _subject_decision_choices(value, kind, subject_id)
    if decision not in allowed:
        raise ValueError(
            f"invalid {kind} decision; choose from {', '.join(sorted(allowed))}"
        )
    if not reviewer or not rationale:
        raise ValueError("reviewer and rationale are required")
    decisions = [
        entry
        for entry in value.get("decisions", [])
        if not (
            str(entry.get("kind", "")) == kind
            and str(entry.get("subject_id", "")) == subject_id
        )
    ]
    at = utc_now()
    decisions.append(
        {
            "id": stable_id("ACTIVATION-DECISION", kind, subject_id, decision, reviewer, rationale),
            "kind": kind,
            "subject_id": subject_id,
            "decision": decision,
            "reviewer": reviewer,
            "rationale": rationale,
            "recorded_at": at,
        }
    )
    decisions.sort(key=lambda entry: (str(entry["kind"]), str(entry["subject_id"])))
    value["decisions"] = decisions
    value.setdefault("summary", {})["recorded_decisions"] = len(decisions)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    return atomic_publish_text(
        document.path,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        expected_destination=expected_destination,
        staged_verifier=lambda path: verify_activation_workspace_file(path)["valid"]
        is True,
    )


def record_activation_assignment(
    source: str | Path,
    *,
    kind: str,
    subject_id: str,
    assignee: str,
    due_date: str = "",
) -> Path:
    """Transactionally add or replace one queue assignment."""

    expected_destination = inspect_artifact_destination(
        source, label="activation workspace"
    )
    document = load_bounded_json_document(
        source,
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        max_depth=MAX_ACTIVATION_DEPTH,
        max_nodes=MAX_ACTIVATION_NODES,
    )
    value = document.value
    verification = _verify_value(value)
    if not verification["valid"]:
        raise ValueError("activation workspace is invalid before assignment update")
    kind = kind.strip()
    subject_id = subject_id.strip()
    assignee = assignee.strip()
    due_date = due_date.strip()
    if kind not in DECISION_CHOICES:
        raise ValueError("unknown activation assignment kind")
    if subject_id not in _queue_ids(value)[kind]:
        raise ValueError(f"unknown {kind} activation subject: {subject_id}")
    if not assignee:
        raise ValueError("assignee is required")
    if due_date:
        try:
            date.fromisoformat(due_date)
        except ValueError as exc:
            raise ValueError("due date must use YYYY-MM-DD") from exc
    assignments = [
        entry
        for entry in value.get("assignments", [])
        if not (
            str(entry.get("kind", "")) == kind
            and str(entry.get("subject_id", "")) == subject_id
        )
    ]
    assignments.append(
        {
            "id": stable_id("ACTIVATION-ASSIGNMENT", kind, subject_id, assignee),
            "kind": kind,
            "subject_id": subject_id,
            "assignee": assignee,
            "due_date": due_date,
            "assigned_at": utc_now(),
        }
    )
    assignments.sort(
        key=lambda entry: (str(entry["kind"]), str(entry["subject_id"]))
    )
    value["assignments"] = assignments
    value.setdefault("summary", {})["assigned_items"] = len(assignments)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    return atomic_publish_text(
        document.path,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        expected_destination=expected_destination,
        staged_verifier=lambda path: verify_activation_workspace_file(path)["valid"]
        is True,
    )


def _apply_finding_consolidation(
    updated: dict[str, Any], workspace: dict[str, Any], decision: dict[str, Any]
) -> str:
    """Create one canonical review group without deleting or disposing members."""

    subject_id = str(decision["subject_id"])
    candidate = next(
        (
            value
            for value in workspace.get("queues", {}).get(
                "finding_consolidations", []
            )
            if isinstance(value, dict) and str(value.get("id", "")) == subject_id
        ),
        None,
    )
    if candidate is None:
        raise ValueError(f"consolidation candidate is missing: {subject_id}")
    member_ids = [str(value) for value in candidate.get("member_finding_ids", [])]
    canonical_id = str(candidate.get("canonical_finding_id", ""))
    items = {
        str(value.get("id", "")): value
        for value in updated.get("items", [])
        if isinstance(value, dict) and value.get("id")
    }
    if (
        len(member_ids) < 2
        or canonical_id not in member_ids
        or any(identifier not in items for identifier in member_ids)
    ):
        raise ValueError(f"consolidation candidate membership is invalid: {subject_id}")
    actual_contract_sha256 = canonical_json_sha256(
        [_finding_consolidation_contract(items[value]) for value in member_ids]
    )
    if actual_contract_sha256 != candidate.get("member_contract_sha256"):
        raise ValueError(f"consolidation member contract changed: {subject_id}")
    conflicts = [
        identifier
        for identifier in member_ids
        if isinstance(items[identifier].get("consolidation"), dict)
    ]
    if conflicts:
        raise ValueError(
            "consolidation members already belong to a canonical group: "
            + ", ".join(conflicts)
        )
    applied_at = utc_now()
    group_id = stable_id(
        "CONSOLIDATION",
        subject_id,
        str(decision["id"]),
        canonical_id,
        *member_ids,
    )
    record = {
        "id": group_id,
        "status": "canonicalized_for_review",
        "candidate_id": subject_id,
        "cluster_id": str(candidate.get("cluster_id", "")),
        "canonical_finding_id": canonical_id,
        "member_finding_ids": member_ids,
        "member_count": len(member_ids),
        "member_contract_sha256": actual_contract_sha256,
        "semantic_basis": copy.deepcopy(candidate.get("semantic_basis", {})),
        "review": {
            "decision_id": str(decision["id"]),
            "decision": "consolidate",
            "reviewer": str(decision["reviewer"]),
            "rationale": str(decision["rationale"]),
            "recorded_at": str(decision["recorded_at"]),
        },
        "applied_at": applied_at,
        "authority": "canonical_review_group_preserves_individual_findings_evidence_citations_and_dispositions",
    }
    registry = updated.setdefault("finding_consolidation", {})
    records = registry.setdefault("records", [])
    if not isinstance(records, list):
        raise ValueError("finding consolidation registry records must be a list")
    records.append(record)
    records.sort(key=lambda value: str(value.get("id", "")))
    for identifier in member_ids:
        items[identifier]["consolidation"] = {
            "group_id": group_id,
            "canonical_finding_id": canonical_id,
            "role": "canonical" if identifier == canonical_id else "member",
            "member_count": len(member_ids),
            "decision_id": str(decision["id"]),
        }
    registry.update(
        {
            "format": "pysfmea-finding-consolidation-register-1",
            "summary": {
                "canonical_groups": len(records),
                "grouped_finding_memberships": sum(
                    int(value.get("member_count", 0) or 0)
                    for value in records
                    if isinstance(value, dict)
                ),
                "source_findings_removed": 0,
            },
            "last_applied_at": applied_at,
            "authority": "review_navigation_and_governance_groups_not_finding_deletion_shared_disposition_or_risk_acceptance",
        }
    )
    return group_id


def apply_activation_workspace(
    analysis: dict[str, Any], workspace: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply exact reviewed decisions to a private analysis copy."""

    verification = _verify_value(workspace, analysis=analysis)
    if not verification["valid"]:
        codes = ", ".join(value["code"] for value in verification["findings"])
        raise ValueError(f"activation workspace cannot be applied: {codes}")
    if not workspace.get("decisions"):
        raise ValueError("activation workspace contains no decisions to apply")
    updated = copy.deepcopy(analysis)
    finding_count = 0
    consolidation_count = 0
    governance_count = 0
    applied_records: list[dict[str, str]] = []
    decisions = workspace.get("decisions", [])
    for decision in decisions:
        kind = str(decision["kind"])
        subject_id = str(decision["subject_id"])
        if kind == "finding":
            update_item_review(
                updated,
                subject_id,
                {
                    "disposition": str(decision["decision"]),
                    "disposition_rationale": str(decision["rationale"]),
                    "reviewer": str(decision["reviewer"]),
                    "status": "in_review",
                },
            )
            finding_count += 1
        elif kind == "consolidation":
            if str(decision["decision"]) == "consolidate":
                _apply_finding_consolidation(updated, workspace, decision)
                consolidation_count += 1
            governance_count += 1
        else:
            governance_count += 1
        applied_records.append(
            {
                "decision_id": str(decision["id"]),
                "kind": kind,
                "subject_id": subject_id,
            }
        )
    activation = updated.setdefault("activation", {})
    history = activation.setdefault("decision_history", [])
    known = {
        str(entry.get("decision_id", ""))
        for entry in history
        if isinstance(entry, dict)
    }
    for decision in decisions:
        if str(decision["id"]) not in known:
            history.append(copy.deepcopy(decision))
    activation["last_workspace_sha256"] = str(workspace.get("content_sha256", ""))
    activation["last_applied_at"] = utc_now()
    activation["authority"] = (
        "review_history_non_finding_decisions_do_not_modify_rules_claim_compliance_or_approve_risk"
    )
    receipt: dict[str, Any] = {
        "format": ACTIVATION_APPLY_RECEIPT_FORMAT,
        "status": "applied",
        "source_analysis_state_sha256": _analysis_binding(analysis)[
            "analysis_state_sha256"
        ],
        "workspace_sha256": str(workspace.get("content_sha256", "")),
        "result_analysis_state_sha256": canonical_json_sha256(updated),
        "finding_reviews_applied": finding_count,
        "finding_consolidations_applied": consolidation_count,
        "governance_decisions_recorded": governance_count,
        "applied_records": applied_records,
        "notice": "Applied records remain subject to analysis validation, evidence review, and named approval gates.",
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return updated, receipt


def load_activation_workspace(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="activation workspace",
        max_bytes=MAX_ACTIVATION_BYTES,
        max_depth=MAX_ACTIVATION_DEPTH,
        max_nodes=MAX_ACTIVATION_NODES,
    )
    if not isinstance(document.value, dict):
        raise ValueError("activation workspace root must be an object")
    return document.value
