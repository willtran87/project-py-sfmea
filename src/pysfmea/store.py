"""Persistence, rescan merging, and reviewer update validation."""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
import stat
import tempfile
import uuid
from datetime import date
from pathlib import Path
from typing import Any

from .adapters import build_adapter_run_ledger
from .assurance import (
    ASSURANCE_STATUSES,
    EVIDENCE_STATUSES,
    IMPLEMENTATION_STATUSES,
    VERIFICATION_METHODS,
    ensure_assurance_register,
    refresh_assurance_register,
)
from .config import DEFAULT_CONFIG, normalize_config
from .execution import EXECUTION_STATUSES
from .guidance import ensure_guidance_traceability
from .integrity import (
    MAX_GOVERNED_JSON_DEPTH,
    bounded_json_structure_metrics,
)
from .manifest import create_run_manifest
from .model import SCHEMA_VERSION, calculate_rpn, empty_review, utc_now, validate_rating
from .repository_inventory import legacy_repository_inventory
from .sfta import build_sfta
from .system_context import build_system_context
from .version import __version__

MAX_ANALYSIS_BYTES = 200_000_000
MAX_ANALYSIS_JSON_DEPTH = MAX_GOVERNED_JSON_DEPTH
# Analyses contain several independently reconciled per-finding projections
# (review records, assurance obligations, diagrams, and flow models). Keep an
# analysis-specific ceiling above the generic governed-document limit so a
# substantial Python monorepo can remain one complete, reviewable artifact.
MAX_ANALYSIS_JSON_NODES = 5_000_000
ANALYSIS_GZIP_COMPRESSION_LEVEL = 6

EDITABLE_REVIEW_FIELDS = {
    "disposition",
    "disposition_rationale",
    "status",
    "requirement",
    "linked_hazards",
    "function",
    "failure_mode",
    "trigger",
    "operational_mode",
    "operational_state",
    "required_safe_state",
    "degraded_behavior",
    "recovery_behavior",
    "causes",
    "local_effect",
    "next_higher_effect",
    "end_effect",
    "severity",
    "severity_category",
    "severity_rationale",
    "occurrence",
    "occurrence_rationale",
    "detection",
    "detection_rationale",
    "prevention_controls",
    "detection_controls",
    "recommended_actions",
    "actions_taken",
    "verification_evidence",
    "post_action_severity",
    "post_action_severity_category",
    "post_action_severity_rationale",
    "post_action_occurrence",
    "post_action_occurrence_rationale",
    "post_action_detection",
    "post_action_detection_rationale",
    "residual_risk",
    "owner",
    "target_date",
    "approved_by",
    "approval_date",
    "reviewer",
    "revalidation_required",
    "notes",
}


class AnalysisRevisionConflictError(RuntimeError):
    """The governed analysis changed before an atomic replacement."""


def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
    common = bool(
        os.path.samestat(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
    )
    # Windows path and descriptor stat calls can expose different creation-time
    # precision for the same file. Identity, size, and modification time remain
    # comparable; POSIX retains the additional metadata-change-time check.
    return common and (os.name == "nt" or first.st_ctime_ns == second.st_ctime_ns)


def _input_path(path: str | Path) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _inspect_regular_file(path: Path, label: str) -> os.stat_result:
    if path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    try:
        inspected = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{label} is unavailable") from exc
    except PermissionError as exc:
        raise PermissionError(f"{label} could not be read safely") from exc
    except OSError as exc:
        raise OSError(f"{label} could not be read safely") from exc
    if not stat.S_ISREG(inspected.st_mode):
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    return inspected


def _read_analysis_bytes(path: Path) -> bytes:
    inspected = _inspect_regular_file(path, "analysis input")
    descriptor: int | None = None
    opened_before: os.stat_result | None = None
    opened_after: os.stat_result | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_file_state(
            inspected, opened_before
        ):
            raise ValueError("analysis input changed during safe open")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(MAX_ANALYSIS_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
    except ValueError:
        raise
    except FileNotFoundError as exc:
        raise FileNotFoundError("analysis input is unavailable") from exc
    except PermissionError as exc:
        raise PermissionError("analysis input could not be read safely") from exc
    except OSError as exc:
        raise OSError("analysis input could not be read safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(raw) > MAX_ANALYSIS_BYTES:
        raise ValueError(
            f"analysis input exceeds the {MAX_ANALYSIS_BYTES}-byte import limit"
        )
    if (
        opened_before is None
        or opened_after is None
        or not _same_file_state(opened_before, opened_after)
    ):
        raise ValueError("analysis input changed while it was being read")
    try:
        current = path.lstat()
    except OSError as exc:
        raise ValueError("analysis input changed while it was being read") from exc
    if not _same_file_state(opened_after, current):
        raise ValueError("analysis input changed while it was being read")
    if raw.startswith(b"\x1f\x8b"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as compressed:
                expanded = compressed.read(MAX_ANALYSIS_BYTES + 1)
        except (EOFError, OSError) as exc:
            raise ValueError("analysis input is not a valid gzip stream") from exc
        if len(expanded) > MAX_ANALYSIS_BYTES:
            raise ValueError(
                f"expanded analysis exceeds the {MAX_ANALYSIS_BYTES}-byte import limit"
            )
        raw = expanded
    return raw


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError(f"analysis JSON contains a duplicate object key: {key}")
        value[key] = entry
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"analysis JSON contains a non-finite number: {value}")


def _enforce_analysis_json_shape(value: Any) -> None:
    metrics = bounded_json_structure_metrics(
        value,
        max_depth=MAX_ANALYSIS_JSON_DEPTH,
        max_nodes=MAX_ANALYSIS_JSON_NODES,
    )
    if not metrics["depth_within_limit"]:
        raise ValueError(
            f"analysis JSON exceeds the {MAX_ANALYSIS_JSON_DEPTH}-level depth limit"
        )
    if not metrics["node_within_limit"]:
        raise ValueError(
            f"analysis JSON exceeds the {MAX_ANALYSIS_JSON_NODES}-node limit"
        )


def _decode_analysis_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("analysis input is not valid bounded UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("analysis file root must be a JSON object")
    _enforce_analysis_json_shape(value)
    return value


def analysis_file_sha256(path: str | Path) -> str:
    """Hash one stable regular analysis file under the persisted-analysis limit."""

    source = _input_path(path)
    inspected = _inspect_regular_file(source, "analysis input")
    descriptor: int | None = None
    digest = hashlib.sha256()
    consumed = 0
    opened_before: os.stat_result | None = None
    opened_after: os.stat_result | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_file_state(
            inspected, opened_before
        ):
            raise ValueError("analysis input changed during safe open")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            while chunk := handle.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > MAX_ANALYSIS_BYTES:
                    raise ValueError(
                        "analysis input exceeds the "
                        f"{MAX_ANALYSIS_BYTES}-byte hash limit"
                    )
                digest.update(chunk)
            opened_after = os.fstat(handle.fileno())
    except ValueError:
        raise
    except FileNotFoundError as exc:
        raise FileNotFoundError("analysis input is unavailable") from exc
    except PermissionError as exc:
        raise PermissionError("analysis input could not be hashed safely") from exc
    except OSError as exc:
        raise OSError("analysis input could not be hashed safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        opened_before is None
        or opened_after is None
        or not _same_file_state(opened_before, opened_after)
    ):
        raise ValueError("analysis input changed while it was being hashed")
    try:
        current = source.lstat()
    except OSError as exc:
        raise ValueError("analysis input changed while it was being hashed") from exc
    if not _same_file_state(opened_after, current):
        raise ValueError("analysis input changed while it was being hashed")
    return digest.hexdigest()


LIST_FIELDS = {
    "causes",
    "prevention_controls",
    "detection_controls",
    "recommended_actions",
    "actions_taken",
    "verification_evidence",
    "linked_hazards",
}
RATING_FIELDS = {
    "severity",
    "occurrence",
    "detection",
    "post_action_severity",
    "post_action_occurrence",
    "post_action_detection",
}
DATE_FIELDS = {"target_date", "approval_date"}
ALLOWED_DISPOSITIONS = {"unreviewed", "accepted", "rejected", "needs_information"}
ALLOWED_STATUSES = {"draft", "in_review", "action_required", "verified", "closed"}


def load_analysis(path: str | Path) -> dict[str, Any]:
    source = _input_path(path)
    analysis = _decode_analysis_object(_read_analysis_bytes(source))
    if analysis.get("schema_version") == "0.1":
        analysis = _migrate_01_to_02(analysis)
    if analysis.get("schema_version") == "0.2":
        analysis = _migrate_02_to_03(analysis)
    if analysis.get("schema_version") == "0.3":
        analysis = _migrate_03_to_04(analysis)
    if analysis.get("schema_version") == "0.4":
        analysis = _migrate_04_to_05(analysis)
    if analysis.get("schema_version") == "0.5":
        analysis = _migrate_05_to_06(analysis)
    if analysis.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema version {analysis.get('schema_version')!r}; expected {SCHEMA_VERSION!r}"
        )
    analysis.setdefault(
        "generator",
        {
            "name": "PySFMEA",
            "version": "unknown",
            "analysis_schema_version": analysis["schema_version"],
            "loaded_by_version": __version__,
        },
    )
    ensure_guidance_traceability(analysis)
    ensure_assurance_register(analysis)
    analysis.setdefault("context", {}).setdefault("fault_trees", [])
    sfta = analysis.get("sfta")
    if (
        not isinstance(sfta, dict)
        or not isinstance(sfta.get("trees"), list)
        or not isinstance(sfta.get("reconciliation"), dict)
    ):
        analysis["sfta"] = build_sfta(analysis)
    if "run_manifest" not in analysis:
        analysis["run_manifest"] = create_run_manifest(analysis)
    _validate_analysis_structure(analysis)
    return analysis


def _validate_analysis_structure(analysis: dict[str, Any]) -> None:
    """Reject malformed persisted records before review or export code consumes them."""

    for field in ("items", "components"):
        if not isinstance(analysis.get(field), list):
            raise ValueError(f"analysis file has no {field} list")
    for field in ("history", "warnings"):
        if field in analysis and not isinstance(analysis[field], list):
            raise ValueError(f"analysis {field} must be a list")
    for field in ("suggestions", "generated_summaries"):
        if not isinstance(analysis.get(field, []), list):
            raise ValueError(f"analysis {field} must be a list")
    assurance = analysis.get("assurance", {})
    if not isinstance(assurance, dict) or not isinstance(
        assurance.get("obligations", []), list
    ):
        raise ValueError("analysis assurance register must contain an obligations list")
    for field in ("executions", "evidence_artifacts"):
        if not isinstance(assurance.get(field, []), list) or not all(
            isinstance(value, dict) for value in assurance.get(field, [])
        ):
            raise ValueError(f"analysis assurance.{field} must be a list of objects")
    execution_ids: set[str] = set()
    for index, execution in enumerate(assurance.get("executions", []), start=1):
        execution_id = execution.get("id", "")
        if not isinstance(execution_id, str) or not execution_id:
            raise ValueError(f"analysis assurance execution {index} requires an ID")
        if execution_id in execution_ids:
            raise ValueError(f"analysis assurance execution ID is duplicated: {execution_id}")
        execution_ids.add(execution_id)
        if execution.get("status") not in EXECUTION_STATUSES:
            raise ValueError(f"analysis assurance execution {index} has an invalid status")
        for field in ("command_argv", "test_command_argv", "artifacts", "reviews"):
            if not isinstance(execution.get(field, []), list):
                raise ValueError(
                    f"analysis assurance execution {index} {field} must be a list"
                )
    artifact_ids: set[str] = set()
    for index, artifact in enumerate(
        assurance.get("evidence_artifacts", []), start=1
    ):
        artifact_id = artifact.get("id", "")
        if not isinstance(artifact_id, str) or not artifact_id:
            raise ValueError(f"analysis evidence artifact {index} requires an ID")
        if artifact_id in artifact_ids:
            raise ValueError(f"analysis evidence artifact ID is duplicated: {artifact_id}")
        artifact_ids.add(artifact_id)
    obligation_ids: set[str] = set()
    for index, obligation in enumerate(assurance.get("obligations", []), start=1):
        if not isinstance(obligation, dict):
            raise ValueError(f"analysis assurance obligation {index} must be an object")
        obligation_id = obligation.get("id", "")
        if not isinstance(obligation_id, str) or not obligation_id:
            raise ValueError(f"analysis assurance obligation {index} requires an ID")
        if obligation_id in obligation_ids:
            raise ValueError(f"analysis assurance obligation ID is duplicated: {obligation_id}")
        obligation_ids.add(obligation_id)
        if obligation.get("assurance_status") not in ASSURANCE_STATUSES:
            raise ValueError(f"analysis assurance obligation {index} has an invalid status")
        if obligation.get("evidence_status") not in EVIDENCE_STATUSES:
            raise ValueError(f"analysis assurance obligation {index} has an invalid evidence status")
        if obligation.get("verification_method") not in VERIFICATION_METHODS:
            raise ValueError(f"analysis assurance obligation {index} has an invalid method")
        automation = obligation.get("automation", {})
        if not isinstance(automation, dict) or automation.get(
            "implementation_status"
        ) not in IMPLEMENTATION_STATUSES:
            raise ValueError(
                f"analysis assurance obligation {index} has invalid automation metadata"
            )
        for field in (
            "preconditions",
            "oracles",
            "acceptance_criteria",
            "required_environment",
            "evidence_requirements",
            "evidence_artifact_ids",
            "executions",
            "planning_gaps",
            "citation_ids",
            "history",
        ):
            if not isinstance(obligation.get(field, []), list):
                raise ValueError(
                    f"analysis assurance obligation {index} {field} must be a list"
                )
        if not all(
            isinstance(value, str) and value in execution_ids
            for value in obligation.get("executions", [])
        ):
            raise ValueError(
                f"analysis assurance obligation {index} references an unknown execution"
            )
        if not all(
            isinstance(value, str) and value in artifact_ids
            for value in obligation.get("evidence_artifact_ids", [])
        ):
            raise ValueError(
                f"analysis assurance obligation {index} references an unknown evidence artifact"
            )
    generator = analysis.get("generator", {})
    if not isinstance(generator, dict) or not all(
        isinstance(generator.get(field, ""), str)
        for field in ("name", "version", "analysis_schema_version")
    ):
        raise ValueError("analysis generator provenance must contain string fields")
    runtime_evidence = analysis.get("runtime_evidence", {})
    if not isinstance(runtime_evidence, dict) or any(
        not isinstance(runtime_evidence.get(field, []), list)
        for field in ("imports", "spans", "edges")
    ):
        raise ValueError("analysis runtime_evidence must contain list-valued imports, spans, and edges")
    sfta = analysis.get("sfta", {})
    if not isinstance(sfta, dict) or not isinstance(sfta.get("trees", []), list):
        raise ValueError("analysis sfta must contain a trees list")
    run_manifest = analysis.get("run_manifest", {})
    if (
        not isinstance(run_manifest, dict)
        or run_manifest.get("schema_version") != "pysfmea-run-manifest-1"
        or not isinstance(run_manifest.get("adapters", {}).get("adapters", []), list)
        or not run_manifest.get("manifest_sha256")
    ):
        raise ValueError("analysis run_manifest is missing required reproducibility fields")
    system_context = analysis.get("system_context", {})
    if (
        not isinstance(system_context, dict)
        or system_context.get("schema_version") != "pysfmea-system-context-1"
        or not isinstance(system_context.get("fields", []), list)
        or not isinstance(system_context.get("unresolved_questions", []), list)
    ):
        raise ValueError("analysis system_context is missing required context fields")
    inventory = analysis.get("repository_inventory", {})
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema_version") != "pysfmea-repository-inventory-1"
        or not isinstance(inventory.get("entries", []), list)
        or not isinstance(inventory.get("regions", []), list)
        or not inventory.get("inventory_sha256")
    ):
        raise ValueError("analysis repository_inventory is missing required coverage fields")
    adapter_runs = analysis.get("adapter_runs", {})
    if (
        not isinstance(adapter_runs, dict)
        or adapter_runs.get("schema_version") != "pysfmea-adapter-run-ledger-1"
        or not isinstance(adapter_runs.get("runs", []), list)
        or not adapter_runs.get("ledger_sha256")
    ):
        raise ValueError("analysis adapter_runs is missing required provenance fields")
    for index, suggestion in enumerate(analysis.get("suggestions", []), start=1):
        if not isinstance(suggestion, dict):
            raise ValueError(f"analysis suggestion {index} must be an object")
        if suggestion.get("status") not in {"proposed", "accepted", "rejected", "stale"}:
            raise ValueError(f"analysis suggestion {index} has an invalid status")
        if not isinstance(suggestion.get("content", {}), dict) or not isinstance(
            suggestion.get("provenance", {}), dict
        ):
            raise ValueError(f"analysis suggestion {index} content and provenance must be objects")
        for field in (
            "evidence_ids",
            "proposed_citation_ids",
            "uncertainties",
            "questions",
            "history",
        ):
            if not isinstance(suggestion.get(field, []), list):
                raise ValueError(f"analysis suggestion {index} {field} must be a list")
        if not isinstance(suggestion.get("id", ""), str) or not suggestion.get("id"):
            raise ValueError(f"analysis suggestion {index} requires an ID")
    for collection in ("spans", "edges", "imports"):
        if not all(isinstance(value, dict) for value in runtime_evidence.get(collection, [])):
            raise ValueError(f"analysis runtime_evidence.{collection} entries must be objects")
    context = analysis.get("context", {})
    if not isinstance(context, dict):
        raise ValueError("analysis context must be an object")
    contracts = context.get("contracts", [])
    if not isinstance(contracts, list) or not all(
        isinstance(contract, dict) for contract in contracts
    ):
        raise ValueError("analysis context.contracts must be a list of objects")
    normalize_config(
        {field: context[field] for field in DEFAULT_CONFIG if field in context}
    )
    for index, item in enumerate(analysis["items"], start=1):
        if not isinstance(item, dict):
            raise ValueError(f"analysis item {index} must be an object")
        for field in ("source", "component", "scanner", "review"):
            if not isinstance(item.get(field), dict):
                raise ValueError(f"analysis item {index} {field} must be an object")
        for field in ("evidence", "screening_reasons"):
            value = item["scanner"].get(field, [])
            if not isinstance(value, list) or not all(
                isinstance(entry, str) for entry in value
            ):
                raise ValueError(f"analysis item {index} scanner.{field} must be a string list")
        citations = item["scanner"].get("citations", [])
        if not isinstance(citations, list) or not all(
            isinstance(entry, dict) for entry in citations
        ):
            raise ValueError(
                f"analysis item {index} scanner.citations must be a list of objects"
            )
        adapter_ids = item["scanner"].get("adapter_ids", [])
        if not isinstance(adapter_ids, list) or not all(
            isinstance(entry, str) and entry for entry in adapter_ids
        ):
            raise ValueError(
                f"analysis item {index} scanner.adapter_ids must be a non-empty string list"
            )
        if not isinstance(item.get("review_history", []), list):
            raise ValueError(f"analysis item {index} review_history must be a list")
        review = item["review"]
        for field in LIST_FIELDS:
            value = review.get(field, [])
            if not isinstance(value, list) or not all(
                isinstance(entry, str) for entry in value
            ):
                raise ValueError(f"analysis item {index} review.{field} must be a string list")
        for field in RATING_FIELDS:
            try:
                validate_rating(review.get(field))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"analysis item {index} review.{field} is invalid") from exc
        if not isinstance(review.get("revalidation_required", False), bool):
            raise ValueError(
                f"analysis item {index} review.revalidation_required must be boolean"
            )
        for field in EDITABLE_REVIEW_FIELDS - LIST_FIELDS - RATING_FIELDS - {
            "revalidation_required"
        }:
            if field in review and not isinstance(review[field], str):
                raise ValueError(f"analysis item {index} review.{field} must be a string")
        for history_index, event in enumerate(item.get("review_history", []), start=1):
            if not isinstance(event, dict) or not isinstance(event.get("changes", {}), dict):
                raise ValueError(
                    f"analysis item {index} review_history entry {history_index} is invalid"
                )
            for change in event.get("changes", {}).values():
                if not isinstance(change, dict):
                    raise ValueError(
                        f"analysis item {index} review_history entry {history_index} "
                        "contains an invalid field change"
                    )


def _migrate_01_to_02(analysis: dict[str, Any]) -> dict[str, Any]:
    """Add 0.2 review fields without changing existing decisions."""

    defaults = empty_review()
    for item in analysis.get("items", []):
        review = item.setdefault("review", {})
        for key, value in defaults.items():
            if key not in review:
                review[key] = list(value) if isinstance(value, list) else value
        item.setdefault("source_change", "legacy")
        item.setdefault("review_history", [])
    analysis.setdefault("context", {})
    analysis["schema_version"] = "0.2"
    return analysis


def _migrate_02_to_03(analysis: dict[str, Any]) -> dict[str, Any]:
    """Add lifecycle traceability fields introduced with schema 0.3."""

    defaults = empty_review()
    for item in analysis.get("items", []):
        review = item.setdefault("review", {})
        for key, value in defaults.items():
            if key not in review:
                review[key] = list(value) if isinstance(value, list) else value
        item.setdefault("review_history", [])
        scanner = item.setdefault("scanner", {})
        source_fingerprint = scanner.get("source_fingerprint", "")
        scanner.setdefault("content_fingerprint", source_fingerprint)
        scanner.setdefault("context_fingerprint", "")
    context = analysis.setdefault("context", {})
    for field, default in (
        ("analysis", {}),
        ("requirements", []),
        ("fault_trees", []),
        ("component_mappings", []),
        ("system_interfaces", []),
        ("reviewers", []),
        ("dependencies", []),
        ("common_causes", []),
    ):
        context.setdefault(field, default)
    analysis["schema_version"] = "0.3"
    return analysis


def _migrate_03_to_04(analysis: dict[str, Any]) -> dict[str, Any]:
    """Add governed discovery, summary, and runtime-evidence collections."""

    analysis.setdefault("suggestions", [])
    analysis.setdefault("generated_summaries", [])
    analysis.setdefault("runtime_evidence", {"imports": [], "spans": [], "edges": []})
    analysis["sfta"] = build_sfta(analysis)
    if "run_manifest" not in analysis:
        analysis["run_manifest"] = create_run_manifest(analysis)
    analysis.setdefault("context", {}).setdefault("contracts", [])
    for component in analysis.get("components", []):
        component.setdefault("ordered_calls", list(component.get("calls", [])))
        component.setdefault("frameworks", [])
        component.setdefault("entrypoint_types", [])
    analysis["schema_version"] = "0.4"
    return analysis


def _migrate_04_to_05(analysis: dict[str, Any]) -> dict[str, Any]:
    """Add the executable assurance-contract register introduced with schema 0.5."""

    analysis["schema_version"] = "0.5"
    if isinstance(analysis.get("generator"), dict):
        analysis["generator"]["analysis_schema_version"] = "0.5"
    refresh_assurance_register(analysis, {})
    return analysis


def _migrate_05_to_06(analysis: dict[str, Any]) -> dict[str, Any]:
    """Add context, coverage, adapter-run, and safe/recovery review records."""

    defaults = empty_review()
    for item in analysis.get("items", []):
        review = item.setdefault("review", {})
        for key, value in defaults.items():
            if key not in review:
                review[key] = list(value) if isinstance(value, list) else value
    context = analysis.setdefault("context", {})
    analysis.setdefault("system_context", build_system_context(context))
    analysis.setdefault(
        "repository_inventory",
        legacy_repository_inventory(
            "Repository artifact coverage was not captured by the original pre-0.6 scan; "
            "rescan to establish analyzed, excluded, unresolved, and opaque regions."
        ),
    )
    refresh_assurance_register(analysis, analysis.get("assurance", {}))
    analysis["sfta"] = build_sfta(analysis)
    analysis["adapter_runs"] = build_adapter_run_ledger(analysis)
    analysis["schema_version"] = "0.6"
    if isinstance(analysis.get("generator"), dict):
        analysis["generator"]["analysis_schema_version"] = "0.6"
    analysis["run_manifest"] = create_run_manifest(analysis)
    return analysis


def _analysis_destination_snapshot(path: Path) -> os.stat_result | None:
    if path.is_symlink():
        raise ValueError("analysis destination must not be a symbolic link")
    try:
        snapshot = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("analysis destination could not be inspected safely") from exc
    if not stat.S_ISREG(snapshot.st_mode):
        raise ValueError("analysis destination must be a regular file path")
    return snapshot


class _BoundedUtf8Writer:
    def __init__(self, handle: Any, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.written = 0

    def write(self, value: str) -> int:
        raw = value.encode("utf-8")
        if self.written + len(raw) > self.limit:
            raise ValueError(
                f"serialized analysis exceeds the {self.limit}-byte output limit"
            )
        self.handle.write(raw)
        self.written += len(raw)
        return len(value)


def save_analysis(
    path: str | Path,
    analysis: dict[str, Any],
    *,
    expected_sha256: str | None = None,
    compact: bool = False,
) -> None:
    """Atomically save an analysis to avoid truncation on interrupted writes."""

    destination = _input_path(path)
    destination_snapshot = _analysis_destination_snapshot(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("analysis destination could not be prepared safely") from exc
    ensure_guidance_traceability(analysis, refresh=True)
    refresh_assurance_register(analysis, analysis.get("assurance", {}))
    analysis["sfta"] = build_sfta(analysis)
    refresh_summary(analysis)
    _reconcile_last_saved_at(destination, analysis)
    _enforce_analysis_json_shape(analysis)
    _validate_analysis_structure(analysis)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            compressed_handle: Any = handle
            gzip_stream: gzip.GzipFile | None = None
            if destination.suffix.casefold() == ".gz":
                gzip_stream = gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=ANALYSIS_GZIP_COMPRESSION_LEVEL,
                    fileobj=handle,
                    mtime=0,
                )
                compressed_handle = gzip_stream
            try:
                writer = _BoundedUtf8Writer(compressed_handle, MAX_ANALYSIS_BYTES)
                json.dump(
                    analysis,
                    writer,
                    indent=None if compact else 2,
                    separators=(",", ":") if compact else None,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                writer.write("\n")
            finally:
                if gzip_stream is not None:
                    gzip_stream.close()
            handle.flush()
            os.fsync(handle.fileno())
        if expected_sha256 is not None:
            try:
                current_sha256 = analysis_file_sha256(destination)
            except (OSError, ValueError) as exc:
                raise AnalysisRevisionConflictError(
                    "governed analysis disappeared before atomic replacement"
                ) from exc
            if current_sha256 != expected_sha256:
                raise AnalysisRevisionConflictError(
                    "governed analysis changed before atomic replacement"
                )
        try:
            current_snapshot = _analysis_destination_snapshot(destination)
        except ValueError as exc:
            raise AnalysisRevisionConflictError(
                "governed analysis changed before atomic replacement"
            ) from exc
        if destination_snapshot is None:
            unchanged = current_snapshot is None
        else:
            unchanged = bool(
                current_snapshot is not None
                and _same_file_state(destination_snapshot, current_snapshot)
            )
        if not unchanged:
            raise AnalysisRevisionConflictError(
                "governed analysis changed before atomic replacement"
            )
        os.replace(temp_name, destination)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _without_last_saved_at(analysis: dict[str, Any]) -> dict[str, Any]:
    snapshot = copy.deepcopy(analysis)
    summary = snapshot.get("summary")
    if isinstance(summary, dict):
        summary.pop("last_saved_at", None)
    return snapshot


def _reconcile_last_saved_at(
    destination: Path, analysis: dict[str, Any]
) -> None:
    """Preserve byte identity for no-op saves and advance time for real changes."""

    summary = analysis.setdefault("summary", {})
    if not destination.is_file() or destination.is_symlink():
        summary.setdefault("last_saved_at", utc_now())
        return
    try:
        previous = _decode_analysis_object(_read_analysis_bytes(destination))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        summary["last_saved_at"] = utc_now()
        return
    previous_summary = previous.get("summary", {})
    previous_saved_at = (
        previous_summary.get("last_saved_at")
        if isinstance(previous_summary, dict)
        else None
    )
    if (
        isinstance(previous_saved_at, str)
        and previous_saved_at
        and _without_last_saved_at(previous) == _without_last_saved_at(analysis)
    ):
        summary["last_saved_at"] = previous_saved_at
    else:
        summary["last_saved_at"] = utc_now()


def merge_rescan(previous: dict[str, Any], scanned: dict[str, Any]) -> dict[str, Any]:
    """Preserve human review fields while refreshing scanner-owned evidence."""

    old_by_id = {item["id"]: item for item in previous.get("items", [])}
    old_by_fingerprint: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for old_item in previous.get("items", []):
        if old_item.get("source_status", "active") != "active":
            continue
        key = (
            old_item.get("scanner", {}).get("content_fingerprint")
            or old_item.get("scanner", {}).get("source_fingerprint", ""),
            old_item.get("scanner", {}).get("rule_id", ""),
        )
        if all(key) and key[1] != "manual":
            old_by_fingerprint.setdefault(key, []).append(old_item)
    new_key_counts: dict[tuple[str, str], int] = {}
    for item in scanned.get("items", []):
        key = (
            item.get("scanner", {}).get("content_fingerprint")
            or item.get("scanner", {}).get("source_fingerprint", ""),
            item.get("scanner", {}).get("rule_id", ""),
        )
        new_key_counts[key] = new_key_counts.get(key, 0) + 1
    active_ids: set[str] = set()
    matched_old_ids: set[str] = set()
    merged_items: list[dict[str, Any]] = []
    change_counts = {
        "new": 0,
        "changed": 0,
        "moved": 0,
        "impacted": 0,
        "unchanged": 0,
        "removed": 0,
        "manual": 0,
    }
    for item in scanned.get("items", []):
        item_id = item["id"]
        active_ids.add(item_id)
        old_item = old_by_id.get(item_id)
        moved = False
        if old_item is None:
            key = (
                item.get("scanner", {}).get("content_fingerprint")
                or item.get("scanner", {}).get("source_fingerprint", ""),
                item.get("scanner", {}).get("rule_id", ""),
            )
            candidates = old_by_fingerprint.get(key, [])
            if len(candidates) == 1 and new_key_counts.get(key) == 1:
                old_item = candidates[0]
                moved = True
                matched_old_ids.add(old_item["id"])
        if old_item and isinstance(old_item.get("review"), dict):
            item["review"] = dict(old_item["review"])
            item["review_history"] = list(old_item.get("review_history", []))
            old_fingerprint = old_item.get("scanner", {}).get("source_fingerprint", "")
            new_fingerprint = item.get("scanner", {}).get("source_fingerprint", "")
            old_context = old_item.get("scanner", {}).get("context_fingerprint", "")
            new_context = item.get("scanner", {}).get("context_fingerprint", "")
            old_analysis_context = old_item.get("scanner", {}).get(
                "analysis_context_fingerprint", ""
            )
            new_analysis_context = item.get("scanner", {}).get(
                "analysis_context_fingerprint", ""
            )
            source_changed = bool(
                old_fingerprint and new_fingerprint and old_fingerprint != new_fingerprint
            )
            context_changed = bool(old_context and new_context and old_context != new_context)
            analysis_context_changed = bool(
                old_analysis_context
                and new_analysis_context
                and old_analysis_context != new_analysis_context
            )
            item["change_reasons"] = [
                reason
                for changed, reason in (
                    (source_changed, "function implementation changed"),
                    (context_changed, "module or class context changed"),
                    (analysis_context_changed, "SFMEA project context changed"),
                    (moved, "component moved or was renamed"),
                )
                if changed
            ]
            if moved:
                item["source_change"] = "moved"
            elif source_changed or context_changed or analysis_context_changed:
                item["source_change"] = "changed"
            else:
                item["source_change"] = "unchanged"
            if moved:
                item["previous_ids"] = [
                    *old_item.get("previous_ids", []),
                    old_item["id"],
                ]
            if (
                source_changed or context_changed or analysis_context_changed or moved
            ) and _has_material_review(item["review"]):
                _mark_revalidation(
                    item,
                    scanned["project"]["scanned_at"],
                    item["change_reasons"],
                )
            change_counts[item["source_change"]] += 1
        else:
            item["source_change"] = "new"
            item["review_history"] = []
            change_counts["new"] += 1
        merged_items.append(item)

    changed_references = {
        _item_reference(item)
        for item in merged_items
        if item.get("source_change") in {"changed", "moved"}
    }
    changed_dependency_baseline = any(
        item.get("source_change") == "changed"
        and item.get("scanner", {}).get("rule_id") == "environment.dependency_drift"
        for item in merged_items
    )
    impacted_reasons: dict[str, set[str]] = {}
    for component in scanned.get("components", []):
        component_reference = (
            f"{component.get('source', {}).get('path', '')}:"
            f"{component.get('qualname', '')}"
        )
        if component_reference not in changed_references:
            continue
        upstream = set(component.get("called_by", []))
        for path in component.get("upstream_paths", []):
            upstream.update(path[:-1])
        for reference in upstream:
            impacted_reasons.setdefault(reference, set()).add(component_reference)

    for item in merged_items:
        if item.get("source_change") != "unchanged":
            continue
        reference = _item_reference(item)
        dependencies = impacted_reasons.get(reference, set())
        if not dependencies and not changed_dependency_baseline:
            continue
        item["source_change"] = "impacted"
        item["change_reasons"] = [
            *(f"called component changed: {value}" for value in sorted(dependencies)),
            *(["declared dependency baseline changed"] if changed_dependency_baseline else []),
        ]
        change_counts["unchanged"] -= 1
        change_counts["impacted"] += 1
        if _has_material_review(item.get("review", {})):
            _mark_revalidation(
                item,
                scanned["project"]["scanned_at"],
                item["change_reasons"],
            )

    for old_item in previous.get("items", []):
        if old_item.get("id") in active_ids or old_item.get("id") in matched_old_ids:
            continue
        if old_item.get("scanner", {}).get("rule_id") in {"manual", "machine_suggestion"}:
            merged_items.append(old_item)
            change_counts["manual"] += 1
            continue
        retired = dict(old_item)
        retired["review"] = dict(old_item.get("review", {}))
        retired["review_history"] = list(old_item.get("review_history", []))
        retired["source_status"] = "removed"
        retired["source_change"] = "removed"
        if _has_material_review(retired.get("review", {})):
            _mark_revalidation(
                retired,
                scanned["project"]["scanned_at"],
                ["source-backed candidate was removed"],
            )
        retired["removed_at"] = scanned["project"]["scanned_at"]
        merged_items.append(retired)
        change_counts["removed"] += 1

    scanned["items"] = merged_items
    previous_baseline_id = previous.get("project", {}).get("baseline", {}).get("id", "")
    current_baseline_id = scanned.get("project", {}).get("baseline", {}).get("id", "")
    scanned["suggestions"] = []
    for old_suggestion in previous.get("suggestions", []):
        suggestion = dict(old_suggestion)
        suggestion["history"] = list(old_suggestion.get("history", []))
        if (
            suggestion.get("status") == "proposed"
            and previous_baseline_id != current_baseline_id
        ):
            suggestion["status"] = "stale"
            suggestion["history"].append(
                {
                    "event": "baseline_invalidated",
                    "at": scanned["project"]["scanned_at"],
                    "previous_baseline_id": previous_baseline_id,
                    "baseline_id": current_baseline_id,
                }
            )
        scanned["suggestions"].append(suggestion)
    scanned["generated_summaries"] = [
        {**summary, "stale": summary.get("baseline_id") != current_baseline_id}
        for summary in previous.get("generated_summaries", [])
    ]
    scanned["runtime_evidence"] = previous.get(
        "runtime_evidence", {"imports": [], "spans": [], "edges": []}
    )
    scanned["history"] = list(previous.get("history", []))
    scanned["history"].append(
        {
            "event": "rescan",
            "at": scanned["project"]["scanned_at"],
            "previous_candidate_count": len(previous.get("items", [])),
            "active_candidate_count": len(active_ids),
            "removed_candidate_count": change_counts["removed"],
            "changes": change_counts,
            "previous_baseline_id": previous.get("project", {})
            .get("baseline", {})
            .get("id", ""),
            "baseline_id": scanned.get("project", {}).get("baseline", {}).get("id", ""),
        }
    )
    refresh_assurance_register(scanned, previous.get("assurance", {}))
    scanned["sfta"] = build_sfta(scanned)
    refresh_summary(scanned)
    return scanned


def _has_material_review(review: dict[str, Any]) -> bool:
    return bool(
        review.get("reviewed_at")
        or review.get("disposition") != "unreviewed"
        or review.get("status") != "draft"
        or review.get("requirement")
        or review.get("next_higher_effect")
        or review.get("prevention_controls")
        or review.get("detection_controls")
        or review.get("actions_taken")
        or review.get("verification_evidence")
        or review.get("post_action_severity") is not None
        or review.get("post_action_occurrence") is not None
        or review.get("post_action_detection") is not None
        or review.get("owner")
        or review.get("approved_by")
        or review.get("notes")
    )


def _item_reference(item: dict[str, Any]) -> str:
    return (
        f"{item.get('source', {}).get('path', '')}:"
        f"{item.get('component', {}).get('qualname', '')}"
    )


def _mark_revalidation(item: dict[str, Any], at: str, reasons: list[str]) -> None:
    review = item.setdefault("review", {})
    if review.get("revalidation_required"):
        return
    review["revalidation_required"] = True
    item.setdefault("review_history", []).append(
        {
            "event": "source_change_revalidation_required",
            "at": at,
            "reviewer": "system",
            "changes": {
                "revalidation_required": {"before": False, "after": True},
            },
            "reasons": list(reasons),
        }
    )


def update_item_review(
    analysis: dict[str, Any], item_id: str, changes: dict[str, Any]
) -> dict[str, Any]:
    items = analysis.get("items", [])
    if not isinstance(items, list):
        raise ValueError("analysis items must be an array")
    item = next(
        (
            entry
            for entry in items
            if isinstance(entry, dict) and entry.get("id") == item_id
        ),
        None,
    )
    if item is None:
        raise KeyError(item_id)
    unknown = set(changes) - EDITABLE_REVIEW_FIELDS
    if unknown:
        raise ValueError("unsupported review field(s): " + ", ".join(sorted(unknown)))

    normalized: dict[str, Any] = {}
    for key, value in changes.items():
        if key in RATING_FIELDS:
            normalized[key] = validate_rating(value)
        elif key in LIST_FIELDS:
            if isinstance(value, str):
                value = [line.strip() for line in value.splitlines() if line.strip()]
            if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
                raise ValueError(f"{key} must be a list of strings")
            normalized[key] = [entry.strip() for entry in value if entry.strip()]
        elif key == "disposition":
            if value not in ALLOWED_DISPOSITIONS:
                raise ValueError(f"invalid disposition: {value!r}")
            normalized[key] = value
        elif key == "status":
            if value not in ALLOWED_STATUSES:
                raise ValueError(f"invalid status: {value!r}")
            normalized[key] = value
        elif key == "revalidation_required":
            if not isinstance(value, bool):
                raise ValueError("revalidation_required must be a boolean")
            normalized[key] = value
        elif key in DATE_FIELDS:
            if not isinstance(value, str):
                raise ValueError(f"{key} must be an ISO date string")
            value = value.strip()
            if value:
                try:
                    date.fromisoformat(value)
                except ValueError as exc:
                    raise ValueError(f"{key} must use YYYY-MM-DD") from exc
            normalized[key] = value
        elif not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        else:
            normalized[key] = value.strip()

    if "linked_hazards" in normalized:
        context = analysis.get("context", {})
        known_hazards = {
            hazard.get("id")
            for hazard in context.get("hazards", [])
            if isinstance(hazard, dict) and hazard.get("id")
        }
        if "hazards" in context:
            unknown_hazards = set(normalized["linked_hazards"]) - known_hazards
            if unknown_hazards:
                raise ValueError(
                    "unknown linked hazard ID(s): " + ", ".join(sorted(unknown_hazards))
                )
    for category_field in ("severity_category", "post_action_severity_category"):
        category = normalized.get(category_field)
        if category:
            categories = set(
                analysis.get("context", {}).get("risk", {}).get("severity_categories", [])
            )
            if category not in categories:
                raise ValueError(
                    f"{category_field} is not in the configured risk.severity_categories"
                )

    item.setdefault("review", {})
    changed_fields = {
        key: {"before": item["review"].get(key), "after": value}
        for key, value in normalized.items()
        if item["review"].get(key) != value
    }
    closure_sensitive_fields = {
        "disposition",
        "disposition_rationale",
        "requirement",
        "linked_hazards",
        "function",
        "failure_mode",
        "trigger",
        "operational_mode",
        "operational_state",
        "required_safe_state",
        "degraded_behavior",
        "recovery_behavior",
        "causes",
        "local_effect",
        "next_higher_effect",
        "end_effect",
        "severity",
        "severity_category",
        "severity_rationale",
        "occurrence",
        "occurrence_rationale",
        "detection",
        "detection_rationale",
        "prevention_controls",
        "detection_controls",
        "recommended_actions",
        "actions_taken",
        "verification_evidence",
        "post_action_severity",
        "post_action_severity_category",
        "post_action_severity_rationale",
        "post_action_occurrence",
        "post_action_occurrence_rationale",
        "post_action_detection",
        "post_action_detection_rationale",
        "residual_risk",
    }
    if (
        item["review"].get("status") in {"verified", "closed"}
        and closure_sensitive_fields & changed_fields.keys()
    ):
        normalized["status"] = "in_review"
        changed_fields["status"] = {
            "before": item["review"].get("status"),
            "after": "in_review",
        }
    if (
        item["review"].get("approved_by")
        and closure_sensitive_fields & changed_fields.keys()
    ):
        normalized["approved_by"] = ""
        normalized["approval_date"] = ""
        changed_fields["approved_by"] = {
            "before": item["review"].get("approved_by"),
            "after": "",
        }
        changed_fields["approval_date"] = {
            "before": item["review"].get("approval_date"),
            "after": "",
        }
    if not changed_fields:
        refresh_summary(analysis)
        return item
    reviewed_at = utc_now()
    item["review"].update(normalized)
    item["review"]["reviewed_at"] = reviewed_at
    if not item["review"].get("revalidation_required"):
        scanner = item.get("scanner", {})
        item["review"]["validated_fingerprint"] = scanner.get("source_fingerprint", "")
        item["review"]["validated_context_fingerprint"] = scanner.get(
            "context_fingerprint", ""
        )
        item["review"]["validated_analysis_context_fingerprint"] = scanner.get(
            "analysis_context_fingerprint", ""
        )
        item["review"]["validated_baseline_id"] = (
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        )
        item["review"]["validated_at"] = reviewed_at
    item.setdefault("review_history", []).append(
        {
            "event": "review_update",
            "at": reviewed_at,
            "reviewer": item["review"].get("reviewer") or "unspecified",
            "changes": changed_fields,
        }
    )
    analysis["sfta"] = build_sfta(analysis)
    refresh_assurance_register(analysis, analysis.get("assurance", {}))
    refresh_summary(analysis)
    return item


def add_manual_item(analysis: dict[str, Any], component_id: str | None = None) -> dict[str, Any]:
    component = next(
        (entry for entry in analysis.get("components", []) if entry.get("id") == component_id),
        None,
    )
    review = empty_review()
    review.update(
        {
            "function": (component or {}).get("docstring_summary", ""),
            "failure_mode": "Describe how the function could fail.",
            "trigger": "Describe the initiating condition.",
        }
    )
    item = {
        "id": "SFMEA-MANUAL-" + uuid.uuid4().hex[:12].upper(),
        "component_id": component_id or "",
        "source_status": "active",
        "source_change": "manual",
        "source": (component or {}).get("source", {"path": "", "line": "", "end_line": ""}),
        "component": {
            "kind": (component or {}).get("kind", "manual"),
            "qualname": (component or {}).get("qualname", "Unassigned component"),
            "signature": (component or {}).get("signature", ""),
        },
        "scanner": {
            "rule_id": "manual",
            "failure_class": "manual",
            "guideword": "Reviewer identified",
            "failure_mode": "",
            "trigger": "",
            "confidence": "reviewer",
            "screening_priority": "manual",
            "screening_reasons": [],
            "evidence": ["Manually added by reviewer"],
            "adapter_id": "human.manual_finding",
            "adapter_ids": ["human.manual_finding"],
            "citations": [],
        },
        "review": review,
        "review_history": [
            {
                "event": "manual_item_created",
                "at": utc_now(),
                "reviewer": "unspecified",
                "changes": {},
            }
        ],
    }
    analysis.setdefault("items", []).append(item)
    refresh_summary(analysis)
    return item


def refresh_summary(analysis: dict[str, Any]) -> None:
    summary = analysis.setdefault("summary", {})
    previous_summary = copy.deepcopy(summary)
    items = analysis.get("items", [])
    active = [item for item in items if item.get("source_status", "active") == "active"]
    dispositions = {name: 0 for name in ALLOWED_DISPOSITIONS}
    statuses = {name: 0 for name in ALLOWED_STATUSES}
    rated = 0
    post_action_rated = 0
    for item in active:
        review = item.get("review", {})
        disposition = review.get("disposition", "unreviewed")
        dispositions[disposition] = dispositions.get(disposition, 0) + 1
        status = review.get("status", "draft")
        statuses[status] = statuses.get(status, 0) + 1
        if calculate_rpn(item) is not None:
            rated += 1
        if calculate_rpn(item, post_action=True) is not None:
            post_action_rated += 1
    summary["candidate_failure_modes"] = len(active)
    summary["removed_candidates"] = len(items) - len(active)
    summary["review_dispositions"] = dispositions
    summary["review_statuses"] = statuses
    summary["fully_sod_rated"] = rated
    summary["fully_post_action_sod_rated"] = post_action_rated
    summary["revalidation_required"] = sum(
        1 for item in active if item.get("review", {}).get("revalidation_required")
    )
    source_changes: dict[str, int] = {}
    failure_classes: dict[str, int] = {}
    screening_priorities: dict[str, int] = {}
    subsystems: dict[str, int] = {}
    for item in items:
        change = item.get("source_change", "unknown")
        source_changes[change] = source_changes.get(change, 0) + 1
        if item.get("source_status", "active") != "active":
            continue
        failure_class = item.get("scanner", {}).get("failure_class", "unknown")
        failure_classes[failure_class] = failure_classes.get(failure_class, 0) + 1
        priority = item.get("scanner", {}).get("screening_priority", "unknown")
        screening_priorities[priority] = screening_priorities.get(priority, 0) + 1
        item_subsystems = item.get("component", {}).get("subsystems", []) or ["unmapped"]
        for subsystem in item_subsystems:
            subsystems[subsystem] = subsystems.get(subsystem, 0) + 1
    summary["source_changes"] = source_changes
    summary["failure_classes"] = failure_classes
    summary["screening_priorities"] = screening_priorities
    summary["subsystems"] = subsystems
    suggestion_statuses: dict[str, int] = {}
    for suggestion in analysis.get("suggestions", []):
        status = suggestion.get("status", "unknown")
        suggestion_statuses[status] = suggestion_statuses.get(status, 0) + 1
    summary["suggestions"] = suggestion_statuses
    runtime = analysis.get("runtime_evidence", {})
    imports = runtime.get("imports", [])
    summary["runtime_imports"] = len(imports)
    summary["runtime_spans"] = len(runtime.get("spans", []))
    summary["runtime_mapped_spans"] = sum(
        int(record.get("mapped_span_count", 0)) for record in imports
    )
    summary["runtime_unmapped_spans"] = sum(
        int(record.get("unmapped_span_count", 0)) for record in imports
    )
    assurance = ensure_assurance_register(analysis)
    summary["assurance"] = copy.deepcopy(assurance.get("summary", {}))
    previous_saved_at = previous_summary.get("last_saved_at")
    previous_content = {
        key: value
        for key, value in previous_summary.items()
        if key != "last_saved_at"
    }
    current_content = {
        key: value for key, value in summary.items() if key != "last_saved_at"
    }
    summary["last_saved_at"] = (
        previous_saved_at
        if isinstance(previous_saved_at, str)
        and previous_saved_at
        and previous_content == current_content
        else utc_now()
    )
