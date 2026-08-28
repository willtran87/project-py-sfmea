"""Exact-byte runtime coverage observations for Python repositories.

The importer consumes coverage.py JSON without executing the target repository.
It maps observed lines and branches to the exact PySFMEA analysis, retains tool
and configuration provenance, and reports explicit omissions.  Branch coverage
is never promoted to decision or MC/DC coverage.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .governed_artifact import (
    analysis_binding,
    bounded_text,
    publish_json,
    seal,
    unique_text_list,
    verify_analysis_binding,
    verify_seal,
)
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import utc_now

COVERAGE_OBSERVATION_FORMAT = "pysfmea-runtime-coverage-observation-1"
COVERAGE_OBSERVATION_VERIFICATION_FORMAT = (
    "pysfmea-runtime-coverage-observation-verification-1"
)
MAX_COVERAGE_BYTES = 100 * 1024 * 1024
MAX_FILES = 100_000
MAX_POINTS = 5_000_000


def _digest(value: Any, label: str, *, zero_allowed: bool = False) -> str:
    text = bounded_text(value, label)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    if not zero_allowed and text == "0" * 64:
        raise ValueError(f"{label} must not be a placeholder digest")
    return text


def _rate(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0.0 <= float(value) <= 1.0
    ):
        raise ValueError(f"{label} must be between zero and one")
    return float(value)


def _normalize_path(value: Any) -> str:
    text = bounded_text(value, "coverage source path").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    drive = re.match(r"^[A-Za-z]:/(.*)$", text)
    if drive:
        text = drive.group(1)
    parts = [part for part in PurePosixPath(text).parts if part not in {"", ".", "/"}]
    if any(part == ".." for part in parts):
        raise ValueError("coverage source path must not contain parent traversal")
    return "/".join(parts)


def _int_set(value: Any, label: str) -> set[int]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_POINTS
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 1
            for item in value
        )
    ):
        raise ValueError(f"{label} must be a bounded list of positive line numbers")
    return set(value)


def _branch_set(value: Any, label: str) -> set[tuple[int, int]]:
    if not isinstance(value, list) or len(value) > MAX_POINTS:
        raise ValueError(f"{label} must be a bounded branch list")
    result: set[tuple[int, int]] = set()
    for branch in value:
        if (
            not isinstance(branch, list)
            or len(branch) != 2
            or not isinstance(branch[0], int)
            or isinstance(branch[0], bool)
            or branch[0] < 1
            or not isinstance(branch[1], int)
            or isinstance(branch[1], bool)
        ):
            raise ValueError(f"{label} contains an invalid branch")
        result.add((branch[0], branch[1]))
    return result


def _load_coverage(source: str | Path) -> tuple[BoundedJsonDocument, dict[str, Any]]:
    document = load_bounded_json_document(
        source,
        label="coverage.py JSON",
        max_bytes=MAX_COVERAGE_BYTES,
        max_depth=80,
        max_nodes=8_000_000,
    )
    value = document.value
    if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
        raise ValueError("coverage.py JSON must contain a files object")
    files = value["files"]
    if not files or len(files) > MAX_FILES:
        raise ValueError("coverage.py JSON file population is empty or exceeds the limit")
    meta = value.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("coverage.py JSON must contain metadata")
    version = meta.get("version")
    bounded_text(version, "coverage.py version")
    return document, value


def _coverage_files(value: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    total_points = 0
    normalized_paths: set[str] = set()
    for raw_path, raw in sorted(value["files"].items()):
        path = _normalize_path(raw_path)
        if path in normalized_paths:
            raise ValueError("coverage.py JSON contains paths that normalize identically")
        normalized_paths.add(path)
        if not isinstance(raw, dict):
            raise ValueError(f"coverage record for {path} must be an object")
        executed_lines = _int_set(raw.get("executed_lines", []), f"{path} executed lines")
        missing_lines = _int_set(raw.get("missing_lines", []), f"{path} missing lines")
        if executed_lines & missing_lines:
            raise ValueError(f"coverage record for {path} marks lines both executed and missing")
        executed_branches = _branch_set(
            raw.get("executed_branches", []), f"{path} executed branches"
        )
        missing_branches = _branch_set(
            raw.get("missing_branches", []), f"{path} missing branches"
        )
        if executed_branches & missing_branches:
            raise ValueError(f"coverage record for {path} marks branches both executed and missing")
        total_points += (
            len(executed_lines)
            + len(missing_lines)
            + len(executed_branches)
            + len(missing_branches)
        )
        if total_points > MAX_POINTS:
            raise ValueError("coverage.py JSON exceeds the global observation limit")
        result.append(
            {
                "path": path,
                "executed_lines": sorted(executed_lines),
                "missing_lines": sorted(missing_lines),
                "executed_branches": [list(item) for item in sorted(executed_branches)],
                "missing_branches": [list(item) for item in sorted(missing_branches)],
            }
        )
    return result


def _matches(coverage_path: str, analysis_path: str) -> bool:
    return bool(
        coverage_path == analysis_path
        or coverage_path.endswith("/" + analysis_path)
        or analysis_path.endswith("/" + coverage_path)
    )


def _component_projection(
    analysis: dict[str, Any], files: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    components = [item for item in analysis.get("components", []) if isinstance(item, dict)]
    paths = {item["path"] for item in files}
    projections: list[dict[str, Any]] = []
    mapped_paths: set[str] = set()
    unmapped_components: list[str] = []
    for component in sorted(components, key=lambda item: str(item.get("id", ""))):
        identifier = bounded_text(component.get("id"), "analysis component id")
        source = component.get("source")
        if not isinstance(source, dict) or not source.get("path"):
            unmapped_components.append(identifier)
            continue
        analysis_path = _normalize_path(source["path"])
        candidates = sorted(path for path in paths if _matches(path, analysis_path))
        if len(candidates) != 1:
            unmapped_components.append(identifier)
            continue
        path = candidates[0]
        record = next(item for item in files if item["path"] == path)
        start = source.get("line", 0)
        end = source.get("end_line", start)
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or start < 1
            or not isinstance(end, int)
            or isinstance(end, bool)
            or end < start
        ):
            unmapped_components.append(identifier)
            continue
        executable = sorted(
            line
            for line in set(record["executed_lines"]) | set(record["missing_lines"])
            if start <= line <= end
        )
        executed = sorted(
            line for line in record["executed_lines"] if start <= line <= end
        )
        branch_total = [
            branch
            for branch in record["executed_branches"] + record["missing_branches"]
            if start <= branch[0] <= end
        ]
        branch_covered = [
            branch
            for branch in record["executed_branches"]
            if start <= branch[0] <= end
        ]
        mapped_paths.add(path)
        projections.append(
            {
                "component_id": identifier,
                "source_path": path,
                "source_range": {"start_line": start, "end_line": end},
                "executable_lines": len(executable),
                "executed_lines": len(executed),
                "statement_rate": round(len(executed) / len(executable), 6)
                if executable
                else None,
                "branches": len(set(map(tuple, branch_total))),
                "branches_executed": len(set(map(tuple, branch_covered))),
                "branch_rate": round(
                    len(set(map(tuple, branch_covered)))
                    / len(set(map(tuple, branch_total))),
                    6,
                )
                if branch_total
                else None,
                "observed": bool(executed),
            }
        )
    return projections, sorted(paths - mapped_paths), sorted(unmapped_components)


def runtime_coverage_observation(
    analysis: dict[str, Any],
    coverage_source: str | Path,
    *,
    authority: str,
    command: str,
    configuration_sha256: str,
    environment: str,
    test_run_ref: str,
    evidence_refs: list[str],
    minimum_statement_rate: float = 0.9,
    minimum_branch_rate: float = 0.9,
    require_all_components: bool = False,
    object_code_basis: str = "not_required",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Import and deterministically assess exact coverage.py JSON bytes."""

    document, raw = _load_coverage(coverage_source)
    files = _coverage_files(raw)
    projections, unmapped_files, unmapped_components = _component_projection(
        analysis, files
    )
    statement_total = sum(
        len(item["executed_lines"]) + len(item["missing_lines"]) for item in files
    )
    statement_covered = sum(len(item["executed_lines"]) for item in files)
    branch_total = sum(
        len(item["executed_branches"]) + len(item["missing_branches"]) for item in files
    )
    branch_covered = sum(len(item["executed_branches"]) for item in files)
    statement_rate = statement_covered / statement_total if statement_total else 0.0
    branch_rate = branch_covered / branch_total if branch_total else 0.0
    statement_threshold = _rate(minimum_statement_rate, "minimum statement rate")
    branch_threshold = _rate(minimum_branch_rate, "minimum branch rate")
    if type(require_all_components) is not bool:
        raise ValueError("require_all_components must be boolean")
    if object_code_basis not in {"not_required", "required_complete", "required_incomplete"}:
        raise ValueError("object_code_basis is invalid")
    refs = unique_text_list(evidence_refs, "runtime coverage evidence refs")
    if not refs:
        raise ValueError("runtime coverage evidence refs must not be empty")
    meta = raw["meta"]
    tool_version = bounded_text(meta.get("version"), "coverage.py version")
    ready = bool(
        statement_total
        and statement_rate >= statement_threshold
        and (not branch_total or branch_rate >= branch_threshold)
        and projections
        and (not require_all_components or not unmapped_components)
        and object_code_basis in {"not_required", "required_complete"}
    )
    result = {
        "format": COVERAGE_OBSERVATION_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": bounded_text(authority, "runtime coverage authority"),
        "analysis_binding": analysis_binding(analysis),
        "artifact": {
            "reference": document.path.name,
            "bytes": document.size,
            "sha256": hashlib.sha256(document.raw).hexdigest(),
        },
        "producer": {
            "name": "coverage.py",
            "version": tool_version,
            "format": bounded_text(
                str(meta.get("format", "coverage.py-json")), "coverage format"
            ),
            "command": bounded_text(command, "coverage command"),
            "configuration_sha256": _digest(
                configuration_sha256, "coverage configuration digest"
            ),
            "environment": bounded_text(environment, "coverage environment"),
            "test_run_ref": bounded_text(test_run_ref, "coverage test run reference"),
        },
        "policy": {
            "minimum_statement_rate": statement_threshold,
            "minimum_branch_rate": branch_threshold,
            "require_all_components": require_all_components,
            "object_code_basis": object_code_basis,
        },
        "files": [
            {
                "path": item["path"],
                "statements": len(item["executed_lines"]) + len(item["missing_lines"]),
                "statements_executed": len(item["executed_lines"]),
                "branches": len(item["executed_branches"]) + len(item["missing_branches"]),
                "branches_executed": len(item["executed_branches"]),
            }
            for item in files
        ],
        "components": projections,
        "omissions": {
            "unmapped_coverage_paths": unmapped_files,
            "unmapped_component_ids": unmapped_components,
        },
        "summary": {
            "files": len(files),
            "components": len(projections),
            "components_observed": sum(item["observed"] for item in projections),
            "statements": statement_total,
            "statements_executed": statement_covered,
            "statement_rate": round(statement_rate, 6),
            "branches": branch_total,
            "branches_executed": branch_covered,
            "branch_rate": round(branch_rate, 6) if branch_total else None,
            "ready_for_structural_coverage_use": ready,
        },
        "evidence_refs": refs,
        "claim_boundary": (
            "This receipt proves exact coverage.py JSON accounting and bounded source-to-component "
            "mapping. Branch observations are not decision coverage or MC/DC. It does not prove "
            "test adequacy, path completeness, object-code equivalence, tool qualification, or certification."
        ),
    }
    return seal(result)


def _structure(value: dict[str, Any]) -> bool:
    required = {
        "format", "generated_at", "authority", "analysis_binding", "artifact",
        "producer", "policy", "files", "components", "omissions", "summary",
        "evidence_refs", "claim_boundary", "content_sha256",
    }
    try:
        return bool(
            set(value) == required
            and value["format"] == COVERAGE_OBSERVATION_FORMAT
            and set(value["artifact"]) == {"reference", "bytes", "sha256"}
            and set(value["producer"]) == {
                "name", "version", "format", "command", "configuration_sha256",
                "environment", "test_run_ref",
            }
            and value["producer"]["name"] == "coverage.py"
            and set(value["policy"]) == {
                "minimum_statement_rate", "minimum_branch_rate",
                "require_all_components", "object_code_basis",
            }
            and isinstance(value["files"], list)
            and isinstance(value["components"], list)
            and set(value["omissions"]) == {
                "unmapped_coverage_paths", "unmapped_component_ids"
            }
            and isinstance(value["summary"], dict)
        )
    except (KeyError, TypeError):
        return False


def _semantics(value: dict[str, Any]) -> bool:
    try:
        _digest(value["artifact"]["sha256"], "coverage artifact digest")
        _digest(
            value["producer"]["configuration_sha256"],
            "coverage configuration digest",
        )
        policy = value["policy"]
        statement_threshold = _rate(
            policy["minimum_statement_rate"], "minimum statement rate"
        )
        branch_threshold = _rate(
            policy["minimum_branch_rate"], "minimum branch rate"
        )
        if type(policy["require_all_components"]) is not bool or policy[
            "object_code_basis"
        ] not in {"not_required", "required_complete", "required_incomplete"}:
            return False
        files = value["files"]
        file_paths: set[str] = set()
        for item in files:
            if not isinstance(item, dict) or set(item) != {
                "path", "statements", "statements_executed", "branches",
                "branches_executed",
            }:
                return False
            path = _normalize_path(item["path"])
            if path in file_paths:
                return False
            file_paths.add(path)
            for field in (
                "statements", "statements_executed", "branches", "branches_executed"
            ):
                if (
                    not isinstance(item[field], int)
                    or isinstance(item[field], bool)
                    or item[field] < 0
                ):
                    return False
            if item["statements_executed"] > item["statements"] or item[
                "branches_executed"
            ] > item["branches"]:
                return False
        components = value["components"]
        component_ids: set[str] = set()
        for item in components:
            if not isinstance(item, dict) or set(item) != {
                "component_id", "source_path", "source_range", "executable_lines",
                "executed_lines", "statement_rate", "branches", "branches_executed",
                "branch_rate", "observed",
            }:
                return False
            identifier = bounded_text(item["component_id"], "coverage component id")
            if identifier in component_ids or item["source_path"] not in file_paths:
                return False
            component_ids.add(identifier)
            executable = item["executable_lines"]
            executed = item["executed_lines"]
            branches = item["branches"]
            branches_executed = item["branches_executed"]
            if any(
                not isinstance(count, int) or isinstance(count, bool) or count < 0
                for count in (executable, executed, branches, branches_executed)
            ) or executed > executable or branches_executed > branches:
                return False
            expected_statement_rate = (
                round(executed / executable, 6) if executable else None
            )
            expected_branch_rate = (
                round(branches_executed / branches, 6) if branches else None
            )
            if (
                item["statement_rate"] != expected_statement_rate
                or item["branch_rate"] != expected_branch_rate
                or item["observed"] is not bool(executed)
            ):
                return False
        omissions = value["omissions"]
        unmapped_paths = unique_text_list(
            omissions["unmapped_coverage_paths"], "unmapped coverage paths"
        )
        unmapped_components = unique_text_list(
            omissions["unmapped_component_ids"], "unmapped component ids"
        )
        summary = value["summary"]
        summary_fields = {
            "files", "components", "components_observed", "statements",
            "statements_executed", "statement_rate", "branches",
            "branches_executed", "branch_rate", "ready_for_structural_coverage_use",
        }
        if not isinstance(summary, dict) or set(summary) != summary_fields:
            return False
        statements = sum(item["statements"] for item in files)
        statements_executed = sum(item["statements_executed"] for item in files)
        branches = sum(item["branches"] for item in files)
        branches_executed = sum(item["branches_executed"] for item in files)
        statement_rate = statements_executed / statements if statements else 0.0
        branch_rate = branches_executed / branches if branches else 0.0
        ready = bool(
            statements
            and statement_rate >= statement_threshold
            and (not branches or branch_rate >= branch_threshold)
            and components
            and (not policy["require_all_components"] or not unmapped_components)
            and policy["object_code_basis"] in {"not_required", "required_complete"}
        )
        return bool(
            summary["files"] == len(files)
            and summary["components"] == len(components)
            and summary["components_observed"]
            == sum(item["observed"] for item in components)
            and summary["statements"] == statements
            and summary["statements_executed"] == statements_executed
            and summary["statement_rate"] == round(statement_rate, 6)
            and summary["branches"] == branches
            and summary["branches_executed"] == branches_executed
            and summary["branch_rate"]
            == (round(branch_rate, 6) if branches else None)
            and summary["ready_for_structural_coverage_use"] is ready
            and set(unmapped_paths) <= file_paths
            and bool(unique_text_list(value["evidence_refs"], "coverage evidence refs"))
        )
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return False


def verify_runtime_coverage_observation(
    value: dict[str, Any],
    *,
    analysis: dict[str, Any] | None = None,
    coverage_source: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    structure = _structure(value)
    if not structure:
        errors.append("runtime coverage observation fields are invalid")
    try:
        checked = verify_seal(
            value,
            label="runtime coverage observation",
            format_value=COVERAGE_OBSERVATION_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
        checked = value
        integrity = False
    semantic = bool(structure and _semantics(checked))
    if not semantic:
        errors.append("runtime coverage observation summary does not reconcile")
    analysis_check: bool | None = None
    if analysis is not None:
        try:
            verify_analysis_binding(checked.get("analysis_binding"), analysis)
            analysis_check = True
        except ValueError as exc:
            errors.append(str(exc))
            analysis_check = False
    source_check: bool | None = None
    regeneration: bool | None = None
    if coverage_source is not None:
        try:
            document, _ = _load_coverage(coverage_source)
            source_check = bool(
                checked.get("artifact", {}).get("bytes") == document.size
                and checked.get("artifact", {}).get("sha256")
                == hashlib.sha256(document.raw).hexdigest()
            )
            if not source_check:
                errors.append("runtime coverage observation does not bind the supplied coverage JSON")
            if analysis is None:
                raise ValueError("analysis is required for exact coverage regeneration")
            producer = checked["producer"]
            policy = checked["policy"]
            expected = runtime_coverage_observation(
                analysis,
                coverage_source,
                authority=checked["authority"],
                command=producer["command"],
                configuration_sha256=producer["configuration_sha256"],
                environment=producer["environment"],
                test_run_ref=producer["test_run_ref"],
                evidence_refs=checked["evidence_refs"],
                minimum_statement_rate=policy["minimum_statement_rate"],
                minimum_branch_rate=policy["minimum_branch_rate"],
                require_all_components=policy["require_all_components"],
                object_code_basis=policy["object_code_basis"],
                generated_at=checked["generated_at"],
            )
            regeneration = expected == checked
            if not regeneration:
                errors.append("runtime coverage observation does not exactly regenerate")
        except (KeyError, OSError, TypeError, ValueError) as exc:
            if str(exc) not in errors:
                errors.append(str(exc))
            source_check = False if source_check is None else source_check
            regeneration = False
    valid = bool(
        structure
        and integrity
        and semantic
        and analysis_check is not False
        and source_check is not False
        and regeneration is not False
    )
    return seal(
        {
            "format": COVERAGE_OBSERVATION_VERIFICATION_FORMAT,
            "valid": valid,
            "ready_for_structural_coverage_use": bool(
                valid and checked.get("summary", {}).get("ready_for_structural_coverage_use")
            ),
            "checks": {
                "closed_structure": structure,
                "content_integrity": integrity,
                "semantic_reconciliation": semantic,
                "analysis_binding": analysis_check,
                "coverage_artifact_binding": source_check,
                "exact_regeneration": regeneration,
            },
            "errors": errors,
            "notice": "Verification establishes exact coverage accounting, not MC/DC, tool qualification, or certification.",
        }
    )


def verify_runtime_coverage_observation_file(
    source: str | Path,
    *,
    analysis: dict[str, Any] | None = None,
    coverage_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="runtime coverage observation",
            max_bytes=64 * 1024 * 1024,
            max_depth=100,
            max_nodes=2_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("runtime coverage observation must contain an object")
        return verify_runtime_coverage_observation(
            document.value, analysis=analysis, coverage_source=coverage_source
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": COVERAGE_OBSERVATION_VERIFICATION_FORMAT,
                "valid": False,
                "ready_for_structural_coverage_use": False,
                "checks": {
                    "closed_structure": False,
                    "content_integrity": False,
                    "semantic_reconciliation": False,
                    "analysis_binding": False if analysis is not None else None,
                    "coverage_artifact_binding": False
                    if coverage_source is not None
                    else None,
                    "exact_regeneration": False if coverage_source is not None else None,
                },
                "errors": [str(exc)],
                "notice": "Runtime coverage observation verification failed closed.",
            }
        )


def export_runtime_coverage_observation(
    value: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_runtime_coverage_observation(value)
    if not verdict["valid"]:
        raise ValueError("runtime coverage observation is internally invalid")
    return publish_json(value, destination)
