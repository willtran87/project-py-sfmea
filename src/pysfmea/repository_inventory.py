"""Bounded, non-executing repository inventory and analysis-region accounting."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import stat
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .guidance import DEFAULT_EXCLUDES
from .json_ingestion import BoundedFileSnapshotError, load_bounded_file_snapshot

MAX_FILES = 100_000
MAX_REGIONS = 100_000
MAX_HASH_BYTES = 20_000_000
MAX_TOTAL_HASH_BYTES = 500_000_000


def legacy_repository_inventory(reason: str) -> dict[str, Any]:
    """Represent unavailable historical coverage without reconstructing past evidence."""

    material = {
        "entries": [],
        "regions": [
            {
                "path": "./",
                "status": "unresolved",
                "reason": reason,
            }
        ],
        "truncated": False,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "pysfmea-repository-inventory-1",
        **material,
        "summary": {
            "files": 0,
            "regions": 1,
            "by_status": {"unresolved": 1},
            "by_kind": {},
            "by_snapshot_source": {},
            "semantic_coverage_percent": None,
            "opaque_or_unresolved": 1,
        },
        "inventory_sha256": digest,
        "notice": reason,
    }


def _matches(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern.replace("\\", "/")) for pattern in patterns)


def _is_test(path: str) -> bool:
    parts = Path(path).parts
    name = parts[-1].lower() if parts else ""
    return any(part.lower() in {"test", "tests"} for part in parts[:-1]) or name.startswith(
        "test_"
    ) or name.endswith("_test.py")


def _kind(path: str) -> str:
    lower = path.lower()
    name = Path(lower).name
    suffix = Path(lower).suffix
    if suffix == ".py":
        return "python_test" if _is_test(path) else "python_source"
    if name in {
        "pyproject.toml",
        "poetry.lock",
        "pdm.lock",
        "pipfile",
        "pipfile.lock",
        "uv.lock",
        "setup.cfg",
        "setup.py",
    } or name.startswith(("requirements", "constraints")):
        return "dependency_manifest"
    if lower.startswith(".github/workflows/") or name in {
        ".gitlab-ci.yml",
        "azure-pipelines.yml",
        "jenkinsfile",
    }:
        return "ci_configuration"
    if name.startswith("dockerfile") or name in {"compose.yml", "compose.yaml"}:
        return "container_or_deployment"
    if suffix in {".tf", ".tfvars"} or "k8s/" in lower or "kubernetes/" in lower:
        return "infrastructure"
    if "openapi" in name or "swagger" in name or name.endswith(".schema.json") or suffix == ".proto":
        return "api_or_data_schema"
    if "migration" in lower or suffix == ".sql":
        return "database_schema_or_migration"
    if suffix in {".md", ".rst", ".adoc", ".txt"}:
        return "documentation"
    if suffix == ".sarif" or name.endswith("sarif.json"):
        return "static_analysis_result"
    if "coverage" in name and suffix in {".json", ".xml", ".lcov"}:
        return "coverage_result"
    if "junit" in name or "test-result" in lower or "test_result" in lower:
        return "test_result"
    if suffix in {".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".env"}:
        return "configuration"
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".whl", ".exe", ".dll", ".so", ".pyd"}:
        return "binary_or_generated"
    return "unclassified"


def build_repository_inventory(
    root: Path,
    *,
    selected_python_paths: set[str],
    parsed_python_paths: set[str],
    include_tests: bool,
    exclude_patterns: Iterable[str] = (),
    source_snapshots: Mapping[str, bytes] | None = None,
    test_evidence_snapshots: Mapping[str, bytes] | None = None,
    dependency_snapshots: Mapping[str, bytes] | None = None,
    contract_snapshots: Mapping[str, bytes] | None = None,
    coverage_snapshots: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Inventory stable artifact snapshots and expose every excluded/opaque region."""

    accepted_source_snapshots = source_snapshots or {}
    accepted_test_evidence_snapshots = test_evidence_snapshots or {}
    accepted_dependency_snapshots = dependency_snapshots or {}
    accepted_contract_snapshots = contract_snapshots or {}
    accepted_coverage_snapshots = coverage_snapshots or {}
    entries: list[dict[str, Any]] = []
    regions: list[dict[str, Any]] = []
    walk_truncated = False
    hash_truncated = False
    hash_consumed = 0
    relative_dir = "."
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        relative_dir = base.relative_to(root).as_posix()
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            if len(regions) >= MAX_REGIONS:
                walk_truncated = True
                kept_dirs = []
                break
            candidate = base / dirname
            rel = candidate.relative_to(root).as_posix()
            reason = ""
            if candidate.is_symlink():
                reason = "Symbolic-link directory is not traversed."
                status = "opaque"
            elif _matches(rel, exclude_patterns) or _matches(
                rel + "/__pysfmea_region__", exclude_patterns
            ):
                reason = "Directory matches a configured scan exclusion and is not traversed."
                status = "excluded_region"
            elif dirname in DEFAULT_EXCLUDES:
                reason = "Default generated, cache, environment, or vendor directory is excluded."
                status = "excluded_region"
            elif dirname.startswith(".") and dirname not in {".github"}:
                reason = "Hidden directory is excluded from repository analysis."
                status = "excluded_region"
            else:
                kept_dirs.append(dirname)
                continue
            regions.append({"path": rel + "/", "status": status, "reason": reason})
        dirnames[:] = [] if walk_truncated else kept_dirs
        if walk_truncated:
            break
        for filename in sorted(filenames):
            if len(entries) >= MAX_FILES:
                walk_truncated = True
                dirnames[:] = []
                break
            path = base / filename
            rel = path.relative_to(root).as_posix()
            kind = _kind(rel)
            record: dict[str, Any] = {
                "path": rel,
                "kind": kind,
                "status": "indexed",
                "analysis_depth": "metadata_and_digest",
                "reason": "Recognized repository artifact is indexed but not semantically analyzed.",
                "size": None,
                "sha256": "",
                "snapshot_source": "none",
                "adapter_ids": ["python.repository_discoverer"],
            }
            snapshot_source = "none"
            raw = accepted_source_snapshots.get(rel)
            if rel in accepted_source_snapshots:
                snapshot_source = "analysis_source_snapshot"
            elif rel in accepted_test_evidence_snapshots:
                raw = accepted_test_evidence_snapshots[rel]
                snapshot_source = "test_evidence_snapshot"
            elif rel in accepted_dependency_snapshots:
                raw = accepted_dependency_snapshots[rel]
                snapshot_source = "dependency_manifest_snapshot"
            elif rel in accepted_contract_snapshots:
                raw = accepted_contract_snapshots[rel]
                snapshot_source = "interface_contract_snapshot"
            elif rel in accepted_coverage_snapshots:
                raw = accepted_coverage_snapshots[rel]
                snapshot_source = "coverage_evidence_snapshot"
            metadata: os.stat_result | None = None
            if raw is not None:
                if not isinstance(raw, bytes):
                    record.update(
                        status="unresolved",
                        analysis_depth="none",
                        reason="Accepted analysis snapshot is not an immutable byte stream.",
                    )
                    entries.append(record)
                    continue
                record["snapshot_source"] = snapshot_source
            else:
                if path.is_symlink():
                    record.update(
                        status="opaque",
                        analysis_depth="none",
                        reason="Symbolic-link file is not followed.",
                    )
                    entries.append(record)
                    continue
                try:
                    metadata = path.lstat()
                except OSError:
                    record.update(
                        status="unresolved",
                        analysis_depth="none",
                        reason="Artifact metadata or content could not be read safely.",
                    )
                    entries.append(record)
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    record.update(
                        status="opaque",
                        analysis_depth="none",
                        reason="Symbolic-link file is not followed.",
                    )
                    entries.append(record)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    record.update(
                        status="opaque",
                        analysis_depth="none",
                        size=metadata.st_size,
                        reason="Non-regular repository artifact is not opened or hashed.",
                    )
                    entries.append(record)
                    continue
            try:
                if hash_truncated:
                    record["size"] = len(raw) if raw is not None else metadata.st_size
                    record.update(
                        analysis_depth="metadata_only",
                        reason="Artifact digest omitted after the aggregate hashing limit.",
                    )
                else:
                    remaining = MAX_TOTAL_HASH_BYTES - hash_consumed
                    if remaining <= 0:
                        hash_truncated = True
                        record["size"] = len(raw) if raw is not None else metadata.st_size
                        record.update(
                            analysis_depth="metadata_only",
                            reason="Artifact digest omitted after the aggregate hashing limit.",
                        )
                    else:
                        read_limit = min(MAX_HASH_BYTES, remaining)
                        if raw is None:
                            snapshot = load_bounded_file_snapshot(
                                path,
                                label="Repository artifact",
                                max_bytes=read_limit,
                            )
                            raw = snapshot.raw
                            record["snapshot_source"] = "identity_stable_inventory_snapshot"
                        record["size"] = len(raw)
                        hash_consumed += min(len(raw), read_limit + 1)
                        if len(raw) > remaining:
                            hash_truncated = True
                            record.update(
                                analysis_depth="metadata_only",
                                reason=(
                                    "Artifact digest omitted because repository hashing reached "
                                    "the aggregate safety limit."
                                ),
                            )
                        elif len(raw) > MAX_HASH_BYTES:
                            record.update(
                                status="opaque",
                                analysis_depth="metadata_only",
                                reason=(
                                    "Artifact exceeds the "
                                    f"{MAX_HASH_BYTES}-byte hashing and analysis limit."
                                ),
                            )
                        else:
                            record["sha256"] = hashlib.sha256(raw).hexdigest()
            except BoundedFileSnapshotError as exc:
                hash_consumed += exc.bytes_consumed
                if exc.bytes_consumed > remaining:
                    hash_truncated = True
                    record.update(
                        analysis_depth="metadata_only",
                        reason=(
                            "Artifact digest omitted because repository hashing reached "
                            "the aggregate safety limit."
                        ),
                    )
                elif str(exc) == (
                    f"Repository artifact exceeds the {read_limit}-byte limit"
                ):
                    record.update(
                        status="opaque",
                        analysis_depth="metadata_only",
                        reason=(
                            "Artifact exceeds the "
                            f"{MAX_HASH_BYTES}-byte hashing and analysis limit."
                        ),
                    )
                else:
                    record.update(
                        status="unresolved",
                        analysis_depth="none",
                        reason=f"Artifact snapshot rejected: {exc}.",
                    )
                entries.append(record)
                continue
            except OSError:
                record.update(
                    status="unresolved",
                    analysis_depth="none",
                    reason="Artifact metadata or content could not be read safely.",
                )
                entries.append(record)
                continue
            if _matches(rel, exclude_patterns):
                record.update(
                    status="excluded_region",
                    analysis_depth=(
                        "metadata_and_digest" if record["sha256"] else "metadata_only"
                    ),
                    reason=(
                        "Path matches a configured scan exclusion."
                        if record["sha256"]
                        else "Path matches a configured scan exclusion; digest unavailable under inventory safety limits."
                    ),
                )
            elif kind == "python_test" and not include_tests:
                record.update(
                    status="excluded_region",
                    analysis_depth=(
                        "metadata_and_digest" if record["sha256"] else "metadata_only"
                    ),
                    reason="Test source was indexed but excluded from component analysis by configuration.",
                )
            elif kind in {"python_source", "python_test"} and rel in parsed_python_paths:
                record.update(
                    status="analyzed",
                    analysis_depth="python_ast",
                    reason="Python source parsed and analyzed without repository execution.",
                    adapter_ids=["python.repository_discoverer", "python.ast_parser"],
                )
            elif kind in {"python_source", "python_test"} and rel in selected_python_paths:
                record.update(
                    status="unresolved",
                    analysis_depth="tokenization_or_parse_failed",
                    reason="Python source was selected but could not be parsed.",
                    adapter_ids=["python.repository_discoverer", "python.ast_parser"],
                )
            elif kind in {"binary_or_generated", "unclassified"}:
                boundary_reason = record["reason"]
                record.update(
                    status="opaque",
                    analysis_depth=(
                        "metadata_and_digest" if record["sha256"] else "metadata_only"
                    ),
                    reason=(
                        "No semantic analyzer is registered for this artifact type."
                        if record["sha256"]
                        else boundary_reason
                    ),
                )
            entries.append(record)
        if walk_truncated:
            break

    if walk_truncated:
        regions.append(
            {
                "path": relative_dir + "/" if relative_dir != "." else "./",
                "status": "unresolved",
                "reason": (
                    "Inventory traversal stopped at its safety limit of "
                    f"{MAX_FILES} files or {MAX_REGIONS} regions."
                ),
            }
        )
    if hash_truncated:
        regions.append(
            {
                "path": "./",
                "status": "unresolved",
                "reason": (
                    "Repository artifact hashing stopped at the "
                    f"{MAX_TOTAL_HASH_BYTES}-byte aggregate safety limit; metadata and semantic "
                    "accounting continued where safe."
                ),
            }
        )
    truncated = walk_truncated or hash_truncated
    status_counts = Counter(value["status"] for value in entries)
    status_counts.update(value["status"] for value in regions)
    kind_counts = Counter(value["kind"] for value in entries)
    snapshot_counts = Counter(value["snapshot_source"] for value in entries)
    material = {"entries": entries, "regions": regions, "truncated": truncated}
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "pysfmea-repository-inventory-1",
        **material,
        "summary": {
            "files": len(entries),
            "regions": len(regions),
            "by_status": dict(sorted(status_counts.items())),
            "by_kind": dict(sorted(kind_counts.items())),
            "by_snapshot_source": dict(sorted(snapshot_counts.items())),
            "semantic_coverage_percent": round(
                100 * status_counts.get("analyzed", 0) / len(entries), 1
            )
            if entries
            else 100.0,
            "opaque_or_unresolved": status_counts.get("opaque", 0)
            + status_counts.get("unresolved", 0),
        },
        "inventory_sha256": digest,
        "notice": (
            "Coverage is artifact accounting, not proof that every behavior or failure mode was "
            "analyzed. Indexed artifacts received metadata/digest handling only."
        ),
    }
