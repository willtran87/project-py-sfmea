"""Bounded, non-executing repository inventory and analysis-region accounting."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .guidance import DEFAULT_EXCLUDES

MAX_FILES = 100_000
MAX_HASH_BYTES = 20_000_000


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
) -> dict[str, Any]:
    """Inventory the repository while making every excluded/opaque region visible."""

    entries: list[dict[str, Any]] = []
    regions: list[dict[str, Any]] = []
    truncated = False
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        relative_dir = base.relative_to(root).as_posix()
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
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
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            if len(entries) >= MAX_FILES:
                truncated = True
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
                "adapter_ids": ["python.repository_discoverer"],
            }
            if path.is_symlink():
                record.update(
                    status="opaque",
                    analysis_depth="none",
                    reason="Symbolic-link file is not followed.",
                )
                entries.append(record)
                continue
            try:
                size = path.stat().st_size
                record["size"] = size
                if size <= MAX_HASH_BYTES:
                    record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                else:
                    record.update(
                        status="opaque",
                        analysis_depth="metadata_only",
                        reason=f"Artifact exceeds the {MAX_HASH_BYTES // 1_000_000} MB hashing and analysis limit.",
                    )
            except OSError as exc:
                record.update(status="unresolved", analysis_depth="none", reason=str(exc))
                entries.append(record)
                continue
            if _matches(rel, exclude_patterns):
                record.update(
                    status="excluded_region",
                    analysis_depth="metadata_and_digest",
                    reason="Path matches a configured scan exclusion.",
                )
            elif kind == "python_test" and not include_tests:
                record.update(
                    status="excluded_region",
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
                record.update(
                    status="opaque",
                    analysis_depth="metadata_and_digest",
                    reason="No semantic analyzer is registered for this artifact type.",
                )
            entries.append(record)
        if truncated:
            break

    if truncated:
        regions.append(
            {
                "path": relative_dir + "/" if relative_dir != "." else "./",
                "status": "unresolved",
                "reason": f"Inventory stopped at the safety limit of {MAX_FILES} files.",
            }
        )
    status_counts = Counter(value["status"] for value in entries)
    status_counts.update(value["status"] for value in regions)
    kind_counts = Counter(value["kind"] for value in entries)
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
