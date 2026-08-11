"""Bounded, non-executing repository inventory and analysis-region accounting."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
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
MAX_LANGUAGE_BOUNDARY_IMPORTS = 500
MAX_LANGUAGE_BOUNDARY_EXPORTS = 500
MAX_LANGUAGE_BOUNDARY_ENDPOINTS = 200
MAX_LANGUAGE_BOUNDARY_VALUE_CHARS = 4_096
MAX_DEPLOYMENT_ENTITIES = 500

SNAPSHOT_SOURCES = frozenset(
    {
        "analysis_source_snapshot",
        "coverage_evidence_snapshot",
        "dependency_manifest_snapshot",
        "identity_stable_inventory_snapshot",
        "interface_contract_snapshot",
        "none",
        "test_evidence_snapshot",
    }
)
RECONCILED_SUMMARY_FIELDS = (
    "files",
    "regions",
    "by_status",
    "by_kind",
    "by_snapshot_source",
    "coverage_dimensions",
    "language_boundaries",
    "opaque_or_unresolved",
)


def summarize_repository_inventory(
    entries: list[dict[str, Any]], regions: list[dict[str, Any]]
) -> dict[str, Any]:
    """Derive the complete repository-inventory summary from governed records."""

    status_counts = Counter(value["status"] for value in entries)
    entry_status_counts = status_counts.copy()
    status_counts.update(value["status"] for value in regions)
    kind_counts = Counter(value["kind"] for value in entries)
    snapshot_counts = Counter(value["snapshot_source"] for value in entries)
    boundary_records = [
        value.get("boundary_facts", {})
        for value in entries
        if isinstance(value.get("boundary_facts"), dict)
    ]
    python_entries = [
        value for value in entries if value.get("kind") == "python_source"
    ]
    web_entries = [
        value
        for value in entries
        if value.get("kind") in {"javascript_source", "typescript_source"}
    ]
    analyzed_files = status_counts.get("analyzed", 0)
    indexed_files = status_counts.get("indexed", 0)
    excluded_files = sum(value.get("status") == "excluded_region" for value in entries)
    accounted_files = analyzed_files + indexed_files + excluded_files

    def percentage(numerator: int, denominator: int) -> float:
        return round(100 * numerator / denominator, 1) if denominator else 100.0

    return {
        "files": len(entries),
        "regions": len(regions),
        "by_status": dict(sorted(status_counts.items())),
        "by_kind": dict(sorted(kind_counts.items())),
        "by_snapshot_source": dict(sorted(snapshot_counts.items())),
        "semantic_coverage_percent": round(100 * analyzed_files / len(entries), 1)
        if entries
        else 100.0,
        "coverage_dimensions": {
            "repository_files": len(entries),
            "semantic": {
                "files": analyzed_files,
                "percent": percentage(analyzed_files, len(entries)),
            },
            "indexed": {
                "files": indexed_files,
                "percent": percentage(indexed_files, len(entries)),
            },
            "accounted": {
                "files": accounted_files,
                "percent": percentage(accounted_files, len(entries)),
            },
            "python_semantic": {
                "files": sum(
                    value.get("status") == "analyzed" for value in python_entries
                ),
                "eligible_files": len(python_entries),
                "percent": percentage(
                    sum(value.get("status") == "analyzed" for value in python_entries),
                    len(python_entries),
                ),
            },
            "web_boundary": {
                "files": sum(value.get("status") == "indexed" for value in web_entries),
                "eligible_files": len(web_entries),
                "percent": percentage(
                    sum(value.get("status") == "indexed" for value in web_entries),
                    len(web_entries),
                ),
                "analysis_depth": "bounded_lexical_boundary_index",
            },
            "excluded_files": excluded_files,
            "opaque_or_unresolved_files": entry_status_counts.get("opaque", 0)
            + entry_status_counts.get("unresolved", 0),
            "unresolved_regions": sum(
                value.get("status") == "unresolved" for value in regions
            ),
        },
        "opaque_or_unresolved": status_counts.get("opaque", 0)
        + status_counts.get("unresolved", 0),
        "language_boundaries": {
            "files": len(boundary_records),
            "imports": sum(
                len(value.get("imports", []))
                for value in boundary_records
                if isinstance(value.get("imports", []), list)
            ),
            "exports": sum(
                len(value.get("exports", []))
                for value in boundary_records
                if isinstance(value.get("exports", []), list)
            ),
            "literal_endpoints": sum(
                len(value.get("endpoint_literals", []))
                for value in boundary_records
                if isinstance(value.get("endpoint_literals", []), list)
            ),
            "external_packages": len(
                {
                    package
                    for value in boundary_records
                    if isinstance(value.get("external_packages", []), list)
                    for package in value.get("external_packages", [])
                    if isinstance(package, str)
                }
            ),
        },
    }


def derive_repository_inventory_summary(inventory: Any) -> dict[str, Any] | None:
    """Safely derive a summary only when every required record field is usable."""

    if not isinstance(inventory, Mapping):
        return None
    entries = inventory.get("entries")
    regions = inventory.get("regions")
    if (
        not isinstance(entries, list)
        or not isinstance(regions, list)
        or any(not isinstance(entry, dict) for entry in entries)
        or any(not isinstance(region, dict) for region in regions)
    ):
        return None
    if not all(
        isinstance(entry.get(field), str) and bool(entry.get(field))
        for entry in entries
        for field in ("status", "kind", "snapshot_source")
    ) or not all(
        isinstance(region.get("status"), str) and bool(region.get("status"))
        for region in regions
    ):
        return None
    return summarize_repository_inventory(entries, regions)


def repository_inventory_summary_mismatches(
    inventory: Any, derived_summary: dict[str, Any] | None = None
) -> list[str]:
    """Return stored-summary fields that differ from safely derived accounting."""

    if not isinstance(inventory, Mapping):
        return list(RECONCILED_SUMMARY_FIELDS)
    derived = derived_summary or derive_repository_inventory_summary(inventory)
    if derived is None:
        return list(RECONCILED_SUMMARY_FIELDS)
    supplied = inventory.get("summary")
    fields = list(RECONCILED_SUMMARY_FIELDS)
    # Historical pre-inventory scans intentionally use null for zero-file semantic coverage.
    if derived["files"]:
        fields.append("semantic_coverage_percent")
    return [
        field
        for field in fields
        if not isinstance(supplied, Mapping) or supplied.get(field) != derived[field]
    ]


def repository_inventory_summary_projection(inventory: Any) -> dict[str, Any]:
    """Return safe display accounting plus its reconciliation state."""

    derived = derive_repository_inventory_summary(inventory)
    if derived is None:
        return {
            "status": "unavailable",
            "display_source": "unavailable",
            "summary": {},
            "notice": (
                "Inventory counts are unavailable because the underlying records cannot be "
                "safely reconciled. Review the quality-gate findings and rescan."
            ),
        }
    if repository_inventory_summary_mismatches(inventory, derived):
        return {
            "status": "recomputed",
            "display_source": "derived_inventory_records",
            "summary": derived,
            "notice": (
                "Displayed inventory counts were recomputed from governed records because the "
                "stored summary is inconsistent. Review the quality-gate finding and rescan."
            ),
        }
    return {
        "status": "reconciled",
        "display_source": "derived_inventory_records",
        "summary": derived,
        "notice": (
            "Displayed inventory counts reconcile with the governed entry and region records."
        ),
    }


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
            "coverage_dimensions": {
                "repository_files": 0,
                "semantic": {"files": 0, "percent": 100.0},
                "indexed": {"files": 0, "percent": 100.0},
                "accounted": {"files": 0, "percent": 100.0},
                "python_semantic": {
                    "files": 0,
                    "eligible_files": 0,
                    "percent": 100.0,
                },
                "web_boundary": {
                    "files": 0,
                    "eligible_files": 0,
                    "percent": 100.0,
                    "analysis_depth": "bounded_lexical_boundary_index",
                },
                "excluded_files": 0,
                "opaque_or_unresolved_files": 0,
                "unresolved_regions": 1,
            },
            "language_boundaries": {
                "files": 0,
                "imports": 0,
                "exports": 0,
                "literal_endpoints": 0,
                "external_packages": 0,
            },
            "opaque_or_unresolved": 1,
        },
        "inventory_sha256": digest,
        "notice": reason,
    }


def _matches(path: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern.replace("\\", "/")) for pattern in patterns
    )


def _may_contain_match(directory: str, patterns: Iterable[str]) -> bool:
    """Conservatively retain an excluded directory needed by an evidence glob."""

    prefix = directory.strip("/") + "/"
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/").lstrip("./")
        wildcard_positions = [
            pattern.find(character) for character in "*[?" if character in pattern
        ]
        literal = pattern[: min(wildcard_positions, default=len(pattern))]
        if not literal or literal.startswith(prefix) or prefix.startswith(literal):
            return True
        if _matches(directory, (pattern,)):
            return True
    return False


def _is_test(path: str) -> bool:
    parts = Path(path).parts
    name = parts[-1].lower() if parts else ""
    return (
        any(part.lower() in {"test", "tests"} for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _kind(path: str) -> str:
    lower = path.lower()
    name = Path(lower).name
    suffix = Path(lower).suffix
    if suffix == ".py":
        return "python_test" if _is_test(path) else "python_source"
    if suffix in {".ts", ".tsx"}:
        return "typescript_source"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript_source"
    if suffix in {".css", ".scss", ".sass", ".less"}:
        return "stylesheet"
    if suffix in {".html", ".htm"}:
        return "user_interface"
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
    if name.startswith("dockerfile") or name in {
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    }:
        return "container_or_deployment"
    kubernetes_names = {
        "configmap.yaml",
        "configmap.yml",
        "cronjob.yaml",
        "cronjob.yml",
        "daemonset.yaml",
        "daemonset.yml",
        "deployment.yaml",
        "deployment.yml",
        "ingress.yaml",
        "ingress.yml",
        "job.yaml",
        "job.yml",
        "namespace.yaml",
        "namespace.yml",
        "secret.yaml",
        "secret.yml",
        "service.yaml",
        "service.yml",
        "statefulset.yaml",
        "statefulset.yml",
    }
    if (
        suffix in {".tf", ".tfvars"}
        or "k8s/" in lower
        or "kubernetes/" in lower
        or "manifests/" in lower
        or "helm/templates/" in lower
        or name in kubernetes_names
    ):
        return "infrastructure"
    if (
        "openapi" in name
        or "swagger" in name
        or name.endswith(".schema.json")
        or suffix == ".proto"
        or name.startswith("asyncapi")
        or suffix in {".graphql", ".graphqls", ".avsc"}
    ):
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
    if suffix in {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".pdf",
        ".zip",
        ".gz",
        ".whl",
        ".exe",
        ".dll",
        ".so",
        ".pyd",
    }:
        return "binary_or_generated"
    return "unclassified"


def _bounded_unique(values: Iterable[str], limit: int) -> tuple[list[str], bool]:
    accepted = sorted(
        {
            value.strip()
            for value in values
            if value.strip() and len(value.strip()) <= MAX_LANGUAGE_BOUNDARY_VALUE_CHARS
        }
    )
    return accepted[:limit], len(accepted) > limit


def _language_boundary_facts(raw: bytes, kind: str) -> dict[str, Any] | None:
    """Extract conservative JS/TS import, export, and literal endpoint boundaries."""

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    imports, imports_truncated = _bounded_unique(
        (
            match.group(1)
            for match in re.finditer(
                r"(?:\bfrom\s*|\brequire\s*\(|\bimport\s*\(?\s*)['\"]([^'\"]+)['\"]",
                source,
            )
        ),
        MAX_LANGUAGE_BOUNDARY_IMPORTS,
    )
    exports, exports_truncated = _bounded_unique(
        (
            match.group(1)
            for match in re.finditer(
                r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)",
                source,
            )
        ),
        MAX_LANGUAGE_BOUNDARY_EXPORTS,
    )
    literal_argument = r"(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\"|`([^`\r\n]+)`)"
    endpoint_candidates: list[dict[str, Any]] = []
    endpoint_candidate_keys: set[tuple[str, str, str]] = set()
    endpoint_candidates_truncated = False

    def add_endpoint(
        literal: str, method: str, operation: str, *, line: int = 0
    ) -> None:
        nonlocal endpoint_candidates_truncated
        key = (literal, method, operation)
        if key in endpoint_candidate_keys:
            return
        if len(endpoint_candidates) >= MAX_LANGUAGE_BOUNDARY_ENDPOINTS:
            endpoint_candidates_truncated = True
            return
        endpoint_candidate_keys.add(key)
        endpoint_candidates.append(
            {
                "literal": literal,
                "method": method,
                "operation": operation,
                "confidence": "lexical_literal",
                "line": line,
            }
        )

    axios_instances: list[dict[str, str]] = []
    for match in re.finditer(
        r"\b(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
        r"axios\.create\s*\(\s*\{(?P<options>[^{}]{0,2000})\}\s*\)",
        source,
        re.DOTALL,
    ):
        options = match.group("options")
        literal_base = re.search(rf"\bbaseURL\s*:\s*{literal_argument}", options)
        symbol_base = re.search(
            r"\bbaseURL\s*:\s*([A-Za-z_$][\w$]*(?:BASE|URL)[\w$]*)",
            options,
            re.IGNORECASE,
        )
        instance = {
            "name": match.group("name"),
            "base_literal": "",
            "base_symbol": symbol_base.group(1) if symbol_base else "",
        }
        if literal_base:
            instance["base_literal"] = next(
                value for value in literal_base.groups() if value is not None
            )
            add_endpoint(
                instance["base_literal"],
                "BASE",
                f"instance:{instance['name']}",
                line=source.count("\n", 0, match.start()) + 1,
            )
        axios_instances.append(instance)
    instance_names = [re.escape(value["name"]) for value in axios_instances[:100]]
    instance_names.append(
        r"(?:api|client|http|[A-Za-z_$][\w$]*(?:Api|API|Client|Http|HTTP))"
    )
    instance_operation = (
        rf"|\b(?:{'|'.join(instance_names)})\.(?:get|post|put|patch|delete)"
    )
    for match in re.finditer(
        rf"(?P<operation>\bfetch|\baxios\.(?:get|post|put|patch|delete){instance_operation}|new\s+(?:WebSocket|EventSource)|\b(?:request|apiRequest|httpRequest)(?:\s*<[^;\r\n()]{{1,300}}>)?)\s*\(\s*{literal_argument}",
        source,
    ):
        operation = match.group("operation")
        normalized_operation = re.sub(r"\s*<.*>\s*$", "", operation).strip()
        value = next(value for value in match.groups()[1:] if value is not None)
        leaf = normalized_operation.casefold().rsplit(".", 1)[-1]
        method = (
            leaf.upper()
            if "." in normalized_operation
            and leaf in {"get", "post", "put", "patch", "delete"}
            else "UNKNOWN"
        )
        if normalized_operation.casefold() in {
            "fetch",
            "request",
            "apirequest",
            "httprequest",
        }:
            options = source[match.end() : match.end() + 500]
            method_match = re.match(
                r"\s*,\s*\{[^{}]{0,450}?\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]",
                options,
                re.DOTALL,
            )
            if method_match:
                method = method_match.group(1).upper()
        if "websocket" in normalized_operation.casefold():
            method = "WEBSOCKET"
        elif "eventsource" in normalized_operation.casefold():
            method = "EVENTSOURCE"
        add_endpoint(
            value,
            method,
            normalized_operation,
            line=source.count("\n", 0, match.start()) + 1,
        )
    for match in re.finditer(rf"\bbaseURL\s*:\s*{literal_argument}", source):
        add_endpoint(
            next(value for value in match.groups() if value is not None),
            "BASE",
            "baseURL",
            line=source.count("\n", 0, match.start()) + 1,
        )
    for match in re.finditer(
        rf"\b(?:export\s+)?const\s+([A-Za-z_$][\w$]*(?:BASE|URL)[\w$]*)\s*=\s*{literal_argument}",
        source,
        re.IGNORECASE,
    ):
        literal = next(value for value in match.groups()[1:] if value is not None)
        if literal.startswith(("/", "http://", "https://")):
            add_endpoint(
                literal,
                "BASE",
                f"constant:{match.group(1)}",
                line=source.count("\n", 0, match.start()) + 1,
            )
    wrapper_bases: list[dict[str, str]] = []
    for match in re.finditer(
        r"\b(?:export\s+)?(?:async\s+)?function\s+"
        r"(?P<operation>request|apiRequest|httpRequest)(?:\s*<[^;\r\n()]{1,300}>)?\s*\(",
        source,
    ):
        window = source[match.end() : match.end() + 4_000]
        symbols = sorted(
            set(re.findall(r"\$\{([A-Za-z_$][\w$]*(?:BASE|URL)[\w$]*)\}", window))
        )
        for symbol in symbols[:10]:
            wrapper_bases.append(
                {"operation": match.group("operation"), "base_symbol": symbol}
            )
    for instance in axios_instances:
        if not instance["base_symbol"]:
            continue
        for method in ("get", "post", "put", "patch", "delete"):
            wrapper_bases.append(
                {
                    "operation": f"{instance['name']}.{method}",
                    "base_symbol": instance["base_symbol"],
                }
            )
    endpoint_values = [value["literal"] for value in endpoint_candidates]
    endpoints, endpoints_truncated = _bounded_unique(
        endpoint_values,
        MAX_LANGUAGE_BOUNDARY_ENDPOINTS,
    )
    external_packages = sorted(
        {
            value.split("/", 1)[0]
            if not value.startswith("@")
            else "/".join(value.split("/")[:2])
            for value in imports
            if not value.startswith((".", "/"))
        }
    )
    return {
        "format": "pysfmea-language-boundary-facts-1",
        "language": "typescript" if kind == "typescript_source" else "javascript",
        "confidence": "lexical_candidate",
        "imports": imports,
        "external_packages": external_packages,
        "exports": exports,
        "endpoint_literals": endpoints,
        "endpoint_candidates": sorted(
            [value for value in endpoint_candidates if value["literal"] in endpoints],
            key=lambda value: (value["literal"], value["method"], value["operation"]),
        ),
        "client_wrappers": wrapper_bases[:100],
        "client_instances": axios_instances[:100],
        "interceptors": sorted(
            {
                match.group(1)
                for match in re.finditer(
                    r"\b([A-Za-z_$][\w$]*)\.interceptors\."
                    r"(?:request|response)\.use\s*\(",
                    source,
                )
            }
        )[:100],
        "truncated": (
            imports_truncated
            or exports_truncated
            or endpoints_truncated
            or endpoint_candidates_truncated
        ),
        "notice": (
            "Lexical boundary extraction resolves bounded literal client wrappers, Axios "
            "instances, interceptors, and base constants but does not resolve types, "
            "generated clients, arbitrary dynamic expressions, control flow, or runtime "
            "service wiring."
        ),
    }


def _deployment_boundary_facts(
    raw: bytes, kind: str, path: str
) -> dict[str, Any] | None:
    """Extract bounded deployment entities without evaluating templates or tooling."""

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    lower_name = Path(path).name.casefold()

    def add_entity(entity_kind: str, name: str, **details: Any) -> None:
        if not name or len(entities) >= MAX_DEPLOYMENT_ENTITIES:
            return
        identifier = f"{entity_kind}:{name}"
        if any(value["key"] == identifier for value in entities):
            return
        entities.append(
            {"key": identifier, "kind": entity_kind, "name": name, **details}
        )

    if lower_name.startswith("dockerfile"):
        for index, match in enumerate(
            re.finditer(
                r"(?im)^\s*FROM\s+([^\s]+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?", source
            )
        ):
            add_entity(
                "container_stage",
                match.group(2) or f"stage-{index + 1}",
                image=match.group(1),
            )
        for match in re.finditer(r"(?im)^\s*EXPOSE\s+([^\r\n#]+)", source):
            add_entity("port", match.group(1).strip())
        for match in re.finditer(r"(?im)^\s*ENV\s+([A-Za-z_][A-Za-z0-9_]*)", source):
            add_entity("environment_variable", match.group(1))
        if re.search(r"(?im)^\s*HEALTHCHECK\b", source):
            add_entity("healthcheck", "container-healthcheck")
    elif lower_name in {
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    }:
        in_services = False
        current_service = ""
        current_collection = ""

        def add_compose_relationship(collection: str, raw_value: str) -> None:
            value = raw_value.strip().strip("'\"")
            if not value:
                return
            if collection == "depends_on":
                target_kind, relation_kind = "service", "depends_on"
            elif collection == "networks":
                target_kind, relation_kind = "network", "uses_network"
            elif collection == "volumes":
                source = value.split(":", 1)[0]
                if not source or source.startswith((".", "/", "~")):
                    return
                value = source
                target_kind, relation_kind = "volume", "uses_volume"
            elif collection in {"configs", "secrets"}:
                target_kind, relation_kind = "configuration", "uses_configuration"
            elif collection == "ports":
                target_kind, relation_kind = "port", "exposes_port"
            elif collection == "environment":
                value = re.split(r"=|:", value, maxsplit=1)[0].strip()
                target_kind, relation_kind = "environment_variable", "uses_environment"
            else:
                return
            add_entity(target_kind, value)
            relationships.append(
                {
                    "source": f"service:{current_service}",
                    "target": f"{target_kind}:{value}",
                    "kind": relation_kind,
                }
            )

        for line in source.splitlines():
            if re.match(r"^services:\s*(?:#.*)?$", line):
                in_services = True
                current_service = ""
                current_collection = ""
                continue
            service_match = re.match(r"^\s{2}([A-Za-z0-9_.-]+):\s*(?:#.*)?$", line)
            if in_services and service_match:
                current_service = service_match.group(1)
                current_collection = ""
                add_entity("service", current_service)
                continue
            if in_services and line and not line.startswith(" "):
                in_services = False
                current_service = ""
                current_collection = ""
            if not current_service:
                continue
            image_match = re.match(r"^\s{4}image:\s*['\"]?([^'\"\s#]+)", line)
            if image_match:
                add_entity("image", image_match.group(1))
                relationships.append(
                    {
                        "source": f"service:{current_service}",
                        "target": f"image:{image_match.group(1)}",
                        "kind": "uses_image",
                    }
                )
                current_collection = ""
                continue
            depends_inline = re.match(r"^\s{4}depends_on:\s*\[([^]]+)\]", line)
            if depends_inline:
                for dependency in re.findall(
                    r"[A-Za-z0-9_.-]+", depends_inline.group(1)
                ):
                    add_compose_relationship("depends_on", dependency)
                current_collection = ""
                continue
            collection_match = re.match(
                r"^\s{4}(depends_on|networks|volumes|configs|secrets|ports|environment):\s*(?:#.*)?$",
                line,
            )
            if collection_match:
                current_collection = collection_match.group(1)
                continue
            if re.match(r"^\s{4}healthcheck:\s*(?:#.*)?$", line):
                add_entity("healthcheck", f"{current_service}-healthcheck")
                relationships.append(
                    {
                        "source": f"service:{current_service}",
                        "target": f"healthcheck:{current_service}-healthcheck",
                        "kind": "declares_healthcheck",
                    }
                )
                current_collection = ""
                continue
            if current_collection:
                list_item = re.match(r"^\s{6,}-\s*([^#]+?)\s*(?:#.*)?$", line)
                mapping_item = re.match(r"^\s{6}([A-Za-z0-9_.-]+):(?:\s*[^#]*)?$", line)
                if list_item:
                    add_compose_relationship(current_collection, list_item.group(1))
                    continue
                if mapping_item:
                    add_compose_relationship(current_collection, mapping_item.group(1))
                    continue
            if re.match(r"^\s{4}\S", line):
                current_collection = ""
    elif kind == "infrastructure" and Path(path).suffix.casefold() in {
        ".tf",
        ".tfvars",
    }:
        for match in re.finditer(
            r'(?m)^\s*(resource|data|module|provider)\s+"([^"]+)"(?:\s+"([^"]+)")?',
            source,
        ):
            entity_kind = f"terraform_{match.group(1)}"
            name = ".".join(value for value in match.groups()[1:] if value)
            add_entity(entity_kind, name)
        for match in re.finditer(r"\b([A-Za-z_]\w*\.[A-Za-z_]\w*)\b", source):
            reference = match.group(1)
            if not reference.startswith(("var.", "local.", "each.", "count.")):
                add_entity("terraform_reference", reference)
    elif kind == "infrastructure":
        documents = re.split(r"(?m)^---\s*$", source)
        for index, document in enumerate(documents):
            kind_match = re.search(r"(?m)^kind:\s*([A-Za-z0-9_.-]+)", document)
            name_match = re.search(
                r"(?ms)^metadata:\s*\n(?:\s+[^\n]*\n)*?\s+name:\s*([A-Za-z0-9_.-]+)",
                document,
            )
            if not kind_match:
                continue
            resource_kind = kind_match.group(1)
            name = name_match.group(1) if name_match else f"document-{index + 1}"
            add_entity(f"kubernetes_{resource_kind.casefold()}", name)
            for image in re.findall(r"(?m)^\s+image:\s*['\"]?([^'\"\s#]+)", document):
                add_entity("image", image)
                relationships.append(
                    {
                        "source": f"kubernetes_{resource_kind.casefold()}:{name}",
                        "target": f"image:{image}",
                        "kind": "uses_image",
                    }
                )
            for dependency in re.findall(
                r"(?m)^\s+(?:configMapRef|secretRef):\s*\n\s+name:\s*([A-Za-z0-9_.-]+)",
                document,
            ):
                relationships.append(
                    {
                        "source": f"kubernetes_{resource_kind.casefold()}:{name}",
                        "target": f"configuration:{dependency}",
                        "kind": "uses_configuration",
                    }
                )
    elif kind == "ci_configuration":
        for environment in re.findall(
            r"(?m)^\s*environment:\s*['\"]?([^'\"\s#]+)", source
        ):
            add_entity("deployment_environment", environment)
        for image in re.findall(
            r"(?m)^\s*(?:image|container):\s*['\"]?([^'\"\s#]+)", source
        ):
            add_entity("image", image)
    else:
        return None
    return {
        "format": "pysfmea-deployment-boundary-facts-1",
        "entities": entities,
        "relationships": relationships[:MAX_DEPLOYMENT_ENTITIES],
        "truncated": len(entities) >= MAX_DEPLOYMENT_ENTITIES
        or len(relationships) > MAX_DEPLOYMENT_ENTITIES,
        "authority": "bounded_lexical_deployment_declarations_not_deployed_runtime_state",
    }


def build_repository_inventory(
    root: Path,
    *,
    selected_python_paths: set[str],
    parsed_python_paths: set[str],
    include_tests: bool,
    exclude_patterns: Iterable[str] = (),
    boundary_evidence_include_patterns: Iterable[str] = (),
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
    boundary_traversal_roots: set[str] = set()
    relative_dir = "."
    for directory, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
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
            elif dirname in DEFAULT_EXCLUDES:
                reason = "Default generated, cache, environment, or vendor directory is excluded."
                status = "excluded_region"
            elif dirname.startswith(".") and dirname not in {".github"}:
                reason = "Hidden directory is excluded from repository analysis."
                status = "excluded_region"
            elif _matches(rel, exclude_patterns) or _matches(
                rel + "/__pysfmea_region__", exclude_patterns
            ):
                if _may_contain_match(rel, boundary_evidence_include_patterns):
                    kept_dirs.append(dirname)
                    boundary_traversal_roots.add(rel)
                    regions.append(
                        {
                            "path": rel + "/",
                            "status": "excluded_region",
                            "reason": (
                                "Directory is excluded from semantic analysis but traversed "
                                "for explicitly configured JS/TS boundary evidence."
                            ),
                        }
                    )
                    continue
                reason = "Directory matches a configured scan exclusion and is not traversed."
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
            configured_excluded = _matches(rel, exclude_patterns)
            boundary_evidence_override = (
                configured_excluded
                and kind in {"javascript_source", "typescript_source"}
                and _matches(rel, boundary_evidence_include_patterns)
            )
            traversed_for_boundary_only = any(
                rel.startswith(root_path + "/")
                for root_path in boundary_traversal_roots
            )
            if (
                configured_excluded
                and traversed_for_boundary_only
                and not boundary_evidence_override
            ):
                # The enclosing excluded region accounts for this path. Do not read
                # unrelated files solely because an evidence glob required traversal.
                continue
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
                metadata_size = metadata.st_size
            try:
                if hash_truncated:
                    record["size"] = len(raw) if raw is not None else metadata_size
                    record.update(
                        analysis_depth="metadata_only",
                        reason="Artifact digest omitted after the aggregate hashing limit.",
                    )
                else:
                    remaining = MAX_TOTAL_HASH_BYTES - hash_consumed
                    if remaining <= 0:
                        hash_truncated = True
                        record["size"] = (
                            len(raw) if raw is not None else metadata_size
                        )
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
                            record["snapshot_source"] = (
                                "identity_stable_inventory_snapshot"
                            )
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
            if configured_excluded and not boundary_evidence_override:
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
            elif (
                kind in {"python_source", "python_test"} and rel in parsed_python_paths
            ):
                record.update(
                    status="analyzed",
                    analysis_depth="python_ast",
                    reason="Python source parsed and analyzed without repository execution.",
                    adapter_ids=["python.repository_discoverer", "python.ast_parser"],
                )
            elif (
                kind in {"python_source", "python_test"}
                and rel in selected_python_paths
            ):
                record.update(
                    status="unresolved",
                    analysis_depth="tokenization_or_parse_failed",
                    reason="Python source was selected but could not be parsed.",
                    adapter_ids=["python.repository_discoverer", "python.ast_parser"],
                )
            elif snapshot_source == "dependency_manifest_snapshot":
                record.update(
                    status="indexed",
                    analysis_depth="dependency_manifest_index",
                    reason=(
                        "Dependency declarations and exact manifest identity were indexed by "
                        "the bounded dependency adapter."
                    ),
                    adapter_ids=[
                        "python.repository_discoverer",
                        "python.dependency_inventory",
                    ],
                )
            elif snapshot_source == "interface_contract_snapshot":
                record.update(
                    status="indexed",
                    analysis_depth="interface_contract_index",
                    reason=(
                        "Interface operations and data types were indexed from an exact bounded "
                        "contract snapshot."
                    ),
                    adapter_ids=[
                        "python.repository_discoverer",
                        "contracts.local_schema",
                    ],
                )
            elif snapshot_source == "coverage_evidence_snapshot":
                record.update(
                    status="indexed",
                    analysis_depth="coverage_evidence_index",
                    reason="Coverage evidence was indexed and bound to the scan manifest.",
                    adapter_ids=[
                        "python.repository_discoverer",
                        "coverage.py_json",
                    ],
                )
            elif kind in {
                "binary_or_generated",
                "unclassified",
            }:
                boundary_reason = record["reason"]
                record.update(
                    status="opaque",
                    analysis_depth=(
                        "metadata_and_digest" if record["sha256"] else "metadata_only"
                    ),
                    reason=(
                        ("No semantic analyzer is registered for this artifact type.")
                        if record["sha256"]
                        else boundary_reason
                    ),
                )
            elif kind in {"javascript_source", "typescript_source"}:
                boundary_facts = (
                    _language_boundary_facts(raw, kind) if raw is not None else None
                )
                if boundary_facts is None:
                    record.update(
                        status="opaque",
                        analysis_depth=(
                            "metadata_and_digest"
                            if record["sha256"]
                            else "metadata_only"
                        ),
                        reason=(
                            "Language-boundary source could not be decoded as UTF-8 for bounded "
                            "lexical interface indexing."
                        ),
                    )
                else:
                    record.update(
                        status="indexed",
                        analysis_depth="lexical_boundary_index",
                        reason=(
                            "Language-boundary imports, exports, packages, and literal endpoints "
                            "were indexed without claiming full semantic analysis."
                            + (
                                " The path remains excluded from semantic component analysis."
                                if boundary_evidence_override
                                else ""
                            )
                        ),
                        adapter_ids=[
                            "python.repository_discoverer",
                            "web.language_boundary_indexer",
                        ],
                        boundary_facts=boundary_facts,
                    )
            elif kind in {
                "container_or_deployment",
                "infrastructure",
                "ci_configuration",
            }:
                deployment_facts = (
                    _deployment_boundary_facts(raw, kind, rel)
                    if raw is not None
                    else None
                )
                if deployment_facts is None:
                    record.update(
                        status="opaque",
                        analysis_depth=(
                            "metadata_and_digest"
                            if record["sha256"]
                            else "metadata_only"
                        ),
                        reason="Deployment artifact could not be decoded for bounded lexical topology indexing.",
                    )
                else:
                    record.update(
                        status="indexed",
                        analysis_depth="deployment_topology_index",
                        reason="Deployment entities and declared relationships were indexed without claiming deployed runtime state.",
                        adapter_ids=[
                            "python.repository_discoverer",
                            "deployment.lexical_topology",
                        ],
                        deployment_facts=deployment_facts,
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
    material = {"entries": entries, "regions": regions, "truncated": truncated}
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "pysfmea-repository-inventory-1",
        **material,
        "summary": summarize_repository_inventory(entries, regions),
        "inventory_sha256": digest,
        "notice": (
            "Coverage is artifact accounting, not proof that every behavior or failure mode was "
            "analyzed. Indexed artifacts received metadata/digest handling only."
        ),
    }
