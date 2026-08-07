"""Bounded reconciliation of Python routes and web-client endpoint literals."""

from __future__ import annotations

import re
import urllib.parse
from collections import defaultdict
from typing import Any

from .model import stable_id

MAX_INTERFACE_RECORDS = 20_000


def _normalized_path(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        text = parsed.path
    else:
        slash = text.find("/")
        if slash > 0 and ("${" in text[:slash] or "{" in text[:slash]):
            text = text[slash:]
        text = text.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/"):
        return ""
    text = re.sub(r"\$?\{[^}/]+\}", "{parameter}", text)
    text = re.sub(r"(?<=/):[A-Za-z_$][\w$]*", "{parameter}", text)
    text = re.sub(r"/{2,}", "/", text)
    return text.rstrip("/") or "/"


def reconcile_cross_stack_interfaces(
    components: list[dict[str, Any]], inventory: dict[str, Any]
) -> dict[str, Any]:
    """Relate bounded route declarations to bounded JS/TS endpoint literals.

    The result is discovery evidence, not proof of deployed reachability. Router
    prefixes, proxies, generated clients, variables, and runtime configuration can
    change the effective path and therefore remain explicit limitations.
    """

    backend: list[dict[str, Any]] = []
    for component in components:
        source = component.get("source", {})
        for endpoint in component.get("interface_endpoints", []):
            if not isinstance(endpoint, dict) or endpoint.get("kind") != "http_route":
                continue
            raw_path = str(endpoint.get("path", ""))
            normalized = _normalized_path(raw_path)
            if not normalized:
                continue
            backend.append(
                {
                    "id": stable_id(
                        "IFACE-SERVER",
                        str(component.get("id", "")),
                        raw_path,
                        ",".join(endpoint.get("methods", [])),
                    ),
                    "component_id": component.get("id", ""),
                    "component": component.get("qualname", ""),
                    "path": raw_path,
                    "normalized_path": normalized,
                    "methods": list(endpoint.get("methods", [])),
                    "source": {
                        "path": source.get("path", ""),
                        "line": source.get("line", 0),
                    },
                    "confidence": endpoint.get("confidence", "static_literal"),
                }
            )
            if len(backend) >= MAX_INTERFACE_RECORDS:
                break
        if len(backend) >= MAX_INTERFACE_RECORDS:
            break

    clients: list[dict[str, Any]] = []
    for entry in inventory.get("entries", []):
        facts = entry.get("boundary_facts", {})
        if not isinstance(facts, dict):
            continue
        candidates = facts.get("endpoint_candidates", [])
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            literal = str(candidate.get("literal", ""))
            normalized = _normalized_path(literal)
            clients.append(
                {
                    "id": stable_id(
                        "IFACE-CLIENT",
                        str(entry.get("path", "")),
                        literal,
                        str(candidate.get("method", "UNKNOWN")),
                    ),
                    "source_path": entry.get("path", ""),
                    "literal": literal,
                    "normalized_path": normalized,
                    "method": candidate.get("method", "UNKNOWN"),
                    "operation": candidate.get("operation", ""),
                    "confidence": candidate.get("confidence", "lexical_literal"),
                    "classification": (
                        "base_configuration"
                        if candidate.get("method") == "BASE"
                        else "endpoint_candidate"
                        if normalized
                        else "dynamic_or_non_path"
                    ),
                }
            )
            if len(clients) >= MAX_INTERFACE_RECORDS:
                break
        if len(clients) >= MAX_INTERFACE_RECORDS:
            break

    backend_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for route in backend:
        backend_by_path[route["normalized_path"]].append(route)
    matches: list[dict[str, Any]] = []
    matched_client_ids: set[str] = set()
    matched_backend_ids: set[str] = set()
    for client in clients:
        if client["classification"] != "endpoint_candidate":
            continue
        for route in backend_by_path.get(client["normalized_path"], []):
            client_method = str(client["method"])
            methods = set(route["methods"])
            method_compatible = client_method == "UNKNOWN" or bool(
                methods.intersection({client_method, "ANY"})
            )
            if not method_compatible:
                continue
            matches.append(
                {
                    "id": stable_id("IFACE-MATCH", client["id"], route["id"]),
                    "client_endpoint_id": client["id"],
                    "server_route_id": route["id"],
                    "normalized_path": client["normalized_path"],
                    "method": client_method,
                    "confidence": "static_literal_exact_path",
                    "evidence": (
                        "Client and server literals have the same normalized path; "
                        "unknown client methods match any declared server method."
                    ),
                }
            )
            matched_client_ids.add(client["id"])
            matched_backend_ids.add(route["id"])

    endpoint_clients = [
        value for value in clients if value["classification"] == "endpoint_candidate"
    ]
    return {
        "format": "pysfmea-cross-stack-interface-reconciliation-1",
        "authority": "derived_static_discovery_evidence_not_runtime_reachability",
        "summary": {
            "server_routes": len(backend),
            "client_endpoint_candidates": len(endpoint_clients),
            "base_configurations": sum(
                value["classification"] == "base_configuration" for value in clients
            ),
            "dynamic_or_non_path": sum(
                value["classification"] == "dynamic_or_non_path" for value in clients
            ),
            "exact_matches": len(matches),
            "matched_client_endpoints": len(matched_client_ids),
            "unmatched_client_endpoints": len(endpoint_clients)
            - len(matched_client_ids),
            "matched_server_routes": len(matched_backend_ids),
            "unmatched_server_routes": len(backend) - len(matched_backend_ids),
            "truncated": len(backend) >= MAX_INTERFACE_RECORDS
            or len(clients) >= MAX_INTERFACE_RECORDS,
        },
        "server_routes": backend,
        "client_endpoints": clients,
        "matches": matches,
        "limitations": [
            "Exact static path matching does not prove deployed connectivity or compatibility.",
            "Router prefixes, reverse proxies, generated clients, variables, and runtime configuration are not resolved.",
            "Fetch calls without an explicit method are recorded with an unknown method.",
            "Unmatched records are review leads, not confirmed defects.",
        ],
    }
