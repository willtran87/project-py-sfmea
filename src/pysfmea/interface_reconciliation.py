"""Bounded reconciliation of Python routes and web-client endpoint literals."""

from __future__ import annotations

import re
import urllib.parse
from collections import defaultdict
from typing import Any

from .model import stable_id

MAX_INTERFACE_RECORDS = 20_000


def _is_web_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    parts = normalized.split("/")
    name = parts[-1] if parts else ""
    return (
        any(part in {"__tests__", "test", "tests", "e2e"} for part in parts[:-1])
        or ".test." in name
        or ".spec." in name
    )


def normalize_interface_path(value: str) -> str:
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
    components: list[dict[str, Any]],
    inventory: dict[str, Any],
    *,
    dispositions: list[dict[str, Any]] | None = None,
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
            normalized = normalize_interface_path(raw_path)
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
                    "declared_path": endpoint.get("declared_path", raw_path),
                    "router_prefix": endpoint.get("router_prefix", ""),
                    "mount_prefix": endpoint.get("mount_prefix", ""),
                    "normalized_path": normalized,
                    "methods": list(endpoint.get("methods", [])),
                    "source": {
                        "path": source.get("path", ""),
                        "line": source.get("line", 0),
                    },
                    "confidence": endpoint.get("confidence", "static_literal"),
                    "registration_source": endpoint.get("registration_source", {}),
                    "registration_confidence": endpoint.get(
                        "registration_confidence", ""
                    ),
                }
            )
            if len(backend) >= MAX_INTERFACE_RECORDS:
                break
        if len(backend) >= MAX_INTERFACE_RECORDS:
            break

    clients: list[dict[str, Any]] = []
    global_base_symbols: dict[str, set[str]] = defaultdict(set)
    wrapper_base_symbols: dict[str, set[str]] = defaultdict(set)
    for entry in inventory.get("entries", []):
        if _is_web_test_path(str(entry.get("path", ""))):
            continue
        facts = entry.get("boundary_facts", {})
        if not isinstance(facts, dict):
            continue
        for candidate in facts.get("endpoint_candidates", []):
            if not isinstance(candidate, dict) or candidate.get("method") != "BASE":
                continue
            operation = str(candidate.get("operation", ""))
            if not operation.startswith("constant:"):
                continue
            normalized = normalize_interface_path(str(candidate.get("literal", "")))
            if normalized:
                global_base_symbols[operation.partition(":")[2]].add(normalized)
        for wrapper in facts.get("client_wrappers", []):
            if (
                isinstance(wrapper, dict)
                and wrapper.get("operation")
                and wrapper.get("base_symbol")
            ):
                wrapper_base_symbols[str(wrapper["operation"])].add(
                    str(wrapper["base_symbol"])
                )
    for entry in inventory.get("entries", []):
        facts = entry.get("boundary_facts", {})
        if not isinstance(facts, dict):
            continue
        candidates = facts.get("endpoint_candidates", [])
        if not isinstance(candidates, list):
            continue
        base_paths = [
            normalize_interface_path(str(value.get("literal", "")))
            for value in candidates
            if isinstance(value, dict) and value.get("method") == "BASE"
        ]
        base_paths = sorted({value for value in base_paths if value})
        test_source = _is_web_test_path(str(entry.get("path", "")))
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            literal = str(candidate.get("literal", ""))
            normalized = normalize_interface_path(literal)
            composed_paths: list[str] = []
            if candidate.get("method") != "BASE":
                resolved_base_paths = set(base_paths)
                leading_symbol = re.match(r"^\$\{([A-Za-z_$][\w$]*)\}", literal)
                if leading_symbol:
                    resolved_base_paths.update(
                        global_base_symbols.get(leading_symbol.group(1), set())
                    )
                for symbol in wrapper_base_symbols.get(
                    str(candidate.get("operation", "")), set()
                ):
                    resolved_base_paths.update(global_base_symbols.get(symbol, set()))
                endpoint_suffix = normalized or (
                    "/" + literal.lstrip("/")
                    if literal and "://" not in literal
                    else ""
                )
                for base_path in sorted(resolved_base_paths):
                    if endpoint_suffix:
                        composed = normalize_interface_path(
                            base_path.rstrip("/") + "/" + endpoint_suffix.lstrip("/")
                        )
                        if composed and composed != normalized:
                            composed_paths.append(composed)
            clients.append(
                {
                    "id": stable_id(
                        "IFACE-CLIENT",
                        str(entry.get("path", "")),
                        literal,
                        str(candidate.get("method", "UNKNOWN")),
                    ),
                    "source_path": entry.get("path", ""),
                    "line": candidate.get("line", 0),
                    "literal": literal,
                    "normalized_path": normalized,
                    "composed_normalized_paths": sorted(set(composed_paths)),
                    "base_configurations": base_paths,
                    "resolved_base_configurations": sorted(
                        {
                            path.rsplit(normalized, 1)[0].rstrip("/") or "/"
                            for path in composed_paths
                            if normalized and path.endswith(normalized)
                        }
                    ),
                    "method": candidate.get("method", "UNKNOWN"),
                    "operation": candidate.get("operation", ""),
                    "confidence": candidate.get("confidence", "lexical_literal"),
                    "classification": (
                        "test_evidence_candidate"
                        if test_source
                        else "base_configuration"
                        if candidate.get("method") == "BASE"
                        else "endpoint_candidate"
                        if normalized or composed_paths
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
    compatibility_findings: list[dict[str, Any]] = []
    matched_client_ids: set[str] = set()
    matched_backend_ids: set[str] = set()
    for client in clients:
        if client["classification"] != "endpoint_candidate":
            continue
        candidate_paths = [
            value
            for value in [
                client["normalized_path"],
                *client.get("composed_normalized_paths", []),
            ]
            if value
        ]
        for candidate_path in candidate_paths:
            routes = backend_by_path.get(candidate_path, [])
            client_method = str(client["method"])
            compatible_routes = [
                route
                for route in routes
                if client_method == "UNKNOWN"
                or bool(set(route["methods"]).intersection({client_method, "ANY"}))
            ]
            if routes and not compatible_routes:
                route_ids = sorted(str(route["id"]) for route in routes)
                server_methods = sorted(
                    {method for route in routes for method in route["methods"]}
                )
                compatibility_findings.append(
                    {
                        "id": stable_id(
                            "IFACE-METHOD-GAP", client["id"], candidate_path
                        ),
                        "kind": "method_mismatch_candidate",
                        "client_endpoint_id": client["id"],
                        "server_route_id": route_ids[0],
                        "server_route_ids": route_ids,
                        "normalized_path": candidate_path,
                        "client_method": client_method,
                        "server_methods": server_methods,
                        "severity": "review",
                        "notice": "Static literals share a path but no discovered route declares a compatible HTTP method.",
                    }
                )
                continue
            for route in compatible_routes:
                matches.append(
                    {
                        "id": stable_id("IFACE-MATCH", client["id"], route["id"]),
                        "client_endpoint_id": client["id"],
                        "server_route_id": route["id"],
                        "normalized_path": candidate_path,
                        "method": client_method,
                        "confidence": (
                            "static_literal_composed_base_path"
                            if candidate_path != client["normalized_path"]
                            else "static_literal_exact_path"
                        ),
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
    unmatched_clients = [
        value for value in endpoint_clients if value["id"] not in matched_client_ids
    ]
    for client in unmatched_clients:
        if any(
            value.get("client_endpoint_id") == client["id"]
            for value in compatibility_findings
        ):
            continue
        compatibility_findings.append(
            {
                "id": stable_id("IFACE-PATH-GAP", client["id"]),
                "kind": "unmatched_client_path_candidate",
                "client_endpoint_id": client["id"],
                "normalized_paths": [
                    value
                    for value in [
                        client.get("normalized_path", ""),
                        *client.get("composed_normalized_paths", []),
                    ]
                    if value
                ],
                "severity": "review",
                "notice": "No statically discovered Python route matched this client path candidate.",
            }
        )
    configured_dispositions = [
        value for value in (dispositions or []) if isinstance(value, dict)
    ]
    dispositions_by_id = {
        str(value.get("endpoint_id", "")): value
        for value in configured_dispositions
        if value.get("endpoint_id")
    }
    applied_disposition_ids: set[str] = set()
    for side, records in (("server", backend), ("client", endpoint_clients)):
        for record in records:
            endpoint_id = str(record.get("id", ""))
            disposition = dispositions_by_id.get(endpoint_id)
            if disposition is None or disposition.get("side") != side:
                continue
            record["reviewed_disposition"] = {
                "decision": str(disposition.get("decision", "")),
                "rationale": str(disposition.get("rationale", "")),
                "reviewed_by": str(disposition.get("reviewed_by", "")),
                "effective_date": str(disposition.get("effective_date", "")),
                "authority": "named_static_interface_disposition_not_runtime_evidence",
            }
            applied_disposition_ids.add(endpoint_id)
    for finding in compatibility_findings:
        endpoint_ids = {
            str(finding.get("client_endpoint_id", "")),
            str(finding.get("server_route_id", "")),
        }
        linked = [
            dispositions_by_id[value]
            for value in sorted(endpoint_ids & applied_disposition_ids)
            if value in dispositions_by_id
        ]
        if linked:
            finding["reviewed_dispositions"] = [
                {
                    "endpoint_id": str(value.get("endpoint_id", "")),
                    "decision": str(value.get("decision", "")),
                    "reviewed_by": str(value.get("reviewed_by", "")),
                    "effective_date": str(value.get("effective_date", "")),
                }
                for value in linked
            ]
    sequences = [
        {
            "id": stable_id("IFACE-SEQUENCE", value["id"]),
            "kind": "static_cross_stack_request_candidate",
            "steps": [
                {
                    "order": 1,
                    "entity_id": value["client_endpoint_id"],
                    "role": "client_request",
                },
                {
                    "order": 2,
                    "entity_id": value["server_route_id"],
                    "role": "server_route",
                },
                {
                    "order": 3,
                    "entity_id": value["client_endpoint_id"],
                    "role": "response_or_failure_effect",
                },
            ],
            "normalized_path": value["normalized_path"],
            "confidence": value["confidence"],
            "notice": "Static sequence candidate; ordering, timing, retries, and deployment reachability require runtime evidence.",
        }
        for value in matches
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
            "test_evidence_candidates": sum(
                value["classification"] == "test_evidence_candidate"
                for value in clients
            ),
            "exact_matches": len(matches),
            "matched_client_endpoints": len(matched_client_ids),
            "unmatched_client_endpoints": len(endpoint_clients)
            - len(matched_client_ids),
            "matched_server_routes": len(matched_backend_ids),
            "unmatched_server_routes": len(backend) - len(matched_backend_ids),
            "compatibility_findings": len(compatibility_findings),
            "configured_dispositions": len(configured_dispositions),
            "applied_dispositions": len(applied_disposition_ids),
            "unmatched_disposition_ids": len(dispositions_by_id)
            - len(applied_disposition_ids),
            "static_sequences": len(sequences),
            "truncated": len(backend) >= MAX_INTERFACE_RECORDS
            or len(clients) >= MAX_INTERFACE_RECORDS,
        },
        "server_routes": backend,
        "client_endpoints": clients,
        "matches": matches,
        "compatibility_findings": compatibility_findings,
        "sequences": sequences,
        "disposition_reconciliation": {
            "configured": len(configured_dispositions),
            "applied": len(applied_disposition_ids),
            "unmatched_endpoint_ids": sorted(
                set(dispositions_by_id) - applied_disposition_ids
            ),
            "authority": "review_history_not_runtime_reachability_or_compatibility_proof",
        },
        "limitations": [
            "Exact static path matching does not prove deployed connectivity or compatibility.",
            "Literal APIRouter/Blueprint prefixes, bounded static include_router/register_blueprint registrations, same-file baseURL values, named base constants, and conventional request wrappers are composed; dynamic registrations, reverse proxies, generated clients, arbitrary variables, and runtime configuration can remain unresolved.",
            "Fetch calls without a bounded literal method option are recorded with an unknown method.",
            "Schema and media-type compatibility require governed contracts or runtime evidence and are not inferred from path agreement.",
            "Unmatched records are review leads, not confirmed defects.",
            "Endpoint literals from conventional web test paths remain indexed as test evidence but are excluded from deployed-client reconciliation metrics.",
        ],
    }
