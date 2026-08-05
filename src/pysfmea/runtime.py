"""Import bounded runtime span evidence without treating observations as completeness proof."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any, Iterable

from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .store import refresh_summary

MAX_SPANS_PER_IMPORT = 50_000
MAX_RUNTIME_TRACE_BYTES = 100_000_000
MAX_RUNTIME_ATTRIBUTE_DEPTH = 32
MAX_RUNTIME_JSON_DEPTH = 100
MAX_RUNTIME_JSON_NODES = 2_000_000


def _attribute_value(value: Any, *, depth: int = 0) -> Any:
    if depth > MAX_RUNTIME_ATTRIBUTE_DEPTH:
        raise ValueError(
            f"runtime trace attribute nesting exceeds {MAX_RUNTIME_ATTRIBUTE_DEPTH} levels"
        )
    if isinstance(value, list):
        return [_attribute_value(entry, depth=depth + 1) for entry in value]
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        array_value = value["arrayValue"]
        if not isinstance(array_value, dict):
            return []
        values = array_value.get("values", [])
        if not isinstance(values, list):
            return []
        return [_attribute_value(entry, depth=depth + 1) for entry in values]
    return {
        str(key): _attribute_value(entry, depth=depth + 1)
        for key, entry in value.items()
    }


def _attributes(values: Any) -> dict[str, Any]:
    if isinstance(values, dict):
        return {
            str(key): _attribute_value(value)
            for key, value in values.items()
        }
    if not isinstance(values, list):
        return {}
    result = {}
    for entry in values:
        if isinstance(entry, dict) and entry.get("key"):
            result[str(entry["key"])] = _attribute_value(entry.get("value"))
    return result


def _iter_spans(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for value in payload:
            if isinstance(value, dict):
                yield value
        return
    if not isinstance(payload, dict):
        return
    spans = payload.get("spans", [])
    if isinstance(spans, list):
        for span in spans:
            if isinstance(span, dict):
                yield span
    resources = payload.get("resourceSpans", [])
    if not isinstance(resources, list):
        return
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        resource_value = resource.get("resource", {})
        resource_attributes = _attributes(
            resource_value.get("attributes", [])
            if isinstance(resource_value, dict)
            else []
        )
        scopes = resource.get(
            "scopeSpans",
            resource.get("instrumentationLibrarySpans", []),
        )
        if not isinstance(scopes, list):
            continue
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            scope_spans = scope.get("spans", [])
            if not isinstance(scope_spans, list):
                continue
            for span in scope_spans:
                if isinstance(span, dict):
                    yield {**span, "_resource_attributes": resource_attributes}


def _read_runtime_trace(path: Path) -> tuple[Any, bytes]:
    """Read strict runtime JSON and retain the exact identity-stable bytes."""

    try:
        document = load_bounded_json_document(
            path,
            label="runtime trace",
            max_bytes=MAX_RUNTIME_TRACE_BYTES,
            max_depth=MAX_RUNTIME_JSON_DEPTH,
            max_nodes=MAX_RUNTIME_JSON_NODES,
        )
    except ValueError as exc:
        message = str(exc)
        if message == f"runtime trace exceeds the {MAX_RUNTIME_TRACE_BYTES}-byte limit":
            raise ValueError(
                f"runtime trace exceeds the {MAX_RUNTIME_TRACE_BYTES}-byte import limit"
            ) from exc
        if message in {
            "runtime trace is not valid UTF-8 JSON",
            "runtime trace is not valid JSON",
            "runtime trace exceeds the JSON parser nesting limit",
        }:
            raise ValueError("runtime trace is not valid bounded UTF-8 JSON") from exc
        raise
    payload = document.value
    if not isinstance(payload, (dict, list)):
        raise ValueError("runtime trace root must be an object or array")
    return payload, document.raw


def _component_lookup(analysis: dict[str, Any]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    collisions: set[str] = set()
    for component in analysis.get("components", []):
        component_id = component.get("id", "")
        for value in (
            component.get("name", ""),
            component.get("qualname", ""),
            f"{component.get('source', {}).get('path', '')}:{component.get('qualname', '')}",
        ):
            if not value:
                continue
            if value in lookup and lookup[value] != component_id:
                collisions.add(value)
            else:
                lookup[value] = component_id
    for value in collisions:
        lookup.pop(value, None)
    return lookup


def _component_from_span(
    analysis: dict[str, Any], lookup: dict[str, str], attributes: dict[str, Any], name: str
) -> tuple[str, str, str]:
    for attribute_name in ("sfmea.component", "code.function", "code.function.name"):
        reference = str(attributes.get(attribute_name, ""))
        if reference and reference in lookup:
            return lookup[reference], attribute_name, reference
    if name in lookup:
        return lookup[name], "span.name", name

    file_reference = str(
        attributes.get("code.file.path") or attributes.get("code.filepath") or ""
    ).replace("\\", "/")
    function_reference = str(
        attributes.get("code.function.name") or attributes.get("code.function") or name
    )
    if file_reference and function_reference:
        matches = []
        for component in analysis.get("components", []):
            component_path = str(component.get("source", {}).get("path", "")).replace(
                "\\", "/"
            )
            if not component_path or not file_reference.endswith(component_path):
                continue
            if function_reference in {
                component.get("name", ""),
                component.get("qualname", ""),
            }:
                matches.append(component.get("id", ""))
        matches = sorted(set(value for value in matches if value))
        if len(matches) == 1:
            return matches[0], "code.file.path+function", f"{file_reference}:{function_reference}"
    return "", "unmapped", function_reference or name


def import_runtime_trace(
    analysis: dict[str, Any], source: str | Path, *, label: str = ""
) -> dict[str, Any]:
    """Import simple or OTLP JSON spans and derive parent-child evidence edges."""

    label = label.strip()
    if len(label) > 500 or any(ord(value) < 32 for value in label):
        raise ValueError("runtime trace label must be at most 500 printable characters")
    path = Path(source).expanduser().absolute()
    payload, raw = _read_runtime_trace(path)
    digest = hashlib.sha256(raw).hexdigest()
    supplied_evidence = analysis.get("runtime_evidence")
    if supplied_evidence is None:
        evidence: dict[str, Any] = {"imports": [], "spans": [], "edges": []}
    elif not isinstance(supplied_evidence, dict) or not all(
        isinstance(supplied_evidence.get(key), list)
        for key in ("imports", "spans", "edges")
    ):
        raise ValueError("analysis runtime evidence container is malformed")
    else:
        evidence = supplied_evidence
    existing_import = next(
        (record for record in evidence["imports"] if record.get("sha256") == digest),
        None,
    )
    if existing_import:
        return {**existing_import, "duplicate": True}
    lookup = _component_lookup(analysis)
    normalized: list[dict[str, Any]] = []
    for index, span in enumerate(_iter_spans(payload)):
        if index >= MAX_SPANS_PER_IMPORT:
            raise ValueError(f"runtime trace exceeds {MAX_SPANS_PER_IMPORT} spans")
        attributes = {
            **_attributes(span.get("_resource_attributes", {})),
            **_attributes(span.get("attributes", {})),
        }
        name = str(span.get("name") or attributes.get("code.function.name") or "unnamed span")
        component_reference = str(
            attributes.get("sfmea.component")
            or attributes.get("code.function")
            or attributes.get("code.function.name")
            or name
        )
        component_id, mapping_method, matched_reference = _component_from_span(
            analysis, lookup, attributes, name
        )
        normalized.append(
            {
                "trace_id": str(span.get("traceId", span.get("trace_id", ""))),
                "span_id": str(span.get("spanId", span.get("span_id", f"span-{index}"))),
                "parent_span_id": str(
                    span.get("parentSpanId", span.get("parent_span_id", ""))
                ),
                "name": name,
                "component_id": component_id,
                "component_reference": component_reference,
                "mapping_method": mapping_method,
                "matched_reference": matched_reference,
                "start_time": str(
                    span.get("startTimeUnixNano", span.get("start_time", ""))
                ),
                "end_time": str(span.get("endTimeUnixNano", span.get("end_time", ""))),
                "status": span.get("status", {}),
                "attributes": attributes,
            }
        )
    if not normalized:
        raise ValueError("runtime trace contains no recognizable spans")
    by_key = {(span["trace_id"], span["span_id"]): span for span in normalized}
    edges = []
    for span in normalized:
        parent = by_key.get((span["trace_id"], span["parent_span_id"]))
        if not parent:
            continue
        edges.append(
            {
                "trace_id": span["trace_id"],
                "source_span_id": parent["span_id"],
                "target_span_id": span["span_id"],
                "source_component_id": parent["component_id"],
                "target_component_id": span["component_id"],
                "source_name": parent["name"],
                "target_name": span["name"],
                "operation": span["name"],
                "evidence": "observed_runtime",
            }
        )
    existing = {(span.get("trace_id"), span.get("span_id")) for span in evidence["spans"]}
    new_spans = [span for span in normalized if (span["trace_id"], span["span_id"]) not in existing]
    existing_edges = {
        (edge.get("trace_id"), edge.get("source_span_id"), edge.get("target_span_id"))
        for edge in evidence["edges"]
    }
    new_edges = [
        edge
        for edge in edges
        if (edge["trace_id"], edge["source_span_id"], edge["target_span_id"])
        not in existing_edges
    ]
    imported_at = utc_now()
    import_record = {
        "id": "TRACE-" + digest[:12].upper(),
        "source": str(path),
        "label": label,
        "sha256": digest,
        "imported_at": imported_at,
        "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", ""),
        "span_count": len(normalized),
        "new_span_count": len(new_spans),
        "mapped_span_count": sum(bool(span["component_id"]) for span in normalized),
        "unmapped_span_count": sum(not span["component_id"] for span in normalized),
        "mapping_methods": {
            method: sum(span["mapping_method"] == method for span in normalized)
            for method in sorted({span["mapping_method"] for span in normalized})
        },
        "duplicate": False,
        "notice": "Observed traces demonstrate captured executions only; they do not prove path completeness.",
    }
    history = analysis.get("history")
    if history is not None and not isinstance(history, list):
        raise ValueError("analysis history container is malformed")
    analysis_snapshot = copy.deepcopy(analysis)
    try:
        if supplied_evidence is None:
            analysis["runtime_evidence"] = evidence
        evidence["spans"].extend(new_spans)
        evidence["edges"].extend(new_edges)
        evidence["imports"].append(import_record)
        analysis.setdefault("history", []).append(
            {"event": "runtime_trace_import", "at": imported_at, **import_record}
        )
        refresh_summary(analysis)
    except Exception:
        analysis.clear()
        analysis.update(analysis_snapshot)
        raise
    return import_record
