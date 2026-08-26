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
MAX_RUNTIME_EXPECTED_COMPONENTS = 10_000
MAX_RUNTIME_EXPECTED_RELATIONSHIPS = 20_000
MAX_RUNTIME_MANIFEST_TEXT = 4_096
RUNTIME_INSTRUMENTATION_FORMAT = "pysfmea-runtime-instrumentation-1"


def _manifest_text(value: Any, *, field: str, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"runtime instrumentation {field} must be a string")
    normalized = value.strip()
    if (required and not normalized) or len(normalized) > MAX_RUNTIME_MANIFEST_TEXT:
        raise ValueError(
            f"runtime instrumentation {field} must be a non-empty string within "
            f"{MAX_RUNTIME_MANIFEST_TEXT} characters"
        )
    if any(ord(character) < 32 for character in normalized):
        raise ValueError(f"runtime instrumentation {field} must be printable")
    return normalized


def _instrumentation_coverage(
    payload: Any,
    lookup: dict[str, str],
    normalized_spans: list[dict[str, Any]],
) -> dict[str, Any]:
    manifest = (
        payload.get("sfmea_instrumentation") if isinstance(payload, dict) else None
    )
    if manifest is None:
        return {
            "declared": False,
            "status": "undeclared",
            "coverage_percent": None,
            "notice": (
                "No instrumentation manifest was supplied; observed spans cannot be assessed "
                "against an expected component scope."
            ),
        }
    if not isinstance(manifest, dict):
        raise ValueError("runtime instrumentation manifest must be an object")
    allowed = {
        "schema_version",
        "scenario_id",
        "producer",
        "clock_domain",
        "sampling_policy",
        "expected_components",
        "expected_relationships",
        "dropped_spans",
        "declared_complete",
    }
    if unknown_fields := set(manifest) - allowed:
        raise ValueError(
            "runtime instrumentation manifest contains unsupported fields: "
            + ", ".join(sorted(unknown_fields))
        )
    if manifest.get("schema_version") != RUNTIME_INSTRUMENTATION_FORMAT:
        raise ValueError(
            "runtime instrumentation schema_version is missing or unsupported"
        )
    scenario_id = _manifest_text(manifest.get("scenario_id"), field="scenario_id")
    producer = _manifest_text(manifest.get("producer"), field="producer")
    clock_domain = _manifest_text(manifest.get("clock_domain"), field="clock_domain")
    sampling_policy = _manifest_text(
        manifest.get("sampling_policy"), field="sampling_policy"
    )
    if sampling_policy not in {"always_on", "head_sampled", "tail_sampled", "unknown"}:
        raise ValueError("runtime instrumentation sampling_policy is unsupported")
    expected = manifest.get("expected_components")
    if not isinstance(expected, list) or not expected:
        raise ValueError(
            "runtime instrumentation expected_components must be a non-empty array"
        )
    if len(expected) > MAX_RUNTIME_EXPECTED_COMPONENTS:
        raise ValueError(
            "runtime instrumentation expected_components exceed the "
            f"{MAX_RUNTIME_EXPECTED_COMPONENTS}-record limit"
        )
    expected_references = [
        _manifest_text(value, field="expected component") for value in expected
    ]
    if len(expected_references) != len(set(expected_references)):
        raise ValueError("runtime instrumentation expected_components must be unique")
    expected_relationship_values = manifest.get("expected_relationships", [])
    if not isinstance(expected_relationship_values, list):
        raise ValueError(
            "runtime instrumentation expected_relationships must be an array"
        )
    if len(expected_relationship_values) > MAX_RUNTIME_EXPECTED_RELATIONSHIPS:
        raise ValueError(
            "runtime instrumentation expected_relationships exceed the "
            f"{MAX_RUNTIME_EXPECTED_RELATIONSHIPS}-record limit"
        )
    expected_relationships: list[dict[str, str]] = []
    for index, relationship in enumerate(expected_relationship_values, start=1):
        if not isinstance(relationship, dict) or set(relationship) != {
            "source",
            "target",
        }:
            raise ValueError(
                f"runtime instrumentation expected relationship {index} must contain "
                "exactly source and target"
            )
        expected_relationships.append(
            {
                "source": _manifest_text(
                    relationship.get("source"), field="expected relationship source"
                ),
                "target": _manifest_text(
                    relationship.get("target"), field="expected relationship target"
                ),
            }
        )
    relationship_keys = {
        (value["source"], value["target"]) for value in expected_relationships
    }
    if len(expected_relationships) != len(relationship_keys):
        raise ValueError(
            "runtime instrumentation expected_relationships must be unique"
        )
    dropped_spans = manifest.get("dropped_spans")
    if (
        not isinstance(dropped_spans, int)
        or isinstance(dropped_spans, bool)
        or dropped_spans < 0
    ):
        raise ValueError(
            "runtime instrumentation dropped_spans must be a non-negative integer"
        )
    if not isinstance(manifest.get("declared_complete"), bool):
        raise ValueError("runtime instrumentation declared_complete must be a boolean")
    component_ids = set(lookup.values())
    resolved = {
        reference: reference
        if reference in component_ids
        else lookup.get(reference, "")
        for reference in expected_references
    }
    unknown_expected = sorted(
        reference for reference, component_id in resolved.items() if not component_id
    )
    observed_ids = {
        str(span.get("component_id", ""))
        for span in normalized_spans
        if span.get("component_id")
    }
    missing = sorted(
        reference
        for reference, component_id in resolved.items()
        if component_id and component_id not in observed_ids
    )
    observed_expected = len(expected_references) - len(unknown_expected) - len(missing)
    coverage = round(observed_expected * 100 / len(expected_references), 1)
    resolved_relationships: dict[tuple[str, str], tuple[str, str]] = {}
    unknown_relationships: list[dict[str, str]] = []
    for relationship in expected_relationships:
        source_reference = relationship["source"]
        target_reference = relationship["target"]
        source_id = (
            source_reference
            if source_reference in component_ids
            else lookup.get(source_reference, "")
        )
        target_id = (
            target_reference
            if target_reference in component_ids
            else lookup.get(target_reference, "")
        )
        if not source_id or not target_id:
            unknown_relationships.append(relationship)
            continue
        resolved_relationships[(source_reference, target_reference)] = (
            source_id,
            target_id,
        )
    spans_by_key = {
        (str(span.get("trace_id", "")), str(span.get("span_id", ""))): span
        for span in normalized_spans
    }
    observed_relationships: set[tuple[str, str]] = set()
    for span in normalized_spans:
        parent = spans_by_key.get(
            (str(span.get("trace_id", "")), str(span.get("parent_span_id", "")))
        )
        if not parent:
            continue
        source_id = str(parent.get("component_id", ""))
        target_id = str(span.get("component_id", ""))
        if source_id and target_id:
            observed_relationships.add((source_id, target_id))
    missing_relationships = [
        {"source": references[0], "target": references[1]}
        for references, component_pair in sorted(resolved_relationships.items())
        if component_pair not in observed_relationships
    ]
    observed_expected_relationships = (
        len(expected_relationships)
        - len(unknown_relationships)
        - len(missing_relationships)
    )
    relationship_coverage = (
        round(observed_expected_relationships * 100 / len(expected_relationships), 1)
        if expected_relationships
        else None
    )
    complete = (
        manifest["declared_complete"]
        and sampling_policy == "always_on"
        and dropped_spans == 0
        and not unknown_expected
        and not missing
        and not unknown_relationships
        and not missing_relationships
    )
    return {
        "declared": True,
        "schema_version": RUNTIME_INSTRUMENTATION_FORMAT,
        "scenario_id": scenario_id,
        "producer": producer,
        "clock_domain": clock_domain,
        "sampling_policy": sampling_policy,
        "declared_complete": manifest["declared_complete"],
        "dropped_spans": dropped_spans,
        "expected_component_count": len(expected_references),
        "resolved_expected_component_count": len(expected_references)
        - len(unknown_expected),
        "observed_expected_component_count": observed_expected,
        "coverage_percent": coverage,
        "missing_expected_components": missing,
        "unknown_expected_components": unknown_expected,
        "expected_relationship_count": len(expected_relationships),
        "resolved_expected_relationship_count": len(resolved_relationships),
        "observed_expected_relationship_count": observed_expected_relationships,
        "relationship_coverage_percent": relationship_coverage,
        "missing_expected_relationships": missing_relationships,
        "unknown_expected_relationships": unknown_relationships,
        "status": "complete_declared_and_observed" if complete else "incomplete",
        "notice": (
            "Completeness is a producer declaration reconciled to mapped spans; it does not "
            "prove instrumentation correctness, scenario representativeness, or causal coverage. "
            "Expected relationships are satisfied only by mapped parent-child spans in this import."
        ),
    }


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
        return {str(key): _attribute_value(value) for key, value in values.items()}
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
    analysis: dict[str, Any],
    lookup: dict[str, str],
    attributes: dict[str, Any],
    name: str,
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
            return (
                matches[0],
                "code.file.path+function",
                f"{file_reference}:{function_reference}",
            )
    return "", "unmapped", function_reference or name


def _span_timing(start_time: str, end_time: str) -> tuple[str, int | None]:
    if not start_time or not end_time:
        return "unavailable", None
    try:
        start = int(start_time)
        end = int(end_time)
    except ValueError:
        return "invalid", None
    if start < 0 or end < start:
        return "invalid", None
    return "observed", end - start


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
        name = str(
            span.get("name") or attributes.get("code.function.name") or "unnamed span"
        )
        component_reference = str(
            attributes.get("sfmea.component")
            or attributes.get("code.function")
            or attributes.get("code.function.name")
            or name
        )
        component_id, mapping_method, matched_reference = _component_from_span(
            analysis, lookup, attributes, name
        )
        start_time = str(span.get("startTimeUnixNano", span.get("start_time", "")))
        end_time = str(span.get("endTimeUnixNano", span.get("end_time", "")))
        timing_status, duration_ns = _span_timing(start_time, end_time)
        normalized.append(
            {
                "trace_id": str(span.get("traceId", span.get("trace_id", ""))),
                "span_id": str(
                    span.get("spanId", span.get("span_id", f"span-{index}"))
                ),
                "parent_span_id": str(
                    span.get("parentSpanId", span.get("parent_span_id", ""))
                ),
                "name": name,
                "component_id": component_id,
                "component_reference": component_reference,
                "mapping_method": mapping_method,
                "matched_reference": matched_reference,
                "start_time": start_time,
                "end_time": end_time,
                "timing_status": timing_status,
                "duration_ns": duration_ns,
                "observation_index": index,
                "status": span.get("status", {}),
                "attributes": attributes,
            }
        )
    if not normalized:
        raise ValueError("runtime trace contains no recognizable spans")
    instrumentation = _instrumentation_coverage(payload, lookup, normalized)
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
                "start_time": span["start_time"],
                "end_time": span["end_time"],
                "timing_status": span["timing_status"],
                "duration_ns": span["duration_ns"],
                "observation_index": span["observation_index"],
            }
        )
    existing = {
        (span.get("trace_id"), span.get("span_id")) for span in evidence["spans"]
    }
    new_spans = [
        span
        for span in normalized
        if (span["trace_id"], span["span_id"]) not in existing
    ]
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
        "timing_statuses": {
            status: sum(span["timing_status"] == status for span in normalized)
            for status in sorted({span["timing_status"] for span in normalized})
        },
        "instrumentation": instrumentation,
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
