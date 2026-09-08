"""Version-pinned OpenTelemetry GenAI span normalization for operational TEVV."""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now

GENAI_TELEMETRY_FORMAT = "pysfmea-genai-telemetry-2"
GENAI_TELEMETRY_VERIFICATION_FORMAT = "pysfmea-genai-telemetry-verification-2"
STABILITY_LEVELS = {"development", "alpha", "beta", "release_candidate", "stable"}
MAX_BYTES = 500 * 1024 * 1024
MAX_SPANS = 2_000_000
SUPPORTED_CONVENTIONS = {
    "1.37.0": {
        "stability": "development",
        "source": "https://github.com/open-telemetry/semantic-conventions/blob/v1.37.0/model/gen-ai/registry.yaml",
        "operation": "gen_ai.operation.name",
        "provider": "gen_ai.provider.name",
        "input_tokens": "gen_ai.usage.input_tokens",
        "output_tokens": "gen_ai.usage.output_tokens",
    }
}
SPAN_FIELDS = {
    "trace_id",
    "span_id",
    "parent_span_id",
    "name",
    "operation",
    "provider",
    "request_model",
    "response_model",
    "input_tokens",
    "output_tokens",
    "duration_ms",
    "status_code",
    "error",
    "service_name",
    "service_version",
    "attributes_sha256",
    "events_sha256",
}


def _value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    variants = {
        "stringValue",
        "intValue",
        "doubleValue",
        "boolValue",
        "bytesValue",
        "arrayValue",
        "kvlistValue",
    }
    if len(set(value) & variants) != 1 or set(value) - variants:
        raise ValueError("OTLP AnyValue must have exactly one typed value")
    for key in (
        "stringValue",
        "intValue",
        "doubleValue",
        "boolValue",
        "bytesValue",
    ):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        values = value["arrayValue"].get("values", [])
        return [_value(item) for item in values]
    if "kvlistValue" in value:
        return _attributes(value["kvlistValue"].get("values", []))
    return value


def _attributes(values: Any) -> dict[str, Any]:
    if isinstance(values, dict):
        return {str(key): _value(value) for key, value in values.items()}
    if not isinstance(values, list):
        raise ValueError("OTLP attributes must be an object or key-value list")
    result = {}
    for item in values:
        if (
            not isinstance(item, dict)
            or set(item) != {"key", "value"}
            or not isinstance(item["key"], str)
            or not item["key"]
            or item["key"] in result
        ):
            raise ValueError("OTLP attributes contain a malformed or duplicate key")
        result[item["key"]] = _value(item["value"])
    return result


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def _duration_ms(start: Any, end: Any) -> float | None:
    start_value = _int(start)
    end_value = _int(end)
    if start_value is None or end_value is None or end_value < start_value:
        return None
    result = (end_value - start_value) / 1_000_000
    return result if math.isfinite(result) else None


def _first(attributes: dict[str, Any], *names: str) -> Any:
    return next((attributes[name] for name in names if name in attributes), None)


def _otel_spans(root: Any) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    def records(value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list) or any(
            not isinstance(item, dict) for item in value
        ):
            raise ValueError("OTLP record population contains malformed entries")
        return value

    if isinstance(root, list):
        return [(item, {}) for item in records(root)]
    if not isinstance(root, dict):
        raise ValueError("OTLP export must be an object or span list")
    if "spans" in root:
        return [(item, {}) for item in records(root["spans"])]
    result: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for resource_span in records(root.get("resourceSpans", [])):
        resource = _attributes(resource_span.get("resource", {}).get("attributes", []))
        scope_spans = resource_span.get(
            "scopeSpans", resource_span.get("instrumentationLibrarySpans", [])
        )
        for scope_span in records(scope_spans):
            for span in records(scope_span.get("spans", [])):
                result.append((span, resource))
    return result


def import_genai_telemetry(
    source: str | Path,
    *,
    authority: str,
    convention_version: str,
    stability: str = "development",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Normalize declared GenAI attributes while retaining exact OTLP source identity."""

    if stability not in STABILITY_LEVELS:
        raise ValueError("OpenTelemetry semantic-convention stability is invalid")
    mapping = SUPPORTED_CONVENTIONS.get(convention_version)
    if mapping is None or mapping["stability"] != stability:
        raise ValueError(
            "unsupported GenAI convention version or stability; supported: 1.37.0 development"
        )
    document = load_bounded_json_document(
        Path(source).expanduser().resolve(),
        label="OpenTelemetry GenAI export",
        max_bytes=MAX_BYTES,
        max_depth=220,
        max_nodes=10_000_000,
    )
    raw_spans = _otel_spans(document.value)
    if len(raw_spans) > MAX_SPANS:
        raise ValueError("OpenTelemetry span population exceeds the governed limit")
    spans = []
    seen: set[str] = set()
    for span, resource in raw_spans:
        attributes = _attributes(span.get("attributes", {}))
        if not any(key.startswith("gen_ai.") for key in attributes):
            continue
        span_id = bounded_text(span.get("spanId", span.get("span_id")), "GenAI span id")
        trace_id = bounded_text(
            span.get("traceId", span.get("trace_id")), "GenAI trace id"
        )
        identity = f"{trace_id}:{span_id}"
        if identity in seen:
            raise ValueError("GenAI trace and span identities must be unique")
        seen.add(identity)
        for legacy in (
            "gen_ai.operation",
            "gen_ai.system",
            "gen_ai.usage.prompt_tokens",
            "gen_ai.usage.completion_tokens",
        ):
            if legacy in attributes:
                raise ValueError(
                    f"attribute {legacy} is outside the selected GenAI mapping"
                )
        operation = _first(attributes, mapping["operation"])
        provider = _first(attributes, mapping["provider"])
        if any(
            v is not None and (not isinstance(v, str) or not v.strip())
            for v in (operation, provider)
        ):
            raise ValueError(
                "GenAI operation and provider identities must be nonempty strings"
            )
        request_model = _first(attributes, "gen_ai.request.model")
        response_model = _first(attributes, "gen_ai.response.model")
        input_tokens = _int(
            _first(
                attributes,
                mapping["input_tokens"],
            )
        )
        output_tokens = _int(
            _first(
                attributes,
                mapping["output_tokens"],
            )
        )
        status = span.get("status", {})
        status_code = (
            str(status.get("code", "UNSET")) if isinstance(status, dict) else "UNSET"
        )
        spans.append(
            {
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": str(
                    span.get("parentSpanId", span.get("parent_span_id", ""))
                ),
                "name": str(span.get("name", "")),
                "operation": None if operation is None else str(operation),
                "provider": None if provider is None else str(provider),
                "request_model": None if request_model is None else str(request_model),
                "response_model": None
                if response_model is None
                else str(response_model),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "duration_ms": _duration_ms(
                    span.get("startTimeUnixNano", span.get("start_time_unix_nano")),
                    span.get("endTimeUnixNano", span.get("end_time_unix_nano")),
                ),
                "status_code": status_code,
                "error": status_code.casefold() in {"error", "status_code_error", "2"},
                "service_name": _first(resource, "service.name"),
                "service_version": _first(resource, "service.version"),
                "attributes_sha256": canonical_json_sha256(attributes),
                "events_sha256": canonical_json_sha256(span.get("events", [])),
            }
        )
    summary = {
        "source_spans": len(raw_spans),
        "genai_spans": len(spans),
        "complete_operation_identity": sum(
            item["operation"] is not None and item["provider"] is not None
            for item in spans
        ),
        "error_spans": sum(item["error"] for item in spans),
        "input_tokens": sum(item["input_tokens"] or 0 for item in spans),
        "output_tokens": sum(item["output_tokens"] or 0 for item in spans),
    }
    result = seal(
        {
            "format": GENAI_TELEMETRY_FORMAT,
            "generated_at": generated_at or utc_now(),
            "authority": bounded_text(authority, "GenAI telemetry authority"),
            "semantic_convention": {
                "name": "OpenTelemetry GenAI semantic conventions",
                "version": bounded_text(convention_version, "GenAI convention version"),
                "stability": stability,
                "mapping": "version-pinned-supported-attribute-subset",
            },
            "source": {
                "name": Path(source).name,
                "bytes": document.size,
                "sha256": hashlib.sha256(document.raw).hexdigest(),
            },
            "spans": spans,
            "summary": summary,
            "claim_boundary": (
                "This artifact preserves exact OTLP source identity and normalizes only a "
                "declared, version-pinned GenAI attribute subset. It does not establish complete "
                "instrumentation, synchronized clocks, causal attribution, model safety, or "
                "stable-standard conformance when the selected convention is experimental."
            ),
        }
    )
    if not verify_genai_telemetry(result)["valid"]:
        raise ValueError("GenAI telemetry failed internal verification")
    return result


def _summary(spans: list[dict[str, Any]], source_spans: int) -> dict[str, int]:
    return {
        "source_spans": source_spans,
        "genai_spans": len(spans),
        "complete_operation_identity": sum(
            item["operation"] is not None and item["provider"] is not None
            for item in spans
        ),
        "error_spans": sum(item["error"] for item in spans),
        "input_tokens": sum(item["input_tokens"] or 0 for item in spans),
        "output_tokens": sum(item["output_tokens"] or 0 for item in spans),
    }


def _structure(value: dict[str, Any]) -> bool:
    try:
        spans = value["spans"]
        convention = value["semantic_convention"]
        source = value["source"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "semantic_convention",
                "source",
                "spans",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(convention) == {"name", "version", "stability", "mapping"}
            and convention["name"] == "OpenTelemetry GenAI semantic conventions"
            and convention["stability"] in STABILITY_LEVELS
            and convention["version"] in SUPPORTED_CONVENTIONS
            and convention["stability"]
            == SUPPORTED_CONVENTIONS[convention["version"]]["stability"]
            and convention["mapping"] == "version-pinned-supported-attribute-subset"
            and set(source) == {"name", "bytes", "sha256"}
            and isinstance(source["bytes"], int)
            and source["bytes"] > 0
            and isinstance(source["sha256"], str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", source["sha256"]))
            and isinstance(spans, list)
            and len(spans) <= MAX_SPANS
            and len({(item.get("trace_id"), item.get("span_id")) for item in spans})
            == len(spans)
            and all(_span_structure(item) for item in spans)
            and value["summary"] == _summary(spans, value["summary"]["source_spans"])
            and value["summary"]["source_spans"] >= len(spans)
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"])
        )
    except (KeyError, TypeError):
        return False


def _span_structure(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != SPAN_FIELDS:
        return False
    optional_text = (
        "operation",
        "provider",
        "request_model",
        "response_model",
        "service_name",
        "service_version",
    )
    return bool(
        all(
            isinstance(item[name], str)
            and re.fullmatch(
                r"[0-9a-f]{32}" if name == "trace_id" else r"[0-9a-f]{16}", item[name]
            )
            is not None
            and int(item[name], 16) != 0
            for name in ("trace_id", "span_id")
        )
        and all(
            isinstance(item[name], str)
            for name in ("parent_span_id", "name", "status_code")
        )
        and all(
            item[name] is None or isinstance(item[name], str) for name in optional_text
        )
        and all(
            item[name] is None
            or (
                isinstance(item[name], int)
                and not isinstance(item[name], bool)
                and item[name] >= 0
            )
            for name in ("input_tokens", "output_tokens")
        )
        and (
            item["duration_ms"] is None
            or (
                isinstance(item["duration_ms"], (int, float))
                and not isinstance(item["duration_ms"], bool)
                and item["duration_ms"] >= 0
                and math.isfinite(item["duration_ms"])
            )
        )
        and isinstance(item["error"], bool)
        and all(
            isinstance(item[name], str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", item[name]))
            for name in ("attributes_sha256", "events_sha256")
        )
    )


def verify_genai_telemetry(
    value: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="GenAI telemetry",
            format_value=GENAI_TELEMETRY_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("GenAI telemetry fields do not reconcile")
    complete = bool(
        structure
        and checked["summary"]["genai_spans"] > 0
        and checked["summary"]["complete_operation_identity"]
        == checked["summary"]["genai_spans"]
    )
    replay: bool | None = None
    if source is not None:
        replay = False
        if structure:
            try:
                replay = (
                    import_genai_telemetry(
                        source,
                        authority=checked["authority"],
                        convention_version=checked["semantic_convention"]["version"],
                        stability=checked["semantic_convention"]["stability"],
                        generated_at=checked["generated_at"],
                    )
                    == value
                )
            except (OSError, TypeError, ValueError):
                replay = False
        if not replay:
            errors.append("GenAI telemetry does not exactly replay")
    valid = integrity and structure and replay is not False
    return seal(
        {
            "format": GENAI_TELEMETRY_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_deployed_tevv": bool(valid and complete and replay is True),
            "checks": {
                "content_integrity": integrity,
                "semantic_reconciliation": structure,
                "complete_operation_identity": complete,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": "Eligibility permits use as deployed-TEVV telemetry evidence; it is not proof of monitoring completeness or model safety.",
        }
    )


def export_genai_telemetry(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_genai_telemetry(value)["valid"]:
        raise ValueError("GenAI telemetry artifact is invalid")
    return publish_json(value, destination)


def verify_genai_telemetry_file(
    source: str | Path, *, otel_source: str | Path | None = None
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            Path(source).expanduser().resolve(),
            label="GenAI telemetry",
            max_bytes=MAX_BYTES,
            max_depth=220,
            max_nodes=10_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("GenAI telemetry must contain an object")
        return verify_genai_telemetry(document.value, source=otel_source)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": GENAI_TELEMETRY_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_deployed_tevv": False,
                "checks": {
                    "content_integrity": False,
                    "semantic_reconciliation": False,
                    "complete_operation_identity": False,
                    "exact_source_replay": False if otel_source is not None else None,
                },
                "errors": [str(exc)],
                "notice": "GenAI telemetry verification failed closed.",
            }
        )
