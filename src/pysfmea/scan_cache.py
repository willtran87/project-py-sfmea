"""Bounded persistence for derived Python scanner facts.

The cache is an optimization artifact, never primary assurance evidence. Exact source
bytes and analyzer options remain authoritative, and malformed or incompatible cache
content is rejected as a cache miss.
"""

from __future__ import annotations

import copy
import re
import sys
from dataclasses import fields
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .scanner import PYTHON_FACT_CACHE_FORMAT, FunctionFacts
from .version import __version__

FACT_CACHE_FORMAT = PYTHON_FACT_CACHE_FORMAT
MAX_FACT_CACHE_BYTES = 256 * 1024 * 1024
MAX_FACT_CACHE_DEPTH = 100
MAX_FACT_CACHE_NODES = 4_000_000
MAX_FACT_CACHE_ENTRIES = 100_000
MAX_FACTS_PER_ENTRY = 10_000
MAX_TOTAL_FACTS = 1_000_000

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STRING_FIELDS = {
    "name",
    "qualname",
    "kind",
    "path",
    "signature",
    "source_fingerprint",
    "content_fingerprint",
    "context_fingerprint",
    "docstring",
}
_INTEGER_FIELDS = {
    "line",
    "end_line",
    "complexity",
    "loops",
    "awaits",
    "broad_handlers",
    "silent_handlers",
    "raises",
    "arithmetic_ops",
    "alias_bindings_omitted",
    "exception_records_omitted",
    "state_records_omitted",
}
_BOOLEAN_FIELDS = {"is_async", "is_private", "mutates_state"}
_STRING_LIST_FIELDS = {"decorators", "parameters", "ordered_calls"}
_STRING_SET_FIELDS = {"calls", "frameworks", "entrypoint_types", "signals"}
_STRING_DICT_FIELDS = {"symbol_types", "symbol_type_sources"}
_DICT_LIST_FIELDS = {
    "call_sites",
    "parameter_contracts",
    "return_values",
    "alias_bindings",
    "exception_raises",
    "exception_handlers",
    "state_guards",
    "state_transitions",
    "external_call_candidates",
    "interface_endpoints",
    "detected_controls",
}
_FACT_FIELDS = {value.name for value in fields(FunctionFacts)}


def _fact_record(fact: FunctionFacts) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for descriptor in fields(FunctionFacts):
        value = getattr(fact, descriptor.name)
        record[descriptor.name] = (
            sorted(value)
            if descriptor.name in _STRING_SET_FIELDS
            else copy.deepcopy(value)
        )
    return record


def _string_list(value: Any, *, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"cached fact {name} must be a string array")
    return list(value)


def _fact_from_record(record: Any) -> FunctionFacts:
    if not isinstance(record, dict) or set(record) != _FACT_FIELDS:
        raise ValueError("cached fact fields do not match the scanner fact contract")
    values: dict[str, Any] = {}
    for name in _STRING_FIELDS:
        value = record[name]
        if not isinstance(value, str):
            raise ValueError(f"cached fact {name} must be a string")
        values[name] = value
    for name in _INTEGER_FIELDS:
        value = record[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"cached fact {name} must be a non-negative integer")
        values[name] = value
    for name in _BOOLEAN_FIELDS:
        value = record[name]
        if not isinstance(value, bool):
            raise ValueError(f"cached fact {name} must be a boolean")
        values[name] = value
    for name in _STRING_LIST_FIELDS:
        values[name] = _string_list(record[name], name=name)
    for name in _STRING_SET_FIELDS:
        values[name] = set(_string_list(record[name], name=name))
    for name in _STRING_DICT_FIELDS:
        value = record[name]
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError(f"cached fact {name} must be a string map")
        values[name] = dict(value)
    for name in _DICT_LIST_FIELDS:
        value = record[name]
        if not isinstance(value, list) or not all(
            isinstance(item, dict) for item in value
        ):
            raise ValueError(f"cached fact {name} must be an object array")
        values[name] = copy.deepcopy(value)
    return FunctionFacts(**values)


def fact_cache_document(cache: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic, portable cache document from an in-memory cache."""

    entries = cache.get("entries", {})
    if not isinstance(entries, dict):
        raise ValueError("fact cache entries must be an object")
    rendered: dict[str, list[dict[str, Any]]] = {}
    total_facts = 0
    for key in sorted(entries):
        facts = entries[key]
        if not isinstance(key, str) or not _HEX_SHA256.fullmatch(key):
            raise ValueError("fact cache entry key must be a lowercase SHA-256")
        if not isinstance(facts, list) or len(facts) > MAX_FACTS_PER_ENTRY:
            raise ValueError("fact cache entry exceeds its fact-count limit")
        if not all(isinstance(fact, FunctionFacts) for fact in facts):
            raise ValueError("fact cache entry contains an invalid fact")
        total_facts += len(facts)
        if total_facts > MAX_TOTAL_FACTS:
            raise ValueError("fact cache exceeds its total fact-count limit")
        rendered[key] = [_fact_record(fact) for fact in facts]
    if len(rendered) > MAX_FACT_CACHE_ENTRIES:
        raise ValueError("fact cache exceeds its entry-count limit")
    payload = {
        "format": FACT_CACHE_FORMAT,
        "producer": {
            "name": "PySFMEA",
            "version": __version__,
            "python_ast": f"{sys.version_info.major}.{sys.version_info.minor}",
        },
        "authority": "derived_performance_artifact_not_primary_assurance_evidence",
        "entries": rendered,
    }
    payload["content_sha256"] = canonical_json_sha256(payload)
    return payload


def load_fact_cache(source: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and validate one exact cache artifact or reject it completely."""

    document = load_bounded_json_document(
        source,
        label="scanner fact cache",
        max_bytes=MAX_FACT_CACHE_BYTES,
        max_depth=MAX_FACT_CACHE_DEPTH,
        max_nodes=MAX_FACT_CACHE_NODES,
    )
    payload = document.value
    if not isinstance(payload, dict):
        raise ValueError("scanner fact cache root must be an object")
    expected_fields = {"format", "producer", "authority", "entries", "content_sha256"}
    if set(payload) != expected_fields or payload.get("format") != FACT_CACHE_FORMAT:
        raise ValueError("scanner fact cache has an unsupported contract")
    supplied_sha256 = payload.get("content_sha256")
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    if (
        not isinstance(supplied_sha256, str)
        or not _HEX_SHA256.fullmatch(supplied_sha256)
        or canonical_json_sha256(unsigned) != supplied_sha256
    ):
        raise ValueError("scanner fact cache failed its content integrity check")
    producer = payload.get("producer")
    if not isinstance(producer, dict) or producer != {
        "name": "PySFMEA",
        "version": __version__,
        "python_ast": f"{sys.version_info.major}.{sys.version_info.minor}",
    }:
        raise ValueError(
            "scanner fact cache is incompatible with this analyzer runtime"
        )
    if (
        payload.get("authority")
        != "derived_performance_artifact_not_primary_assurance_evidence"
    ):
        raise ValueError("scanner fact cache authority declaration is invalid")
    entries = payload.get("entries")
    if not isinstance(entries, dict) or len(entries) > MAX_FACT_CACHE_ENTRIES:
        raise ValueError("scanner fact cache entries are invalid or excessive")
    restored: dict[str, list[FunctionFacts]] = {}
    total_facts = 0
    for key, facts in entries.items():
        if not isinstance(key, str) or not _HEX_SHA256.fullmatch(key):
            raise ValueError("scanner fact cache entry key is invalid")
        if not isinstance(facts, list) or len(facts) > MAX_FACTS_PER_ENTRY:
            raise ValueError("scanner fact cache entry exceeds its fact-count limit")
        restored[key] = [_fact_from_record(record) for record in facts]
        total_facts += len(restored[key])
        if total_facts > MAX_TOTAL_FACTS:
            raise ValueError("scanner fact cache exceeds its total fact-count limit")
    cache = {"format": FACT_CACHE_FORMAT, "entries": restored}
    receipt = {
        "path": str(document.path),
        "bytes": document.size,
        "sha256": supplied_sha256,
        "entries": len(restored),
        "facts": total_facts,
        "status": "accepted",
        "authority": payload["authority"],
    }
    return cache, receipt


def save_fact_cache(
    destination: str | Path, cache: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    """Atomically publish a compact, integrity-protected cache artifact."""

    import json

    payload = fact_cache_document(cache)
    rendered = (
        json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        + "\n"
    )
    path = atomic_publish_text(
        destination,
        rendered,
        max_bytes=MAX_FACT_CACHE_BYTES,
        label="scanner fact cache",
    )
    receipt = {
        "path": str(path),
        "bytes": len(rendered.encode("utf-8")),
        "sha256": payload["content_sha256"],
        "entries": len(payload["entries"]),
        "facts": sum(len(value) for value in payload["entries"].values()),
        "status": "published",
        "authority": payload["authority"],
    }
    return path, receipt
