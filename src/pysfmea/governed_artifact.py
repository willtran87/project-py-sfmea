"""Shared integrity primitives for governed engineering evidence artifacts."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .report import analysis_state_sha256

MAX_TEXT = 20_000


def bounded_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be bounded text")
    result = value.strip()
    if not result and not allow_empty:
        raise ValueError(f"{label} must not be empty")
    return result


def unique_text_list(value: Any, label: str, *, maximum: int = 100_000) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded list")
    result = [bounded_text(item, f"{label} item") for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def analysis_binding(analysis: dict[str, Any]) -> dict[str, str]:
    return {
        "baseline_id": str(analysis.get("project", {}).get("baseline", {}).get("id", "")),
        "analysis_state_sha256": analysis_state_sha256(analysis),
    }


def verify_analysis_binding(value: Any, analysis: dict[str, Any]) -> dict[str, str]:
    expected = analysis_binding(analysis)
    if not isinstance(value, dict) or set(value) != set(expected) or value != expected:
        raise ValueError("artifact does not bind the exact analysis state")
    return copy.deepcopy(expected)


def seal(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.pop("content_sha256", None)
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_seal(value: Any, *, label: str, format_value: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("format") != format_value:
        raise ValueError(f"{label} format is invalid")
    result = copy.deepcopy(value)
    claimed = result.pop("content_sha256", "")
    if (
        not isinstance(claimed, str)
        or not re.fullmatch(r"[0-9a-f]{64}", claimed)
        or canonical_json_sha256(result) != claimed
    ):
        raise ValueError(f"{label} content digest does not match")
    result["content_sha256"] = claimed
    return result


def load_json(source: str | Path, *, label: str) -> dict[str, Any]:
    value = load_bounded_json_document(
        source,
        label=label,
        max_bytes=64 * 1024 * 1024,
        max_depth=100,
        max_nodes=2_000_000,
    ).value
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def publish_json(value: dict[str, Any], destination: str | Path) -> Path:
    import json

    target = Path(destination).expanduser().resolve()
    atomic_publish_text(target, json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    return target
