"""Shared bounded primitives for public PySFMEA JSON Schemas."""

from __future__ import annotations

from typing import Any

from .diagrams import MAX_TEXT_LENGTH

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"


def scalar_schema() -> dict[str, Any]:
    """Return the metadata scalar union."""

    return {"type": ["string", "number", "boolean", "null"]}


def metadata_schema() -> dict[str, Any]:
    """Return the bounded free-form metadata object contract."""

    scalar = scalar_schema()
    return {
        "type": "object",
        "additionalProperties": {
            "oneOf": [
                scalar,
                {"type": "array", "maxItems": 100, "items": scalar},
            ]
        },
    }


def identifier_schema() -> dict[str, Any]:
    """Return the shared bounded identifier contract."""

    return {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_TEXT_LENGTH,
        "pattern": IDENTIFIER_PATTERN,
    }


def text_schema(*, required: bool = False) -> dict[str, Any]:
    """Return the shared bounded text contract."""

    schema: dict[str, Any] = {"type": "string", "maxLength": MAX_TEXT_LENGTH}
    if required:
        schema["minLength"] = 1
    return schema
