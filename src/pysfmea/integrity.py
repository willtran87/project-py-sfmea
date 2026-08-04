"""Canonical hashing primitives shared by governed PySFMEA artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_sha256(value: Any) -> str:
    """Hash JSON-compatible data using the project's canonical UTF-8 encoding."""

    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
