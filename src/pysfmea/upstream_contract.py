"""Caller-approved upstream contract identities, independent of imported artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .json_ingestion import load_bounded_json_document


def approved_inspect_schema(
    policy_source: str | Path | None, *, version: str, uri: str, digest: str
) -> tuple[bool, str]:
    if policy_source is None:
        return False, ""
    document = load_bounded_json_document(
        Path(policy_source),
        label="upstream schema trust policy",
        max_bytes=1000000,
        max_depth=20,
        max_nodes=10000,
    )
    value: Any = document.value
    if (
        not isinstance(value, dict)
        or set(value) != {"format", "schemas"}
        or value["format"] != "pysfmea-upstream-schema-policy-1"
        or not isinstance(value["schemas"], list)
    ):
        raise ValueError("upstream schema policy is invalid")
    expected = {
        "tool": "Inspect AI",
        "version": version,
        "uri": uri,
        "sha256": digest,
        "configuration_projection": "inspect-export-config-1",
    }
    return sum(row == expected for row in value["schemas"]) == 1, hashlib.sha256(
        document.raw
    ).hexdigest()
