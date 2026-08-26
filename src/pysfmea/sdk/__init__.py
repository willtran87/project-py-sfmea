"""Stable public contracts for explicitly configured PySFMEA plugins.

The 1.x API follows semantic versioning: additive fields may appear in minor releases;
required fields and meanings are not removed or changed before 2.0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

SDK_API_VERSION = "1.0"
PLUGIN_MANIFEST_FORMAT = "pysfmea-plugin-manifest-1"
PLUGIN_REQUEST_FORMAT = "pysfmea-plugin-request-1"
PLUGIN_RESPONSE_FORMAT = "pysfmea-plugin-response-1"
PLUGIN_RUN_FORMAT = "pysfmea-plugin-run-1"
PLUGIN_RUN_VERIFICATION_FORMAT = "pysfmea-plugin-run-verification-1"
SUPPORTED_CAPABILITIES = frozenset({"analyze", "enrich_findings", "summarize"})
MAX_PLUGIN_OBSERVATIONS = 5_000


@dataclass(frozen=True)
class PluginManifest:
    """Validated process-plugin identity and execution declaration."""

    id: str
    name: str
    version: str
    sdk_api: str
    command: tuple[str, ...]
    capabilities: tuple[str, ...]
    deterministic: bool
    timeout_seconds: int
    trust: Literal["project", "organization", "third_party"]
    path: Path


@runtime_checkable
class Plugin(Protocol):
    """Reference in-process authoring protocol; production hosting is out-of-process."""

    def handle(self, request: dict[str, Any]) -> dict[str, Any]: ...


def _bounded_text(value: Any, *, label: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be a non-empty string up to {maximum} characters")
    return value.strip()


def validate_manifest(document: Any, *, path: str | Path) -> PluginManifest:
    """Fail closed on unknown, incompatible, or unsafe manifest declarations."""

    if not isinstance(document, dict):
        raise ValueError("plugin manifest must be an object")
    allowed = {
        "format",
        "id",
        "name",
        "version",
        "sdk_api",
        "command",
        "capabilities",
        "deterministic",
        "timeout_seconds",
        "trust",
    }
    unknown = set(document) - allowed
    if unknown:
        raise ValueError("plugin manifest contains unknown fields: " + ", ".join(sorted(unknown)))
    if document.get("format") != PLUGIN_MANIFEST_FORMAT:
        raise ValueError(f"plugin manifest format must be {PLUGIN_MANIFEST_FORMAT}")
    identifier = _bounded_text(document.get("id"), label="plugin id", maximum=120)
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+", identifier):
        raise ValueError("plugin id must be a lowercase, namespaced identifier")
    version = _bounded_text(document.get("version"), label="plugin version", maximum=40)
    if not re.fullmatch(r"0|[1-9]\d*(?:\.(?:0|[1-9]\d*)){2}(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError("plugin version must use semantic versioning")
    sdk_api = _bounded_text(document.get("sdk_api"), label="sdk_api", maximum=20)
    try:
        requested_major, requested_minor = (int(value) for value in sdk_api.split("."))
        host_major, host_minor = (int(value) for value in SDK_API_VERSION.split("."))
    except (ValueError, TypeError) as exc:
        raise ValueError("sdk_api must use MAJOR.MINOR") from exc
    if requested_major != host_major or requested_minor > host_minor:
        raise ValueError(
            f"plugin requires SDK API {sdk_api}; host supports {SDK_API_VERSION}"
        )
    command = document.get("command")
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 20
        or any(not isinstance(value, str) or not value or len(value) > 1_000 for value in command)
    ):
        raise ValueError("plugin command must contain 1-20 bounded argument strings")
    capabilities = document.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or len(capabilities) > len(SUPPORTED_CAPABILITIES)
        or any(value not in SUPPORTED_CAPABILITIES for value in capabilities)
        or len(set(capabilities)) != len(capabilities)
    ):
        raise ValueError("plugin capabilities must be unique supported capability IDs")
    timeout = document.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise ValueError("plugin timeout_seconds must be from 1 through 300")
    deterministic = document.get("deterministic")
    if not isinstance(deterministic, bool):
        raise ValueError("plugin deterministic must be a boolean")
    trust = document.get("trust", "third_party")
    if trust not in {"project", "organization", "third_party"}:
        raise ValueError("plugin trust must be project, organization, or third_party")
    return PluginManifest(
        id=identifier,
        name=_bounded_text(document.get("name"), label="plugin name", maximum=120),
        version=version,
        sdk_api=sdk_api,
        command=tuple(command),
        capabilities=tuple(capabilities),
        deterministic=deterministic,
        timeout_seconds=timeout,
        trust=trust,
        path=Path(path).expanduser().resolve(),
    )


__all__ = [
    "MAX_PLUGIN_OBSERVATIONS",
    "PLUGIN_MANIFEST_FORMAT",
    "PLUGIN_REQUEST_FORMAT",
    "PLUGIN_RESPONSE_FORMAT",
    "PLUGIN_RUN_FORMAT",
    "PLUGIN_RUN_VERIFICATION_FORMAT",
    "SDK_API_VERSION",
    "SUPPORTED_CAPABILITIES",
    "Plugin",
    "PluginManifest",
    "validate_manifest",
]
