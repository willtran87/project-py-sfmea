"""Explicit out-of-process host for the versioned PySFMEA plugin protocol."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ..file_publication import atomic_publish_text
from ..integrity import canonical_json_sha256
from ..json_ingestion import load_bounded_json_document
from ..model import utc_now
from ..version import __version__
from . import (
    MAX_PLUGIN_OBSERVATIONS,
    PLUGIN_REQUEST_FORMAT,
    PLUGIN_RESPONSE_FORMAT,
    PLUGIN_RUN_FORMAT,
    PLUGIN_RUN_VERIFICATION_FORMAT,
    SDK_API_VERSION,
    PluginManifest,
    validate_manifest,
)

MAX_PLUGIN_DOCUMENT_BYTES = 20_000_000
MAX_PLUGIN_STDERR_BYTES = 1_000_000
MAX_PLUGIN_DEPTH = 80
MAX_PLUGIN_NODES = 500_000


def load_plugin_manifest(source: str | Path) -> PluginManifest:
    document = load_bounded_json_document(
        source,
        label="plugin manifest",
        max_bytes=1_000_000,
        max_depth=20,
        max_nodes=10_000,
    )
    return validate_manifest(document.value, path=document.path)


def _resolve_command(manifest: PluginManifest) -> list[str]:
    command = list(manifest.command)
    command[0] = sys.executable if command[0] == "{python}" else command[0]
    for index in range(1, len(command)):
        if command[index].startswith("-"):
            continue
        candidate = Path(command[index])
        if not candidate.is_absolute() and (manifest.path.parent / candidate).exists():
            command[index] = str((manifest.path.parent / candidate).resolve())
    executable = Path(command[0])
    if not executable.is_absolute() and (manifest.path.parent / executable).exists():
        command[0] = str((manifest.path.parent / executable).resolve())
    return command


def _validate_observations(observations: Any) -> list[dict[str, Any]]:
    if not isinstance(observations, list) or len(observations) > MAX_PLUGIN_OBSERVATIONS:
        raise ValueError("plugin observations must be a bounded list")
    allowed = {
        "id",
        "kind",
        "subject_id",
        "message",
        "evidence_ids",
        "confidence",
        "properties",
    }
    ids: set[str] = set()
    for index, value in enumerate(observations):
        if not isinstance(value, dict) or set(value) - allowed:
            raise ValueError(f"plugin observation {index} has an invalid structure")
        identifier = value.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 160 or identifier in ids:
            raise ValueError(f"plugin observation {index} has a missing, long, or duplicate id")
        ids.add(identifier)
        for field in ("kind", "subject_id", "message"):
            if not isinstance(value.get(field), str) or len(value[field]) > 20_000:
                raise ValueError(f"plugin observation {identifier} has an invalid {field}")
        evidence = value.get("evidence_ids", [])
        if not isinstance(evidence, list) or len(evidence) > 100 or any(
            not isinstance(item, str) or len(item) > 500 for item in evidence
        ):
            raise ValueError(f"plugin observation {identifier} has invalid evidence_ids")
        if value.get("confidence", "low") not in {"low", "medium", "high"}:
            raise ValueError(f"plugin observation {identifier} has invalid confidence")
        if not isinstance(value.get("properties", {}), dict):
            raise ValueError(f"plugin observation {identifier} has invalid properties")
    return observations


def _validate_response(response: Any, manifest: PluginManifest) -> list[dict[str, Any]]:
    if not isinstance(response, dict) or set(response) != {
        "format",
        "plugin_id",
        "observations",
    }:
        raise ValueError("plugin response must contain only format, plugin_id, and observations")
    if response["format"] != PLUGIN_RESPONSE_FORMAT or response["plugin_id"] != manifest.id:
        raise ValueError("plugin response identity or format does not match its manifest")
    return _validate_observations(response["observations"])


def run_plugin(
    manifest_source: str | Path,
    analysis: dict[str, Any],
    *,
    capability: str = "analyze",
) -> dict[str, Any]:
    """Run one explicit plugin without shell expansion or ambient secret inheritance."""

    manifest = load_plugin_manifest(manifest_source)
    if capability not in manifest.capabilities:
        raise ValueError(f"plugin does not declare the {capability!r} capability")
    request = {
        "format": PLUGIN_REQUEST_FORMAT,
        "sdk_api": SDK_API_VERSION,
        "plugin_id": manifest.id,
        "capability": capability,
        "analysis_binding": {
            "baseline_id": str(analysis.get("project", {}).get("baseline", {}).get("id", "")),
            "analysis_state_sha256": canonical_json_sha256(analysis),
        },
        "analysis": analysis,
        "authority": (
            "Return observations only. Do not set reviewer decisions, compliance status, "
            "risk acceptance, or evidence sufficiency."
        ),
    }
    encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_PLUGIN_DOCUMENT_BYTES:
        raise ValueError("plugin request exceeds the 20 MB protocol limit")
    with tempfile.TemporaryDirectory(prefix="pysfmea-plugin-") as temporary:
        root = Path(temporary)
        request_path, response_path, error_path = (
            root / "request.json",
            root / "response.json",
            root / "stderr.txt",
        )
        request_path.write_bytes(encoded)
        environment = {
            key: os.environ[key]
            for key in ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TMP", "TEMP")
            if key in os.environ
        }
        environment["PYTHONNOUSERSITE"] = "1"
        with request_path.open("rb") as stdin, response_path.open("wb") as stdout, error_path.open("wb") as stderr:
            process = subprocess.Popen(
                _resolve_command(manifest),
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                cwd=root,
                env=environment,
                shell=False,
            )
            try:
                return_code = process.wait(timeout=manifest.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise RuntimeError("plugin exceeded its declared timeout") from exc
        if response_path.stat().st_size > MAX_PLUGIN_DOCUMENT_BYTES:
            raise ValueError("plugin response exceeds the 20 MB protocol limit")
        stderr_size = error_path.stat().st_size
        error_text = error_path.read_bytes()[:MAX_PLUGIN_STDERR_BYTES].decode(
            "utf-8", errors="replace"
        )
        if return_code:
            raise RuntimeError(
                f"plugin exited with status {return_code}: {error_text.strip() or 'no diagnostic'}"
            )
        response = load_bounded_json_document(
            response_path,
            label="plugin response",
            max_bytes=MAX_PLUGIN_DOCUMENT_BYTES,
            max_depth=MAX_PLUGIN_DEPTH,
            max_nodes=MAX_PLUGIN_NODES,
        ).value
    observations = _validate_response(response, manifest)
    run: dict[str, Any] = {
        "format": PLUGIN_RUN_FORMAT,
        "generated_at": utc_now(),
        "host": {"name": "PySFMEA", "version": __version__, "sdk_api": SDK_API_VERSION},
        "plugin": {
            "id": manifest.id,
            "name": manifest.name,
            "version": manifest.version,
            "capability": capability,
            "deterministic": manifest.deterministic,
            "trust": manifest.trust,
            "manifest_sha256": hashlib.sha256(manifest.path.read_bytes()).hexdigest(),
        },
        "analysis_binding": request["analysis_binding"],
        "observations": observations,
        "execution": {
            "isolation": "separate_process_reduced_environment_temporary_working_directory",
            "os_sandbox": False,
            "network_restricted_by_host": False,
            "filesystem_restricted_by_host": False,
            "stderr_bytes": stderr_size,
            "stderr_truncated": stderr_size > MAX_PLUGIN_STDERR_BYTES,
        },
        "notice": (
            "Plugin output is untrusted observation data. Process separation is not an OS "
            "sandbox; use an external container or sandbox for untrusted executable code."
        ),
    }
    run["content_sha256"] = canonical_json_sha256(run)
    return run


def export_plugin_run(run: dict[str, Any], output: str | Path) -> Path:
    verification = verify_plugin_run(run)
    if not verification["valid"]:
        raise ValueError(
            "plugin run is not publishable: " + "; ".join(verification["errors"])
        )
    return atomic_publish_text(
        output,
        json.dumps(run, indent=2, ensure_ascii=False) + "\n",
        label="plugin run",
        max_bytes=MAX_PLUGIN_DOCUMENT_BYTES,
    )


def verify_plugin_run(
    run: dict[str, Any],
    *,
    analysis: dict[str, Any] | None = None,
    manifest_source: str | Path | None = None,
) -> dict[str, Any]:
    """Verify run integrity, protocol semantics, and optional exact input bindings."""

    checks: dict[str, bool | None] = {
        "content_integrity": False,
        "structure": False,
        "observation_contract": False,
        "execution_disclosure": False,
        "analysis_binding": None,
        "manifest_binding": None,
    }
    errors: list[str] = []
    expected_fields = {
        "format",
        "generated_at",
        "host",
        "plugin",
        "analysis_binding",
        "observations",
        "execution",
        "notice",
        "content_sha256",
    }
    declared = str(run.get("content_sha256", ""))
    unsigned = dict(run)
    unsigned.pop("content_sha256", None)
    checks["content_integrity"] = (
        len(declared) == 64 and declared == canonical_json_sha256(unsigned)
    )
    if not checks["content_integrity"]:
        errors.append("plugin-run content digest is invalid")
    host = run.get("host", {})
    plugin = run.get("plugin", {})
    binding = run.get("analysis_binding", {})
    checks["structure"] = (
        set(run) == expected_fields
        and run.get("format") == PLUGIN_RUN_FORMAT
        and isinstance(host, dict)
        and host.get("name") == "PySFMEA"
        and host.get("sdk_api") == SDK_API_VERSION
        and isinstance(plugin, dict)
        and isinstance(plugin.get("id"), str)
        and bool(plugin.get("id"))
        and isinstance(plugin.get("version"), str)
        and bool(plugin.get("version"))
        and plugin.get("capability") in {"analyze", "enrich_findings", "summarize"}
        and isinstance(plugin.get("deterministic"), bool)
        and plugin.get("trust") in {"project", "organization", "third_party"}
        and isinstance(plugin.get("manifest_sha256"), str)
        and len(plugin.get("manifest_sha256", "")) == 64
        and isinstance(binding, dict)
        and isinstance(binding.get("baseline_id"), str)
        and isinstance(binding.get("analysis_state_sha256"), str)
        and len(binding.get("analysis_state_sha256", "")) == 64
        and isinstance(run.get("notice"), str)
        and bool(run.get("notice"))
    )
    if not checks["structure"]:
        errors.append("plugin-run structure or protocol identity is invalid")
    try:
        _validate_observations(run.get("observations"))
        checks["observation_contract"] = True
    except ValueError as exc:
        errors.append(str(exc))
    execution = run.get("execution", {})
    checks["execution_disclosure"] = (
        isinstance(execution, dict)
        and execution.get("isolation")
        == "separate_process_reduced_environment_temporary_working_directory"
        and execution.get("os_sandbox") is False
        and execution.get("network_restricted_by_host") is False
        and execution.get("filesystem_restricted_by_host") is False
        and isinstance(execution.get("stderr_bytes"), int)
        and not isinstance(execution.get("stderr_bytes"), bool)
        and execution.get("stderr_bytes", -1) >= 0
        and isinstance(execution.get("stderr_truncated"), bool)
    )
    if not checks["execution_disclosure"]:
        errors.append("plugin execution boundary is missing or unsupported")
    if analysis is not None:
        checks["analysis_binding"] = (
            binding.get("baseline_id")
            == analysis.get("project", {}).get("baseline", {}).get("id", "")
            and binding.get("analysis_state_sha256") == canonical_json_sha256(analysis)
        )
        if not checks["analysis_binding"]:
            errors.append("plugin run does not match the supplied analysis")
    if manifest_source is not None:
        manifest = load_plugin_manifest(manifest_source)
        checks["manifest_binding"] = (
            plugin.get("id") == manifest.id
            and plugin.get("version") == manifest.version
            and plugin.get("capability") in manifest.capabilities
            and plugin.get("deterministic") == manifest.deterministic
            and plugin.get("trust") == manifest.trust
            and plugin.get("manifest_sha256")
            == hashlib.sha256(manifest.path.read_bytes()).hexdigest()
        )
        if not checks["manifest_binding"]:
            errors.append("plugin run does not match the supplied manifest")
    valid = all(value is not False for value in checks.values())
    return {
        "format": PLUGIN_RUN_VERIFICATION_FORMAT,
        "valid": valid,
        "checks": checks,
        "plugin_id": str(plugin.get("id", "")) if isinstance(plugin, dict) else "",
        "observation_count": (
            len(run.get("observations", []))
            if isinstance(run.get("observations"), list)
            else 0
        ),
        "errors": errors,
        "notice": (
            "Verification proves protocol integrity and selected bindings; plugin observations "
            "remain untrusted and receive no engineering authority."
        ),
    }


def verify_plugin_run_file(
    source: str | Path,
    *,
    analysis: dict[str, Any] | None = None,
    manifest_source: str | Path | None = None,
) -> dict[str, Any]:
    supplied = Path(source).expanduser().absolute()
    try:
        document = load_bounded_json_document(
            supplied,
            label="plugin run",
            max_bytes=MAX_PLUGIN_DOCUMENT_BYTES,
            max_depth=MAX_PLUGIN_DEPTH,
            max_nodes=MAX_PLUGIN_NODES,
        )
        if not isinstance(document.value, dict):
            raise ValueError("plugin run must contain a JSON object")
        result = verify_plugin_run(
            document.value, analysis=analysis, manifest_source=manifest_source
        )
        result["path"] = str(document.path)
        return result
    except (OSError, ValueError) as exc:
        return {
            "format": PLUGIN_RUN_VERIFICATION_FORMAT,
            "valid": False,
            "checks": {
                "content_integrity": False,
                "structure": False,
                "observation_contract": False,
                "execution_disclosure": False,
                "analysis_binding": False if analysis is not None else None,
                "manifest_binding": False if manifest_source is not None else None,
            },
            "plugin_id": "",
            "observation_count": 0,
            "errors": [f"plugin run could not be verified: {exc}"],
            "notice": (
                "Verification proves protocol integrity and selected bindings; plugin "
                "observations remain untrusted and receive no engineering authority."
            ),
            "path": str(supplied),
        }
