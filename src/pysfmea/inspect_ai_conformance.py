"""Upstream-schema and reproducible-configuration receipts for Inspect AI evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .inspect_ai_evidence import verify_inspect_ai_evidence_file
from .inspect_config import configuration_matches
from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .upstream_contract import approved_inspect_schema

INSPECT_AI_CONFORMANCE_FORMAT = "pysfmea-inspect-ai-conformance-3"
INSPECT_AI_CONFORMANCE_VERIFICATION_FORMAT = (
    "pysfmea-inspect-ai-conformance-verification-3"
)
MAX_BYTES = 500 * 1024 * 1024
MAX_SCHEMA_ERRORS = 100


def _assigned(value: Any) -> bool:
    return value is not None and value != "" and value != "unassigned"


def _document(source: str | Path, label: str) -> tuple[Any, dict[str, Any]]:
    document = load_bounded_json_document(
        Path(source).expanduser().resolve(),
        label=label,
        max_bytes=MAX_BYTES,
        max_depth=220,
        max_nodes=8_000_000,
    )
    return document.value, {
        "name": Path(source).name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "content_sha256": (
            str(document.value.get("content_sha256", ""))
            if isinstance(document.value, dict)
            else ""
        ),
    }


def _validate_schema(instance: Any, schema: Any) -> list[str]:
    if not isinstance(schema, dict) or not schema:
        return ["Inspect schema must contain a nonempty object"]
    try:
        from jsonschema.validators import validator_for  # type: ignore[import-untyped]
        from referencing import Registry

        validator_type = validator_for(schema)
        validator_type.check_schema(schema)
        validator = validator_type(schema, registry=Registry())
        errors = sorted(
            validator.iter_errors(instance), key=lambda item: str(item.path)
        )
        return [
            f"/{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
            for error in errors[:MAX_SCHEMA_ERRORS]
        ]
    except ImportError as exc:
        raise RuntimeError(
            "Inspect conformance requires the 'interop' optional dependency"
        ) from exc
    except Exception as exc:  # schema implementation errors fail closed
        return [f"Inspect schema validation failed: {exc}"]


def inspect_ai_conformance_receipt(
    evidence_source: str | Path,
    log_source: str | Path,
    schema_source: str | Path,
    run_config_source: str | Path,
    *,
    authority: str,
    inspect_version: str,
    schema_uri: str,
    generated_at: str | None = None,
    schema_policy_source: str | Path | None = None,
) -> dict[str, Any]:
    evidence, evidence_binding = _document(evidence_source, "Inspect AI evidence")
    log, log_binding = _document(log_source, "Inspect AI JSON log")
    schema, schema_binding = _document(schema_source, "Inspect AI official schema")
    run_config, config_binding = _document(
        run_config_source, "Inspect AI exported run configuration"
    )
    if not isinstance(evidence, dict):
        raise ValueError("Inspect AI evidence must contain an object")
    evidence_verdict = verify_inspect_ai_evidence_file(
        evidence_source, source=log_source
    )
    schema_errors = _validate_schema(log, schema)
    configuration_present = configuration_matches(log, run_config)
    evaluation = evidence.get("evaluation", {})
    execution_identity = {
        "run_id": str(evaluation.get("run_id", "unassigned")),
        "eval_id": str(evaluation.get("eval_id", "unassigned")),
        "task": evaluation.get("task"),
        "model": evaluation.get("model"),
        "sandbox": evaluation.get("sandbox"),
        "schema_version": str(
            evidence.get("source", {}).get("schema_version", "unassigned")
        ),
    }
    approved, policy_digest = approved_inspect_schema(
        schema_policy_source,
        version=inspect_version,
        uri=schema_uri,
        digest=schema_binding["sha256"],
    )
    checks = {
        "approved_upstream_contract": approved,
        "evidence_exact_replay": bool(evidence_verdict["eligible_for_evaluation_join"]),
        "official_schema_valid": not schema_errors,
        "exported_run_configuration_matches_log": configuration_present,
        "execution_identity_complete": all(
            _assigned(execution_identity[name])
            for name in (
                "run_id",
                "eval_id",
                "task",
                "model",
                "sandbox",
                "schema_version",
            )
        ),
    }
    eligible = all(checks.values())
    return seal(
        {
            "format": INSPECT_AI_CONFORMANCE_FORMAT,
            "generated_at": generated_at or utc_now(),
            "authority": bounded_text(authority, "Inspect conformance authority"),
            "upstream": {
                "tool": "UK AISI Inspect AI",
                "version": bounded_text(inspect_version, "Inspect AI version"),
                "schema_uri": bounded_text(schema_uri, "Inspect schema URI"),
                "schema_command": "inspect log schema",
                "export_config_command": "inspect log export-config --format json",
            },
            "bindings": {
                "evidence": evidence_binding,
                "log": log_binding,
                "schema": schema_binding,
                "run_config": config_binding,
            },
            "execution_identity": execution_identity,
            "configuration_keys": sorted(str(key) for key in run_config)
            if isinstance(run_config, dict)
            else [],
            "schema_policy_sha256": policy_digest,
            "schema_errors": schema_errors,
            "checks": checks,
            "eligible_for_evaluation_portfolio": eligible,
            "claim_boundary": (
                "Eligibility proves exact PySFMEA replay, validation against the supplied "
                "upstream schema, and retention of an exported run configuration. It does not "
                "authenticate the schema publisher, prove sandbox isolation, validate scorer "
                "meaning, establish model safety, or grant certification."
            ),
        }
    )


def _binding(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == {"name", "bytes", "sha256", "content_sha256"}
        and isinstance(value["name"], str)
        and bool(value["name"])
        and isinstance(value["bytes"], int)
        and not isinstance(value["bytes"], bool)
        and value["bytes"] > 0
        and isinstance(value["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
        and isinstance(value["content_sha256"], str)
        and len(value["content_sha256"]) in {0, 64}
    )


def _structure(value: dict[str, Any]) -> bool:
    try:
        checks = value["checks"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "upstream",
                "bindings",
                "execution_identity",
                "configuration_keys",
                "schema_errors",
                "schema_policy_sha256",
                "checks",
                "eligible_for_evaluation_portfolio",
                "claim_boundary",
                "content_sha256",
            }
            and set(value["upstream"])
            == {
                "tool",
                "version",
                "schema_uri",
                "schema_command",
                "export_config_command",
            }
            and value["upstream"]["schema_command"] == "inspect log schema"
            and value["upstream"]["export_config_command"]
            == "inspect log export-config --format json"
            and set(value["bindings"]) == {"evidence", "log", "schema", "run_config"}
            and all(_binding(item) for item in value["bindings"].values())
            and set(value["execution_identity"])
            == {"run_id", "eval_id", "task", "model", "sandbox", "schema_version"}
            and isinstance(value["configuration_keys"], list)
            and value["configuration_keys"] == sorted(set(value["configuration_keys"]))
            and isinstance(value["schema_errors"], list)
            and all(
                isinstance(item, str) and bool(item) for item in value["schema_errors"]
            )
            and set(checks)
            == {
                "evidence_exact_replay",
                "approved_upstream_contract",
                "official_schema_valid",
                "exported_run_configuration_matches_log",
                "execution_identity_complete",
            }
            and all(isinstance(item, bool) for item in checks.values())
            and checks["official_schema_valid"] == (not value["schema_errors"])
            and value["eligible_for_evaluation_portfolio"] == all(checks.values())
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"])
        )
    except (KeyError, TypeError):
        return False


def verify_inspect_ai_conformance(
    value: dict[str, Any],
    *,
    evidence_source: str | Path | None = None,
    log_source: str | Path | None = None,
    schema_source: str | Path | None = None,
    run_config_source: str | Path | None = None,
    schema_policy_source: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="Inspect AI conformance",
            format_value=INSPECT_AI_CONFORMANCE_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("Inspect AI conformance fields do not reconcile")
    sources = (evidence_source, log_source, schema_source, run_config_source)
    replay: bool | None = None
    if schema_policy_source is not None or any(item is not None for item in sources):
        replay = False
        if all(item is not None for item in sources) and structure:
            try:
                expected = inspect_ai_conformance_receipt(
                    evidence_source,  # type: ignore[arg-type]
                    log_source,  # type: ignore[arg-type]
                    schema_source,  # type: ignore[arg-type]
                    run_config_source,  # type: ignore[arg-type]
                    authority=checked["authority"],
                    inspect_version=checked["upstream"]["version"],
                    schema_uri=checked["upstream"]["schema_uri"],
                    generated_at=checked["generated_at"],
                    schema_policy_source=schema_policy_source,
                )
                replay = expected == value
            except (OSError, RuntimeError, TypeError, ValueError):
                replay = False
        if not replay:
            errors.append("Inspect AI conformance does not exactly replay")
    valid = integrity and structure and replay is not False
    return seal(
        {
            "format": INSPECT_AI_CONFORMANCE_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_evaluation_portfolio": bool(
                valid
                and checked.get("eligible_for_evaluation_portfolio")
                and replay is True
            ),
            "checks": {
                "content_integrity": integrity,
                "semantic_reconciliation": structure,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": "Eligibility requires exact replay; it is not an evaluation or safety certification.",
        }
    )


def export_inspect_ai_conformance(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_inspect_ai_conformance(value)["valid"]:
        raise ValueError("Inspect AI conformance receipt is invalid")
    return publish_json(value, destination)


def verify_inspect_ai_conformance_file(
    source: str | Path,
    *,
    evidence_source: str | Path | None = None,
    log_source: str | Path | None = None,
    schema_source: str | Path | None = None,
    run_config_source: str | Path | None = None,
    schema_policy_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        value, _ = _document(source, "Inspect AI conformance receipt")
        if not isinstance(value, dict):
            raise ValueError("Inspect AI conformance receipt must contain an object")
        return verify_inspect_ai_conformance(
            value,
            evidence_source=evidence_source,
            log_source=log_source,
            schema_source=schema_source,
            run_config_source=run_config_source,
            schema_policy_source=schema_policy_source,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": INSPECT_AI_CONFORMANCE_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_evaluation_portfolio": False,
                "checks": {
                    "content_integrity": False,
                    "semantic_reconciliation": False,
                    "exact_source_replay": False,
                },
                "errors": [str(exc)],
                "notice": "Inspect AI conformance verification failed closed.",
            }
        )
