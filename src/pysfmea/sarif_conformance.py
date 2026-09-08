"""Official-schema and semantic conformance evidence for SARIF 2.1.0 consumers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from jsonschema import validators  # type: ignore[import-untyped]

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_json_document
from .model import utc_now

SARIF_CONFORMANCE_FORMAT = "pysfmea-sarif-conformance-1"
SARIF_CONFORMANCE_VERIFICATION_FORMAT = "pysfmea-sarif-conformance-verification-1"
MAX_BYTES = 100 * 1024 * 1024


def _semantic_errors(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        return ["document must declare SARIF version 2.1.0"]
    runs = document.get("runs")
    if not isinstance(runs, list):
        return ["runs must be an array"]
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"runs[{run_index}] is not an object")
            continue
        driver = (
            run.get("tool", {}).get("driver", {})
            if isinstance(run.get("tool"), dict)
            else {}
        )
        if (
            not isinstance(driver, dict)
            or not isinstance(driver.get("name"), str)
            or not driver.get("name")
        ):
            errors.append(f"runs[{run_index}] lacks tool.driver.name")
        rules = driver.get("rules", []) if isinstance(driver, dict) else []
        rule_ids = {
            item.get("id")
            for item in rules
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        artifacts = run.get("artifacts", [])
        results = run.get("results", [])
        if not isinstance(results, list):
            errors.append(f"runs[{run_index}].results is not an array")
            continue
        for result_index, result in enumerate(results):
            prefix = f"runs[{run_index}].results[{result_index}]"
            if not isinstance(result, dict):
                errors.append(prefix + " is not an object")
                continue
            rule_id = result.get("ruleId")
            if rule_id is not None and rule_ids and rule_id not in rule_ids:
                errors.append(prefix + " references an undeclared ruleId")
            message = result.get("message")
            if not isinstance(message, dict) or not (
                message.get("text") or message.get("markdown")
            ):
                errors.append(prefix + " lacks a message")
            locations = result.get("locations", [])
            if locations is not None and not isinstance(locations, list):
                errors.append(prefix + ".locations is not an array")
                continue
            for location_index, location in enumerate(locations or []):
                physical = (
                    location.get("physicalLocation", {})
                    if isinstance(location, dict)
                    else {}
                )
                artifact = (
                    physical.get("artifactLocation", {})
                    if isinstance(physical, dict)
                    else {}
                )
                index = artifact.get("index") if isinstance(artifact, dict) else None
                if index is not None and (
                    not isinstance(index, int)
                    or isinstance(index, bool)
                    or not isinstance(artifacts, list)
                    or not 0 <= index < len(artifacts)
                ):
                    errors.append(
                        prefix
                        + f".locations[{location_index}] has an invalid artifact index"
                    )
                region = (
                    physical.get("region", {}) if isinstance(physical, dict) else {}
                )
                if isinstance(region, dict):
                    start, end = region.get("startLine"), region.get("endLine")
                    if start is not None and (
                        not isinstance(start, int)
                        or isinstance(start, bool)
                        or start < 1
                    ):
                        errors.append(prefix + " has an invalid startLine")
                    if end is not None and (
                        not isinstance(end, int)
                        or isinstance(end, bool)
                        or end < 1
                        or (isinstance(start, int) and end < start)
                    ):
                        errors.append(prefix + " has an invalid endLine")
    return errors[:10_000]


def sarif_conformance(
    sarif_source: str | Path,
    official_schema: str | Path,
    *,
    authority: str,
    schema_release: str = "SARIF 2.1.0",
) -> dict[str, Any]:
    sarif = load_bounded_json_document(
        sarif_source,
        label="SARIF",
        max_bytes=MAX_BYTES,
        max_depth=100,
        max_nodes=8_000_000,
    )
    schema = load_bounded_json_document(
        official_schema,
        label="official SARIF schema",
        max_bytes=MAX_BYTES,
        max_depth=100,
        max_nodes=8_000_000,
    )
    if not isinstance(schema.value, dict):
        raise ValueError("official SARIF schema must be an object")
    validator_type = validators.validator_for(schema.value)
    validator_type.check_schema(schema.value)
    schema_errors = sorted(
        validator_type(schema.value).iter_errors(sarif.value),
        key=lambda item: list(item.absolute_path),
    )
    schema_messages = [
        f"{'.'.join(str(part) for part in error.absolute_path) or '$'}: {error.message}"[
            :20_000
        ]
        for error in schema_errors[:10_000]
    ]
    semantic_messages = _semantic_errors(sarif.value)
    result = seal(
        {
            "format": SARIF_CONFORMANCE_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "SARIF conformance authority"),
            "sarif": {
                "name": sarif.path.name,
                "bytes": sarif.size,
                "sha256": hashlib.sha256(sarif.raw).hexdigest(),
            },
            "official_schema": {
                "name": schema.path.name,
                "bytes": schema.size,
                "sha256": hashlib.sha256(schema.raw).hexdigest(),
                "release": bounded_text(schema_release, "SARIF schema release"),
                "schema_id": str(
                    schema.value.get("$id") or schema.value.get("id") or "unidentified"
                )[:20_000],
            },
            "assessment": {
                "schema_valid": not schema_messages,
                "semantic_valid": not semantic_messages,
                "schema_errors": schema_messages,
                "semantic_errors": semantic_messages,
            },
            "claim_boundary": "This receipt validates exact SARIF bytes against the supplied official schema and PySFMEA consumer invariants. It does not establish producer correctness, interoperability with every consumer, or OASIS certification.",
        }
    )
    if not verify_sarif_conformance(result)["valid"]:
        raise ValueError("SARIF conformance receipt failed internal verification")
    return result


def _structure(value: dict[str, Any]) -> bool:
    try:
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "sarif",
                "official_schema",
                "assessment",
                "claim_boundary",
                "content_sha256",
            }
            and set(value["sarif"]) == {"name", "bytes", "sha256"}
            and set(value["official_schema"])
            == {"name", "bytes", "sha256", "release", "schema_id"}
            and all(
                isinstance(value[name]["bytes"], int)
                and value[name]["bytes"] > 0
                and bool(re.fullmatch(r"[0-9a-f]{64}", value[name]["sha256"]))
                for name in ("sarif", "official_schema")
            )
            and set(value["assessment"])
            == {"schema_valid", "semantic_valid", "schema_errors", "semantic_errors"}
            and all(
                isinstance(value["assessment"][name], bool)
                for name in ("schema_valid", "semantic_valid")
            )
            and all(
                isinstance(value["assessment"][name], list)
                and len(value["assessment"][name]) <= 10_000
                and all(
                    isinstance(item, str) and item for item in value["assessment"][name]
                )
                for name in ("schema_errors", "semantic_errors")
            )
            and value["assessment"]["schema_valid"]
            == (not value["assessment"]["schema_errors"])
            and value["assessment"]["semantic_valid"]
            == (not value["assessment"]["semantic_errors"])
        )
    except (KeyError, TypeError):
        return False


def verify_sarif_conformance(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="SARIF conformance", format_value=SARIF_CONFORMANCE_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("SARIF conformance fields are invalid")
    passed = bool(
        structure
        and checked["assessment"]["schema_valid"]
        and checked["assessment"]["semantic_valid"]
    )
    if structure and not passed:
        errors.append("SARIF failed official-schema or consumer-semantic validation")
    return seal(
        {
            "format": SARIF_CONFORMANCE_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "conformant_for_pysfmea_consumption": integrity and structure and passed,
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "official_schema_and_semantics_passed": passed,
            },
            "errors": errors,
            "notice": "Conformance is scoped to the exact schema, SARIF bytes, and declared PySFMEA consumer invariants.",
        }
    )


def export_sarif_conformance(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_sarif_conformance(value)["valid"]:
        raise ValueError("SARIF conformance receipt is invalid")
    return publish_json(value, destination)


def verify_sarif_conformance_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_sarif_conformance(load_json(source, label="SARIF conformance"))
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": SARIF_CONFORMANCE_VERIFICATION_FORMAT,
                "valid": False,
                "conformant_for_pysfmea_consumption": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "official_schema_and_semantics_passed": False,
                },
                "errors": [str(exc)],
                "notice": "SARIF conformance verification failed closed.",
            }
        )
