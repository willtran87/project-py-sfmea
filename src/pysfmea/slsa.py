"""SLSA v1 provenance for exact PySFMEA analysis artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .json_ingestion import load_bounded_file_snapshot, load_bounded_json_document
from .model import utc_now
from .report import analysis_state_sha256
from .version import __version__

SLSA_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SLSA_BUILD_TYPE = "https://github.com/willtran87/project-py-sfmea/slsa/analysis/v1"
SLSA_BUILDER_ID = "https://github.com/willtran87/project-py-sfmea"
SLSA_VERIFICATION_FORMAT = "pysfmea-slsa-provenance-verification-1"
MAX_SLSA_BYTES = 10_000_000


def _sha(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def slsa_provenance_statement(
    analysis: dict[str, Any],
    analysis_path: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create an in-toto Statement carrying a SLSA Provenance v1 predicate."""

    snapshot = load_bounded_file_snapshot(
        analysis_path,
        label="SLSA provenance subject analysis",
        max_bytes=250_000_000,
    )
    baseline = analysis.get("project", {}).get("baseline", {})
    manifest = analysis.get("run_manifest", {})
    resolved = manifest.get("resolved_inputs", {}) if isinstance(manifest, dict) else {}
    materials = []
    material_names = {
        "source_snapshot_sha256": "urn:pysfmea:material:python-source-snapshot",
        "test_evidence_snapshot_sha256": "urn:pysfmea:material:test-evidence-snapshot",
        "configuration_digest": "urn:pysfmea:material:configuration",
        "guidance_catalog_sha256": "urn:pysfmea:material:guidance-catalog",
        "adapter_registry_sha256": "urn:pysfmea:material:adapter-registry",
        "dependency_inventory_sha256": "urn:pysfmea:material:dependency-inventory",
        "contract_inventory_sha256": "urn:pysfmea:material:contract-inventory",
        "repository_inventory_sha256": "urn:pysfmea:material:repository-inventory",
        "system_context_sha256": "urn:pysfmea:material:system-context",
    }
    for field, uri in material_names.items():
        digest = resolved.get(field) if isinstance(resolved, dict) else None
        if _sha(digest):
            materials.append({"uri": uri, "digest": {"sha256": digest}})
    vcs = baseline.get("vcs", {}) if isinstance(baseline, dict) else {}
    revision = vcs.get("revision") if isinstance(vcs, dict) else None
    if isinstance(revision, str) and revision:
        materials.append(
            {
                "uri": "urn:pysfmea:material:repository-revision",
                "digest": {"gitCommit": revision},
            }
        )
    settings = (
        manifest.get("tool", {}).get("settings", {})
        if isinstance(manifest, dict)
        else {}
    )
    safe_parameters = {
        key: settings[key]
        for key in (
            "include_private",
            "include_tests",
            "include_nested",
            "review_depth",
            "review_queue_max_per_component",
            "review_queue_max_total",
        )
        if isinstance(settings, dict) and key in settings
    }
    completion = generated_at or utc_now()
    started = (
        str(manifest.get("created_at", completion))
        if isinstance(manifest, dict)
        else completion
    )
    invocation = (
        str(manifest.get("id", baseline.get("id", "")))
        if isinstance(manifest, dict)
        else str(baseline.get("id", ""))
    )
    return {
        "_type": SLSA_STATEMENT_TYPE,
        "subject": [
            {
                "name": snapshot.path.name,
                "digest": {"sha256": hashlib.sha256(snapshot.raw).hexdigest()},
            }
        ],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": SLSA_BUILD_TYPE,
                "externalParameters": {
                    "baselineId": str(baseline.get("id", "")),
                    "analysisSchemaVersion": str(analysis.get("schema_version", "")),
                    "analysisStateSha256": analysis_state_sha256(analysis),
                    "settings": safe_parameters,
                    "repositoryDirty": bool(vcs.get("dirty", False))
                    if isinstance(vcs, dict)
                    else False,
                },
                "internalParameters": {},
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {"id": SLSA_BUILDER_ID, "version": {"pysfmea": __version__}},
                "metadata": {
                    "invocationId": invocation,
                    "startedOn": started,
                    "finishedOn": completion,
                },
                "byproducts": [],
            },
        },
    }


def verify_slsa_provenance(
    statement: dict[str, Any],
    *,
    analysis: dict[str, Any] | None = None,
    analysis_path: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    checks: dict[str, bool | None] = {
        "statement_type": statement.get("_type") == SLSA_STATEMENT_TYPE,
        "predicate_type": statement.get("predicateType") == SLSA_PREDICATE_TYPE,
        "closed_subject": False,
        "build_definition": False,
        "builder_identity": False,
        "material_digests": False,
        "analysis_subject_binding": None,
        "analysis_state_binding": None,
    }
    subjects = statement.get("subject")
    checks["closed_subject"] = bool(
        isinstance(subjects, list)
        and len(subjects) == 1
        and isinstance(subjects[0], dict)
        and set(subjects[0]) == {"name", "digest"}
        and isinstance(subjects[0].get("name"), str)
        and isinstance(subjects[0].get("digest"), dict)
        and set(subjects[0]["digest"]) == {"sha256"}
        and _sha(subjects[0]["digest"].get("sha256"))
    )
    predicate = statement.get("predicate")
    definition = (
        predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    )
    run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    checks["build_definition"] = bool(
        isinstance(definition, dict)
        and definition.get("buildType") == SLSA_BUILD_TYPE
        and isinstance(definition.get("externalParameters"), dict)
        and isinstance(definition.get("internalParameters"), dict)
        and isinstance(definition.get("resolvedDependencies"), list)
    )
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    checks["builder_identity"] = bool(
        isinstance(builder, dict)
        and builder.get("id") == SLSA_BUILDER_ID
        and isinstance(builder.get("version"), dict)
        and isinstance(builder["version"].get("pysfmea"), str)
    )
    dependencies = (
        definition.get("resolvedDependencies", [])
        if isinstance(definition, dict)
        else []
    )
    checks["material_digests"] = bool(
        isinstance(dependencies, list)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("uri"), str)
            and isinstance(item.get("digest"), dict)
            and bool(item["digest"])
            and all(
                isinstance(key, str) and isinstance(value, str) and bool(value)
                for key, value in item["digest"].items()
            )
            for item in dependencies
        )
    )
    if analysis_path is not None:
        try:
            snapshot = load_bounded_file_snapshot(
                analysis_path,
                label="SLSA provenance verification subject",
                max_bytes=250_000_000,
            )
            subject = (
                subjects[0]
                if isinstance(subjects, list)
                and subjects
                and isinstance(subjects[0], dict)
                else {}
            )
            raw_subject_digest = subject.get("digest")
            subject_digest: dict[str, Any] = (
                raw_subject_digest if isinstance(raw_subject_digest, dict) else {}
            )
            checks["analysis_subject_binding"] = bool(
                checks["closed_subject"]
                and subject.get("name") == snapshot.path.name
                and subject_digest.get("sha256")
                == hashlib.sha256(snapshot.raw).hexdigest()
            )
        except (OSError, ValueError) as exc:
            checks["analysis_subject_binding"] = False
            errors.append(str(exc))
    if analysis is not None:
        parameters = (
            definition.get("externalParameters", {})
            if isinstance(definition, dict)
            else {}
        )
        checks["analysis_state_binding"] = bool(
            isinstance(parameters, dict)
            and parameters.get("baselineId")
            == str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
            and parameters.get("analysisSchemaVersion")
            == str(analysis.get("schema_version", ""))
            and parameters.get("analysisStateSha256") == analysis_state_sha256(analysis)
        )
    for name, passed in checks.items():
        if passed is False:
            errors.append(f"SLSA provenance check failed: {name}")
    valid = all(value is not False for value in checks.values())
    return {
        "format": SLSA_VERIFICATION_FORMAT,
        "valid": valid,
        "checks": checks,
        "errors": errors,
        "subject_sha256": (
            str(subjects[0]["digest"]["sha256"])
            if checks["closed_subject"] and isinstance(subjects, list)
            else ""
        ),
        "notice": "This verifies SLSA statement structure and optional exact subject/state bindings. It does not authenticate the builder; sign and transparently publish the statement under organizational release policy.",
    }


def load_slsa_provenance(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="SLSA provenance",
        max_bytes=MAX_SLSA_BYTES,
        max_depth=60,
        max_nodes=500_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("SLSA provenance must contain a JSON object")
    return document.value


def export_slsa_provenance(statement: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(
        destination,
        json.dumps(statement, indent=2, ensure_ascii=False) + "\n",
        label="SLSA provenance statement",
    )


def verify_slsa_provenance_file(
    source: str | Path,
    *,
    analysis: dict[str, Any] | None = None,
    analysis_path: str | Path | None = None,
) -> dict[str, Any]:
    try:
        return {
            "path": str(Path(source).expanduser().resolve()),
            **verify_slsa_provenance(
                load_slsa_provenance(source),
                analysis=analysis,
                analysis_path=analysis_path,
            ),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": SLSA_VERIFICATION_FORMAT,
            "valid": False,
            "checks": {
                "statement_type": False,
                "predicate_type": False,
                "closed_subject": False,
                "build_definition": False,
                "builder_identity": False,
                "material_digests": False,
                "analysis_subject_binding": None if analysis_path is None else False,
                "analysis_state_binding": None if analysis is None else False,
            },
            "errors": [str(exc)],
            "subject_sha256": "",
            "notice": "The SLSA provenance statement could not be safely verified.",
        }
