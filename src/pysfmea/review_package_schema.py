"""Public structural schema for a PySFMEA review-package manifest."""

from __future__ import annotations

from typing import Any

from .schema_registry import SCHEMA_CATALOG_FILENAME

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_CATALOG_FORMAT = "pysfmea-schema-catalog-1"
REVIEW_PACKAGE_FORMAT = "pysfmea-review-package-1"

def _schema_id(name: str) -> str:
    return f"urn:pysfmea:schema:{name}:1"


def _review_package_manifest_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    nonempty = {"type": "string", "minLength": 1, "maxLength": 4096}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("review-package-manifest"),
        "title": "PySFMEA review-package manifest",
        "description": (
            "Structural contract for checksum-manifested review packages. File-set, "
            "digest, provenance, and governed-state semantics require verify-package."
        ),
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "exporter",
            "analysis_generator",
            "analysis_schema_version",
            "project",
            "baseline_id",
            "analysis_state_sha256",
            "portable",
            "source_analysis",
            "files",
        ],
        "properties": {
            "format": {"const": REVIEW_PACKAGE_FORMAT},
            "generated_at": nonempty,
            "exporter": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": nonempty,
                },
                "additionalProperties": False,
            },
            "analysis_generator": {"type": "object"},
            "analysis_schema_version": {"type": "string", "maxLength": 256},
            "project": {"type": "string", "maxLength": 4096},
            "baseline_id": {"type": "string", "maxLength": 4096},
            "analysis_state_sha256": digest,
            "capabilities": {
                "type": "array",
                "uniqueItems": True,
                "items": {
                    "enum": [
                        "analysis_diagnostics_projection_v1",
                        "assurance_register_projection",
                        "assurance_work_queue_projection",
                        "evidence_catalog_projection_v1",
                        "guidance_traceability_projection_v1",
                        "cross_reference_projection_v1",
                        "interchange_artifacts_projection_v1",
                        "package_provenance_projection_v1",
                        "review_views_projection_v1",
                        "sfta_projection_v1",
                    ]
                },
            },
            "schema_catalog": {
                "type": "object",
                "required": [
                    "format",
                    "path",
                    "canonical_sha256",
                    "schema_count",
                ],
                "properties": {
                    "format": {"const": SCHEMA_CATALOG_FORMAT},
                    "path": {"const": SCHEMA_CATALOG_FILENAME},
                    "canonical_sha256": digest,
                    "schema_count": {"type": "integer", "minimum": 1},
                },
                "additionalProperties": False,
            },
            "portable": {"type": "boolean"},
            "source_analysis": {"type": "string", "maxLength": 32768},
            "files": {
                "type": "array",
                "minItems": 1,
                "maxItems": 128,
                "items": {
                    "type": "object",
                    "required": ["path", "bytes", "sha256"],
                    "properties": {
                        "path": nonempty,
                        "bytes": {"type": "integer", "minimum": 0},
                        "sha256": digest,
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": True,
    }
