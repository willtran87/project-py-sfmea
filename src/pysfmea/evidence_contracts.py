"""Public contracts for raw measurements, scored cases, and scope decisions."""

from __future__ import annotations

from typing import Any, Callable

TEXT = {"type": "string", "minLength": 1, "maxLength": 20_000}
BOOL = {"type": "boolean"}
DIGEST = {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def obj(fields: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": fields,
        "required": list(fields) if required is None else required,
        "additionalProperties": False,
    }


def array(items: dict[str, Any], *, unique: bool = False) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": 1,
        "maxItems": 1_000_000,
        "items": items,
        "uniqueItems": unique,
    }


def evidence_contract_builders(
    schema_id: Callable[[str], str], draft: str
) -> dict[str, Callable[[], dict[str, Any]]]:
    identity = {"system_version": TEXT, "model_version": TEXT}
    cases = obj(
        {
            "case_id": TEXT,
            "repository_id": TEXT,
            "executed": BOOL,
            "metrics": {
                "type": "object",
                "additionalProperties": obj({"expected": BOOL, "predicted": BOOL}),
            },
        }
    )
    contracts = {
        "callgraph-benchmark": obj(
            {
                "format": {"const": "pysfmea-callgraph-benchmark-1"},
                "subject_revision": TEXT,
                "authority": TEXT,
                "sources": obj(
                    {
                        name: obj(
                            {
                                "name": TEXT,
                                "bytes": {"type": "integer", "minimum": 1},
                                "sha256": DIGEST,
                            }
                        )
                        for name in ("expected", "actual")
                    }
                ),
                "metrics": obj(
                    {
                        "true_positive": {"type": "integer", "minimum": 0},
                        "false_positive": {"type": "integer", "minimum": 0},
                        "false_negative": {"type": "integer", "minimum": 0},
                        "precision": {
                            "type": ["number", "null"],
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "recall": {
                            "type": ["number", "null"],
                            "minimum": 0,
                            "maximum": 1,
                        },
                    }
                ),
                "edges": {
                    "type": "array",
                    "maxItems": 2000000,
                    "items": obj(
                        {
                            "caller": TEXT,
                            "callee": TEXT,
                            "expected": BOOL,
                            "predicted": BOOL,
                        }
                    ),
                },
                "claim_boundary": TEXT,
                "content_sha256": DIGEST,
            }
        ),
        "tevv-collection": obj(
            {
                "format": {"const": "pysfmea-tevv-collection-1"},
                "window_id": TEXT,
                "started_at": {**TEXT, "format": "date-time"},
                "ended_at": {**TEXT, "format": "date-time"},
                "telemetry_sha256": DIGEST,
                "expected_requests": {"type": "integer", "minimum": 1},
                "dropped_records": {"type": "integer", "minimum": 0},
                "sampling_probability": {"type": "number", "minimum": 0, "maximum": 1},
                "counter_source": TEXT,
                "population": {"const": "one-span-per-request"},
            }
        ),
        "scope-trust-policy": obj(
            {
                "format": {"const": "pysfmea-scope-trust-policy-1"},
                "authorities": array(
                    obj(
                        {
                            "identity": TEXT,
                            "public_key": TEXT,
                            "roles": array(TEXT, unique=True),
                            "not_before": {**TEXT, "format": "date-time"},
                            "not_after": {**TEXT, "format": "date-time"},
                            "revoked": BOOL,
                        }
                    )
                ),
            }
        ),
        "upstream-schema-policy": obj(
            {
                "format": {"const": "pysfmea-upstream-schema-policy-1"},
                "schemas": array(
                    obj(
                        {
                            "tool": {"const": "Inspect AI"},
                            "version": TEXT,
                            "uri": TEXT,
                            "sha256": DIGEST,
                            "configuration_projection": {
                                "const": "inspect-export-config-1"
                            },
                        }
                    ),
                    unique=True,
                ),
            }
        ),
        "benchmark-case-results": obj(
            {
                "format": {"const": "pysfmea-benchmark-case-results-1"},
                "suite_id": TEXT,
                "suite_revision": TEXT,
                "source_sha256": DIGEST,
                "cases": array(cases),
            }
        ),
        "tevv-request-events": obj(
            {
                "format": {"const": "pysfmea-tevv-request-events-1"},
                "events": array(
                    obj(
                        {
                            "request_id": TEXT,
                            "timestamp": {**TEXT, "format": "date-time"},
                            **identity,
                            "latency_ms": {"type": "number", "minimum": 0},
                            "error": BOOL,
                        }
                    )
                ),
            }
        ),
        "tevv-evaluation-events": obj(
            {
                "format": {"const": "pysfmea-tevv-evaluation-events-2"},
                "dataset_sha256": DIGEST,
                "oracle_sha256": DIGEST,
                **identity,
                "cases": array(obj({"id": TEXT, "passed": BOOL})),
            }
        ),
        "tevv-control-events": obj(
            {
                "format": {"const": "pysfmea-tevv-control-events-2"},
                **identity,
                "control": {"enum": ["circuit_breaker", "rollback"]},
                "tested": BOOL,
                "breaker_policy": obj(
                    {
                        "failure_threshold": {"type": "integer", "minimum": 1},
                        "cooldown_seconds": {"type": "number", "exclusiveMinimum": 0},
                        "half_open_successes": {"type": "integer", "minimum": 1},
                    }
                ),
                "requests": array(
                    obj(
                        {
                            "id": TEXT,
                            "started_at": {**TEXT, "format": "date-time"},
                            "completed_at": {**TEXT, "format": "date-time"},
                            "outcome": {"enum": ["success", "failure", "rejected"]},
                            "state_before": {"enum": ["closed", "open", "half_open"]},
                            "state_after": {"enum": ["closed", "open", "half_open"]},
                        }
                    )
                ),
                "succeeded": BOOL,
                "started_at": {**TEXT, "format": "date-time"},
                "recovered_at": {**TEXT, "format": "date-time"},
            },
            ["format", "system_version", "model_version", "control", "tested"],
        ),
        "qualification-scope": obj(
            {
                "intended_use": TEXT,
                "owner": TEXT,
                "reviewer": TEXT,
                "approval_authority": TEXT,
                "approval_ref": TEXT,
                "approved_at": {**TEXT, "format": "date-time"},
                "next_review_at": {**TEXT, "format": "date-time"},
                "required_standards": array(TEXT, unique=True),
                "required_suites": array(TEXT, unique=True),
                "standard_exclusions": {"type": "object", "additionalProperties": TEXT},
                "suite_exclusions": {"type": "object", "additionalProperties": TEXT},
                "acceptance_policy": {"type": "object"},
                "change_triggers": array(TEXT, unique=True),
            }
        ),
    }
    contracts["tevv-control-events"]["allOf"] = [
        {
            "if": {"properties": {"control": {"const": "circuit_breaker"}}},
            "then": {"required": ["breaker_policy", "requests"]},
        },
        {
            "if": {"properties": {"control": {"const": "rollback"}}},
            "then": {"required": ["succeeded", "started_at", "recovered_at"]},
        },
    ]

    def bind(name: str, contract: dict[str, Any]) -> Callable[[], dict[str, Any]]:
        return lambda: {
            "$schema": draft,
            "$id": schema_id(name),
            "title": f"PySFMEA {name}",
            **contract,
        }

    return {name: bind(name, value) for name, value in contracts.items()}
