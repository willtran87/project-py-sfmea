from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.cli import main
from pysfmea.deployed_tevv import (
    MONITORING_CATEGORIES,
    deployed_tevv_assessment,
    deployed_tevv_template,
    export_deployed_tevv_assessment,
    export_deployed_tevv_source,
    verify_deployed_tevv_assessment,
)
from pysfmea.genai_telemetry import (
    export_genai_telemetry,
    import_genai_telemetry,
    verify_genai_telemetry,
)
from pysfmea.governed_artifact import seal
from pysfmea.schemas import schema_document


def _source(tmp_path: Path) -> Path:
    value = deployed_tevv_template(authority="campaign owner")
    value["authority"] = {
        "campaign_owner": "campaign owner",
        "monitoring_authority": "monitoring laboratory",
        "incident_authority": "incident commander",
        "approval_authority": "operational review board",
        "independence_basis": "Separate accountable roles and reporting lines.",
    }
    value["system"] = {
        "id": "sfmea-test-agent",
        "version": "1.0.0",
        "model": "provider/model",
        "model_version": "2026-08-01",
        "prompt_sha256": "1" * 64,
        "tool_policy_sha256": "2" * 64,
        "deployment_environment": "controlled CI worker",
        "intended_use": "Generate review-gated Python hardening tests.",
    }
    value["baseline"] = {
        "system_version": "1.0.0",
        "model_version": "2026-08-01",
        "evidence_ref": "evidence://tevv/baseline",
        "evidence_sha256": "3" * 64,
        "evaluation_count": 100,
        "evaluation_pass_rate": 0.99,
    }
    value["category_evidence"] = {
        name: [f"evidence://monitoring/{name}"] for name in MONITORING_CATEGORIES
    }
    common = {
        "system_version": "1.0.0",
        "model_version": "2026-08-01",
        "telemetry_schema": "pysfmea-tevv-request-events-1",
        "telemetry_schema_version": "1",
        "telemetry_ref": "evidence://telemetry/window",
        "telemetry_sha256": "4" * 64,
        "requests": 1000,
        "errors": 1,
        "p95_latency_ms": 1000.0,
        "drift_score": 0.01,
        "evaluation_ref": "evidence://evaluation/window",
        "evaluation_sha256": "5" * 64,
        "evaluation_count": 100,
        "evaluation_pass_rate": 0.98,
        "threshold_breaches": [],
        "open_incidents": 0,
    }
    value["monitoring_windows"] = [
        {
            "id": "window-1",
            "started_at": "2026-08-01T00:00:00+00:00",
            "ended_at": "2026-08-07T00:00:00+00:00",
            **copy.deepcopy(common),
        },
        {
            "id": "window-2",
            "started_at": "2026-08-07T00:00:00+00:00",
            "ended_at": "2026-08-14T00:00:00+00:00",
            **copy.deepcopy(common),
        },
    ]
    value["controls"] = {
        "circuit_breaker": {
            "tested": True,
            "activated": True,
            "evidence_ref": "evidence://resilience/circuit-breaker",
        },
        "rollback": {
            "tested": True,
            "succeeded": True,
            "recovery_seconds": 90.0,
            "evidence_ref": "evidence://resilience/rollback",
        },
    }

    def retain(name: str, payload: dict) -> tuple[str, str]:
        path = tmp_path / name
        raw = json.dumps(payload).encode()
        path.write_bytes(raw)
        return name, hashlib.sha256(raw).hexdigest()

    def eval_events(count: int, failures: int) -> dict:
        return {
            "format": "pysfmea-tevv-evaluation-events-2",
            "dataset_sha256": "a" * 64,
            "oracle_sha256": "b" * 64,
            "system_version": "1.0.0",
            "model_version": "2026-08-01",
            "cases": [{"id": str(i), "passed": i >= failures} for i in range(count)],
        }

    baseline = value["baseline"]
    baseline["evidence_ref"], baseline["evidence_sha256"] = retain(
        "baseline.json", eval_events(100, 1)
    )
    for window in value["monitoring_windows"]:
        wid = window["id"]
        window["evaluation_ref"], window["evaluation_sha256"] = retain(
            f"{wid}-eval.json", eval_events(100, 2)
        )
        events = [
            {
                "request_id": f"{wid}-{i}",
                "timestamp": window["started_at"],
                "system_version": "1.0.0",
                "model_version": "2026-08-01",
                "latency_ms": 1000.0,
                "error": i == 0,
            }
            for i in range(1000)
        ]
        window["telemetry_ref"], window["telemetry_sha256"] = retain(
            f"{wid}-telemetry.json",
            {"format": "pysfmea-tevv-request-events-1", "events": events},
        )
        window["collection_ref"], window["collection_sha256"] = retain(
            f"{wid}-collection.json",
            {
                "format": "pysfmea-tevv-collection-1",
                "window_id": wid,
                "started_at": window["started_at"],
                "ended_at": window["ended_at"],
                "telemetry_sha256": window["telemetry_sha256"],
                "expected_requests": len(events),
                "dropped_records": 0,
                "sampling_probability": 1,
                "counter_source": "gateway-request-counter",
                "population": "one-span-per-request",
            },
        )
    for kind in ("circuit_breaker", "rollback"):
        event = {
            "format": "pysfmea-tevv-control-events-2",
            "control": kind,
            "tested": True,
            "system_version": "1.0.0",
            "model_version": "2026-08-01",
            "breaker_policy": {
                "failure_threshold": 1,
                "cooldown_seconds": 10,
                "half_open_successes": 1,
            },
            "requests": [
                {
                    "id": "failure",
                    "started_at": "2026-08-14T00:00:00Z",
                    "completed_at": "2026-08-14T00:00:01Z",
                    "outcome": "failure",
                    "state_before": "closed",
                    "state_after": "open",
                },
                {
                    "id": "rejected",
                    "started_at": "2026-08-14T00:00:02Z",
                    "completed_at": "2026-08-14T00:00:02Z",
                    "outcome": "rejected",
                    "state_before": "open",
                    "state_after": "open",
                },
                {
                    "id": "probe",
                    "started_at": "2026-08-14T00:00:11Z",
                    "completed_at": "2026-08-14T00:00:12Z",
                    "outcome": "success",
                    "state_before": "half_open",
                    "state_after": "closed",
                },
            ],
            "succeeded": True,
            "started_at": "2026-08-14T00:00:00Z",
            "recovered_at": "2026-08-14T00:01:30Z",
        }
        value["controls"][kind]["evidence_ref"], _ = retain(f"{kind}.json", event)
    value = seal(value)
    source = tmp_path / "deployed-tevv-source.json"
    export_deployed_tevv_source(value, source)
    return source


def test_deployed_tevv_reconciles_monitoring_thresholds_and_replay(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path)
    assessment = deployed_tevv_assessment(source)
    assert assessment["summary"]["passed"] is True
    assert set(assessment["checks"]) == {
        "raw_measurement_replay",
        "change_history_consistent",
        "governance_separation",
        "exact_system_identity",
        "predeployment_baseline",
        "repeated_postdeployment_tevv",
        "all_six_monitoring_categories",
        "threshold_conformance",
        "incident_closure",
        "circuit_breaker_verified",
        "rollback_recovery_verified",
        "version_and_telemetry_traceability",
    }
    local = verify_deployed_tevv_assessment(assessment)
    assert local["valid"] is True
    assert local["eligible_for_authorized_operational_review"] is False
    exact = verify_deployed_tevv_assessment(assessment, source=source)
    assert exact["eligible_for_authorized_operational_review"] is True
    Draft202012Validator(schema_document("deployed-tevv-source")).validate(
        json.loads(source.read_text(encoding="utf-8"))
    )
    Draft202012Validator(schema_document("deployed-tevv-assessment")).validate(
        assessment
    )
    Draft202012Validator(schema_document("deployed-tevv-verification")).validate(exact)
    assessment_path = tmp_path / "deployed-tevv-assessment.json"
    export_deployed_tevv_assessment(assessment, assessment_path)
    assert (
        main(
            [
                "deployed-tevv-verify",
                str(assessment_path),
                "--source",
                str(source),
                "--json",
            ]
        )
        == 0
    )


def test_deployed_tevv_fails_closed_on_drift_and_open_incident(tmp_path: Path) -> None:
    source = _source(tmp_path)
    value = json.loads(source.read_text(encoding="utf-8"))
    value.pop("content_sha256")
    value["monitoring_windows"][1]["drift_score"] = 0.5
    value["monitoring_windows"][1]["threshold_breaches"] = ["drift"]
    value["monitoring_windows"][1]["open_incidents"] = 1
    source.write_text(json.dumps(seal(value)), encoding="utf-8")
    assessment = deployed_tevv_assessment(source)
    assert assessment["summary"]["passed"] is False
    assert assessment["checks"]["threshold_conformance"] is False
    assert assessment["checks"]["incident_closure"] is False


def test_genai_telemetry_is_version_pinned_and_exactly_replayable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "otel.json"
    source.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {
                                    "key": "service.name",
                                    "value": {"stringValue": "sfmea-agent"},
                                },
                                {
                                    "key": "service.version",
                                    "value": {"stringValue": "1.0.0"},
                                },
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "traceId": "a" * 32,
                                        "spanId": "b" * 16,
                                        "name": "chat",
                                        "startTimeUnixNano": "1000000",
                                        "endTimeUnixNano": "4000000",
                                        "status": {"code": "STATUS_CODE_UNSET"},
                                        "attributes": [
                                            {
                                                "key": "gen_ai.operation.name",
                                                "value": {"stringValue": "chat"},
                                            },
                                            {
                                                "key": "gen_ai.provider.name",
                                                "value": {"stringValue": "provider"},
                                            },
                                            {
                                                "key": "gen_ai.request.model",
                                                "value": {"stringValue": "model"},
                                            },
                                            {
                                                "key": "gen_ai.usage.input_tokens",
                                                "value": {"intValue": "10"},
                                            },
                                            {
                                                "key": "gen_ai.usage.output_tokens",
                                                "value": {"intValue": "5"},
                                            },
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    value = import_genai_telemetry(
        source,
        authority="monitoring laboratory",
        convention_version="1.37.0",
        stability="development",
        generated_at="2026-08-31T12:00:00+00:00",
    )
    assert value["summary"] == {
        "source_spans": 1,
        "genai_spans": 1,
        "complete_operation_identity": 1,
        "error_spans": 0,
        "input_tokens": 10,
        "output_tokens": 5,
    }
    assert verify_genai_telemetry(value)["eligible_for_deployed_tevv"] is False
    exact = verify_genai_telemetry(value, source=source)
    assert exact["eligible_for_deployed_tevv"] is True
    Draft202012Validator(schema_document("genai-telemetry")).validate(value)
    Draft202012Validator(schema_document("genai-telemetry-verification")).validate(
        exact
    )
    artifact = tmp_path / "genai-telemetry.json"
    export_genai_telemetry(value, artifact)
    assert (
        main(
            [
                "genai-telemetry-verify",
                str(artifact),
                "--source",
                str(source),
                "--json",
            ]
        )
        == 0
    )
