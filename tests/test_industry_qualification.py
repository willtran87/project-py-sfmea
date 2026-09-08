from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.benchmark_native import normalize_native_benchmark, verify_native_benchmark
from pysfmea.benchmark_source_health import (
    benchmark_source_health_template,
    verify_benchmark_source_health,
)
from pysfmea.causal_validation import causal_validation, verify_causal_validation
from pysfmea.confidence_calibration import (
    confidence_calibration,
    verify_confidence_calibration,
)
from pysfmea.industry_benchmarks import BENCHMARK_SUITES
from pysfmea.integrity import canonical_json_sha256
from pysfmea.sarif_conformance import sarif_conformance, verify_sarif_conformance
from pysfmea.schemas import schema_document
from pysfmea.scorecard_evidence import (
    import_scorecard_evidence,
    verify_scorecard_evidence,
)
from pysfmea.standards_watchlist import standards_watchlist, verify_standards_watchlist


def test_source_health_is_catalog_closed_and_fail_closed_until_reviewed() -> None:
    value = benchmark_source_health_template(authority="benchmark board")
    verdict = verify_benchmark_source_health(value)
    assert verdict["valid"] is True
    assert verdict["eligible_for_external_execution"] is False
    tdd = next(
        item for item in value["sources"] if item["suite_id"] == "tdd-bench-verified"
    )
    assert tdd["canonical_url"] == "https://github.com/IBM/TDD-Bench-Verified"
    owasp = next(
        item for item in BENCHMARK_SUITES if item["id"] == "owasp-benchmark-python"
    )
    assert "preliminary (v0.1)" in owasp["limitation"]
    assert value["summary"]["native_or_direct_adapters"] == 24
    Draft202012Validator(schema_document("benchmark-source-health")).validate(value)


def test_native_swe_bench_normalization_preserves_exact_source(tmp_path: Path) -> None:
    source = tmp_path / "results.jsonl"
    source.write_text(
        json.dumps(
            {"instance_id": "django__django-1", "passed": True, "resolved": True}
        )
        + "\n",
        encoding="utf-8",
    )
    value = normalize_native_benchmark(
        source,
        suite_id="swe-bench-verified",
        suite_revision="2026-08-01",
        authority="benchmark board",
    )
    assert value["summary"] == {
        "cases": 1,
        "classification_cases": 0,
        "execution_cases": 1,
        "resolved_cases": 1,
        "outcomes": {
            "error": 0,
            "failure": 0,
            "incomplete": 0,
            "not_reported": 1,
            "success": 0,
        },
    }
    assert verify_native_benchmark(value)["eligible_for_observation_join"] is True
    Draft202012Validator(schema_document("native-benchmark-normalization")).validate(
        value
    )


def test_confidence_calibration_reconciles_strata_and_detects_tamper() -> None:
    observations = [
        {
            "id": "a",
            "confidence": 0.9,
            "outcome": True,
            "stratum": "timing",
            "evidence_ref": "evidence://a",
        },
        {
            "id": "b",
            "confidence": 0.8,
            "outcome": False,
            "stratum": "timing",
            "evidence_ref": "evidence://b",
        },
        {
            "id": "c",
            "confidence": 0.2,
            "outcome": False,
            "stratum": "control",
            "evidence_ref": "evidence://c",
        },
    ]
    value = confidence_calibration(
        observations,
        subject_id="scanner-0.73",
        subject_sha256="a" * 64,
        authority="validation board",
        bins=5,
    )
    assert value["metrics"]["brier_score"] == 0.23
    assert set(value["by_stratum"]) == {"control", "timing"}
    assert verify_confidence_calibration(value)["valid"] is True
    tampered = copy.deepcopy(value)
    tampered["metrics"]["brier_score"] = 0
    tampered["content_sha256"] = canonical_json_sha256(
        {k: v for k, v in tampered.items() if k != "content_sha256"}
    )
    assert verify_confidence_calibration(tampered)["valid"] is False
    Draft202012Validator(schema_document("confidence-calibration")).validate(value)


def test_causal_validation_measures_paths_timing_breaker_and_recovery() -> None:
    scenario = {
        "id": "scenario-1",
        "finding_id": "finding-1",
        "injection_point": "client.fetch",
        "fault": "TimeoutError",
        "predicted_path": ["client.fetch", "service.handle", "breaker.open"],
        "observed_path": ["client.fetch", "service.handle", "breaker.open"],
        "predicted_effects": ["request_rejected", "fallback_used"],
        "observed_effects": ["request_rejected", "fallback_used"],
        "deadline_ms": 250,
        "observed_duration_ms": 210,
        "expected_breaker_state": "open",
        "observed_breaker_state": "open",
        "recovery_deadline_ms": 5000,
        "observed_recovery_ms": 4200,
        "trace_sha256": "b" * 64,
        "execution_evidence_ref": "evidence://trace/1",
    }
    value = causal_validation(
        [scenario],
        analysis_sha256="a" * 64,
        producer="test laboratory",
        reviewer="independent reviewer",
        authority="assurance board",
    )
    assert value["metrics"]["path_edge_recall"] == 1
    assert value["metrics"]["deadline_conformance"] == 1
    assert verify_causal_validation(value)["eligible_for_independent_claim"] is True
    Draft202012Validator(schema_document("causal-validation")).validate(value)


def test_sarif_conformance_uses_supplied_schema_and_semantics(tmp_path: Path) -> None:
    schema = tmp_path / "sarif-schema.json"
    schema.write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version", "runs"],
                "properties": {
                    "version": {"const": "2.1.0"},
                    "runs": {"type": "array"},
                },
            }
        ),
        encoding="utf-8",
    )
    sarif = tmp_path / "result.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {"name": "example", "rules": [{"id": "R1"}]}
                        },
                        "results": [{"ruleId": "R1", "message": {"text": "finding"}}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    value = sarif_conformance(sarif, schema, authority="interop laboratory")
    assert value["assessment"] == {
        "schema_valid": True,
        "semantic_valid": True,
        "schema_errors": [],
        "semantic_errors": [],
    }
    assert verify_sarif_conformance(value)["conformant_for_pysfmea_consumption"] is True
    Draft202012Validator(schema_document("sarif-conformance")).validate(value)


def test_scorecard_maps_review_candidates_without_claiming_compliance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "scorecard.json"
    source.write_text(
        json.dumps(
            {
                "date": "2026-08-30",
                "repo": {"name": "github.com/example/project"},
                "scorecard": {"version": "v5.3.0", "commit": "abc"},
                "score": 8.0,
                "checks": [
                    {
                        "name": "SAST",
                        "score": 10,
                        "reason": "tool detected",
                        "details": [],
                        "documentation": {"url": "https://example.test/sast"},
                    },
                    {
                        "name": "Signed-Releases",
                        "score": 5,
                        "reason": "partial",
                        "details": [],
                    },
                    {
                        "name": "New-Check",
                        "score": -1,
                        "reason": "unknown",
                        "details": [],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    value = import_scorecard_evidence(source, authority="supply-chain reviewer")
    assert value["summary"]["mapped_checks"] == 2
    assert value["summary"]["unmapped_checks"] == 1
    assert verify_scorecard_evidence(value)["eligible_as_review_input"] is True
    assert "do not satisfy" in value["claim_boundary"]
    Draft202012Validator(schema_document("openssf-scorecard-evidence")).validate(value)


def test_watchlist_is_non_normative_and_schema_valid() -> None:
    value = standards_watchlist()
    assert verify_standards_watchlist(value)["valid"] is True
    assert {item["development_stage"] for item in value["items"]} == {
        "CD",
        "DIS",
        "FDIS",
        "active_PAR",
        "initial_public_draft",
    }
    Draft202012Validator(schema_document("standards-watchlist")).validate(value)
