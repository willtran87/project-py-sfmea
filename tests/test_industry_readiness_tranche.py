from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pysfmea.benchmark_adapter import ADAPTER_BLUEPRINTS, benchmark_adapter_template
from pysfmea.benchmark_source_health import benchmark_source_health_template
from pysfmea.causal_validation import causal_validation, verify_causal_validation
from pysfmea.conformance import standards_catalog
from pysfmea.industry_benchmarks import BENCHMARK_SUITES, benchmark_suite_catalog
from pysfmea.interoperability_validation import (
    normative_schema_validation,
    verify_normative_schema_validation,
)
from pysfmea.schemas import schema_document


def _scenario(
    identifier: str,
    predicted_path: list[str],
    observed_path: list[str],
    predicted_effects: list[str],
    observed_effects: list[str],
) -> dict[str, object]:
    return {
        "id": identifier,
        "finding_id": f"finding-{identifier}",
        "injection_point": predicted_path[0],
        "fault": "TimeoutError",
        "predicted_path": predicted_path,
        "observed_path": observed_path,
        "predicted_effects": predicted_effects,
        "observed_effects": observed_effects,
        "deadline_ms": 250,
        "observed_duration_ms": 200,
        "expected_breaker_state": "open",
        "observed_breaker_state": "open",
        "recovery_deadline_ms": 5000,
        "observed_recovery_ms": 4000,
        "trace_sha256": "a" * 64,
        "execution_evidence_ref": f"evidence://trace/{identifier}",
    }


def test_targeted_industry_readiness_profiles_are_governed() -> None:
    catalog = standards_catalog()
    identifiers = {profile["id"] for profile in catalog["profiles"]}
    assert {
        "iso-15939-2017",
        "iso-25020-2019",
        "iso-25041-2012",
        "iso-25012-25024-data-quality",
        "faa-do-356a-do-355a",
        "nist-sp-800-190",
        "nist-sp-800-207a",
        "openssf-security-insights-2-2",
        "eu-cra-2024-2847",
    } <= identifiers
    assert len(identifiers) == 144
    assert len(identifiers) == len(catalog["profiles"])
    catalog_schema = schema_document("standards-catalog")
    assert catalog_schema["properties"]["profiles"]["maxItems"] >= len(identifiers)
    Draft202012Validator(catalog_schema).validate(catalog)
    for profile in catalog["profiles"]:
        objective_ids = [item["id"] for item in profile["objectives"]]
        assert objective_ids
        assert len(objective_ids) == len(set(objective_ids))


def test_graph_propagation_and_proactive_test_benchmarks_are_closed() -> None:
    catalog = benchmark_suite_catalog()
    identifiers = {suite["id"] for suite in catalog["suites"]}
    assert {
        "pysfmea-causal-propagation",
        "pycg-callgraph",
        "jarvis-callgraph",
        "dypybench",
        "testexplora",
    } <= identifiers
    assert len(identifiers) == len(BENCHMARK_SUITES) == len(ADAPTER_BLUEPRINTS) == 41
    for suite_id in identifiers:
        adapter = benchmark_adapter_template(suite_id=suite_id, authority="owner")
        assert adapter["normalization"]["metric_mappings"]
    health = benchmark_source_health_template(authority="benchmark board")
    assert health["summary"] == {
        "sources": 41,
        "verified": 0,
        "complete": 0,
        "native_or_direct_adapters": 24,
        "contract_only_adapters": 17,
    }
    Draft202012Validator(schema_document("industry-benchmark-catalog")).validate(
        catalog
    )


def test_causal_metrics_use_per_scenario_conventional_denominators() -> None:
    scenarios = [
        _scenario(
            "one",
            ["a", "b", "c"],
            ["a", "b", "x", "c"],
            ["fallback", "rejected"],
            ["fallback", "late"],
        ),
        # The x->c edge observed above must not satisfy the prediction below;
        # accounting is intentionally scenario-local.
        _scenario(
            "two",
            ["d", "x", "c"],
            ["d", "q", "c"],
            ["isolated"],
            ["isolated"],
        ),
    ]
    value = causal_validation(
        scenarios,
        analysis_sha256="b" * 64,
        producer="execution laboratory",
        reviewer="independent reviewer",
        authority="assurance board",
    )
    metrics = value["metrics"]
    assert metrics["path_edge_precision"] == 0.25
    assert metrics["path_edge_recall"] == 0.2
    assert metrics["effect_precision"] == 0.666667
    assert metrics["effect_recall"] == 0.666667
    assert metrics["exact_ordered_path_rate"] == 0
    assert metrics["exact_effect_set_rate"] == 0.5
    assert metrics["deadline_population"] == 2
    assert metrics["breaker_population"] == 2
    assert metrics["recovery_population"] == 2
    verdict = verify_causal_validation(value)
    assert verdict["valid"] is True
    assert verdict["eligible_for_independent_claim"] is True
    Draft202012Validator(schema_document("causal-validation")).validate(value)


def test_security_insights_yaml_validates_against_exact_supplied_schema(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "security-insights.yml"
    artifact.write_text(
        "schema-version: 2.2.0\nlast-reviewed: 2026-08-30\nproject:\n  name: example\n",
        encoding="utf-8",
    )
    schema = tmp_path / "security-insights.schema.json"
    schema.write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://security-insights.openssf.org/schema/2.2.0",
                "type": "object",
                "required": ["schema-version", "last-reviewed", "project"],
                "properties": {
                    "schema-version": {"const": "2.2.0"},
                    "last-reviewed": {"type": "string"},
                    "project": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {"name": {"type": "string"}},
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    receipt = normative_schema_validation(
        artifact,
        schema,
        schema_kind="yaml-json-schema",
        standard_name="OpenSSF Security Insights",
        standard_edition="2.2.0",
        normative_schema_uri="https://security-insights.openssf.org/schema/2.2.0",
    )
    assert receipt["outcome"] == {"valid": True, "error_count": 0, "errors": []}
    assert receipt["validator"]["engine"].startswith("pyyaml-safe+")
    assert verify_normative_schema_validation(receipt)["valid"] is True
    Draft202012Validator(schema_document("normative-schema-validation")).validate(
        receipt
    )

    aliased = tmp_path / "aliased.yml"
    aliased.write_text(
        "schema-version: 2.2.0\nlast-reviewed: 2026-08-30\nproject: &p\n  name: example\ncopy: *p\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="aliases or cycles"):
        normative_schema_validation(
            aliased,
            schema,
            schema_kind="yaml-json-schema",
            standard_name="OpenSSF Security Insights",
            standard_edition="2.2.0",
            normative_schema_uri="https://security-insights.openssf.org/schema/2.2.0",
        )
