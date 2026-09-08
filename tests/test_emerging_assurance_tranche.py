from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pysfmea.benchmark_adapter import (
    ADAPTER_BLUEPRINTS,
    benchmark_adapter_template,
)
from pysfmea.benchmark_native import normalize_native_benchmark
from pysfmea.benchmark_source_health import benchmark_source_health_template
from pysfmea.conformance import standards_catalog
from pysfmea.industry_benchmarks import BENCHMARK_SUITES, benchmark_suite_catalog
from pysfmea.schemas import schema_document

EMERGING_PROFILES = {
    "nist-ai-800-4-deployed-monitoring",
    "nist-ai-100-2e2025-adversarial-ml",
    "owasp-agentic-ai-2025",
    "iso-12792-2025-ai-transparency",
    "iso-24027-12791-ai-bias",
    "iso-27004-2016-security-measurement",
    "iec-61508-7-2010-techniques",
    "iso-26262-8-9-2018-supporting-analysis",
    "owasp-api-security-2023",
    "tmmi-2-0-test-maturity",
    "owasp-genai-llm-top10-2026",
}

EMERGING_BENCHMARKS = {
    "swe-bench-live",
    "cyberseceval-4",
    "crosscodeeval-python",
    "crosscodelongeval-python",
    "pysfmea-nondeterminism-concurrency",
    "agentdojo",
    "swe-polybench-verified-python",
    "idoft-python",
    "terminal-bench-2",
}


def test_emerging_profiles_are_closed_distinct_and_schema_valid() -> None:
    catalog = standards_catalog()
    profiles = {profile["id"]: profile for profile in catalog["profiles"]}
    assert catalog["version"] == "2026.08.31-r14"
    assert len(profiles) == len(catalog["profiles"]) == 144
    assert EMERGING_PROFILES <= profiles.keys()
    for identifier in EMERGING_PROFILES:
        profile = profiles[identifier]
        assert profile["reference_url"].startswith("https://")
        assert profile["access"]
        assert profile["status"]
        objectives = profile["objectives"]
        assert len(objectives) == 4
        assert len({item["id"] for item in objectives}) == len(objectives)
        assert all(item["expected_evidence"] for item in objectives)
    assert profiles["owasp-agentic-ai-2025"]["access"] == (
        "public_non_normative_guidance"
    )
    assert profiles["iso-27004-2016-security-measurement"]["status"] == (
        "published_to_be_revised"
    )
    Draft202012Validator(schema_document("standards-catalog")).validate(catalog)


def test_emerging_benchmarks_have_suite_specific_fail_closed_contracts() -> None:
    catalog = benchmark_suite_catalog()
    suites = {suite["id"]: suite for suite in catalog["suites"]}
    assert catalog["version"] == "1.10.0"
    assert len(suites) == len(BENCHMARK_SUITES) == len(ADAPTER_BLUEPRINTS) == 41
    assert EMERGING_BENCHMARKS <= suites.keys()
    for identifier in EMERGING_BENCHMARKS:
        suite = suites[identifier]
        assert suite["source_url"].startswith("https://")
        assert suite["measures"] == ADAPTER_BLUEPRINTS[identifier]["metric_mappings"]
        manifest = benchmark_adapter_template(suite_id=identifier, authority="owner")
        assert manifest["normalization"]["metric_mappings"] == suite["measures"]
        assert manifest["authority"]["independent_reviewer"] == "unassigned"
    Draft202012Validator(schema_document("industry-benchmark-catalog")).validate(
        catalog
    )


def test_source_health_exposes_new_contract_debt_without_fake_verification() -> None:
    health = benchmark_source_health_template(authority="benchmark board")
    assert health["summary"] == {
        "sources": 41,
        "verified": 0,
        "complete": 0,
        "native_or_direct_adapters": 24,
        "contract_only_adapters": 17,
    }
    sources = {item["suite_id"]: item for item in health["sources"]}
    assert sources["pysfmea-nondeterminism-concurrency"]["adapter_mode"] == "direct"
    for identifier in (
        "cyberseceval-4",
        "crosscodeeval-python",
        "crosscodelongeval-python",
    ):
        assert sources[identifier]["adapter_mode"] == "contract-only"
        assert sources[identifier]["status"] == "unreviewed"


def test_contract_only_external_format_is_not_guessed(tmp_path: Path) -> None:
    source = tmp_path / "cyberseceval.json"
    source.write_text('{"results":[{"id":"one","passed":true}]}', encoding="utf-8")
    with pytest.raises(
        ValueError, match="does not declare a native external-result adapter"
    ):
        normalize_native_benchmark(
            source,
            suite_id="cyberseceval-4",
            suite_revision="unreviewed",
            authority="adapter owner",
        )


def test_nondeterminism_corpus_is_closed_and_traceable() -> None:
    root = Path("benchmarks/nondeterminism_concurrency_corpus")
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    assert expected["format"] == "pysfmea-nondeterminism-concurrency-corpus-1"
    assert {case["mechanism"] for case in expected["cases"]} == {
        "pseudo_random_input",
        "wall_clock_boundary",
        "unsynchronized_shared_state",
        "task_completion_order",
        "eventual_consistency",
    }
    assert all(case["required_controls"] for case in expected["cases"])
    assert (root / "repository/cases.py").is_file()
    assert "do not establish empirical flakiness" in expected["claim_boundary"]
