from __future__ import annotations

import copy
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from pysfmea.benchmark_adapter import ADAPTER_BLUEPRINTS
from pysfmea.benchmark_proficiency import (
    assess_benchmark_proficiency,
    benchmark_proficiency_template,
    export_benchmark_proficiency,
)
from pysfmea.benchmark_source_health import (
    benchmark_source_health_template,
    export_benchmark_source_health,
)
from pysfmea.cli import main
from pysfmea.conformance import standards_catalog
from pysfmea.governed_artifact import load_json, publish_json, seal
from pysfmea.industry_benchmarks import BENCHMARK_SUITES, benchmark_suite_catalog
from pysfmea.industry_qualification_readiness import (
    export_industry_qualification_readiness,
    industry_qualification_readiness,
    verify_industry_qualification_readiness,
    verify_industry_qualification_readiness_file,
)
from pysfmea.schemas import schema_document
from pysfmea.standards_lifecycle import (
    export_standards_lifecycle,
    standards_lifecycle_template,
)
from pysfmea.validation_portfolio import (
    export_validation_portfolio_assessment,
    export_validation_portfolio_source,
    validation_portfolio_assessment,
    validation_portfolio_template,
)


def test_cross_industry_profiles_are_first_class_and_schema_valid() -> None:
    catalog = standards_catalog()
    identifiers = {profile["id"] for profile in catalog["profiles"]}
    assert {
        "nasa-7150-8739-software-assurance",
        "iso-9001-2026-90003-2018",
        "iso-17020-17029-19011-assessment-governance",
        "iso-17065-17067-product-certification",
        "ieee-828-2012-configuration-management",
        "machinery-iec-62061-iso-13849",
        "faa-do-278a-do-200b-ground-data-assurance",
        "nuclear-iec-61513-60880-62138-62645",
        "mil-std-882e-system-safety",
        "medical-iso-13485-fda-csa",
        "iso-17043-13528-benchmark-proficiency",
        "iso-27036-software-supply-chain",
        "iso-20000-ieee-2675-service-devops",
        "nist-800-61-iso-27035-incident-response",
        "nist-800-204c-d-cloud-devsecops",
        "iso-27017-2026-cloud-security",
        "nist-rmf-800-37-137",
        "iso-25002-25019-quality-use",
        "eu-ai-act-2024-1689",
        "mitre-atlas-ai-threats",
        "iso-27031-2025-ict-continuity",
        "iso-27037-27043-digital-evidence",
        "iso-24748-1-2024-lifecycle-management",
        "iso-38507-2022-ai-governance",
    } <= identifiers
    assert len(identifiers) == len(catalog["profiles"]) == 144
    assert catalog["version"] == "2026.08.31-r14"
    Draft202012Validator(schema_document("standards-catalog")).validate(catalog)


def test_qualification_benchmark_families_are_catalog_closed() -> None:
    catalog = benchmark_suite_catalog()
    identifiers = {suite["id"] for suite in catalog["suites"]}
    assert {
        "pysfmea-modern-python-dynamics",
        "pysfmea-distributed-resilience",
        "pysfmea-interoperability-conformance",
        "pysfmea-longitudinal-drift",
        "pynguin-sbft-python",
        "pysfmea-mutation-proficiency",
        "pysfmea-fuzz-ground-truth",
        "pysfmea-framework-negative-controls",
        "pysfmea-python-platform-matrix",
        "pysfmea-temporal-hidden-holdout",
        "pysfmea-cross-organization-proficiency",
        "livecodebench-test-generation",
        "fuzzbench-statistical-trials",
        "quixbugs-python",
        "bigcodebench",
        "pysfmea-dual-mutation-engine-qualification",
        "pysfmea-scale-resource-exhaustion",
    } <= identifiers
    assert len(identifiers) == len(BENCHMARK_SUITES) == len(ADAPTER_BLUEPRINTS) == 41
    assert catalog["version"] == "1.10.0"
    assert all(
        ADAPTER_BLUEPRINTS[suite_id]["metric_mappings"] for suite_id in identifiers
    )
    Draft202012Validator(schema_document("industry-benchmark-catalog")).validate(
        catalog
    )


def _incomplete_evidence(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    lifecycle_path = tmp_path / "standards-lifecycle.json"
    export_standards_lifecycle(
        standards_lifecycle_template(authority="standards-curator"), lifecycle_path
    )
    source_health_path = tmp_path / "benchmark-source-health.json"
    export_benchmark_source_health(
        benchmark_source_health_template(authority="benchmark-curator"),
        source_health_path,
    )
    proficiency_source = benchmark_proficiency_template(authority="scheme-provider")
    proficiency_source_path = tmp_path / "benchmark-proficiency-source.json"
    export_benchmark_proficiency(proficiency_source, proficiency_source_path)
    proficiency_path = tmp_path / "benchmark-proficiency-assessment.json"
    export_benchmark_proficiency(
        assess_benchmark_proficiency(proficiency_source), proficiency_path
    )
    portfolio_source = validation_portfolio_template(authority="portfolio-owner")
    portfolio_source_path = tmp_path / "validation-portfolio.json"
    export_validation_portfolio_source(portfolio_source, portfolio_source_path)
    portfolio = validation_portfolio_assessment(portfolio_source_path)
    portfolio_path = tmp_path / "validation-portfolio-assessment.json"
    export_validation_portfolio_assessment(portfolio, portfolio_path)
    return (
        lifecycle_path,
        source_health_path,
        proficiency_source_path,
        proficiency_path,
        portfolio_source_path,
        portfolio_path,
    )


def test_readiness_gate_reports_debt_and_requires_exact_replay(tmp_path: Path) -> None:
    lifecycle, sources, proficiency_source, proficiency, portfolio_source, portfolio = (
        _incomplete_evidence(tmp_path)
    )
    value = industry_qualification_readiness(
        standards_lifecycle=lifecycle,
        benchmark_source_health=sources,
        benchmark_proficiency_source=proficiency_source,
        benchmark_proficiency_assessment=proficiency,
        validation_portfolio_source=portfolio_source,
        validation_portfolio_assessment=portfolio,
        authority="independent-readiness-assessor",
        generated_at="2026-08-30T12:00:00+00:00",
    )
    assert value["summary"]["passed"] is False
    failed = {item["check"] for item in value["summary"]["blockers"]}
    assert {
        "standards_catalog_current",
        "benchmark_sources_pinned",
        "benchmark_adapters_operational",
        "independent_validation_portfolio",
    } <= failed
    assert value["catalogs"]["standards"]["profiles"] == 144
    assert value["catalogs"]["benchmarks"]["suites"] == 41
    local = verify_industry_qualification_readiness(value)
    assert local["valid"] is True
    assert local["passed"] is False
    assert local["checks"]["exact_source_replay"] is None
    assert local["eligible_for_authorized_industry_qualification_review"] is False
    exact = verify_industry_qualification_readiness(
        value,
        standards_lifecycle=lifecycle,
        benchmark_source_health=sources,
        benchmark_proficiency_source=proficiency_source,
        benchmark_proficiency_assessment=proficiency,
        validation_portfolio_source=portfolio_source,
        validation_portfolio_assessment=portfolio,
    )
    assert exact["valid"] is True
    assert exact["checks"]["exact_source_replay"] is True
    assert exact["eligible_for_authorized_industry_qualification_review"] is False
    Draft202012Validator(schema_document("industry-qualification-readiness")).validate(
        value
    )
    Draft202012Validator(
        schema_document("industry-qualification-readiness-verification")
    ).validate(exact)

    readiness_path = tmp_path / "industry-readiness.json"
    export_industry_qualification_readiness(value, readiness_path)
    file_verdict = verify_industry_qualification_readiness_file(
        readiness_path,
        standards_lifecycle=lifecycle,
        benchmark_source_health=sources,
        benchmark_proficiency_source=proficiency_source,
        benchmark_proficiency_assessment=proficiency,
        validation_portfolio_source=portfolio_source,
        validation_portfolio_assessment=portfolio,
    )
    assert file_verdict["valid"] is True


def test_readiness_tamper_and_partial_replay_fail_closed(tmp_path: Path) -> None:
    lifecycle, sources, proficiency_source, proficiency, portfolio_source, portfolio = (
        _incomplete_evidence(tmp_path)
    )
    value = industry_qualification_readiness(
        standards_lifecycle=lifecycle,
        benchmark_source_health=sources,
        benchmark_proficiency_source=proficiency_source,
        benchmark_proficiency_assessment=proficiency,
        validation_portfolio_source=portfolio_source,
        validation_portfolio_assessment=portfolio,
        authority="independent-readiness-assessor",
        generated_at="2026-08-30T12:00:00+00:00",
    )
    partial = verify_industry_qualification_readiness(
        value, standards_lifecycle=lifecycle
    )
    assert partial["valid"] is False
    assert partial["checks"]["exact_source_replay"] is False

    forged = copy.deepcopy(value)
    forged["summary"]["passed"] = True
    forged["summary"]["status"] = (
        "eligible_for_authorized_industry_qualification_review"
    )
    forged["summary"]["blockers"] = []
    forged.pop("content_sha256")
    forged = seal(forged)
    forged_path = tmp_path / "forged-readiness.json"
    publish_json(forged, forged_path)
    verdict = verify_industry_qualification_readiness_file(forged_path)
    assert verdict["valid"] is False
    assert verdict["eligible_for_authorized_industry_qualification_review"] is False

    malformed_binding = copy.deepcopy(value)
    malformed_binding["evidence"][0]["sha256"] = "not-a-digest"
    malformed_binding.pop("content_sha256")
    malformed_binding = seal(malformed_binding)
    malformed_verdict = verify_industry_qualification_readiness(malformed_binding)
    assert malformed_verdict["valid"] is False
    assert malformed_verdict["checks"]["closed_structure"] is False

    detached_portfolio = load_json(portfolio, label="portfolio assessment")
    detached_portfolio["limitations"].append("detached source mutation")
    detached_portfolio.pop("content_sha256")
    detached_portfolio = seal(detached_portfolio)
    detached_path = tmp_path / "detached-portfolio-assessment.json"
    publish_json(detached_portfolio, detached_path)
    detached_readiness = industry_qualification_readiness(
        standards_lifecycle=lifecycle,
        benchmark_source_health=sources,
        benchmark_proficiency_source=proficiency_source,
        benchmark_proficiency_assessment=proficiency,
        validation_portfolio_source=portfolio_source,
        validation_portfolio_assessment=detached_path,
        authority="independent-readiness-assessor",
    )
    assert detached_readiness["checks"]["independent_validation_portfolio"] is False
    portfolio_bindings = {item["kind"]: item for item in detached_readiness["evidence"]}
    assert portfolio_bindings["validation_portfolio_source"]["valid"] is False
    assert portfolio_bindings["validation_portfolio_assessment"]["valid"] is False


def test_authenticated_scope_receipt_contract_and_partial_replay(
    tmp_path: Path,
) -> None:
    inputs = dict(
        zip(
            (
                "standards_lifecycle",
                "benchmark_source_health",
                "benchmark_proficiency_source",
                "benchmark_proficiency_assessment",
                "validation_portfolio_source",
                "validation_portfolio_assessment",
            ),
            _incomplete_evidence(tmp_path),
            strict=True,
        )
    )
    authentication = {
        "authenticated": True,
        "trust_policy_sha256": "a" * 64,
        "signature_sha256": "b" * 64,
        "key_fingerprint": "sha256:" + "c" * 64,
        "errors": [],
    }
    with patch(
        "pysfmea.industry_qualification_readiness.authenticate_scope",
        return_value=authentication,
    ):
        value = industry_qualification_readiness(**inputs, authority="reviewer")
    Draft202012Validator(schema_document("industry-qualification-readiness")).validate(
        value
    )
    assert verify_industry_qualification_readiness(value)["valid"]
    assert not value["summary"][
        "passed"
    ]  # Signature alone cannot qualify the portfolio.
    assert not verify_industry_qualification_readiness(
        value, scope_trust_policy=tmp_path / "trust.json"
    )["valid"]
    malformed = copy.deepcopy(value)
    malformed["scope_authentication"]["key_fingerprint"] = ""
    assert not verify_industry_qualification_readiness(seal(malformed))["valid"]


def test_readiness_cli_creates_and_exactly_replays_artifact(tmp_path: Path) -> None:
    lifecycle, sources, proficiency_source, proficiency, portfolio_source, portfolio = (
        _incomplete_evidence(tmp_path)
    )
    readiness = tmp_path / "industry-readiness.json"
    assert (
        main(
            [
                "industry-qualification-readiness",
                "--standards-lifecycle",
                str(lifecycle),
                "--benchmark-source-health",
                str(sources),
                "--benchmark-proficiency-source",
                str(proficiency_source),
                "--benchmark-proficiency",
                str(proficiency),
                "--validation-portfolio-source",
                str(portfolio_source),
                "--validation-portfolio",
                str(portfolio),
                "--authority",
                "independent-readiness-assessor",
                "-o",
                str(readiness),
            ]
        )
        == 0
    )
    assert readiness.is_file()
    assert (
        main(
            [
                "industry-qualification-readiness-verify",
                str(readiness),
                "--standards-lifecycle",
                str(lifecycle),
                "--benchmark-source-health",
                str(sources),
                "--benchmark-proficiency-source",
                str(proficiency_source),
                "--benchmark-proficiency",
                str(proficiency),
                "--validation-portfolio-source",
                str(portfolio_source),
                "--validation-portfolio",
                str(portfolio),
                "--json",
            ]
        )
        == 0
    )
