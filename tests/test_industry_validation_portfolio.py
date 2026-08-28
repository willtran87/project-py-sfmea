from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.benchmark_v2 import (
    BENCHMARK_OBSERVATIONS_V2_FORMAT,
    BENCHMARK_PROTOCOL_V2_FORMAT,
    REQUALIFICATION_TRIGGERS_V2,
    benchmark_v2_assessment,
    export_benchmark_v2_assessment,
)
from pysfmea.conformance import standards_catalog
from pysfmea.coverage_observation import (
    runtime_coverage_observation,
    verify_runtime_coverage_observation,
)
from pysfmea.governed_artifact import publish_json, seal
from pysfmea.schemas import schema_document
from pysfmea.validation_portfolio import (
    export_validation_portfolio_assessment,
    export_validation_portfolio_source,
    validation_portfolio_assessment,
    validation_portfolio_template,
    verify_validation_portfolio_assessment,
)
from pysfmea.validation_portfolio_report import (
    export_validation_portfolio_report,
    verify_validation_portfolio_report_file,
)


def _analysis() -> dict:
    return {
        "project": {"baseline": {"id": "baseline-1"}},
        "components": [
            {
                "id": "alpha",
                "name": "alpha",
                "qualname": "app.alpha",
                "source": {"path": "app.py", "line": 1, "end_line": 4},
            },
            {
                "id": "beta",
                "name": "beta",
                "qualname": "app.beta",
                "source": {"path": "app.py", "line": 5, "end_line": 8},
            },
        ],
    }


def _coverage(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "meta": {"format": 3, "version": "7.10.0"},
                "files": {
                    "app.py": {
                        "executed_lines": list(range(1, 9)),
                        "missing_lines": [],
                        "executed_branches": [[2, 3], [2, 4], [6, 7], [6, -1]],
                        "missing_branches": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def _benchmark(root: Path) -> Path:
    thresholds = {
        "finding_detection": {
            "minimum_recall_lower": 0.0,
            "minimum_precision_lower": 0.0,
        }
    }
    protocol = seal(
        {
            "format": BENCHMARK_PROTOCOL_V2_FORMAT,
            "id": "external-composite",
            "title": "External composite Python benchmark",
            "pre_registered_at": "2026-08-28T00:00:00+00:00",
            "pre_registration_evidence_ref": "evidence://registry/external-composite",
            "governance": {
                "protocol_owner": "protocol-owner",
                "label_authority": "label-authority",
                "approval_authority": "approval-authority",
                "independence_basis": "Separate organizations and reporting lines.",
            },
            "design": {
                "frozen_before_execution": True,
                "blinded_holdout": True,
                "minimum_repositories": 2,
                "selection_method": "Pre-registered suite-stratified selection.",
                "represented_populations": ["security", "real defects"],
                "excluded_populations": ["native extensions"],
                "strata_fields": ["benchmark_suite"],
                "minimum_repositories_per_stratum": 1,
            },
            "statistics": {
                "confidence_level": 0.95,
                "bootstrap_replicates": 200,
                "bootstrap_seed": "external-composite-2026",
                "metric_thresholds": thresholds,
                "minimum_krippendorff_alpha": 0.8,
                "minimum_calibration_samples": 0,
                "maximum_brier_score": 1.0,
                "maximum_expected_calibration_error": 1.0,
            },
            "power_analysis": {
                "method": "pre-registered repository-cluster simulation",
                "alpha": 0.05,
                "target_power": 0.8,
                "minimum_effect_size": 0.2,
                "required_repositories": 2,
                "evidence_ref": "evidence://power/1",
            },
            "requalification_triggers": sorted(REQUALIFICATION_TRIGGERS_V2),
        }
    )
    metric = {
        "true_positive": 20,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 20,
    }
    observations = seal(
        {
            "format": BENCHMARK_OBSERVATIONS_V2_FORMAT,
            "protocol_id": "external-composite",
            "sealed_at": "2026-08-28T01:00:00+00:00",
            "labeling_completed_at": "2026-08-28T02:00:00+00:00",
            "repositories": [
                {
                    "id": "owasp-python",
                    "source_ref": "https://github.com/OWASP-Benchmark/BenchmarkPython",
                    "strata": {"benchmark_suite": ["owasp-python"]},
                    "metrics": {"finding_detection": copy.deepcopy(metric)},
                    "predictions": [],
                },
                {
                    "id": "bugsinpy",
                    "source_ref": "https://github.com/soarsmu/BugsInPy",
                    "strata": {"benchmark_suite": ["bugsinpy"]},
                    "metrics": {"finding_detection": copy.deepcopy(metric)},
                    "predictions": [],
                },
            ],
            "rating_items": [
                {
                    "id": "rating-positive",
                    "ratings": {"reviewer-a": True, "reviewer-b": True},
                    "adjudication_ref": "evidence://ratings/positive",
                },
                {
                    "id": "rating-negative",
                    "ratings": {"reviewer-a": False, "reviewer-b": False},
                    "adjudication_ref": "evidence://ratings/negative",
                },
            ],
        }
    )
    protocol_path = root / "protocol.json"
    observations_path = root / "observations.json"
    publish_json(protocol, protocol_path)
    publish_json(observations, observations_path)
    assessment = benchmark_v2_assessment(
        protocol_path,
        observations_path,
        generated_at="2026-08-28T03:00:00+00:00",
    )
    assert assessment["summary"]["passed"] is True
    assessment_path = root / "benchmark-assessment.json"
    export_benchmark_v2_assessment(assessment, assessment_path)
    return assessment_path


def test_runtime_coverage_is_exact_bound_and_does_not_claim_mcdc(tmp_path: Path) -> None:
    coverage_path = tmp_path / "coverage.json"
    _coverage(coverage_path)
    analysis = _analysis()
    observation = runtime_coverage_observation(
        analysis,
        coverage_path,
        authority="verification-authority",
        command="coverage json -o coverage.json",
        configuration_sha256="c" * 64,
        environment="Python 3.13 on controlled Linux runner",
        test_run_ref="evidence://ci/run-1",
        evidence_refs=["evidence://ci/run-1/log"],
        minimum_statement_rate=1.0,
        minimum_branch_rate=1.0,
        require_all_components=True,
        generated_at="2026-08-28T04:00:00+00:00",
    )
    assert observation["summary"]["ready_for_structural_coverage_use"] is True
    assert observation["summary"]["components_observed"] == 2
    assert "not decision coverage or MC/DC" in observation["claim_boundary"]
    verdict = verify_runtime_coverage_observation(
        observation, analysis=analysis, coverage_source=coverage_path
    )
    assert verdict["valid"] is True
    assert verdict["ready_for_structural_coverage_use"] is True
    forged = copy.deepcopy(observation)
    forged["summary"]["ready_for_structural_coverage_use"] = False
    forged = seal(forged)
    assert verify_runtime_coverage_observation(forged)["valid"] is False
    Draft202012Validator(schema_document("runtime-coverage-observation")).validate(
        observation
    )
    Draft202012Validator(
        schema_document("runtime-coverage-observation-verification")
    ).validate(verdict)


def test_external_validation_portfolio_requires_traceable_composite_evidence(
    tmp_path: Path,
) -> None:
    benchmark_path = _benchmark(tmp_path)
    coverage_path = tmp_path / "coverage.json"
    _coverage(coverage_path)
    coverage_observation = runtime_coverage_observation(
        _analysis(),
        coverage_path,
        authority="coverage-authority",
        command="coverage json -o coverage.json",
        configuration_sha256="d" * 64,
        environment="controlled runner",
        test_run_ref="evidence://ci/coverage",
        evidence_refs=["evidence://ci/coverage/log"],
        minimum_statement_rate=1.0,
        minimum_branch_rate=1.0,
        require_all_components=True,
    )
    coverage_observation_path = tmp_path / "coverage-observation.json"
    publish_json(coverage_observation, coverage_observation_path)

    source = validation_portfolio_template(authority="portfolio-owner")
    source["authority"] = {
        "portfolio_owner": "portfolio-owner",
        "verification_authority": "independent-verifier",
        "approval_authority": "approval-board",
        "independence_basis": "Separate employers and reporting lines.",
    }
    source["product"] = {
        "name": "PySFMEA",
        "version": "0.67.0",
        "intended_use": "Python repository SFMEA discovery and assurance planning",
        "operational_scope": "Python 3.11-3.14 service and library repositories",
    }
    source["benchmark_assessment_paths"] = [benchmark_path.name]
    source["benchmark_suites"] = [
        {
            "id": "owasp-python",
            "title": "OWASP Benchmark for Python",
            "publisher": "OWASP Foundation",
            "version": "0.1 pinned revision",
            "suite_type": "executable_synthetic",
            "language": "Python",
            "source_uri": "https://github.com/OWASP-Benchmark/BenchmarkPython",
            "source_sha256": "1" * 64,
            "license": "GPL-3.0",
            "taxonomy": ["CWE", "security"],
            "repository_ids": ["owasp-python"],
            "label_authority": "OWASP Benchmark maintainers",
            "evidence_ref": "evidence://suite/owasp-python",
        },
        {
            "id": "bugsinpy",
            "title": "BugsInPy",
            "publisher": "BugsInPy research maintainers",
            "version": "pinned revision",
            "suite_type": "real_world_defect",
            "language": "Python",
            "source_uri": "https://github.com/soarsmu/BugsInPy",
            "source_sha256": "2" * 64,
            "license": "repository-declared license",
            "taxonomy": ["real defect", "testing"],
            "repository_ids": ["bugsinpy"],
            "label_authority": "independent defect adjudication team",
            "evidence_ref": "evidence://suite/bugsinpy",
        },
    ]
    counts = {
        "finding_detection": {
            "true_positive": 10,
            "false_positive": 1,
            "false_negative": 1,
            "true_negative": 10,
        }
    }
    source["comparator_observations"] = [
        {
            "id": "bandit-baseline",
            "tool": "Bandit",
            "version": "pinned",
            "runner": "independent-security-lab",
            "independence_basis": "Separate organization.",
            "suite_ids": ["owasp-python", "bugsinpy"],
            "metrics": copy.deepcopy(counts),
            "raw_result_ref": "evidence://comparators/bandit",
            "raw_result_sha256": "3" * 64,
        },
        {
            "id": "semgrep-baseline",
            "tool": "Semgrep",
            "version": "pinned",
            "runner": "independent-security-lab",
            "independence_basis": "Separate organization.",
            "suite_ids": ["owasp-python", "bugsinpy"],
            "metrics": copy.deepcopy(counts),
            "raw_result_ref": "evidence://comparators/semgrep",
            "raw_result_sha256": "4" * 64,
        },
    ]
    source["runtime_coverage_paths"] = [coverage_observation_path.name]
    source["usability_studies"] = [
        {
            "id": "analyst-study",
            "method": "moderated representative task study",
            "operator": "ux-researcher",
            "reviewer": "independent-human-factors-reviewer",
            "representative_user_basis": "SFMEA analysts from two organizations",
            "participant_count": 5,
            "task_attempts": 20,
            "successful_tasks": 20,
            "critical_use_errors": 0,
            "median_time_seconds": 180.0,
            "satisfaction_instrument": "pre-registered normalized instrument",
            "satisfaction_score": 0.9,
            "minimum_satisfaction_score": 0.8,
            "accessibility_evidence_refs": ["evidence://a11y/report"],
            "evidence_refs": ["evidence://usability/raw", "evidence://usability/report"],
        }
    ]
    source["evidence_refs"] = ["evidence://portfolio/approval-package"]
    source["limitations"] = ["Native-extension repositories are excluded."]
    source = seal(source)
    source_path = tmp_path / "portfolio.json"
    export_validation_portfolio_source(source, source_path)

    assessment = validation_portfolio_assessment(source_path)
    assert assessment["summary"]["passed"] is True
    assert assessment["benchmark"]["exact_suite_repository_trace"] is True
    assert {item["reference"] for item in assessment["artifacts"]} == {
        benchmark_path.name,
        coverage_observation_path.name,
    }
    verdict = verify_validation_portfolio_assessment(
        assessment, source=source_path
    )
    assert verdict["valid"] is True
    assert verdict["passed"] is True
    Draft202012Validator(
        schema_document("industry-validation-portfolio-source")
    ).validate(source)
    Draft202012Validator(
        schema_document("industry-validation-portfolio-assessment")
    ).validate(assessment)
    Draft202012Validator(
        schema_document("industry-validation-portfolio-verification")
    ).validate(verdict)
    assessment_path = tmp_path / "portfolio-assessment.json"
    export_validation_portfolio_assessment(assessment, assessment_path)
    report_path = tmp_path / "portfolio-report.html"
    export_validation_portfolio_report(assessment_path, report_path)
    report_verdict = verify_validation_portfolio_report_file(
        report_path, assessment_source=assessment_path
    )
    assert report_verdict["valid"] is True
    assert report_verdict["passed"] is True
    Draft202012Validator(
        schema_document("industry-validation-portfolio-report-verification")
    ).validate(report_verdict)
    report_path.write_text(
        report_path.read_text(encoding="utf-8").replace("Qualification gates", "Rewritten gates", 1),
        encoding="utf-8",
    )
    assert verify_validation_portfolio_report_file(report_path)["valid"] is False
    forged = copy.deepcopy(assessment)
    forged["checks"]["runtime_coverage"] = False
    forged = seal(forged)
    forged_verdict = verify_validation_portfolio_assessment(forged)
    assert forged_verdict["valid"] is False
    assert any("summary does not reconcile" in error for error in forged_verdict["errors"])


def test_catalog_includes_current_governance_and_evaluation_profiles() -> None:
    identifiers = {item["id"] for item in standards_catalog()["profiles"]}
    assert {
        "nist-csf-2-0",
        "iso-27001-27002-27005",
        "iso-27701-2025",
        "iso-29147-30111",
        "iso-15408-18045-2026",
        "iso-9241-210-171",
        "iec-62366-1",
        "iso-22301-2019",
        "iso-42006-2025",
        "faa-do-333-formal-methods",
    } <= identifiers
