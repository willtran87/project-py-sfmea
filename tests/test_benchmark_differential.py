from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.benchmark_differential import (
    assess_benchmark_differential,
    benchmark_differential_template,
    export_benchmark_differential,
    verify_benchmark_differential,
    verify_benchmark_differential_file,
)
from pysfmea.cli import main
from pysfmea.governed_artifact import seal
from pysfmea.schemas import schema_document
from pysfmea.validation_portfolio import (
    export_validation_portfolio_source,
    validation_portfolio_assessment,
    validation_portfolio_template,
    verify_validation_portfolio_assessment,
)


def _source(tmp_path: Path, *, pending: bool = False) -> Path:
    value = benchmark_differential_template(authority="comparison-owner")
    value.pop("content_sha256")
    value["authority"] = {
        "comparison_owner": "comparison-owner",
        "label_authority": "independent-label-board",
        "adjudication_authority": "independent-adjudicator",
        "independence_basis": "separate reporting lines and write-restricted evidence stores",
    }
    value["suite"] = {
        "id": "pysfmea-semantic-corpus",
        "revision": "2026.08.31",
        "snapshot_sha256": "1" * 64,
    }
    value["tools"] = [
        {
            "id": "pysfmea",
            "version": "0.77.0",
            "runner": "isolated-runner-a",
            "source_sha256": "2" * 64,
            "evidence_ref": "evidence/pysfmea.json",
        },
        {
            "id": "comparator",
            "version": "4.1.0",
            "runner": "isolated-runner-b",
            "source_sha256": "3" * 64,
            "evidence_ref": "evidence/comparator.json",
        },
    ]
    rows = [
        ("positive-a", "positive", "positive", "positive"),
        ("positive-b", "positive", "positive", "negative"),
        ("negative-a", "negative", "negative", "negative"),
        ("negative-b", "negative", "positive", "negative"),
    ]
    value["cases"] = []
    for case_id, expected, left, right in rows:
        disagreement = left != right
        value["cases"].append(
            {
                "case_id": case_id,
                "expected_label": expected,
                "label_evidence_ref": f"labels/{case_id}.json",
                "observations": [
                    {
                        "tool_id": "pysfmea",
                        "predicted_label": left,
                        "evidence_ref": f"runs/pysfmea/{case_id}.json",
                    },
                    {
                        "tool_id": "comparator",
                        "predicted_label": right,
                        "evidence_ref": f"runs/comparator/{case_id}.json",
                    },
                ],
                "adjudication": {
                    "status": "pending"
                    if disagreement and pending
                    else "completed"
                    if disagreement
                    else "not_required",
                    "disposition": "reviewed prediction difference"
                    if disagreement and not pending
                    else "",
                    "evidence_ref": f"adjudication/{case_id}.json"
                    if disagreement and not pending
                    else "",
                },
            }
        )
    path = tmp_path / ("pending.json" if pending else "source.json")
    export_benchmark_differential(seal(value), path)
    return path


def test_paired_differential_metrics_replay_and_schema(tmp_path: Path) -> None:
    source = _source(tmp_path)
    assessment = assess_benchmark_differential(source)
    assert assessment["summary"] == {
        "passed": True,
        "status": "eligible_for_validation_portfolio",
        "tools": 2,
        "cases": 4,
        "pairwise_comparisons": 1,
        "disagreements": 2,
        "pending_adjudications": 0,
        "significant_pairwise_differences": 0,
        "failed_checks": [],
    }
    assert assessment["pairwise_comparisons"][0]["discordant"] == 2
    assert assessment["pairwise_comparisons"][0]["mcnemar_exact_p"] == 1.0
    local = verify_benchmark_differential(assessment)
    assert local["valid"] is True
    assert local["eligible_for_validation_portfolio"] is False
    assessment_path = tmp_path / "assessment.json"
    export_benchmark_differential(assessment, assessment_path)
    exact = verify_benchmark_differential_file(assessment_path, evidence_source=source)
    assert exact["valid"] is True
    assert exact["eligible_for_validation_portfolio"] is True
    for name, value in (
        (
            "benchmark-differential-source",
            json.loads(source.read_text(encoding="utf-8")),
        ),
        ("benchmark-differential-assessment", assessment),
        ("benchmark-differential-verification", exact),
    ):
        Draft202012Validator(schema_document(name)).validate(value)


def test_pending_adjudication_and_tamper_fail_closed(tmp_path: Path) -> None:
    source = _source(tmp_path, pending=True)
    assessment = assess_benchmark_differential(source)
    assert assessment["summary"]["passed"] is False
    assert assessment["summary"]["pending_adjudications"] == 2
    forged = copy.deepcopy(assessment)
    forged["summary"]["passed"] = True
    forged.pop("content_sha256")
    verdict = verify_benchmark_differential(seal(forged))
    assert verdict["valid"] is False
    assert verdict["eligible_for_validation_portfolio"] is False


def test_differential_cli_round_trip(tmp_path: Path) -> None:
    source = _source(tmp_path)
    assessment = tmp_path / "cli-assessment.json"
    assert (
        main(["benchmark-differential-assess", str(source), "-o", str(assessment)]) == 0
    )
    assert (
        main(
            [
                "benchmark-differential-verify",
                str(assessment),
                "--source",
                str(source),
                "--json",
            ]
        )
        == 0
    )


def test_validation_portfolio_consumes_exact_differential_evidence(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path)
    assessment_path = tmp_path / "differential.json"
    export_benchmark_differential(
        assess_benchmark_differential(source), assessment_path
    )
    portfolio = validation_portfolio_template(authority="portfolio-owner")
    portfolio.pop("content_sha256")
    portfolio["policy"]["case_paired_differential_required"] = True
    portfolio["differential_evidence"] = [
        {
            "id": "semantic-comparison",
            "assessment_path": assessment_path.name,
            "source_path": source.name,
        }
    ]
    portfolio_path = tmp_path / "portfolio.json"
    export_validation_portfolio_source(seal(portfolio), portfolio_path)
    result = validation_portfolio_assessment(portfolio_path)
    assert result["checks"]["case_paired_differential"] is True
    assert result["benchmark"]["differential_assessments"] == 1
    assert result["artifacts"][0]["kind"] == "benchmark_differential"
    assert result["artifacts"][0]["passed"] is True
    assert (
        verify_validation_portfolio_assessment(result, source=portfolio_path)["valid"]
        is True
    )
