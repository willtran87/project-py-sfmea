from __future__ import annotations

import json
from pathlib import Path

import pytest

from pysfmea.benchmark_native import normalize_native_benchmark
from pysfmea.benchmark_source_health import (
    benchmark_source_health_template,
    qualify_benchmark_source,
    verify_benchmark_source_health,
)
from pysfmea.standards_watchlist import standards_watchlist, verify_standards_watchlist


def test_source_qualification_computes_local_evidence_and_stays_fail_closed(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "dataset.jsonl"
    snapshot.write_text('{"instance_id":"one"}\n', encoding="utf-8")
    license_file = tmp_path / "LICENSE"
    license_file.write_text("reviewed license evidence", encoding="utf-8")
    ledger = benchmark_source_health_template(authority="benchmark board")

    qualified = qualify_benchmark_source(
        ledger,
        suite_id="swe-polybench-verified-python",
        snapshot=snapshot,
        observed_revision="commit:0123456789abcdef",
        observed_url="https://github.com/amazon-science/SWE-PolyBench",
        license_id="Apache-2.0",
        license_evidence=license_file,
        schema_version="SWE-PolyBench result.json @ 0123456789abcdef",
        reviewer="independent reviewer",
        observed_at="2026-08-31T12:00:00+00:00",
        next_review_at="2027-02-28T12:00:00+00:00",
        notes="Local fixture proves acquisition mechanics only.",
    )

    assert qualified["summary"]["verified"] == 1
    assert qualified["summary"]["complete"] == 1
    source = next(
        item
        for item in qualified["sources"]
        if item["suite_id"] == "swe-polybench-verified-python"
    )
    assert source["snapshot_sha256"] != "0" * 64
    assert "#sha256=" in source["source_evidence_ref"]
    assert "#sha256=" in source["license_evidence_ref"]
    verdict = verify_benchmark_source_health(qualified)
    assert verdict["valid"] is True
    assert verdict["eligible_for_external_execution"] is False
    assert verdict["checks"]["all_sources_reviewed_and_pinned"] is False


def test_source_qualification_rejects_self_review(tmp_path: Path) -> None:
    snapshot = tmp_path / "dataset.json"
    snapshot.write_text("{}", encoding="utf-8")
    license_file = tmp_path / "LICENSE"
    license_file.write_text("license", encoding="utf-8")
    with pytest.raises(ValueError, match="independent"):
        qualify_benchmark_source(
            benchmark_source_health_template(authority="same authority"),
            suite_id="agentdojo",
            snapshot=snapshot,
            observed_revision="v1.2.2",
            observed_url="https://github.com/ethz-spylab/agentdojo",
            license_id="MIT",
            license_evidence=license_file,
            schema_version="TaskResults v1.2.2",
            reviewer="same authority",
            observed_at="2026-08-31T12:00:00+00:00",
            next_review_at="2027-02-28T12:00:00+00:00",
        )


def test_agentdojo_native_normalization_preserves_security_and_utility(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agentdojo.json"
    source.write_text(
        json.dumps(
            [
                {
                    "suite_name": "workspace",
                    "user_task_id": "user_task_0",
                    "injection_task_id": "injection_task_0",
                    "attack_type": "tool_knowledge",
                    "utility": True,
                    "security": False,
                }
            ]
        ),
        encoding="utf-8",
    )
    result = normalize_native_benchmark(
        source,
        suite_id="agentdojo",
        suite_revision="v1.2.2",
        authority="evaluation operator",
    )
    assert result["cases"][0]["passed"] is False  # security outcome
    assert result["cases"][0]["resolved"] is True  # utility outcome


def test_swe_polybench_and_idoft_native_normalization(tmp_path: Path) -> None:
    poly = tmp_path / "result.json"
    poly.write_text(
        json.dumps({"python__project-1": {"resolved": True}}), encoding="utf-8"
    )
    poly_result = normalize_native_benchmark(
        poly,
        suite_id="swe-polybench-verified-python",
        suite_revision="verified-2025-09-18",
        authority="evaluation operator",
    )
    assert poly_result["cases"][0]["case_id"] == "python__project-1"
    assert poly_result["cases"][0]["resolved"] is True

    idoft = tmp_path / "py-data.csv"
    idoft.write_text(
        "Project URL,SHA Detected,Pytest Test Name (PathToFile::TestClass::TestMethod or PathToFile::TestMethod),Category,Status,PR Link,Notes\n"
        "https://example.test/repo,abc123,tests/test_one.py::test_one,OD-Vic,Opened,,\n",
        encoding="utf-8",
    )
    idoft_result = normalize_native_benchmark(
        idoft,
        suite_id="idoft-python",
        suite_revision="commit:abc123",
        authority="evaluation operator",
    )
    assert idoft_result["cases"][0]["expected_label"] == "positive"
    assert "tests/test_one.py::test_one" in idoft_result["cases"][0]["case_id"]


def test_iso_42007_is_watchlisted_and_cannot_support_normative_use() -> None:
    value = standards_watchlist()
    item = next(item for item in value["items"] if item["id"] == "iso-iec-42007")
    assert item["development_stage"] == "DIS"
    assert value["policy"]["normative_use"] == "prohibited_until_published_and_adopted"
    assert verify_standards_watchlist(value)["valid"] is True
