from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.benchmark_adapter import ADAPTER_BLUEPRINTS, benchmark_adapter_template
from pysfmea.governed_artifact import seal
from pysfmea.integrity import canonical_json_sha256
from pysfmea.performance_history import performance_history, verify_performance_history
from pysfmea.schemas import schema_document
from pysfmea.vulnerability_intelligence import (
    import_vulnerability_intelligence,
    verify_vulnerability_intelligence,
    vulnerability_intelligence_match,
)


def _write_intelligence_sources(root: Path) -> tuple[Path, Path, Path]:
    osv = root / "osv.json"
    kev = root / "kev.json"
    epss = root / "epss.csv"
    osv.write_text(
        json.dumps(
            {
                "vulns": [
                    {
                        "id": "PYSEC-2026-1",
                        "aliases": ["CVE-2026-12345"],
                        "affected": [
                            {
                                "package": {
                                    "ecosystem": "PyPI",
                                    "name": "example",
                                    "purl": "pkg:pypi/example",
                                },
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.0"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    kev.write_text(
        json.dumps(
            {
                "catalogVersion": "fixture",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-12345",
                        "dateAdded": "2026-08-29",
                        "dueDate": "2026-09-01",
                        "knownRansomwareCampaignUse": "Known",
                        "requiredAction": "Apply mitigations.",
                        "vendorProject": "Example",
                        "product": "example",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    epss.write_text(
        "#model_version:v5,score_date:2026-08-29\n"
        "cve,epss,percentile,date\n"
        "CVE-2026-12345,0.75,0.98,2026-08-29\n",
        encoding="utf-8",
    )
    return osv, kev, epss


def test_vulnerability_intelligence_preserves_exact_sources_and_distinct_priority_inputs(
    tmp_path: Path,
) -> None:
    osv, kev, epss = _write_intelligence_sources(tmp_path)
    value = import_vulnerability_intelligence(
        osv=osv,
        kev=kev,
        epss=epss,
        authority="security-board",
        observed_at="2026-08-30T00:00:00+00:00",
    )
    verdict = verify_vulnerability_intelligence(
        value,
        as_of="2026-08-30T12:00:00+00:00",
        sources={"osv": osv, "cisa-kev": kev, "first-epss": epss},
    )
    assert verdict["eligible_for_priority_input"] is True
    assert (
        verify_vulnerability_intelligence(
            value,
            as_of="2026-08-30T12:00:00+00:00",
            sources={"osv": osv},
        )["valid"]
        is False
    )
    assert value["summary"] == {
        "records": 1,
        "osv_advisories": 1,
        "known_exploited": 1,
        "epss_observations": 1,
        "package_identities": 1,
    }
    match = vulnerability_intelligence_match(value, purls=["pkg:pypi/example"])
    assert match["matches"][0]["known_exploited"] is True
    assert match["matches"][0]["epss_probability"] == 0.75
    assert match["matches"][0]["applicability"] == "unresolved"
    Draft202012Validator(schema_document("vulnerability-intelligence")).validate(value)
    Draft202012Validator(schema_document("vulnerability-intelligence-match")).validate(
        match
    )

    osv.write_text("{}", encoding="utf-8")
    assert (
        verify_vulnerability_intelligence(
            value,
            as_of="2026-08-30T12:00:00+00:00",
            sources={"osv": osv, "cisa-kev": kev, "first-epss": epss},
        )["valid"]
        is False
    )


def _performance_receipt(
    path: Path, *, generated_at: str, version: str, median: float, peak: int
) -> Path:
    value = {
        "format": "pysfmea-scan-performance-2",
        "generated_at": generated_at,
        "tool": {"name": "PySFMEA", "version": version},
        "environment": {
            "python": "3.14.0",
            "implementation": "CPython",
            "platform": "controlled-runner",
            "machine": "x86_64",
            "processor": "controlled-cpu",
            "logical_cpu_count": 4,
        },
        "repository": {
            "baseline_ids": ["sha256:corpus"],
            "inventory_files": 100,
            "inventory_bytes": 100_000,
            "source_snapshot_files": 90,
            "source_snapshot_bytes": 90_000,
            "components": 300,
            "candidates": 120,
        },
        "summary": {
            "median_seconds": median,
            "p95_seconds": median * 1.1,
            "maximum_peak_traced_bytes": peak,
            "maximum_process_peak_rss_bytes": peak * 2,
            "coefficient_of_variation_percent": 1.0,
            "fact_reuse_enabled": True,
        },
    }
    value["content_sha256"] = canonical_json_sha256(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_performance_history_requires_comparable_multi_release_evidence(
    tmp_path: Path,
) -> None:
    receipts = [
        _performance_receipt(
            tmp_path / "one.json",
            generated_at="2026-01-01T00:00:00Z",
            version="0.69.0",
            median=10.0,
            peak=1000,
        ),
        _performance_receipt(
            tmp_path / "two.json",
            generated_at="2026-02-01T00:00:00Z",
            version="0.70.0",
            median=10.2,
            peak=1020,
        ),
        _performance_receipt(
            tmp_path / "three.json",
            generated_at="2026-03-01T00:00:00Z",
            version="0.71.0",
            median=10.5,
            peak=1050,
        ),
    ]
    value = performance_history(receipts, authority="release-board")
    verdict = verify_performance_history(value)
    assert value["comparison"]["runtime_change_percent"] == 5.0
    assert value["summary"]["passed"] is True
    assert verdict["eligible_for_release_gate"] is True
    assert verify_performance_history(value, receipts=receipts)["valid"] is True
    Draft202012Validator(schema_document("performance-history")).validate(value)

    forged = json.loads(json.dumps(value))
    forged["comparison"]["runtime_change_percent"] = 0.0
    forged = seal(
        {key: item for key, item in forged.items() if key != "content_sha256"}
    )
    assert verify_performance_history(forged)["valid"] is False

    changed = json.loads(receipts[-1].read_text(encoding="utf-8"))
    changed["environment"]["machine"] = "arm64"
    changed.pop("content_sha256")
    changed["content_sha256"] = canonical_json_sha256(changed)
    receipts[-1].write_text(json.dumps(changed), encoding="utf-8")
    incomparable = performance_history(receipts, authority="release-board")
    assert incomparable["summary"]["passed"] is False


def test_every_benchmark_suite_has_a_non_placeholder_normalization_blueprint() -> None:
    assert len(ADAPTER_BLUEPRINTS) == 41
    for suite_id, blueprint in ADAPTER_BLUEPRINTS.items():
        value = benchmark_adapter_template(suite_id=suite_id, authority="owner")
        assert value["normalization"] == {
            "output_format": "pysfmea-benchmark-observations-2",
            **blueprint,
        }
        assert all("unassigned" not in str(item) for item in blueprint.values())
