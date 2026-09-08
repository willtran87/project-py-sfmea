from __future__ import annotations

import copy
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.benchmark_corpus import (
    INTERNAL_CORPORA,
    benchmark_corpus_inventory,
    verify_benchmark_corpus_inventory,
)
from pysfmea.benchmark_proficiency import (
    assess_benchmark_proficiency,
    benchmark_proficiency_template,
    verify_benchmark_proficiency,
)
from pysfmea.governed_artifact import seal
from pysfmea.schemas import schema_document

ROOT = Path(__file__).resolve().parents[1]


def _source() -> dict[str, object]:
    value = benchmark_proficiency_template(authority="Scheme provider")
    value.pop("content_sha256")
    value["generated_at"] = "2026-08-30T12:00:00Z"
    value["scheme"] = {
        "id": "round-robin-1",
        "round": "2026-Q3",
        "scope": "Python SFMEA benchmark proficiency",
    }
    value["authorities"] = {
        "provider": "Scheme provider",
        "technical_reviewer": "Independent reviewer",
        "approval_authority": "Approval board",
    }
    value["items"] = [
        {
            "id": "recall",
            "kind": "quantitative",
            "assigned_value": 0.9,
            "proficiency_standard_deviation": 0.05,
            "homogeneous": True,
            "stable": True,
            "evidence_refs": ["assigned-value-study.json"],
        },
        {
            "id": "cascade",
            "kind": "qualitative",
            "assigned_value": "detected",
            "proficiency_standard_deviation": None,
            "homogeneous": True,
            "stable": True,
            "evidence_refs": ["expert-consensus.json"],
        },
    ]
    value["participants"] = [
        {
            "id": "lab-a",
            "organization": "Organization A",
            "results": [
                {"item_id": "recall", "value": 0.91, "evidence_ref": "lab-a.json"},
                {
                    "item_id": "cascade",
                    "value": "detected",
                    "evidence_ref": "lab-a.json",
                },
            ],
        },
        {
            "id": "lab-b",
            "organization": "Organization B",
            "results": [
                {"item_id": "recall", "value": 0.89, "evidence_ref": "lab-b.json"},
                {
                    "item_id": "cascade",
                    "value": "detected",
                    "evidence_ref": "lab-b.json",
                },
            ],
        },
    ]
    return seal(value)


def test_proficiency_replays_and_validates_public_schemas() -> None:
    source = _source()
    assessment = assess_benchmark_proficiency(source)
    verdict = verify_benchmark_proficiency(assessment, source=source)
    assert assessment["summary"]["passed"] is True
    assert verdict["eligible_for_qualification_input"] is True
    assert assessment["participant_ledger"][0]["outcomes"][0]["z_score"] == 0.2
    for name, artifact in (
        ("benchmark-proficiency-source", source),
        ("benchmark-proficiency-assessment", assessment),
        ("benchmark-proficiency-verification", verdict),
    ):
        Draft202012Validator(schema_document(name)).validate(artifact)


def test_proficiency_detects_action_result_and_tampering() -> None:
    source = _source()
    source.pop("content_sha256")
    source["participants"][0]["results"][0]["value"] = 1.1
    source = seal(source)
    assessment = assess_benchmark_proficiency(source)
    assert assessment["summary"]["passed"] is False
    assert assessment["participant_ledger"][0]["outcomes"][0]["status"] == "action"
    altered = copy.deepcopy(assessment)
    altered["summary"]["passed"] = True
    assert verify_benchmark_proficiency(altered, source=source)["valid"] is False


def test_bundled_corpus_inventory_exactly_replays_and_is_closed() -> None:
    value = benchmark_corpus_inventory(
        ROOT / "benchmarks",
        authority="Benchmark custodian",
        generated_at="2026-08-30T12:00:00Z",
    )
    verdict = verify_benchmark_corpus_inventory(value, root=ROOT / "benchmarks")
    assert value["summary"]["corpora"] == len(INTERNAL_CORPORA) == 15
    assert verdict["eligible_as_corpus_identity_evidence"] is True
    Draft202012Validator(schema_document("benchmark-corpus-inventory")).validate(value)
    Draft202012Validator(schema_document("benchmark-corpus-verification")).validate(
        verdict
    )
