from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pysfmea.benchmark_case_inventory import (
    benchmark_case_inventory,
    export_benchmark_case_inventory,
    verify_benchmark_case_inventory,
    verify_benchmark_case_inventory_file,
)
from pysfmea.benchmark_item_quality import (
    CRITERIA,
    benchmark_item_quality_audit,
    verify_benchmark_item_quality,
)
from pysfmea.benchmark_native import (
    export_native_benchmark,
    normalize_native_benchmark,
)
from pysfmea.cli import main
from pysfmea.inspect_ai_conformance import (
    export_inspect_ai_conformance,
    inspect_ai_conformance_receipt,
    verify_inspect_ai_conformance,
)
from pysfmea.inspect_ai_evidence import (
    import_inspect_ai_log,
    verify_inspect_ai_evidence,
)
from pysfmea.schemas import schema_document


def _criteria(status: str = "pass") -> dict[str, dict[str, object]]:
    return {
        name: {
            "status": status,
            "rationale": f"Independent rationale for {name}",
            "evidence_refs": [f"evidence://review/{name}"],
        }
        for name in CRITERIA
    }


def _normalization(tmp_path: Path) -> tuple[Path, Path]:
    result_source = tmp_path / "results.json"
    result_source.write_text(
        json.dumps(
            {
                "success_ids": ["python__one"],
                "failure_ids": ["python__two"],
                "incomplete_ids": [],
                "error_ids": [],
            }
        ),
        encoding="utf-8",
    )
    value = normalize_native_benchmark(
        result_source,
        suite_id="swe-bench-live",
        suite_revision="commit:0123456789abcdef",
        authority="execution laboratory",
    )
    normalization = tmp_path / "normalization.json"
    export_native_benchmark(value, normalization)
    reviews = tmp_path / "reviews.json"
    reviews.write_text(
        json.dumps(
            [
                {
                    "case_id": case_id,
                    "disposition": "accepted",
                    "criteria": _criteria(),
                    "reviewers": ["reviewer alpha", "reviewer beta"],
                    "exclusion_reason": "",
                    "notes": "Reviewed against the exact instance evidence.",
                }
                for case_id in ("python__one", "python__two")
            ]
        ),
        encoding="utf-8",
    )
    return normalization, reviews


def test_case_inventory_exactly_replays_raw_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        json.dumps(
            {"cases": [{"case_id": "task-1", "evidence_refs": ["evidence://task/1"]}]}
        ),
        encoding="utf-8",
    )
    value = benchmark_case_inventory(
        manifest,
        suite_id="terminal-bench-2",
        suite_revision="commit:0123456789abcdef",
        authority="population custodian",
        population_basis="Immutable upstream task manifest.",
    )
    local = verify_benchmark_case_inventory(value)
    assert local["valid"] is True
    assert local["checks"]["exact_source_replay"] is None
    exact = verify_benchmark_case_inventory(value, source=manifest)
    assert exact["checks"]["exact_source_replay"] is True
    Draft202012Validator(
        schema_document("benchmark-case-inventory-verification")
    ).validate(exact)

    artifact = tmp_path / "inventory.json"
    export_benchmark_case_inventory(value, artifact)
    assert (
        verify_benchmark_case_inventory_file(artifact, source=manifest)["valid"] is True
    )
    manifest.write_text(json.dumps({"cases": ["task-2"]}), encoding="utf-8")
    mismatch = verify_benchmark_case_inventory_file(artifact, source=manifest)
    assert mismatch["checks"]["exact_source_replay"] is False
    assert mismatch["valid"] is False
    assert (
        main(
            [
                "benchmark-case-inventory-verify",
                str(artifact),
                "--manifest",
                str(manifest),
                "--json",
            ]
        )
        == 1
    )


def test_swe_bench_live_and_item_quality_are_exact_and_fail_closed(
    tmp_path: Path,
) -> None:
    normalization, reviews = _normalization(tmp_path)
    normalized = json.loads(normalization.read_text(encoding="utf-8"))
    assert [item["outcome"] for item in normalized["cases"]] == [
        "success",
        "failure",
    ]
    value = benchmark_item_quality_audit(
        normalization,
        reviews,
        authority="benchmark quality board",
        max_exclusion_rate=0.05,
        generated_at="2026-08-31T12:00:00+00:00",
    )
    assert value["summary"] == {
        "items": 2,
        "accepted": 2,
        "excluded": 0,
        "remediation_required": 0,
        "exclusion_rate": 0.0,
        "passed": True,
    }
    local = verify_benchmark_item_quality(value)
    assert local["valid"] is True
    assert local["eligible_for_benchmark_claim"] is False
    exact = verify_benchmark_item_quality(
        value,
        normalization_source=normalization,
        reviews_source=reviews,
    )
    assert exact["eligible_for_benchmark_claim"] is True
    Draft202012Validator(schema_document("benchmark-item-quality")).validate(value)
    Draft202012Validator(
        schema_document("benchmark-item-quality-verification")
    ).validate(exact)

    tampered = copy.deepcopy(value)
    tampered["items"][0]["criteria"]["oracle_valid"]["status"] = "fail"
    assert verify_benchmark_item_quality(tampered)["valid"] is False


def test_item_quality_rejects_self_review_and_population_gaps(tmp_path: Path) -> None:
    normalization, reviews = _normalization(tmp_path)
    review_values = json.loads(reviews.read_text(encoding="utf-8"))
    review_values[0]["reviewers"] = ["benchmark quality board", "reviewer beta"]
    reviews.write_text(json.dumps(review_values), encoding="utf-8")
    with pytest.raises(ValueError, match="cannot review its own"):
        benchmark_item_quality_audit(
            normalization, reviews, authority="benchmark quality board"
        )

    review_values = review_values[:1]
    review_values[0]["reviewers"] = ["reviewer alpha", "reviewer beta"]
    reviews.write_text(json.dumps(review_values), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly account"):
        benchmark_item_quality_audit(
            normalization, reviews, authority="benchmark quality board"
        )


def test_item_quality_cli_creates_and_exactly_verifies_audit(tmp_path: Path) -> None:
    normalization, reviews = _normalization(tmp_path)
    output = tmp_path / "item-quality.json"
    assert (
        main(
            [
                "benchmark-item-quality",
                str(normalization),
                str(reviews),
                "--authority",
                "benchmark quality board",
                "-o",
                str(output),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "benchmark-item-quality-verify",
                str(output),
                "--normalization",
                str(normalization),
                "--reviews",
                str(reviews),
                "--json",
            ]
        )
        == 0
    )


def test_inspect_ai_intake_preserves_identity_scores_usage_and_replay(
    tmp_path: Path,
) -> None:
    source = tmp_path / "evaluation.json"
    source.write_text(
        json.dumps(
            {
                "version": 2,
                "status": "success",
                "eval": {
                    "run_id": "run-1",
                    "eval_id": "eval-1",
                    "task": "python_sfmea",
                    "task_version": "1",
                    "model": "provider/model",
                    "created": "2026-08-31T12:00:00Z",
                    "sandbox": {"type": "docker"},
                    "dataset": {"name": "hidden-python"},
                    "task_args": {"split": "test"},
                    "model_args": {"temperature": 0},
                    "config": {"epochs": 1},
                },
                "plan": {"name": "agent"},
                "results": {"scores": []},
                "stats": {"started_at": "2026-08-31T12:00:00Z"},
                "samples": [
                    {
                        "id": "case-1",
                        "epoch": 1,
                        "input": "analyze repository",
                        "target": "reviewed finding",
                        "messages": [{"role": "assistant", "content": "result"}],
                        "output": {"completion": "result"},
                        "events": [{"event": "tool", "function": "scan"}],
                        "store": {"artifact": "analysis.json"},
                        "metadata": {"stratum": "python"},
                        "scores": {
                            "correctness": {
                                "value": 1,
                                "answer": "C",
                                "explanation": "reviewed",
                                "metadata": {"judge": "human"},
                            }
                        },
                        "model_usage": {
                            "provider/model": {
                                "input_tokens": 10,
                                "output_tokens": 5,
                                "total_tokens": 15,
                            }
                        },
                        "error": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    value = import_inspect_ai_log(
        source,
        authority="evaluation evidence board",
        generated_at="2026-08-31T12:30:00+00:00",
    )
    assert value["summary"] == {
        "samples": 1,
        "completed_samples": 1,
        "error_samples": 0,
        "scored_samples": 1,
        "tool_events": 1,
        "input_tokens": 10,
        "output_tokens": 5,
        "total_tokens": 15,
    }
    assert value["samples"][0]["scores"][0]["name"] == "correctness"
    assert verify_inspect_ai_evidence(value)["eligible_for_evaluation_join"] is False
    exact = verify_inspect_ai_evidence(value, source=source)
    assert exact["eligible_for_evaluation_join"] is True
    Draft202012Validator(schema_document("inspect-ai-evidence")).validate(value)
    Draft202012Validator(schema_document("inspect-ai-evidence-verification")).validate(
        exact
    )

    evidence = tmp_path / "inspect-evidence.json"
    evidence.write_text(json.dumps(value), encoding="utf-8")
    schema = tmp_path / "inspect-schema.json"
    schema.write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["version", "status", "eval", "samples"],
                "properties": {
                    "version": {"const": 2},
                    "status": {"type": "string"},
                    "eval": {"type": "object"},
                    "samples": {"type": "array"},
                },
            }
        ),
        encoding="utf-8",
    )
    run_config = tmp_path / "run-config.json"
    run_config.write_text(
        json.dumps(
            {
                "task": {"task": "python_sfmea", "args": {"split": "test"}},
                "model": {"model": "provider/model", "args": {"temperature": 0}},
                "sandbox": "docker",
                "eval_config": {"epochs": 1},
            }
        ),
        encoding="utf-8",
    )
    schema_policy = tmp_path / "schema-policy.json"
    schema_policy.write_text(
        json.dumps(
            {
                "format": "pysfmea-upstream-schema-policy-1",
                "schemas": [
                    {
                        "tool": "Inspect AI",
                        "version": "0.3.206",
                        "uri": "https://inspect.aisi.org.uk/schema/eval-log-v2",
                        "sha256": hashlib.sha256(schema.read_bytes()).hexdigest(),
                        "configuration_projection": "inspect-export-config-1",
                    }
                ],
            }
        )
    )
    conformance = inspect_ai_conformance_receipt(
        evidence,
        source,
        schema,
        run_config,
        authority="interop laboratory",
        inspect_version="0.3.206",
        schema_uri="https://inspect.aisi.org.uk/schema/eval-log-v2",
        generated_at="2026-08-31T13:00:00+00:00",
        schema_policy_source=schema_policy,
    )
    assert conformance["eligible_for_evaluation_portfolio"] is True
    unapproved = inspect_ai_conformance_receipt(
        evidence,
        source,
        schema,
        run_config,
        authority="interop laboratory",
        inspect_version="0.3.206",
        schema_uri="https://inspect.aisi.org.uk/schema/eval-log-v2",
        generated_at="2026-08-31T13:00:00+00:00",
    )
    assert not unapproved["checks"]["approved_upstream_contract"]
    assert not unapproved["eligible_for_evaluation_portfolio"]
    assert not verify_inspect_ai_conformance(
        conformance, schema_policy_source=schema_policy
    )["valid"]
    conformance_verdict = verify_inspect_ai_conformance(
        conformance,
        evidence_source=evidence,
        log_source=source,
        schema_source=schema,
        run_config_source=run_config,
        schema_policy_source=schema_policy,
    )
    assert conformance_verdict["eligible_for_evaluation_portfolio"] is True
    Draft202012Validator(schema_document("inspect-ai-conformance")).validate(
        conformance
    )
    Draft202012Validator(
        schema_document("inspect-ai-conformance-verification")
    ).validate(conformance_verdict)
    conformance_path = tmp_path / "inspect-conformance.json"
    export_inspect_ai_conformance(conformance, conformance_path)
    assert (
        main(
            [
                "inspect-ai-conformance-verify",
                str(conformance_path),
                "--evidence",
                str(evidence),
                "--log",
                str(source),
                "--schema",
                str(schema),
                "--run-config",
                str(run_config),
                "--schema-policy",
                str(schema_policy),
                "--json",
            ]
        )
        == 0
    )
