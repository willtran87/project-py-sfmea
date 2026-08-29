from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.conformance import standards_catalog
from pysfmea.fuzz_campaign import fuzz_campaign_template, verify_fuzz_campaign
from pysfmea.governed_artifact import seal
from pysfmea.industry_benchmarks import (
    BENCHMARK_SUITES,
    benchmark_execution_template,
    benchmark_suite_catalog,
    verify_benchmark_execution,
)
from pysfmea.interoperability_validation import normative_schema_validation
from pysfmea.oscal_exchange import (
    OSCAL_SCHEMA,
    oscal_assessment_results,
    verify_oscal_assessment_results,
)
from pysfmea.sarif_ingestion import sarif_fusion, verify_sarif_fusion
from pysfmea.schemas import schema_document


def _analysis() -> dict:
    return {
        "project": {"baseline": {"id": "baseline-1"}},
        "components": [
            {
                "id": "controller",
                "source": {"path": "src/app.py", "line": 1, "end_line": 20},
            }
        ],
        "findings": [
            {
                "id": "FM-1",
                "component_id": "controller",
                "failure_mode": "Unhandled timeout",
                "effect": "Request can exceed its deadline.",
                "status": "open",
            }
        ],
    }


def _sarif(path: Path, *, tool: str = "Bandit") -> None:
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": tool, "version": "1.0"}},
                        "results": [
                            {
                                "ruleId": "B101",
                                "level": "warning",
                                "message": {"text": "Unsafe assertion"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/app.py"},
                                            "region": {"startLine": 5, "startColumn": 1},
                                        }
                                    }
                                ],
                                "taxa": [{"id": "CWE-703"}],
                                "partialFingerprints": {"primary": "known-1"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_sarif_fusion_is_lossless_exact_bound_and_tamper_evident(tmp_path: Path) -> None:
    first = tmp_path / "bandit.sarif"
    second = tmp_path / "semgrep.sarif"
    _sarif(first)
    _sarif(second, tool="Semgrep")
    analysis = _analysis()
    value = sarif_fusion(
        analysis,
        [first, second],
        authority="security-review-board",
        evidence_refs=["evidence://sarif/run-1"],
        generated_at="2026-08-28T00:00:00+00:00",
    )
    assert value["summary"] == {
        "inputs": 2,
        "runs": 2,
        "tools": 2,
        "results": 2,
        "mapped": 2,
        "ambiguous": 0,
        "unmapped": 0,
        "clusters": 1,
        "multi_tool_clusters": 1,
    }
    assert verify_sarif_fusion(
        value, analysis=analysis, sarif_sources=[first, second]
    )["valid"] is True
    Draft202012Validator(schema_document("sarif-fusion")).validate(value)

    tampered = copy.deepcopy(value)
    tampered["summary"]["mapped"] = 1
    tampered = seal({key: val for key, val in tampered.items() if key != "content_sha256"})
    assert verify_sarif_fusion(tampered)["valid"] is False


def test_oscal_projection_is_deterministic_and_analysis_bound() -> None:
    analysis = _analysis()
    value = oscal_assessment_results(
        analysis,
        authority="assurance-board",
        generated_at="2026-08-28T00:00:00+00:00",
    )
    assert value["$schema"] == OSCAL_SCHEMA
    observations = value["assessment-results"]["results"][0]["observations"]
    assert len(observations) == 1
    assert observations[0]["props"][0]["value"] == "FM-1"
    assert verify_oscal_assessment_results(value, analysis=analysis)["valid"] is True
    Draft202012Validator(schema_document("oscal-assessment-results")).validate(value)

    drifted = copy.deepcopy(analysis)
    drifted["findings"][0]["effect"] = "Changed effect"
    assert verify_oscal_assessment_results(value, analysis=drifted)["valid"] is False


def test_benchmark_registry_and_execution_contract_fail_closed() -> None:
    catalog = benchmark_suite_catalog()
    assert len(catalog["suites"]) == len(BENCHMARK_SUITES) == 5
    Draft202012Validator(schema_document("industry-benchmark-catalog")).validate(catalog)
    value = benchmark_execution_template(suite_id="bugsinpy", authority="owner")
    initial = verify_benchmark_execution(value)
    assert initial["valid"] is True
    assert initial["eligible_for_benchmark_assessment"] is False

    value["suite"].update(
        {
            "revision": "commit-abc",
            "snapshot_sha256": "1" * 64,
            "license_evidence_ref": "evidence://license/bugsinpy",
        }
    )
    value["authority"].update(
        {
            "execution_operator": "operator",
            "label_authority": "labeler",
            "approval_authority": "approver",
            "independence_basis": "Separate reporting lines and blinded labels.",
        }
    )
    value["execution"].update(
        {
            "image": "runner@sha256:" + "2" * 64,
            "command": ["python", "run.py"],
            "started_at": "2026-08-28T00:00:00Z",
            "completed_at": "2026-08-28T00:10:00Z",
            "timeout_seconds": 900,
            "cpu_limit": 2.0,
            "memory_mb": 4096,
            "exit_code": 0,
        }
    )
    value["outcome"].update(
        {
            "status": "completed",
            "cases_total": 10,
            "cases_completed": 10,
            "metrics": {"defects_detected": 8, "defects_missed": 2},
        }
    )
    value["evidence_refs"] = ["evidence://benchmark/run-1"]
    value = seal({key: val for key, val in value.items() if key != "content_sha256"})
    assert verify_benchmark_execution(value)["eligible_for_benchmark_assessment"] is True
    Draft202012Validator(schema_document("benchmark-execution")).validate(value)


def test_fuzz_campaign_requires_isolation_coverage_and_closed_crash_triage() -> None:
    value = fuzz_campaign_template(authority="owner")
    assert verify_fuzz_campaign(value)["eligible_for_assurance_use"] is False
    value["authority"].update(
        {
            "execution_operator": "operator",
            "triage_authority": "triager",
            "approval_authority": "approver",
            "independence_basis": "Independent triage and approval.",
        }
    )
    value["target"].update(
        {
            "repository_revision": "commit-abc",
            "repository_sha256": "1" * 64,
            "component_ids": ["controller"],
            "entrypoint": "fuzz_target.py:test_one_input",
        }
    )
    value["engine"].update(
        {
            "version": "2.3.0",
            "image": "atheris@sha256:" + "2" * 64,
            "command": ["python", "fuzz_target.py"],
            "configuration_sha256": "3" * 64,
        }
    )
    value["isolation"].update(
        {"cpu_limit": 2.0, "memory_mb": 4096, "timeout_seconds": 3600}
    )
    value["corpus"].update(
        {
            "initial_sha256": "4" * 64,
            "final_sha256": "5" * 64,
            "initial_inputs": 10,
            "final_inputs": 30,
        }
    )
    value["execution"].update(
        {
            "status": "completed",
            "started_at": "2026-08-28T00:00:00Z",
            "completed_at": "2026-08-28T01:00:00Z",
            "executions": 1_000_000,
            "execs_per_second": 277.7,
            "exit_code": 0,
            "coverage_observation_ref": "evidence://coverage/fuzz-1",
        }
    )
    value["evidence_refs"] = ["evidence://fuzz/run-1"]
    value = seal({key: val for key, val in value.items() if key != "content_sha256"})
    assert verify_fuzz_campaign(value)["eligible_for_assurance_use"] is True
    Draft202012Validator(schema_document("fuzz-campaign")).validate(value)


def test_missing_industry_profiles_are_governed_and_discoverable() -> None:
    catalog = standards_catalog()
    identifiers = {profile["id"] for profile in catalog["profiles"]}
    assert len(identifiers) == 78
    assert {
        "nist-sp-800-53-53a-r5",
        "nist-sp-800-160-v1r1",
        "nist-sp-800-161-r1",
        "nistir-8397",
        "owasp-samm-v2",
        "iso-iec-20246-2017",
        "iec-62443-3-3",
    } <= identifiers


def test_normative_json_schema_supports_unicode_property_patterns(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    schema = tmp_path / "schema.json"
    artifact.write_text(json.dumps({"name": "München"}), encoding="utf-8")
    schema.write_text(
        json.dumps(
            {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "pattern": r"^\p{L}+$"}
                },
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )
    receipt = normative_schema_validation(
        artifact,
        schema,
        schema_kind="json-schema",
        standard_name="Unicode JSON Schema fixture",
        standard_edition="1",
        normative_schema_uri="controlled://unicode-schema.json",
    )
    assert receipt["outcome"] == {"valid": True, "error_count": 0, "errors": []}
    assert receipt["validator"]["engine"].endswith("+regex")
