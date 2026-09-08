from __future__ import annotations

import copy
import hashlib
import json
import runpy
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pysfmea.benchmark_native import normalize_native_benchmark
from pysfmea.cli import main
from pysfmea.conformance import standards_catalog
from pysfmea.deployed_tevv import (
    deployed_tevv_assessment,
    verify_deployed_tevv_assessment,
)
from pysfmea.genai_telemetry import import_genai_telemetry
from pysfmea.governed_artifact import publish_json, seal
from pysfmea.industry_benchmarks import benchmark_suite_catalog
from pysfmea.industry_qualification_readiness import (
    industry_qualification_readiness,
    verify_industry_qualification_readiness,
)
from pysfmea.inspect_config import configuration_matches, expected_run_config
from pysfmea.operational_evidence import change_history_consistent, request_events
from pysfmea.qualification_scope import scope_portfolio, scoped_checks
from pysfmea.schemas import schema_document
from pysfmea.validation_portfolio import validation_portfolio_assessment

TESTS = Path(__file__).parent


def test_scoped_readiness_does_not_waive_selected_contract_adapter_or_evidence(
    tmp_path: Path,
) -> None:
    fixture = runpy.run_path(str(TESTS / "test_industry_standard_level.py"))
    lifecycle, sources, proficiency_source, proficiency, portfolio_source, portfolio = (
        fixture["_incomplete_evidence"](tmp_path)
    )
    complete_dir = tmp_path / "external"
    complete_dir.mkdir()
    runpy.run_path(str(TESTS / "test_industry_validation_portfolio.py"))[
        "test_external_validation_portfolio_requires_traceable_composite_evidence"
    ](complete_dir)
    portfolio_source = complete_dir / "portfolio.json"
    value = scope_portfolio(
        json.loads(portfolio_source.read_text()),
        standards=[standards_catalog()["profiles"][0]["id"]],
        owner="scope owner",
        reviewer="scope reviewer",
        approver="scope board",
        approval_ref="evidence://scope",
        approved_at="2026-09-01T00:00:00Z",
        next_review_at="2026-10-01T00:00:00Z",
        exclusion_rationale="outside reviewed use",
    )
    publish_json(seal(value), portfolio_source)
    publish_json(validation_portfolio_assessment(portfolio_source), portfolio)
    args = dict(
        standards_lifecycle=lifecycle,
        benchmark_source_health=sources,
        benchmark_proficiency_source=proficiency_source,
        benchmark_proficiency_assessment=proficiency,
        validation_portfolio_source=portfolio_source,
        validation_portfolio_assessment=portfolio,
    )
    result = industry_qualification_readiness(
        **args, authority="readiness assessor", generated_at="2026-09-07T00:00:00Z"
    )
    # BugsInPy is explicitly selected and remains contract-only; scope cannot waive it.
    assert not result["checks"]["benchmark_adapters_operational"]
    assert result["checks"]["independent_validation_portfolio"]
    assert not result["checks"]["benchmark_sources_pinned"]
    assert not result["summary"]["passed"]
    assert verify_industry_qualification_readiness(result, **args)["checks"][
        "exact_source_replay"
    ]


def test_otlp_bridges_to_version_bound_tevv_events(tmp_path: Path) -> None:
    started = "2026-09-07T00:00:00+00:00"
    nanos = int(datetime.fromisoformat(started).timestamp()) * 1_000_000_000
    resource = {"service.version": "1", "pysfmea.model.version": "model-rev"}
    raw = {
        "resourceSpans": [
            {
                "resource": {"attributes": resource},
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "spanId": "b" * 16,
                                "traceId": "a" * 32,
                                "startTimeUnixNano": str(nanos),
                                "endTimeUnixNano": str(nanos + 3_000_000),
                                "attributes": {
                                    "gen_ai.operation.name": "chat",
                                    "gen_ai.provider.name": "provider",
                                    "gen_ai.request.model": "model",
                                },
                            }
                        ]
                    }
                ],
            }
        ]
    }
    path = tmp_path / "otel.json"
    publish_json(raw, path)
    window = {
        "telemetry_ref": path.name,
        "telemetry_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "telemetry_schema": "OpenTelemetry GenAI semantic conventions",
        "telemetry_schema_version": "1.37.0",
        "system_version": "1",
        "model_version": "model-rev",
        "ended_at": "2026-09-07T01:00:00Z",
    }
    events = request_events(tmp_path, window, {"model": "model"})
    assert (
        len(events) == 1
        and events[0]["latency_ms"] == 3.0
        and events[0]["error"] is False
    )
    Draft202012Validator(schema_document("tevv-request-events")).validate(
        {"format": "pysfmea-tevv-request-events-1", "events": events}
    )
    resource["pysfmea.model.version"] = "other-model-rev"
    publish_json(raw, path)
    window["telemetry_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="deployment versions"):
        request_events(tmp_path, window, {"model": "model"})


def test_deployment_history_accepts_old_windows_but_not_midwindow_changes() -> None:
    value = {
        "baseline": {"system_version": "1", "model_version": "a"},
        "system": {"version": "2", "model_version": "b"},
        "change_records": [
            {
                "effective_at": "2026-09-02T00:00:00Z",
                "previous_system_version": "1",
                "previous_model_version": "a",
                "new_system_version": "2",
                "new_model_version": "b",
            }
        ],
        "monitoring_windows": [
            {
                "started_at": "2026-09-01T00:00:00Z",
                "ended_at": "2026-09-02T00:00:00Z",
                "system_version": "1",
                "model_version": "a",
            },
            {
                "started_at": "2026-09-02T00:00:00Z",
                "ended_at": "2026-09-03T00:00:00Z",
                "system_version": "2",
                "model_version": "b",
            },
        ],
    }
    assert change_history_consistent(value)
    value["change_records"][0]["effective_at"] = "2026-09-01T12:00:00Z"
    assert not change_history_consistent(value)


def test_scope_cli_emits_schema_valid_bound_decision(tmp_path: Path) -> None:
    source, output = tmp_path / "portfolio.json", tmp_path / "scoped.json"
    publish_json(
        seal(
            {
                "product": {"intended_use": "test generation"},
                "policy": {"minimum_benchmark_suites": 2},
                "benchmark_suites": [{"id": "testgeneval"}],
            }
        ),
        source,
    )
    assert (
        main(
            [
                "validation-portfolio-scope",
                str(source),
                "--standard",
                standards_catalog()["profiles"][0]["id"],
                "--owner",
                "owner",
                "--reviewer",
                "reviewer",
                "--approver",
                "board",
                "--approval-ref",
                "evidence://approval",
                "--approved-at",
                "2026-09-01T00:00:00Z",
                "--next-review-at",
                "2026-10-01T00:00:00Z",
                "--exclusion-rationale",
                "outside reviewed intended use",
                "-o",
                str(output),
            ]
        )
        == 0
    )
    scoped = json.loads(output.read_text())
    scope = scoped["product"]["qualification_scope"]
    Draft202012Validator(schema_document("qualification-scope")).validate(scope)
    assert scope["acceptance_policy"] == scoped["policy"]


@pytest.mark.parametrize(
    "mutation", ["unrelated", "model", "task_args", "epochs", "sandbox", "unknown"]
)
def test_inspect_rejects_configuration_not_reproducible_from_log(mutation: str) -> None:
    log = {
        "eval": {
            "task": "analyze",
            "task_args": {"split": "hidden"},
            "model": "provider/model",
            "config": {"epochs": 2, "log_samples": True},
            "sandbox": {"type": "docker"},
        }
    }
    config = expected_run_config(log)
    assert config == {
        "task": {"task": "analyze", "args": {"split": "hidden"}},
        "model": {"model": "provider/model"},
        "eval_config": {"epochs": 2},
        "sandbox": "docker",
    }
    assert configuration_matches(log, config)
    if mutation == "unrelated":
        config = {"unrelated": True}
    elif mutation == "model":
        config["model"]["model"] = "other/model"
    elif mutation == "task_args":
        config["task"]["args"] = {"split": "train"}
    elif mutation == "epochs":
        config["eval_config"]["epochs"] = 1
    elif mutation == "sandbox":
        config["sandbox"] = "local"
    else:
        config["unknown"] = True
    assert not configuration_matches(log, config)


@pytest.mark.parametrize(
    "mutation", ["missing_raw", "metric", "wrong_change", "control_tamper"]
)
def test_tevv_requires_underlying_events_and_consistent_changes(
    tmp_path: Path, mutation: str
) -> None:
    fixture = runpy.run_path(str(TESTS / "test_deployed_tevv.py"))
    source = fixture["_source"](tmp_path)
    initial = deployed_tevv_assessment(source)
    assert initial["summary"]["passed"]
    value = json.loads(source.read_text())
    if mutation == "missing_raw":
        value["monitoring_windows"][0]["telemetry_ref"] = "does-not-exist.json"
    elif mutation == "metric":
        value["monitoring_windows"][0]["p95_latency_ms"] = 10.0
    elif mutation == "wrong_change":
        value["change_records"] = [
            {
                "id": "bad",
                "effective_at": "2026-08-05T00:00:00Z",
                "previous_system_version": "unrelated",
                "new_system_version": "1.0.0",
                "previous_model_version": "unrelated",
                "new_model_version": "2026-08-01",
                "approval_ref": "baseline.json",
                "regression_evidence_ref": "baseline.json",
            }
        ]
    else:
        control = json.loads((tmp_path / "circuit_breaker.json").read_text())
        control["requests"] = []
        publish_json(control, tmp_path / "circuit_breaker.json")
    publish_json(seal(value), source)
    assert not deployed_tevv_assessment(source)["summary"]["passed"]
    assert not verify_deployed_tevv_assessment(initial, source=source)["valid"]


@pytest.mark.parametrize(
    "mutation", ["revision", "case", "score", "execution", "missing_manifest"]
)
def test_portfolio_cannot_substitute_audit_population_or_scores(
    tmp_path: Path, mutation: str
) -> None:
    fixture = runpy.run_path(str(TESTS / "test_industry_validation_portfolio.py"))
    fixture["test_external_validation_portfolio_requires_traceable_composite_evidence"](
        tmp_path
    )
    source = tmp_path / "portfolio.json"
    assert validation_portfolio_assessment(source)["summary"]["passed"]
    ledger = tmp_path / "bugsinpy-execution.json"
    value = json.loads(ledger.read_text())
    if mutation == "revision":
        value["suite_revision"] = "other-revision"
    elif mutation == "case":
        value["cases"][0]["case_id"] = "unreviewed-case"
    elif mutation == "score":
        value["cases"][0]["metrics"]["finding_detection"]["predicted"] = False
    elif mutation == "execution":
        value["cases"][0]["executed"] = False
    else:
        (tmp_path / "bugsinpy-cases.json").unlink()
    publish_json(value, ledger)
    assessment = validation_portfolio_assessment(source)
    assert not assessment["checks"]["benchmark_item_quality"]
    assert not assessment["summary"]["passed"]


def test_genai_rejects_unknown_versions_and_mixed_legacy_fields(tmp_path: Path) -> None:
    source = tmp_path / "otel.json"
    publish_json(
        {
            "spans": [
                {
                    "spanId": "b" * 16,
                    "traceId": "a" * 32,
                    "attributes": {
                        "gen_ai.operation.name": "chat",
                        "gen_ai.provider.name": "p",
                        "gen_ai.system": "legacy",
                    },
                }
            ]
        },
        source,
    )
    with pytest.raises(ValueError, match="unsupported GenAI"):
        import_genai_telemetry(
            source, authority="lab", convention_version="invented-version"
        )
    with pytest.raises(ValueError, match="outside the selected"):
        import_genai_telemetry(source, authority="lab", convention_version="1.37.0")
    with pytest.raises(ValueError, match="stability"):
        import_genai_telemetry(
            source, authority="lab", convention_version="1.37.0", stability="stable"
        )


def test_harbor_preserves_every_attempt_and_typed_failure(tmp_path: Path) -> None:
    common = {
        "task_name": "python-task",
        "task_checksum": "a" * 64,
        "config": {"task": "pinned"},
        "agent_info": {"name": "agent", "version": "1"},
        "finished_at": "2026-09-07T00:00:00Z",
    }
    trials = [
        {
            **copy.deepcopy(common),
            "id": str(i),
            "trial_name": f"attempt-{i}",
            "verifier_result": {"rewards": {"reward": int(i == 0)}},
        }
        for i in range(4)
    ]
    trials[2]["exception_info"] = {"exception_type": "TimeoutError"}
    trials[3]["finished_at"] = None
    source = tmp_path / "trials.json"
    publish_json(trials, source)
    result = normalize_native_benchmark(
        source,
        suite_id="terminal-bench-2",
        suite_revision="2.0-pinned",
        authority="lab",
    )
    assert [c["outcome"] for c in result["cases"]] == [
        "success",
        "failure",
        "error",
        "incomplete",
    ]
    assert len(result["cases"]) == 4
    trials[0]["verifier_result"]["rewards"]["reward"] = 0.5
    publish_json(trials, source)
    with pytest.raises(ValueError, match="numeric zero or one"):
        normalize_native_benchmark(
            source,
            suite_id="terminal-bench-2",
            suite_revision="2.0-pinned",
            authority="lab",
        )


def test_qualification_scope_requires_closed_approved_applicability() -> None:
    standard = standards_catalog()["profiles"][0]["id"]
    suite = "testgeneval"
    policy = {"minimum_benchmark_suites": 2}
    portfolio = {
        "product": {"intended_use": "test generation"},
        "policy": policy,
        "benchmark_suites": [
            {"id": suite, "version": "abc", "source_sha256": "a" * 64}
        ],
    }
    scope = {
        "intended_use": "test generation",
        "owner": "owner",
        "reviewer": "reviewer",
        "approval_authority": "board",
        "approval_ref": "evidence://approval",
        "approved_at": "2026-09-01T00:00:00Z",
        "next_review_at": "2026-10-01T00:00:00Z",
        "required_standards": [standard],
        "required_suites": [suite],
        "standard_exclusions": {
            p["id"]: "outside approved intended use"
            for p in standards_catalog()["profiles"]
            if p["id"] != standard
        },
        "suite_exclusions": {
            s["id"]: "outside approved task population"
            for s in benchmark_suite_catalog()["suites"]
            if s["id"] != suite
        },
        "acceptance_policy": policy,
        "change_triggers": [
            "product",
            "model",
            "dataset",
            "standard",
            "adapter",
            "policy",
        ],
    }
    lifecycle = {
        "reviews": [
            {
                "profile_id": standard,
                "disposition": "current",
                "reviewer": "reviewer",
                "source_evidence_ref": "evidence://standard",
                "observed_at": scope["approved_at"],
                "next_review_at": scope["next_review_at"],
            }
        ]
    }
    entry = {
        "suite_id": suite,
        "adapter_mode": "native-json",
        "status": "verified",
        "canonical_url": "https://example.org",
        "observed_url": "https://example.org",
        "observed_revision": "abc",
        "observed_at": scope["approved_at"],
        "next_review_at": scope["next_review_at"],
        "license_id": "MIT",
        "license_evidence_ref": "license",
        "snapshot_sha256": "a" * 64,
        "schema_version": "1",
        "source_evidence_ref": "source",
        "reviewer": "reviewer",
    }
    health = {"authority": "custodian", "sources": [entry]}
    assert all(
        scoped_checks(
            scope, portfolio, lifecycle, health, "2026-09-07T00:00:00Z"
        ).values()
    )
    for field, replacement in (
        ("observed_revision", "other"),
        ("snapshot_sha256", "b" * 64),
    ):
        original = entry[field]
        entry[field] = replacement
        assert not scoped_checks(
            scope, portfolio, lifecycle, health, "2026-09-07T00:00:00Z"
        )["benchmark_sources_pinned"]
        entry[field] = original
    with pytest.raises(ValueError, match="currently approved"):
        scoped_checks(scope, portfolio, lifecycle, health, "2026-11-01T00:00:00Z")
    scope["suite_exclusions"].pop(next(iter(scope["suite_exclusions"])))
    with pytest.raises(ValueError, match="account for every"):
        scoped_checks(scope, portfolio, lifecycle, health, "2026-09-07T00:00:00Z")
