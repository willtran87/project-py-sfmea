from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator

import pysfmea.campaign_runner as campaign_runner
from pysfmea.benchmark_adapter import (
    benchmark_adapter_template,
    verify_benchmark_adapter,
)
from pysfmea.benchmark_observations import (
    benchmark_observations,
    verify_benchmark_observations,
)
from pysfmea.campaign_runner import (
    repository_snapshot_sha256,
    run_benchmark_campaign,
    run_fuzz_campaign,
)
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
from pysfmea.oscal_lifecycle import (
    OSCAL_ASSESSMENT_PLAN_SCHEMA,
    OSCAL_POAM_SCHEMA,
    oscal_assessment_plan,
    oscal_poam,
    verify_oscal_assessment_plan,
    verify_oscal_poam,
)
from pysfmea.sarif_ingestion import sarif_fusion, verify_sarif_fusion
from pysfmea.schemas import schema_document
from pysfmea.security_taxonomy import (
    import_security_taxonomy,
    verify_security_taxonomy,
)
from pysfmea.sigstore_verification import (
    execute_sigstore_verification,
    sigstore_verification_receipt,
    verify_sigstore_verification,
    verify_sigstore_verification_file,
)
from pysfmea.standards_lifecycle import (
    standards_lifecycle_template,
    verify_standards_lifecycle,
)


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


def _attempt(**overrides) -> dict:
    value = {
        "passed": True,
        "resolved": True,
        "coverage_delta": 0.2,
        "mutation_score": 0.75,
        "flaky": False,
        "unsafe_oracle": False,
        "latency_ms": 1250.0,
        "input_tokens": 100,
        "output_tokens": 50,
        "cost_usd": 0.01,
        "error": None,
        "output_sha256": "4" * 64,
        "test_artifact_sha256": "5" * 64,
        "environment_sha256": "6" * 64,
        "output_evidence_ref": "sha256:" + "4" * 64 + ":output.json",
        "test_artifact_evidence_ref": "sha256:" + "5" * 64 + ":test.py",
        "environment_evidence_ref": "sha256:" + "6" * 64 + ":environment.json",
        "execution_evidence_ref": "sha256:" + "7" * 64 + ":execution.json",
        "coverage_evidence_ref": "sha256:" + "8" * 64 + ":coverage.json",
        "mutation_evidence_ref": "sha256:" + "9" * 64 + ":mutation.json",
    }
    value.update(overrides)
    return value


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
                                            "region": {
                                                "startLine": 5,
                                                "startColumn": 1,
                                            },
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


def test_sarif_fusion_is_lossless_exact_bound_and_tamper_evident(
    tmp_path: Path,
) -> None:
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
    assert (
        verify_sarif_fusion(value, analysis=analysis, sarif_sources=[first, second])[
            "valid"
        ]
        is True
    )
    Draft202012Validator(schema_document("sarif-fusion")).validate(value)

    tampered = copy.deepcopy(value)
    tampered["summary"]["mapped"] = 1
    tampered = seal(
        {key: val for key, val in tampered.items() if key != "content_sha256"}
    )
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


def test_oscal_plan_and_poam_close_the_assessment_lifecycle() -> None:
    analysis = _analysis()
    plan = oscal_assessment_plan(
        analysis,
        authority="assurance-board",
        ssp_href="ssp.oscal.json",
        generated_at="2026-08-29T00:00:00+00:00",
    )
    assert plan["$schema"] == OSCAL_ASSESSMENT_PLAN_SCHEMA
    assert len(plan["assessment-plan"]["tasks"]) == 1
    assert verify_oscal_assessment_plan(plan, analysis=analysis)["valid"] is True
    Draft202012Validator(schema_document("oscal-assessment-plan")).validate(plan)

    poam = oscal_poam(
        analysis,
        authority="assurance-board",
        ssp_href="ssp.oscal.json",
        generated_at="2026-08-29T00:00:00+00:00",
    )
    assert poam["$schema"] == OSCAL_POAM_SCHEMA
    root = poam["plan-of-action-and-milestones"]
    assert (
        len(root["observations"]) == len(root["risks"]) == len(root["poam-items"]) == 1
    )
    assert root["poam-items"][0]["props"][0]["value"] == "FM-1"
    assert verify_oscal_poam(poam, analysis=analysis)["valid"] is True
    Draft202012Validator(schema_document("oscal-poam")).validate(poam)

    drifted = copy.deepcopy(analysis)
    drifted["findings"][0]["effect"] = "different"
    assert verify_oscal_assessment_plan(plan, analysis=drifted)["valid"] is False
    assert verify_oscal_poam(poam, analysis=drifted)["valid"] is False


def test_benchmark_registry_and_execution_contract_fail_closed() -> None:
    catalog = benchmark_suite_catalog()
    assert len(catalog["suites"]) == len(BENCHMARK_SUITES) == 41
    Draft202012Validator(schema_document("industry-benchmark-catalog")).validate(
        catalog
    )
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
    value["adapter"].update(
        {
            "manifest_sha256": "a" * 64,
            "evidence_ref": "sha256:" + "a" * 64 + ":adapter.json",
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
    assert (
        verify_benchmark_execution(value)["eligible_for_benchmark_assessment"] is True
    )
    Draft202012Validator(schema_document("benchmark-execution")).validate(value)


def test_case_level_benchmark_metrics_are_recomputed_and_tamper_evident() -> None:
    attempt = _attempt()
    cases = [
        {
            "id": "case-positive",
            "repository_id": "repo-1",
            "input_sha256": "a" * 64,
            "input_evidence_ref": "sha256:" + "a" * 64 + ":input.json",
            "ground_truth_sha256": "b" * 64,
            "ground_truth_evidence_ref": "sha256:" + "b" * 64 + ":ground-truth.json",
            "expected_label": "positive",
            "predicted_label": "positive",
            "attempts": [attempt, {**attempt, "flaky": True, "passed": False}],
        },
        {
            "id": "case-negative",
            "repository_id": "repo-2",
            "input_sha256": "c" * 64,
            "input_evidence_ref": "sha256:" + "c" * 64 + ":input.json",
            "ground_truth_sha256": "d" * 64,
            "ground_truth_evidence_ref": "sha256:" + "d" * 64 + ":ground-truth.json",
            "expected_label": "negative",
            "predicted_label": "positive",
            "attempts": [{**attempt, "resolved": None}, {**attempt, "resolved": None}],
        },
    ]
    value = benchmark_observations(
        suite_id="realvuln-python",
        suite_revision="v2.0.0",
        suite_sha256="1" * 64,
        runner_image="runner@sha256:" + "2" * 64,
        runner_command=["python", "run.py"],
        cases=cases,
        repetitions=2,
        authority="independent-lab",
        model={
            "provider": "provider",
            "name": "model",
            "version": "1",
            "prompt_sha256": "3" * 64,
            "temperature": 0.2,
            "seed": 7,
        },
        generated_at="2026-08-29T00:00:00+00:00",
    )
    assert value["summary"]["pass_at_1"] == 1.0
    assert value["summary"]["classification"]["precision"] == 0.5
    assert value["summary"]["flaky_attempt_rate"] == 0.25
    assert verify_benchmark_observations(value)["valid"] is True
    Draft202012Validator(schema_document("benchmark-observations")).validate(value)

    tampered = copy.deepcopy(value)
    tampered["summary"]["pass_at_1"] = 0.0
    tampered = seal(
        {key: val for key, val in tampered.items() if key != "content_sha256"}
    )
    assert verify_benchmark_observations(tampered)["valid"] is False


def test_campaign_snapshot_binds_names_and_bytes(tmp_path: Path) -> None:
    source = tmp_path / "suite"
    source.mkdir()
    (source / "a.py").write_text("print('a')\n", encoding="utf-8")
    first = repository_snapshot_sha256(source)
    assert first == repository_snapshot_sha256(source)
    (source / "a.py").write_text("print('b')\n", encoding="utf-8")
    assert repository_snapshot_sha256(source) != first


def test_benchmark_runner_reconciles_exact_container_observations(
    tmp_path: Path, monkeypatch
) -> None:
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "case.py").write_text("CASE = 1\n", encoding="utf-8")
    snapshot = repository_snapshot_sha256(suite)
    receipt = benchmark_execution_template(
        suite_id="realvuln-python", authority="owner"
    )
    receipt["suite"].update(
        {
            "revision": "v2.0.0",
            "snapshot_sha256": snapshot,
            "license_evidence_ref": "evidence://licenses/realvuln",
        }
    )
    receipt["authority"].update(
        {
            "execution_operator": "operator",
            "label_authority": "labeler",
            "approval_authority": "approver",
            "independence_basis": "Separate execution, labeling, and approval roles.",
        }
    )
    receipt["execution"].update(
        {
            "image": "runner@sha256:" + "2" * 64,
            "command": ["python", "run.py"],
            "timeout_seconds": 900,
            "cpu_limit": 2.0,
            "memory_mb": 2048,
        }
    )
    adapter = benchmark_adapter_template(
        suite_id="realvuln-python", authority="adapter-owner"
    )
    adapter["suite"].update({name: receipt["suite"][name] for name in adapter["suite"]})
    adapter["adapter"].update(
        {
            "version": "1.0.0",
            "source_sha256": "3" * 64,
            "source_evidence_ref": "evidence://adapter/source/realvuln",
            "image": receipt["execution"]["image"],
            "command": receipt["execution"]["command"],
        }
    )
    adapter["normalization"].update(
        {
            "case_identity_policy": "upstream immutable case identifier",
            "label_policy": "reviewed upstream ground truth",
            "exclusion_policy": "predeclared unsupported cases only",
            "metric_mappings": [
                "passed",
                "resolved",
                "coverage_delta",
                "mutation_score",
            ],
        }
    )
    adapter["authority"].update(
        {
            "independent_reviewer": "adapter-reviewer",
            "review_evidence_ref": "evidence://adapter/review-1",
        }
    )
    adapter = seal(
        {key: value for key, value in adapter.items() if key != "content_sha256"}
    )
    adapter_verdict = verify_benchmark_adapter(adapter)
    assert adapter_verdict["eligible_for_execution"] is True, adapter_verdict
    adapter_path = tmp_path / "adapter.json"
    adapter_path.write_text(json.dumps(adapter), encoding="utf-8")
    receipt["adapter"].update(
        {
            "manifest_sha256": adapter["content_sha256"],
            "evidence_ref": "sha256:"
            + hashlib.sha256(adapter_path.read_bytes()).hexdigest()
            + ":adapter.json",
        }
    )
    receipt = seal(
        {key: value for key, value in receipt.items() if key != "content_sha256"}
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    def fake_run_container(**kwargs):
        artifacts = {
            "input.json": b'{"task": "case-1"}\n',
            "ground-truth.json": b'{"label": "positive"}\n',
            "output.json": b'{"prediction": "positive"}\n',
            "test.py": b"def test_case(): assert True\n",
            "environment.json": b'{"python": "3.13"}\n',
            "execution.json": b'{"exit_code": 0}\n',
            "coverage.json": b'{"delta": 0.1}\n',
            "mutation.json": b'{"score": 0.8}\n',
        }
        for name, raw in artifacts.items():
            (kwargs["evidence"] / name).write_bytes(raw)

        def digest(name: str) -> str:
            return hashlib.sha256(artifacts[name]).hexdigest()

        def reference(name: str) -> str:
            return f"sha256:{digest(name)}:{name}"

        attempt = _attempt(
            coverage_delta=0.1,
            mutation_score=0.8,
            latency_ms=10.0,
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            output_sha256=digest("output.json"),
            test_artifact_sha256=digest("test.py"),
            environment_sha256=digest("environment.json"),
            output_evidence_ref=reference("output.json"),
            test_artifact_evidence_ref=reference("test.py"),
            environment_evidence_ref=reference("environment.json"),
            execution_evidence_ref=reference("execution.json"),
            coverage_evidence_ref=reference("coverage.json"),
            mutation_evidence_ref=reference("mutation.json"),
        )
        observations = benchmark_observations(
            suite_id="realvuln-python",
            suite_revision="v2.0.0",
            suite_sha256=snapshot,
            runner_image="runner@sha256:" + "2" * 64,
            runner_command=["python", "run.py"],
            cases=[
                {
                    "id": "case-1",
                    "repository_id": "repo-1",
                    "input_sha256": digest("input.json"),
                    "input_evidence_ref": reference("input.json"),
                    "ground_truth_sha256": digest("ground-truth.json"),
                    "ground_truth_evidence_ref": reference("ground-truth.json"),
                    "expected_label": "positive",
                    "predicted_label": "positive",
                    "attempts": [attempt],
                }
            ],
            repetitions=1,
            authority="labeler",
        )
        (kwargs["evidence"] / "benchmark-observations.json").write_text(
            json.dumps(observations), encoding="utf-8"
        )
        return 0, "ok", "", "2026-08-29T00:00:00Z", "2026-08-29T00:01:00Z", "docker"

    monkeypatch.setattr(campaign_runner, "_run_container", fake_run_container)
    destination = run_benchmark_campaign(
        receipt_path,
        suite,
        adapter_path,
        tmp_path / "benchmark-evidence",
        tmp_path / "completed.json",
    )
    completed = json.loads(destination.read_text(encoding="utf-8"))
    assert (
        verify_benchmark_execution(completed)["eligible_for_benchmark_assessment"]
        is True
    )
    assert completed["outcome"]["metrics"]["pass_at_k"] == 1.0


def test_fuzz_runner_emits_a_governed_eligible_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "target.py").write_text("def fuzz(data): pass\n", encoding="utf-8")
    snapshot = repository_snapshot_sha256(repository)
    campaign = fuzz_campaign_template(authority="owner")
    campaign["authority"].update(
        {
            "execution_operator": "operator",
            "triage_authority": "triager",
            "approval_authority": "approver",
            "independence_basis": "Separate execution, triage, and approval roles.",
        }
    )
    campaign["target"].update(
        {
            "repository_revision": "commit-abc",
            "repository_sha256": snapshot,
            "component_ids": ["target.fuzz"],
            "entrypoint": "target.py:fuzz",
        }
    )
    campaign["engine"].update(
        {
            "version": "2.3.0",
            "image": "atheris@sha256:" + "2" * 64,
            "command": ["python", "target.py"],
            "configuration_sha256": "3" * 64,
        }
    )
    campaign["isolation"].update(
        {"cpu_limit": 2.0, "memory_mb": 2048, "timeout_seconds": 900}
    )
    campaign["corpus"].update({"initial_sha256": "4" * 64, "initial_inputs": 10})
    campaign = seal(
        {key: value for key, value in campaign.items() if key != "content_sha256"}
    )
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")

    def fake_run_container(**kwargs):
        artifacts = {
            "coverage.json": b'{"covered": [1, 2]}\n',
            "crash.bin": b"crashing-input",
            "stack.txt": b"target.py:1 fuzz\n",
            "reproducer.py": b"def test_reproducer(): assert True\n",
        }
        for name, raw in artifacts.items():
            (kwargs["evidence"] / name).write_bytes(raw)
        result = {
            "executions": 100_000,
            "execs_per_second": 250.0,
            "coverage_observation": {
                "path": "coverage.json",
                "sha256": hashlib.sha256(artifacts["coverage.json"]).hexdigest(),
                "bytes": len(artifacts["coverage.json"]),
            },
            "corpus": {
                "initial_sha256": "4" * 64,
                "final_sha256": "5" * 64,
                "initial_inputs": 10,
                "final_inputs": 20,
            },
            "crashes": [
                {
                    "id": "crash-1",
                    "input_sha256": hashlib.sha256(artifacts["crash.bin"]).hexdigest(),
                    "input_path": "crash.bin",
                    "input_bytes": len(artifacts["crash.bin"]),
                    "stack_sha256": hashlib.sha256(artifacts["stack.txt"]).hexdigest(),
                    "stack_path": "stack.txt",
                    "stack_bytes": len(artifacts["stack.txt"]),
                    "reproducer_sha256": hashlib.sha256(
                        artifacts["reproducer.py"]
                    ).hexdigest(),
                    "reproducer_path": "reproducer.py",
                    "reproducer_bytes": len(artifacts["reproducer.py"]),
                    "reproduced": True,
                    "disposition": "fixed",
                    "finding_ref": "FM-1",
                    "fixed_in_revision": "commit-def",
                }
            ],
        }
        (kwargs["evidence"] / "fuzz-result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )
        return 0, "ok", "", "2026-08-29T00:00:00Z", "2026-08-29T00:01:00Z", "docker"

    monkeypatch.setattr(campaign_runner, "_run_container", fake_run_container)
    destination = run_fuzz_campaign(
        campaign_path,
        repository,
        tmp_path / "fuzz-evidence",
        tmp_path / "completed-fuzz.json",
    )
    completed = json.loads(destination.read_text(encoding="utf-8"))
    assert verify_fuzz_campaign(completed)["eligible_for_assurance_use"] is True
    assert completed["execution"]["executions"] == 100_000
    assert (
        completed["execution"]["coverage_observation"]["sha256"]
        == hashlib.sha256(b'{"covered": [1, 2]}\n').hexdigest()
    )
    assert completed["crashes"][0]["disposition"] == "fixed"


def test_sigstore_receipt_binds_exact_artifact_bundle_and_identity(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "analysis.json"
    bundle = tmp_path / "analysis.sigstore.json"
    trusted_root = tmp_path / "trusted-root.json"
    artifact.write_text('{"format":"fixture"}\n', encoding="utf-8")
    bundle.write_text('{"verificationMaterial":{}}\n', encoding="utf-8")
    trusted_root.write_text(
        '{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}\n',
        encoding="utf-8",
    )
    value = sigstore_verification_receipt(
        artifact,
        bundle,
        trusted_root,
        certificate_identity="https://github.com/example/project/.github/workflows/release.yml@refs/heads/main",
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
        authority="release-board",
        cosign_version="v2.5.0",
        exit_code=0,
        stdout="Verified OK",
        stderr="",
        observed_at="2026-08-29T00:00:00+00:00",
    )
    verdict = verify_sigstore_verification(
        value, artifact=artifact, bundle=bundle, trusted_root=trusted_root
    )
    assert verdict["valid"] is True
    assert verdict["authenticated"] is True
    Draft202012Validator(schema_document("sigstore-verification")).validate(value)

    artifact.write_text('{"format":"changed"}\n', encoding="utf-8")
    assert verify_sigstore_verification(value, artifact=artifact)["valid"] is False


def test_sigstore_execution_uses_current_bundle_and_trusted_root_interface(
    tmp_path: Path, monkeypatch
) -> None:
    artifact = tmp_path / "analysis.json"
    bundle = tmp_path / "analysis.sigstore.json"
    trusted_root = tmp_path / "trusted-root.json"
    artifact.write_text('{"format":"fixture"}\n', encoding="utf-8")
    bundle.write_text('{"verificationMaterial":{}}\n', encoding="utf-8")
    trusted_root.write_text('{"trustedRoot":{}}\n', encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs):
        commands.append(command)
        if command[1:] == ["version", "--json"]:
            return subprocess.CompletedProcess(
                command, 0, stdout='{"gitVersion":"v3.0.2"}', stderr=""
            )
        return subprocess.CompletedProcess(command, 0, stdout="Verified OK", stderr="")

    monkeypatch.setattr(
        "pysfmea.sigstore_verification.shutil.which", lambda _name: "cosign"
    )
    monkeypatch.setattr("pysfmea.sigstore_verification.subprocess.run", fake_run)
    destination = execute_sigstore_verification(
        artifact,
        bundle,
        trusted_root,
        certificate_identity="https://github.com/example/project/.github/workflows/release.yml@refs/heads/main",
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
        authority="release-board",
        destination=tmp_path / "sigstore-receipt.json",
    )
    verify_command = commands[1]
    assert verify_command[1] == "verify-blob"
    assert "--offline" not in verify_command
    assert verify_command[verify_command.index("--trusted-root") + 1] == str(
        trusted_root.resolve()
    )
    verdict = verify_sigstore_verification_file(
        destination,
        artifact=artifact,
        bundle=bundle,
        trusted_root=trusted_root,
    )
    assert verdict["authenticated"] is True


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
            "coverage_observation": {
                "ref": "sha256:" + "6" * 64 + ":coverage.json",
                "sha256": "6" * 64,
                "bytes": 128,
            },
        }
    )
    value["evidence_refs"] = ["evidence://fuzz/run-1"]
    value = seal({key: val for key, val in value.items() if key != "content_sha256"})
    assert verify_fuzz_campaign(value)["eligible_for_assurance_use"] is True
    Draft202012Validator(schema_document("fuzz-campaign")).validate(value)


def test_official_taxonomy_xml_is_versioned_normalized_and_exact_bound(
    tmp_path: Path,
) -> None:
    source = tmp_path / "cwe.xml"
    source.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="4.20" Date="2026-04-30">
  <Weaknesses>
    <Weakness ID="20" Name="Improper Input Validation" Abstraction="Class" Status="Stable">
      <Description>The product receives input but does not validate it.</Description>
      <Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="707" View_ID="1000" /></Related_Weaknesses>
    </Weakness>
    <Weakness ID="707" Name="Improper Neutralization" Abstraction="Pillar" Status="Deprecated">
      <Description>Neutralization weakness.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
""",
        encoding="utf-8",
    )
    artifact = import_security_taxonomy(
        source,
        authority="security-board",
        expected_kind="cwe",
        expected_version="4.20",
        generated_at="2026-08-29T00:00:00+00:00",
    )
    assert artifact["summary"] == {"entries": 2, "deprecated": 1, "relationships": 1}
    assert (
        verify_security_taxonomy(artifact, source=source)["eligible_for_mapping"]
        is True
    )
    Draft202012Validator(schema_document("security-taxonomy")).validate(artifact)
    source.write_text(
        source.read_text(encoding="utf-8").replace("Stable", "Draft"), encoding="utf-8"
    )
    assert verify_security_taxonomy(artifact, source=source)["valid"] is False


def test_capec_taxonomy_preserves_attack_pattern_and_cwe_relationships(
    tmp_path: Path,
) -> None:
    source = tmp_path / "capec.xml"
    source.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.9" Date="2024-11-21">
  <Attack_Patterns>
    <Attack_Pattern ID="100" Name="Overflow Buffers" Abstraction="Standard" Status="Stable">
      <Description>Attack input exceeds a buffer boundary.</Description>
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="10" /></Related_Attack_Patterns>
      <Related_Weaknesses><Related_Weakness CWE_ID="120" /></Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
""",
        encoding="utf-8",
    )
    artifact = import_security_taxonomy(
        source,
        authority="security-board",
        expected_kind="capec",
        expected_version="3.9",
        generated_at="2026-08-29T00:00:00+00:00",
    )
    assert artifact["entries"][0]["relationships"] == [
        {
            "target_kind": "capec",
            "nature": "childof",
            "target_id": "10",
            "view_id": "",
        },
        {
            "target_kind": "cwe",
            "nature": "related",
            "target_id": "120",
            "view_id": "",
        },
    ]
    assert (
        verify_security_taxonomy(artifact, source=source)["eligible_for_mapping"]
        is True
    )


def test_standards_lifecycle_binds_catalog_and_fails_closed_on_review_debt() -> None:
    value = standards_lifecycle_template(
        authority="quality-board", generated_at="2026-08-29T00:00:00+00:00"
    )
    initial = verify_standards_lifecycle(value)
    assert initial["valid"] is True
    assert initial["eligible_as_current_catalog_evidence"] is False
    for review in value["reviews"]:
        review.update(
            {
                "observed_edition": review["catalog_edition"],
                "observed_status": review["catalog_status"],
                "disposition": "current",
                "observed_at": "2026-08-29T00:00:00+00:00",
                "next_review_at": "2027-02-28T00:00:00+00:00",
                "source_evidence_ref": f"evidence://publisher/{review['profile_id']}",
                "reviewer": "standards-librarian",
            }
        )
    value["summary"] = {
        "profiles": len(value["reviews"]),
        "complete_reviews": len(value["reviews"]),
        "overdue_reviews": 0,
        "changed_sources": 0,
        "by_disposition": {
            "current": len(value["reviews"]),
            "revised": 0,
            "superseded": 0,
            "unknown": 0,
            "unreviewed": 0,
            "withdrawn": 0,
        },
    }
    value = seal({key: item for key, item in value.items() if key != "content_sha256"})
    verdict = verify_standards_lifecycle(value)
    assert verdict["eligible_as_current_catalog_evidence"] is True
    Draft202012Validator(schema_document("standards-lifecycle")).validate(value)


def test_benchmark_adapter_requires_exact_provenance_and_independent_review() -> None:
    value = benchmark_adapter_template(suite_id="bugsinpy", authority="owner")
    assert verify_benchmark_adapter(value)["eligible_for_execution"] is False
    value["suite"].update(
        {
            "revision": "v1",
            "snapshot_sha256": "1" * 64,
            "license_evidence_ref": "evidence://license/bugsinpy",
        }
    )
    value["adapter"].update(
        {
            "version": "1.0.0",
            "source_sha256": "2" * 64,
            "source_evidence_ref": "evidence://adapter/source",
            "image": "adapter@sha256:" + "3" * 64,
            "command": ["python", "/adapter/run.py"],
        }
    )
    value["normalization"].update(
        {
            "case_identity_policy": "upstream immutable id",
            "label_policy": "reviewed upstream labels",
            "exclusion_policy": "predeclared only",
            "metric_mappings": ["passed", "resolved"],
        }
    )
    value["authority"].update(
        {
            "independent_reviewer": "reviewer",
            "review_evidence_ref": "evidence://adapter/review",
        }
    )
    value = seal({key: item for key, item in value.items() if key != "content_sha256"})
    assert verify_benchmark_adapter(value)["eligible_for_execution"] is True
    Draft202012Validator(schema_document("benchmark-adapter")).validate(value)


def test_missing_industry_profiles_are_governed_and_discoverable() -> None:
    catalog = standards_catalog()
    identifiers = {profile["id"] for profile in catalog["profiles"]}
    assert len(identifiers) == 144
    assert {
        "nist-sp-800-53-53a-r5",
        "nist-sp-800-160-v1r1",
        "nist-sp-800-161-r1",
        "nistir-8397",
        "owasp-samm-v2",
        "iso-iec-20246-2017",
        "iec-62443-3-3",
        "iec-62443-3-2-2020",
        "faa-do-331-model-based",
        "faa-do-332-object-oriented",
        "iso-15026-1-2025",
        "iso-15026-3-2023",
        "iso-15026-4-2021",
        "openchain-5230-18974",
        "sbom-iso-5962-ecma-424",
        "ieee-730-2026",
        "owasp-wstg-v42",
        "nist-sp-800-115",
        "nist-samate-scas-500-268-270",
        "iso-29119-3-2021",
        "iso-29119-4-2021",
        "iso-42119-2-2025",
        "osv-kev-epss-vulnerability-intelligence",
    } <= identifiers


def test_normative_json_schema_supports_unicode_property_patterns(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact.json"
    schema = tmp_path / "schema.json"
    artifact.write_text(json.dumps({"name": "München"}), encoding="utf-8")
    schema.write_text(
        json.dumps(
            {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string", "pattern": r"^\p{L}+$"}},
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
