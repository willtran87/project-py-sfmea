"""Contracts for CI evidence publication and mutation isolation."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPLOAD_ARTIFACT_V7_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
SCORECARD_ACTION_SHA = "2d1146689b8cda280b9bc96326124645441f03bc"


def test_artifact_uploads_use_the_node24_release_with_an_immutable_pin() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    uploads = re.findall(r"actions/upload-artifact@([^\s]+)", workflow)

    assert uploads
    assert set(uploads) == {UPLOAD_ARTIFACT_V7_SHA}
    assert workflow.count("# v7.0.1") == len(uploads)


def test_hidden_browser_evidence_is_explicitly_uploaded() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    upload = re.search(
        r"name: Publish browser quality evidence(?P<body>.*?)(?:\n  \S|\Z)",
        workflow,
        flags=re.DOTALL,
    )
    assert upload is not None
    body = upload.group("body")
    assert ".ci-report/*" in body
    assert ".ci-scale-report/*" in body
    assert "include-hidden-files: true" in body
    assert "if-no-files-found: error" in body


def test_openssf_scorecard_is_pinned_least_privilege_and_publishes_sarif() -> None:
    workflow = (ROOT / ".github" / "workflows" / "scorecard.yml").read_text(
        encoding="utf-8"
    )

    assert "permissions: read-all" in workflow
    assert "security-events: write" in workflow
    assert "id-token: write" in workflow
    assert f"ossf/scorecard-action@{SCORECARD_ACTION_SHA}" in workflow
    assert "publish_results: true" in workflow
    assert "persist-credentials: false" in workflow
    assert "results.sarif" in workflow
    assert f"actions/upload-artifact@{UPLOAD_ARTIFACT_V7_SHA}" in workflow


def test_mutation_sandbox_copies_the_complete_package() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)["tool"]["mutmut"]

    assert config["source_paths"] == ["src/pysfmea"]
    assert set(config["only_mutate"]) == {
        "src/pysfmea/assurance_planning.py",
        "src/pysfmea/fault_injection.py",
        "src/pysfmea/runtime.py",
        "src/pysfmea/sandbox_policy.py",
        "src/pysfmea/readiness.py",
        "src/pysfmea/scan_cache.py",
        "src/pysfmea/diagnostics.py",
        "src/pysfmea/llm_quality.py",
    }


def test_mutation_gate_targets_mutmut_3_mangled_names() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    expected_functions = {
        "x_assert_fault_injection_result__mutmut_",
        "x__expected_outcomes__mutmut_",
        "x_verify_fault_injection_plan__mutmut_",
        "x__span_timing__mutmut_",
        "x__component_from_span__mutmut_",
        "x_sandbox_command__mutmut_",
        "x__runtime_corroboration__mutmut_",
        "x_project_llm_quality_corpus__mutmut_",
    }

    for function in expected_functions:
        assert f"{function}*" in workflow
    assert '"mutmut>=3.7,<4"' in (ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "timeout --signal=TERM 30m mutmut run" in workflow


def test_temporary_repository_fixtures_use_canonical_roots() -> None:
    noncanonical_assignment = re.compile(
        r"self\.root\s*=\s*Path\(self\.(?:temp|temporary)\.name\)(?!\.resolve\(\))"
    )

    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "tests").glob("test_*.py"))
        if noncanonical_assignment.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
