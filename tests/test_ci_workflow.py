"""Contracts for CI evidence publication and mutation isolation."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    assert "path: .ci-report/*" in body
    assert "include-hidden-files: true" in body
    assert "if-no-files-found: error" in body


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
    }

    for function in expected_functions:
        assert f"{function}*" in workflow
    assert '"mutmut>=3.7,<4"' in (ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    )
