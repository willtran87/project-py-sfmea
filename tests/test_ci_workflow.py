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
