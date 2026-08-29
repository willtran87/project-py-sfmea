"""Governed external benchmark registry and execution-evidence contract."""

from __future__ import annotations

import copy
import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import (
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_seal,
)
from .model import utc_now

BENCHMARK_CATALOG_FORMAT = "pysfmea-industry-benchmark-catalog-1"
BENCHMARK_EXECUTION_FORMAT = "pysfmea-benchmark-execution-1"
BENCHMARK_EXECUTION_VERIFICATION_FORMAT = "pysfmea-benchmark-execution-verification-1"

BENCHMARK_SUITES: tuple[dict[str, Any], ...] = (
    {"id": "owasp-benchmark-python", "title": "OWASP Benchmark for Python", "source_url": "https://github.com/OWASP-Benchmark/BenchmarkPython", "population": "synthetic Python security test cases with known labels", "measures": ["true_positive", "false_positive", "false_negative", "true_negative"], "use": "Security finding detection and false-positive characterization.", "limitation": "Synthetic security cases do not establish performance on operational repositories."},
    {"id": "bugsinpy", "title": "BugsInPy", "source_url": "https://github.com/soarsmu/BugsInPy", "population": "reproducible real Python defects", "measures": ["defects_detected", "defects_missed", "tests_passing"], "use": "Real-defect detection, localization, and regression-test evaluation.", "limitation": "Project and defect sampling does not represent every Python domain."},
    {"id": "testgeneval", "title": "TestGenEval", "source_url": "https://github.com/facebookresearch/testgeneval", "population": "repository-level Python test-generation tasks", "measures": ["test_pass_rate", "coverage_delta", "mutation_score"], "use": "Evaluate LLM-generated tests for executability, coverage, and fault sensitivity.", "limitation": "Benchmark success is not evidence that generated tests satisfy project safety requirements."},
    {"id": "tdd-bench-verified", "title": "TDD-Bench Verified", "source_url": "https://github.com/All-Hands-AI/TDD-Bench-Verified", "population": "verified issue-driven test-generation tasks", "measures": ["resolved", "fail_to_pass", "pass_to_pass"], "use": "Evaluate whether generated tests reproduce requested behavior without regressions.", "limitation": "Issue resolution is not a substitute for requirements-based verification."},
    {"id": "swe-bench-verified", "title": "SWE-bench Verified", "source_url": "https://www.swebench.com/", "population": "human-validated software engineering tasks", "measures": ["resolved", "fail_to_pass", "pass_to_pass"], "use": "Comparator baseline for repository-level repair and test workflows.", "limitation": "A general coding benchmark is indirect evidence for SFMEA accuracy."},
)


def benchmark_suite_catalog() -> dict[str, Any]:
    return seal({"format": BENCHMARK_CATALOG_FORMAT, "version": "1.0.0", "suites": copy.deepcopy(list(BENCHMARK_SUITES)), "notice": "Registry entries are evaluation targets, not bundled datasets or endorsements. Pin an exact lawful snapshot and preserve licenses, labels, provenance, exclusions, and independent review."})


def benchmark_execution_template(*, suite_id: str, authority: str) -> dict[str, Any]:
    if suite_id not in {item["id"] for item in BENCHMARK_SUITES}:
        raise ValueError("unknown governed benchmark suite")
    return seal({
        "format": BENCHMARK_EXECUTION_FORMAT,
        "generated_at": utc_now(),
        "suite": {"id": suite_id, "source_url": next(item["source_url"] for item in BENCHMARK_SUITES if item["id"] == suite_id), "revision": "unassigned", "snapshot_sha256": "0" * 64, "license_evidence_ref": "unassigned"},
        "authority": {"protocol_owner": bounded_text(authority, "benchmark authority"), "execution_operator": "unassigned", "label_authority": "unassigned", "approval_authority": "unassigned", "independence_basis": "unassigned"},
        "execution": {"runner": "oci", "image": "unassigned@sha256:" + "0" * 64, "command": [], "network": "none", "source_mount": "read_only", "started_at": "unassigned", "completed_at": "unassigned", "timeout_seconds": 0, "cpu_limit": 0.0, "memory_mb": 0, "exit_code": None},
        "outcome": {"status": "not_run", "cases_total": 0, "cases_completed": 0, "metrics": {}, "failures": [], "excluded_cases": []},
        "evidence_refs": [],
        "limitations": ["No benchmark claim is supported until an independently governed execution is complete."],
        "claim_boundary": "The receipt records an exact benchmark snapshot, isolated execution configuration, results, and authorities. It does not prove label correctness, population representativeness, tool qualification, or certification.",
    })


def _execution_semantics(value: dict[str, Any]) -> tuple[bool, bool]:
    try:
        suite = value["suite"]
        authority = value["authority"]
        execution = value["execution"]
        outcome = value["outcome"]
        structure = bool(
            set(value) == {"format", "generated_at", "suite", "authority", "execution", "outcome", "evidence_refs", "limitations", "claim_boundary", "content_sha256"}
            and set(suite) == {"id", "source_url", "revision", "snapshot_sha256", "license_evidence_ref"}
            and set(authority) == {"protocol_owner", "execution_operator", "label_authority", "approval_authority", "independence_basis"}
            and set(execution) == {"runner", "image", "command", "network", "source_mount", "started_at", "completed_at", "timeout_seconds", "cpu_limit", "memory_mb", "exit_code"}
            and set(outcome) == {"status", "cases_total", "cases_completed", "metrics", "failures", "excluded_cases"}
            and suite["id"] in {item["id"] for item in BENCHMARK_SUITES}
            and isinstance(execution["command"], list)
            and len(execution["command"]) <= 100
            and all(isinstance(item, str) and 0 < len(item) <= 20_000 for item in execution["command"])
            and execution["network"] == "none"
            and execution["source_mount"] == "read_only"
            and outcome["status"] in {"not_run", "completed", "failed", "aborted"}
            and isinstance(outcome["metrics"], dict)
            and all(
                isinstance(metric, (int, float))
                and not isinstance(metric, bool)
                and math.isfinite(float(metric))
                for metric in outcome["metrics"].values()
            )
            and isinstance(outcome["failures"], list)
            and isinstance(outcome["excluded_cases"], list)
            and all(
                isinstance(outcome[name], int)
                and not isinstance(outcome[name], bool)
                and outcome[name] >= 0
                for name in ("cases_total", "cases_completed")
            )
            and outcome["cases_completed"] <= outcome["cases_total"]
        )
        snapshot = suite["snapshot_sha256"]
        image = execution["image"]
        roles = [authority[name] for name in ("protocol_owner", "execution_operator", "label_authority", "approval_authority")]
        completed = bool(
            outcome["status"] == "completed"
            and re.fullmatch(r"[0-9a-f]{64}", snapshot or "") and snapshot != "0" * 64
            and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image or "") and not image.endswith("0" * 64)
            and execution["command"] and execution["exit_code"] == 0
            and isinstance(outcome["cases_total"], int) and outcome["cases_total"] > 0
            and outcome["cases_completed"] == outcome["cases_total"]
            and outcome["metrics"] and len(set(roles)) == len(roles)
            and authority["independence_basis"] != "unassigned"
            and suite["revision"] != "unassigned" and suite["license_evidence_ref"] != "unassigned"
            and bool(unique_text_list(value["evidence_refs"], "benchmark evidence refs"))
        )
        return structure, completed
    except (KeyError, TypeError, ValueError):
        return False, False


def seal_benchmark_execution_source(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="benchmark execution")
    value.pop("content_sha256", None)
    value = seal(value)
    structure, _ = _execution_semantics(value)
    if not structure:
        raise ValueError("benchmark execution source fields are invalid")
    return publish_json(value, destination)


def verify_benchmark_execution(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(value, label="benchmark execution", format_value=BENCHMARK_EXECUTION_FORMAT)
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure, eligible = _execution_semantics(checked)
    if not structure:
        errors.append("benchmark execution fields or isolation policy are invalid")
    if structure and not eligible:
        errors.append("benchmark execution is not complete and independently governed")
    valid = integrity and structure
    return seal({"format": BENCHMARK_EXECUTION_VERIFICATION_FORMAT, "valid": valid, "eligible_for_benchmark_assessment": bool(valid and eligible), "checks": {"content_integrity": integrity, "closed_structure_and_isolation": structure, "execution_and_governance_complete": eligible}, "errors": errors, "notice": "Eligibility means the evidence contract is complete; statistical validity and external label correctness require separate assessment."})


def verify_benchmark_execution_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_benchmark_execution(load_json(source, label="benchmark execution"))
    except (OSError, TypeError, ValueError) as exc:
        return seal({"format": BENCHMARK_EXECUTION_VERIFICATION_FORMAT, "valid": False, "eligible_for_benchmark_assessment": False, "checks": {"content_integrity": False, "closed_structure_and_isolation": False, "execution_and_governance_complete": False}, "errors": [str(exc)], "notice": "Benchmark execution verification failed closed."})


def export_benchmark_catalog(destination: str | Path) -> Path:
    return publish_json(benchmark_suite_catalog(), destination)


def export_benchmark_execution(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_benchmark_execution(value)["valid"]:
        raise ValueError("benchmark execution source is internally invalid")
    return publish_json(value, destination)
