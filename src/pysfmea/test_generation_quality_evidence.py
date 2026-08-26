"""Exact artifact reconciliation for generated-test qualification."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from .assurance import ensure_assurance_register
from .execution import verify_execution_artifacts
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document

TEST_GENERATION_FAULT_EVIDENCE_FORMAT = (
    "pysfmea-test-generation-fault-detection-evidence-1"
)
MAX_QUALITY_EVIDENCE_TEXT = 20_000
_ARTIFACT_REFERENCE_FIELDS = {"path", "sha256"}
_FAULT_EVIDENCE_FIELDS = {
    "format",
    "sample_id",
    "test_sha256",
    "environment",
    "baseline",
    "seeded",
    "content_sha256",
}
_FAULT_RUN_FIELDS = {"execution_id", "status", "evidence_sha256"}
_SEEDED_RUN_FIELDS = {*_FAULT_RUN_FIELDS, "fault_id"}


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > MAX_QUALITY_EVIDENCE_TEXT
    ):
        raise ValueError(f"{label} must be bounded non-empty text")
    return value.strip()


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def load_quality_artifact_document(
    evidence_root: str | Path,
    reference: Any,
    *,
    label: str,
    max_bytes: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one root-confined, content-addressed qualification JSON artifact."""

    if not isinstance(reference, dict) or set(reference) != _ARTIFACT_REFERENCE_FIELDS:
        raise ValueError(f"{label} reference must match the closed contract")
    relative = Path(_text(reference.get("path"), f"{label} path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path must be a safe relative path")
    declared = _digest(reference.get("sha256"), f"{label} sha256")
    root = Path(evidence_root).expanduser().absolute().resolve()
    candidate = root / relative
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} path escapes the evidence root")
    document = load_bounded_json_document(
        candidate,
        label=label,
        max_bytes=max_bytes,
        max_depth=100,
        max_nodes=2_000_000,
    )
    actual = hashlib.sha256(document.raw).hexdigest()
    if actual != declared:
        raise ValueError(f"{label} bytes do not match the declared SHA-256")
    if not isinstance(document.value, dict):
        raise ValueError(f"{label} root must be an object")
    return document.value, {
        "path": relative.as_posix(),
        "sha256": actual,
        "bytes": len(document.raw),
    }


def unsafe_generation_attempted(proposal: dict[str, Any]) -> bool:
    """Return whether retained validator feedback records an unsafe change attempt."""

    safety_markers = (
        "allowlist",
        "network or shell",
        "dynamic or shell",
        "escapes",
        "unsafe",
        "overwrite",
    )
    records = proposal.get("generation", {}).get("attempt_records", [])
    return any(
        isinstance(record, dict)
        and any(
            marker in str(record.get("validation_error", "")).casefold()
            for marker in safety_markers
        )
        for record in records
    )


def _execution(analysis: dict[str, Any], execution_id: str) -> dict[str, Any]:
    register = ensure_assurance_register(analysis)
    execution = next(
        (
            value
            for value in register.get("executions", [])
            if isinstance(value, dict) and value.get("id") == execution_id
        ),
        None,
    )
    if execution is None:
        raise ValueError(f"fault-detection execution is unavailable: {execution_id}")
    return execution


def _verified_execution(
    analysis: dict[str, Any],
    run: dict[str, Any],
    *,
    expected_status: str,
    test_sha256: str,
    label: str,
    evidence_root: str | Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    execution_id = _text(run.get("execution_id"), f"fault-detection {label} execution id")
    declared_status = run.get("status")
    if declared_status != expected_status:
        raise ValueError(f"fault-detection {label} must declare status {expected_status}")
    declared_manifest = _digest(
        run.get("evidence_sha256"), f"fault-detection {label} evidence"
    )
    execution = _execution(analysis, execution_id)
    if execution.get("status") != declared_status:
        raise ValueError(f"fault-detection {label} status does not match the execution")
    if execution.get("test", {}).get("sha256") != test_sha256:
        raise ValueError(f"fault-detection {label} test does not match the generated test")
    verification = verify_execution_artifacts(
        analysis, execution_id, evidence_root=evidence_root
    )
    if not verification["valid"]:
        raise ValueError(
            f"fault-detection {label} raw execution evidence is invalid: "
            + "; ".join(str(value) for value in verification["errors"])
        )
    if verification["manifest_sha256"] != declared_manifest:
        raise ValueError(
            f"fault-detection {label} manifest does not match the declared evidence"
        )
    return execution, verification


def verify_fault_detection_evidence(
    value: dict[str, Any],
    analysis: dict[str, Any],
    *,
    sample_id: str,
    test_sha256: str,
    evidence_root: str | Path,
) -> dict[str, Any]:
    """Reconcile a fault claim to two exact manifests and their raw artifacts."""

    if set(value) != _FAULT_EVIDENCE_FIELDS:
        raise ValueError("fault-detection evidence must match the closed root contract")
    unsigned = copy.deepcopy(value)
    declared = unsigned.pop("content_sha256", "")
    if declared != canonical_json_sha256(unsigned):
        raise ValueError("fault-detection evidence content digest does not match")
    if (
        value.get("format") != TEST_GENERATION_FAULT_EVIDENCE_FORMAT
        or value.get("sample_id") != sample_id
        or value.get("test_sha256") != test_sha256
    ):
        raise ValueError("fault-detection evidence identity does not match the sample")
    _text(value.get("environment"), "fault-detection environment")
    baseline = value.get("baseline")
    seeded = value.get("seeded")
    if not isinstance(baseline, dict) or set(baseline) != _FAULT_RUN_FIELDS:
        raise ValueError("fault-detection baseline must match the closed contract")
    if not isinstance(seeded, dict) or set(seeded) != _SEEDED_RUN_FIELDS:
        raise ValueError("fault-detection seeded run must match the closed contract")
    _text(seeded.get("fault_id"), "fault-detection fault id")
    if baseline.get("execution_id") == seeded.get("execution_id"):
        raise ValueError("fault-detection baseline and seeded executions must be distinct")
    baseline_execution, baseline_verification = _verified_execution(
        analysis,
        baseline,
        expected_status="passed",
        test_sha256=test_sha256,
        label="baseline",
        evidence_root=evidence_root,
    )
    seeded_execution, seeded_verification = _verified_execution(
        analysis,
        seeded,
        expected_status="failed",
        test_sha256=test_sha256,
        label="seeded",
        evidence_root=evidence_root,
    )
    if baseline_verification["manifest_sha256"] == seeded_verification["manifest_sha256"]:
        raise ValueError("fault-detection baseline and seeded manifests must be distinct")
    return {
        "detected": True,
        "baseline_execution_id": str(baseline_execution["id"]),
        "seeded_execution_id": str(seeded_execution["id"]),
        "baseline_artifacts": len(baseline_verification["artifact_ids"]),
        "seeded_artifacts": len(seeded_verification["artifact_ids"]),
        "raw_artifacts_verified": True,
    }


def build_fault_detection_evidence(
    analysis: dict[str, Any],
    *,
    sample_id: str,
    baseline_execution_id: str,
    seeded_execution_id: str,
    fault_id: str,
    environment: str,
    evidence_root: str | Path,
) -> dict[str, Any]:
    """Build a sealed claim only after both raw execution records verify."""

    sample = _text(sample_id, "fault-detection sample id")
    fault = _text(fault_id, "fault-detection fault id")
    environment_value = _text(environment, "fault-detection environment")
    baseline = _execution(analysis, baseline_execution_id)
    seeded = _execution(analysis, seeded_execution_id)
    test_sha256 = _digest(
        baseline.get("test", {}).get("sha256"), "fault-detection test sha256"
    )
    if seeded.get("test", {}).get("sha256") != test_sha256:
        raise ValueError("fault-detection executions must bind the same generated test")
    baseline_manifest = _digest(
        baseline.get("execution_manifest_sha256"),
        "fault-detection baseline manifest sha256",
    )
    seeded_manifest = _digest(
        seeded.get("execution_manifest_sha256"),
        "fault-detection seeded manifest sha256",
    )
    evidence = {
        "format": TEST_GENERATION_FAULT_EVIDENCE_FORMAT,
        "sample_id": sample,
        "test_sha256": test_sha256,
        "environment": environment_value,
        "baseline": {
            "execution_id": baseline_execution_id,
            "status": "passed",
            "evidence_sha256": baseline_manifest,
        },
        "seeded": {
            "execution_id": seeded_execution_id,
            "status": "failed",
            "evidence_sha256": seeded_manifest,
            "fault_id": fault,
        },
    }
    evidence["content_sha256"] = canonical_json_sha256(evidence)
    verify_fault_detection_evidence(
        evidence,
        analysis,
        sample_id=sample,
        test_sha256=test_sha256,
        evidence_root=evidence_root,
    )
    return evidence


def export_fault_detection_evidence(
    evidence: dict[str, Any], destination: str | Path
) -> Path:
    return atomic_publish_text(
        destination,
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        max_bytes=2_000_000,
        label="generated-test fault-detection evidence",
    )
