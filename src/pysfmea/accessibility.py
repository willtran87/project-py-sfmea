"""Integrity-bound manual accessibility qualification evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .html_report import verify_html_report_file
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now

ACCESSIBILITY_DRAFT_FORMAT = "pysfmea-accessibility-evidence-draft-1"
ACCESSIBILITY_FORMAT = "pysfmea-accessibility-evidence-1"
ACCESSIBILITY_VERIFICATION_FORMAT = "pysfmea-accessibility-evidence-verification-1"
MAX_ACCESSIBILITY_BYTES = 2_000_000

REQUIRED_ACCESSIBILITY_SCENARIOS = (
    ("keyboard-only", "Complete every report workflow using a keyboard only."),
    ("zoom-200", "Verify readable content and operable controls at 200% browser zoom."),
    ("reflow-400-css-px", "Verify reflow without two-dimensional page scrolling at 400 CSS px."),
    ("forced-colors", "Verify focus, controls, diagrams, and status in forced-colors mode."),
    ("reduced-motion", "Verify the reduced-motion preference removes nonessential transitions."),
    ("nvda-firefox", "Navigate landmarks, filters, table, dialog, and diagrams with NVDA and Firefox."),
    ("jaws-chrome", "Navigate landmarks, filters, table, dialog, and diagrams with JAWS and Chrome."),
    ("voiceover-safari", "Navigate landmarks, filters, table, dialog, and diagrams with VoiceOver and Safari."),
)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_accessibility_evidence(report: str | Path) -> dict[str, Any]:
    path = Path(report).expanduser().resolve(strict=True)
    report_verification = verify_html_report_file(path)
    if not report_verification["valid"]:
        raise ValueError("accessibility evidence requires an internally valid HTML report")
    payload: dict[str, Any] = {
        "format": ACCESSIBILITY_DRAFT_FORMAT,
        "generated_at": utc_now(),
        "report": {
            "filename": path.name,
            "bytes": path.stat().st_size,
            "sha256": _file_sha256(path),
            "analysis_baseline": report_verification["declared"]["baseline_id"],
            "analysis_state_sha256": report_verification["declared"]["analysis_state_sha256"],
        },
        "standard": {
            "target": "WCAG 2.2 Level AA",
            "scope": "self-contained interactive HTML report",
            "claim": "qualification evidence only; no conformance claim until all applicable checks pass",
        },
        "evaluator": {"name": "", "organization": ""},
        "reviewed_at": "",
        "scenarios": [
            {
                "id": identifier,
                "procedure": procedure,
                "status": "not_run",
                "environment": "",
                "evidence_refs": [],
                "notes": "",
            }
            for identifier, procedure in REQUIRED_ACCESSIBILITY_SCENARIOS
        ],
        "exceptions": [],
        "notice": (
            "Automated checks cannot establish assistive-technology usability. Record exact "
            "environments and evidence; not-applicable decisions require a rationale."
        ),
    }
    payload["content_sha256"] = canonical_json_sha256(payload)
    return payload


def load_accessibility_evidence(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="accessibility evidence",
        max_bytes=MAX_ACCESSIBILITY_BYTES,
        max_depth=40,
        max_nodes=100_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("accessibility evidence must contain a JSON object")
    return document.value


def export_accessibility_evidence(report: str | Path, output: str | Path) -> Path:
    payload = build_accessibility_evidence(report)
    return atomic_publish_text(
        output,
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        label="accessibility evidence",
        max_bytes=MAX_ACCESSIBILITY_BYTES,
    )


def seal_accessibility_evidence(source: str | Path) -> Path:
    path = Path(source).expanduser().resolve()
    payload = load_accessibility_evidence(path)
    payload["format"] = ACCESSIBILITY_FORMAT
    payload.pop("content_sha256", None)
    payload["content_sha256"] = canonical_json_sha256(payload)
    verification = verify_accessibility_evidence(payload)
    if not verification["valid"]:
        raise ValueError(
            "accessibility evidence cannot be sealed: "
            + "; ".join(verification["errors"])
        )
    return atomic_publish_text(
        path,
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        label="accessibility evidence",
        max_bytes=MAX_ACCESSIBILITY_BYTES,
    )


def verify_accessibility_evidence(
    evidence: dict[str, Any], *, report: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    expected_fields = {
        "format",
        "generated_at",
        "report",
        "standard",
        "evaluator",
        "reviewed_at",
        "scenarios",
        "exceptions",
        "notice",
        "content_sha256",
    }
    if set(evidence) != expected_fields:
        errors.append("evidence fields do not match the closed format")
    unsigned = copy.deepcopy(evidence)
    declared = str(unsigned.pop("content_sha256", ""))
    integrity = bool(re.fullmatch(r"[0-9a-f]{64}", declared)) and declared == canonical_json_sha256(unsigned)
    if evidence.get("format") != ACCESSIBILITY_FORMAT:
        errors.append("evidence must be sealed with accessibility evidence format 1")
    if not isinstance(evidence.get("generated_at"), str) or not evidence.get(
        "generated_at"
    ):
        errors.append("generated_at must be a non-empty string")
    if not isinstance(evidence.get("reviewed_at"), str) or len(
        evidence.get("reviewed_at", "")
    ) > 100:
        errors.append("reviewed_at must be a bounded string")
    if not isinstance(evidence.get("notice"), str) or not evidence.get("notice"):
        errors.append("notice must be a non-empty string")
    exceptions = evidence.get("exceptions")
    if not isinstance(exceptions, list) or len(exceptions) > 1_000:
        errors.append("exceptions must be a bounded list")
    report_record = evidence.get("report")
    report_fields = {
        "filename",
        "bytes",
        "sha256",
        "analysis_baseline",
        "analysis_state_sha256",
    }
    if not isinstance(report_record, dict) or set(report_record) != report_fields:
        errors.append("report binding must match the closed format")
        report_record = {}
    elif (
        not isinstance(report_record.get("filename"), str)
        or not report_record.get("filename")
        or len(report_record["filename"]) > 500
        or not isinstance(report_record.get("bytes"), int)
        or isinstance(report_record.get("bytes"), bool)
        or report_record["bytes"] < 0
        or not re.fullmatch(r"[0-9a-f]{64}", str(report_record.get("sha256", "")))
        or not isinstance(report_record.get("analysis_baseline"), str)
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(report_record.get("analysis_state_sha256", ""))
        )
    ):
        errors.append("report binding contains invalid values")
    standard = evidence.get("standard")
    if (
        not isinstance(standard, dict)
        or set(standard) != {"target", "scope", "claim"}
        or standard.get("target") != "WCAG 2.2 Level AA"
        or not isinstance(standard.get("scope"), str)
        or not standard.get("scope")
        or not isinstance(standard.get("claim"), str)
        or not standard.get("claim")
    ):
        errors.append("standard declaration does not match the supported contract")
    scenarios = evidence.get("scenarios")
    if not isinstance(scenarios, list):
        errors.append("scenarios must be a list")
        scenarios = []
    expected = {identifier for identifier, _ in REQUIRED_ACCESSIBILITY_SCENARIOS}
    actual = {
        str(value.get("id", "")) for value in scenarios if isinstance(value, dict)
    }
    if actual != expected or len(scenarios) != len(expected):
        errors.append("scenarios must contain each required scenario exactly once")
    statuses: dict[str, str] = {}
    for value in scenarios:
        if not isinstance(value, dict):
            errors.append("each scenario must be an object")
            continue
        identifier, status = str(value.get("id", "")), value.get("status")
        if set(value) != {
            "id",
            "procedure",
            "status",
            "environment",
            "evidence_refs",
            "notes",
        }:
            errors.append(f"scenario {identifier} fields do not match the closed format")
        statuses[identifier] = str(status)
        if status not in {"pass", "fail", "not_applicable", "not_run"}:
            errors.append(f"scenario {identifier} has an invalid status")
        if status in {"pass", "fail"} and (
            not str(value.get("environment", "")).strip()
            or not isinstance(value.get("evidence_refs"), list)
            or not value["evidence_refs"]
        ):
            errors.append(f"scenario {identifier} requires environment and evidence references")
        if status == "not_applicable" and not str(value.get("notes", "")).strip():
            errors.append(f"scenario {identifier} requires a not-applicable rationale")
        evidence_refs = value.get("evidence_refs")
        if (
            not isinstance(value.get("procedure"), str)
            or not value.get("procedure")
            or len(value["procedure"]) > 5_000
            or not isinstance(value.get("environment"), str)
            or len(value["environment"]) > 10_000
            or not isinstance(evidence_refs, list)
            or len(evidence_refs) > 100
            or any(
                not isinstance(item, str) or not item or len(item) > 2_000
                for item in evidence_refs
            )
            or len(evidence_refs) != len(set(evidence_refs))
            or not isinstance(value.get("notes"), str)
            or len(value["notes"]) > 20_000
        ):
            errors.append(f"scenario {identifier} contains invalid values")
    evaluator = evidence.get("evaluator", {})
    if (
        not isinstance(evaluator, dict)
        or set(evaluator) != {"name", "organization"}
        or any(
            not isinstance(evaluator.get(field), str)
            or len(evaluator.get(field, "")) > 500
            for field in ("name", "organization")
        )
    ):
        errors.append("evaluator must match the closed bounded format")
        evaluator = {}
    complete = all(
        statuses.get(identifier) in {"pass", "fail", "not_applicable"}
        for identifier in expected
    )
    all_required_passed = all(
        statuses.get(identifier) == "pass" for identifier in expected
    )
    if complete and (
        not str(evaluator.get("name", "")).strip()
        or not str(evidence.get("reviewed_at", "")).strip()
    ):
        errors.append("completed evidence requires a named evaluator and reviewed_at")
    structure_valid = not errors
    binding: bool | None = None
    if report is not None:
        path = Path(report).expanduser().resolve(strict=True)
        report_verification = verify_html_report_file(path)
        binding = (
            report_verification["valid"]
            and report_record.get("filename") == path.name
            and report_record.get("sha256") == _file_sha256(path)
            and report_record.get("bytes") == path.stat().st_size
            and report_record.get("analysis_baseline")
            == report_verification["declared"]["baseline_id"]
            and report_record.get("analysis_state_sha256")
            == report_verification["declared"]["analysis_state_sha256"]
        )
        if not binding:
            errors.append("evidence does not match the exact report bytes")
    qualified = structure_valid and complete and all_required_passed and binding is not False
    return {
        "format": ACCESSIBILITY_VERIFICATION_FORMAT,
        "valid": integrity and structure_valid and binding is not False,
        "qualified": integrity and qualified,
        "checks": {
            "content_integrity": integrity,
            "structure": structure_valid,
            "report_binding": binding,
            "manual_scenarios_complete": complete,
            "all_required_scenarios_passed": all_required_passed,
            "no_failed_scenarios": all(status != "fail" for status in statuses.values()),
        },
        "scenario_statuses": statuses,
        "errors": errors,
        "notice": (
            "A qualified receipt records the required evaluation evidence; it does not "
            "replace independent conformance assessment or user research."
        ),
    }


def verify_accessibility_evidence_file(
    source: str | Path, *, report: str | Path | None = None
) -> dict[str, Any]:
    supplied = Path(source).expanduser().absolute()
    try:
        result = verify_accessibility_evidence(
            load_accessibility_evidence(supplied), report=report
        )
        result["path"] = str(supplied.resolve())
        return result
    except (OSError, ValueError) as exc:
        return {
            "format": ACCESSIBILITY_VERIFICATION_FORMAT,
            "valid": False,
            "qualified": False,
            "checks": {
                "content_integrity": False,
                "structure": False,
                "report_binding": False if report is not None else None,
                "manual_scenarios_complete": False,
                "all_required_scenarios_passed": False,
                "no_failed_scenarios": False,
            },
            "scenario_statuses": {},
            "errors": [f"accessibility evidence could not be verified: {exc}"],
            "notice": (
                "A qualified receipt records the required evaluation evidence; it does not "
                "replace independent conformance assessment or user research."
            ),
            "path": str(supplied),
        }
