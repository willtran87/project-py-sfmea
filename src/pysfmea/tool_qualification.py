"""Fail-visible, exact-bound tool qualification dossier.

The dossier organizes evidence commonly expected by DO-330, ISO 26262-8,
IEC 61508, and organizational tool-validation processes. Only an authorized
authority can select the basis, classify the tool, and approve qualification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .benchmark_assurance import verify_benchmark_assessment_file
from .benchmark_v2 import (
    BENCHMARK_ASSESSMENT_V2_FORMAT,
    verify_benchmark_v2_assessment_file,
)
from .conformance import verify_conformance_workspace_file
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import utc_now
from .report import analysis_state_sha256

TOOL_QUALIFICATION_FORMAT = "pysfmea-tool-qualification-dossier-1"
TOOL_QUALIFICATION_VERIFICATION_FORMAT = "pysfmea-tool-qualification-verification-1"
MAX_DOSSIER_BYTES = 100_000_000
MAX_TEXT = 20_000
APPLICABILITY = {"applicable", "not_applicable", "undetermined"}
STATUSES = {
    "unassessed",
    "satisfied",
    "partially_satisfied",
    "not_satisfied",
    "not_applicable",
}
ANOMALY_STATUSES = {"open", "mitigated", "accepted", "closed"}

OBJECTIVES: tuple[dict[str, Any], ...] = (
    {
        "id": "TQ-CLASSIFY",
        "title": "Intended use, reliance, failure consequence, qualification basis, and tool classification are approved.",
        "expected_evidence": [
            "tool-use analysis",
            "classification decision",
            "approval record",
        ],
    },
    {
        "id": "TQ-TOR",
        "title": "Tool operational requirements define supported functions, inputs, outputs, constraints, diagnostics, interfaces, and intended environments.",
        "expected_evidence": ["tool operational requirements", "requirements review"],
    },
    {
        "id": "TQ-TQP",
        "title": "The qualification plan defines lifecycle, standards, methods, independence, environment, acceptance criteria, configuration, and deliverables.",
        "expected_evidence": ["tool qualification plan", "approved tailoring"],
    },
    {
        "id": "TQ-TVP",
        "title": "Verification procedures trace every applicable operational requirement to positive, negative, robustness, and error-detection cases.",
        "expected_evidence": [
            "verification plan",
            "requirements-to-case matrix",
            "procedure reviews",
        ],
    },
    {
        "id": "TQ-TVR",
        "title": "Verification results retain exact inputs, expected and actual outcomes, environments, deviations, coverage, and independent review.",
        "expected_evidence": [
            "verification results",
            "benchmark assessment",
            "coverage and deviation records",
        ],
    },
    {
        "id": "TQ-CONFIG",
        "title": "The qualified baseline identifies source, dependencies, build, executable artifacts, configuration, standards, test assets, and provenance.",
        "expected_evidence": [
            "configuration index",
            "SBOM",
            "provenance",
            "release hashes",
        ],
    },
    {
        "id": "TQ-ANOMALY",
        "title": "Known anomalies are complete for the baseline and have evaluated impact, workaround, disclosure, and authorized disposition.",
        "expected_evidence": [
            "known-anomaly register",
            "impact analyses",
            "dispositions",
        ],
    },
    {
        "id": "TQ-TQAS",
        "title": "The qualification accomplishment summary reconciles plans, requirements, results, deviations, anomalies, configuration, and compliance evidence.",
        "expected_evidence": [
            "tool qualification accomplishment summary",
            "compliance matrix",
        ],
    },
    {
        "id": "TQ-REQUALIFY",
        "title": "Change impact and requalification criteria cover code, rules, dependencies, Python, environments, benchmarks, labels, standards, and LLM configuration.",
        "expected_evidence": [
            "change process",
            "requalification policy",
            "impact records",
        ],
    },
)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _bounded_text(value: Any, *, required: bool = True) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) <= MAX_TEXT
        and (not required or value.strip())
    )


def _evidence_references(value: Any) -> bool:
    return bool(
        isinstance(value, list)
        and len(value) <= 1_000
        and len(value) == len(set(value))
        and all(_bounded_text(item) for item in value)
    )


def _json_document(
    source: str | Path, label: str, max_bytes: int
) -> BoundedJsonDocument:
    return load_bounded_json_document(
        source,
        label=label,
        max_bytes=max_bytes,
        max_depth=100,
        max_nodes=2_000_000,
    )


def _binding(
    document: BoundedJsonDocument, *, state_sha256: str = ""
) -> dict[str, Any]:
    result = {
        "reference": document.path.name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "canonical_sha256": canonical_json_sha256(document.value),
    }
    if state_sha256:
        result["analysis_state_sha256"] = state_sha256
    return result


def _verify_benchmark_document(document: BoundedJsonDocument) -> dict[str, Any]:
    """Verify the benchmark generation selected by its closed format identifier."""

    if (
        isinstance(document.value, dict)
        and document.value.get("format") == BENCHMARK_ASSESSMENT_V2_FORMAT
    ):
        return verify_benchmark_v2_assessment_file(document.path)
    return verify_benchmark_assessment_file(document.path)


def _load_anomalies(
    source: str | Path,
) -> tuple[BoundedJsonDocument, list[dict[str, Any]]]:
    document = _json_document(source, "known anomaly register", 10_000_000)
    if (
        not isinstance(document.value, dict)
        or set(document.value) != {"format", "anomalies"}
        or document.value.get("format") != "pysfmea-known-anomaly-register-1"
    ):
        raise ValueError(
            "known anomaly register fields or format do not match format 1"
        )
    values = document.value.get("anomalies")
    if not isinstance(values, list) or len(values) > 10_000:
        raise ValueError("known anomaly register must contain a bounded list")
    identifiers: set[str] = set()
    anomalies: list[dict[str, Any]] = []
    required = {"id", "title", "status", "impact", "disposition", "evidence_refs"}
    for value in values:
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("known anomaly fields do not match format 1")
        identifier = _text(value["id"], "anomaly id")
        if identifier in identifiers:
            raise ValueError("known anomaly identifiers must be unique")
        identifiers.add(identifier)
        if value["status"] not in ANOMALY_STATUSES:
            raise ValueError("known anomaly status is unsupported")
        for field in ("title", "impact", "disposition"):
            _text(value[field], f"anomaly {field}")
        refs = value["evidence_refs"]
        if (
            not isinstance(refs, list)
            or len(refs) > 1_000
            or any(
                not isinstance(ref, str) or not ref.strip() or len(ref) > MAX_TEXT
                for ref in refs
            )
        ):
            raise ValueError("known anomaly evidence references are invalid")
        if value["status"] in {"mitigated", "accepted", "closed"} and not refs:
            raise ValueError("disposed known anomalies require evidence")
        anomalies.append(copy.deepcopy(value))
    return document, anomalies


def _summary(dossier: dict[str, Any]) -> dict[str, Any]:
    objectives = dossier.get("objectives", [])
    blockers = [
        item["id"]
        for item in objectives
        if item.get("applicability") == "undetermined"
        or (
            item.get("applicability") == "applicable"
            and item.get("status") != "satisfied"
        )
    ]
    open_anomalies = [
        item["id"]
        for item in dossier.get("known_anomalies", [])
        if item.get("status") == "open"
    ]
    inputs = dossier.get("input_assessments", {})
    classification = dossier.get("classification", {})
    classification_decided = bool(
        isinstance(classification, dict)
        and str(classification.get("tool_classification", "")).strip().casefold()
        not in {"", "undetermined", "not_assessed"}
    )
    inputs_ready = bool(
        isinstance(inputs, dict)
        and inputs.get("benchmark_valid")
        and inputs.get("benchmark_passed")
        and inputs.get("conformance_valid")
        and inputs.get("conformance_supported")
    )
    complete = not blockers and len(objectives) == len(OBJECTIVES)
    ready = complete and inputs_ready and classification_decided and not open_anomalies
    return {
        "objectives": len(objectives),
        "satisfied": sum(item.get("status") == "satisfied" for item in objectives),
        "not_applicable": sum(
            item.get("status") == "not_applicable" for item in objectives
        ),
        "blocking_objective_ids": sorted(blockers),
        "open_anomaly_ids": sorted(open_anomalies),
        "classification_decided": classification_decided,
        "inputs_ready": inputs_ready,
        "assessment_complete": complete,
        "eligible_for_authorized_qualification_decision": ready,
        "status": "eligible_for_authorized_qualification_decision"
        if ready
        else "qualification_dossier_incomplete",
    }


def _digest(dossier: dict[str, Any]) -> str:
    content = copy.deepcopy(dossier)
    content.pop("content_sha256", None)
    return canonical_json_sha256(content)


def tool_qualification_dossier(
    analysis: dict[str, Any],
    analysis_source: str | Path,
    benchmark_assessment_source: str | Path,
    conformance_workspace_source: str | Path,
    anomaly_register_source: str | Path,
    *,
    intended_use: str,
    reliance: str,
    qualification_basis: str,
    tool_classification: str,
    intended_environment: str,
    classification_authority: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create an exact-bound, initially unassessed qualification dossier."""

    classification = {
        "intended_use": _text(intended_use, "intended use"),
        "reliance": _text(reliance, "tool reliance"),
        "qualification_basis": _text(qualification_basis, "qualification basis"),
        "tool_classification": _text(tool_classification, "tool classification"),
        "intended_environment": _text(intended_environment, "intended environment"),
        "classification_authority": _text(
            classification_authority, "classification authority"
        ),
    }
    analysis_document = _json_document(
        analysis_source, "qualified analysis", MAX_DOSSIER_BYTES
    )
    if analysis_document.value != analysis:
        raise ValueError("supplied analysis does not match the exact analysis file")
    benchmark_document = _json_document(
        benchmark_assessment_source,
        "independent benchmark assessment",
        MAX_DOSSIER_BYTES,
    )
    conformance_document = _json_document(
        conformance_workspace_source, "conformance workspace", MAX_DOSSIER_BYTES
    )
    anomaly_document, anomalies = _load_anomalies(anomaly_register_source)
    benchmark_verdict = _verify_benchmark_document(benchmark_document)
    conformance_verdict = verify_conformance_workspace_file(
        conformance_document.path, analysis=analysis
    )
    dossier: dict[str, Any] = {
        "format": TOOL_QUALIFICATION_FORMAT,
        "generated_at": generated_at or utc_now(),
        "tool": {
            "name": "PySFMEA",
            "qualified_baseline": str(analysis.get("tool", {}).get("version", "")),
        },
        "classification": classification,
        "bindings": {
            "analysis": _binding(
                analysis_document, state_sha256=analysis_state_sha256(analysis)
            ),
            "benchmark_assessment": _binding(benchmark_document),
            "conformance_workspace": _binding(conformance_document),
            "known_anomaly_register": _binding(anomaly_document),
        },
        "input_assessments": {
            "benchmark_valid": bool(benchmark_verdict.get("valid")),
            "benchmark_passed": bool(benchmark_verdict.get("passed")),
            "conformance_valid": bool(conformance_verdict.get("valid")),
            "conformance_supported": bool(
                conformance_verdict.get("conformance_supported")
            ),
        },
        "objectives": [
            {
                **copy.deepcopy(objective),
                "applicability": "undetermined",
                "status": "unassessed",
                "rationale": "",
                "reviewer": "",
                "reviewed_at": "",
                "evidence_refs": [],
            }
            for objective in OBJECTIVES
        ],
        "known_anomalies": anomalies,
        "summary": {},
        "claim": "This dossier does not assert tool qualification, certification credit, or approval.",
        "content_sha256": "",
    }
    dossier["summary"] = _summary(dossier)
    dossier["content_sha256"] = _digest(dossier)
    return dossier


def assess_tool_qualification_objective(
    dossier: dict[str, Any],
    objective_id: str,
    *,
    applicability: str,
    status: str,
    rationale: str,
    reviewer: str,
    evidence_refs: list[str],
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    """Record one reviewed qualification objective and reseal the dossier."""

    if applicability not in APPLICABILITY or status not in STATUSES:
        raise ValueError("unsupported qualification applicability or status")
    if applicability == "not_applicable" and status != "not_applicable":
        raise ValueError("not-applicable objectives must use not_applicable status")
    if applicability == "undetermined" and status != "unassessed":
        raise ValueError("undetermined objectives must remain unassessed")
    if applicability == "applicable" and status == "not_applicable":
        raise ValueError("applicable objectives cannot use not_applicable status")
    if status == "satisfied" and not evidence_refs:
        raise ValueError("satisfied qualification objectives require evidence")
    if status != "unassessed":
        _text(rationale, "assessment rationale")
        _text(reviewer, "assessment reviewer")
    if len(evidence_refs) > 1_000 or any(
        not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT
        for value in evidence_refs
    ):
        raise ValueError("qualification evidence references are invalid")
    updated = copy.deepcopy(dossier)
    matches = [
        item for item in updated.get("objectives", []) if item.get("id") == objective_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"unknown or ambiguous qualification objective: {objective_id}"
        )
    matches[0].update(
        {
            "applicability": applicability,
            "status": status,
            "rationale": rationale.strip(),
            "reviewer": reviewer.strip(),
            "reviewed_at": (reviewed_at or utc_now()) if status != "unassessed" else "",
            "evidence_refs": list(
                dict.fromkeys(value.strip() for value in evidence_refs)
            ),
        }
    )
    updated["generated_at"] = utc_now()
    updated["summary"] = _summary(updated)
    updated["content_sha256"] = _digest(updated)
    verdict = verify_tool_qualification_dossier(updated)
    if not verdict["valid"]:
        raise ValueError(
            "updated tool qualification dossier is invalid: "
            + "; ".join(verdict["errors"])
        )
    return updated


def verify_tool_qualification_dossier(dossier: dict[str, Any]) -> dict[str, Any]:
    """Verify dossier structure, governed objectives, bindings, and summaries."""

    errors: list[str] = []
    required = {
        "format",
        "generated_at",
        "tool",
        "classification",
        "bindings",
        "input_assessments",
        "objectives",
        "known_anomalies",
        "summary",
        "claim",
        "content_sha256",
    }
    closed = (
        set(dossier) == required and dossier.get("format") == TOOL_QUALIFICATION_FORMAT
    )
    if not closed:
        errors.append("dossier fields or format do not match format 1")
    claimed = str(dossier.get("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed) and claimed == _digest(dossier)
    )
    if not integrity:
        errors.append("dossier content digest does not match")
    tool = dossier.get("tool")
    classification = dossier.get("classification")
    input_assessments = dossier.get("input_assessments")
    classification_fields = {
        "intended_use",
        "reliance",
        "qualification_basis",
        "tool_classification",
        "intended_environment",
        "classification_authority",
    }
    input_fields = {
        "benchmark_valid",
        "benchmark_passed",
        "conformance_valid",
        "conformance_supported",
    }
    metadata_semantics = bool(
        isinstance(tool, dict)
        and set(tool) == {"name", "qualified_baseline"}
        and tool.get("name") == "PySFMEA"
        and _bounded_text(tool.get("qualified_baseline"), required=False)
        and isinstance(classification, dict)
        and set(classification) == classification_fields
        and all(
            _bounded_text(classification.get(name)) for name in classification_fields
        )
        and isinstance(input_assessments, dict)
        and set(input_assessments) == input_fields
        and all(type(input_assessments.get(name)) is bool for name in input_fields)
        and _bounded_text(dossier.get("generated_at"))
        and _bounded_text(dossier.get("claim"))
    )
    if not metadata_semantics:
        errors.append("tool, classification, or input-assessment metadata is invalid")
    objective_integrity = True
    objective_semantics = True
    objectives = dossier.get("objectives")
    expected = {value["id"]: value for value in OBJECTIVES}
    if not isinstance(objectives, list) or len(objectives) != len(expected):
        objective_integrity = False
        objective_semantics = False
    else:
        seen: set[str] = set()
        for value in objectives:
            if not isinstance(value, dict):
                objective_integrity = False
                objective_semantics = False
                continue
            identifier = str(value.get("id", ""))
            expected_value = expected.get(identifier)
            if identifier in seen or expected_value is None:
                objective_integrity = False
            seen.add(identifier)
            if expected_value and any(
                value.get(key) != item for key, item in expected_value.items()
            ):
                objective_integrity = False
            applicability = value.get("applicability")
            status = value.get("status")
            evidence = value.get("evidence_refs")
            rationale = value.get("rationale")
            reviewer = value.get("reviewer")
            reviewed_at = value.get("reviewed_at")
            semantic = bool(
                set(value)
                == {
                    "id",
                    "title",
                    "expected_evidence",
                    "applicability",
                    "status",
                    "rationale",
                    "reviewer",
                    "reviewed_at",
                    "evidence_refs",
                }
                and applicability in APPLICABILITY
                and status in STATUSES
                and _evidence_references(evidence)
                and _bounded_text(rationale, required=False)
                and _bounded_text(reviewer, required=False)
                and _bounded_text(reviewed_at, required=False)
                and not (
                    applicability == "not_applicable" and status != "not_applicable"
                )
                and not (applicability == "undetermined" and status != "unassessed")
                and not (applicability == "applicable" and status == "not_applicable")
                and not (status == "satisfied" and not evidence)
                and not (
                    status != "unassessed"
                    and (
                        not isinstance(rationale, str)
                        or not rationale.strip()
                        or not isinstance(reviewer, str)
                        or not reviewer.strip()
                        or not reviewed_at
                    )
                )
            )
            objective_semantics = objective_semantics and semantic
    if not objective_integrity:
        errors.append(
            "qualification objectives do not match the governed objective set"
        )
    if not objective_semantics:
        errors.append("qualification objective assessment semantics are invalid")
    try:
        anomalies = dossier.get("known_anomalies")
        anomaly_semantics = (
            isinstance(anomalies, list)
            and len(anomalies) <= 10_000
            and len({item["id"] for item in anomalies}) == len(anomalies)
            and all(
                isinstance(item, dict)
                and set(item)
                == {"id", "title", "status", "impact", "disposition", "evidence_refs"}
                and _bounded_text(item.get("id"))
                and _bounded_text(item.get("title"))
                and _bounded_text(item.get("impact"))
                and _bounded_text(item.get("disposition"))
                and item.get("status") in ANOMALY_STATUSES
                and _evidence_references(item.get("evidence_refs"))
                and not (
                    item.get("status") in {"mitigated", "accepted", "closed"}
                    and not item.get("evidence_refs")
                )
                for item in anomalies
            )
        )
    except (KeyError, TypeError):
        anomaly_semantics = False
    if not anomaly_semantics:
        errors.append("known anomaly semantics are invalid")
    try:
        summary = _summary(dossier)
        summary_reconciliation = dossier.get("summary") == summary
    except (AttributeError, KeyError, TypeError, ValueError):
        summary = {}
        summary_reconciliation = False
    if not summary_reconciliation:
        errors.append("qualification dossier summary does not reconcile")
    bindings = dossier.get("bindings")
    binding_structure = (
        isinstance(bindings, dict)
        and set(bindings)
        == {
            "analysis",
            "benchmark_assessment",
            "conformance_workspace",
            "known_anomaly_register",
        }
        and isinstance(bindings["analysis"], dict)
        and set(bindings["analysis"])
        == {"reference", "bytes", "sha256", "canonical_sha256", "analysis_state_sha256"}
        and all(
            isinstance(bindings[name], dict)
            and set(bindings[name])
            == (
                {"reference", "bytes", "sha256", "canonical_sha256"}
                if name != "analysis"
                else {
                    "reference",
                    "bytes",
                    "sha256",
                    "canonical_sha256",
                    "analysis_state_sha256",
                }
            )
            and _bounded_text(bindings[name].get("reference"))
            and type(bindings[name].get("bytes")) is int
            and bindings[name]["bytes"] >= 0
            and bindings[name]["bytes"] <= MAX_DOSSIER_BYTES
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", ""))))
            and bool(
                re.fullmatch(r"[0-9a-f]{64}", str(value.get("canonical_sha256", "")))
            )
            and (
                name != "analysis"
                or bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(bindings[name].get("analysis_state_sha256", "")),
                    )
                )
            )
            for name, value in bindings.items()
        )
    )
    if not binding_structure:
        errors.append("qualification dossier bindings are malformed")
    valid = all(
        (
            closed,
            integrity,
            metadata_semantics,
            objective_integrity,
            objective_semantics,
            anomaly_semantics,
            summary_reconciliation,
            binding_structure,
        )
    )
    return {
        "format": TOOL_QUALIFICATION_VERIFICATION_FORMAT,
        "valid": valid,
        "eligible_for_authorized_qualification_decision": bool(
            valid and summary.get("eligible_for_authorized_qualification_decision")
        ),
        "checks": {
            "closed_structure": closed,
            "content_integrity": integrity,
            "metadata_semantics": metadata_semantics,
            "objective_integrity": objective_integrity,
            "assessment_semantics": objective_semantics,
            "anomaly_semantics": anomaly_semantics,
            "summary_reconciliation": summary_reconciliation,
            "binding_structure": binding_structure,
            "source_bindings": None,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification establishes dossier integrity and readiness for an authorized decision; it does not qualify the tool or grant certification credit.",
    }


def verify_tool_qualification_dossier_file(
    source: str | Path,
    *,
    analysis_source: str | Path | None = None,
    benchmark_assessment_source: str | Path | None = None,
    conformance_workspace_source: str | Path | None = None,
    anomaly_register_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = _json_document(
            source, "tool qualification dossier", MAX_DOSSIER_BYTES
        )
        if not isinstance(document.value, dict):
            raise ValueError("tool qualification dossier must contain an object")
        verdict = {
            "path": str(document.path),
            **verify_tool_qualification_dossier(document.value),
        }
        supplied = (
            analysis_source,
            benchmark_assessment_source,
            conformance_workspace_source,
            anomaly_register_source,
        )
        if any(value is not None for value in supplied):
            source_bindings = False
            if all(value is not None for value in supplied):
                analysis_document = _json_document(
                    analysis_source or "", "qualified analysis", MAX_DOSSIER_BYTES
                )
                benchmark_document = _json_document(
                    benchmark_assessment_source or "",
                    "independent benchmark assessment",
                    MAX_DOSSIER_BYTES,
                )
                conformance_document = _json_document(
                    conformance_workspace_source or "",
                    "conformance workspace",
                    MAX_DOSSIER_BYTES,
                )
                anomaly_document, anomalies = _load_anomalies(
                    anomaly_register_source or ""
                )
                analysis = analysis_document.value
                if not isinstance(analysis, dict):
                    raise ValueError("qualified analysis must contain an object")
                expected_bindings = {
                    "analysis": _binding(
                        analysis_document,
                        state_sha256=analysis_state_sha256(analysis),
                    ),
                    "benchmark_assessment": _binding(benchmark_document),
                    "conformance_workspace": _binding(conformance_document),
                    "known_anomaly_register": _binding(anomaly_document),
                }
                benchmark_verdict = _verify_benchmark_document(benchmark_document)
                conformance_verdict = verify_conformance_workspace_file(
                    conformance_document.path, analysis=analysis
                )
                expected_inputs = {
                    "benchmark_valid": bool(benchmark_verdict.get("valid")),
                    "benchmark_passed": bool(benchmark_verdict.get("passed")),
                    "conformance_valid": bool(conformance_verdict.get("valid")),
                    "conformance_supported": bool(
                        conformance_verdict.get("conformance_supported")
                    ),
                }
                source_bindings = bool(
                    document.value.get("bindings") == expected_bindings
                    and document.value.get("input_assessments") == expected_inputs
                    and document.value.get("known_anomalies") == anomalies
                )
            verdict["checks"]["source_bindings"] = source_bindings
            if not source_bindings:
                verdict["valid"] = False
                verdict["eligible_for_authorized_qualification_decision"] = False
                verdict["errors"].append(
                    "dossier does not match all supplied exact source artifacts"
                )
        else:
            verdict["checks"]["source_bindings"] = None
        return verdict
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": TOOL_QUALIFICATION_VERIFICATION_FORMAT,
            "valid": False,
            "eligible_for_authorized_qualification_decision": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "objective_integrity": False,
                "assessment_semantics": False,
                "anomaly_semantics": False,
                "summary_reconciliation": False,
                "binding_structure": False,
                "source_bindings": False,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The tool qualification dossier could not be safely verified.",
        }


def load_tool_qualification_dossier(source: str | Path) -> dict[str, Any]:
    document = _json_document(source, "tool qualification dossier", MAX_DOSSIER_BYTES)
    if not isinstance(document.value, dict):
        raise ValueError("tool qualification dossier must contain an object")
    return document.value


def export_tool_qualification_dossier(
    dossier: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_tool_qualification_dossier(dossier)
    if not verdict["valid"]:
        raise ValueError("tool qualification dossier is not internally valid")
    return atomic_publish_text(
        destination,
        json.dumps(dossier, indent=2, ensure_ascii=False) + "\n",
        label="tool qualification dossier",
    )
