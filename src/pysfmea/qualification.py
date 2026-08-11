"""Governed, independently regenerable multi-repository scanner qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from datetime import date
from pathlib import Path
from typing import Any

from .discovery import (
    MAX_EVALUATION_FILE_BYTES,
    MAX_EVALUATION_JSON_DEPTH,
    MAX_EVALUATION_JSON_NODES,
    evaluate_candidates,
    load_evaluation_spec,
)
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .report import analysis_state_sha256
from .store import (
    MAX_ANALYSIS_BYTES,
    MAX_ANALYSIS_JSON_DEPTH,
    MAX_ANALYSIS_JSON_NODES,
    load_analysis,
)
from .version import __version__

QUALIFICATION_CAMPAIGN_MANIFEST_FORMAT = (
    "pysfmea-qualification-campaign-manifest-1"
)
QUALIFICATION_CAMPAIGN_RESULT_FORMAT = "pysfmea-qualification-campaign-result-1"
QUALIFICATION_CAMPAIGN_VERIFICATION_FORMAT = (
    "pysfmea-qualification-campaign-verification-1"
)

MAX_QUALIFICATION_MANIFEST_BYTES = 5_000_000
MAX_QUALIFICATION_RESULT_BYTES = 25_000_000
MAX_QUALIFICATION_REPOSITORIES = 100
MAX_QUALIFICATION_LABELS = 100
MAX_QUALIFICATION_TEXT = 20_000
MAX_EVALUATION_RESULT_BYTES = 25_000_000

FEATURE_KEYS = (
    "finding_detection",
    "call_resolution",
    "control_detection",
    "semantic_output",
)
CONTROL_POPULATION_KEYS = (
    "evaluated_components",
    "positive_components",
    "negative_components",
)
QUALIFICATION_CHECKS = (
    "artifact_bindings",
    "evaluation_regeneration",
    "no_duplicate_candidates",
    "no_unsupported_verification_claims",
    "source_localization_complete",
    "traceability_complete",
    "adapter_provenance_complete",
    "repository_source_accounting_complete",
    "citation_links_valid",
    "campaign_governance",
    "independent_corpora",
    "minimum_repositories",
    "minimum_frameworks",
    "minimum_domains",
    "minimum_expected_findings",
    "finding_recall",
    "finding_precision",
    "repository_finding_cases_present",
    "repository_finding_recall",
    "repository_finding_precision",
    "framework_finding_recall",
    "framework_finding_precision",
    "domain_finding_recall",
    "domain_finding_precision",
    "call_cases_present",
    "call_recall",
    "call_precision",
    "call_population_recall",
    "call_population_precision",
    "control_cases_present",
    "control_negative_population",
    "control_recall",
    "control_precision",
    "control_population_recall",
    "control_population_precision",
    "semantic_cases_present",
    "semantic_recall",
    "semantic_precision",
    "semantic_population_recall",
    "semantic_population_precision",
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_THRESHOLD_FIELDS = {
    "minimum_repositories",
    "minimum_frameworks",
    "minimum_domains",
    "minimum_expected_findings",
    "minimum_finding_recall",
    "minimum_finding_precision",
    "require_call_cases",
    "minimum_call_recall",
    "minimum_call_precision",
    "require_control_cases",
    "minimum_control_negative_components_per_repository",
    "minimum_control_recall",
    "minimum_control_precision",
    "require_semantic_cases",
    "minimum_semantic_recall",
    "minimum_semantic_precision",
}


def _text(value: Any, *, label: str, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = value.strip()
    if required and not result:
        raise ValueError(f"{label} must not be empty")
    if len(result) > MAX_QUALIFICATION_TEXT:
        raise ValueError(f"{label} exceeds the text limit")
    return result


def _identifier(value: Any, *, label: str) -> str:
    result = _text(value, label=label)
    if not _IDENTIFIER.fullmatch(result):
        raise ValueError(
            f"{label} must use 1-100 letters, digits, periods, underscores, or hyphens"
        )
    return result


def _labels(value: Any, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_QUALIFICATION_LABELS
        or not all(isinstance(entry, str) for entry in value)
    ):
        raise ValueError(f"{label} must be a bounded string array")
    values = [_identifier(entry, label=f"{label} entry") for entry in value]
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must not contain duplicates")
    return values


def _ratio(value: Any, *, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 <= float(value) <= 1
    ):
        raise ValueError(f"{label} must be a number from 0 through 1")
    return float(value)


def _count(value: Any, *, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer of at least {minimum}")
    return value


def _validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("qualification campaign manifest must be a JSON object")
    required = {
        "format",
        "id",
        "title",
        "purpose",
        "governance",
        "thresholds",
        "repositories",
    }
    if set(manifest) != required:
        raise ValueError("qualification campaign manifest fields do not match format 1")
    if manifest.get("format") != QUALIFICATION_CAMPAIGN_MANIFEST_FORMAT:
        raise ValueError("qualification campaign manifest format is unsupported")
    _identifier(manifest.get("id"), label="campaign ID")
    _text(manifest.get("title"), label="campaign title")
    _text(manifest.get("purpose"), label="campaign purpose")

    governance = manifest.get("governance")
    governance_fields = {
        "independent",
        "labeled_by",
        "approved_by",
        "approval_date",
        "selection_method",
        "representativeness_rationale",
    }
    if not isinstance(governance, dict) or set(governance) != governance_fields:
        raise ValueError("campaign governance fields do not match format 1")
    if not isinstance(governance.get("independent"), bool):
        raise ValueError("campaign governance independent must be boolean")
    for field in governance_fields - {"independent"}:
        _text(governance.get(field), label=f"campaign governance {field}")
    try:
        date.fromisoformat(str(governance["approval_date"]))
    except ValueError as exc:
        raise ValueError("campaign approval_date must use YYYY-MM-DD") from exc

    thresholds = manifest.get("thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != _THRESHOLD_FIELDS:
        raise ValueError("campaign threshold fields do not match format 1")
    for field in (
        "minimum_repositories",
        "minimum_frameworks",
        "minimum_domains",
        "minimum_expected_findings",
        "minimum_control_negative_components_per_repository",
    ):
        _count(
            thresholds[field],
            label=f"campaign threshold {field}",
            minimum=1 if field in {"minimum_repositories", "minimum_expected_findings"} else 0,
        )
    for field in (
        "minimum_finding_recall",
        "minimum_finding_precision",
        "minimum_call_recall",
        "minimum_call_precision",
        "minimum_control_recall",
        "minimum_control_precision",
        "minimum_semantic_recall",
        "minimum_semantic_precision",
    ):
        _ratio(thresholds[field], label=f"campaign threshold {field}")
    for field in (
        "require_call_cases",
        "require_control_cases",
        "require_semantic_cases",
    ):
        if not isinstance(thresholds[field], bool):
            raise ValueError(f"campaign threshold {field} must be boolean")

    repositories = manifest.get("repositories")
    if (
        not isinstance(repositories, list)
        or not repositories
        or len(repositories) > MAX_QUALIFICATION_REPOSITORIES
        or not all(isinstance(entry, dict) for entry in repositories)
    ):
        raise ValueError("campaign repositories must be a non-empty bounded object array")
    repository_fields = {
        "id",
        "analysis",
        "corpus",
        "evaluation",
        "frameworks",
        "domains",
        "selection_rationale",
    }
    identifiers: list[str] = []
    for index, entry in enumerate(repositories, start=1):
        if set(entry) != repository_fields:
            raise ValueError(f"campaign repository {index} fields do not match format 1")
        identifiers.append(_identifier(entry["id"], label=f"repository {index} ID"))
        references = [
            _text(entry[field], label=f"repository {index} {field}")
            for field in ("analysis", "corpus", "evaluation")
        ]
        if len(set(references)) != 3:
            raise ValueError(f"repository {index} artifact references must be distinct")
        _labels(entry["frameworks"], label=f"repository {index} frameworks")
        _labels(entry["domains"], label=f"repository {index} domains")
        _text(
            entry["selection_rationale"],
            label=f"repository {index} selection rationale",
        )
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("campaign repository IDs must be unique")
    return manifest


def load_qualification_campaign_manifest(source: str | Path) -> BoundedJsonDocument:
    document = load_bounded_json_document(
        source,
        label="qualification campaign manifest",
        max_bytes=MAX_QUALIFICATION_MANIFEST_BYTES,
        max_depth=30,
        max_nodes=250_000,
    )
    _validate_manifest(document.value)
    return document


def _artifact_path(root: Path, reference: str) -> Path:
    candidate = Path(reference)
    if candidate.is_absolute():
        raise ValueError("campaign artifact references must be relative to the manifest")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("campaign artifact reference escapes the manifest directory")
    return resolved


def _binding(document: BoundedJsonDocument, reference: str) -> dict[str, Any]:
    return {
        "reference": reference,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "canonical_sha256": canonical_json_sha256(document.value),
    }


def _feature(expected: Any, actual: Any, matched: Any) -> dict[str, Any]:
    expected_count = _count(expected, label="feature expected")
    actual_count = _count(actual, label="feature actual")
    matched_count = _count(matched, label="feature matched")
    if matched_count > expected_count or matched_count > actual_count:
        raise ValueError("feature matched count exceeds its expected or actual population")
    return {
        "expected": expected_count,
        "actual": actual_count,
        "matched": matched_count,
        "recall": round(matched_count / expected_count, 4)
        if expected_count
        else None,
        "precision": round(matched_count / actual_count, 4)
        if actual_count
        else None,
    }


def _repository_metrics(evaluation: dict[str, Any]) -> dict[str, Any]:
    if evaluation.get("format") != "pysfmea-evaluation-result-1":
        raise ValueError("evaluation artifact format is unsupported")
    call = evaluation.get("call_resolution", {})
    controls = evaluation.get("control_detection", {})
    semantics = evaluation.get("semantic_output", {})
    by_rule = evaluation.get("by_rule", {})
    by_resolution = call.get("by_resolution", {}) if isinstance(call, dict) else {}
    by_kind = controls.get("by_kind", {}) if isinstance(controls, dict) else {}
    by_semantic_field = (
        semantics.get("by_field", {}) if isinstance(semantics, dict) else {}
    )
    by_semantic_rule = (
        semantics.get("by_rule", {}) if isinstance(semantics, dict) else {}
    )
    quality = evaluation.get("metrics", {})
    if not all(
        isinstance(value, dict)
        for value in (call, controls, semantics, by_rule, quality)
    ):
        raise ValueError("evaluation artifact metric collections are malformed")
    duplicate_count = _count(
        quality.get("duplicate_count"), label="evaluation duplicate count"
    )
    unsupported_claims = quality.get("unsupported_verification_claims")
    if not isinstance(unsupported_claims, list):
        raise ValueError("evaluation unsupported verification claims are malformed")
    control_population = controls.get("population")
    if not isinstance(control_population, dict):
        raise ValueError("evaluation control population is missing or malformed")
    control_population_counts = {
        field: _count(
            control_population.get(field),
            label=f"evaluation control population {field}",
        )
        for field in CONTROL_POPULATION_KEYS
    }
    if (
        control_population_counts["positive_components"]
        + control_population_counts["negative_components"]
        != control_population_counts["evaluated_components"]
    ):
        raise ValueError("evaluation control population counts do not reconcile")

    def optional_ratio(field: str) -> float | None:
        value = quality.get(field)
        return None if value is None else _ratio(value, label=f"evaluation {field}")

    def collection(source: Any, *, label: str) -> dict[str, dict[str, Any]]:
        if not isinstance(source, dict) or not all(
            isinstance(key, str) and isinstance(value, dict)
            for key, value in source.items()
        ):
            raise ValueError(f"evaluation {label} metrics are malformed")
        return {
            key: _feature(value.get("expected"), value.get("actual"), value.get("matched"))
            for key, value in sorted(source.items())
        }

    control_feature = _feature(
        controls.get("expected"),
        controls.get("actual"),
        controls.get("matched"),
    )
    control_feature.update(control_population_counts)
    return {
        "features": {
            "finding_detection": _feature(
                evaluation.get("expected"),
                evaluation.get("actual"),
                evaluation.get("matched"),
            ),
            "call_resolution": _feature(
                call.get("expected"), call.get("actual"), call.get("matched")
            ),
            "control_detection": control_feature,
            "semantic_output": _feature(
                semantics.get("expected"),
                semantics.get("actual"),
                semantics.get("matched"),
            ),
        },
        "quality": {
            "duplicate_count": duplicate_count,
            "unsupported_verification_claim_count": len(unsupported_claims),
            "source_localization_accuracy": optional_ratio(
                "source_localization_accuracy"
            ),
            "citation_link_accuracy": optional_ratio("citation_link_accuracy"),
            "traceability_integrity": optional_ratio("traceability_integrity"),
            "adapter_provenance_coverage": optional_ratio(
                "adapter_provenance_coverage"
            ),
            "repository_source_accounting": optional_ratio(
                "repository_source_accounting"
            ),
        },
        "by_rule": collection(by_rule, label="by-rule"),
        "by_call_resolution": collection(by_resolution, label="call-resolution"),
        "by_control_kind": collection(by_kind, label="control-kind"),
        "by_semantic_field": collection(
            by_semantic_field, label="semantic-field"
        ),
        "by_semantic_rule": collection(by_semantic_rule, label="semantic-rule"),
    }


def _load_repository(
    entry: dict[str, Any], manifest_root: Path
) -> dict[str, Any]:
    references = {
        field: str(entry[field]) for field in ("analysis", "corpus", "evaluation")
    }
    paths = {
        field: _artifact_path(manifest_root, reference)
        for field, reference in references.items()
    }
    analysis_document = load_bounded_json_document(
        paths["analysis"],
        label=f"qualification analysis {entry['id']}",
        max_bytes=MAX_ANALYSIS_BYTES,
        max_depth=MAX_ANALYSIS_JSON_DEPTH,
        max_nodes=MAX_ANALYSIS_JSON_NODES,
    )
    if not isinstance(analysis_document.value, dict):
        raise ValueError(f"qualification analysis {entry['id']} must be an object")
    analysis = load_analysis(paths["analysis"])
    if canonical_json_sha256(analysis_document.value) != canonical_json_sha256(analysis):
        raise ValueError(
            f"qualification analysis {entry['id']} is not a canonical current analysis"
        )
    corpus_document = load_bounded_json_document(
        paths["corpus"],
        label=f"qualification corpus {entry['id']}",
        max_bytes=MAX_EVALUATION_FILE_BYTES,
        max_depth=MAX_EVALUATION_JSON_DEPTH,
        max_nodes=MAX_EVALUATION_JSON_NODES,
    )
    corpus = load_evaluation_spec(paths["corpus"])
    if canonical_json_sha256(corpus_document.value) != canonical_json_sha256(corpus):
        raise ValueError(f"qualification corpus {entry['id']} changed during loading")
    evaluation_document = load_bounded_json_document(
        paths["evaluation"],
        label=f"qualification evaluation {entry['id']}",
        max_bytes=MAX_EVALUATION_RESULT_BYTES,
        max_depth=60,
        max_nodes=1_000_000,
    )
    if not isinstance(evaluation_document.value, dict):
        raise ValueError(f"qualification evaluation {entry['id']} must be an object")
    regenerated = evaluate_candidates(analysis, corpus)
    if canonical_json_sha256(regenerated) != canonical_json_sha256(
        evaluation_document.value
    ):
        raise ValueError(
            f"qualification evaluation {entry['id']} does not exactly regenerate"
        )
    governance = regenerated.get("corpus", {}).get("governance", {})
    return {
        "id": entry["id"],
        "frameworks": list(entry["frameworks"]),
        "domains": list(entry["domains"]),
        "selection_rationale": entry["selection_rationale"],
        "analysis_state_sha256": analysis_state_sha256(analysis),
        "corpus_governance_qualification_ready": bool(
            isinstance(governance, dict) and governance.get("qualification_ready")
        ),
        "corpus_governance": copy.deepcopy(governance),
        "evaluation_verifier": copy.deepcopy(regenerated.get("verifier", {})),
        "artifacts": {
            "analysis": _binding(analysis_document, references["analysis"]),
            "corpus": _binding(corpus_document, references["corpus"]),
            "evaluation": _binding(evaluation_document, references["evaluation"]),
        },
        **_repository_metrics(regenerated),
    }


def _aggregate_features(repositories: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for feature_key in FEATURE_KEYS:
        expected = sum(repo["features"][feature_key]["expected"] for repo in repositories)
        actual = sum(repo["features"][feature_key]["actual"] for repo in repositories)
        matched = sum(repo["features"][feature_key]["matched"] for repo in repositories)
        result[feature_key] = {
            **_feature(expected, actual, matched),
            "repositories": sum(
                bool(
                    repo["features"][feature_key]["expected"]
                    or repo["features"][feature_key]["actual"]
                )
                for repo in repositories
            ),
        }
        if feature_key == "control_detection":
            result[feature_key].update(
                {
                    field: sum(
                        repo["features"][feature_key][field]
                        for repo in repositories
                    )
                    for field in CONTROL_POPULATION_KEYS
                }
            )
    return result


def _aggregate_named(
    repositories: list[dict[str, Any]], field: str
) -> dict[str, Any]:
    labels = sorted(
        {
            label
            for repository in repositories
            for label in repository.get(field, {})
        }
    )
    result: dict[str, Any] = {}
    for label in labels:
        values = [
            repository[field][label]
            for repository in repositories
            if label in repository.get(field, {})
        ]
        result[label] = {
            **_feature(
                sum(value["expected"] for value in values),
                sum(value["actual"] for value in values),
                sum(value["matched"] for value in values),
            ),
            "repositories": len(values),
        }
    return result


def _segments(repositories: list[dict[str, Any]], field: str) -> dict[str, Any]:
    labels = sorted({label for repo in repositories for label in repo[field]})
    return {
        label: {
            "repository_count": len(selected),
            "repository_ids": [repo["id"] for repo in selected],
            "features": _aggregate_features(selected),
        }
        for label in labels
        for selected in [[repo for repo in repositories if label in repo[field]]]
    }


def _governance_projection(governance: dict[str, Any]) -> dict[str, Any]:
    ready = bool(
        governance["independent"]
        and governance["labeled_by"].casefold()
        != governance["approved_by"].casefold()
        and governance["selection_method"]
        and governance["representativeness_rationale"]
    )
    return {
        **copy.deepcopy(governance),
        "qualification_ready_claim": ready,
        "authority": (
            "named identities and corpus representativeness are asserted by the manifest; "
            "PySFMEA verifies structure, separation, bindings, and metrics but does not "
            "authenticate people or approve tool qualification"
        ),
    }


def _projection(
    governance: dict[str, Any],
    thresholds: dict[str, Any],
    repositories: list[dict[str, Any]],
) -> dict[str, Any]:
    features = _aggregate_features(repositories)
    frameworks = sorted({value for repo in repositories for value in repo["frameworks"]})
    domains = sorted({value for repo in repositories for value in repo["domains"]})
    governance_result = _governance_projection(governance)
    finding = features["finding_detection"]
    calls = features["call_resolution"]
    controls = features["control_detection"]
    semantics = features["semantic_output"]

    def complete_quality(field: str, *, optional: bool = False) -> bool:
        values = [repo["quality"][field] for repo in repositories]
        return all(
            (value is None and optional) or value == 1.0 for value in values
        )

    def metric_check(
        metric: dict[str, Any], key: str, threshold: float
    ) -> bool | None:
        value = metric[key]
        return None if value is None else bool(float(value) >= threshold)

    call_present = calls["expected"] > 0
    control_present = controls["expected"] > 0
    semantic_present = semantics["expected"] > 0
    framework_segments = _segments(repositories, "frameworks")
    domain_segments = _segments(repositories, "domains")

    def population_check(
        metrics: list[dict[str, Any]], key: str, threshold: float
    ) -> bool:
        relevant = [
            metric for metric in metrics if metric["expected"] or metric["actual"]
        ]
        return bool(relevant) and all(
            metric[key] is not None and float(metric[key]) >= threshold
            for metric in relevant
        )

    repository_findings = [
        repo["features"]["finding_detection"] for repo in repositories
    ]
    framework_findings = [
        segment["features"]["finding_detection"]
        for segment in framework_segments.values()
    ]
    domain_findings = [
        segment["features"]["finding_detection"]
        for segment in domain_segments.values()
    ]
    call_populations = [
        repo["features"]["call_resolution"] for repo in repositories
    ]
    control_populations = [
        repo["features"]["control_detection"] for repo in repositories
    ]
    semantic_populations = [
        repo["features"]["semantic_output"] for repo in repositories
    ]
    checks: dict[str, bool | None] = {
        "artifact_bindings": True,
        "evaluation_regeneration": True,
        "no_duplicate_candidates": all(
            repo["quality"]["duplicate_count"] == 0 for repo in repositories
        ),
        "no_unsupported_verification_claims": all(
            repo["quality"]["unsupported_verification_claim_count"] == 0
            for repo in repositories
        ),
        "source_localization_complete": complete_quality(
            "source_localization_accuracy"
        ),
        "traceability_complete": complete_quality("traceability_integrity"),
        "adapter_provenance_complete": complete_quality(
            "adapter_provenance_coverage", optional=True
        ),
        "repository_source_accounting_complete": complete_quality(
            "repository_source_accounting"
        ),
        "citation_links_valid": complete_quality(
            "citation_link_accuracy", optional=True
        ),
        "campaign_governance": governance_result["qualification_ready_claim"],
        "independent_corpora": all(
            repo["corpus_governance_qualification_ready"] for repo in repositories
        ),
        "minimum_repositories": len(repositories)
        >= thresholds["minimum_repositories"],
        "minimum_frameworks": len(frameworks) >= thresholds["minimum_frameworks"],
        "minimum_domains": len(domains) >= thresholds["minimum_domains"],
        "minimum_expected_findings": finding["expected"]
        >= thresholds["minimum_expected_findings"],
        "finding_recall": metric_check(
            finding, "recall", thresholds["minimum_finding_recall"]
        ),
        "finding_precision": metric_check(
            finding, "precision", thresholds["minimum_finding_precision"]
        ),
        "repository_finding_cases_present": all(
            metric["expected"] > 0 for metric in repository_findings
        ),
        "repository_finding_recall": population_check(
            repository_findings, "recall", thresholds["minimum_finding_recall"]
        ),
        "repository_finding_precision": population_check(
            repository_findings, "precision", thresholds["minimum_finding_precision"]
        ),
        "framework_finding_recall": population_check(
            framework_findings, "recall", thresholds["minimum_finding_recall"]
        ),
        "framework_finding_precision": population_check(
            framework_findings, "precision", thresholds["minimum_finding_precision"]
        ),
        "domain_finding_recall": population_check(
            domain_findings, "recall", thresholds["minimum_finding_recall"]
        ),
        "domain_finding_precision": population_check(
            domain_findings, "precision", thresholds["minimum_finding_precision"]
        ),
        "call_cases_present": call_present
        if thresholds["require_call_cases"]
        else None,
        "call_recall": metric_check(
            calls, "recall", thresholds["minimum_call_recall"]
        )
        if call_present
        else None,
        "call_precision": metric_check(
            calls, "precision", thresholds["minimum_call_precision"]
        )
        if call_present
        else None,
        "call_population_recall": population_check(
            call_populations, "recall", thresholds["minimum_call_recall"]
        )
        if call_present
        else None,
        "call_population_precision": population_check(
            call_populations, "precision", thresholds["minimum_call_precision"]
        )
        if call_present
        else None,
        "control_cases_present": control_present
        if thresholds["require_control_cases"]
        else None,
        "control_negative_population": all(
            metric["negative_components"]
            >= thresholds["minimum_control_negative_components_per_repository"]
            for metric in control_populations
            if metric["expected"] > 0
        )
        and any(metric["expected"] > 0 for metric in control_populations)
        if thresholds["minimum_control_negative_components_per_repository"] > 0
        else None,
        "control_recall": metric_check(
            controls, "recall", thresholds["minimum_control_recall"]
        )
        if control_present
        else None,
        "control_precision": metric_check(
            controls, "precision", thresholds["minimum_control_precision"]
        )
        if control_present
        else None,
        "control_population_recall": population_check(
            control_populations, "recall", thresholds["minimum_control_recall"]
        )
        if control_present
        else None,
        "control_population_precision": population_check(
            control_populations, "precision", thresholds["minimum_control_precision"]
        )
        if control_present
        else None,
        "semantic_cases_present": all(
            metric["expected"] > 0 for metric in semantic_populations
        )
        if thresholds["require_semantic_cases"]
        else None,
        "semantic_recall": metric_check(
            semantics, "recall", thresholds["minimum_semantic_recall"]
        )
        if semantic_present
        else None,
        "semantic_precision": metric_check(
            semantics, "precision", thresholds["minimum_semantic_precision"]
        )
        if semantic_present
        else None,
        "semantic_population_recall": population_check(
            semantic_populations, "recall", thresholds["minimum_semantic_recall"]
        )
        if semantic_present
        else None,
        "semantic_population_precision": population_check(
            semantic_populations, "precision", thresholds["minimum_semantic_precision"]
        )
        if semantic_present
        else None,
    }
    eligible = all(value is not False for value in checks.values())
    return {
        "governance": governance_result,
        "summary": {
            "repository_count": len(repositories),
            "framework_count": len(frameworks),
            "domain_count": len(domains),
            "frameworks": frameworks,
            "domains": domains,
            "independently_governed_corpora": sum(
                repo["corpus_governance_qualification_ready"]
                for repo in repositories
            ),
        },
        "features": features,
        "by_rule": _aggregate_named(repositories, "by_rule"),
        "by_call_resolution": _aggregate_named(
            repositories, "by_call_resolution"
        ),
        "by_control_kind": _aggregate_named(repositories, "by_control_kind"),
        "by_semantic_field": _aggregate_named(
            repositories, "by_semantic_field"
        ),
        "by_semantic_rule": _aggregate_named(repositories, "by_semantic_rule"),
        "segments": {
            "frameworks": framework_segments,
            "domains": domain_segments,
        },
        "checks": checks,
        "eligible_for_independent_review": eligible,
        "status": (
            "eligible_for_independent_review"
            if eligible
            else "qualification_evidence_incomplete"
        ),
    }


def build_qualification_campaign(source: str | Path) -> dict[str, Any]:
    """Regenerate and aggregate every exact-bound repository evaluation."""

    document = load_qualification_campaign_manifest(source)
    manifest = document.value
    manifest_root = document.path.parent
    repositories = [
        _load_repository(entry, manifest_root) for entry in manifest["repositories"]
    ]
    for artifact_name in ("analysis", "corpus"):
        digests = [
            repository["artifacts"][artifact_name]["canonical_sha256"]
            for repository in repositories
        ]
        if len(digests) != len(set(digests)):
            raise ValueError(
                f"qualification campaign reuses one {artifact_name} artifact across repositories"
            )
    projection = _projection(
        manifest["governance"], manifest["thresholds"], repositories
    )
    result = {
        "format": QUALIFICATION_CAMPAIGN_RESULT_FORMAT,
        "tool": {"name": "PySFMEA", "version": __version__},
        "campaign": {
            "id": manifest["id"],
            "title": manifest["title"],
            "purpose": manifest["purpose"],
        },
        "manifest": {
            "reference": document.path.name,
            "bytes": document.size,
            "sha256": hashlib.sha256(document.raw).hexdigest(),
            "canonical_sha256": canonical_json_sha256(manifest),
        },
        "thresholds": copy.deepcopy(manifest["thresholds"]),
        "repositories": repositories,
        **projection,
        "notice": (
            "This campaign verifies retained inputs and aggregates exact labeled outcomes. "
            "Eligibility advances evidence to independent review; it is not tool qualification, "
            "certification, representative-population proof, or release approval."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    rendered_size = len(
        (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    )
    if rendered_size > MAX_QUALIFICATION_RESULT_BYTES:
        raise ValueError(
            "qualification campaign result exceeds the supported publication byte limit"
        )
    return result


def load_qualification_campaign_result(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="qualification campaign result",
        max_bytes=MAX_QUALIFICATION_RESULT_BYTES,
        max_depth=80,
        max_nodes=1_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("qualification campaign result must be a JSON object")
    return document.value


def _validate_binding(value: Any, *, label: str) -> None:
    fields = {"reference", "bytes", "sha256", "canonical_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} binding fields do not match format 1")
    _text(value["reference"], label=f"{label} reference")
    _count(value["bytes"], label=f"{label} bytes")
    for field in ("sha256", "canonical_sha256"):
        if not isinstance(value[field], str) or not re.fullmatch(
            r"[0-9a-f]{64}", value[field]
        ):
            raise ValueError(f"{label} {field} must be a lowercase SHA-256 digest")


def _validate_metric(
    value: Any,
    *,
    label: str,
    aggregate: bool,
    control_population: bool = False,
) -> None:
    fields = {"expected", "actual", "matched", "recall", "precision"}
    if aggregate:
        fields.add("repositories")
    if control_population:
        fields.update(CONTROL_POPULATION_KEYS)
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields do not match format 1")
    expected = _feature(value["expected"], value["actual"], value["matched"])
    if any(value[field] != expected[field] for field in expected):
        raise ValueError(f"{label} rates do not reconcile with counts")
    if aggregate:
        _count(value["repositories"], label=f"{label} repositories")
    if control_population:
        population = {
            field: _count(value[field], label=f"{label} {field}")
            for field in CONTROL_POPULATION_KEYS
        }
        if (
            population["positive_components"]
            + population["negative_components"]
            != population["evaluated_components"]
        ):
            raise ValueError(f"{label} control population counts do not reconcile")


def _validate_metric_map(value: Any, *, label: str, aggregate: bool) -> None:
    if (
        not isinstance(value, dict)
        or len(value) > 20_000
        or not all(isinstance(key, str) and isinstance(metric, dict) for key, metric in value.items())
    ):
        raise ValueError(f"{label} must be a bounded metric map")
    for key, metric in value.items():
        _text(key, label=f"{label} key")
        _validate_metric(metric, label=f"{label} {key}", aggregate=aggregate)


def _validate_features(value: Any, *, label: str, aggregate: bool) -> None:
    if not isinstance(value, dict) or set(value) != set(FEATURE_KEYS):
        raise ValueError(f"{label} must contain the closed feature set")
    for key in FEATURE_KEYS:
        _validate_metric(
            value[key],
            label=f"{label} {key}",
            aggregate=aggregate,
            control_population=key == "control_detection",
        )


def _validate_result_repository(value: dict[str, Any], *, index: int) -> None:
    label = f"result repository {index}"
    fields = {
        "id",
        "frameworks",
        "domains",
        "selection_rationale",
        "analysis_state_sha256",
        "corpus_governance_qualification_ready",
        "corpus_governance",
        "evaluation_verifier",
        "quality",
        "artifacts",
        "features",
        "by_rule",
        "by_call_resolution",
        "by_control_kind",
        "by_semantic_field",
        "by_semantic_rule",
    }
    if set(value) != fields:
        raise ValueError(f"{label} fields do not match format 1")
    _identifier(value["id"], label=f"{label} ID")
    _labels(value["frameworks"], label=f"{label} frameworks")
    _labels(value["domains"], label=f"{label} domains")
    _text(value["selection_rationale"], label=f"{label} selection rationale")
    if not isinstance(value["analysis_state_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["analysis_state_sha256"]
    ):
        raise ValueError(f"{label} analysis state digest is malformed")
    if not isinstance(value["corpus_governance_qualification_ready"], bool):
        raise ValueError(f"{label} corpus governance readiness must be boolean")
    governance = value["corpus_governance"]
    governance_fields = {
        "independent",
        "repositories",
        "labeled_by",
        "approved_by",
        "approval_date",
        "qualification_ready",
        "authority",
    }
    if not isinstance(governance, dict) or set(governance) != governance_fields:
        raise ValueError(f"{label} corpus governance fields do not match format 1")
    if not isinstance(governance["independent"], bool) or not isinstance(
        governance["qualification_ready"], bool
    ):
        raise ValueError(f"{label} corpus governance flags must be boolean")
    corpus_repositories = governance["repositories"]
    if (
        not isinstance(corpus_repositories, list)
        or len(corpus_repositories) > MAX_QUALIFICATION_LABELS
        or not all(isinstance(entry, str) for entry in corpus_repositories)
    ):
        raise ValueError(f"{label} corpus repositories must be a bounded text array")
    normalized_repositories = [
        _text(entry, label=f"{label} corpus repository")
        for entry in corpus_repositories
    ]
    if len(normalized_repositories) != len(set(normalized_repositories)):
        raise ValueError(f"{label} corpus repositories must not contain duplicates")
    for field in ("labeled_by", "approved_by", "approval_date", "authority"):
        _text(governance[field], label=f"{label} corpus governance {field}", required=False)
    if value["corpus_governance_qualification_ready"] != governance["qualification_ready"]:
        raise ValueError(f"{label} corpus governance readiness does not reconcile")
    verifier = value["evaluation_verifier"]
    if not isinstance(verifier, dict) or set(verifier) != {"name", "version"}:
        raise ValueError(f"{label} evaluation verifier is malformed")
    _text(verifier["name"], label=f"{label} verifier name")
    _text(verifier["version"], label=f"{label} verifier version")
    quality = value["quality"]
    quality_fields = {
        "duplicate_count",
        "unsupported_verification_claim_count",
        "source_localization_accuracy",
        "citation_link_accuracy",
        "traceability_integrity",
        "adapter_provenance_coverage",
        "repository_source_accounting",
    }
    if not isinstance(quality, dict) or set(quality) != quality_fields:
        raise ValueError(f"{label} quality fields do not match format 1")
    for field in ("duplicate_count", "unsupported_verification_claim_count"):
        _count(quality[field], label=f"{label} quality {field}")
    for field in quality_fields - {
        "duplicate_count",
        "unsupported_verification_claim_count",
    }:
        if quality[field] is not None:
            _ratio(quality[field], label=f"{label} quality {field}")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "analysis",
        "corpus",
        "evaluation",
    }:
        raise ValueError(f"{label} artifacts do not match the closed set")
    for artifact_name, binding in artifacts.items():
        _validate_binding(binding, label=f"{label} {artifact_name}")
    _validate_features(value["features"], label=f"{label} features", aggregate=False)
    for field in (
        "by_rule",
        "by_call_resolution",
        "by_control_kind",
        "by_semantic_field",
        "by_semantic_rule",
    ):
        _validate_metric_map(value[field], label=f"{label} {field}", aggregate=False)


def _validate_result_contract(
    result: dict[str, Any], repositories: list[dict[str, Any]], thresholds: dict[str, Any]
) -> None:
    tool = result.get("tool")
    if (
        not isinstance(tool, dict)
        or set(tool) != {"name", "version"}
        or tool.get("name") != "PySFMEA"
    ):
        raise ValueError("result tool identity is malformed")
    _text(tool["version"], label="result tool version")
    campaign = result.get("campaign")
    if not isinstance(campaign, dict) or set(campaign) != {"id", "title", "purpose"}:
        raise ValueError("result campaign identity is malformed")
    _identifier(campaign["id"], label="result campaign ID")
    _text(campaign["title"], label="result campaign title")
    _text(campaign["purpose"], label="result campaign purpose")
    _validate_binding(result.get("manifest"), label="result manifest")
    for field in (
        "minimum_repositories",
        "minimum_frameworks",
        "minimum_domains",
        "minimum_expected_findings",
        "minimum_control_negative_components_per_repository",
    ):
        _count(thresholds[field], label=f"result threshold {field}")
    for field in (
        "minimum_finding_recall",
        "minimum_finding_precision",
        "minimum_call_recall",
        "minimum_call_precision",
        "minimum_control_recall",
        "minimum_control_precision",
        "minimum_semantic_recall",
        "minimum_semantic_precision",
    ):
        _ratio(thresholds[field], label=f"result threshold {field}")
    for field in (
        "require_call_cases",
        "require_control_cases",
        "require_semantic_cases",
    ):
        if not isinstance(thresholds[field], bool):
            raise ValueError(f"result threshold {field} must be boolean")
    for index, repository in enumerate(repositories, start=1):
        _validate_result_repository(repository, index=index)
    identifiers = [repository["id"] for repository in repositories]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("result repository IDs must be unique")
    for artifact_name in ("analysis", "corpus"):
        digests = [
            repository["artifacts"][artifact_name]["canonical_sha256"]
            for repository in repositories
        ]
        if len(digests) != len(set(digests)):
            raise ValueError(f"result reuses one {artifact_name} artifact")


def verify_qualification_campaign(
    result: dict[str, Any], *, manifest: str | Path | None = None
) -> dict[str, Any]:
    """Verify result integrity and optionally perform exact artifact regeneration."""

    errors: list[str] = []
    required = {
        "format",
        "tool",
        "campaign",
        "manifest",
        "thresholds",
        "governance",
        "repositories",
        "summary",
        "features",
        "by_rule",
        "by_call_resolution",
        "by_control_kind",
        "by_semantic_field",
        "by_semantic_rule",
        "segments",
        "checks",
        "eligible_for_independent_review",
        "status",
        "notice",
        "content_sha256",
    }
    structure = set(result) == required
    if not structure:
        errors.append("result fields do not match qualification campaign format 1")
    if result.get("format") != QUALIFICATION_CAMPAIGN_RESULT_FORMAT:
        structure = False
        errors.append("qualification campaign result format is unsupported")
    repositories = result.get("repositories")
    thresholds = result.get("thresholds")
    governance = result.get("governance")
    if (
        not isinstance(repositories, list)
        or not repositories
        or len(repositories) > MAX_QUALIFICATION_REPOSITORIES
        or not all(isinstance(entry, dict) for entry in repositories)
    ):
        structure = False
        errors.append("result repositories must be a non-empty bounded object array")
        repositories = []
    if not isinstance(thresholds, dict) or set(thresholds) != _THRESHOLD_FIELDS:
        structure = False
        errors.append("result thresholds do not match the closed threshold set")
        thresholds = {}
    if not isinstance(governance, dict):
        structure = False
        errors.append("result governance must be an object")
        governance = {}
    elif set(governance) != {
        "independent",
        "labeled_by",
        "approved_by",
        "approval_date",
        "selection_method",
        "representativeness_rationale",
        "qualification_ready_claim",
        "authority",
    }:
        structure = False
        errors.append("result governance fields do not match format 1")
    checks = result.get("checks")
    if (
        not isinstance(checks, dict)
        or set(checks) != set(QUALIFICATION_CHECKS)
        or not all(value in {True, False, None} for value in checks.values())
    ):
        structure = False
        errors.append("result checks do not match the closed qualification check set")
    if structure:
        try:
            _validate_result_contract(result, repositories, thresholds)
        except (KeyError, TypeError, ValueError) as exc:
            structure = False
            errors.append(f"qualification campaign structure is malformed: {exc}")

    unsigned = copy.deepcopy(result)
    declared_content_sha256 = str(unsigned.pop("content_sha256", ""))
    actual_content_sha256 = canonical_json_sha256(unsigned)
    content_integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", declared_content_sha256)
        and declared_content_sha256 == actual_content_sha256
    )
    if not content_integrity:
        errors.append("qualification campaign content digest does not match")

    semantic_consistency = False
    if structure:
        try:
            source_governance = {
                field: governance[field]
                for field in (
                    "independent",
                    "labeled_by",
                    "approved_by",
                    "approval_date",
                    "selection_method",
                    "representativeness_rationale",
                )
            }
            expected = _projection(source_governance, thresholds, repositories)
            semantic_fields = {
                "governance",
                "summary",
                "features",
                "by_rule",
                "by_call_resolution",
                "by_control_kind",
                "by_semantic_field",
                "by_semantic_rule",
                "segments",
                "checks",
                "eligible_for_independent_review",
                "status",
            }
            semantic_consistency = all(
                result.get(field) == expected[field] for field in semantic_fields
            )
            if not semantic_consistency:
                errors.append("qualification campaign aggregates do not reconcile")
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"qualification campaign semantics are malformed: {exc}")

    manifest_binding: bool | None = None
    exact_regeneration: bool | None = None
    if manifest is not None:
        try:
            manifest_document = load_qualification_campaign_manifest(manifest)
            binding = result.get("manifest", {})
            manifest_binding = bool(
                isinstance(binding, dict)
                and binding.get("reference") == manifest_document.path.name
                and binding.get("bytes") == manifest_document.size
                and binding.get("sha256")
                == hashlib.sha256(manifest_document.raw).hexdigest()
                and binding.get("canonical_sha256")
                == canonical_json_sha256(manifest_document.value)
            )
            if not manifest_binding:
                errors.append("qualification manifest binding does not match")
            regenerated = build_qualification_campaign(manifest_document.path)
            exact_regeneration = canonical_json_sha256(regenerated) == canonical_json_sha256(
                result
            )
            if not exact_regeneration:
                errors.append("qualification campaign does not exactly regenerate")
        except (OSError, ValueError) as exc:
            manifest_binding = False
            exact_regeneration = False
            errors.append(f"qualification campaign regeneration failed: {exc}")

    valid = structure and content_integrity and semantic_consistency
    reconciled = bool(valid and manifest_binding and exact_regeneration)
    eligible = bool(result.get("eligible_for_independent_review")) if valid else False
    return {
        "format": QUALIFICATION_CAMPAIGN_VERIFICATION_FORMAT,
        "valid": valid,
        "reconciled": reconciled,
        "eligible_for_independent_review": eligible,
        "mode": "complete" if manifest is not None else "integrity_only",
        "checks": {
            "structure": structure,
            "content_integrity": content_integrity,
            "semantic_consistency": semantic_consistency,
            "manifest_binding": manifest_binding,
            "exact_regeneration": exact_regeneration,
        },
        "declared_content_sha256": declared_content_sha256,
        "actual_content_sha256": actual_content_sha256,
        "errors": errors,
        "notice": (
            "Complete reconciliation proves exact retained-artifact regeneration under the "
            "current verifier. It does not authenticate reviewers, prove corpus "
            "representativeness, or approve qualification."
        ),
        "path": "",
        "source_bytes": 0,
        "source_sha256": "",
    }


def _rejection(message: str, *, path: str = "") -> dict[str, Any]:
    return {
        "format": QUALIFICATION_CAMPAIGN_VERIFICATION_FORMAT,
        "valid": False,
        "reconciled": False,
        "eligible_for_independent_review": False,
        "mode": "rejected",
        "checks": {
            "structure": False,
            "content_integrity": False,
            "semantic_consistency": False,
            "manifest_binding": None,
            "exact_regeneration": None,
        },
        "declared_content_sha256": "",
        "actual_content_sha256": "",
        "errors": [message],
        "notice": (
            "The qualification campaign result was unavailable or malformed and receives "
            "no evidence credit."
        ),
        "path": path,
        "source_bytes": 0,
        "source_sha256": "",
    }


def verify_qualification_campaign_file(
    source: str | Path, *, manifest: str | Path | None = None
) -> dict[str, Any]:
    path = Path(source).expanduser().absolute()
    try:
        document = load_bounded_json_document(
            path,
            label="qualification campaign result",
            max_bytes=MAX_QUALIFICATION_RESULT_BYTES,
            max_depth=80,
            max_nodes=1_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("qualification campaign result must be a JSON object")
        verdict = verify_qualification_campaign(document.value, manifest=manifest)
        verdict["path"] = str(document.path)
        verdict["source_bytes"] = document.size
        verdict["source_sha256"] = hashlib.sha256(document.raw).hexdigest()
        return verdict
    except (OSError, ValueError) as exc:
        return _rejection(str(exc), path=str(path))


def qualification_validation_cohorts(
    result_source: str | Path,
    manifest_source: str | Path,
    *,
    program_destination: str | Path,
) -> list[dict[str, Any]]:
    """Project a completely reconciled campaign into assurance-program cohorts."""

    result = load_qualification_campaign_result(result_source)
    verdict = verify_qualification_campaign(result, manifest=manifest_source)
    if not verdict["reconciled"]:
        detail = "; ".join(verdict["errors"][:5]) or "reconciliation failed"
        raise ValueError(
            f"qualification campaign must completely reconcile before import: {detail}"
        )
    manifest_document = load_qualification_campaign_manifest(manifest_source)
    manifest_binding = result["manifest"]
    if (
        manifest_binding["sha256"]
        != hashlib.sha256(manifest_document.raw).hexdigest()
        or manifest_binding["canonical_sha256"]
        != canonical_json_sha256(manifest_document.value)
    ):
        raise ValueError("qualification manifest changed after campaign verification")
    manifest_repositories = {
        entry["id"]: entry for entry in manifest_document.value["repositories"]
    }
    program_root = Path(program_destination).expanduser().absolute().parent

    def program_reference(path: Path) -> str:
        try:
            return Path(os.path.relpath(path, program_root)).as_posix()
        except ValueError:
            return str(path)

    cohorts: list[dict[str, Any]] = []
    for repository in result["repositories"]:
        repository_id = repository["id"]
        manifest_repository = manifest_repositories.get(repository_id)
        if manifest_repository is None:
            raise ValueError(
                f"qualification repository {repository_id} is absent from the manifest"
            )
        governance = repository["corpus_governance"]
        if not repository["corpus_governance_qualification_ready"]:
            raise ValueError(
                f"qualification repository {repository_id} lacks an independently governed corpus"
            )
        quality = repository["quality"]
        if quality["duplicate_count"] or quality[
            "unsupported_verification_claim_count"
        ]:
            raise ValueError(
                f"qualification repository {repository_id} has disqualifying evaluation findings"
            )
        finding = repository["features"]["finding_detection"]
        if (
            finding["expected"] < 1
            or finding["recall"] is None
            or finding["precision"] is None
        ):
            raise ValueError(
                f"qualification repository {repository_id} lacks complete finding metrics"
            )
        evaluation_reference = str(manifest_repository["evaluation"])
        evaluation_path = _artifact_path(
            manifest_document.path.parent, evaluation_reference
        )
        evaluation_binding = repository["artifacts"]["evaluation"]
        if evaluation_binding["reference"] != evaluation_reference:
            raise ValueError(
                f"qualification repository {repository_id} evaluation reference changed"
            )
        frameworks = repository["frameworks"]
        cohort_id = f"QUAL.{result['campaign']['id']}.{repository_id}"
        if len(cohort_id) > 200:
            cohort_id = (
                cohort_id[:183]
                + "."
                + hashlib.sha256(cohort_id.encode("utf-8")).hexdigest()[:16]
            )
        for role in ("labeled_by", "approved_by"):
            if len(governance[role]) > 2_000:
                raise ValueError(
                    f"qualification repository {repository_id} {role} exceeds the assurance-program limit"
                )
        cohort: dict[str, Any] = {
            "id": cohort_id,
            "repository": repository_id,
            "framework": (
                frameworks[0] + (f" (+{len(frameworks) - 1})" if len(frameworks) > 1 else "")
                if frameworks
                else "unclassified"
            ),
            "corpus_sha256": repository["artifacts"]["corpus"][
                "canonical_sha256"
            ],
            "case_count": finding["expected"],
            "recall": finding["recall"],
            "precision": finding["precision"],
            "matched_count": finding["matched"],
            "actual_matched_count": finding["matched"],
            "actual_count": finding["actual"],
            "evaluation_result_format": "pysfmea-evaluation-result-1",
            "evaluation_result_sha256": evaluation_binding["canonical_sha256"],
            "evaluation_verifier_version": repository["evaluation_verifier"][
                "version"
            ],
            "evaluation_result_artifact": {
                "path": program_reference(evaluation_path),
                "sha256": evaluation_binding["sha256"],
            },
            "independent_reviewed": True,
            "producer": governance["labeled_by"],
            "reviewer": governance["approved_by"],
        }
        calls = repository["features"]["call_resolution"]
        if calls["expected"]:
            if calls["recall"] is None or calls["precision"] is None:
                raise ValueError(
                    f"qualification repository {repository_id} lacks complete call metrics"
                )
            cohort.update(
                {
                    "call_case_count": calls["expected"],
                    "call_resolution_recall": calls["recall"],
                    "call_resolution_precision": calls["precision"],
                    "call_matched_count": calls["matched"],
                    "call_actual_matched_count": calls["matched"],
                    "call_actual_count": calls["actual"],
                }
            )
        cohorts.append(cohort)
    return cohorts
