"""Industry-validation portfolio across independent benchmark and evidence types.

The portfolio does not create independence, accreditation, or regulatory
acceptance.  It makes the evidence population, external-suite provenance,
comparator baselines, runtime coverage, receiving-tool round trips, usability,
formal verification, and continuity exercises explicit and fail-visible.
"""

from __future__ import annotations

import copy
import hashlib
import re
from pathlib import Path
from typing import Any

from .benchmark_v2 import verify_benchmark_v2_assessment_file
from .coverage_observation import verify_runtime_coverage_observation_file
from .governed_artifact import (
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_seal,
)
from .interoperability_validation import verify_independent_roundtrip_evidence_file
from .json_ingestion import load_bounded_json_document
from .model import utc_now

VALIDATION_PORTFOLIO_SOURCE_FORMAT = "pysfmea-industry-validation-portfolio-source-1"
VALIDATION_PORTFOLIO_ASSESSMENT_FORMAT = (
    "pysfmea-industry-validation-portfolio-assessment-1"
)
VALIDATION_PORTFOLIO_VERIFICATION_FORMAT = (
    "pysfmea-industry-validation-portfolio-verification-1"
)
SUITE_TYPES = frozenset({"executable_synthetic", "real_world_defect", "field_repository"})
MAX_ITEMS = 10_000


def validation_portfolio_template(*, authority: str) -> dict[str, Any]:
    """Create a closed, conservative portfolio authoring template."""

    result = {
        "format": VALIDATION_PORTFOLIO_SOURCE_FORMAT,
        "generated_at": utc_now(),
        "authority": {
            "portfolio_owner": bounded_text(authority, "portfolio authority"),
            "verification_authority": "replace-with-independent-verification-authority",
            "approval_authority": "replace-with-authorized-approval-authority",
            "independence_basis": "replace-with-organizational-and-reporting-line-separation",
        },
        "product": {
            "name": "PySFMEA",
            "version": "replace-with-qualified-version",
            "intended_use": "replace-with-qualified-intended-use",
            "operational_scope": "replace-with-represented-python-population",
        },
        "policy": {
            "minimum_benchmark_suites": 2,
            "required_suite_types": ["executable_synthetic", "real_world_defect"],
            "minimum_comparator_tools": 2,
            "required_interoperability_formats": [],
            "runtime_coverage_required": True,
            "usability_required": True,
            "minimum_usability_participants": 5,
            "maximum_critical_use_errors": 0,
            "formal_methods_required": False,
            "continuity_exercise_required": False,
        },
        "benchmark_assessment_paths": [],
        "benchmark_suites": [],
        "comparator_observations": [],
        "runtime_coverage_paths": [],
        "roundtrip_evidence": [],
        "usability_studies": [],
        "formal_verification_records": [],
        "continuity_exercises": [],
        "evidence_refs": [],
        "limitations": [],
        "notice": (
            "Populate exact evidence and reseal. Passing means the declared portfolio is "
            "complete under its policy; it is not accreditation, qualification, or certification."
        ),
    }
    return seal(result)


def _identifier(value: Any, label: str) -> str:
    text = bounded_text(value, label)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", text):
        raise ValueError(f"{label} is not a portable identifier")
    return text


def _digest(value: Any, label: str) -> str:
    text = bounded_text(value, label)
    if not re.fullmatch(r"[0-9a-f]{64}", text) or text == "0" * 64:
        raise ValueError(f"{label} must be a non-placeholder lowercase SHA-256 digest")
    return text


def _nonnegative(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _ratio(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0.0 <= float(value) <= 1.0
    ):
        raise ValueError(f"{label} must be between zero and one")
    return float(value)


def _placeholder(value: str) -> bool:
    return not value or value.startswith("replace-")


def _source(value: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(
        value,
        label="industry validation portfolio",
        format_value=VALIDATION_PORTFOLIO_SOURCE_FORMAT,
    )
    required = {
        "format", "generated_at", "authority", "product", "policy",
        "benchmark_assessment_paths", "benchmark_suites", "comparator_observations",
        "runtime_coverage_paths", "roundtrip_evidence", "usability_studies",
        "formal_verification_records", "continuity_exercises", "evidence_refs",
        "limitations", "notice", "content_sha256",
    }
    if set(result) != required:
        raise ValueError("industry validation portfolio fields are invalid")
    authority = result["authority"]
    authority_fields = {
        "portfolio_owner", "verification_authority", "approval_authority", "independence_basis"
    }
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        raise ValueError("portfolio authority fields are invalid")
    for field in authority_fields:
        bounded_text(authority[field], f"portfolio authority {field}")
    product = result["product"]
    product_fields = {"name", "version", "intended_use", "operational_scope"}
    if not isinstance(product, dict) or set(product) != product_fields:
        raise ValueError("portfolio product fields are invalid")
    for field in product_fields:
        bounded_text(product[field], f"portfolio product {field}")
    policy = result["policy"]
    policy_fields = {
        "minimum_benchmark_suites", "required_suite_types", "minimum_comparator_tools",
        "required_interoperability_formats", "runtime_coverage_required",
        "usability_required", "minimum_usability_participants",
        "maximum_critical_use_errors", "formal_methods_required",
        "continuity_exercise_required",
    }
    if not isinstance(policy, dict) or set(policy) != policy_fields:
        raise ValueError("portfolio policy fields are invalid")
    for field in (
        "minimum_benchmark_suites", "minimum_comparator_tools",
        "minimum_usability_participants", "maximum_critical_use_errors",
    ):
        _nonnegative(policy[field], f"portfolio policy {field}")
    if policy["minimum_benchmark_suites"] < 2:
        raise ValueError("industry portfolio requires at least two benchmark suites")
    if policy["minimum_comparator_tools"] < 2:
        raise ValueError("industry portfolio requires at least two comparator tools")
    if policy["usability_required"] and policy["minimum_usability_participants"] < 5:
        raise ValueError("required usability evaluation needs at least five participants")
    required_types = set(unique_text_list(policy["required_suite_types"], "required suite types"))
    if not required_types or not required_types <= SUITE_TYPES:
        raise ValueError("required benchmark suite types are invalid")
    unique_text_list(
        policy["required_interoperability_formats"],
        "required interoperability formats",
    )
    for field in (
        "runtime_coverage_required", "usability_required", "formal_methods_required",
        "continuity_exercise_required",
    ):
        if type(policy[field]) is not bool:
            raise ValueError(f"portfolio policy {field} must be boolean")
    for field in ("benchmark_assessment_paths", "runtime_coverage_paths"):
        unique_text_list(result[field], field, maximum=MAX_ITEMS)
    unique_text_list(result["evidence_refs"], "portfolio evidence refs", maximum=MAX_ITEMS)
    unique_text_list(result["limitations"], "portfolio limitations", maximum=MAX_ITEMS)
    bounded_text(result["notice"], "portfolio notice")

    suites = result["benchmark_suites"]
    if not isinstance(suites, list) or len(suites) > MAX_ITEMS:
        raise ValueError("benchmark suite records are invalid")
    suite_ids: list[str] = []
    repository_ids: set[str] = set()
    suite_fields = {
        "id", "title", "publisher", "version", "suite_type", "language",
        "source_uri", "source_sha256", "license", "taxonomy", "repository_ids",
        "label_authority", "evidence_ref",
    }
    for suite in suites:
        if not isinstance(suite, dict) or set(suite) != suite_fields:
            raise ValueError("benchmark suite fields are invalid")
        suite_id = _identifier(suite["id"], "benchmark suite id")
        suite_ids.append(suite_id)
        for field in suite_fields - {"id", "repository_ids", "taxonomy", "source_sha256"}:
            bounded_text(suite[field], f"benchmark suite {field}")
        _digest(suite["source_sha256"], "benchmark suite source digest")
        if suite["suite_type"] not in SUITE_TYPES:
            raise ValueError("benchmark suite type is invalid")
        taxonomy = unique_text_list(suite["taxonomy"], "benchmark suite taxonomy")
        repositories = unique_text_list(suite["repository_ids"], "benchmark suite repository ids")
        if not taxonomy or not repositories:
            raise ValueError("benchmark suite taxonomy and repository ids must not be empty")
        if repository_ids & set(repositories):
            raise ValueError("benchmark repositories must belong to exactly one suite")
        repository_ids.update(repositories)
    if len(suite_ids) != len(set(suite_ids)):
        raise ValueError("benchmark suite ids must be unique")

    comparators = result["comparator_observations"]
    if not isinstance(comparators, list) or len(comparators) > MAX_ITEMS:
        raise ValueError("comparator observations are invalid")
    comparator_ids: list[str] = []
    comparator_fields = {
        "id", "tool", "version", "runner", "independence_basis", "suite_ids",
        "metrics", "raw_result_ref", "raw_result_sha256",
    }
    for item in comparators:
        if not isinstance(item, dict) or set(item) != comparator_fields:
            raise ValueError("comparator observation fields are invalid")
        comparator_ids.append(_identifier(item["id"], "comparator observation id"))
        for field in ("tool", "version", "runner", "independence_basis", "raw_result_ref"):
            bounded_text(item[field], f"comparator {field}")
        _digest(item["raw_result_sha256"], "comparator raw result digest")
        linked_suites = unique_text_list(item["suite_ids"], "comparator suite ids")
        if not linked_suites or not set(linked_suites) <= set(suite_ids):
            raise ValueError("comparator references unknown benchmark suites")
        metrics = item["metrics"]
        if not isinstance(metrics, dict) or not metrics or len(metrics) > 100:
            raise ValueError("comparator metrics are invalid")
        for metric_name, counts in metrics.items():
            _identifier(metric_name, "comparator metric")
            if not isinstance(counts, dict) or set(counts) != {
                "true_positive", "false_positive", "false_negative", "true_negative"
            }:
                raise ValueError("comparator metric count fields are invalid")
            for name, count in counts.items():
                _nonnegative(count, f"comparator {metric_name} {name}")
    if len(comparator_ids) != len(set(comparator_ids)):
        raise ValueError("comparator observation ids must be unique")

    roundtrips = result["roundtrip_evidence"]
    if not isinstance(roundtrips, list) or len(roundtrips) > MAX_ITEMS:
        raise ValueError("round-trip evidence records are invalid")
    roundtrip_ids: list[str] = []
    for item in roundtrips:
        if not isinstance(item, dict) or set(item) != {"id", "format_id", "path", "required"}:
            raise ValueError("round-trip evidence fields are invalid")
        roundtrip_ids.append(_identifier(item["id"], "round-trip evidence id"))
        _identifier(item["format_id"], "round-trip format id")
        bounded_text(item["path"], "round-trip evidence path")
        if type(item["required"]) is not bool:
            raise ValueError("round-trip required must be boolean")
    if len(roundtrip_ids) != len(set(roundtrip_ids)):
        raise ValueError("round-trip evidence ids must be unique")

    studies = result["usability_studies"]
    if not isinstance(studies, list) or len(studies) > MAX_ITEMS:
        raise ValueError("usability studies are invalid")
    study_ids: list[str] = []
    study_fields = {
        "id", "method", "operator", "reviewer", "representative_user_basis",
        "participant_count", "task_attempts", "successful_tasks", "critical_use_errors",
        "median_time_seconds", "satisfaction_instrument", "satisfaction_score",
        "minimum_satisfaction_score", "accessibility_evidence_refs", "evidence_refs",
    }
    for study in studies:
        if not isinstance(study, dict) or set(study) != study_fields:
            raise ValueError("usability study fields are invalid")
        study_ids.append(_identifier(study["id"], "usability study id"))
        for field in (
            "method", "operator", "reviewer", "representative_user_basis",
            "satisfaction_instrument",
        ):
            bounded_text(study[field], f"usability study {field}")
        if study["operator"].casefold() == study["reviewer"].casefold():
            raise ValueError("usability study operator and reviewer must be distinct")
        for field in (
            "participant_count", "task_attempts", "successful_tasks", "critical_use_errors"
        ):
            _nonnegative(study[field], f"usability study {field}")
        if study["successful_tasks"] > study["task_attempts"]:
            raise ValueError("successful usability tasks exceed attempts")
        if (
            not isinstance(study["median_time_seconds"], (int, float))
            or isinstance(study["median_time_seconds"], bool)
            or study["median_time_seconds"] <= 0
        ):
            raise ValueError("usability median time must be positive")
        _ratio(study["satisfaction_score"], "usability satisfaction score")
        _ratio(study["minimum_satisfaction_score"], "usability satisfaction threshold")
        unique_text_list(study["accessibility_evidence_refs"], "accessibility evidence refs")
        if not unique_text_list(study["evidence_refs"], "usability evidence refs"):
            raise ValueError("usability study must retain evidence")
    if len(study_ids) != len(set(study_ids)):
        raise ValueError("usability study ids must be unique")

    formal = result["formal_verification_records"]
    if not isinstance(formal, list) or len(formal) > MAX_ITEMS:
        raise ValueError("formal verification records are invalid")
    formal_ids: list[str] = []
    formal_fields = {
        "id", "method", "tool", "version", "model_sha256", "property_count",
        "properties_proved", "counterexample_count", "assumptions", "reviewer",
        "evidence_refs",
    }
    for item in formal:
        if not isinstance(item, dict) or set(item) != formal_fields:
            raise ValueError("formal verification record fields are invalid")
        formal_ids.append(_identifier(item["id"], "formal verification id"))
        for field in ("method", "tool", "version", "reviewer"):
            bounded_text(item[field], f"formal verification {field}")
        _digest(item["model_sha256"], "formal verification model digest")
        for field in ("property_count", "properties_proved", "counterexample_count"):
            _nonnegative(item[field], f"formal verification {field}")
        if item["properties_proved"] > item["property_count"]:
            raise ValueError("proved property count exceeds formal property population")
        if not unique_text_list(item["assumptions"], "formal assumptions"):
            raise ValueError("formal verification assumptions must be explicit")
        if not unique_text_list(item["evidence_refs"], "formal evidence refs"):
            raise ValueError("formal verification evidence must not be empty")
    if len(formal_ids) != len(set(formal_ids)):
        raise ValueError("formal verification ids must be unique")

    exercises = result["continuity_exercises"]
    if not isinstance(exercises, list) or len(exercises) > MAX_ITEMS:
        raise ValueError("continuity exercises are invalid")
    exercise_ids: list[str] = []
    exercise_fields = {
        "id", "scenario", "recovery_time_objective_seconds", "observed_recovery_seconds",
        "recovery_point_objective_seconds", "observed_data_loss_seconds", "critical_services_restored",
        "unresolved_findings", "reviewer", "evidence_refs",
    }
    for item in exercises:
        if not isinstance(item, dict) or set(item) != exercise_fields:
            raise ValueError("continuity exercise fields are invalid")
        exercise_ids.append(_identifier(item["id"], "continuity exercise id"))
        for field in ("scenario", "reviewer"):
            bounded_text(item[field], f"continuity exercise {field}")
        for field in (
            "recovery_time_objective_seconds", "observed_recovery_seconds",
            "recovery_point_objective_seconds", "observed_data_loss_seconds",
            "unresolved_findings",
        ):
            _nonnegative(item[field], f"continuity exercise {field}")
        if type(item["critical_services_restored"]) is not bool:
            raise ValueError("continuity service restoration must be boolean")
        if not unique_text_list(item["evidence_refs"], "continuity evidence refs"):
            raise ValueError("continuity exercise evidence must not be empty")
    if len(exercise_ids) != len(set(exercise_ids)):
        raise ValueError("continuity exercise ids must be unique")
    return copy.deepcopy(result)


def seal_validation_portfolio_source(
    source: str | Path, destination: str | Path
) -> Path:
    value = load_json(source, label="industry validation portfolio")
    validated = _source(seal(value))
    return publish_json(validated, destination)


def _artifact(
    path: Path,
    label: str,
    *,
    reference: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    document = load_bounded_json_document(
        path,
        label=label,
        max_bytes=100 * 1024 * 1024,
        max_depth=160,
        max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError(f"{label} must contain an object")
    return document.value, {
        # Preserve the portfolio's logical reference so a directory containing
        # the source and its evidence can move without changing the assessment.
        # Integrity remains bound to the bytes loaded from the resolved path.
        "reference": reference,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "content_sha256": str(document.value.get("content_sha256", "")),
    }


def _resolve_artifact(base: Path, candidate: str) -> Path:
    supplied = Path(candidate).expanduser()
    if supplied.is_absolute():
        return supplied.resolve()
    resolved = (base / supplied).resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("relative portfolio artifact path escapes the portfolio directory") from exc
    return resolved


def validation_portfolio_assessment(source: str | Path) -> dict[str, Any]:
    source_path = Path(source).expanduser().resolve()
    value = _source(load_json(source_path, label="industry validation portfolio"))
    base = source_path.parent
    artifacts: list[dict[str, Any]] = []
    benchmark_valid = True
    benchmark_passed = True
    benchmark_suite_ids: set[str] = set()
    benchmark_repository_ids: set[str] = set()
    for candidate in value["benchmark_assessment_paths"]:
        path = _resolve_artifact(base, candidate)
        document, binding = _artifact(
            path,
            "benchmark v2 assessment",
            reference=candidate,
        )
        verdict = verify_benchmark_v2_assessment_file(path)
        artifacts.append({"kind": "benchmark_v2", **binding, "valid": verdict["valid"], "passed": verdict["passed"]})
        benchmark_valid = benchmark_valid and verdict["valid"]
        benchmark_passed = benchmark_passed and verdict["passed"]
        suite_dimension = document.get("strata", {}).get("benchmark_suite", {})
        if not isinstance(suite_dimension, dict):
            suite_dimension = {}
        for suite_id, repositories in suite_dimension.items():
            benchmark_suite_ids.add(str(suite_id))
            if isinstance(repositories, list):
                benchmark_repository_ids.update(str(item) for item in repositories)
    suite_ids = {item["id"] for item in value["benchmark_suites"]}
    declared_repository_ids = {
        repository
        for suite in value["benchmark_suites"]
        for repository in suite["repository_ids"]
    }
    suite_types = {item["suite_type"] for item in value["benchmark_suites"]}
    external_suites = all(
        item["publisher"].casefold() not in {"pysfmea", "project-py-sfmea"}
        and item["source_uri"].startswith(("https://", "http://"))
        for item in value["benchmark_suites"]
    )
    suite_trace = bool(
        benchmark_suite_ids
        and benchmark_suite_ids == suite_ids
        and benchmark_repository_ids == declared_repository_ids
    )

    coverage_valid = coverage_passed = True
    for candidate in value["runtime_coverage_paths"]:
        path = _resolve_artifact(base, candidate)
        _, binding = _artifact(
            path,
            "runtime coverage observation",
            reference=candidate,
        )
        verdict = verify_runtime_coverage_observation_file(path)
        artifacts.append({"kind": "runtime_coverage", **binding, "valid": verdict["valid"], "passed": verdict["ready_for_structural_coverage_use"]})
        coverage_valid = coverage_valid and verdict["valid"]
        coverage_passed = coverage_passed and verdict["ready_for_structural_coverage_use"]

    roundtrip_valid = roundtrip_passed = True
    observed_formats: set[str] = set()
    for item in value["roundtrip_evidence"]:
        path_value = item["path"]
        path = _resolve_artifact(base, path_value)
        _, binding = _artifact(
            path,
            "independent round-trip evidence",
            reference=path_value,
        )
        verdict = verify_independent_roundtrip_evidence_file(path)
        artifacts.append({"kind": "roundtrip", "format_id": item["format_id"], **binding, "valid": verdict["valid"], "passed": verdict["passed"]})
        roundtrip_valid = roundtrip_valid and verdict["valid"]
        roundtrip_passed = roundtrip_passed and verdict["passed"]
        if verdict["passed"]:
            observed_formats.add(item["format_id"])

    policy = value["policy"]
    roles = [
        value["authority"][name]
        for name in ("portfolio_owner", "verification_authority", "approval_authority")
    ]
    governance = bool(
        len({item.casefold() for item in roles}) == 3
        and not any(_placeholder(item) for item in roles)
        and not _placeholder(value["authority"]["independence_basis"])
    )
    product_complete = not any(_placeholder(str(item)) for item in value["product"].values())
    required_types = set(policy["required_suite_types"])
    benchmark = bool(
        value["benchmark_assessment_paths"]
        and benchmark_valid
        and benchmark_passed
        and len(value["benchmark_suites"]) >= policy["minimum_benchmark_suites"]
        and required_types <= suite_types
        and external_suites
        and suite_trace
    )
    comparator_tools = {item["tool"].casefold() for item in value["comparator_observations"]}
    comparator_independence = all(
        item["runner"].casefold() not in {"pysfmea", "project-py-sfmea"}
        for item in value["comparator_observations"]
    )
    comparators = bool(
        len(comparator_tools) >= policy["minimum_comparator_tools"]
        and comparator_independence
    )
    runtime_coverage = bool(
        (not value["runtime_coverage_paths"] or (coverage_valid and coverage_passed))
        and (
            not policy["runtime_coverage_required"]
            or bool(value["runtime_coverage_paths"])
        )
    )
    interoperability = bool(
        roundtrip_valid
        and roundtrip_passed
        and set(policy["required_interoperability_formats"]) <= observed_formats
    )
    study_results = []
    for item in value["usability_studies"]:
        pass_state = bool(
            item["participant_count"] >= policy["minimum_usability_participants"]
            and item["task_attempts"] > 0
            and item["successful_tasks"] / item["task_attempts"] >= 0.9
            and item["critical_use_errors"] <= policy["maximum_critical_use_errors"]
            and item["satisfaction_score"] >= item["minimum_satisfaction_score"]
            and item["accessibility_evidence_refs"]
        )
        study_results.append(
            {
                "id": item["id"],
                "participant_count": item["participant_count"],
                "task_attempts": item["task_attempts"],
                "successful_tasks": item["successful_tasks"],
                "task_success_rate": round(
                    item["successful_tasks"] / item["task_attempts"], 6
                )
                if item["task_attempts"]
                else 0.0,
                "critical_use_errors": item["critical_use_errors"],
                "satisfaction_score": item["satisfaction_score"],
                "minimum_satisfaction_score": item["minimum_satisfaction_score"],
                "accessibility_evidence_present": bool(
                    item["accessibility_evidence_refs"]
                ),
                "passed": pass_state,
            }
        )
    usability = bool(
        (not study_results or all(item["passed"] for item in study_results))
        and (not policy["usability_required"] or bool(study_results))
    )
    formal_results = [
        {
            "id": item["id"],
            "property_count": item["property_count"],
            "properties_proved": item["properties_proved"],
            "counterexample_count": item["counterexample_count"],
            "passed": bool(
                item["property_count"] > 0
                and item["properties_proved"] == item["property_count"]
                and item["counterexample_count"] == 0
            ),
        }
        for item in value["formal_verification_records"]
    ]
    formal = bool(
        (not formal_results or all(item["passed"] for item in formal_results))
        and (not policy["formal_methods_required"] or bool(formal_results))
    )
    continuity_results = [
        {
            "id": item["id"],
            "recovery_time_objective_seconds": item[
                "recovery_time_objective_seconds"
            ],
            "observed_recovery_seconds": item["observed_recovery_seconds"],
            "recovery_point_objective_seconds": item[
                "recovery_point_objective_seconds"
            ],
            "observed_data_loss_seconds": item["observed_data_loss_seconds"],
            "critical_services_restored": item["critical_services_restored"],
            "unresolved_findings": item["unresolved_findings"],
            "passed": bool(
                item["critical_services_restored"]
                and item["observed_recovery_seconds"] <= item["recovery_time_objective_seconds"]
                and item["observed_data_loss_seconds"] <= item["recovery_point_objective_seconds"]
                and item["unresolved_findings"] == 0
            ),
        }
        for item in value["continuity_exercises"]
    ]
    continuity = bool(
        (not continuity_results or all(item["passed"] for item in continuity_results))
        and (not policy["continuity_exercise_required"] or bool(continuity_results))
    )
    checks = {
        "governance_separation": governance,
        "product_scope_complete": product_complete,
        "external_composite_benchmark": benchmark,
        "comparator_baselines": comparators,
        "runtime_coverage": runtime_coverage,
        "independent_interoperability": interoperability,
        "representative_usability": usability,
        "formal_verification": formal,
        "continuity_exercise": continuity,
        "portfolio_evidence": bool(value["evidence_refs"]),
    }
    passed = all(checks.values())
    assessment = {
        "format": VALIDATION_PORTFOLIO_ASSESSMENT_FORMAT,
        "generated_at": value["generated_at"],
        "source_sha256": value["content_sha256"],
        "authority": copy.deepcopy(value["authority"]),
        "product": copy.deepcopy(value["product"]),
        "policy": copy.deepcopy(policy),
        "artifacts": artifacts,
        "benchmark": {
            "suite_ids": sorted(suite_ids),
            "suite_types": sorted(suite_types),
            "repository_ids": sorted(declared_repository_ids),
            "external_suite_provenance": external_suites,
            "exact_suite_repository_trace": suite_trace,
            "comparator_tools": sorted(comparator_tools),
            "comparator_independence": comparator_independence,
        },
        "interoperability": {
            "required_formats": sorted(policy["required_interoperability_formats"]),
            "passing_formats": sorted(observed_formats),
        },
        "usability_studies": study_results,
        "formal_verification": formal_results,
        "continuity_exercises": continuity_results,
        "checks": checks,
        "summary": {
            "passed": passed,
            "status": "eligible_for_external_authority_decision" if passed else "evidence_incomplete",
            "checks_passed": sum(checks.values()),
            "checks_required": len(checks),
            "failed_checks": sorted(name for name, state in checks.items() if not state),
            "artifacts": len(artifacts),
        },
        "limitations": copy.deepcopy(value["limitations"]),
        "evidence_refs": copy.deepcopy(value["evidence_refs"]),
        "notice": (
            "Passing proves deterministic accounting over the supplied portfolio. It does not "
            "authenticate people or publishers, establish corpus representativeness, accredit a "
            "laboratory, qualify the tool, accept risk, or grant certification."
        ),
    }
    return seal(assessment)


def verify_validation_portfolio_assessment(
    assessment: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        value = verify_seal(
            assessment,
            label="industry validation portfolio assessment",
            format_value=VALIDATION_PORTFOLIO_ASSESSMENT_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
        value = assessment
        integrity = False
    required = {
        "format", "generated_at", "source_sha256", "authority", "product", "policy",
        "artifacts", "benchmark", "interoperability", "usability_studies",
        "formal_verification", "continuity_exercises", "checks", "summary",
        "limitations", "evidence_refs", "notice", "content_sha256",
    }
    structure = bool(set(value) == required)
    if not structure:
        errors.append("portfolio assessment fields are invalid")
    summary = value.get("summary", {})
    checks = value.get("checks", {})
    try:
        policy = value["policy"]
        authority = value["authority"]
        roles = [
            authority[name]
            for name in (
                "portfolio_owner",
                "verification_authority",
                "approval_authority",
            )
        ]
        artifacts = value["artifacts"]
        benchmark_artifacts = [item for item in artifacts if item["kind"] == "benchmark_v2"]
        coverage_artifacts = [item for item in artifacts if item["kind"] == "runtime_coverage"]
        roundtrip_artifacts = [item for item in artifacts if item["kind"] == "roundtrip"]
        benchmark = value["benchmark"]
        expected_studies = [
            bool(
                item["participant_count"] >= policy["minimum_usability_participants"]
                and item["task_attempts"] > 0
                and item["successful_tasks"] / item["task_attempts"] >= 0.9
                and item["critical_use_errors"] <= policy["maximum_critical_use_errors"]
                and item["satisfaction_score"] >= item["minimum_satisfaction_score"]
                and item["accessibility_evidence_present"]
            )
            for item in value["usability_studies"]
        ]
        expected_formal = [
            bool(
                item["property_count"] > 0
                and item["properties_proved"] == item["property_count"]
                and item["counterexample_count"] == 0
            )
            for item in value["formal_verification"]
        ]
        expected_continuity = [
            bool(
                item["critical_services_restored"]
                and item["observed_recovery_seconds"]
                <= item["recovery_time_objective_seconds"]
                and item["observed_data_loss_seconds"]
                <= item["recovery_point_objective_seconds"]
                and item["unresolved_findings"] == 0
            )
            for item in value["continuity_exercises"]
        ]
        expected_checks = {
            "governance_separation": bool(
                len({item.casefold() for item in roles}) == 3
                and not any(_placeholder(item) for item in roles)
                and not _placeholder(authority["independence_basis"])
            ),
            "product_scope_complete": not any(
                _placeholder(str(item)) for item in value["product"].values()
            ),
            "external_composite_benchmark": bool(
                benchmark_artifacts
                and all(item["valid"] and item["passed"] for item in benchmark_artifacts)
                and len(benchmark["suite_ids"]) >= policy["minimum_benchmark_suites"]
                and set(policy["required_suite_types"]) <= set(benchmark["suite_types"])
                and benchmark["external_suite_provenance"]
                and benchmark["exact_suite_repository_trace"]
            ),
            "comparator_baselines": len(benchmark["comparator_tools"])
            >= policy["minimum_comparator_tools"]
            and benchmark["comparator_independence"],
            "runtime_coverage": bool(
                (not coverage_artifacts or all(item["valid"] and item["passed"] for item in coverage_artifacts))
                and (not policy["runtime_coverage_required"] or coverage_artifacts)
            ),
            "independent_interoperability": bool(
                all(item["valid"] for item in roundtrip_artifacts)
                and all(item["passed"] for item in roundtrip_artifacts)
                and set(policy["required_interoperability_formats"])
                <= set(value["interoperability"]["passing_formats"])
            ),
            "representative_usability": bool(
                all(
                    item["passed"] == expected
                    for item, expected in zip(
                        value["usability_studies"], expected_studies, strict=True
                    )
                )
                and (not expected_studies or all(expected_studies))
                and (not policy["usability_required"] or bool(expected_studies))
            ),
            "formal_verification": bool(
                all(
                    item["passed"] == expected
                    for item, expected in zip(
                        value["formal_verification"], expected_formal, strict=True
                    )
                )
                and (not expected_formal or all(expected_formal))
                and (not policy["formal_methods_required"] or bool(expected_formal))
            ),
            "continuity_exercise": bool(
                all(
                    item["passed"] == expected
                    for item, expected in zip(
                        value["continuity_exercises"], expected_continuity, strict=True
                    )
                )
                and (not expected_continuity or all(expected_continuity))
                and (
                    not policy["continuity_exercise_required"]
                    or bool(expected_continuity)
                )
            ),
            "portfolio_evidence": bool(value["evidence_refs"]),
        }
        semantic = bool(
            structure
            and checks == expected_checks
            and isinstance(summary, dict)
            and summary.get("passed") == all(checks.values())
            and summary.get("checks_passed") == sum(checks.values())
            and summary.get("checks_required") == len(checks)
            and summary.get("failed_checks")
            == sorted(name for name, state in checks.items() if not state)
            and summary.get("artifacts") == len(artifacts)
        )
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        semantic = False
    if not semantic:
        errors.append("portfolio assessment summary does not reconcile")
    regeneration: bool | None = None
    if source is not None:
        try:
            expected = validation_portfolio_assessment(source)
            regeneration = expected == assessment
        except (OSError, TypeError, ValueError):
            regeneration = False
        if not regeneration:
            errors.append("portfolio assessment does not exactly regenerate")
    valid = bool(structure and integrity and semantic and regeneration is not False)
    return seal(
        {
            "format": VALIDATION_PORTFOLIO_VERIFICATION_FORMAT,
            "valid": valid,
            "passed": bool(valid and summary.get("passed")),
            "checks": {
                "closed_structure": structure,
                "content_integrity": integrity,
                "semantic_reconciliation": semantic,
                "source_regeneration": regeneration,
            },
            "errors": errors,
            "notice": "Verification proves portfolio accounting, not evidence truth, independence, accreditation, qualification, or certification.",
        }
    )


def verify_validation_portfolio_assessment_file(
    source: str | Path, *, portfolio_source: str | Path | None = None
) -> dict[str, Any]:
    try:
        value = load_json(source, label="industry validation portfolio assessment")
        return verify_validation_portfolio_assessment(value, source=portfolio_source)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": VALIDATION_PORTFOLIO_VERIFICATION_FORMAT,
                "valid": False,
                "passed": False,
                "checks": {
                    "closed_structure": False,
                    "content_integrity": False,
                    "semantic_reconciliation": False,
                    "source_regeneration": False if portfolio_source is not None else None,
                },
                "errors": [str(exc)],
                "notice": "Industry validation portfolio verification failed closed.",
            }
        )


def export_validation_portfolio_source(
    value: dict[str, Any], destination: str | Path
) -> Path:
    return publish_json(value, destination)


def export_validation_portfolio_assessment(
    value: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_validation_portfolio_assessment(value)
    if not verdict["valid"]:
        raise ValueError("industry validation portfolio assessment is internally invalid")
    return publish_json(value, destination)
