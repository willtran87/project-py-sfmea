"""Governed system-level assurance programs spanning repositories and evidence sources."""

from __future__ import annotations

import hashlib
import json
import os
import unicodedata
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Iterable

from .file_publication import (
    atomic_publish_text,
    inspect_artifact_destination,
)
from .integrity import canonical_json_sha256
from .json_ingestion import (
    BoundedFileSnapshotError,
    load_bounded_file_snapshot,
    load_bounded_json_document,
)
from .llm_quality import project_llm_quality_corpus
from .model import utc_now
from .report import analysis_state_sha256
from .store import load_analysis
from .version import __version__

PROGRAM_FORMAT = "pysfmea-assurance-program-1"
PROGRAM_VERIFICATION_FORMAT = "pysfmea-assurance-program-verification-1"
MAX_PROGRAM_BYTES = 10 * 1024 * 1024
MAX_PROGRAM_DEPTH = 100
MAX_PROGRAM_NODES = 500_000
MAX_PROGRAM_REPOSITORIES = 100
MAX_PROGRAM_RELATIONSHIPS = 10_000
MAX_PROGRAM_REQUIREMENTS = 50_000
MAX_PROGRAM_EVIDENCE = 50_000
MAX_PROGRAM_APPROVALS = 50_000
MAX_PROGRAM_COHORTS = 2_000
MAX_PROGRAM_LLM_EVALUATIONS = 10_000
MAX_PROGRAM_FINDINGS = 200_000
MAX_EVIDENCE_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 500 * 1024 * 1024
MAX_EVALUATION_RESULT_BYTES = 20 * 1024 * 1024
MAX_TOTAL_EVALUATION_BYTES = 200 * 1024 * 1024
MAX_LLM_CORPUS_BYTES = 20 * 1024 * 1024
MAX_TOTAL_LLM_CORPUS_BYTES = 200 * 1024 * 1024

RELATIONSHIP_KINDS = {
    "calls",
    "publishes",
    "subscribes",
    "data_flow",
    "depends_on",
    "controls",
    "fallback",
}
EVIDENCE_TECHNIQUES = {
    "coverage",
    "mutation",
    "property_based",
    "fault_injection",
    "concurrency",
    "load",
    "chaos",
    "sast",
    "dast",
    "runtime_trace",
    "formal_analysis",
    "manual_inspection",
}
EVIDENCE_STATUSES = {"passed", "failed", "inconclusive", "not_run"}
TIMING_EVIDENCE_TECHNIQUES = {
    "runtime_trace",
    "load",
    "fault_injection",
    "concurrency",
    "chaos",
}
RESILIENCE_EVIDENCE_TECHNIQUES = {"fault_injection", "concurrency", "chaos"}
APPROVAL_SUBJECT_KINDS = {
    "program",
    "repository",
    "requirement",
    "relationship",
    "evidence",
}


def _program_material(program: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in program.items() if key != "integrity"}


def seal_program(program: dict[str, Any]) -> dict[str, Any]:
    """Return *program* with deterministic content integrity metadata."""

    sealed = json.loads(json.dumps(program, ensure_ascii=False))
    sealed.pop("integrity", None)
    sealed["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "json-sort-keys-compact-utf8",
        "content_sha256": canonical_json_sha256(sealed),
    }
    return sealed


def _bounded_text(value: Any, *, label: str, limit: int = 2_000) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    cleaned = value.strip()
    if (
        not cleaned
        or len(cleaned) > limit
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in cleaned)
    ):
        raise ValueError(
            f"{label} must be non-empty printable text within {limit} characters"
        )
    return cleaned


def _identifier(value: Any, *, label: str) -> str:
    text = _bounded_text(value, label=label, limit=200)
    if any(char.isspace() for char in text):
        raise ValueError(f"{label} must not contain whitespace")
    return text


def _relative_reference(path: str | Path, base: Path) -> str:
    absolute = Path(os.path.abspath(Path(path).expanduser()))
    try:
        relative = os.path.relpath(absolute, base)
    except ValueError:
        return str(absolute)
    return Path(relative).as_posix()


def build_program_template(
    analyses: Iterable[tuple[str, str | Path]],
    *,
    destination: str | Path,
    name: str = "System assurance program",
) -> dict[str, Any]:
    """Build a state-bound multi-repository program starter."""

    destination_path = Path(os.path.abspath(Path(destination).expanduser()))
    repositories = []
    seen: set[str] = set()
    for repository_id, source in analyses:
        identifier = _identifier(repository_id, label="repository ID")
        if identifier in seen:
            raise ValueError(f"duplicate repository ID: {identifier}")
        seen.add(identifier)
        analysis = load_analysis(source)
        repositories.append(
            {
                "id": identifier,
                "analysis": _relative_reference(source, destination_path.parent),
                "analysis_state_sha256": analysis_state_sha256(analysis),
                "baseline_id": str(
                    analysis.get("project", {}).get("baseline", {}).get("id", "")
                ),
                "role": str(analysis.get("project", {}).get("name", identifier)),
            }
        )
    if not repositories:
        raise ValueError("at least one --analysis ID=PATH reference is required")
    if len(repositories) > MAX_PROGRAM_REPOSITORIES:
        raise ValueError(
            f"program exceeds the {MAX_PROGRAM_REPOSITORIES}-repository limit"
        )
    program = {
        "format": PROGRAM_FORMAT,
        "name": _bounded_text(name, label="program name", limit=500),
        "purpose": "Federate repository SFMEAs, external evidence, temporal interfaces, validation cohorts, and governed approvals.",
        "created_at": utc_now(),
        "repositories": repositories,
        "relationships": [],
        "requirements_sources": [],
        "external_evidence": [],
        "validation_cohorts": [],
        "llm_evaluations": [],
        "governance": {
            "required_roles": ["software", "safety"],
            "independent_evidence_review": True,
            "require_program_approval": True,
            "approvals": [],
        },
        "quality_gates": {
            "min_validation_repositories": 3,
            "require_independent_validation": True,
            "min_recall": 0.8,
            "min_precision": 0.8,
            "require_count_backed_validation": True,
            "require_evaluation_result_artifacts": True,
            "min_micro_recall": 0.8,
            "min_micro_precision": 0.8,
            "min_call_resolution_recall": 0.8,
            "min_call_resolution_precision": 0.8,
            "min_micro_call_resolution_recall": 0.8,
            "min_micro_call_resolution_precision": 0.8,
            "require_temporal_evidence": True,
            "require_resilience_evidence": True,
            "min_llm_samples": 0,
            "require_independent_llm_evaluation": True,
            "require_llm_count_backing": True,
            "require_llm_corpus_artifacts": True,
            "require_llm_subject_binding": True,
            "min_llm_grounding": 0.9,
            "min_llm_citation_accuracy": 0.9,
            "max_llm_unsupported_claim_rate": 0.02,
        },
    }
    return seal_program(program)


def write_program_template(
    destination: str | Path,
    analyses: Iterable[tuple[str, str | Path]],
    *,
    name: str = "System assurance program",
    force: bool = False,
) -> Path:
    """Publish an assurance-program template without overwriting unrelated content."""

    state = inspect_artifact_destination(destination, label="assurance program")
    if state.snapshot is not None and not force:
        raise ValueError(f"assurance program already exists: {state.path}")
    if state.snapshot is not None:
        current = load_bounded_json_document(
            state.path,
            label="existing assurance program",
            max_bytes=MAX_PROGRAM_BYTES,
            max_depth=MAX_PROGRAM_DEPTH,
            max_nodes=MAX_PROGRAM_NODES,
        ).value
        if not isinstance(current, dict) or current.get("format") != PROGRAM_FORMAT:
            raise ValueError("--force only replaces a recognized assurance program")
    program = build_program_template(analyses, destination=state.path, name=name)
    content = json.dumps(program, indent=2, ensure_ascii=False) + "\n"
    return atomic_publish_text(
        state.path,
        content,
        max_bytes=MAX_PROGRAM_BYTES,
        label="assurance program",
        expected_destination=state,
    )


def seal_program_file(source: str | Path) -> Path:
    """Refresh only the integrity declaration of a recognized program file."""

    state = inspect_artifact_destination(source, label="assurance program")
    if state.snapshot is None:
        raise ValueError("assurance program is unavailable")
    document = load_bounded_json_document(
        state.path,
        label="assurance program",
        max_bytes=MAX_PROGRAM_BYTES,
        max_depth=MAX_PROGRAM_DEPTH,
        max_nodes=MAX_PROGRAM_NODES,
    )
    if (
        not isinstance(document.value, dict)
        or document.value.get("format") != PROGRAM_FORMAT
    ):
        raise ValueError("assurance program format is missing or unsupported")
    sealed = seal_program(document.value)
    return atomic_publish_text(
        state.path,
        json.dumps(sealed, indent=2, ensure_ascii=False) + "\n",
        max_bytes=MAX_PROGRAM_BYTES,
        label="assurance program",
        expected_destination=state,
    )


def _finding(
    findings: list[dict[str, str]],
    code: str,
    level: str,
    message: str,
    location: str = "",
) -> None:
    if len(findings) >= MAX_PROGRAM_FINDINGS:
        return
    if len(findings) == MAX_PROGRAM_FINDINGS - 1:
        findings.append(
            {
                "code": "program.finding_limit",
                "level": "error",
                "message": (
                    "Verification findings reached the bounded output limit; "
                    "additional findings were omitted."
                ),
                "location": "program",
            }
        )
        return
    findings.append(
        {"code": code, "level": level, "message": message, "location": location}
    )


def _reject_unknown_fields(
    record: dict[str, Any],
    allowed: set[str],
    findings: list[dict[str, str]],
    *,
    code: str,
    location: str,
) -> bool:
    unknown = set(record) - allowed
    if unknown:
        _finding(
            findings,
            code,
            "error",
            "Unsupported field(s): " + ", ".join(sorted(unknown)) + ".",
            location,
        )
        return False
    return True


def _timestamp(
    value: Any,
    *,
    label: str,
    findings: list[dict[str, str]],
    location: str,
) -> bool:
    try:
        text = _bounded_text(value, label=label, limit=200)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(f"{label} must include a UTC offset")
    except (TypeError, ValueError) as exc:
        _finding(findings, "program.timestamp", "error", str(exc), location)
        return False
    return True


def _boolean(
    record: dict[str, Any],
    field: str,
    default: bool,
    findings: list[dict[str, str]],
    *,
    location: str,
) -> bool:
    value = record.get(field, default)
    if not isinstance(value, bool):
        _finding(
            findings,
            "program.boolean_value",
            "error",
            f"{field} must be a boolean.",
            f"{location}.{field}",
        )
        return default
    return value


def _list(
    program: dict[str, Any],
    field: str,
    limit: int,
    findings: list[dict[str, str]],
) -> list[dict[str, Any]]:
    value = program.get(field, [])
    if not isinstance(value, list) or not all(
        isinstance(entry, dict) for entry in value
    ):
        _finding(
            findings,
            "program.invalid_collection",
            "error",
            f"{field} must be an array of objects.",
            field,
        )
        return []
    if len(value) > limit:
        _finding(
            findings,
            "program.collection_limit",
            "error",
            f"{field} exceeds the {limit}-record limit.",
            field,
        )
        return value[:limit]
    return value


def _id_map(
    entries: list[dict[str, Any]],
    field: str,
    findings: list[dict[str, str]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        try:
            identifier = _identifier(entry.get("id"), label=f"{field} ID")
        except ValueError as exc:
            _finding(
                findings,
                "program.invalid_id",
                "error",
                str(exc),
                f"{field}[{index}].id",
            )
            continue
        if identifier in result:
            _finding(
                findings,
                "program.duplicate_id",
                "error",
                f"Duplicate {field} ID: {identifier}.",
                f"{field}[{index}].id",
            )
            continue
        result[identifier] = entry
    return result


def _program_result(
    source: Path,
    findings: list[dict[str, str]],
    *,
    program_sha256: str = "",
    checks: dict[str, bool | None] | None = None,
    summary: dict[str, Any] | None = None,
    relationships: list[dict[str, Any]] | None = None,
    validation: dict[str, Any] | None = None,
    llm_quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    counts = Counter(value["level"] for value in findings)
    effective_checks = checks or {}
    valid = not counts["error"] and all(
        value is not False for value in effective_checks.values()
    )
    return {
        "format": PROGRAM_VERIFICATION_FORMAT,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "program": {"path": str(source), "content_sha256": program_sha256},
        "valid": valid,
        "checks": effective_checks,
        "counts": {
            "errors": counts["error"],
            "warnings": counts["warning"],
            "information": counts["information"],
        },
        "summary": summary or {},
        "relationships": relationships or [],
        "validation": validation or {},
        "llm_quality": llm_quality or {},
        "findings": findings,
        "notice": "Program verification binds declared analyses and evidence, evaluates configured gates, and exposes missing assurance. It does not certify the system, approve risk, or prove causal completeness.",
    }


def _ratio(value: Any, *, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number from 0 through 1")
    number = float(value)
    if not 0 <= number <= 1:
        raise ValueError(f"{label} must be a number from 0 through 1")
    return number


def _string_array(
    record: dict[str, Any],
    field: str,
    findings: list[dict[str, str]],
    *,
    location: str,
    limit: int = 10_000,
) -> list[str]:
    value = record.get(field, [])
    if (
        not isinstance(value, list)
        or len(value) > limit
        or not all(
            isinstance(entry, str)
            and entry == entry.strip()
            and entry
            and not any(char.isspace() for char in entry)
            for entry in value
        )
        or len(set(value)) != len(value)
    ):
        _finding(
            findings,
            "program.invalid_reference_array",
            "error",
            f"{field} must be a bounded array of non-empty strings.",
            f"{location}.{field}",
        )
        return []
    return value


def _quality_integer(
    quality: dict[str, Any],
    field: str,
    findings: list[dict[str, str]],
) -> int:
    value = quality.get(field, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _finding(
            findings,
            "program.quality_value",
            "error",
            f"{field} must be a non-negative integer.",
            f"quality_gates.{field}",
        )
        return 0
    return value


def _quality_ratio(
    quality: dict[str, Any],
    field: str,
    default: float,
    findings: list[dict[str, str]],
) -> float:
    try:
        value = _ratio(quality.get(field, default), label=field)
    except ValueError as exc:
        _finding(
            findings,
            "program.quality_value",
            "error",
            str(exc),
            f"quality_gates.{field}",
        )
        return default
    return default if value is None else value


def _evaluation_result_matches_cohort(
    result: Any,
    cohort: dict[str, Any],
) -> bool:
    """Reconcile one retained evaluator result with its cohort projection."""

    if not isinstance(result, dict):
        return False
    corpus = result.get("corpus")
    verifier = result.get("verifier")
    metrics = result.get("metrics")
    if (
        not isinstance(corpus, dict)
        or not isinstance(verifier, dict)
        or not isinstance(metrics, dict)
    ):
        return False
    duplicate_count = metrics.get("duplicate_count")
    unsupported_claims = metrics.get("unsupported_verification_claims")
    missing = result.get("missing")
    unexpected = result.get("unexpected")
    counts = [result.get(name) for name in ("expected", "actual", "matched")]
    if (
        not isinstance(missing, list)
        or not isinstance(unexpected, list)
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in counts
        )
    ):
        return False
    expected, actual, matched = counts
    if (
        result.get("format") != cohort.get("evaluation_result_format")
        or verifier.get("name") != "PySFMEA"
        or verifier.get("version") != cohort.get("evaluation_verifier_version")
        or corpus.get("content_sha256") != cohort.get("corpus_sha256")
        or corpus.get("case_count") != cohort.get("case_count")
        or expected != cohort.get("case_count")
        or actual != cohort.get("actual_count")
        or matched != cohort.get("matched_count")
        or actual - len(unexpected) != cohort.get("actual_matched_count")
        or matched != expected - len(missing)
        or result.get("recall") != cohort.get("recall")
        or result.get("precision") != cohort.get("precision")
        or not isinstance(duplicate_count, int)
        or isinstance(duplicate_count, bool)
        or duplicate_count != 0
        or not isinstance(unsupported_claims, list)
        or unsupported_claims
    ):
        return False
    call_case_count = cohort.get("call_case_count", 0)
    call_result = result.get("call_resolution")
    if not isinstance(call_result, dict):
        return False
    if not call_case_count:
        return call_result.get("enabled") is False
    call_missing = call_result.get("missing")
    call_unexpected = call_result.get("unexpected")
    call_counts = [call_result.get(name) for name in ("expected", "actual", "matched")]
    if (
        call_result.get("enabled") is not True
        or corpus.get("call_case_count") != call_case_count
        or not isinstance(call_missing, list)
        or not isinstance(call_unexpected, list)
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in call_counts
        )
    ):
        return False
    call_expected, call_actual, call_matched = call_counts
    return bool(
        call_expected == call_case_count
        and call_actual == cohort.get("call_actual_count")
        and call_matched == cohort.get("call_matched_count")
        and call_actual - len(call_unexpected)
        == cohort.get("call_actual_matched_count")
        and call_matched == call_expected - len(call_missing)
        and call_result.get("recall") == cohort.get("call_resolution_recall")
        and call_result.get("precision") == cohort.get("call_resolution_precision")
    )


def _llm_corpus_evidence_fingerprint(
    corpus: Any,
    evaluation: dict[str, Any],
) -> str | None:
    """Recompute metrics and the order/metadata-insensitive evidence identity."""

    try:
        projection = project_llm_quality_corpus(
            corpus,
            expected_subject={
                "provider": evaluation.get("provider"),
                "model": evaluation.get("model"),
                "prompt_version": evaluation.get("prompt_version"),
            },
        )
    except ValueError:
        return None
    claimed_fingerprint = evaluation.get("evidence_fingerprint_sha256")
    if (
        evaluation.get("corpus_format") not in {None, projection.corpus_format}
        or evaluation.get("subject_bound", False) is not projection.subject_bound
        or claimed_fingerprint
        not in {None, projection.evidence_fingerprint_sha256}
        or evaluation.get("sample_count") != projection.sample_count
        or evaluation.get("grounded_sample_count")
        != projection.grounded_sample_count
        or evaluation.get("citation_correct_sample_count")
        != projection.citation_correct_sample_count
        or evaluation.get("claim_count") != projection.claim_count
        or evaluation.get("unsupported_claim_count")
        != projection.unsupported_claim_count
        or evaluation.get("grounding") != projection.grounding
        or evaluation.get("citation_accuracy") != projection.citation_accuracy
        or evaluation.get("unsupported_claim_rate")
        != projection.unsupported_claim_rate
    ):
        return None
    return projection.evidence_fingerprint_sha256


def verify_assurance_program(source: str | Path) -> dict[str, Any]:
    """Verify one bounded, state-bound, system-level assurance program."""

    supplied = Path(os.path.abspath(Path(source).expanduser()))
    findings: list[dict[str, str]] = []
    try:
        document = load_bounded_json_document(
            supplied,
            label="assurance program",
            max_bytes=MAX_PROGRAM_BYTES,
            max_depth=MAX_PROGRAM_DEPTH,
            max_nodes=MAX_PROGRAM_NODES,
        )
    except (ValueError, BoundedFileSnapshotError) as exc:
        _finding(findings, "program.input_rejected", "error", str(exc), "program")
        return _program_result(supplied, findings, checks={"input": False})
    program_sha256 = hashlib.sha256(document.raw).hexdigest()
    program = document.value
    if not isinstance(program, dict):
        _finding(
            findings,
            "program.invalid_root",
            "error",
            "Assurance program root must be an object.",
            "program",
        )
        return _program_result(
            supplied,
            findings,
            program_sha256=program_sha256,
            checks={"input": True, "format": False},
        )

    allowed = {
        "format",
        "name",
        "purpose",
        "created_at",
        "repositories",
        "relationships",
        "requirements_sources",
        "external_evidence",
        "validation_cohorts",
        "llm_evaluations",
        "governance",
        "quality_gates",
        "integrity",
    }
    unknown = set(program) - allowed
    if unknown:
        _finding(
            findings,
            "program.unknown_fields",
            "error",
            "Unsupported program field(s): " + ", ".join(sorted(unknown)),
            "program",
        )
    format_valid = program.get("format") == PROGRAM_FORMAT
    if not format_valid:
        _finding(
            findings,
            "program.format",
            "error",
            "Assurance program format is missing or unsupported.",
            "format",
        )
    integrity = program.get("integrity", {})
    integrity_valid = bool(
        isinstance(integrity, dict)
        and integrity.get("algorithm") == "sha256"
        and integrity.get("canonicalization") == "json-sort-keys-compact-utf8"
        and integrity.get("content_sha256")
        == canonical_json_sha256(_program_material(program))
    )
    if not integrity_valid:
        _finding(
            findings,
            "program.integrity",
            "error",
            "Program integrity is missing or does not match; run `sfmea program-seal` after intentional edits.",
            "integrity",
        )
    for field, limit in (("name", 500), ("purpose", 2_000)):
        try:
            _bounded_text(program.get(field), label=f"program {field}", limit=limit)
        except ValueError as exc:
            _finding(findings, "program.metadata", "error", str(exc), field)
    _timestamp(
        program.get("created_at"),
        label="program created_at",
        findings=findings,
        location="created_at",
    )

    repositories = _list(program, "repositories", MAX_PROGRAM_REPOSITORIES, findings)
    relationships = _list(program, "relationships", MAX_PROGRAM_RELATIONSHIPS, findings)
    requirements_sources = _list(
        program, "requirements_sources", MAX_PROGRAM_REQUIREMENTS, findings
    )
    evidence = _list(program, "external_evidence", MAX_PROGRAM_EVIDENCE, findings)
    cohorts = _list(program, "validation_cohorts", MAX_PROGRAM_COHORTS, findings)
    llm_evaluations = _list(
        program, "llm_evaluations", MAX_PROGRAM_LLM_EVALUATIONS, findings
    )
    repository_map = _id_map(repositories, "repositories", findings)
    relationship_map = _id_map(relationships, "relationships", findings)
    evidence_map = _id_map(evidence, "external_evidence", findings)
    if not repository_map:
        _finding(
            findings,
            "repository.missing",
            "error",
            "At least one governed repository analysis is required.",
            "repositories",
        )

    loaded_analyses: dict[str, dict[str, Any]] = {}
    repository_checks: dict[str, bool] = {}
    for repository_id, record in repository_map.items():
        location = f"repositories.{repository_id}"
        _reject_unknown_fields(
            record,
            {"id", "analysis", "analysis_state_sha256", "baseline_id", "role"},
            findings,
            code="repository.unknown_fields",
            location=location,
        )
        for field in ("baseline_id", "role"):
            try:
                _bounded_text(record.get(field), label=f"repository {field}")
            except ValueError as exc:
                _finding(
                    findings,
                    "repository.metadata",
                    "error",
                    str(exc),
                    f"{location}.{field}",
                )
        reference = record.get("analysis")
        if not isinstance(reference, str) or not reference.strip():
            _finding(
                findings,
                "repository.analysis_missing",
                "error",
                f"Repository {repository_id} has no analysis reference.",
                location,
            )
            repository_checks[repository_id] = False
            continue
        analysis_path = Path(reference).expanduser()
        if not analysis_path.is_absolute():
            analysis_path = document.path.parent / analysis_path
        try:
            analysis = load_analysis(analysis_path)
        except (ValueError, OSError) as exc:
            _finding(
                findings,
                "repository.analysis_rejected",
                "error",
                f"Repository {repository_id} analysis was rejected: {exc}",
                location,
            )
            repository_checks[repository_id] = False
            continue
        state = analysis_state_sha256(analysis)
        declared_state = record.get("analysis_state_sha256", "")
        expected_state = str(declared_state)
        baseline = str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
        expected_baseline = str(record.get("baseline_id", ""))
        digest_valid = (
            len(expected_state) == 64
            and expected_state == expected_state.lower()
            and all(char in "0123456789abcdef" for char in expected_state)
        )
        valid_binding = (
            digest_valid
            and state == expected_state
            and baseline == expected_baseline
            and bool(expected_baseline)
        )
        if not valid_binding:
            _finding(
                findings,
                "repository.binding_mismatch",
                "error",
                f"Repository {repository_id} no longer matches its declared analysis state and baseline.",
                location,
            )
        repository_checks[repository_id] = valid_binding
        loaded_analyses[repository_id] = analysis

    component_ids_by_repository = {
        repository_id: {
            str(value.get("id", ""))
            for value in analysis.get("components", [])
            if value.get("id")
        }
        for repository_id, analysis in loaded_analyses.items()
    }
    finding_ids = {
        f"{repository_id}:{value.get('id')}"
        for repository_id, analysis in loaded_analyses.items()
        for value in analysis.get("items", [])
        if value.get("id")
    }
    hazard_ids = {
        f"{repository_id}:{value.get('id')}"
        for repository_id, analysis in loaded_analyses.items()
        for value in analysis.get("context", {}).get("hazards", [])
        if isinstance(value, dict) and value.get("id")
    }

    derived_relationships: list[dict[str, Any]] = []
    relationship_contracts: dict[str, dict[str, Any]] = {}
    for relationship_id, record in relationship_map.items():
        location = f"relationships.{relationship_id}"
        _reject_unknown_fields(
            record,
            {"id", "kind", "source", "target", "temporal", "circuit_breaker"},
            findings,
            code="relationship.unknown_fields",
            location=location,
        )
        kind = record.get("kind")
        if kind not in RELATIONSHIP_KINDS:
            _finding(
                findings,
                "relationship.kind",
                "error",
                f"Relationship {relationship_id} has an unsupported kind.",
                location,
            )
        endpoints_valid = True
        for end in ("source", "target"):
            endpoint = record.get(end, {})
            if isinstance(endpoint, dict):
                _reject_unknown_fields(
                    endpoint,
                    {"repository_id", "component_id"},
                    findings,
                    code="relationship.endpoint_unknown_fields",
                    location=f"{location}.{end}",
                )
            repository_id = (
                endpoint.get("repository_id") if isinstance(endpoint, dict) else None
            )
            component_id = (
                endpoint.get("component_id") if isinstance(endpoint, dict) else None
            )
            analysis = loaded_analyses.get(str(repository_id))
            component_ids = component_ids_by_repository.get(str(repository_id), set())
            if not analysis or component_id not in component_ids:
                endpoints_valid = False
                _finding(
                    findings,
                    "relationship.endpoint",
                    "error",
                    f"Relationship {relationship_id} {end} does not identify a known repository component.",
                    f"{location}.{end}",
                )
        temporal = record.get("temporal", {})
        if not isinstance(temporal, dict):
            temporal = {}
            _finding(
                findings,
                "relationship.temporal_shape",
                "error",
                f"Relationship {relationship_id} temporal policy must be an object.",
                f"{location}.temporal",
            )
        else:
            _reject_unknown_fields(
                temporal,
                {
                    "deadline_ms",
                    "timeout_ms",
                    "retry_limit",
                    "backoff_ms",
                    "max_in_flight",
                    "ordering",
                    "clock",
                },
                findings,
                code="relationship.temporal_unknown_fields",
                location=f"{location}.temporal",
            )
        deadline = temporal.get("deadline_ms")
        deadline_valid = deadline is None or (
            isinstance(deadline, (int, float))
            and not isinstance(deadline, bool)
            and deadline > 0
        )
        if not deadline_valid:
            _finding(
                findings,
                "relationship.deadline",
                "error",
                f"Relationship {relationship_id} deadline_ms must be positive.",
                f"{location}.temporal.deadline_ms",
            )
        timeout = temporal.get("timeout_ms")
        if timeout is not None and (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout <= 0
            or (isinstance(deadline, (int, float)) and timeout > deadline)
        ):
            _finding(
                findings,
                "relationship.timeout",
                "error",
                f"Relationship {relationship_id} timeout_ms must be positive and no greater than deadline_ms.",
                f"{location}.temporal.timeout_ms",
            )
        for field, minimum in (("retry_limit", 0), ("max_in_flight", 1)):
            configured = temporal.get(field)
            if configured is not None and (
                not isinstance(configured, int)
                or isinstance(configured, bool)
                or configured < minimum
            ):
                _finding(
                    findings,
                    "relationship.temporal_value",
                    "error",
                    f"Relationship {relationship_id} {field} must be an integer of at least {minimum}.",
                    f"{location}.temporal.{field}",
                )
        backoff = temporal.get("backoff_ms")
        if backoff is not None and (
            not isinstance(backoff, (int, float))
            or isinstance(backoff, bool)
            or backoff < 0
        ):
            _finding(
                findings,
                "relationship.temporal_value",
                "error",
                f"Relationship {relationship_id} backoff_ms must be non-negative.",
                f"{location}.temporal.backoff_ms",
            )
        if deadline is not None and (
            not temporal.get("clock") or not temporal.get("ordering")
        ):
            _finding(
                findings,
                "relationship.temporal_contract_incomplete",
                "error",
                f"Relationship {relationship_id} requires explicit clock and ordering semantics when a deadline is configured.",
                f"{location}.temporal",
            )
        elif deadline is not None:
            for field in ("clock", "ordering"):
                try:
                    _bounded_text(
                        temporal.get(field),
                        label=f"relationship temporal {field}",
                    )
                except ValueError as exc:
                    _finding(
                        findings,
                        "relationship.temporal_contract_incomplete",
                        "error",
                        str(exc),
                        f"{location}.temporal.{field}",
                    )
        circuit_breaker = record.get("circuit_breaker")
        breaker_valid = True
        if circuit_breaker is not None:
            if not isinstance(circuit_breaker, dict):
                breaker_valid = False
                circuit_breaker = {}
                _finding(
                    findings,
                    "relationship.circuit_breaker_shape",
                    "error",
                    f"Relationship {relationship_id} circuit_breaker must be an object.",
                    f"{location}.circuit_breaker",
                )
            else:
                _reject_unknown_fields(
                    circuit_breaker,
                    {
                        "failure_threshold",
                        "open_state_timeout_ms",
                        "half_open_max_calls",
                        "recovery_deadline_ms",
                    },
                    findings,
                    code="relationship.circuit_breaker_unknown_fields",
                    location=f"{location}.circuit_breaker",
                )
            for field in ("failure_threshold", "half_open_max_calls"):
                value = circuit_breaker.get(field)
                if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                    breaker_valid = False
                    _finding(
                        findings,
                        "relationship.circuit_breaker_value",
                        "error",
                        f"Relationship {relationship_id} {field} must be a positive integer.",
                        f"{location}.circuit_breaker.{field}",
                    )
            for field in ("open_state_timeout_ms", "recovery_deadline_ms"):
                value = circuit_breaker.get(field)
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or value <= 0
                ):
                    breaker_valid = False
                    _finding(
                        findings,
                        "relationship.circuit_breaker_value",
                        "error",
                        f"Relationship {relationship_id} {field} must be positive.",
                        f"{location}.circuit_breaker.{field}",
                    )
        source = record.get("source", {})
        target = record.get("target", {})
        relationship_contracts[relationship_id] = {
            "deadline_ms": deadline if deadline_valid else None,
            "circuit_breaker": circuit_breaker if breaker_valid else None,
        }
        derived_relationships.append(
            {
                "id": relationship_id,
                "kind": kind,
                "source": (
                    f"{source.get('repository_id')}:{source.get('component_id')}"
                    if isinstance(source, dict)
                    else ""
                ),
                "source_repository": (
                    str(source.get("repository_id")) if isinstance(source, dict) else ""
                ),
                "target": (
                    f"{target.get('repository_id')}:{target.get('component_id')}"
                    if isinstance(target, dict)
                    else ""
                ),
                "target_repository": (
                    str(target.get("repository_id")) if isinstance(target, dict) else ""
                ),
                "endpoints_valid": endpoints_valid,
                "temporal_status": "not_configured"
                if deadline is None
                else "unverified",
                "resilience_status": (
                    "not_configured" if circuit_breaker is None else "unverified"
                ),
                "deadline_ms": deadline if deadline_valid else None,
                "observed_max_ms": None,
                "recovery_deadline_ms": (
                    circuit_breaker.get("recovery_deadline_ms")
                    if isinstance(circuit_breaker, dict)
                    else None
                ),
                "observed_recovery_ms": None,
                "evidence_ids": [],
            }
        )

    requirement_ids: set[str] = set()
    requirement_source_ids: set[str] = set()
    requirement_count = 0
    for source_index, source_record in enumerate(requirements_sources):
        location = f"requirements_sources[{source_index}]"
        _reject_unknown_fields(
            source_record,
            {
                "id",
                "provider",
                "revision",
                "retrieved_at",
                "source_uri",
                "content_sha256",
                "requirements",
            },
            findings,
            code="requirements.unknown_fields",
            location=location,
        )
        try:
            source_id = _identifier(
                source_record.get("id"), label="requirement source ID"
            )
        except ValueError as exc:
            _finding(
                findings, "requirements.invalid_source_id", "error", str(exc), location
            )
            continue
        if source_id in requirement_source_ids:
            _finding(
                findings,
                "requirements.duplicate_source_id",
                "error",
                f"Duplicate requirement source ID: {source_id}.",
                location,
            )
            continue
        requirement_source_ids.add(source_id)
        for field in ("provider", "revision", "source_uri"):
            try:
                _bounded_text(
                    source_record.get(field), label=f"requirement source {field}"
                )
            except ValueError as exc:
                _finding(
                    findings,
                    "requirements.metadata",
                    "error",
                    str(exc),
                    f"{location}.{field}",
                )
        _timestamp(
            source_record.get("retrieved_at"),
            label="requirement source retrieved_at",
            findings=findings,
            location=f"{location}.retrieved_at",
        )
        records = source_record.get("requirements", [])
        if not isinstance(records, list) or not all(
            isinstance(value, dict) for value in records
        ):
            _finding(
                findings,
                "requirements.invalid_records",
                "error",
                f"Requirement source {source_id} requirements must be an array of objects.",
                f"requirements_sources[{source_index}]",
            )
            continue
        declared = str(source_record.get("content_sha256", "")).lower()
        if declared != canonical_json_sha256(records):
            _finding(
                findings,
                "requirements.integrity",
                "error",
                f"Requirement source {source_id} content digest does not match its records.",
                f"requirements_sources[{source_index}].content_sha256",
            )
        for record in records:
            requirement_count += 1
            if requirement_count > MAX_PROGRAM_REQUIREMENTS:
                _finding(
                    findings,
                    "requirements.record_limit",
                    "error",
                    f"Requirements exceed the {MAX_PROGRAM_REQUIREMENTS}-record limit.",
                    "requirements_sources",
                )
                break
            try:
                requirement_id = _identifier(record.get("id"), label="requirement ID")
            except ValueError as exc:
                _finding(
                    findings,
                    "requirements.invalid_id",
                    "error",
                    str(exc),
                    f"requirements_sources.{source_id}",
                )
                continue
            _reject_unknown_fields(
                record,
                {"id", "text", "repository_ids", "hazard_ids", "finding_ids"},
                findings,
                code="requirements.record_unknown_fields",
                location=f"requirements_sources.{source_id}.{requirement_id}",
            )
            try:
                _bounded_text(record.get("text"), label="requirement text")
            except ValueError as exc:
                _finding(
                    findings,
                    "requirements.text",
                    "error",
                    str(exc),
                    f"requirements_sources.{source_id}.{requirement_id}.text",
                )
            qualified = f"{source_id}:{requirement_id}"
            if qualified in requirement_ids:
                _finding(
                    findings,
                    "requirements.duplicate_id",
                    "error",
                    f"Duplicate qualified requirement ID: {qualified}.",
                    f"requirements_sources.{source_id}",
                )
            requirement_ids.add(qualified)
            for repository_id in _string_array(
                record,
                "repository_ids",
                findings,
                location=f"requirements_sources.{source_id}",
            ):
                if repository_id not in repository_map:
                    _finding(
                        findings,
                        "requirements.unknown_repository",
                        "error",
                        f"Requirement {qualified} references unknown repository {repository_id}.",
                        f"requirements_sources.{source_id}",
                    )
            unknown_hazards = (
                set(
                    _string_array(
                        record,
                        "hazard_ids",
                        findings,
                        location=f"requirements_sources.{source_id}",
                    )
                )
                - hazard_ids
            )
            unknown_findings = (
                set(
                    _string_array(
                        record,
                        "finding_ids",
                        findings,
                        location=f"requirements_sources.{source_id}",
                    )
                )
                - finding_ids
            )
            if unknown_hazards:
                _finding(
                    findings,
                    "requirements.unknown_hazard",
                    "error",
                    f"Requirement {qualified} references unknown hazards: {', '.join(sorted(unknown_hazards))}.",
                    f"requirements_sources.{source_id}",
                )
            if unknown_findings:
                _finding(
                    findings,
                    "requirements.unknown_finding",
                    "error",
                    f"Requirement {qualified} references unknown findings: {', '.join(sorted(unknown_findings))}.",
                    f"requirements_sources.{source_id}",
                )

    total_evidence_bytes = 0
    evidence_statuses = Counter()
    trusted_evidence: dict[str, dict[str, Any]] = {}
    artifact_cache: dict[Path, tuple[int, str]] = {}
    for evidence_id, record in evidence_map.items():
        location = f"external_evidence.{evidence_id}"
        evidence_valid = _reject_unknown_fields(
            record,
            {
                "id",
                "technique",
                "status",
                "repository_ids",
                "relationship_ids",
                "finding_ids",
                "producer",
                "reviewer",
                "metrics",
                "artifact",
            },
            findings,
            code="evidence.unknown_fields",
            location=location,
        )
        technique = record.get("technique")
        status = record.get("status")
        if technique not in EVIDENCE_TECHNIQUES:
            evidence_valid = False
            _finding(
                findings,
                "evidence.technique",
                "error",
                f"Evidence {evidence_id} has an unsupported technique.",
                location,
            )
        if status not in EVIDENCE_STATUSES:
            evidence_valid = False
            _finding(
                findings,
                "evidence.status",
                "error",
                f"Evidence {evidence_id} has an unsupported status.",
                location,
            )
        evidence_statuses[str(status)] += 1
        evidence_repositories = _string_array(
            record, "repository_ids", findings, location=location
        )
        evidence_relationships = _string_array(
            record, "relationship_ids", findings, location=location
        )
        evidence_findings = _string_array(
            record, "finding_ids", findings, location=location
        )
        unknown_repositories = set(evidence_repositories) - set(repository_map)
        unknown_relationships = set(evidence_relationships) - set(relationship_map)
        if unknown_repositories or unknown_relationships:
            evidence_valid = False
            _finding(
                findings,
                "evidence.unknown_subject",
                "error",
                f"Evidence {evidence_id} references unknown repositories or relationships.",
                location,
            )
        unknown_findings = set(evidence_findings) - finding_ids
        if unknown_findings:
            evidence_valid = False
            _finding(
                findings,
                "evidence.unknown_finding",
                "error",
                f"Evidence {evidence_id} references unknown findings: {', '.join(sorted(unknown_findings))}.",
                location,
            )
        metrics = record.get("metrics")
        if not isinstance(metrics, dict) or len(metrics) > 100:
            evidence_valid = False
            metrics = {}
            _finding(
                findings,
                "evidence.metrics",
                "error",
                f"Evidence {evidence_id} metrics must be an object with at most 100 fields.",
                f"{location}.metrics",
            )
        for metric_name in ("observed_max_ms", "recovery_time_ms"):
            metric_value = metrics.get(metric_name)
            if metric_value is not None and (
                not isinstance(metric_value, (int, float))
                or isinstance(metric_value, bool)
                or metric_value < 0
            ):
                evidence_valid = False
                _finding(
                    findings,
                    "evidence.metric_value",
                    "error",
                    f"Evidence {evidence_id} {metric_name} must be non-negative.",
                    f"{location}.metrics.{metric_name}",
                )
        for metric_name in ("circuit_breaker_opened", "half_open_recovered"):
            metric_value = metrics.get(metric_name)
            if metric_value is not None and not isinstance(metric_value, bool):
                evidence_valid = False
                _finding(
                    findings,
                    "evidence.metric_value",
                    "error",
                    f"Evidence {evidence_id} {metric_name} must be a boolean.",
                    f"{location}.metrics.{metric_name}",
                )
        artifact = record.get("artifact", {})
        artifact_verified = False
        if status in {"passed", "failed"}:
            for field in ("producer", "reviewer"):
                try:
                    _bounded_text(
                        record.get(field),
                        label=f"completed evidence {field}",
                        limit=500,
                    )
                except ValueError as exc:
                    evidence_valid = False
                    _finding(
                        findings,
                        "evidence.provenance",
                        "error",
                        str(exc),
                        f"{location}.{field}",
                    )
            if not isinstance(artifact, dict) or not artifact.get("path"):
                evidence_valid = False
                _finding(
                    findings,
                    "evidence.artifact_missing",
                    "error",
                    f"Completed evidence {evidence_id} requires a content-addressed artifact.",
                    location,
                )
            else:
                if not _reject_unknown_fields(
                    artifact,
                    {"path", "sha256"},
                    findings,
                    code="evidence.artifact_unknown_fields",
                    location=f"{location}.artifact",
                ):
                    evidence_valid = False
                artifact_path = Path(str(artifact["path"])).expanduser()
                if not artifact_path.is_absolute():
                    artifact_path = document.path.parent / artifact_path
                artifact_path = Path(os.path.abspath(artifact_path))
                try:
                    if artifact_path not in artifact_cache:
                        snapshot = load_bounded_file_snapshot(
                            artifact_path,
                            label=f"evidence {evidence_id} artifact",
                            max_bytes=MAX_EVIDENCE_ARTIFACT_BYTES,
                        )
                        digest = hashlib.sha256(snapshot.raw).hexdigest()
                        if (
                            total_evidence_bytes + snapshot.size
                            > MAX_TOTAL_EVIDENCE_BYTES
                        ):
                            raise ValueError(
                                f"evidence artifacts exceed the {MAX_TOTAL_EVIDENCE_BYTES}-byte aggregate limit"
                            )
                        artifact_cache[artifact_path] = (snapshot.size, digest)
                        total_evidence_bytes += snapshot.size
                    _, digest = artifact_cache[artifact_path]
                    if digest != str(artifact.get("sha256", "")):
                        evidence_valid = False
                        _finding(
                            findings,
                            "evidence.artifact_digest",
                            "error",
                            f"Evidence {evidence_id} artifact digest does not match.",
                            location,
                        )
                    else:
                        artifact_verified = True
                except (ValueError, BoundedFileSnapshotError) as exc:
                    evidence_valid = False
                    _finding(
                        findings,
                        "evidence.artifact_rejected",
                        "error",
                        str(exc),
                        location,
                    )
        elif isinstance(artifact, dict) and artifact:
            _reject_unknown_fields(
                artifact,
                {"path", "sha256"},
                findings,
                code="evidence.artifact_unknown_fields",
                location=f"{location}.artifact",
            )
        if status == "failed":
            _finding(
                findings,
                "evidence.failed",
                "error",
                f"Evidence {evidence_id} records a failed assurance result.",
                location,
            )
        elif status in {"inconclusive", "not_run"}:
            _finding(
                findings,
                "evidence.incomplete",
                "warning",
                f"Evidence {evidence_id} is {str(status).replace('_', ' ')} and cannot support an assurance claim.",
                location,
            )
        if evidence_valid and artifact_verified and status in {"passed", "failed"}:
            trusted_evidence[evidence_id] = {
                "id": evidence_id,
                "technique": technique,
                "status": status,
                "relationship_ids": evidence_relationships,
                "metrics": metrics,
            }

    for relationship in derived_relationships:
        relationship_id = str(relationship["id"])
        contract = relationship_contracts.get(relationship_id, {})
        linked = [
            value
            for value in trusted_evidence.values()
            if relationship_id in value["relationship_ids"]
        ]
        relationship["evidence_ids"] = sorted(value["id"] for value in linked)
        deadline = contract.get("deadline_ms")
        timing = [
            value
            for value in linked
            if value["technique"] in TIMING_EVIDENCE_TECHNIQUES
            and isinstance(value["metrics"].get("observed_max_ms"), (int, float))
            and not isinstance(value["metrics"].get("observed_max_ms"), bool)
        ]
        observed = [float(value["metrics"]["observed_max_ms"]) for value in timing]
        relationship["observed_max_ms"] = max(observed) if observed else None
        if deadline is not None:
            if any(value > deadline for value in observed):
                relationship["temporal_status"] = "violated"
                _finding(
                    findings,
                    "relationship.deadline_violated",
                    "error",
                    f"Relationship {relationship_id} observed maximum {max(observed)} ms exceeds its {deadline} ms deadline.",
                    f"relationships.{relationship_id}",
                )
            elif any(value["status"] == "passed" for value in timing):
                relationship["temporal_status"] = "supported"

        breaker = contract.get("circuit_breaker")
        if isinstance(breaker, dict):
            resilience = [
                value
                for value in linked
                if value["technique"] in RESILIENCE_EVIDENCE_TECHNIQUES
            ]
            recovery_values = [
                float(value["metrics"]["recovery_time_ms"])
                for value in resilience
                if isinstance(value["metrics"].get("recovery_time_ms"), (int, float))
                and not isinstance(value["metrics"].get("recovery_time_ms"), bool)
            ]
            relationship["observed_recovery_ms"] = (
                max(recovery_values) if recovery_values else None
            )
            recovery_deadline = breaker.get("recovery_deadline_ms")
            violated = any(
                value["metrics"].get("circuit_breaker_opened") is False
                or value["metrics"].get("half_open_recovered") is False
                or (
                    isinstance(value["metrics"].get("recovery_time_ms"), (int, float))
                    and value["metrics"].get("recovery_time_ms") > recovery_deadline
                )
                for value in resilience
            )
            supported = any(
                value["status"] == "passed"
                and value["metrics"].get("circuit_breaker_opened") is True
                and value["metrics"].get("half_open_recovered") is True
                and isinstance(value["metrics"].get("recovery_time_ms"), (int, float))
                and value["metrics"].get("recovery_time_ms") <= recovery_deadline
                for value in resilience
            )
            if violated:
                relationship["resilience_status"] = "violated"
                _finding(
                    findings,
                    "relationship.circuit_breaker_violated",
                    "error",
                    f"Relationship {relationship_id} circuit-breaker evidence violates its opening or recovery contract.",
                    f"relationships.{relationship_id}.circuit_breaker",
                )
            elif supported:
                relationship["resilience_status"] = "supported"

    quality = program.get("quality_gates", {})
    if not isinstance(quality, dict):
        quality = {}
        _finding(
            findings,
            "program.quality_shape",
            "error",
            "quality_gates must be an object.",
            "quality_gates",
        )
    else:
        allowed_quality = {
            "min_validation_repositories",
            "require_independent_validation",
            "min_recall",
            "min_precision",
            "require_count_backed_validation",
            "require_evaluation_result_artifacts",
            "min_micro_recall",
            "min_micro_precision",
            "min_call_resolution_recall",
            "min_call_resolution_precision",
            "min_micro_call_resolution_recall",
            "min_micro_call_resolution_precision",
            "require_temporal_evidence",
            "require_resilience_evidence",
            "min_llm_samples",
            "require_independent_llm_evaluation",
            "require_llm_count_backing",
            "require_llm_corpus_artifacts",
            "require_llm_subject_binding",
            "min_llm_grounding",
            "min_llm_citation_accuracy",
            "max_llm_unsupported_claim_rate",
        }
        unknown_quality = set(quality) - allowed_quality
        if unknown_quality:
            _finding(
                findings,
                "program.quality_unknown",
                "error",
                "Unsupported quality gate(s): "
                + ", ".join(sorted(unknown_quality))
                + ".",
                "quality_gates",
            )
    require_temporal_evidence = _boolean(
        quality,
        "require_temporal_evidence",
        True,
        findings,
        location="quality_gates",
    )
    require_resilience_evidence = _boolean(
        quality,
        "require_resilience_evidence",
        True,
        findings,
        location="quality_gates",
    )
    require_independent_validation = _boolean(
        quality,
        "require_independent_validation",
        False,
        findings,
        location="quality_gates",
    )
    require_count_backed_validation = _boolean(
        quality,
        "require_count_backed_validation",
        False,
        findings,
        location="quality_gates",
    )
    require_evaluation_result_artifacts = _boolean(
        quality,
        "require_evaluation_result_artifacts",
        False,
        findings,
        location="quality_gates",
    )
    require_independent_llm = _boolean(
        quality,
        "require_independent_llm_evaluation",
        True,
        findings,
        location="quality_gates",
    )
    require_llm_count_backing = _boolean(
        quality,
        "require_llm_count_backing",
        False,
        findings,
        location="quality_gates",
    )
    require_llm_corpus_artifacts = _boolean(
        quality,
        "require_llm_corpus_artifacts",
        False,
        findings,
        location="quality_gates",
    )
    require_llm_subject_binding = _boolean(
        quality,
        "require_llm_subject_binding",
        False,
        findings,
        location="quality_gates",
    )
    if require_temporal_evidence:
        for relationship in derived_relationships:
            if (
                relationship["deadline_ms"] is not None
                and relationship["temporal_status"] == "unverified"
            ):
                _finding(
                    findings,
                    "relationship.temporal_evidence_missing",
                    "error",
                    f"Relationship {relationship['id']} has a deadline but no observed timing evidence.",
                    f"relationships.{relationship['id']}",
                )
    if require_resilience_evidence:
        for relationship in derived_relationships:
            if relationship["resilience_status"] == "unverified":
                _finding(
                    findings,
                    "relationship.circuit_breaker_evidence_missing",
                    "error",
                    f"Relationship {relationship['id']} configures a circuit breaker but lacks passing content-addressed fault evidence.",
                    f"relationships.{relationship['id']}.circuit_breaker",
                )

    validation_records = []
    total_evaluation_bytes = 0
    evaluation_artifact_cache: dict[Path, tuple[int, str, Any]] = {}
    cohort_ids: set[str] = set()
    validation_corpus_owners: dict[str, str] = {}
    for index, cohort in enumerate(cohorts):
        location = f"validation_cohorts[{index}]"
        _reject_unknown_fields(
            cohort,
            {
                "id",
                "repository",
                "framework",
                "corpus_sha256",
                "case_count",
                "recall",
                "precision",
                "matched_count",
                "actual_matched_count",
                "actual_count",
                "evaluation_result_format",
                "evaluation_result_sha256",
                "evaluation_verifier_version",
                "evaluation_result_artifact",
                "call_case_count",
                "call_resolution_recall",
                "call_resolution_precision",
                "call_matched_count",
                "call_actual_matched_count",
                "call_actual_count",
                "independent_reviewed",
                "producer",
                "reviewer",
            },
            findings,
            code="validation.unknown_fields",
            location=location,
        )
        try:
            cohort_id = _identifier(cohort.get("id"), label="validation cohort ID")
        except ValueError as exc:
            _finding(
                findings,
                "validation.id",
                "error",
                str(exc),
                f"validation_cohorts[{index}]",
            )
            continue
        if cohort_id in cohort_ids:
            _finding(
                findings,
                "validation.duplicate_id",
                "error",
                f"Duplicate validation cohort ID: {cohort_id}.",
                f"validation_cohorts[{index}]",
            )
            continue
        cohort_ids.add(cohort_id)
        corpus_digest = str(cohort.get("corpus_sha256", "")).lower()
        if len(corpus_digest) != 64 or any(
            char not in "0123456789abcdef" for char in corpus_digest
        ):
            _finding(
                findings,
                "validation.corpus_digest",
                "error",
                "Validation cohort corpus_sha256 must be a lowercase SHA-256 digest.",
                f"validation_cohorts[{index}]",
            )
        try:
            recall = _ratio(cohort.get("recall"), label="cohort recall")
            precision = _ratio(cohort.get("precision"), label="cohort precision")
        except ValueError as exc:
            _finding(
                findings,
                "validation.metric",
                "error",
                str(exc),
                f"validation_cohorts[{index}]",
            )
            continue
        if recall is None or precision is None:
            _finding(
                findings,
                "validation.metric_missing",
                "error",
                "Validation cohorts require recall and precision.",
                f"validation_cohorts[{index}]",
            )
            continue
        case_count = cohort.get("case_count", 0)
        if (
            not isinstance(case_count, int)
            or isinstance(case_count, bool)
            or case_count < 1
        ):
            _finding(
                findings,
                "validation.case_count",
                "error",
                "Validation cohort case_count must be a positive integer.",
                f"validation_cohorts[{index}]",
            )
            continue
        call_case_count = cohort.get("call_case_count", 0)
        if (
            not isinstance(call_case_count, int)
            or isinstance(call_case_count, bool)
            or call_case_count < 0
        ):
            _finding(
                findings,
                "validation.call_case_count",
                "error",
                "Validation cohort call_case_count must be a non-negative integer.",
                location,
            )
            continue
        try:
            call_recall = _ratio(
                cohort.get("call_resolution_recall"),
                label="cohort call-resolution recall",
            )
            call_precision = _ratio(
                cohort.get("call_resolution_precision"),
                label="cohort call-resolution precision",
            )
        except ValueError as exc:
            _finding(findings, "validation.call_metric", "error", str(exc), location)
            continue
        if call_case_count and (call_recall is None or call_precision is None):
            _finding(
                findings,
                "validation.call_metric_missing",
                "error",
                "Validation cohorts with call cases require call-resolution recall and precision.",
                location,
            )
            continue
        if not call_case_count and (
            call_recall is not None or call_precision is not None
        ):
            _finding(
                findings,
                "validation.call_metric_without_cases",
                "error",
                "Call-resolution metrics require a positive call_case_count.",
                location,
            )
            continue

        count_fields = {
            "matched_count",
            "actual_matched_count",
            "actual_count",
            "evaluation_result_format",
            "evaluation_result_sha256",
            "evaluation_verifier_version",
        }
        supplied_count_fields = count_fields & set(cohort)
        count_backed = bool(supplied_count_fields)
        matched_count: int | None = None
        actual_matched_count: int | None = None
        actual_count: int | None = None
        if count_backed and supplied_count_fields != count_fields:
            _finding(
                findings,
                "validation.count_provenance_incomplete",
                "error",
                "Count-backed validation requires matched_count, actual_matched_count, actual_count, evaluation_result_format, evaluation_result_sha256, and evaluation_verifier_version together.",
                location,
            )
            count_backed = False
        elif count_backed:
            matched_value = cohort.get("matched_count")
            actual_matched_value = cohort.get("actual_matched_count")
            actual_value = cohort.get("actual_count")
            counts_valid = all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in (matched_value, actual_matched_value, actual_value)
            )
            if not counts_valid:
                _finding(
                    findings,
                    "validation.count_value",
                    "error",
                    "matched_count, actual_matched_count, and actual_count must be non-negative integers.",
                    location,
                )
                count_backed = False
            else:
                matched_count = int(matched_value)
                actual_matched_count = int(actual_matched_value)
                actual_count = int(actual_value)
                if (
                    actual_count < 1
                    or matched_count > case_count
                    or actual_matched_count > actual_count
                ):
                    _finding(
                        findings,
                        "validation.count_relationship",
                        "error",
                        "Count-backed validation requires positive actual_count, expected-side matches no greater than case_count, and actual-side matches no greater than actual_count.",
                        location,
                    )
                    count_backed = False
                elif recall != round(
                    matched_count / case_count, 4
                ) or precision != round(actual_matched_count / actual_count, 4):
                    _finding(
                        findings,
                        "validation.metric_reconciliation",
                        "error",
                        "Claimed recall or precision does not reconcile with matched, expected, and actual counts.",
                        location,
                    )
                    count_backed = False
            evaluation_digest = str(cohort.get("evaluation_result_sha256", "")).lower()
            if (
                cohort.get("evaluation_result_format") != "pysfmea-evaluation-result-1"
                or len(evaluation_digest) != 64
                or any(char not in "0123456789abcdef" for char in evaluation_digest)
            ):
                _finding(
                    findings,
                    "validation.evaluation_provenance",
                    "error",
                    "Count-backed validation requires the supported evaluation-result format and a lowercase SHA-256 digest.",
                    location,
                )
                count_backed = False
            try:
                _bounded_text(
                    cohort.get("evaluation_verifier_version"),
                    label="evaluation verifier version",
                    limit=100,
                )
            except ValueError as exc:
                _finding(
                    findings,
                    "validation.evaluation_provenance",
                    "error",
                    str(exc),
                    location,
                )
                count_backed = False

        call_count_fields = {
            "call_matched_count",
            "call_actual_matched_count",
            "call_actual_count",
        }
        supplied_call_count_fields = call_count_fields & set(cohort)
        call_count_backed = bool(supplied_call_count_fields)
        call_matched_count: int | None = None
        call_actual_matched_count: int | None = None
        call_actual_count: int | None = None
        if call_count_backed and supplied_call_count_fields != call_count_fields:
            _finding(
                findings,
                "validation.call_count_provenance_incomplete",
                "error",
                "Count-backed call validation requires call_matched_count, call_actual_matched_count, and call_actual_count together.",
                location,
            )
            call_count_backed = False
        elif call_count_backed:
            call_matched_value = cohort.get("call_matched_count")
            call_actual_matched_value = cohort.get("call_actual_matched_count")
            call_actual_value = cohort.get("call_actual_count")
            call_counts_valid = all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in (
                    call_matched_value,
                    call_actual_matched_value,
                    call_actual_value,
                )
            )
            if not call_counts_valid or not count_backed or not call_case_count:
                _finding(
                    findings,
                    "validation.call_count_value",
                    "error",
                    "Call counts must be non-negative integers on a count-backed cohort with positive call_case_count.",
                    location,
                )
                call_count_backed = False
            else:
                call_matched_count = int(call_matched_value)
                call_actual_matched_count = int(call_actual_matched_value)
                call_actual_count = int(call_actual_value)
                if (
                    call_actual_count < 1
                    or call_matched_count > call_case_count
                    or call_actual_matched_count > call_actual_count
                ):
                    _finding(
                        findings,
                        "validation.call_count_relationship",
                        "error",
                        "Call expected-side matches must not exceed call_case_count, actual-side matches must not exceed call_actual_count, and the actual count must be positive.",
                        location,
                    )
                    call_count_backed = False
                elif call_recall != round(
                    call_matched_count / call_case_count, 4
                ) or call_precision != round(
                    call_actual_matched_count / call_actual_count, 4
                ):
                    _finding(
                        findings,
                        "validation.call_metric_reconciliation",
                        "error",
                        "Claimed call-resolution metrics do not reconcile with matched, expected, and actual counts.",
                        location,
                    )
                    call_count_backed = False
        if call_case_count and count_backed and not supplied_call_count_fields:
            call_count_backed = False

        evaluation_artifact = cohort.get("evaluation_result_artifact")
        artifact_declared = evaluation_artifact is not None
        evaluation_artifact_verified = False
        if artifact_declared:
            if not isinstance(evaluation_artifact, dict):
                _finding(
                    findings,
                    "validation.evaluation_artifact_shape",
                    "error",
                    "evaluation_result_artifact must be an object with path and sha256.",
                    location,
                )
            else:
                artifact_fields_valid = _reject_unknown_fields(
                    evaluation_artifact,
                    {"path", "sha256"},
                    findings,
                    code="validation.evaluation_artifact_unknown_fields",
                    location=f"{location}.evaluation_result_artifact",
                )
                try:
                    artifact_reference = _bounded_text(
                        evaluation_artifact.get("path"),
                        label="evaluation result artifact path",
                        limit=4096,
                    )
                except ValueError as exc:
                    artifact_fields_valid = False
                    artifact_reference = ""
                    _finding(
                        findings,
                        "validation.evaluation_artifact_path",
                        "error",
                        str(exc),
                        location,
                    )
                artifact_digest = str(evaluation_artifact.get("sha256", "")).lower()
                if len(artifact_digest) != 64 or any(
                    char not in "0123456789abcdef" for char in artifact_digest
                ):
                    artifact_fields_valid = False
                    _finding(
                        findings,
                        "validation.evaluation_artifact_digest",
                        "error",
                        "Evaluation result artifact sha256 must be a lowercase SHA-256 digest.",
                        location,
                    )
                if artifact_fields_valid:
                    artifact_path = Path(artifact_reference).expanduser()
                    if not artifact_path.is_absolute():
                        artifact_path = document.path.parent / artifact_path
                    artifact_path = Path(os.path.abspath(artifact_path))
                    try:
                        if artifact_path not in evaluation_artifact_cache:
                            evaluation_document = load_bounded_json_document(
                                artifact_path,
                                label=f"validation cohort {cohort_id} evaluation result",
                                max_bytes=MAX_EVALUATION_RESULT_BYTES,
                                max_depth=50,
                                max_nodes=500_000,
                            )
                            raw_digest = hashlib.sha256(
                                evaluation_document.raw
                            ).hexdigest()
                            if (
                                total_evaluation_bytes + evaluation_document.size
                                > MAX_TOTAL_EVALUATION_BYTES
                            ):
                                raise ValueError(
                                    f"evaluation artifacts exceed the {MAX_TOTAL_EVALUATION_BYTES}-byte aggregate limit"
                                )
                            evaluation_artifact_cache[artifact_path] = (
                                evaluation_document.size,
                                raw_digest,
                                evaluation_document.value,
                            )
                            total_evaluation_bytes += evaluation_document.size
                        _, raw_digest, evaluation_result = evaluation_artifact_cache[
                            artifact_path
                        ]
                        if raw_digest != artifact_digest:
                            _finding(
                                findings,
                                "validation.evaluation_artifact_digest",
                                "error",
                                "Evaluation result artifact bytes do not match the declared digest.",
                                location,
                            )
                        elif canonical_json_sha256(evaluation_result) != str(
                            cohort.get("evaluation_result_sha256", "")
                        ):
                            _finding(
                                findings,
                                "validation.evaluation_artifact_content",
                                "error",
                                "Evaluation result artifact content does not match the cohort's canonical digest.",
                                location,
                            )
                        elif not _evaluation_result_matches_cohort(
                            evaluation_result, cohort
                        ):
                            _finding(
                                findings,
                                "validation.evaluation_artifact_claims",
                                "error",
                                "Evaluation result artifact metrics, counts, corpus, or verifier do not match the cohort projection.",
                                location,
                            )
                        else:
                            evaluation_artifact_verified = True
                    except (ValueError, BoundedFileSnapshotError) as exc:
                        _finding(
                            findings,
                            "validation.evaluation_artifact_rejected",
                            "error",
                            str(exc),
                            location,
                        )
        for field in ("repository", "framework", "producer", "reviewer"):
            try:
                _bounded_text(cohort.get(field), label=f"validation cohort {field}")
            except ValueError as exc:
                _finding(
                    findings,
                    "validation.provenance",
                    "error",
                    str(exc),
                    f"{location}.{field}",
                )
        if not isinstance(cohort.get("independent_reviewed"), bool):
            _finding(
                findings,
                "validation.independence_value",
                "error",
                "Validation cohort independent_reviewed must be a boolean.",
                f"{location}.independent_reviewed",
            )
        independent = cohort.get("independent_reviewed") is True
        producer = str(cohort.get("producer", "")).strip().casefold()
        reviewer = str(cohort.get("reviewer", "")).strip().casefold()
        if independent and (not producer or not reviewer or producer == reviewer):
            _finding(
                findings,
                "validation.independence_identity",
                "error",
                f"Validation cohort {cohort_id} requires distinct named producer and reviewer identities.",
                location,
            )
            independent = False
        duplicate_evidence = False
        if len(corpus_digest) == 64 and not any(
            char not in "0123456789abcdef" for char in corpus_digest
        ):
            previous_cohort = validation_corpus_owners.get(corpus_digest)
            if previous_cohort is not None:
                duplicate_evidence = True
                _finding(
                    findings,
                    "validation.duplicate_corpus_evidence",
                    "error",
                    f"Validation cohort {cohort_id} reuses the labeled corpus already declared by {previous_cohort}; duplicate evidence receives no aggregate credit.",
                    location,
                )
            else:
                validation_corpus_owners[corpus_digest] = cohort_id
        validation_records.append(
            {
                "id": cohort_id,
                "repository": str(cohort.get("repository", "")),
                "recall": recall,
                "precision": precision,
                "call_recall": call_recall,
                "call_precision": call_precision,
                "independent": independent,
                "case_count": case_count,
                "call_case_count": call_case_count,
                "count_backed": count_backed,
                "matched_count": matched_count,
                "actual_matched_count": actual_matched_count,
                "actual_count": actual_count,
                "call_count_backed": call_count_backed,
                "call_matched_count": call_matched_count,
                "call_actual_matched_count": call_actual_matched_count,
                "call_actual_count": call_actual_count,
                "evaluation_artifact_declared": artifact_declared,
                "evaluation_artifact_verified": evaluation_artifact_verified,
                "duplicate_evidence": duplicate_evidence,
            }
        )
    credited_validation_records = [
        value for value in validation_records if not value["duplicate_evidence"]
    ]
    declared_call_validation_records = [
        value for value in validation_records if value["call_case_count"] > 0
    ]
    call_validation_records = [
        value
        for value in credited_validation_records
        if value["call_case_count"] > 0
    ]
    count_backed_records = [
        value for value in credited_validation_records if value["count_backed"]
    ]
    call_count_backed_records = [
        value for value in call_validation_records if value["call_count_backed"]
    ]
    total_count_backed_cases = sum(
        value["case_count"] for value in count_backed_records
    )
    total_count_backed_actual = sum(
        value["actual_count"] for value in count_backed_records
    )
    total_count_backed_expected_matched = sum(
        value["matched_count"] for value in count_backed_records
    )
    total_count_backed_actual_matched = sum(
        value["actual_matched_count"] for value in count_backed_records
    )
    total_call_count_backed_cases = sum(
        value["call_case_count"] for value in call_count_backed_records
    )
    total_call_count_backed_actual = sum(
        value["call_actual_count"] for value in call_count_backed_records
    )
    total_call_count_backed_expected_matched = sum(
        value["call_matched_count"] for value in call_count_backed_records
    )
    total_call_count_backed_actual_matched = sum(
        value["call_actual_matched_count"] for value in call_count_backed_records
    )
    validation_summary = {
        "cohorts": len(validation_records),
        "credited_cohorts": len(credited_validation_records),
        "duplicate_evidence": len(validation_records)
        - len(credited_validation_records),
        "repositories": len(
            {
                value["repository"]
                for value in credited_validation_records
                if value["repository"]
            }
        ),
        "independently_reviewed": sum(
            value["independent"] for value in credited_validation_records
        ),
        "macro_recall": round(
            sum(value["recall"] for value in credited_validation_records)
            / len(credited_validation_records),
            4,
        )
        if credited_validation_records
        else None,
        "macro_precision": round(
            sum(value["precision"] for value in credited_validation_records)
            / len(credited_validation_records),
            4,
        )
        if credited_validation_records
        else None,
        "cases": sum(value["case_count"] for value in credited_validation_records),
        "count_backed_cohorts": len(count_backed_records),
        "count_backed_cases": total_count_backed_cases,
        "evaluation_artifacts": sum(
            value["evaluation_artifact_declared"]
            for value in credited_validation_records
        ),
        "verified_evaluation_artifacts": sum(
            value["evaluation_artifact_verified"]
            for value in credited_validation_records
        ),
        "evaluation_artifact_bytes": total_evaluation_bytes,
        "micro_recall": round(
            total_count_backed_expected_matched / total_count_backed_cases, 4
        )
        if total_count_backed_cases
        else None,
        "micro_precision": round(
            total_count_backed_actual_matched / total_count_backed_actual, 4
        )
        if total_count_backed_actual
        else None,
        "call_cases": sum(
            value["call_case_count"] for value in credited_validation_records
        ),
        "call_resolution_cohorts": len(call_validation_records),
        "call_count_backed_cohorts": len(call_count_backed_records),
        "call_count_backed_cases": total_call_count_backed_cases,
        "macro_call_resolution_recall": round(
            sum(value["call_recall"] for value in call_validation_records)
            / len(call_validation_records),
            4,
        )
        if call_validation_records
        else None,
        "macro_call_resolution_precision": round(
            sum(value["call_precision"] for value in call_validation_records)
            / len(call_validation_records),
            4,
        )
        if call_validation_records
        else None,
        "micro_call_resolution_recall": round(
            total_call_count_backed_expected_matched / total_call_count_backed_cases,
            4,
        )
        if total_call_count_backed_cases
        else None,
        "micro_call_resolution_precision": round(
            total_call_count_backed_actual_matched / total_call_count_backed_actual,
            4,
        )
        if total_call_count_backed_actual
        else None,
    }
    min_repositories = _quality_integer(
        quality, "min_validation_repositories", findings
    )
    if validation_summary["repositories"] < min_repositories:
        _finding(
            findings,
            "validation.repository_count",
            "error",
            f"Independent validation covers {validation_summary['repositories']} repositories; {min_repositories} required.",
            "validation_cohorts",
        )
    if require_independent_validation and sum(
        value["independent"] for value in validation_records
    ) < len(validation_records):
        _finding(
            findings,
            "validation.independence",
            "error",
            "Every configured validation cohort must be independently reviewed.",
            "validation_cohorts",
        )
    if require_count_backed_validation and sum(
        value["count_backed"] for value in validation_records
    ) < len(validation_records):
        _finding(
            findings,
            "validation.count_backing",
            "error",
            "Every configured validation cohort must carry reconciled counts and evaluation-result provenance.",
            "validation_cohorts",
        )
    if require_evaluation_result_artifacts and sum(
        value["evaluation_artifact_verified"] for value in validation_records
    ) < len(validation_records):
        _finding(
            findings,
            "validation.evaluation_artifacts",
            "error",
            "Every configured validation cohort must bind a verified retained evaluation-result artifact.",
            "validation_cohorts",
        )
    if require_count_backed_validation and sum(
        value["call_count_backed"] for value in declared_call_validation_records
    ) < len(declared_call_validation_records):
        _finding(
            findings,
            "validation.call_count_backing",
            "error",
            "Every cohort with call cases must carry reconciled call-resolution counts.",
            "validation_cohorts",
        )
    for metric in ("recall", "precision"):
        value = validation_summary[f"macro_{metric}"]
        threshold = _quality_ratio(quality, f"min_{metric}", 0.0, findings)
        if value is not None and value < threshold:
            _finding(
                findings,
                f"validation.{metric}",
                "error",
                f"Macro {metric} {value:.4f} is below the configured {threshold:.4f} threshold.",
                "validation_cohorts",
            )
    for metric in ("recall", "precision"):
        value = validation_summary[f"micro_{metric}"]
        threshold = _quality_ratio(quality, f"min_micro_{metric}", 0.0, findings)
        if value is None and threshold > 0 and validation_records:
            _finding(
                findings,
                f"validation.micro_{metric}_unavailable",
                "error",
                f"Micro {metric} cannot be computed without count-backed validation cohorts.",
                "validation_cohorts",
            )
        elif value is not None and value < threshold:
            _finding(
                findings,
                f"validation.micro_{metric}",
                "error",
                f"Micro {metric} {value:.4f} is below the configured {threshold:.4f} threshold.",
                "validation_cohorts",
            )
    for metric in ("recall", "precision"):
        value = validation_summary[f"macro_call_resolution_{metric}"]
        threshold = _quality_ratio(
            quality,
            f"min_call_resolution_{metric}",
            0.0,
            findings,
        )
        if value is not None and value < threshold:
            _finding(
                findings,
                f"validation.call_resolution_{metric}",
                "error",
                f"Macro call-resolution {metric} {value:.4f} is below the configured {threshold:.4f} threshold.",
                "validation_cohorts",
            )
    for metric in ("recall", "precision"):
        value = validation_summary[f"micro_call_resolution_{metric}"]
        threshold = _quality_ratio(
            quality,
            f"min_micro_call_resolution_{metric}",
            0.0,
            findings,
        )
        if value is None and threshold > 0 and call_validation_records:
            _finding(
                findings,
                f"validation.micro_call_resolution_{metric}_unavailable",
                "error",
                f"Micro call-resolution {metric} cannot be computed without count-backed call cohorts.",
                "validation_cohorts",
            )
        elif value is not None and value < threshold:
            _finding(
                findings,
                f"validation.micro_call_resolution_{metric}",
                "error",
                f"Micro call-resolution {metric} {value:.4f} is below the configured {threshold:.4f} threshold.",
                "validation_cohorts",
            )

    llm_records = []
    total_llm_corpus_bytes = 0
    llm_corpus_cache: dict[Path, tuple[int, str, Any]] = {}
    llm_ids: set[str] = set()
    llm_corpus_owners: dict[str, str] = {}
    for index, evaluation in enumerate(llm_evaluations):
        location = f"llm_evaluations[{index}]"
        _reject_unknown_fields(
            evaluation,
            {
                "id",
                "provider",
                "model",
                "prompt_version",
                "sample_count",
                "grounding",
                "citation_accuracy",
                "unsupported_claim_rate",
                "grounded_sample_count",
                "citation_correct_sample_count",
                "claim_count",
                "unsupported_claim_count",
                "corpus_sha256",
                "evidence_fingerprint_sha256",
                "corpus_format",
                "subject_bound",
                "corpus_artifact",
                "independent_reviewed",
                "producer",
                "reviewer",
            },
            findings,
            code="llm.unknown_fields",
            location=location,
        )
        try:
            evaluation_id = _identifier(evaluation.get("id"), label="LLM evaluation ID")
        except ValueError as exc:
            _finding(findings, "llm.id", "error", str(exc), f"llm_evaluations[{index}]")
            continue
        if evaluation_id in llm_ids:
            _finding(
                findings,
                "llm.duplicate_id",
                "error",
                f"Duplicate LLM evaluation ID: {evaluation_id}.",
                f"llm_evaluations[{index}]",
            )
            continue
        llm_ids.add(evaluation_id)
        if not all(
            isinstance(evaluation.get(field), str) and evaluation.get(field).strip()
            for field in ("provider", "model", "prompt_version", "producer", "reviewer")
        ):
            _finding(
                findings,
                "llm.provenance",
                "error",
                "LLM evaluations require provider, model, prompt version, producer, and reviewer provenance.",
                f"llm_evaluations[{index}]",
            )
            continue
        corpus_digest = str(evaluation.get("corpus_sha256", ""))
        if len(corpus_digest) != 64 or any(
            char not in "0123456789abcdef" for char in corpus_digest
        ):
            _finding(
                findings,
                "llm.corpus_digest",
                "error",
                "LLM evaluation corpus_sha256 must be a lowercase SHA-256 digest.",
                location,
            )
        evidence_fingerprint_claim = evaluation.get("evidence_fingerprint_sha256")
        if evidence_fingerprint_claim is not None and (
            not isinstance(evidence_fingerprint_claim, str)
            or len(evidence_fingerprint_claim) != 64
            or any(
                char not in "0123456789abcdef"
                for char in evidence_fingerprint_claim
            )
        ):
            _finding(
                findings,
                "llm.evidence_fingerprint",
                "error",
                "LLM evidence_fingerprint_sha256 must be a lowercase SHA-256 digest when declared.",
                location,
            )
        subject_fields = {"corpus_format", "subject_bound"} & set(evaluation)
        subject_binding_claimed = False
        if subject_fields and subject_fields != {"corpus_format", "subject_bound"}:
            _finding(
                findings,
                "llm.subject_provenance_incomplete",
                "error",
                "LLM corpus_format and subject_bound must be declared together.",
                location,
            )
        elif subject_fields:
            corpus_format = evaluation.get("corpus_format")
            subject_bound_value = evaluation.get("subject_bound")
            if (
                corpus_format
                not in {
                    "pysfmea-llm-quality-corpus-1",
                    "pysfmea-llm-quality-corpus-2",
                }
                or not isinstance(subject_bound_value, bool)
                or subject_bound_value
                != (corpus_format == "pysfmea-llm-quality-corpus-2")
            ):
                _finding(
                    findings,
                    "llm.subject_provenance",
                    "error",
                    "subject_bound must be true exactly for the subject-bound corpus format.",
                    location,
                )
            else:
                subject_binding_claimed = subject_bound_value
        try:
            grounding = _ratio(evaluation.get("grounding"), label="LLM grounding")
            citation = _ratio(
                evaluation.get("citation_accuracy"), label="LLM citation accuracy"
            )
            unsupported = _ratio(
                evaluation.get("unsupported_claim_rate"),
                label="LLM unsupported claim rate",
            )
        except ValueError as exc:
            _finding(
                findings, "llm.metric", "error", str(exc), f"llm_evaluations[{index}]"
            )
            continue
        samples = evaluation.get("sample_count", 0)
        if (
            any(value is None for value in (grounding, citation, unsupported))
            or not isinstance(samples, int)
            or isinstance(samples, bool)
            or samples < 1
        ):
            _finding(
                findings,
                "llm.metric_missing",
                "error",
                "LLM evaluations require three ratios and a positive sample_count.",
                f"llm_evaluations[{index}]",
            )
            continue

        llm_count_fields = {
            "grounded_sample_count",
            "citation_correct_sample_count",
            "claim_count",
            "unsupported_claim_count",
        }
        supplied_llm_count_fields = llm_count_fields & set(evaluation)
        llm_count_backed = bool(supplied_llm_count_fields)
        grounded_count: int | None = None
        citation_count: int | None = None
        claim_count: int | None = None
        unsupported_count: int | None = None
        if llm_count_backed and supplied_llm_count_fields != llm_count_fields:
            _finding(
                findings,
                "llm.count_provenance_incomplete",
                "error",
                "Count-backed LLM evaluation requires grounded, citation-correct, total-claim, and unsupported-claim counts together.",
                location,
            )
            llm_count_backed = False
        elif llm_count_backed:
            raw_counts = [evaluation.get(field) for field in llm_count_fields]
            if not all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in raw_counts
            ):
                _finding(
                    findings,
                    "llm.count_value",
                    "error",
                    "LLM quality counts must be non-negative integers.",
                    location,
                )
                llm_count_backed = False
            else:
                grounded_count = int(evaluation["grounded_sample_count"])
                citation_count = int(evaluation["citation_correct_sample_count"])
                claim_count = int(evaluation["claim_count"])
                unsupported_count = int(evaluation["unsupported_claim_count"])
                if (
                    grounded_count > samples
                    or citation_count > samples
                    or claim_count < 1
                    or unsupported_count > claim_count
                ):
                    _finding(
                        findings,
                        "llm.count_relationship",
                        "error",
                        "LLM decision counts must not exceed sample_count and unsupported claims must not exceed a positive claim_count.",
                        location,
                    )
                    llm_count_backed = False
                elif (
                    grounding != round(grounded_count / samples, 4)
                    or citation != round(citation_count / samples, 4)
                    or unsupported != round(unsupported_count / claim_count, 4)
                ):
                    _finding(
                        findings,
                        "llm.metric_reconciliation",
                        "error",
                        "Claimed LLM quality rates do not reconcile with their sample and claim counts.",
                        location,
                    )
                    llm_count_backed = False

        corpus_artifact = evaluation.get("corpus_artifact")
        corpus_artifact_declared = corpus_artifact is not None
        corpus_artifact_verified = False
        semantic_fingerprint: str | None = None
        if corpus_artifact_declared:
            if not isinstance(corpus_artifact, dict):
                _finding(
                    findings,
                    "llm.corpus_artifact_shape",
                    "error",
                    "corpus_artifact must be an object with path and sha256.",
                    location,
                )
            else:
                artifact_fields_valid = _reject_unknown_fields(
                    corpus_artifact,
                    {"path", "sha256"},
                    findings,
                    code="llm.corpus_artifact_unknown_fields",
                    location=f"{location}.corpus_artifact",
                )
                try:
                    corpus_reference = _bounded_text(
                        corpus_artifact.get("path"),
                        label="LLM quality corpus artifact path",
                        limit=4096,
                    )
                except ValueError as exc:
                    artifact_fields_valid = False
                    corpus_reference = ""
                    _finding(
                        findings,
                        "llm.corpus_artifact_path",
                        "error",
                        str(exc),
                        location,
                    )
                corpus_artifact_digest = str(corpus_artifact.get("sha256", ""))
                if (
                    len(corpus_artifact_digest) != 64
                    or any(
                        char not in "0123456789abcdef"
                        for char in corpus_artifact_digest
                    )
                    or corpus_artifact_digest != corpus_digest
                ):
                    artifact_fields_valid = False
                    _finding(
                        findings,
                        "llm.corpus_artifact_digest",
                        "error",
                        "LLM corpus artifact digest must be lowercase SHA-256 and match corpus_sha256.",
                        location,
                    )
                if artifact_fields_valid:
                    corpus_path = Path(corpus_reference).expanduser()
                    if not corpus_path.is_absolute():
                        corpus_path = document.path.parent / corpus_path
                    corpus_path = Path(os.path.abspath(corpus_path))
                    try:
                        if corpus_path not in llm_corpus_cache:
                            corpus_document = load_bounded_json_document(
                                corpus_path,
                                label=f"LLM evaluation {evaluation_id} corpus artifact",
                                max_bytes=MAX_LLM_CORPUS_BYTES,
                                max_depth=30,
                                max_nodes=1_000_000,
                            )
                            raw_digest = hashlib.sha256(corpus_document.raw).hexdigest()
                            if (
                                total_llm_corpus_bytes + corpus_document.size
                                > MAX_TOTAL_LLM_CORPUS_BYTES
                            ):
                                raise ValueError(
                                    f"LLM corpus artifacts exceed the {MAX_TOTAL_LLM_CORPUS_BYTES}-byte aggregate limit"
                                )
                            llm_corpus_cache[corpus_path] = (
                                corpus_document.size,
                                raw_digest,
                                corpus_document.value,
                            )
                            total_llm_corpus_bytes += corpus_document.size
                        _, raw_digest, corpus_value = llm_corpus_cache[corpus_path]
                        if raw_digest != corpus_digest:
                            _finding(
                                findings,
                                "llm.corpus_artifact_digest",
                                "error",
                                "LLM corpus artifact bytes do not match corpus_sha256.",
                                location,
                            )
                        else:
                            semantic_fingerprint = (
                                _llm_corpus_evidence_fingerprint(
                                    corpus_value, evaluation
                                )
                                if llm_count_backed
                                else None
                            )
                        if raw_digest == corpus_digest and semantic_fingerprint is None:
                            _finding(
                                findings,
                                "llm.corpus_artifact_claims",
                                "error",
                                "LLM corpus samples do not match the evaluation counts or metrics.",
                                location,
                            )
                        elif semantic_fingerprint is not None:
                            corpus_artifact_verified = True
                    except (ValueError, BoundedFileSnapshotError) as exc:
                        _finding(
                            findings,
                            "llm.corpus_artifact_rejected",
                            "error",
                            str(exc),
                            location,
                        )
        if not isinstance(evaluation.get("independent_reviewed"), bool):
            _finding(
                findings,
                "llm.independence_value",
                "error",
                "LLM evaluation independent_reviewed must be a boolean.",
                f"{location}.independent_reviewed",
            )
        independent = evaluation.get("independent_reviewed") is True
        if (
            independent
            and str(evaluation.get("producer", "")).strip().casefold()
            == str(evaluation.get("reviewer", "")).strip().casefold()
        ):
            _finding(
                findings,
                "llm.independence_identity",
                "error",
                f"LLM evaluation {evaluation_id} requires distinct producer and reviewer identities.",
                location,
            )
            independent = False
        duplicate_evidence = False
        credit_identity = semantic_fingerprint or corpus_digest
        if len(credit_identity) == 64 and not any(
            char not in "0123456789abcdef" for char in credit_identity
        ):
            previous_evaluation = llm_corpus_owners.get(credit_identity)
            if previous_evaluation is not None:
                duplicate_evidence = True
                _finding(
                    findings,
                    "llm.duplicate_corpus_evidence",
                    "error",
                    f"LLM evaluation {evaluation_id} reuses semantically equivalent labeled evidence already declared by {previous_evaluation}; duplicate evidence receives no aggregate credit.",
                    location,
                )
            else:
                llm_corpus_owners[credit_identity] = evaluation_id
        llm_records.append(
            {
                "id": evaluation_id,
                "grounding": grounding,
                "citation_accuracy": citation,
                "unsupported_claim_rate": unsupported,
                "sample_count": samples,
                "independent": independent,
                "count_backed": llm_count_backed,
                "grounded_count": grounded_count,
                "citation_count": citation_count,
                "claim_count": claim_count,
                "unsupported_count": unsupported_count,
                "corpus_artifact_declared": corpus_artifact_declared,
                "corpus_artifact_verified": corpus_artifact_verified,
                "semantic_fingerprint_verified": semantic_fingerprint is not None,
                "subject_binding_verified": subject_binding_claimed
                and corpus_artifact_verified,
                "duplicate_evidence": duplicate_evidence,
            }
        )
    credited_llm_records = [
        value for value in llm_records if not value["duplicate_evidence"]
    ]
    llm_samples = sum(value["sample_count"] for value in credited_llm_records)
    llm_count_backed_records = [
        value for value in credited_llm_records if value["count_backed"]
    ]
    llm_counts_complete = bool(credited_llm_records) and len(
        llm_count_backed_records
    ) == len(credited_llm_records)
    llm_claims = sum(value["claim_count"] for value in llm_count_backed_records)
    llm_unsupported_claims = sum(
        value["unsupported_count"] for value in llm_count_backed_records
    )

    def weighted(field: str) -> float | None:
        return (
            round(
                sum(
                    value[field] * value["sample_count"]
                    for value in credited_llm_records
                )
                / llm_samples,
                4,
            )
            if llm_samples
            else None
        )

    llm_summary = {
        "evaluations": len(llm_records),
        "credited_evaluations": len(credited_llm_records),
        "duplicate_evidence": len(llm_records) - len(credited_llm_records),
        "samples": llm_samples,
        "independently_reviewed": sum(
            value["independent"] for value in credited_llm_records
        ),
        "count_backed_evaluations": len(llm_count_backed_records),
        "verified_corpus_artifacts": sum(
            value["corpus_artifact_verified"] for value in credited_llm_records
        ),
        "subject_bound_evaluations": sum(
            value["subject_binding_verified"] for value in credited_llm_records
        ),
        "semantic_fingerprinted_evaluations": sum(
            value["semantic_fingerprint_verified"] for value in credited_llm_records
        ),
        "corpus_artifacts": sum(
            value["corpus_artifact_declared"] for value in credited_llm_records
        ),
        "corpus_artifact_bytes": total_llm_corpus_bytes,
        "claim_count": llm_claims if llm_counts_complete else None,
        "unsupported_claim_count": llm_unsupported_claims
        if llm_counts_complete
        else None,
        "aggregation_method": "count-backed"
        if llm_counts_complete
        else (
            "legacy-sample-weighted" if credited_llm_records else "unavailable"
        ),
        "grounding": round(
            sum(value["grounded_count"] for value in llm_count_backed_records)
            / llm_samples,
            4,
        )
        if llm_counts_complete
        else weighted("grounding"),
        "citation_accuracy": round(
            sum(value["citation_count"] for value in llm_count_backed_records)
            / llm_samples,
            4,
        )
        if llm_counts_complete
        else weighted("citation_accuracy"),
        "unsupported_claim_rate": round(llm_unsupported_claims / llm_claims, 4)
        if llm_counts_complete and llm_claims
        else weighted("unsupported_claim_rate"),
    }
    min_llm_samples = _quality_integer(quality, "min_llm_samples", findings)
    if llm_samples < min_llm_samples:
        _finding(
            findings,
            "llm.sample_count",
            "error",
            f"LLM quality evaluation covers {llm_samples} samples; {min_llm_samples} required.",
            "llm_evaluations",
        )
    if (
        require_independent_llm
        and llm_records
        and sum(value["independent"] for value in llm_records) < len(llm_records)
    ):
        _finding(
            findings,
            "llm.independence",
            "error",
            "Every configured LLM evaluation must be independently reviewed.",
            "llm_evaluations",
        )
    if require_llm_count_backing and sum(
        value["count_backed"] for value in llm_records
    ) < len(llm_records):
        _finding(
            findings,
            "llm.count_backing",
            "error",
            "Every configured LLM quality evaluation must carry reconciled decision and claim counts.",
            "llm_evaluations",
        )
    if require_llm_corpus_artifacts and sum(
        value["corpus_artifact_verified"] for value in llm_records
    ) < len(llm_records):
        _finding(
            findings,
            "llm.corpus_artifacts",
            "error",
            "Every configured LLM quality evaluation must bind a verified retained labeled corpus.",
            "llm_evaluations",
        )
    if require_llm_subject_binding and sum(
        value["subject_binding_verified"] for value in llm_records
    ) < len(llm_records):
        _finding(
            findings,
            "llm.subject_binding",
            "error",
            "Every configured LLM quality evaluation must bind its retained corpus to the declared provider, model, and prompt version.",
            "llm_evaluations",
        )
    if llm_samples:
        for field, gate, direction in (
            ("grounding", "min_llm_grounding", "min"),
            ("citation_accuracy", "min_llm_citation_accuracy", "min"),
            ("unsupported_claim_rate", "max_llm_unsupported_claim_rate", "max"),
        ):
            threshold = _quality_ratio(
                quality, gate, 0.0 if direction == "min" else 1.0, findings
            )
            value = llm_summary[field]
            failed = value < threshold if direction == "min" else value > threshold
            if failed:
                _finding(
                    findings,
                    f"llm.{field}",
                    "error",
                    f"LLM {field.replace('_', ' ')} {value:.4f} does not satisfy the configured {threshold:.4f} threshold.",
                    "llm_evaluations",
                )

    governance = program.get("governance", {})
    if not isinstance(governance, dict):
        governance = {}
        _finding(
            findings,
            "governance.shape",
            "error",
            "governance must be an object.",
            "governance",
        )
    else:
        allowed_governance = {
            "required_roles",
            "independent_evidence_review",
            "require_program_approval",
            "approvals",
        }
        unknown_governance = set(governance) - allowed_governance
        if unknown_governance:
            _finding(
                findings,
                "governance.unknown",
                "error",
                "Unsupported governance field(s): "
                + ", ".join(sorted(unknown_governance))
                + ".",
                "governance",
            )
    approvals = governance.get("approvals", [])
    if (
        not isinstance(approvals, list)
        or not all(isinstance(value, dict) for value in approvals)
        or len(approvals) > MAX_PROGRAM_APPROVALS
    ):
        approvals = []
        _finding(
            findings,
            "governance.approvals",
            "error",
            "governance approvals must be a bounded array of objects.",
            "governance.approvals",
        )
    independent_evidence_review = _boolean(
        governance,
        "independent_evidence_review",
        False,
        findings,
        location="governance",
    )
    require_program_approval = _boolean(
        governance,
        "require_program_approval",
        False,
        findings,
        location="governance",
    )
    approved_roles: set[str] = set()
    rejected_program_roles: set[str] = set()
    program_role_reviewers: dict[str, set[str]] = {}
    program_approved = False
    for index, approval in enumerate(approvals):
        location = f"governance.approvals[{index}]"
        _reject_unknown_fields(
            approval,
            {"subject_kind", "subject_id", "reviewer", "role", "decision", "at"},
            findings,
            code="governance.approval_unknown_fields",
            location=location,
        )
        subject_kind = approval.get("subject_kind")
        if subject_kind not in APPROVAL_SUBJECT_KINDS:
            _finding(
                findings,
                "governance.subject_kind",
                "error",
                "Approval subject_kind is unsupported.",
                location,
            )
        subject_id = str(approval.get("subject_id", ""))
        for field in ("subject_id", "reviewer", "role"):
            try:
                _bounded_text(approval.get(field), label=f"approval {field}", limit=500)
            except ValueError as exc:
                _finding(
                    findings,
                    "governance.approval_identity",
                    "error",
                    str(exc),
                    f"{location}.{field}",
                )
        known_subjects = {
            "program": {str(program.get("name", ""))},
            "repository": set(repository_map),
            "relationship": set(relationship_map),
            "requirement": requirement_ids,
            "evidence": set(evidence_map),
        }
        if (
            subject_kind in known_subjects
            and subject_id not in known_subjects[subject_kind]
        ):
            _finding(
                findings,
                "governance.unknown_subject",
                "error",
                f"Approval references unknown {subject_kind} subject {subject_id}.",
                location,
            )
        decision = approval.get("decision")
        if decision not in {"approved", "rejected"}:
            _finding(
                findings,
                "governance.decision",
                "error",
                "Approval decision must be approved or rejected.",
                f"{location}.decision",
            )
        _timestamp(
            approval.get("at"),
            label="approval timestamp",
            findings=findings,
            location=f"{location}.at",
        )
        if decision == "approved":
            role = str(approval.get("role", "")).strip().lower()
            reviewer = str(approval.get("reviewer", "")).strip()
            if not role or not reviewer:
                _finding(
                    findings,
                    "governance.approval_identity",
                    "error",
                    "Approved decisions require reviewer and role identities.",
                    location,
                )
            if subject_kind == "program" and subject_id == str(program.get("name", "")):
                approved_roles.add(role)
                program_role_reviewers.setdefault(role, set()).add(reviewer.casefold())
                program_approved = True
        elif (
            decision == "rejected"
            and subject_kind == "program"
            and subject_id == str(program.get("name", ""))
        ):
            rejected_program_roles.add(str(approval.get("role", "")).strip().lower())
    required_role_values = governance.get("required_roles", [])
    if not isinstance(required_role_values, list) or not all(
        isinstance(value, str) for value in required_role_values
    ):
        required_role_values = []
        _finding(
            findings,
            "governance.required_roles",
            "error",
            "required_roles must be an array of strings.",
            "governance.required_roles",
        )
    required_roles = {
        value.strip().lower() for value in required_role_values if value.strip()
    }
    missing_roles = required_roles - approved_roles
    if missing_roles:
        _finding(
            findings,
            "governance.roles",
            "error",
            "Required program-level approval roles are missing: "
            + ", ".join(sorted(missing_roles))
            + ".",
            "governance",
        )
    rejected_required_roles = rejected_program_roles & required_roles
    if rejected_required_roles:
        _finding(
            findings,
            "governance.program_rejected",
            "error",
            "Required program role rejection(s) remain unresolved: "
            + ", ".join(sorted(rejected_required_roles))
            + ".",
            "governance.approvals",
        )
    reviewer_roles: dict[str, set[str]] = {}
    for role, reviewers in program_role_reviewers.items():
        for reviewer in reviewers:
            reviewer_roles.setdefault(reviewer, set()).add(role)
    shared_authorities = {
        reviewer: roles
        for reviewer, roles in reviewer_roles.items()
        if len(roles & required_roles) > 1
    }
    if shared_authorities:
        _finding(
            findings,
            "governance.role_independence",
            "error",
            "Distinct required program approval roles must be exercised by distinct named reviewers.",
            "governance.approvals",
        )
    if require_program_approval and not program_approved:
        _finding(
            findings,
            "governance.program_approval",
            "error",
            "A named program-level approval is required.",
            "governance",
        )
    if independent_evidence_review:
        for evidence_id, record in evidence_map.items():
            if record.get("status") not in {"passed", "failed"}:
                continue
            producer = str(record.get("producer", "")).strip().casefold()
            reviewer = str(record.get("reviewer", "")).strip().casefold()
            if not producer or not reviewer or producer == reviewer:
                _finding(
                    findings,
                    "governance.evidence_independence",
                    "error",
                    f"Completed evidence {evidence_id} requires distinct named producer and reviewer identities.",
                    f"external_evidence.{evidence_id}",
                )

    checks = {
        "input": True,
        "format": format_valid,
        "integrity": integrity_valid,
        "program_contract": not any(
            value["code"].startswith("program.") and value["level"] == "error"
            for value in findings
        ),
        "repository_bindings": bool(repository_checks)
        and all(repository_checks.values()),
        "relationships": not any(
            value["code"].startswith("relationship.") and value["level"] == "error"
            for value in findings
        ),
        "requirements": not any(
            value["code"].startswith("requirements.") and value["level"] == "error"
            for value in findings
        ),
        "external_evidence": not any(
            value["code"].startswith("evidence.") and value["level"] == "error"
            for value in findings
        ),
        "validation": not any(
            value["code"].startswith("validation.") and value["level"] == "error"
            for value in findings
        ),
        "llm_quality": not any(
            value["code"].startswith("llm.") and value["level"] == "error"
            for value in findings
        ),
        "governance": not any(
            value["code"].startswith("governance.") and value["level"] == "error"
            for value in findings
        ),
    }
    summary = {
        "name": str(program.get("name", "System assurance program")),
        "purpose": str(program.get("purpose", "")),
        "repositories": len(repository_map),
        "repository_ids": sorted(repository_map),
        "bound_repositories": sum(repository_checks.values()),
        "relationships": len(relationship_map),
        "requirements": requirement_count,
        "external_evidence": len(evidence_map),
        "trusted_evidence": len(trusted_evidence),
        "evidence_bytes": total_evidence_bytes,
        "evidence_statuses": dict(sorted(evidence_statuses.items())),
        "approvals": len(approvals),
        "required_roles": sorted(required_roles),
        "approved_roles": sorted(approved_roles),
        "program_approval": program_approved,
    }
    return _program_result(
        document.path,
        findings,
        program_sha256=program_sha256,
        checks=checks,
        summary=summary,
        relationships=derived_relationships,
        validation=validation_summary,
        llm_quality=llm_summary,
    )


def _markdown_cell(value: Any) -> str:
    normalized = (
        str("" if value is None else value).replace("\r", " ").replace("\n", " ")
    )
    return "".join(f"\\{char}" if char in "\\|*_[]<>`" else char for char in normalized)


def _program_topology_svg(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    repositories = [str(value) for value in summary.get("repository_ids", [])][:40]
    positions = {
        repository_id: (45 + (index % 4) * 260, 45 + (index // 4) * 110)
        for index, repository_id in enumerate(repositories)
    }
    height = max(150, 95 + ((len(repositories) + 3) // 4) * 110)
    edges: list[tuple[str, str, str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for relationship in result.get("relationships", []):
        source = str(relationship.get("source_repository", ""))
        target = str(relationship.get("target_repository", ""))
        kind = str(relationship.get("kind", ""))
        key = (source, target, kind)
        if source in positions and target in positions and key not in seen_edges:
            seen_edges.add(key)
            edges.append((source, target, kind, str(relationship.get("id", ""))))
        if len(edges) >= 100:
            break

    def svg_text(value: Any) -> str:
        return escape(str(value), quote=True)

    edge_svg = "".join(
        (
            f'<line x1="{positions[source][0] + 100}" y1="{positions[source][1] + 28}" '
            f'x2="{positions[target][0] + 100}" y2="{positions[target][1] + 28}" '
            'marker-end="url(#arrow)" class="edge">'
            f"<title>{svg_text(identifier)}: {svg_text(source)} {svg_text(kind)} {svg_text(target)}</title></line>"
        )
        for source, target, kind, identifier in edges
    )
    node_svg = "".join(
        (
            f'<g class="node"><rect x="{x}" y="{y}" width="200" height="56" rx="9" />'
            f"<title>{svg_text(repository_id)}</title>"
            f'<text x="{x + 100}" y="{y + 34}" text-anchor="middle">'
            f"{svg_text(repository_id[:28] + ('…' if len(repository_id) > 28 else ''))}</text></g>"
        )
        for repository_id, (x, y) in positions.items()
    )
    if not repositories:
        node_svg = '<text x="35" y="70" class="empty-svg">No bound repositories to visualize.</text>'
    truncated = (
        len(summary.get("repository_ids", [])) > len(repositories)
        or len(seen_edges) >= 100
    )
    note = (
        '<p class="diagram-note">The visual is bounded to 40 repositories and 100 unique repository-level edges; use the relationship table for the complete contract.</p>'
        if truncated
        else ""
    )
    return (
        f'<div class="topology" tabindex="0"><svg viewBox="0 0 1080 {height}" '
        'role="img" aria-labelledby="topology-title topology-description">'
        '<title id="topology-title">System assurance repository topology</title>'
        '<desc id="topology-description">Directed repository-level relationships derived from the verified assurance program.</desc>'
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L8,3 z" /></marker></defs>'
        f"{edge_svg}{node_svg}</svg></div>{note}"
    )


def program_verification_markdown(result: dict[str, Any]) -> str:
    """Render a compact human review view from a machine verification result."""

    summary = result.get("summary", {})
    validation = result.get("validation", {})
    llm = result.get("llm_quality", {})
    lines = [
        "# System assurance program verification",
        "",
        f"- Result: **{'VALID' if result.get('valid') else 'NOT READY'}**",
        f"- Repositories: {summary.get('bound_repositories', 0)} / {summary.get('repositories', 0)} bound",
        f"- Relationships: {summary.get('relationships', 0)}",
        f"- External evidence records: {summary.get('external_evidence', 0)}",
        f"- Validation repositories: {validation.get('repositories', 0)}",
        f"- Credited validation cohorts: {validation.get('credited_cohorts', validation.get('cohorts', 0))} of {validation.get('cohorts', 0)} (duplicate evidence: {validation.get('duplicate_evidence', 0)})",
        f"- Macro recall / precision: {validation.get('macro_recall')} / {validation.get('macro_precision')}",
        f"- Micro recall / precision: {validation.get('micro_recall')} / {validation.get('micro_precision')}",
        f"- Count-backed cohorts: {validation.get('count_backed_cohorts', 0)} of {validation.get('credited_cohorts', validation.get('cohorts', 0))} credited",
        f"- Verified evaluation artifacts: {validation.get('verified_evaluation_artifacts', 0)} of {validation.get('credited_cohorts', validation.get('cohorts', 0))} credited",
        f"- Micro call-resolution recall / precision: {validation.get('micro_call_resolution_recall')} / {validation.get('micro_call_resolution_precision')}",
        f"- LLM samples: {llm.get('samples', 0)}",
        f"- Credited LLM evaluations: {llm.get('credited_evaluations', llm.get('evaluations', 0))} of {llm.get('evaluations', 0)} (duplicate evidence: {llm.get('duplicate_evidence', 0)})",
        f"- LLM aggregation: {llm.get('aggregation_method', 'unavailable')}",
        f"- Count-backed LLM evaluations: {llm.get('count_backed_evaluations', 0)} of {llm.get('credited_evaluations', llm.get('evaluations', 0))} credited",
        f"- Verified LLM corpus artifacts: {llm.get('verified_corpus_artifacts', 0)} of {llm.get('credited_evaluations', llm.get('evaluations', 0))} credited",
        f"- Subject-bound LLM evaluations: {llm.get('subject_bound_evaluations', 0)} of {llm.get('credited_evaluations', llm.get('evaluations', 0))} credited",
        f"- Semantically fingerprinted LLM evaluations: {llm.get('semantic_fingerprinted_evaluations', 0)} of {llm.get('credited_evaluations', llm.get('evaluations', 0))} credited",
        f"- LLM claims / unsupported claims: {llm.get('claim_count')} / {llm.get('unsupported_claim_count')}",
        "",
        "## Cross-repository relationships",
        "",
        "| ID | Source | Target | Kind | Timing | Resilience | Deadline (ms) | Observed max (ms) |",
        "|---|---|---|---|---|---|---:|---:|",
    ]
    for relationship in result.get("relationships", []):
        cells = [
            relationship.get("id", ""),
            relationship.get("source", ""),
            relationship.get("target", ""),
            relationship.get("kind", ""),
            relationship.get("temporal_status", ""),
            relationship.get("resilience_status", ""),
            relationship.get("deadline_ms") or "",
            relationship.get("observed_max_ms") or "",
        ]
        lines.append("| " + " | ".join(_markdown_cell(value) for value in cells) + " |")
    if not result.get("relationships"):
        lines.append("| _None configured_ | | | | | | | |")
    lines.extend(["", "## Findings", ""])
    for finding in result.get("findings", []):
        lines.append(
            f"- **{_markdown_cell(str(finding.get('level', '')).upper())} · "
            f"{_markdown_cell(finding.get('code', ''))}** — "
            f"{_markdown_cell(finding.get('message', ''))}"
        )
    if not result.get("findings"):
        lines.append("- No verification findings.")
    lines.extend(["", str(result.get("notice", "")), ""])
    return "\n".join(lines)


def program_verification_html(result: dict[str, Any]) -> str:
    """Render a self-contained accessible system-level assurance report."""

    summary = result.get("summary", {})
    validation = result.get("validation", {})
    llm = result.get("llm_quality", {})
    valid = bool(result.get("valid"))

    def value(item: Any) -> str:
        return escape("" if item is None else str(item), quote=True)

    def metric(number: Any, label: str) -> str:
        return f'<div class="metric"><strong>{value(number)}</strong><span>{value(label)}</span></div>'

    relationship_rows = (
        "".join(
            "<tr>"
            f"<td>{value(item.get('id'))}</td><td>{value(item.get('source'))}</td><td>{value(item.get('target'))}</td><td>{value(item.get('kind'))}</td>"
            f'<td><span class="tag {value(item.get("temporal_status"))}">{value(item.get("temporal_status"))}</span></td>'
            f'<td><span class="tag {value(item.get("resilience_status"))}">{value(item.get("resilience_status"))}</span></td>'
            f"<td>{value(item.get('deadline_ms'))}</td><td>{value(item.get('observed_max_ms'))}</td><td>{value(item.get('observed_recovery_ms'))}</td>"
            f"<td>{value(', '.join(item.get('evidence_ids', [])))}</td></tr>"
            for item in result.get("relationships", [])
        )
        or '<tr><td colspan="10" class="empty">No cross-repository relationships were configured.</td></tr>'
    )
    finding_rows = (
        "".join(
            "<tr data-filter-row>"
            f'<td><span class="tag {value(item.get("level"))}">{value(str(item.get("level", "")).upper())}</span></td>'
            f"<td>{value(item.get('code'))}</td><td>{value(item.get('message'))}</td>"
            f"<td><code>{value(item.get('location'))}</code></td></tr>"
            for item in result.get("findings", [])
        )
        or '<tr><td colspan="4" class="empty">No verification findings.</td></tr>'
    )
    check_rows = "".join(
        f'<tr><td>{value(name.replace("_", " "))}</td><td><span class="tag {"supported" if state is True else "error" if state is False else "unverified"}">{value("passed" if state is True else "failed" if state is False else "not checked")}</span></td></tr>'
        for name, state in result.get("checks", {}).items()
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{value(summary.get("name", "System assurance program"))}</title>
<style>
:root{{--ink:#17212b;--muted:#5f6b76;--line:#d9e0e5;--paper:#fff;--canvas:#f2f5f7;--accent:#155f75;--good:#176b4d;--bad:#9b2c2c;--warn:#8a5a00}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth}} body{{margin:0;background:var(--canvas);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
header{{background:linear-gradient(135deg,#123645,#17647a);color:#fff;padding:38px max(24px,calc((100vw - 1180px)/2))}} header p{{max-width:850px;color:#d9edf3}}
nav{{position:sticky;top:0;z-index:3;background:#fff;border-bottom:1px solid var(--line);padding:10px max(24px,calc((100vw - 1180px)/2));display:flex;gap:16px;overflow:auto}} nav a{{color:var(--accent);font-weight:650;white-space:nowrap}} .skip{{position:absolute;left:-10000px;top:auto}} .skip:focus{{left:12px;top:12px;z-index:10;background:#fff;color:#000;padding:10px}} main{{max-width:1180px;margin:0 auto;padding:24px}} section{{scroll-margin-top:65px;background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:22px;margin:0 0 20px;box-shadow:0 2px 8px #18323f0d}}
h1{{margin:0 0 8px;font-size:2rem}} h2{{margin:0 0 15px;font-size:1.25rem}} .status{{display:inline-block;padding:5px 10px;border-radius:999px;font-weight:750;background:{"#d9f2e8" if valid else "#f9dddd"};color:{"#14583f" if valid else "#842020"}}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}} .metric{{padding:15px;border:1px solid var(--line);border-radius:9px;background:#fbfcfd}} .metric strong{{display:block;font-size:1.55rem}} .metric span{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}} code{{font-size:.85em;overflow-wrap:anywhere}}
.tag{{display:inline-block;border-radius:999px;padding:2px 8px;background:#e8edf0;color:#384650;font-size:.78rem;font-weight:700}} .tag.supported,.tag.passed{{background:#d9f2e8;color:var(--good)}} .tag.error,.tag.failed,.tag.violated{{background:#f9dddd;color:var(--bad)}} .tag.warning,.tag.unverified{{background:#f8ebc9;color:var(--warn)}}
.notice{{border-left:4px solid var(--accent);padding:12px 15px;background:#eaf4f7}} .empty{{color:var(--muted);font-style:italic}} .filters{{display:flex;gap:10px;flex-wrap:wrap}} input,select{{width:100%;max-width:480px;padding:10px 12px;border:1px solid #aebbc4;border-radius:7px;margin:0 0 12px;background:#fff}} select{{max-width:190px}} .topology{{overflow:auto;border:1px solid var(--line);border-radius:9px;background:#f8fbfc}} .topology svg{{display:block;min-width:760px;width:100%;height:auto}} .node rect{{fill:#fff;stroke:#39758a;stroke-width:2}} .node text{{fill:var(--ink);font-weight:700;font-size:14px}} .edge{{stroke:#70838e;stroke-width:1.8;opacity:.8}} marker path{{fill:#70838e}} .empty-svg{{fill:var(--muted)}} .diagram-note{{color:var(--muted);font-size:.9rem}}
@media(max-width:720px){{section{{padding:14px;overflow:auto}} th,td{{min-width:130px}}}} @media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}}} @media print{{body{{background:#fff}} header{{background:#fff;color:#000;padding:20px 0}} header p{{color:#333}} nav,.filters{{display:none}} main{{padding:0}} section{{box-shadow:none;break-inside:avoid}}}}
</style></head><body><a class="skip" href="#main">Skip to assurance results</a>
<header><h1>{value(summary.get("name", "System assurance program"))}</h1><span class="status">{"VALID" if valid else "NOT READY"}</span><p>{value(summary.get("purpose", result.get("notice", "")))}</p><p><code>Program SHA-256 {value(result.get("program", {}).get("content_sha256"))}</code></p></header>
<nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#topology">Topology</a><a href="#checks">Checks</a><a href="#quality">Quality</a><a href="#relationships">Relationships</a><a href="#findings">Findings</a></nav>
<main id="main"><section id="overview"><h2>Executive assurance state</h2><div class="metrics">
{metric(f"{summary.get('bound_repositories', 0)} / {summary.get('repositories', 0)}", "bound repositories")}{metric(summary.get("relationships", 0), "relationships")}{metric(summary.get("requirements", 0), "external requirements")}{metric(f"{summary.get('trusted_evidence', 0)} / {summary.get('external_evidence', 0)}", "trusted evidence")}{metric(validation.get("repositories", 0), "validation repositories")}{metric(llm.get("samples", 0), "LLM evaluation samples")}
</div></section>
<section id="topology"><h2>System topology</h2>{_program_topology_svg(result)}</section>
<section id="checks"><h2>Verification checks</h2><table><thead><tr><th>Check</th><th>State</th></tr></thead><tbody>{check_rows}</tbody></table></section>
<section id="quality"><h2>Validation and model quality</h2><div class="metrics">{metric(validation.get("macro_recall"), "macro recall")}{metric(validation.get("macro_precision"), "macro precision")}{metric(validation.get("micro_recall"), "micro recall")}{metric(validation.get("micro_precision"), "micro precision")}{metric(validation.get("credited_cohorts", validation.get("cohorts", 0)), "credited validation cohorts")}{metric(validation.get("duplicate_evidence", 0), "duplicate validation evidence")}{metric(validation.get("macro_call_resolution_recall"), "macro call-resolution recall")}{metric(validation.get("macro_call_resolution_precision"), "macro call-resolution precision")}{metric(validation.get("micro_call_resolution_recall"), "micro call-resolution recall")}{metric(validation.get("micro_call_resolution_precision"), "micro call-resolution precision")}{metric(validation.get("count_backed_cohorts", 0), "count-backed cohorts")}{metric(validation.get("verified_evaluation_artifacts", 0), "verified evaluation artifacts")}{metric(validation.get("evaluation_artifact_bytes", 0), "evaluation artifact bytes")}{metric(validation.get("call_count_backed_cohorts", 0), "count-backed call cohorts")}{metric(validation.get("cases", 0), "labelled failure-mode cases")}{metric(validation.get("call_cases", 0), "labelled call-site cases")}{metric(validation.get("independently_reviewed", 0), "independent cohorts")}{metric(llm.get("grounding"), "LLM grounding")}{metric(llm.get("citation_accuracy"), "LLM citation accuracy")}{metric(llm.get("unsupported_claim_rate"), "unsupported claim rate")}{metric(llm.get("claim_count"), "LLM claims")}{metric(llm.get("unsupported_claim_count"), "unsupported LLM claims")}{metric(llm.get("credited_evaluations", llm.get("evaluations", 0)), "credited LLM evaluations")}{metric(llm.get("duplicate_evidence", 0), "duplicate LLM evidence")}{metric(llm.get("count_backed_evaluations", 0), "count-backed LLM evaluations")}{metric(llm.get("verified_corpus_artifacts", 0), "verified LLM corpus artifacts")}{metric(llm.get("subject_bound_evaluations", 0), "subject-bound LLM evaluations")}{metric(llm.get("semantic_fingerprinted_evaluations", 0), "semantic LLM fingerprints")}{metric(llm.get("corpus_artifact_bytes", 0), "LLM corpus bytes")}{metric(llm.get("aggregation_method", "unavailable"), "LLM aggregation")}{metric(llm.get("independently_reviewed", 0), "independent LLM evaluations")}</div></section>
<section id="relationships"><h2>Cross-repository relationships, timing, and resilience</h2><table><thead><tr><th>ID</th><th>Source</th><th>Target</th><th>Kind</th><th>Timing</th><th>Resilience</th><th>Deadline ms</th><th>Observed max ms</th><th>Recovery ms</th><th>Evidence</th></tr></thead><tbody>{relationship_rows}</tbody></table></section>
<section id="findings"><h2>Actionable findings</h2><div class="filters"><label for="finding-search">Search findings<br><input id="finding-search" type="search" placeholder="Code, message, or location"></label><label for="finding-level">Severity<br><select id="finding-level"><option value="">All levels</option><option value="error">Errors</option><option value="warning">Warnings</option><option value="information">Information</option></select></label></div><table><thead><tr><th>Level</th><th>Code</th><th>Message</th><th>Location</th></tr></thead><tbody>{finding_rows}</tbody></table></section>
<section class="notice"><strong>Interpretation boundary.</strong> {value(result.get("notice"))}</section></main>
<script>const q=document.getElementById('finding-search'),l=document.getElementById('finding-level');function filterFindings(){{const s=q.value.toLowerCase(),v=l.value;document.querySelectorAll('[data-filter-row]').forEach(r=>{{const level=r.querySelector('.tag')?.textContent.toLowerCase()||'';r.hidden=!r.textContent.toLowerCase().includes(s)||(v&&level!==v)}})}}q.addEventListener('input',filterFindings);l.addEventListener('change',filterFindings);</script>
</body></html>"""
    return document


def export_program_verification(
    result: dict[str, Any], destination: str | Path, *, format: str
) -> Path:
    """Atomically publish a JSON or Markdown program-verification view."""

    if format == "json":
        content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    elif format == "markdown":
        content = program_verification_markdown(result)
    elif format == "html":
        content = program_verification_html(result)
    else:
        raise ValueError("program verification format must be json, markdown, or html")
    return atomic_publish_text(
        destination,
        content,
        max_bytes=MAX_PROGRAM_BYTES,
        label="assurance program verification",
    )
