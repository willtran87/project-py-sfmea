"""Independent release qualification over benchmark format 2 evidence.

This layer closes the gap between a one-time accuracy assessment and a release
decision.  It derives leakage, temporal holdout, non-inferiority, and resource
budget gates from exact evidence; it never manufactures independence or approval.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .benchmark_v2 import verify_benchmark_v2_assessment
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import utc_now

RELEASE_QUALIFICATION_SOURCE_FORMAT = "pysfmea-release-qualification-source-1"
RELEASE_QUALIFICATION_ASSESSMENT_FORMAT = "pysfmea-release-qualification-assessment-1"
RELEASE_QUALIFICATION_VERIFICATION_FORMAT = "pysfmea-release-qualification-verification-1"
MAX_REPOSITORIES = 5_000
MAX_PAIRS = 1_000_000
MAX_TEXT = 20_000


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _digest(value: Any, label: str) -> str:
    result = _text(value, label)
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return result


def _timestamp(value: Any, label: str) -> datetime:
    raw = _text(value, label)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must carry an explicit timezone")
    return parsed


def _sealed(value: dict[str, Any], label: str) -> dict[str, Any]:
    unsigned = copy.deepcopy(value)
    claimed = unsigned.pop("content_sha256", "")
    if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed) or canonical_json_sha256(unsigned) != claimed:
        raise ValueError(f"{label} content digest does not match")
    return copy.deepcopy(value)


def release_qualification_source_template(*, authority: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": RELEASE_QUALIFICATION_SOURCE_FORMAT,
        "id": "replace-with-pre-registered-release-qualification-id",
        "pre_registered_at": utc_now(),
        "pre_registration_evidence_ref": "replace-with-immutable-registration-reference",
        "authority": {
            "protocol_owner": authority.strip(),
            "benchmark_authority": "replace-with-independent-benchmark-authority",
            "approval_authority": "replace-with-independent-release-approval-authority",
            "independence_basis": "replace-with-organizational-and-reporting-line-separation",
        },
        "candidate": {"version": "replace-candidate-version", "subject_sha256": "0" * 64, "assessment_ref": "candidate-assessment.json"},
        "baseline": {"version": "replace-baseline-version", "subject_sha256": "0" * 64, "assessment_ref": "baseline-assessment.json"},
        "corpus": {
            "temporal_cutoff": "2026-01-01T00:00:00Z",
            "similarity_threshold": 0.9,
            "candidate_repositories": [],
            "excluded_reference_repositories": [],
            "pairwise_similarity_evidence": [],
        },
        "noninferiority": {"metric_margins": {}, "maximum_duration_ratio": 1.1, "maximum_peak_rss_ratio": 1.1, "maximum_artifact_size_ratio": 1.1},
        "performance": {
            "candidate": {"duration_seconds": 0.0, "peak_rss_bytes": 0, "artifact_size_bytes": 0, "evidence_ref": "replace-with-candidate-performance-evidence"},
            "baseline": {"duration_seconds": 0.0, "peak_rss_bytes": 0, "artifact_size_bytes": 0, "evidence_ref": "replace-with-baseline-performance-evidence"},
        },
        "evidence_refs": [],
        "notice": "Populate from a pre-registered, independently governed release campaign.",
    }
    if not result["authority"]["protocol_owner"]:
        raise ValueError("release qualification authority must not be empty")
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def _repository(value: Any, label: str) -> dict[str, Any]:
    fields = {"id", "source_ref", "content_sha256", "history_root_sha256", "lineage_ids", "observed_at"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    result = {
        "id": _text(value["id"], f"{label} id"),
        "source_ref": _text(value["source_ref"], f"{label} source_ref"),
        "content_sha256": _digest(value["content_sha256"], f"{label} content_sha256"),
        "history_root_sha256": _digest(value["history_root_sha256"], f"{label} history_root_sha256"),
        "lineage_ids": value["lineage_ids"],
        "observed_at": _text(value["observed_at"], f"{label} observed_at"),
    }
    _timestamp(result["observed_at"], f"{label} observed_at")
    lineage = result["lineage_ids"]
    if not isinstance(lineage, list) or not lineage or len(lineage) > 10_000 or len(lineage) != len(set(lineage)) or any(not isinstance(item, str) or not item.strip() for item in lineage):
        raise ValueError(f"{label} lineage_ids are invalid")
    return result


def _source(value: dict[str, Any]) -> dict[str, Any]:
    fields = {"format", "id", "pre_registered_at", "pre_registration_evidence_ref", "authority", "candidate", "baseline", "corpus", "noninferiority", "performance", "evidence_refs", "notice", "content_sha256"}
    result = _sealed(value, "release qualification source")
    if set(result) != fields or result.get("format") != RELEASE_QUALIFICATION_SOURCE_FORMAT:
        raise ValueError("release qualification source fields or format are invalid")
    _text(result["id"], "release qualification id")
    _timestamp(result["pre_registered_at"], "release qualification pre_registered_at")
    _text(result["pre_registration_evidence_ref"], "release qualification pre_registration_evidence_ref")
    authority = result["authority"]
    authority_fields = {"protocol_owner", "benchmark_authority", "approval_authority", "independence_basis"}
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        raise ValueError("release qualification authority is invalid")
    identities = [_text(authority[name], f"authority {name}") for name in ("protocol_owner", "benchmark_authority", "approval_authority")]
    _text(authority["independence_basis"], "authority independence_basis")
    if len({item.casefold() for item in identities}) != 3:
        raise ValueError("release qualification roles must have distinct identities")
    for name in ("candidate", "baseline"):
        item = result[name]
        if not isinstance(item, dict) or set(item) != {"version", "subject_sha256", "assessment_ref"}:
            raise ValueError(f"release qualification {name} is invalid")
        _text(item["version"], f"{name} version")
        _digest(item["subject_sha256"], f"{name} subject_sha256")
        _text(item["assessment_ref"], f"{name} assessment_ref")
    if result["candidate"]["version"] == result["baseline"]["version"]:
        raise ValueError("candidate and baseline versions must differ")
    if result["candidate"]["subject_sha256"] == result["baseline"]["subject_sha256"]:
        raise ValueError("candidate and baseline subject digests must differ")
    corpus = result["corpus"]
    corpus_fields = {"temporal_cutoff", "similarity_threshold", "candidate_repositories", "excluded_reference_repositories", "pairwise_similarity_evidence"}
    if not isinstance(corpus, dict) or set(corpus) != corpus_fields:
        raise ValueError("release qualification corpus is invalid")
    _timestamp(corpus["temporal_cutoff"], "corpus temporal_cutoff")
    threshold = corpus["similarity_threshold"]
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0.0 < float(threshold) <= 1.0:
        raise ValueError("corpus similarity threshold is invalid")
    candidates = corpus["candidate_repositories"]
    references = corpus["excluded_reference_repositories"]
    if not isinstance(candidates, list) or not candidates or len(candidates) > MAX_REPOSITORIES or not isinstance(references, list) or not references or len(references) > MAX_REPOSITORIES:
        raise ValueError("release qualification corpus populations are invalid")
    corpus["candidate_repositories"] = [_repository(item, "candidate repository") for item in candidates]
    corpus["excluded_reference_repositories"] = [_repository(item, "reference repository") for item in references]
    pairs = corpus["pairwise_similarity_evidence"]
    if not isinstance(pairs, list) or len(pairs) > MAX_PAIRS:
        raise ValueError("pairwise similarity evidence is invalid")
    pair_fields = {"candidate_id", "reference_id", "similarity", "method", "evidence_ref"}
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != pair_fields:
            raise ValueError("pairwise similarity record fields are invalid")
        for name in ("candidate_id", "reference_id", "method", "evidence_ref"):
            _text(pair[name], f"similarity {name}")
        similarity = pair["similarity"]
        if not isinstance(similarity, (int, float)) or isinstance(similarity, bool) or not 0.0 <= float(similarity) <= 1.0:
            raise ValueError("pairwise similarity value is invalid")
    policy = result["noninferiority"]
    policy_fields = {"metric_margins", "maximum_duration_ratio", "maximum_peak_rss_ratio", "maximum_artifact_size_ratio"}
    if not isinstance(policy, dict) or set(policy) != policy_fields or not isinstance(policy["metric_margins"], dict) or not policy["metric_margins"]:
        raise ValueError("release non-inferiority policy is invalid")
    for metric, margin in policy["metric_margins"].items():
        if not isinstance(metric, str) or not metric or not isinstance(margin, (int, float)) or isinstance(margin, bool) or not 0.0 <= float(margin) < 1.0:
            raise ValueError("release metric non-inferiority margin is invalid")
    for name in ("maximum_duration_ratio", "maximum_peak_rss_ratio", "maximum_artifact_size_ratio"):
        item = policy[name]
        if not isinstance(item, (int, float)) or isinstance(item, bool) or float(item) <= 0.0:
            raise ValueError(f"release {name} is invalid")
    performance = result["performance"]
    if not isinstance(performance, dict) or set(performance) != {"candidate", "baseline"}:
        raise ValueError("release performance evidence is invalid")
    for population in ("candidate", "baseline"):
        item = performance[population]
        if not isinstance(item, dict) or set(item) != {"duration_seconds", "peak_rss_bytes", "artifact_size_bytes", "evidence_ref"}:
            raise ValueError(f"{population} performance fields are invalid")
        if not isinstance(item["duration_seconds"], (int, float)) or isinstance(item["duration_seconds"], bool) or float(item["duration_seconds"]) <= 0.0:
            raise ValueError(f"{population} duration is invalid")
        for name in ("peak_rss_bytes", "artifact_size_bytes"):
            if not isinstance(item[name], int) or isinstance(item[name], bool) or item[name] <= 0:
                raise ValueError(f"{population} {name} is invalid")
        _text(item["evidence_ref"], f"{population} performance evidence_ref")
    evidence = result["evidence_refs"]
    if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)) or any(not isinstance(item, str) or not item.strip() for item in evidence):
        raise ValueError("release qualification evidence_refs are invalid")
    return result


def seal_release_qualification_source(source: str | Path, destination: str | Path) -> Path:
    document = load_bounded_json_document(source, label="release qualification source", max_bytes=100_000_000, max_depth=100, max_nodes=3_000_000)
    if not isinstance(document.value, dict):
        raise ValueError("release qualification source must contain an object")
    value = copy.deepcopy(document.value)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    _source(value)
    return export_release_qualification_source(value, destination)


def _load_assessment(source: str | Path, label: str) -> tuple[BoundedJsonDocument, dict[str, Any]]:
    document = load_bounded_json_document(source, label=label, max_bytes=100_000_000, max_depth=150, max_nodes=3_000_000)
    if not isinstance(document.value, dict) or not verify_benchmark_v2_assessment(document.value)["valid"]:
        raise ValueError(f"{label} is not a valid benchmark format-2 assessment")
    return document, document.value


def _binding(document: BoundedJsonDocument, value: dict[str, Any]) -> dict[str, Any]:
    return {"reference": document.path.name, "bytes": document.size, "sha256": hashlib.sha256(document.raw).hexdigest(), "content_sha256": str(value.get("content_sha256", ""))}


def release_qualification_assessment(
    source_path: str | Path,
    candidate_assessment_path: str | Path,
    baseline_assessment_path: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    source_document = load_bounded_json_document(source_path, label="release qualification source", max_bytes=100_000_000, max_depth=100, max_nodes=3_000_000)
    if not isinstance(source_document.value, dict):
        raise ValueError("release qualification source must contain an object")
    source = _source(source_document.value)
    candidate_document, candidate = _load_assessment(candidate_assessment_path, "candidate benchmark assessment")
    baseline_document, baseline = _load_assessment(baseline_assessment_path, "baseline benchmark assessment")
    if source["candidate"]["assessment_ref"] != candidate_document.path.name or source["baseline"]["assessment_ref"] != baseline_document.path.name:
        raise ValueError("release source assessment references do not match supplied files")
    candidate_repositories = source["corpus"]["candidate_repositories"]
    references = source["corpus"]["excluded_reference_repositories"]
    candidate_ids = {item["id"] for item in candidate_repositories}
    reference_ids = {item["id"] for item in references}
    unique_populations = len(candidate_ids) == len(candidate_repositories) and len(reference_ids) == len(references) and not candidate_ids.intersection(reference_ids)
    cutoff = _timestamp(source["corpus"]["temporal_cutoff"], "corpus temporal_cutoff")
    registered = _timestamp(source["pre_registered_at"], "release qualification pre_registered_at")
    temporal = all(_timestamp(item["observed_at"], "candidate observed_at") >= cutoff for item in candidate_repositories) and all(_timestamp(item["observed_at"], "reference observed_at") < cutoff for item in references)
    preregistered = bool(
        _timestamp(candidate["generated_at"], "candidate benchmark generated_at") >= registered
        and all(
            _timestamp(item["observed_at"], "candidate observed_at") >= registered
            for item in candidate_repositories
        )
    )

    def benchmark_repository_ids(assessment: dict[str, Any]) -> set[str]:
        strata = assessment.get("strata", {})
        if not isinstance(strata, dict):
            return set()
        return {
            str(repository_id)
            for values in strata.values()
            if isinstance(values, dict)
            for repository_ids in values.values()
            if isinstance(repository_ids, list)
            for repository_id in repository_ids
        }

    candidate_benchmark_ids = benchmark_repository_ids(candidate)
    baseline_benchmark_ids = benchmark_repository_ids(baseline)
    corpus_binding = bool(candidate_ids and candidate_ids == candidate_benchmark_ids)
    comparable_populations = bool(
        candidate_benchmark_ids
        and candidate_benchmark_ids == baseline_benchmark_ids
        and candidate.get("strata") == baseline.get("strata")
        and candidate.get("summary", {}).get("repositories")
        == baseline.get("summary", {}).get("repositories")
    )
    assessments_distinct = bool(
        candidate_document.raw != baseline_document.raw
        and candidate.get("content_sha256") != baseline.get("content_sha256")
    )
    def population_values(records: list[dict[str, Any]], name: str) -> set[str]:
        return {str(record[name]) for record in records}
    content_disjoint = not population_values(candidate_repositories, "content_sha256").intersection(population_values(references, "content_sha256"))
    history_disjoint = not population_values(candidate_repositories, "history_root_sha256").intersection(population_values(references, "history_root_sha256"))
    candidate_lineage = {lineage for record in candidate_repositories for lineage in record["lineage_ids"]}
    reference_lineage = {lineage for record in references for lineage in record["lineage_ids"]}
    lineage_disjoint = not candidate_lineage.intersection(reference_lineage)
    expected_pairs = {(left, right) for left in candidate_ids for right in reference_ids}
    supplied_pairs = {(pair["candidate_id"], pair["reference_id"]) for pair in source["corpus"]["pairwise_similarity_evidence"]}
    pair_coverage = supplied_pairs == expected_pairs and len(supplied_pairs) == len(source["corpus"]["pairwise_similarity_evidence"])
    similarity_passed = pair_coverage and all(float(pair["similarity"]) < float(source["corpus"]["similarity_threshold"]) for pair in source["corpus"]["pairwise_similarity_evidence"])
    margins = source["noninferiority"]["metric_margins"]
    metric_names_match = set(margins) == set(candidate.get("metrics", {})) == set(baseline.get("metrics", {}))
    comparisons: dict[str, Any] = {}
    if metric_names_match:
        for name, margin in margins.items():
            dimensions: dict[str, Any] = {}
            for dimension in ("recall", "precision"):
                candidate_lower = float(candidate["metrics"][name][dimension]["conservative_lower"])
                baseline_lower = float(baseline["metrics"][name][dimension]["conservative_lower"])
                dimensions[dimension] = {"candidate_lower": candidate_lower, "baseline_lower": baseline_lower, "margin": float(margin), "passed": candidate_lower >= baseline_lower - float(margin)}
            comparisons[name] = {"dimensions": dimensions, "passed": all(item["passed"] for item in dimensions.values())}
    performance = source["performance"]
    ratios = {
        "duration": float(performance["candidate"]["duration_seconds"]) / float(performance["baseline"]["duration_seconds"]),
        "peak_rss": int(performance["candidate"]["peak_rss_bytes"]) / int(performance["baseline"]["peak_rss_bytes"]),
        "artifact_size": int(performance["candidate"]["artifact_size_bytes"]) / int(performance["baseline"]["artifact_size_bytes"]),
    }
    performance_checks = {
        "duration": ratios["duration"] <= float(source["noninferiority"]["maximum_duration_ratio"]),
        "peak_rss": ratios["peak_rss"] <= float(source["noninferiority"]["maximum_peak_rss_ratio"]),
        "artifact_size": ratios["artifact_size"] <= float(source["noninferiority"]["maximum_artifact_size_ratio"]),
    }
    checks = {
        "candidate_benchmark_passed": bool(candidate.get("summary", {}).get("passed")),
        "baseline_benchmark_passed": bool(baseline.get("summary", {}).get("passed")),
        "assessment_artifacts_distinct": assessments_distinct,
        "candidate_corpus_bound_to_benchmark": corpus_binding,
        "candidate_baseline_populations_comparable": comparable_populations,
        "population_identities_unique": unique_populations,
        "pre_registered_before_candidate_evidence": preregistered,
        "temporal_holdout": temporal,
        "content_hash_disjoint": content_disjoint,
        "history_roots_disjoint": history_disjoint,
        "lineage_disjoint": lineage_disjoint,
        "pairwise_similarity_complete": pair_coverage,
        "near_duplicate_exclusion": similarity_passed,
        "metric_populations_match": metric_names_match,
        "all_metrics_noninferior": bool(comparisons) and all(item["passed"] for item in comparisons.values()),
        "performance_budgets": all(performance_checks.values()),
    }
    passed = all(checks.values())
    result: dict[str, Any] = {
        "format": RELEASE_QUALIFICATION_ASSESSMENT_FORMAT,
        "generated_at": generated_at or utc_now(),
        "id": source["id"],
        "authority": source["authority"],
        "subjects": {
            "candidate": {"version": source["candidate"]["version"], "subject_sha256": source["candidate"]["subject_sha256"]},
            "baseline": {"version": source["baseline"]["version"], "subject_sha256": source["baseline"]["subject_sha256"]},
        },
        "bindings": {"source": _binding(source_document, source), "candidate_assessment": _binding(candidate_document, candidate), "baseline_assessment": _binding(baseline_document, baseline)},
        "leakage": {"candidate_repositories": len(candidate_repositories), "reference_repositories": len(references), "expected_similarity_pairs": len(expected_pairs), "supplied_similarity_pairs": len(supplied_pairs), "similarity_threshold": source["corpus"]["similarity_threshold"]},
        "metric_comparisons": comparisons,
        "performance": {"ratios": {name: round(value, 6) for name, value in ratios.items()}, "checks": performance_checks},
        "checks": checks,
        "summary": {"passed": passed, "status": "eligible_for_independent_release_approval" if passed else "release_qualification_blocked", "failed_checks": sorted(name for name, state in checks.items() if not state)},
        "notice": "Passing proves exact policy accounting over supplied evidence. It does not authenticate authorities, prove corpus independence, qualify the tool, or approve the release.",
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_release_qualification_assessment(value: dict[str, Any]) -> dict[str, Any]:
    expected = {"format", "generated_at", "id", "authority", "subjects", "bindings", "leakage", "metric_comparisons", "performance", "checks", "summary", "notice", "content_sha256"}
    structure = bool(set(value) == expected and value.get("format") == RELEASE_QUALIFICATION_ASSESSMENT_FORMAT and isinstance(value.get("checks"), dict))
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(re.fullmatch(r"[0-9a-f]{64}", claimed) and canonical_json_sha256(unsigned) == claimed)
    semantic = False
    try:
        passed = all(state is True for state in value["checks"].values())
        semantic = value["summary"] == {"passed": passed, "status": "eligible_for_independent_release_approval" if passed else "release_qualification_blocked", "failed_checks": sorted(name for name, state in value["checks"].items() if not state)}
    except (KeyError, TypeError):
        semantic = False
    errors = []
    if not structure: errors.append("release qualification fields do not match format 1")
    if not integrity: errors.append("release qualification content digest does not match")
    if not semantic: errors.append("release qualification summary does not reconcile")
    return {"format": RELEASE_QUALIFICATION_VERIFICATION_FORMAT, "valid": bool(structure and integrity and semantic), "passed": bool(structure and integrity and semantic and value.get("summary", {}).get("passed")), "checks": {"closed_structure": structure, "content_integrity": integrity, "semantic_reconciliation": semantic, "source_regeneration": None}, "errors": errors, "content_sha256": claimed, "notice": "Verification proves release-policy accounting, not independence, qualification, certification, or approval."}


def verify_release_qualification_assessment_file(source: str | Path, *, source_path: str | Path | None = None, candidate_assessment_path: str | Path | None = None, baseline_assessment_path: str | Path | None = None) -> dict[str, Any]:
    try:
        exact_sources = (source_path, candidate_assessment_path, baseline_assessment_path)
        if any(item is not None for item in exact_sources) and not all(item is not None for item in exact_sources):
            raise ValueError("exact regeneration requires source, candidate, and baseline together")
        document = load_bounded_json_document(source, label="release qualification assessment", max_bytes=100_000_000, max_depth=150, max_nodes=3_000_000)
        if not isinstance(document.value, dict): raise ValueError("release qualification assessment must contain an object")
        result = verify_release_qualification_assessment(document.value)
        result["path"] = str(document.path)
        if source_path is not None and candidate_assessment_path is not None and baseline_assessment_path is not None and result["valid"]:
            regenerated = release_qualification_assessment(source_path, candidate_assessment_path, baseline_assessment_path, generated_at=str(document.value.get("generated_at", "")))
            exact = regenerated == document.value
            result["checks"]["source_regeneration"] = exact
            result["valid"] = bool(result["valid"] and exact)
            result["passed"] = bool(result["passed"] and exact)
            if not exact: result["errors"].append("release qualification does not exactly regenerate")
        return result
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"path": str(Path(source).expanduser().absolute()), "format": RELEASE_QUALIFICATION_VERIFICATION_FORMAT, "valid": False, "passed": False, "checks": {"closed_structure": False, "content_integrity": False, "semantic_reconciliation": False, "source_regeneration": None}, "errors": [str(exc)], "content_sha256": "", "notice": "The release qualification assessment could not be safely verified."}


def export_release_qualification_source(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="release qualification source")


def export_release_qualification_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="release qualification assessment")
