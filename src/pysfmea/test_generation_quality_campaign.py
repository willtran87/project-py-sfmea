"""Stratified, artifact-replay qualification for generated assurance tests.

Format 3 adds campaign-design controls to the exact artifact derivation in format 2.
It intentionally treats repository, framework, domain, and fault-category labels as
reviewed declarations: they improve sampling discipline without pretending to prove
that a corpus is representative or that an actor identity is authenticated.
"""

from __future__ import annotations

import copy
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .integrity import canonical_json_sha256
from .test_generation_quality import (
    MAX_QUALITY_SAMPLES,
    MAX_TEXT,
    TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT,
    TEST_GENERATION_CAMPAIGN_RESULT_FORMAT,
    TEST_GENERATION_EVIDENCE_CORPUS_FORMAT,
    evaluate_test_generation_quality_evidence,
)
from .test_generation_quality_evidence import load_quality_artifact_document

_ROOT_FIELDS = {"format", "name", "subject", "governance", "policy", "samples"}
_BASE_GOVERNANCE_FIELDS = {
    "independent",
    "labeled_by",
    "reviewed_by",
    "review_date",
    "selection_method",
    "representativeness_rationale",
}
_CAMPAIGN_GOVERNANCE_FIELDS = {
    *_BASE_GOVERNANCE_FIELDS,
    "selection_frozen_at",
    "outcomes_observed_at",
}
_BASE_POLICY_FIELDS = {
    "min_samples",
    "min_proposed_samples",
    "min_refused_samples",
    "min_decision_accuracy",
    "min_valid_proposal_rate",
    "min_execution_pass_rate",
    "min_stimulus_observed_rate",
    "min_criteria_pass_rate",
    "min_fault_detection_rate",
    "min_reviewer_acceptance_rate",
    "max_unsafe_change_rate",
}
_CAMPAIGN_COUNT_POLICY_FIELDS = {
    "min_repositories",
    "min_frameworks",
    "min_domains",
    "min_fault_categories",
    "min_samples_per_repository",
    "min_samples_per_framework",
    "min_samples_per_domain",
}
_CAMPAIGN_POLICY_FIELDS = {
    *_BASE_POLICY_FIELDS,
    *_CAMPAIGN_COUNT_POLICY_FIELDS,
    "require_decision_balance_per_repository",
    "max_single_repository_fraction",
}
_SAMPLE_FIELDS = {
    "id",
    "expected_decision",
    "repository_id",
    "frameworks",
    "domains",
    "fault_category",
    "artifacts",
}
_ARTIFACT_FIELDS = {
    "analysis",
    "proposal",
    "application_receipt",
    "fault_detection",
}
_RESULT_FIELDS = {
    "format",
    "generated_at",
    "producer",
    "corpus",
    "subject",
    "governance",
    "policy",
    "population",
    "metrics",
    "gates",
    "qualified",
    "status",
    "evidence_fingerprint_sha256",
    "notice",
    "content_sha256",
    "evidence",
    "campaign",
}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > MAX_TEXT:
        raise ValueError(f"{label} must be bounded non-empty text")
    return value.strip()


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    text = _text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return text, parsed


def _bounded_count(value: Any, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_QUALITY_SAMPLES
    ):
        raise ValueError(f"campaign policy {label} must be a positive bounded integer")
    return value


def _rate(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 <= float(value) <= 1
    ):
        raise ValueError(f"campaign policy {label} must be between zero and one")
    return float(value)


def _labels(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 100:
        raise ValueError(f"{label} must be a bounded non-empty array")
    normalized = [_text(item, label) for item in value]
    if len({item.casefold() for item in normalized}) != len(normalized):
        raise ValueError(f"{label} values must be unique")
    return sorted(normalized, key=str.casefold)


def _gate(
    gate_id: str,
    *,
    passed: bool,
    value: int | float,
    operator: str,
    threshold: int | float,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "passed": passed,
        "value": value,
        "operator": operator,
        "threshold": threshold,
    }


def _segment_records(
    memberships: dict[str, set[str]],
    expected: dict[str, str],
    actual: dict[str, str],
    categories: dict[str, str | None],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for segment_id in sorted(memberships, key=str.casefold):
        sample_ids = memberships[segment_id]
        expected_proposed = sum(expected[item] == "proposed" for item in sample_ids)
        actual_proposed = sum(actual[item] == "proposed" for item in sample_ids)
        matches = sum(expected[item] == actual[item] for item in sample_ids)
        records.append(
            {
                "id": segment_id,
                "samples": len(sample_ids),
                "expected_proposed": expected_proposed,
                "expected_refused": len(sample_ids) - expected_proposed,
                "actual_proposed": actual_proposed,
                "actual_refused": len(sample_ids) - actual_proposed,
                "decision_accuracy": round(matches / len(sample_ids), 4),
                "fault_categories": sorted(
                    {
                        category
                        for item in sample_ids
                        if (category := categories[item]) is not None
                    },
                    key=str.casefold,
                ),
            }
        )
    return records


def evaluate_test_generation_quality_campaign(
    corpus: dict[str, Any], evidence_root: str | Path
) -> dict[str, Any]:
    """Replay exact lifecycle evidence and apply stratified campaign-design gates."""

    if (
        set(corpus) != _ROOT_FIELDS
        or corpus.get("format") != TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT
    ):
        raise ValueError("stratified quality corpus must match the closed root contract")
    governance = corpus.get("governance")
    if not isinstance(governance, dict) or set(governance) != _CAMPAIGN_GOVERNANCE_FIELDS:
        raise ValueError("stratified quality governance must match the closed contract")
    frozen_text, frozen_at = _timestamp(
        governance.get("selection_frozen_at"), "governance selection_frozen_at"
    )
    observed_text, observed_at = _timestamp(
        governance.get("outcomes_observed_at"), "governance outcomes_observed_at"
    )

    policy = corpus.get("policy")
    if not isinstance(policy, dict) or set(policy) != _CAMPAIGN_POLICY_FIELDS:
        raise ValueError("stratified quality policy must match the closed contract")
    campaign_counts = {
        field: _bounded_count(policy.get(field), field)
        for field in _CAMPAIGN_COUNT_POLICY_FIELDS
    }
    concentration_limit = _rate(
        policy.get("max_single_repository_fraction"),
        "max_single_repository_fraction",
    )
    decision_balance = policy.get("require_decision_balance_per_repository")
    if not isinstance(decision_balance, bool):
        raise ValueError(
            "campaign policy require_decision_balance_per_repository must be boolean"
        )

    source_samples = corpus.get("samples")
    if (
        not isinstance(source_samples, list)
        or not source_samples
        or len(source_samples) > MAX_QUALITY_SAMPLES
    ):
        raise ValueError("stratified quality corpus requires bounded non-empty samples")
    base_samples: list[dict[str, Any]] = []
    normalized_samples: list[dict[str, Any]] = []
    actual: dict[str, str] = {}
    expected: dict[str, str] = {}
    categories: dict[str, str | None] = {}
    repositories: dict[str, set[str]] = {}
    frameworks: dict[str, set[str]] = {}
    domains: dict[str, set[str]] = {}
    sample_ids: set[str] = set()

    for index, sample in enumerate(source_samples, start=1):
        if not isinstance(sample, dict) or set(sample) != _SAMPLE_FIELDS:
            raise ValueError(f"stratified quality sample {index} must match the closed contract")
        sample_id = _text(sample.get("id"), f"quality sample {index} id")
        if sample_id in sample_ids:
            raise ValueError("quality sample ids must be unique")
        sample_ids.add(sample_id)
        expected_decision = sample.get("expected_decision")
        if expected_decision not in {"proposed", "refused"}:
            raise ValueError(f"quality sample {index} has an invalid expected decision")
        repository_id = _text(
            sample.get("repository_id"), f"quality sample {index} repository_id"
        )
        sample_frameworks = _labels(
            sample.get("frameworks"), f"quality sample {index} frameworks"
        )
        sample_domains = _labels(sample.get("domains"), f"quality sample {index} domains")
        category_value = sample.get("fault_category")
        category = (
            None
            if category_value is None
            else _text(category_value, f"quality sample {index} fault_category")
        )
        artifacts = sample.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != _ARTIFACT_FIELDS:
            raise ValueError(
                f"stratified quality sample {index} artifacts must match the closed contract"
            )
        proposal, _ = load_quality_artifact_document(
            evidence_root,
            artifacts.get("proposal"),
            label=f"quality sample {sample_id} proposal",
            max_bytes=3_000_000,
        )
        actual_decision = proposal.get("response", {}).get("decision")
        if actual_decision not in {"proposed", "refused"}:
            raise ValueError(f"quality sample {sample_id} proposal has no valid provider decision")
        if actual_decision == "refused" and category is not None:
            raise ValueError(f"refused quality sample {sample_id} must not declare a fault category")
        if actual_decision == "proposed":
            if category is None:
                raise ValueError(f"proposed quality sample {sample_id} requires a fault category")
            fault, _ = load_quality_artifact_document(
                evidence_root,
                artifacts.get("fault_detection"),
                label=f"quality sample {sample_id} fault-detection evidence",
                max_bytes=2_000_000,
            )
            fault_id = fault.get("seeded", {}).get("fault_id")
            if not isinstance(fault_id, str) or not (
                fault_id == category or fault_id.startswith(f"{category}:")
            ):
                raise ValueError(
                    f"quality sample {sample_id} fault category does not bind its seeded fault id"
                )

        base_sample = {
            "id": sample_id,
            "expected_decision": expected_decision,
            "artifacts": copy.deepcopy(artifacts),
        }
        base_samples.append(base_sample)
        normalized_samples.append(
            {
                **base_sample,
                "repository_id": repository_id,
                "frameworks": sample_frameworks,
                "domains": sample_domains,
                "fault_category": category,
            }
        )
        expected[sample_id] = expected_decision
        actual[sample_id] = actual_decision
        categories[sample_id] = category
        repositories.setdefault(repository_id, set()).add(sample_id)
        for framework in sample_frameworks:
            frameworks.setdefault(framework, set()).add(sample_id)
        for domain in sample_domains:
            domains.setdefault(domain, set()).add(sample_id)

    base_corpus = copy.deepcopy(corpus)
    base_corpus["format"] = TEST_GENERATION_EVIDENCE_CORPUS_FORMAT
    base_corpus["governance"] = {
        field: copy.deepcopy(governance[field]) for field in _BASE_GOVERNANCE_FIELDS
    }
    base_corpus["policy"] = {
        field: copy.deepcopy(policy[field]) for field in _BASE_POLICY_FIELDS
    }
    base_corpus["samples"] = base_samples
    result = evaluate_test_generation_quality_evidence(base_corpus, evidence_root)

    repository_segments = _segment_records(repositories, expected, actual, categories)
    framework_segments = _segment_records(frameworks, expected, actual, categories)
    domain_segments = _segment_records(domains, expected, actual, categories)
    fault_population = Counter(
        category for category in categories.values() if category is not None
    )
    maximum_repository_population = max(len(items) for items in repositories.values())
    max_repository_fraction = round(
        maximum_repository_population / len(normalized_samples), 4
    )
    balanced_repositories = sum(
        record["expected_proposed"] > 0 and record["expected_refused"] > 0
        for record in repository_segments
    )

    campaign_gates = [
        _gate(
            "selection_precedes_outcomes",
            passed=frozen_at <= observed_at,
            value=int(frozen_at <= observed_at),
            operator="==",
            threshold=1,
        ),
        _gate(
            "repository_population",
            passed=len(repositories) >= campaign_counts["min_repositories"],
            value=len(repositories),
            operator=">=",
            threshold=campaign_counts["min_repositories"],
        ),
        _gate(
            "framework_population",
            passed=len(frameworks) >= campaign_counts["min_frameworks"],
            value=len(frameworks),
            operator=">=",
            threshold=campaign_counts["min_frameworks"],
        ),
        _gate(
            "domain_population",
            passed=len(domains) >= campaign_counts["min_domains"],
            value=len(domains),
            operator=">=",
            threshold=campaign_counts["min_domains"],
        ),
        _gate(
            "fault_category_population",
            passed=len(fault_population) >= campaign_counts["min_fault_categories"],
            value=len(fault_population),
            operator=">=",
            threshold=campaign_counts["min_fault_categories"],
        ),
        _gate(
            "samples_per_repository",
            passed=min(len(items) for items in repositories.values())
            >= campaign_counts["min_samples_per_repository"],
            value=min(len(items) for items in repositories.values()),
            operator=">=",
            threshold=campaign_counts["min_samples_per_repository"],
        ),
        _gate(
            "samples_per_framework",
            passed=min(len(items) for items in frameworks.values())
            >= campaign_counts["min_samples_per_framework"],
            value=min(len(items) for items in frameworks.values()),
            operator=">=",
            threshold=campaign_counts["min_samples_per_framework"],
        ),
        _gate(
            "samples_per_domain",
            passed=min(len(items) for items in domains.values())
            >= campaign_counts["min_samples_per_domain"],
            value=min(len(items) for items in domains.values()),
            operator=">=",
            threshold=campaign_counts["min_samples_per_domain"],
        ),
        _gate(
            "decision_balance_per_repository",
            passed=(not decision_balance) or balanced_repositories == len(repositories),
            value=(len(repositories) if not decision_balance else balanced_repositories),
            operator="==",
            threshold=len(repositories),
        ),
        _gate(
            "repository_concentration",
            passed=max_repository_fraction <= concentration_limit,
            value=max_repository_fraction,
            operator="<=",
            threshold=concentration_limit,
        ),
    ]

    normalized_governance = {
        **{field: copy.deepcopy(governance[field]) for field in _BASE_GOVERNANCE_FIELDS},
        "selection_frozen_at": frozen_text,
        "outcomes_observed_at": observed_text,
    }
    normalized_policy = {
        **{field: copy.deepcopy(policy[field]) for field in _BASE_POLICY_FIELDS},
        **campaign_counts,
        "require_decision_balance_per_repository": decision_balance,
        "max_single_repository_fraction": concentration_limit,
    }
    result["format"] = TEST_GENERATION_CAMPAIGN_RESULT_FORMAT
    result["corpus"] = {
        "name": result["corpus"]["name"],
        "sha256": canonical_json_sha256(corpus),
    }
    result["governance"] = normalized_governance
    result["policy"] = normalized_policy
    result["campaign"] = {
        "design": "stratified_artifact_replay",
        "selection_frozen_at": frozen_text,
        "outcomes_observed_at": observed_text,
        "repositories": len(repositories),
        "frameworks": len(frameworks),
        "domains": len(domains),
        "fault_categories": len(fault_population),
        "max_single_repository_fraction": max_repository_fraction,
        "fault_category_population": [
            {"id": category, "samples": count}
            for category, count in sorted(fault_population.items(), key=lambda item: item[0].casefold())
        ],
        "segments": {
            "repositories": repository_segments,
            "frameworks": framework_segments,
            "domains": domain_segments,
        },
    }
    result["gates"].extend(campaign_gates)
    result["qualified"] = all(bool(gate["passed"]) for gate in result["gates"])
    result["status"] = (
        "qualified_stratified_artifact_sample"
        if result["qualified"]
        else "not_qualified"
    )
    result["evidence_fingerprint_sha256"] = canonical_json_sha256(
        {
            "corpus_sha256": result["corpus"]["sha256"],
            "artifact_manifest_sha256": result["evidence"]["manifest_sha256"],
            "campaign": result["campaign"],
            "samples": sorted(normalized_samples, key=lambda item: str(item["id"])),
        }
    )
    result["notice"] = (
        "This result derives claims from exact retained lifecycle artifacts and applies "
        "declared repository, framework, domain, chronology, concentration, and fault-category "
        "sampling controls for only the named provider/model/prompt campaign. Labels remain "
        "reviewed declarations; this does not authenticate actors, prove representativeness, "
        "or constitute general model, tool, safety, or certification approval."
    )
    result.pop("content_sha256", None)
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_test_generation_quality_campaign_result(
    result: dict[str, Any],
    corpus: dict[str, Any],
    *,
    evidence_root: str | Path | None = None,
) -> dict[str, Any]:
    """Verify format-3 integrity, corpus binding, and deterministic semantic replay."""

    errors: list[str] = []
    structure_valid = set(result) == _RESULT_FIELDS
    if not structure_valid:
        errors.append("quality result fields do not match the closed campaign contract")
    unsigned = copy.deepcopy(result)
    declared_digest = unsigned.pop("content_sha256", "")
    actual_digest = canonical_json_sha256(unsigned)
    content_integrity = declared_digest == actual_digest
    if not content_integrity:
        errors.append("quality result content digest does not match")
    declared_corpus = result.get("corpus", {})
    corpus_binding = isinstance(declared_corpus, dict) and declared_corpus.get(
        "sha256"
    ) == canonical_json_sha256(corpus)
    if not corpus_binding:
        errors.append("quality result does not bind the supplied corpus")
    if evidence_root is None:
        errors.append("stratified artifact quality verification requires an evidence root")
        replayed = None
    else:
        replayed = evaluate_test_generation_quality_campaign(corpus, evidence_root)
    comparable_result = copy.deepcopy(result)
    comparable_replay = copy.deepcopy(replayed) if replayed is not None else {}
    for candidate in (comparable_result, comparable_replay):
        candidate.pop("generated_at", None)
        candidate.pop("content_sha256", None)
    semantic_replay = replayed is not None and comparable_result == comparable_replay
    if not semantic_replay:
        errors.append("quality result does not match semantic campaign replay")
    return {
        "valid": structure_valid
        and content_integrity
        and corpus_binding
        and semantic_replay,
        "structure_valid": structure_valid,
        "content_integrity": content_integrity,
        "corpus_binding": corpus_binding,
        "semantic_replay": semantic_replay,
        "declared_content_sha256": declared_digest,
        "actual_content_sha256": actual_digest,
        "errors": errors,
    }
