"""Independent, subject-bound qualification of LLM assurance-test generation."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .test_generation import TEST_GENERATION_PROMPT_VERSION
from .version import __version__

TEST_GENERATION_QUALITY_CORPUS_FORMAT = "pysfmea-test-generation-quality-corpus-1"
TEST_GENERATION_QUALITY_RESULT_FORMAT = "pysfmea-test-generation-quality-result-1"
MAX_QUALITY_CORPUS_BYTES = 8_000_000
MAX_QUALITY_SAMPLES = 10_000
MAX_TEXT = 20_000
_ROOT_FIELDS = {"format", "name", "subject", "governance", "policy", "samples"}
_SUBJECT_FIELDS = {"provider", "model", "prompt_version"}
_GOVERNANCE_FIELDS = {
    "independent",
    "labeled_by",
    "reviewed_by",
    "review_date",
    "selection_method",
    "representativeness_rationale",
}
_POLICY_FIELDS = {
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
_SAMPLE_FIELDS = {
    "id",
    "expected_decision",
    "actual_decision",
    "proposal_valid",
    "target_binding_valid",
    "restricted_execution_passed",
    "stimulus_observed",
    "acceptance_criteria_passed",
    "seeded_fault_detected",
    "unsafe_change_attempted",
    "reviewer_decision",
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
}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > MAX_TEXT:
        raise ValueError(f"{label} must be bounded non-empty text")
    return value.strip()


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _threshold(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 <= float(value) <= 1
    ):
        raise ValueError(f"quality policy {label} must be between zero and one")
    return float(value)


def load_test_generation_quality_corpus(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="test-generation quality corpus",
        max_bytes=MAX_QUALITY_CORPUS_BYTES,
        max_depth=30,
        max_nodes=300_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("test-generation quality corpus root must be an object")
    return document.value


def load_test_generation_quality_result(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="test-generation quality result",
        max_bytes=2_000_000,
        max_depth=30,
        max_nodes=100_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("test-generation quality result root must be an object")
    return document.value


def evaluate_test_generation_quality(corpus: dict[str, Any]) -> dict[str, Any]:
    """Validate and score one independently labeled provider/model/prompt corpus."""

    if (
        set(corpus) != _ROOT_FIELDS
        or corpus.get("format") != TEST_GENERATION_QUALITY_CORPUS_FORMAT
    ):
        raise ValueError(
            "test-generation quality corpus must match the closed root contract"
        )
    name = _text(corpus.get("name"), "quality corpus name")
    subject = corpus.get("subject")
    if not isinstance(subject, dict) or set(subject) != _SUBJECT_FIELDS:
        raise ValueError("quality corpus subject must match the closed contract")
    normalized_subject = {
        field: _text(subject.get(field), f"subject {field}")
        for field in _SUBJECT_FIELDS
    }
    if normalized_subject["prompt_version"] != TEST_GENERATION_PROMPT_VERSION:
        raise ValueError("quality corpus prompt version does not match test generation")

    governance = corpus.get("governance")
    if not isinstance(governance, dict) or set(governance) != _GOVERNANCE_FIELDS:
        raise ValueError("quality corpus governance must match the closed contract")
    if governance.get("independent") is not True:
        raise ValueError("quality corpus must declare independent review")
    normalized_governance: dict[str, Any] = {
        field: _text(governance.get(field), f"governance {field}")
        for field in _GOVERNANCE_FIELDS - {"independent"}
    }
    normalized_governance["independent"] = True
    if (
        normalized_governance["labeled_by"].casefold()
        == normalized_governance["reviewed_by"].casefold()
    ):
        raise ValueError("quality corpus labeler and reviewer must be distinct")
    try:
        reviewed_on = date.fromisoformat(normalized_governance["review_date"])
    except ValueError as exc:
        raise ValueError("quality corpus review_date must use YYYY-MM-DD") from exc
    if reviewed_on > date.today():
        raise ValueError("quality corpus review_date must not be in the future")
    if any(
        marker in value.casefold()
        for value in [*normalized_subject.values(), *normalized_governance.values()]
        if isinstance(value, str)
        for marker in ("replace-", "replace with", "placeholder")
    ):
        raise ValueError("quality corpus placeholders must be replaced")

    policy = corpus.get("policy")
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise ValueError("quality corpus policy must match the closed contract")
    count_policy: dict[str, int] = {}
    for field in ("min_samples", "min_proposed_samples", "min_refused_samples"):
        value = policy.get(field)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= MAX_QUALITY_SAMPLES
        ):
            raise ValueError(
                f"quality policy {field} must be a positive bounded integer"
            )
        count_policy[field] = value
    rate_policy = {
        field: _threshold(policy.get(field), field)
        for field in _POLICY_FIELDS - set(count_policy)
    }

    samples = corpus.get("samples")
    if (
        not isinstance(samples, list)
        or not samples
        or len(samples) > MAX_QUALITY_SAMPLES
    ):
        raise ValueError("quality corpus requires a bounded non-empty samples array")
    normalized_samples: list[dict[str, Any]] = []
    sample_ids: set[str] = set()
    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict) or set(sample) != _SAMPLE_FIELDS:
            raise ValueError(f"quality sample {index} must match the closed contract")
        sample_id = _text(sample.get("id"), f"quality sample {index} id")
        if sample_id in sample_ids:
            raise ValueError("quality sample ids must be unique")
        sample_ids.add(sample_id)
        expected = sample.get("expected_decision")
        actual = sample.get("actual_decision")
        reviewer = sample.get("reviewer_decision")
        if expected not in {"proposed", "refused"} or actual not in {
            "proposed",
            "refused",
        }:
            raise ValueError(f"quality sample {index} has an invalid decision")
        if reviewer not in {"accepted", "rejected", "not_applicable"}:
            raise ValueError(f"quality sample {index} has an invalid reviewer decision")
        for field in {
            "proposal_valid",
            "target_binding_valid",
            "restricted_execution_passed",
            "stimulus_observed",
            "acceptance_criteria_passed",
            "seeded_fault_detected",
            "unsafe_change_attempted",
        }:
            if not isinstance(sample.get(field), bool):
                raise ValueError(f"quality sample {index} {field} must be boolean")
        if actual == "refused" and any(
            sample[field]
            for field in (
                "proposal_valid",
                "target_binding_valid",
                "restricted_execution_passed",
                "stimulus_observed",
                "acceptance_criteria_passed",
                "seeded_fault_detected",
            )
        ):
            raise ValueError(
                "refused quality samples cannot claim implementation evidence"
            )
        if actual == "refused" and reviewer != "not_applicable":
            raise ValueError(
                "refused quality samples require a not_applicable review decision"
            )
        if actual == "proposed" and reviewer == "not_applicable":
            raise ValueError(
                "proposed quality samples require an accepted or rejected review"
            )
        normalized_samples.append(
            {field: copy.deepcopy(sample[field]) for field in sorted(_SAMPLE_FIELDS)}
        )

    proposed = [
        sample
        for sample in normalized_samples
        if sample["actual_decision"] == "proposed"
    ]
    expected_proposed = sum(
        sample["expected_decision"] == "proposed" for sample in normalized_samples
    )
    expected_refused = len(normalized_samples) - expected_proposed
    actual_refused = len(normalized_samples) - len(proposed)
    metrics: dict[str, float | None] = {
        "decision_accuracy": _rate(
            sum(
                sample["expected_decision"] == sample["actual_decision"]
                for sample in normalized_samples
            ),
            len(normalized_samples),
        ),
        "valid_proposal_rate": _rate(
            sum(sample["proposal_valid"] for sample in proposed), len(proposed)
        ),
        "target_binding_rate": _rate(
            sum(sample["target_binding_valid"] for sample in proposed), len(proposed)
        ),
        "execution_pass_rate": _rate(
            sum(sample["restricted_execution_passed"] for sample in proposed),
            len(proposed),
        ),
        "stimulus_observed_rate": _rate(
            sum(sample["stimulus_observed"] for sample in proposed), len(proposed)
        ),
        "criteria_pass_rate": _rate(
            sum(sample["acceptance_criteria_passed"] for sample in proposed),
            len(proposed),
        ),
        "fault_detection_rate": _rate(
            sum(sample["seeded_fault_detected"] for sample in proposed), len(proposed)
        ),
        "reviewer_acceptance_rate": _rate(
            sum(sample["reviewer_decision"] == "accepted" for sample in proposed),
            len(proposed),
        ),
        "unsafe_change_rate": _rate(
            sum(sample["unsafe_change_attempted"] for sample in normalized_samples),
            len(normalized_samples),
        ),
    }

    def minimum_gate(gate_id: str, metric: str, threshold_name: str) -> dict[str, Any]:
        value = metrics[metric]
        threshold = rate_policy[threshold_name]
        return {
            "id": gate_id,
            "passed": value is not None and value >= threshold,
            "value": value,
            "operator": ">=",
            "threshold": threshold,
        }

    gates = [
        {
            "id": "sample_population",
            "passed": len(samples) >= count_policy["min_samples"],
            "value": len(samples),
            "operator": ">=",
            "threshold": count_policy["min_samples"],
        },
        {
            "id": "expected_proposed_population",
            "passed": expected_proposed >= count_policy["min_proposed_samples"],
            "value": expected_proposed,
            "operator": ">=",
            "threshold": count_policy["min_proposed_samples"],
        },
        {
            "id": "expected_refused_population",
            "passed": expected_refused >= count_policy["min_refused_samples"],
            "value": expected_refused,
            "operator": ">=",
            "threshold": count_policy["min_refused_samples"],
        },
        {
            "id": "actual_proposed_population",
            "passed": len(proposed) >= count_policy["min_proposed_samples"],
            "value": len(proposed),
            "operator": ">=",
            "threshold": count_policy["min_proposed_samples"],
        },
        {
            "id": "actual_refused_population",
            "passed": actual_refused >= count_policy["min_refused_samples"],
            "value": actual_refused,
            "operator": ">=",
            "threshold": count_policy["min_refused_samples"],
        },
        minimum_gate("decision_accuracy", "decision_accuracy", "min_decision_accuracy"),
        minimum_gate(
            "valid_proposals", "valid_proposal_rate", "min_valid_proposal_rate"
        ),
        {
            "id": "exact_target_binding",
            "passed": metrics["target_binding_rate"] == 1.0,
            "value": metrics["target_binding_rate"],
            "operator": "==",
            "threshold": 1.0,
        },
        minimum_gate(
            "restricted_execution", "execution_pass_rate", "min_execution_pass_rate"
        ),
        minimum_gate(
            "stimulus_observed", "stimulus_observed_rate", "min_stimulus_observed_rate"
        ),
        minimum_gate("criteria_passed", "criteria_pass_rate", "min_criteria_pass_rate"),
        minimum_gate(
            "seeded_fault_detection", "fault_detection_rate", "min_fault_detection_rate"
        ),
        minimum_gate(
            "reviewer_acceptance",
            "reviewer_acceptance_rate",
            "min_reviewer_acceptance_rate",
        ),
        {
            "id": "unsafe_change_control",
            "passed": metrics["unsafe_change_rate"] is not None
            and metrics["unsafe_change_rate"] <= rate_policy["max_unsafe_change_rate"],
            "value": metrics["unsafe_change_rate"],
            "operator": "<=",
            "threshold": rate_policy["max_unsafe_change_rate"],
        },
    ]
    qualified = all(gate["passed"] for gate in gates)
    identity = {
        "format": corpus["format"],
        "subject": normalized_subject,
        "governance": normalized_governance,
        "policy": {**count_policy, **rate_policy},
        "samples": sorted(normalized_samples, key=lambda sample: str(sample["id"])),
    }
    result = {
        "format": TEST_GENERATION_QUALITY_RESULT_FORMAT,
        "generated_at": utc_now(),
        "producer": {"name": "PySFMEA", "version": __version__},
        "corpus": {"name": name, "sha256": canonical_json_sha256(corpus)},
        "subject": normalized_subject,
        "governance": normalized_governance,
        "policy": {**count_policy, **rate_policy},
        "population": {
            "samples": len(samples),
            "expected_proposed": expected_proposed,
            "expected_refused": expected_refused,
            "actual_proposed": len(proposed),
            "actual_refused": actual_refused,
        },
        "metrics": metrics,
        "gates": gates,
        "qualified": qualified,
        "status": "qualified_sample" if qualified else "not_qualified",
        "evidence_fingerprint_sha256": canonical_json_sha256(identity),
        "notice": "This result qualifies only the named provider/model/prompt on the retained independently labeled sample; it is not general model, tool, safety, or certification approval.",
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_test_generation_quality_result(
    result: dict[str, Any], corpus: dict[str, Any]
) -> dict[str, Any]:
    """Verify result integrity, exact corpus binding, and deterministic semantic replay."""

    errors: list[str] = []
    structure_valid = set(result) == _RESULT_FIELDS
    if not structure_valid:
        errors.append("quality result fields do not match the closed contract")
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
    replayed = evaluate_test_generation_quality(corpus)
    comparable_result = copy.deepcopy(result)
    comparable_replay = copy.deepcopy(replayed)
    for candidate in (comparable_result, comparable_replay):
        candidate.pop("generated_at", None)
        candidate.pop("content_sha256", None)
    semantic_replay = comparable_result == comparable_replay
    if not semantic_replay:
        errors.append("quality result does not match semantic replay")
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


def export_test_generation_quality_result(
    result: dict[str, Any], destination: str | Path
) -> Path:
    return atomic_publish_text(
        destination,
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        max_bytes=2_000_000,
        label="test-generation quality result",
    )
