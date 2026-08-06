"""Canonical projection of independently labeled LLM quality corpora."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .integrity import canonical_json_sha256

LEGACY_CORPUS_FORMAT = "pysfmea-llm-quality-corpus-1"
CORPUS_FORMAT = "pysfmea-llm-quality-corpus-2"
SUPPORTED_CORPUS_FORMATS = {LEGACY_CORPUS_FORMAT, CORPUS_FORMAT}
MAX_SAMPLES = 100_000


@dataclass(frozen=True)
class LlmQualityProjection:
    """Recomputed metrics and semantic identity for one closed corpus."""

    corpus_format: str
    subject_bound: bool
    sample_count: int
    grounded_sample_count: int
    citation_correct_sample_count: int
    claim_count: int
    unsupported_claim_count: int
    evidence_fingerprint_sha256: str

    @property
    def grounding(self) -> float:
        return round(self.grounded_sample_count / self.sample_count, 4)

    @property
    def citation_accuracy(self) -> float:
        return round(self.citation_correct_sample_count / self.sample_count, 4)

    @property
    def unsupported_claim_rate(self) -> float:
        return round(self.unsupported_claim_count / self.claim_count, 4)


def project_llm_quality_corpus(
    corpus: Any,
    *,
    expected_subject: Mapping[str, str] | None = None,
) -> LlmQualityProjection:
    """Validate and canonically project a closed labeled LLM corpus."""

    if not isinstance(corpus, dict):
        raise ValueError("LLM quality corpus root must be an object")
    schema_version = corpus.get("schema_version")
    if schema_version not in SUPPORTED_CORPUS_FORMATS:
        raise ValueError("LLM quality corpus schema_version is missing or unsupported")
    allowed_root = {"schema_version", "name", "purpose", "samples"}
    if schema_version == CORPUS_FORMAT:
        allowed_root.add("subject")
    if set(corpus) - allowed_root:
        raise ValueError("LLM quality corpus contains unsupported fields")

    subject_bound = schema_version == CORPUS_FORMAT
    subject: dict[str, str] | None = None
    if subject_bound:
        raw_subject = corpus.get("subject")
        expected_keys = {"provider", "model", "prompt_version"}
        if (
            not isinstance(raw_subject, dict)
            or set(raw_subject) != expected_keys
            or any(
                not isinstance(value, str)
                or not value.strip()
                or len(value) > 4096
                for value in raw_subject.values()
            )
        ):
            raise ValueError(
                "LLM quality corpus subject must exactly match provider, model, and prompt version"
            )
        subject = {key: raw_subject[key].strip() for key in sorted(expected_keys)}
        if expected_subject is not None and subject != {
            key: str(expected_subject.get(key, "")).strip() for key in expected_keys
        }:
            raise ValueError(
                "LLM quality corpus subject must exactly match provider, model, and prompt version"
            )

    samples = corpus.get("samples")
    if not isinstance(samples, list) or not samples or len(samples) > MAX_SAMPLES:
        raise ValueError("LLM quality corpus requires a bounded non-empty samples array")

    allowed_sample = {
        "id",
        "grounded",
        "citations_correct",
        "claim_count",
        "unsupported_claim_count",
    }
    sample_ids: set[str] = set()
    normalized_samples: list[dict[str, str | bool | int]] = []
    grounded = 0
    citations_correct = 0
    claim_count = 0
    unsupported_claim_count = 0
    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict) or set(sample) != allowed_sample:
            raise ValueError(
                f"LLM quality sample {index} does not match the closed contract"
            )
        sample_id = sample.get("id")
        if (
            not isinstance(sample_id, str)
            or not sample_id.strip()
            or len(sample_id) > 4096
        ):
            raise ValueError(f"LLM quality sample {index} requires a bounded id")
        normalized_id = sample_id.strip()
        if normalized_id in sample_ids:
            raise ValueError("LLM quality sample ids must be unique after normalization")
        sample_ids.add(normalized_id)
        if not all(
            isinstance(sample.get(field), bool)
            for field in ("grounded", "citations_correct")
        ):
            raise ValueError(f"LLM quality sample {index} decisions must be booleans")
        claims = sample.get("claim_count")
        unsupported = sample.get("unsupported_claim_count")
        if (
            not isinstance(claims, int)
            or isinstance(claims, bool)
            or claims < 1
            or not isinstance(unsupported, int)
            or isinstance(unsupported, bool)
            or unsupported < 0
            or unsupported > claims
        ):
            raise ValueError(f"LLM quality sample {index} claim counts are invalid")
        grounded_value = bool(sample["grounded"])
        citations_value = bool(sample["citations_correct"])
        grounded += int(grounded_value)
        citations_correct += int(citations_value)
        claim_count += claims
        unsupported_claim_count += unsupported
        normalized_samples.append(
            {
                "id": normalized_id,
                "grounded": grounded_value,
                "citations_correct": citations_value,
                "claim_count": claims,
                "unsupported_claim_count": unsupported,
            }
        )

    identity: dict[str, Any] = {
        "schema_version": schema_version,
        "samples": sorted(normalized_samples, key=lambda value: str(value["id"])),
    }
    if subject is not None:
        identity["subject"] = subject
    return LlmQualityProjection(
        corpus_format=schema_version,
        subject_bound=subject_bound,
        sample_count=len(samples),
        grounded_sample_count=grounded,
        citation_correct_sample_count=citations_correct,
        claim_count=claim_count,
        unsupported_claim_count=unsupported_claim_count,
        evidence_fingerprint_sha256=canonical_json_sha256(identity),
    )
