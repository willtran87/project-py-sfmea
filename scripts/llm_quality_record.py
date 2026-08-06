"""Build a program-compatible LLM quality record from independently labeled samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.json_ingestion import load_bounded_json_document

LEGACY_CORPUS_FORMAT = "pysfmea-llm-quality-corpus-1"
CORPUS_FORMAT = "pysfmea-llm-quality-corpus-2"
MAX_CORPUS_BYTES = 20_000_000
MAX_SAMPLES = 100_000


def quality_record(
    corpus: dict[str, Any],
    *,
    raw: bytes,
    evaluation_id: str,
    provider: str,
    model: str,
    prompt_version: str,
    producer: str,
    reviewer: str,
    artifact_path: str | None = None,
) -> dict[str, Any]:
    provenance = [evaluation_id, provider, model, prompt_version, producer, reviewer]
    if not all(
        isinstance(value, str) and value.strip() and len(value) <= 4096
        for value in provenance
    ):
        raise ValueError(
            "LLM quality identity and provenance fields must be non-empty and bounded"
        )
    if producer.strip().casefold() == reviewer.strip().casefold():
        raise ValueError(
            "LLM quality record requires distinct producer and reviewer identities"
        )
    schema_version = corpus.get("schema_version")
    allowed_root = {"schema_version", "name", "purpose", "samples"}
    if schema_version == CORPUS_FORMAT:
        allowed_root.add("subject")
    if set(corpus) - allowed_root:
        raise ValueError("LLM quality corpus contains unsupported fields")
    if schema_version not in {LEGACY_CORPUS_FORMAT, CORPUS_FORMAT}:
        raise ValueError("LLM quality corpus schema_version is missing or unsupported")
    subject_bound = schema_version == CORPUS_FORMAT
    if subject_bound:
        subject = corpus.get("subject")
        expected_subject = {
            "provider": provider.strip(),
            "model": model.strip(),
            "prompt_version": prompt_version.strip(),
        }
        if (
            not isinstance(subject, dict)
            or set(subject) != set(expected_subject)
            or any(
                not isinstance(value, str) or not value.strip() or len(value) > 4096
                for value in subject.values()
            )
            or subject != expected_subject
        ):
            raise ValueError(
                "LLM quality corpus subject must exactly match provider, model, and prompt version"
            )
    samples = corpus.get("samples")
    if not isinstance(samples, list) or not samples or len(samples) > MAX_SAMPLES:
        raise ValueError(
            "LLM quality corpus requires a bounded non-empty samples array"
        )
    sample_ids: set[str] = set()
    grounded = 0
    citations_correct = 0
    claim_count = 0
    unsupported_claim_count = 0
    allowed_sample = {
        "id",
        "grounded",
        "citations_correct",
        "claim_count",
        "unsupported_claim_count",
    }
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
        if sample_id in sample_ids:
            raise ValueError("LLM quality sample ids must be unique")
        sample_ids.add(sample_id)
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
        grounded += int(sample["grounded"])
        citations_correct += int(sample["citations_correct"])
        claim_count += claims
        unsupported_claim_count += unsupported
    raw_digest = hashlib.sha256(raw).hexdigest()
    record: dict[str, Any] = {
        "id": evaluation_id.strip(),
        "provider": provider.strip(),
        "model": model.strip(),
        "prompt_version": prompt_version.strip(),
        "sample_count": len(samples),
        "grounding": round(grounded / len(samples), 4),
        "citation_accuracy": round(citations_correct / len(samples), 4),
        "unsupported_claim_rate": round(unsupported_claim_count / claim_count, 4),
        "grounded_sample_count": grounded,
        "citation_correct_sample_count": citations_correct,
        "claim_count": claim_count,
        "unsupported_claim_count": unsupported_claim_count,
        "corpus_sha256": raw_digest,
        "corpus_format": schema_version,
        "subject_bound": subject_bound,
        "independent_reviewed": True,
        "producer": producer.strip(),
        "reviewer": reviewer.strip(),
    }
    if artifact_path is not None:
        path = artifact_path.strip()
        if not path or len(path) > 4096:
            raise ValueError(
                "LLM quality corpus artifact path must be non-empty and bounded"
            )
        record["corpus_artifact"] = {"path": path, "sha256": raw_digest}
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    parser.add_argument("--id", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--prompt-version", required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument(
        "--artifact-path",
        help="Program-relative reference to the retained corpus JSON (defaults to the input argument).",
    )
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    document = load_bounded_json_document(
        args.corpus,
        label="LLM quality corpus",
        max_bytes=MAX_CORPUS_BYTES,
        max_depth=30,
        max_nodes=1_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("LLM quality corpus root must be an object")
    record = quality_record(
        document.value,
        raw=document.raw,
        evaluation_id=args.id,
        provider=args.provider,
        model=args.model,
        prompt_version=args.prompt_version,
        producer=args.producer,
        reviewer=args.reviewer,
        artifact_path=args.artifact_path or args.corpus,
    )
    rendered = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        destination = atomic_publish_text(
            args.output, rendered, label="LLM quality record"
        )
        print(destination)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
