"""Build a program-compatible LLM quality record from independently labeled samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.json_ingestion import load_bounded_json_document
from pysfmea.llm_quality import project_llm_quality_corpus

MAX_CORPUS_BYTES = 20_000_000


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
    projection = project_llm_quality_corpus(
        corpus,
        expected_subject={
            "provider": provider.strip(),
            "model": model.strip(),
            "prompt_version": prompt_version.strip(),
        },
    )
    raw_digest = hashlib.sha256(raw).hexdigest()
    record: dict[str, Any] = {
        "id": evaluation_id.strip(),
        "provider": provider.strip(),
        "model": model.strip(),
        "prompt_version": prompt_version.strip(),
        "sample_count": projection.sample_count,
        "grounding": projection.grounding,
        "citation_accuracy": projection.citation_accuracy,
        "unsupported_claim_rate": projection.unsupported_claim_rate,
        "grounded_sample_count": projection.grounded_sample_count,
        "citation_correct_sample_count": projection.citation_correct_sample_count,
        "claim_count": projection.claim_count,
        "unsupported_claim_count": projection.unsupported_claim_count,
        "corpus_sha256": raw_digest,
        "corpus_format": projection.corpus_format,
        "subject_bound": projection.subject_bound,
        "evidence_fingerprint_sha256": projection.evidence_fingerprint_sha256,
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
