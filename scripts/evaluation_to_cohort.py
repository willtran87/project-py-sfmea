"""Convert one reconciled PySFMEA evaluation result into a validation cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.integrity import canonical_json_sha256
from pysfmea.json_ingestion import load_bounded_json_document

MAX_RESULT_BYTES = 20_000_000


def _verified_counts(
    record: dict[str, Any],
    *,
    expected_count: int,
    recall: float,
    precision: float,
    label: str,
) -> tuple[int, int, int]:
    """Return count evidence only when it reconciles with reported metrics."""

    counts = {name: record.get(name) for name in ("expected", "actual", "matched")}
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts.values()
    ):
        raise ValueError(f"{label} evaluation requires non-negative integer counts")
    expected = counts["expected"]
    actual = counts["actual"]
    matched = counts["matched"]
    if expected != expected_count:
        raise ValueError(f"{label} expected count does not match the corpus case count")
    if matched > expected or matched > actual:
        raise ValueError(f"{label} matched count exceeds expected or actual count")
    if actual < 1:
        raise ValueError(
            f"{label} actual count must be positive when precision is reported"
        )
    missing = record.get("missing")
    unexpected = record.get("unexpected")
    if not isinstance(missing, list) or not isinstance(unexpected, list):
        raise ValueError(f"{label} evaluation requires missing and unexpected arrays")
    actual_matched = actual - len(unexpected)
    if matched != expected - len(missing) or actual_matched < 0:
        raise ValueError(
            f"{label} counts do not reconcile with missing/unexpected cases"
        )
    computed_recall = round(matched / expected, 4)
    computed_precision = round(actual_matched / actual, 4)
    if recall != computed_recall or precision != computed_precision:
        raise ValueError(
            f"{label} recall or precision does not reconcile with matched/expected/actual counts"
        )
    return matched, actual_matched, actual


def _verified_semantic_counts(
    record: dict[str, Any],
    *,
    expected_count: int,
) -> tuple[float, float, int, int, int]:
    """Reconcile exact semantic-case metrics without conflating field mismatches."""

    recall = record.get("recall")
    precision = record.get("precision")
    if not all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= 1
        for value in (recall, precision)
    ):
        raise ValueError("semantic-output evaluation requires bounded recall and precision")
    counts = {name: record.get(name) for name in ("expected", "actual", "matched")}
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts.values()
    ):
        raise ValueError("semantic-output evaluation requires non-negative integer counts")
    expected = counts["expected"]
    actual = counts["actual"]
    matched = counts["matched"]
    missing = record.get("missing")
    mismatches = record.get("mismatches")
    if expected != expected_count or not isinstance(missing, list) or not isinstance(
        mismatches, list
    ):
        raise ValueError("semantic-output corpus counts or diagnostics are malformed")
    if actual < 1 or matched > expected or matched > actual:
        raise ValueError("semantic-output counts do not reconcile")
    if matched != expected - len(missing):
        raise ValueError("semantic-output expected-side counts do not reconcile")
    if float(recall) != round(matched / expected, 4) or float(precision) != round(
        matched / actual, 4
    ):
        raise ValueError("semantic-output recall or precision does not reconcile")
    return float(recall), float(precision), matched, matched, actual



def cohort_from_result(
    result: dict[str, Any],
    *,
    cohort_id: str,
    repository: str,
    framework: str,
    producer: str,
    reviewer: str,
    artifact_path: str | None = None,
    artifact_sha256: str | None = None,
) -> dict[str, Any]:
    values = {
        "id": cohort_id.strip(),
        "repository": repository.strip(),
        "framework": framework.strip(),
        "producer": producer.strip(),
        "reviewer": reviewer.strip(),
    }
    if not all(values.values()) or any(len(value) > 4096 for value in values.values()):
        raise ValueError(
            "cohort identity and provenance fields must be non-empty and bounded"
        )
    if values["producer"].casefold() == values["reviewer"].casefold():
        raise ValueError(
            "validation cohort requires distinct producer and reviewer identities"
        )
    if result.get("format") != "pysfmea-evaluation-result-1":
        raise ValueError("evaluation result format is missing or unsupported")
    verifier = result.get("verifier", {})
    verifier_version = (
        str(verifier.get("version", "")).strip()
        if isinstance(verifier, dict) and verifier.get("name") == "PySFMEA"
        else ""
    )
    if not verifier_version or len(verifier_version) > 100:
        raise ValueError(
            "evaluation result requires a bounded PySFMEA verifier version"
        )
    call_resolution = result.get("call_resolution", {})
    metrics = result.get("metrics", {})
    duplicate_count = (
        metrics.get("duplicate_count") if isinstance(metrics, dict) else None
    )
    unsupported_claims = (
        metrics.get("unsupported_verification_claims")
        if isinstance(metrics, dict)
        else None
    )
    if (
        not isinstance(metrics, dict)
        or not isinstance(duplicate_count, int)
        or isinstance(duplicate_count, bool)
        or duplicate_count != 0
        or not isinstance(unsupported_claims, list)
        or unsupported_claims
    ):
        raise ValueError("evaluation result contains disqualifying quality findings")
    recall = result.get("recall")
    precision = result.get("precision")
    if not all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= 1
        for value in (recall, precision)
    ):
        raise ValueError("evaluation result requires bounded recall and precision")
    corpus = result.get("corpus", {})
    digest = str(corpus.get("content_sha256", "")).lower()
    case_count = corpus.get("case_count")
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError("evaluation result corpus digest is invalid")
    if (
        not isinstance(case_count, int)
        or isinstance(case_count, bool)
        or case_count < 1
    ):
        raise ValueError("evaluation result corpus case_count must be positive")
    matched_count, actual_matched_count, actual_count = _verified_counts(
        result,
        expected_count=case_count,
        recall=float(recall),
        precision=float(precision),
        label="failure-mode",
    )
    record: dict[str, Any] = {
        "id": values["id"],
        "repository": values["repository"],
        "framework": values["framework"],
        "corpus_sha256": digest,
        "case_count": case_count,
        "recall": recall,
        "precision": precision,
        "matched_count": matched_count,
        "actual_matched_count": actual_matched_count,
        "actual_count": actual_count,
        "evaluation_result_format": result["format"],
        "evaluation_result_sha256": canonical_json_sha256(result),
        "evaluation_verifier_version": verifier_version,
        "independent_reviewed": True,
        "producer": values["producer"],
        "reviewer": values["reviewer"],
    }
    if artifact_path is not None or artifact_sha256 is not None:
        path = str(artifact_path or "").strip()
        digest_value = str(artifact_sha256 or "").lower()
        if (
            not path
            or len(path) > 4096
            or len(digest_value) != 64
            or any(character not in "0123456789abcdef" for character in digest_value)
        ):
            raise ValueError(
                "evaluation artifact requires a bounded path and lowercase SHA-256 digest"
            )
        record["evaluation_result_artifact"] = {
            "path": path,
            "sha256": digest_value,
        }
    if call_resolution.get("enabled"):
        call_case_count = corpus.get("call_case_count")
        call_recall = call_resolution.get("recall")
        call_precision = call_resolution.get("precision")
        if (
            not isinstance(call_case_count, int)
            or isinstance(call_case_count, bool)
            or call_case_count < 1
        ):
            raise ValueError(
                "enabled call-resolution evaluation requires a positive call_case_count"
            )
        if not all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and 0 <= value <= 1
            for value in (call_recall, call_precision)
        ):
            raise ValueError(
                "enabled call-resolution evaluation requires bounded recall and precision"
            )
        call_matched_count, call_actual_matched_count, call_actual_count = (
            _verified_counts(
                call_resolution,
                expected_count=call_case_count,
                recall=float(call_recall),
                precision=float(call_precision),
                label="call-resolution",
            )
        )
        record.update(
            {
                "call_case_count": call_case_count,
                "call_resolution_recall": call_recall,
                "call_resolution_precision": call_precision,
                "call_matched_count": call_matched_count,
                "call_actual_matched_count": call_actual_matched_count,
                "call_actual_count": call_actual_count,
            }
        )
    semantic_output = result.get("semantic_output", {})
    if semantic_output.get("enabled"):
        semantic_case_count = corpus.get("semantic_case_count")
        if not isinstance(semantic_case_count, int) or isinstance(
            semantic_case_count, bool
        ) or semantic_case_count < 1:
            raise ValueError("enabled semantic output requires semantic cases")
        semantic_recall, semantic_precision, semantic_matched, semantic_actual_matched, semantic_actual = _verified_semantic_counts(
            semantic_output, expected_count=semantic_case_count
        )
        record.update(
            {
                "semantic_case_count": semantic_case_count,
                "semantic_output_recall": semantic_recall,
                "semantic_output_precision": semantic_precision,
                "semantic_matched_count": semantic_matched,
                "semantic_actual_matched_count": semantic_actual_matched,
                "semantic_actual_count": semantic_actual,
            }
        )
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evaluation_result")
    parser.add_argument("--id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--framework", required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument(
        "--artifact-path",
        help="Program-relative reference to the retained evaluation JSON (defaults to the input argument).",
    )
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    document = load_bounded_json_document(
        args.evaluation_result,
        label="evaluation result",
        max_bytes=MAX_RESULT_BYTES,
        max_depth=50,
        max_nodes=500_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("evaluation result root must be an object")
    record = cohort_from_result(
        document.value,
        cohort_id=args.id,
        repository=args.repository,
        framework=args.framework,
        producer=args.producer,
        reviewer=args.reviewer,
        artifact_path=args.artifact_path or args.evaluation_result,
        artifact_sha256=hashlib.sha256(document.raw).hexdigest(),
    )
    rendered = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        destination = atomic_publish_text(
            args.output, rendered, label="validation cohort record"
        )
        print(destination)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
