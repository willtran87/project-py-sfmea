"""Direct, governed benchmark for PySFMEA semantic discovery claims.

The bundled corpus is useful regression evidence.  This module makes the same
runner usable with independently labeled repository corpora without promoting
the bundled fixture to independent validation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .campaign_runner import repository_snapshot_sha256
from .discovery import evaluate_candidates, load_evaluation_spec
from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_file_snapshot
from .model import utc_now
from .scanner import scan_repository
from .version import __version__

SFMEA_BENCHMARK_FORMAT = "pysfmea-semantic-benchmark-1"
SFMEA_BENCHMARK_VERIFICATION_FORMAT = "pysfmea-semantic-benchmark-verification-1"
MAX_CORPUS_BYTES = 100 * 1024 * 1024


def _metrics(evaluation: dict[str, Any]) -> dict[str, Any]:
    calls = evaluation.get("call_resolution", {})
    controls = evaluation.get("control_detection", {})
    semantics = evaluation.get("semantic_output", {})
    return {
        "finding_precision": evaluation.get("precision"),
        "finding_recall": evaluation.get("recall"),
        "call_resolution_precision": calls.get("precision"),
        "call_resolution_recall": calls.get("recall"),
        "control_precision": controls.get("precision"),
        "control_recall": controls.get("recall"),
        "semantic_case_precision": semantics.get("precision"),
        "semantic_case_recall": semantics.get("recall"),
        "semantic_claim_precision": semantics.get("claim_precision"),
        "semantic_claim_recall": semantics.get("claim_recall"),
    }


def _eligible(evaluation: dict[str, Any], metrics: dict[str, Any]) -> bool:
    governance = evaluation.get("corpus", {}).get("governance", {})
    required = (
        "finding_precision",
        "finding_recall",
        "call_resolution_precision",
        "call_resolution_recall",
        "control_precision",
        "control_recall",
        "semantic_claim_precision",
        "semantic_claim_recall",
    )
    return bool(
        governance.get("qualification_ready")
        and all(isinstance(metrics[name], (int, float)) for name in required)
    )


def run_sfmea_semantic_benchmark(
    repository: str | Path,
    corpus: str | Path,
    *,
    authority: str,
    destination: str | Path | None = None,
) -> dict[str, Any]:
    """Scan one repository and evaluate exact governed SFMEA labels."""

    root = Path(repository).expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("semantic benchmark repository must be a regular directory")
    corpus_path = Path(corpus).expanduser().resolve()
    snapshot = load_bounded_file_snapshot(
        corpus_path, label="semantic benchmark corpus", max_bytes=MAX_CORPUS_BYTES
    )
    expected = load_evaluation_spec(corpus_path)
    before = repository_snapshot_sha256(root)
    analysis = scan_repository(root)
    after = repository_snapshot_sha256(root)
    if before != after:
        raise ValueError("semantic benchmark repository changed during execution")
    evaluation = evaluate_candidates(analysis, expected)
    metrics = _metrics(evaluation)
    result = seal(
        {
            "format": SFMEA_BENCHMARK_FORMAT,
            "generated_at": utc_now(),
            "tool": {"name": "PySFMEA", "version": __version__},
            "repository": {
                "reference": str(root),
                "snapshot_sha256": before,
                "analysis_content_sha256": analysis.get("content_sha256", ""),
                "source_digest": analysis.get("project", {})
                .get("baseline", {})
                .get("source_digest", ""),
            },
            "corpus": {
                "reference": str(corpus_path),
                "bytes": snapshot.size,
                "sha256": hashlib.sha256(snapshot.raw).hexdigest(),
                "content_sha256": evaluation.get("corpus", {}).get(
                    "content_sha256", ""
                ),
                "governance": evaluation.get("corpus", {}).get("governance", {}),
            },
            "authority": bounded_text(authority, "semantic benchmark authority"),
            "metrics": metrics,
            "population": {
                "finding_cases": evaluation.get("corpus", {}).get("case_count", 0),
                "call_cases": evaluation.get("corpus", {}).get("call_case_count", 0),
                "control_cases": evaluation.get("corpus", {}).get(
                    "control_case_count", 0
                ),
                "semantic_cases": evaluation.get("corpus", {}).get(
                    "semantic_case_count", 0
                ),
                "semantic_claims": evaluation.get("corpus", {}).get(
                    "semantic_claim_count", 0
                ),
            },
            "eligible_for_independent_claim": _eligible(evaluation, metrics),
            "evaluation": evaluation,
            "claim_boundary": "This artifact directly measures declared scanner outputs against exact corpus labels. Eligibility additionally requires the corpus's distinct independent labeling and approval claims, but cannot authenticate those people, establish population representativeness, qualify the tool, or grant certification.",
        }
    )
    verdict = verify_sfmea_semantic_benchmark(result)
    if not verdict["valid"]:
        raise ValueError("semantic benchmark result failed internal verification")
    if destination is not None:
        publish_json(result, destination)
    return result


def verify_sfmea_semantic_benchmark(
    value: dict[str, Any],
    *,
    repository: str | Path | None = None,
    corpus: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    integrity = structure = reconciliation = source_binding = True
    try:
        checked = verify_seal(
            value, label="semantic benchmark", format_value=SFMEA_BENCHMARK_FORMAT
        )
        required = {
            "format",
            "generated_at",
            "tool",
            "repository",
            "corpus",
            "authority",
            "metrics",
            "population",
            "eligible_for_independent_claim",
            "evaluation",
            "claim_boundary",
            "content_sha256",
        }
        if set(checked) != required:
            raise ValueError("semantic benchmark fields are invalid")
        bounded_text(checked["authority"], "semantic benchmark authority")
        bounded_text(checked["claim_boundary"], "semantic benchmark claim boundary")
        evaluation = checked["evaluation"]
        metrics = _metrics(evaluation)
        population = {
            "finding_cases": evaluation.get("corpus", {}).get("case_count", 0),
            "call_cases": evaluation.get("corpus", {}).get("call_case_count", 0),
            "control_cases": evaluation.get("corpus", {}).get("control_case_count", 0),
            "semantic_cases": evaluation.get("corpus", {}).get(
                "semantic_case_count", 0
            ),
            "semantic_claims": evaluation.get("corpus", {}).get(
                "semantic_claim_count", 0
            ),
        }
        reconciliation = bool(
            checked["metrics"] == metrics
            and checked["population"] == population
            and checked["eligible_for_independent_claim"]
            == _eligible(evaluation, metrics)
        )
        if not reconciliation:
            errors.append("semantic benchmark metrics or eligibility do not reconcile")
        structure = True
        if repository is not None:
            source_binding = (
                source_binding
                and repository_snapshot_sha256(repository)
                == checked["repository"]["snapshot_sha256"]
            )
        if corpus is not None:
            snapshot = load_bounded_file_snapshot(
                corpus, label="semantic benchmark corpus", max_bytes=MAX_CORPUS_BYTES
            )
            source_binding = (
                source_binding
                and snapshot.size == checked["corpus"]["bytes"]
                and hashlib.sha256(snapshot.raw).hexdigest()
                == checked["corpus"]["sha256"]
            )
        if not source_binding:
            errors.append("semantic benchmark source binding does not match")
    except (OSError, TypeError, ValueError) as exc:
        integrity = structure = False
        errors.append(str(exc))
    valid = integrity and structure and reconciliation and source_binding and not errors
    return seal(
        {
            "format": SFMEA_BENCHMARK_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_independent_claim": bool(
                valid and value.get("eligible_for_independent_claim")
            ),
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "metric_and_population_reconciliation": reconciliation,
                "source_binding": source_binding,
            },
            "errors": errors,
            "notice": "Verification establishes deterministic accounting and optional exact source binding, not reviewer identity, representativeness, qualification, or certification.",
        }
    )


def verify_sfmea_semantic_benchmark_file(
    source: str | Path,
    *,
    repository: str | Path | None = None,
    corpus: str | Path | None = None,
) -> dict[str, Any]:
    try:
        return verify_sfmea_semantic_benchmark(
            load_json(source, label="semantic benchmark"),
            repository=repository,
            corpus=corpus,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": SFMEA_BENCHMARK_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_independent_claim": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "metric_and_population_reconciliation": False,
                    "source_binding": False,
                },
                "errors": [str(exc)],
                "notice": "Semantic benchmark verification failed closed.",
            }
        )
