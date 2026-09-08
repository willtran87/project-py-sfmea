"""Governed benchmark-source currency, licensing, and adapter capability evidence."""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .industry_benchmarks import BENCHMARK_SUITES
from .model import utc_now

BENCHMARK_SOURCE_HEALTH_FORMAT = "pysfmea-benchmark-source-health-1"
BENCHMARK_SOURCE_HEALTH_VERIFICATION_FORMAT = (
    "pysfmea-benchmark-source-health-verification-1"
)
STATUSES = {"unreviewed", "verified", "moved", "unavailable", "superseded"}
MATURITY = {"internal-regression", "preliminary", "research", "stable"}

_MATURITY = {
    "pysfmea-semantic-corpus": "internal-regression",
    "pysfmea-causal-propagation": "internal-regression",
    "pysfmea-modern-python-dynamics": "internal-regression",
    "pysfmea-distributed-resilience": "internal-regression",
    "pysfmea-interoperability-conformance": "internal-regression",
    "pysfmea-longitudinal-drift": "internal-regression",
    "pysfmea-mutation-proficiency": "internal-regression",
    "pysfmea-fuzz-ground-truth": "internal-regression",
    "pysfmea-framework-negative-controls": "internal-regression",
    "pysfmea-python-platform-matrix": "internal-regression",
    "pysfmea-temporal-hidden-holdout": "preliminary",
    "pysfmea-cross-organization-proficiency": "preliminary",
    "pysfmea-dual-mutation-engine-qualification": "internal-regression",
    "pysfmea-scale-resource-exhaustion": "internal-regression",
    "pysfmea-nondeterminism-concurrency": "internal-regression",
    "owasp-benchmark-python": "preliminary",
    "cyberseceval-4": "research",
    "crosscodeeval-python": "research",
    "crosscodelongeval-python": "research",
    "agentdojo": "research",
    "swe-polybench-verified-python": "research",
    "idoft-python": "stable",
    "swe-bench-live": "research",
}
_ADAPTER_MODE = {
    "terminal-bench-2": "native-json",
    "pysfmea-semantic-corpus": "direct",
    "pysfmea-causal-propagation": "direct",
    "pysfmea-modern-python-dynamics": "direct",
    "pysfmea-distributed-resilience": "direct",
    "pysfmea-interoperability-conformance": "direct",
    "pysfmea-longitudinal-drift": "direct",
    "pysfmea-mutation-proficiency": "direct",
    "pysfmea-fuzz-ground-truth": "direct",
    "pysfmea-framework-negative-controls": "direct",
    "pysfmea-python-platform-matrix": "direct",
    "pysfmea-temporal-hidden-holdout": "direct",
    "pysfmea-cross-organization-proficiency": "direct",
    "pysfmea-dual-mutation-engine-qualification": "direct",
    "pysfmea-scale-resource-exhaustion": "direct",
    "pysfmea-nondeterminism-concurrency": "direct",
    "owasp-benchmark-python": "native-csv",
    "testgeneval": "native-json",
    "tdd-bench-verified": "native-jsonl",
    "swe-bench-verified": "native-jsonl",
    "cyberseceval-4": "contract-only",
    "crosscodeeval-python": "contract-only",
    "crosscodelongeval-python": "contract-only",
    "agentdojo": "native-json",
    "swe-polybench-verified-python": "native-json",
    "idoft-python": "native-csv",
    "swe-bench-live": "native-json",
}

MAX_QUALIFICATION_BYTES = 20_000_000_000


def _local_digest(source: str | Path) -> tuple[Path, str]:
    path = Path(source).expanduser().resolve()
    if path.is_symlink() or not path.exists():
        raise ValueError("qualification evidence must be an existing non-symbolic path")
    if path.is_dir():
        from .campaign_runner import repository_snapshot_sha256

        return path, repository_snapshot_sha256(path)
    if not path.is_file():
        raise ValueError("qualification evidence must be a regular file or directory")
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > MAX_QUALIFICATION_BYTES:
                raise ValueError(
                    "qualification evidence exceeds the governed byte limit"
                )
            digest.update(chunk)
    return path, digest.hexdigest()


def qualify_benchmark_source(
    ledger: dict[str, Any],
    *,
    suite_id: str,
    snapshot: str | Path,
    observed_revision: str,
    observed_url: str,
    license_id: str,
    license_evidence: str | Path,
    schema_version: str,
    reviewer: str,
    next_review_at: str,
    notes: str = "",
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Bind one suite to locally observed bytes and detached review evidence.

    This intentionally performs no network acquisition and never assigns a reviewer.
    The caller must lawfully acquire the source and identify a real independent reviewer.
    """

    checked = copy.deepcopy(ledger)
    checked.pop("content_sha256", None)
    if not _structure(seal(checked)):
        raise ValueError("benchmark source-health ledger is not catalog-bound")
    authority = bounded_text(checked.get("authority"), "benchmark source authority")
    reviewer_value = bounded_text(reviewer, "benchmark source reviewer")
    if reviewer_value == authority or reviewer_value == "unassigned":
        raise ValueError("benchmark source reviewer must be assigned and independent")
    source_path, source_sha256 = _local_digest(snapshot)
    license_path, license_sha256 = _local_digest(license_evidence)
    observed = observed_at or utc_now()
    if _date(observed) is None or _date(next_review_at) is None:
        raise ValueError("observed and next-review timestamps must be timezone-aware")
    if _date(next_review_at) <= _date(observed):  # type: ignore[operator]
        raise ValueError("next review must occur after the source observation")
    matching = [item for item in checked["sources"] if item["suite_id"] == suite_id]
    if len(matching) != 1:
        raise ValueError("unknown governed benchmark suite")
    item = matching[0]
    if observed_url != item["canonical_url"]:
        raise ValueError("observed URL must match the catalog canonical URL")
    item.update(
        {
            "observed_url": observed_url,
            "observed_revision": bounded_text(observed_revision, "observed revision"),
            "observed_at": observed,
            "next_review_at": next_review_at,
            "status": "verified",
            "license_id": bounded_text(license_id, "license id"),
            "license_evidence_ref": f"{license_path}#sha256={license_sha256}",
            "snapshot_sha256": source_sha256,
            "schema_version": bounded_text(schema_version, "source schema version"),
            "source_evidence_ref": f"{source_path}#sha256={source_sha256}",
            "reviewer": reviewer_value,
            "notes": bounded_text(
                notes, "source qualification notes", allow_empty=True
            ),
        }
    )
    checked["summary"] = _summary(checked["sources"])
    result = seal(checked)
    if not verify_benchmark_source_health(result)["valid"]:
        raise ValueError("qualified benchmark source ledger failed verification")
    return result


def benchmark_source_health_template(*, authority: str) -> dict[str, Any]:
    sources = [
        {
            "suite_id": suite["id"],
            "canonical_url": suite["source_url"],
            "observed_url": "unassigned",
            "observed_revision": "unassigned",
            "observed_at": "unassigned",
            "next_review_at": "unassigned",
            "status": "unreviewed",
            "maturity": _MATURITY.get(suite["id"], "research"),
            "adapter_mode": _ADAPTER_MODE.get(suite["id"], "contract-only"),
            "license_id": "unassigned",
            "license_evidence_ref": "unassigned",
            "snapshot_sha256": "0" * 64,
            "schema_version": "unassigned",
            "source_evidence_ref": "unassigned",
            "reviewer": "unassigned",
            "notes": "",
        }
        for suite in BENCHMARK_SUITES
    ]
    return seal(
        {
            "format": BENCHMARK_SOURCE_HEALTH_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "benchmark source-health authority"),
            "sources": sources,
            "summary": _summary(sources),
            "claim_boundary": "This ledger records reviewed source identity, revision, license evidence, maturity, and normalization capability. It does not fetch sources, grant redistribution rights, validate labels, or establish benchmark representativeness.",
        }
    )


def _summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    verified = sum(item.get("status") == "verified" for item in sources)
    native = sum(
        item.get("adapter_mode", "contract-only") != "contract-only" for item in sources
    )
    complete = sum(_complete(item) for item in sources)
    return {
        "sources": len(sources),
        "verified": verified,
        "complete": complete,
        "native_or_direct_adapters": native,
        "contract_only_adapters": len(sources) - native,
    }


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value))
        and value != "0" * 64
    )


def _date(value: Any) -> datetime | None:
    if not isinstance(value, str) or value == "unassigned":
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _complete(item: dict[str, Any]) -> bool:
    observed = _date(item.get("observed_at"))
    next_review = _date(item.get("next_review_at"))
    return bool(
        item.get("status") == "verified"
        and item.get("observed_url") == item.get("canonical_url")
        and item.get("observed_revision") != "unassigned"
        and observed is not None
        and next_review is not None
        and next_review > observed
        and item.get("license_id") != "unassigned"
        and item.get("license_evidence_ref") != "unassigned"
        and _digest(item.get("snapshot_sha256"))
        and item.get("schema_version") != "unassigned"
        and item.get("source_evidence_ref") != "unassigned"
        and item.get("reviewer") != "unassigned"
    )


def _structure(value: dict[str, Any]) -> bool:
    try:
        expected = {item["id"]: item["source_url"] for item in BENCHMARK_SUITES}
        sources = value["sources"]
        fields = {
            "suite_id",
            "canonical_url",
            "observed_url",
            "observed_revision",
            "observed_at",
            "next_review_at",
            "status",
            "maturity",
            "adapter_mode",
            "license_id",
            "license_evidence_ref",
            "snapshot_sha256",
            "schema_version",
            "source_evidence_ref",
            "reviewer",
            "notes",
        }
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "sources",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and isinstance(sources, list)
            and len(sources) == len(expected)
            and {item.get("suite_id") for item in sources} == set(expected)
            and all(
                isinstance(item, dict)
                and set(item) == fields
                and item["canonical_url"] == expected[item["suite_id"]]
                and item["status"] in STATUSES
                and item["maturity"] in MATURITY
                and item["adapter_mode"]
                in {
                    "direct",
                    "native-csv",
                    "native-json",
                    "native-jsonl",
                    "contract-only",
                }
                and isinstance(item["notes"], str)
                and len(item["notes"]) <= 20_000
                for item in sources
            )
            and value["summary"] == _summary(sources)
        )
    except (KeyError, TypeError):
        return False


def verify_benchmark_source_health(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark source health",
            format_value=BENCHMARK_SOURCE_HEALTH_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("benchmark source-health structure or catalog binding is invalid")
    complete = bool(
        structure
        and checked["summary"]["complete"] == checked["summary"]["sources"]
        and all(item["reviewer"] != checked["authority"] for item in checked["sources"])
    )
    if structure and not complete:
        errors.append(
            "one or more benchmark sources lack reviewed immutable provenance"
        )
    return seal(
        {
            "format": BENCHMARK_SOURCE_HEALTH_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "eligible_for_external_execution": integrity and structure and complete,
            "checks": {
                "content_integrity": integrity,
                "closed_catalog_binding": structure,
                "all_sources_reviewed_and_pinned": complete,
            },
            "errors": errors,
            "notice": "Execution eligibility requires every source to be reviewed and pinned; it is not an accuracy or certification conclusion.",
        }
    )


def seal_benchmark_source_health(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="benchmark source health")
    value.pop("content_sha256", None)
    value["summary"] = _summary(value.get("sources", []))
    result = seal(value)
    if not verify_benchmark_source_health(result)["valid"]:
        raise ValueError("benchmark source-health source is invalid")
    return publish_json(result, destination)


def export_benchmark_source_health(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_benchmark_source_health(value)["valid"]:
        raise ValueError("benchmark source-health artifact is invalid")
    return publish_json(value, destination)


def verify_benchmark_source_health_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_benchmark_source_health(
            load_json(source, label="benchmark source health")
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_SOURCE_HEALTH_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_external_execution": False,
                "checks": {
                    "content_integrity": False,
                    "closed_catalog_binding": False,
                    "all_sources_reviewed_and_pinned": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark source-health verification failed closed.",
            }
        )
