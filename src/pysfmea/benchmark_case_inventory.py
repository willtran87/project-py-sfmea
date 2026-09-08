"""Exact-source benchmark case inventories for suites without native result adapters."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_json_document
from .model import utc_now

BENCHMARK_CASE_INVENTORY_FORMAT = "pysfmea-benchmark-case-inventory-1"
BENCHMARK_CASE_INVENTORY_VERIFICATION_FORMAT = (
    "pysfmea-benchmark-case-inventory-verification-1"
)
MAX_BYTES = 500 * 1024 * 1024
MAX_CASES = 1_000_000


def _case(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        return {
            "case_id": bounded_text(value, "benchmark case id"),
            "evidence_refs": [],
        }
    if not isinstance(value, dict):
        raise ValueError("benchmark inventory cases must be strings or objects")
    identifier = value.get("case_id", value.get("id", value.get("instance_id")))
    refs = value.get("evidence_refs", [])
    if (
        not isinstance(refs, list)
        or len(refs) > 100
        or not all(isinstance(item, str) and item.strip() for item in refs)
    ):
        raise ValueError("benchmark case evidence references are invalid")
    return {
        "case_id": bounded_text(identifier, "benchmark case id"),
        "evidence_refs": list(dict.fromkeys(item.strip() for item in refs)),
    }


def benchmark_case_inventory(
    source: str | Path,
    *,
    suite_id: str,
    suite_revision: str,
    authority: str,
    adapter_mode: str = "governed-inventory",
    population_basis: str,
) -> dict[str, Any]:
    """Create a reviewable case population without guessing a suite result schema."""

    document = load_bounded_json_document(
        Path(source).expanduser().resolve(),
        label="benchmark case manifest",
        max_bytes=MAX_BYTES,
        max_depth=160,
        max_nodes=3_000_000,
    )
    raw_cases = (
        document.value.get("cases")
        if isinstance(document.value, dict)
        else document.value
    )
    if not isinstance(raw_cases, list) or not 0 < len(raw_cases) <= MAX_CASES:
        raise ValueError(
            "benchmark case manifest requires a bounded non-empty population"
        )
    cases = [_case(item) for item in raw_cases]
    if len({item["case_id"] for item in cases}) != len(cases):
        raise ValueError("benchmark case inventory ids must be unique")
    result = seal(
        {
            "format": BENCHMARK_CASE_INVENTORY_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "benchmark inventory authority"),
            "suite": {
                "id": bounded_text(suite_id, "benchmark suite id"),
                "revision": bounded_text(suite_revision, "benchmark suite revision"),
                "adapter_mode": bounded_text(adapter_mode, "benchmark adapter mode"),
            },
            "population_basis": bounded_text(
                population_basis, "benchmark population basis"
            ),
            "source": {
                "name": Path(source).name,
                "bytes": document.size,
                "sha256": hashlib.sha256(document.raw).hexdigest(),
            },
            "cases": cases,
            "summary": {
                "cases": len(cases),
                "cases_with_evidence": sum(
                    bool(item["evidence_refs"]) for item in cases
                ),
            },
            "claim_boundary": (
                "This inventory proves exact case-population identity for item review. It does "
                "not interpret suite results, validate labels, establish representativeness, "
                "or prove benchmark execution."
            ),
        }
    )
    if not verify_benchmark_case_inventory(result)["valid"]:
        raise ValueError("benchmark case inventory failed internal verification")
    return result


def _structure(value: dict[str, Any]) -> bool:
    try:
        cases = value["cases"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "suite",
                "population_basis",
                "source",
                "cases",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(value["suite"]) == {"id", "revision", "adapter_mode"}
            and all(
                isinstance(item, str) and bool(item) for item in value["suite"].values()
            )
            and isinstance(value["authority"], str)
            and bool(value["authority"])
            and isinstance(value["population_basis"], str)
            and bool(value["population_basis"])
            and set(value["source"]) == {"name", "bytes", "sha256"}
            and isinstance(value["source"]["name"], str)
            and bool(value["source"]["name"])
            and isinstance(value["source"]["bytes"], int)
            and not isinstance(value["source"]["bytes"], bool)
            and value["source"]["bytes"] > 0
            and isinstance(value["source"]["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["source"]["sha256"]) is not None
            and isinstance(cases, list)
            and 0 < len(cases) <= MAX_CASES
            and len({item.get("case_id") for item in cases}) == len(cases)
            and all(
                isinstance(item, dict)
                and set(item) == {"case_id", "evidence_refs"}
                and isinstance(item["case_id"], str)
                and bool(item["case_id"])
                and isinstance(item["evidence_refs"], list)
                and all(
                    isinstance(ref, str) and bool(ref) for ref in item["evidence_refs"]
                )
                for item in cases
            )
            and value["summary"]
            == {
                "cases": len(cases),
                "cases_with_evidence": sum(
                    bool(item["evidence_refs"]) for item in cases
                ),
            }
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"])
        )
    except (KeyError, TypeError):
        return False


def verify_benchmark_case_inventory(
    value: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark case inventory",
            format_value=BENCHMARK_CASE_INVENTORY_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("benchmark case inventory fields do not reconcile")
    exact_source_replay: bool | None = None
    if source is not None:
        try:
            regenerated = benchmark_case_inventory(
                source,
                suite_id=checked["suite"]["id"],
                suite_revision=checked["suite"]["revision"],
                authority=checked["authority"],
                adapter_mode=checked["suite"]["adapter_mode"],
                population_basis=checked["population_basis"],
            )
            exact_source_replay = all(
                regenerated[field] == checked[field]
                for field in ("suite", "population_basis", "source", "cases", "summary")
            )
            if not exact_source_replay:
                errors.append(
                    "benchmark case inventory does not replay from the supplied manifest"
                )
        except (KeyError, TypeError, ValueError) as exc:
            exact_source_replay = False
            errors.append(f"benchmark case manifest replay failed: {exc}")
    return seal(
        {
            "format": BENCHMARK_CASE_INVENTORY_VERIFICATION_FORMAT,
            "valid": integrity and structure and exact_source_replay is not False,
            "eligible_for_item_review": (
                integrity and structure and exact_source_replay is not False
            ),
            "checks": {
                "content_integrity": integrity,
                "closed_population": structure,
                "exact_source_replay": exact_source_replay,
            },
            "errors": errors,
            "notice": "Eligibility permits exact-population item review, not a benchmark claim.",
        }
    )


def export_benchmark_case_inventory(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_benchmark_case_inventory(value)["valid"]:
        raise ValueError("benchmark case inventory is invalid")
    return publish_json(value, destination)


def verify_benchmark_case_inventory_file(
    artifact: str | Path, *, source: str | Path | None = None
) -> dict[str, Any]:
    value = load_bounded_json_document(
        Path(artifact).expanduser().resolve(),
        label="benchmark case inventory",
        max_bytes=MAX_BYTES,
        max_depth=160,
        max_nodes=3_000_000,
    ).value
    if not isinstance(value, dict):
        raise ValueError("benchmark case inventory must be a JSON object")
    return verify_benchmark_case_inventory(value, source=source)
