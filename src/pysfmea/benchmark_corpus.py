"""Content-addressed inventory for bundled benchmark corpora and protocols."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .integrity import canonical_json_sha256
from .model import utc_now

BENCHMARK_CORPUS_INVENTORY_FORMAT = "pysfmea-benchmark-corpus-inventory-1"
BENCHMARK_CORPUS_VERIFICATION_FORMAT = "pysfmea-benchmark-corpus-verification-1"
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024

INTERNAL_CORPORA = {
    "pysfmea-semantic-corpus": "python_sfmea_corpus",
    "pysfmea-causal-propagation": "causal_propagation_corpus",
    "pysfmea-modern-python-dynamics": "dynamic_python_corpus",
    "pysfmea-distributed-resilience": "distributed_resilience_corpus",
    "pysfmea-interoperability-conformance": "interoperability_conformance_corpus",
    "pysfmea-longitudinal-drift": "longitudinal_drift_corpus",
    "pysfmea-mutation-proficiency": "mutation_proficiency_corpus",
    "pysfmea-fuzz-ground-truth": "fuzz_ground_truth_corpus",
    "pysfmea-framework-negative-controls": "framework_negative_controls",
    "pysfmea-python-platform-matrix": "python_platform_matrix",
    "pysfmea-temporal-hidden-holdout": "temporal_holdout_protocol",
    "pysfmea-cross-organization-proficiency": "proficiency_scheme",
    "pysfmea-dual-mutation-engine-qualification": "dual_mutation_corpus",
    "pysfmea-scale-resource-exhaustion": "scale_resource_corpus",
    "pysfmea-nondeterminism-concurrency": "nondeterminism_concurrency_corpus",
}


def benchmark_corpus_inventory(
    root: str | Path, *, authority: str, generated_at: str | None = None
) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir() or base.is_symlink():
        raise ValueError("benchmark corpus root must be a regular directory")
    corpora: list[dict[str, Any]] = []
    total_bytes = 0
    for suite_id, relative in INTERNAL_CORPORA.items():
        directory = (base / relative).resolve()
        try:
            directory.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"benchmark corpus escapes root: {relative}") from exc
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"benchmark corpus is missing or linked: {relative}")
        files: list[dict[str, Any]] = []
        for path in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_dir():
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(
                    f"benchmark corpus contains a non-regular file: {path}"
                )
            data = path.read_bytes()
            if len(data) > MAX_FILE_BYTES:
                raise ValueError(
                    f"benchmark corpus file exceeds {MAX_FILE_BYTES} bytes: {path}"
                )
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError(
                    "benchmark corpus aggregate exceeds governed byte limit"
                )
            files.append(
                {
                    "path": path.relative_to(base).as_posix(),
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        if not files or not any(item["path"].endswith("README.md") for item in files):
            raise ValueError(
                f"benchmark corpus must contain files and README.md: {relative}"
            )
        corpora.append(
            {
                "suite_id": suite_id,
                "path": relative,
                "files": files,
                "tree_sha256": canonical_json_sha256(files),
            }
        )
    result = {
        "format": BENCHMARK_CORPUS_INVENTORY_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": bounded_text(authority, "benchmark corpus authority"),
        "root": str(base),
        "corpora": corpora,
        "summary": {
            "corpora": len(corpora),
            "files": sum(len(item["files"]) for item in corpora),
            "bytes": total_bytes,
        },
        "claim_boundary": (
            "This inventory proves the exact bundled file population and bytes only. "
            "It does not validate labels, representativeness, independence, or fitness for use."
        ),
    }
    return seal(result)


def _structure(value: dict[str, Any]) -> bool:
    try:
        corpora = value["corpora"]
        files = [file for corpus in corpora for file in corpus["files"]]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "root",
                "corpora",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and len(corpora) == len(INTERNAL_CORPORA)
            and {item["suite_id"]: item["path"] for item in corpora} == INTERNAL_CORPORA
            and all(
                isinstance(item, dict)
                and set(item) == {"suite_id", "path", "files", "tree_sha256"}
                and item["tree_sha256"] == canonical_json_sha256(item["files"])
                and bool(item["files"])
                for item in corpora
            )
            and all(
                isinstance(item, dict)
                and set(item) == {"path", "bytes", "sha256"}
                and isinstance(item["path"], str)
                and isinstance(item["bytes"], int)
                and not isinstance(item["bytes"], bool)
                and 0 <= item["bytes"] <= MAX_FILE_BYTES
                and isinstance(item["sha256"], str)
                and len(item["sha256"]) == 64
                for item in files
            )
            and value["summary"]
            == {
                "corpora": len(corpora),
                "files": len(files),
                "bytes": sum(item["bytes"] for item in files),
            }
        )
    except (KeyError, TypeError):
        return False


def verify_benchmark_corpus_inventory(
    value: dict[str, Any], *, root: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark corpus inventory",
            format_value=BENCHMARK_CORPUS_INVENTORY_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("benchmark corpus inventory structure is invalid")
    replay: bool | None = None
    if root is not None:
        try:
            replay = (
                benchmark_corpus_inventory(
                    root,
                    authority=checked["authority"],
                    generated_at=checked["generated_at"],
                )
                == value
            )
        except (KeyError, OSError, TypeError, ValueError):
            replay = False
        if not replay:
            errors.append(
                "benchmark corpus inventory does not exactly replay from root"
            )
    valid = integrity and structure and replay is not False
    return seal(
        {
            "format": BENCHMARK_CORPUS_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_as_corpus_identity_evidence": valid and replay is True,
            "checks": {
                "content_integrity": integrity,
                "closed_structure": structure,
                "exact_root_replay": replay,
            },
            "errors": errors,
            "notice": "Corpus identity evidence does not establish ground-truth correctness or representativeness.",
        }
    )


def export_benchmark_corpus_inventory(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_benchmark_corpus_inventory(value)["valid"]:
        raise ValueError("benchmark corpus inventory is invalid")
    return publish_json(value, destination)


def verify_benchmark_corpus_inventory_file(
    source: str | Path, *, root: str | Path | None = None
) -> dict[str, Any]:
    try:
        return verify_benchmark_corpus_inventory(
            load_json(source, label="benchmark corpus inventory"), root=root
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": BENCHMARK_CORPUS_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_as_corpus_identity_evidence": False,
                "checks": {
                    "content_integrity": False,
                    "closed_structure": False,
                    "exact_root_replay": False,
                },
                "errors": [str(exc)],
                "notice": "Benchmark corpus inventory verification failed closed.",
            }
        )
