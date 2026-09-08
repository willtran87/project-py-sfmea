"""Content-addressed intake for downloaded ClusterFuzzLite CI artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .integrity import canonical_json_sha256
from .model import utc_now

CLUSTERFUZZ_INTAKE_FORMAT = "pysfmea-clusterfuzzlite-intake-1"
CLUSTERFUZZ_INTAKE_VERIFICATION_FORMAT = "pysfmea-clusterfuzzlite-intake-verification-1"
MODES = {"code-change", "batch", "prune", "coverage", "build"}
MAX_FILES = 500_000
MAX_FILE_BYTES = 2_000_000_000


def _file_digest(path: Path) -> tuple[str, int]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(
            f"ClusterFuzzLite artifact exceeds the {MAX_FILE_BYTES}-byte per-file limit: {path}"
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), size


def _kind(relative: str) -> str:
    lowered = relative.lower()
    if lowered.endswith(".sarif") or lowered.endswith(".sarif.json"):
        return "sarif"
    if "crash" in lowered or "/artifacts/" in f"/{lowered}":
        return "crash"
    if "coverage" in lowered or lowered.endswith((".profdata", ".profraw", ".lcov")):
        return "coverage"
    if "/corpus/" in f"/{lowered}" or lowered.startswith("corpus/"):
        return "corpus"
    if "build" in lowered or lowered.endswith((".whl", ".tar.gz")):
        return "build"
    if lowered.endswith((".log", ".txt")):
        return "log"
    return "other"


def _sarif_results(path: Path) -> int | None:
    if path.stat().st_size > 100_000_000:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return sum(
            len(run.get("results", []))
            for run in value.get("runs", [])
            if isinstance(run, dict) and isinstance(run.get("results", []), list)
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        AttributeError,
        TypeError,
    ):
        return None


def _inventory(root: Path) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise ValueError(f"ClusterFuzzLite artifact root is not a directory: {root}")
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not files or len(files) > MAX_FILES:
        raise ValueError(
            f"ClusterFuzzLite artifact population must contain 1..{MAX_FILES} files"
        )
    result: list[dict[str, Any]] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest, size = _file_digest(path)
        kind = _kind(relative)
        result.append(
            {
                "path": relative,
                "sha256": digest,
                "bytes": size,
                "kind": kind,
                "sarif_results": _sarif_results(path) if kind == "sarif" else None,
            }
        )
    return result


def import_clusterfuzzlite_intake(
    artifact_root: str | Path,
    *,
    authority: str,
    repository: str,
    revision: str,
    run_id: str,
    run_attempt: int,
    workflow: str,
    job: str,
    event: str,
    mode: str,
    sanitizer: str,
    action_sha: str,
    run_url: str,
) -> dict[str, Any]:
    if (
        mode not in MODES
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
    ):
        raise ValueError("ClusterFuzzLite mode or run attempt is invalid")
    manifest = _inventory(Path(artifact_root).resolve())
    kinds = {
        name: sum(item["kind"] == name for item in manifest)
        for name in ("sarif", "crash", "coverage", "corpus", "build", "log", "other")
    }
    result = seal(
        {
            "format": CLUSTERFUZZ_INTAKE_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "ClusterFuzzLite intake authority"),
            "run": {
                "repository": bounded_text(repository, "ClusterFuzzLite repository"),
                "revision": bounded_text(revision, "ClusterFuzzLite revision"),
                "run_id": bounded_text(run_id, "ClusterFuzzLite run id"),
                "run_attempt": run_attempt,
                "workflow": bounded_text(workflow, "ClusterFuzzLite workflow"),
                "job": bounded_text(job, "ClusterFuzzLite job"),
                "event": bounded_text(event, "ClusterFuzzLite event"),
                "mode": mode,
                "sanitizer": bounded_text(sanitizer, "ClusterFuzzLite sanitizer"),
                "action_sha": bounded_text(action_sha, "ClusterFuzzLite action SHA"),
                "run_url": bounded_text(run_url, "ClusterFuzzLite run URL"),
            },
            "artifact_set": {
                "tree_sha256": canonical_json_sha256(manifest),
                "files": len(manifest),
                "bytes": sum(item["bytes"] for item in manifest),
                "kinds": kinds,
                "sarif_results": sum(item["sarif_results"] or 0 for item in manifest),
            },
            "manifest": manifest,
            "campaign_projection": {
                "engine": "clusterfuzzlite",
                "repository_revision": revision,
                "evidence_ref": run_url,
                "evidence_sha256": canonical_json_sha256(manifest),
                "coverage_present": kinds["coverage"] > 0,
                "crash_material_present": kinds["crash"] > 0 or kinds["sarif"] > 0,
                "requires_operator_completion": True,
            },
            "claim_boundary": "This receipt inventories downloaded ClusterFuzzLite artifacts and CI identity exactly. It does not infer execution counts, corpus quality, crash reproducibility, coverage adequacy, or campaign completion; project those only after governed operator review.",
        }
    )
    if not verify_clusterfuzzlite_intake(result)["valid"]:
        raise ValueError("ClusterFuzzLite intake failed internal verification")
    return result


def verify_clusterfuzzlite_intake(
    value: dict[str, Any], *, artifact_root: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    integrity = structure = reconciliation = source_binding = False
    try:
        checked = verify_seal(
            value,
            label="ClusterFuzzLite intake",
            format_value=CLUSTERFUZZ_INTAKE_FORMAT,
        )
        required = {
            "format",
            "generated_at",
            "authority",
            "run",
            "artifact_set",
            "manifest",
            "campaign_projection",
            "claim_boundary",
            "content_sha256",
        }
        run_fields = {
            "repository",
            "revision",
            "run_id",
            "run_attempt",
            "workflow",
            "job",
            "event",
            "mode",
            "sanitizer",
            "action_sha",
            "run_url",
        }
        if (
            set(checked) != required
            or not isinstance(checked["run"], dict)
            or set(checked["run"]) != run_fields
            or checked["run"]["mode"] not in MODES
            or not isinstance(checked["manifest"], list)
            or not checked["manifest"]
            or len(checked["manifest"]) > MAX_FILES
        ):
            raise ValueError("ClusterFuzzLite intake fields are invalid")
        paths: list[str] = []
        for item in checked["manifest"]:
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "sha256", "bytes", "kind", "sarif_results"}
                or item["kind"]
                not in {"sarif", "crash", "coverage", "corpus", "build", "log", "other"}
                or not isinstance(item["path"], str)
                or not isinstance(item["sha256"], str)
                or len(item["sha256"]) != 64
                or not isinstance(item["bytes"], int)
                or isinstance(item["bytes"], bool)
                or item["bytes"] < 0
            ):
                raise ValueError("ClusterFuzzLite manifest entry is invalid")
            paths.append(item["path"])
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("ClusterFuzzLite manifest paths are not unique and sorted")
        kinds = {
            name: sum(item["kind"] == name for item in checked["manifest"])
            for name in (
                "sarif",
                "crash",
                "coverage",
                "corpus",
                "build",
                "log",
                "other",
            )
        }
        expected_set = {
            "tree_sha256": canonical_json_sha256(checked["manifest"]),
            "files": len(checked["manifest"]),
            "bytes": sum(item["bytes"] for item in checked["manifest"]),
            "kinds": kinds,
            "sarif_results": sum(
                item["sarif_results"] or 0 for item in checked["manifest"]
            ),
        }
        expected_projection = {
            "engine": "clusterfuzzlite",
            "repository_revision": checked["run"]["revision"],
            "evidence_ref": checked["run"]["run_url"],
            "evidence_sha256": expected_set["tree_sha256"],
            "coverage_present": kinds["coverage"] > 0,
            "crash_material_present": kinds["crash"] > 0 or kinds["sarif"] > 0,
            "requires_operator_completion": True,
        }
        reconciliation = (
            checked["artifact_set"] == expected_set
            and checked["campaign_projection"] == expected_projection
        )
        if not reconciliation:
            errors.append(
                "ClusterFuzzLite artifact summary or campaign projection does not reconcile"
            )
        source_binding = artifact_root is None or checked["manifest"] == _inventory(
            Path(artifact_root).resolve()
        )
        if not source_binding:
            errors.append(
                "ClusterFuzzLite intake does not bind the supplied artifact directory"
            )
        integrity = structure = True
    except (OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    valid = integrity and structure and reconciliation and source_binding and not errors
    return seal(
        {
            "format": CLUSTERFUZZ_INTAKE_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_campaign_input": valid,
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "manifest_reconciliation": reconciliation,
                "artifact_directory_binding": source_binding,
            },
            "errors": errors,
            "notice": "Eligibility means exact intake evidence is suitable for governed operator review, not that a fuzz campaign is complete or adequate.",
        }
    )


def export_clusterfuzzlite_intake(
    value: dict[str, Any], destination: str | Path
) -> Path:
    return publish_json(value, destination)


def verify_clusterfuzzlite_intake_file(
    source: str | Path, *, artifact_root: str | Path | None = None
) -> dict[str, Any]:
    try:
        return verify_clusterfuzzlite_intake(
            load_json(source, label="ClusterFuzzLite intake"),
            artifact_root=artifact_root,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": CLUSTERFUZZ_INTAKE_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_campaign_input": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "manifest_reconciliation": False,
                    "artifact_directory_binding": False,
                },
                "errors": [str(exc)],
                "notice": "ClusterFuzzLite intake verification failed closed.",
            }
        )
