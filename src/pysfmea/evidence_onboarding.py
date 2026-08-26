"""Transactional orchestration for already-produced repository evidence."""

from __future__ import annotations

import copy
import hashlib
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .assurance import (
    assurance_summary,
    assurance_work_queue,
    verify_assurance_work_queue,
)
from .diagnostics import analysis_diagnostics
from .enhancements import evidence_preflight
from .execution import import_execution_evidence
from .integrity import canonical_json_sha256, verify_run_manifest_integrity
from .json_ingestion import load_bounded_file_snapshot, load_bounded_json_file
from .manifest import create_run_manifest
from .model import stable_id, utc_now
from .runtime import import_runtime_trace
from .scanner import import_coverage_evidence
from .store import refresh_summary
from .version import __version__

EVIDENCE_ONBOARDING_RECEIPT_FORMAT = "pysfmea-evidence-onboarding-receipt-1"
MAX_SELECTED_EVIDENCE = 100
MAX_SELECTED_EVIDENCE_BYTES = 100_000_000
MAX_EVIDENCE_LABEL = 500
MAX_ONBOARDING_RECEIPT_BYTES = 100_000_000
MAX_ONBOARDING_RECEIPT_JSON_DEPTH = 100
MAX_ONBOARDING_RECEIPT_JSON_NODES = 1_000_000


def _result_projection(kind: str, imported: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "coverage": (
            "id",
            "sha256",
            "duplicate",
            "components",
            "files",
            "imported_at",
            "baseline_id",
            "notice",
        ),
        "runtime_trace": (
            "id",
            "sha256",
            "duplicate",
            "span_count",
            "new_span_count",
            "mapped_span_count",
            "unmapped_span_count",
            "mapping_methods",
            "timing_statuses",
            "instrumentation",
            "baseline_id",
            "notice",
        ),
        "execution_manifest": (
            "id",
            "obligation_id",
            "finding_id",
            "baseline_id",
            "status",
            "execution_mode",
            "import_trust",
            "test",
            "command_argv",
            "source_manifest_sha256",
        ),
    }[kind]
    projected = {key: copy.deepcopy(imported[key]) for key in fields if key in imported}
    if kind == "execution_manifest":
        artifacts = imported.get("artifacts", [])
        projected["artifact_count"] = len(artifacts) if isinstance(artifacts, list) else 0
    return projected


def _repository(analysis: dict[str, Any], repository: str | Path) -> Path:
    supplied = Path(repository).expanduser().absolute()
    recorded = Path(str(analysis.get("project", {}).get("root", ""))).expanduser()
    if not recorded.is_absolute():
        recorded = recorded.absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise ValueError("evidence-onboarding repository must be a regular directory")
    try:
        supplied_resolved = supplied.resolve(strict=True)
        recorded_resolved = recorded.resolve(strict=True)
    except OSError as exc:
        raise ValueError("analysis repository root could not be resolved") from exc
    if supplied_resolved != recorded_resolved:
        raise ValueError(
            "evidence-onboarding repository differs from the analysis root"
        )
    return supplied_resolved


def _snapshot(
    kind: str, source: str | Path, *, subject_id: str = "", label: str = ""
) -> dict[str, Any]:
    captured = load_bounded_file_snapshot(
        source,
        label=f"selected {kind} evidence",
        max_bytes=MAX_SELECTED_EVIDENCE_BYTES,
    )
    return {
        "kind": kind,
        "subject_id": subject_id,
        "label": label,
        "path": str(captured.path),
        "bytes": captured.size,
        "sha256": hashlib.sha256(captured.raw).hexdigest(),
    }


def _selected_inputs(
    preflight: dict[str, Any],
    *,
    coverage_json: str | Path | None,
    use_discovered_coverage: bool,
    runtime_traces: Iterable[tuple[str | Path, str]],
    execution_manifests: Iterable[tuple[str, str | Path]],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    coverage = coverage_json
    if coverage is None and use_discovered_coverage:
        discovered = preflight.get("discovery", {}).get("coverage", {})
        if discovered.get("status") == "ready":
            coverage = str(discovered.get("path", ""))
    if coverage is not None:
        selected.append(_snapshot("coverage", coverage))

    seen_traces: set[tuple[str, str]] = set()
    for source, raw_label in runtime_traces:
        label = raw_label.strip()
        if len(label) > MAX_EVIDENCE_LABEL or any(ord(value) < 32 for value in label):
            raise ValueError(
                "runtime trace label must be at most 500 printable characters"
            )
        value = _snapshot("runtime_trace", source, label=label)
        key = (str(value["path"]).casefold(), label)
        if key in seen_traces:
            raise ValueError("runtime trace selection is duplicated")
        seen_traces.add(key)
        selected.append(value)

    seen_obligations: set[str] = set()
    for obligation_id, source in execution_manifests:
        normalized = obligation_id.strip()
        if not normalized:
            raise ValueError("execution evidence requires an obligation ID")
        if normalized in seen_obligations:
            raise ValueError(
                f"execution evidence obligation is selected more than once: {normalized}"
            )
        seen_obligations.add(normalized)
        selected.append(_snapshot("execution_manifest", source, subject_id=normalized))

    if len(selected) > MAX_SELECTED_EVIDENCE:
        raise ValueError(
            f"evidence onboarding exceeds the {MAX_SELECTED_EVIDENCE}-artifact limit"
        )
    identities = [
        (value["kind"], value["subject_id"], value["sha256"]) for value in selected
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("selected evidence contains an exact duplicate")
    return selected


def _apply_selected(
    analysis: dict[str, Any],
    selected: list[dict[str, Any]],
    *,
    initiated_by: str,
    evidence_root: Path,
) -> list[dict[str, Any]]:
    if any(value["kind"] == "execution_manifest" for value in selected):
        if not initiated_by.strip():
            raise ValueError("--initiated-by is required for execution evidence")
    results: list[dict[str, Any]] = []
    created_directories: list[Path] = []
    try:
        for value in selected:
            kind = str(value["kind"])
            before_executions = len(
                analysis.get("assurance", {}).get("executions", [])
                if isinstance(analysis.get("assurance"), dict)
                else []
            )
            if kind == "coverage":
                imported = import_coverage_evidence(analysis, str(value["path"]))
            elif kind == "runtime_trace":
                imported = import_runtime_trace(
                    analysis, str(value["path"]), label=str(value["label"])
                )
            elif kind == "execution_manifest":
                imported = import_execution_evidence(
                    analysis,
                    str(value["subject_id"]),
                    manifest_path=str(value["path"]),
                    evidence_root=evidence_root,
                    initiated_by=initiated_by,
                )
            else:  # pragma: no cover - closed construction above
                raise RuntimeError(f"unsupported evidence kind: {kind}")
            after_executions = len(
                analysis.get("assurance", {}).get("executions", [])
                if isinstance(analysis.get("assurance"), dict)
                else []
            )
            duplicate = bool(imported.get("duplicate")) or (
                kind == "execution_manifest" and after_executions == before_executions
            )
            if kind == "execution_manifest" and not duplicate:
                directory = Path(str(imported.get("evidence_directory", ""))).resolve()
                try:
                    directory.relative_to(evidence_root.resolve())
                except ValueError as exc:  # pragma: no cover - importer owns this invariant
                    raise RuntimeError("imported evidence escaped its managed root") from exc
                created_directories.append(directory)
            results.append(
                {
                    **value,
                    "status": "duplicate" if duplicate else "imported",
                    "record_id": str(imported.get("id", "")),
                    "result": _result_projection(kind, imported),
                }
            )
    except Exception:
        for directory in reversed(created_directories):
            shutil.rmtree(directory, ignore_errors=True)
        raise
    return results


def onboard_evidence(
    analysis: dict[str, Any],
    repository: str | Path,
    *,
    coverage_json: str | Path | None = None,
    use_discovered_coverage: bool = True,
    runtime_traces: Iterable[tuple[str | Path, str]] = (),
    execution_manifests: Iterable[tuple[str, str | Path]] = (),
    initiated_by: str = "",
    evidence_root: str | Path | None = None,
    apply: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate and optionally apply all selected evidence as one workflow.

    Repository code is never executed. In plan mode the same import paths are run
    against a deep copy and a temporary evidence directory, so a successful plan is
    materially stronger than file discovery alone.
    """

    root = _repository(analysis, repository)
    source_manifest = verify_run_manifest_integrity(analysis)
    if not source_manifest.get("valid"):
        raise ValueError(
            "source analysis run manifest is invalid; verify or regenerate the analysis before onboarding evidence"
        )
    preflight = evidence_preflight(analysis, root)
    selected = _selected_inputs(
        preflight,
        coverage_json=coverage_json,
        use_discovered_coverage=use_discovered_coverage,
        runtime_traces=runtime_traces,
        execution_manifests=execution_manifests,
    )
    if apply and not selected:
        raise ValueError(
            "evidence onboarding apply requires at least one discovered or explicitly selected artifact"
        )
    source_digest = canonical_json_sha256(analysis)
    working = copy.deepcopy(analysis)
    applied_at = utc_now()
    selection_digest = canonical_json_sha256(selected)
    onboarding_id = stable_id(
        "ONBOARD",
        source_digest,
        selection_digest,
        str(analysis.get("project", {}).get("baseline", {}).get("id", "")),
    )

    prospective_evidence: dict[str, Any] | None = None
    prospective_assurance: dict[str, Any] | None = None
    if apply:
        destination_root = (
            Path(evidence_root).expanduser().absolute()
            if evidence_root is not None
            else root / ".artifacts" / "sfmea-evidence"
        )
        results = _apply_selected(
            working,
            selected,
            initiated_by=initiated_by,
            evidence_root=destination_root,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="pysfmea-onboarding-") as temporary:
            results = _apply_selected(
                working,
                selected,
                initiated_by=initiated_by,
                evidence_root=Path(temporary),
            )
        results = [
            {
                **value,
                "status": "validated"
                if value.get("status") == "imported"
                else value.get("status"),
            }
            for value in results
        ]
        prospective_evidence = analysis_diagnostics(working).get("evidence", {})
        prospective_assurance = assurance_summary(
            working.get("assurance", {})
            if isinstance(working.get("assurance"), dict)
            else {}
        )
        working = copy.deepcopy(analysis)

    if apply:
        refresh_summary(working)
        working.setdefault("history", []).append(
            {
                "event": "evidence_onboarding_applied",
                "at": applied_at,
                "id": onboarding_id,
                "selected_evidence_sha256": selection_digest,
                "selected": len(selected),
                "imported": sum(value["status"] == "imported" for value in results),
                "duplicates": sum(value["status"] == "duplicate" for value in results),
                "initiated_by": initiated_by.strip(),
            }
        )
        working["run_manifest"] = create_run_manifest(working)
    queue = assurance_work_queue(working)
    queue_verification = verify_assurance_work_queue(queue, analysis=working)
    if not queue_verification["valid"]:
        raise RuntimeError("generated assurance work queue failed exact verification")
    diagnostics = analysis_diagnostics(working)
    evidence_summary = diagnostics.get("evidence", {})
    receipt: dict[str, Any] = {
        "format": EVIDENCE_ONBOARDING_RECEIPT_FORMAT,
        "id": onboarding_id,
        "mode": "applied" if apply else "validated_plan",
        "created_at": applied_at,
        "generator": {"name": "PySFMEA", "version": __version__},
        "repository": str(root),
        "source_binding": {
            "baseline_id": str(
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            ),
            "analysis_state_sha256": source_digest,
        },
        "result_binding": {
            "baseline_id": str(
                working.get("project", {}).get("baseline", {}).get("id", "")
            ),
            "analysis_state_sha256": canonical_json_sha256(working),
            "run_manifest_sha256": canonical_json_sha256(working["run_manifest"]),
            "assurance_work_queue_sha256": str(
                queue.get("integrity", {}).get("content_sha256", "")
            ),
        },
        "preflight": preflight,
        "selection_sha256": selection_digest,
        "selected_evidence": results,
        "summary": {
            "selected": len(selected),
            "imported": sum(value["status"] == "imported" for value in results),
            "validated": sum(value["status"] == "validated" for value in results),
            "duplicates": sum(value["status"] == "duplicate" for value in results),
            "coverage_components": int(
                evidence_summary.get("components_with_coverage", 0) or 0
            ),
            "runtime_imports": int(evidence_summary.get("runtime_imports", 0) or 0),
            "assurance": assurance_summary(
                working.get("assurance", {})
                if isinstance(working.get("assurance"), dict)
                else {}
            ),
            "queue": copy.deepcopy(queue.get("summary", {})),
            "prospective": {
                "coverage_components": int(
                    (prospective_evidence or evidence_summary).get(
                        "components_with_coverage", 0
                    )
                    or 0
                ),
                "runtime_imports": int(
                    (prospective_evidence or evidence_summary).get(
                        "runtime_imports", 0
                    )
                    or 0
                ),
                "assurance": prospective_assurance
                or assurance_summary(
                    working.get("assurance", {})
                    if isinstance(working.get("assurance"), dict)
                    else {}
                ),
            },
        },
        "queue_verification": queue_verification,
        "authority": (
            "validated_evidence_ingestion_and_projection_receipt_not_test_execution_"
            "evidence_sufficiency_engineering_approval_or_risk_acceptance"
        ),
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return working, receipt, queue


def verify_evidence_onboarding_receipt(
    receipt: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify receipt integrity and, when supplied, its resulting analysis binding."""

    supplied_digest = str(receipt.get("content_sha256", ""))
    content = copy.deepcopy(receipt)
    content.pop("content_sha256", None)
    selected = receipt.get("selected_evidence")
    selected_list: list[Any] = selected if isinstance(selected, list) else []
    summary = receipt.get("summary")
    binding = receipt.get("result_binding")
    queue_verification = receipt.get("queue_verification")
    selected_valid = bool(
        isinstance(selected, list)
        and len(selected_list) <= MAX_SELECTED_EVIDENCE
        and all(
            isinstance(value, dict)
            and value.get("kind")
            in {"coverage", "runtime_trace", "execution_manifest"}
            and value.get("status") in {"validated", "imported", "duplicate"}
            and isinstance(value.get("bytes"), int)
            and not isinstance(value.get("bytes"), bool)
            and 0 <= int(value["bytes"]) <= MAX_SELECTED_EVIDENCE_BYTES
            and len(str(value.get("sha256", ""))) == 64
            and bool(value.get("record_id"))
            for value in selected_list
        )
    )
    selection_projection = (
        [
            {
                key: value.get(key)
                for key in ("kind", "subject_id", "label", "path", "bytes", "sha256")
            }
            for value in selected_list
        ]
        if isinstance(selected, list)
        else []
    )
    selection_integrity = bool(
        selected_valid
        and receipt.get("selection_sha256")
        == canonical_json_sha256(selection_projection)
    )
    summary_object = summary if isinstance(summary, dict) else {}
    current_assurance = summary_object.get("assurance", {})
    current_assurance = current_assurance if isinstance(current_assurance, dict) else {}
    prospective = summary_object.get("prospective", {})
    prospective = prospective if isinstance(prospective, dict) else {}
    prospective_assurance = prospective.get("assurance", {})
    prospective_assurance = (
        prospective_assurance if isinstance(prospective_assurance, dict) else {}
    )
    validated_coverage = next(
        (
            int(value.get("result", {}).get("components", 0) or 0)
            for value in selected_list
            if value.get("kind") == "coverage" and value.get("status") == "validated"
        ),
        None,
    )
    validated_runtime = sum(
        value.get("kind") == "runtime_trace" and value.get("status") == "validated"
        for value in selected_list
    )
    validated_executions = sum(
        value.get("kind") == "execution_manifest"
        and value.get("status") == "validated"
        for value in selected_list
    )
    expected_prospective_coverage = (
        validated_coverage
        if validated_coverage is not None
        else int(summary_object.get("coverage_components", 0) or 0)
    )
    prospective_valid = bool(
        prospective.get("coverage_components") == expected_prospective_coverage
        and prospective.get("runtime_imports")
        == int(summary_object.get("runtime_imports", 0) or 0) + validated_runtime
        and prospective_assurance.get("executions")
        == int(current_assurance.get("executions", 0) or 0) + validated_executions
    )
    summary_valid = bool(
        selected_valid
        and isinstance(summary, dict)
        and summary.get("selected") == len(selected_list)
        and summary.get("imported")
        == sum(value.get("status") == "imported" for value in selected_list)
        and summary.get("validated")
        == sum(value.get("status") == "validated" for value in selected_list)
        and summary.get("duplicates")
        == sum(value.get("status") == "duplicate" for value in selected_list)
        and prospective_valid
    )
    queue_valid = bool(
        isinstance(queue_verification, dict)
        and queue_verification.get("valid") is True
        and isinstance(binding, dict)
        and binding.get("assurance_work_queue_sha256")
        == queue_verification.get("content_sha256")
        and queue_verification.get("binding", {}).get("analysis_state_sha256")
        == binding.get("analysis_state_sha256")
    )
    checks: dict[str, bool | None] = {
        "format": receipt.get("format") == EVIDENCE_ONBOARDING_RECEIPT_FORMAT,
        "mode": receipt.get("mode") in {"validated_plan", "applied"},
        "content_integrity": supplied_digest == canonical_json_sha256(content),
        "selected_evidence": selected_valid,
        "selection_integrity": selection_integrity,
        "summary_reconciliation": summary_valid,
        "queue_verification": queue_valid,
        "result_binding": None,
        "baseline": None,
        "run_manifest": None,
    }
    if analysis is not None:
        binding = binding if isinstance(binding, dict) else {}
        checks["result_binding"] = str(
            binding.get("analysis_state_sha256", "")
        ) == canonical_json_sha256(analysis)
        checks["baseline"] = str(binding.get("baseline_id", "")) == str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        )
        checks["run_manifest"] = str(binding.get("run_manifest_sha256", "")) == canonical_json_sha256(
            analysis.get("run_manifest", {})
        ) and bool(verify_run_manifest_integrity(analysis).get("valid"))
    failed = [name for name, value in checks.items() if value is False]
    unchecked = [name for name, value in checks.items() if value is None]
    return {
        "format": "pysfmea-evidence-onboarding-receipt-verification-1",
        "path": "<memory>",
        "valid": not failed,
        "status": "matched"
        if analysis is not None and not failed
        else "valid_binding_not_checked"
        if not failed
        else "invalid",
        "checks": checks,
        "failed_checks": failed,
        "unchecked_checks": unchecked,
        "receipt_id": str(receipt.get("id", "")),
        "content_sha256": canonical_json_sha256(content),
        "notice": (
            "Receipt verification establishes artifact integrity and optional result binding; "
            "it does not establish evidence sufficiency or engineering approval."
        ),
    }


def verify_evidence_onboarding_receipt_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Load and verify one bounded, regular onboarding receipt."""

    path, value, _size = load_bounded_json_file(
        source,
        label="evidence-onboarding receipt",
        max_bytes=MAX_ONBOARDING_RECEIPT_BYTES,
        max_depth=MAX_ONBOARDING_RECEIPT_JSON_DEPTH,
        max_nodes=MAX_ONBOARDING_RECEIPT_JSON_NODES,
    )
    if not isinstance(value, dict):
        raise ValueError("evidence-onboarding receipt root must be an object")
    result = verify_evidence_onboarding_receipt(value, analysis=analysis)
    result["path"] = str(path)
    return result
