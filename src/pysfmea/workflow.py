"""Read-only cross-lifecycle status for the PySFMEA workflow."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .assurance import assurance_progress, verify_pytest_scaffold
from .html_report import HTML_REPORT_FORMAT
from .model import utc_now
from .readiness import repository_readiness
from .report import analysis_state_sha256, verify_review_package
from .store import load_analysis
from .validation import validate_analysis
from .visuals import coverage_metrics

WORKFLOW_STATUS_FORMAT = "pysfmea-workflow-status-2"
MAX_STATUS_HTML_BYTES = 256 * 1024 * 1024
WORKFLOW_NOTICE = (
    "Workflow status reports file presence, freshness, review progress, and quality-gate "
    "state. Valid package integrity proves the recorded bytes and provenance checks only; "
    "HTML report binding detects accidental staleness and embedded-payload changes only; "
    "an assurance scaffold is optional and its reported state is not a handoff gate; "
    "it does not establish analytical sufficiency, engineering approval, risk acceptance, "
    "or certification."
)


def _discover_path(
    root: Path,
    explicit: str | Path | None,
    candidates: Iterable[Path],
) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    resolved = [value.expanduser().resolve() for value in candidates]
    return next((value for value in resolved if value.exists()), resolved[0])


def _quote(path: Path) -> str:
    return f'"{str(path).replace(chr(34), chr(34) * 2)}"'


def _modified_at(path: Path) -> str:
    timestamp = path.stat().st_mtime
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _artifact_state(
    analysis_path: Path,
    preferred: list[Path],
    patterns: tuple[str, ...] = (),
) -> dict[str, Any]:
    candidates = list(dict.fromkeys(value.resolve() for value in preferred))
    for pattern in patterns:
        candidates.extend(
            value.resolve()
            for value in sorted(analysis_path.parent.glob(pattern))
            if value.resolve() not in candidates
        )
    selected = next((value for value in candidates if value.exists()), candidates[0])
    if not selected.exists():
        return {
            "path": str(selected),
            "status": "missing",
            "exists": False,
            "current": False,
            "timestamp_current": False,
            "modified_at": "",
        }
    comparison_path = selected
    if selected.is_dir() and (selected / "manifest.json").is_file():
        comparison_path = selected / "manifest.json"
    current = comparison_path.stat().st_mtime_ns >= analysis_path.stat().st_mtime_ns
    return {
        "path": str(selected),
        "status": "current" if current else "stale",
        "exists": True,
        "current": current,
        "timestamp_current": current,
        "modified_at": _modified_at(comparison_path),
    }


def _verify_package_artifact(
    artifact: dict[str, Any], analysis: dict[str, Any]
) -> dict[str, Any]:
    """Attach bounded integrity results without equating them with approval."""

    if not artifact.get("exists"):
        return artifact
    verification = verify_review_package(artifact["path"])
    artifact["integrity"] = {
        "valid": bool(verification.get("valid")),
        "checked_files": int(verification.get("checked_files", 0) or 0),
        "counts": dict(verification.get("counts", {})),
        "findings": [
            {
                "rule_id": str(value.get("rule_id", "")),
                "level": str(value.get("level", "error")),
                "path": str(value.get("path", "")),
                "message": str(value.get("message", "")),
            }
            for value in verification.get("findings", [])[:50]
            if isinstance(value, dict)
        ],
        "findings_truncated": len(verification.get("findings", [])) > 50,
        "archive_sha256": str(verification.get("archive_sha256", "")),
        "notice": str(verification.get("notice", "")),
    }
    package_binding = verification.get("binding", {})
    portable = bool(package_binding.get("portable", False))
    current_baseline = str(
        analysis.get("project", {}).get("baseline", {}).get("id", "")
    )
    current_schema = str(analysis.get("schema_version", ""))
    current_digest = analysis_state_sha256(analysis, portable=portable)
    package_digest = str(package_binding.get("analysis_state_sha256", ""))
    digest_available = len(package_digest) == 64
    binding_checks = {
        "baseline": current_baseline == str(package_binding.get("baseline_id", "")),
        "schema": current_schema
        == str(package_binding.get("analysis_schema_version", "")),
        "analysis_state": digest_available and current_digest == package_digest.lower(),
    }
    binding_valid = all(binding_checks.values())
    artifact["binding"] = {
        "valid": binding_valid,
        "status": (
            "matched"
            if binding_valid
            else "unbound"
            if not digest_available
            else "mismatched"
        ),
        "checks": binding_checks,
        "current": {
            "baseline_id": current_baseline,
            "analysis_schema_version": current_schema,
            "analysis_state_sha256": current_digest,
        },
        "package": {
            "baseline_id": str(package_binding.get("baseline_id", "")),
            "analysis_schema_version": str(
                package_binding.get("analysis_schema_version", "")
            ),
            "analysis_state_sha256": package_digest,
            "portable": portable,
        },
    }
    if not verification.get("valid"):
        artifact["status"] = "invalid"
    elif not binding_valid:
        artifact["status"] = artifact["binding"]["status"]
    else:
        artifact["status"] = "current"
    artifact["current"] = bool(verification.get("valid") and binding_valid)
    return artifact


def _html_report_meta(document: str, name: str) -> str:
    match = re.search(
        rf'<meta name="{re.escape(name)}" content="([^"]*)">',
        document,
    )
    return match.group(1) if match else ""


def _verify_html_report_artifact(
    artifact: dict[str, Any], analysis: dict[str, Any]
) -> dict[str, Any]:
    """Validate the report payload and bind its declared source to the analysis."""

    if not artifact.get("exists"):
        return artifact
    report_path = Path(artifact["path"])
    declared: dict[str, str] = {}
    payload_present = False
    payload_digest = ""
    read_error = ""
    try:
        if not report_path.is_file():
            raise ValueError("report path is not a regular file")
        if report_path.stat().st_size > MAX_STATUS_HTML_BYTES:
            raise ValueError(
                f"report exceeds the {MAX_STATUS_HTML_BYTES}-byte status verification limit"
            )
        document = report_path.read_text(encoding="utf-8")
        declared = {
            "format": _html_report_meta(document, "pysfmea-report-format"),
            "baseline_id": _html_report_meta(
                document, "pysfmea-analysis-baseline"
            ),
            "analysis_schema_version": _html_report_meta(
                document, "pysfmea-analysis-schema"
            ),
            "analysis_state_sha256": _html_report_meta(
                document, "pysfmea-analysis-state-sha256"
            ),
            "report_data_sha256": _html_report_meta(
                document, "pysfmea-report-data-sha256"
            ),
        }
        payload_match = re.search(
            r'<script id="report-data" type="application/json">(.*?)</script>',
            document,
            re.DOTALL,
        )
        payload_present = payload_match is not None
        if payload_match:
            payload_digest = hashlib.sha256(
                payload_match.group(1).encode("utf-8")
            ).hexdigest()
    except (OSError, UnicodeError, ValueError) as exc:
        read_error = str(exc)

    metadata_present = any(declared.values())
    metadata_complete = bool(declared) and all(declared.values())
    declared_data_digest = declared.get("report_data_sha256", "")
    digest_shape_valid = all(
        len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
        for value in (
            declared.get("analysis_state_sha256", ""),
            declared_data_digest,
        )
    )
    internal_checks = {
        "readable": not read_error,
        "metadata_complete": metadata_complete,
        "report_format": declared.get("format") == HTML_REPORT_FORMAT,
        "payload_present": payload_present,
        "payload_integrity": bool(
            digest_shape_valid
            and payload_present
            and payload_digest == declared_data_digest.lower()
        ),
    }
    current_baseline = str(
        analysis.get("project", {}).get("baseline", {}).get("id", "")
    )
    current_schema = str(analysis.get("schema_version", ""))
    current_digest = analysis_state_sha256(analysis)
    source_checks = {
        "baseline": current_baseline == declared.get("baseline_id", ""),
        "schema": current_schema == declared.get("analysis_schema_version", ""),
        "analysis_state": current_digest
        == declared.get("analysis_state_sha256", "").lower(),
    }
    internal_valid = all(internal_checks.values())
    binding_valid = internal_valid and all(source_checks.values())
    if not metadata_present and not read_error:
        status = "unbound"
    elif not internal_valid:
        status = "invalid"
    elif not binding_valid:
        status = "mismatched"
    else:
        status = "matched"
    artifact["binding"] = {
        "valid": binding_valid,
        "status": status,
        "checks": {**internal_checks, **source_checks},
        "current": {
            "baseline_id": current_baseline,
            "analysis_schema_version": current_schema,
            "analysis_state_sha256": current_digest,
        },
        "report": declared,
        "error": read_error,
        "notice": (
            "Report binding detects accidental staleness and payload changes; it is not "
            "an authenticated signature or engineering approval."
        ),
    }
    if status != "matched":
        artifact["status"] = status
    else:
        artifact["status"] = "current"
    artifact["current"] = binding_valid
    return artifact


def _verify_assurance_scaffold_artifact(
    artifact: dict[str, Any], analysis: dict[str, Any]
) -> dict[str, Any]:
    """Attach scaffold integrity and freshness without making it a handoff gate."""

    if not artifact.get("exists"):
        return artifact
    verification = verify_pytest_scaffold(analysis, artifact["path"])
    internal_checks = {
        key: bool(verification["checks"].get(key))
        for key in (
            "readable",
            "format",
            "manifest_integrity",
            "obligations",
            "contract_snapshot",
            "contract_snapshot_integrity",
            "selection_contract",
            "queue_metadata",
            "generated_files_declared",
            "retirement_record",
        )
    }
    internal_valid = all(internal_checks.values())
    artifact["integrity"] = {
        "valid": internal_valid,
        "checked_files": (
            1
            + len(verification["generated_files"])
            + int(verification["retirement"]["present"])
        ),
        "findings": list(verification["findings"]),
    }
    artifact["binding"] = {
        "valid": bool(verification["valid"]),
        "status": verification["status"],
        "checks": dict(verification["checks"]),
        **verification["binding"],
    }
    artifact["generated_files_changed"] = sum(
        not value["unchanged_from_generated"]
        for value in verification["generated_files"]
    )
    artifact["contract_change_summary"] = dict(
        verification["contract_change_summary"]
    )
    artifact["contract_changes"] = list(verification["contract_changes"])
    artifact["obligation_ids"] = list(verification["obligation_ids"])
    artifact["current_selection"] = dict(verification["current_selection"])
    artifact["lifecycle"] = str(verification["lifecycle"])
    artifact["retirement"] = dict(verification["retirement"])
    artifact["queue"] = dict(verification["queue"])
    artifact["status"] = "current" if verification["valid"] else verification["status"]
    artifact["current"] = bool(verification["valid"])
    artifact["notice"] = verification["notice"]
    return artifact


def _assurance_scaffold_portfolio(
    analysis: dict[str, Any], scaffold_artifacts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Summarize queue coverage and overlap without creating a handoff gate."""

    assignments: dict[str, list[dict[str, str]]] = {}
    for artifact in scaffold_artifacts:
        if not artifact.get("current"):
            continue
        for obligation_id in artifact.get("obligation_ids", []):
            assignments.setdefault(str(obligation_id), []).append(
                {
                    "queue_id": str(artifact.get("queue", {}).get("id", "")),
                    "owner": str(artifact.get("queue", {}).get("owner", "")),
                    "path": str(artifact.get("path", "")),
                }
            )
    dispositions = {
        str(item.get("id", "")): str(
            item.get("review", {}).get("disposition", "unreviewed")
        )
        for item in analysis.get("items", [])
        if isinstance(item, dict)
    }
    accepted_pending = sorted(
        str(value.get("id", ""))
        for value in analysis.get("assurance", {}).get("obligations", [])
        if isinstance(value, dict)
        and value.get("source_status", "active") == "active"
        and dispositions.get(str(value.get("finding_id", ""))) == "accepted"
        and value.get("assurance_status") not in {"not_applicable", "accepted_risk"}
        and value.get("automation", {}).get("implementation_status") != "implemented"
    )
    accepted_set = set(accepted_pending)
    assigned_set = set(assignments)
    duplicates = [
        {
            "obligation_id": obligation_id,
            "scaffold_paths": [value["path"] for value in queues],
            "queues": queues,
        }
        for obligation_id, queues in sorted(assignments.items())
        if len(queues) > 1
    ]
    queue_ids: dict[str, list[str]] = {}
    for artifact in scaffold_artifacts:
        if not artifact.get("integrity", {}).get("valid"):
            continue
        identifier = str(artifact.get("queue", {}).get("id", ""))
        if identifier:
            queue_ids.setdefault(identifier, []).append(str(artifact.get("path", "")))
    duplicate_queue_ids = [
        {"queue_id": identifier, "scaffold_paths": paths}
        for identifier, paths in sorted(queue_ids.items())
        if len(paths) > 1
    ]
    uncovered = sorted(accepted_set - assigned_set)
    covered = sorted(accepted_set & assigned_set)
    return {
        "format": "pysfmea-assurance-scaffold-portfolio-1",
        "queue_count": len(scaffold_artifacts),
        "existing_queues": sum(value.get("exists", False) for value in scaffold_artifacts),
        "current_queues": sum(value.get("current", False) for value in scaffold_artifacts),
        "attention_queues": sum(
            not value.get("current", False) for value in scaffold_artifacts
        ),
        "unowned_current_queues": sum(
            value.get("current", False)
            and not str(value.get("queue", {}).get("owner", "")).strip()
            for value in scaffold_artifacts
        ),
        "duplicate_queue_id_count": len(duplicate_queue_ids),
        "duplicate_queue_ids": duplicate_queue_ids,
        "unique_assigned_obligations": len(assigned_set),
        "accepted_pending_obligations": len(accepted_pending),
        "covered_accepted_obligations": len(covered),
        "uncovered_accepted_obligations": len(uncovered),
        "coverage_percent": (
            round((len(covered) / len(accepted_pending)) * 100, 1)
            if accepted_pending
            else None
        ),
        "duplicate_assignment_count": len(duplicates),
        "duplicate_assignments": duplicates,
        "uncovered_accepted_obligation_ids": uncovered,
        "notice": (
            "Queue coverage is an operational ownership aid, not evidence, approval, risk "
            "acceptance, or a handoff gate. Only current queue bindings contribute coverage."
        ),
    }


def _analysis_counts(analysis: dict[str, Any]) -> dict[str, Any]:
    active = [
        item
        for item in analysis.get("items", [])
        if item.get("source_status", "active") == "active"
    ]
    dispositions = Counter(
        str(item.get("review", {}).get("disposition", "unreviewed"))
        for item in active
    )
    statuses = Counter(
        str(item.get("review", {}).get("status", "draft")) for item in active
    )
    validation = validate_analysis(analysis)
    coverage = coverage_metrics(analysis)
    return {
        "components": len(analysis.get("components", [])),
        "active_findings": len(active),
        "unreviewed": dispositions["unreviewed"],
        "accepted": dispositions["accepted"],
        "rejected": dispositions["rejected"],
        "revalidation_required": sum(
            bool(item.get("review", {}).get("revalidation_required"))
            for item in active
        ),
        "by_disposition": dict(sorted(dispositions.items())),
        "by_status": dict(sorted(statuses.items())),
        "review_percent": coverage.get("failure_modes", {}).get("review_percent"),
        "validation": validation.get("counts", {}),
        "assurance": assurance_progress(analysis),
    }


def workflow_status(
    repository: str | Path,
    *,
    config_path: str | Path | None = None,
    analysis_path: str | Path | None = None,
    assurance_scaffold_path: str | Path | Iterable[str | Path] | None = None,
) -> dict[str, Any]:
    """Build a truthful workflow stage and ordered next-action list."""

    root = Path(repository).expanduser().resolve()
    config = _discover_path(
        root,
        config_path,
        (root / "sfmea.toml", root / ".artifacts" / "sfmea.toml"),
    )
    analysis_file = _discover_path(
        root,
        analysis_path,
        (
            root / "sfmea-analysis.json",
            root / ".artifacts" / "sfmea-analysis.json",
        ),
    )
    readiness = repository_readiness(root, config_path=config)
    requested_values = (
        [assurance_scaffold_path]
        if isinstance(assurance_scaffold_path, (str, Path))
        else list(assurance_scaffold_path or [])
    )
    requested_scaffolds = list(
        dict.fromkeys(Path(value).expanduser().resolve() for value in requested_values)
    )
    analysis: dict[str, Any] | None = None
    counts: dict[str, Any] = {}
    artifacts: dict[str, dict[str, Any]] = {}
    scaffold_artifacts: list[dict[str, Any]] = []
    scaffold_portfolio: dict[str, Any] = {}
    if analysis_file.is_file():
        analysis = load_analysis(analysis_file)
        counts = _analysis_counts(analysis)
        stem = analysis_file.stem
        artifacts = {
            "html_report": _verify_html_report_artifact(
                _artifact_state(
                    analysis_file,
                    [
                        analysis_file.with_name("sfmea-report.html"),
                        analysis_file.with_name(f"{stem}-report.html"),
                    ],
                    ("*sfmea*report.html",),
                ),
                analysis,
            ),
            "pdf_report": _artifact_state(
                analysis_file,
                [
                    analysis_file.with_name("sfmea-report.pdf"),
                    analysis_file.with_name(f"{stem}-report.pdf"),
                ],
                ("*sfmea*report.pdf",),
            ),
            "review_package": _verify_package_artifact(
                _artifact_state(
                    analysis_file,
                    [
                        analysis_file.with_name(f"{stem}-review-package.zip"),
                        analysis_file.with_name(f"{stem}-review-package"),
                    ],
                    ("*review-package.zip", "*review-package"),
                ),
                analysis,
            ),
        }
        scaffold_candidates = requested_scaffolds or [
            analysis_file.with_name("assurance-tests"),
            analysis_file.with_name(f"{stem}-assurance-tests"),
        ]
        if requested_scaffolds:
            candidate_states = [
                _artifact_state(analysis_file, [candidate])
                for candidate in scaffold_candidates
            ]
        else:
            candidate_states = [
                _artifact_state(
                    analysis_file,
                    scaffold_candidates,
                    ("*assurance-tests",),
                )
            ]
        scaffold_artifacts = [
            _verify_assurance_scaffold_artifact(value, analysis)
            for value in candidate_states
            if requested_scaffolds or value["exists"]
        ]
        if scaffold_artifacts:
            artifacts["assurance_scaffold"] = scaffold_artifacts[0]
            scaffold_portfolio = _assurance_scaffold_portfolio(
                analysis, scaffold_artifacts
            )

    validation_errors = int(counts.get("validation", {}).get("error", 0) or 0)
    unreviewed = int(counts.get("unreviewed", 0) or 0)
    revalidation = int(counts.get("revalidation_required", 0) or 0)
    assurance = counts.get("assurance", {})
    assurance_plan_ready = bool(assurance.get("gates", {}).get("plan_ready"))
    report_artifact = artifacts.get("html_report", {})
    report_binding_valid = bool(report_artifact.get("binding", {}).get("valid"))
    report_current = bool(report_artifact.get("current") and report_binding_valid)
    package_artifact = artifacts.get("review_package", {})
    package_integrity_valid = bool(
        package_artifact.get("integrity", {}).get("valid")
    )
    package_binding_valid = bool(package_artifact.get("binding", {}).get("valid"))
    package_current = bool(
        package_artifact.get("current")
        and package_integrity_valid
        and package_binding_valid
    )
    ready_for_handoff = bool(
        analysis
        and readiness["ready"]
        and validation_errors == 0
        and unreviewed == 0
        and revalidation == 0
        and assurance_plan_ready
        and report_current
        and package_current
    )
    if not analysis and not readiness["ready"]:
        stage = "configuration_required"
    elif not analysis:
        stage = "ready_to_scan"
    elif not readiness["ready"]:
        stage = "inputs_need_attention"
    elif revalidation:
        stage = "revalidation_required"
    elif unreviewed or validation_errors:
        stage = "engineering_review"
    elif not assurance_plan_ready:
        stage = "assurance_planning"
    elif report_artifact.get("exists") and report_artifact.get("status") == "invalid":
        stage = "report_invalid"
    elif report_artifact.get("exists") and not report_binding_valid:
        stage = "report_binding_required"
    elif package_artifact.get("exists") and not package_integrity_valid:
        stage = "package_invalid"
    elif package_artifact.get("exists") and not package_binding_valid:
        stage = "package_binding_required"
    elif not report_current or not package_current:
        stage = "handoff_preparation"
    else:
        stage = "handoff_ready"

    actions: list[dict[str, str]] = []

    def add(action_id: str, command: str, reason: str) -> None:
        actions.append({"id": action_id, "command": command, "reason": reason})

    if not config.is_file():
        add("create_configuration", f"sfmea init {_quote(root)}", "Create governed project context.")
    if not readiness["ready"]:
        add(
            "resolve_readiness",
            f"sfmea doctor {_quote(root)} --config {_quote(config)}",
            f"Resolve {readiness['counts']['error']} pre-scan readiness error(s).",
        )
    if not analysis:
        if readiness["ready"]:
            add(
                "scan_repository",
                f"sfmea scan {_quote(root)} --config {_quote(config)} -o {_quote(analysis_file)}",
                "Create the governed starter analysis.",
            )
    else:
        if unreviewed or revalidation:
            add(
                "review_findings",
                f"sfmea review {_quote(analysis_file)}",
                f"Review {unreviewed} unreviewed and {revalidation} revalidation-required finding(s).",
            )
        add(
            "validate_analysis",
            f"sfmea validate {_quote(analysis_file)}",
            f"Evaluate the current {validation_errors} validation error(s).",
        )
        if assurance.get("planning_pending", 0):
            checklist_path = analysis_file.with_name(
                analysis_file.stem + "-assurance.md"
            )
            add(
                "review_assurance_plan",
                (
                    f"sfmea assurance {_quote(analysis_file)} --format markdown "
                    f"-o {_quote(checklist_path)}"
                ),
                (
                    f"Review {assurance['planning_pending']} accepted-finding assurance "
                    "plan(s), then record governed decisions with sfmea assurance-review."
                ),
            )
        for index, scaffold_artifact in enumerate(scaffold_artifacts, start=1):
            suffix = "" if index == 1 else f"_{index}"
            if scaffold_artifact.get("exists") and not scaffold_artifact.get("current"):
                refresh_safe = bool(
                    scaffold_artifact.get("integrity", {}).get("valid")
                    and scaffold_artifact.get("generated_files_changed") == 0
                )
                if (
                    refresh_safe
                    and scaffold_artifact.get("lifecycle")
                    == "retirement_candidate"
                ):
                    add(
                        "archive_empty_assurance_scaffold" + suffix,
                        (
                            f"sfmea assurance-scaffold-archive {_quote(analysis_file)} "
                            f"{_quote(Path(scaffold_artifact['path']))}"
                        ),
                        (
                            "The saved selection now matches no pending obligations. "
                            "Preserve its removal diff and audit history in the inactive "
                            "archive instead of refreshing or deleting it."
                        ),
                    )
                elif refresh_safe:
                    add(
                        "refresh_assurance_scaffold" + suffix,
                        (
                            f"sfmea assurance-scaffold-refresh {_quote(analysis_file)} "
                            f"{_quote(Path(scaffold_artifact['path']))}"
                        ),
                        (
                            "Refresh the stale scaffold in place; its generated files are "
                            "unchanged and its governed selection/identity will be preserved."
                        ),
                    )
                else:
                    add(
                        "verify_assurance_scaffold" + suffix,
                        (
                            f"sfmea assurance-scaffold-verify {_quote(analysis_file)} "
                            f"{_quote(Path(scaffold_artifact['path']))}"
                        ),
                        (
                            "Inspect the existing scaffold and use a new destination if "
                            "necessary so implementation edits are preserved."
                        ),
                    )
            elif (
                requested_scaffolds
                and not scaffold_artifact.get("exists")
                and assurance.get("implementation_pending", 0)
            ):
                add(
                    "create_assurance_scaffold" + suffix,
                    (
                        f"sfmea assurance-scaffold {_quote(analysis_file)} "
                        f"-o {_quote(Path(scaffold_artifact['path']))}"
                    ),
                    (
                        "Create the explicitly requested scaffold for the pending accepted "
                        "verification obligations."
                    ),
                )
        if scaffold_portfolio.get("duplicate_assignment_count", 0):
            status_command = [
                f"sfmea status {_quote(root)}",
                f"--analysis {_quote(analysis_file)}",
            ]
            for value in scaffold_artifacts:
                status_command.append(
                    f"--assurance-scaffold {_quote(Path(value['path']))}"
                )
            status_command.append("--json")
            add(
                "review_assurance_scaffold_overlap",
                " ".join(status_command),
                (
                    f"Resolve {scaffold_portfolio['duplicate_assignment_count']} "
                    "obligation assignment overlap(s) across current queues."
                ),
            )
        if not report_current:
            if report_artifact.get("status") == "invalid":
                report_reason = "Replace the report because its embedded payload verification failed."
            elif report_artifact.get("status") in {"unbound", "mismatched"}:
                report_reason = (
                    "Refresh the report because it is not bound to the current governed "
                    "analysis state."
                )
            else:
                report_reason = "Create or refresh the self-contained reviewer report."
            add(
                "refresh_report",
                f"sfmea report {_quote(analysis_file)} -o {_quote(Path(report_artifact['path']))}",
                report_reason,
            )
        if not package_current:
            if package_artifact.get("status") == "invalid":
                package_reason = "Replace the package because integrity verification failed."
            elif package_artifact.get("status") in {"unbound", "mismatched"}:
                package_reason = (
                    "Refresh the package because it is not bound to the current governed "
                    "analysis state."
                )
            else:
                package_reason = (
                    "Create or refresh the checksum-manifested handoff package."
                )
            package_flags = ["--portable"]
            if Path(package_artifact["path"]).suffix.lower() == ".zip":
                package_flags.append("--zip")
            if package_artifact.get("exists"):
                package_flags.append("--force")
            add(
                "refresh_package",
                " ".join(
                    [
                        f"sfmea package {_quote(analysis_file)}",
                        f"-o {_quote(Path(package_artifact['path']))}",
                        *package_flags,
                    ]
                ),
                package_reason,
            )

    return {
        "format": WORKFLOW_STATUS_FORMAT,
        "generated_at": utc_now(),
        "repository": str(root),
        "stage": stage,
        "ready_for_handoff": ready_for_handoff,
        "paths": {
            "configuration": str(config),
            "analysis": str(analysis_file),
            "assurance_scaffold": str(
                scaffold_artifacts[0].get("path", "") if scaffold_artifacts else ""
            ),
            "assurance_scaffolds": [
                str(value.get("path", "")) for value in scaffold_artifacts
            ],
        },
        "readiness": {
            "ready": readiness["ready"],
            "counts": readiness["counts"],
        },
        "analysis": {
            "exists": analysis is not None,
            "baseline_id": (
                analysis.get("project", {}).get("baseline", {}).get("id", "")
                if analysis
                else ""
            ),
            "schema_version": analysis.get("schema_version", "") if analysis else "",
            "counts": counts,
        },
        "artifacts": artifacts,
        "assurance_scaffolds": scaffold_artifacts,
        "assurance_scaffold_portfolio": scaffold_portfolio,
        "next_actions": actions,
        "notice": WORKFLOW_NOTICE,
    }
