"""Read-only pre-scan readiness diagnostics for SFMEA projects."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .config import load_config
from .guidance import DEFAULT_EXCLUDES
from .json_ingestion import load_bounded_json_document
from .system_context import build_system_context

MAX_READINESS_COVERAGE_BYTES = 100_000_000
MAX_READINESS_COVERAGE_DEPTH = 100
MAX_READINESS_COVERAGE_NODES = 2_000_000


def _coverage_json_error(path: Path) -> str:
    try:
        document = load_bounded_json_document(
            path,
            label="coverage JSON",
            max_bytes=MAX_READINESS_COVERAGE_BYTES,
            max_depth=MAX_READINESS_COVERAGE_DEPTH,
            max_nodes=MAX_READINESS_COVERAGE_NODES,
        )
    except (OSError, ValueError) as exc:
        return str(exc)
    if not isinstance(document.value, dict) or not isinstance(
        document.value.get("files"), dict
    ):
        return "coverage JSON must contain an object-valued files field"
    return ""


def repository_readiness(
    repository: str | Path, *, config_path: str | Path | None = None
) -> dict[str, Any]:
    root = Path(repository).expanduser().resolve()
    checks: list[dict[str, str]] = []

    def add(
        check_id: str,
        status: str,
        message: str,
        *,
        next_action: str = "",
    ) -> None:
        check = {"id": check_id, "status": status, "message": message}
        if next_action:
            check["next_action"] = next_action
        checks.append(check)

    if not root.is_dir():
        add("repository.directory", "error", f"Repository directory does not exist: {root}")
        return _result(root, None, checks)
    add("repository.directory", "pass", f"Repository: {root}")

    python_files = []
    for path in root.rglob("*.py"):
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if any(part in DEFAULT_EXCLUDES or part.startswith(".") for part in relative.parts[:-1]):
            continue
        python_files.append(resolved)
    if python_files:
        add(
            "repository.python_sources",
            "pass",
            f"Found {len(python_files)} Python source file(s) before configured exclusions.",
        )
    else:
        add("repository.python_sources", "error", "No Python source files were found.")

    selected_config = Path(config_path).expanduser().resolve() if config_path else root / "sfmea.toml"
    if not selected_config.is_file():
        add(
            "configuration.file",
            "error",
            f"No SFMEA configuration found: {selected_config}. Run `sfmea init {root}`.",
        )
        return _result(root, selected_config, checks)
    try:
        config, resolved_config = load_config(selected_config)
    except (OSError, ValueError) as exc:
        add("configuration.valid", "error", f"Configuration is invalid: {exc}")
        return _result(root, selected_config, checks)
    assert resolved_config is not None
    add("configuration.valid", "pass", f"Configuration loaded: {resolved_config}")

    template_markers = sum(
        (
            config["project"].get("name") == "Example Python System",
            any(
                value.get("description") == "Example unacceptable system condition"
                for value in config["hazards"]
            ),
            any(value.get("name") == "Example reviewer" for value in config["reviewers"]),
            any(
                str(value.get("pattern", "")).startswith("src/example/")
                for value in config["component_mappings"]
            ),
        )
    )
    if template_markers >= 3:
        add(
            "configuration.example_template",
            "error",
            "The configuration still contains the generated example project, catalogs, "
            "reviewer, and mappings; replace them with authoritative project inputs.",
        )

    project = config["project"]
    for field in ("name", "purpose", "boundary", "operating_context"):
        if project.get(field, "").strip():
            add(f"project.{field}", "pass", f"Project {field.replace('_', ' ')} is configured.")
        else:
            add(f"project.{field}", "error", f"Project {field.replace('_', ' ')} is blank.")
    resolved_context = build_system_context(config)
    add(
        "project.context_completeness",
        "pass" if resolved_context["status"] == "complete" else "warning",
        f"System context is {resolved_context['status']} "
        f"({resolved_context['completeness_percent']}% of governed fields supplied).",
    )
    for field in resolved_context["missing_recommended"]:
        add(
            f"project.context.{field}",
            "information",
            f"Recommended context is unresolved: {field.replace('_', ' ')}.",
        )
    analysis = config["analysis"]
    add(
        "analysis.revision",
        "pass" if analysis.get("revision", "").strip() else "error",
        "Analysis revision is configured."
        if analysis.get("revision", "").strip()
        else "Analysis revision is blank.",
    )
    add(
        "analysis.ground_rules",
        "pass" if analysis.get("ground_rules") else "error",
        f"Configured {len(analysis.get('ground_rules', []))} ground rule(s)."
        if analysis.get("ground_rules")
        else "No SFMEA ground rules are configured.",
    )
    active_profiles = set(analysis.get("guidance_profiles", []))
    decided_profiles = {
        value.get("profile_id")
        for value in config.get("guidance_applicability", [])
        if isinstance(value, dict)
    }
    missing_profile_decisions = sorted(active_profiles - decided_profiles)
    add(
        "guidance.applicability",
        "pass" if not missing_profile_decisions else "warning",
        (
            f"Recorded named applicability decisions for {len(active_profiles)} active "
            "guidance profile(s)."
            if not missing_profile_decisions
            else "Active guidance profiles lack named applicability decisions: "
            + ", ".join(missing_profile_decisions)
            + "."
        ),
        next_action=(
            "Add one [[guidance_applicability]] decision with rationale, selector, and "
            "effective date for every active profile."
            if missing_profile_decisions
            else ""
        ),
    )

    for field, label in (
        ("hazards", "hazard"),
        ("requirements", "requirement"),
        ("system_interfaces", "system interface"),
        ("component_mappings", "component mapping"),
    ):
        count = len(config[field])
        add(
            f"catalog.{field}",
            "pass" if count else "warning",
            f"Configured {count} {label}(s)."
            if count
            else f"No {label}s are configured; confirm this is intentional.",
        )
    reviewers = config["reviewers"]
    if not reviewers:
        add("review.team", "error", "No reviewers are configured.")
    else:
        roles = {value.get("role", "").strip() for value in reviewers if value.get("role", "").strip()}
        add("review.team", "pass", f"Configured {len(reviewers)} named reviewer(s).")
        add(
            "review.role_diversity",
            "pass" if len(roles) >= 2 else "warning",
            f"Review team represents {len(roles)} distinct role(s).",
        )
    coverage_path = config["scan"].get("coverage_json", "")
    if coverage_path:
        configured_coverage = Path(coverage_path).expanduser()
        if not configured_coverage.is_absolute():
            configured_coverage = resolved_config.parent / configured_coverage
        configured_coverage = configured_coverage.resolve()
        coverage_error = (
            _coverage_json_error(configured_coverage)
            if configured_coverage.is_file()
            else "coverage file is unavailable"
        )
        add(
            "evidence.coverage",
            "pass" if not coverage_error else "error",
            "Coverage evidence "
            f"{'validated' if not coverage_error else 'is not usable'}: "
            f"{configured_coverage}"
            + (f" ({coverage_error})" if coverage_error else ""),
            next_action=(
                "Run `coverage run -m pytest && coverage json -o coverage.json`, "
                "then set scan.coverage_json to that file."
                if coverage_error
                else ""
            ),
        )
    else:
        discovered_coverage = next(
            (
                candidate
                for candidate in (
                    root / "coverage.json",
                    root / ".artifacts" / "coverage.json",
                )
                if candidate.is_file()
            ),
            None,
        )
        add(
            "evidence.coverage",
            "warning" if discovered_coverage else "information",
            (
                f"Coverage JSON exists but is not configured: {discovered_coverage}."
                if discovered_coverage
                else "No coverage.py JSON is configured; findings cannot use observed "
                "line-coverage evidence."
            ),
            next_action=(
                f"Set scan.coverage_json = \"{discovered_coverage.as_posix()}\"."
                if discovered_coverage
                else "Run `coverage run -m pytest && coverage json -o coverage.json`, "
                "then set scan.coverage_json = \"coverage.json\"."
            ),
        )
    test_files = [
        path
        for path in python_files
        if path.name.startswith("test_") or "tests" in path.relative_to(root).parts
    ]
    add(
        "evidence.test_sources",
        "pass" if test_files else "warning",
        f"Found {len(test_files)} Python test source file(s)."
        if test_files
        else "No Python test sources were discovered; generated assurance obligations "
        "will begin without repository test references.",
        next_action=(
            "Add focused tests for safety-significant interfaces and failure controls."
            if not test_files
            else ""
        ),
    )
    return _result(root, resolved_config, checks)


def _result(root: Path, config_path: Path | None, checks: list[dict[str, str]]) -> dict[str, Any]:
    counts = Counter(check["status"] for check in checks)
    return {
        "repository": str(root),
        "configuration": str(config_path or ""),
        "ready": counts["error"] == 0,
        "counts": {
            status: counts[status]
            for status in ("error", "warning", "information", "pass")
        },
        "checks": checks,
        "suggested_actions": [
            {"check_id": check["id"], "action": check["next_action"]}
            for check in checks
            if check.get("next_action")
        ],
        "notice": "Readiness confirms pre-scan inputs only; run sfmea validate after scanning.",
    }
