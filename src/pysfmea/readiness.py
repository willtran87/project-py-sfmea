"""Read-only pre-scan readiness diagnostics for SFMEA projects."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .config import load_config
from .guidance import DEFAULT_EXCLUDES


def repository_readiness(
    repository: str | Path, *, config_path: str | Path | None = None
) -> dict[str, Any]:
    root = Path(repository).expanduser().resolve()
    checks: list[dict[str, str]] = []

    def add(check_id: str, status: str, message: str) -> None:
        checks.append({"id": check_id, "status": status, "message": message})

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
        add(
            "evidence.coverage",
            "pass" if Path(coverage_path).is_file() else "error",
            f"Coverage evidence {'found' if Path(coverage_path).is_file() else 'not found'}: {coverage_path}",
        )
    else:
        add(
            "evidence.coverage",
            "information",
            "No coverage.py evidence is configured; this is optional execution evidence.",
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
        "notice": "Readiness confirms pre-scan inputs only; run sfmea validate after scanning.",
    }
