"""Preflight a qualification campaign without pretending to supply external authority."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.qualification import load_qualification_campaign_manifest

FORMAT = "pysfmea-qualification-readiness-1"
PLACEHOLDER_MARKERS = ("replace", "placeholder", "example", "your ")


def qualification_readiness(source: str | Path) -> dict[str, Any]:
    document = load_qualification_campaign_manifest(source)
    manifest = document.value
    assert isinstance(manifest, dict)
    root = document.path.parent.resolve()
    governance = manifest["governance"]
    thresholds = manifest["thresholds"]
    repositories = manifest["repositories"]
    assert isinstance(governance, dict)
    assert isinstance(thresholds, dict)
    assert isinstance(repositories, list)

    governed_text = [
        str(manifest.get("title", "")),
        str(manifest.get("purpose", "")),
        *(str(governance.get(field, "")) for field in governance),
        *(
            str(repository.get(field, ""))
            for repository in repositories
            if isinstance(repository, dict)
            for field in ("id", "selection_rationale")
        ),
    ]
    placeholders = sorted(
        {
            value
            for value in governed_text
            if any(marker in value.casefold() for marker in PLACEHOLDER_MARKERS)
        }
    )
    artifact_checks: list[dict[str, Any]] = []
    for repository in repositories:
        assert isinstance(repository, dict)
        for field in ("analysis", "corpus", "evaluation"):
            reference = str(repository[field])
            candidate = (root / reference).resolve()
            contained = candidate.is_relative_to(root)
            exists = contained and candidate.is_file() and not candidate.is_symlink()
            artifact_checks.append(
                {
                    "repository_id": repository["id"],
                    "kind": field,
                    "reference": reference,
                    "contained_regular_file": exists,
                }
            )
    frameworks = {
        value
        for repository in repositories
        if isinstance(repository, dict)
        for value in repository.get("frameworks", [])
    }
    domains = {
        value
        for repository in repositories
        if isinstance(repository, dict)
        for value in repository.get("domains", [])
    }
    try:
        approval_not_future = date.fromisoformat(str(governance["approval_date"])) <= date.today()
    except ValueError:
        approval_not_future = False
    checks = {
        "no_placeholders": not placeholders,
        "independence_asserted": governance.get("independent") is True,
        "distinct_governance_identities": str(governance.get("labeled_by", "")).strip().casefold()
        != str(governance.get("approved_by", "")).strip().casefold(),
        "approval_date_not_future": approval_not_future,
        "minimum_repository_population": len(repositories)
        >= int(thresholds["minimum_repositories"]),
        "minimum_framework_population": len(frameworks)
        >= int(thresholds["minimum_frameworks"]),
        "minimum_domain_population": len(domains)
        >= int(thresholds["minimum_domains"]),
        "all_retained_artifacts_present": bool(artifact_checks)
        and all(value["contained_regular_file"] for value in artifact_checks),
    }
    ready = all(checks.values())
    return {
        "format": FORMAT,
        "authority": "campaign_execution_preflight_not_independent_validation_or_tool_qualification",
        "manifest": {
            "path": str(document.path),
            "bytes": document.size,
            "campaign_id": manifest["id"],
        },
        "population": {
            "repositories": len(repositories),
            "frameworks": len(frameworks),
            "domains": len(domains),
            "artifact_references": len(artifact_checks),
        },
        "checks": checks,
        "placeholders": placeholders,
        "artifacts": artifact_checks,
        "ready_for_campaign_execution": ready,
        "next_actions": [
            name for name, passed in checks.items() if not passed
        ],
        "notice": (
            "A passing preflight only makes the retained campaign executable. Repository "
            "selection, labels, identities, representativeness, and qualification approval "
            "must still be supplied and adjudicated independently."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--require-ready", action="store_true")
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    result = qualification_readiness(args.manifest)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        print(
            atomic_publish_text(
                args.output, rendered, label="qualification readiness record"
            )
        )
    else:
        sys.stdout.write(rendered)
    return int(args.require_ready and not result["ready_for_campaign_execution"])


if __name__ == "__main__":
    raise SystemExit(main())
