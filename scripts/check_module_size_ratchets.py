"""Prevent renewed growth in concentrated modules while refactoring remains incremental."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

FORMAT = "pysfmea-module-size-ratchet-1"


def module_size_record(source: str | Path, policy_source: str | Path) -> dict[str, Any]:
    root = Path(source).resolve()
    policy = json.loads(Path(policy_source).read_text(encoding="utf-8"))
    required = {
        "format",
        "watched_maximum_lines",
        "maximum_unlisted_module_lines",
        "maximum_top_five_percent",
        "minimum_module_count",
    }
    if not isinstance(policy, dict) or set(policy) != required:
        raise ValueError("module-size policy fields do not match format 1")
    if policy.get("format") != FORMAT:
        raise ValueError("module-size policy format is unsupported")
    watched = policy.get("watched_maximum_lines")
    if not isinstance(watched, dict) or not watched or not all(
        isinstance(name, str)
        and name.endswith(".py")
        and isinstance(limit, int)
        and not isinstance(limit, bool)
        and limit > 0
        for name, limit in watched.items()
    ):
        raise ValueError("watched module limits are invalid")
    maximum_unlisted = policy.get("maximum_unlisted_module_lines")
    minimum_modules = policy.get("minimum_module_count")
    maximum_concentration = policy.get("maximum_top_five_percent")
    if (
        not isinstance(maximum_unlisted, int)
        or isinstance(maximum_unlisted, bool)
        or maximum_unlisted < 1
        or not isinstance(minimum_modules, int)
        or isinstance(minimum_modules, bool)
        or minimum_modules < 1
        or not isinstance(maximum_concentration, (int, float))
        or isinstance(maximum_concentration, bool)
        or not 0 < float(maximum_concentration) <= 100
    ):
        raise ValueError("module-size aggregate limits are invalid")
    modules: dict[str, int] = {}
    for path in sorted(root.glob("*.py")):
        if path.is_symlink() or not path.is_file():
            continue
        modules[path.name] = len(path.read_text(encoding="utf-8").splitlines())
    total_lines = sum(modules.values())
    largest = sorted(modules.items(), key=lambda value: (-value[1], value[0]))[:5]
    concentration = (
        round(sum(lines for _, lines in largest) / total_lines * 100, 4)
        if total_lines
        else 100.0
    )
    violations = [
        {
            "code": "watched_module_growth",
            "module": name,
            "actual": modules.get(name),
            "limit": limit,
        }
        for name, limit in watched.items()
        if modules.get(name) is None or modules[name] > limit
    ]
    violations.extend(
        {
            "code": "new_large_module",
            "module": name,
            "actual": lines,
            "limit": maximum_unlisted,
        }
        for name, lines in modules.items()
        if name not in watched and lines > maximum_unlisted
    )
    if len(modules) < minimum_modules:
        violations.append(
            {
                "code": "module_population_regression",
                "actual": len(modules),
                "limit": minimum_modules,
            }
        )
    if concentration > float(maximum_concentration):
        violations.append(
            {
                "code": "top_five_concentration_regression",
                "actual": concentration,
                "limit": float(maximum_concentration),
            }
        )
    return {
        "format": FORMAT,
        "authority": "maintainability_non_regression_not_architecture_quality_proof",
        "source": str(root),
        "module_count": len(modules),
        "total_lines": total_lines,
        "top_five": [{"module": name, "lines": lines} for name, lines in largest],
        "top_five_percent": concentration,
        "violations": violations,
        "passed": not violations,
        "notice": (
            "Existing large modules are frozen at explicit ceilings. New behavior should be "
            "implemented behind smaller typed subsystem boundaries, and ceilings should only move down."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", default="src/pysfmea")
    parser.add_argument("--policy", default="quality/module-size-ratchet.json")
    args = parser.parse_args(argv)
    result = module_size_record(args.source, args.policy)
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        print("Module-size ratchet failed.", file=sys.stderr)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
