"""Produce a bounded, content-addressed scanner performance evidence record."""

from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.scanner import scan_repository
from pysfmea.version import __version__

FORMAT = "pysfmea-scan-performance-1"
MAX_REPEATS = 20


def benchmark_repository(
    repository: str | Path,
    *,
    repeats: int = 3,
    reuse_facts: bool = False,
    max_median_seconds: float | None = None,
    max_peak_bytes: int | None = None,
) -> dict[str, Any]:
    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= MAX_REPEATS:
        raise ValueError(f"repeats must be between 1 and {MAX_REPEATS}")
    if max_median_seconds is not None and max_median_seconds <= 0:
        raise ValueError("max_median_seconds must be greater than zero")
    if max_peak_bytes is not None and (
        isinstance(max_peak_bytes, bool) or max_peak_bytes <= 0
    ):
        raise ValueError("max_peak_bytes must be a positive integer")
    root = Path(repository).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository path is not a directory: {root}")
    runs: list[dict[str, Any]] = []
    baseline_ids: set[str] = set()
    last_analysis: dict[str, Any] = {}
    fact_cache: dict[str, Any] | None = {} if reuse_facts else None
    for index in range(repeats):
        telemetry: dict[str, Any] = {}
        tracemalloc.start()
        started = time.perf_counter_ns()
        try:
            analysis = scan_repository(
                root,
                telemetry=telemetry,
                fact_cache=fact_cache,
            )
            elapsed_ns = time.perf_counter_ns() - started
            _current, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        last_analysis = analysis
        baseline_ids.add(str(analysis.get("project", {}).get("baseline", {}).get("id", "")))
        runs.append(
            {
                "run": index + 1,
                "elapsed_seconds": round(elapsed_ns / 1_000_000_000, 6),
                "peak_traced_bytes": peak_bytes,
                "phases_seconds": telemetry.get("phases_seconds", {}),
                "fact_cache": telemetry.get("fact_cache", {}),
            }
        )
    durations = sorted(float(value["elapsed_seconds"]) for value in runs)
    peaks = [int(value["peak_traced_bytes"]) for value in runs]
    phase_names = sorted(
        {
            str(name)
            for run in runs
            for name in run.get("phases_seconds", {})
        }
    )
    phase_samples = {
        name: [
            float(run["phases_seconds"][name])
            for run in runs
            if name in run.get("phases_seconds", {})
        ]
        for name in phase_names
    }
    inventory = last_analysis.get("repository_inventory", {})
    summary = inventory.get("summary", {}) if isinstance(inventory, dict) else {}
    entries = inventory.get("entries", []) if isinstance(inventory, dict) else []
    inventory_bytes = sum(
        int(entry.get("size", 0))
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("size", 0), int)
        and not isinstance(entry.get("size", 0), bool)
        and int(entry.get("size", 0)) >= 0
    )
    baseline = last_analysis.get("project", {}).get("baseline", {})
    p95_index = max(0, math.ceil(len(durations) * 0.95) - 1)
    stable = len(baseline_ids) == 1 and "" not in baseline_ids
    median_seconds = round(statistics.median(durations), 6)
    cold_start_seconds = float(runs[0]["elapsed_seconds"])
    warm_durations = [
        float(value["elapsed_seconds"])
        for value in runs[1:]
        if int(value.get("fact_cache", {}).get("hits", 0)) > 0
    ]
    steady_state_median_seconds = (
        round(statistics.median(warm_durations), 6) if warm_durations else None
    )
    warm_speedup_percent = (
        round(
            (cold_start_seconds - steady_state_median_seconds)
            / cold_start_seconds
            * 100,
            2,
        )
        if steady_state_median_seconds is not None and cold_start_seconds > 0
        else None
    )
    maximum_peak_bytes = max(peaks)
    budget_checks = {
        "median_seconds": (
            None
            if max_median_seconds is None
            else median_seconds <= max_median_seconds
        ),
        "peak_traced_bytes": (
            None if max_peak_bytes is None else maximum_peak_bytes <= max_peak_bytes
        ),
    }
    budgets_passed = all(value is not False for value in budget_checks.values())
    return {
        "format": FORMAT,
        "tool": {"name": "PySFMEA", "version": __version__},
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "repository": {
            "path": str(root),
            "baseline_ids": sorted(baseline_ids),
            "stable_baseline": stable,
            "inventory_files": summary.get("files"),
            "inventory_bytes": inventory_bytes,
            "source_snapshot_files": baseline.get("source_snapshot_files"),
            "source_snapshot_bytes": baseline.get("source_snapshot_bytes"),
            "test_evidence_snapshot_files": baseline.get(
                "test_evidence_snapshot_files"
            ),
            "test_evidence_snapshot_bytes": baseline.get(
                "test_evidence_snapshot_bytes"
            ),
            "components": len(last_analysis.get("components", [])),
            "candidates": len(last_analysis.get("items", [])),
        },
        "runs": runs,
        "budgets": {
            "configured": {
                "max_median_seconds": max_median_seconds,
                "max_peak_traced_bytes": max_peak_bytes,
            },
            "checks": budget_checks,
            "passed": budgets_passed,
        },
        "summary": {
            "repeats": repeats,
            "fact_reuse_enabled": reuse_facts,
            "fact_cache_hits": sum(
                int(run.get("fact_cache", {}).get("hits", 0)) for run in runs
            ),
            "fact_cache_misses": sum(
                int(run.get("fact_cache", {}).get("misses", 0)) for run in runs
            ),
            "cold_start_seconds": cold_start_seconds,
            "steady_state_median_seconds": steady_state_median_seconds,
            "warm_speedup_percent": warm_speedup_percent,
            "median_seconds": median_seconds,
            "p95_seconds": durations[p95_index],
            "minimum_seconds": durations[0],
            "maximum_seconds": durations[-1],
            "maximum_peak_traced_bytes": maximum_peak_bytes,
            "phase_medians_seconds": {
                name: round(statistics.median(values), 6)
                for name, values in phase_samples.items()
            },
            "phase_maximums_seconds": {
                name: round(max(values), 6)
                for name, values in phase_samples.items()
            },
        },
        "notice": (
            "This record characterizes one machine, repository, configuration, and Python "
            "runtime. tracemalloc measures traced Python allocations, not total process memory; "
            "thresholds require an independently approved environment-specific baseline."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--reuse-facts",
        action="store_true",
        help="measure exact-content in-process parser fact reuse after the cold run",
    )
    parser.add_argument(
        "--max-median-seconds",
        type=float,
        help="fail when measured median scan time exceeds this CI budget",
    )
    parser.add_argument(
        "--max-peak-bytes",
        type=int,
        help="fail when peak traced Python allocations exceed this CI budget",
    )
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    result = benchmark_repository(
        args.repository,
        repeats=args.repeats,
        reuse_facts=args.reuse_facts,
        max_median_seconds=args.max_median_seconds,
        max_peak_bytes=args.max_peak_bytes,
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        destination = atomic_publish_text(
            args.output, rendered, label="scanner performance evidence"
        )
        print(destination)
    else:
        sys.stdout.write(rendered)
    return int(
        not result["repository"]["stable_baseline"]
        or not result["budgets"]["passed"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
