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


def benchmark_repository(repository: str | Path, *, repeats: int = 3) -> dict[str, Any]:
    if not isinstance(repeats, int) or isinstance(repeats, bool) or not 1 <= repeats <= MAX_REPEATS:
        raise ValueError(f"repeats must be between 1 and {MAX_REPEATS}")
    root = Path(repository).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository path is not a directory: {root}")
    runs: list[dict[str, int | float]] = []
    baseline_ids: set[str] = set()
    last_analysis: dict[str, Any] = {}
    for index in range(repeats):
        tracemalloc.start()
        started = time.perf_counter_ns()
        try:
            analysis = scan_repository(root)
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
            }
        )
    durations = sorted(float(value["elapsed_seconds"]) for value in runs)
    peaks = [int(value["peak_traced_bytes"]) for value in runs]
    inventory = last_analysis.get("repository_inventory", {})
    summary = inventory.get("summary", {}) if isinstance(inventory, dict) else {}
    p95_index = max(0, math.ceil(len(durations) * 0.95) - 1)
    stable = len(baseline_ids) == 1 and "" not in baseline_ids
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
            "inventory_bytes": summary.get("bytes"),
            "components": len(last_analysis.get("components", [])),
            "candidates": len(last_analysis.get("items", [])),
        },
        "runs": runs,
        "summary": {
            "repeats": repeats,
            "median_seconds": round(statistics.median(durations), 6),
            "p95_seconds": durations[p95_index],
            "minimum_seconds": durations[0],
            "maximum_seconds": durations[-1],
            "maximum_peak_traced_bytes": max(peaks),
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
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    result = benchmark_repository(args.repository, repeats=args.repeats)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        destination = atomic_publish_text(
            args.output, rendered, label="scanner performance evidence"
        )
        print(destination)
    else:
        sys.stdout.write(rendered)
    return int(not result["repository"]["stable_baseline"])


if __name__ == "__main__":
    raise SystemExit(main())
