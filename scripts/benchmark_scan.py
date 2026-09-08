"""Produce a bounded, content-addressed scanner performance evidence record."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import time
import tracemalloc
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.integrity import canonical_json_sha256
from pysfmea.model import utc_now
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis
from pysfmea.version import __version__

FORMAT = "pysfmea-scan-performance-2"
MAX_REPEATS = 20
MAX_WARMUPS = 10


def _process_peak_rss_bytes() -> int | None:
    """Return process high-water RSS where the standard library exposes it."""

    if os.name == "nt":
        return None
    try:
        import resource

        getrusage = getattr(resource, "getrusage", None)
        rusage_self = getattr(resource, "RUSAGE_SELF", None)
        if not callable(getrusage) or rusage_self is None:
            return None
        value = int(getrusage(rusage_self).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return None
    multiplier = 1 if platform.system() == "Darwin" else 1024
    return value * multiplier if value > 0 else None


def _measure_scan_worker(repository: str) -> dict[str, Any]:
    """Measure one scan in a fresh worker process."""

    telemetry: dict[str, Any] = {}
    tracemalloc.start()
    started = time.perf_counter_ns()
    try:
        analysis = scan_repository(repository, telemetry=telemetry)
        elapsed_ns = time.perf_counter_ns() - started
        _current, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "elapsed_seconds": round(elapsed_ns / 1_000_000_000, 6),
        "peak_traced_bytes": peak_bytes,
        "process_peak_rss_bytes": _process_peak_rss_bytes(),
        "phases_seconds": telemetry.get("phases_seconds", {}),
        "fact_cache": telemetry.get("fact_cache", {}),
        "baseline_id": str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        ),
    }


def _fresh_process_measurements(root: Path, count: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=1, max_tasks_per_child=1) as executor:
        for _index in range(count):
            results.append(executor.submit(_measure_scan_worker, str(root)).result())
    return results


def benchmark_repository(
    repository: str | Path,
    *,
    repeats: int = 3,
    warmups: int = 1,
    process_isolation: bool | None = None,
    reuse_facts: bool = False,
    max_median_seconds: float | None = None,
    max_peak_bytes: int | None = None,
    max_rss_bytes: int | None = None,
    min_source_files: int | None = None,
    min_components: int | None = None,
    min_candidates: int | None = None,
    analysis_output: str | Path | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(repeats, int)
        or isinstance(repeats, bool)
        or not 1 <= repeats <= MAX_REPEATS
    ):
        raise ValueError(f"repeats must be between 1 and {MAX_REPEATS}")
    if (
        not isinstance(warmups, int)
        or isinstance(warmups, bool)
        or not 0 <= warmups <= MAX_WARMUPS
    ):
        raise ValueError(f"warmups must be between 0 and {MAX_WARMUPS}")
    if process_isolation is None:
        process_isolation = not reuse_facts
    if not isinstance(process_isolation, bool):
        raise ValueError("process_isolation must be boolean")
    if process_isolation and reuse_facts:
        raise ValueError(
            "fact reuse requires explicitly selected in-process measurement"
        )
    if max_median_seconds is not None and max_median_seconds <= 0:
        raise ValueError("max_median_seconds must be greater than zero")
    if max_peak_bytes is not None and (
        isinstance(max_peak_bytes, bool) or max_peak_bytes <= 0
    ):
        raise ValueError("max_peak_bytes must be a positive integer")
    for label, value in (
        ("max_rss_bytes", max_rss_bytes),
        ("min_source_files", min_source_files),
        ("min_components", min_components),
        ("min_candidates", min_candidates),
    ):
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
        ):
            raise ValueError(f"{label} must be a positive integer")
    root = Path(repository).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository path is not a directory: {root}")
    runs: list[dict[str, Any]] = []
    baseline_ids: set[str] = set()
    last_analysis: dict[str, Any] = {}
    if process_isolation:
        _fresh_process_measurements(root, warmups)
        measured = _fresh_process_measurements(root, repeats)
        for index, run in enumerate(measured):
            baseline_ids.add(str(run.pop("baseline_id")))
            runs.append({"run": index + 1, **run})
        last_analysis = scan_repository(root)
        baseline_ids.add(
            str(last_analysis.get("project", {}).get("baseline", {}).get("id", ""))
        )
    else:
        fact_cache: dict[str, Any] | None = {} if reuse_facts else None
        for _index in range(warmups):
            scan_repository(root, fact_cache=fact_cache)
        for index in range(repeats):
            telemetry: dict[str, Any] = {}
            tracemalloc.start()
            started = time.perf_counter_ns()
            try:
                analysis = scan_repository(
                    root, telemetry=telemetry, fact_cache=fact_cache
                )
                elapsed_ns = time.perf_counter_ns() - started
                _current, peak_bytes = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            last_analysis = analysis
            baseline_ids.add(
                str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
            )
            runs.append(
                {
                    "run": index + 1,
                    "elapsed_seconds": round(elapsed_ns / 1_000_000_000, 6),
                    "peak_traced_bytes": peak_bytes,
                    "process_peak_rss_bytes": _process_peak_rss_bytes(),
                    "phases_seconds": telemetry.get("phases_seconds", {}),
                    "fact_cache": telemetry.get("fact_cache", {}),
                }
            )
    durations = sorted(float(value["elapsed_seconds"]) for value in runs)
    peaks = [int(value["peak_traced_bytes"]) for value in runs]
    phase_names = sorted(
        {str(name) for run in runs for name in run.get("phases_seconds", {})}
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
    mean_seconds = statistics.fmean(durations)
    standard_deviation_seconds = (
        statistics.stdev(durations) if len(durations) > 1 else 0.0
    )
    median_absolute_deviation_seconds = statistics.median(
        [abs(value - median_seconds) for value in durations]
    )
    cold_start_seconds = float(runs[0]["elapsed_seconds"])
    warm_durations = [
        float(value["elapsed_seconds"])
        for value in runs[1:]
        if not process_isolation and int(value.get("fact_cache", {}).get("hits", 0)) > 0
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
    rss_samples = [
        int(value["process_peak_rss_bytes"])
        for value in runs
        if isinstance(value.get("process_peak_rss_bytes"), int)
    ]
    maximum_rss_bytes = max(rss_samples) if rss_samples else None
    source_files = baseline.get("source_snapshot_files")
    component_count = len(last_analysis.get("components", []))
    candidate_count = len(last_analysis.get("items", []))
    budget_checks = {
        "median_seconds": (
            None if max_median_seconds is None else median_seconds <= max_median_seconds
        ),
        "peak_traced_bytes": (
            None if max_peak_bytes is None else maximum_peak_bytes <= max_peak_bytes
        ),
        "process_peak_rss_bytes": (
            None
            if max_rss_bytes is None
            else maximum_rss_bytes is not None and maximum_rss_bytes <= max_rss_bytes
        ),
        "minimum_source_files": (
            None
            if min_source_files is None
            else isinstance(source_files, int) and source_files >= min_source_files
        ),
        "minimum_components": (
            None if min_components is None else component_count >= min_components
        ),
        "minimum_candidates": (
            None if min_candidates is None else candidate_count >= min_candidates
        ),
    }
    budgets_passed = all(value is not False for value in budget_checks.values())
    result: dict[str, Any] = {
        "format": FORMAT,
        "generated_at": utc_now(),
        "tool": {"name": "PySFMEA", "version": __version__},
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
        },
        "measurement_policy": {
            "clock": "time.perf_counter_ns",
            "memory": "tracemalloc peak with optional process high-water RSS",
            "warmup_runs": warmups,
            "process_model": "fresh spawned worker per measured scan"
            if process_isolation
            else "repeated scans in one interpreter",
            "process_isolation": process_isolation,
            "calibration": "fixed governed repeat and warmup counts; compare only like-for-like policies",
            "outlier_policy": "retain every finite measured run; report median, MAD, standard deviation, coefficient of variation, and extrema",
            "network_required": False,
            "historical_comparison_requires_matching_environment": True,
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
            "components": component_count,
            "candidates": candidate_count,
        },
        "runs": runs,
        "budgets": {
            "configured": {
                "max_median_seconds": max_median_seconds,
                "max_peak_traced_bytes": max_peak_bytes,
                "max_process_peak_rss_bytes": max_rss_bytes,
                "minimum_source_files": min_source_files,
                "minimum_components": min_components,
                "minimum_candidates": min_candidates,
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
            "mean_seconds": round(mean_seconds, 6),
            "standard_deviation_seconds": round(standard_deviation_seconds, 6),
            "median_absolute_deviation_seconds": round(
                median_absolute_deviation_seconds, 6
            ),
            "coefficient_of_variation_percent": (
                round(standard_deviation_seconds / mean_seconds * 100, 3)
                if mean_seconds > 0
                else 0.0
            ),
            "p95_seconds": durations[p95_index],
            "minimum_seconds": durations[0],
            "maximum_seconds": durations[-1],
            "maximum_peak_traced_bytes": maximum_peak_bytes,
            "maximum_process_peak_rss_bytes": maximum_rss_bytes,
            "phase_medians_seconds": {
                name: round(statistics.median(values), 6)
                for name, values in phase_samples.items()
            },
            "phase_maximums_seconds": {
                name: round(max(values), 6) for name, values in phase_samples.items()
            },
        },
        "notice": (
            "This record characterizes one machine, repository, configuration, and Python "
            "runtime. tracemalloc measures traced Python allocations. Process RSS is a platform "
            "high-water mark and may include allocations retained from earlier repeats; "
            "thresholds require an independently approved environment-specific baseline."
        ),
    }
    if analysis_output is not None:
        destination = Path(analysis_output).expanduser().resolve()
        save_analysis(destination, last_analysis, compact=True)
        digest = hashlib.sha256()
        with destination.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        result["retained_analysis"] = {
            "path": str(destination),
            "bytes": destination.stat().st_size,
            "sha256": digest.hexdigest(),
            "outside_timed_scan": True,
        }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument(
        "--in-process",
        action="store_true",
        help="measure repeated scans in one interpreter; required for --reuse-facts",
    )
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
    parser.add_argument(
        "--max-rss-bytes",
        type=int,
        help="fail when the supported process RSS high-water mark exceeds this budget",
    )
    parser.add_argument("--min-source-files", type=int)
    parser.add_argument("--min-components", type=int)
    parser.add_argument("--min-candidates", type=int)
    parser.add_argument(
        "--analysis-output",
        help="retain the final governed analysis outside the timed scan interval",
    )
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    result = benchmark_repository(
        args.repository,
        repeats=args.repeats,
        warmups=args.warmups,
        process_isolation=not args.in_process,
        reuse_facts=args.reuse_facts,
        max_median_seconds=args.max_median_seconds,
        max_peak_bytes=args.max_peak_bytes,
        max_rss_bytes=args.max_rss_bytes,
        min_source_files=args.min_source_files,
        min_components=args.min_components,
        min_candidates=args.min_candidates,
        analysis_output=args.analysis_output,
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
        not result["repository"]["stable_baseline"] or not result["budgets"]["passed"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
