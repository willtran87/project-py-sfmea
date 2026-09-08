"""Case-level joins between audited populations and scored benchmark observations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .benchmark_case_inventory import (
    BENCHMARK_CASE_INVENTORY_FORMAT,
    verify_benchmark_case_inventory,
)
from .operational_evidence import read_evidence


def population_score_join(
    base: Path,
    record: dict[str, Any],
    suite: dict[str, Any],
    audit: dict[str, Any],
    observations: list[dict[str, Any]],
) -> bool:
    try:
        population_path = Path(record["population_path"])
        if not population_path.is_absolute():
            population_path = base / population_path
        population = read_evidence(base, record["population_path"])
        if population["format"] == BENCHMARK_CASE_INVENTORY_FORMAT:
            manifest = population_path.parent / population["source"]["name"]
            if not verify_benchmark_case_inventory(population, source=manifest)[
                "checks"
            ]["exact_source_replay"]:
                return False
        execution = read_evidence(base, record["execution_path"])
        if execution["format"] != "pysfmea-benchmark-case-results-1":
            return False
        if (
            execution["suite_id"],
            execution["suite_revision"],
            execution["source_sha256"],
        ) != (suite["id"], suite["version"], suite["source_sha256"]):
            return False
        if audit["suite"]["revision"] != suite["version"]:
            return False
        dispositions = {i["case_id"]: i["disposition"] for i in audit["items"]}
        cases = execution["cases"]
        if len({c["case_id"] for c in cases}) != len(cases) or {
            c["case_id"] for c in cases
        } != set(dispositions):
            return False
        repositories: dict[str, dict[str, dict[str, int]]] = {}
        for case in cases:
            rid = case["repository_id"]
            if rid not in suite["repository_ids"] or type(case["executed"]) is not bool:
                return False
            if dispositions[case["case_id"]] == "excluded":
                if case["metrics"]:
                    return False
                continue
            if (
                dispositions[case["case_id"]] != "accepted"
                or not case["executed"]
                or not case["metrics"]
            ):
                return False
            metrics = repositories.setdefault(rid, {})
            for name, observation in case["metrics"].items():
                if set(observation) != {"expected", "predicted"} or any(
                    type(v) is not bool for v in observation.values()
                ):
                    return False
                counts = metrics.setdefault(
                    name,
                    {
                        "true_positive": 0,
                        "false_positive": 0,
                        "false_negative": 0,
                        "true_negative": 0,
                    },
                )
                expected, predicted = observation["expected"], observation["predicted"]
                key = ("true_" if expected == predicted else "false_") + (
                    "positive" if predicted else "negative"
                )
                counts[key] += 1
        scored = [
            r
            for document in observations
            for r in document["repositories"]
            if r["id"] in suite["repository_ids"]
        ]
        if len({r["id"] for r in scored}) != len(scored):
            return False
        return repositories == {r["id"]: r["metrics"] for r in scored} and set(
            repositories
        ) == set(suite["repository_ids"])
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        return False
