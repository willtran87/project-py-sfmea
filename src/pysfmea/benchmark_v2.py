"""Repository-clustered, stratified benchmark assessment for Python SFMEA.

Format 2 complements the qualification campaign rather than replacing it.  It
supports failure-chain, timing, citation, traceability, and generated-test
metrics; repository-cluster bootstrap intervals; calibration; multi-rater
agreement; predeclared sample-size evidence; and exact-source regeneration.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import random
import re
from pathlib import Path
from statistics import NormalDist
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import utc_now

BENCHMARK_PROTOCOL_V2_FORMAT = "pysfmea-independent-benchmark-protocol-2"
BENCHMARK_OBSERVATIONS_V2_FORMAT = "pysfmea-independent-benchmark-observations-2"
BENCHMARK_ASSESSMENT_V2_FORMAT = "pysfmea-independent-benchmark-assessment-2"
BENCHMARK_VERIFICATION_V2_FORMAT = "pysfmea-independent-benchmark-verification-2"
DEFAULT_METRICS = (
    "finding_detection",
    "component_inventory",
    "interface_inventory",
    "sequence_edges",
    "propagation_paths",
    "timing_contracts",
    "circuit_breaker_semantics",
    "citation_entailment",
    "requirement_trace",
    "generated_test_effectiveness",
)
REQUALIFICATION_TRIGGERS_V2 = frozenset(
    {
        "scanner_or_rule_change",
        "python_or_dependency_change",
        "benchmark_or_label_change",
        "llm_model_prompt_or_policy_change",
        "intended_environment_change",
        "new_or_changed_known_anomaly",
        "standards_profile_or_citation_change",
        "exchange_or_model_adapter_change",
        "statistical_protocol_change",
    }
)
MAX_REPOSITORIES = 1_000
MAX_METRICS = 100
MAX_BOOTSTRAP_REPLICATES = 20_000
MAX_PREDICTIONS = 1_000_000
MAX_RATING_ITEMS = 1_000_000
MAX_TEXT = 20_000


def seal_benchmark_v2_source(
    source: str | Path,
    destination: str | Path,
    *,
    protocol_source: str | Path | None = None,
) -> Path:
    """Reseal and validate an edited format-2 protocol or observation set.

    Sealing proves integrity only. It does not establish pre-registration,
    independence, label correctness, or approval authority.
    """

    document = load_bounded_json_document(
        source,
        label="benchmark v2 authoring source",
        max_bytes=100_000_000,
        max_depth=150,
        max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("benchmark v2 authoring source must contain an object")
    value = copy.deepcopy(document.value)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    artifact_format = value.get("format")
    if artifact_format == BENCHMARK_PROTOCOL_V2_FORMAT:
        _protocol(value)
    elif artifact_format == BENCHMARK_OBSERVATIONS_V2_FORMAT:
        if protocol_source is None:
            raise ValueError("sealing benchmark observations requires --protocol")
        protocol_document = load_bounded_json_document(
            protocol_source,
            label="benchmark v2 protocol",
            max_bytes=10_000_000,
            max_depth=100,
            max_nodes=500_000,
        )
        if not isinstance(protocol_document.value, dict):
            raise ValueError("benchmark v2 protocol must contain an object")
        _observations(value, _protocol(protocol_document.value))
    else:
        raise ValueError("only benchmark protocol or observations format 2 can be sealed")
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="sealed benchmark v2 authoring source",
    )


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _sealed(value: dict[str, Any], label: str) -> dict[str, Any]:
    claimed = value.get("content_sha256")
    unsigned = copy.deepcopy(value)
    unsigned.pop("content_sha256", None)
    if (
        not isinstance(claimed, str)
        or not re.fullmatch(r"[0-9a-f]{64}", claimed)
        or canonical_json_sha256(unsigned) != claimed
    ):
        raise ValueError(f"{label} content digest does not match")
    return copy.deepcopy(value)


def _protocol(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "format",
        "id",
        "title",
        "pre_registered_at",
        "pre_registration_evidence_ref",
        "governance",
        "design",
        "statistics",
        "power_analysis",
        "requalification_triggers",
        "content_sha256",
    }
    if set(value) != required or value.get("format") != BENCHMARK_PROTOCOL_V2_FORMAT:
        raise ValueError("benchmark protocol fields or format do not match format 2")
    result = _sealed(value, "benchmark protocol")
    for field in ("id", "title", "pre_registered_at", "pre_registration_evidence_ref"):
        _text(result[field], f"protocol {field}")
    governance = result["governance"]
    if not isinstance(governance, dict) or set(governance) != {
        "protocol_owner",
        "label_authority",
        "approval_authority",
        "independence_basis",
    }:
        raise ValueError("benchmark protocol governance is invalid")
    identities = [
        _text(governance[field], f"governance {field}")
        for field in ("protocol_owner", "label_authority", "approval_authority")
    ]
    _text(governance["independence_basis"], "governance independence basis")
    if len({identity.casefold() for identity in identities}) != 3:
        raise ValueError("benchmark governance roles must use distinct identities")
    design = result["design"]
    design_fields = {
        "frozen_before_execution",
        "blinded_holdout",
        "minimum_repositories",
        "selection_method",
        "represented_populations",
        "excluded_populations",
        "strata_fields",
        "minimum_repositories_per_stratum",
    }
    if (
        not isinstance(design, dict)
        or set(design) != design_fields
        or design["frozen_before_execution"] is not True
        or design["blinded_holdout"] is not True
        or not isinstance(design["minimum_repositories"], int)
        or isinstance(design["minimum_repositories"], bool)
        or not 2 <= design["minimum_repositories"] <= MAX_REPOSITORIES
        or not isinstance(design["minimum_repositories_per_stratum"], int)
        or isinstance(design["minimum_repositories_per_stratum"], bool)
        or not 1 <= design["minimum_repositories_per_stratum"] <= MAX_REPOSITORIES
    ):
        raise ValueError("benchmark protocol design is invalid")
    _text(design["selection_method"], "benchmark selection method")
    for field in ("represented_populations", "excluded_populations", "strata_fields"):
        entries = design[field]
        if (
            not isinstance(entries, list)
            or not entries
            or len(entries) > 100
            or len(entries) != len(set(entries))
            or any(not isinstance(item, str) or not item.strip() for item in entries)
        ):
            raise ValueError(f"benchmark design {field} is invalid")
    statistics = result["statistics"]
    if not isinstance(statistics, dict) or set(statistics) != {
        "confidence_level",
        "bootstrap_replicates",
        "bootstrap_seed",
        "metric_thresholds",
        "minimum_krippendorff_alpha",
        "minimum_calibration_samples",
        "maximum_brier_score",
        "maximum_expected_calibration_error",
    }:
        raise ValueError("benchmark protocol statistics are invalid")
    confidence = statistics["confidence_level"]
    replicates = statistics["bootstrap_replicates"]
    thresholds = statistics["metric_thresholds"]
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0.8 <= float(confidence) < 1.0
        or not isinstance(replicates, int)
        or isinstance(replicates, bool)
        or not 200 <= replicates <= MAX_BOOTSTRAP_REPLICATES
        or not isinstance(statistics["bootstrap_seed"], str)
        or not statistics["bootstrap_seed"]
        or not isinstance(thresholds, dict)
        or not thresholds
        or len(thresholds) > MAX_METRICS
    ):
        raise ValueError("benchmark statistical design is invalid")
    for name, threshold in thresholds.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(threshold, dict)
            or set(threshold) != {"minimum_recall_lower", "minimum_precision_lower"}
            or any(
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not 0.0 <= float(item) <= 1.0
                for item in threshold.values()
            )
        ):
            raise ValueError(f"benchmark threshold {name!r} is invalid")
    for field in (
        "minimum_krippendorff_alpha",
        "maximum_brier_score",
        "maximum_expected_calibration_error",
    ):
        item = statistics[field]
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not -1.0 <= float(item) <= 1.0
        ):
            raise ValueError(f"benchmark statistic {field} is invalid")
    calibration_samples = statistics["minimum_calibration_samples"]
    if (
        not isinstance(calibration_samples, int)
        or isinstance(calibration_samples, bool)
        or not 0 <= calibration_samples <= MAX_PREDICTIONS
    ):
        raise ValueError("minimum calibration samples is invalid")
    power = result["power_analysis"]
    if not isinstance(power, dict) or set(power) != {
        "method",
        "alpha",
        "target_power",
        "minimum_effect_size",
        "required_repositories",
        "evidence_ref",
    }:
        raise ValueError("benchmark power analysis is invalid")
    for field in ("method", "evidence_ref"):
        _text(power[field], f"power analysis {field}")
    for field in ("alpha", "target_power", "minimum_effect_size"):
        item = power[field]
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not 0.0 < float(item) < 1.0
        ):
            raise ValueError(f"power analysis {field} is invalid")
    required_repositories = power["required_repositories"]
    if (
        not isinstance(required_repositories, int)
        or isinstance(required_repositories, bool)
        or not 2 <= required_repositories <= MAX_REPOSITORIES
        or required_repositories < design["minimum_repositories"]
    ):
        raise ValueError("power analysis required repositories is invalid")
    if set(result["requalification_triggers"]) != REQUALIFICATION_TRIGGERS_V2:
        raise ValueError("benchmark requalification trigger set is incomplete")
    return result


def _count(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _observations(value: dict[str, Any], protocol: dict[str, Any]) -> dict[str, Any]:
    required = {
        "format",
        "protocol_id",
        "sealed_at",
        "labeling_completed_at",
        "repositories",
        "rating_items",
        "content_sha256",
    }
    if set(value) != required or value.get("format") != BENCHMARK_OBSERVATIONS_V2_FORMAT:
        raise ValueError("benchmark observation fields or format do not match format 2")
    result = _sealed(value, "benchmark observations")
    if result["protocol_id"] != protocol["id"]:
        raise ValueError("benchmark observations do not identify the protocol")
    _text(result["sealed_at"], "observations sealed_at")
    _text(result["labeling_completed_at"], "observations labeling_completed_at")
    repositories = result["repositories"]
    if (
        not isinstance(repositories, list)
        or not repositories
        or len(repositories) > MAX_REPOSITORIES
        or not all(isinstance(repository, dict) for repository in repositories)
    ):
        raise ValueError("benchmark repositories are invalid")
    identifiers: set[str] = set()
    source_references: set[str] = set()
    metric_names = set(protocol["statistics"]["metric_thresholds"])
    strata_fields = set(protocol["design"]["strata_fields"])
    prediction_count = 0
    for repository in repositories:
        if set(repository) != {"id", "source_ref", "strata", "metrics", "predictions"}:
            raise ValueError("benchmark repository fields are invalid")
        identifier = _text(repository["id"], "repository id")
        source_ref = _text(repository["source_ref"], "repository source_ref")
        if identifier in identifiers:
            raise ValueError("benchmark repository identifiers must be unique")
        identifiers.add(identifier)
        if source_ref in source_references:
            raise ValueError(
                "benchmark repository source references must be unique to prevent holdout leakage"
            )
        source_references.add(source_ref)
        strata = repository["strata"]
        if not isinstance(strata, dict) or set(strata) != strata_fields:
            raise ValueError(f"repository {identifier} strata do not match the protocol")
        for field, labels in strata.items():
            if (
                not isinstance(labels, list)
                or not labels
                or len(labels) > 100
                or len(labels) != len(set(labels))
                or any(not isinstance(label, str) or not label.strip() for label in labels)
            ):
                raise ValueError(f"repository {identifier} stratum {field} is invalid")
        metrics = repository["metrics"]
        if not isinstance(metrics, dict) or set(metrics) != metric_names:
            raise ValueError(f"repository {identifier} metrics do not match the protocol")
        for name, metric in metrics.items():
            if not isinstance(metric, dict) or set(metric) != {"true_positive", "false_positive", "false_negative", "true_negative"}:
                raise ValueError(f"repository {identifier} metric {name} is invalid")
            counts = {key: _count(item, f"metric {name} {key}") for key, item in metric.items()}
            if counts["true_positive"] + counts["false_negative"] <= 0:
                raise ValueError(f"repository {identifier} metric {name} has no labeled positives")
            if counts["true_positive"] + counts["false_positive"] <= 0:
                raise ValueError(f"repository {identifier} metric {name} has no produced positives")
        predictions = repository["predictions"]
        if not isinstance(predictions, list):
            raise ValueError(f"repository {identifier} predictions must be an array")
        prediction_count += len(predictions)
        if prediction_count > MAX_PREDICTIONS:
            raise ValueError("benchmark predictions exceed the global limit")
        for prediction in predictions:
            if (
                not isinstance(prediction, dict)
                or set(prediction) != {"confidence", "outcome"}
                or not isinstance(prediction["confidence"], (int, float))
                or isinstance(prediction["confidence"], bool)
                or not 0.0 <= float(prediction["confidence"]) <= 1.0
                or not isinstance(prediction["outcome"], bool)
            ):
                raise ValueError(f"repository {identifier} prediction is invalid")
    rating_items = result["rating_items"]
    if (
        not isinstance(rating_items, list)
        or len(rating_items) > MAX_RATING_ITEMS
        or not rating_items
    ):
        raise ValueError("benchmark rating items are invalid")
    rating_ids: set[str] = set()
    for item in rating_items:
        if not isinstance(item, dict) or set(item) != {"id", "ratings", "adjudication_ref"}:
            raise ValueError("benchmark rating item fields are invalid")
        identifier = _text(item["id"], "rating item id")
        _text(item["adjudication_ref"], "rating adjudication_ref")
        if identifier in rating_ids:
            raise ValueError("benchmark rating item identifiers must be unique")
        rating_ids.add(identifier)
        ratings = item["ratings"]
        if (
            not isinstance(ratings, dict)
            or len(ratings) < 2
            or len(ratings) > 100
            or any(not isinstance(label, bool) for label in ratings.values())
            or any(not isinstance(rater, str) or not rater for rater in ratings)
        ):
            raise ValueError(f"rating item {identifier} requires at least two boolean ratings")
    return result


def load_benchmark_v2_sources(
    protocol_source: str | Path, observations_source: str | Path
) -> tuple[BoundedJsonDocument, dict[str, Any], BoundedJsonDocument, dict[str, Any]]:
    protocol_document = load_bounded_json_document(
        protocol_source,
        label="benchmark protocol v2",
        max_bytes=5_000_000,
        max_depth=60,
        max_nodes=250_000,
    )
    if not isinstance(protocol_document.value, dict):
        raise ValueError("benchmark protocol v2 must contain an object")
    protocol = _protocol(protocol_document.value)
    observations_document = load_bounded_json_document(
        observations_source,
        label="benchmark observations v2",
        max_bytes=100_000_000,
        max_depth=100,
        max_nodes=3_000_000,
    )
    if not isinstance(observations_document.value, dict):
        raise ValueError("benchmark observations v2 must contain an object")
    observations = _observations(observations_document.value, protocol)
    return protocol_document, protocol, observations_document, observations


def _binding(document: BoundedJsonDocument) -> dict[str, Any]:
    return {
        "reference": document.path.name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "canonical_sha256": canonical_json_sha256(document.value),
    }


def _wilson(matched: int, population: int, confidence: float) -> dict[str, Any]:
    estimate = matched / population
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    denominator = 1.0 + z * z / population
    center = (estimate + z * z / (2.0 * population)) / denominator
    margin = z * math.sqrt(
        estimate * (1.0 - estimate) / population
        + z * z / (4.0 * population * population)
    ) / denominator
    return {
        "matched": matched,
        "population": population,
        "estimate": round(estimate, 6),
        "lower": round(max(0.0, center - margin), 6),
        "upper": round(min(1.0, center + margin), 6),
    }


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = probability * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _cluster_interval(
    repositories: list[dict[str, Any]],
    metric_name: str,
    dimension: str,
    *,
    confidence: float,
    replicates: int,
    seed: str,
) -> dict[str, Any]:
    randomizer = random.Random(
        int(hashlib.sha256(f"{seed}:{metric_name}:{dimension}".encode()).hexdigest(), 16)
    )
    estimates: list[float] = []
    for _ in range(replicates):
        selected = [randomizer.choice(repositories) for _ in repositories]
        tp = sum(item["metrics"][metric_name]["true_positive"] for item in selected)
        other_key = "false_negative" if dimension == "recall" else "false_positive"
        population = tp + sum(item["metrics"][metric_name][other_key] for item in selected)
        estimates.append(tp / population)
    alpha = (1.0 - confidence) / 2.0
    return {
        "method": "repository_cluster_percentile_bootstrap",
        "replicates": replicates,
        "lower": round(_quantile(estimates, alpha), 6),
        "upper": round(_quantile(estimates, 1.0 - alpha), 6),
    }


def _metric_result(
    repositories: list[dict[str, Any]],
    name: str,
    *,
    confidence: float,
    replicates: int,
    seed: str,
) -> dict[str, Any]:
    tp = sum(item["metrics"][name]["true_positive"] for item in repositories)
    fp = sum(item["metrics"][name]["false_positive"] for item in repositories)
    fn = sum(item["metrics"][name]["false_negative"] for item in repositories)
    tn = sum(item["metrics"][name]["true_negative"] for item in repositories)
    recall = _wilson(tp, tp + fn, confidence)
    precision = _wilson(tp, tp + fp, confidence)
    recall_cluster = _cluster_interval(
        repositories,
        name,
        "recall",
        confidence=confidence,
        replicates=replicates,
        seed=seed,
    )
    precision_cluster = _cluster_interval(
        repositories,
        name,
        "precision",
        confidence=confidence,
        replicates=replicates,
        seed=seed,
    )
    return {
        "counts": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn},
        "recall": {
            "wilson": recall,
            "cluster_bootstrap": recall_cluster,
            "conservative_lower": min(recall["lower"], recall_cluster["lower"]),
        },
        "precision": {
            "wilson": precision,
            "cluster_bootstrap": precision_cluster,
            "conservative_lower": min(precision["lower"], precision_cluster["lower"]),
        },
    }


def _strata(repositories: list[dict[str, Any]], fields: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in fields:
        labels = sorted(
            {label for repository in repositories for label in repository["strata"][field]}
        )
        result[field] = {
            label: sorted(
                repository["id"]
                for repository in repositories
                if label in repository["strata"][field]
            )
            for label in labels
        }
    return result


def _stratum_metric_results(
    repositories: list[dict[str, Any]],
    strata: dict[str, Any],
    statistics: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bool]]:
    """Measure every declared metric inside every represented stratum."""

    by_id = {str(item["id"]): item for item in repositories}
    results: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    for field, labels in strata.items():
        results[field] = {}
        for label, repository_ids in labels.items():
            selected = [by_id[str(identifier)] for identifier in repository_ids]
            label_metrics: dict[str, Any] = {}
            for name, threshold in statistics["metric_thresholds"].items():
                metric = _metric_result(
                    selected,
                    name,
                    confidence=float(statistics["confidence_level"]),
                    replicates=int(statistics["bootstrap_replicates"]),
                    seed=f"{statistics['bootstrap_seed']}:{field}:{label}",
                )
                label_metrics[name] = metric
                checks[f"{field}:{label}:{name}"] = bool(
                    metric["recall"]["conservative_lower"]
                    >= threshold["minimum_recall_lower"]
                    and metric["precision"]["conservative_lower"]
                    >= threshold["minimum_precision_lower"]
                )
            results[field][label] = {
                "repository_ids": list(repository_ids),
                "metrics": label_metrics,
            }
    return results, checks


def _calibration(repositories: list[dict[str, Any]]) -> dict[str, Any]:
    values = [
        prediction
        for repository in repositories
        for prediction in repository["predictions"]
    ]
    if not values:
        return {"samples": 0, "brier_score": None, "expected_calibration_error": None, "bins": []}
    brier = sum(
        (float(value["confidence"]) - (1.0 if value["outcome"] else 0.0)) ** 2
        for value in values
    ) / len(values)
    bins: list[dict[str, Any]] = []
    weighted_error = 0.0
    for index in range(10):
        lower = index / 10.0
        upper = (index + 1) / 10.0
        selected = [
            value
            for value in values
            if lower <= float(value["confidence"]) <= upper
            and (index == 9 or float(value["confidence"]) < upper)
        ]
        if not selected:
            continue
        mean_confidence = sum(float(value["confidence"]) for value in selected) / len(selected)
        observed = sum(1 for value in selected if value["outcome"]) / len(selected)
        weighted_error += len(selected) / len(values) * abs(mean_confidence - observed)
        bins.append(
            {
                "lower": lower,
                "upper": upper,
                "samples": len(selected),
                "mean_confidence": round(mean_confidence, 6),
                "observed_frequency": round(observed, 6),
            }
        )
    return {
        "samples": len(values),
        "brier_score": round(brier, 6),
        "expected_calibration_error": round(weighted_error, 6),
        "bins": bins,
    }


def _krippendorff_alpha(items: list[dict[str, Any]]) -> dict[str, Any]:
    total_pairs = 0
    observed_disagreements = 0
    category_counts = {False: 0, True: 0}
    raters: set[str] = set()
    for item in items:
        ratings = list(item["ratings"].values())
        raters.update(item["ratings"])
        false_count = ratings.count(False)
        true_count = ratings.count(True)
        total_pairs += len(ratings) * (len(ratings) - 1)
        observed_disagreements += 2 * false_count * true_count
        category_counts[False] += false_count
        category_counts[True] += true_count
    total_ratings = sum(category_counts.values())
    observed = observed_disagreements / total_pairs
    expected = (
        2 * category_counts[False] * category_counts[True]
        / (total_ratings * (total_ratings - 1))
        if total_ratings > 1
        else 0.0
    )
    alpha = 1.0 if expected == 0.0 and observed == 0.0 else 1.0 - observed / expected
    return {
        "method": "krippendorff_alpha_nominal",
        "items": len(items),
        "raters": len(raters),
        "observed_disagreement": round(observed, 6),
        "expected_disagreement": round(expected, 6),
        "alpha": round(alpha, 6),
    }


def benchmark_v2_assessment(
    protocol_source: str | Path,
    observations_source: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    protocol_document, protocol, observations_document, observations = (
        load_benchmark_v2_sources(protocol_source, observations_source)
    )
    repositories = observations["repositories"]
    statistics = protocol["statistics"]
    metrics = {
        name: _metric_result(
            repositories,
            name,
            confidence=float(statistics["confidence_level"]),
            replicates=int(statistics["bootstrap_replicates"]),
            seed=str(statistics["bootstrap_seed"]),
        )
        for name in sorted(statistics["metric_thresholds"])
    }
    strata = _strata(repositories, protocol["design"]["strata_fields"])
    stratum_metrics, stratum_metric_checks = _stratum_metric_results(
        repositories, strata, statistics
    )
    calibration = _calibration(repositories)
    agreement = _krippendorff_alpha(observations["rating_items"])
    metric_checks = {
        name: bool(
            metrics[name]["recall"]["conservative_lower"]
            >= threshold["minimum_recall_lower"]
            and metrics[name]["precision"]["conservative_lower"]
            >= threshold["minimum_precision_lower"]
        )
        for name, threshold in statistics["metric_thresholds"].items()
    }
    minimum_per_stratum = protocol["design"]["minimum_repositories_per_stratum"]
    stratum_checks = {
        f"{field}:{label}": len(repository_ids) >= minimum_per_stratum
        for field, values in strata.items()
        for label, repository_ids in values.items()
    }
    calibration_check = bool(
        calibration["samples"] >= statistics["minimum_calibration_samples"]
        and (
            calibration["samples"] == 0
            or (
                calibration["brier_score"] <= statistics["maximum_brier_score"]
                and calibration["expected_calibration_error"]
                <= statistics["maximum_expected_calibration_error"]
            )
        )
    )
    checks = {
        "minimum_repositories": len(repositories)
        >= protocol["design"]["minimum_repositories"],
        "power_analysis_population": len(repositories)
        >= protocol["power_analysis"]["required_repositories"],
        "all_metric_bounds": all(metric_checks.values()),
        "all_strata_populated": bool(stratum_checks) and all(stratum_checks.values()),
        "all_stratum_metric_bounds": bool(stratum_metric_checks)
        and all(stratum_metric_checks.values()),
        "calibration": calibration_check,
        "multi_rater_agreement": agreement["alpha"]
        >= statistics["minimum_krippendorff_alpha"],
        "frozen_blinded_design": True,
        "independent_governance": True,
        "closed_requalification_policy": set(protocol["requalification_triggers"])
        == REQUALIFICATION_TRIGGERS_V2,
    }
    passed = all(checks.values())
    result: dict[str, Any] = {
        "format": BENCHMARK_ASSESSMENT_V2_FORMAT,
        "generated_at": generated_at or utc_now(),
        "protocol": protocol,
        "bindings": {
            "protocol": _binding(protocol_document),
            "observations": _binding(observations_document),
        },
        "metrics": metrics,
        "strata": strata,
        "stratum_metrics": stratum_metrics,
        "calibration": calibration,
        "reviewer_agreement": agreement,
        "metric_checks": metric_checks,
        "stratum_checks": stratum_checks,
        "stratum_metric_checks": stratum_metric_checks,
        "checks": checks,
        "summary": {
            "passed": passed,
            "status": (
                "eligible_for_authorized_independent_review"
                if passed
                else "benchmark_evidence_incomplete"
            ),
            "repositories": len(repositories),
            "metrics_passing": sum(metric_checks.values()),
            "metrics_required": len(metric_checks),
            "strata_passing": sum(stratum_checks.values()),
            "strata_required": len(stratum_checks),
            "stratum_metrics_passing": sum(stratum_metric_checks.values()),
            "stratum_metrics_required": len(stratum_metric_checks),
            "failed_checks": sorted(name for name, state in checks.items() if not state),
            "failed_metrics": sorted(name for name, state in metric_checks.items() if not state),
            "failed_strata": sorted(name for name, state in stratum_checks.items() if not state),
            "failed_stratum_metrics": sorted(
                name for name, state in stratum_metric_checks.items() if not state
            ),
        },
        "notice": (
            "Passing establishes repository-clustered, stratified evidence eligible for "
            "authorized review. It does not authenticate authorities, prove population "
            "representativeness, qualify the tool, or certify a product."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_benchmark_v2_assessment(
    value: dict[str, Any],
    *,
    protocol_source: str | Path | None = None,
    observations_source: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    expected = {
        "format",
        "generated_at",
        "protocol",
        "bindings",
        "metrics",
        "strata",
        "stratum_metrics",
        "calibration",
        "reviewer_agreement",
        "metric_checks",
        "stratum_checks",
        "stratum_metric_checks",
        "checks",
        "summary",
        "notice",
        "content_sha256",
    }
    structure = bool(
        set(value) == expected
        and value.get("format") == BENCHMARK_ASSESSMENT_V2_FORMAT
        and isinstance(value.get("bindings"), dict)
        and set(value.get("bindings", {})) == {"protocol", "observations"}
    )
    if not structure:
        errors.append("benchmark assessment fields do not match format 2")
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(unsigned) == claimed
    )
    if not integrity:
        errors.append("benchmark assessment content digest does not match")
    semantic = False
    try:
        protocol = _protocol(value["protocol"])
        expected_passed = all(value["checks"].values())
        semantic = bool(
            value["summary"]["passed"] == expected_passed
            and value["summary"]["metrics_passing"]
            == sum(value["metric_checks"].values())
            and value["summary"]["metrics_required"] == len(value["metric_checks"])
            and value["summary"]["strata_passing"]
            == sum(value["stratum_checks"].values())
            and value["summary"]["strata_required"] == len(value["stratum_checks"])
            and value["summary"]["stratum_metrics_passing"]
            == sum(value["stratum_metric_checks"].values())
            and value["summary"]["stratum_metrics_required"]
            == len(value["stratum_metric_checks"])
            and value["summary"]["failed_checks"]
            == sorted(name for name, state in value["checks"].items() if not state)
            and value["summary"]["failed_metrics"]
            == sorted(name for name, state in value["metric_checks"].items() if not state)
            and value["summary"]["failed_strata"]
            == sorted(name for name, state in value["stratum_checks"].items() if not state)
            and value["summary"]["failed_stratum_metrics"]
            == sorted(
                name
                for name, state in value["stratum_metric_checks"].items()
                if not state
            )
            and set(protocol["statistics"]["metric_thresholds"])
            == set(value["metrics"])
        )
    except (KeyError, TypeError, ValueError):
        semantic = False
    if not semantic:
        errors.append("benchmark assessment statistics or summary do not reconcile")
    regeneration: bool | None = None
    if protocol_source is not None or observations_source is not None:
        if protocol_source is None or observations_source is None:
            regeneration = False
            errors.append("protocol and observations must be supplied together")
        else:
            try:
                regenerated = benchmark_v2_assessment(
                    protocol_source,
                    observations_source,
                    generated_at=str(value.get("generated_at", "")),
                )
                regeneration = regenerated == value
            except (OSError, ValueError, json.JSONDecodeError):
                regeneration = False
            if not regeneration:
                errors.append("benchmark assessment does not regenerate from supplied sources")
    valid = bool(
        structure and integrity and semantic and regeneration is not False
    )
    return {
        "format": BENCHMARK_VERIFICATION_V2_FORMAT,
        "valid": valid,
        "passed": bool(valid and value.get("summary", {}).get("passed")),
        "checks": {
            "closed_structure": structure,
            "content_integrity": integrity,
            "semantic_reconciliation": semantic,
            "source_regeneration": regeneration,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification proves exact statistical reconciliation, not independence, label truth, representativeness, qualification, or certification.",
    }


def verify_benchmark_v2_assessment_file(
    source: str | Path,
    *,
    protocol_source: str | Path | None = None,
    observations_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="benchmark assessment v2",
            max_bytes=100_000_000,
            max_depth=150,
            max_nodes=3_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("benchmark assessment v2 must contain an object")
        return {
            "path": str(document.path),
            **verify_benchmark_v2_assessment(
                document.value,
                protocol_source=protocol_source,
                observations_source=observations_source,
            ),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": BENCHMARK_VERIFICATION_V2_FORMAT,
            "valid": False,
            "passed": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "semantic_reconciliation": False,
                "source_regeneration": False
                if protocol_source is not None or observations_source is not None
                else None,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The benchmark assessment v2 could not be safely verified.",
        }


def export_benchmark_v2_assessment(
    value: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_benchmark_v2_assessment(value)
    if not verdict["valid"]:
        raise ValueError("benchmark assessment v2 is internally invalid")
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="benchmark assessment v2",
    )
