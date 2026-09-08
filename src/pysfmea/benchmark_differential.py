"""Case-paired differential benchmark evidence with disagreement adjudication."""

from __future__ import annotations

import itertools
import math
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .industry_benchmarks import BENCHMARK_SUITES
from .model import utc_now

DIFFERENTIAL_SOURCE_FORMAT = "pysfmea-benchmark-differential-source-1"
DIFFERENTIAL_ASSESSMENT_FORMAT = "pysfmea-benchmark-differential-assessment-1"
DIFFERENTIAL_VERIFICATION_FORMAT = "pysfmea-benchmark-differential-verification-1"
SUITE_IDS = {item["id"] for item in BENCHMARK_SUITES}
LABELS = {"positive", "negative"}
MAX_CASES = 1_000_000


def benchmark_differential_template(*, authority: str) -> dict[str, Any]:
    """Create a closed authoring template; empty evidence deliberately cannot pass."""

    return seal(
        {
            "format": DIFFERENTIAL_SOURCE_FORMAT,
            "generated_at": utc_now(),
            "authority": {
                "comparison_owner": bounded_text(authority, "comparison authority"),
                "label_authority": "replace-with-independent-label-authority",
                "adjudication_authority": "replace-with-independent-adjudicator",
                "independence_basis": "replace-with-organizational-and-technical-separation",
            },
            "suite": {
                "id": "pysfmea-semantic-corpus",
                "revision": "unassigned",
                "snapshot_sha256": "0" * 64,
            },
            "policy": {
                "minimum_tools": 2,
                "significance_alpha": 0.05,
                "require_all_disagreements_adjudicated": True,
            },
            "tools": [],
            "cases": [],
            "limitations": [],
            "claim_boundary": (
                "This case-paired comparison quantifies tool disagreement and queues "
                "adjudication. Agreement is not ground truth, statistical significance "
                "is not practical significance, and passing is not tool qualification."
            ),
        }
    )


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value != "0" * 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _source(value: dict[str, Any]) -> dict[str, Any]:
    checked = verify_seal(
        value,
        label="benchmark differential source",
        format_value=DIFFERENTIAL_SOURCE_FORMAT,
    )
    expected = {
        "format",
        "generated_at",
        "authority",
        "suite",
        "policy",
        "tools",
        "cases",
        "limitations",
        "claim_boundary",
        "content_sha256",
    }
    if set(checked) != expected:
        raise ValueError("benchmark differential source fields are invalid")
    authority = checked["authority"]
    if not isinstance(authority, dict) or set(authority) != {
        "comparison_owner",
        "label_authority",
        "adjudication_authority",
        "independence_basis",
    }:
        raise ValueError("benchmark differential authority fields are invalid")
    for name, item in authority.items():
        bounded_text(item, f"benchmark differential {name}")
    suite = checked["suite"]
    if not isinstance(suite, dict) or set(suite) != {
        "id",
        "revision",
        "snapshot_sha256",
    }:
        raise ValueError("benchmark differential suite fields are invalid")
    if suite["id"] not in SUITE_IDS:
        raise ValueError("benchmark differential suite is not cataloged")
    bounded_text(suite["revision"], "benchmark differential suite revision")
    if (
        not isinstance(suite["snapshot_sha256"], str)
        or len(suite["snapshot_sha256"]) != 64
    ):
        raise ValueError("benchmark differential suite digest is invalid")
    policy = checked["policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "minimum_tools",
        "significance_alpha",
        "require_all_disagreements_adjudicated",
    }:
        raise ValueError("benchmark differential policy fields are invalid")
    if (
        not isinstance(policy["minimum_tools"], int)
        or isinstance(policy["minimum_tools"], bool)
        or not 2 <= policy["minimum_tools"] <= 100
        or not isinstance(policy["significance_alpha"], (int, float))
        or isinstance(policy["significance_alpha"], bool)
        or not 0.0 < float(policy["significance_alpha"]) < 1.0
        or type(policy["require_all_disagreements_adjudicated"]) is not bool
    ):
        raise ValueError("benchmark differential policy is invalid")
    tools = checked["tools"]
    if not isinstance(tools, list) or len(tools) > 100:
        raise ValueError("benchmark differential tools are invalid")
    tool_ids: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {
            "id",
            "version",
            "runner",
            "source_sha256",
            "evidence_ref",
        }:
            raise ValueError("benchmark differential tool fields are invalid")
        tool_ids.append(bounded_text(tool["id"], "benchmark differential tool id"))
        for name in ("version", "runner", "evidence_ref"):
            bounded_text(tool[name], f"benchmark differential tool {name}")
        if (
            not isinstance(tool["source_sha256"], str)
            or len(tool["source_sha256"]) != 64
        ):
            raise ValueError("benchmark differential tool digest is invalid")
    if len(tool_ids) != len(set(tool_ids)):
        raise ValueError("benchmark differential tool ids must be unique")
    cases = checked["cases"]
    if not isinstance(cases, list) or len(cases) > MAX_CASES:
        raise ValueError("benchmark differential case population is invalid")
    case_ids: list[str] = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "case_id",
            "expected_label",
            "label_evidence_ref",
            "observations",
            "adjudication",
        }:
            raise ValueError("benchmark differential case fields are invalid")
        case_ids.append(bounded_text(case["case_id"], "benchmark differential case id"))
        if case["expected_label"] not in LABELS:
            raise ValueError("benchmark differential expected label is invalid")
        bounded_text(
            case["label_evidence_ref"], "benchmark differential label evidence"
        )
        observations = case["observations"]
        if not isinstance(observations, list) or {
            item.get("tool_id") for item in observations if isinstance(item, dict)
        } != set(tool_ids):
            raise ValueError(
                "each differential case must contain every declared tool exactly once"
            )
        if len(observations) != len(tool_ids):
            raise ValueError("differential case contains duplicate tool observations")
        for observation in observations:
            if (
                not isinstance(observation, dict)
                or set(observation) != {"tool_id", "predicted_label", "evidence_ref"}
                or observation["predicted_label"] not in LABELS
            ):
                raise ValueError("benchmark differential observation is invalid")
            bounded_text(
                observation["evidence_ref"], "differential observation evidence"
            )
        adjudication = case["adjudication"]
        if (
            not isinstance(adjudication, dict)
            or set(adjudication) != {"status", "disposition", "evidence_ref"}
            or adjudication["status"] not in {"not_required", "pending", "completed"}
        ):
            raise ValueError("benchmark differential adjudication is invalid")
        if not isinstance(adjudication["disposition"], str) or not isinstance(
            adjudication["evidence_ref"], str
        ):
            raise ValueError("benchmark differential adjudication text is invalid")
        predictions = {item["predicted_label"] for item in observations}
        disagreement = len(predictions) > 1
        if disagreement and adjudication["status"] == "not_required":
            raise ValueError("tool disagreement cannot be marked not required")
        if not disagreement and adjudication["status"] != "not_required":
            raise ValueError("agreement must be marked not required")
        if adjudication["status"] == "completed" and (
            not adjudication["disposition"].strip()
            or not adjudication["evidence_ref"].strip()
        ):
            raise ValueError("completed adjudication requires disposition and evidence")
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("benchmark differential case ids must be unique")
    if not isinstance(checked["limitations"], list) or any(
        not isinstance(item, str) for item in checked["limitations"]
    ):
        raise ValueError("benchmark differential limitations are invalid")
    bounded_text(checked["claim_boundary"], "benchmark differential claim boundary")
    return checked


def seal_benchmark_differential_source(
    source: str | Path, destination: str | Path
) -> Path:
    value = load_json(source, label="benchmark differential source")
    value.pop("content_sha256", None)
    result = seal(value)
    _source(result)
    return publish_json(result, destination)


def _binomial_two_sided(successes: int, trials: int) -> float:
    if trials == 0:
        return 1.0
    tail = sum(math.comb(trials, index) for index in range(successes + 1)) / (2**trials)
    return float(round(min(1.0, 2.0 * tail), 12))


def _derive(source: dict[str, Any]) -> dict[str, Any]:
    tool_ids = [item["id"] for item in source["tools"]]
    counts = {
        tool_id: {
            "true_positive": 0,
            "false_positive": 0,
            "false_negative": 0,
            "true_negative": 0,
        }
        for tool_id in tool_ids
    }
    predictions: dict[str, dict[str, str]] = {}
    queue: list[dict[str, Any]] = []
    for case in source["cases"]:
        observed = {
            item["tool_id"]: item["predicted_label"] for item in case["observations"]
        }
        predictions[case["case_id"]] = observed
        for tool_id, predicted in observed.items():
            expected = case["expected_label"]
            key = (
                "true_positive"
                if expected == predicted == "positive"
                else "true_negative"
                if expected == predicted == "negative"
                else "false_positive"
                if predicted == "positive"
                else "false_negative"
            )
            counts[tool_id][key] += 1
        if len(set(observed.values())) > 1:
            queue.append(
                {
                    "case_id": case["case_id"],
                    "expected_label": case["expected_label"],
                    "predictions": observed,
                    "status": case["adjudication"]["status"],
                    "disposition": case["adjudication"]["disposition"],
                    "evidence_ref": case["adjudication"]["evidence_ref"],
                }
            )
    tool_results = []
    for tool_id in tool_ids:
        item = counts[tool_id]
        tp, fp, fn, tn = (
            item[name]
            for name in (
                "true_positive",
                "false_positive",
                "false_negative",
                "true_negative",
            )
        )
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        accuracy = (tp + tn) / len(source["cases"]) if source["cases"] else None
        tool_results.append(
            {
                "tool_id": tool_id,
                **item,
                "precision": None if precision is None else round(precision, 6),
                "recall": None if recall is None else round(recall, 6),
                "accuracy": None if accuracy is None else round(accuracy, 6),
            }
        )
    pairwise = []
    for left, right in itertools.combinations(tool_ids, 2):
        left_only = right_only = agreements = 0
        for case in source["cases"]:
            expected = case["expected_label"]
            left_ok = predictions[case["case_id"]][left] == expected
            right_ok = predictions[case["case_id"]][right] == expected
            if left_ok and not right_ok:
                left_only += 1
            elif right_ok and not left_ok:
                right_only += 1
            else:
                agreements += 1
        pairwise.append(
            {
                "left_tool": left,
                "right_tool": right,
                "agreements": agreements,
                "left_only_correct": left_only,
                "right_only_correct": right_only,
                "discordant": left_only + right_only,
                "mcnemar_exact_p": _binomial_two_sided(
                    min(left_only, right_only), left_only + right_only
                ),
            }
        )
    roles = [
        source["authority"][name].casefold()
        for name in ("comparison_owner", "label_authority", "adjudication_authority")
    ]
    checks = {
        "cataloged_pinned_suite": source["suite"]["id"] in SUITE_IDS
        and source["suite"]["revision"] != "unassigned"
        and _digest(source["suite"]["snapshot_sha256"]),
        "independent_authorities": len(set(roles)) == 3
        and not any(item.startswith("replace-") for item in roles)
        and not source["authority"]["independence_basis"].startswith("replace-"),
        "minimum_tools": len(tool_ids) >= source["policy"]["minimum_tools"],
        "case_population": bool(source["cases"]),
        "tool_provenance": all(
            item["version"] != "unassigned"
            and _digest(item["source_sha256"])
            and item["evidence_ref"] != "unassigned"
            for item in source["tools"]
        ),
        "case_evidence": all(
            case["label_evidence_ref"] != "unassigned"
            and all(
                item["evidence_ref"] != "unassigned" for item in case["observations"]
            )
            for case in source["cases"]
        ),
        "disagreements_adjudicated": not source["policy"][
            "require_all_disagreements_adjudicated"
        ]
        or all(item["status"] == "completed" for item in queue),
    }
    return {
        "tool_results": tool_results,
        "pairwise_comparisons": pairwise,
        "disagreement_queue": queue,
        "checks": checks,
        "summary": {
            "passed": all(checks.values()),
            "status": "eligible_for_validation_portfolio"
            if all(checks.values())
            else "differential_evidence_incomplete",
            "tools": len(tool_ids),
            "cases": len(source["cases"]),
            "pairwise_comparisons": len(pairwise),
            "disagreements": len(queue),
            "pending_adjudications": sum(
                item["status"] != "completed" for item in queue
            ),
            "significant_pairwise_differences": sum(
                item["mcnemar_exact_p"] < float(source["policy"]["significance_alpha"])
                for item in pairwise
            ),
            "failed_checks": sorted(
                name for name, passed in checks.items() if not passed
            ),
        },
    }


def assess_benchmark_differential(source: str | Path) -> dict[str, Any]:
    value = _source(load_json(source, label="benchmark differential source"))
    derived = _derive(value)
    return seal(
        {
            "format": DIFFERENTIAL_ASSESSMENT_FORMAT,
            "generated_at": utc_now(),
            "source_sha256": value["content_sha256"],
            "suite": value["suite"],
            "policy": value["policy"],
            **derived,
            "claim_boundary": value["claim_boundary"],
        }
    )


def verify_benchmark_differential(
    value: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="benchmark differential assessment",
            format_value=DIFFERENTIAL_ASSESSMENT_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    required = {
        "format",
        "generated_at",
        "source_sha256",
        "suite",
        "policy",
        "tool_results",
        "pairwise_comparisons",
        "disagreement_queue",
        "checks",
        "summary",
        "claim_boundary",
        "content_sha256",
    }
    structure = bool(
        isinstance(checked, dict)
        and set(checked) == required
        and isinstance(checked.get("checks"), dict)
        and isinstance(checked.get("summary"), dict)
        and checked.get("summary", {}).get("passed")
        == all(checked.get("checks", {}).values())
    )
    if not structure:
        errors.append("benchmark differential assessment structure does not reconcile")
    replay: bool | None = None
    if source is not None:
        try:
            source_value = _source(
                load_json(source, label="benchmark differential source")
            )
            expected = assess_benchmark_differential(source)
            replay = bool(
                source_value["content_sha256"] == checked["source_sha256"]
                and {
                    name: expected[name]
                    for name in (
                        "source_sha256",
                        "suite",
                        "policy",
                        "tool_results",
                        "pairwise_comparisons",
                        "disagreement_queue",
                        "checks",
                        "summary",
                        "claim_boundary",
                    )
                }
                == {
                    name: checked[name]
                    for name in (
                        "source_sha256",
                        "suite",
                        "policy",
                        "tool_results",
                        "pairwise_comparisons",
                        "disagreement_queue",
                        "checks",
                        "summary",
                        "claim_boundary",
                    )
                }
            )
        except (KeyError, OSError, TypeError, ValueError):
            replay = False
        if not replay:
            errors.append("benchmark differential assessment does not exactly replay")
    valid = integrity and structure and replay is not False
    passed = bool(valid and checked.get("summary", {}).get("passed"))
    return seal(
        {
            "format": DIFFERENTIAL_VERIFICATION_FORMAT,
            "valid": valid,
            "passed": passed,
            "eligible_for_validation_portfolio": bool(passed and replay is True),
            "checks": {
                "content_integrity": integrity,
                "semantic_reconciliation": structure,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": "Eligibility requires exact source replay and completed disagreement adjudication; it is not qualification or certification.",
        }
    )


def export_benchmark_differential(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if value.get("format") == DIFFERENTIAL_SOURCE_FORMAT:
        _source(value)
    elif not verify_benchmark_differential(value)["valid"]:
        raise ValueError("benchmark differential assessment is invalid")
    return publish_json(value, destination)


def verify_benchmark_differential_file(
    source: str | Path, *, evidence_source: str | Path | None = None
) -> dict[str, Any]:
    try:
        return verify_benchmark_differential(
            load_json(source, label="benchmark differential assessment"),
            source=evidence_source,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": DIFFERENTIAL_VERIFICATION_FORMAT,
                "valid": False,
                "passed": False,
                "eligible_for_validation_portfolio": False,
                "checks": {
                    "content_integrity": False,
                    "semantic_reconciliation": False,
                    "exact_source_replay": False
                    if evidence_source is not None
                    else None,
                },
                "errors": [str(exc)],
                "notice": "Benchmark differential verification failed closed.",
            }
        )
