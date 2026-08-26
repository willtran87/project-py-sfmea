"""Convert bounded mutmut 3 metadata into an enforceable mutation-score ratchet."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from pysfmea.file_publication import atomic_publish_text

FORMAT = "pysfmea-mutation-quality-2"
POLICY_FORMAT = "pysfmea-mutation-ratchet-policy-2"
MAX_METADATA_BYTES = 50_000_000
MAX_METADATA_FILES = 10_000
MAX_TESTCASES = 1_000_000

KILLED_EXIT_CODES = {1, 3, 37}
SURVIVED_EXIT_CODES = {0}
SKIPPED_EXIT_CODES = {34}


def _load_policy(source: str | Path) -> dict[str, Any]:
    path = Path(source)
    raw = path.read_bytes()
    if len(raw) > 1_000_000:
        raise ValueError("mutation policy exceeds the 1 MB limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("mutation policy is not valid UTF-8 JSON") from exc
    required = {
        "format",
        "selectors",
        "minimum_mutants",
        "minimum_score",
        "maximum_survived",
        "maximum_invalid",
        "maximum_skipped",
        "allowed_runner_exit_codes",
        "groups",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("mutation policy fields do not match format 2")
    if value.get("format") != POLICY_FORMAT:
        raise ValueError("mutation policy format is unsupported")
    selectors = value.get("selectors")
    if (
        not isinstance(selectors, list)
        or not selectors
        or len(selectors) > 100
        or not all(isinstance(item, str) and item.strip() for item in selectors)
    ):
        raise ValueError("mutation selectors must be a bounded non-empty string array")
    for field in (
        "minimum_mutants",
        "maximum_survived",
        "maximum_invalid",
        "maximum_skipped",
    ):
        current = value.get(field)
        if not isinstance(current, int) or isinstance(current, bool) or current < 0:
            raise ValueError(f"mutation policy {field} must be a non-negative integer")
    score = value.get("minimum_score")
    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not 0 <= float(score) <= 1
    ):
        raise ValueError("mutation policy minimum_score must be between zero and one")
    exit_codes = value.get("allowed_runner_exit_codes")
    if (
        not isinstance(exit_codes, list)
        or not exit_codes
        or len(exit_codes) > 16
        or not all(
            isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
            for item in exit_codes
        )
    ):
        raise ValueError("allowed runner exit codes must be a bounded integer array")
    groups = value.get("groups")
    group_fields = {
        "id",
        "selectors",
        "minimum_mutants",
        "minimum_score",
        "maximum_survived",
        "maximum_invalid",
        "maximum_skipped",
    }
    if not isinstance(groups, list) or not groups or len(groups) > 100:
        raise ValueError("mutation groups must be a bounded non-empty array")
    group_ids: set[str] = set()
    partition_selectors: list[str] = []
    for group in groups:
        if not isinstance(group, dict) or set(group) != group_fields:
            raise ValueError("mutation group fields do not match format 2")
        group_id = group.get("id")
        if (
            not isinstance(group_id, str)
            or not group_id.strip()
            or group_id in group_ids
        ):
            raise ValueError("mutation group ids must be unique non-empty strings")
        group_ids.add(group_id)
        group_selectors = group.get("selectors")
        if (
            not isinstance(group_selectors, list)
            or not group_selectors
            or len(group_selectors) > 20
            or not all(
                isinstance(item, str) and item.strip() for item in group_selectors
            )
        ):
            raise ValueError("mutation group selectors are invalid")
        partition_selectors.extend(group_selectors)
        for field in (
            "minimum_mutants",
            "maximum_survived",
            "maximum_invalid",
            "maximum_skipped",
        ):
            current = group.get(field)
            if not isinstance(current, int) or isinstance(current, bool) or current < 0:
                raise ValueError(f"mutation group {field} must be non-negative")
        group_score = group.get("minimum_score")
        if (
            not isinstance(group_score, (int, float))
            or isinstance(group_score, bool)
            or not 0 <= float(group_score) <= 1
        ):
            raise ValueError("mutation group minimum_score must be between zero and one")
    if len(partition_selectors) != len(set(partition_selectors)):
        raise ValueError("mutation group selectors must not be duplicated")
    if sorted(partition_selectors) != sorted(selectors):
        raise ValueError("mutation groups must partition the aggregate selectors")
    return value


def _empty_counts() -> dict[str, int]:
    return {"killed": 0, "survived": 0, "invalid": 0, "skipped": 0}


def _score_and_checks(
    counts: dict[str, int], policy: dict[str, Any]
) -> tuple[int, int, float, dict[str, bool]]:
    total = sum(counts.values())
    scored = counts["killed"] + counts["survived"]
    score = round(counts["killed"] / scored, 6) if scored else 0.0
    checks = {
        "minimum_mutants": total >= int(policy["minimum_mutants"]),
        "minimum_score": score >= float(policy["minimum_score"]),
        "maximum_survived": counts["survived"] <= int(policy["maximum_survived"]),
        "maximum_invalid": counts["invalid"] <= int(policy["maximum_invalid"]),
        "maximum_skipped": counts["skipped"] <= int(policy["maximum_skipped"]),
    }
    return total, scored, score, checks


def mutation_quality_record(
    metadata_source: str | Path,
    policy_source: str | Path,
    *,
    runner_exit_code: int,
) -> dict[str, Any]:
    """Recompute focused mutation quality from bounded mutmut 3 metadata."""

    if not isinstance(runner_exit_code, int) or isinstance(runner_exit_code, bool):
        raise ValueError("runner exit code must be an integer")
    policy = _load_policy(policy_source)
    source = Path(metadata_source)
    metadata_files = sorted(source.rglob("*.meta")) if source.is_dir() else [source]
    if not metadata_files or len(metadata_files) > MAX_METADATA_FILES:
        raise ValueError("mutation metadata file population is empty or exceeds the limit")
    counts = _empty_counts()
    examples: dict[str, list[str]] = {key: [] for key in counts}
    group_counts = {str(group["id"]): _empty_counts() for group in policy["groups"]}
    matched_identities: set[str] = set()
    bindings: list[dict[str, Any]] = []
    consumed_bytes = 0
    for metadata_file in metadata_files:
        raw = metadata_file.read_bytes()
        consumed_bytes += len(raw)
        if consumed_bytes > MAX_METADATA_BYTES:
            raise ValueError("mutation metadata exceeds the 50 MB aggregate limit")
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"mutation metadata is invalid: {metadata_file}") from exc
        exit_codes = document.get("exit_code_by_key") if isinstance(document, dict) else None
        if not isinstance(exit_codes, dict):
            raise ValueError(f"mutation metadata lacks exit_code_by_key: {metadata_file}")
        bindings.append(
            {
                "path": str(metadata_file),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        for raw_identity, exit_code in exit_codes.items():
            if not isinstance(raw_identity, str):
                continue
            matching_groups = [
                group
                for group in policy["groups"]
                if any(
                    fnmatch.fnmatchcase(raw_identity, selector)
                    for selector in group["selectors"]
                )
            ]
            if not matching_groups:
                continue
            if len(matching_groups) != 1:
                raise ValueError(f"mutation testcase belongs to multiple groups: {raw_identity}")
            identity = raw_identity.strip()
            if identity in matched_identities:
                raise ValueError(f"duplicate focused mutation testcase: {identity}")
            if len(matched_identities) >= MAX_TESTCASES:
                raise ValueError("mutation metadata exceeds the mutant limit")
            matched_identities.add(identity)
            if exit_code in KILLED_EXIT_CODES:
                status = "killed"
            elif exit_code in SURVIVED_EXIT_CODES:
                status = "survived"
            elif exit_code in SKIPPED_EXIT_CODES:
                status = "skipped"
            else:
                status = "invalid"
            counts[status] += 1
            group_counts[str(matching_groups[0]["id"])][status] += 1
            if len(examples[status]) < 25:
                examples[status].append(identity)

    total, scored, score, checks = _score_and_checks(counts, policy)
    group_results: list[dict[str, Any]] = []
    for group in policy["groups"]:
        current_counts = group_counts[str(group["id"])]
        group_total, group_scored, group_score, group_checks = _score_and_checks(
            current_counts, group
        )
        group_results.append(
            {
                "id": group["id"],
                "selectors": group["selectors"],
                "counts": {
                    **current_counts,
                    "total": group_total,
                    "scored": group_scored,
                },
                "mutation_score": group_score,
                "checks": group_checks,
                "passed": all(group_checks.values()),
            }
        )
    checks["all_groups"] = all(group["passed"] for group in group_results)
    checks["runner_exit_code"] = runner_exit_code in policy["allowed_runner_exit_codes"]
    passed = all(checks.values())
    return {
        "format": FORMAT,
        "authority": "focused_mutation_score_non_regression_not_complete_test_adequacy",
        "source": {
            "path": str(source),
            "files": len(bindings),
            "bytes": consumed_bytes,
            "sha256": hashlib.sha256(
                json.dumps(bindings, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "bindings": bindings,
        },
        "policy": {
            **policy,
            "path": str(Path(policy_source)),
        },
        "runner_exit_code": runner_exit_code,
        "counts": {**counts, "total": total, "scored": scored},
        "mutation_score": score,
        "groups": group_results,
        "checks": checks,
        "passed": passed,
        "examples": examples,
        "notice": (
            "Aggregate and independently partitioned function-level scores cover only "
            "policy-selected mutants. Surviving mutants remain explicit test-oracle debt; "
            "a passing ratchet prevents cross-function masking but does not establish that all "
            "critical behavior is mutation-tested."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", help="mutmut mutants directory or one .meta file")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--runner-exit-code", type=int)
    parser.add_argument("--runner-exit-code-file")
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    if (args.runner_exit_code is None) == (args.runner_exit_code_file is None):
        parser.error("provide exactly one runner exit-code source")
    runner_exit_code = args.runner_exit_code
    if args.runner_exit_code_file is not None:
        try:
            runner_exit_code = int(
                Path(args.runner_exit_code_file).read_text(encoding="ascii").strip()
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError("mutation runner exit-code file is invalid") from exc
    assert runner_exit_code is not None
    result = mutation_quality_record(
        args.metadata,
        args.policy,
        runner_exit_code=runner_exit_code,
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        destination = atomic_publish_text(
            args.output, rendered, label="mutation quality evidence"
        )
        print(destination)
    else:
        sys.stdout.write(rendered)
    if not result["passed"]:
        failed = ", ".join(
            name for name, passed in result["checks"].items() if not passed
        )
        print(f"Mutation ratchet failed: {failed}", file=sys.stderr)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
