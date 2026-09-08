"""Approved applicability and acceptance policy for a concrete product use case."""

from __future__ import annotations

import copy
from typing import Any

from .benchmark_source_health import _ADAPTER_MODE, _complete
from .conformance import standards_catalog
from .industry_benchmarks import benchmark_suite_catalog
from .operational_evidence import timestamp


def scope_portfolio(
    portfolio: dict[str, Any],
    *,
    standards: list[str],
    owner: str,
    reviewer: str,
    approver: str,
    approval_ref: str,
    approved_at: str,
    next_review_at: str,
    exclusion_rationale: str,
) -> dict[str, Any]:
    """Bind an explicit applicability decision to the existing portfolio policy."""
    result = copy.deepcopy(portfolio)
    suites = [s["id"] for s in result["benchmark_suites"]]
    scope = {
        "intended_use": result["product"]["intended_use"],
        "owner": owner,
        "reviewer": reviewer,
        "approval_authority": approver,
        "approval_ref": approval_ref,
        "approved_at": approved_at,
        "next_review_at": next_review_at,
        "required_standards": standards,
        "required_suites": suites,
        "standard_exclusions": {
            p["id"]: exclusion_rationale
            for p in standards_catalog()["profiles"]
            if p["id"] not in standards
        },
        "suite_exclusions": {
            s["id"]: exclusion_rationale
            for s in benchmark_suite_catalog()["suites"]
            if s["id"] not in suites
        },
        "acceptance_policy": copy.deepcopy(result["policy"]),
        "change_triggers": [
            "product",
            "model",
            "dataset",
            "standard",
            "adapter",
            "policy",
        ],
    }
    scoped_checks(scope, result, {"reviews": []}, {"sources": []}, approved_at)
    result["product"]["qualification_scope"] = scope
    return result


def scoped_checks(
    scope: dict[str, Any],
    portfolio: dict[str, Any],
    lifecycle: dict[str, Any],
    sources: dict[str, Any],
    as_of: str,
) -> dict[str, bool]:
    required = {
        "intended_use",
        "owner",
        "reviewer",
        "approval_authority",
        "approval_ref",
        "approved_at",
        "next_review_at",
        "required_standards",
        "required_suites",
        "standard_exclusions",
        "suite_exclusions",
        "acceptance_policy",
        "change_triggers",
    }
    if not isinstance(scope, dict) or set(scope) != required:
        raise ValueError("qualification scope fields are invalid")
    roles = [scope[k] for k in ("owner", "reviewer", "approval_authority")]
    for text in [*roles, scope["approval_ref"], scope["intended_use"]]:
        if not isinstance(text, str) or not text.strip() or text.startswith("replace-"):
            raise ValueError(
                "qualification scope requires assigned authorities and approval"
            )
    if len({r.strip().casefold() for r in roles}) != 3:
        raise ValueError("qualification scope roles must be distinct")
    if (
        scope["intended_use"] != portfolio["product"]["intended_use"]
        or scope["acceptance_policy"] != portfolio["policy"]
    ):
        raise ValueError(
            "qualification scope must bind the exact intended use and acceptance policy"
        )
    if (
        not timestamp(scope["approved_at"])
        <= timestamp(as_of)
        <= timestamp(scope["next_review_at"])
    ):
        raise ValueError("qualification scope is not currently approved")
    if not {"product", "model", "dataset", "standard", "adapter", "policy"} <= set(
        scope["change_triggers"]
    ):
        raise ValueError("qualification scope must cover material change triggers")
    catalogs = {
        "standards": {p["id"] for p in standards_catalog()["profiles"]},
        "suites": {s["id"] for s in benchmark_suite_catalog()["suites"]},
    }
    for kind, all_ids in catalogs.items():
        selected = scope[f"required_{kind}"]
        excluded = scope[
            "standard_exclusions" if kind == "standards" else "suite_exclusions"
        ]
        if (
            not isinstance(selected, list)
            or not selected
            or len(set(selected)) != len(selected)
        ):
            raise ValueError("qualification scope requires a unique nonempty selection")
        if (
            not isinstance(excluded, dict)
            or set(selected) & set(excluded)
            or set(selected) | set(excluded) != all_ids
        ):
            raise ValueError(
                "qualification scope must explicitly account for every catalog entry"
            )
        if any(
            not isinstance(reason, str) or not reason.strip()
            for reason in excluded.values()
        ):
            raise ValueError("every scope exclusion requires a rationale")
    if set(scope["required_suites"]) != {
        s["id"] for s in portfolio["benchmark_suites"]
    }:
        raise ValueError("qualification scope and portfolio suite populations differ")
    reviews = [
        r
        for r in lifecycle["reviews"]
        if r["profile_id"] in scope["required_standards"]
    ]
    entries = [
        s for s in sources["sources"] if s["suite_id"] in scope["required_suites"]
    ]
    now = timestamp(as_of)

    def current(review: dict[str, Any]) -> bool:
        try:
            return bool(
                review["disposition"] == "current"
                and review["reviewer"] != "unassigned"
                and review["source_evidence_ref"] != "unassigned"
                and timestamp(review["observed_at"])
                <= now
                <= timestamp(review["next_review_at"])
            )
        except (TypeError, ValueError):
            return False

    def pinned(entry: dict[str, Any]) -> bool:
        try:
            declared = next(
                s for s in portfolio["benchmark_suites"] if s["id"] == entry["suite_id"]
            )
            return bool(
                _complete(entry)
                and entry["observed_revision"] == declared["version"]
                and entry["snapshot_sha256"] == declared["source_sha256"]
                and entry["reviewer"].strip().casefold()
                != sources["authority"].strip().casefold()
                and timestamp(entry["observed_at"])
                <= now
                <= timestamp(entry["next_review_at"])
            )
        except (KeyError, TypeError, ValueError, StopIteration):
            return False

    return {
        "standards_catalog_current": len(reviews) == len(scope["required_standards"])
        and all(current(r) for r in reviews),
        "benchmark_sources_pinned": len(entries) == len(scope["required_suites"])
        and all(pinned(e) for e in entries),
        "benchmark_adapters_operational": bool(entries)
        and all(
            e["adapter_mode"] == _ADAPTER_MODE.get(e["suite_id"], "contract-only")
            and e["adapter_mode"] != "contract-only"
            for e in entries
        ),
    }
