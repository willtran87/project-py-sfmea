"""Fail-closed readiness gate over standards and benchmark qualification evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .benchmark_proficiency import verify_benchmark_proficiency
from .benchmark_source_health import verify_benchmark_source_health
from .conformance import standards_catalog
from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .industry_benchmarks import benchmark_suite_catalog
from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .qualification_scope import scoped_checks
from .scope_authentication import authenticate_scope
from .standards_lifecycle import verify_standards_lifecycle
from .validation_portfolio import verify_validation_portfolio_assessment

INDUSTRY_QUALIFICATION_READINESS_FORMAT = "pysfmea-industry-qualification-readiness-3"
INDUSTRY_QUALIFICATION_READINESS_VERIFICATION_FORMAT = (
    "pysfmea-industry-qualification-readiness-verification-3"
)
MAX_EVIDENCE_BYTES = 100 * 1024 * 1024


def _artifact(source: str | Path, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = Path(source).expanduser().resolve()
    document = load_bounded_json_document(
        path,
        label=label,
        max_bytes=MAX_EVIDENCE_BYTES,
        max_depth=180,
        max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError(f"{label} must contain an object")
    return document.value, {
        "reference": str(source),
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "content_sha256": str(document.value.get("content_sha256", "")),
    }


def industry_qualification_readiness(
    *,
    standards_lifecycle: str | Path,
    benchmark_source_health: str | Path,
    benchmark_proficiency_source: str | Path,
    benchmark_proficiency_assessment: str | Path,
    validation_portfolio_source: str | Path,
    validation_portfolio_assessment: str | Path,
    authority: str,
    generated_at: str | None = None,
    scope_trust_policy: str | Path | None = None,
) -> dict[str, Any]:
    """Assess whether evidence is ready for an authorized qualification review.

    This function validates and binds exact artifact bytes.  It never repairs,
    completes, or upgrades evidence and therefore remains useful on incomplete
    templates: every unmet gate is reported as explicit qualification debt.
    """

    lifecycle, lifecycle_binding = _artifact(standards_lifecycle, "standards lifecycle")
    sources, source_binding = _artifact(
        benchmark_source_health, "benchmark source health"
    )
    proficiency_source, proficiency_source_binding = _artifact(
        benchmark_proficiency_source, "benchmark proficiency source"
    )
    proficiency, proficiency_binding = _artifact(
        benchmark_proficiency_assessment, "benchmark proficiency assessment"
    )
    portfolio_source, portfolio_source_binding = _artifact(
        validation_portfolio_source, "industry validation portfolio source"
    )
    portfolio, portfolio_binding = _artifact(
        validation_portfolio_assessment, "industry validation portfolio assessment"
    )
    lifecycle_verdict = verify_standards_lifecycle(lifecycle)
    source_verdict = verify_benchmark_source_health(sources)
    proficiency_verdict = verify_benchmark_proficiency(
        proficiency, source=proficiency_source
    )
    portfolio_verdict = verify_validation_portfolio_assessment(
        portfolio, source=validation_portfolio_source
    )
    standards = standards_catalog()
    benchmarks = benchmark_suite_catalog()
    reviewer = bounded_text(authority, "industry qualification readiness authority")

    source_authorities = {
        str(lifecycle.get("authority", "")).casefold(),
        str(sources.get("authority", "")).casefold(),
    }
    declared_scope = portfolio_source.get("product", {}).get("qualification_scope")
    if isinstance(declared_scope, dict):
        source_authorities.update(
            str(declared_scope.get(k, "")).strip().casefold()
            for k in ("owner", "reviewer", "approval_authority")
        )
    portfolio_authority = portfolio.get("authority", {})
    if isinstance(portfolio_authority, dict):
        source_authorities.update(
            str(portfolio_authority.get(name, "")).casefold()
            for name in (
                "portfolio_owner",
                "verification_authority",
                "approval_authority",
            )
        )
    proficiency_authorities = proficiency.get("authorities", {})
    if isinstance(proficiency_authorities, dict):
        source_authorities.update(
            str(proficiency_authorities.get(name, "")).casefold()
            for name in ("provider", "technical_reviewer", "approval_authority")
        )
    authority_separation = bool(
        reviewer.casefold() not in source_authorities
        and "" not in source_authorities
        and len(source_authorities) >= 5
    )
    source_summary = sources.get("summary", {})
    checks = {
        "standards_artifact_valid": bool(lifecycle_verdict["valid"]),
        "standards_catalog_current": bool(
            lifecycle_verdict["eligible_as_current_catalog_evidence"]
        ),
        "benchmark_source_artifact_valid": bool(source_verdict["valid"]),
        "benchmark_sources_pinned": bool(
            source_verdict["eligible_for_external_execution"]
        ),
        "benchmark_adapters_operational": bool(
            isinstance(source_summary, dict)
            and source_summary.get("sources") == len(benchmarks["suites"])
            and source_summary.get("contract_only_adapters") == 0
            and source_summary.get("native_or_direct_adapters")
            == len(benchmarks["suites"])
        ),
        "benchmark_proficiency_passed": bool(
            proficiency_verdict["valid"]
            and proficiency_verdict["passed"]
            and proficiency_verdict["eligible_for_qualification_input"]
        ),
        "independent_validation_portfolio": bool(
            portfolio_verdict["valid"] and portfolio_verdict["passed"]
        ),
        "benchmark_item_quality_qualified": bool(
            portfolio_verdict["valid"]
            and portfolio.get("checks", {}).get("benchmark_item_quality") is True
            and portfolio.get("benchmark", {}).get("exact_item_quality_coverage")
            is True
        ),
        "readiness_authority_separate": authority_separation,
    }
    scope = portfolio_source.get("product", {}).get("qualification_scope")
    if scope is not None:
        scoped = scoped_checks(
            scope, portfolio_source, lifecycle, sources, generated_at or utc_now()
        )
        scoped["standards_catalog_current"] = (
            scoped["standards_catalog_current"] and lifecycle_verdict["valid"]
        )
        scoped["benchmark_sources_pinned"] = (
            scoped["benchmark_sources_pinned"] and source_verdict["valid"]
        )
        checks.update(scoped)
    authentication = authenticate_scope(
        validation_portfolio_source, scope_trust_policy, as_of=generated_at or utc_now()
    )
    checks["scope_approval_authenticated"] = authentication["authenticated"]
    passed = all(checks.values())
    blockers = [
        {
            "check": name,
            "remediation": {
                "scope_approval_authenticated": "sign the exact scoped portfolio with an authorized, current key and supply an external scope trust policy",
                "standards_artifact_valid": "repair and reseal the exact catalog-bound standards lifecycle ledger",
                "standards_catalog_current": "review every profile against publisher evidence and resolve stale, changed, or non-current dispositions",
                "benchmark_source_artifact_valid": "repair and reseal the closed benchmark source-health ledger",
                "benchmark_sources_pinned": "pin every lawful suite revision, license, schema, digest, reviewer, and review interval",
                "benchmark_adapters_operational": "implement and independently review every remaining contract-only adapter",
                "benchmark_proficiency_passed": "complete an independently governed, stable, homogeneous, cross-organization proficiency round and provide exact source replay",
                "independent_validation_portfolio": "complete the external benchmark, comparator, runtime, interoperability, usability, and required portfolio evidence",
                "benchmark_item_quality_qualified": "provide an exact-replay, passing independent item-quality audit for every declared benchmark suite",
                "readiness_authority_separate": "assign a readiness assessor distinct from source, verification, and approval authorities",
            }[name],
        }
        for name, state in checks.items()
        if not state
    ]
    result = {
        "format": INDUSTRY_QUALIFICATION_READINESS_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": reviewer,
        "catalogs": {
            "standards": {
                "version": standards["version"],
                "content_sha256": standards["content_sha256"],
                "profiles": len(standards["profiles"]),
            },
            "benchmarks": {
                "version": benchmarks["version"],
                "content_sha256": benchmarks["content_sha256"],
                "suites": len(benchmarks["suites"]),
            },
        },
        "evidence": [
            {
                "kind": "standards_lifecycle",
                **lifecycle_binding,
                "valid": lifecycle_verdict["valid"],
                "ready": lifecycle_verdict["eligible_as_current_catalog_evidence"],
            },
            {
                "kind": "benchmark_source_health",
                **source_binding,
                "valid": source_verdict["valid"],
                "ready": source_verdict["eligible_for_external_execution"],
            },
            {
                "kind": "benchmark_proficiency_source",
                **proficiency_source_binding,
                "valid": proficiency_verdict["checks"]["exact_source_replay"] is True,
                "ready": proficiency_verdict["checks"]["exact_source_replay"] is True,
            },
            {
                "kind": "benchmark_proficiency_assessment",
                **proficiency_binding,
                "valid": proficiency_verdict["valid"],
                "ready": proficiency_verdict["eligible_for_qualification_input"],
            },
            {
                "kind": "validation_portfolio_source",
                **portfolio_source_binding,
                "valid": portfolio_verdict["checks"]["source_regeneration"] is True,
                "ready": portfolio_verdict["checks"]["source_regeneration"] is True,
            },
            {
                "kind": "validation_portfolio_assessment",
                **portfolio_binding,
                "valid": portfolio_verdict["valid"],
                "ready": portfolio_verdict["passed"],
            },
        ],
        "checks": checks,
        "scope_authentication": authentication,
        "summary": {
            "passed": passed,
            "status": (
                "eligible_for_authorized_industry_qualification_review"
                if passed
                else "industry_qualification_evidence_incomplete"
            ),
            "checks_passed": sum(checks.values()),
            "checks_required": len(checks),
            "blockers": blockers,
        },
        "claim_boundary": (
            "Passing establishes exact evidence completeness under these gates only. "
            "Scope authentication is limited to the supplied trust policy. This does not "
            "authenticate other authorities, validate licensed interpretations or "
            "ground truth, establish representativeness, accept risk, accredit a body, "
            "qualify the tool, certify a product, or grant regulatory approval."
        ),
    }
    return seal(result)


def _structure(value: dict[str, Any]) -> bool:
    try:
        evidence = value["evidence"]
        checks = value["checks"]
        blockers = value["summary"]["blockers"]
        expected_checks = {
            "scope_approval_authenticated",
            "standards_artifact_valid",
            "standards_catalog_current",
            "benchmark_source_artifact_valid",
            "benchmark_sources_pinned",
            "benchmark_adapters_operational",
            "benchmark_proficiency_passed",
            "independent_validation_portfolio",
            "benchmark_item_quality_qualified",
            "readiness_authority_separate",
        }
        evidence_fields = {
            "kind",
            "reference",
            "bytes",
            "sha256",
            "content_sha256",
            "valid",
            "ready",
        }
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "catalogs",
                "evidence",
                "scope_authentication",
                "checks",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and isinstance(evidence, list)
            and len(evidence) == 6
            and {item.get("kind") for item in evidence}
            == {
                "standards_lifecycle",
                "benchmark_source_health",
                "benchmark_proficiency_source",
                "benchmark_proficiency_assessment",
                "validation_portfolio_source",
                "validation_portfolio_assessment",
            }
            and all(
                isinstance(item, dict)
                and set(item) == evidence_fields
                and isinstance(item["reference"], str)
                and bool(item["reference"].strip())
                and isinstance(item["bytes"], int)
                and not isinstance(item["bytes"], bool)
                and item["bytes"] > 0
                and isinstance(item["sha256"], str)
                and bool(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
                and isinstance(item["content_sha256"], str)
                and (
                    not item["content_sha256"]
                    or bool(re.fullmatch(r"[0-9a-f]{64}", item["content_sha256"]))
                )
                and isinstance(item["valid"], bool)
                and isinstance(item["ready"], bool)
                for item in evidence
            )
            and isinstance(checks, dict)
            and isinstance(value["scope_authentication"], dict)
            and set(value["scope_authentication"])
            == {
                "authenticated",
                "trust_policy_sha256",
                "signature_sha256",
                "key_fingerprint",
                "errors",
            }
            and all(
                isinstance(value["scope_authentication"][name], str)
                and re.fullmatch(
                    r"(?:[0-9a-f]{64})?", value["scope_authentication"][name]
                )
                for name in ("trust_policy_sha256", "signature_sha256")
            )
            and isinstance(value["scope_authentication"]["key_fingerprint"], str)
            and re.fullmatch(
                r"(?:sha256:[0-9a-f]{64})?",
                value["scope_authentication"]["key_fingerprint"],
            )
            and isinstance(value["scope_authentication"]["errors"], list)
            and all(
                isinstance(error, str)
                for error in value["scope_authentication"]["errors"]
            )
            and (
                not value["scope_authentication"]["authenticated"]
                or (
                    not value["scope_authentication"]["errors"]
                    and all(
                        value["scope_authentication"][name]
                        for name in (
                            "trust_policy_sha256",
                            "signature_sha256",
                            "key_fingerprint",
                        )
                    )
                )
            )
            and value["scope_authentication"].get("authenticated")
            is checks["scope_approval_authenticated"]
            and set(checks) == expected_checks
            and all(isinstance(state, bool) for state in checks.values())
            and isinstance(value["generated_at"], str)
            and bool(value["generated_at"].strip())
            and isinstance(value["authority"], str)
            and bool(value["authority"].strip())
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"].strip())
            and isinstance(blockers, list)
            and all(
                isinstance(item, dict)
                and set(item) == {"check", "remediation"}
                and item["check"] in expected_checks
                and isinstance(item["remediation"], str)
                and item["remediation"]
                for item in blockers
            )
        )
    except (KeyError, TypeError):
        return False


def _semantics(value: dict[str, Any]) -> bool:
    try:
        standards = standards_catalog()
        benchmarks = benchmark_suite_catalog()
        checks = value["checks"]
        passed = all(checks.values())
        failed = {name for name, state in checks.items() if not state}
        blockers = value["summary"]["blockers"]
        return bool(
            value["catalogs"]
            == {
                "standards": {
                    "version": standards["version"],
                    "content_sha256": standards["content_sha256"],
                    "profiles": len(standards["profiles"]),
                },
                "benchmarks": {
                    "version": benchmarks["version"],
                    "content_sha256": benchmarks["content_sha256"],
                    "suites": len(benchmarks["suites"]),
                },
            }
            and value["summary"]["passed"] == passed
            and value["summary"]["checks_passed"] == sum(checks.values())
            and value["summary"]["checks_required"] == len(checks)
            and {item["check"] for item in blockers} == failed
            and len(blockers) == len(failed)
            and value["summary"]["status"]
            == (
                "eligible_for_authorized_industry_qualification_review"
                if passed
                else "industry_qualification_evidence_incomplete"
            )
        )
    except (KeyError, TypeError):
        return False


def verify_industry_qualification_readiness(
    value: dict[str, Any],
    *,
    standards_lifecycle: str | Path | None = None,
    benchmark_source_health: str | Path | None = None,
    benchmark_proficiency_source: str | Path | None = None,
    benchmark_proficiency_assessment: str | Path | None = None,
    validation_portfolio_source: str | Path | None = None,
    validation_portfolio_assessment: str | Path | None = None,
    scope_trust_policy: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="industry qualification readiness",
            format_value=INDUSTRY_QUALIFICATION_READINESS_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    semantics = structure and _semantics(checked)
    if not structure:
        errors.append("industry qualification readiness structure is invalid")
    elif not semantics:
        errors.append("industry qualification readiness accounting does not reconcile")
    supplied = (
        standards_lifecycle,
        benchmark_source_health,
        benchmark_proficiency_source,
        benchmark_proficiency_assessment,
        validation_portfolio_source,
        validation_portfolio_assessment,
    )
    exact_replay: bool | None = None
    if scope_trust_policy is not None or any(item is not None for item in supplied):
        exact_replay = False
        if all(item is not None for item in supplied):
            try:
                expected = industry_qualification_readiness(
                    standards_lifecycle=standards_lifecycle,  # type: ignore[arg-type]
                    benchmark_source_health=benchmark_source_health,  # type: ignore[arg-type]
                    benchmark_proficiency_source=benchmark_proficiency_source,  # type: ignore[arg-type]
                    benchmark_proficiency_assessment=benchmark_proficiency_assessment,  # type: ignore[arg-type]
                    validation_portfolio_source=validation_portfolio_source,  # type: ignore[arg-type]
                    validation_portfolio_assessment=validation_portfolio_assessment,  # type: ignore[arg-type]
                    authority=checked["authority"],
                    generated_at=checked["generated_at"],
                    scope_trust_policy=scope_trust_policy,
                )
                exact_replay = expected == value
            except (OSError, TypeError, ValueError):
                exact_replay = False
        if not exact_replay:
            errors.append("industry qualification readiness does not exactly replay")
    valid = integrity and structure and semantics and exact_replay is not False
    passed = bool(valid and checked.get("summary", {}).get("passed"))
    eligible = passed and exact_replay is True
    return seal(
        {
            "format": INDUSTRY_QUALIFICATION_READINESS_VERIFICATION_FORMAT,
            "valid": valid,
            "passed": passed,
            "eligible_for_authorized_industry_qualification_review": eligible,
            "checks": {
                "content_integrity": integrity,
                "closed_structure": structure,
                "semantic_reconciliation": semantics,
                "exact_source_replay": exact_replay,
            },
            "errors": errors,
            "notice": (
                "Eligibility requires exact source replay and complete evidence. It remains "
                "an input to an authorized decision, not qualification, certification, "
                "accreditation, regulatory approval, or risk acceptance."
            ),
        }
    )


def verify_industry_qualification_readiness_file(
    source: str | Path,
    *,
    standards_lifecycle: str | Path | None = None,
    benchmark_source_health: str | Path | None = None,
    benchmark_proficiency_source: str | Path | None = None,
    benchmark_proficiency_assessment: str | Path | None = None,
    validation_portfolio_source: str | Path | None = None,
    validation_portfolio_assessment: str | Path | None = None,
    scope_trust_policy: str | Path | None = None,
) -> dict[str, Any]:
    try:
        value, _ = _artifact(source, "industry qualification readiness")
        return verify_industry_qualification_readiness(
            value,
            standards_lifecycle=standards_lifecycle,
            benchmark_source_health=benchmark_source_health,
            benchmark_proficiency_source=benchmark_proficiency_source,
            benchmark_proficiency_assessment=benchmark_proficiency_assessment,
            validation_portfolio_source=validation_portfolio_source,
            validation_portfolio_assessment=validation_portfolio_assessment,
            scope_trust_policy=scope_trust_policy,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": INDUSTRY_QUALIFICATION_READINESS_VERIFICATION_FORMAT,
                "valid": False,
                "passed": False,
                "eligible_for_authorized_industry_qualification_review": False,
                "checks": {
                    "content_integrity": False,
                    "closed_structure": False,
                    "semantic_reconciliation": False,
                    "exact_source_replay": False,
                },
                "errors": [str(exc)],
                "notice": "Industry qualification readiness verification failed closed.",
            }
        )


def export_industry_qualification_readiness(
    value: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_industry_qualification_readiness(value)
    if not verdict["valid"]:
        raise ValueError("industry qualification readiness artifact is invalid")
    return publish_json(value, destination)
