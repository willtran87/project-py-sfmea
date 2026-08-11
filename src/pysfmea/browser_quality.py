"""Governed browser-quality receipts for self-contained HTML reports."""

from __future__ import annotations

import copy
import hashlib
import re
from pathlib import Path
from typing import Any, cast

from .integrity import canonical_json_sha256
from .json_ingestion import (
    load_bounded_file_snapshot,
    load_bounded_json_document,
)

BROWSER_QUALITY_FORMAT = "pysfmea-report-browser-quality-4"
BROWSER_QUALITY_VERIFICATION_FORMAT = (
    "pysfmea-report-browser-quality-verification-1"
)
MAX_BROWSER_QUALITY_RECEIPT_BYTES = 5_000_000
MAX_BROWSER_QUALITY_REPORT_BYTES = 512 * 1024 * 1024
MAX_BROWSER_QUALITY_JSON_DEPTH = 60
MAX_BROWSER_QUALITY_JSON_NODES = 250_000

BROWSER_QUALITY_CHECKS = (
    "report_integrity",
    "size_budget",
    "browser_execution",
    "load_budget",
    "js_heap_measurement",
    "js_heap_budget",
    "progressive_rendering",
    "navigation",
    "responsive_layout",
    "saved_and_shareable_views",
    "automated_accessibility",
    "manual_accessibility_evidence",
    "console_errors",
    "page_errors",
)

_RECEIPT_FIELDS = {
    "format",
    "tool",
    "report",
    "bytes",
    "report_sha256",
    "load_seconds",
    "budgets",
    "browser_memory",
    "rendering",
    "checks",
    "views",
    "responsive",
    "saved_views",
    "accessibility",
    "console_errors",
    "page_errors",
    "browser_execution_error",
    "passed",
    "notice",
    "content_sha256",
}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _is_nonnegative_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value >= 0
    )


def bind_browser_quality_receipt(
    receipt: dict[str, Any], report: str | Path
) -> dict[str, Any]:
    """Bind a browser result to exact bounded report bytes and seal its content."""

    snapshot = load_bounded_file_snapshot(
        report,
        label="browser-quality report",
        max_bytes=MAX_BROWSER_QUALITY_REPORT_BYTES,
    )
    result = copy.deepcopy(receipt)
    result["format"] = BROWSER_QUALITY_FORMAT
    result["report"] = str(snapshot.path)
    result["bytes"] = snapshot.size
    result["report_sha256"] = hashlib.sha256(snapshot.raw).hexdigest()
    result.pop("content_sha256", None)
    result["content_sha256"] = canonical_json_sha256(result)
    verification = verify_browser_quality_receipt(result)
    if not verification["valid"]:
        raise ValueError(
            "browser-quality receipt could not be sealed: "
            + "; ".join(verification["errors"])
        )
    return result


def load_browser_quality_receipt(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="browser-quality receipt",
        max_bytes=MAX_BROWSER_QUALITY_RECEIPT_BYTES,
        max_depth=MAX_BROWSER_QUALITY_JSON_DEPTH,
        max_nodes=MAX_BROWSER_QUALITY_JSON_NODES,
    )
    if not isinstance(document.value, dict):
        raise ValueError("browser-quality receipt must contain a JSON object")
    return document.value


def verify_browser_quality_receipt(
    receipt: dict[str, Any], *, report: str | Path | None = None
) -> dict[str, Any]:
    """Verify receipt integrity, closed structure, semantics, and optional report binding."""

    errors: list[str] = []
    structure = set(receipt) == _RECEIPT_FIELDS
    if not structure:
        errors.append("receipt fields do not match browser-quality format 4")

    unsigned = copy.deepcopy(receipt)
    declared_content_sha256 = str(unsigned.pop("content_sha256", ""))
    actual_content_sha256 = canonical_json_sha256(unsigned)
    content_integrity = _is_sha256(declared_content_sha256) and (
        declared_content_sha256 == actual_content_sha256
    )
    if not content_integrity:
        errors.append("receipt content digest does not match")

    if receipt.get("format") != BROWSER_QUALITY_FORMAT:
        structure = False
        errors.append("receipt format is unsupported")
    if not isinstance(receipt.get("report"), str) or not receipt.get("report"):
        structure = False
        errors.append("report path must be a non-empty string")
    declared_report_sha256 = receipt.get("report_sha256")
    if not _is_sha256(declared_report_sha256):
        structure = False
        errors.append("report_sha256 must be a lowercase SHA-256 digest")
    declared_bytes = receipt.get("bytes")
    if (
        not isinstance(declared_bytes, int)
        or isinstance(declared_bytes, bool)
        or declared_bytes < 0
    ):
        structure = False
        errors.append("bytes must be a non-negative integer")

    load_seconds = receipt.get("load_seconds")
    if load_seconds is not None and not _is_nonnegative_number(load_seconds):
        structure = False
        errors.append("load_seconds must be null or a non-negative number")
    if not isinstance(receipt.get("passed"), bool):
        structure = False
        errors.append("passed must be boolean")
    execution_error = receipt.get("browser_execution_error")
    if not isinstance(execution_error, str) or len(execution_error) > 500:
        structure = False
        errors.append("browser_execution_error must be a bounded string")

    checks = receipt.get("checks")
    checks_valid = isinstance(checks, dict) and set(checks) == set(
        BROWSER_QUALITY_CHECKS
    ) and all(value in {True, False, None} for value in checks.values())
    if not checks_valid:
        structure = False
        errors.append("checks do not match the closed browser-quality check set")
        checks = {}

    budgets = receipt.get("budgets")
    budget_fields = {
        "max_bytes",
        "max_load_seconds",
        "max_js_heap_bytes",
        "authority",
    }
    if not isinstance(budgets, dict) or set(budgets) != budget_fields:
        structure = False
        errors.append("budgets do not match the closed format")
        budgets = {}
    else:
        for field in ("max_bytes", "max_js_heap_bytes"):
            value = budgets[field]
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):
                structure = False
                errors.append(f"{field} must be null or a positive integer")
        max_load_value = budgets["max_load_seconds"]
        if max_load_value is not None and (
            not _is_nonnegative_number(max_load_value) or max_load_value == 0
        ):
            structure = False
            errors.append("max_load_seconds must be null or greater than zero")
        if not isinstance(budgets["authority"], str) or not budgets["authority"]:
            structure = False
            errors.append("budget authority must be a non-empty string")

    for field in ("views", "responsive", "console_errors", "page_errors"):
        value = receipt.get(field)
        if not isinstance(value, list) or len(value) > 1_000:
            structure = False
            errors.append(f"{field} must be a bounded list")
        elif field in {"views", "responsive"} and not all(
            isinstance(item, dict) for item in value
        ):
            structure = False
            errors.append(f"{field} entries must be objects")
        elif field in {"console_errors", "page_errors"} and not all(
            isinstance(item, str) and len(item) <= 4_000 for item in value
        ):
            structure = False
            errors.append(f"{field} entries must be bounded strings")
    views_value = receipt.get("views")
    view_fields = {"view", "visible", "navigation_active", "render_state"}
    if isinstance(views_value, list) and not all(
        isinstance(item, dict)
        and set(item) == view_fields
        and isinstance(item.get("view"), str)
        and bool(item.get("view"))
        and isinstance(item.get("visible"), bool)
        and isinstance(item.get("navigation_active"), bool)
        and item.get("render_state") in {"ready", "error"}
        for item in views_value
    ):
        structure = False
        errors.append("views do not match the closed render-aware navigation format")
    for field in ("saved_views", "accessibility"):
        if not isinstance(receipt.get(field), dict):
            structure = False
            errors.append(f"{field} must be an object")
    tool = receipt.get("tool")
    if (
        not isinstance(tool, dict)
        or set(tool) != {"name", "version"}
        or tool.get("name") != "PySFMEA"
        or not isinstance(tool.get("version"), str)
        or not tool.get("version")
    ):
        structure = False
        errors.append("tool identity does not match the closed format")
    browser_memory = receipt.get("browser_memory")
    if (
        not isinstance(browser_memory, dict)
        or set(browser_memory)
        != {
            "maximum_used_js_heap_bytes",
            "samples",
            "measurement",
            "limitations",
        }
        or not isinstance(browser_memory.get("samples"), list)
        or len(browser_memory.get("samples", [])) > 100
        or not all(
            isinstance(item, dict) for item in browser_memory.get("samples", [])
        )
        or not isinstance(browser_memory.get("measurement"), str)
        or not browser_memory.get("measurement")
        or not isinstance(browser_memory.get("limitations"), str)
        or not browser_memory.get("limitations")
    ):
        structure = False
        errors.append("browser_memory does not match the closed bounded format")
    else:
        maximum_heap = browser_memory["maximum_used_js_heap_bytes"]
        if maximum_heap is not None and (
            not isinstance(maximum_heap, int)
            or isinstance(maximum_heap, bool)
            or maximum_heap < 1
        ):
            structure = False
            errors.append(
                "maximum_used_js_heap_bytes must be null or a positive integer"
            )
    rendering = receipt.get("rendering")
    rendering_fields = {
        "mode",
        "initial_view",
        "initial_ready",
        "boot_seconds",
        "initial_render_seconds",
        "rendered_view_count",
        "total_view_count",
        "all_views_ready",
        "maximum_view_render_seconds",
        "samples",
        "limitations",
    }
    if (
        not isinstance(rendering, dict)
        or set(rendering) != rendering_fields
        or rendering.get("mode") != "progressive_on_demand"
        or not isinstance(rendering.get("initial_view"), str)
        or not rendering.get("initial_view")
        or not isinstance(rendering.get("initial_ready"), bool)
        or not isinstance(rendering.get("all_views_ready"), bool)
        or not isinstance(rendering.get("rendered_view_count"), int)
        or isinstance(rendering.get("rendered_view_count"), bool)
        or rendering.get("rendered_view_count", -1) < 0
        or not isinstance(rendering.get("total_view_count"), int)
        or isinstance(rendering.get("total_view_count"), bool)
        or rendering.get("total_view_count", 0) < 1
        or not isinstance(rendering.get("samples"), list)
        or len(rendering.get("samples", [])) > 100
        or not isinstance(rendering.get("limitations"), str)
        or not rendering.get("limitations")
    ):
        structure = False
        errors.append("rendering does not match the closed progressive-rendering format")
        rendering = {}
    else:
        for field in (
            "boot_seconds",
            "initial_render_seconds",
            "maximum_view_render_seconds",
        ):
            value = rendering[field]
            if value is not None and not _is_nonnegative_number(value):
                structure = False
                errors.append(f"rendering {field} must be null or non-negative")
        samples = rendering["samples"]
        sample_fields = {"view", "state", "render_seconds"}
        if not all(
            isinstance(sample, dict)
            and set(sample) == sample_fields
            and isinstance(sample.get("view"), str)
            and bool(sample.get("view"))
            and sample.get("state") in {"ready", "error"}
            and _is_nonnegative_number(sample.get("render_seconds"))
            for sample in samples
        ):
            structure = False
            errors.append("rendering samples do not match the closed format")
    if not isinstance(receipt.get("notice"), str) or not receipt.get("notice"):
        structure = False
        errors.append("notice must be a non-empty string")

    semantic_consistency = checks_valid and isinstance(receipt.get("passed"), bool)
    if semantic_consistency:
        checks_map: dict[str, Any] = checks if isinstance(checks, dict) else {}
        budgets_map: dict[str, Any] = budgets if isinstance(budgets, dict) else {}
        expected_passed = all(value is not False for value in checks_map.values())
        if receipt["passed"] != expected_passed:
            semantic_consistency = False
            errors.append("passed does not reconcile with the check verdicts")
        execution_passed = checks_map.get("browser_execution") is True
        if execution_passed != (execution_error == ""):
            semantic_consistency = False
            errors.append("browser execution check does not reconcile with its error")
        max_bytes = budgets_map.get("max_bytes")
        if (
            isinstance(max_bytes, int)
            and not isinstance(max_bytes, bool)
            and isinstance(declared_bytes, int)
            and not isinstance(declared_bytes, bool)
        ):
            if checks_map.get("size_budget") != (declared_bytes <= max_bytes):
                semantic_consistency = False
                errors.append("size budget verdict does not reconcile")
        max_load = budgets_map.get("max_load_seconds")
        if _is_nonnegative_number(max_load):
            expected_load = load_seconds is not None and load_seconds <= max_load
            if checks_map.get("load_budget") != expected_load:
                semantic_consistency = False
                errors.append("load budget verdict does not reconcile")
        maximum_heap = (
            browser_memory.get("maximum_used_js_heap_bytes")
            if isinstance(browser_memory, dict)
            else None
        )
        expected_measurement = isinstance(maximum_heap, int) and not isinstance(
            maximum_heap, bool
        )
        if checks_map.get("js_heap_measurement") != expected_measurement:
            semantic_consistency = False
            errors.append("JavaScript heap measurement verdict does not reconcile")
        max_heap = budgets_map.get("max_js_heap_bytes")
        if isinstance(max_heap, int) and not isinstance(max_heap, bool):
            expected_heap_budget = (
                isinstance(maximum_heap, int)
                and not isinstance(maximum_heap, bool)
                and maximum_heap <= max_heap
            )
        if checks_map.get("js_heap_budget") != expected_heap_budget:
            semantic_consistency = False
            errors.append("JavaScript heap budget verdict does not reconcile")

        rendering_map = rendering if isinstance(rendering, dict) else {}
        render_samples = rendering_map.get("samples", [])
        render_sample_views = [
            sample.get("view")
            for sample in render_samples
            if isinstance(sample, dict)
        ]
        render_sample_seconds: list[float] = []
        for sample in render_samples:
            if not isinstance(sample, dict):
                continue
            render_seconds = sample.get("render_seconds")
            if _is_nonnegative_number(render_seconds):
                render_sample_seconds.append(cast(float, render_seconds))
        expected_all_views_ready = (
            bool(render_samples)
            and len(render_samples) == rendering_map.get("total_view_count")
            and len(set(render_sample_views)) == len(render_samples)
            and all(
                isinstance(sample, dict) and sample.get("state") == "ready"
                for sample in render_samples
            )
        )
        expected_progressive_rendering = (
            rendering_map.get("initial_ready") is True
            and rendering_map.get("all_views_ready") is True
            and expected_all_views_ready
            and rendering_map.get("rendered_view_count")
            == rendering_map.get("total_view_count")
        )
        if checks_map.get("progressive_rendering") != expected_progressive_rendering:
            semantic_consistency = False
            errors.append("progressive-rendering verdict does not reconcile")
        if rendering_map.get("all_views_ready") != expected_all_views_ready:
            semantic_consistency = False
            errors.append("all_views_ready does not reconcile with rendering samples")
        if rendering_map.get("rendered_view_count") != len(render_samples):
            semantic_consistency = False
            errors.append("rendered view count does not reconcile with rendering samples")
        expected_maximum_render_seconds = (
            max(render_sample_seconds) if render_sample_seconds else None
        )
        if rendering_map.get("maximum_view_render_seconds") != (
            expected_maximum_render_seconds
        ):
            semantic_consistency = False
            errors.append("maximum view render time does not reconcile")

        views = receipt.get("views")
        expected_navigation = isinstance(views, list) and bool(views) and all(
            isinstance(item, dict)
            and item.get("visible") is True
            and item.get("navigation_active") is True
            and item.get("render_state") == "ready"
            for item in views
        )
        if execution_passed:
            navigation_views = (
                [item.get("view") for item in views if isinstance(item, dict)]
                if isinstance(views, list)
                else []
            )
            if rendering_map.get("total_view_count") != len(navigation_views):
                semantic_consistency = False
                errors.append("total view count does not reconcile with navigation views")
            if set(render_sample_views) != set(navigation_views):
                semantic_consistency = False
                errors.append("rendering samples do not reconcile with navigation views")
        if checks_map.get("navigation") != expected_navigation:
            semantic_consistency = False
            errors.append("navigation verdict does not reconcile")
        responsive = receipt.get("responsive")
        expected_responsive = (
            isinstance(responsive, list)
            and bool(responsive)
            and all(
                isinstance(item, dict) and item.get("passed") is True
                for item in responsive
            )
        )
        if checks_map.get("responsive_layout") != expected_responsive:
            semantic_consistency = False
            errors.append("responsive-layout verdict does not reconcile")
        saved_views = receipt.get("saved_views")
        expected_saved = isinstance(saved_views, dict) and saved_views.get("passed") is True
        if checks_map.get("saved_and_shareable_views") != expected_saved:
            semantic_consistency = False
            errors.append("saved-view verdict does not reconcile")
        accessibility = receipt.get("accessibility")
        automated_rules = (
            accessibility.get("automated_rules", [])
            if isinstance(accessibility, dict)
            else []
        )
        expected_automated = isinstance(automated_rules, list) and bool(
            automated_rules
        ) and all(
            isinstance(item, dict) and item.get("passed") is True
            for item in automated_rules
        )
        if checks_map.get("automated_accessibility") != expected_automated:
            semantic_consistency = False
            errors.append("automated-accessibility verdict does not reconcile")
        manual_evidence = (
            accessibility.get("manual_evidence")
            if isinstance(accessibility, dict)
            else None
        )
        expected_manual = (
            None
            if manual_evidence is None
            else isinstance(manual_evidence, dict)
            and manual_evidence.get("qualified") is True
        )
        if checks_map.get("manual_accessibility_evidence") != expected_manual:
            semantic_consistency = False
            errors.append("manual-accessibility verdict does not reconcile")
        for check_name, field in (
            ("console_errors", "console_errors"),
            ("page_errors", "page_errors"),
        ):
            records = receipt.get(field)
            expected_clear = isinstance(records, list) and not records
            if checks_map.get(check_name) != expected_clear:
                semantic_consistency = False
                errors.append(f"{field} verdict does not reconcile")

    report_binding: bool | None = None
    actual_report_sha256 = ""
    actual_report_bytes: int | None = None
    if report is not None:
        try:
            snapshot = load_bounded_file_snapshot(
                report,
                label="browser-quality report",
                max_bytes=MAX_BROWSER_QUALITY_REPORT_BYTES,
            )
            actual_report_sha256 = hashlib.sha256(snapshot.raw).hexdigest()
            actual_report_bytes = snapshot.size
            report_binding = (
                actual_report_sha256 == declared_report_sha256
                and actual_report_bytes == declared_bytes
            )
        except (OSError, ValueError) as exc:
            report_binding = False
            errors.append(f"report binding could not be verified: {exc}")
        if report_binding is False and not any(
            value.startswith("report binding could not") for value in errors
        ):
            errors.append("receipt does not match the exact report bytes")

    valid = (
        content_integrity
        and structure
        and semantic_consistency
        and report_binding is not False
    )
    return {
        "format": BROWSER_QUALITY_VERIFICATION_FORMAT,
        "valid": valid,
        "quality_passed": valid and receipt.get("passed") is True,
        "checks": {
            "content_integrity": content_integrity,
            "structure": structure,
            "semantic_consistency": semantic_consistency,
            "report_binding": report_binding,
        },
        "declared_content_sha256": declared_content_sha256,
        "actual_content_sha256": actual_content_sha256,
        "declared_report_sha256": str(declared_report_sha256 or ""),
        "actual_report_sha256": actual_report_sha256,
        "declared_report_bytes": declared_bytes if isinstance(declared_bytes, int) else None,
        "actual_report_bytes": actual_report_bytes,
        "errors": errors,
        "notice": (
            "Verification proves receipt integrity and optional exact-report binding. A passing "
            "browser gate is product-quality evidence, not representative-user evaluation, "
            "regulatory approval, or accessibility conformance."
        ),
    }


def verify_browser_quality_receipt_file(
    source: str | Path, *, report: str | Path | None = None
) -> dict[str, Any]:
    supplied = Path(source).expanduser().absolute()
    try:
        document = load_bounded_json_document(
            supplied,
            label="browser-quality receipt",
            max_bytes=MAX_BROWSER_QUALITY_RECEIPT_BYTES,
            max_depth=MAX_BROWSER_QUALITY_JSON_DEPTH,
            max_nodes=MAX_BROWSER_QUALITY_JSON_NODES,
        )
        if not isinstance(document.value, dict):
            raise ValueError("browser-quality receipt must contain a JSON object")
        result = verify_browser_quality_receipt(document.value, report=report)
        result.update(
            {
                "path": str(document.path),
                "source_bytes": document.size,
                "source_sha256": hashlib.sha256(document.raw).hexdigest(),
            }
        )
        return result
    except (OSError, ValueError) as exc:
        return {
            "format": BROWSER_QUALITY_VERIFICATION_FORMAT,
            "valid": False,
            "quality_passed": False,
            "checks": {
                "content_integrity": False,
                "structure": False,
                "semantic_consistency": False,
                "report_binding": False if report is not None else None,
            },
            "declared_content_sha256": "",
            "actual_content_sha256": "",
            "declared_report_sha256": "",
            "actual_report_sha256": "",
            "declared_report_bytes": None,
            "actual_report_bytes": None,
            "errors": [f"browser-quality receipt could not be verified: {exc}"],
            "notice": (
                "Verification proves receipt integrity and optional exact-report binding. A "
                "passing browser gate is product-quality evidence, not representative-user "
                "evaluation, regulatory approval, or accessibility conformance."
            ),
            "path": str(supplied),
            "source_bytes": 0,
            "source_sha256": "",
        }
