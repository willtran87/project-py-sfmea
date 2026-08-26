"""Exercise a generated SFMEA report in Chromium and emit a CI quality receipt."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from pysfmea.accessibility import (
    REQUIRED_ACCESSIBILITY_SCENARIOS,
    load_accessibility_evidence,
    verify_accessibility_evidence,
)
from pysfmea.browser_quality import BROWSER_QUALITY_FORMAT, bind_browser_quality_receipt
from pysfmea.file_publication import atomic_publish_text
from pysfmea.html_report import verify_html_report_file
from pysfmea.store import load_analysis
from pysfmea.version import __version__

DEFAULT_MAX_REPORT_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_LOAD_SECONDS = 10.0
DEFAULT_MAX_JS_HEAP_BYTES = 256 * 1024 * 1024


def browser_quality_gate(
    report: str | Path,
    *,
    analysis: str | Path | None = None,
    max_bytes: int | None = DEFAULT_MAX_REPORT_BYTES,
    max_load_seconds: float | None = DEFAULT_MAX_LOAD_SECONDS,
    max_js_heap_bytes: int | None = DEFAULT_MAX_JS_HEAP_BYTES,
    manual_evidence: str | Path | None = None,
) -> dict[str, Any]:
    if max_bytes is not None and (isinstance(max_bytes, bool) or max_bytes <= 0):
        raise ValueError("max_bytes must be a positive integer")
    if max_load_seconds is not None and max_load_seconds <= 0:
        raise ValueError("max_load_seconds must be greater than zero")
    if max_js_heap_bytes is not None and (
        isinstance(max_js_heap_bytes, bool) or max_js_heap_bytes <= 0
    ):
        raise ValueError("max_js_heap_bytes must be a positive integer")
    path = Path(report).expanduser().resolve()
    current = load_analysis(analysis) if analysis else None
    integrity = verify_html_report_file(path, analysis=current)
    try:
        from playwright.sync_api import (  # type: ignore[import-not-found,unused-ignore]
            Error as PlaywrightError,
        )
        from playwright.sync_api import (  # type: ignore[import-not-found,unused-ignore]
            sync_playwright,
        )
    except ImportError as exc:
        raise RuntimeError(
            "browser quality gates require `pip install -e .[browser]` and "
            "`playwright install chromium`"
        ) from exc

    console_errors: list[str] = []
    page_errors: list[str] = []
    view_checks: list[dict[str, Any]] = []
    responsive_checks: list[dict[str, Any]] = []
    accessibility: dict[str, Any] = {}
    saved_view_checks: dict[str, Any] = {}
    heap_samples: list[dict[str, Any]] = []
    rendering: dict[str, Any] = {
        "mode": "progressive_on_demand",
        "initial_view": "overview",
        "initial_ready": False,
        "boot_seconds": None,
        "initial_render_seconds": None,
        "rendered_view_count": 0,
        "total_view_count": 1,
        "all_views_ready": False,
        "maximum_view_render_seconds": None,
        "samples": [],
        "limitations": (
            "Browser execution did not produce progressive-rendering telemetry; "
            "timing uses browser performance.now() and excludes JSON parsing, browser "
            "startup, paint completion, native DOM memory, and GPU work."
        ),
    }
    initial_rendering: dict[str, Any] = {}
    load_seconds: float | None = None
    focus_indicator: dict[str, Any] = {"visible": False}
    browser_execution_error = ""
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, args=["--enable-precise-memory-info"]
            )
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.set_default_timeout(10_000)
                page.on(
                    "console",
                    lambda message: (
                        console_errors.append(message.text)
                        if message.type == "error"
                        else None
                    ),
                )
                page.on("pageerror", lambda error: page_errors.append(str(error)))
            # Measure document load/render readiness, excluding one-time Playwright and
            # browser-process startup overhead that is unrelated to report performance.
                started = time.perf_counter()
                page.goto(path.as_uri(), wait_until="domcontentloaded")
                page.locator("#topTitle").wait_for(state="visible")
                page.wait_for_function(
                    "document.querySelector('#topTitle').textContent.trim().length > 0"
                )
                page.wait_for_function(
                    "document.documentElement.dataset.reportReady === 'true'"
                )
                load_seconds = round(time.perf_counter() - started, 6)
                initial_rendering = page.evaluate(
                    "({...window.__PYSFMEA_RENDERING__, "
                    "boot_seconds: window.__PYSFMEA_REPORT_BOOT_SECONDS__ ?? null})"
                )
                views = page.locator("#nav button[data-view]").evaluate_all(
                    "nodes => nodes.map(node => node.dataset.view)"
                )
                accessibility = page.evaluate(
                """() => {
                    const ids = [...document.querySelectorAll('[id]')].map(node => node.id);
                    const duplicates = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
                    const controls = [...document.querySelectorAll('input, select, textarea')];
                    const hasLabel = node => Boolean(
                        node.getAttribute('aria-label') ||
                        node.getAttribute('aria-labelledby') ||
                        node.closest('label') ||
                        (node.id && document.querySelector(`label[for="${CSS.escape(node.id)}"]`))
                    );
                    const buttons = [...document.querySelectorAll('button')];
                    return {
                        duplicate_ids: duplicates,
                        unnamed_buttons: buttons.filter(node => !(
                            node.textContent.trim() || node.getAttribute('aria-label') ||
                            node.getAttribute('aria-labelledby')
                        )).length,
                        unlabeled_controls: controls.filter(node => !hasLabel(node)).map(node => ({
                            tag: node.tagName.toLowerCase(),
                            id: node.id,
                            type: node.getAttribute('type') || '',
                            name: node.getAttribute('name') || '',
                        })),
                        images_without_alt: [...document.querySelectorAll('img:not([alt])')].length,
                        main_landmarks: document.querySelectorAll('main').length,
                        navigation_landmarks: document.querySelectorAll('nav').length,
                        level_one_headings: document.querySelectorAll('h1').length,
                        html_lang: document.documentElement.lang,
                        document_title: document.title.trim(),
                        links_without_name: [...document.querySelectorAll('a')].filter(node => !(
                            node.textContent.trim() || node.getAttribute('aria-label') ||
                            node.getAttribute('aria-labelledby')
                        )).length,
                        tables_without_caption: [...document.querySelectorAll('table')].filter(
                            node => !node.querySelector('caption')
                        ).length,
                        headers_without_scope: [...document.querySelectorAll('th')].filter(
                            node => !node.hasAttribute('scope')
                        ).length,
                        dialogs_without_name: [...document.querySelectorAll('dialog')].filter(node => !(
                            node.getAttribute('aria-label') || node.getAttribute('aria-labelledby')
                        )).length,
                        skip_link_target: document.querySelector('.skip-link')?.getAttribute('href') || '',
                    };
                }"""
            )
                focus_indicator = page.evaluate(
                """() => {
                    const control = document.querySelector('#nav button');
                    control.focus();
                    const style = getComputedStyle(control);
                    return {
                        focused_element: control?.dataset.view || '',
                        outline_width: style.outlineWidth,
                        outline_style: style.outlineStyle,
                        box_shadow: style.boxShadow,
                        visible: style.outlineStyle !== 'none' || style.boxShadow !== 'none',
                    };
                }"""
            )
                page.locator('#nav button[data-view="failure-modes"]').click()
                selected_priority = page.locator("#priorityFilter").evaluate(
                """node => {
                    const option = [...node.options].find(value => value.value);
                    if (!option) return '';
                    node.value = option.value;
                    node.dispatchEvent(new Event('change', {bubbles: true}));
                    return option.value;
                }"""
            )
                page.locator("#savedViewName").fill("Browser qualification view")
                page.locator("#saveView").click()
                saved_before_reload = page.locator("#savedViewSelect option").count() > 1
                page.locator("#shareView").click()
                share_hash = page.evaluate("location.hash")
                page.reload(wait_until="domcontentloaded")
                page.locator("#topTitle").wait_for(state="visible")
                page.wait_for_function(
                    "document.documentElement.dataset.reportReady === 'true'"
                )
                saved_after_reload = page.locator("#savedViewSelect option").count() > 1
                saved_view_checks = {
                "selected_priority": selected_priority,
                "saved_before_reload": saved_before_reload,
                "saved_after_reload": saved_after_reload,
                "share_hash": share_hash,
                "share_state_bounded": share_hash.startswith("#failure-modes")
                and len(share_hash) <= 1_000,
                "passed": saved_before_reload
                and saved_after_reload
                and share_hash.startswith("#failure-modes")
                and len(share_hash) <= 1_000,
                }
                for view in views:
                    page.locator(f'#nav button[data-view="{view}"]').click()
                    page.wait_for_function(
                        "view => document.querySelector(`.view[data-view=\"${view}\"]`)"
                        ".dataset.renderState === 'ready'",
                        arg=view,
                    )
                    visible = page.locator(f'.view[data-view="{view}"]').is_visible()
                    active = (
                        page.locator(f'#nav button[data-view="{view}"].active').count()
                        == 1
                    )
                    view_checks.append(
                        {
                            "view": view,
                            "visible": visible,
                            "navigation_active": active,
                            "render_state": page.locator(
                                f'.view[data-view="{view}"]'
                            ).get_attribute("data-render-state"),
                        }
                    )
                    heap_samples.append(
                        {
                            "view": view,
                            "used_js_heap_bytes": int(
                                page.evaluate(
                                    "Number(performance.memory?.usedJSHeapSize || 0)"
                                )
                            ),
                        }
                    )
                rendering = page.evaluate("window.__PYSFMEA_RENDERING__")
                rendering["initial_view"] = initial_rendering.get(
                    "initial_view", "overview"
                )
                rendering["initial_ready"] = initial_rendering.get(
                    "initial_ready", False
                )
                rendering["initial_render_seconds"] = initial_rendering.get(
                    "initial_render_seconds"
                )
                rendering["boot_seconds"] = initial_rendering.get("boot_seconds")
                for width, height, label in (
                    (1440, 900, "desktop"),
                    (390, 844, "mobile"),
                ):
                    page.set_viewport_size({"width": width, "height": height})
                    if label == "mobile":
                        page.locator("#menuButton").click()
                        page.wait_for_function(
                            "document.body.classList.contains('menu-open')"
                        )
                    overview = page.locator('#nav button[data-view="overview"]')
                    overview.scroll_into_view_if_needed()
                    overview.click()
                    overflow = page.evaluate(
                        "Math.max(document.documentElement.scrollWidth, "
                        "document.body.scrollWidth) - window.innerWidth"
                    )
                    responsive_checks.append(
                        {
                            "viewport": label,
                            "width": width,
                            "height": height,
                            "horizontal_overflow_pixels": max(0, int(overflow)),
                            "passed": overflow <= 2,
                        }
                    )
            finally:
                browser.close()
    except PlaywrightError as exc:
        browser_execution_error = f"{type(exc).__name__}: {str(exc).splitlines()[0]}"[
            :500
        ]

    measured_heap_values = [
        int(value["used_js_heap_bytes"])
        for value in heap_samples
        if int(value["used_js_heap_bytes"]) > 0
    ]
    maximum_js_heap_bytes = max(measured_heap_values, default=None)
    automated_accessibility_rules = [
        {
            "id": "A11Y-001",
            "wcag": ["4.1.1"],
            "title": "Unique element identifiers",
            "passed": not accessibility.get("duplicate_ids"),
            "evidence": accessibility.get("duplicate_ids", []),
        },
        {
            "id": "A11Y-002",
            "wcag": ["4.1.2", "2.4.4"],
            "title": "Accessible names for buttons and links",
            "passed": not accessibility.get("unnamed_buttons")
            and not accessibility.get("links_without_name"),
            "evidence": {
                "unnamed_buttons": accessibility.get("unnamed_buttons"),
                "unnamed_links": accessibility.get("links_without_name"),
            },
        },
        {
            "id": "A11Y-003",
            "wcag": ["1.3.1", "3.3.2"],
            "title": "Programmatic form labels",
            "passed": not accessibility.get("unlabeled_controls"),
            "evidence": accessibility.get("unlabeled_controls", []),
        },
        {
            "id": "A11Y-004",
            "wcag": ["1.3.1", "2.4.2", "3.1.1"],
            "title": "Language, title, headings, and landmarks",
            "passed": bool(accessibility.get("html_lang"))
            and bool(accessibility.get("document_title"))
            and accessibility.get("main_landmarks") == 1
            and accessibility.get("navigation_landmarks", 0) >= 1
            and accessibility.get("level_one_headings") == 1,
            "evidence": {
                key: accessibility.get(key)
                for key in (
                    "html_lang",
                    "document_title",
                    "main_landmarks",
                    "navigation_landmarks",
                    "level_one_headings",
                )
            },
        },
        {
            "id": "A11Y-005",
            "wcag": ["1.3.1"],
            "title": "Table captions and header scope",
            "passed": not accessibility.get("tables_without_caption")
            and not accessibility.get("headers_without_scope"),
            "evidence": {
                "tables_without_caption": accessibility.get("tables_without_caption"),
                "headers_without_scope": accessibility.get("headers_without_scope"),
            },
        },
        {
            "id": "A11Y-006",
            "wcag": ["2.4.1", "2.4.7"],
            "title": "Bypass block and visible keyboard focus",
            "passed": accessibility.get("skip_link_target") == "#mainContent"
            and focus_indicator["visible"],
            "evidence": {
                "skip_link_target": accessibility.get("skip_link_target"),
                "focus_indicator": focus_indicator,
            },
        },
        {
            "id": "A11Y-007",
            "wcag": ["1.1.1", "4.1.2"],
            "title": "Text alternatives and named dialogs",
            "passed": not accessibility.get("images_without_alt")
            and not accessibility.get("dialogs_without_name"),
            "evidence": {
                "images_without_alt": accessibility.get("images_without_alt"),
                "dialogs_without_name": accessibility.get("dialogs_without_name"),
            },
        },
    ]
    manual_verification = None
    if manual_evidence is not None:
        manual_verification = verify_accessibility_evidence(
            load_accessibility_evidence(manual_evidence), report=path
        )
    checks = {
        "report_integrity": bool(integrity["valid"]),
        "size_budget": None if max_bytes is None else integrity["bytes"] <= max_bytes,
        "browser_execution": not browser_execution_error,
        "load_budget": (
            None
            if max_load_seconds is None
            else load_seconds is not None and load_seconds <= max_load_seconds
        ),
        "js_heap_measurement": maximum_js_heap_bytes is not None,
        "js_heap_budget": (
            None
            if max_js_heap_bytes is None
            else maximum_js_heap_bytes is not None
            and maximum_js_heap_bytes <= max_js_heap_bytes
        ),
        "progressive_rendering": bool(rendering)
        and rendering.get("mode") == "progressive_on_demand"
        and rendering.get("initial_ready") is True
        and rendering.get("all_views_ready") is True
        and rendering.get("rendered_view_count") == rendering.get("total_view_count")
        and rendering.get("total_view_count") == len(view_checks),
        "navigation": bool(view_checks)
        and all(
            value["visible"]
            and value["navigation_active"]
            and value["render_state"] == "ready"
            for value in view_checks
        ),
        "responsive_layout": bool(responsive_checks)
        and all(value["passed"] for value in responsive_checks),
        "saved_and_shareable_views": saved_view_checks.get("passed", False),
        "automated_accessibility": all(
            value["passed"] for value in automated_accessibility_rules
        ),
        "manual_accessibility_evidence": (
            None if manual_verification is None else manual_verification["qualified"]
        ),
        "console_errors": not console_errors,
        "page_errors": not page_errors,
    }
    passed = all(value is not False for value in checks.values())
    receipt = {
        "format": BROWSER_QUALITY_FORMAT,
        "tool": {"name": "PySFMEA", "version": __version__},
        "report": str(path),
        "bytes": integrity["bytes"],
        "load_seconds": load_seconds,
        "budgets": {
            "max_bytes": max_bytes,
            "max_load_seconds": max_load_seconds,
            "max_js_heap_bytes": max_js_heap_bytes,
            "authority": (
                "explicit_or_supported_default_quality_thresholds_not_representative_user_evidence"
            ),
        },
        "browser_memory": {
            "maximum_used_js_heap_bytes": maximum_js_heap_bytes,
            "samples": heap_samples,
            "measurement": "Chromium performance.memory usedJSHeapSize with precise-memory-info",
            "limitations": "Browser-process, GPU, native DOM, and operating-system memory are not included.",
        },
        "rendering": rendering,
        "checks": checks,
        "views": view_checks,
        "responsive": responsive_checks,
        "saved_views": saved_view_checks,
        "accessibility": {
            "automated_rules": automated_accessibility_rules,
            "manual_evidence": manual_verification,
            "manual_scenarios": [
                {"id": identifier, "procedure": procedure}
                for identifier, procedure in REQUIRED_ACCESSIBILITY_SCENARIOS
            ],
            "coverage_notice": (
                "The automated subset covers deterministic DOM semantics and keyboard "
                "focus. Contrast, zoom/reflow, display preferences, and assistive-technology "
                "usability require the bound manual evidence workflow."
            ),
        },
        "console_errors": console_errors,
        "page_errors": page_errors,
        "browser_execution_error": browser_execution_error,
        "passed": passed,
        "notice": (
            "This receipt separates deterministic browser checks from exact-report manual "
            "accessibility evidence; neither substitutes for representative-user evaluation."
        ),
    }
    return bind_browser_quality_receipt(receipt, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--analysis")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_REPORT_BYTES,
        help=f"maximum report bytes (default: {DEFAULT_MAX_REPORT_BYTES})",
    )
    parser.add_argument(
        "--max-load-seconds",
        type=float,
        default=DEFAULT_MAX_LOAD_SECONDS,
        help=f"maximum measured report load seconds (default: {DEFAULT_MAX_LOAD_SECONDS:g})",
    )
    parser.add_argument(
        "--max-js-heap-bytes",
        type=int,
        default=DEFAULT_MAX_JS_HEAP_BYTES,
        help=(
            "maximum measured Chromium JavaScript heap bytes "
            f"(default: {DEFAULT_MAX_JS_HEAP_BYTES})"
        ),
    )
    parser.add_argument(
        "--manual-evidence",
        help="sealed exact-report accessibility evidence; when supplied it must qualify",
    )
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    try:
        result = browser_quality_gate(
            args.report,
            analysis=args.analysis,
            max_bytes=args.max_bytes,
            max_load_seconds=args.max_load_seconds,
            max_js_heap_bytes=args.max_js_heap_bytes,
            manual_evidence=args.manual_evidence,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"report browser gate failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        atomic_publish_text(args.output, rendered, label="browser quality receipt")
    else:
        sys.stdout.write(rendered)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
