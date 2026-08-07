"""Exercise a generated SFMEA report in Chromium and emit a CI quality receipt."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from pysfmea.file_publication import atomic_publish_text
from pysfmea.html_report import verify_html_report_file
from pysfmea.store import load_analysis
from pysfmea.version import __version__


def browser_quality_gate(
    report: str | Path,
    *,
    analysis: str | Path | None = None,
    max_bytes: int | None = None,
    max_load_seconds: float | None = None,
) -> dict[str, Any]:
    if max_bytes is not None and (isinstance(max_bytes, bool) or max_bytes <= 0):
        raise ValueError("max_bytes must be a positive integer")
    if max_load_seconds is not None and max_load_seconds <= 0:
        raise ValueError("max_load_seconds must be greater than zero")
    path = Path(report).expanduser().resolve()
    current = load_analysis(analysis) if analysis else None
    integrity = verify_html_report_file(path, analysis=current)
    try:
        from playwright.sync_api import (  # type: ignore[import-not-found]
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
    started = time.perf_counter()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            page.goto(path.as_uri(), wait_until="domcontentloaded")
            page.locator("#topTitle").wait_for(state="visible")
            page.wait_for_function(
                "document.querySelector('#topTitle').textContent.trim().length > 0"
            )
            load_seconds = round(time.perf_counter() - started, 6)
            views = page.locator("#nav button[data-view]").evaluate_all(
                "nodes => nodes.map(node => node.dataset.view)"
            )
            for view in views:
                page.locator(f'#nav button[data-view="{view}"]').click()
                visible = page.locator(f'.view[data-view="{view}"]').is_visible()
                active = page.locator(
                    f'#nav button[data-view="{view}"].active'
                ).count() == 1
                view_checks.append(
                    {"view": view, "visible": visible, "navigation_active": active}
                )
            for width, height, label in (
                (1440, 900, "desktop"),
                (390, 844, "mobile"),
            ):
                page.set_viewport_size({"width": width, "height": height})
                page.locator('#nav button[data-view="overview"]').click()
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

    checks = {
        "report_integrity": bool(integrity["valid"]),
        "size_budget": None if max_bytes is None else integrity["bytes"] <= max_bytes,
        "load_budget": (
            None if max_load_seconds is None else load_seconds <= max_load_seconds
        ),
        "navigation": all(
            value["visible"] and value["navigation_active"] for value in view_checks
        ),
        "responsive_layout": all(value["passed"] for value in responsive_checks),
        "console_errors": not console_errors,
        "page_errors": not page_errors,
    }
    passed = all(value is not False for value in checks.values())
    return {
        "format": "pysfmea-report-browser-quality-1",
        "tool": {"name": "PySFMEA", "version": __version__},
        "report": str(path),
        "bytes": integrity["bytes"],
        "load_seconds": load_seconds,
        "checks": checks,
        "views": view_checks,
        "responsive": responsive_checks,
        "console_errors": console_errors,
        "page_errors": page_errors,
        "passed": passed,
        "notice": (
            "This is a deterministic Chromium smoke and budget gate, not a substitute "
            "for accessibility review or representative-user evaluation."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--analysis")
    parser.add_argument("--max-bytes", type=int)
    parser.add_argument("--max-load-seconds", type=float)
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    try:
        result = browser_quality_gate(
            args.report,
            analysis=args.analysis,
            max_bytes=args.max_bytes,
            max_load_seconds=args.max_load_seconds,
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
