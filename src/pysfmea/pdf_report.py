"""Deterministic browser-backed rendering of the self-contained HTML report to PDF."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .html_report import MAX_REPORT_RECORDS, export_html_report

_BROWSER_COMMANDS = (
    "msedge",
    "microsoft-edge",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)


def _platform_browser_candidates() -> Iterable[Path]:
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        root = os.environ.get(variable)
        if not root:
            continue
        base = Path(root)
        yield base / "Microsoft" / "Edge" / "Application" / "msedge.exe"
        yield base / "Google" / "Chrome" / "Application" / "chrome.exe"
    yield Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    yield Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")


def resolve_pdf_browser(explicit: str | Path | None = None) -> Path:
    """Resolve a Chromium-family executable without invoking a shell."""

    requested = explicit or os.environ.get("PYSFMEA_BROWSER", "")
    if requested:
        candidate = Path(requested).expanduser().resolve()
        if not candidate.is_file():
            raise ValueError(f"PDF browser executable is not a regular file: {candidate}")
        return candidate
    for command in _BROWSER_COMMANDS:
        resolved = shutil.which(command)
        if resolved:
            candidate = Path(resolved).resolve()
            if candidate.is_file():
                return candidate
    for candidate in _platform_browser_candidates():
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError(
        "No Chromium-family browser was found. Install Edge, Chrome, or Chromium, "
        "or pass --browser /path/to/browser (PYSFMEA_BROWSER is also supported)."
    )


def verify_pdf_file(path: str | Path) -> dict[str, Any]:
    """Perform dependency-free structural checks on a generated PDF."""

    source = Path(path).expanduser().resolve()
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"generated PDF is not a regular file: {source}")
    size = source.stat().st_size
    if size < 1024:
        raise ValueError(f"generated PDF is unexpectedly small ({size} bytes): {source}")
    with source.open("rb") as handle:
        header = handle.read(8)
        handle.seek(max(0, size - 4096))
        trailer = handle.read()
    if not header.startswith(b"%PDF-"):
        raise ValueError(f"generated output has no PDF header: {source}")
    if b"%%EOF" not in trailer:
        raise ValueError(f"generated output has no PDF end marker: {source}")
    return {"path": str(source), "bytes": size, "header": header.decode("ascii", "replace")}


def export_pdf_report(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    title: str | None = None,
    notes: str | Path | None = None,
    max_records: int = 10_000,
    diagrams: list[str | Path] | None = None,
    browser: str | Path | None = None,
    timeout_seconds: int = 180,
) -> Path:
    """Render the polished report to an atomically published, verified PDF."""

    if not 1 <= max_records <= MAX_REPORT_RECORDS:
        raise ValueError(f"max_records must be from 1 through {MAX_REPORT_RECORDS}")
    if not 10 <= timeout_seconds <= 900:
        raise ValueError("timeout_seconds must be from 10 through 900")
    target = Path(destination).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    executable = resolve_pdf_browser(browser)
    with tempfile.TemporaryDirectory(prefix="pysfmea-pdf-") as temporary:
        staging = Path(temporary)
        html_path = export_html_report(
            analysis,
            staging / "report.html",
            title=title,
            notes=notes,
            max_records=max_records,
            diagrams=diagrams,
        )
        rendered = staging / "report.pdf"
        command = [
            str(executable),
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--allow-file-access-from-files",
            "--no-pdf-header-footer",
            f"--print-to-pdf={rendered}",
            html_path.as_uri(),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode != 0 or not rendered.is_file():
            detail = (completed.stderr or completed.stdout or "no browser diagnostics").strip()
            raise RuntimeError(
                f"PDF browser render failed with exit code {completed.returncode}: {detail[:2000]}"
            )
        verify_pdf_file(rendered)
        publish = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        shutil.copyfile(rendered, publish)
        os.replace(publish, target)
    verify_pdf_file(target)
    return target
