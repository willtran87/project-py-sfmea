"""Deterministic browser-backed rendering of the self-contained HTML report to PDF."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterable
from os import replace as atomic_replace
from pathlib import Path
from typing import Any

from .diagrams import (
    DEFAULT_PROPAGATION_DEPTH,
    DEFAULT_PROPAGATION_PATH_LIMIT,
    DEFAULT_PROPAGATION_RECORD_LIMIT,
)
from .html_report import MAX_REPORT_RECORDS, export_html_report

_BROWSER_COMMANDS = (
    "msedge",
    "microsoft-edge",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)

MAX_PDF_REPORT_BYTES = 250_000_000
_PDF_COPY_CHUNK_BYTES = 1024 * 1024


def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
    common = bool(
        os.path.samestat(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
    )
    # On Windows, path stat and descriptor stat can expose different creation-time
    # precision for the same file. File identity, size, and modification time remain
    # stable across both APIs; descriptor-to-descriptor changes still alter size or mtime.
    return common and (os.name == "nt" or first.st_ctime_ns == second.st_ctime_ns)


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _inspect_regular_pdf(path: Path) -> os.stat_result:
    try:
        inspected = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError("generated PDF is unavailable") from exc
    except OSError as exc:
        raise ValueError("generated PDF could not be inspected safely") from exc
    if not stat.S_ISREG(inspected.st_mode):
        raise ValueError("generated PDF is not a regular non-symbolic-link file")
    return inspected


def _inspect_pdf_destination(path: Path) -> os.stat_result | None:
    try:
        inspected = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("PDF destination could not be inspected safely") from exc
    if not stat.S_ISREG(inspected.st_mode):
        raise ValueError("PDF destination must be a regular non-symbolic-link file")
    return inspected


def _destination_is_unchanged(path: Path, expected: os.stat_result | None) -> bool:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return expected is None
    except OSError:
        return False
    return bool(
        expected is not None
        and stat.S_ISREG(current.st_mode)
        and _same_file_state(expected, current)
    )


def _copy_stable_pdf(source: Path, destination_descriptor: int) -> None:
    inspected = _inspect_regular_pdf(source)
    source_descriptor: int | None = None
    destination_open = True
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, flags)
        opened_before = os.fstat(source_descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_file_state(
            inspected, opened_before
        ):
            raise ValueError("generated PDF changed during safe open")
        consumed = 0
        with (
            os.fdopen(source_descriptor, "rb") as source_handle,
            os.fdopen(destination_descriptor, "wb") as destination_handle,
        ):
            source_descriptor = None
            destination_open = False
            while chunk := source_handle.read(_PDF_COPY_CHUNK_BYTES):
                consumed += len(chunk)
                if consumed > MAX_PDF_REPORT_BYTES:
                    raise ValueError(
                        "generated PDF exceeds the bounded publication size limit"
                    )
                destination_handle.write(chunk)
            opened_after = os.fstat(source_handle.fileno())
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        if not _same_file_state(opened_before, opened_after):
            raise ValueError("generated PDF changed while it was being published")
        try:
            current = source.lstat()
        except OSError as exc:
            raise ValueError(
                "generated PDF changed while it was being published"
            ) from exc
        if not _same_file_state(opened_after, current):
            raise ValueError("generated PDF changed while it was being published")
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_open:
            os.close(destination_descriptor)


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
    """Perform bounded, identity-stable structural checks on a generated PDF."""

    source = _absolute_path(path)
    inspected = _inspect_regular_pdf(source)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_file_state(
            inspected, opened_before
        ):
            raise ValueError("generated PDF changed during safe open")
        size = opened_before.st_size
        if size > MAX_PDF_REPORT_BYTES:
            raise ValueError("generated PDF exceeds the bounded verification size limit")
        if size < 1024:
            raise ValueError(f"generated PDF is unexpectedly small ({size} bytes)")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            header = handle.read(8)
            handle.seek(max(0, size - 4096))
            trailer = handle.read(4096)
            opened_after = os.fstat(handle.fileno())
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("generated PDF could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not _same_file_state(opened_before, opened_after):
        raise ValueError("generated PDF changed while it was being verified")
    try:
        current = source.lstat()
    except OSError as exc:
        raise ValueError("generated PDF changed while it was being verified") from exc
    if not _same_file_state(opened_after, current):
        raise ValueError("generated PDF changed while it was being verified")
    if not header.startswith(b"%PDF-"):
        raise ValueError("generated output has no PDF header")
    if b"%%EOF" not in trailer:
        raise ValueError("generated output has no PDF end marker")
    return {"path": str(source), "bytes": size, "header": header.decode("ascii", "replace")}


def export_pdf_report(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    title: str | None = None,
    notes: str | Path | None = None,
    max_records: int = 10_000,
    diagrams: list[str | Path] | None = None,
    propagation_record_limit: int = DEFAULT_PROPAGATION_RECORD_LIMIT,
    propagation_path_limit: int = DEFAULT_PROPAGATION_PATH_LIMIT,
    propagation_depth: int = DEFAULT_PROPAGATION_DEPTH,
    propagation_include_finding_ids: Iterable[str] | None = None,
    browser: str | Path | None = None,
    timeout_seconds: int = 180,
) -> Path:
    """Render the polished report to an atomically published, verified PDF."""

    if not 1 <= max_records <= MAX_REPORT_RECORDS:
        raise ValueError(f"max_records must be from 1 through {MAX_REPORT_RECORDS}")
    if not 10 <= timeout_seconds <= 900:
        raise ValueError("timeout_seconds must be from 10 through 900")
    supplied_target = _absolute_path(destination)
    if supplied_target.is_symlink():
        raise ValueError("PDF destination must be a regular non-symbolic-link file")
    supplied_target.parent.mkdir(parents=True, exist_ok=True)
    target = supplied_target.parent.resolve() / supplied_target.name
    destination_state = _inspect_pdf_destination(target)
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
            propagation_record_limit=propagation_record_limit,
            propagation_path_limit=propagation_path_limit,
            propagation_depth=propagation_depth,
            propagation_include_finding_ids=propagation_include_finding_ids,
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
        publish: Path | None = None
        try:
            descriptor, staging_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            publish = Path(staging_name)
            _copy_stable_pdf(rendered, descriptor)
            verify_pdf_file(publish)
            if not _destination_is_unchanged(target, destination_state):
                raise ValueError("PDF destination changed before atomic replacement")
            atomic_replace(publish, target)
            publish = None
        finally:
            if publish is not None:
                try:
                    publish.unlink(missing_ok=True)
                except OSError:
                    pass
    return target
