"""Convert one bounded JUnit test result into a platform qualification receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from pysfmea.file_publication import atomic_publish_text
from pysfmea.integrity import canonical_json_sha256
from pysfmea.version import __version__

FORMAT = "pysfmea-platform-qualification-1"
MAX_JUNIT_BYTES = 50_000_000


def platform_qualification_receipt(source: str | Path) -> dict[str, Any]:
    path = Path(os.path.abspath(Path(source).expanduser()))
    inspected = path.lstat()
    if not stat.S_ISREG(inspected.st_mode):
        raise ValueError("JUnit evidence must be a regular non-symbolic-link file")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            inspected.st_dev,
            inspected.st_ino,
            inspected.st_size,
            inspected.st_mtime_ns,
        ) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise ValueError("JUnit evidence changed during safe open")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_JUNIT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_JUNIT_BYTES:
        raise ValueError(f"JUnit evidence exceeds {MAX_JUNIT_BYTES} bytes")
    current = path.lstat()
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_size,
        opened_after.st_mtime_ns,
    ) or (
        opened_after.st_dev,
        opened_after.st_ino,
        opened_after.st_size,
        opened_after.st_mtime_ns,
    ) != (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    ):
        raise ValueError("JUnit evidence changed while it was being consumed")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise ValueError("JUnit evidence is not safe, valid XML") from exc
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if root.tag not in {"testsuite", "testsuites"} or not suites:
        raise ValueError("JUnit evidence must contain testsuite records")

    def total(field: str) -> int:
        try:
            return sum(int(value.attrib.get(field, "0")) for value in suites)
        except ValueError as exc:
            raise ValueError(f"JUnit {field} totals must be integers") from exc

    counts = {
        "tests": total("tests"),
        "failures": total("failures"),
        "errors": total("errors"),
        "skipped": total("skipped"),
    }
    passed = counts["tests"] > 0 and not counts["failures"] and not counts["errors"]
    material = {
        "format": FORMAT,
        "tool": {"name": "PySFMEA", "version": __version__},
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "junit": {
            "path": path.name,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "counts": counts,
        },
        "passed": passed,
        "authority": "as_run_test_receipt_for_exact_platform_not_general_qualification",
        "limitations": [
            "The receipt proves only the captured test run and exact JUnit bytes.",
            "Hosted-runner hardware, filesystem, locale, and security behavior may differ from deployment environments.",
            "Skipped tests remain visible and require compatible-runner evidence where they cover platform-specific behavior.",
        ],
    }
    return {**material, "content_sha256": canonical_json_sha256(material)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit")
    parser.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    try:
        result = platform_qualification_receipt(args.junit)
    except (OSError, ValueError) as exc:
        print(f"platform qualification failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        atomic_publish_text(
            args.output, rendered, label="platform qualification receipt"
        )
    else:
        sys.stdout.write(rendered)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
