"""Strict, bounded, identity-stable ingestion for governed JSON artifacts."""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .integrity import bounded_json_structure_metrics

_same_file_identity = os.path.samestat


class BoundedFileSnapshotError(ValueError):
    """Reject a file snapshot while retaining its bounded I/O accounting."""

    def __init__(self, message: str, *, bytes_consumed: int = 0) -> None:
        super().__init__(message)
        self.bytes_consumed = bytes_consumed


@dataclass(frozen=True)
class BoundedFileSnapshot:
    """One exact bounded snapshot from a stable regular non-link file."""

    path: Path
    raw: bytes

    @property
    def size(self) -> int:
        return len(self.raw)


@dataclass(frozen=True)
class BoundedJsonDocument:
    """One stable governed JSON file, its decoded value, and exact captured bytes."""

    path: Path
    value: Any
    raw: bytes

    @property
    def size(self) -> int:
        return len(self.raw)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"JSON contains a non-finite number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON contains a non-finite number")
    return parsed


def _validate_limits(
    *, label: str, max_bytes: int, max_depth: int, max_nodes: int
) -> None:
    for name, value in (
        ("byte", max_bytes),
        ("depth", max_depth),
        ("node", max_nodes),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{label} {name} limit must be a positive integer")


def load_bounded_file_snapshot(
    source: str | Path,
    *,
    label: str,
    max_bytes: int,
) -> BoundedFileSnapshot:
    """Capture one exact bounded stream from a stable regular non-link file."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError(f"{label} byte limit must be a positive integer")

    path = Path(os.path.abspath(Path(source).expanduser()))
    try:
        inspected = path.lstat()
    except OSError as exc:
        raise BoundedFileSnapshotError(
            f"{label} must be an available regular file"
        ) from exc
    if stat.S_ISLNK(inspected.st_mode) or not stat.S_ISREG(inspected.st_mode):
        raise BoundedFileSnapshotError(
            f"{label} must be a regular non-symbolic-link file"
        )

    descriptor: int | None = None
    opened: os.stat_result | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_identity(inspected, opened):
            raise BoundedFileSnapshotError(f"{label} changed during safe open")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(max_bytes + 1)
    except BoundedFileSnapshotError:
        raise
    except OSError as exc:
        raise BoundedFileSnapshotError(f"{label} could not be read safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    try:
        current = path.lstat()
    except OSError as exc:
        raise BoundedFileSnapshotError(
            f"{label} changed during bounded consumption",
            bytes_consumed=len(raw),
        ) from exc
    if opened is None or not _same_file_identity(opened, current):
        raise BoundedFileSnapshotError(
            f"{label} changed during bounded consumption",
            bytes_consumed=len(raw),
        )
    if len(raw) > max_bytes:
        raise BoundedFileSnapshotError(
            f"{label} exceeds the {max_bytes}-byte limit",
            bytes_consumed=len(raw),
        )
    return BoundedFileSnapshot(path=path, raw=raw)


def parse_bounded_json_bytes(
    raw: bytes,
    *,
    label: str,
    max_bytes: int,
    max_depth: int,
    max_nodes: int,
) -> Any:
    """Strictly decode one already-captured bounded UTF-8 JSON document."""

    _validate_limits(
        label=label,
        max_bytes=max_bytes,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    if not isinstance(raw, bytes):
        raise ValueError(f"{label} input must be bytes")
    if len(raw) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    except RecursionError as exc:
        raise ValueError(f"{label} exceeds the JSON parser nesting limit") from exc

    metrics = bounded_json_structure_metrics(
        value,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    if not metrics["depth_within_limit"]:
        raise ValueError(f"{label} exceeds the {max_depth}-level JSON depth limit")
    if not metrics["node_within_limit"]:
        raise ValueError(f"{label} exceeds the {max_nodes}-node JSON structure limit")
    return value


def load_bounded_json_document(
    source: str | Path,
    *,
    label: str,
    max_bytes: int,
    max_depth: int,
    max_nodes: int,
) -> BoundedJsonDocument:
    """Capture strict UTF-8 JSON from one stable regular non-link file."""

    _validate_limits(
        label=label,
        max_bytes=max_bytes,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )

    snapshot = load_bounded_file_snapshot(
        source,
        label=label,
        max_bytes=max_bytes,
    )

    value = parse_bounded_json_bytes(
        snapshot.raw,
        label=label,
        max_bytes=max_bytes,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    return BoundedJsonDocument(
        path=snapshot.path,
        value=value,
        raw=snapshot.raw,
    )


def load_bounded_json_file(
    source: str | Path,
    *,
    label: str,
    max_bytes: int,
    max_depth: int,
    max_nodes: int,
) -> tuple[Path, Any, int]:
    """Load strict JSON and return the compatibility path/value/size tuple."""

    document = load_bounded_json_document(
        source,
        label=label,
        max_bytes=max_bytes,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    return document.path, document.value, document.size
