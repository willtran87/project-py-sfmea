"""Bounded, identity-safe publication for deterministic single-file artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAX_ARTIFACT_PUBLICATION_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArtifactDestinationState:
    """Opaque final-path state retained across validation and publication."""

    path: Path
    snapshot: tuple[int, int, int, int, int] | None


def _destination_snapshot(path: Path) -> tuple[int, int, int, int, int] | None:
    """Describe a final path without following symbolic links."""

    try:
        state = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(state.st_mode):
        raise ValueError("artifact destination must not be a symbolic link")
    if not stat.S_ISREG(state.st_mode):
        raise ValueError("artifact destination must be a regular file path")
    return (
        state.st_dev,
        state.st_ino,
        state.st_size,
        state.st_mtime_ns,
        state.st_ctime_ns,
    )


def _destination_is_unchanged(
    path: Path, expected: tuple[int, int, int, int, int] | None
) -> bool:
    """Return whether the final path still has its inspected identity and state."""

    try:
        current = _destination_snapshot(path)
    except ValueError:
        return False
    return current == expected


def inspect_artifact_destination(
    destination: str | Path, *, label: str = "artifact"
) -> ArtifactDestinationState:
    """Prepare and inspect a final artifact path without following its final link."""

    supplied = Path(os.path.abspath(Path(destination).expanduser()))
    if supplied.is_symlink():
        raise ValueError(f"{label} destination must not be a symbolic link")
    try:
        supplied.parent.mkdir(parents=True, exist_ok=True)
        target = supplied.parent.resolve(strict=True) / supplied.name
        snapshot = _destination_snapshot(target)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} destination could not be prepared safely") from exc
    return ArtifactDestinationState(path=target, snapshot=snapshot)


def atomic_publish_bytes(
    destination: str | Path,
    content: bytes,
    *,
    max_bytes: int = MAX_ARTIFACT_PUBLICATION_BYTES,
    label: str = "artifact",
    expected_destination: ArtifactDestinationState | None = None,
) -> Path:
    """Atomically publish bounded bytes while preserving a concurrently changed target."""

    if not isinstance(content, bytes):
        raise TypeError("artifact content must be bytes")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("artifact publication byte limit must be a positive integer")
    if len(content) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte publication limit")

    current = inspect_artifact_destination(destination, label=label)
    if expected_destination is None:
        expected = current
    elif isinstance(expected_destination, ArtifactDestinationState):
        expected = expected_destination
        if current.path != expected.path or current.snapshot != expected.snapshot:
            raise ValueError(f"{label} destination changed before staging")
    else:
        raise TypeError("expected artifact destination state is invalid")
    target = expected.path

    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as handle:
            written = handle.write(content)
            if written != len(content):
                raise OSError("short artifact write")
            handle.flush()
            os.fsync(handle.fileno())
        staged = temporary.lstat()
        if not stat.S_ISREG(staged.st_mode) or staged.st_size != len(content):
            raise ValueError(f"staged {label} did not preserve the rendered content")
        if not _destination_is_unchanged(target, expected.snapshot):
            raise ValueError(f"{label} destination changed before atomic replacement")
        os.replace(temporary, target)
        temporary = None
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} could not be published safely") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return target


def atomic_publish_text(
    destination: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
    max_bytes: int = MAX_ARTIFACT_PUBLICATION_BYTES,
    label: str = "artifact",
    expected_destination: ArtifactDestinationState | None = None,
) -> Path:
    """Encode and atomically publish a bounded deterministic text artifact."""

    if not isinstance(content, str):
        raise TypeError("artifact content must be text")
    try:
        encoded = content.encode(encoding)
    except (LookupError, UnicodeEncodeError) as exc:
        raise ValueError(f"{label} could not be encoded as {encoding}") from exc
    return atomic_publish_bytes(
        destination,
        encoded,
        max_bytes=max_bytes,
        label=label,
        expected_destination=expected_destination,
    )
