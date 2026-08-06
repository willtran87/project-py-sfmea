"""Bounded, identity-safe publication for deterministic single-file artifacts."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

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
    staged_verifier: Callable[[Path], bool] | None = None,
) -> Path:
    """Atomically publish bounded, optionally verified bytes without losing prior content."""

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
        if staged_verifier is not None:
            try:
                verified = staged_verifier(temporary)
            except Exception as exc:
                raise ValueError(f"staged {label} verification failed") from exc
            if verified is not True:
                raise ValueError(f"staged {label} verification failed")
            staged_descriptor: int | None = None
            try:
                verified_stage = temporary.lstat()
                if (
                    not stat.S_ISREG(verified_stage.st_mode)
                    or verified_stage.st_size != len(content)
                    or not os.path.samestat(staged, verified_stage)
                ):
                    raise ValueError(f"staged {label} changed during verification")
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                staged_descriptor = os.open(temporary, flags)
                opened_stage = os.fstat(staged_descriptor)
                if (
                    not stat.S_ISREG(opened_stage.st_mode)
                    or not os.path.samestat(verified_stage, opened_stage)
                ):
                    raise ValueError(f"staged {label} changed during verification")
                with os.fdopen(staged_descriptor, "rb") as staged_file:
                    staged_descriptor = None
                    staged_digest = hashlib.file_digest(staged_file, "sha256").digest()
                final_stage = temporary.lstat()
                if not os.path.samestat(opened_stage, final_stage):
                    raise ValueError(f"staged {label} changed during verification")
            except ValueError:
                raise
            except OSError as exc:
                raise ValueError(
                    f"staged {label} changed during verification"
                ) from exc
            finally:
                if staged_descriptor is not None:
                    try:
                        os.close(staged_descriptor)
                    except OSError:
                        pass
            if staged_digest != hashlib.sha256(content).digest():
                raise ValueError(f"staged {label} changed during verification")
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
    staged_verifier: Callable[[Path], bool] | None = None,
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
        staged_verifier=staged_verifier,
    )
