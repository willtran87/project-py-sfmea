"""Optional detached Ed25519 signatures for verified review packages."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .model import utc_now
from .report import verify_review_package

SIGNATURE_FORMAT = "pysfmea-detached-signature-1"
STATEMENT_FORMAT = "pysfmea-signature-statement-1"
MAX_KEY_BYTES = 1_000_000
MAX_SIGNATURE_BYTES = 1_000_000
MAX_MANIFEST_BYTES = 10_000_000
MAX_SIGNED_ARCHIVE_BYTES = 550_000_000
MAX_SIGNER_CHARS = 4_096
MAX_PASSPHRASE_BYTES = 1_000_000


def sign_review_package(
    package: str | Path,
    private_key: str | Path,
    signer: str,
    *,
    destination: str | Path | None = None,
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> Path:
    """Create an atomic detached signature for a valid directory or ZIP package."""

    if not isinstance(signer, str):
        raise ValueError("signer must be a string identity label")
    signer_name = signer.strip()
    if not signer_name:
        raise ValueError("signer must be a non-empty identity label")
    if len(signer_name) > MAX_SIGNER_CHARS:
        raise ValueError(
            f"signer identity exceeds the {MAX_SIGNER_CHARS}-character limit"
        )
    if passphrase is not None and not isinstance(passphrase, bytes):
        raise ValueError("private-key passphrase must be bytes")
    if passphrase is not None and len(passphrase) > MAX_PASSPHRASE_BYTES:
        raise ValueError(
            f"private-key passphrase exceeds the {MAX_PASSPHRASE_BYTES}-byte limit"
        )
    verification = verify_review_package(package)
    if not verification["valid"]:
        raise ValueError("review package must pass integrity verification before signing")

    artifact = Path(package).expanduser().absolute()
    key_path = Path(private_key).expanduser().absolute()
    output = (
        Path(destination).expanduser().absolute()
        if destination
        else artifact.with_name(artifact.name + ".sig.json")
    )
    if artifact.is_dir() and _is_within(output, artifact):
        raise ValueError("detached signature must be stored outside the package directory")
    if output == artifact or output == key_path:
        raise ValueError("signature destination must be separate from the package and key")
    output_snapshot = _publication_destination_snapshot(output)
    if output_snapshot is not None:
        if not overwrite:
            raise ValueError("signature already exists; use --force to replace it")

    _key_path, private_key_bytes = _read_regular_bounded(
        key_path, "private key", MAX_KEY_BYTES
    )

    Ed25519PrivateKey, _Ed25519PublicKey, serialization, _InvalidSignature = _crypto()
    try:
        loaded = serialization.load_pem_private_key(
            private_key_bytes, password=passphrase
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Ed25519 private key could not be loaded with the supplied credentials"
        ) from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("private key must be an Ed25519 PEM key")

    public_key = loaded.public_key()
    statement = {
        "format": STATEMENT_FORMAT,
        "algorithm": "Ed25519",
        "signed_at": utc_now(),
        "signer": signer_name,
        "subject": _signature_subject(artifact, verification),
    }
    signature = loaded.sign(_canonical(statement))
    envelope = {
        "format": SIGNATURE_FORMAT,
        "statement": statement,
        "key_fingerprint": _public_key_fingerprint(public_key, serialization),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    _atomic_write_json(
        output,
        envelope,
        expected_destination=output_snapshot,
    )
    return output


def verify_review_signature(
    package: str | Path,
    signature: str | Path,
    public_key: str | Path,
    *,
    package_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify integrity and a detached signature against an explicitly trusted key."""

    # A caller-supplied verdict is advisory only. Authentication always starts from a
    # fresh package verification so a stale or fabricated result cannot bypass integrity.
    del package_verification
    result = copy.deepcopy(verify_review_package(package))
    status: dict[str, Any] = {
        "present": True,
        "valid": False,
        "file": str(Path(signature).expanduser().absolute()),
        "signer": "",
        "signed_at": "",
        "key_fingerprint": "",
    }
    result["signature"] = status
    if not result["valid"]:
        return _signature_error(
            result,
            "signature.package_invalid",
            "Package integrity must pass before its detached signature can be trusted.",
        )

    try:
        signature_path, signature_raw = _read_regular_bounded(
            signature, "detached signature", MAX_SIGNATURE_BYTES
        )
        _key_path, public_key_bytes = _read_regular_bounded(
            public_key, "public key", MAX_KEY_BYTES
        )
        envelope = json.loads(signature_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        return _signature_error(
            result, "signature.input_invalid", f"Signature input cannot be read: {exc}"
        )

    if not isinstance(envelope, dict) or set(envelope) != {
        "format",
        "statement",
        "key_fingerprint",
        "signature",
    }:
        return _signature_error(
            result,
            "signature.envelope_invalid",
            "Detached signature envelope has unexpected or missing fields.",
        )
    statement = envelope.get("statement")
    if (
        envelope.get("format") != SIGNATURE_FORMAT
        or not isinstance(statement, dict)
        or set(statement) != {"format", "algorithm", "signed_at", "signer", "subject"}
        or statement.get("format") != STATEMENT_FORMAT
        or statement.get("algorithm") != "Ed25519"
        or not isinstance(statement.get("signed_at"), str)
        or not statement["signed_at"]
        or not isinstance(statement.get("signer"), str)
        or not statement["signer"].strip()
        or len(statement["signer"]) > MAX_SIGNER_CHARS
        or not isinstance(statement.get("subject"), dict)
        or not isinstance(envelope.get("key_fingerprint"), str)
        or len(envelope["key_fingerprint"]) != 71
        or not isinstance(envelope.get("signature"), str)
        or len(envelope["signature"]) != 88
    ):
        return _signature_error(
            result,
            "signature.envelope_invalid",
            "Detached signature metadata is malformed or uses an unsupported format.",
        )

    status.update(
        {
            "signer": statement["signer"],
            "signed_at": statement["signed_at"],
            "key_fingerprint": envelope["key_fingerprint"],
        }
    )
    artifact = Path(package).expanduser().absolute()
    try:
        expected_subject = _signature_subject(artifact, result)
    except ValueError:
        return _signature_error(
            result,
            "signature.package_changed",
            "Package bytes changed after integrity verification; signature verification stopped.",
        )
    if statement["subject"] != expected_subject:
        return _signature_error(
            result,
            "signature.subject_mismatch",
            "Signature claims do not match the current package digest or provenance.",
        )

    Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature = _crypto()
    del Ed25519PrivateKey
    try:
        loaded = serialization.load_pem_public_key(public_key_bytes)
    except (TypeError, ValueError):
        return _signature_error(
            result,
            "signature.key_invalid",
            "Trusted public key is not a loadable Ed25519 PEM key.",
        )
    if not isinstance(loaded, Ed25519PublicKey):
        return _signature_error(
            result, "signature.key_invalid", "Public key must be an Ed25519 PEM key."
        )
    fingerprint = _public_key_fingerprint(loaded, serialization)
    if envelope["key_fingerprint"] != fingerprint:
        return _signature_error(
            result,
            "signature.key_mismatch",
            "Trusted public-key fingerprint does not match the signed envelope.",
        )
    try:
        signature_bytes = base64.b64decode(envelope["signature"], validate=True)
    except (binascii.Error, ValueError) as exc:
        return _signature_error(
            result, "signature.value_invalid", f"Signature is not valid base64: {exc}"
        )
    if len(signature_bytes) != 64:
        return _signature_error(
            result,
            "signature.value_invalid",
            "Ed25519 signature must contain exactly 64 decoded bytes.",
        )
    try:
        loaded.verify(signature_bytes, _canonical(statement))
    except InvalidSignature:
        return _signature_error(
            result,
            "signature.verification_failed",
            "Detached signature does not verify with the trusted public key.",
        )

    status["valid"] = True
    result["notice"] = (
        result["notice"]
        + " The detached signature authenticates this package to the supplied public key; "
        "key ownership, authorization, and engineering approval remain external controls."
    )
    return result


def passphrase_from_environment(variable: str | None) -> bytes | None:
    if not variable:
        return None
    value = os.environ.get(variable)
    if value is None:
        raise ValueError(f"private-key passphrase environment variable is not set: {variable}")
    if not value:
        raise ValueError(f"private-key passphrase environment variable is empty: {variable}")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_PASSPHRASE_BYTES:
        raise ValueError(
            "private-key passphrase environment value exceeds the "
            f"{MAX_PASSPHRASE_BYTES}-byte limit"
        )
    return encoded


def _signature_subject(artifact: Path, verification: dict[str, Any]) -> dict[str, str]:
    manifest, manifest_sha256 = _read_manifest(artifact)
    verified_manifest_sha256 = verification.get("manifest_sha256")
    if (
        not _is_sha256(verified_manifest_sha256)
        or manifest_sha256 != verified_manifest_sha256
    ):
        raise ValueError("package manifest changed after integrity verification")
    if verification["container"] == "zip":
        digest_scope = "zip_bytes"
        digest = verification.get("archive_sha256")
        _archive_path, observed_archive_sha256 = _hash_regular_bounded(
            artifact,
            "verified package archive",
            MAX_SIGNED_ARCHIVE_BYTES,
        )
        if digest != observed_archive_sha256:
            raise ValueError("package archive changed after integrity verification")
    else:
        digest_scope = "manifest_bytes"
        digest = manifest_sha256
    if not _is_sha256(digest):
        raise ValueError("verified package digest is unavailable or malformed")
    return {
        "container": verification["container"],
        "digest_scope": digest_scope,
        "sha256": digest,
        "package_format": verification["format"],
        "project": str(manifest.get("project", "")),
        "baseline_id": str(manifest.get("baseline_id", "")),
        "analysis_schema_version": str(manifest.get("analysis_schema_version", "")),
        "package_generated_at": str(manifest.get("generated_at", "")),
    }


def _read_manifest(artifact: Path) -> tuple[dict[str, Any], str]:
    try:
        if artifact.suffix.lower() == ".zip":
            with zipfile.ZipFile(artifact, "r", allowZip64=True) as bundle:
                entry = bundle.getinfo("manifest.json")
                if entry.file_size > MAX_MANIFEST_BYTES:
                    raise ValueError(
                        "verified package manifest exceeds the bounded read limit"
                    )
                with bundle.open(entry, "r") as source:
                    raw = source.read(MAX_MANIFEST_BYTES + 1)
        else:
            _path, raw = _read_regular_bounded(
                artifact / "manifest.json",
                "verified package manifest",
                MAX_MANIFEST_BYTES,
            )
    except ValueError:
        raise
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ValueError("verified package manifest could not be read safely") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("verified package manifest exceeds the bounded read limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(
            "verified package manifest is not valid bounded UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError("verified package manifest is not an object")
    return value, hashlib.sha256(raw).hexdigest()


def _read_regular_bounded(
    source: str | Path, label: str, limit: int
) -> tuple[Path, bytes]:
    path = Path(source).expanduser().absolute()
    if path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    try:
        inspected = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    if not stat.S_ISREG(inspected.st_mode):
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(inspected, opened):
            raise ValueError(f"{label} changed during safe open")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(limit + 1)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte limit")
    return path, raw


def _publication_destination_snapshot(destination: Path) -> os.stat_result | None:
    if destination.is_symlink():
        raise ValueError("signature destination must not be a symbolic link")
    try:
        snapshot = destination.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("signature destination could not be inspected safely") from exc
    if not stat.S_ISREG(snapshot.st_mode):
        raise ValueError("signature destination must be a regular file path")
    return snapshot


def _hash_regular_bounded(
    source: str | Path, label: str, limit: int
) -> tuple[Path, str]:
    path = Path(source).expanduser().absolute()
    if path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    try:
        inspected = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} could not be hashed safely") from exc
    if not stat.S_ISREG(inspected.st_mode):
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    descriptor: int | None = None
    digest = hashlib.sha256()
    consumed = 0
    opened: os.stat_result | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(inspected, opened):
            raise ValueError(f"{label} changed during safe open")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            while chunk := handle.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > limit:
                    raise ValueError(f"{label} exceeds the {limit}-byte limit")
                digest.update(chunk)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} could not be hashed safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        current = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} changed during bounded hashing") from exc
    if opened is None or not os.path.samestat(opened, current):
        raise ValueError(f"{label} changed during bounded hashing")
    return path, digest.hexdigest()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _public_key_fingerprint(public_key: Any, serialization: Any) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _atomic_write_json(
    destination: Path,
    value: dict[str, Any],
    *,
    expected_destination: os.stat_result | None,
) -> None:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(destination.parent),
        )
    except OSError as exc:
        raise ValueError("signature destination could not be prepared safely") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        current_destination = _publication_destination_snapshot(destination)
        if expected_destination is None:
            if current_destination is not None:
                raise ValueError("signature destination changed before publication")
        elif current_destination is None or not os.path.samestat(
            expected_destination, current_destination
        ):
            raise ValueError("signature destination changed before publication")
        os.replace(temporary, destination)
        temporary = ""
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("detached signature could not be published safely") from exc
    finally:
        try:
            if temporary:
                os.unlink(temporary)
        except OSError:
            pass


def _signature_error(
    result: dict[str, Any], rule_id: str, message: str
) -> dict[str, Any]:
    result["findings"].append(
        {"rule_id": rule_id, "level": "error", "message": message, "path": ""}
    )
    result["counts"]["error"] += 1
    result["valid"] = False
    return result


def _crypto() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ValueError(
            "package signing requires the optional dependency: pip install 'pysfmea[signing]'"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature
