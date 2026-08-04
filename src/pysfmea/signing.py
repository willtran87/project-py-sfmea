"""Optional detached Ed25519 signatures for verified review packages."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
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

    signer_name = signer.strip()
    if not signer_name:
        raise ValueError("signer must be a non-empty identity label")
    verification = verify_review_package(package)
    if not verification["valid"]:
        raise ValueError("review package must pass integrity verification before signing")

    artifact = Path(package).expanduser().absolute()
    key_path = _regular_input_file(private_key, "private key", MAX_KEY_BYTES)
    output = (
        Path(destination).expanduser().absolute()
        if destination
        else artifact.with_name(artifact.name + ".sig.json")
    )
    if artifact.is_dir() and _is_within(output, artifact):
        raise ValueError("detached signature must be stored outside the package directory")
    if output == artifact or output == key_path:
        raise ValueError("signature destination must be separate from the package and key")
    if output.exists():
        if output.is_dir() or output.is_symlink():
            raise ValueError(f"signature destination is not a replaceable regular file: {output}")
        if not overwrite:
            raise ValueError(f"signature already exists: {output}; use --force to replace it")

    Ed25519PrivateKey, _Ed25519PublicKey, serialization, _InvalidSignature = _crypto()
    try:
        loaded = serialization.load_pem_private_key(
            key_path.read_bytes(), password=passphrase
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"Ed25519 private key cannot be loaded: {exc}") from exc
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
    _atomic_write_json(output, envelope)
    return output


def verify_review_signature(
    package: str | Path,
    signature: str | Path,
    public_key: str | Path,
    *,
    package_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify integrity and a detached signature against an explicitly trusted key."""

    result = copy.deepcopy(package_verification or verify_review_package(package))
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
        signature_path = _regular_input_file(
            signature, "detached signature", MAX_SIGNATURE_BYTES
        )
        key_path = _regular_input_file(public_key, "public key", MAX_KEY_BYTES)
        envelope = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
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
        or not isinstance(statement.get("subject"), dict)
        or not isinstance(envelope.get("key_fingerprint"), str)
        or not isinstance(envelope.get("signature"), str)
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
    if statement["subject"] != _signature_subject(artifact, result):
        return _signature_error(
            result,
            "signature.subject_mismatch",
            "Signature claims do not match the current package digest or provenance.",
        )

    Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature = _crypto()
    del Ed25519PrivateKey
    try:
        loaded = serialization.load_pem_public_key(key_path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        return _signature_error(
            result, "signature.key_invalid", f"Ed25519 public key cannot be loaded: {exc}"
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
    return value.encode("utf-8")


def _signature_subject(artifact: Path, verification: dict[str, Any]) -> dict[str, str]:
    manifest = _read_manifest(artifact)
    if verification["container"] == "zip":
        digest_scope = "zip_bytes"
        digest = _sha256_file(artifact)
    else:
        digest_scope = "manifest_bytes"
        digest = _sha256_file(artifact / "manifest.json")
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


def _read_manifest(artifact: Path) -> dict[str, Any]:
    if artifact.suffix.lower() == ".zip":
        with zipfile.ZipFile(artifact, "r") as bundle:
            raw = bundle.read("manifest.json")
    else:
        raw = (artifact / "manifest.json").read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("verified package manifest is not an object")
    return value


def _regular_input_file(source: str | Path, label: str, limit: int) -> Path:
    path = Path(source).expanduser().absolute()
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular file: {path}")
    if path.stat().st_size > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte limit")
    return path


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _public_key_fingerprint(public_key: Any, serialization: Any) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _atomic_write_json(destination: Path, value: dict[str, Any]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


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
