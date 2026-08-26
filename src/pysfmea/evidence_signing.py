"""Detached Ed25519 authentication for bounded PySFMEA JSON evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
from pathlib import Path
from typing import Any

from .integrity import canonical_json_sha256
from .json_ingestion import parse_bounded_json_bytes
from .model import utc_now
from .signing import (
    MAX_KEY_BYTES,
    MAX_PASSPHRASE_BYTES,
    MAX_SIGNER_CHARS,
    _atomic_write_json,
    _canonical,
    _crypto,
    _public_key_fingerprint,
    _publication_destination_snapshot,
    _read_regular_bounded,
)

EVIDENCE_SIGNATURE_FORMAT = "pysfmea-json-evidence-signature-1"
EVIDENCE_STATEMENT_FORMAT = "pysfmea-json-evidence-statement-1"
MAX_EVIDENCE_BYTES = 100_000_000
MAX_SIGNATURE_BYTES = 1_000_000
MAX_JSON_DEPTH = 100
MAX_JSON_NODES = 2_000_000


def _artifact_subject(path: Path, raw: bytes, value: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": path.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_json_sha256(value),
        "artifact_format": str(value.get("format", "")),
    }


def _read_artifact(source: str | Path) -> tuple[Path, bytes, dict[str, Any]]:
    path, raw = _read_regular_bounded(
        source, "JSON evidence artifact", MAX_EVIDENCE_BYTES
    )
    value = parse_bounded_json_bytes(
        raw,
        label="JSON evidence artifact",
        max_bytes=MAX_EVIDENCE_BYTES,
        max_depth=MAX_JSON_DEPTH,
        max_nodes=MAX_JSON_NODES,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON evidence artifact must contain an object")
    return path, raw, value


def sign_json_evidence(
    artifact: str | Path,
    private_key: str | Path,
    signer: str,
    *,
    destination: str | Path | None = None,
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> Path:
    """Authenticate exact JSON bytes and their canonical semantic projection."""

    signer_name = signer.strip() if isinstance(signer, str) else ""
    if not signer_name or len(signer_name) > MAX_SIGNER_CHARS:
        raise ValueError("signer must be a bounded non-empty identity label")
    if passphrase is not None and (
        not isinstance(passphrase, bytes) or len(passphrase) > MAX_PASSPHRASE_BYTES
    ):
        raise ValueError("private-key passphrase is invalid or exceeds its byte limit")
    path, raw, value = _read_artifact(artifact)
    key_path, key_bytes = _read_regular_bounded(
        private_key, "private key", MAX_KEY_BYTES
    )
    output = (
        Path(destination).expanduser().absolute()
        if destination
        else path.with_name(path.name + ".sig.json")
    )
    if output in {path, key_path}:
        raise ValueError("signature destination must differ from artifact and key")
    snapshot = _publication_destination_snapshot(output)
    if snapshot is not None and not overwrite:
        raise ValueError("signature already exists; use --force to replace it")
    Ed25519PrivateKey, _public_type, serialization, _invalid = _crypto()
    try:
        loaded = serialization.load_pem_private_key(key_bytes, password=passphrase)
    except (TypeError, ValueError) as exc:
        raise ValueError("Ed25519 private key could not be loaded") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("private key must be an Ed25519 PEM key")
    statement = {
        "format": EVIDENCE_STATEMENT_FORMAT,
        "algorithm": "Ed25519",
        "signed_at": utc_now(),
        "signer": signer_name,
        "subject": _artifact_subject(path, raw, value),
    }
    envelope = {
        "format": EVIDENCE_SIGNATURE_FORMAT,
        "statement": statement,
        "key_fingerprint": _public_key_fingerprint(loaded.public_key(), serialization),
        "signature": base64.b64encode(loaded.sign(_canonical(statement))).decode(
            "ascii"
        ),
    }
    _atomic_write_json(output, envelope, expected_destination=snapshot)
    return output


def verify_json_evidence_signature(
    artifact: str | Path, signature: str | Path, public_key: str | Path
) -> dict[str, Any]:
    """Verify exact evidence bytes against an explicitly trusted public key."""

    checks = {
        "artifact_readable": False,
        "envelope_contract": False,
        "artifact_binding": False,
        "trusted_key_binding": False,
        "signature": False,
    }
    errors: list[str] = []
    signer = ""
    signed_at = ""
    fingerprint = ""
    try:
        path, raw, value = _read_artifact(artifact)
        checks["artifact_readable"] = True
        _signature_path, signature_raw = _read_regular_bounded(
            signature, "JSON evidence signature", MAX_SIGNATURE_BYTES
        )
        _key_path, key_raw = _read_regular_bounded(
            public_key, "public key", MAX_KEY_BYTES
        )
        envelope = parse_bounded_json_bytes(
            signature_raw,
            label="JSON evidence signature",
            max_bytes=MAX_SIGNATURE_BYTES,
            max_depth=20,
            max_nodes=10_000,
        )
        if not isinstance(envelope, dict) or set(envelope) != {
            "format",
            "statement",
            "key_fingerprint",
            "signature",
        }:
            raise ValueError("signature envelope has unexpected or missing fields")
        statement = envelope.get("statement")
        if (
            envelope.get("format") != EVIDENCE_SIGNATURE_FORMAT
            or not isinstance(statement, dict)
            or set(statement)
            != {"format", "algorithm", "signed_at", "signer", "subject"}
            or statement.get("format") != EVIDENCE_STATEMENT_FORMAT
            or statement.get("algorithm") != "Ed25519"
            or not isinstance(statement.get("signed_at"), str)
            or not statement["signed_at"]
            or not isinstance(statement.get("signer"), str)
            or not statement["signer"].strip()
            or len(statement["signer"]) > MAX_SIGNER_CHARS
            or not isinstance(statement.get("subject"), dict)
            or not isinstance(envelope.get("key_fingerprint"), str)
            or not isinstance(envelope.get("signature"), str)
        ):
            raise ValueError("signature metadata is malformed or unsupported")
        checks["envelope_contract"] = True
        signer = statement["signer"]
        signed_at = statement["signed_at"]
        fingerprint = envelope["key_fingerprint"]
        if statement["subject"] != _artifact_subject(path, raw, value):
            raise ValueError("signature subject does not match the exact artifact")
        checks["artifact_binding"] = True
        _private_type, Ed25519PublicKey, serialization, InvalidSignature = _crypto()
        try:
            loaded = serialization.load_pem_public_key(key_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("trusted public key cannot be loaded") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("trusted public key must be an Ed25519 PEM key")
        if fingerprint != _public_key_fingerprint(loaded, serialization):
            raise ValueError(
                "trusted public-key fingerprint does not match the envelope"
            )
        checks["trusted_key_binding"] = True
        try:
            signature_bytes = base64.b64decode(envelope["signature"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("signature is not valid base64") from exc
        if len(signature_bytes) != 64:
            raise ValueError("Ed25519 signature must contain 64 decoded bytes")
        try:
            loaded.verify(signature_bytes, _canonical(statement))
        except InvalidSignature as exc:
            raise ValueError("signature does not verify with the trusted key") from exc
        checks["signature"] = True
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "format": "pysfmea-json-evidence-signature-verification-1",
        "valid": all(checks.values()),
        "checks": checks,
        "signer": signer,
        "signed_at": signed_at,
        "key_fingerprint": fingerprint,
        "errors": errors,
        "notice": (
            "A valid signature authenticates exact evidence to the supplied public key. "
            "Key ownership, reviewer authorization, independence, and engineering approval "
            "remain external governance controls."
        ),
    }
