"""Offline Sigstore/cosign verification receipts for exact assurance artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_file_snapshot
from .model import utc_now

SIGSTORE_VERIFICATION_FORMAT = "pysfmea-sigstore-verification-1"
SIGSTORE_VERIFICATION_VERDICT_FORMAT = "pysfmea-sigstore-verification-verdict-1"
MAX_ARTIFACT_BYTES = 550_000_000
MAX_BUNDLE_BYTES = 20_000_000
MAX_TRUST_ROOT_BYTES = 20_000_000
MAX_OUTPUT_CHARS = 2_000_000
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _binding(source: str | Path, *, label: str, maximum: int) -> dict[str, Any]:
    snapshot = load_bounded_file_snapshot(source, label=label, max_bytes=maximum)
    return {
        "reference": snapshot.path.name,
        "bytes": snapshot.size,
        "sha256": hashlib.sha256(snapshot.raw).hexdigest(),
    }


def sigstore_verification_receipt(
    artifact: str | Path,
    bundle: str | Path,
    trusted_root: str | Path,
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    authority: str,
    cosign_version: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Create a sealed receipt from one offline cosign verification observation."""

    verified = exit_code == 0
    return seal(
        {
            "format": SIGSTORE_VERIFICATION_FORMAT,
            "observed_at": observed_at or utc_now(),
            "authority": bounded_text(authority, "Sigstore verification authority"),
            "verifier": {
                "name": "cosign",
                "version": bounded_text(cosign_version, "cosign version"),
                "mode": "verify-blob-offline-bundle",
            },
            "subject": _binding(
                artifact, label="Sigstore subject", maximum=MAX_ARTIFACT_BYTES
            ),
            "bundle": _binding(
                bundle, label="Sigstore bundle", maximum=MAX_BUNDLE_BYTES
            ),
            "trusted_root": _binding(
                trusted_root,
                label="Sigstore trusted root",
                maximum=MAX_TRUST_ROOT_BYTES,
            ),
            "certificate": {
                "identity": bounded_text(
                    certificate_identity, "Sigstore certificate identity"
                ),
                "oidc_issuer": bounded_text(
                    certificate_oidc_issuer, "Sigstore certificate OIDC issuer"
                ),
            },
            "outcome": {
                "exit_code": exit_code,
                "signature_verified": verified,
                "certificate_identity_verified": verified,
                "transparency_log_verified": verified,
                "offline_bundle_verified": verified,
                "stdout_sha256": hashlib.sha256(
                    stdout.encode("utf-8", "replace")
                ).hexdigest(),
                "stderr_sha256": hashlib.sha256(
                    stderr.encode("utf-8", "replace")
                ).hexdigest(),
            },
            "claim_boundary": "A successful receipt records cosign verification of the exact artifact against the exact Sigstore bundle, locally supplied trusted root, and expected certificate identity. Trusted-root authorization, identity ownership, policy suitability, and engineering approval remain external decisions.",
        }
    )


def execute_sigstore_verification(
    artifact: str | Path,
    bundle: str | Path,
    trusted_root: str | Path,
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    authority: str,
    destination: str | Path,
    cosign: str = "cosign",
) -> Path:
    """Run shell-free offline cosign verification and publish its exact receipt."""

    executable = shutil.which(cosign)
    if not executable:
        raise ValueError("cosign executable is unavailable")
    artifact_path = load_bounded_file_snapshot(
        artifact, label="Sigstore subject", max_bytes=MAX_ARTIFACT_BYTES
    ).path
    bundle_path = load_bounded_file_snapshot(
        bundle, label="Sigstore bundle", max_bytes=MAX_BUNDLE_BYTES
    ).path
    trusted_root_path = load_bounded_file_snapshot(
        trusted_root,
        label="Sigstore trusted root",
        max_bytes=MAX_TRUST_ROOT_BYTES,
    ).path
    version = subprocess.run(
        [executable, "version", "--json"],
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
        timeout=30,
    )
    version_text = version.stdout.strip() or version.stderr.strip()
    if version.returncode != 0 or not version_text:
        raise ValueError("cosign version could not be established")
    try:
        parsed = json.loads(version.stdout)
        version_text = str(
            parsed.get("gitVersion") or parsed.get("version") or version_text
        )
    except (json.JSONDecodeError, AttributeError):
        pass
    command = [
        executable,
        "verify-blob",
        "--bundle",
        str(bundle_path),
        "--trusted-root",
        str(trusted_root_path),
        "--certificate-identity",
        bounded_text(certificate_identity, "Sigstore certificate identity"),
        "--certificate-oidc-issuer",
        bounded_text(certificate_oidc_issuer, "Sigstore certificate OIDC issuer"),
        str(artifact_path),
    ]
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
        timeout=120,
    )
    receipt = sigstore_verification_receipt(
        artifact_path,
        bundle_path,
        trusted_root_path,
        certificate_identity=certificate_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
        authority=authority,
        cosign_version=version_text[:20_000],
        exit_code=result.returncode,
        stdout=result.stdout[-MAX_OUTPUT_CHARS:],
        stderr=result.stderr[-MAX_OUTPUT_CHARS:],
    )
    return publish_json(receipt, destination)


def _structure(value: dict[str, Any]) -> bool:
    try:
        verifier = value["verifier"]
        subject = value["subject"]
        bundle = value["bundle"]
        trusted_root = value["trusted_root"]
        certificate = value["certificate"]
        outcome = value["outcome"]
        verified = outcome["exit_code"] == 0
        return bool(
            set(value)
            == {
                "format",
                "observed_at",
                "authority",
                "verifier",
                "subject",
                "bundle",
                "trusted_root",
                "certificate",
                "outcome",
                "claim_boundary",
                "content_sha256",
            }
            and set(verifier) == {"name", "version", "mode"}
            and verifier["name"] == "cosign"
            and verifier["mode"] == "verify-blob-offline-bundle"
            and all(
                isinstance(verifier[name], str) and verifier[name].strip()
                for name in ("name", "version", "mode")
            )
            and all(
                isinstance(binding, dict)
                and set(binding) == {"reference", "bytes", "sha256"}
                and isinstance(binding["reference"], str)
                and binding["reference"]
                and isinstance(binding["bytes"], int)
                and binding["bytes"] > 0
                and isinstance(binding["sha256"], str)
                and SHA256_PATTERN.fullmatch(binding["sha256"]) is not None
                for binding in (subject, bundle, trusted_root)
            )
            and set(certificate) == {"identity", "oidc_issuer"}
            and all(
                isinstance(certificate[name], str) and certificate[name].strip()
                for name in certificate
            )
            and set(outcome)
            == {
                "exit_code",
                "signature_verified",
                "certificate_identity_verified",
                "transparency_log_verified",
                "offline_bundle_verified",
                "stdout_sha256",
                "stderr_sha256",
            }
            and isinstance(outcome["exit_code"], int)
            and not isinstance(outcome["exit_code"], bool)
            and all(
                isinstance(outcome[name], bool) and outcome[name] == verified
                for name in (
                    "signature_verified",
                    "certificate_identity_verified",
                    "transparency_log_verified",
                    "offline_bundle_verified",
                )
            )
            and all(
                isinstance(outcome[name], str)
                and SHA256_PATTERN.fullmatch(outcome[name]) is not None
                for name in ("stdout_sha256", "stderr_sha256")
            )
        )
    except (KeyError, TypeError):
        return False


def verify_sigstore_verification(
    value: dict[str, Any],
    *,
    artifact: str | Path | None = None,
    bundle: str | Path | None = None,
    trusted_root: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="Sigstore verification receipt",
            format_value=SIGSTORE_VERIFICATION_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("Sigstore verification receipt fields are invalid")
    subject_binding: bool | None = None
    bundle_binding: bool | None = None
    trusted_root_binding: bool | None = None
    if artifact is not None:
        try:
            subject_binding = checked["subject"] == _binding(
                artifact, label="Sigstore subject", maximum=MAX_ARTIFACT_BYTES
            )
        except (OSError, TypeError, ValueError):
            subject_binding = False
        if not subject_binding:
            errors.append("Sigstore receipt does not bind the supplied artifact")
    if bundle is not None:
        try:
            bundle_binding = checked["bundle"] == _binding(
                bundle, label="Sigstore bundle", maximum=MAX_BUNDLE_BYTES
            )
        except (OSError, TypeError, ValueError):
            bundle_binding = False
        if not bundle_binding:
            errors.append("Sigstore receipt does not bind the supplied bundle")
    if trusted_root is not None:
        try:
            trusted_root_binding = checked["trusted_root"] == _binding(
                trusted_root,
                label="Sigstore trusted root",
                maximum=MAX_TRUST_ROOT_BYTES,
            )
        except (OSError, TypeError, ValueError):
            trusted_root_binding = False
        if not trusted_root_binding:
            errors.append("Sigstore receipt does not bind the supplied trusted root")
    valid = bool(
        integrity
        and structure
        and subject_binding is not False
        and bundle_binding is not False
        and trusted_root_binding is not False
    )
    authenticated = bool(valid and checked.get("outcome", {}).get("signature_verified"))
    return seal(
        {
            "format": SIGSTORE_VERIFICATION_VERDICT_FORMAT,
            "valid": valid,
            "authenticated": authenticated,
            "checks": {
                "content_integrity": integrity,
                "closed_structure": structure,
                "artifact_binding": subject_binding,
                "bundle_binding": bundle_binding,
                "trusted_root_binding": trusted_root_binding,
            },
            "errors": errors,
            "notice": "Receipt verification proves accounting and optional exact-file binding. Trust in the authority, certificate identity, OIDC issuer, and Sigstore roots remains a policy decision.",
        }
    )


def verify_sigstore_verification_file(
    source: str | Path,
    *,
    artifact: str | Path | None = None,
    bundle: str | Path | None = None,
    trusted_root: str | Path | None = None,
) -> dict[str, Any]:
    try:
        return verify_sigstore_verification(
            load_json(source, label="Sigstore verification receipt"),
            artifact=artifact,
            bundle=bundle,
            trusted_root=trusted_root,
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": SIGSTORE_VERIFICATION_VERDICT_FORMAT,
                "valid": False,
                "authenticated": False,
                "checks": {
                    "content_integrity": False,
                    "closed_structure": False,
                    "artifact_binding": False if artifact is not None else None,
                    "bundle_binding": False if bundle is not None else None,
                    "trusted_root_binding": False if trusted_root is not None else None,
                },
                "errors": [str(exc)],
                "notice": "Sigstore verification receipt validation failed closed.",
            }
        )
