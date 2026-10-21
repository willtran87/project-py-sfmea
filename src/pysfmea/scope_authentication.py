"""Authenticate portfolio approval against caller-selected organizational trust.

The trust policy is an external trust root: never load it from the portfolio itself.
Key custody and authorization of policy updates remain organizational responsibilities.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .evidence_signing import verify_json_evidence_signature
from .json_ingestion import load_bounded_json_document
from .measurement_validity import instant


def authenticate_scope(
    portfolio: str | Path, trust_policy: str | Path | None, *, as_of: str
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "authenticated": False,
        "trust_policy_sha256": "",
        "signature_sha256": "",
        "key_fingerprint": "",
        "errors": [],
    }
    try:
        if trust_policy is None:
            raise ValueError("an externally selected scope trust policy is required")
        policy_path = Path(trust_policy).absolute()
        policy_doc = load_bounded_json_document(
            policy_path,
            label="scope trust policy",
            max_bytes=1000000,
            max_depth=20,
            max_nodes=10000,
        )
        result["trust_policy_sha256"] = hashlib.sha256(policy_doc.raw).hexdigest()
        policy = policy_doc.value
        if (
            set(policy) != {"format", "authorities"}
            or policy["format"] != "pysfmea-scope-trust-policy-1"
            or not isinstance(policy["authorities"], list)
        ):
            raise ValueError("scope trust policy contract is invalid")
        document = load_bounded_json_document(
            Path(portfolio),
            label="approved portfolio",
            max_bytes=100000000,
            max_depth=100,
            max_nodes=2000000,
        )
        scope = document.value["product"]["qualification_scope"]
        entries = policy["authorities"]
        if not entries or len(
            {e["identity"].strip().casefold() for e in entries}
        ) != len(entries):
            raise ValueError("trusted authority identities must be nonempty and unique")
        for e in entries:
            if (
                set(e)
                != {
                    "identity",
                    "public_key",
                    "roles",
                    "not_before",
                    "not_after",
                    "revoked",
                }
                or type(e["revoked"]) is not bool
                or not isinstance(e["roles"], list)
                or any(not isinstance(role, str) or not role for role in e["roles"])
            ):
                raise ValueError("trusted authority fields are invalid")
        entry = next(e for e in entries if e["identity"] == scope["approval_authority"])
        now = instant(as_of)
        if entry["revoked"] or "scope-approver" not in entry["roles"]:
            raise ValueError("scope approver is revoked or unauthorized")
        if not instant(entry["not_before"]) <= now <= instant(entry["not_after"]):
            raise ValueError("scope approver trust interval is not current")
        if not instant(scope["approved_at"]) <= now <= instant(scope["next_review_at"]):
            raise ValueError("scope approval interval is not current")
        signature = Path(scope["approval_ref"])
        if signature.is_absolute():
            raise ValueError("approval signature must be relative to the portfolio")
        signature = Path(portfolio).absolute().parent / signature
        signature.resolve().relative_to(Path(portfolio).resolve().parent)
        key = Path(entry["public_key"])
        if not key.is_absolute():
            key = policy_path.parent / key
            key.resolve().relative_to(policy_path.resolve().parent)
        signature_doc = load_bounded_json_document(
            signature,
            label="scope signature",
            max_bytes=1000000,
            max_depth=20,
            max_nodes=10000,
        )
        signature_digest = hashlib.sha256(signature_doc.raw).hexdigest()
        verdict = verify_json_evidence_signature(
            portfolio,
            signature,
            key,
            expected_artifact_sha256=hashlib.sha256(document.raw).hexdigest(),
            expected_signature_sha256=signature_digest,
        )
        if not verdict["valid"] or verdict["signer"] != entry["identity"]:
            raise ValueError("scope signature or authorized signer does not match")
        signed = instant(verdict["signed_at"])
        earliest = max(instant(scope["approved_at"]), instant(entry["not_before"]))
        latest = min(now, instant(entry["not_after"]))
        if not earliest <= signed <= latest:
            raise ValueError("scope signature is outside its authorized interval")
        result.update(
            authenticated=True,
            signature_sha256=signature_digest,
            key_fingerprint=verdict["key_fingerprint"],
        )
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        StopIteration,
        AttributeError,
    ) as exc:
        result["errors"] = [str(exc) or "scope authorization evidence is incomplete"]
    return result
