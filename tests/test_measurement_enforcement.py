from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pysfmea.evidence_signing import sign_json_evidence, verify_json_evidence_signature
from pysfmea.genai_telemetry import _attributes, _otel_spans, _value
from pysfmea.measurement_validity import (
    complete_collection,
    paired_cohort,
    timed_breaker,
)
from pysfmea.scope_authentication import authenticate_scope
from pysfmea.upstream_contract import approved_inspect_schema


def breaker() -> dict:
    def event(i: int, second: int, outcome: str, before: str, after: str) -> dict:
        time = f"2026-09-01T00:00:{second:02d}Z"
        return {
            "id": str(i),
            "started_at": time,
            "completed_at": time,
            "outcome": outcome,
            "state_before": before,
            "state_after": after,
        }

    return {
        "breaker_policy": {
            "failure_threshold": 2,
            "cooldown_seconds": 10,
            "half_open_successes": 2,
        },
        "requests": [
            event(0, 0, "failure", "closed", "closed"),
            event(1, 1, "failure", "closed", "open"),
            event(2, 2, "rejected", "open", "open"),
            event(3, 11, "success", "half_open", "half_open"),
            event(4, 12, "success", "half_open", "closed"),
        ],
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "early_probe",
        "no_rejection",
        "threshold",
        "probe_count",
        "duplicate",
        "overlap",
        "invalid_outcome",
        "bad_state",
        "negative_cooldown",
    ],
)
def test_timed_breaker_replays_policy_and_boundary_conditions(mutation: str) -> None:
    value = breaker()
    assert timed_breaker(value)
    if mutation == "none":
        return
    if mutation == "early_probe":
        value["requests"][3]["started_at"] = "2026-09-01T00:00:10Z"
    elif mutation == "no_rejection":
        value["requests"].pop(2)
    elif mutation == "threshold":
        value["breaker_policy"]["failure_threshold"] = 3
    elif mutation == "probe_count":
        value["breaker_policy"]["half_open_successes"] = 1
    elif mutation == "duplicate":
        value["requests"][1]["id"] = "0"
    elif mutation == "overlap":
        value["requests"][0]["completed_at"] = "2026-09-01T00:00:02Z"
    elif mutation == "invalid_outcome":
        value["requests"][2]["outcome"] = "success"
    elif mutation == "bad_state":
        value["requests"][1]["state_after"] = "closed"
    else:
        value["breaker_policy"]["cooldown_seconds"] = -1
    assert not timed_breaker(value)


def test_breaker_failed_probe_reopens_and_resets_cooldown() -> None:
    value = breaker()
    value["requests"][3].update(outcome="failure", state_after="open")
    value["requests"][4].update(
        started_at="2026-09-01T00:00:21Z",
        completed_at="2026-09-01T00:00:21Z",
        state_after="half_open",
    )
    last = copy.deepcopy(value["requests"][4])
    last.update(
        id="final",
        started_at="2026-09-01T00:00:22Z",
        completed_at="2026-09-01T00:00:22Z",
        state_after="closed",
    )
    value["requests"].append(last)
    assert timed_breaker(value)


@pytest.mark.parametrize("field", ["dataset_sha256", "oracle_sha256", "cases"])
def test_drift_cannot_compare_substituted_populations(field: str) -> None:
    baseline = {
        "dataset_sha256": "a" * 64,
        "oracle_sha256": "b" * 64,
        "cases": [{"id": "case", "passed": True}],
    }
    current = copy.deepcopy(baseline)
    assert paired_cohort(baseline, current)
    current[field] = (
        [{"id": "different", "passed": True}] if field == "cases" else "c" * 64
    )
    assert not paired_cohort(baseline, current)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sampling_probability", 0.5),
        ("dropped_records", 1),
        ("expected_requests", 11),
        ("expected_requests", True),
        ("telemetry_sha256", "b" * 64),
        ("population", "all-spans"),
        ("counter_source", "telemetry.json"),
    ],
)
def test_collection_cannot_hide_loss_sampling_or_wrong_denominators(
    field: str, value: object
) -> None:
    window = {
        "id": "w",
        "started_at": "2026-09-01T00:00:00Z",
        "ended_at": "2026-09-01T01:00:00Z",
        "telemetry_sha256": "a" * 64,
        "telemetry_ref": "telemetry.json",
    }
    collection = {
        "format": "pysfmea-tevv-collection-1",
        "window_id": "w",
        "started_at": window["started_at"],
        "ended_at": window["ended_at"],
        "telemetry_sha256": "a" * 64,
        "expected_requests": 10,
        "sampling_probability": 1,
        "dropped_records": 0,
        "counter_source": "gateway counter",
        "population": "one-span-per-request",
    }
    assert complete_collection(collection, window, 10)
    collection[field] = value
    assert not complete_collection(collection, window, 10)


@pytest.mark.parametrize(
    "value",
    [
        [None],
        {"spans": [None]},
        {"spans": "malformed"},
        {"resourceSpans": [None]},
        {"resourceSpans": [{"scopeSpans": [None]}]},
    ],
)
def test_otlp_never_silently_discards_malformed_records(value: object) -> None:
    with pytest.raises(ValueError):
        _otel_spans(value)


def test_otlp_rejects_ambiguous_attributes_and_anyvalues() -> None:
    with pytest.raises(ValueError):
        _attributes(
            [
                {"key": "provider", "value": "first"},
                {"key": "provider", "value": "second"},
            ]
        )
    with pytest.raises(ValueError):
        _value({"stringValue": "1", "intValue": 1})
    with pytest.raises(ValueError):
        _attributes([{}])
    assert _attributes([{"key": "k", "value": {"stringValue": "v"}}]) == {"k": "v"}


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "revoked",
        "expired",
        "role",
        "identity",
        "tamper",
        "missing_policy",
        "missing_signature",
        "extra_policy_field",
        "wrong_policy_format",
        "authorities_not_list",
        "empty_authorities",
        "duplicate_identity",
        "case_duplicate_identity",
        "extra_authority_field",
        "revoked_not_bool",
        "roles_not_list",
        "non_string_role",
        "empty_role",
        "trust_not_started",
        "approval_not_started",
        "approval_expired",
        "absolute_signature",
        "signature_escape",
        "key_escape",
        "wrong_signer",
        "signed_before_approval",
        "signed_before_trust",
        "signed_in_future",
        "signed_at_approval",
        "signed_at_now",
        "trust_start_boundary",
        "trust_end_boundary",
        "approval_start_boundary",
        "approval_end_boundary",
        "absolute_key",
    ],
)
def test_scope_approval_requires_exact_signed_subject_and_authorized_key(
    tmp_path: Path, mutation: str
) -> None:
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    key = ed25519.Ed25519PrivateKey.generate()
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    portfolio_dir = tmp_path / "portfolio"
    portfolio_dir.mkdir()
    source, policy_path = portfolio_dir / "portfolio.json", tmp_path / "trust.json"
    if mutation == "key_escape":
        policy_path = tmp_path / "policy" / "trust.json"
        policy_path.parent.mkdir()
    value = {
        "product": {
            "qualification_scope": {
                "approval_authority": "board",
                "approval_ref": "portfolio.sig.json",
                "approved_at": "2026-09-01T00:00:00Z",
                "next_review_at": "2026-10-01T00:00:00Z",
            }
        }
    }
    scope = value["product"]["qualification_scope"]
    if mutation == "approval_not_started":
        scope["approved_at"] = "2026-09-08T00:00:00Z"
    elif mutation == "approval_expired":
        scope["next_review_at"] = "2026-09-06T00:00:00Z"
    elif mutation == "absolute_signature":
        scope["approval_ref"] = str(tmp_path / "portfolio.sig.json")
    elif mutation == "signature_escape":
        scope["approval_ref"] = "../portfolio.sig.json"
    elif mutation == "approval_start_boundary":
        scope["approved_at"] = "2026-09-07T00:00:00Z"
    elif mutation == "approval_end_boundary":
        scope["next_review_at"] = "2026-09-07T00:00:00Z"
    source.write_text(json.dumps(value))
    policy = {
        "format": "pysfmea-scope-trust-policy-1",
        "authorities": [
            {
                "identity": "board",
                "public_key": public.name,
                "roles": ["scope-approver"],
                "not_before": "2026-09-01T00:00:00Z",
                "not_after": "2026-10-01T00:00:00Z",
                "revoked": False,
            }
        ],
    }
    signature = portfolio_dir / "portfolio.sig.json"
    if mutation == "signature_escape":
        # Keep a real, valid signature outside the allowed directory. A missing
        # file would reject even if containment enforcement were accidentally lost.
        signature = tmp_path / "portfolio.sig.json"
    signed_at = {
        "signed_before_approval": "2026-08-31T23:59:59Z",
        "signed_before_trust": "2026-09-02T00:00:00Z",
        "signed_in_future": "2026-09-07T00:00:01Z",
        "signed_at_approval": "2026-09-01T00:00:00Z",
        "signed_at_now": "2026-09-07T00:00:00Z",
        "trust_start_boundary": "2026-09-07T00:00:00Z",
        "approval_start_boundary": "2026-09-07T00:00:00Z",
    }.get(mutation, "2026-09-02T00:00:00Z")
    with patch("pysfmea.evidence_signing.utc_now", return_value=signed_at):
        sign_json_evidence(
            source,
            private,
            "other" if mutation == "wrong_signer" else "board",
            destination=signature,
        )
    if mutation == "none":
        assert verify_json_evidence_signature(
            source,
            signature,
            public,
            expected_artifact_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            expected_signature_sha256=hashlib.sha256(
                signature.read_bytes()
            ).hexdigest(),
        )["valid"]
        assert not verify_json_evidence_signature(
            source, signature, public, expected_artifact_sha256="0" * 64
        )["valid"]
        assert not verify_json_evidence_signature(
            source, signature, public, expected_signature_sha256="0" * 64
        )["valid"]
    if mutation == "revoked":
        policy["authorities"][0]["revoked"] = True
    elif mutation == "expired":
        policy["authorities"][0]["not_after"] = "2026-09-03T00:00:00Z"
    elif mutation == "role":
        policy["authorities"][0]["roles"] = ["observer"]
    elif mutation == "identity":
        policy["authorities"][0]["identity"] = "other"
    elif mutation == "tamper":
        value["substituted"] = True
        source.write_text(json.dumps(value))
    elif mutation == "missing_signature":
        signature.unlink()
    elif mutation == "extra_policy_field":
        policy["unexpected"] = True
    elif mutation == "wrong_policy_format":
        policy["format"] = "unknown"
    elif mutation == "authorities_not_list":
        policy["authorities"] = {}
    elif mutation == "empty_authorities":
        policy["authorities"] = []
    elif mutation in {"duplicate_identity", "case_duplicate_identity"}:
        duplicate = copy.deepcopy(policy["authorities"][0])
        if mutation == "case_duplicate_identity":
            duplicate["identity"] = " BOARD "
        policy["authorities"].append(duplicate)
    else:
        authority_updates = {
            "extra_authority_field": {"unexpected": True},
            "revoked_not_bool": {"revoked": 0},
            "roles_not_list": {"roles": "scope-approver"},
            "non_string_role": {"roles": ["scope-approver", 1]},
            "empty_role": {"roles": ["scope-approver", ""]},
            "trust_not_started": {"not_before": "2026-09-08T00:00:00Z"},
            "signed_before_trust": {"not_before": "2026-09-03T00:00:00Z"},
            "trust_start_boundary": {"not_before": "2026-09-07T00:00:00Z"},
            "trust_end_boundary": {"not_after": "2026-09-07T00:00:00Z"},
            "key_escape": {"public_key": "../public.pem"},
            "absolute_key": {"public_key": str(public)},
        }
        policy["authorities"][0].update(authority_updates.get(mutation, {}))
    policy_path.write_text(json.dumps(policy))
    result = authenticate_scope(
        source,
        None if mutation == "missing_policy" else policy_path,
        as_of="2026-09-07T00:00:00Z",
    )
    accepted = mutation in {
        "none",
        "signed_at_approval",
        "signed_at_now",
        "trust_start_boundary",
        "trust_end_boundary",
        "approval_start_boundary",
        "approval_end_boundary",
        "absolute_key",
    }
    assert result["authenticated"] is accepted
    assert result["trust_policy_sha256"] == (
        ""
        if mutation == "missing_policy"
        else hashlib.sha256(policy_path.read_bytes()).hexdigest()
    )
    if accepted:
        verdict = verify_json_evidence_signature(source, signature, public)
        assert result == {
            "authenticated": True,
            "trust_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "signature_sha256": hashlib.sha256(signature.read_bytes()).hexdigest(),
            "key_fingerprint": verdict["key_fingerprint"],
            "errors": [],
        }
    else:
        assert result["signature_sha256"] == result["key_fingerprint"] == ""
        assert isinstance(result["errors"], list) and len(result["errors"]) == 1
        assert isinstance(result["errors"][0], str) and result["errors"][0]
        # Diagnostic categories are part of the reviewable assurance contract:
        # an authorization denial must explain which evidence needs correction.
        expected_errors = {
            "missing_policy": "an externally selected scope trust policy is required",
            "extra_policy_field": "scope trust policy contract is invalid",
            "wrong_policy_format": "scope trust policy contract is invalid",
            "authorities_not_list": "scope trust policy contract is invalid",
            "empty_authorities": "trusted authority identities must be nonempty and unique",
            "duplicate_identity": "trusted authority identities must be nonempty and unique",
            "case_duplicate_identity": "trusted authority identities must be nonempty and unique",
            "extra_authority_field": "trusted authority fields are invalid",
            "revoked_not_bool": "trusted authority fields are invalid",
            "roles_not_list": "trusted authority fields are invalid",
            "non_string_role": "trusted authority fields are invalid",
            "empty_role": "trusted authority fields are invalid",
            "revoked": "scope approver is revoked or unauthorized",
            "role": "scope approver is revoked or unauthorized",
            "expired": "scope approver trust interval is not current",
            "trust_not_started": "scope approver trust interval is not current",
            "approval_not_started": "scope approval interval is not current",
            "approval_expired": "scope approval interval is not current",
            "absolute_signature": "approval signature must be relative to the portfolio",
            "wrong_signer": "scope signature or authorized signer does not match",
            "tamper": "scope signature or authorized signer does not match",
            "signed_before_approval": "scope signature is outside its authorized interval",
            "signed_before_trust": "scope signature is outside its authorized interval",
            "signed_in_future": "scope signature is outside its authorized interval",
            "identity": "scope authorization evidence is incomplete",
        }
        if mutation in expected_errors:
            assert result["errors"] == [expected_errors[mutation]]


def test_upstream_policy_pins_schema_version_uri_bytes_and_projection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "approved.json"
    expected = {
        "tool": "Inspect AI",
        "version": "v",
        "uri": "https://publisher/schema",
        "sha256": "a" * 64,
        "configuration_projection": "inspect-export-config-1",
    }
    path.write_text(
        json.dumps(
            {"format": "pysfmea-upstream-schema-policy-1", "schemas": [expected]}
        )
    )
    result, digest = approved_inspect_schema(
        path, version="v", uri=expected["uri"], digest="a" * 64
    )
    assert result and digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not approved_inspect_schema(
        path, version="other", uri=expected["uri"], digest="a" * 64
    )[0]
    assert not approved_inspect_schema(
        path, version="v", uri=expected["uri"], digest="b" * 64
    )[0]
    assert approved_inspect_schema(None, version="v", uri="u", digest="a" * 64) == (
        False,
        "",
    )
    path.write_text('{"format": "wrong", "schemas": []}')
    with pytest.raises(ValueError, match="policy is invalid"):
        approved_inspect_schema(path, version="v", uri="u", digest="a" * 64)


@pytest.mark.parametrize("value", [None, 4, True, [], {}, "2026-09-01T00:00:00"])
def test_invalid_timestamps_fail_closed(value: object) -> None:
    source = breaker()
    source["requests"][0]["started_at"] = value
    assert not timed_breaker(source)
