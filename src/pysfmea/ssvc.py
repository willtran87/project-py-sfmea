"""Governed, versioned SSVC-style vulnerability decision tables.

PySFMEA does not hard-code a mutable CISA decision tree.  A controlled policy
must enumerate every decision-point combination exactly once; evaluation then
becomes deterministic, reviewable, and exactly reproducible.
"""

from __future__ import annotations

import copy
import itertools
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now

SSVC_POLICY_FORMAT = "pysfmea-ssvc-policy-1"
SSVC_OBSERVATIONS_FORMAT = "pysfmea-ssvc-observations-1"
SSVC_ASSESSMENT_FORMAT = "pysfmea-ssvc-assessment-1"
SSVC_VERIFICATION_FORMAT = "pysfmea-ssvc-verification-1"
DECISION_POINTS = {
    "exploitation": ("none", "proof_of_concept", "active"),
    "automatable": ("no", "yes"),
    "technical_impact": ("partial", "total"),
    "mission_prevalence": ("minimal", "support", "essential"),
    "public_wellbeing_impact": ("minimal", "material", "irreversible"),
}
OUTCOMES = {"track", "track_star", "attend", "act"}
MAX_RULES = 10_000
MAX_RECORDS = 100_000


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 20_000:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _timestamp(value: Any, label: str) -> datetime:
    text = _text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


def _sealed(value: dict[str, Any], label: str) -> dict[str, Any]:
    unsigned = copy.deepcopy(value)
    claimed = unsigned.pop("content_sha256", "")
    if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed) or canonical_json_sha256(unsigned) != claimed:
        raise ValueError(f"{label} content digest does not match")
    return copy.deepcopy(value)


def ssvc_policy_template(*, authority: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": SSVC_POLICY_FORMAT,
        "model": "CISA SSVC",
        "model_version": "replace-with-controlled-guide-version",
        "authority": authority.strip(),
        "approved_at": "replace-with-approval-timestamp",
        "source_url": "https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc",
        "rules": [],
        "reassessment_triggers": ["decision_point_evidence_changed", "policy_version_changed", "vulnerability_scope_changed"],
        "notice": "Populate an approved complete decision table from the controlled policy; the tool does not infer CISA endorsement.",
    }
    if not result["authority"]:
        raise ValueError("SSVC policy authority must not be empty")
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def ssvc_observations_template(*, policy_id: str, authority: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": SSVC_OBSERVATIONS_FORMAT,
        "policy_content_sha256": policy_id,
        "authority": authority.strip(),
        "observed_at": utc_now(),
        "vulnerabilities": [],
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def _policy(value: dict[str, Any]) -> dict[str, Any]:
    fields = {"format", "model", "model_version", "authority", "approved_at", "source_url", "rules", "reassessment_triggers", "notice", "content_sha256"}
    result = _sealed(value, "SSVC policy")
    if set(result) != fields or result.get("format") != SSVC_POLICY_FORMAT:
        raise ValueError("SSVC policy fields or format are invalid")
    for name in ("model", "model_version", "authority", "source_url"):
        _text(result[name], f"SSVC policy {name}")
    _timestamp(result["approved_at"], "SSVC policy approved_at")
    rules = result["rules"]
    if not isinstance(rules, list) or not rules or len(rules) > MAX_RULES:
        raise ValueError("SSVC policy rules are invalid")
    combinations: dict[tuple[str, ...], str] = {}
    rule_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"id", "conditions", "outcome", "rationale"}:
            raise ValueError("SSVC rule fields are invalid")
        identifier = _text(rule["id"], "SSVC rule id")
        if identifier in rule_ids or rule["outcome"] not in OUTCOMES:
            raise ValueError(f"SSVC rule {identifier} identity or outcome is invalid")
        rule_ids.add(identifier)
        _text(rule["rationale"], f"SSVC rule {identifier} rationale")
        conditions = rule["conditions"]
        if not isinstance(conditions, dict) or set(conditions) != set(DECISION_POINTS):
            raise ValueError(f"SSVC rule {identifier} conditions are invalid")
        lists: list[list[str]] = []
        for name, allowed in DECISION_POINTS.items():
            selected = conditions[name]
            if not isinstance(selected, list) or not selected or len(selected) != len(set(selected)) or not set(selected) <= set(allowed):
                raise ValueError(f"SSVC rule {identifier} condition {name} is invalid")
            lists.append(selected)
        for combination in itertools.product(*lists):
            if combination in combinations:
                raise ValueError(f"SSVC policy rules overlap at {combination}")
            combinations[combination] = identifier
    expected = set(itertools.product(*(DECISION_POINTS[name] for name in DECISION_POINTS)))
    if set(combinations) != expected:
        raise ValueError(f"SSVC policy decision table is incomplete: {len(expected) - len(combinations)} combinations missing")
    triggers = result["reassessment_triggers"]
    if not isinstance(triggers, list) or not triggers or len(triggers) != len(set(triggers)) or any(not isinstance(item, str) or not item.strip() for item in triggers):
        raise ValueError("SSVC reassessment triggers are invalid")
    return result


def _observations(value: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    fields = {"format", "policy_content_sha256", "authority", "observed_at", "vulnerabilities", "content_sha256"}
    result = _sealed(value, "SSVC observations")
    if set(result) != fields or result.get("format") != SSVC_OBSERVATIONS_FORMAT or result["policy_content_sha256"] != policy["content_sha256"]:
        raise ValueError("SSVC observations fields, format, or policy binding are invalid")
    _text(result["authority"], "SSVC observation authority")
    observed_at = _timestamp(result["observed_at"], "SSVC observation timestamp")
    entries = result["vulnerabilities"]
    record_fields = {"id", *DECISION_POINTS, "evidence_refs", "rationale", "next_review_at"}
    if not isinstance(entries, list) or not entries or len(entries) > MAX_RECORDS:
        raise ValueError("SSVC vulnerability observations are invalid")
    identifiers: set[str] = set()
    for record in entries:
        if not isinstance(record, dict) or set(record) != record_fields:
            raise ValueError("SSVC vulnerability observation fields are invalid")
        identifier = _text(record["id"], "SSVC vulnerability id")
        if identifier in identifiers:
            raise ValueError("SSVC vulnerability IDs must be unique")
        identifiers.add(identifier)
        for name, allowed in DECISION_POINTS.items():
            if record[name] not in allowed:
                raise ValueError(f"SSVC vulnerability {identifier} decision point {name} is invalid")
        evidence = record["evidence_refs"]
        if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)) or any(not isinstance(item, str) or not item.strip() for item in evidence):
            raise ValueError(f"SSVC vulnerability {identifier} evidence is invalid")
        _text(record["rationale"], f"SSVC vulnerability {identifier} rationale")
        next_review_at = _timestamp(
            record["next_review_at"], f"SSVC vulnerability {identifier} next_review_at"
        )
        if next_review_at <= observed_at:
            raise ValueError(
                f"SSVC vulnerability {identifier} next review must follow observation time"
            )
    return result


def seal_ssvc_source(source: str | Path, destination: str | Path, *, policy_source: str | Path | None = None) -> Path:
    document = load_bounded_json_document(source, label="SSVC source", max_bytes=100_000_000, max_depth=100, max_nodes=3_000_000)
    if not isinstance(document.value, dict):
        raise ValueError("SSVC source must contain an object")
    value = copy.deepcopy(document.value)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    if value.get("format") == SSVC_POLICY_FORMAT:
        _policy(value)
    elif value.get("format") == SSVC_OBSERVATIONS_FORMAT:
        if policy_source is None:
            raise ValueError("sealing SSVC observations requires a policy")
        policy_document = load_bounded_json_document(policy_source, label="SSVC policy", max_bytes=20_000_000, max_depth=100, max_nodes=500_000)
        if not isinstance(policy_document.value, dict):
            raise ValueError("SSVC policy must contain an object")
        _observations(value, _policy(policy_document.value))
    else:
        raise ValueError("unsupported SSVC source format")
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="sealed SSVC source")


def ssvc_assessment(policy_source: str | Path, observations_source: str | Path, *, generated_at: str | None = None) -> dict[str, Any]:
    policy_document = load_bounded_json_document(policy_source, label="SSVC policy", max_bytes=20_000_000, max_depth=100, max_nodes=500_000)
    observations_document = load_bounded_json_document(observations_source, label="SSVC observations", max_bytes=100_000_000, max_depth=100, max_nodes=3_000_000)
    if not isinstance(policy_document.value, dict) or not isinstance(observations_document.value, dict):
        raise ValueError("SSVC sources must contain objects")
    policy = _policy(policy_document.value)
    observations = _observations(observations_document.value, policy)
    table: dict[tuple[str, ...], dict[str, Any]] = {}
    for rule in policy["rules"]:
        lists = [rule["conditions"][name] for name in DECISION_POINTS]
        for combination in itertools.product(*lists):
            table[combination] = rule
    decisions = []
    for record in observations["vulnerabilities"]:
        combination = tuple(record[name] for name in DECISION_POINTS)
        rule = table[combination]
        decisions.append({"id": record["id"], "outcome": rule["outcome"], "rule_id": rule["id"], "decision_points": {name: record[name] for name in DECISION_POINTS}, "evidence_refs": record["evidence_refs"], "rationale": record["rationale"], "next_review_at": record["next_review_at"]})
    result: dict[str, Any] = {
        "format": SSVC_ASSESSMENT_FORMAT,
        "generated_at": generated_at or utc_now(),
        "model": {"name": policy["model"], "version": policy["model_version"], "authority": policy["authority"], "source_url": policy["source_url"]},
        "bindings": {"policy_content_sha256": policy["content_sha256"], "observations_content_sha256": observations["content_sha256"]},
        "decisions": decisions,
        "summary": {"vulnerabilities": len(decisions), "outcomes": {outcome: sum(item["outcome"] == outcome for item in decisions) for outcome in sorted(OUTCOMES)}, "complete": True},
        "notice": "Outcomes are deterministic applications of the controlled local policy to authority-attributed evidence; they are not CISA decisions or independently established facts.",
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_ssvc_assessment(value: dict[str, Any]) -> dict[str, Any]:
    expected = {"format", "generated_at", "model", "bindings", "decisions", "summary", "notice", "content_sha256"}
    structure = bool(set(value) == expected and value.get("format") == SSVC_ASSESSMENT_FORMAT and isinstance(value.get("decisions"), list))
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(re.fullmatch(r"[0-9a-f]{64}", claimed) and canonical_json_sha256(unsigned) == claimed)
    semantic = False
    try:
        decisions = value["decisions"]
        semantic = value["summary"] == {"vulnerabilities": len(decisions), "outcomes": {outcome: sum(item["outcome"] == outcome for item in decisions) for outcome in sorted(OUTCOMES)}, "complete": True}
    except (KeyError, TypeError):
        semantic = False
    errors = []
    if not structure: errors.append("SSVC assessment fields do not match format 1")
    if not integrity: errors.append("SSVC assessment content digest does not match")
    if not semantic: errors.append("SSVC assessment summary does not reconcile")
    return {"format": SSVC_VERIFICATION_FORMAT, "valid": bool(structure and integrity and semantic), "complete": bool(structure and integrity and semantic), "checks": {"closed_structure": structure, "content_integrity": integrity, "semantic_reconciliation": semantic, "source_regeneration": None}, "errors": errors, "content_sha256": claimed, "notice": "Verification proves deterministic policy application, not evidence truth or remediation authority."}


def verify_ssvc_assessment_file(source: str | Path, *, policy_source: str | Path | None = None, observations_source: str | Path | None = None) -> dict[str, Any]:
    try:
        if (policy_source is None) != (observations_source is None):
            raise ValueError("exact regeneration requires policy and observations together")
        document = load_bounded_json_document(source, label="SSVC assessment", max_bytes=100_000_000, max_depth=100, max_nodes=3_000_000)
        if not isinstance(document.value, dict): raise ValueError("SSVC assessment must contain an object")
        result = verify_ssvc_assessment(document.value)
        result["path"] = str(document.path)
        if policy_source is not None and observations_source is not None and result["valid"]:
            exact = ssvc_assessment(policy_source, observations_source, generated_at=str(document.value.get("generated_at", ""))) == document.value
            result["checks"]["source_regeneration"] = exact
            result["valid"] = bool(result["valid"] and exact)
            result["complete"] = bool(result["complete"] and exact)
            if not exact: result["errors"].append("SSVC assessment does not exactly regenerate")
        return result
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"path": str(Path(source).expanduser().absolute()), "format": SSVC_VERIFICATION_FORMAT, "valid": False, "complete": False, "checks": {"closed_structure": False, "content_integrity": False, "semantic_reconciliation": False, "source_regeneration": None}, "errors": [str(exc)], "content_sha256": "", "notice": "The SSVC assessment could not be safely verified."}


def export_ssvc_source(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="SSVC source")


def export_ssvc_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="SSVC assessment")
