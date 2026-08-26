"""Governed authoring of reusable SFMEA project configuration additions."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any

from .config import load_config, load_config_source, normalize_config
from .diagnostics import analysis_diagnostics
from .enhancements import enhancement_workbench
from .file_publication import atomic_publish_text, inspect_artifact_destination
from .guidance import MAPPING_STRENGTHS, RELATIONSHIP_TYPES
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id, utc_now

CONFIGURATION_AUTHORING_DRAFT_FORMAT = "pysfmea-configuration-authoring-draft-1"
CONFIGURATION_AUTHORING_FORMAT = "pysfmea-configuration-authoring-1"
CONFIGURATION_AUTHORING_VERIFICATION_FORMAT = (
    "pysfmea-configuration-authoring-verification-1"
)
CONFIGURATION_AUTHORING_APPLY_RECEIPT_FORMAT = (
    "pysfmea-configuration-authoring-apply-receipt-1"
)
MAX_CONFIGURATION_AUTHORING_BYTES = 20_000_000
MAX_CONFIGURATION_AUTHORING_DEPTH = 100
MAX_CONFIGURATION_AUTHORING_NODES = 750_000


def _analysis_binding(analysis: dict[str, Any]) -> dict[str, str]:
    baseline = analysis.get("project", {}).get("baseline", {})
    return {
        "baseline_id": str(baseline.get("id", "")),
        "repository_sha256": str(baseline.get("repository_sha256", "")),
        "analysis_state_sha256": canonical_json_sha256(analysis),
    }


def _configuration_binding(config: dict[str, Any], raw: bytes) -> dict[str, str]:
    return {
        "normalized_configuration_sha256": canonical_json_sha256(config),
        "source_bytes_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _review() -> dict[str, str]:
    return {
        "status": "unreviewed",
        "reviewer": "",
        "rationale": "",
        "reviewed_at": "",
    }


def _review_from_activation(decision: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(decision, dict):
        return _review()
    return {
        "status": "approved",
        "reviewer": str(decision.get("reviewer", "")),
        "rationale": str(decision.get("rationale", "")),
        "reviewed_at": str(decision.get("recorded_at", ""))[:10],
    }


def _subject_entries(analysis: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    diagnostics = analysis_diagnostics(analysis)
    workbench = enhancement_workbench(analysis, diagnostics=diagnostics)
    activation_decisions = {
        (str(value.get("kind", "")), str(value.get("subject_id", ""))): value
        for value in analysis.get("activation", {}).get("decision_history", [])
        if isinstance(value, dict)
    }
    entries: list[dict[str, Any]] = []
    for value in workbench.get("guidance_specificity_program", {}).get(
        "closure_queue", []
    ):
        if not isinstance(value, dict) or not value.get("rule_id"):
            continue
        rule_id = str(value["rule_id"])
        prior = activation_decisions.get(("guidance", rule_id))
        prior_choice = str(prior.get("decision", "")) if prior else ""
        entries.append(
            {
                "kind": "guidance",
                "subject_id": rule_id,
                "action": "defer",
                "proposal": {
                    "rule_selector": rule_id,
                    "citation_id": "",
                    "relationship": "supports_review_question",
                    "strength": (
                        "supporting" if prior_choice == "supporting_only" else "direct"
                    ),
                },
                "review": _review_from_activation(prior) if prior else _review(),
            }
        )
    architecture = workbench.get("architecture_mapping_queue", {})
    for value in architecture.get("proposals", []):
        if not isinstance(value, dict) or not value.get("component_id"):
            continue
        component_id = str(value["component_id"])
        source_path = str(value.get("source_path", ""))
        component = str(value.get("component", ""))
        subsystems = [
            str(item) for item in value.get("suggested_subsystems", []) if item
        ]
        subject_id = stable_id("CONFIG-AUTHORING-ARCH", component_id)
        prior = activation_decisions.get(
            ("architecture", stable_id("ACTIVATION-ARCH", component_id))
        )
        has_relationship = bool(
            subsystems
            or value.get("suggested_requirements")
            or value.get("suggested_hazards")
            or value.get("suggested_interfaces")
        )
        accepted = prior is not None and prior.get("decision") == "accepted"
        entries.append(
            {
                "kind": "architecture",
                "subject_id": subject_id,
                "action": "apply" if accepted and has_relationship else "defer",
                "proposal": {
                    "component_id": component_id,
                    "pattern": f"{source_path}:{component}",
                    "subsystem": subsystems[0] if subsystems else "",
                    "requirements": list(value.get("suggested_requirements", [])),
                    "hazards": list(value.get("suggested_hazards", [])),
                    "interfaces": list(value.get("suggested_interfaces", [])),
                    "confidence": str(value.get("confidence", "unclassified")),
                    "supporting_component_ids": list(
                        value.get("supporting_component_ids", [])
                    ),
                },
                "review": _review_from_activation(prior) if prior else _review(),
            }
        )
    interface_queue = workbench.get("interface_disposition_queue", {})
    for side, plural in (("server", "servers"), ("client", "clients")):
        for value in interface_queue.get(plural, []):
            if not isinstance(value, dict) or not value.get("id"):
                continue
            endpoint_id = str(value["id"])
            prior = activation_decisions.get(("interface", endpoint_id))
            prior_choice = str(prior.get("decision", "")) if prior else ""
            reusable = prior_choice in {
                str(choice) for choice in value.get("suggested_dispositions", [])
            } and prior_choice != "needs_information"
            entries.append(
                {
                    "kind": "interface",
                    "subject_id": endpoint_id,
                    "action": "apply" if reusable else "defer",
                    "proposal": {
                        "endpoint_id": endpoint_id,
                        "side": side,
                        "decision": prior_choice if reusable else "needs_information",
                    },
                    "review": _review_from_activation(prior) if prior else _review(),
                }
            )
    entries.sort(key=lambda value: (str(value["kind"]), str(value["subject_id"])))
    omitted = {
        "architecture": int(architecture.get("proposals_omitted", 0) or 0),
        "interface_clients": int(interface_queue.get("clients_omitted", 0) or 0),
        "interface_servers": int(interface_queue.get("servers_omitted", 0) or 0),
    }
    return entries, omitted


def configuration_authoring_draft(
    analysis: dict[str, Any], config: dict[str, Any], raw_config: bytes
) -> dict[str, Any]:
    entries, omitted = _subject_entries(analysis)
    return {
        "format": CONFIGURATION_AUTHORING_DRAFT_FORMAT,
        "created_at": utc_now(),
        "analysis_binding": _analysis_binding(analysis),
        "configuration_binding": _configuration_binding(config, raw_config),
        "summary": {
            "guidance": sum(value["kind"] == "guidance" for value in entries),
            "architecture": sum(value["kind"] == "architecture" for value in entries),
            "interfaces": sum(value["kind"] == "interface" for value in entries),
            "omitted": omitted,
        },
        "entries": entries,
        "instructions": [
            "Keep action=defer until the proposal is complete and independently reviewed.",
            "Every action=apply entry requires review.status=approved, reviewer, rationale, and a YYYY-MM-DD reviewed_at date.",
            "Guidance mappings require a known citation, typed relationship, and direct/supporting/contextual strength.",
            "Architecture proposals are proximity-based until a reviewer confirms actual subsystem, requirement, hazard, and interface relationships.",
            "Interface dispositions preserve static candidates and never establish runtime compatibility or reachability.",
        ],
        "authority": "editable_configuration_proposals_not_engineering_approval_or_runtime_evidence",
    }


def export_configuration_authoring_draft(
    analysis: dict[str, Any], config_source: str | Path, destination: str | Path
) -> Path:
    config, _path, raw = load_config_source(config_source)
    expected = inspect_artifact_destination(
        destination, label="configuration authoring draft"
    )
    return atomic_publish_text(
        destination,
        json.dumps(
            configuration_authoring_draft(analysis, config, raw),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        label="configuration authoring draft",
        max_bytes=MAX_CONFIGURATION_AUTHORING_BYTES,
        expected_destination=expected,
    )


def _review_fields(entry: dict[str, Any], index: int) -> dict[str, str]:
    review = entry.get("review")
    if not isinstance(review, dict) or set(review) != {
        "status",
        "reviewer",
        "rationale",
        "reviewed_at",
    }:
        raise ValueError(f"configuration authoring entry {index} review is malformed")
    if review.get("status") not in {"unreviewed", "approved", "rejected", "rework"}:
        raise ValueError(f"configuration authoring entry {index} review status is invalid")
    if not all(isinstance(review.get(field), str) for field in review):
        raise ValueError(f"configuration authoring entry {index} review fields must be strings")
    return {field: str(review[field]) for field in review}


def _validate_entries(
    entries: Any, analysis: dict[str, Any], config: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    if not isinstance(entries, list) or not all(isinstance(value, dict) for value in entries):
        raise ValueError("configuration authoring entries must be a list of objects")
    expected_entries, _omitted = _subject_entries(analysis)
    expected = {
        (str(value["kind"]), str(value["subject_id"])) for value in expected_entries
    }
    expected_by_identity = {
        (str(value["kind"]), str(value["subject_id"])): value
        for value in expected_entries
    }
    seen: set[tuple[str, str]] = set()
    additions: dict[str, list[dict[str, Any]]] = {
        "guidance_rule_mappings": [],
        "component_mappings": [],
        "interface_dispositions": [],
    }
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries, start=1):
        if set(entry) != {"kind", "subject_id", "action", "proposal", "review"}:
            raise ValueError(f"configuration authoring entry {index} has unsupported fields")
        kind = str(entry.get("kind", ""))
        subject_id = str(entry.get("subject_id", ""))
        identity = (kind, subject_id)
        if identity not in expected:
            raise ValueError(f"configuration authoring entry {index} targets an unknown subject")
        if identity in seen:
            raise ValueError(f"configuration authoring subject is duplicated: {kind}:{subject_id}")
        seen.add(identity)
        action = str(entry.get("action", ""))
        if action not in {"defer", "apply"}:
            raise ValueError(f"configuration authoring entry {index} action is invalid")
        proposal = entry.get("proposal")
        if not isinstance(proposal, dict):
            raise ValueError(f"configuration authoring entry {index} proposal is malformed")
        review = _review_fields(entry, index)
        expected_proposal = expected_by_identity[identity]["proposal"]
        if kind == "guidance":
            if (
                set(proposal)
                != {"rule_selector", "citation_id", "relationship", "strength"}
                or proposal.get("rule_selector") != subject_id
                or proposal.get("relationship") not in RELATIONSHIP_TYPES
                or proposal.get("strength") not in MAPPING_STRENGTHS
                or not isinstance(proposal.get("citation_id"), str)
            ):
                raise ValueError(f"guidance proposal {subject_id} is malformed")
        elif kind == "architecture":
            required = {
                "component_id",
                "pattern",
                "subsystem",
                "requirements",
                "hazards",
                "interfaces",
                "confidence",
                "supporting_component_ids",
            }
            if (
                set(proposal) != required
                or proposal.get("component_id")
                != expected_proposal.get("component_id")
                or not str(proposal.get("pattern", "")).strip()
                or not isinstance(proposal.get("subsystem"), str)
                or not all(
                    isinstance(proposal.get(field), list)
                    and all(
                        isinstance(value, str) and value
                        for value in proposal.get(field, [])
                    )
                    for field in (
                        "requirements",
                        "hazards",
                        "interfaces",
                        "supporting_component_ids",
                    )
                )
            ):
                raise ValueError(f"architecture proposal {subject_id} is malformed")
        elif kind == "interface":
            if (
                set(proposal) != {"endpoint_id", "side", "decision"}
                or proposal.get("endpoint_id") != subject_id
                or proposal.get("side") != expected_proposal.get("side")
                or proposal.get("decision")
                not in {
                    "confirmed_compatible",
                    "deployment_prefix_or_proxy",
                    "generated_or_external_server",
                    "test_only",
                    "confirmed_mismatch",
                    "intentional_backend_only",
                    "external_or_generated_client",
                    "deprecated_or_unreachable",
                    "missing_client_coverage",
                    "needs_information",
                }
            ):
                raise ValueError(f"interface proposal {subject_id} is malformed")
        if action == "apply":
            if (
                review["status"] != "approved"
                or not review["reviewer"].strip()
                or not review["rationale"].strip()
            ):
                raise ValueError(
                    f"configuration proposal {kind}:{subject_id} requires an approved named review and rationale"
                )
            try:
                date.fromisoformat(review["reviewed_at"])
            except ValueError as exc:
                raise ValueError(
                    f"configuration proposal {kind}:{subject_id} reviewed_at must use YYYY-MM-DD"
                ) from exc
            if kind == "guidance":
                additions["guidance_rule_mappings"].append(
                    {
                        **copy.deepcopy(proposal),
                        "rationale": review["rationale"],
                        "reviewed_by": review["reviewer"],
                        "effective_date": review["reviewed_at"],
                    }
                )
            elif kind == "architecture":
                linked = [
                    str(proposal.get("subsystem", "")).strip(),
                    *[str(value) for value in proposal.get("requirements", [])],
                    *[str(value) for value in proposal.get("hazards", [])],
                    *[str(value) for value in proposal.get("interfaces", [])],
                ]
                if not any(linked):
                    raise ValueError(
                        f"architecture proposal {subject_id} must establish at least one relationship"
                    )
                additions["component_mappings"].append(
                    {
                        key: copy.deepcopy(proposal[key])
                        for key in (
                            "pattern",
                            "subsystem",
                            "requirements",
                            "hazards",
                            "interfaces",
                        )
                    }
                )
            elif kind == "interface":
                additions["interface_dispositions"].append(
                    {
                        **copy.deepcopy(proposal),
                        "rationale": review["rationale"],
                        "reviewed_by": review["reviewer"],
                        "effective_date": review["reviewed_at"],
                    }
                )
        normalized.append(copy.deepcopy(entry))
    if seen != expected:
        missing = ", ".join(f"{kind}:{subject}" for kind, subject in sorted(expected - seen))
        raise ValueError(f"configuration authoring entries omit queued subjects: {missing}")
    combined = copy.deepcopy(config)
    for key, values in additions.items():
        combined[key] = [*combined.get(key, []), *values]
    normalize_config(combined)
    return normalized, additions


def seal_configuration_authoring_draft(
    source: str | Path,
    analysis: dict[str, Any],
    config_source: str | Path,
    destination: str | Path,
) -> Path:
    document = load_bounded_json_document(
        source,
        label="configuration authoring draft",
        max_bytes=MAX_CONFIGURATION_AUTHORING_BYTES,
        max_depth=MAX_CONFIGURATION_AUTHORING_DEPTH,
        max_nodes=MAX_CONFIGURATION_AUTHORING_NODES,
    )
    draft = document.value
    if not isinstance(draft, dict) or draft.get("format") != CONFIGURATION_AUTHORING_DRAFT_FORMAT:
        raise ValueError("configuration authoring draft format is missing or unsupported")
    config, _path, raw = load_config_source(config_source)
    if draft.get("analysis_binding") != _analysis_binding(analysis):
        raise ValueError("configuration authoring draft does not match the exact analysis state")
    if draft.get("configuration_binding") != _configuration_binding(config, raw):
        raise ValueError("configuration authoring draft does not match the exact configuration")
    entries, additions = _validate_entries(draft.get("entries"), analysis, config)
    applied = sum(value.get("action") == "apply" for value in entries)
    sealed: dict[str, Any] = {
        "format": CONFIGURATION_AUTHORING_FORMAT,
        "sealed_at": utc_now(),
        "analysis_binding": _analysis_binding(analysis),
        "configuration_binding": _configuration_binding(config, raw),
        "source_draft_sha256": hashlib.sha256(document.raw).hexdigest(),
        "summary": {
            "entries": len(entries),
            "applied": applied,
            "deferred": len(entries) - applied,
            "guidance_mappings": len(additions["guidance_rule_mappings"]),
            "component_mappings": len(additions["component_mappings"]),
            "interface_dispositions": len(additions["interface_dispositions"]),
        },
        "entries": entries,
        "authority": "named_configuration_review_not_independent_approval_runtime_evidence_or_compliance",
    }
    sealed["content_sha256"] = canonical_json_sha256(sealed)
    expected = inspect_artifact_destination(
        destination, label="sealed configuration authoring input"
    )
    return atomic_publish_text(
        destination,
        json.dumps(sealed, indent=2, ensure_ascii=False) + "\n",
        label="sealed configuration authoring input",
        max_bytes=MAX_CONFIGURATION_AUTHORING_BYTES,
        expected_destination=expected,
        staged_verifier=lambda path: verify_configuration_authoring_file(
            path, analysis=analysis, config_source=config_source
        )["valid"]
        is True,
    )


def _verify_value(
    value: Any,
    analysis: dict[str, Any] | None,
    config: dict[str, Any] | None,
    raw_config: bytes | None,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    findings: list[dict[str, str]] = []

    def check(name: str, passed: bool, code: str, message: str) -> None:
        checks[name] = passed
        if not passed:
            findings.append({"code": code, "message": message})

    shape = isinstance(value, dict)
    check("object_shape", shape, "configuration_authoring.invalid_shape", "Root must be an object.")
    if not shape:
        return _verdict(False, checks, findings, analysis is not None, config is not None)
    check(
        "format",
        value.get("format") == CONFIGURATION_AUTHORING_FORMAT,
        "configuration_authoring.unsupported_format",
        "Sealed configuration authoring format is unsupported.",
    )
    canonical = dict(value)
    supplied = canonical.pop("content_sha256", None)
    check(
        "content_integrity",
        isinstance(supplied, str) and supplied == canonical_json_sha256(canonical),
        "configuration_authoring.content_mismatch",
        "Sealed content differs from its declared digest.",
    )
    check(
        "sealed_structure",
        isinstance(value.get("analysis_binding"), dict)
        and isinstance(value.get("configuration_binding"), dict)
        and isinstance(value.get("summary"), dict)
        and isinstance(value.get("entries"), list)
        and len(str(value.get("source_draft_sha256", ""))) == 64
        and set(str(value.get("source_draft_sha256", "")))
        <= set("0123456789abcdef"),
        "configuration_authoring.invalid_structure",
        "Sealed metadata or entries are malformed.",
    )
    if analysis is not None:
        check(
            "analysis_binding",
            value.get("analysis_binding") == _analysis_binding(analysis),
            "configuration_authoring.analysis_mismatch",
            "Sealed input does not match the exact supplied analysis.",
        )
    if config is not None and raw_config is not None:
        check(
            "configuration_binding",
            value.get("configuration_binding") == _configuration_binding(config, raw_config),
            "configuration_authoring.configuration_mismatch",
            "Sealed input does not match the exact supplied configuration.",
        )
    if analysis is not None and config is not None:
        try:
            normalized_entries, additions = _validate_entries(
                value.get("entries"), analysis, config
            )
            semantic_valid = True
            semantic_message = ""
        except ValueError as exc:
            semantic_valid = False
            semantic_message = str(exc)
        check(
            "configuration_semantics",
            semantic_valid,
            "configuration_authoring.invalid_semantics",
            semantic_message,
        )
        expected_summary = (
            {
                "entries": len(normalized_entries),
                "applied": sum(
                    entry.get("action") == "apply" for entry in normalized_entries
                ),
                "deferred": sum(
                    entry.get("action") == "defer" for entry in normalized_entries
                ),
                "guidance_mappings": len(additions["guidance_rule_mappings"]),
                "component_mappings": len(additions["component_mappings"]),
                "interface_dispositions": len(additions["interface_dispositions"]),
            }
            if semantic_valid
            else None
        )
        check(
            "summary_reconciliation",
            semantic_valid and value.get("summary") == expected_summary,
            "configuration_authoring.summary_mismatch",
            "Sealed summary does not reconcile to the reviewed entries.",
        )
    return _verdict(
        all(checks.values()), checks, findings, analysis is not None, config is not None
    )


def _verdict(
    valid: bool,
    checks: dict[str, bool],
    findings: list[dict[str, str]],
    analysis_checked: bool,
    configuration_checked: bool,
) -> dict[str, Any]:
    return {
        "format": CONFIGURATION_AUTHORING_VERIFICATION_FORMAT,
        "valid": valid,
        "status": (
            "matched"
            if valid and analysis_checked and configuration_checked
            else "internally_valid"
            if valid
            else "invalid"
        ),
        "analysis_checked": analysis_checked,
        "configuration_checked": configuration_checked,
        "checks": checks,
        "counts": {"error": len(findings)},
        "findings": findings,
        "notice": "Verification establishes integrity, semantics, and requested bindings; it does not establish architecture truth, runtime compatibility, independent approval, or compliance.",
    }


def verify_configuration_authoring_file(
    source: str | Path,
    *,
    analysis: dict[str, Any] | None = None,
    config_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="sealed configuration authoring input",
            max_bytes=MAX_CONFIGURATION_AUTHORING_BYTES,
            max_depth=MAX_CONFIGURATION_AUTHORING_DEPTH,
            max_nodes=MAX_CONFIGURATION_AUTHORING_NODES,
        )
        config: dict[str, Any] | None = None
        raw: bytes | None = None
        if config_source is not None:
            config, _path, raw = load_config_source(config_source)
    except ValueError as exc:
        result = _verdict(
            False,
            {"bounded_ingestion": False},
            [{"code": "configuration_authoring.ingestion_failed", "message": str(exc)}],
            analysis is not None,
            config_source is not None,
        )
        result.update({"source": str(Path(source).absolute()), "source_bytes": 0, "source_sha256": ""})
        return result
    result = _verify_value(document.value, analysis, config, raw)
    result.update(
        {
            "source": str(document.path),
            "source_bytes": document.size,
            "source_sha256": hashlib.sha256(document.raw).hexdigest(),
        }
    )
    return result


def load_configuration_authoring(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="sealed configuration authoring input",
        max_bytes=MAX_CONFIGURATION_AUTHORING_BYTES,
        max_depth=MAX_CONFIGURATION_AUTHORING_DEPTH,
        max_nodes=MAX_CONFIGURATION_AUTHORING_NODES,
    )
    if not isinstance(document.value, dict):
        raise ValueError("sealed configuration authoring input root must be an object")
    return document.value


def _toml_string(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _toml_array(values: Any) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _toml_appendix(
    additions: dict[str, list[dict[str, Any]]], sealed_sha256: str
) -> str:
    lines = [
        "",
        "# Governed PySFMEA configuration additions",
        f"# Sealed authoring input: {sealed_sha256}",
    ]
    for mapping in additions["guidance_rule_mappings"]:
        lines.extend(
            [
                "",
                "[[guidance_rule_mappings]]",
                f"rule_selector = {_toml_string(mapping['rule_selector'])}",
                f"citation_id = {_toml_string(mapping['citation_id'])}",
                f"relationship = {_toml_string(mapping['relationship'])}",
                f"strength = {_toml_string(mapping['strength'])}",
                f"rationale = {_toml_string(mapping['rationale'])}",
                f"reviewed_by = {_toml_string(mapping['reviewed_by'])}",
                f"effective_date = {_toml_string(mapping['effective_date'])}",
            ]
        )
    for mapping in additions["component_mappings"]:
        lines.extend(
            [
                "",
                "[[component_mappings]]",
                f"pattern = {_toml_string(mapping['pattern'])}",
                f"subsystem = {_toml_string(mapping['subsystem'])}",
                f"requirements = {_toml_array(mapping['requirements'])}",
                f"hazards = {_toml_array(mapping['hazards'])}",
                f"interfaces = {_toml_array(mapping['interfaces'])}",
            ]
        )
    for disposition in additions["interface_dispositions"]:
        lines.extend(
            [
                "",
                "[[interface_dispositions]]",
                f"endpoint_id = {_toml_string(disposition['endpoint_id'])}",
                f"side = {_toml_string(disposition['side'])}",
                f"decision = {_toml_string(disposition['decision'])}",
                f"rationale = {_toml_string(disposition['rationale'])}",
                f"reviewed_by = {_toml_string(disposition['reviewed_by'])}",
                f"effective_date = {_toml_string(disposition['effective_date'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def apply_configuration_authoring(
    analysis: dict[str, Any],
    sealed: dict[str, Any],
    config_source: str | Path,
    destination: str | Path,
) -> tuple[Path, dict[str, Any]]:
    config, source_path, raw = load_config_source(config_source)
    verification = _verify_value(sealed, analysis, config, raw)
    if not verification["valid"]:
        codes = ", ".join(value["code"] for value in verification["findings"])
        raise ValueError(f"configuration authoring input cannot be applied: {codes}")
    _entries, additions = _validate_entries(sealed.get("entries"), analysis, config)
    total = sum(len(values) for values in additions.values())
    if not total:
        raise ValueError("sealed configuration authoring input contains no approved additions")
    output = Path(destination).expanduser().absolute()
    if output == source_path.absolute():
        raise ValueError("configuration authoring must publish to a new file")
    if output.parent != source_path.parent:
        raise ValueError(
            "updated configuration must be written beside the source so relative evidence paths retain their meaning"
        )
    text = raw.decode("utf-8")
    text = text.rstrip("\r\n") + _toml_appendix(
        additions, str(sealed.get("content_sha256", ""))
    )
    updated = copy.deepcopy(config)
    for key, values in additions.items():
        updated[key] = [*updated.get(key, []), *copy.deepcopy(values)]
    normalized_updated = normalize_config(updated)
    expected = inspect_artifact_destination(output, label="updated SFMEA configuration")
    if expected.snapshot is not None:
        raise ValueError(
            "updated SFMEA configuration destination already exists; choose a new path so prior project configuration is preserved"
        )

    def staged_valid(path: Path) -> bool:
        loaded, _resolved = load_config(path)
        return canonical_json_sha256(loaded) == canonical_json_sha256(normalized_updated)

    published = atomic_publish_text(
        output,
        text,
        label="updated SFMEA configuration",
        max_bytes=MAX_CONFIGURATION_AUTHORING_BYTES,
        expected_destination=expected,
        staged_verifier=staged_valid,
    )
    receipt: dict[str, Any] = {
        "format": CONFIGURATION_AUTHORING_APPLY_RECEIPT_FORMAT,
        "status": "applied",
        "analysis_state_sha256": _analysis_binding(analysis)["analysis_state_sha256"],
        "source_configuration_sha256": _configuration_binding(config, raw)[
            "normalized_configuration_sha256"
        ],
        "sealed_input_sha256": str(sealed.get("content_sha256", "")),
        "result_configuration_sha256": canonical_json_sha256(normalized_updated),
        "output": str(published),
        "guidance_mappings": len(additions["guidance_rule_mappings"]),
        "component_mappings": len(additions["component_mappings"]),
        "interface_dispositions": len(additions["interface_dispositions"]),
        "notice": "The generated configuration records named review decisions; rescan and validate it before treating the relationships as current project inputs.",
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return published, receipt
