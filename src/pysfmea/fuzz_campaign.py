"""Governed evidence contract for Python fuzzing campaigns."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .governed_artifact import (
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_seal,
)
from .model import utc_now

FUZZ_CAMPAIGN_FORMAT = "pysfmea-fuzz-campaign-1"
FUZZ_CAMPAIGN_VERIFICATION_FORMAT = "pysfmea-fuzz-campaign-verification-1"
ENGINES = {"atheris", "clusterfuzzlite", "libfuzzer", "custom"}


def fuzz_campaign_template(*, authority: str) -> dict[str, Any]:
    return seal({
        "format": FUZZ_CAMPAIGN_FORMAT,
        "generated_at": utc_now(),
        "authority": {"campaign_owner": bounded_text(authority, "fuzz campaign authority"), "execution_operator": "unassigned", "triage_authority": "unassigned", "approval_authority": "unassigned", "independence_basis": "unassigned"},
        "target": {"repository_revision": "unassigned", "repository_sha256": "0" * 64, "component_ids": [], "entrypoint": "unassigned", "threat_model_refs": []},
        "engine": {"name": "atheris", "version": "unassigned", "image": "unassigned@sha256:" + "0" * 64, "command": [], "configuration_sha256": "0" * 64},
        "isolation": {"network": "none", "source_mount": "read_only", "cpu_limit": 0.0, "memory_mb": 0, "timeout_seconds": 0},
        "corpus": {"initial_sha256": "0" * 64, "final_sha256": "0" * 64, "initial_inputs": 0, "final_inputs": 0, "seed_provenance_refs": []},
        "execution": {"status": "not_run", "started_at": "unassigned", "completed_at": "unassigned", "executions": 0, "execs_per_second": 0.0, "exit_code": None, "coverage_observation_ref": "unassigned"},
        "crashes": [],
        "evidence_refs": [],
        "limitations": ["No fuzzing adequacy claim is supported until the target, corpus, campaign budget, coverage, and reproducible crash triage are evidenced."],
        "claim_boundary": "This artifact records bounded fuzz-campaign provenance, isolation, execution, corpus evolution, and crash triage. A crash-free run does not prove absence of defects, path completeness, or certification.",
    })


def _digest(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value)) and value != "0" * 64


def _semantics(value: dict[str, Any]) -> tuple[bool, bool]:
    try:
        authority = value["authority"]
        target = value["target"]
        engine = value["engine"]
        isolation = value["isolation"]
        corpus = value["corpus"]
        execution = value["execution"]
        crashes = value["crashes"]
        structure = bool(
            set(value) == {"format", "generated_at", "authority", "target", "engine", "isolation", "corpus", "execution", "crashes", "evidence_refs", "limitations", "claim_boundary", "content_sha256"}
            and set(authority) == {"campaign_owner", "execution_operator", "triage_authority", "approval_authority", "independence_basis"}
            and set(target) == {"repository_revision", "repository_sha256", "component_ids", "entrypoint", "threat_model_refs"}
            and set(engine) == {"name", "version", "image", "command", "configuration_sha256"}
            and set(isolation) == {"network", "source_mount", "cpu_limit", "memory_mb", "timeout_seconds"}
            and set(corpus) == {"initial_sha256", "final_sha256", "initial_inputs", "final_inputs", "seed_provenance_refs"}
            and set(execution) == {"status", "started_at", "completed_at", "executions", "execs_per_second", "exit_code", "coverage_observation_ref"}
            and engine["name"] in ENGINES and isinstance(engine["command"], list) and len(engine["command"]) <= 100
            and all(isinstance(item, str) and 0 < len(item) <= 20_000 for item in engine["command"])
            and isolation["network"] == "none" and isolation["source_mount"] == "read_only"
            and execution["status"] in {"not_run", "completed", "failed", "aborted"}
            and isinstance(crashes, list) and len(crashes) <= 100_000
            and isinstance(target["component_ids"], list) and isinstance(target["threat_model_refs"], list)
            and all(
                isinstance(corpus[name], int)
                and not isinstance(corpus[name], bool)
                and corpus[name] >= 0
                for name in ("initial_inputs", "final_inputs")
            )
            and isinstance(execution["executions"], int)
            and not isinstance(execution["executions"], bool)
            and execution["executions"] >= 0
        )
        crash_ids: set[str] = set()
        triage_complete = True
        unresolved = False
        for crash in crashes:
            if not isinstance(crash, dict) or set(crash) != {"id", "input_sha256", "stack_sha256", "reproducer_ref", "reproduced", "disposition", "finding_ref", "fixed_in_revision"}:
                return False, False
            identifier = bounded_text(crash["id"], "fuzz crash id")
            if identifier in crash_ids or not _digest(crash["input_sha256"]) or not _digest(crash["stack_sha256"]):
                return False, False
            crash_ids.add(identifier)
            if type(crash["reproduced"]) is not bool or crash["disposition"] not in {"open", "fixed", "accepted", "not_reproducible", "duplicate"}:
                return False, False
            triage_complete &= crash["reproducer_ref"] != "unassigned" and crash["finding_ref"] != "unassigned"
            unresolved |= bool(crash["reproduced"] and crash["disposition"] == "open")
        roles = [authority[name] for name in ("campaign_owner", "execution_operator", "triage_authority", "approval_authority")]
        complete = bool(
            execution["status"] == "completed" and execution["exit_code"] == 0
            and isinstance(execution["executions"], int) and execution["executions"] > 0
            and engine["command"] and engine["version"] != "unassigned"
            and _digest(target["repository_sha256"]) and _digest(engine["configuration_sha256"])
            and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", engine["image"] or "") and not engine["image"].endswith("0" * 64)
            and _digest(corpus["initial_sha256"]) and _digest(corpus["final_sha256"])
            and corpus["final_inputs"] >= corpus["initial_inputs"] >= 0
            and isolation["timeout_seconds"] > 0 and isolation["cpu_limit"] > 0 and isolation["memory_mb"] > 0
            and target["repository_revision"] != "unassigned" and target["entrypoint"] != "unassigned"
            and execution["coverage_observation_ref"] != "unassigned"
            and len(set(roles)) == len(roles) and authority["independence_basis"] != "unassigned"
            and triage_complete and not unresolved
            and bool(unique_text_list(value["evidence_refs"], "fuzz evidence refs"))
        )
        return structure, complete
    except (KeyError, TypeError, ValueError):
        return False, False


def seal_fuzz_campaign(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="fuzz campaign")
    value.pop("content_sha256", None)
    value = seal(value)
    if not _semantics(value)[0]:
        raise ValueError("fuzz campaign fields are invalid")
    return publish_json(value, destination)


def verify_fuzz_campaign(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(value, label="fuzz campaign", format_value=FUZZ_CAMPAIGN_FORMAT)
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure, complete = _semantics(checked)
    if not structure:
        errors.append("fuzz campaign fields or isolation policy are invalid")
    if structure and not complete:
        errors.append("fuzz campaign execution, coverage, governance, or crash triage is incomplete")
    valid = integrity and structure
    return seal({"format": FUZZ_CAMPAIGN_VERIFICATION_FORMAT, "valid": valid, "eligible_for_assurance_use": bool(valid and complete), "checks": {"content_integrity": integrity, "closed_structure_and_isolation": structure, "campaign_complete": complete}, "errors": errors, "notice": "Eligibility establishes a complete evidence contract, not exhaustive path coverage or absence of defects."})


def verify_fuzz_campaign_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_fuzz_campaign(load_json(source, label="fuzz campaign"))
    except (OSError, TypeError, ValueError) as exc:
        return seal({"format": FUZZ_CAMPAIGN_VERIFICATION_FORMAT, "valid": False, "eligible_for_assurance_use": False, "checks": {"content_integrity": False, "closed_structure_and_isolation": False, "campaign_complete": False}, "errors": [str(exc)], "notice": "Fuzz campaign verification failed closed."})


def export_fuzz_campaign(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_fuzz_campaign(value)["valid"]:
        raise ValueError("fuzz campaign is internally invalid")
    return publish_json(value, destination)
