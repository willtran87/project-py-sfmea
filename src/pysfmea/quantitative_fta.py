"""Bounded exact quantitative fault-tree evaluation with shared-event handling."""

from __future__ import annotations

import copy
import itertools
from pathlib import Path
from typing import Any

from .governed_artifact import (
    analysis_binding,
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_analysis_binding,
    verify_seal,
)
from .integrity import canonical_json_sha256
from .model import utc_now

QFTA_SOURCE_FORMAT = "pysfmea-quantitative-fta-source-1"
QFTA_ASSESSMENT_FORMAT = "pysfmea-quantitative-fta-assessment-1"
QFTA_VERIFICATION_FORMAT = "pysfmea-quantitative-fta-verification-1"
MAX_BASIC_EVENTS = 20
MAX_GATES = 10_000
MAX_CUT_SETS = 100_000
SUPPORTED_DEPENDENCY_TREATMENTS = {
    "represented_by_shared_basic_event",
    "represented_by_explicit_common_cause_event",
}


def quantitative_fta_template(analysis: dict[str, Any], *, authority: str) -> dict[str, Any]:
    result = {
        "format": QFTA_SOURCE_FORMAT,
        "generated_at": utc_now(),
        "authority": bounded_text(authority, "FTA authority"),
        "analysis_binding": analysis_binding(analysis),
        "model_scope": {"top_event": "", "system_boundary": "", "mission_time_hours": 1.0, "operating_modes": [], "assumptions": [], "exclusions": []},
        "independence_basis": "",
        "basic_events": [],
        "gates": [],
        "top_gate_id": "",
        "dependency_declarations": [],
        "evidence_refs": [],
        "notice": "Populate reviewed logic, probabilities, intervals, dependencies/common causes, assumptions, and source evidence. Exact evaluation is bounded to 20 basic events.",
    }
    return seal(result)


def _probability(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{label} must be between zero and one")
    return result


def _source(value: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(value, label="quantitative FTA source", format_value=QFTA_SOURCE_FORMAT)
    required = {"format", "generated_at", "authority", "analysis_binding", "model_scope", "independence_basis", "basic_events", "gates", "top_gate_id", "dependency_declarations", "evidence_refs", "notice", "content_sha256"}
    if set(result) != required:
        raise ValueError("quantitative FTA source fields are invalid")
    bounded_text(result["authority"], "FTA authority")
    verify_analysis_binding(result["analysis_binding"], analysis)
    scope = result["model_scope"]
    if not isinstance(scope, dict) or set(scope) != {"top_event", "system_boundary", "mission_time_hours", "operating_modes", "assumptions", "exclusions"}:
        raise ValueError("FTA model scope fields are invalid")
    bounded_text(scope["top_event"], "FTA top event", allow_empty=True)
    bounded_text(scope["system_boundary"], "FTA system boundary", allow_empty=True)
    mission = scope["mission_time_hours"]
    if isinstance(mission, bool) or not isinstance(mission, (int, float)) or float(mission) <= 0:
        raise ValueError("FTA mission time must be positive")
    for name in ("operating_modes", "assumptions", "exclusions"):
        unique_text_list(scope[name], f"FTA {name}")
    bounded_text(result["independence_basis"], "FTA independence basis", allow_empty=True)
    unique_text_list(result["evidence_refs"], "FTA evidence refs")

    events = result["basic_events"]
    if not isinstance(events, list) or len(events) > MAX_BASIC_EVENTS:
        raise ValueError(f"FTA must contain no more than {MAX_BASIC_EVENTS} basic events")
    event_fields = {"id", "description", "probability", "probability_interval", "component_ids", "source_kind", "evidence_ref"}
    event_ids: list[str] = []
    for event in events:
        if not isinstance(event, dict) or set(event) != event_fields:
            raise ValueError("basic event fields are invalid")
        event_ids.append(bounded_text(event["id"], "basic event id"))
        bounded_text(event["description"], "basic event description")
        probability = _probability(event["probability"], "basic event probability")
        interval = event["probability_interval"]
        if not isinstance(interval, list) or len(interval) != 2:
            raise ValueError("basic event probability interval is invalid")
        lower = _probability(interval[0], "basic event lower probability")
        upper = _probability(interval[1], "basic event upper probability")
        if not lower <= probability <= upper:
            raise ValueError("basic event probability is outside its interval")
        unique_text_list(event["component_ids"], "basic event component ids")
        bounded_text(event["source_kind"], "basic event source kind")
        bounded_text(event["evidence_ref"], "basic event evidence ref")
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("basic event ids must be unique")

    gates = result["gates"]
    if not isinstance(gates, list) or len(gates) > MAX_GATES:
        raise ValueError("FTA gates are invalid")
    gate_fields = {"id", "kind", "input_ids", "rationale", "evidence_ref"}
    gate_ids: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != gate_fields:
            raise ValueError("FTA gate fields are invalid")
        gate_ids.append(bounded_text(gate["id"], "FTA gate id"))
        if gate["kind"] not in {"and", "or"}:
            raise ValueError("FTA supports only AND and OR gates")
        if len(unique_text_list(gate["input_ids"], "FTA gate inputs")) < 2:
            raise ValueError("FTA gates require at least two inputs")
        bounded_text(gate["rationale"], "FTA gate rationale")
        bounded_text(gate["evidence_ref"], "FTA gate evidence ref")
    if len(gate_ids) != len(set(gate_ids)) or set(event_ids) & set(gate_ids):
        raise ValueError("FTA event and gate ids must be globally unique")
    all_ids = set(event_ids) | set(gate_ids)
    gate_map = {item["id"]: item for item in gates}
    for gate in gates:
        if not set(gate["input_ids"]) <= all_ids:
            raise ValueError(f"FTA gate {gate['id']} has an unresolved input")
    top = bounded_text(result["top_gate_id"], "FTA top gate id", allow_empty=True)
    if top and top not in gate_map:
        raise ValueError("FTA top gate id does not reference a gate")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValueError("FTA gate graph contains a cycle")
        if identifier in visited or identifier not in gate_map:
            return
        visiting.add(identifier)
        for child in gate_map[identifier]["input_ids"]:
            visit(child)
        visiting.remove(identifier)
        visited.add(identifier)

    for gate_id in gate_ids:
        visit(gate_id)
    dependencies = result["dependency_declarations"]
    if not isinstance(dependencies, list) or len(dependencies) > MAX_GATES:
        raise ValueError("FTA dependency declarations are invalid")
    dependency_fields = {"id", "kind", "event_ids", "modeling_treatment", "basis", "evidence_ref"}
    dependency_ids: list[str] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != dependency_fields:
            raise ValueError("FTA dependency declaration fields are invalid")
        dependency_ids.append(bounded_text(dependency["id"], "dependency id"))
        bounded_text(dependency["kind"], "dependency kind")
        linked = unique_text_list(dependency["event_ids"], "dependency event ids")
        if len(linked) < 2 or not set(linked) <= set(event_ids):
            raise ValueError("dependency declaration has unresolved basic events")
        for name in ("modeling_treatment", "basis", "evidence_ref"):
            bounded_text(dependency[name], f"dependency {name}")
        if dependency["modeling_treatment"] not in SUPPORTED_DEPENDENCY_TREATMENTS:
            raise ValueError(
                "FTA dependency treatment is unsupported; represent it through a shared "
                "or explicit common-cause basic event"
            )
    if len(dependency_ids) != len(set(dependency_ids)):
        raise ValueError("FTA dependency ids must be unique")
    return copy.deepcopy(result)


def _evaluate(identifier: str, assignment: dict[str, bool], gates: dict[str, dict[str, Any]]) -> bool:
    if identifier in assignment:
        return assignment[identifier]
    gate = gates[identifier]
    values = [_evaluate(child, assignment, gates) for child in gate["input_ids"]]
    return all(values) if gate["kind"] == "and" else any(values)


def _exact_probability(event_ids: list[str], probabilities: dict[str, float], gates: dict[str, dict[str, Any]], top: str, forced: dict[str, bool] | None = None) -> float:
    forced = forced or {}
    variables = [identifier for identifier in event_ids if identifier not in forced]
    total = 0.0
    for values in itertools.product((False, True), repeat=len(variables)):
        assignment = dict(forced)
        assignment.update(zip(variables, values, strict=True))
        weight = 1.0
        for identifier, state in zip(variables, values, strict=True):
            probability = probabilities[identifier]
            weight *= probability if state else 1.0 - probability
        if _evaluate(top, assignment, gates):
            total += weight
    return total


def _minimal_cut_sets(identifier: str, events: set[str], gates: dict[str, dict[str, Any]], memo: dict[str, set[frozenset[str]]]) -> set[frozenset[str]]:
    if identifier in memo:
        return memo[identifier]
    if identifier in events:
        return {frozenset({identifier})}
    gate = gates[identifier]
    child_sets = [_minimal_cut_sets(child, events, gates, memo) for child in gate["input_ids"]]
    if gate["kind"] == "or":
        candidates = set().union(*child_sets)
    else:
        candidates = {frozenset().union(*parts) for parts in itertools.product(*child_sets)}
    minimal = {candidate for candidate in candidates if not any(other < candidate for other in candidates)}
    if len(minimal) > MAX_CUT_SETS:
        raise ValueError("FTA minimal cut-set limit exceeded")
    memo[identifier] = minimal
    return minimal


def quantitative_fta_assessment(analysis: dict[str, Any], source: str | Path | dict[str, Any]) -> dict[str, Any]:
    raw = load_json(source, label="quantitative FTA source") if not isinstance(source, dict) else source
    value = _source(raw, analysis)
    event_ids = [item["id"] for item in value["basic_events"]]
    event_set = set(event_ids)
    gates = {item["id"]: item for item in value["gates"]}
    top = value["top_gate_id"]
    ready = bool(value["model_scope"]["top_event"] and value["model_scope"]["system_boundary"] and value["model_scope"]["operating_modes"] and value["model_scope"]["assumptions"] and value["independence_basis"] and value["evidence_refs"] and event_ids and gates and top)
    if ready:
        nominal = {item["id"]: float(item["probability"]) for item in value["basic_events"]}
        lower = {item["id"]: float(item["probability_interval"][0]) for item in value["basic_events"]}
        upper = {item["id"]: float(item["probability_interval"][1]) for item in value["basic_events"]}
        top_probability = _exact_probability(event_ids, nominal, gates, top)
        interval = [_exact_probability(event_ids, lower, gates, top), _exact_probability(event_ids, upper, gates, top)]
        cut_sets = sorted((sorted(item) for item in _minimal_cut_sets(top, event_set, gates, {})), key=lambda item: (len(item), item))
        importance = [
            {"event_id": identifier, "birnbaum_importance": _exact_probability(event_ids, nominal, gates, top, {identifier: True}) - _exact_probability(event_ids, nominal, gates, top, {identifier: False})}
            for identifier in event_ids
        ]
    else:
        top_probability = None
        interval = None
        cut_sets = []
        importance = []
    assessment = {
        "format": QFTA_ASSESSMENT_FORMAT,
        "generated_at": value["generated_at"],
        "source_sha256": value["content_sha256"],
        "analysis_binding": copy.deepcopy(value["analysis_binding"]),
        "evaluation": {"method": "exact Boolean state enumeration with shared basic events", "top_event_probability": top_probability, "probability_interval": interval, "minimal_cut_sets": cut_sets, "importance": importance},
        "summary": {"complete": ready, "basic_events": len(event_ids), "gates": len(gates), "minimal_cut_sets": len(cut_sets), "dependency_declarations": len(value["dependency_declarations"])},
        "notice": "Results assume the supplied probability model and declared dependence treatment; they do not establish risk acceptability.",
    }
    return seal(assessment)


def seal_quantitative_fta_source(analysis: dict[str, Any], source: str | Path, destination: str | Path) -> Path:
    return publish_json(_source(seal(load_json(source, label="quantitative FTA source")), analysis), destination)


def verify_quantitative_fta_assessment(assessment: dict[str, Any], *, analysis: dict[str, Any] | None = None, source: dict[str, Any] | None = None) -> dict[str, Any]:
    errors: list[str] = []
    complete = False
    try:
        value = verify_seal(assessment, label="quantitative FTA assessment", format_value=QFTA_ASSESSMENT_FORMAT)
        if analysis is not None:
            verify_analysis_binding(value.get("analysis_binding"), analysis)
        if source is not None:
            if analysis is None:
                raise ValueError("analysis is required for exact source regeneration")
            if canonical_json_sha256(value) != canonical_json_sha256(quantitative_fta_assessment(analysis, source)):
                raise ValueError("quantitative FTA assessment does not exactly regenerate")
        complete = bool(value.get("summary", {}).get("complete"))
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return seal({"format": QFTA_VERIFICATION_FORMAT, "valid": not errors, "complete": not errors and complete, "errors": errors, "notice": "Verification establishes integrity and optional exact regeneration only."})


def verify_quantitative_fta_assessment_file(assessment_source: str | Path, *, analysis: dict[str, Any] | None = None, source_path: str | Path | None = None) -> dict[str, Any]:
    try:
        assessment = load_json(assessment_source, label="quantitative FTA assessment")
        source = load_json(source_path, label="quantitative FTA source") if source_path else None
        return verify_quantitative_fta_assessment(assessment, analysis=analysis, source=source)
    except (OSError, ValueError, TypeError) as exc:
        return seal({"format": QFTA_VERIFICATION_FORMAT, "valid": False, "complete": False, "errors": [str(exc)], "notice": "Verification failed closed."})


def export_quantitative_fta_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def export_quantitative_fta_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
