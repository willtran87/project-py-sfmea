"""IEC-aligned HAZOP, RBD, and Markov dependability workbench.

Static analysis supplies review scope and traceable candidates.  Design intent,
success logic, failure/repair rates, independence, and risk acceptance always
remain explicit engineering inputs; this module never invents them from a call
graph.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id, utc_now
from .report import analysis_state_sha256

DEPENDABILITY_AUTHORING_FORMAT = "pysfmea-dependability-authoring-1"
DEPENDABILITY_ASSESSMENT_FORMAT = "pysfmea-dependability-assessment-1"
DEPENDABILITY_VERIFICATION_FORMAT = "pysfmea-dependability-verification-1"
DEFAULT_HAZOP_GUIDEWORDS = (
    "omitted",
    "excessive",
    "insufficient",
    "incorrect",
    "early",
    "late",
    "out_of_order",
)
MAX_COMPONENTS = 10_000
MAX_DEVIATIONS = 250_000
MAX_BLOCKS = 10_000
MAX_GATES = 20_000
MAX_MARKOV_STATES = 250
MAX_MARKOV_TRANSITIONS = 10_000
MAX_TEXT = 20_000


def _text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be bounded text")
    result = value.strip()
    if not result and not allow_empty:
        raise ValueError(f"{label} must not be empty")
    return result


def dependability_authoring_template(
    analysis: dict[str, Any],
    *,
    authority: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Create a conservative engineering template from discovered components."""

    components = [
        item
        for item in analysis.get("components", [])
        if isinstance(item, dict)
    ][:MAX_COMPONENTS]
    timing_component_ids = {
        str(item.get("source_component_id", item.get("component_id", "")))
        for item in analysis.get("resilience_semantics", {}).get(
            "timing_relations", []
        )
        if isinstance(item, dict)
    }
    nodes: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    for component in components:
        identifier = str(component.get("id", ""))
        if not identifier:
            continue
        parameters = ["function_output"]
        if component.get("is_async") or identifier in timing_component_ids:
            parameters.append("timing")
        if len(component.get("ordered_calls", [])) > 1:
            parameters.append("ordering")
        if component.get("state_transitions"):
            parameters.append("state")
        source = component.get("source", {})
        reference = (
            f"{source.get('path', '')}:{component.get('qualname', '')}"
            if isinstance(source, dict)
            else str(component.get("qualname", ""))
        )
        nodes.append(
            {
                "id": identifier,
                "name": str(component.get("qualname", component.get("name", identifier))),
                "design_intent": "",
                "parameters": parameters,
                "deviations": [],
                "source_ref": reference,
            }
        )
        blocks.append(
            {
                "id": identifier,
                "name": str(component.get("qualname", component.get("name", identifier))),
                "reliability": None,
                "reliability_interval": None,
                "failure_rate_per_hour": None,
                "repair_rate_per_hour": None,
                "evidence_ref": "",
                "source_ref": reference,
            }
        )
    markov_models: list[dict[str, Any]] = []
    for breaker in analysis.get("resilience_semantics", {}).get(
        "circuit_breakers", []
    )[:1_000]:
        if not isinstance(breaker, dict):
            continue
        reference = str(
            breaker.get("component_reference", breaker.get("component_id", "breaker"))
        )
        model_id = stable_id("MARKOV", reference)
        markov_models.append(
            {
                "id": model_id,
                "title": f"Circuit-breaker state model for {reference}",
                "mission_time_hours": 1.0,
                "initial_state": "closed",
                "states": ["closed", "open", "half_open"],
                "transitions": [
                    {
                        "source": "closed",
                        "target": "open",
                        "rate_per_hour": None,
                        "evidence_ref": "replace-with-observed-failure-rate",
                    },
                    {
                        "source": "open",
                        "target": "half_open",
                        "rate_per_hour": None,
                        "evidence_ref": "replace-with-recovery-policy-rate",
                    },
                    {
                        "source": "half_open",
                        "target": "closed",
                        "rate_per_hour": None,
                        "evidence_ref": "replace-with-recovery-success-rate",
                    },
                    {
                        "source": "half_open",
                        "target": "open",
                        "rate_per_hour": None,
                        "evidence_ref": "replace-with-probe-failure-rate",
                    },
                ],
                "source_ref": reference,
            }
        )
    result: dict[str, Any] = {
        "format": DEPENDABILITY_AUTHORING_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": _text(authority, "dependability authority"),
        "analysis_binding": {
            "baseline_id": str(
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            ),
            "analysis_state_sha256": analysis_state_sha256(analysis),
        },
        "assumptions": [],
        "hazop": {"guidewords": list(DEFAULT_HAZOP_GUIDEWORDS), "nodes": nodes},
        "rbd": {
            "mission_time_hours": 1.0,
            "success_criterion": "",
            "blocks": blocks,
            "gates": [],
            "top_gate_id": "",
        },
        "markov_models": markov_models,
        "notice": (
            "Populate design intent, deviations, safeguards, success logic, rates, "
            "dependencies, uncertainty, and evidence under authorized engineering review."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def _authoring(value: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    required = {
        "format",
        "generated_at",
        "authority",
        "analysis_binding",
        "assumptions",
        "hazop",
        "rbd",
        "markov_models",
        "notice",
        "content_sha256",
    }
    if set(value) != required or value.get("format") != DEPENDABILITY_AUTHORING_FORMAT:
        raise ValueError("dependability authoring fields or format do not match format 1")
    unsigned = copy.deepcopy(value)
    claimed = unsigned.pop("content_sha256", "")
    if (
        not isinstance(claimed, str)
        or not re.fullmatch(r"[0-9a-f]{64}", claimed)
        or canonical_json_sha256(unsigned) != claimed
    ):
        raise ValueError("dependability authoring content digest does not match")
    _text(value["authority"], "dependability authority")
    binding = value["analysis_binding"]
    if (
        not isinstance(binding, dict)
        or set(binding) != {"baseline_id", "analysis_state_sha256"}
        or binding["analysis_state_sha256"] != analysis_state_sha256(analysis)
    ):
        raise ValueError("dependability authoring does not bind the exact analysis state")
    assumptions = value["assumptions"]
    if (
        not isinstance(assumptions, list)
        or len(assumptions) > 10_000
        or any(not isinstance(item, str) or not item.strip() for item in assumptions)
    ):
        raise ValueError("dependability assumptions are invalid")
    return copy.deepcopy(value)


def seal_dependability_authoring(
    analysis: dict[str, Any], source: str | Path, destination: str | Path
) -> Path:
    """Reseal and validate an edited, exact-analysis-bound authoring artifact."""

    document = load_bounded_json_document(
        source,
        label="dependability authoring",
        max_bytes=100_000_000,
        max_depth=150,
        max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("dependability authoring must contain an object")
    value = copy.deepcopy(document.value)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    validated = _authoring(value, analysis)
    return export_dependability_authoring(validated, destination)


def _hazop(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"guidewords", "nodes"}:
        raise ValueError("HAZOP authoring is invalid")
    guidewords = value["guidewords"]
    nodes = value["nodes"]
    if (
        not isinstance(guidewords, list)
        or not guidewords
        or len(guidewords) > 100
        or len(guidewords) != len(set(guidewords))
        or any(not isinstance(item, str) or not item for item in guidewords)
        or not isinstance(nodes, list)
        or len(nodes) > MAX_COMPONENTS
    ):
        raise ValueError("HAZOP guidewords or nodes are invalid")
    required_pairs: set[tuple[str, str, str]] = set()
    covered_pairs: set[tuple[str, str, str]] = set()
    complete_deviations = 0
    node_results: list[dict[str, Any]] = []
    total_deviations = 0
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {
            "id",
            "name",
            "design_intent",
            "parameters",
            "deviations",
            "source_ref",
        }:
            raise ValueError("HAZOP node fields are invalid")
        node_id = _text(node["id"], "HAZOP node id")
        parameters = node["parameters"]
        deviations = node["deviations"]
        if (
            not isinstance(parameters, list)
            or not parameters
            or len(parameters) > 100
            or not isinstance(deviations, list)
            or total_deviations + len(deviations) > MAX_DEVIATIONS
        ):
            raise ValueError(f"HAZOP node {node_id} parameters or deviations are invalid")
        total_deviations += len(deviations)
        for parameter in parameters:
            for guideword in guidewords:
                required_pairs.add((node_id, str(parameter), str(guideword)))
        node_complete = 0
        for deviation in deviations:
            fields = {
                "parameter",
                "guideword",
                "deviation",
                "causes",
                "effects",
                "safeguards",
                "recommendations",
                "evidence_refs",
                "status",
            }
            if not isinstance(deviation, dict) or set(deviation) != fields:
                raise ValueError(f"HAZOP node {node_id} deviation fields are invalid")
            pair = (node_id, str(deviation["parameter"]), str(deviation["guideword"]))
            if pair not in required_pairs or pair in covered_pairs:
                raise ValueError(f"HAZOP node {node_id} deviation pair is invalid or duplicated")
            covered_pairs.add(pair)
            arrays = [
                deviation[name]
                for name in ("causes", "effects", "safeguards", "recommendations", "evidence_refs")
            ]
            complete = bool(
                deviation["status"] in {"reviewed", "closed"}
                and _text(deviation["deviation"], "HAZOP deviation")
                and all(
                    isinstance(items, list)
                    and items
                    and all(isinstance(item, str) and item.strip() for item in items)
                    for items in arrays
                )
            )
            if complete:
                complete_deviations += 1
                node_complete += 1
        node_results.append(
            {
                "node_id": node_id,
                "required_pairs": len(parameters) * len(guidewords),
                "recorded_pairs": len(deviations),
                "complete_pairs": node_complete,
                "design_intent_present": bool(str(node["design_intent"]).strip()),
            }
        )
    missing = sorted(
        {f"{node}:{parameter}:{guideword}" for node, parameter, guideword in required_pairs - covered_pairs}
    )
    return {
        "guidewords": len(guidewords),
        "nodes": len(nodes),
        "required_pairs": len(required_pairs),
        "recorded_pairs": len(covered_pairs),
        "complete_pairs": complete_deviations,
        "missing_pairs": missing[:MAX_DEVIATIONS],
        "node_results": node_results,
        "complete": bool(
            required_pairs
            and not missing
            and complete_deviations == len(required_pairs)
            and all(item["design_intent_present"] for item in node_results)
        ),
    }


def _vote_probability(values: list[float], minimum_success: int) -> float:
    distribution = [1.0] + [0.0] * len(values)
    for probability in values:
        updated = [0.0] * len(distribution)
        for successes, prior in enumerate(distribution):
            updated[successes] += prior * (1.0 - probability)
            if successes + 1 < len(updated):
                updated[successes + 1] += prior * probability
        distribution = updated
    return sum(distribution[minimum_success:])


def _rbd(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "mission_time_hours",
        "success_criterion",
        "blocks",
        "gates",
        "top_gate_id",
    }:
        raise ValueError("RBD authoring is invalid")
    blocks = value["blocks"]
    gates = value["gates"]
    if (
        not isinstance(blocks, list)
        or len(blocks) > MAX_BLOCKS
        or not isinstance(gates, list)
        or len(gates) > MAX_GATES
    ):
        raise ValueError("RBD block or gate population is invalid")
    mission = value["mission_time_hours"]
    if not isinstance(mission, (int, float)) or isinstance(mission, bool) or not 0.0 < float(mission) <= 1_000_000.0:
        raise ValueError("RBD mission time is invalid")
    probabilities: dict[str, float | None] = {}
    bounds: dict[str, tuple[float, float] | None] = {}
    block_measures: list[dict[str, Any]] = []
    for block in blocks:
        legacy_fields = {"id", "name", "reliability", "source_ref"}
        quantitative_fields = legacy_fields | {
            "reliability_interval", "failure_rate_per_hour", "repair_rate_per_hour", "evidence_ref"
        }
        if not isinstance(block, dict) or frozenset(block) not in {frozenset(legacy_fields), frozenset(quantitative_fields)}:
            raise ValueError("RBD block fields are invalid")
        identifier = _text(block["id"], "RBD block id")
        reliability = block["reliability"]
        if reliability is not None and (
            not isinstance(reliability, (int, float))
            or isinstance(reliability, bool)
            or not 0.0 <= float(reliability) <= 1.0
        ):
            raise ValueError(f"RBD block {identifier} reliability is invalid")
        rate = block.get("failure_rate_per_hour")
        repair_rate = block.get("repair_rate_per_hour")
        interval = block.get("reliability_interval")
        evidence_ref = str(block.get("evidence_ref", "")).strip()
        for label, parameter in (("failure", rate), ("repair", repair_rate)):
            if parameter is not None and (
                not isinstance(parameter, (int, float)) or isinstance(parameter, bool) or not 0.0 <= float(parameter) <= 1_000_000.0
            ):
                raise ValueError(f"RBD block {identifier} {label} rate is invalid")
        if reliability is not None and rate is not None:
            raise ValueError(f"RBD block {identifier} cannot declare both direct reliability and a failure rate")
        if reliability is None and rate is not None:
            if not evidence_ref:
                raise ValueError(f"RBD block {identifier} failure rate requires evidence")
            reliability = math.exp(-float(rate) * float(mission))
        interval_value: tuple[float, float] | None = None
        if interval is not None:
            if (
                not isinstance(interval, list) or len(interval) != 2
                or any(not isinstance(item, (int, float)) or isinstance(item, bool) for item in interval)
                or not 0.0 <= float(interval[0]) <= float(interval[1]) <= 1.0
                or reliability is None
                or not float(interval[0]) <= float(reliability) <= float(interval[1])
                or not evidence_ref
            ):
                raise ValueError(f"RBD block {identifier} reliability interval is invalid")
            interval_value = (float(interval[0]), float(interval[1]))
        elif reliability is not None:
            interval_value = (float(reliability), float(reliability))
        if identifier in probabilities:
            raise ValueError("RBD identifiers must be unique")
        probabilities[identifier] = None if reliability is None else float(reliability)
        bounds[identifier] = interval_value
        availability = None
        if rate is not None and repair_rate is not None:
            denominator = float(rate) + float(repair_rate)
            availability = 1.0 if denominator == 0.0 else float(repair_rate) / denominator
        block_measures.append(
            {
                "id": identifier,
                "reliability": None if reliability is None else round(float(reliability), 12),
                "reliability_interval": None if interval_value is None else [round(interval_value[0], 12), round(interval_value[1], 12)],
                "steady_state_availability": None if availability is None else round(availability, 12),
                "rate_evidence_present": bool(evidence_ref) if rate is not None or repair_rate is not None else None,
            }
        )
    gate_map: dict[str, dict[str, Any]] = {}
    for gate in gates:
        legacy_gate_fields = {"id", "type", "inputs", "minimum_success"}
        quantitative_gate_fields = legacy_gate_fields | {"independence_evidence_ref", "common_cause_beta"}
        if not isinstance(gate, dict) or frozenset(gate) not in {frozenset(legacy_gate_fields), frozenset(quantitative_gate_fields)}:
            raise ValueError("RBD gate fields are invalid")
        identifier = _text(gate["id"], "RBD gate id")
        if identifier in probabilities or identifier in gate_map:
            raise ValueError("RBD identifiers must be unique")
        if gate["type"] not in {"series", "parallel", "vote"}:
            raise ValueError(f"RBD gate {identifier} type is invalid")
        inputs = gate["inputs"]
        if not isinstance(inputs, list) or not inputs or len(inputs) > MAX_BLOCKS + MAX_GATES:
            raise ValueError(f"RBD gate {identifier} inputs are invalid")
        minimum = gate["minimum_success"]
        if gate["type"] == "vote" and (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or not 1 <= minimum <= len(inputs)
        ):
            raise ValueError(f"RBD gate {identifier} vote threshold is invalid")
        if gate["type"] != "vote" and minimum is not None:
            raise ValueError(f"RBD gate {identifier} threshold only applies to vote gates")
        beta = gate.get("common_cause_beta", 0.0)
        if not isinstance(beta, (int, float)) or isinstance(beta, bool) or not 0.0 <= float(beta) <= 1.0:
            raise ValueError(f"RBD gate {identifier} common-cause beta is invalid")
        if len(inputs) > 1 and not str(gate.get("independence_evidence_ref", "")).strip():
            raise ValueError(f"RBD gate {identifier} requires an explicit independence evidence reference")
        gate_map[identifier] = gate

    visiting: set[str] = set()

    def combine(gate: dict[str, Any], numeric: list[float]) -> float:
        if gate["type"] == "series":
            independent = math.prod(numeric)
        elif gate["type"] == "parallel":
            independent = 1.0 - math.prod(1.0 - item for item in numeric)
        else:
            independent = _vote_probability(numeric, int(gate["minimum_success"]))
        beta = float(gate.get("common_cause_beta", 0.0))
        # A beta-factor sensitivity adjustment: the beta share succeeds only when the
        # weakest modeled channel succeeds. It is intentionally identified as an
        # engineering approximation, not inferred physical dependence.
        return (1.0 - beta) * independent + beta * min(numeric)

    def evaluate(identifier: str) -> float | None:
        if identifier in probabilities:
            return probabilities[identifier]
        if identifier not in gate_map:
            raise ValueError(f"RBD reference {identifier!r} is unresolved")
        if identifier in visiting:
            raise ValueError("RBD gate graph contains a cycle")
        visiting.add(identifier)
        gate = gate_map[identifier]
        values = [evaluate(str(item)) for item in gate["inputs"]]
        visiting.remove(identifier)
        if any(item is None for item in values):
            result = None
        else:
            numeric = [float(item) for item in values if item is not None]
            result = combine(gate, numeric)
        probabilities[identifier] = result
        return result

    bound_visiting: set[tuple[str, bool]] = set()

    def evaluate_bound(identifier: str, upper: bool) -> float | None:
        if identifier in bounds:
            pair = bounds[identifier]
            return None if pair is None else pair[1 if upper else 0]
        key = (identifier, upper)
        if identifier not in gate_map or key in bound_visiting:
            raise ValueError("RBD bound graph is cyclic or unresolved")
        bound_visiting.add(key)
        numeric = [evaluate_bound(str(item), upper) for item in gate_map[identifier]["inputs"]]
        bound_visiting.remove(key)
        if any(item is None for item in numeric):
            return None
        return combine(gate_map[identifier], [float(item) for item in numeric if item is not None])

    top = str(value["top_gate_id"])
    top_probability = evaluate(top) if top else None
    lower = evaluate_bound(top, False) if top else None
    upper = evaluate_bound(top, True) if top else None
    # Birnbaum structural importance is the change in top-event success when one
    # block is forced from failed to perfect.  It is a deterministic sensitivity
    # measure over the declared RBD, not a causal or physical-dependence claim.
    def evaluate_override(
        identifier: str,
        block_id: str,
        replacement: float,
        active: set[str],
    ) -> float | None:
        if identifier == block_id:
            return replacement
        if identifier in probabilities and identifier not in gate_map:
            return probabilities[identifier]
        if identifier not in gate_map or identifier in active:
            raise ValueError("RBD importance graph is cyclic or unresolved")
        active.add(identifier)
        values = [
            evaluate_override(str(item), block_id, replacement, active)
            for item in gate_map[identifier]["inputs"]
        ]
        active.remove(identifier)
        if any(item is None for item in values):
            return None
        return combine(gate_map[identifier], [float(item) for item in values if item is not None])

    for measure in block_measures:
        block_id = str(measure["id"])
        perfect = evaluate_override(top, block_id, 1.0, set()) if top else None
        failed = evaluate_override(top, block_id, 0.0, set()) if top else None
        measure["birnbaum_importance"] = (
            None
            if perfect is None or failed is None
            else round(max(0.0, perfect - failed), 12)
        )
    all_rates_present = all(probability is not None for probability in probabilities.values())
    return {
        "mission_time_hours": float(mission),
        "success_criterion_present": bool(str(value["success_criterion"]).strip()),
        "blocks": len(blocks),
        "gates": len(gates),
        "top_gate_id": top,
        "top_success_probability": None if top_probability is None else round(top_probability, 12),
        "top_success_interval": None if lower is None or upper is None else [round(lower, 12), round(upper, 12)],
        "block_measures": block_measures,
        "common_cause_gates": sum(float(gate.get("common_cause_beta", 0.0)) > 0.0 for gate in gates),
        "independence_evidence_complete": all(len(gate["inputs"]) <= 1 or bool(str(gate.get("independence_evidence_ref", "")).strip()) for gate in gates),
        "all_reliabilities_present": all_rates_present,
        "complete": bool(top and top_probability is not None and str(value["success_criterion"]).strip()),
        "notice": "The calculation uses only explicit inputs. Intervals are monotone sensitivity bounds; beta-factor common-cause adjustment is an engineering approximation; Birnbaum importance is structural sensitivity. Input validity, causality, and physical independence are not inferred.",
    }


def _row_vector_matrix(vector: list[float], matrix: list[list[float]]) -> list[float]:
    return [
        sum(vector[row] * matrix[row][column] for row in range(len(vector)))
        for column in range(len(vector))
    ]


def _markov_model(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {
        "id",
        "title",
        "mission_time_hours",
        "initial_state",
        "states",
        "transitions",
        "source_ref",
    }:
        raise ValueError("Markov model fields are invalid")
    identifier = _text(value["id"], "Markov model id")
    states = value["states"]
    transitions = value["transitions"]
    mission = value["mission_time_hours"]
    if (
        not isinstance(states, list)
        or not 1 <= len(states) <= MAX_MARKOV_STATES
        or len(states) != len(set(states))
        or not isinstance(transitions, list)
        or len(transitions) > MAX_MARKOV_TRANSITIONS
        or not isinstance(mission, (int, float))
        or isinstance(mission, bool)
        or not 0.0 < float(mission) <= 1_000_000.0
        or value["initial_state"] not in states
    ):
        raise ValueError(f"Markov model {identifier} shape is invalid")
    if any(
        not isinstance(transition, dict)
        or set(transition) != {"source", "target", "rate_per_hour", "evidence_ref"}
        for transition in transitions
    ):
        raise ValueError(f"Markov model {identifier} transitions are invalid")
    missing_rate = any(transition["rate_per_hour"] is None for transition in transitions)
    if missing_rate:
        return {
            "id": identifier,
            "states": len(states),
            "transitions": len(transitions),
            "mission_time_hours": float(mission),
            "state_probabilities": None,
            "probability_sum": None,
            "complete": False,
            "reason": "one or more transition rates are unresolved",
        }
    indexes = {state: index for index, state in enumerate(states)}
    generator = [[0.0 for _ in states] for _ in states]
    for transition in transitions:
        source = transition["source"]
        target = transition["target"]
        rate = transition["rate_per_hour"]
        if (
            source not in indexes
            or target not in indexes
            or source == target
            or not isinstance(rate, (int, float))
            or isinstance(rate, bool)
            or not 0.0 < float(rate) <= 1_000_000.0
            or not str(transition["evidence_ref"]).strip()
        ):
            raise ValueError(f"Markov model {identifier} transition is invalid")
        generator[indexes[source]][indexes[target]] += float(rate)
    for row in range(len(states)):
        generator[row][row] = -sum(generator[row][column] for column in range(len(states)) if column != row)
    uniform_rate = max(-generator[row][row] for row in range(len(states)))
    if uniform_rate == 0.0:
        probabilities = [1.0 if state == value["initial_state"] else 0.0 for state in states]
    else:
        scaled_time = uniform_rate * float(mission)
        if scaled_time > 500.0:
            raise ValueError(
                f"Markov model {identifier} rate-time product exceeds the bounded solver domain"
            )
        transition_matrix = [
            [
                (1.0 if row == column else 0.0)
                + generator[row][column] / uniform_rate
                for column in range(len(states))
            ]
            for row in range(len(states))
        ]
        term = [1.0 if state == value["initial_state"] else 0.0 for state in states]
        weight = math.exp(-scaled_time)
        probabilities = [weight * item for item in term]
        cumulative_weight = weight
        for order in range(1, 100_001):
            term = _row_vector_matrix(term, transition_matrix)
            weight *= scaled_time / order
            cumulative_weight += weight
            probabilities = [
                probabilities[index] + weight * term[index]
                for index in range(len(states))
            ]
            if 1.0 - cumulative_weight < 1e-13:
                break
        else:
            raise ValueError(f"Markov model {identifier} did not converge within the solver limit")
    total = sum(probabilities)
    if not math.isclose(total, 1.0, rel_tol=1e-9, abs_tol=1e-9):
        raise ValueError(f"Markov model {identifier} violates probability conservation")
    return {
        "id": identifier,
        "states": len(states),
        "transitions": len(transitions),
        "mission_time_hours": float(mission),
        "state_probabilities": {
            state: round(probabilities[index], 12) for index, state in enumerate(states)
        },
        "probability_sum": round(total, 12),
        "complete": True,
        "reason": "",
    }


def dependability_assessment(
    analysis: dict[str, Any],
    authoring_source: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    document = load_bounded_json_document(
        authoring_source,
        label="dependability authoring",
        max_bytes=100_000_000,
        max_depth=100,
        max_nodes=2_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("dependability authoring must contain an object")
    authoring = _authoring(document.value, analysis)
    hazop = _hazop(authoring["hazop"])
    rbd = _rbd(authoring["rbd"])
    markov = [_markov_model(item) for item in authoring["markov_models"]]
    checks = {
        "analysis_binding": True,
        "hazop_complete": hazop["complete"],
        "rbd_complete": rbd["complete"],
        "markov_complete": bool(markov) and all(item["complete"] for item in markov),
        "assumptions_present": bool(authoring["assumptions"]),
    }
    complete = all(checks.values())
    result: dict[str, Any] = {
        "format": DEPENDABILITY_ASSESSMENT_FORMAT,
        "generated_at": generated_at or utc_now(),
        "binding": {
            "analysis_state_sha256": analysis_state_sha256(analysis),
            "authoring_reference": document.path.name,
            "authoring_bytes": document.size,
            "authoring_sha256": hashlib.sha256(document.raw).hexdigest(),
            "authoring_content_sha256": authoring["content_sha256"],
        },
        "authority": authoring["authority"],
        "hazop": hazop,
        "rbd": rbd,
        "markov_models": markov,
        "checks": checks,
        "summary": {
            "complete": complete,
            "status": "eligible_for_authorized_dependability_review" if complete else "engineering_inputs_incomplete",
            "failed_checks": sorted(name for name, state in checks.items() if not state),
        },
        "notice": (
            "Results apply only to the explicit design intent, logic, rates, assumptions, "
            "and exact source baseline. Authorized review is still required."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_dependability_assessment(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "format",
        "generated_at",
        "binding",
        "authority",
        "hazop",
        "rbd",
        "markov_models",
        "checks",
        "summary",
        "notice",
        "content_sha256",
    }
    errors: list[str] = []
    structure = bool(
        set(value) == expected
        and value.get("format") == DEPENDABILITY_ASSESSMENT_FORMAT
        and isinstance(value.get("checks"), dict)
        and isinstance(value.get("summary"), dict)
    )
    if not structure:
        errors.append("dependability assessment fields do not match format 1")
    semantic = False
    try:
        complete = all(value["checks"].values())
        semantic = bool(
            value["summary"]
            == {
                "complete": complete,
                "status": "eligible_for_authorized_dependability_review" if complete else "engineering_inputs_incomplete",
                "failed_checks": sorted(name for name, state in value["checks"].items() if not state),
            }
        )
    except (KeyError, TypeError):
        semantic = False
    if not semantic:
        errors.append("dependability summary does not reconcile")
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(unsigned) == claimed
    )
    if not integrity:
        errors.append("dependability assessment content digest does not match")
    return {
        "format": DEPENDABILITY_VERIFICATION_FORMAT,
        "valid": bool(structure and semantic and integrity),
        "complete": bool(structure and semantic and integrity and value.get("summary", {}).get("complete")),
        "checks": {
            "closed_structure": structure,
            "content_integrity": integrity,
            "semantic_reconciliation": semantic,
            "source_regeneration": None,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification proves exact assessment accounting, not engineering authority, input validity, independence, or risk acceptance.",
    }


def verify_dependability_assessment_file(
    source: str | Path,
    *,
    analysis: dict[str, Any] | None = None,
    authoring_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="dependability assessment",
            max_bytes=100_000_000,
            max_depth=150,
            max_nodes=3_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("dependability assessment must contain an object")
        verdict = {"path": str(document.path), **verify_dependability_assessment(document.value)}
        if analysis is not None or authoring_source is not None:
            if analysis is None or authoring_source is None:
                verdict["valid"] = False
                verdict["complete"] = False
                verdict["checks"]["source_regeneration"] = False
                verdict["errors"].append("analysis and authoring must be supplied together")
            else:
                regenerated = dependability_assessment(
                    analysis,
                    authoring_source,
                    generated_at=str(document.value.get("generated_at", "")),
                )
                matches = regenerated == document.value
                verdict["checks"]["source_regeneration"] = matches
                if not matches:
                    verdict["valid"] = False
                    verdict["complete"] = False
                    verdict["errors"].append("assessment does not regenerate from supplied sources")
        return verdict
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": DEPENDABILITY_VERIFICATION_FORMAT,
            "valid": False,
            "complete": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "semantic_reconciliation": False,
                "source_regeneration": False if analysis is not None or authoring_source is not None else None,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The dependability assessment could not be safely verified.",
        }


def export_dependability_authoring(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="dependability authoring",
    )


def export_dependability_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    verdict = verify_dependability_assessment(value)
    if not verdict["valid"]:
        raise ValueError("dependability assessment is internally invalid")
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="dependability assessment",
    )
