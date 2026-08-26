"""Deterministic, fail-visible pytest designs for assurance obligations.

The synthesizer deliberately stops at the repository adapter boundary.  It can turn a
governed obligation into bounded inputs, cases, and assertion contracts, but it cannot
infer that a project callable is safe to invoke or that an observed result satisfies an
engineering oracle.  Generated adapters therefore fail until a project engineer supplies
that connection explicitly.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterable
from typing import Any

from .model import stable_id

ASSURANCE_TEST_DESIGNS_FORMAT = "pysfmea-assurance-test-designs-1"
MAX_SYNTHESIZED_PARAMETERS = 32
MAX_CONTRACTS_PER_DESIGN = 20
MAX_OPERATIONS_PER_CONTRACT = 20
MAX_CONTRACT_CASES_PER_DESIGN = 40
ASSURANCE_SCAFFOLD_GENERATED_FILE_ROLES = {
    "README.md": "operator_notice",
    "sfmea_assurance_runtime.py": "bounded_manifest_and_observation_runtime",
    "sfmea_assurance_adapters.py": "project_owned_failing_adapters",
    "test_sfmea_assurance.py": "failing_unsynthesized_placeholders",
    "test_sfmea_generated_properties.py": "hypothesis_property_test_designs",
    "test_sfmea_generated_contracts.py": "producer_consumer_contract_test_designs",
}

_BOOLEAN_NAMES = {
    "active",
    "allow",
    "allowed",
    "enabled",
    "exists",
    "force",
    "ready",
    "required",
    "success",
    "valid",
}
_INTEGER_TOKENS = {
    "attempt",
    "count",
    "depth",
    "index",
    "limit",
    "offset",
    "page",
    "port",
    "retries",
    "retry",
    "size",
    "timeout",
    "ttl",
    "version",
}
_FLOAT_TOKENS = {
    "amount",
    "duration",
    "percent",
    "probability",
    "ratio",
    "rate",
    "score",
    "seconds",
    "threshold",
    "weight",
}
_TEXT_TOKENS = {
    "address",
    "email",
    "host",
    "id",
    "key",
    "label",
    "name",
    "path",
    "query",
    "role",
    "scope",
    "token",
    "url",
}


def _signature_parameter_annotations(signature: Any) -> dict[str, str]:
    """Recover exact parameter annotations retained in the scanner signature."""

    text = str(signature or "")
    if not text or len(text) > 20_000:
        return {}
    try:
        parsed = ast.parse(f"def {text}:\n    pass\n")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {}
    function = parsed.body[0] if parsed.body else None
    if not isinstance(function, ast.FunctionDef):
        return {}
    arguments = function.args
    values = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        values.append(arguments.vararg)
    if arguments.kwarg is not None:
        values.append(arguments.kwarg)
    return {
        value.arg: ast.unparse(value.annotation)
        for value in values
        if value.annotation is not None
    }


def _normalized_type(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "").casefold())


def _name_tokens(name: str) -> set[str]:
    return {
        token
        for token in re.split(r"[^a-z0-9]+|(?<=[a-z])(?=[A-Z])", name.casefold())
        if token
    }


def _strategy_for(name: str, annotation: Any) -> dict[str, Any]:
    """Derive one bounded JSON strategy specification with explicit provenance."""

    normalized = _normalized_type(annotation)
    tokens = _name_tokens(name)
    nullable = "optional[" in normalized or "none" in normalized or "|null" in normalized
    basis = "parameter_annotation" if normalized else "parameter_name_heuristic"

    if normalized in {"bool", "builtins.bool"} or tokens & _BOOLEAN_NAMES:
        strategy: dict[str, Any] = {"kind": "booleans", "basis": basis}
    elif "bytes" in normalized or "bytearray" in normalized:
        strategy = {"kind": "binary", "minimum_size": 0, "maximum_size": 256, "basis": basis}
    elif any(marker in normalized for marker in ("list[", "sequence[", "tuple[", "set[")):
        strategy = {
            "kind": "lists",
            "minimum_size": 0,
            "maximum_size": 20,
            "item_strategy": {"kind": "bounded_scalar"},
            "basis": basis,
        }
    elif any(marker in normalized for marker in ("dict[", "mapping[")):
        strategy = {
            "kind": "dictionaries",
            "minimum_size": 0,
            "maximum_size": 20,
            "key_strategy": {"kind": "text", "minimum_size": 1, "maximum_size": 32},
            "value_strategy": {"kind": "bounded_scalar"},
            "basis": basis,
        }
    elif any(
        marker in normalized
        for marker in ("int", "integer", "nonnegativeint", "positiveint")
    ) or tokens & _INTEGER_TOKENS:
        strategy = {
            "kind": "integers",
            "minimum": -(2**31),
            "maximum": 2**31 - 1,
            "basis": basis,
        }
    elif any(marker in normalized for marker in ("float", "decimal", "number")) or (
        tokens & _FLOAT_TOKENS
    ):
        strategy = {
            "kind": "floats",
            "minimum": -1.0e12,
            "maximum": 1.0e12,
            "allow_nan": False,
            "allow_infinity": False,
            "basis": basis,
        }
    elif any(marker in normalized for marker in ("str", "path", "uuid", "url")) or (
        tokens & _TEXT_TOKENS
    ):
        strategy = {
            "kind": "text",
            "minimum_size": 0,
            "maximum_size": 256,
            "basis": basis,
        }
    else:
        strategy = {
            "kind": "bounded_scalar",
            "basis": "unresolved_type_bounded_fallback",
        }
    if nullable:
        strategy = {
            "kind": "one_of",
            "strategies": [{"kind": "none"}, strategy],
            "basis": f"nullable_{basis}",
        }
    return strategy


def _criteria(obligation: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "id": stable_id("AC", str(obligation.get("id", "")), str(index), text),
            "text": text,
        }
        for index, text in enumerate(
            (str(value) for value in obligation.get("acceptance_criteria", []) if value),
            start=1,
        )
    ]


def _oracles(obligation: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "id": stable_id("ORACLE", str(obligation.get("id", "")), str(index), text),
            "text": text,
        }
        for index, text in enumerate(
            (str(value) for value in obligation.get("oracles", []) if value),
            start=1,
        )
    ]


def _scenarios(obligation: dict[str, Any]) -> list[str]:
    failure_class = str(obligation.get("failure_class", "functional"))
    scenarios = {
        "calculation": ["nominal", "lower_boundary", "upper_boundary", "near_zero", "invalid"],
        "data": ["nominal", "empty", "missing", "malformed", "boundary"],
        "interface": ["nominal", "unavailable", "malformed_response", "late_response"],
        "timing": ["nominal", "early", "deadline_boundary", "late", "reordered"],
        "resource": ["nominal", "empty", "capacity_boundary", "over_capacity"],
        "security": ["authorized", "unauthorized", "wrong_scope", "malformed_identity"],
        "state": ["valid_transition", "invalid_transition", "duplicate_transition", "reordered"],
    }.get(failure_class, ["nominal", "boundary", "invalid", "adversarial"])
    return scenarios


def _common_design(obligation: dict[str, Any], *, prefix: str) -> dict[str, Any]:
    return {
        "id": stable_id(prefix, str(obligation.get("id", ""))),
        "obligation_id": str(obligation.get("id", "")),
        "finding_id": str(obligation.get("finding_id", "")),
        "component_id": str(obligation.get("component_id", "")),
        "component": str(obligation.get("component", "")),
        "source": obligation.get("source", {}),
        "contract_sha256": str(
            obligation.get("provenance", {}).get("contract_sha256", "")
        ),
        "failure_condition": str(obligation.get("failure_condition", "")),
        "oracles": _oracles(obligation),
        "acceptance_criteria": _criteria(obligation),
        "adapter_status": "project_implementation_required",
    }


def _property_design(
    obligation: dict[str, Any], component: dict[str, Any]
) -> dict[str, Any]:
    design = _common_design(obligation, prefix="PROPERTY-DESIGN")
    parameters = [str(value) for value in component.get("parameters", []) if value]
    symbol_types = component.get("symbol_types", {})
    if not isinstance(symbol_types, dict):
        symbol_types = {}
    annotations = {
        **{str(key): str(value) for key, value in symbol_types.items()},
        **_signature_parameter_annotations(component.get("signature", "")),
    }
    truncated = len(parameters) > MAX_SYNTHESIZED_PARAMETERS
    parameter_designs: list[dict[str, Any]] = [
        {
            "name": name,
            "annotation": str(annotations.get(name, "")),
            "strategy": _strategy_for(name, annotations.get(name, "")),
        }
        for name in parameters[:MAX_SYNTHESIZED_PARAMETERS]
    ]
    unresolved = sum(
        value["strategy"].get("basis") == "unresolved_type_bounded_fallback"
        for value in parameter_designs
    )
    design.update(
        {
            "method": "property_test",
            "adapter_function": "exercise_property",
            "parameters": parameter_designs,
            "scenarios": _scenarios(obligation),
            "generation": {
                "engine": "hypothesis",
                "max_examples": 40,
                "derandomize": True,
                "deadline": None,
            },
            "strategy_strength": (
                "annotation_and_name_based"
                if parameter_designs and unresolved == 0
                else "bounded_heuristic"
            ),
            "limitations": [
                "Generated values do not establish semantic validity or repository-safe invocation.",
                "A project adapter must invoke the exact subject and return observable oracle results.",
                "Passing generated executions are not assurance evidence until registered and reviewed.",
                *(
                    [
                        f"Only the first {MAX_SYNTHESIZED_PARAMETERS} parameters were synthesized."
                    ]
                    if truncated
                    else []
                ),
                *(
                    [f"{unresolved} parameter strategy or strategies use a bounded scalar fallback."]
                    if unresolved
                    else []
                ),
            ],
        }
    )
    return design


def _contract_reference(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(value.get("id", "")),
        "path": str(value.get("path", "")),
        "kind": str(value.get("kind", "")),
        "sha256": str(value.get("sha256", "")),
        "operations": [
            str(item)
            for item in value.get("operations", [])[:MAX_OPERATIONS_PER_CONTRACT]
            if item
        ],
        "data_types": [str(item) for item in value.get("data_types", [])[:100] if item],
    }


def _contract_match_score(
    contract: dict[str, Any], obligation: dict[str, Any], component: dict[str, Any]
) -> int:
    searchable = " ".join(
        [
            str(obligation.get("component", "")),
            str(obligation.get("source", {}).get("path", "")),
            json.dumps(component.get("interface_endpoints", []), sort_keys=True),
            " ".join(str(value) for value in component.get("interface_ids", [])),
        ]
    ).casefold()
    score = 0
    path = str(contract.get("path", "")).casefold()
    if path and path in searchable:
        score += 10
    component_name = str(obligation.get("component", "")).casefold()
    for operation in contract.get("operations", []):
        operation_text = str(operation).casefold()
        if component_name and component_name in operation_text:
            score += 5
        for token in re.findall(r"/[a-z0-9_{}.-]+", operation_text):
            if token in searchable:
                score += 3
    return score


def _contract_cases(
    design_id: str, contracts: list[dict[str, Any]], binding_status: str
) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for contract in contracts:
        operations = contract.get("operations", []) or [""]
        for operation in operations:
            for kind, expectation in (
                (
                    "conforming_exchange",
                    "A conforming producer/consumer exchange satisfies the reviewed contract.",
                ),
                (
                    "missing_required_input",
                    "Missing required input is rejected through the declared error contract.",
                ),
                (
                    "malformed_input",
                    "Malformed input is rejected without an unsafe side effect.",
                ),
                (
                    "incompatible_response",
                    "An incompatible producer response is detected before consumer misuse.",
                ),
                (
                    "declared_error_exchange",
                    "Declared error behavior preserves the reviewed status and payload contract.",
                ),
            ):
                cases.append(
                    {
                        "id": stable_id(
                            "CONTRACT-CASE",
                            design_id,
                            str(contract.get("sha256", "")),
                            str(operation),
                            kind,
                        ),
                        "kind": kind,
                        "contract_id": str(contract.get("id", "")),
                        "contract_sha256": str(contract.get("sha256", "")),
                        "operation": str(operation),
                        "expected_behavior": expectation,
                        "binding_status": binding_status,
                    }
                )
                if len(cases) >= MAX_CONTRACT_CASES_PER_DESIGN:
                    return cases
    if not cases:
        cases.append(
            {
                "id": stable_id("CONTRACT-CASE", design_id, "unresolved"),
                "kind": "establish_contract_binding",
                "contract_id": "",
                "contract_sha256": "",
                "operation": "",
                "expected_behavior": (
                    "A named reviewer binds this obligation to an exact producer/consumer "
                    "contract before an exchange is exercised."
                ),
                "binding_status": "unresolved",
            }
        )
    return cases


def _contract_design(
    obligation: dict[str, Any],
    component: dict[str, Any],
    contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    design = _common_design(obligation, prefix="CONTRACT-DESIGN")
    ranked = sorted(
        (
            (_contract_match_score(value, obligation, component), value)
            for value in contracts
            if isinstance(value, dict)
        ),
        key=lambda value: (-value[0], str(value[1].get("path", ""))),
    )
    positive = [value for score, value in ranked if score > 0]
    if positive:
        chosen = positive[:MAX_CONTRACTS_PER_DESIGN]
        binding_status = "static_candidate_match_requires_review"
    elif len(ranked) == 1:
        chosen = [ranked[0][1]]
        binding_status = "single_inventory_candidate_requires_review"
    else:
        chosen = []
        binding_status = "unresolved"
    references = [_contract_reference(value) for value in chosen]
    cases = _contract_cases(str(design["id"]), references, binding_status)
    design.update(
        {
            "method": "contract_test",
            "adapter_function": "exercise_contract",
            "binding_status": binding_status,
            "contracts": references,
            "cases": cases,
            "limitations": [
                "Static contract association is a candidate mapping until a named project reviewer confirms it.",
                "Operation inventory does not infer required payload values, authentication, transport, or safe execution.",
                "A project adapter must exercise both producer and consumer boundaries and report every oracle.",
                "Passing generated executions are not assurance evidence until registered and reviewed.",
                *(
                    ["No exact contract association was inferred; the generated binding case fails visibly."]
                    if binding_status == "unresolved"
                    else []
                ),
            ],
        }
    )
    return design


def synthesize_assurance_test_designs(
    analysis: dict[str, Any], obligations: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    """Return deterministic property/contract designs for selected obligations."""

    components = {
        str(value.get("id", "")): value
        for value in analysis.get("components", [])
        if isinstance(value, dict) and value.get("id")
    }
    contract_values = analysis.get("context", {}).get("contracts", [])
    contracts = (
        [value for value in contract_values if isinstance(value, dict)]
        if isinstance(contract_values, list)
        else []
    )
    properties: list[dict[str, Any]] = []
    contract_designs: list[dict[str, Any]] = []
    for obligation in obligations:
        component = components.get(str(obligation.get("component_id", "")), {})
        method = str(obligation.get("verification_method", ""))
        if method == "property_test":
            properties.append(_property_design(obligation, component))
        elif method == "contract_test":
            contract_designs.append(_contract_design(obligation, component, contracts))
    properties.sort(key=lambda value: (value["obligation_id"], value["id"]))
    contract_designs.sort(key=lambda value: (value["obligation_id"], value["id"]))
    result = {
        "format": ASSURANCE_TEST_DESIGNS_FORMAT,
        "property_tests": properties,
        "contract_tests": contract_designs,
        "summary": {
            "property_designs": len(properties),
            "property_parameters": sum(len(value["parameters"]) for value in properties),
            "contract_designs": len(contract_designs),
            "contract_cases": sum(len(value["cases"]) for value in contract_designs),
            "unresolved_contract_bindings": sum(
                value["binding_status"] == "unresolved" for value in contract_designs
            ),
        },
        "notice": (
            "Generated designs are executable pytest starting points, not implemented project "
            "tests or evidence. Project adapters must safely exercise the exact subject and "
            "truthfully report stimulus, oracle, and acceptance-criterion observations."
        ),
        "authority": "deterministic_test_design_not_project_oracle_or_assurance_evidence",
    }
    result["content_sha256"] = stable_designs_sha256(result)
    return result


def stable_designs_sha256(value: dict[str, Any]) -> str:
    """Hash the complete design projection excluding its self-declared digest."""

    import hashlib

    canonical = dict(value)
    canonical.pop("content_sha256", None)
    return hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _digest(value: Any, *, allow_empty: bool = False) -> bool:
    return bool(
        isinstance(value, str)
        and ((allow_empty and value == "") or re.fullmatch(r"[0-9a-f]{64}", value))
    )


def _strategy_spec_valid(value: Any, *, depth: int = 0) -> bool:
    if not isinstance(value, dict) or depth > 8:
        return False
    kind = value.get("kind")
    basis = value.get("basis")
    if basis is not None and (not isinstance(basis, str) or not basis):
        return False
    if kind in {"none", "booleans", "bounded_scalar"}:
        return set(value) <= {"kind", "basis"}
    if kind in {"integers", "floats"}:
        minimum = value.get("minimum")
        maximum = value.get("maximum")
        numeric = (int, float)
        if (
            not isinstance(minimum, numeric)
            or isinstance(minimum, bool)
            or not isinstance(maximum, numeric)
            or isinstance(maximum, bool)
            or minimum > maximum
        ):
            return False
        expected = {"kind", "minimum", "maximum", "basis"}
        if kind == "floats":
            expected |= {"allow_nan", "allow_infinity"}
            if type(value.get("allow_nan")) is not bool or type(
                value.get("allow_infinity")
            ) is not bool:
                return False
        return set(value) == expected
    if kind in {"text", "binary"}:
        minimum_size = value.get("minimum_size", 0)
        maximum_size = value.get("maximum_size")
        return bool(
            set(value) <= {"kind", "minimum_size", "maximum_size", "basis"}
            and type(minimum_size) is int
            and type(maximum_size) is int
            and 0 <= minimum_size <= maximum_size <= 10_000
        )
    if kind == "lists":
        minimum_size = value.get("minimum_size", 0)
        maximum_size = value.get("maximum_size")
        return bool(
            set(value)
            == {"kind", "minimum_size", "maximum_size", "item_strategy", "basis"}
            and type(minimum_size) is int
            and type(maximum_size) is int
            and 0 <= minimum_size <= maximum_size <= 1_000
            and _strategy_spec_valid(value.get("item_strategy"), depth=depth + 1)
        )
    if kind == "dictionaries":
        minimum_size = value.get("minimum_size", 0)
        maximum_size = value.get("maximum_size")
        return bool(
            set(value)
            == {
                "kind",
                "minimum_size",
                "maximum_size",
                "key_strategy",
                "value_strategy",
                "basis",
            }
            and type(minimum_size) is int
            and type(maximum_size) is int
            and 0 <= minimum_size <= maximum_size <= 1_000
            and _strategy_spec_valid(value.get("key_strategy"), depth=depth + 1)
            and _strategy_spec_valid(value.get("value_strategy"), depth=depth + 1)
        )
    if kind == "one_of":
        strategies = value.get("strategies")
        return bool(
            set(value) == {"kind", "strategies", "basis"}
            and isinstance(strategies, list)
            and 1 <= len(strategies) <= 10
            and all(
                _strategy_spec_valid(item, depth=depth + 1) for item in strategies
            )
        )
    return False


def _observation_contract_valid(value: Any) -> bool:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        return False
    ids: list[str] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "text"}
            or not isinstance(item.get("id"), str)
            or not item["id"]
            or not isinstance(item.get("text"), str)
            or not item["text"]
        ):
            return False
        ids.append(item["id"])
    return len(ids) == len(set(ids))


def _common_design_valid(value: dict[str, Any], method: str) -> bool:
    return bool(
        value.get("method") == method
        and value.get("adapter_function")
        == ("exercise_property" if method == "property_test" else "exercise_contract")
        and value.get("adapter_status") == "project_implementation_required"
        and all(
            isinstance(value.get(key), str) and bool(value.get(key))
            for key in (
                "id",
                "obligation_id",
                "finding_id",
                "component_id",
                "component",
                "failure_condition",
            )
        )
        and _digest(value.get("contract_sha256"))
        and isinstance(value.get("source"), dict)
        and _observation_contract_valid(value.get("oracles"))
        and _observation_contract_valid(value.get("acceptance_criteria"))
        and isinstance(value.get("limitations"), list)
        and bool(value["limitations"])
        and len(value["limitations"]) <= 20
        and all(isinstance(item, str) and bool(item) for item in value["limitations"])
    )


def test_designs_are_valid(value: Any, obligations: Iterable[dict[str, Any]]) -> bool:
    """Perform the closed semantic checks needed by scaffold verification."""

    if not isinstance(value, dict) or value.get("format") != ASSURANCE_TEST_DESIGNS_FORMAT:
        return False
    if value.get("content_sha256") != stable_designs_sha256(value):
        return False
    properties = value.get("property_tests")
    contracts = value.get("contract_tests")
    summary = value.get("summary")
    if not isinstance(properties, list) or not isinstance(contracts, list) or not isinstance(summary, dict):
        return False
    obligation_values = list(obligations)
    expected = {
        "property_test": {
            str(item.get("id", ""))
            for item in obligation_values
            if item.get("verification_method") == "property_test"
        },
        "contract_test": {
            str(item.get("id", ""))
            for item in obligation_values
            if item.get("verification_method") == "contract_test"
        },
    }
    actual_property = {
        str(item.get("obligation_id", "")) for item in properties if isinstance(item, dict)
    }
    actual_contract = {
        str(item.get("obligation_id", "")) for item in contracts if isinstance(item, dict)
    }
    if actual_property != expected["property_test"] or actual_contract != expected["contract_test"]:
        return False
    if len(actual_property) != len(properties) or len(actual_contract) != len(contracts):
        return False
    design_ids: list[str] = []
    for item in properties:
        if not isinstance(item, dict) or not _common_design_valid(item, "property_test"):
            return False
        parameters = item.get("parameters")
        scenarios = item.get("scenarios")
        generation = item.get("generation")
        if (
            not isinstance(parameters, list)
            or len(parameters) > MAX_SYNTHESIZED_PARAMETERS
            or not isinstance(scenarios, list)
            or not 1 <= len(scenarios) <= 20
            or not all(isinstance(scenario, str) and scenario for scenario in scenarios)
            or len(scenarios) != len(set(scenarios))
            or generation
            != {
                "engine": "hypothesis",
                "max_examples": 40,
                "derandomize": True,
                "deadline": None,
            }
            or item.get("strategy_strength")
            not in {"annotation_and_name_based", "bounded_heuristic"}
        ):
            return False
        parameter_names: list[str] = []
        for parameter in parameters:
            if (
                not isinstance(parameter, dict)
                or set(parameter) != {"name", "annotation", "strategy"}
                or not isinstance(parameter.get("name"), str)
                or not parameter["name"]
                or not isinstance(parameter.get("annotation"), str)
                or not _strategy_spec_valid(parameter.get("strategy"))
            ):
                return False
            parameter_names.append(parameter["name"])
        if len(parameter_names) != len(set(parameter_names)):
            return False
        design_ids.append(str(item["id"]))
    valid_binding_statuses = {
        "static_candidate_match_requires_review",
        "single_inventory_candidate_requires_review",
        "unresolved",
    }
    valid_case_kinds = {
        "conforming_exchange",
        "missing_required_input",
        "malformed_input",
        "incompatible_response",
        "declared_error_exchange",
        "establish_contract_binding",
    }
    for item in contracts:
        if not isinstance(item, dict) or not _common_design_valid(item, "contract_test"):
            return False
        binding_status = item.get("binding_status")
        references = item.get("contracts")
        cases = item.get("cases")
        if (
            binding_status not in valid_binding_statuses
            or not isinstance(references, list)
            or len(references) > MAX_CONTRACTS_PER_DESIGN
            or not isinstance(cases, list)
            or not 1 <= len(cases) <= MAX_CONTRACT_CASES_PER_DESIGN
        ):
            return False
        reference_digests: set[str] = set()
        for reference in references:
            if (
                not isinstance(reference, dict)
                or not reference.get("id")
                or not _digest(reference.get("sha256"))
                or not isinstance(reference.get("operations"), list)
                or len(reference["operations"]) > MAX_OPERATIONS_PER_CONTRACT
                or not isinstance(reference.get("data_types"), list)
                or len(reference["data_types"]) > 100
            ):
                return False
            reference_digests.add(str(reference["sha256"]))
        case_ids: list[str] = []
        for case in cases:
            if (
                not isinstance(case, dict)
                or case.get("kind") not in valid_case_kinds
                or case.get("binding_status") != binding_status
                or not case.get("id")
                or not case.get("expected_behavior")
                or not _digest(case.get("contract_sha256"), allow_empty=True)
            ):
                return False
            if case["kind"] == "establish_contract_binding":
                if case.get("contract_id") or case.get("contract_sha256") or case.get("operation"):
                    return False
            elif case.get("contract_sha256") not in reference_digests:
                return False
            case_ids.append(str(case["id"]))
        if len(case_ids) != len(set(case_ids)):
            return False
        if binding_status == "unresolved":
            if references or {case["kind"] for case in cases} != {"establish_contract_binding"}:
                return False
        elif not references or any(
            case["kind"] == "establish_contract_binding" for case in cases
        ):
            return False
        design_ids.append(str(item["id"]))
    if len(design_ids) != len(set(design_ids)):
        return False
    expected_summary = {
        "property_designs": len(properties),
        "property_parameters": sum(len(item["parameters"]) for item in properties),
        "contract_designs": len(contracts),
        "contract_cases": sum(len(item["cases"]) for item in contracts),
        "unresolved_contract_bindings": sum(
            item["binding_status"] == "unresolved" for item in contracts
        ),
    }
    return summary == expected_summary


_GENERATED_RUNTIME_SOURCE = '''"""Generated bounded runtime for PySFMEA assurance tests.

This module validates the scaffold manifest and the adapter observation contract.  It does
not execute repository code by itself and does not turn a passing test into assurance evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_DEPTH = 100
MAX_MANIFEST_NODES = 500_000
SCAFFOLD_FORMAT = "__SCAFFOLD_FORMAT__"
TEST_DESIGNS_FORMAT = "pysfmea-assurance-test-designs-1"


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite number")
    return parsed


def _validate_structure(payload: object) -> None:
    nodes = 0
    stack = [(payload, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_MANIFEST_DEPTH or nodes > MAX_MANIFEST_NODES:
            raise RuntimeError(
                "assurance-manifest.json exceeds its bounded JSON structure limits; "
                "regenerate the scaffold from the governed analysis"
            )
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _canonical_sha256(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _validate_designs(payload: dict) -> None:
    designs = payload.get("test_designs")
    if not isinstance(designs, dict) or designs.get("format") != TEST_DESIGNS_FORMAT:
        raise RuntimeError(
            "assurance-manifest.json has no supported synthesized test-design projection"
        )
    canonical = dict(designs)
    supplied = canonical.pop("content_sha256", "")
    if not supplied or supplied != _canonical_sha256(canonical):
        raise RuntimeError("synthesized test designs failed their SHA-256 integrity check")
    obligations = payload["obligations"]
    expected_property = {
        item["id"] for item in obligations if item.get("verification_method") == "property_test"
    }
    expected_contract = {
        item["id"] for item in obligations if item.get("verification_method") == "contract_test"
    }
    properties = designs.get("property_tests")
    contracts = designs.get("contract_tests")
    if not isinstance(properties, list) or not isinstance(contracts, list):
        raise RuntimeError("synthesized test-design collections are malformed")
    actual_property = {
        item.get("obligation_id") for item in properties if isinstance(item, dict)
    }
    actual_contract = {
        item.get("obligation_id") for item in contracts if isinstance(item, dict)
    }
    if (
        actual_property != expected_property
        or actual_contract != expected_contract
        or len(actual_property) != len(properties)
        or len(actual_contract) != len(contracts)
    ):
        raise RuntimeError("synthesized test designs do not account for selected obligations")


def load_manifest() -> dict:
    path = Path(__file__).with_name("assurance-manifest.json")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(
            "assurance-manifest.json must be a regular non-symbolic-link file; "
            "regenerate the scaffold from the governed analysis"
        )
    try:
        with path.open("rb") as source_file:
            raw = source_file.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(
            "assurance-manifest.json could not be read safely; regenerate the scaffold "
            "from the governed analysis"
        ) from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RuntimeError(
            f"assurance-manifest.json exceeds the {MAX_MANIFEST_BYTES}-byte collection "
            "limit; inspect or regenerate the scaffold"
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RuntimeError(
            "assurance-manifest.json must be valid bounded UTF-8 JSON with "
            "unambiguous objects and finite numbers; regenerate the scaffold from the "
            "governed analysis"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            "assurance-manifest.json root must be an object; regenerate the scaffold "
            "from the governed analysis"
        )
    _validate_structure(payload)
    if payload.get("format") != SCAFFOLD_FORMAT:
        raise RuntimeError(
            "assurance-manifest.json has an unsupported scaffold format; regenerate it "
            "from the governed analysis"
        )
    canonical = dict(payload)
    expected = canonical.pop("manifest_sha256", "")
    if not expected or _canonical_sha256(canonical) != expected:
        raise RuntimeError(
            "assurance-manifest.json failed its SHA-256 integrity check; regenerate "
            "the scaffold from the governed analysis"
        )
    obligations = payload.get("obligations")
    if not isinstance(obligations, list) or not obligations or not all(
        isinstance(value, dict) and value.get("id") for value in obligations
    ):
        raise RuntimeError(
            "assurance-manifest.json has no valid obligation list; regenerate the "
            "scaffold from the governed analysis"
        )
    _validate_designs(payload)
    return payload


def assert_observation(design: dict, observation: object) -> None:
    """Require explicit stimulus, oracle, criterion, and evidence accounting."""

    assert isinstance(observation, dict), "project adapter must return a dictionary observation"
    assert observation.get("obligation_id") == design["obligation_id"], (
        "project adapter observation must identify the exact obligation"
    )
    assert observation.get("stimulus_observed") is True, (
        "project adapter did not prove that the intended failure stimulus was exercised"
    )
    evidence = observation.get("evidence")
    assert isinstance(evidence, list) and evidence and all(
        isinstance(item, str) and item.strip() for item in evidence
    ), "project adapter must return non-empty observation evidence references"
    oracle_results = observation.get("oracles")
    assert isinstance(oracle_results, dict), "project adapter must return oracle results"
    missing_oracles = [
        item["id"] for item in design["oracles"] if item["id"] not in oracle_results
    ]
    failed_oracles = [
        item["id"] for item in design["oracles"] if oracle_results.get(item["id"]) is not True
    ]
    assert not missing_oracles, f"project adapter omitted oracle results: {missing_oracles}"
    assert not failed_oracles, f"assurance oracles were not satisfied: {failed_oracles}"
    criterion_results = observation.get("acceptance_criteria")
    assert isinstance(criterion_results, dict), (
        "project adapter must return acceptance-criterion results"
    )
    missing_criteria = [
        item["id"]
        for item in design["acceptance_criteria"]
        if item["id"] not in criterion_results
    ]
    failed_criteria = [
        item["id"]
        for item in design["acceptance_criteria"]
        if criterion_results.get(item["id"]) is not True
    ]
    assert not missing_criteria, (
        f"project adapter omitted acceptance-criterion results: {missing_criteria}"
    )
    assert not failed_criteria, (
        f"assurance acceptance criteria were not satisfied: {failed_criteria}"
    )
'''


_GENERATED_ADAPTER_SOURCE = '''"""Project-owned adapters for generated PySFMEA assurance tests.

Implement these functions to invoke the exact analyzed subject inside an approved sandbox.
Never return fabricated True values merely to make a scaffold pass.  Each result must identify
the obligation, prove stimulus activation, assess every oracle and acceptance criterion, and
retain non-empty evidence references.  A passing result is still unreviewed execution output.
"""

from __future__ import annotations


def exercise_property(design: dict, case: dict) -> dict:
    """Exercise one generated property case and return a structured observation."""

    raise NotImplementedError(
        f"Implement project property adapter for {design['obligation_id']} and case {case!r}"
    )


def exercise_contract(design: dict, case: dict) -> dict:
    """Exercise one producer/consumer contract case and return a structured observation."""

    raise NotImplementedError(
        f"Implement project contract adapter for {design['obligation_id']} and case {case!r}"
    )
'''


_GENERATED_GENERIC_TEST_SOURCE = '''"""Generated fail-visible placeholders for unsynthesized assurance methods."""

from __future__ import annotations

import pytest

from sfmea_assurance_runtime import load_manifest

MANIFEST = load_manifest()
SYNTHESIZED_METHODS = {"property_test", "contract_test"}
UNSYNTHESIZED = [
    value
    for value in MANIFEST["obligations"]
    if value.get("verification_method") not in SYNTHESIZED_METHODS
]


def test_sfmea_scaffold_accounts_for_every_selected_obligation() -> None:
    designs = MANIFEST["test_designs"]
    synthesized = {
        value["obligation_id"]
        for value in designs["property_tests"] + designs["contract_tests"]
    }
    generic = {value["id"] for value in UNSYNTHESIZED}
    selected = {value["id"] for value in MANIFEST["obligations"]}
    assert synthesized.isdisjoint(generic)
    assert synthesized | generic == selected


if UNSYNTHESIZED:

    @pytest.mark.parametrize(
        "obligation",
        UNSYNTHESIZED,
        ids=lambda value: value["id"],
    )
    def test_sfmea_assurance_obligation(obligation: dict) -> None:
        pytest.fail(
            f"{obligation['id']} is not implemented: "
            f"{obligation['verification_method']} for {obligation['failure_condition']} "
            f"(planned test: {obligation['automation']['proposed_test_path']})"
        )
'''


_GENERATED_PROPERTY_TEST_SOURCE = '''"""Generated Hypothesis designs for property-test obligations."""

from __future__ import annotations

import pytest

from sfmea_assurance_adapters import exercise_property
from sfmea_assurance_runtime import assert_observation, load_manifest

MANIFEST = load_manifest()
PROPERTY_DESIGNS = MANIFEST["test_designs"]["property_tests"]


if PROPERTY_DESIGNS:
    from hypothesis import given, settings, strategies as st

    def _strategy(spec: dict, *, depth: int = 0):
        if depth > 8:
            raise RuntimeError("generated property strategy exceeds the 8-level runtime limit")
        kind = spec.get("kind")
        if kind == "none":
            return st.none()
        if kind == "booleans":
            return st.booleans()
        if kind == "integers":
            return st.integers(
                min_value=int(spec["minimum"]), max_value=int(spec["maximum"])
            )
        if kind == "floats":
            return st.floats(
                min_value=float(spec["minimum"]),
                max_value=float(spec["maximum"]),
                allow_nan=bool(spec.get("allow_nan", False)),
                allow_infinity=bool(spec.get("allow_infinity", False)),
            )
        if kind == "text":
            return st.text(
                min_size=int(spec.get("minimum_size", 0)),
                max_size=int(spec.get("maximum_size", 256)),
            )
        if kind == "binary":
            return st.binary(
                min_size=int(spec.get("minimum_size", 0)),
                max_size=int(spec.get("maximum_size", 256)),
            )
        if kind == "lists":
            return st.lists(
                _strategy(spec["item_strategy"], depth=depth + 1),
                min_size=int(spec.get("minimum_size", 0)),
                max_size=int(spec.get("maximum_size", 20)),
            )
        if kind == "dictionaries":
            return st.dictionaries(
                _strategy(spec["key_strategy"], depth=depth + 1),
                _strategy(spec["value_strategy"], depth=depth + 1),
                min_size=int(spec.get("minimum_size", 0)),
                max_size=int(spec.get("maximum_size", 20)),
            )
        if kind == "one_of":
            choices = spec.get("strategies", [])
            if not choices:
                raise RuntimeError("generated one_of strategy has no choices")
            return st.one_of(*[_strategy(value, depth=depth + 1) for value in choices])
        if kind == "bounded_scalar":
            return st.sampled_from([None, False, True, -1, 0, 1, "", "value"])
        raise RuntimeError(f"unsupported generated property strategy: {kind!r}")


    @pytest.mark.parametrize(
        "design",
        PROPERTY_DESIGNS,
        ids=lambda value: value["id"],
    )
    @settings(max_examples=40, derandomize=True, deadline=None)
    @given(data=st.data())
    def test_sfmea_generated_property(design: dict, data) -> None:
        inputs = {
            value["name"]: data.draw(
                _strategy(value["strategy"]), label=value["name"]
            )
            for value in design["parameters"]
        }
        scenario = data.draw(st.sampled_from(design["scenarios"]), label="scenario")
        case = {"inputs": inputs, "scenario": scenario}
        observation = exercise_property(design, case)
        assert_observation(design, observation)

else:

    def test_sfmea_property_design_inventory_is_explicitly_empty() -> None:
        assert MANIFEST["test_designs"]["summary"]["property_designs"] == 0
'''


_GENERATED_CONTRACT_TEST_SOURCE = '''"""Generated positive and negative producer/consumer contract cases."""

from __future__ import annotations

import pytest

from sfmea_assurance_adapters import exercise_contract
from sfmea_assurance_runtime import assert_observation, load_manifest

MANIFEST = load_manifest()
CONTRACT_DESIGNS = MANIFEST["test_designs"]["contract_tests"]
CONTRACT_CASES = [
    (design, case)
    for design in CONTRACT_DESIGNS
    for case in design["cases"]
]


if CONTRACT_CASES:

    @pytest.mark.parametrize(
        "design,case",
        CONTRACT_CASES,
        ids=[case["id"] for _design, case in CONTRACT_CASES],
    )
    def test_sfmea_generated_contract(design: dict, case: dict) -> None:
        observation = exercise_contract(design, case)
        assert_observation(design, observation)

else:

    def test_sfmea_contract_design_inventory_is_explicitly_empty() -> None:
        assert MANIFEST["test_designs"]["summary"]["contract_designs"] == 0
'''


def render_assurance_scaffold_sources(
    *, scaffold_format: str, queue_id: str, owner: str, purpose: str
) -> dict[str, tuple[str, str]]:
    """Return the closed generated-file set as name -> (role, UTF-8 text)."""

    runtime = _GENERATED_RUNTIME_SOURCE.replace("__SCAFFOLD_FORMAT__", scaffold_format)
    readme = (
        "# PySFMEA executable assurance scaffold\n\n"
        f"Queue: `{queue_id}`  \n"
        f"Owner: {owner or 'not assigned'}  \n"
        f"Purpose: {purpose or 'not recorded'}\n\n"
        "## Generated starting points\n\n"
        "- `test_sfmea_generated_properties.py` uses bounded Hypothesis strategies derived "
        "from parameter annotations and names.\n"
        "- `test_sfmea_generated_contracts.py` emits positive, malformed, missing-input, "
        "incompatible-response, and declared-error cases for associated contract operations.\n"
        "- `sfmea_assurance_adapters.py` is the project-owned integration boundary. It fails "
        "until an engineer safely invokes the exact subject and reports stimulus, oracle, "
        "criterion, and evidence observations.\n"
        "- `test_sfmea_assurance.py` retains fail-visible placeholders for other verification "
        "methods and checks complete obligation accounting.\n\n"
        "Do not convert tests to empty, skipped, assertion-free, or fabricated passing cases. "
        "Run repository code only in an approved sandbox. A passing test remains unreviewed "
        "execution output until its source is registered, its execution is captured, and an "
        "independent reviewer accepts evidence sufficiency. The manifest binds the exact "
        "analysis state, selected verification contracts, synthesized designs, and generated "
        "starting-file hashes. Digests detect accidental change; they are not authenticated "
        "approval signatures.\n"
    )
    sources = {
        "README.md": readme,
        "sfmea_assurance_runtime.py": runtime,
        "sfmea_assurance_adapters.py": _GENERATED_ADAPTER_SOURCE,
        "test_sfmea_assurance.py": _GENERATED_GENERIC_TEST_SOURCE,
        "test_sfmea_generated_properties.py": _GENERATED_PROPERTY_TEST_SOURCE,
        "test_sfmea_generated_contracts.py": _GENERATED_CONTRACT_TEST_SOURCE,
    }
    return {
        name: (ASSURANCE_SCAFFOLD_GENERATED_FILE_ROLES[name], source)
        for name, source in sources.items()
    }
