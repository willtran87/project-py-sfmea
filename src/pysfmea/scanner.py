"""AST-based Python repository inventory and SFMEA candidate generation."""

from __future__ import annotations

import ast
import copy
import fnmatch
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import tokenize
import tomllib
from collections import Counter, defaultdict
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import build_adapter_run_ledger
from .assurance import refresh_assurance_register
from .config import normalize_config
from .guidance import (
    DEFAULT_EXCLUDES,
    METHODOLOGY_NOTICE,
    REVIEW_CHECKLIST,
    apply_guidance_applicability,
    apply_project_guidance_mappings,
    citations_for_rule,
    guidance_bundle,
    load_organizational_guidance_pack,
    selected_sources_from_bundle,
)
from .interface_reconciliation import (
    normalize_interface_path,
    reconcile_cross_stack_interfaces,
)
from .json_ingestion import (
    load_bounded_file_snapshot,
    load_bounded_json_document,
    parse_bounded_json_bytes,
)
from .manifest import create_run_manifest
from .model import SCHEMA_VERSION, empty_review, stable_id, utc_now
from .repository_inventory import build_repository_inventory
from .sfta import build_sfta
from .system_context import build_system_context
from .version import __version__

EXTERNAL_PREFIXES = {
    "aiohttp",
    "anthropic",
    "azure",
    "boto3",
    "botocore",
    "grpc",
    "google.cloud",
    "httpx",
    "kafka",
    "langchain",
    "langgraph",
    "mcp",
    "openai",
    "pika",
    "redis",
    "requests",
    "socket",
    "urllib",
    "websockets",
}
PERSISTENCE_PREFIXES = {
    "asyncpg",
    "django.db",
    "motor",
    "pymongo",
    "psycopg",
    "psycopg2",
    "sqlalchemy",
    "sqlite3",
}
SERIALIZATION_PREFIXES = {"csv", "json", "msgpack", "pickle", "tomllib", "xml", "yaml"}
CONCURRENCY_NAMES = {
    "asyncio.create_task",
    "asyncio.gather",
    "asyncio.wait",
    "concurrent.futures",
    "multiprocessing",
    "threading",
}
TIMING_NAMES = {"asyncio.sleep", "sched", "time.sleep", "time.monotonic", "time.time"}
MAX_PYTHON_SOURCE_BYTES = 20_000_000
MAX_PYTHON_SOURCE_FILES = 100_000
MAX_TEST_EVIDENCE_FILES = 10_000
MAX_TEST_EVIDENCE_BYTES = 100_000_000
MAX_DEPENDENCY_MANIFEST_BYTES = 20_000_000
MAX_DEPENDENCY_MANIFEST_FILES = 1_000
MAX_DEPENDENCY_MANIFEST_TOTAL_BYTES = 100_000_000
MAX_CONTRACT_BYTES = 20_000_000
MAX_CONTRACT_FILES = 1_000
MAX_CONTRACT_TOTAL_BYTES = 100_000_000
MAX_CONTRACT_ENTITIES = 500
MAX_CONTRACT_JSON_DEPTH = 100
MAX_CONTRACT_JSON_NODES = 1_000_000
MAX_ROUTE_REGISTRATIONS = 10_000
MAX_INTERPROCEDURAL_FLOW_EDGES = 100_000
MAX_FLOW_ARGUMENTS_PER_CALL = 100
MAX_FLOW_SYMBOLS_PER_EXPRESSION = 100
MAX_ALIAS_OBJECT_FLOW_RECORDS = 100_000
MAX_ALIAS_BINDINGS_PER_COMPONENT = 10_000
MAX_CONCURRENCY_OPERATIONS = 100_000
MAX_CONCURRENCY_RELATIONS = 200_000
MAX_EXCEPTION_RECORDS_PER_COMPONENT = 10_000
MAX_EXCEPTION_RAISE_RECORDS = 100_000
MAX_EXCEPTION_HANDLER_RECORDS = 100_000
MAX_EXCEPTION_PROPAGATION_EDGES = 200_000
MAX_STATE_RECORDS_PER_COMPONENT = 10_000
MAX_STATE_TRANSITIONS = 100_000
MAX_RESILIENCE_SEMANTIC_OPERATIONS = 200_000
MAX_RETRY_PATH_DEPTH = 12
MAX_RETRY_PATH_STATES_PER_ORIGIN = 10_000
MAX_RETRY_AMPLIFICATION = 1_000_000_000
MAX_AUTHORIZATION_FLOW_EDGES = 100_000
MAX_CONTRACT_SEMANTIC_RECORDS = 20_000
MAX_ARCHITECTURE_MODEL_RECORDS = 100_000
PYTHON_FACT_CACHE_FORMAT = "pysfmea-python-fact-cache-2"
CONFIG_NAMES = {"os.environ", "os.getenv", "dotenv", "argparse", "click", "typer"}
FILESYSTEM_NAMES = {
    "open",
    "io.open",
    "pathlib.Path",
    "os.remove",
    "os.rename",
    "shutil",
}
SUBPROCESS_NAMES = {"os.popen", "os.system", "subprocess"}
OBSERVABILITY_PREFIXES = {
    "logging",
    "opentelemetry",
    "prometheus_client",
    "sentry_sdk",
    "structlog",
}
VALIDATION_PREFIXES = {"pydantic", "marshmallow", "cerberus", "jsonschema"}
CALCULATION_PREFIXES = {"decimal", "fractions", "math", "numpy", "scipy", "statistics"}
RUNTIME_ENVIRONMENT_PREFIXES = {"importlib", "platform", "pkg_resources", "sys"}
HARDWARE_INTERFACE_PREFIXES = {
    "RPi.GPIO",
    "can",
    "gpiozero",
    "serial",
    "smbus",
    "smbus2",
    "usb",
}
FILESYSTEM_METHODS = {
    "open",
    "read_bytes",
    "read_text",
    "replace",
    "rename",
    "unlink",
    "write_bytes",
    "write_text",
}


def _matches_any(value: str, prefixes: Iterable[str]) -> bool:
    return any(value == prefix or value.startswith(prefix + ".") for prefix in prefixes)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _resolve_alias_reference(reference: str, aliases: dict[str, str]) -> str:
    if not reference:
        return ""
    head, dot, rest = reference.partition(".")
    mapped = aliases.get(head, head)
    return f"{mapped}.{rest}" if dot else mapped


def _annotation_reference(node: ast.AST | None, aliases: dict[str, str]) -> str:
    """Return one conservative concrete type reference from an annotation."""

    if node is None:
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            parsed = ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return ""
        return _annotation_reference(parsed, aliases)
    if isinstance(node, (ast.Name, ast.Attribute)):
        reference = _resolve_alias_reference(_dotted_name(node), aliases)
        return (
            "" if reference in {"None", "NoneType", "typing.Any", "Any"} else reference
        )
    if isinstance(node, ast.Subscript):
        container = _dotted_name(node.value).rsplit(".", 1)[-1]
        if container in {"Annotated", "ClassVar", "Final", "Optional"}:
            value = node.slice
            if isinstance(value, ast.Tuple) and value.elts:
                value = value.elts[0]
            return _annotation_reference(value, aliases)
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        candidates = {
            value
            for value in (
                _annotation_reference(node.left, aliases),
                _annotation_reference(node.right, aliases),
            )
            if value
        }
        return next(iter(candidates)) if len(candidates) == 1 else ""
    return ""


def _humanize(name: str) -> str:
    value = name.strip("_").replace("_", " ") or name
    return value[:1].upper() + value[1:]


def _literal_text(node: ast.AST) -> str:
    """Return one bounded static string without evaluating repository code."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value[:4_096]
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("{dynamic}")
        return "".join(parts)[:4_096]
    return ""


def _decorator_endpoint(decorator: ast.AST) -> dict[str, Any] | None:
    """Extract a conservative HTTP route declaration from a decorator."""

    if not isinstance(decorator, ast.Call):
        return None
    reference = _dotted_name(decorator.func)
    leaf = reference.casefold().rsplit(".", 1)[-1]
    if leaf not in {"get", "post", "put", "patch", "delete", "route"}:
        return None
    route = _literal_text(decorator.args[0]) if decorator.args else ""
    if not route:
        return None
    methods = [leaf.upper()] if leaf != "route" else []
    if leaf == "route":
        for keyword in decorator.keywords:
            if keyword.arg != "methods" or not isinstance(
                keyword.value, (ast.List, ast.Tuple, ast.Set)
            ):
                continue
            methods.extend(
                value.upper()
                for item in keyword.value.elts
                if (value := _literal_text(item))
            )
    return {
        "kind": "http_route",
        "path": route,
        "methods": sorted(set(methods)) or ["ANY"],
        "declaration": reference,
        "confidence": "static_literal",
    }


@dataclass
class FunctionFacts:
    name: str
    qualname: str
    kind: str
    path: str
    line: int
    end_line: int
    signature: str
    source_fingerprint: str
    content_fingerprint: str
    context_fingerprint: str
    docstring: str
    is_async: bool
    is_private: bool
    decorators: list[str]
    parameters: list[str]
    parameter_contracts: list[dict[str, Any]] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    ordered_calls: list[str] = field(default_factory=list)
    call_sites: list[dict[str, Any]] = field(default_factory=list)
    return_values: list[dict[str, Any]] = field(default_factory=list)
    alias_bindings: list[dict[str, Any]] = field(default_factory=list)
    alias_bindings_omitted: int = 0
    exception_raises: list[dict[str, Any]] = field(default_factory=list)
    exception_handlers: list[dict[str, Any]] = field(default_factory=list)
    exception_records_omitted: int = 0
    state_guards: list[dict[str, Any]] = field(default_factory=list)
    state_transitions: list[dict[str, Any]] = field(default_factory=list)
    state_records_omitted: int = 0
    external_call_candidates: list[dict[str, str]] = field(default_factory=list)
    symbol_types: dict[str, str] = field(default_factory=dict)
    symbol_type_sources: dict[str, str] = field(default_factory=dict)
    frameworks: set[str] = field(default_factory=set)
    entrypoint_types: set[str] = field(default_factory=set)
    interface_endpoints: list[dict[str, Any]] = field(default_factory=list)
    complexity: int = 1
    loops: int = 0
    awaits: int = 0
    broad_handlers: int = 0
    silent_handlers: int = 0
    mutates_state: bool = False
    raises: int = 0
    arithmetic_ops: int = 0
    signals: set[str] = field(default_factory=set)
    detected_controls: list[dict[str, Any]] = field(default_factory=list)


def _circuit_breaker_control(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    scope_qualname: str = "",
    member_qualname: str = "",
) -> dict[str, Any] | None:
    """Extract bounded circuit-breaker semantics without crediting effectiveness.

    ``scope_qualname`` lets methods contribute evidence to a breaker implemented
    across a class without pretending that any one method contains the complete
    control.  A naming hint is never sufficient on its own: the callable must also
    contain state, admission, accounting, timing, reset, or fallback behavior.
    """

    identifiers: set[str] = {node.name.casefold()}
    strings: set[str] = set()
    calls: set[str] = set()
    for value in ast.walk(node):
        if isinstance(value, ast.Name):
            identifiers.add(value.id.casefold())
        elif isinstance(value, ast.Attribute):
            identifiers.add(_dotted_name(value).casefold())
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            text = value.value.strip()
            if text:
                strings.add(text[:500])
        elif isinstance(value, ast.Call):
            name = _dotted_name(value.func).casefold()
            if name:
                calls.add(name)

    searchable = " ".join(
        [
            scope_qualname.casefold(),
            member_qualname.casefold(),
            *identifiers,
            *(value.casefold() for value in strings),
        ]
    )
    explicit = any(
        token in searchable
        for token in (
            "circuit_breaker",
            "circuitbreaker",
            "check_circuit",
            "circuit_open",
            "breaker",
            "half-open",
            "half_open",
        )
    )
    supporting = sum(
        token in searchable
        for token in (
            "cooldown",
            "failure",
            "threshold",
            "record_success",
            "record_failure",
        )
    )
    if not explicit and supporting < 3:
        return None

    comparisons = [value for value in ast.walk(node) if isinstance(value, ast.Compare)]
    comparison_text = [ast.unparse(value)[:500] for value in comparisons]
    assignments = [
        value
        for value in ast.walk(node)
        if isinstance(value, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete))
    ]
    assignment_text = [ast.unparse(value)[:500] for value in assignments]
    structural_text = " ".join(
        value.casefold() for value in [*comparison_text, *assignment_text]
    )
    roles: set[str] = set()
    comparison_structure = " ".join(value.casefold() for value in comparison_text)
    if any(
        token in searchable for token in ("check_circuit", "circuit_open", "is_open")
    ) or (
        "open" in comparison_structure
        and any(
            token in comparison_structure for token in ("state", "circuit", "breaker")
        )
    ):
        roles.add("admission_guard")
    if any(
        token in searchable for token in ("record_failure", "failure_count", "failures")
    ) and any(
        isinstance(value, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        for value in assignments
    ):
        roles.add("failure_recording")
    if (
        any(token in searchable for token in ("record_success", "reset", "clear"))
        and bool(assignments)
    ) or any(call.endswith((".pop", ".clear")) for call in calls):
        roles.add("success_reset")
    has_clock_call = any(
        call.endswith(("time", "monotonic", "perf_counter")) for call in calls
    )
    deletes_state = any(isinstance(value, ast.Delete) for value in ast.walk(node))
    if (
        "cooldown" in searchable
        or "half-open" in searchable
        or "half_open" in searchable
        or (has_clock_call and deletes_state)
    ):
        roles.add("recovery_timer")
    if any(
        token in searchable
        for token in ("fallback", "placeholder", "skipping", "temporarily unavailable")
    ):
        roles.add("degraded_fallback")
    if any(token in structural_text for token in ("circuit", "breaker")) or (
        "state" in structural_text
        and any(
            token in structural_text
            for token in ("closed", "open", "half_open", "half-open")
        )
    ):
        roles.add("breaker_state_management")
    if not roles:
        return None

    state_symbols = sorted(
        {
            identifier
            for identifier in identifiers
            if any(token in identifier for token in ("circuit", "breaker", "open"))
        }
    )[:20]
    failure_counter_symbols = sorted(
        {
            identifier
            for identifier in identifiers
            if "failure" in identifier or "failures" in identifier
        }
    )[:20]
    threshold_expressions: list[str] = []
    cooldown_expressions: list[str] = []
    for value, expression in zip(comparisons, comparison_text, strict=True):
        lowered = expression.casefold()
        if "fail" in lowered and any(
            isinstance(operator, (ast.Gt, ast.GtE, ast.Eq)) for operator in value.ops
        ):
            threshold_expressions.append(expression)
        if any(
            token in lowered for token in ("cooldown", "circuit_open", "breaker")
        ) and any(token in lowered for token in ("time", "monotonic", "clock")):
            cooldown_expressions.append(expression)

    clock_sources = sorted(
        call for call in calls if call.endswith(("time", "monotonic", "perf_counter"))
    )[:10]
    synchronization = sorted(
        {
            ast.unparse(item.context_expr)[:300]
            for value in ast.walk(node)
            if isinstance(value, (ast.With, ast.AsyncWith))
            for item in value.items
            if "lock" in ast.unparse(item.context_expr).casefold()
        }
    )[:10]
    fallback_indicators = sorted(
        {
            value
            for value in [*calls, *strings]
            if any(
                token in value.casefold()
                for token in (
                    "fallback",
                    "placeholder",
                    "skipping",
                    "temporarily unavailable",
                )
            )
        }
    )[:20]
    scope_keys = sorted(
        parameter
        for parameter in (
            argument.arg
            for argument in [
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            ]
        )
        if any(
            token in parameter.casefold()
            for token in ("server", "dependency", "client", "service", "key", "id")
        )
    )[:10]
    state_material = " ".join(
        [
            structural_text,
            *identifiers,
            *(value.casefold() for value in strings),
        ]
    ).replace("_", "-")
    state_tokens = set(re.findall(r"[a-z0-9]+", state_material))
    observed_states = []
    if "closed" in state_tokens:
        observed_states.append("closed")
    if "open" in state_tokens:
        observed_states.append("open")
    if {"half", "open"} <= state_tokens:
        observed_states.append("half_open")
    expected_states = ["closed", "open"]
    if "recovery_timer" in roles or "half_open" in observed_states:
        expected_states.append("half_open")
    detection_basis = []
    if explicit:
        detection_basis.append("breaker naming or state terminology")
    if comparison_text:
        detection_basis.append("state or threshold comparison")
    if assignment_text:
        detection_basis.append("state or counter mutation")
    if calls:
        detection_basis.append("control-related call behavior")
    return {
        "schema_version": "pysfmea-detected-circuit-breaker-3",
        "kind": "circuit_breaker",
        "confidence": "static_candidate",
        "evidence_strength": "strong" if len(roles) >= 2 else "moderate",
        "scope_qualname": scope_qualname or member_qualname or node.name,
        "member_qualname": member_qualname or node.name,
        "detection_basis": detection_basis,
        "roles": sorted(roles),
        "states": observed_states,
        "observed_states": observed_states,
        "expected_states": expected_states,
        "state_symbols": state_symbols,
        "failure_counter_symbols": failure_counter_symbols,
        "threshold_expressions": list(dict.fromkeys(threshold_expressions))[:10],
        "cooldown_expressions": list(dict.fromkeys(cooldown_expressions))[:10],
        "clock_sources": clock_sources,
        "synchronization": synchronization,
        "scope_keys": scope_keys,
        "fallback_indicators": fallback_indicators,
        "notice": "Static candidate only; containment effectiveness requires fault-injection evidence.",
    }


def _flow_expression_kind(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return "name"
    if isinstance(node, ast.Attribute):
        return "attribute"
    if isinstance(node, ast.Subscript):
        return "container_item"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return "container"
    if isinstance(node, ast.Call):
        return "call_result"
    if isinstance(node, ast.Constant):
        return "literal"
    return "expression"


def _flow_symbols(node: ast.AST) -> list[dict[str, str]]:
    """Extract bounded value-bearing names without treating callees as values."""

    symbols: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(reference: str, kind: str) -> None:
        key = (reference, kind)
        if (
            reference
            and key not in seen
            and len(symbols) < MAX_FLOW_SYMBOLS_PER_EXPRESSION
        ):
            seen.add(key)
            symbols.append({"reference": reference, "kind": kind})

    def walk(value: ast.AST) -> None:
        if len(symbols) >= MAX_FLOW_SYMBOLS_PER_EXPRESSION:
            return
        if isinstance(value, ast.Name):
            add(value.id, "name")
            return
        if isinstance(value, ast.Attribute):
            reference = _dotted_name(value)
            if reference:
                add(reference, "attribute")
            else:
                walk(value.value)
            return
        if isinstance(value, ast.Subscript):
            reference = ast.unparse(value)[:500]
            add(reference, "container_item")
            walk(value.value)
            walk(value.slice)
            return
        if isinstance(value, ast.Call):
            for argument in value.args:
                walk(argument)
            for keyword in value.keywords:
                walk(keyword.value)
            return
        for child in ast.iter_child_nodes(value):
            walk(child)

    walk(node)
    return symbols


def _flow_value(node: ast.AST) -> dict[str, Any]:
    symbols = _flow_symbols(node)
    return {
        "expression": ast.unparse(node)[:1_000],
        "kind": _flow_expression_kind(node),
        "symbols": symbols,
        "symbols_truncated": len(symbols) >= MAX_FLOW_SYMBOLS_PER_EXPRESSION,
    }


class _FactVisitor(ast.NodeVisitor):
    def __init__(self, facts: FunctionFacts, aliases: dict[str, str]) -> None:
        self.facts = facts
        self.aliases = aliases
        self.control_context: list[str] = []
        self.await_depth = 0
        self.value_context: list[dict[str, Any]] = []
        self.alias_origins: dict[str, list[str]] = {}

    def _visit_with_context(self, value: ast.AST, context: str) -> None:
        self.control_context.append(context)
        try:
            self.visit(value)
        finally:
            self.control_context.pop()

    def _visit_block(self, values: list[ast.stmt], context: str) -> None:
        for value in values:
            self._visit_with_context(value, context)

    def _visit_as_value(self, value: ast.AST, context: dict[str, Any]) -> None:
        self.value_context.append(context)
        try:
            self.visit(value)
        finally:
            self.value_context.pop()

    def _flow_value(self, node: ast.AST) -> dict[str, Any]:
        value = _flow_value(node)
        for symbol in value["symbols"]:
            reference = str(symbol.get("reference", ""))
            head, dot, rest = reference.partition(".")
            origins = self.alias_origins.get(head, [])
            if origins:
                symbol["alias_origins"] = [
                    f"{origin}.{rest}" if dot else origin for origin in origins
                ][:MAX_FLOW_SYMBOLS_PER_EXPRESSION]
        return value

    def _record_alias_binding(self, target: ast.AST, value: ast.AST, line: int) -> None:
        target_expression = ast.unparse(target)[:500]
        if not target_expression or isinstance(value, ast.Constant):
            return
        source = self._flow_value(value)
        if isinstance(value, ast.Call):
            producer_call, producer_resolution = self._resolve_with_provenance(
                _dotted_name(value.func)
            )
            source["producer_call"] = producer_call
            source["producer_resolution"] = producer_resolution
        target_kind = _flow_expression_kind(target)
        binding_kind = {
            "name": "local_alias_or_value_binding",
            "attribute": "attribute_write",
            "container_item": "container_write",
        }.get(target_kind, "destructuring_or_expression_binding")
        identifier = stable_id(
            "ALIAS-FLOW",
            self.facts.path,
            self.facts.qualname,
            str(line),
            target_expression,
            str(source.get("expression", "")),
        )
        if len(self.facts.alias_bindings) >= MAX_ALIAS_BINDINGS_PER_COMPONENT:
            self.facts.alias_bindings_omitted += 1
            return
        self.facts.alias_bindings.append(
            {
                "id": identifier,
                "line": line,
                "target": target_expression,
                "target_kind": target_kind,
                "binding_kind": binding_kind,
                "source": source,
                "control_context": list(self.control_context),
                "authority": "bounded_order_aware_local_binding_not_heap_or_path_soundness",
            }
        )
        if isinstance(target, ast.Name):
            origins: list[str] = []
            for symbol in source.get("symbols", []):
                if not isinstance(symbol, dict):
                    continue
                expanded = symbol.get("alias_origins", [])
                if isinstance(expanded, list) and expanded:
                    origins.extend(str(origin) for origin in expanded)
                elif symbol.get("reference"):
                    origins.append(str(symbol["reference"]))
            if source.get("producer_call"):
                origins = ["call:" + str(source["producer_call"])]
            self.alias_origins[target.id] = list(dict.fromkeys(origins))[
                :MAX_FLOW_SYMBOLS_PER_EXPRESSION
            ] or [str(source.get("expression", ""))]

    @staticmethod
    def _state_reference(node: ast.AST) -> str:
        reference = _dotted_name(node) or (
            ast.unparse(node)[:500] if isinstance(node, ast.Subscript) else ""
        )
        leaf = re.split(r"[^a-z0-9_]+", reference.casefold())[-1]
        return (
            reference
            if leaf in {"state", "status", "phase", "mode"} or leaf.endswith("_state")
            else ""
        )

    def _record_state_transition(
        self, target: ast.AST, value: ast.AST, line: int
    ) -> None:
        state_variable = self._state_reference(target)
        if not state_variable:
            return
        if len(self.facts.state_transitions) >= MAX_STATE_RECORDS_PER_COMPONENT:
            self.facts.state_records_omitted += 1
            return
        active_guards = [
            value
            for value in self.facts.state_guards
            if any(
                context.startswith(f"if@{value['line']}:")
                or context.startswith(f"while@{value['line']}:")
                for context in self.control_context
            )
        ]
        self.facts.state_transitions.append(
            {
                "id": stable_id(
                    "STATE-TRANSITION",
                    self.facts.path,
                    self.facts.qualname,
                    str(line),
                    state_variable,
                    ast.unparse(value)[:1_000],
                ),
                "line": line,
                "state_variable": state_variable,
                "target_state_expression": ast.unparse(value)[:1_000],
                "guard_ids": [str(guard["id"]) for guard in active_guards],
                "control_context": list(self.control_context),
                "authority": "static_guarded_state_assignment_candidate",
            }
        )

    def _record_state_guard(self, node: ast.AST, line: int, kind: str) -> None:
        references = sorted(
            {
                reference
                for value in ast.walk(node)
                if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript))
                and (reference := self._state_reference(value))
            }
        )
        if not references:
            return
        if len(self.facts.state_guards) >= MAX_STATE_RECORDS_PER_COMPONENT:
            self.facts.state_records_omitted += 1
            return
        expression = ast.unparse(node)[:1_000]
        self.facts.state_guards.append(
            {
                "id": stable_id(
                    "STATE-GUARD",
                    self.facts.path,
                    self.facts.qualname,
                    str(line),
                    kind,
                    expression,
                ),
                "line": line,
                "kind": kind,
                "expression": expression,
                "state_variables": references,
                "authority": "static_state_guard_candidate",
            }
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Do not attribute nested function implementation to its parent.
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        raw = _dotted_name(node.func)
        resolved, resolution = self._resolve_with_provenance(raw)
        # Python evaluates the callable expression and arguments before invoking the
        # outer call. Recording after child traversal preserves that lexical order for
        # nested calls without claiming runtime path feasibility.
        result_context = (
            copy.deepcopy(self.value_context[-1])
            if self.value_context
            else {"kind": "discarded"}
        )
        self.visit(node.func)
        for index, argument in enumerate(node.args):
            self._visit_as_value(
                argument,
                {
                    "kind": "call_argument",
                    "call_reference": resolved or raw,
                    "position": index,
                },
            )
        for keyword in node.keywords:
            self._visit_as_value(
                keyword.value,
                {
                    "kind": "call_argument",
                    "call_reference": resolved or raw,
                    "keyword": keyword.arg or "**",
                },
            )
        if resolved:
            self.facts.calls.add(resolved)
            self.facts.ordered_calls.append(resolved)
            self.facts.call_sites.append(
                {
                    "raw_reference": raw,
                    "reference": resolved,
                    "resolution": resolution,
                    "line": getattr(node, "lineno", 0),
                    "column": getattr(node, "col_offset", 0),
                    "order": len(self.facts.call_sites),
                    "control_context": list(self.control_context),
                    "awaited": self.await_depth > 0,
                    "arguments": [
                        {
                            "position": index,
                            "keyword": "",
                            "unpacked": isinstance(argument, ast.Starred),
                            **self._flow_value(
                                argument.value
                                if isinstance(argument, ast.Starred)
                                else argument
                            ),
                        }
                        for index, argument in enumerate(
                            node.args[:MAX_FLOW_ARGUMENTS_PER_CALL]
                        )
                    ]
                    + [
                        {
                            "position": -1,
                            "keyword": keyword.arg or "**",
                            "unpacked": keyword.arg is None,
                            **self._flow_value(keyword.value),
                        }
                        for keyword in node.keywords[:MAX_FLOW_ARGUMENTS_PER_CALL]
                    ],
                    "arguments_omitted": max(
                        0, len(node.args) - MAX_FLOW_ARGUMENTS_PER_CALL
                    )
                    + max(0, len(node.keywords) - MAX_FLOW_ARGUMENTS_PER_CALL),
                    "result_context": result_context,
                }
            )
            self._classify_call(resolved)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        resolved = self._resolve(_dotted_name(node))
        if resolved:
            self._classify_call(resolved)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name != "*":
                self.aliases[alias.asname or alias.name] = (
                    f"{module}.{alias.name}".strip(".")
                )

    def visit_If(self, node: ast.If) -> None:
        self.facts.complexity += 1
        self.facts.signals.add("control_logic")
        self._record_state_guard(node.test, node.lineno, "if")
        self._visit_with_context(node.test, f"if@{node.lineno}:condition")
        self._visit_block(node.body, f"if@{node.lineno}:body")
        self._visit_block(node.orelse, f"if@{node.lineno}:else")

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.facts.complexity += 1
        self.facts.signals.add("control_logic")
        self._visit_with_context(node.test, f"ifexp@{node.lineno}:condition")
        self._visit_with_context(node.body, f"ifexp@{node.lineno}:body")
        self._visit_with_context(node.orelse, f"ifexp@{node.lineno}:else")

    def visit_For(self, node: ast.For) -> None:
        self.facts.complexity += 1
        self.facts.loops += 1
        self.facts.signals.add("control_logic")
        self.visit(node.target)
        self._visit_with_context(node.iter, f"for@{node.lineno}:iterator")
        self._visit_block(node.body, f"for@{node.lineno}:body")
        self._visit_block(node.orelse, f"for@{node.lineno}:else")

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.facts.complexity += 1
        self.facts.loops += 1
        self.facts.signals.add("concurrency")
        self.visit(node.target)
        self._visit_with_context(node.iter, f"async-for@{node.lineno}:iterator")
        self._visit_block(node.body, f"async-for@{node.lineno}:body")
        self._visit_block(node.orelse, f"async-for@{node.lineno}:else")

    def visit_While(self, node: ast.While) -> None:
        self.facts.complexity += 1
        self.facts.loops += 1
        self.facts.signals.add("control_logic")
        self._record_state_guard(node.test, node.lineno, "while")
        self._visit_with_context(node.test, f"while@{node.lineno}:condition")
        self._visit_block(node.body, f"while@{node.lineno}:body")
        self._visit_block(node.orelse, f"while@{node.lineno}:else")

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.facts.complexity += max(1, len(node.values) - 1)
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.facts.complexity += max(1, len(node.cases) - 1)
        self.facts.signals.add("control_logic")
        self._visit_with_context(node.subject, f"match@{node.lineno}:subject")
        for index, case in enumerate(node.cases):
            self.visit(case.pattern)
            if case.guard is not None:
                self._visit_with_context(
                    case.guard, f"match@{node.lineno}:case-{index + 1}-guard"
                )
            self._visit_block(case.body, f"match@{node.lineno}:case-{index + 1}")

    def visit_BinOp(self, node: ast.BinOp) -> None:
        self.facts.arithmetic_ops += 1
        self.facts.signals.add("calculation")
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
            self.facts.arithmetic_ops += 1
            self.facts.signals.add("calculation")
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try | ast.TryStar) -> None:
        self.facts.complexity += len(node.handlers)
        for index, handler in enumerate(node.handlers):
            handler_types = self._exception_handler_types(handler.type)
            if handler.type is None or _dotted_name(handler.type) in {
                "Exception",
                "BaseException",
            }:
                self.facts.broad_handlers += 1
            if not handler.body or all(
                isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in handler.body
            ):
                self.facts.silent_handlers += 1
            raised_types = [
                self._exception_raise_type(value.exc)
                for value in ast.walk(ast.Module(body=handler.body, type_ignores=[]))
                if isinstance(value, ast.Raise)
            ]
            actions = []
            if any(value is None for value in raised_types):
                actions.append("reraises")
            translated_types = sorted(
                {
                    value
                    for value in raised_types
                    if value and value not in handler_types
                }
            )
            if translated_types:
                actions.append("translates")
            if any(
                isinstance(value, (ast.Return, ast.Break, ast.Continue))
                for value in ast.walk(ast.Module(body=handler.body, type_ignores=[]))
            ):
                actions.append("control_flow_exit")
            if not actions and (
                not handler.body
                or all(
                    isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in handler.body
                )
            ):
                actions.append("suppresses")
            if any(
                isinstance(value, ast.Call)
                and _dotted_name(value.func).rsplit(".", 1)[-1].casefold()
                in {"debug", "info", "warning", "error", "exception", "critical", "log"}
                for value in ast.walk(ast.Module(body=handler.body, type_ignores=[]))
            ):
                actions.append("records_or_logs")
            self._record_exception_handler(
                node,
                handler,
                index,
                handler_types,
                sorted(set(actions)) or ["continues_after_handler"],
                translated_types,
            )
        self._visit_block(node.body, f"try@{node.lineno}:body")
        for index, handler in enumerate(node.handlers):
            if handler.type is not None:
                self.visit(handler.type)
            self._visit_block(
                handler.body,
                f"try@{node.lineno}:handler-{index + 1}",
            )
        self._visit_block(node.orelse, f"try@{node.lineno}:else")
        self._visit_block(node.finalbody, f"try@{node.lineno}:finally")

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.visit_Try(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self._visit_with_context(item.context_expr, f"with@{node.lineno}:context")
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        labels = ", ".join(ast.unparse(item.context_expr)[:200] for item in node.items)
        self._visit_block(node.body, f"with@{node.lineno}:scope:{labels}")

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        for item in node.items:
            self._visit_with_context(
                item.context_expr, f"async-with@{node.lineno}:context"
            )
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        labels = ", ".join(ast.unparse(item.context_expr)[:200] for item in node.items)
        self._visit_block(node.body, f"async-with@{node.lineno}:scope:{labels}")

    def visit_Await(self, node: ast.Await) -> None:
        self.facts.awaits += 1
        self.facts.signals.add("concurrency")
        self.await_depth += 1
        try:
            self.visit(node.value)
        finally:
            self.await_depth -= 1

    def visit_Raise(self, node: ast.Raise) -> None:
        self.facts.raises += 1
        self.facts.signals.add("exception")
        exception_type = self._exception_raise_type(node.exc)
        if len(self.facts.exception_raises) >= MAX_EXCEPTION_RECORDS_PER_COMPONENT:
            self.facts.exception_records_omitted += 1
        else:
            self.facts.exception_raises.append(
                {
                    "id": stable_id(
                        "EXCEPTION-RAISE",
                        self.facts.path,
                        self.facts.qualname,
                        str(node.lineno),
                        exception_type or "bare_reraise",
                    ),
                    "line": node.lineno,
                    "exception_type": exception_type or "active_handler_exception",
                    "expression": ast.unparse(node.exc)[:1_000] if node.exc else "",
                    "bare_reraise": node.exc is None,
                    "cause_expression": ast.unparse(node.cause)[:1_000]
                    if node.cause
                    else "",
                    "control_context": list(self.control_context),
                    "authority": "static_raise_statement_type_candidate",
                }
            )
        if node.exc is not None:
            self._visit_with_context(node.exc, f"raise@{node.lineno}:exception")
        if node.cause is not None:
            self._visit_with_context(node.cause, f"raise@{node.lineno}:cause")

    def _exception_raise_type(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        target = node.func if isinstance(node, ast.Call) else node
        reference = _resolve_alias_reference(_dotted_name(target), self.aliases)
        return reference or "unknown_exception_expression"

    def _exception_handler_types(self, node: ast.AST | None) -> list[str]:
        if node is None:
            return ["BaseException"]
        values = node.elts if isinstance(node, ast.Tuple) else [node]
        return sorted(
            {
                _resolve_alias_reference(_dotted_name(value), self.aliases)
                or "unknown_exception_type"
                for value in values
            }
        )

    def _record_exception_handler(
        self,
        node: ast.Try | ast.TryStar,
        handler: ast.ExceptHandler,
        index: int,
        handler_types: list[str],
        actions: list[str],
        translated_types: list[str],
    ) -> None:
        if len(self.facts.exception_handlers) >= MAX_EXCEPTION_RECORDS_PER_COMPONENT:
            self.facts.exception_records_omitted += 1
            return
        self.facts.exception_handlers.append(
            {
                "id": stable_id(
                    "EXCEPTION-HANDLER",
                    self.facts.path,
                    self.facts.qualname,
                    str(node.lineno),
                    str(index),
                    *handler_types,
                ),
                "try_line": node.lineno,
                "line": handler.lineno,
                "exception_types": handler_types,
                "binding_name": handler.name or "",
                "actions": actions,
                "translated_exception_types": translated_types,
                "authority": "lexically_scoped_static_exception_handler_candidate",
            }
        )

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.facts.return_values.append(
                {
                    "line": node.lineno,
                    "statement_kind": "return",
                    **self._flow_value(node.value),
                }
            )
            self.control_context.append(f"return@{node.lineno}:value")
            try:
                self._visit_as_value(node.value, {"kind": "function_return"})
            finally:
                self.control_context.pop()

    def visit_Yield(self, node: ast.Yield) -> None:
        if node.value is not None:
            self.facts.return_values.append(
                {
                    "line": node.lineno,
                    "statement_kind": "yield",
                    **self._flow_value(node.value),
                }
            )
            self.control_context.append(f"yield@{node.lineno}:value")
            try:
                self._visit_as_value(node.value, {"kind": "function_yield"})
            finally:
                self.control_context.pop()

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.facts.return_values.append(
            {
                "line": node.lineno,
                "statement_kind": "yield_from",
                **self._flow_value(node.value),
            }
        )
        self.control_context.append(f"yield-from@{node.lineno}:value")
        try:
            self._visit_as_value(node.value, {"kind": "function_yield"})
        finally:
            self.control_context.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if any(
            isinstance(target, (ast.Attribute, ast.Subscript))
            for target in node.targets
        ):
            self.facts.mutates_state = True
            self.facts.signals.add("state_mutation")
        for target in node.targets:
            self._record_assigned_type(target, node.value, "constructor_assignment")
            self._record_alias_binding(target, node.value, node.lineno)
            self._record_state_transition(target, node.value, node.lineno)
            self.visit(target)
        targets = [ast.unparse(target)[:500] for target in node.targets]
        sink_kind = (
            "attribute"
            if any(isinstance(target, ast.Attribute) for target in node.targets)
            else "container_item"
            if any(isinstance(target, ast.Subscript) for target in node.targets)
            else "assignment"
        )
        self._visit_as_value(
            node.value,
            {"kind": sink_kind, "targets": targets, "line": node.lineno},
        )

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, (ast.Attribute, ast.Subscript)):
            self.facts.mutates_state = True
            self.facts.signals.add("state_mutation")
        annotated = _annotation_reference(node.annotation, self.aliases)
        target = _dotted_name(node.target)
        if target and annotated:
            self.facts.symbol_types[target] = annotated
            self.facts.symbol_type_sources[target] = "annotation"
        elif node.value is not None:
            self._record_assigned_type(
                node.target, node.value, "annotated_constructor_assignment"
            )
        if node.value is not None:
            self._record_alias_binding(node.target, node.value, node.lineno)
            self._record_state_transition(node.target, node.value, node.lineno)
        self.visit(node.target)
        self.visit(node.annotation)
        if node.value is not None:
            sink_kind = (
                "attribute"
                if isinstance(node.target, ast.Attribute)
                else "container_item"
                if isinstance(node.target, ast.Subscript)
                else "assignment"
            )
            self._visit_as_value(
                node.value,
                {
                    "kind": sink_kind,
                    "targets": [ast.unparse(node.target)[:500]],
                    "line": node.lineno,
                },
            )

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, (ast.Attribute, ast.Subscript, ast.Name)):
            self.facts.mutates_state = True
            self.facts.signals.add("state_mutation")
        self._record_alias_binding(node.target, node.value, node.lineno)
        self._record_state_transition(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def _record_assigned_type(
        self, target: ast.AST, value: ast.AST, source: str
    ) -> None:
        target_name = _dotted_name(target)
        if not target_name or not isinstance(value, ast.Call):
            return
        constructor = _resolve_alias_reference(_dotted_name(value.func), self.aliases)
        constructor_name = constructor.rsplit(".", 1)[-1]
        if not constructor or not constructor_name[:1].isupper():
            return
        self.facts.symbol_types[target_name] = constructor
        self.facts.symbol_type_sources[target_name] = source

    def _resolve_with_provenance(self, raw: str) -> tuple[str, str]:
        if not raw:
            return "", "unresolved"
        head, dot, rest = raw.partition(".")
        alias_origins = self.alias_origins.get(head, [])
        alias_resolution = ""
        if dot and len(alias_origins) == 1:
            origin = alias_origins[0]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", origin):
                alias_resolution = f"{origin}.{rest}"
                raw = alias_resolution
        typed_prefixes = sorted(
            (
                symbol
                for symbol in self.facts.symbol_types
                if raw.startswith(symbol + ".")
            ),
            key=len,
            reverse=True,
        )
        if typed_prefixes:
            symbol = typed_prefixes[0]
            suffix = raw[len(symbol) + 1 :]
            return (
                f"{self.facts.symbol_types[symbol]}.{suffix}",
                "local_alias_to_"
                + self.facts.symbol_type_sources.get(symbol, "type_evidence")
                if alias_resolution
                else self.facts.symbol_type_sources.get(symbol, "type_evidence"),
            )
        resolved = _resolve_alias_reference(raw, self.aliases)
        head = raw.partition(".")[0]
        return resolved, (
            "local_alias"
            if alias_resolution
            else "import_alias"
            if head in self.aliases
            else "lexical_name"
        )

    def _resolve(self, raw: str) -> str:
        return self._resolve_with_provenance(raw)[0]

    def _classify_call(self, name: str) -> None:
        framework_prefixes = {
            "fastapi": "fastapi",
            "flask": "flask",
            "django": "django",
            "celery": "celery",
            "kafka": "kafka",
            "pika": "rabbitmq",
            "sqlalchemy": "sqlalchemy",
            "pydantic": "pydantic",
            "click": "click",
            "typer": "typer",
        }
        for prefix, framework in framework_prefixes.items():
            if name == prefix or name.startswith(prefix + "."):
                self.facts.frameworks.add(framework)
        if _matches_any(name, EXTERNAL_PREFIXES):
            self.facts.signals.add("external_interface")
        if _matches_any(name, PERSISTENCE_PREFIXES):
            self.facts.signals.add("persistence")
        if _matches_any(name, SERIALIZATION_PREFIXES):
            self.facts.signals.add("serialization")
        if _matches_any(name, CONCURRENCY_NAMES):
            self.facts.signals.add("concurrency")
        if _matches_any(name, TIMING_NAMES):
            self.facts.signals.add("timing")
        if _matches_any(name, CONFIG_NAMES):
            self.facts.signals.add("configuration")
        if _matches_any(name, FILESYSTEM_NAMES):
            self.facts.signals.add("filesystem")
        if _matches_any(name, SUBPROCESS_NAMES):
            self.facts.signals.add("subprocess")
        if _matches_any(name, OBSERVABILITY_PREFIXES):
            self.facts.signals.add("observability_control")
        if _matches_any(name, VALIDATION_PREFIXES):
            self.facts.signals.add("validation_control")
        if _matches_any(name, CALCULATION_PREFIXES):
            self.facts.signals.add("calculation")
        if _matches_any(name, RUNTIME_ENVIRONMENT_PREFIXES):
            self.facts.signals.add("runtime_environment")
        if _matches_any(name, HARDWARE_INTERFACE_PREFIXES):
            self.facts.signals.add("hardware_interface")
        if name.rsplit(".", 1)[-1] in FILESYSTEM_METHODS:
            self.facts.signals.add("filesystem")


def _parameter_contracts(arguments: ast.arguments) -> list[dict[str, Any]]:
    positional = [*arguments.posonlyargs, *arguments.args]
    required_boundary = len(positional) - len(arguments.defaults)
    contracts: list[dict[str, Any]] = []
    for index, argument in enumerate(positional):
        if argument.arg in {"self", "cls"}:
            continue
        contracts.append(
            {
                "name": argument.arg,
                "kind": "positional_only"
                if index < len(arguments.posonlyargs)
                else "positional_or_keyword",
                "position": len(
                    [value for value in contracts if value["position"] >= 0]
                ),
                "required": index < required_boundary,
                "annotation": ast.unparse(argument.annotation)[:500]
                if argument.annotation is not None
                else "",
            }
        )
    if arguments.vararg is not None:
        contracts.append(
            {
                "name": arguments.vararg.arg,
                "kind": "var_positional",
                "position": -1,
                "required": False,
                "annotation": ast.unparse(arguments.vararg.annotation)[:500]
                if arguments.vararg.annotation is not None
                else "",
            }
        )
    for index, argument in enumerate(arguments.kwonlyargs):
        contracts.append(
            {
                "name": argument.arg,
                "kind": "keyword_only",
                "position": -1,
                "required": arguments.kw_defaults[index] is None,
                "annotation": ast.unparse(argument.annotation)[:500]
                if argument.annotation is not None
                else "",
            }
        )
    if arguments.kwarg is not None:
        contracts.append(
            {
                "name": arguments.kwarg.arg,
                "kind": "var_keyword",
                "position": -1,
                "required": False,
                "annotation": ast.unparse(arguments.kwarg.annotation)[:500]
                if arguments.kwarg.annotation is not None
                else "",
            }
        )
    return contracts


class _ModuleCollector(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        include_private: bool,
        aliases: dict[str, str],
        context_fingerprint: str,
        include_nested: bool,
    ) -> None:
        self.path = path
        self.include_private = include_private
        self.aliases = aliases
        self.context_fingerprint = context_fingerprint
        self.include_nested = include_nested
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.scope_stack: list[str] = []
        self.function_depth = 0
        self.functions: list[FunctionFacts] = []
        self.route_prefixes: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}".strip(
                "."
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.function_depth and not self.include_nested:
            return
        self._collect_class_model(node)
        self.class_stack.append(node.name)
        self.scope_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope_stack.pop()
        self.class_stack.pop()

    def _collect_class_model(self, node: ast.ClassDef) -> None:
        if node.name.startswith("_") and not self.include_private:
            return
        fields: list[str] = []
        class_context: list[ast.stmt] = []
        for statement in node.body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            class_context.append(statement)
            if isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                fields.append(statement.target.id)
            elif isinstance(statement, ast.Assign):
                fields.extend(
                    target.id
                    for target in statement.targets
                    if isinstance(target, ast.Name)
                )
        decorators = [
            _dotted_name(value.func if isinstance(value, ast.Call) else value)
            for value in node.decorator_list
        ]
        bases = [_dotted_name(value) for value in node.bases]
        model_markers = {
            "BaseModel",
            "TypedDict",
            "Enum",
            "IntEnum",
            "StrEnum",
            "Protocol",
        }
        is_model = bool(
            fields
            or any(value.rsplit(".", 1)[-1] in model_markers for value in bases)
            or any(
                value.rsplit(".", 1)[-1] in {"dataclass", "define", "frozen"}
                for value in decorators
            )
        )
        if not is_model:
            return
        qualname = ".".join([*self.scope_stack, node.name])
        material = {
            "name": "<class-model>",
            "bases": [
                ast.dump(value, include_attributes=False) for value in node.bases
            ],
            "decorators": [
                ast.dump(value, include_attributes=False)
                for value in node.decorator_list
            ],
            "context": [
                ast.dump(value, include_attributes=False) for value in class_context
            ],
        }
        fingerprint = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        class_doc = (
            ast.get_docstring(node, clean=True)
            or f"Define the {node.name} data contract."
        )
        facts = FunctionFacts(
            name=node.name,
            qualname=qualname,
            kind="class_model",
            path=self.path,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            signature=f"class {node.name}({', '.join(value for value in bases if value)})",
            source_fingerprint=fingerprint,
            content_fingerprint=fingerprint,
            context_fingerprint=self.context_fingerprint,
            docstring=class_doc.splitlines()[0][:300],
            is_async=False,
            is_private=node.name.startswith("_"),
            decorators=[value for value in decorators if value],
            parameters=fields,
        )
        facts.signals.add("data_model")
        if (
            any(value.rsplit(".", 1)[-1] in model_markers for value in bases)
            or decorators
        ):
            facts.signals.add("serialization")
        visitor = _FactVisitor(facts, dict(self.aliases))
        for statement in class_context:
            visitor.visit(statement)
        self.functions.append(facts)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._collect_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._collect_function(node, is_async=True)

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            if isinstance(node.value, ast.Lambda):
                self._collect_lambda(target, node.value)
            elif isinstance(node.value, ast.Call) and _dotted_name(
                node.value.func
            ).rsplit(".", 1)[-1] in {"APIRouter", "Blueprint"}:
                for keyword in node.value.keywords:
                    if keyword.arg not in {"prefix", "url_prefix"}:
                        continue
                    prefix = _literal_text(keyword.value)
                    if prefix.startswith("/"):
                        self.route_prefixes[target] = prefix.rstrip("/")
        self.generic_visit(node)

    def _collect_lambda(self, name: str, node: ast.Lambda) -> None:
        if self.function_depth and not self.include_nested:
            return
        if name.startswith("_") and not self.include_private:
            return
        parameters = [
            arg.arg
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        ]
        fingerprint = hashlib.sha256(
            ast.dump(node, include_attributes=False).encode("utf-8")
        ).hexdigest()
        facts = FunctionFacts(
            name=name,
            qualname=".".join([*self.scope_stack, name]),
            kind="lambda",
            path=self.path,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            signature=f"{name}({', '.join(parameters)})",
            source_fingerprint=fingerprint,
            content_fingerprint=fingerprint,
            context_fingerprint=self.context_fingerprint,
            docstring=f"Compute the {name} lambda result.",
            is_async=False,
            is_private=name.startswith("_"),
            decorators=[],
            parameters=parameters,
            parameter_contracts=_parameter_contracts(node.args),
        )
        _FactVisitor(facts, dict(self.aliases)).visit(node.body)
        self.functions.append(facts)

    def _collect_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool
    ) -> None:
        if self.function_depth and not self.include_nested:
            return
        private = node.name.startswith("_") and node.name not in {
            "__init__",
            "__new__",
            "__post_init__",
            "__call__",
            "__enter__",
            "__exit__",
            "__aenter__",
            "__aexit__",
            "__iter__",
            "__next__",
            "__aiter__",
            "__anext__",
            "__getitem__",
            "__setitem__",
        }
        if private and not self.include_private:
            return

        qualname = ".".join([*self.scope_stack, node.name])
        if self.function_stack:
            kind = "nested_function"
        else:
            kind = "method" if self.class_stack else "function"
        params = [
            arg.arg
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if arg.arg not in {"self", "cls"}
        ]
        if node.args.vararg:
            params.append("*" + node.args.vararg.arg)
        if node.args.kwarg:
            params.append("**" + node.args.kwarg.arg)
        signature = self._signature(node)
        decorators = [
            _dotted_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator
            )
            for decorator in node.decorator_list
        ]
        decorators = [decorator for decorator in decorators if decorator]
        doc = ast.get_docstring(node, clean=True) or ""
        normalized_node = copy.deepcopy(node)
        normalized_node.name = "<callable>"
        facts = FunctionFacts(
            name=node.name,
            qualname=qualname,
            kind=kind,
            path=self.path,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            signature=signature,
            source_fingerprint=hashlib.sha256(
                ast.dump(node, include_attributes=False).encode("utf-8")
            ).hexdigest(),
            content_fingerprint=hashlib.sha256(
                ast.dump(normalized_node, include_attributes=False).encode("utf-8")
            ).hexdigest(),
            context_fingerprint=self.context_fingerprint,
            docstring=doc.splitlines()[0][:300] if doc else "",
            is_async=is_async,
            is_private=private,
            decorators=decorators,
            parameters=params,
            parameter_contracts=_parameter_contracts(node.args),
        )
        facts.interface_endpoints.extend(
            endpoint
            for decorator in node.decorator_list
            if (endpoint := _decorator_endpoint(decorator)) is not None
        )
        for endpoint in facts.interface_endpoints:
            receiver = str(endpoint.get("declaration", "")).partition(".")[0]
            prefix = self.route_prefixes.get(receiver, "")
            declared_path = str(endpoint.get("path", ""))
            if prefix and declared_path.startswith("/"):
                endpoint["declared_path"] = declared_path
                endpoint["router_prefix"] = prefix
                endpoint["path"] = prefix + declared_path
                endpoint["confidence"] = "static_literal_composed_router_prefix"
        annotated_arguments = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg:
            annotated_arguments.append(node.args.vararg)
        if node.args.kwarg:
            annotated_arguments.append(node.args.kwarg)
        for argument in annotated_arguments:
            reference = _annotation_reference(argument.annotation, self.aliases)
            if reference:
                facts.symbol_types[argument.arg] = reference
                facts.symbol_type_sources[argument.arg] = "parameter_annotation"
        if is_async:
            facts.signals.add("concurrency")
        if decorators:
            entrypoint_names = {
                "route",
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "command",
                "task",
                "shared_task",
                "consumer",
                "receiver",
            }
            if any(
                item.lower().rsplit(".", 1)[-1] in entrypoint_names
                for item in decorators
            ):
                facts.signals.add("entrypoint")
                facts.signals.add("external_interface")
                imported_frameworks = {
                    prefix
                    for value in self.aliases.values()
                    for prefix in (
                        "fastapi",
                        "flask",
                        "django",
                        "celery",
                        "kafka",
                        "pika",
                        "click",
                        "typer",
                    )
                    if value == prefix or value.startswith(prefix + ".")
                }
                facts.frameworks.update(imported_frameworks)
            for decorator in decorators:
                head, dot, rest = decorator.partition(".")
                resolved_head = self.aliases.get(head, head)
                resolved = f"{resolved_head}.{rest}" if dot else resolved_head
                facts.calls.add(resolved)
                facts.ordered_calls.append(resolved)
                facts.call_sites.append(
                    {
                        "raw_reference": decorator,
                        "reference": resolved,
                        "resolution": "decorator_import_alias",
                        "line": getattr(node, "lineno", 0),
                        "column": getattr(node, "col_offset", 0),
                        "order": len(facts.call_sites),
                        "control_context": ["decorator"],
                        "awaited": False,
                    }
                )
                _FactVisitor(facts, self.aliases)._classify_call(resolved)
                leaf = decorator.lower().rsplit(".", 1)[-1]
                if leaf in {"get", "post", "put", "patch", "delete", "route"}:
                    facts.entrypoint_types.add("http_route")
                elif leaf in {"task", "shared_task"}:
                    facts.entrypoint_types.add("background_task")
                elif leaf in {"consumer", "receiver"}:
                    facts.entrypoint_types.add("event_handler")
                elif leaf == "command":
                    facts.entrypoint_types.add("cli_command")
        visitor = _FactVisitor(facts, self.aliases)
        for statement in node.body:
            visitor.visit(statement)
        member_qualname = qualname
        scope_qualname = (
            ".".join(self.scope_stack) if self.class_stack else member_qualname
        )
        circuit_breaker = _circuit_breaker_control(
            node,
            scope_qualname=scope_qualname,
            member_qualname=member_qualname,
        )
        if circuit_breaker:
            facts.detected_controls.append(circuit_breaker)
            facts.signals.update(
                {"circuit_breaker", "resilience_control", "state_mutation"}
            )
            if circuit_breaker.get("clock_sources") or circuit_breaker.get(
                "cooldown_expressions"
            ):
                facts.signals.add("timing")
            if circuit_breaker.get("synchronization"):
                facts.signals.add("concurrency")
        self.functions.append(facts)
        if self.include_nested:
            self.function_depth += 1
            self.function_stack.append(node.name)
            self.scope_stack.append(node.name)
            for statement in node.body:
                self.visit(statement)
            self.scope_stack.pop()
            self.function_stack.pop()
            self.function_depth -= 1

    @staticmethod
    def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        parts: list[str] = []
        for arg in [*node.args.posonlyargs, *node.args.args]:
            parts.append(_formatted_arg(arg))
        if node.args.vararg:
            parts.append("*" + node.args.vararg.arg)
        elif node.args.kwonlyargs:
            parts.append("*")
        parts.extend(_formatted_arg(arg) for arg in node.args.kwonlyargs)
        if node.args.kwarg:
            parts.append("**" + node.args.kwarg.arg)
        result = f"{node.name}({', '.join(parts)})"
        if node.returns is not None:
            result += " -> " + ast.unparse(node.returns)
        return result


def _formatted_arg(arg: ast.arg) -> str:
    return (
        arg.arg
        if arg.annotation is None
        else f"{arg.arg}: {ast.unparse(arg.annotation)}"
    )


def _module_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = (
                        f"{module}.{alias.name}".strip(".")
                    )
    return aliases


def _symbolic_router_value(
    node: ast.AST,
    aliases: dict[str, str],
    environment: dict[str, Any],
) -> Any:
    """Evaluate a deliberately small, non-executable router-registration subset.

    Values are limited to strings, references, and bounded tuple/list containers.  This
    is enough for conventional ``include_router`` tables and loops while refusing calls,
    comprehensions, operators, and arbitrary repository behavior.
    """

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value[:4_096]
    if isinstance(node, ast.Name):
        if node.id in environment:
            return copy.deepcopy(environment[node.id])
        return {"reference": _resolve_alias_reference(node.id, aliases)}
    if isinstance(node, ast.Attribute):
        reference = _resolve_alias_reference(_dotted_name(node), aliases)
        return {"reference": reference} if reference else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if not isinstance(value, ast.FormattedValue):
                return None
            resolved = _symbolic_router_value(value.value, aliases, environment)
            if not isinstance(resolved, str):
                return None
            parts.append(resolved)
        return "".join(parts)[:4_096]
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > MAX_ROUTE_REGISTRATIONS:
            return None
        values = [
            _symbolic_router_value(value, aliases, environment) for value in node.elts
        ]
        return None if any(value is None for value in values) else values
    return None


def _bind_symbolic_target(
    target: ast.AST, value: Any, environment: dict[str, Any]
) -> bool:
    if isinstance(target, ast.Name):
        environment[target.id] = copy.deepcopy(value)
        return True
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, list):
        if len(target.elts) != len(value):
            return False
        return all(
            _bind_symbolic_target(child, item, environment)
            for child, item in zip(target.elts, value, strict=True)
        )
    return False


def _router_registrations(
    path: str, raw: bytes, warnings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return bounded static FastAPI/Flask router mounts from one source snapshot."""

    if b"include_router" not in raw and b"register_blueprint" not in raw:
        return []
    try:
        tree = ast.parse(_decode_python_source(raw), filename=path)
    except (SyntaxError, ValueError):
        return []
    aliases = _module_aliases(tree)
    environment: dict[str, Any] = {}
    registrations: list[dict[str, Any]] = []

    def collect_call(node: ast.Call, active: dict[str, Any], confidence: str) -> None:
        if len(registrations) >= MAX_ROUTE_REGISTRATIONS:
            return
        raw_reference = _dotted_name(node.func)
        operation = raw_reference.casefold().rsplit(".", 1)[-1]
        if operation not in {"include_router", "register_blueprint"} or not node.args:
            return
        target = _symbolic_router_value(node.args[0], aliases, active)
        if not isinstance(target, dict) or not isinstance(target.get("reference"), str):
            return
        prefix_names = (
            {"prefix"} if operation == "include_router" else {"url_prefix", "prefix"}
        )
        prefix = ""
        for keyword in node.keywords:
            if keyword.arg not in prefix_names:
                continue
            candidate = _symbolic_router_value(keyword.value, aliases, active)
            if isinstance(candidate, str) and candidate.startswith("/"):
                prefix = candidate.rstrip("/")
        registrations.append(
            {
                "target": target["reference"],
                "prefix": prefix,
                "operation": operation,
                "source": {"path": path, "line": getattr(node, "lineno", 0)},
                "confidence": confidence,
            }
        )

    def visit_statements(
        statements: list[ast.stmt], active: dict[str, Any], confidence: str
    ) -> None:
        for statement in statements:
            if len(registrations) >= MAX_ROUTE_REGISTRATIONS:
                return
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                value_node = statement.value
                if value_node is None:
                    continue
                value = _symbolic_router_value(value_node, aliases, active)
                if value is not None:
                    for target in targets:
                        _bind_symbolic_target(target, value, active)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                iterable = _symbolic_router_value(statement.iter, aliases, active)
                if not isinstance(iterable, list):
                    continue
                for item in iterable[:MAX_ROUTE_REGISTRATIONS]:
                    nested = copy.deepcopy(active)
                    if _bind_symbolic_target(statement.target, item, nested):
                        visit_statements(
                            statement.body, nested, "bounded_static_registration_loop"
                        )
                continue
            if isinstance(statement, ast.If):
                visit_statements(statement.body, copy.deepcopy(active), "static_branch")
                visit_statements(
                    statement.orelse, copy.deepcopy(active), "static_branch"
                )
                continue
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Call
            ):
                collect_call(statement.value, active, confidence)

    visit_statements(tree.body, environment, "static_literal_registration")
    if len(registrations) >= MAX_ROUTE_REGISTRATIONS:
        warnings.append(
            {
                "path": path,
                "type": "RouteRegistrationLimit",
                "message": (
                    f"Router registration discovery stopped at {MAX_ROUTE_REGISTRATIONS} "
                    "bounded records."
                ),
            }
        )
    unique = {
        (
            value["target"],
            value["prefix"],
            value["source"]["path"],
            value["source"]["line"],
        ): value
        for value in registrations
    }
    return [unique[key] for key in sorted(unique)]


def _module_reference_candidates(path: str, receiver: str) -> set[str]:
    module_parts = Path(path).with_suffix("").parts
    if module_parts and module_parts[-1] == "__init__":
        module_parts = module_parts[:-1]
    return {
        ".".join((*module_parts[index:], receiver))
        for index in range(len(module_parts))
        if module_parts[index:]
    }


def _compose_registered_route_prefixes(
    facts_list: list[FunctionFacts],
    source_snapshots: dict[Path, bytes],
    root: Path,
    warnings: list[dict[str, Any]],
) -> None:
    """Apply bounded inter-module router mounts to declared route endpoints in place."""

    registrations = [
        registration
        for source_path, raw in source_snapshots.items()
        for registration in _router_registrations(
            source_path.relative_to(root).as_posix(), raw, warnings
        )
    ]
    if not registrations:
        return
    for facts in facts_list:
        expanded: list[dict[str, Any]] = []
        for endpoint in facts.interface_endpoints:
            declaration = str(endpoint.get("declaration", ""))
            receiver = declaration.partition(".")[0]
            candidates = _module_reference_candidates(facts.path, receiver)
            mounts = [
                value
                for value in registrations
                if value["target"] in candidates
                or any(value["target"].endswith("." + item) for item in candidates)
            ]
            if not mounts:
                expanded.append(endpoint)
                continue
            for mount in mounts:
                candidate = copy.deepcopy(endpoint)
                local_path = str(candidate.get("path", ""))
                local_prefix = str(candidate.get("router_prefix", ""))
                mount_prefix = str(mount.get("prefix", ""))
                combined_prefix = (mount_prefix.rstrip("/") + local_prefix).rstrip("/")
                candidate["declared_path"] = candidate.get("declared_path", local_path)
                candidate["mount_prefix"] = mount_prefix
                candidate["router_prefix"] = combined_prefix
                candidate["path"] = mount_prefix.rstrip("/") + local_path
                candidate["registration_source"] = copy.deepcopy(mount["source"])
                candidate["confidence"] = "static_composed_registered_router"
                candidate["registration_confidence"] = mount["confidence"]
                expanded.append(candidate)
        facts.interface_endpoints = expanded


def _module_context_fingerprint(tree: ast.Module) -> str:
    """Fingerprint imports, globals, and class context without function implementations."""

    entries: list[Any] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.ClassDef):
            class_context = [
                statement
                for statement in node.body
                if not isinstance(
                    statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
            ]
            entries.append(
                {
                    "class": node.name,
                    "bases": [
                        ast.dump(value, include_attributes=False)
                        for value in node.bases
                    ],
                    "keywords": [
                        ast.dump(value, include_attributes=False)
                        for value in node.keywords
                    ],
                    "decorators": [
                        ast.dump(value, include_attributes=False)
                        for value in node.decorator_list
                    ],
                    "context": [
                        ast.dump(value, include_attributes=False)
                        for value in class_context
                    ],
                }
            )
        else:
            entries.append(ast.dump(node, include_attributes=False))
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _module_initialization_facts(
    path: str,
    tree: ast.Module,
    aliases: dict[str, str],
    context_fingerprint: str,
) -> FunctionFacts | None:
    executable: list[ast.stmt] = []
    for index, node in enumerate(tree.body):
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Import,
                ast.ImportFrom,
            ),
        ):
            continue
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            try:
                ast.literal_eval(value) if value is not None else None
                continue
            except (ValueError, TypeError):
                pass
        executable.append(node)
    if not executable:
        return None
    synthetic = ast.Module(body=executable, type_ignores=[])
    fingerprint = hashlib.sha256(
        ast.dump(synthetic, include_attributes=False).encode("utf-8")
    ).hexdigest()
    facts = FunctionFacts(
        name="<module>",
        qualname="<module initialization>",
        kind="module_initialization",
        path=path,
        line=min(getattr(node, "lineno", 1) for node in executable),
        end_line=max(
            getattr(node, "end_lineno", getattr(node, "lineno", 1))
            for node in executable
        ),
        signature="module initialization",
        source_fingerprint=fingerprint,
        content_fingerprint=fingerprint,
        context_fingerprint=context_fingerprint,
        docstring="Initialize module startup state and execute top-level behavior.",
        is_async=False,
        is_private=False,
        decorators=[],
        parameters=[],
    )
    # Import-time execution is review-worthy, but it is not automatically an externally
    # reachable entrypoint. Keeping a distinct signal prevents startup declarations from
    # dominating high-priority queues while preserving their complete candidate inventory.
    facts.signals.add("module_initialization")
    visitor = _FactVisitor(facts, dict(aliases))
    for statement in executable:
        visitor.visit(statement)
    return facts


def _matches_pattern(value: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(value, pattern.replace("\\", "/")) for pattern in patterns
    )


def _read_python_source_bytes_bounded(path: Path) -> bytes:
    """Capture one exact identity-stable Python source stream under the byte limit."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Python source must be a regular non-symbolic-link file")
    try:
        snapshot = load_bounded_file_snapshot(
            path,
            label="Python source",
            max_bytes=MAX_PYTHON_SOURCE_BYTES,
        )
    except ValueError as exc:
        message = str(exc)
        if message == f"Python source exceeds the {MAX_PYTHON_SOURCE_BYTES}-byte limit":
            message = (
                "Python source exceeds the "
                f"{MAX_PYTHON_SOURCE_BYTES}-byte analysis limit"
            )
        elif message in {
            "Python source must be an available regular file",
            "Python source must be a regular non-symbolic-link file",
        }:
            message = "Python source must be a regular non-symbolic-link file"
        raise ValueError(message) from exc
    return snapshot.raw


def _read_python_source_bounded(path: Path) -> str:
    """Decode bounded Python source using its PEP 263 encoding declaration."""

    raw = _read_python_source_bytes_bounded(path)
    return _decode_python_source(raw)


def _decode_python_source(raw: bytes) -> str:
    """Decode already-bounded source using its PEP 263 encoding declaration."""

    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding)
    except (LookupError, SyntaxError, UnicodeDecodeError) as exc:
        raise ValueError(
            "Python source has an invalid or unsupported encoding"
        ) from exc


def _python_files(
    root: Path,
    include_tests: bool,
    exclude_patterns: Iterable[str] = (),
    warnings: list[dict[str, Any]] | None = None,
) -> list[Path]:
    result: list[Path] = []
    for path in root.rglob("*.py"):
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError):
            if warnings is not None:
                warnings.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "message": "Python source resolves outside the repository",
                        "type": "OutsideRepository",
                    }
                )
            continue
        relative = path.relative_to(root)
        if path.is_symlink() or not path.is_file():
            if warnings is not None:
                warnings.append(
                    {
                        "path": relative.as_posix(),
                        "message": "Python source must be a regular non-symbolic-link file",
                        "type": "PythonSourceBoundary",
                    }
                )
            continue
        if any(
            part in DEFAULT_EXCLUDES or part.startswith(".")
            for part in relative.parts[:-1]
        ):
            continue
        if _matches_pattern(relative.as_posix(), exclude_patterns):
            continue
        if not include_tests and (
            any(part.lower() in {"test", "tests"} for part in relative.parts[:-1])
            or path.name.startswith("test_")
            or path.name.endswith("_test.py")
        ):
            continue
        if len(result) >= MAX_PYTHON_SOURCE_FILES:
            if warnings is not None:
                warnings.append(
                    {
                        "path": "./",
                        "message": (
                            "Python source discovery reached the "
                            f"{MAX_PYTHON_SOURCE_FILES}-file analysis limit"
                        ),
                        "type": "PythonSourceLimit",
                    }
                )
            break
        result.append(path)
    return sorted(result)


def _pattern_may_match_descendant(directory: str, patterns: Iterable[str]) -> bool:
    prefix = directory.strip("/") + "/"
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/").lstrip("./")
        wildcard_positions = [
            pattern.find(character) for character in "*[?" if character in pattern
        ]
        literal = pattern[: min(wildcard_positions, default=len(pattern))]
        if not literal or literal.startswith(prefix) or prefix.startswith(literal):
            return True
        if _matches_pattern(directory, (pattern,)):
            return True
    return False


def _test_index(
    root: Path,
    warnings: list[dict[str, Any]] | None = None,
    source_snapshots: dict[Path, bytes] | None = None,
    test_evidence_snapshots: dict[Path, bytes] | None = None,
    test_evidence_errors: dict[Path, str] | None = None,
    exclude_patterns: Iterable[str] = (),
    evidence_include_patterns: Iterable[str] = (),
) -> dict[str, str]:
    tests: dict[str, str] = {}
    consumed = 0
    candidates = 0
    test_paths: list[Path] = []
    for directory, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        base = Path(directory)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            candidate = base / dirname
            relative_dir = candidate.relative_to(root).as_posix()
            if (
                candidate.is_symlink()
                or dirname in DEFAULT_EXCLUDES
                or dirname.startswith(".")
            ):
                continue
            configured_excluded = _matches_pattern(
                relative_dir, exclude_patterns
            ) or _matches_pattern(
                relative_dir + "/__pysfmea_region__", exclude_patterns
            )
            if configured_excluded and not _pattern_may_match_descendant(
                relative_dir, evidence_include_patterns
            ):
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        test_paths.extend(
            base / filename
            for filename in sorted(filenames)
            if filename.casefold().endswith(".py")
        )
    for path in test_paths:
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError):
            if warnings is not None:
                warnings.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "message": "Test evidence resolves outside the repository",
                        "type": "TestEvidenceBoundary",
                    }
                )
            if test_evidence_errors is not None:
                test_evidence_errors[path] = (
                    "Test evidence resolves outside the repository"
                )
            continue
        relative = path.relative_to(root)
        is_test = (
            any(part.lower() in {"test", "tests"} for part in relative.parts[:-1])
            or path.name.startswith("test_")
            or path.name.endswith("_test.py")
        )
        configured_excluded = _matches_pattern(relative.as_posix(), exclude_patterns)
        evidence_override = _matches_pattern(
            relative.as_posix(), evidence_include_patterns
        )
        if (
            not is_test
            or any(
                part in DEFAULT_EXCLUDES or part.startswith(".")
                for part in relative.parts[:-1]
            )
            or (configured_excluded and not evidence_override)
        ):
            continue
        if path.is_symlink() or not path.is_file():
            message = "Test evidence must be a regular non-symbolic-link file"
            if warnings is not None:
                warnings.append(
                    {
                        "path": relative.as_posix(),
                        "message": message,
                        "type": "TestEvidenceBoundary",
                    }
                )
            if test_evidence_errors is not None:
                test_evidence_errors[path] = message
            continue
        if candidates >= MAX_TEST_EVIDENCE_FILES:
            if warnings is not None:
                message = (
                    "Test evidence indexing reached the "
                    f"{MAX_TEST_EVIDENCE_FILES}-file limit"
                )
                warnings.append(
                    {
                        "path": relative.as_posix(),
                        "message": message,
                        "type": "TestEvidenceLimit",
                    }
                )
            if test_evidence_errors is not None:
                test_evidence_errors[path] = (
                    "Test evidence indexing reached the "
                    f"{MAX_TEST_EVIDENCE_FILES}-file limit"
                )
            break
        candidates += 1
        try:
            raw = (source_snapshots or {}).get(path)
            if raw is None:
                raw = _read_python_source_bytes_bounded(path)
            if consumed + len(raw) > MAX_TEST_EVIDENCE_BYTES:
                message = (
                    "Test evidence indexing exceeds the "
                    f"{MAX_TEST_EVIDENCE_BYTES}-byte aggregate limit"
                )
                if warnings is not None:
                    warnings.append(
                        {
                            "path": relative.as_posix(),
                            "message": message,
                            "type": "TestEvidenceLimit",
                        }
                    )
                if test_evidence_errors is not None:
                    test_evidence_errors[path] = message
                break
            consumed += len(raw)
            if test_evidence_snapshots is not None:
                test_evidence_snapshots[path] = raw
            tests[relative.as_posix()] = _decode_python_source(raw)
        except ValueError as exc:
            if test_evidence_errors is not None and path not in (
                test_evidence_snapshots or {}
            ):
                test_evidence_errors[path] = str(exc)
            if warnings is not None:
                warnings.append(
                    {
                        "path": relative.as_posix(),
                        "message": str(exc),
                        "type": "TestEvidenceError",
                    }
                )
            continue
    return tests


def _dependency_inventory(
    root: Path,
    warnings: list[dict[str, Any]],
    evidence_snapshots: dict[Path, bytes] | None = None,
) -> list[dict[str, Any]]:
    dependencies: dict[tuple[str, str], dict[str, Any]] = {}
    recorded_files: set[Path] = set()
    attempted_files: set[Path] = set()
    loaded_files: dict[Path, tuple[Path, str, bytes]] = {}
    loaded_resolved_files: dict[Path, tuple[Path, str, bytes]] = {}
    consumed_bytes = 0
    file_limit_reported = False
    aggregate_limit_reported = False

    def warn(path: str, message: str) -> None:
        warnings.append({"path": path, "message": message, "type": "DependencyError"})

    def display_path(path: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return str(path)

    def load_manifest(path: Path) -> tuple[Path, str, bytes] | None:
        nonlocal consumed_bytes, file_limit_reported, aggregate_limit_reported
        candidate = path.expanduser().absolute()
        if candidate in loaded_files:
            return loaded_files[candidate]
        if candidate in attempted_files:
            return None
        if aggregate_limit_reported:
            return None
        if len(attempted_files) >= MAX_DEPENDENCY_MANIFEST_FILES:
            if not file_limit_reported:
                warn(
                    display_path(candidate),
                    "Dependency manifest discovery reached the "
                    f"{MAX_DEPENDENCY_MANIFEST_FILES}-file limit",
                )
                file_limit_reported = True
            return None
        attempted_files.add(candidate)
        if candidate.is_symlink():
            warn(
                display_path(candidate),
                "Dependency manifest must be a regular non-symbolic-link file",
            )
            return None
        try:
            resolved = candidate.resolve()
            relative = resolved.relative_to(root).as_posix()
        except (OSError, ValueError):
            warn(
                display_path(candidate),
                "Dependency manifest resolves outside the repository",
            )
            return None
        if resolved in loaded_resolved_files:
            loaded_files[candidate] = loaded_resolved_files[resolved]
            return loaded_files[candidate]
        if not candidate.is_file():
            warn(
                relative,
                "Dependency manifest must be a regular non-symbolic-link file",
            )
            return None
        try:
            snapshot = load_bounded_file_snapshot(
                candidate,
                label="Dependency manifest",
                max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
            )
        except ValueError as exc:
            message = str(exc)
            if message == (
                "Dependency manifest exceeds the "
                f"{MAX_DEPENDENCY_MANIFEST_BYTES}-byte limit"
            ):
                message = (
                    "Dependency manifest exceeds the "
                    f"{MAX_DEPENDENCY_MANIFEST_BYTES}-byte analysis limit"
                )
            elif message in {
                "Dependency manifest must be an available regular file",
                "Dependency manifest must be a regular non-symbolic-link file",
            }:
                message = "Dependency manifest must be a regular non-symbolic-link file"
            warn(relative, message)
            return None
        raw = snapshot.raw
        if consumed_bytes + len(raw) > MAX_DEPENDENCY_MANIFEST_TOTAL_BYTES:
            warn(
                relative,
                "Dependency manifest ingestion exceeds the "
                f"{MAX_DEPENDENCY_MANIFEST_TOTAL_BYTES}-byte aggregate limit",
            )
            aggregate_limit_reported = True
            return None
        consumed_bytes += len(raw)
        if evidence_snapshots is not None:
            evidence_snapshots[resolved] = raw
        loaded = (resolved, relative, raw)
        loaded_files[candidate] = loaded
        loaded_resolved_files[resolved] = loaded
        return loaded

    def record(specification: str, source: str) -> None:
        value = specification.strip()
        if (
            not value
            or value.startswith("#")
            or value.startswith(("-r", "--requirement"))
        ):
            return
        name_match = re.match(r"[A-Za-z0-9_.-]+", value)
        name = name_match.group(0) if name_match else value
        dependencies[(name.lower(), source)] = {
            "name": name,
            "specification": value,
            "source": source,
        }

    def record_file(path: Path) -> tuple[Path, str, bytes] | None:
        loaded = load_manifest(path)
        if loaded is None:
            return None
        resolved, relative, raw = loaded
        if resolved in recorded_files:
            return loaded
        recorded_files.add(resolved)
        name = f"manifest:{relative}"
        digest = hashlib.sha256(raw).hexdigest()
        dependencies[(name, relative)] = {
            "name": name,
            "specification": f"sha256:{digest}",
            "source": relative,
            "evidence_type": "manifest_snapshot",
            "bytes": len(raw),
            "sha256": digest,
        }
        return loaded

    def read_requirements(path: Path, seen: set[Path]) -> None:
        loaded = record_file(path)
        if loaded is None:
            return
        resolved, relative, raw = loaded
        if resolved in seen:
            return
        seen.add(resolved)
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            warn(relative, "Dependency manifest is not valid UTF-8 text")
            return
        for raw_line in lines:
            line = raw_line.split(" #", 1)[0].strip()
            include_match = re.match(
                r"^(?:-r|--requirement|-c|--constraint)[= ]+(.+)$", line
            )
            if include_match:
                read_requirements(
                    resolved.parent / include_match.group(1).strip(), seen
                )
            else:
                record(line, resolved.relative_to(root).as_posix())

    manifest_patterns = (
        "pyproject.toml",
        "requirements*.txt",
        "constraints*.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "pdm.lock",
        "pylock.toml",
        "setup.cfg",
        "uv.lock",
    )
    manifest_candidates: dict[str, list[Path]] = {
        "pyproject": [],
        "requirements": [],
        "auxiliary": [],
    }
    for current, directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in DEFAULT_EXCLUDES and not directory.startswith(".")
        )
        for filename in sorted(filenames):
            if filename == "pyproject.toml":
                category = "pyproject"
            elif any(
                fnmatch.fnmatchcase(filename, pattern)
                for pattern in ("requirements*.txt", "constraints*.txt")
            ):
                category = "requirements"
            elif any(
                fnmatch.fnmatchcase(filename, pattern)
                for pattern in manifest_patterns[3:]
            ):
                category = "auxiliary"
            else:
                continue
            if len(manifest_candidates[category]) < MAX_DEPENDENCY_MANIFEST_FILES:
                manifest_candidates[category].append(Path(current) / filename)

    def discovered_manifests(patterns: tuple[str, ...]) -> list[Path]:
        return [
            path
            for candidates in manifest_candidates.values()
            for path in candidates
            if any(fnmatch.fnmatchcase(path.name, pattern) for pattern in patterns)
        ]

    for pyproject in discovered_manifests(("pyproject.toml",)):
        loaded = record_file(pyproject)
        try:
            if loaded is None:
                raise ValueError
            _, relative, raw = loaded
            payload = tomllib.loads(raw.decode("utf-8"))
            project = payload.get("project", {})
            if not isinstance(project, dict):
                raise TypeError
            claims: list[tuple[str, str]] = []
            project_dependencies = project.get("dependencies", []) or []
            if not isinstance(project_dependencies, list) or not all(
                isinstance(value, str) for value in project_dependencies
            ):
                raise TypeError
            for value in project_dependencies:
                claims.append((value, f"{relative}:project.dependencies"))
            optional = project.get("optional-dependencies", {}) or {}
            if not isinstance(optional, dict):
                raise TypeError
            for group, values in optional.items():
                group_values = values or []
                if not isinstance(group_values, list) or not all(
                    isinstance(value, str) for value in group_values
                ):
                    raise TypeError
                for value in group_values:
                    claims.append(
                        (
                            value,
                            f"{relative}:project.optional-dependencies.{group}",
                        )
                    )
            tool = payload.get("tool", {}) or {}
            if not isinstance(tool, dict):
                raise TypeError
            poetry_config = tool.get("poetry", {}) or {}
            if not isinstance(poetry_config, dict):
                raise TypeError
            poetry = poetry_config.get("dependencies", {}) or {}
            if not isinstance(poetry, dict):
                raise TypeError
            for name, constraint in poetry.items():
                if name == "python":
                    continue
                specification = (
                    f"{name}{constraint}" if isinstance(constraint, str) else name
                )
                claims.append((specification, f"{relative}:tool.poetry.dependencies"))
            for specification, source in claims:
                record(specification, source)
        except UnicodeDecodeError:
            warn(
                display_path(pyproject),
                "Dependency manifest is not valid UTF-8 TOML",
            )
        except (tomllib.TOMLDecodeError, TypeError):
            warn(
                display_path(pyproject),
                "Dependency manifest is not valid supported TOML",
            )
        except ValueError:
            pass
    requirement_files = discovered_manifests(("requirements*.txt", "constraints*.txt"))
    seen_requirements: set[Path] = set()
    for requirements in requirement_files:
        read_requirements(requirements, seen_requirements)
    for candidate in discovered_manifests(
        (
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "pdm.lock",
            "pylock.toml",
            "setup.cfg",
            "uv.lock",
        )
    ):
        record_file(candidate)
    return sorted(
        dependencies.values(),
        key=lambda value: (value["name"].lower(), value["source"]),
    )


def _contract_inventory(
    root: Path,
    warnings: list[dict[str, Any]],
    evidence_snapshots: dict[Path, bytes] | None = None,
) -> list[dict[str, Any]]:
    """Inventory common interface/data contracts without requiring third-party parsers."""

    candidates: list[Path] = []
    discovery_truncated = False
    # Walk once instead of issuing one recursive traversal per contract pattern.
    # Final candidate sorting preserves deterministic ingestion order.
    for current, directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in DEFAULT_EXCLUDES and not directory.startswith(".")
        )
        for filename in sorted(filenames):
            folded = filename.casefold()
            supported = (
                (
                    folded.startswith(("openapi", "swagger", "asyncapi"))
                    and folded.endswith((".json", ".yaml", ".yml"))
                )
                or folded.endswith(".schema.json")
                or folded.endswith(".proto")
                or folded.endswith((".graphql", ".graphqls", ".avsc"))
            )
            if not supported:
                continue
            if len(candidates) >= MAX_CONTRACT_FILES:
                discovery_truncated = True
                break
            candidates.append(Path(current) / filename)
        if discovery_truncated:
            break
    if discovery_truncated:
        warnings.append(
            {
                "path": "./",
                "message": (
                    "Contract discovery reached the "
                    f"{MAX_CONTRACT_FILES}-file analysis limit"
                ),
                "type": "ContractLimit",
            }
        )
    contracts = []
    consumed_bytes = 0
    for path in sorted(candidates):
        candidate = path.absolute()
        lexical_relative = path.relative_to(root).as_posix()
        if candidate.is_symlink():
            warnings.append(
                {
                    "path": lexical_relative,
                    "message": "Contract must be a regular non-symbolic-link file",
                    "type": "ContractBoundary",
                }
            )
            continue
        try:
            resolved = candidate.resolve()
            relative = resolved.relative_to(root)
        except (OSError, ValueError):
            warnings.append(
                {
                    "path": lexical_relative,
                    "message": "Contract resolves outside the repository",
                    "type": "OutsideRepository",
                }
            )
            continue
        if not candidate.is_file():
            warnings.append(
                {
                    "path": relative.as_posix(),
                    "message": "Contract must be a regular non-symbolic-link file",
                    "type": "ContractBoundary",
                }
            )
            continue
        try:
            snapshot = load_bounded_file_snapshot(
                candidate,
                label="Contract",
                max_bytes=MAX_CONTRACT_BYTES,
            )
        except ValueError as exc:
            message = str(exc)
            if message == f"Contract exceeds the {MAX_CONTRACT_BYTES}-byte limit":
                warning_type = "ContractTooLarge"
                message = (
                    f"Contract exceeds the {MAX_CONTRACT_BYTES}-byte analysis limit"
                )
            elif message in {
                "Contract must be an available regular file",
                "Contract must be a regular non-symbolic-link file",
            }:
                warning_type = "ContractBoundary"
                message = "Contract must be a regular non-symbolic-link file"
            else:
                warning_type = "ContractError"
            warnings.append(
                {
                    "path": relative.as_posix(),
                    "message": message,
                    "type": warning_type,
                }
            )
            continue
        raw = snapshot.raw
        if consumed_bytes + len(raw) > MAX_CONTRACT_TOTAL_BYTES:
            warnings.append(
                {
                    "path": relative.as_posix(),
                    "message": (
                        "Contract ingestion exceeds the "
                        f"{MAX_CONTRACT_TOTAL_BYTES}-byte aggregate limit"
                    ),
                    "type": "ContractLimit",
                }
            )
            break
        consumed_bytes += len(raw)
        if evidence_snapshots is not None:
            evidence_snapshots[resolved] = raw
        try:
            text: str | None = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
            warnings.append(
                {
                    "path": relative.as_posix(),
                    "message": "Contract is not valid UTF-8 text",
                    "type": "ContractError",
                }
            )
        operations: set[str] = set()
        data_types: set[str] = set()
        operation_contracts: list[dict[str, Any]] = []
        type_contracts: list[dict[str, Any]] = []
        contract_version = ""
        entities_truncated = False

        def retain(target: set[str], value: str) -> bool:
            if value in target:
                return True
            if len(target) >= MAX_CONTRACT_ENTITIES:
                return False
            target.add(value)
            return True

        lower_name = candidate.name.lower()
        suffix = resolved.suffix.lower()
        kind = "protobuf" if suffix == ".proto" else "openapi"
        if lower_name.endswith(".schema.json"):
            kind = "json_schema"
        elif lower_name.startswith("asyncapi"):
            kind = "asyncapi"
        elif suffix in {".graphql", ".graphqls"}:
            kind = "graphql"
        elif suffix == ".avsc":
            kind = "avro"
        malformed_structure = False
        json_error = ""
        if (
            text is not None
            and kind in {"openapi", "asyncapi", "json_schema", "avro"}
            and (resolved.suffix.lower() == ".json" or kind == "avro")
        ):
            try:
                payload = parse_bounded_json_bytes(
                    raw,
                    label="Contract JSON",
                    max_bytes=MAX_CONTRACT_BYTES,
                    max_depth=MAX_CONTRACT_JSON_DEPTH,
                    max_nodes=MAX_CONTRACT_JSON_NODES,
                )
                if not isinstance(payload, dict):
                    raise TypeError
                if kind == "openapi":
                    contract_version = str(
                        payload.get("openapi") or payload.get("swagger") or ""
                    )
                    paths = payload.get("paths", {})
                    if not isinstance(paths, dict):
                        raise TypeError
                    stop_operations = False
                    for route, methods in paths.items():
                        if not isinstance(route, str) or not isinstance(methods, dict):
                            malformed_structure = True
                            continue
                        for method in methods:
                            if not isinstance(method, str):
                                malformed_structure = True
                                continue
                            if method.lower() not in {
                                "get",
                                "post",
                                "put",
                                "patch",
                                "delete",
                                "options",
                                "head",
                            }:
                                continue
                            if not retain(operations, f"{method.upper()} {route}"):
                                entities_truncated = True
                                stop_operations = True
                                break
                            operation_spec = methods.get(method, {})
                            if not isinstance(operation_spec, dict):
                                malformed_structure = True
                                operation_spec = {}
                            combined_parameters = [
                                value
                                for value in [
                                    *(
                                        methods.get("parameters", [])
                                        if isinstance(
                                            methods.get("parameters", []), list
                                        )
                                        else []
                                    ),
                                    *(
                                        operation_spec.get("parameters", [])
                                        if isinstance(
                                            operation_spec.get("parameters", []), list
                                        )
                                        else []
                                    ),
                                ]
                                if isinstance(value, dict)
                            ]
                            request_body = operation_spec.get("requestBody", {})
                            responses = operation_spec.get("responses", {})
                            operation_contracts.append(
                                {
                                    "id": stable_id(
                                        "CONTRACT-OP",
                                        relative.as_posix(),
                                        method.upper(),
                                        route,
                                    ),
                                    "operation": f"{method.upper()} {route}",
                                    "operation_id": str(
                                        operation_spec.get("operationId", "")
                                    ),
                                    "request": {
                                        "parameters": [
                                            {
                                                "name": str(value.get("name", "")),
                                                "location": str(value.get("in", "")),
                                                "required": bool(
                                                    value.get("required", False)
                                                ),
                                                "schema": copy.deepcopy(
                                                    value.get("schema", {})
                                                ),
                                            }
                                            for value in combined_parameters
                                        ],
                                        "body_required": bool(
                                            isinstance(request_body, dict)
                                            and request_body.get("required", False)
                                        ),
                                        "media_types": sorted(
                                            str(value)
                                            for value in (
                                                request_body.get("content", {})
                                                if isinstance(request_body, dict)
                                                and isinstance(
                                                    request_body.get("content", {}),
                                                    dict,
                                                )
                                                else {}
                                            )
                                        ),
                                    },
                                    "responses": [
                                        {
                                            "status": str(status),
                                            "media_types": sorted(
                                                str(value)
                                                for value in (
                                                    response.get("content", {})
                                                    if isinstance(response, dict)
                                                    and isinstance(
                                                        response.get("content", {}),
                                                        dict,
                                                    )
                                                    else {}
                                                )
                                            ),
                                        }
                                        for status, response in (
                                            responses.items()
                                            if isinstance(responses, dict)
                                            else []
                                        )
                                    ],
                                    "security_declared": bool(
                                        operation_spec.get("security")
                                        or payload.get("security")
                                    ),
                                    "deprecated": bool(
                                        operation_spec.get("deprecated", False)
                                    ),
                                }
                            )
                        if stop_operations:
                            break
                    components = payload.get("components", {})
                    if not isinstance(components, dict):
                        raise TypeError
                    schemas = components.get("schemas", {})
                    if not isinstance(schemas, dict):
                        raise TypeError
                    for value in schemas:
                        if not isinstance(value, str):
                            malformed_structure = True
                            continue
                        if not retain(data_types, value):
                            entities_truncated = True
                            break
                        schema = schemas.get(value, {})
                        type_contracts.append(
                            {
                                "name": value,
                                "kind": "object_schema",
                                "type": str(schema.get("type", ""))
                                if isinstance(schema, dict)
                                else "",
                                "required": sorted(
                                    str(item)
                                    for item in (
                                        schema.get("required", [])
                                        if isinstance(schema, dict)
                                        and isinstance(schema.get("required", []), list)
                                        else []
                                    )
                                ),
                                "properties": sorted(
                                    str(item)
                                    for item in (
                                        schema.get("properties", {})
                                        if isinstance(schema, dict)
                                        and isinstance(
                                            schema.get("properties", {}), dict
                                        )
                                        else {}
                                    )
                                ),
                                "additional_properties": (
                                    schema.get("additionalProperties")
                                    if isinstance(schema, dict)
                                    else None
                                ),
                            }
                        )
                elif kind == "asyncapi":
                    contract_version = str(payload.get("asyncapi", ""))
                    channels = payload.get("channels", {})
                    if not isinstance(channels, dict):
                        raise TypeError
                    for channel, declaration in channels.items():
                        if not isinstance(channel, str) or not isinstance(
                            declaration, dict
                        ):
                            malformed_structure = True
                            continue
                        for direction in ("publish", "subscribe"):
                            operation_spec = declaration.get(direction)
                            if not isinstance(operation_spec, dict):
                                continue
                            operation = f"{direction.upper()} {channel}"
                            if not retain(operations, operation):
                                entities_truncated = True
                                break
                            message = operation_spec.get("message", {})
                            operation_contracts.append(
                                {
                                    "id": stable_id(
                                        "CONTRACT-OP", relative.as_posix(), operation
                                    ),
                                    "operation": operation,
                                    "operation_id": str(
                                        operation_spec.get("operationId", "")
                                    ),
                                    "request": {
                                        "message_reference": str(
                                            message.get("$ref", "")
                                            if isinstance(message, dict)
                                            else ""
                                        )
                                    },
                                    "responses": [],
                                    "security_declared": bool(
                                        operation_spec.get("security")
                                        or payload.get("security")
                                    ),
                                    "deprecated": False,
                                }
                            )
                    components = payload.get("components", {})
                    messages = (
                        components.get("messages", {})
                        if isinstance(components, dict)
                        else {}
                    )
                    if isinstance(messages, dict):
                        for name in messages:
                            if isinstance(name, str) and retain(data_types, name):
                                type_contracts.append(
                                    {
                                        "name": name,
                                        "kind": "message",
                                        "required": [],
                                        "properties": [],
                                    }
                                )
                elif kind == "avro":
                    contract_version = str(payload.get("namespace", ""))
                    name = payload.get("name")
                    fields = payload.get("fields", [])
                    if isinstance(name, str):
                        retain(data_types, name)
                        type_contracts.append(
                            {
                                "name": name,
                                "kind": "avro_record",
                                "type": str(payload.get("type", "")),
                                "required": [
                                    str(value.get("name", ""))
                                    for value in fields
                                    if isinstance(value, dict)
                                    and value.get("name")
                                    and "default" not in value
                                ]
                                if isinstance(fields, list)
                                else [],
                                "properties": [
                                    str(value.get("name", ""))
                                    for value in fields
                                    if isinstance(value, dict) and value.get("name")
                                ]
                                if isinstance(fields, list)
                                else [],
                            }
                        )
                else:
                    title = payload.get("title")
                    if title is not None and not isinstance(title, str):
                        malformed_structure = True
                    elif title:
                        retain(data_types, title)
                    properties = payload.get("properties", {})
                    if not isinstance(properties, dict):
                        raise TypeError
                    for value in properties:
                        if not isinstance(value, str):
                            malformed_structure = True
                            continue
                        if not retain(data_types, value):
                            entities_truncated = True
                            break
            except ValueError as exc:
                malformed_structure = True
                json_error = str(exc)
            except TypeError:
                malformed_structure = True
        elif text is not None and kind == "openapi":
            current_route = ""
            for line in text.splitlines():
                route_match = re.match(r"^\s{0,8}(/[^:]+)\s*:\s*(?:#.*)?$", line)
                if route_match:
                    current_route = route_match.group(1).strip()
                    continue
                method_match = re.match(
                    r"^\s+(get|post|put|patch|delete|options|head)\s*:\s*(?:#.*)?$",
                    line,
                    re.IGNORECASE,
                )
                if (
                    current_route
                    and method_match
                    and not retain(
                        operations,
                        f"{method_match.group(1).upper()} {current_route}",
                    )
                ):
                    entities_truncated = True
                    break
        elif text is not None and kind == "protobuf":
            syntax = re.search(r"\bsyntax\s*=\s*[\"']([^\"']+)[\"']", text)
            contract_version = syntax.group(1) if syntax else ""
            for match in re.finditer(
                r"\brpc\s+([A-Za-z_]\w*)\s*\(\s*(stream\s+)?([.A-Za-z_]\w*)\s*\)\s*returns\s*\(\s*(stream\s+)?([.A-Za-z_]\w*)\s*\)",
                text,
            ):
                if not retain(operations, match.group(1)):
                    entities_truncated = True
                    break
                operation_contracts.append(
                    {
                        "id": stable_id(
                            "CONTRACT-OP", relative.as_posix(), match.group(1)
                        ),
                        "operation": match.group(1),
                        "operation_id": match.group(1),
                        "request": {
                            "type": match.group(3),
                            "streaming": bool(match.group(2)),
                        },
                        "responses": [
                            {
                                "status": "rpc_result",
                                "type": match.group(5),
                                "streaming": bool(match.group(4)),
                            }
                        ],
                        "security_declared": False,
                        "deprecated": False,
                    }
                )
            for match in re.finditer(
                r"\bmessage\s+([A-Za-z_]\w*)\s*\{([^}]*)\}", text, re.DOTALL
            ):
                if not retain(data_types, match.group(1)):
                    entities_truncated = True
                    break
                fields = [
                    {
                        "type": field.group(1),
                        "name": field.group(2),
                        "number": int(field.group(3)),
                    }
                    for field in re.finditer(
                        r"(?:optional\s+|repeated\s+)?([.A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*(\d+)",
                        match.group(2),
                    )
                ]
                type_contracts.append(
                    {
                        "name": match.group(1),
                        "kind": "protobuf_message",
                        "required": [],
                        "properties": [value["name"] for value in fields],
                        "fields": fields,
                    }
                )
        elif text is not None and kind == "graphql":
            for match in re.finditer(
                r"\b(type|input|interface|enum)\s+([A-Za-z_]\w*)\s*[^\{]*\{([^}]*)\}",
                text,
                re.DOTALL,
            ):
                declaration_kind, name, body = match.groups()
                if not retain(data_types, name):
                    entities_truncated = True
                    break
                fields = [
                    value.group(1)
                    for value in re.finditer(
                        r"^\s*([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:", body, re.MULTILINE
                    )
                ]
                type_contracts.append(
                    {
                        "name": name,
                        "kind": f"graphql_{declaration_kind}",
                        "required": [],
                        "properties": fields,
                    }
                )
                if name in {"Query", "Mutation", "Subscription"}:
                    for field in fields:
                        operation = f"{name.upper()} {field}"
                        retain(operations, operation)
                        operation_contracts.append(
                            {
                                "id": stable_id(
                                    "CONTRACT-OP", relative.as_posix(), operation
                                ),
                                "operation": operation,
                                "operation_id": field,
                                "request": {},
                                "responses": [{"status": "graphql_result"}],
                                "security_declared": False,
                                "deprecated": False,
                            }
                        )
        if malformed_structure:
            message = "Contract JSON has malformed or unsupported structure"
            if json_error:
                message += f": {json_error}"
            warnings.append(
                {
                    "path": relative.as_posix(),
                    "message": message,
                    "type": "ContractError",
                }
            )
        if entities_truncated:
            warnings.append(
                {
                    "path": relative.as_posix(),
                    "message": (
                        "Contract semantic extraction reached the "
                        f"{MAX_CONTRACT_ENTITIES}-entity per-category limit"
                    ),
                    "type": "ContractLimit",
                }
            )
        digest = hashlib.sha256(raw).hexdigest()
        contracts.append(
            {
                "id": stable_id("CONTRACT", relative.as_posix(), digest),
                "path": relative.as_posix(),
                "kind": kind,
                "version": contract_version,
                "bytes": len(raw),
                "sha256": digest,
                "operations": sorted(operations),
                "data_types": sorted(data_types),
                "operation_contracts": operation_contracts[:MAX_CONTRACT_ENTITIES],
                "type_contracts": type_contracts[:MAX_CONTRACT_ENTITIES],
            }
        )
    return contracts


def _repository_baseline(
    root: Path,
    files: list[Path],
    config: dict[str, Any],
    dependencies: list[dict[str, Any]],
    contracts: list[dict[str, Any]],
    repository_inventory: dict[str, Any],
    source_snapshots: dict[Path, bytes],
    source_snapshot_errors: dict[Path, str],
    test_evidence_snapshots: dict[Path, bytes],
    test_evidence_errors: dict[Path, str],
) -> dict[str, Any]:
    content_hash = hashlib.sha256()
    source_snapshot_records: list[dict[str, Any]] = []
    source_snapshot_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        content_hash.update(relative.encode("utf-8"))
        content_hash.update(b"\0")
        raw = source_snapshots.get(path)
        if raw is not None:
            digest = hashlib.sha256(raw).hexdigest()
            content_hash.update(raw)
            source_snapshot_bytes += len(raw)
            source_snapshot_records.append(
                {
                    "path": relative,
                    "status": "accepted",
                    "bytes": len(raw),
                    "sha256": digest,
                }
            )
        else:
            error = source_snapshot_errors.get(path, "source snapshot unavailable")
            content_hash.update(f"<bounded-source:{error}>".encode("utf-8"))
            source_snapshot_records.append(
                {"path": relative, "status": "rejected", "reason": error}
            )
        content_hash.update(b"\0")
    content_hash.update(
        json.dumps(dependencies, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    content_hash.update(
        json.dumps(contracts, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    content_hash.update(
        str(repository_inventory.get("inventory_sha256", "")).encode("utf-8")
    )
    config_digest = hashlib.sha256(
        json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    source_snapshot_sha256 = hashlib.sha256(
        json.dumps(
            source_snapshot_records,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    test_evidence_snapshot_records: list[dict[str, Any]] = []
    test_evidence_snapshot_bytes = 0
    for path in sorted(set(test_evidence_snapshots) | set(test_evidence_errors)):
        relative = path.relative_to(root).as_posix()
        raw = test_evidence_snapshots.get(path)
        if raw is not None:
            test_evidence_snapshot_bytes += len(raw)
            test_evidence_snapshot_records.append(
                {
                    "path": relative,
                    "status": "accepted",
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        else:
            test_evidence_snapshot_records.append(
                {
                    "path": relative,
                    "status": "rejected",
                    "reason": test_evidence_errors[path],
                }
            )
    test_evidence_snapshot_sha256 = hashlib.sha256(
        json.dumps(
            test_evidence_snapshot_records,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    content_hash.update(test_evidence_snapshot_sha256.encode("utf-8"))
    source_digest = content_hash.hexdigest()
    vcs: dict[str, Any] = {"type": "", "revision": "", "dirty": None}
    try:
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        if revision.returncode == 0:
            status = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            vcs = {
                "type": "git",
                "revision": revision.stdout.strip(),
                "dirty": bool(status.stdout.strip())
                if status.returncode == 0
                else None,
            }
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        "id": stable_id("BASELINE", source_digest, config_digest),
        "source_digest": source_digest,
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_snapshot_files": len(source_snapshots),
        "source_snapshot_bytes": source_snapshot_bytes,
        "source_snapshot_rejected_files": len(files) - len(source_snapshots),
        "test_evidence_snapshot_sha256": test_evidence_snapshot_sha256,
        "test_evidence_snapshot_files": len(test_evidence_snapshots),
        "test_evidence_snapshot_bytes": test_evidence_snapshot_bytes,
        "test_evidence_snapshot_rejected_files": len(test_evidence_errors),
        "config_digest": config_digest,
        "repository_inventory_sha256": repository_inventory.get("inventory_sha256", ""),
        "vcs": vcs,
    }


def _dependency_component_and_item(
    dependencies: list[dict[str, Any]], analysis_rules: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    included = set(analysis_rules.get("included_failure_classes", []))
    excluded = set(analysis_rules.get("excluded_failure_classes", []))
    if (
        not dependencies
        or "environment" in excluded
        or (included and "environment" not in included)
    ):
        return None
    fingerprint = hashlib.sha256(
        json.dumps(dependencies, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    component_id = stable_id("CMP", "project-environment")
    component = {
        "id": component_id,
        "kind": "environment",
        "name": "Runtime and dependency environment",
        "qualname": "Runtime and dependency environment",
        "source": {
            "path": "pyproject.toml / requirements files",
            "line": "",
            "end_line": "",
        },
        "signature": "",
        "docstring_summary": "Declared Python runtime dependencies",
        "is_async": False,
        "decorators": [],
        "parameters": [],
        "calls": [],
        "fan_in": 0,
        "called_by": [],
        "upstream_paths": [],
        "complexity": 1,
        "arithmetic_operations": 0,
        "source_fingerprint": fingerprint,
        "content_fingerprint": fingerprint,
        "context_fingerprint": fingerprint,
        "signals": ["runtime_environment"],
        "test_references": [],
        "coverage": None,
        "critical_context": [],
        "mapping_context": [],
        "subsystems": [],
        "requirement_ids": [],
        "interface_ids": [],
        "screening": {
            "priority": "medium",
            "score": 2,
            "reasons": [f"{len(dependencies)} declared dependency entries"],
        },
    }
    review = empty_review()
    review.update(
        {
            "function": "Provide the reviewed runtime and third-party dependency environment.",
            "failure_mode": "A runtime, dependency, resolver, or build-environment change alters behavior or makes the system unavailable.",
            "trigger": "The installed or resolved environment differs from the analyzed and verified baseline.",
            "causes": [
                "Unpinned or incompatible dependency",
                "Resolver or index change",
                "Interpreter or operating-system change",
                "Incorrect optional dependency set",
            ],
            "local_effect": "One or more software components execute different code or cannot start.",
            "recommended_actions": [
                "Record a reproducible dependency and interpreter baseline",
                "Review dependency changes for affected critical functions",
                "Verify supported upgrade and rollback paths",
            ],
        }
    )
    item = {
        "id": stable_id("SFMEA", component_id, "environment.dependency_drift"),
        "component_id": component_id,
        "source_status": "active",
        "source_change": "new",
        "source": component["source"],
        "component": {
            "kind": "environment",
            "qualname": component["qualname"],
            "signature": "",
            "subsystems": [],
            "requirement_ids": [],
            "interface_ids": [],
        },
        "scanner": {
            "rule_id": "environment.dependency_drift",
            "failure_class": "environment",
            "source_fingerprint": fingerprint,
            "content_fingerprint": fingerprint,
            "context_fingerprint": fingerprint,
            "guideword": "Environment / dependency change",
            "failure_mode": review["failure_mode"],
            "trigger": review["trigger"],
            "confidence": "high",
            "screening_priority": "medium",
            "screening_reasons": [f"{len(dependencies)} declared dependency entries"],
            "evidence": [
                f"Declared dependency: {entry['specification']} ({entry['source']})"
                for entry in dependencies[:50]
            ],
        },
        "review": review,
        "review_history": [],
    }
    return component, item


def _contract_components_and_items(
    contracts: list[dict[str, Any]], config: dict[str, Any]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    analysis_rules = config.get("analysis", {})
    included = set(analysis_rules.get("included_failure_classes", []))
    excluded = set(analysis_rules.get("excluded_failure_classes", []))
    if "interface" in excluded or (included and "interface" not in included):
        return []
    result = []
    for contract in contracts:
        component_id = stable_id("CMP", "contract", contract["path"])
        fingerprint = contract["sha256"]
        qualname = f"Interface contract {contract['path']}"
        reference = f"{contract['path']}:{qualname}"
        mapping_context = [
            entry
            for entry in config.get("component_mappings", [])
            if fnmatch.fnmatchcase(reference, entry.get("pattern", ""))
        ]
        critical_context = [
            entry
            for entry in config.get("critical_functions", [])
            if fnmatch.fnmatchcase(reference, entry.get("pattern", ""))
        ]
        requirement_ids = sorted(
            {
                requirement
                for entry in mapping_context
                for requirement in entry.get("requirements", [])
            }
        )
        interface_ids = sorted(
            {
                interface
                for entry in mapping_context
                for interface in entry.get("interfaces", [])
            }
        )
        linked_hazards = sorted(
            {
                hazard
                for entry in [*critical_context, *mapping_context]
                for hazard in entry.get("hazards", [])
            }
        )
        component = {
            "id": component_id,
            "kind": "interface_contract",
            "name": Path(contract["path"]).name,
            "qualname": qualname,
            "source": {"path": contract["path"], "line": 1, "end_line": 1},
            "signature": contract["kind"],
            "docstring_summary": "Define an external interface or data compatibility contract.",
            "is_async": False,
            "decorators": [],
            "parameters": contract.get("data_types", []),
            "calls": [],
            "ordered_calls": [],
            "frameworks": [contract["kind"]],
            "entrypoint_types": ["interface_contract"],
            "fan_in": 0,
            "called_by": [],
            "upstream_paths": [],
            "complexity": 1,
            "arithmetic_operations": 0,
            "source_fingerprint": fingerprint,
            "content_fingerprint": fingerprint,
            "context_fingerprint": fingerprint,
            "signals": ["external_interface", "serialization"],
            "test_references": [],
            "coverage": None,
            "critical_context": critical_context,
            "mapping_context": mapping_context,
            "subsystems": sorted(
                {
                    entry.get("subsystem", "")
                    for entry in mapping_context
                    if entry.get("subsystem")
                }
            ),
            "requirement_ids": requirement_ids,
            "interface_ids": interface_ids,
            "screening": {
                "priority": "medium",
                "score": 3,
                "reasons": [
                    f"{contract['kind']} contract with {len(contract.get('operations', []))} operation(s)"
                ],
            },
        }
        component["analysis_context_fingerprint"] = _analysis_context_fingerprint(
            component, config
        )
        review = empty_review()
        review.update(
            {
                "function": "Define compatible operations, messages, fields, and behavior across an interface boundary.",
                "failure_mode": "The implemented or deployed interface is missing, incompatible with, or semantically different from the analyzed contract.",
                "trigger": "A producer, consumer, client, server, or deployed version relies on a different contract interpretation.",
                "causes": [
                    "Breaking schema or operation change",
                    "Generated client/server artifact is stale",
                    "Field units, optionality, defaults, or error semantics differ",
                    "Deployment combines incompatible versions",
                ],
                "local_effect": "The interface rejects, misinterprets, truncates, or silently transforms a request or response.",
                "recommended_actions": [
                    "Version and review interface contracts",
                    "Run producer/consumer compatibility tests",
                    "Verify generated artifacts and deployed versions against the baseline",
                ],
                "requirement": "\n".join(requirement_ids),
                "linked_hazards": linked_hazards,
            }
        )
        if len(linked_hazards) == 1:
            hazard: dict[str, Any] = next(
                (
                    value
                    for value in config.get("hazards", [])
                    if isinstance(value, dict)
                    and value.get("id") == linked_hazards[0]
                ),
                {},
            )
            if hazard.get("end_effect"):
                review["end_effect"] = hazard["end_effect"]
            if isinstance(hazard.get("severity"), int):
                review["severity"] = hazard["severity"]
            if hazard.get("severity_category"):
                review["severity_category"] = hazard["severity_category"]
            if review["severity"] is not None or review["severity_category"]:
                review["severity_rationale"] = (
                    f"Inherited from project-defined hazard {linked_hazards[0]}; "
                    "confirm applicability."
                )
        item = {
            "id": stable_id("SFMEA", component_id, "interface.contract_compatibility"),
            "component_id": component_id,
            "source_status": "active",
            "source_change": "new",
            "source": component["source"],
            "component": {
                "kind": component["kind"],
                "qualname": component["qualname"],
                "signature": component["signature"],
                "subsystems": component["subsystems"],
                "requirement_ids": requirement_ids,
                "interface_ids": interface_ids,
            },
            "scanner": {
                "rule_id": "interface.contract_compatibility",
                "failure_class": "interface",
                "source_fingerprint": fingerprint,
                "content_fingerprint": fingerprint,
                "context_fingerprint": fingerprint,
                "analysis_context_fingerprint": component[
                    "analysis_context_fingerprint"
                ],
                "guideword": "Contract mismatch / version incompatibility",
                "failure_mode": review["failure_mode"],
                "trigger": review["trigger"],
                "confidence": "high",
                "screening_priority": "medium",
                "screening_reasons": component["screening"]["reasons"],
                "evidence": [
                    f"Contract: {contract['path']} ({contract['kind']})",
                    *(
                        f"Operation: {value}"
                        for value in contract.get("operations", [])[:50]
                    ),
                    *(
                        f"Data type: {value}"
                        for value in contract.get("data_types", [])[:50]
                    ),
                    *(f"Requirement mapping: {value}" for value in requirement_ids),
                    *(f"Hazard mapping: {value}" for value in linked_hazards),
                    *(f"System interface mapping: {value}" for value in interface_ids),
                ],
            },
            "review": review,
            "review_history": [],
        }
        result.append((component, item))
    return result


def _common_cause_elements(
    definitions: list[dict[str, Any]],
    components: list[dict[str, Any]],
    hazards: dict[str, dict[str, Any]],
    analysis_rules: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    included = set(analysis_rules.get("included_failure_classes", []))
    excluded = set(analysis_rules.get("excluded_failure_classes", []))
    if "common_cause" in excluded or (included and "common_cause" not in included):
        return []
    result: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for definition in definitions:
        patterns = definition.get("component_patterns", [])
        affected = [
            component
            for component in components
            if _matches_pattern(
                f"{component.get('source', {}).get('path', '')}:{component.get('qualname', '')}",
                patterns,
            )
        ]
        definition_id = definition["id"]
        component_id = stable_id("CMP", "common-cause", definition_id)
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "definition": definition,
                    "affected": [component.get("id") for component in affected],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        subsystems = sorted(
            {
                subsystem
                for component in affected
                for subsystem in component.get("subsystems", [])
            }
        )
        component = {
            "id": component_id,
            "kind": "common_cause",
            "name": definition_id,
            "qualname": f"Common cause {definition_id}",
            "source": {"path": "sfmea.toml", "line": "", "end_line": ""},
            "signature": "",
            "docstring_summary": definition["description"],
            "is_async": False,
            "decorators": [],
            "parameters": [],
            "calls": [],
            "fan_in": 0,
            "called_by": [],
            "upstream_paths": [],
            "complexity": 1,
            "arithmetic_operations": 0,
            "source_fingerprint": fingerprint,
            "content_fingerprint": fingerprint,
            "context_fingerprint": fingerprint,
            "signals": ["common_cause"],
            "test_references": [],
            "coverage": None,
            "critical_context": [],
            "mapping_context": [],
            "subsystems": subsystems,
            "requirement_ids": list(definition.get("requirements", [])),
            "interface_ids": [],
            "affected_component_ids": [component.get("id") for component in affected],
            "screening": {
                "priority": "high",
                "score": 8,
                "reasons": [
                    f"project-defined common cause affecting {len(affected)} scanned components"
                ],
            },
        }
        review = empty_review()
        linked_hazards = list(definition.get("hazards", []))
        review.update(
            {
                "function": "Maintain required independence and prevent dependent failures across affected components.",
                "requirement": "\n".join(definition.get("requirements", [])),
                "linked_hazards": linked_hazards,
                "failure_mode": definition["description"],
                "trigger": "A shared cause or violated independence assumption affects multiple components.",
                "causes": list(definition.get("causes", [])),
                "local_effect": "Multiple nominally separate functions become unavailable or incorrect together.",
                "prevention_controls": list(definition.get("controls", [])),
                "recommended_actions": [
                    "Verify independence assumptions and common dependencies",
                    "Test shared-cause and dependent-failure scenarios",
                ],
            }
        )
        if len(linked_hazards) == 1:
            hazard = hazards.get(linked_hazards[0], {})
            review["end_effect"] = hazard.get("end_effect", "")
            if isinstance(hazard.get("severity"), int):
                review["severity"] = hazard["severity"]
                review["severity_rationale"] = (
                    f"Inherited from project-defined hazard {linked_hazards[0]}; confirm applicability."
                )
            if hazard.get("severity_category"):
                review["severity_category"] = hazard["severity_category"]
                review["severity_rationale"] = (
                    f"Inherited from project-defined hazard {linked_hazards[0]}; confirm applicability."
                )
        item = {
            "id": stable_id("SFMEA", component_id, f"common_cause.{definition_id}"),
            "component_id": component_id,
            "source_status": "active",
            "source_change": "new",
            "source": component["source"],
            "component": {
                "kind": "common_cause",
                "qualname": component["qualname"],
                "signature": "",
                "subsystems": subsystems,
                "requirement_ids": component["requirement_ids"],
                "interface_ids": [],
            },
            "scanner": {
                "rule_id": f"common_cause.{definition_id}",
                "failure_class": "common_cause",
                "source_fingerprint": fingerprint,
                "content_fingerprint": fingerprint,
                "context_fingerprint": fingerprint,
                "guideword": "Common cause / dependent failure",
                "failure_mode": review["failure_mode"],
                "trigger": review["trigger"],
                "confidence": "project",
                "screening_priority": "high",
                "screening_reasons": component["screening"]["reasons"],
                "evidence": [
                    "Affected component: "
                    f"{entry.get('source', {}).get('path', '')}:{entry.get('qualname', '')}"
                    for entry in affected
                ],
            },
            "review": review,
            "review_history": [],
        }
        result.append((component, item))
    return result


def _test_evidence_analysis(
    tests: dict[str, str],
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Build an AST-grounded symbol index and bounded test-quality signal summary."""

    symbol_paths: dict[str, set[str]] = defaultdict(set)
    dimensions: dict[str, set[str]] = defaultdict(set)
    parse_errors: list[str] = []
    for path, content in tests.items():
        try:
            tree = ast.parse(content, filename=path)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            parse_errors.append(path)
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        symbol_paths[alias.asname or alias.name].add(path)
            elif isinstance(node, ast.Call):
                reference = _dotted_name(node.func)
                if reference:
                    symbol_paths[reference.rsplit(".", 1)[-1]].add(path)
                    lowered = reference.casefold()
                    if lowered.endswith((".raises", ".warns")):
                        dimensions["negative_or_exception"].add(path)
                    if any(
                        token in lowered for token in ("mock", "patch", "monkeypatch")
                    ):
                        dimensions["mock_or_isolation"].add(path)
                    if any(
                        token in lowered
                        for token in ("thread", "gather", "create_task")
                    ):
                        dimensions["concurrency"].add(path)
            elif isinstance(node, ast.Assert):
                dimensions["assertion"].add(path)
            elif isinstance(node, ast.AsyncFunctionDef):
                dimensions["async"].add(path)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(
                    "parametrize"
                    in _dotted_name(
                        value.func if isinstance(value, ast.Call) else value
                    ).casefold()
                    for value in node.decorator_list
                ):
                    dimensions["parameterized"].add(path)
        lowered_content = content.casefold()
        if "hypothesis" in lowered_content or "@given" in lowered_content:
            dimensions["property_based"].add(path)
        if any(token in lowered_content for token in ("timeout", "deadline", "clock")):
            dimensions["timing"].add(path)
        if any(
            token in lowered_content
            for token in ("fault", "failure injection", "chaos", "circuit breaker")
        ):
            dimensions["fault_injection_or_resilience"].add(path)
    return (
        {name: sorted(paths)[:5] for name, paths in symbol_paths.items()},
        {
            "format": "pysfmea-static-test-evidence-analysis-1",
            "authority": "static_test_structure_candidates_not_execution_or_test_adequacy",
            "indexed_files": len(tests),
            "parsed_files": len(tests) - len(parse_errors),
            "parse_error_files": parse_errors[:25],
            "parse_error_files_omitted": max(0, len(parse_errors) - 25),
            "dimensions": {
                name: {
                    "files": len(paths),
                    "percent": round(100 * len(paths) / len(tests), 1)
                    if tests
                    else 100.0,
                    "sample_paths": sorted(paths)[:25],
                    "sample_paths_omitted": max(0, len(paths) - 25),
                }
                for name, paths in sorted(dimensions.items())
            },
        },
    )


def _find_test_references(
    name: str, reference_index: dict[str, list[str]]
) -> list[str]:
    return reference_index.get(name, [])[:5]


MAX_COVERAGE_JSON_BYTES = 100_000_000
MAX_COVERAGE_JSON_DEPTH = 100
MAX_COVERAGE_JSON_NODES = 2_000_000
MAX_COVERAGE_FILE_RECORDS = 100_000
MAX_COVERAGE_PATH_CHARS = 4_096


def _coverage_warning(path: Path, message: str) -> dict[str, str]:
    return {"path": str(path), "message": message, "type": "CoverageError"}


def _normalize_coverage_file(value: Any) -> tuple[dict[str, Any] | None, bool]:
    """Keep only typed coverage.py line/branch evidence used by the scanner."""

    if not isinstance(value, dict):
        return None, True
    malformed = False
    normalized: dict[str, Any] = {}
    for key in ("executed_lines", "missing_lines"):
        supplied = value.get(key, [])
        if not isinstance(supplied, list):
            supplied = []
            malformed = True
        accepted_lines = [
            entry
            for entry in supplied
            if isinstance(entry, int) and not isinstance(entry, bool) and entry > 0
        ]
        malformed = malformed or len(accepted_lines) != len(supplied)
        normalized[key] = accepted_lines
    for key in ("executed_branches", "missing_branches"):
        supplied = value.get(key, [])
        if not isinstance(supplied, list):
            supplied = []
            malformed = True
        accepted_branches = [
            [int(entry[0]), int(entry[1])]
            for entry in supplied
            if isinstance(entry, list)
            and len(entry) == 2
            and isinstance(entry[0], int)
            and not isinstance(entry[0], bool)
            and entry[0] > 0
            and isinstance(entry[1], int)
            and not isinstance(entry[1], bool)
            and entry[1] != 0
        ]
        malformed = malformed or len(accepted_branches) != len(supplied)
        normalized[key] = accepted_branches
    return normalized, malformed


def _load_coverage_document(
    path: str | Path | None,
    root: Path,
    evidence_snapshots: dict[Path, bytes] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    if not path:
        return {}, [], {}
    coverage_path = Path(path).expanduser()
    if not coverage_path.is_absolute():
        coverage_path = root / coverage_path
    coverage_path = coverage_path.absolute()
    try:
        document = load_bounded_json_document(
            coverage_path,
            label="coverage JSON",
            max_bytes=MAX_COVERAGE_JSON_BYTES,
            max_depth=MAX_COVERAGE_JSON_DEPTH,
            max_nodes=MAX_COVERAGE_JSON_NODES,
        )
    except ValueError as exc:
        message = str(exc)
        if message == f"coverage JSON exceeds the {MAX_COVERAGE_JSON_BYTES}-byte limit":
            message = (
                f"coverage JSON exceeds the {MAX_COVERAGE_JSON_BYTES}-byte import limit"
            )
        elif message in {
            "coverage JSON is not valid UTF-8 JSON",
            "coverage JSON is not valid JSON",
            "coverage JSON exceeds the JSON parser nesting limit",
        }:
            message = "coverage JSON is not valid bounded UTF-8 JSON"
        elif message in {
            "coverage JSON must be an available regular file",
            "coverage JSON must be a regular non-symbolic-link file",
        }:
            message = "coverage JSON must be a regular non-symbolic-link file"
        return {}, [_coverage_warning(coverage_path, message)], {}
    coverage_path = document.path
    try:
        coverage_path.relative_to(root)
    except ValueError:
        pass
    else:
        if evidence_snapshots is not None:
            evidence_snapshots[coverage_path] = document.raw
    payload = document.value
    if not isinstance(payload, dict):
        return (
            {},
            [_coverage_warning(coverage_path, "coverage JSON root must be an object")],
            {},
        )
    if "files" not in payload:
        return (
            {},
            [_coverage_warning(coverage_path, "coverage JSON has no files object")],
            {},
        )
    files = payload["files"]
    if not isinstance(files, dict):
        return (
            {},
            [_coverage_warning(coverage_path, "coverage JSON has no files object")],
            {},
        )
    if len(files) > MAX_COVERAGE_FILE_RECORDS:
        return (
            {},
            [
                _coverage_warning(
                    coverage_path,
                    "coverage JSON exceeds the "
                    f"{MAX_COVERAGE_FILE_RECORDS}-file record limit",
                )
            ],
            {},
        )
    indexed: dict[str, Any] = {}
    ignored_paths = 0
    malformed_records = 0
    duplicate_paths = 0
    for raw_path, value in files.items():
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or len(raw_path) > MAX_COVERAGE_PATH_CHARS
        ):
            ignored_paths += 1
            continue
        candidate = Path(raw_path)
        if candidate.is_absolute():
            try:
                key = candidate.resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                ignored_paths += 1
                continue
        else:
            if ".." in candidate.parts or not candidate.parts:
                ignored_paths += 1
                continue
            key = candidate.as_posix()
            if key.startswith("./"):
                key = key[2:]
        normalized, malformed = _normalize_coverage_file(value)
        if normalized is None:
            malformed_records += 1
            continue
        if key in indexed:
            duplicate_paths += 1
            continue
        indexed[key] = normalized
        malformed_records += int(malformed)
    warnings = []
    if ignored_paths or malformed_records or duplicate_paths:
        warnings.append(
            _coverage_warning(
                coverage_path,
                "coverage JSON ignored unsafe paths, malformed records, or duplicate normalized "
                f"paths (unsafe={ignored_paths}, malformed={malformed_records}, "
                f"duplicates={duplicate_paths})",
            )
        )
    provenance = {
        "format": "coverage.py-json",
        "path": str(coverage_path),
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "file_records": len(files),
        "accepted_file_records": len(indexed),
        "coverage_generated_at": (
            payload.get("meta", {}).get("timestamp", "")
            if isinstance(payload.get("meta"), dict)
            and isinstance(payload.get("meta", {}).get("timestamp", ""), str)
            else ""
        ),
        "coverage_tool_version": (
            payload.get("meta", {}).get("version", "")
            if isinstance(payload.get("meta"), dict)
            and isinstance(payload.get("meta", {}).get("version", ""), str)
            else ""
        ),
        "branch_coverage": (
            payload.get("meta", {}).get("branch_coverage")
            if isinstance(payload.get("meta"), dict)
            and isinstance(payload.get("meta", {}).get("branch_coverage"), bool)
            else None
        ),
    }
    return indexed, warnings, provenance


def _load_coverage(
    path: str | Path | None, root: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compatibility wrapper for callers that do not consume coverage provenance."""

    indexed, warnings, _provenance = _load_coverage_document(path, root)
    return indexed, warnings


def _function_coverage(
    facts: FunctionFacts, coverage: dict[str, Any]
) -> dict[str, Any] | None:
    return _line_range_coverage(facts.path, facts.line, facts.end_line, coverage)


def _line_range_coverage(
    path: str, start_line: int, end_line: int, coverage: dict[str, Any]
) -> dict[str, Any] | None:
    file_data = coverage.get(path)
    if not isinstance(file_data, dict):
        return None
    executed = {
        observed_line
        for observed_line in file_data.get("executed_lines", [])
        if start_line <= observed_line <= end_line
    }
    missing = {
        observed_line
        for observed_line in file_data.get("missing_lines", [])
        if start_line <= observed_line <= end_line
    }
    relevant = executed | missing
    executed_branches = [
        branch
        for branch in file_data.get("executed_branches", [])
        if isinstance(branch, list)
        and len(branch) == 2
        and start_line <= branch[0] <= end_line
    ]
    missing_branches = [
        branch
        for branch in file_data.get("missing_branches", [])
        if isinstance(branch, list)
        and len(branch) == 2
        and start_line <= branch[0] <= end_line
    ]
    branch_total = len(executed_branches) + len(missing_branches)
    if not relevant:
        return {
            "line_percent": None,
            "covered_lines": 0,
            "missing_lines": 0,
            "branch_percent": round(100 * len(executed_branches) / branch_total, 1)
            if branch_total
            else None,
            "covered_branches": len(executed_branches),
            "missing_branches": len(missing_branches),
        }
    return {
        "line_percent": round(100 * len(executed) / len(relevant), 1),
        "covered_lines": len(executed),
        "missing_lines": len(missing),
        "branch_percent": round(100 * len(executed_branches) / branch_total, 1)
        if branch_total
        else None,
        "covered_branches": len(executed_branches),
        "missing_branches": len(missing_branches),
    }


def _source_range_coverage(
    source: dict[str, Any], coverage: dict[str, Any]
) -> dict[str, Any] | None:
    """Project coverage onto a persisted component without reparsing source code."""

    path = source.get("path")
    line = source.get("line")
    end_line = source.get("end_line")
    if not (
        isinstance(path, str)
        and path
        and isinstance(line, int)
        and not isinstance(line, bool)
        and line > 0
        and isinstance(end_line, int)
        and not isinstance(end_line, bool)
        and end_line >= line
    ):
        return None
    return _line_range_coverage(path, line, end_line, coverage)


def import_coverage_evidence(
    analysis: dict[str, Any], source: str | Path
) -> dict[str, Any]:
    """Import one bounded coverage.py JSON artifact into a governed analysis.

    This is an evidence projection only. It does not execute tests or claim that a
    covered line exercised a failure stimulus, oracle, or acceptance criterion.
    """

    root = Path(str(analysis.get("project", {}).get("root", ""))).expanduser()
    if not root.is_absolute():
        root = root.absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("analysis repository root must be a regular directory")
    coverage, warnings, provenance = _load_coverage_document(source, root)
    if warnings:
        raise ValueError(str(warnings[0].get("message", "coverage import failed")))
    if not provenance or not coverage:
        raise ValueError("coverage JSON contains no accepted file evidence")

    settings = analysis.setdefault("project", {}).setdefault("settings", {})
    previous = settings.get("coverage_evidence", {})
    if isinstance(previous, dict) and previous.get("sha256") == provenance.get(
        "sha256"
    ):
        return {
            "id": "COVERAGE-" + str(provenance["sha256"])[:12].upper(),
            "sha256": provenance["sha256"],
            "duplicate": True,
            "components": sum(
                isinstance(value, dict) and value.get("coverage") is not None
                for value in analysis.get("components", [])
            ),
            "files": provenance["accepted_file_records"],
            "notice": "The exact coverage artifact was already projected.",
        }

    components = analysis.get("components")
    items = analysis.get("items")
    if not isinstance(components, list) or not isinstance(items, list):
        raise ValueError("analysis components and findings must be lists")
    projected: dict[str, dict[str, Any]] = {}
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("analysis component records must be objects")
        value = _source_range_coverage(component.get("source", {}), coverage)
        component["coverage"] = value
        component_id = component.get("id")
        if isinstance(component_id, str) and value is not None:
            projected[component_id] = value

    prefixes = (
        "Coverage.py observed lines in function:",
        "Coverage.py observed branches in function:",
    )
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("analysis finding records must be objects")
        scanner = item.get("scanner")
        if not isinstance(scanner, dict) or not isinstance(
            scanner.get("evidence"), list
        ):
            raise ValueError("analysis finding scanner evidence must be a list")
        evidence = [
            value
            for value in scanner["evidence"]
            if not (isinstance(value, str) and value.startswith(prefixes))
        ]
        value = projected.get(str(item.get("component_id", "")))
        if value is not None:
            evidence.append(
                "Coverage.py observed lines in function: "
                f"{value.get('covered_lines', 0)} covered, "
                f"{value.get('missing_lines', 0)} missing"
            )
            if value.get("branch_percent") is not None:
                evidence.append(
                    "Coverage.py observed branches in function: "
                    f"{value.get('covered_branches', 0)} covered, "
                    f"{value.get('missing_branches', 0)} missing"
                )
        scanner["evidence"] = evidence

    provenance = {**provenance, "selection": "evidence_onboarding"}
    settings["coverage_json"] = str(provenance["path"])
    settings["coverage_evidence"] = provenance
    imported_at = utc_now()
    record = {
        "id": "COVERAGE-" + str(provenance["sha256"])[:12].upper(),
        "sha256": provenance["sha256"],
        "duplicate": False,
        "components": len(projected),
        "files": provenance["accepted_file_records"],
        "imported_at": imported_at,
        "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", ""),
        "notice": (
            "Coverage records observed line and branch execution only; they do not prove "
            "failure-stimulus, oracle, or requirement satisfaction."
        ),
    }
    analysis.setdefault("history", []).append(
        {"event": "coverage_evidence_import", "at": imported_at, **record}
    )
    return record


def _component_ref(facts: FunctionFacts) -> str:
    return f"{facts.path}:{facts.qualname}"


def _critical_context(
    facts: FunctionFacts, entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    reference = _component_ref(facts)
    return [
        entry
        for entry in entries
        if fnmatch.fnmatchcase(reference, entry.get("pattern", ""))
    ]


def _mapping_context(
    facts: FunctionFacts, entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    reference = _component_ref(facts)
    return [
        entry
        for entry in entries
        if fnmatch.fnmatchcase(reference, entry.get("pattern", ""))
    ]


def _module_suffixes(path: str) -> list[str]:
    parts = list(Path(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return [".".join(parts[index:]) for index in range(len(parts)) if parts[index:]]


def _internal_resolution_indexes(
    facts_list: list[FunctionFacts],
) -> tuple[dict[tuple[str, str], list[FunctionFacts]], dict[str, list[FunctionFacts]]]:
    by_file_name: dict[tuple[str, str], list[FunctionFacts]] = {}
    by_full: dict[str, list[FunctionFacts]] = {}
    for target in facts_list:
        by_file_name.setdefault((target.path, target.name), []).append(target)
        by_full.setdefault(target.qualname, []).append(target)
        for module in _module_suffixes(target.path):
            by_full.setdefault(f"{module}.{target.qualname}", []).append(target)
            by_full.setdefault(f"{module}.{target.name}", []).append(target)
    return by_file_name, by_full


def _resolve_internal_targets(
    caller: FunctionFacts,
    called: str,
    by_file_name: dict[tuple[str, str], list[FunctionFacts]],
    by_full: dict[str, list[FunctionFacts]],
) -> list[FunctionFacts]:
    caller_class = caller.qualname.rsplit(".", 1)[0] if "." in caller.qualname else ""
    targets: list[FunctionFacts] = []
    if "." not in called:
        targets = by_file_name.get((caller.path, called), [])
        if len(targets) > 1:
            caller_scope = caller.qualname.split(".")[:-1]
            scored = [
                (
                    sum(
                        1
                        for left, right in zip(
                            caller_scope, target.qualname.split(".")[:-1]
                        )
                        if left == right
                    ),
                    target,
                )
                for target in targets
            ]
            best = max(score for score, _target in scored)
            targets = [target for score, target in scored if score == best]
    elif called.startswith(("self.", "cls.")) and caller_class:
        method = called.rsplit(".", 1)[-1]
        targets = [
            target
            for target in by_file_name.get((caller.path, method), [])
            if target.qualname == f"{caller_class}.{method}"
        ]
    else:
        targets = by_full.get(called, [])
    unique: dict[str, FunctionFacts] = {}
    for target in targets:
        unique[_component_ref(target)] = target
    return [unique[key] for key in sorted(unique)]


def _internal_call_resolution(
    facts_list: list[FunctionFacts],
) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
    by_file_name, by_full = _internal_resolution_indexes(facts_list)

    callers: dict[str, set[str]] = {
        _component_ref(target): set() for target in facts_list
    }
    resolved_calls: dict[str, set[str]] = {
        _component_ref(caller): set() for caller in facts_list
    }
    for caller in facts_list:
        caller_ref = _component_ref(caller)
        for called in caller.calls:
            targets = _resolve_internal_targets(caller, called, by_file_name, by_full)
            for target in targets:
                target_ref = _component_ref(target)
                if target_ref != caller_ref:
                    callers[target_ref].add(caller_ref)
                    resolved_calls[caller_ref].add(called)
    return (
        {key: sorted(value) for key, value in callers.items()},
        resolved_calls,
    )


def _argument_parameter_binding(
    argument: dict[str, Any], target: FunctionFacts
) -> dict[str, Any]:
    keyword = str(argument.get("keyword", ""))
    unpacked = bool(argument.get("unpacked", False))
    contracts = target.parameter_contracts
    matched: dict[str, Any] | None = None
    status = "unresolved"
    if unpacked:
        status = "unpacked_requires_runtime_resolution"
    elif keyword:
        matched = next(
            (value for value in contracts if value.get("name") == keyword), None
        )
        if matched is None:
            matched = next(
                (value for value in contracts if value.get("kind") == "var_keyword"),
                None,
            )
        status = "bound" if matched is not None else "unknown_keyword"
    else:
        position = int(argument.get("position", -1) or 0)
        matched = next(
            (value for value in contracts if value.get("position") == position), None
        )
        if matched is None:
            matched = next(
                (value for value in contracts if value.get("kind") == "var_positional"),
                None,
            )
        status = "bound" if matched is not None else "excess_positional"
    return {
        **copy.deepcopy(argument),
        "target_parameter": str(matched.get("name", "")) if matched else "",
        "target_parameter_kind": str(matched.get("kind", "")) if matched else "",
        "binding_status": status,
    }


def _interprocedural_data_flow(facts_list: list[FunctionFacts]) -> dict[str, Any]:
    """Build bounded, path-insensitive call argument and result-flow records."""

    by_file_name, by_full = _internal_resolution_indexes(facts_list)
    edges: list[dict[str, Any]] = []
    total_candidates = 0
    ambiguous_sites = 0
    unresolved_sites = 0
    argument_bindings = 0
    return_flows = 0
    attribute_flows = 0
    container_flows = 0
    for caller in sorted(facts_list, key=_component_ref):
        caller_ref = _component_ref(caller)
        for site in caller.call_sites:
            called = str(site.get("reference", ""))
            targets = _resolve_internal_targets(caller, called, by_file_name, by_full)
            if not targets:
                unresolved_sites += 1
                continue
            if len(targets) > 1:
                ambiguous_sites += 1
            for target in targets:
                total_candidates += 1
                if len(edges) >= MAX_INTERPROCEDURAL_FLOW_EDGES:
                    continue
                arguments = [
                    _argument_parameter_binding(argument, target)
                    for argument in site.get("arguments", [])
                    if isinstance(argument, dict)
                ]
                argument_bindings += sum(
                    value["binding_status"] == "bound" for value in arguments
                )
                raw_result_context = site.get("result_context")
                result_context = (
                    copy.deepcopy(raw_result_context)
                    if isinstance(raw_result_context, dict)
                    and raw_result_context.get("kind")
                    else {"kind": "discarded"}
                )
                target_returns = copy.deepcopy(target.return_values)
                if target_returns and result_context.get("kind") != "discarded":
                    return_flows += 1
                edge_attribute_flows = sum(
                    symbol.get("kind") == "attribute"
                    for value in arguments
                    for symbol in value.get("symbols", [])
                    if isinstance(symbol, dict)
                ) + int(result_context.get("kind") == "attribute")
                edge_container_flows = sum(
                    value.get("kind") in {"container", "container_item"}
                    or any(
                        isinstance(symbol, dict)
                        and symbol.get("kind") == "container_item"
                        for symbol in value.get("symbols", [])
                    )
                    for value in arguments
                ) + int(result_context.get("kind") == "container_item")
                attribute_flows += edge_attribute_flows
                container_flows += edge_container_flows
                target_ref = _component_ref(target)
                edge = {
                    "id": stable_id(
                        "DATA-FLOW",
                        caller_ref,
                        target_ref,
                        str(site.get("line", 0)),
                        str(site.get("column", 0)),
                        str(site.get("order", 0)),
                    ),
                    "caller_component_id": stable_id(
                        "CMP", caller.path, caller.qualname, caller.kind
                    ),
                    "caller_reference": caller_ref,
                    "callee_component_id": stable_id(
                        "CMP", target.path, target.qualname, target.kind
                    ),
                    "callee_reference": target_ref,
                    "call_reference": called,
                    "call_site": {
                        key: copy.deepcopy(site.get(key))
                        for key in (
                            "line",
                            "column",
                            "order",
                            "control_context",
                            "awaited",
                        )
                    },
                    "resolution": "unique_static_target"
                    if len(targets) == 1
                    else "ambiguous_static_candidates",
                    "arguments": arguments,
                    "arguments_omitted": int(site.get("arguments_omitted", 0) or 0),
                    "result_flow": {
                        "context": result_context,
                        "callee_return_values": target_returns,
                        "observed": bool(
                            target_returns and result_context.get("kind") != "discarded"
                        ),
                    },
                    "flow_dimensions": {
                        "parameter": bool(arguments),
                        "return": bool(
                            target_returns and result_context.get("kind") != "discarded"
                        ),
                        "attribute": bool(edge_attribute_flows),
                        "container": bool(edge_container_flows),
                    },
                    "authority": "bounded_path_insensitive_static_value_flow_not_runtime_taint_or_semantic_equivalence",
                }
                edges.append(edge)
    return {
        "format": "pysfmea-interprocedural-data-flow-1",
        "summary": {
            "resolved_call_edges": total_candidates,
            "embedded_edges": len(edges),
            "edges_omitted": max(0, total_candidates - len(edges)),
            "truncated": total_candidates > len(edges),
            "embedded_argument_bindings": argument_bindings,
            "embedded_return_flows": return_flows,
            "embedded_attribute_flows": attribute_flows,
            "embedded_container_flows": container_flows,
            "ambiguous_call_sites": ambiguous_sites,
            "unresolved_call_sites": unresolved_sites,
        },
        "edges": edges,
        "limits": {
            "edges": MAX_INTERPROCEDURAL_FLOW_EDGES,
            "arguments_per_call_kind": MAX_FLOW_ARGUMENTS_PER_CALL,
            "symbols_per_expression": MAX_FLOW_SYMBOLS_PER_EXPRESSION,
        },
        "limitations": [
            "The model is intra-repository, path-insensitive, and based on conservative static call resolution.",
            "Reflection, dynamic dispatch, decorators, descriptors, mutation through aliases, and native code can create unmodeled flows.",
            "A recorded value path does not establish data validity, confidentiality, hazard causality, or runtime reachability.",
        ],
        "authority": "static_discovery_projection_requires_runtime_and_engineering_corroboration",
    }


def _alias_object_flow(facts_list: list[FunctionFacts]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    total = 0
    source_omitted = 0
    for facts in sorted(facts_list, key=_component_ref):
        source_omitted += facts.alias_bindings_omitted
        component_id = stable_id("CMP", facts.path, facts.qualname, facts.kind)
        for binding in facts.alias_bindings:
            total += 1
            if len(records) >= MAX_ALIAS_OBJECT_FLOW_RECORDS:
                continue
            records.append(
                {
                    **copy.deepcopy(binding),
                    "component_id": component_id,
                    "component_reference": _component_ref(facts),
                }
            )
    kinds = Counter(str(value.get("binding_kind", "unknown")) for value in records)
    omitted = source_omitted + max(0, total - len(records))
    return {
        "format": "pysfmea-alias-object-flow-1",
        "summary": {
            "bindings_discovered": total + source_omitted,
            "embedded_bindings": len(records),
            "bindings_omitted": omitted,
            "truncated": omitted > 0,
            "by_kind": dict(sorted(kinds.items())),
            "bindings_with_expanded_alias_origins": sum(
                bool(symbol.get("alias_origins"))
                for value in records
                for symbol in value.get("source", {}).get("symbols", [])
                if isinstance(symbol, dict)
            ),
        },
        "records": records,
        "limits": {
            "bindings_per_component": MAX_ALIAS_BINDINGS_PER_COMPONENT,
            "bindings_total": MAX_ALIAS_OBJECT_FLOW_RECORDS,
            "origins_per_expression": MAX_FLOW_SYMBOLS_PER_EXPRESSION,
        },
        "limitations": [
            "Bindings are local, order-aware, and path-insensitive; branch joins are conservative.",
            "Mutation through aliases, descriptors, reflection, closures, globals, and native extensions can escape the model.",
            "Object-flow records describe static value movement and do not prove ownership, lifetime, identity, or runtime reachability.",
        ],
        "authority": "bounded_static_alias_and_object_flow_not_heap_or_taint_soundness",
    }


def _concurrency_model(facts_list: list[FunctionFacts]) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []
    embedded_operation_ids: set[str] = set()
    total_operations = 0
    total_relations = 0
    spawn_names = {"create_task", "ensure_future", "submit", "start_soon"}
    join_names = {"gather", "wait", "wait_for", "as_completed", "join"}
    cancellation_names = {"cancel", "cancelled", "shield", "timeout"}
    synchronization_names = {
        "acquire",
        "release",
        "set",
        "clear",
        "wait",
        "notify",
        "notify_all",
    }
    for facts in sorted(facts_list, key=_component_ref):
        local: list[dict[str, Any]] = []
        for site in facts.call_sites:
            reference = str(site.get("reference", ""))
            leaf = reference.rsplit(".", 1)[-1].casefold()
            contexts = [str(value) for value in site.get("control_context", [])]
            synchronized_scope = any(
                ("with@" in value or "async-with@" in value)
                and any(
                    token in value.casefold()
                    for token in ("lock", "semaphore", "condition")
                )
                for value in contexts
            )
            categories: list[str] = []
            if leaf in spawn_names:
                categories.append("task_spawn")
            if leaf in join_names:
                categories.append("task_join_or_wait")
            if leaf in cancellation_names:
                categories.append("cancellation_or_timeout")
            if leaf in synchronization_names or synchronized_scope:
                categories.append("synchronization")
            if bool(site.get("awaited")):
                categories.append("await_completion")
            if not categories:
                continue
            total_operations += 1
            identifier = stable_id(
                "CONCURRENCY-OP",
                _component_ref(facts),
                str(site.get("line", 0)),
                str(site.get("column", 0)),
                str(site.get("order", 0)),
                reference,
            )
            operation = {
                "id": identifier,
                "component_id": stable_id(
                    "CMP", facts.path, facts.qualname, facts.kind
                ),
                "component_reference": _component_ref(facts),
                "reference": reference,
                "line": int(site.get("line", 0) or 0),
                "order": int(site.get("order", 0) or 0),
                "categories": categories,
                "control_context": contexts,
                "synchronized_scope": synchronized_scope,
                "authority": "static_concurrency_operation_candidate",
            }
            local.append(operation)
            if len(operations) < MAX_CONCURRENCY_OPERATIONS:
                operations.append(operation)
                embedded_operation_ids.add(identifier)
        local.sort(key=lambda value: (int(value["order"]), str(value["id"])))
        for left, right in zip(local, local[1:]):
            relation_kinds = ["lexical_program_order"]
            if "await_completion" in left["categories"]:
                relation_kinds.append("await_completion_before_next_operation")
            for kind in relation_kinds:
                total_relations += 1
                if (
                    left["id"] in embedded_operation_ids
                    and right["id"] in embedded_operation_ids
                    and len(relations) < MAX_CONCURRENCY_RELATIONS
                ):
                    relations.append(
                        {
                            "id": stable_id(
                                "CONCURRENCY-REL",
                                str(left["id"]),
                                str(right["id"]),
                                kind,
                            ),
                            "source_operation_id": left["id"],
                            "target_operation_id": right["id"],
                            "kind": kind,
                            "component_id": left["component_id"],
                            "authority": "lexical_order_candidate_not_path_feasible_happens_before_proof",
                        }
                    )
        spawns = [value for value in local if "task_spawn" in value["categories"]]
        joins = [value for value in local if "task_join_or_wait" in value["categories"]]
        for spawn in spawns:
            later = next(
                (value for value in joins if int(value["order"]) > int(spawn["order"])),
                None,
            )
            if later is None:
                continue
            total_relations += 1
            if (
                spawn["id"] in embedded_operation_ids
                and later["id"] in embedded_operation_ids
                and len(relations) < MAX_CONCURRENCY_RELATIONS
            ):
                relations.append(
                    {
                        "id": stable_id(
                            "CONCURRENCY-REL",
                            str(spawn["id"]),
                            str(later["id"]),
                            "spawn_to_join",
                        ),
                        "source_operation_id": spawn["id"],
                        "target_operation_id": later["id"],
                        "kind": "spawn_to_later_join_candidate",
                        "component_id": spawn["component_id"],
                        "authority": "lexical_pairing_candidate_requires_runtime_task_identity",
                    }
                )
    operation_counts = Counter(
        category for value in operations for category in value["categories"]
    )
    relation_counts = Counter(str(value["kind"]) for value in relations)
    return {
        "format": "pysfmea-concurrency-model-1",
        "summary": {
            "operations_discovered": total_operations,
            "operations_embedded": len(operations),
            "operations_omitted": max(0, total_operations - len(operations)),
            "relations_discovered": total_relations,
            "relations_embedded": len(relations),
            "relations_omitted": max(0, total_relations - len(relations)),
            "operation_categories": dict(sorted(operation_counts.items())),
            "relation_kinds": dict(sorted(relation_counts.items())),
            "truncated": total_operations > len(operations)
            or total_relations > len(relations),
        },
        "operations": operations,
        "relations": relations,
        "limits": {
            "operations": MAX_CONCURRENCY_OPERATIONS,
            "relations": MAX_CONCURRENCY_RELATIONS,
        },
        "limitations": [
            "Lexical relations are path-insensitive and do not establish a complete happens-before graph.",
            "Task identity, scheduler behavior, cancellation delivery, lock ownership, deadlock freedom, and race freedom require runtime or formal evidence.",
            "Dynamic task creation and framework-specific concurrency semantics may be unresolved.",
        ],
        "authority": "bounded_static_concurrency_model_not_scheduling_or_race_proof",
    }


def _exception_type_matches(exception_type: str, handler_types: list[str]) -> bool:
    exception_leaf = exception_type.rsplit(".", 1)[-1]
    return any(
        handler_type.rsplit(".", 1)[-1]
        in {exception_leaf, "Exception", "BaseException"}
        for handler_type in handler_types
    )


def _active_try_lines(control_context: list[Any]) -> list[int]:
    lines: list[int] = []
    for raw in control_context:
        match = re.fullmatch(r"try@(\d+):body", str(raw))
        if match:
            lines.append(int(match.group(1)))
    return lines


def _exception_propagation_model(facts_list: list[FunctionFacts]) -> dict[str, Any]:
    """Build a bounded, lexical typed-exception propagation approximation."""

    by_file_name, by_full = _internal_resolution_indexes(facts_list)
    handlers_by_component: dict[str, dict[int, list[dict[str, Any]]]] = {}
    outgoing: dict[str, set[str]] = {}
    locally_caught_raises = 0
    for facts in facts_list:
        reference = _component_ref(facts)
        by_try_line: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for handler in facts.exception_handlers:
            by_try_line[int(handler.get("try_line", 0))].append(handler)
        handlers_by_component[reference] = by_try_line
        outgoing[reference] = set()
        for raised in facts.exception_raises:
            exception_type = str(
                raised.get("exception_type", "unknown_exception_expression")
            )
            active_handlers = [
                handler
                for line in _active_try_lines(raised.get("control_context", []))
                for handler in by_try_line.get(line, [])
            ]
            if any(
                _exception_type_matches(
                    exception_type,
                    [str(value) for value in handler.get("exception_types", [])],
                )
                for handler in active_handlers
            ):
                locally_caught_raises += 1
            else:
                outgoing[reference].add(exception_type)

    changed = True
    iterations = 0
    while changed and iterations <= len(facts_list):
        changed = False
        iterations += 1
        for caller in sorted(facts_list, key=_component_ref):
            caller_reference = _component_ref(caller)
            by_try_line = handlers_by_component.get(caller_reference, {})
            for site in caller.call_sites:
                called = str(site.get("reference", ""))
                targets = _resolve_internal_targets(
                    caller,
                    called,
                    by_file_name,
                    by_full,
                )
                for target in targets:
                    target_reference = _component_ref(target)
                    for exception_type in sorted(outgoing.get(target_reference, set())):
                        active_handlers = [
                            handler
                            for line in _active_try_lines(
                                site.get("control_context", [])
                            )
                            for handler in by_try_line.get(line, [])
                        ]
                        matching = [
                            handler
                            for handler in active_handlers
                            if _exception_type_matches(
                                exception_type,
                                [
                                    str(value)
                                    for value in handler.get("exception_types", [])
                                ],
                            )
                        ]
                        if (
                            not matching
                            and exception_type not in outgoing[caller_reference]
                        ):
                            outgoing[caller_reference].add(exception_type)
                            changed = True

    edges: list[dict[str, Any]] = []
    total_edges = 0
    for caller in sorted(facts_list, key=_component_ref):
        caller_reference = _component_ref(caller)
        by_try_line = handlers_by_component.get(caller_reference, {})
        for site in caller.call_sites:
            targets = _resolve_internal_targets(
                caller,
                str(site.get("reference", "")),
                by_file_name,
                by_full,
            )
            resolution = (
                "unique_static_target"
                if len(targets) == 1
                else "ambiguous_static_candidates"
            )
            for target in targets:
                target_reference = _component_ref(target)
                for exception_type in sorted(outgoing.get(target_reference, set())):
                    active_handlers = [
                        handler
                        for line in _active_try_lines(site.get("control_context", []))
                        for handler in by_try_line.get(line, [])
                    ]
                    matching = [
                        handler
                        for handler in active_handlers
                        if _exception_type_matches(
                            exception_type,
                            [
                                str(value)
                                for value in handler.get("exception_types", [])
                            ],
                        )
                    ]
                    disposition = (
                        "caught_by_lexical_handler" if matching else "may_propagate"
                    )
                    total_edges += 1
                    if len(edges) < MAX_EXCEPTION_PROPAGATION_EDGES:
                        edges.append(
                            {
                                "id": stable_id(
                                    "EXCEPTION-PROPAGATION",
                                    caller_reference,
                                    target_reference,
                                    str(site.get("line", 0)),
                                    str(site.get("order", 0)),
                                    exception_type,
                                    disposition,
                                ),
                                "caller_component_id": stable_id(
                                    "CMP", caller.path, caller.qualname, caller.kind
                                ),
                                "caller_reference": caller_reference,
                                "callee_component_id": stable_id(
                                    "CMP", target.path, target.qualname, target.kind
                                ),
                                "callee_reference": target_reference,
                                "call_site": {
                                    "line": int(site.get("line", 0) or 0),
                                    "column": int(site.get("column", 0) or 0),
                                    "order": int(site.get("order", 0) or 0),
                                    "reference": str(site.get("reference", "")),
                                },
                                "exception_type": exception_type,
                                "disposition": disposition,
                                "handler_ids": [
                                    str(value.get("id", "")) for value in matching
                                ],
                                "resolution": resolution,
                                "authority": "bounded_lexical_typed_exception_propagation_candidate",
                            }
                        )
    raises: list[dict[str, Any]] = []
    handlers: list[dict[str, Any]] = []
    raises_discovered = 0
    handlers_discovered = 0
    source_omitted = 0
    for facts in sorted(facts_list, key=_component_ref):
        source_omitted += facts.exception_records_omitted
        for record in facts.exception_raises:
            raises_discovered += 1
            if len(raises) < MAX_EXCEPTION_RAISE_RECORDS:
                raises.append(
                    {
                        **copy.deepcopy(record),
                        "component_id": stable_id(
                            "CMP", facts.path, facts.qualname, facts.kind
                        ),
                        "component_reference": _component_ref(facts),
                    }
                )
        for record in facts.exception_handlers:
            handlers_discovered += 1
            if len(handlers) < MAX_EXCEPTION_HANDLER_RECORDS:
                handlers.append(
                    {
                        **copy.deepcopy(record),
                        "component_id": stable_id(
                            "CMP", facts.path, facts.qualname, facts.kind
                        ),
                        "component_reference": _component_ref(facts),
                    }
                )
    source_omitted += raises_discovered - len(raises)
    source_omitted += handlers_discovered - len(handlers)
    return {
        "format": "pysfmea-exception-propagation-1",
        "summary": {
            "raise_records_discovered": raises_discovered,
            "raise_records_embedded": len(raises),
            "handler_records_discovered": handlers_discovered,
            "handler_records_embedded": len(handlers),
            "source_records_omitted": source_omitted,
            "propagation_edges_discovered": total_edges,
            "propagation_edges_embedded": len(edges),
            "propagation_edges_omitted": total_edges - len(edges),
            "locally_caught_raise_candidates": locally_caught_raises,
            "outgoing_exception_types": sum(len(value) for value in outgoing.values()),
            "fixed_point_iterations": iterations,
            "truncated": bool(source_omitted or total_edges > len(edges)),
        },
        "raises": raises,
        "handlers": handlers,
        "edges": edges,
        "limits": {
            "records_per_component": MAX_EXCEPTION_RECORDS_PER_COMPONENT,
            "raise_records": MAX_EXCEPTION_RAISE_RECORDS,
            "handler_records": MAX_EXCEPTION_HANDLER_RECORDS,
            "propagation_edges": MAX_EXCEPTION_PROPAGATION_EDGES,
        },
        "limitations": [
            "Handler matching uses statically named exception types and broad-base recognition; inheritance and runtime aliases are not resolved.",
            "Propagation is path-insensitive beyond lexical try-body scope and does not model ExceptionGroup splitting, callbacks, generators, native extensions, or dynamic dispatch completely.",
            "A propagation edge is a conservative review candidate, not proof that the call or exception is runtime reachable.",
        ],
        "authority": "bounded_typed_static_exception_model_not_runtime_or_path_proof",
    }


def _state_machine_model(facts_list: list[FunctionFacts]) -> dict[str, Any]:
    guards: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    guards_discovered = 0
    transitions_discovered = 0
    source_omitted = 0
    for facts in sorted(facts_list, key=_component_ref):
        component_id = stable_id("CMP", facts.path, facts.qualname, facts.kind)
        component_reference = _component_ref(facts)
        source_omitted += facts.state_records_omitted
        for guard in facts.state_guards:
            guards_discovered += 1
            if len(guards) < MAX_STATE_TRANSITIONS:
                guards.append(
                    {
                        **copy.deepcopy(guard),
                        "component_id": component_id,
                        "component_reference": component_reference,
                    }
                )
        for transition in facts.state_transitions:
            transitions_discovered += 1
            if len(transitions) < MAX_STATE_TRANSITIONS:
                transitions.append(
                    {
                        **copy.deepcopy(transition),
                        "component_id": component_id,
                        "component_reference": component_reference,
                    }
                )
    source_omitted += guards_discovered - len(guards)
    source_omitted += transitions_discovered - len(transitions)
    state_nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
    for transition in transitions:
        key = (
            str(transition["component_id"]),
            str(transition["state_variable"]),
            str(transition["target_state_expression"]),
        )
        state_nodes[key] = {
            "id": stable_id("STATE", *key),
            "component_id": key[0],
            "state_variable": key[1],
            "state_expression": key[2],
            "authority": "assigned_state_expression_candidate",
        }
        transition["target_state_id"] = state_nodes[key]["id"]
    return {
        "format": "pysfmea-state-machine-model-1",
        "summary": {
            "guards_discovered": guards_discovered,
            "guards_embedded": len(guards),
            "transitions_discovered": transitions_discovered,
            "transitions_embedded": len(transitions),
            "state_nodes": len(state_nodes),
            "source_records_omitted": source_omitted,
            "guarded_transitions": sum(
                bool(value.get("guard_ids")) for value in transitions
            ),
            "truncated": bool(source_omitted),
        },
        "states": [state_nodes[key] for key in sorted(state_nodes)],
        "guards": guards,
        "transitions": transitions,
        "limits": {
            "records_per_component": MAX_STATE_RECORDS_PER_COMPONENT,
            "guards": MAX_STATE_TRANSITIONS,
            "transitions": MAX_STATE_TRANSITIONS,
        },
        "limitations": [
            "States are assigned expressions and guards are lexical predicates; enum values, aliases, inheritance, and runtime invariants are not fully resolved.",
            "Transitions are path-insensitive assignment candidates and do not establish reachability, exclusivity, liveness, or completeness.",
            "Indirect mutation, descriptors, native code, persistence effects, and transitions encoded only through calls may escape the model.",
        ],
        "authority": "bounded_static_guarded_state_assignment_model_not_formal_state_machine_proof",
    }


def _static_positive_number(expression: str) -> float | None:
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    return float(value)


def _call_argument_number(site: dict[str, Any], names: set[str]) -> float | None:
    for argument in site.get("arguments", []):
        if not isinstance(argument, dict):
            continue
        keyword = str(argument.get("keyword", "")).casefold()
        if keyword in names:
            return _static_positive_number(str(argument.get("expression", "")))
    return None


def _resilience_semantics_model(facts_list: list[FunctionFacts]) -> dict[str, Any]:
    """Build compositional transaction, effect, timing, retry, breaker, and resource facts."""

    by_file_name, by_full = _internal_resolution_indexes(facts_list)
    operations: list[dict[str, Any]] = []
    total_operations = 0
    direct_effects: dict[str, set[str]] = {}
    direct_idempotency_controls: dict[str, set[str]] = {}
    local_retry_factor: dict[str, int] = {}
    local_timeout: dict[str, float | None] = {}
    transaction_summaries: list[dict[str, Any]] = []
    resource_summaries: list[dict[str, Any]] = []
    call_edges: dict[str, set[str]] = defaultdict(set)
    begin_names = {"begin", "begin_nested", "atomic", "transaction"}
    commit_names = {"commit"}
    rollback_names = {"rollback"}
    savepoint_names = {"savepoint"}
    write_names = {
        "add",
        "delete",
        "execute",
        "insert",
        "insert_many",
        "insert_one",
        "save",
        "update",
        "update_many",
        "update_one",
        "write",
        "write_bytes",
        "write_text",
    }
    messaging_names = {"emit", "enqueue", "publish", "send", "send_message"}
    compensation_names = {"compensate", "refund", "revert", "reverse", "undo"}
    idempotency_names = {"deduplicate", "get_or_create", "setnx", "upsert"}
    retry_names = {"retry", "retrying", "attempt"}
    backoff_names = {"backoff", "sleep"}
    queue_growth_names = {"append", "extend", "put", "put_nowait", "enqueue"}
    resource_constructor_names = {
        "queue",
        "semaphore",
        "threadpoolexecutor",
        "processpoolexecutor",
    }

    for facts in sorted(facts_list, key=_component_ref):
        reference = _component_ref(facts)
        component_id = stable_id("CMP", facts.path, facts.qualname, facts.kind)
        effects: set[str] = set()
        idempotency_controls: set[str] = set()
        retry_factor = 1
        timeout_value: float | None = None
        transaction_depth = 0
        transaction_ops: list[str] = []
        transaction_risks: set[str] = set()
        persistence_writes = 0
        bounded_resources: list[dict[str, Any]] = []
        bounded_resource_receivers: set[str] = set()
        unbounded_resource_candidates: list[dict[str, Any]] = []

        for decorator in facts.decorators:
            if "retry" in decorator.casefold():
                retry_factor = max(retry_factor, 2)

        for site in sorted(
            facts.call_sites,
            key=lambda value: (int(value.get("order", 0)), int(value.get("line", 0))),
        ):
            called = str(site.get("reference", ""))
            leaf = called.rsplit(".", 1)[-1].casefold()
            categories: set[str] = set()
            transaction_scope = any(
                any(
                    token in str(context).casefold()
                    for token in ("atomic", "transaction", "session")
                )
                and ("with@" in str(context) or "async-with@" in str(context))
                for context in site.get("control_context", [])
            )
            if leaf in begin_names:
                categories.add("transaction_begin")
                transaction_depth += 1
            if leaf in commit_names:
                categories.add("transaction_commit")
                if transaction_depth:
                    transaction_depth -= 1
                else:
                    transaction_risks.add("commit_without_observed_begin")
            if leaf in rollback_names:
                categories.add("transaction_rollback")
                if transaction_depth:
                    transaction_depth -= 1
                else:
                    transaction_risks.add("rollback_without_observed_begin")
            if leaf in savepoint_names:
                categories.add("transaction_savepoint")
            if leaf in write_names:
                categories.update({"persistence_write", "side_effect"})
                effects.add("persistence_write")
                persistence_writes += 1
                if transaction_depth == 0 and not transaction_scope:
                    transaction_risks.add("write_without_observed_transaction_boundary")
            if leaf in messaging_names:
                categories.update({"message_or_external_side_effect", "side_effect"})
                effects.add("message_or_external_side_effect")
            if leaf in compensation_names:
                categories.add("compensation")
                effects.add("compensation")
                idempotency_controls.add("compensation")
            if leaf in idempotency_names:
                categories.add("idempotency_control")
                idempotency_controls.add(leaf)
            if any(
                isinstance(value, dict)
                and str(value.get("keyword", "")).casefold()
                in {"idempotency_key", "deduplication_key", "request_id"}
                for value in site.get("arguments", [])
            ):
                categories.add("idempotency_key")
                idempotency_controls.add("idempotency_key")
            if _matches_any(called, FILESYSTEM_NAMES) or leaf in FILESYSTEM_METHODS:
                categories.update({"filesystem_side_effect", "side_effect"})
                effects.add("filesystem_side_effect")
            if _matches_any(called, SUBPROCESS_NAMES):
                categories.update({"subprocess_side_effect", "side_effect"})
                effects.add("subprocess_side_effect")
            if leaf in retry_names:
                categories.add("retry")
                declared_attempts = _call_argument_number(
                    site, {"attempts", "max_attempts", "retries", "stop"}
                )
                retry_factor = max(retry_factor, int(declared_attempts or 2))
            if leaf in backoff_names and any(
                "retry" in str(value).casefold()
                for value in site.get("control_context", [])
            ):
                categories.add("retry_backoff")
            declared_timeout = _call_argument_number(
                site, {"timeout", "deadline", "total", "seconds"}
            )
            if declared_timeout is None and leaf in {"timeout", "wait_for"}:
                positional = [
                    value
                    for value in site.get("arguments", [])
                    if isinstance(value, dict)
                    and not value.get("keyword")
                    and int(value.get("position", -1))
                    >= (1 if leaf == "wait_for" else 0)
                ]
                if positional:
                    declared_timeout = _static_positive_number(
                        str(positional[0].get("expression", ""))
                    )
            if declared_timeout is not None:
                categories.add("temporal_budget")
                timeout_value = (
                    declared_timeout
                    if timeout_value is None
                    else min(timeout_value, declared_timeout)
                )
            resource_bound = _call_argument_number(
                site,
                {
                    "maxsize",
                    "max_size",
                    "max_workers",
                    "pool_size",
                    "capacity",
                    "limit",
                    "batch_size",
                },
            )
            if resource_bound is None and leaf in resource_constructor_names:
                positional = [
                    value
                    for value in site.get("arguments", [])
                    if isinstance(value, dict) and not value.get("keyword")
                ]
                if positional:
                    resource_bound = _static_positive_number(
                        str(positional[0].get("expression", ""))
                    )
            if resource_bound is not None:
                categories.add("resource_bound")
                result_context = site.get("result_context", {})
                if isinstance(result_context, dict):
                    bounded_resource_receivers.update(
                        str(value).casefold()
                        for value in result_context.get("targets", [])
                    )
                bounded_resources.append(
                    {
                        "reference": called,
                        "line": int(site.get("line", 0)),
                        "bound": resource_bound,
                    }
                )
            elif (
                leaf in queue_growth_names
                and called.rsplit(".", 1)[0].casefold()
                not in bounded_resource_receivers
            ) or leaf in resource_constructor_names:
                categories.add("resource_growth_candidate")
                unbounded_resource_candidates.append(
                    {"reference": called, "line": int(site.get("line", 0))}
                )

            targets = _resolve_internal_targets(
                caller=facts, called=called, by_file_name=by_file_name, by_full=by_full
            )
            for target in targets:
                target_reference = _component_ref(target)
                call_edges[reference].add(target_reference)
            if not categories:
                continue
            total_operations += 1
            operation_id = stable_id(
                "RESILIENCE-OP",
                reference,
                str(site.get("line", 0)),
                str(site.get("order", 0)),
                called,
                *sorted(categories),
            )
            if len(operations) < MAX_RESILIENCE_SEMANTIC_OPERATIONS:
                operations.append(
                    {
                        "id": operation_id,
                        "component_id": component_id,
                        "component_reference": reference,
                        "reference": called,
                        "line": int(site.get("line", 0) or 0),
                        "order": int(site.get("order", 0) or 0),
                        "categories": sorted(categories),
                        "transaction_scope": transaction_scope,
                        "declared_timeout": declared_timeout,
                        "resource_bound": resource_bound,
                        "authority": "bounded_static_resilience_semantic_operation",
                    }
                )
                if categories & {
                    "transaction_begin",
                    "transaction_commit",
                    "transaction_rollback",
                    "transaction_savepoint",
                    "persistence_write",
                    "compensation",
                }:
                    transaction_ops.append(operation_id)
        if transaction_depth:
            transaction_risks.add("begin_without_observed_commit_or_rollback")
        if persistence_writes > 1 and "compensation" not in effects:
            transaction_risks.add("multi_write_flow_without_observed_compensation")
        if "state_mutation" in facts.signals:
            effects.add("in_memory_state_mutation")
        direct_effects[reference] = effects
        direct_idempotency_controls[reference] = idempotency_controls
        local_retry_factor[reference] = retry_factor
        local_timeout[reference] = timeout_value
        transaction_summaries.append(
            {
                "component_id": component_id,
                "component_reference": reference,
                "operation_ids": transaction_ops,
                "persistence_writes": persistence_writes,
                "open_transaction_depth_at_exit": transaction_depth,
                "consistency_risks": sorted(transaction_risks),
                "compensation_observed": "compensation" in effects,
                "authority": "lexical_transaction_and_consistency_summary_not_runtime_atomicity_proof",
            }
        )
        resource_summaries.append(
            {
                "component_id": component_id,
                "component_reference": reference,
                "bounded_resources": bounded_resources,
                "unbounded_growth_candidates": unbounded_resource_candidates,
                "loop_count": facts.loops,
                "recursive_call_candidate": reference
                in call_edges.get(reference, set()),
                "authority": "static_resource_bound_candidates_not_symbolic_complexity_proof",
            }
        )

    transitive_effects = {key: set(value) for key, value in direct_effects.items()}
    changed = True
    effect_iterations = 0
    while changed and effect_iterations <= len(facts_list):
        changed = False
        effect_iterations += 1
        for caller_reference, callee_references in sorted(call_edges.items()):
            combined = set(transitive_effects.get(caller_reference, set()))
            for target_reference in callee_references:
                combined.update(transitive_effects.get(target_reference, set()))
            if combined != transitive_effects.get(caller_reference, set()):
                transitive_effects[caller_reference] = combined
                changed = True

    retry_paths: list[dict[str, Any]] = []
    for origin in sorted(direct_effects):
        stack = [(origin, [origin], local_retry_factor.get(origin, 1))]
        best_factor = local_retry_factor.get(origin, 1)
        best_path = [origin]
        cycle = False
        search_states = 0
        search_truncated = False
        while stack:
            if search_states >= MAX_RETRY_PATH_STATES_PER_ORIGIN:
                search_truncated = True
                break
            current_reference, path, factor = stack.pop()
            search_states += 1
            if factor > best_factor:
                best_factor, best_path = factor, path
            if len(path) >= MAX_RETRY_PATH_DEPTH:
                continue
            for target_reference in sorted(
                call_edges.get(current_reference, set()), reverse=True
            ):
                if target_reference in path:
                    cycle = True
                    continue
                next_factor = min(
                    MAX_RETRY_AMPLIFICATION,
                    factor * local_retry_factor.get(target_reference, 1),
                )
                stack.append(
                    (target_reference, [*path, target_reference], next_factor)
                )
        if best_factor > 1 or cycle:
            retry_paths.append(
                {
                    "origin_component_reference": origin,
                    "path": best_path,
                    "amplification_factor_upper_candidate": best_factor,
                    "cycle_detected": cycle,
                    "depth_limited": len(best_path) >= MAX_RETRY_PATH_DEPTH,
                    "search_states": search_states,
                    "search_truncated": search_truncated,
                    "authority": "static_nested_retry_upper_candidate_not_runtime_attempt_count_proof",
                }
            )

    timing_relations: list[dict[str, Any]] = []
    for caller_reference, callee_references in sorted(call_edges.items()):
        caller_budget = local_timeout.get(caller_reference)
        for target_reference in sorted(callee_references):
            target_budget = local_timeout.get(target_reference)
            if caller_budget is None and target_budget is None:
                continue
            timing_relations.append(
                {
                    "id": stable_id(
                        "TIMING-BUDGET", caller_reference, target_reference
                    ),
                    "caller_reference": caller_reference,
                    "callee_reference": target_reference,
                    "caller_budget": caller_budget,
                    "callee_budget": target_budget,
                    "status": (
                        "callee_budget_exceeds_caller"
                        if caller_budget is not None
                        and target_budget is not None
                        and target_budget > caller_budget
                        else "bounded_compatible_literals"
                        if caller_budget is not None and target_budget is not None
                        else "incomplete_budget_chain"
                    ),
                    "authority": "same-unit-literal_budget_constraint_not_end_to_end_latency_proof",
                }
            )

    breaker_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for facts in facts_list:
        for control in facts.detected_controls:
            if control.get("kind") == "circuit_breaker":
                breaker_groups[
                    str(control.get("scope_qualname") or facts.qualname)
                ].append(control)
    breaker_models = []
    required_roles = {
        "admission_guard",
        "failure_recording",
        "success_reset",
        "recovery_timer",
    }
    for scope in sorted(breaker_groups):
        members = breaker_groups[scope]
        roles = sorted(
            {str(role) for value in members for role in value.get("roles", [])}
        )
        states = sorted(
            {str(state) for value in members for state in value.get("states", [])}
        )
        breaker_models.append(
            {
                "id": stable_id("BREAKER-SEMANTICS", scope),
                "scope": scope,
                "roles": roles,
                "states": states,
                "threshold_expressions": sorted(
                    {
                        str(item)
                        for value in members
                        for item in value.get("threshold_expressions", [])
                    }
                ),
                "cooldown_expressions": sorted(
                    {
                        str(item)
                        for value in members
                        for item in value.get("cooldown_expressions", [])
                    }
                ),
                "synchronization": sorted(
                    {
                        str(item)
                        for value in members
                        for item in value.get("synchronization", [])
                    }
                ),
                "scope_keys": sorted(
                    {
                        str(item)
                        for value in members
                        for item in value.get("scope_keys", [])
                    }
                ),
                "fallback_indicators": sorted(
                    {
                        str(item)
                        for value in members
                        for item in value.get("fallback_indicators", [])
                    }
                ),
                "semantic_gaps": sorted(
                    [f"missing_role:{role}" for role in required_roles - set(roles)]
                    + (
                        ["missing_closed_open_state_pair"]
                        if not {"closed", "open"} <= set(states)
                        else []
                    )
                ),
                "authority": "class_scope_static_breaker_semantics_not_effectiveness_or_transition_proof",
            }
        )

    effect_summaries = [
        {
            "component_reference": reference,
            "direct_effects": sorted(direct_effects.get(reference, set())),
            "transitive_effects": sorted(transitive_effects.get(reference, set())),
            "retry_factor": local_retry_factor.get(reference, 1),
            "idempotency_controls": sorted(
                direct_idempotency_controls.get(reference, set())
            ),
            "unprotected_retry_side_effect": local_retry_factor.get(reference, 1) > 1
            and bool(transitive_effects.get(reference, set()) - {"compensation"})
            and not direct_idempotency_controls.get(reference, set()),
            "authority": "bounded_interprocedural_effect_summary_not_runtime_exactly_once_proof",
        }
        for reference in sorted(direct_effects)
    ]
    return {
        "format": "pysfmea-resilience-semantics-1",
        "summary": {
            "operations_discovered": total_operations,
            "operations_embedded": len(operations),
            "operations_omitted": total_operations - len(operations),
            "transaction_components": sum(
                bool(value["operation_ids"]) for value in transaction_summaries
            ),
            "transaction_risks": sum(
                len(value["consistency_risks"]) for value in transaction_summaries
            ),
            "effect_components": sum(
                bool(value["transitive_effects"]) for value in effect_summaries
            ),
            "retry_paths": len(retry_paths),
            "timing_relations": len(timing_relations),
            "breaker_models": len(breaker_models),
            "resource_risks": sum(
                len(value["unbounded_growth_candidates"])
                for value in resource_summaries
            ),
            "truncated": total_operations > len(operations),
        },
        "operations": operations,
        "transactions": transaction_summaries,
        "effects": effect_summaries,
        "timing_relations": timing_relations,
        "retry_paths": retry_paths,
        "circuit_breakers": breaker_models,
        "resources": resource_summaries,
        "limits": {
            "operations": MAX_RESILIENCE_SEMANTIC_OPERATIONS,
            "retry_path_depth": MAX_RETRY_PATH_DEPTH,
            "retry_path_states_per_origin": MAX_RETRY_PATH_STATES_PER_ORIGIN,
            "retry_amplification": MAX_RETRY_AMPLIFICATION,
        },
        "limitations": [
            "All models are bounded, path-insensitive static candidates and do not prove runtime atomicity, exactly-once behavior, latency, breaker effectiveness, or resource complexity.",
            "Literal timing and resource values are compared only when their local syntax implies compatible units; configuration indirection requires project evidence.",
            "Framework-specific transaction, retry, breaker, and compensation semantics may require adapters or runtime corroboration.",
        ],
        "authority": "integrated_bounded_static_resilience_semantics_not_runtime_or_formal_proof",
    }


def _security_context_dimensions(reference: str) -> set[str]:
    tokens = set(re.split(r"[^a-z0-9]+", reference.casefold()))
    dimensions: set[str] = set()
    if tokens & {"user", "identity", "principal", "subject", "actor", "account"}:
        dimensions.add("identity")
    if tokens & {"tenant", "organization", "organisation", "workspace", "customer"}:
        dimensions.add("tenant")
    if tokens & {"role", "roles", "permission", "permissions", "privilege"}:
        dimensions.add("role_or_permission")
    if tokens & {"scope", "scopes", "audience", "claim", "claims"}:
        dimensions.add("scope_or_claim")
    if tokens & {"token", "credential", "credentials", "apikey", "api_key", "session"}:
        dimensions.add("credential")
    return dimensions


def _authorization_scope_flow(
    facts_list: list[FunctionFacts], data_flow: dict[str, Any]
) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    component_dimensions: dict[str, set[str]] = {}
    component_controls: dict[str, list[dict[str, Any]]] = {}
    control_names = {
        "authenticate",
        "authorize",
        "check_permission",
        "check_scope",
        "enforce_permission",
        "has_permission",
        "has_role",
        "require_permission",
        "require_role",
        "require_scope",
        "verify_token",
    }
    for facts in sorted(facts_list, key=_component_ref):
        component_id = stable_id("CMP", facts.path, facts.qualname, facts.kind)
        component_security_dimensions: set[str] = set()
        for parameter in facts.parameter_contracts:
            component_security_dimensions.update(
                _security_context_dimensions(str(parameter.get("name", "")))
            )
        controls: list[dict[str, Any]] = []
        for decorator in facts.decorators:
            decorator_dimensions = _security_context_dimensions(decorator)
            if decorator_dimensions or any(
                token in decorator.casefold()
                for token in ("auth", "permission", "login_required", "role", "scope")
            ):
                controls.append(
                    {
                        "kind": "decorator_guard",
                        "reference": decorator,
                        "line": facts.line,
                        "dimensions": sorted(decorator_dimensions),
                    }
                )
        for site in facts.call_sites:
            called = str(site.get("reference", ""))
            leaf = called.rsplit(".", 1)[-1].casefold()
            if leaf in control_names or any(
                token in leaf
                for token in ("authoriz", "permission", "require_role", "require_scope")
            ):
                controls.append(
                    {
                        "kind": "call_guard",
                        "reference": called,
                        "line": int(site.get("line", 0) or 0),
                        "dimensions": sorted(_security_context_dimensions(called)),
                    }
                )
        component_dimensions[component_id] = component_security_dimensions
        component_controls[component_id] = controls

    flow_edges: list[dict[str, Any]] = []
    total_edges = 0
    for edge in data_flow.get("edges", []):
        if not isinstance(edge, dict):
            continue
        flow_dimensions: set[str] = set()
        bindings: list[dict[str, Any]] = []
        for argument in edge.get("arguments", []):
            if not isinstance(argument, dict):
                continue
            argument_dimensions = _security_context_dimensions(
                str(argument.get("target_parameter", ""))
            )
            for symbol in argument.get("symbols", []):
                if isinstance(symbol, dict):
                    argument_dimensions.update(
                        _security_context_dimensions(str(symbol.get("reference", "")))
                    )
            if argument_dimensions:
                flow_dimensions.update(argument_dimensions)
                bindings.append(
                    {
                        "target_parameter": str(argument.get("target_parameter", "")),
                        "source_expression": str(argument.get("expression", "")),
                        "dimensions": sorted(argument_dimensions),
                    }
                )
        if not flow_dimensions:
            continue
        total_edges += 1
        caller_id = str(edge.get("caller_component_id", ""))
        callee_id = str(edge.get("callee_component_id", ""))
        component_dimensions.setdefault(caller_id, set()).update(flow_dimensions)
        component_dimensions.setdefault(callee_id, set()).update(flow_dimensions)
        if len(flow_edges) < MAX_AUTHORIZATION_FLOW_EDGES:
            flow_edges.append(
                {
                    "id": stable_id(
                        "AUTH-SCOPE-FLOW",
                        str(edge.get("id", "")),
                        *sorted(flow_dimensions),
                    ),
                    "data_flow_edge_id": str(edge.get("id", "")),
                    "caller_component_id": caller_id,
                    "callee_component_id": callee_id,
                    "dimensions": sorted(flow_dimensions),
                    "bindings": bindings,
                    "authority": "security_context_name_flow_candidate_not_identity_or_authorization_proof",
                }
            )

    for facts in sorted(facts_list, key=_component_ref):
        component_id = stable_id("CMP", facts.path, facts.qualname, facts.kind)
        resolved_dimensions = sorted(component_dimensions.get(component_id, set()))
        controls = component_controls.get(component_id, [])
        risks: list[str] = []
        boundary = bool(facts.entrypoint_types or facts.interface_endpoints)
        sensitive_side_effect = bool(
            {"persistence", "external_interface", "filesystem"} & facts.signals
        )
        if boundary and resolved_dimensions and not controls:
            risks.append(
                "security_context_boundary_without_observed_authorization_guard"
            )
        if "tenant" in resolved_dimensions and sensitive_side_effect and not controls:
            risks.append("tenant_scoped_side_effect_without_observed_scope_guard")
        if "credential" in resolved_dimensions and not controls:
            risks.append("credential_context_without_observed_verification_guard")
        components.append(
            {
                "component_id": component_id,
                "component_reference": _component_ref(facts),
                "context_dimensions": resolved_dimensions,
                "controls": controls,
                "risks": risks,
                "boundary": boundary,
                "sensitive_side_effect": sensitive_side_effect,
                "authority": "bounded_static_security_context_and_guard_summary_not_access_control_proof",
            }
        )
    return {
        "format": "pysfmea-authorization-scope-flow-1",
        "summary": {
            "components": len(components),
            "components_with_context": sum(
                bool(value["context_dimensions"]) for value in components
            ),
            "components_with_controls": sum(
                bool(value["controls"]) for value in components
            ),
            "risk_candidates": sum(len(value["risks"]) for value in components),
            "flow_edges_discovered": total_edges,
            "flow_edges_embedded": len(flow_edges),
            "flow_edges_omitted": total_edges - len(flow_edges),
            "truncated": total_edges > len(flow_edges),
        },
        "components": components,
        "edges": flow_edges,
        "limits": {"flow_edges": MAX_AUTHORIZATION_FLOW_EDGES},
        "limitations": [
            "Dimensions are inferred conservatively from names, annotations, decorators, and resolved argument flow; framework semantics and runtime values may differ.",
            "Observed guards do not prove dominance, correctness, tenant isolation, least privilege, token validity, or enforcement on every runtime path.",
            "Reflection, middleware configured outside Python, generated code, and cross-service context propagation require contract or runtime evidence.",
        ],
        "authority": "bounded_static_authorization_scope_context_model_not_security_or_access_proof",
    }


def _contract_semantics_model(
    contracts: list[dict[str, Any]], components: list[dict[str, Any]]
) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    types: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    operations_discovered = 0
    types_discovered = 0
    python_routes: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for component in components:
        if not isinstance(component, dict):
            continue
        for endpoint in component.get("interface_endpoints", []):
            if not isinstance(endpoint, dict) or endpoint.get("kind") != "http_route":
                continue
            path = normalize_interface_path(str(endpoint.get("path", "")))
            for method in endpoint.get("methods", []):
                python_routes[(str(method).upper(), path)].append(component)

    operation_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    type_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for contract in contracts:
        contract_id = str(contract.get("id", ""))
        contract_path = str(contract.get("path", ""))
        contract_kind = str(contract.get("kind", ""))
        for source in contract.get("operation_contracts", []):
            if not isinstance(source, dict):
                continue
            operations_discovered += 1
            operation = str(source.get("operation", ""))
            method, separator, raw_path = operation.partition(" ")
            normalized_path = (
                normalize_interface_path(raw_path)
                if separator
                and method
                in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
                else ""
            )
            record = {
                **copy.deepcopy(source),
                "contract_id": contract_id,
                "contract_path": contract_path,
                "contract_kind": contract_kind,
                "contract_version": str(contract.get("version", "")),
                "normalized_path": normalized_path,
                "semantic_sha256": hashlib.sha256(
                    json.dumps(source, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                ).hexdigest(),
                "authority": "governed_local_contract_semantics",
            }
            operation_groups[(method, normalized_path or operation)].append(record)
            if len(operations) < MAX_CONTRACT_SEMANTIC_RECORDS:
                operations.append(record)
            if normalized_path:
                route_candidates = python_routes.get((method, normalized_path), [])
                request = source.get("request", {})
                required_parameters = {
                    str(value.get("name", ""))
                    for value in (
                        request.get("parameters", [])
                        if isinstance(request, dict)
                        and isinstance(request.get("parameters", []), list)
                        else []
                    )
                    if isinstance(value, dict) and value.get("required")
                }
                route_parameters = {
                    str(value)
                    for component in route_candidates
                    for value in component.get("parameters", [])
                }
                responses = source.get("responses", [])
                response_statuses = (
                    {
                        str(value.get("status", ""))
                        for value in responses
                        if isinstance(value, dict)
                    }
                    if isinstance(responses, list)
                    else set()
                )
                compatibility_gaps: list[str] = []
                if not route_candidates:
                    compatibility_gaps.append(
                        "contract_operation_without_python_route_match"
                    )
                missing_parameters = sorted(required_parameters - route_parameters)
                if missing_parameters:
                    compatibility_gaps.append(
                        "required_contract_parameters_missing_from_route_signature"
                    )
                if responses and not any(
                    status.startswith("2") or status == "default"
                    for status in response_statuses
                ):
                    compatibility_gaps.append("contract_has_no_success_response")
                if responses and not any(
                    status.startswith(("4", "5")) or status == "default"
                    for status in response_statuses
                ):
                    compatibility_gaps.append("contract_has_no_error_response")
                findings.append(
                    {
                        "id": stable_id("CONTRACT-COMPAT", contract_id, operation),
                        "contract_operation_id": str(source.get("id", "")),
                        "operation": operation,
                        "python_component_ids": sorted(
                            str(value.get("id", "")) for value in route_candidates
                        ),
                        "status": "compatible_static_shape"
                        if not compatibility_gaps
                        else "review_required",
                        "gaps": compatibility_gaps,
                        "required_parameters": sorted(required_parameters),
                        "route_parameters": sorted(route_parameters),
                        "missing_parameters": missing_parameters,
                        "response_statuses": sorted(response_statuses),
                        "authority": "static_contract_to_route_shape_reconciliation_not_runtime_compatibility_proof",
                    }
                )
        for source in contract.get("type_contracts", []):
            if not isinstance(source, dict):
                continue
            types_discovered += 1
            record = {
                **copy.deepcopy(source),
                "id": stable_id(
                    "CONTRACT-TYPE", contract_id, str(source.get("name", ""))
                ),
                "contract_id": contract_id,
                "contract_path": contract_path,
                "contract_kind": contract_kind,
                "contract_version": str(contract.get("version", "")),
                "semantic_sha256": hashlib.sha256(
                    json.dumps(source, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                ).hexdigest(),
                "authority": "governed_local_contract_type_semantics",
            }
            type_groups[str(source.get("name", ""))].append(record)
            if len(types) < MAX_CONTRACT_SEMANTIC_RECORDS:
                types.append(record)

    evolution: list[dict[str, Any]] = []
    for key, records in sorted(operation_groups.items()):
        digests = {str(value["semantic_sha256"]) for value in records}
        if len(records) > 1 and len(digests) > 1:
            findings.append(
                {
                    "id": stable_id("CONTRACT-CONFLICT", "operation", *key),
                    "kind": "conflicting_operation_contracts",
                    "operation": key[1],
                    "contract_ids": sorted(
                        str(value["contract_id"]) for value in records
                    ),
                    "semantic_sha256": sorted(digests),
                    "status": "review_required",
                    "authority": "same_operation_different_local_contract_semantics",
                }
            )
        ordered = sorted(
            records,
            key=lambda value: (
                str(value.get("contract_version", "")),
                str(value.get("contract_path", "")),
            ),
        )
        for previous, current in zip(ordered, ordered[1:]):
            if previous["semantic_sha256"] == current["semantic_sha256"]:
                continue
            previous_request = previous.get("request", {})
            current_request = current.get("request", {})
            previous_required = (
                {
                    str(value.get("name", ""))
                    for value in previous_request.get("parameters", [])
                    if isinstance(value, dict) and value.get("required")
                }
                if isinstance(previous_request, dict)
                else set()
            )
            current_required = (
                {
                    str(value.get("name", ""))
                    for value in current_request.get("parameters", [])
                    if isinstance(value, dict) and value.get("required")
                }
                if isinstance(current_request, dict)
                else set()
            )
            previous_statuses = {
                str(value.get("status", ""))
                for value in previous.get("responses", [])
                if isinstance(value, dict)
            }
            current_statuses = {
                str(value.get("status", ""))
                for value in current.get("responses", [])
                if isinstance(value, dict)
            }
            breaking = []
            if current_required - previous_required:
                breaking.append("new_required_request_parameter")
            if previous_statuses - current_statuses:
                breaking.append("declared_response_status_removed")
            evolution.append(
                {
                    "id": stable_id(
                        "CONTRACT-EVOLUTION",
                        "operation",
                        key[0],
                        key[1],
                        str(previous["contract_id"]),
                        str(current["contract_id"]),
                    ),
                    "kind": "operation_evolution",
                    "subject": key[1],
                    "from_contract_id": previous["contract_id"],
                    "to_contract_id": current["contract_id"],
                    "from_version": previous.get("contract_version", ""),
                    "to_version": current.get("contract_version", ""),
                    "changes": {
                        "required_parameters_added": sorted(
                            current_required - previous_required
                        ),
                        "required_parameters_removed": sorted(
                            previous_required - current_required
                        ),
                        "response_statuses_added": sorted(
                            current_statuses - previous_statuses
                        ),
                        "response_statuses_removed": sorted(
                            previous_statuses - current_statuses
                        ),
                    },
                    "breaking_change_candidates": breaking,
                    "ordering_authority": "declared_version_then_repository_path",
                    "authority": "bounded_static_contract_evolution_candidate_requires_version_policy_review",
                }
            )
    for name, records in sorted(type_groups.items()):
        digests = {str(value["semantic_sha256"]) for value in records}
        if name and len(records) > 1 and len(digests) > 1:
            findings.append(
                {
                    "id": stable_id("CONTRACT-CONFLICT", "type", name),
                    "kind": "conflicting_type_contracts",
                    "type_name": name,
                    "contract_ids": sorted(
                        str(value["contract_id"]) for value in records
                    ),
                    "semantic_sha256": sorted(digests),
                    "status": "review_required",
                    "authority": "same_type_name_different_local_contract_semantics",
                }
            )
        ordered = sorted(
            records,
            key=lambda value: (
                str(value.get("contract_version", "")),
                str(value.get("contract_path", "")),
            ),
        )
        for previous, current in zip(ordered, ordered[1:]):
            if previous["semantic_sha256"] == current["semantic_sha256"]:
                continue
            previous_properties = set(
                str(value) for value in previous.get("properties", [])
            )
            current_properties = set(
                str(value) for value in current.get("properties", [])
            )
            previous_required = set(
                str(value) for value in previous.get("required", [])
            )
            current_required = set(str(value) for value in current.get("required", []))
            breaking = []
            if previous_properties - current_properties:
                breaking.append("field_removed")
            if current_required - previous_required:
                breaking.append("required_field_added")
            evolution.append(
                {
                    "id": stable_id(
                        "CONTRACT-EVOLUTION",
                        "type",
                        name,
                        str(previous["contract_id"]),
                        str(current["contract_id"]),
                    ),
                    "kind": "type_evolution",
                    "subject": name,
                    "from_contract_id": previous["contract_id"],
                    "to_contract_id": current["contract_id"],
                    "from_version": previous.get("contract_version", ""),
                    "to_version": current.get("contract_version", ""),
                    "changes": {
                        "properties_added": sorted(
                            current_properties - previous_properties
                        ),
                        "properties_removed": sorted(
                            previous_properties - current_properties
                        ),
                        "required_added": sorted(current_required - previous_required),
                        "required_removed": sorted(
                            previous_required - current_required
                        ),
                    },
                    "breaking_change_candidates": breaking,
                    "ordering_authority": "declared_version_then_repository_path",
                    "authority": "bounded_static_contract_evolution_candidate_requires_version_policy_review",
                }
            )
    embedded_evolution = evolution[:MAX_CONTRACT_SEMANTIC_RECORDS]
    return {
        "format": "pysfmea-contract-semantics-1",
        "summary": {
            "contracts": len(contracts),
            "contract_kinds": dict(
                sorted(
                    Counter(str(value.get("kind", "")) for value in contracts).items()
                )
            ),
            "operations_discovered": operations_discovered,
            "operations_embedded": len(operations),
            "operations_omitted": operations_discovered - len(operations),
            "types_discovered": types_discovered,
            "types_embedded": len(types),
            "types_omitted": types_discovered - len(types),
            "compatibility_records": len(findings),
            "evolution_records_discovered": len(evolution),
            "evolution_records_embedded": len(embedded_evolution),
            "evolution_records_omitted": len(evolution) - len(embedded_evolution),
            "breaking_change_candidates": sum(
                bool(value["breaking_change_candidates"])
                for value in embedded_evolution
            ),
            "review_required": sum(
                value.get("status") == "review_required" for value in findings
            ),
            "truncated": operations_discovered > len(operations)
            or types_discovered > len(types)
            or len(evolution) > len(embedded_evolution),
        },
        "operations": operations,
        "types": types,
        "compatibility": findings,
        "evolution": embedded_evolution,
        "supported_contract_kinds": [
            "openapi",
            "asyncapi",
            "protobuf",
            "graphql",
            "json_schema",
            "avro",
        ],
        "limits": {
            "operations": MAX_CONTRACT_SEMANTIC_RECORDS,
            "types": MAX_CONTRACT_SEMANTIC_RECORDS,
        },
        "limitations": [
            "Static Python route comparison covers method, normalized path, required named parameters, and declared success/error status families; complete serialization and runtime behavior require execution evidence.",
            "Evolution pairs use declared version then repository path ordering; authoritative compatibility policy and historical baselines remain project evidence.",
            "YAML, framework indirection, generated clients, custom scalars/options, and cross-repository contracts may require dedicated adapters.",
        ],
        "authority": "bounded_local_cross_language_contract_and_evolution_candidates_not_runtime_proof",
    }


def _architecture_models(
    inventory: dict[str, Any],
    components: list[dict[str, Any]],
    deployment_environments: list[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    code_components = [
        value
        for value in components
        if value.get("kind") not in {"environment", "common_cause"}
    ]
    deployment_nodes: list[dict[str, Any]] = []
    deployment_edges: list[dict[str, Any]] = []
    node_by_artifact_key: dict[tuple[str, str], str] = {}
    discovered_node_ids: set[str] = set()
    discovered_edge_ids: set[str] = set()
    embedded_node_ids: set[str] = set()
    embedded_edge_ids: set[str] = set()
    for entry in inventory.get("entries", []):
        if not isinstance(entry, dict):
            continue
        facts = entry.get("deployment_facts")
        if not isinstance(facts, dict):
            continue
        path = str(entry.get("path", ""))
        for entity in facts.get("entities", []):
            if not isinstance(entity, dict):
                continue
            key = str(entity.get("key", ""))
            node_id = stable_id("DEPLOYMENT-NODE", path, key)
            node_by_artifact_key[(path, key)] = node_id
            discovered_node_ids.add(node_id)
            if (
                node_id not in embedded_node_ids
                and len(deployment_nodes) < MAX_ARCHITECTURE_MODEL_RECORDS
            ):
                deployment_nodes.append(
                    {
                        "id": node_id,
                        "kind": str(entity.get("kind", "")),
                        "name": str(entity.get("name", "")),
                        "artifact_path": path,
                        "artifact_sha256": str(entry.get("sha256", "")),
                        "details": {
                            key: copy.deepcopy(value)
                            for key, value in entity.items()
                            if key not in {"key", "kind", "name"}
                        },
                        "authority": "declared_repository_deployment_entity_not_observed_runtime",
                    }
                )
                embedded_node_ids.add(node_id)
        for relation in facts.get("relationships", []):
            if not isinstance(relation, dict):
                continue
            source_key = str(relation.get("source", ""))
            target_key = str(relation.get("target", ""))
            source_id = node_by_artifact_key.get((path, source_key))
            target_id = node_by_artifact_key.get((path, target_key))
            if target_id is None and target_key:
                target_id = stable_id("DEPLOYMENT-NODE", path, target_key)
                node_by_artifact_key[(path, target_key)] = target_id
                discovered_node_ids.add(target_id)
                kind, _separator, name = target_key.partition(":")
                if (
                    target_id not in embedded_node_ids
                    and len(deployment_nodes) < MAX_ARCHITECTURE_MODEL_RECORDS
                ):
                    deployment_nodes.append(
                        {
                            "id": target_id,
                            "kind": kind or "referenced_resource",
                            "name": name or target_key,
                            "artifact_path": path,
                            "artifact_sha256": str(entry.get("sha256", "")),
                            "details": {"declaration": "referenced_only"},
                            "authority": "declared_repository_deployment_reference_not_observed_runtime",
                        }
                    )
                    embedded_node_ids.add(target_id)
            edge_id = stable_id(
                "DEPLOYMENT-EDGE",
                str(source_id or ""),
                str(target_id or ""),
                str(relation.get("kind", "")),
            )
            if source_id and target_id:
                discovered_edge_ids.add(edge_id)
            if (
                source_id in embedded_node_ids
                and target_id in embedded_node_ids
                and edge_id not in embedded_edge_ids
                and len(deployment_edges) < MAX_ARCHITECTURE_MODEL_RECORDS
            ):
                deployment_edges.append(
                    {
                        "id": edge_id,
                        "source_node_id": source_id,
                        "target_node_id": target_id,
                        "kind": str(relation.get("kind", "")),
                        "artifact_path": path,
                        "authority": "declared_static_deployment_relationship",
                    }
                )
                embedded_edge_ids.add(edge_id)
    for environment in sorted(
        {value.strip() for value in deployment_environments if value.strip()}
    ):
        node_id = stable_id("DEPLOYMENT-NODE", "configuration", environment)
        discovered_node_ids.add(node_id)
        if (
            node_id not in embedded_node_ids
            and len(deployment_nodes) < MAX_ARCHITECTURE_MODEL_RECORDS
        ):
            deployment_nodes.append(
                {
                    "id": node_id,
                    "kind": "configured_environment",
                    "name": environment,
                    "artifact_path": "configuration.project.deployment_environments",
                    "artifact_sha256": "",
                    "details": {},
                    "authority": "reviewed_configuration_declaration_not_observed_runtime",
                }
            )
            embedded_node_ids.add(node_id)
    placements: list[dict[str, Any]] = []
    components_by_node: dict[str, set[str]] = defaultdict(set)
    deployment_nodes_by_token: dict[str, list[str]] = defaultdict(list)
    for node in deployment_nodes:
        node_name = str(node.get("name", "")).casefold()
        if len(node_name) < 3:
            continue
        for token in sorted(
            value for value in re.split(r"[^a-z0-9]+", node_name) if len(value) >= 3
        ):
            deployment_nodes_by_token[token].append(str(node["id"]))
    for component in code_components:
        source_path = str(component.get("source", {}).get("path", "")).casefold()
        qualname = str(component.get("qualname", "")).casefold()
        searchable = {
            value
            for value in re.split(r"[^a-z0-9]+", source_path + " " + qualname)
            if len(value) >= 3
        }
        candidates: list[str] = []
        candidate_ids: set[str] = set()
        for token in sorted(searchable):
            for node_id in deployment_nodes_by_token.get(token, []):
                if node_id in candidate_ids:
                    continue
                candidates.append(node_id)
                candidate_ids.add(node_id)
                if len(candidates) >= 100:
                    break
            if len(candidates) >= 100:
                break
        for node_id in candidates:
            components_by_node[node_id].add(str(component.get("id", "")))
        placements.append(
            {
                "component_id": str(component.get("id", "")),
                "node_ids": candidates,
                "status": "candidate_placement" if candidates else "unplaced",
                "basis": "name_and_source_token_overlap"
                if candidates
                else "no_static_deployment_match",
                "authority": "heuristic_static_placement_requires_deployment_review",
            }
        )
    deployment = {
        "format": "pysfmea-deployment-topology-1",
        "summary": {
            "nodes_discovered": len(discovered_node_ids),
            "nodes_embedded": len(deployment_nodes),
            "nodes_omitted": len(discovered_node_ids) - len(deployment_nodes),
            "edges_discovered": len(discovered_edge_ids),
            "edges_embedded": len(deployment_edges),
            "edges_omitted": len(discovered_edge_ids) - len(deployment_edges),
            "components": len(placements),
            "placed_components": sum(bool(value["node_ids"]) for value in placements),
            "unplaced_components": sum(not value["node_ids"] for value in placements),
            "truncated": len(discovered_node_ids) > len(deployment_nodes)
            or len(discovered_edge_ids) > len(deployment_edges),
        },
        "nodes": deployment_nodes,
        "edges": deployment_edges,
        "placements": placements,
        "limits": {"records": MAX_ARCHITECTURE_MODEL_RECORDS},
        "limitations": [
            "Topology reflects bounded repository declarations and reviewed environment names, not live deployed state, routing, replicas, health, or reachability.",
            "Component placement is a token-overlap candidate and must be confirmed or replaced by project mappings/runtime evidence.",
        ],
        "authority": "bounded_declared_deployment_topology_not_observed_environment",
    }

    fate_groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for node_id, affected in components_by_node.items():
        if len(affected) >= 2:
            fate_groups[("deployment_node", node_id)].update(affected)
    for component in code_components:
        component_id = str(component.get("id", ""))
        for subsystem in component.get("subsystems", []):
            fate_groups[("subsystem", str(subsystem))].add(component_id)
        external_roots = {
            str(value.get("reference", "")).split(".", 1)[0]
            for value in component.get("external_call_candidates", [])
            if isinstance(value, dict) and value.get("reference")
        }
        for root in external_roots:
            fate_groups[("external_dependency", root)].add(component_id)
    eligible_fate_groups = [
        ((kind, key), affected)
        for (kind, key), affected in sorted(fate_groups.items())
        if len(affected) >= 2
    ]
    regions = [
        {
            "id": stable_id("SHARED-FATE", kind, key, *sorted(affected)),
            "kind": kind,
            "key": key,
            "affected_component_ids": sorted(affected),
            "review_questions": [
                "Can one fault in this shared resource affect all listed components?",
                "Are isolation, redundancy, recovery, and monitoring independent enough for the claimed assurance?",
            ],
            "authority": "automatically_discovered_shared_fate_candidate_requires_common_cause_review",
        }
        for (kind, key), affected in eligible_fate_groups
    ][:MAX_ARCHITECTURE_MODEL_RECORDS]
    shared_fate = {
        "format": "pysfmea-shared-fate-analysis-1",
        "summary": {
            "regions": len(regions),
            "affected_components": len(
                {
                    value
                    for region in regions
                    for value in region["affected_component_ids"]
                }
            ),
            "by_kind": dict(
                sorted(Counter(value["kind"] for value in regions).items())
            ),
            "regions_discovered": len(eligible_fate_groups),
            "regions_omitted": len(eligible_fate_groups) - len(regions),
            "truncated": len(eligible_fate_groups) > len(regions),
        },
        "regions": regions,
        "limits": {"regions": MAX_ARCHITECTURE_MODEL_RECORDS},
        "limitations": [
            "Shared membership is a conservative common-cause lead; it does not establish correlated failure probability or independence.",
            "Undeclared infrastructure, runtime routing, credentials, zones, and organizational dependencies require project evidence.",
        ],
        "authority": "automatic_static_shared_fate_candidates_not_common_cause_proof",
    }

    hierarchy_nodes: dict[str, dict[str, Any]] = {}
    omitted_hierarchy_paths: set[str] = set()
    root_id = stable_id("ARCH-NODE", "repository")
    hierarchy_nodes[root_id] = {
        "id": root_id,
        "kind": "repository",
        "name": "Repository",
        "parent_id": "",
        "path": "repository",
        "component_ids": [],
        "direct_trace": {"requirements": [], "hazards": [], "interfaces": []},
        "effective_trace": {"requirements": [], "hazards": [], "interfaces": []},
    }

    def ensure_hierarchy_path(kind: str, parts: list[str]) -> str:
        parent_id = root_id
        accumulated: list[str] = []
        for part in parts:
            accumulated.append(part)
            path = f"{kind}:" + "/".join(accumulated)
            node_id = stable_id("ARCH-NODE", path)
            if (
                node_id not in hierarchy_nodes
                and len(hierarchy_nodes) >= MAX_ARCHITECTURE_MODEL_RECORDS
            ):
                omitted_hierarchy_paths.add(path)
                continue
            hierarchy_nodes.setdefault(
                node_id,
                {
                    "id": node_id,
                    "kind": kind,
                    "name": part,
                    "parent_id": parent_id,
                    "path": path,
                    "component_ids": [],
                    "direct_trace": {
                        "requirements": [],
                        "hazards": [],
                        "interfaces": [],
                    },
                    "effective_trace": {
                        "requirements": [],
                        "hazards": [],
                        "interfaces": [],
                    },
                },
            )
            parent_id = node_id
        return parent_id

    memberships: list[dict[str, Any]] = []
    for component in code_components:
        component_id = str(component.get("id", ""))
        subsystem_paths = [
            [part.strip() for part in re.split(r"/|>|::", str(value)) if part.strip()]
            for value in component.get("subsystems", [])
        ]
        source = Path(str(component.get("source", {}).get("path", "")))
        directory_parts = [
            value for value in source.parent.parts if value not in {".", ""}
        ]
        node_ids: list[str] = []
        for parts in subsystem_paths:
            if parts:
                node_ids.append(ensure_hierarchy_path("subsystem", parts))
        if directory_parts:
            node_ids.append(ensure_hierarchy_path("source_package", directory_parts))
        if not node_ids:
            node_ids = [root_id]
        trace = {
            "requirements": sorted(
                str(value) for value in component.get("requirement_ids", [])
            ),
            "hazards": sorted(
                {
                    str(value)
                    for mapping in component.get("mapping_context", [])
                    if isinstance(mapping, dict)
                    for value in mapping.get("hazards", [])
                }
            ),
            "interfaces": sorted(
                str(value) for value in component.get("interface_ids", [])
            ),
        }
        for node_id in node_ids:
            hierarchy_nodes[node_id]["component_ids"].append(component_id)
            for trace_field, values in trace.items():
                hierarchy_nodes[node_id]["direct_trace"][trace_field] = sorted(
                    set(hierarchy_nodes[node_id]["direct_trace"][trace_field])
                    | set(values)
                )
        memberships.append(
            {
                "component_id": component_id,
                "node_ids": sorted(set(node_ids)),
                "effective_trace": trace,
                "authority": "reviewed_mapping_and_repository_path_hierarchy",
            }
        )
    ordered_nodes = sorted(
        hierarchy_nodes.values(),
        key=lambda value: str(value["path"]).count("/"),
        reverse=True,
    )
    for node in ordered_nodes:
        node["component_ids"] = sorted(set(node["component_ids"]))
        node["effective_trace"] = copy.deepcopy(node["direct_trace"])
    for node in ordered_nodes:
        parent = hierarchy_nodes.get(str(node.get("parent_id", "")))
        if parent is not None:
            parent["component_ids"].extend(node["component_ids"])
            for trace_field, values in node["effective_trace"].items():
                parent["effective_trace"][trace_field] = sorted(
                    set(parent["effective_trace"][trace_field]) | set(values)
                )
    for node in ordered_nodes:
        node["component_ids"] = sorted(set(node["component_ids"]))
    hierarchy = {
        "format": "pysfmea-architecture-hierarchy-1",
        "summary": {
            "nodes": len(hierarchy_nodes),
            "memberships": len(memberships),
            "subsystem_nodes": sum(
                value["kind"] == "subsystem" for value in hierarchy_nodes.values()
            ),
            "source_package_nodes": sum(
                value["kind"] == "source_package" for value in hierarchy_nodes.values()
            ),
            "unmapped_to_subsystem": sum(
                not any(
                    hierarchy_nodes[node_id]["kind"] == "subsystem"
                    for node_id in value["node_ids"]
                )
                for value in memberships
            ),
            "nodes_omitted": len(omitted_hierarchy_paths),
            "truncated": bool(omitted_hierarchy_paths),
        },
        "nodes": sorted(hierarchy_nodes.values(), key=lambda value: str(value["path"])),
        "memberships": memberships,
        "inheritance_rules": [
            "Trace mappings aggregate from component memberships to every ancestor.",
            "Subsystem hierarchy uses reviewed mapping delimiters '/', '>', or '::'; source-package hierarchy uses repository paths.",
            "No requirement, hazard, interface, or approval is inferred when absent from reviewed mappings.",
        ],
        "limits": {"nodes": MAX_ARCHITECTURE_MODEL_RECORDS},
        "authority": "deterministic_hierarchy_and_upward_trace_aggregation_not_architecture_approval",
    }
    return deployment, shared_fate, hierarchy


def _internal_callers(facts_list: list[FunctionFacts]) -> dict[str, list[str]]:
    callers, _resolved_calls = _internal_call_resolution(facts_list)
    return callers


def _external_call_candidates(
    facts: FunctionFacts,
    resolved_calls: set[str],
    *,
    configured_prefixes: Iterable[str] = (),
    configured_receiver_hints: Iterable[str] = (),
    configured_method_hints: Iterable[str] = (),
) -> list[dict[str, str]]:
    interface_verbs = {
        "call",
        "connect",
        "consume",
        "execute",
        "fetch",
        "invoke",
        "open",
        "publish",
        "read",
        "receive",
        "request",
        "send",
        "write",
    }
    provider_methods = {
        "aggregate",
        "ainvoke",
        "chat",
        "commit",
        "complete",
        "create",
        "delete",
        "delete_one",
        "dispatch",
        "download",
        "emit",
        "enqueue",
        "find",
        "find_one",
        "generate",
        "get",
        "insert_many",
        "insert_one",
        "invoke",
        "patch",
        "post",
        "put",
        "stream",
        "subscribe",
        "unsubscribe",
        "update_many",
        "update_one",
        "upload",
    }
    provider_methods.update(value.casefold() for value in configured_method_hints)
    receiver_hints = {
        "api",
        "channel",
        "client",
        "collection",
        "consumer",
        "db",
        "http",
        "llm",
        "mcp",
        "model",
        "producer",
        "queue",
        "redis",
        "session",
        "socket",
        "transport",
    }
    receiver_hints.update(value.casefold() for value in configured_receiver_hints)
    external_prefixes = tuple(EXTERNAL_PREFIXES) + tuple(configured_prefixes)
    candidates: list[dict[str, str]] = []
    for reference in sorted(facts.calls - resolved_calls):
        root = reference.split(".", 1)[0]
        leaf = reference.rsplit(".", 1)[-1].casefold()
        receiver = reference.rsplit(".", 1)[0].casefold()
        receiver_tokens = set(re.split(r"[^a-z0-9]+", receiver))
        if root in {"self", "cls"}:
            continue
        resolution_sources = {
            str(site.get("resolution", "lexical_name"))
            for site in facts.call_sites
            if site.get("reference") == reference
        }
        resolution = (
            sorted(resolution_sources)[0] if resolution_sources else "lexical_name"
        )
        if _matches_any(
            reference,
            (
                *external_prefixes,
                *PERSISTENCE_PREFIXES,
                *SUBPROCESS_NAMES,
                *HARDWARE_INTERFACE_PREFIXES,
            ),
        ):
            confidence = "high"
            basis = (
                "typed_receiver_known_external_api"
                if resolution
                in {
                    "parameter_annotation",
                    "annotation",
                    "constructor_assignment",
                    "annotated_constructor_assignment",
                }
                else "known_external_api"
            )
        elif "." in reference and (
            leaf in interface_verbs
            or (leaf in provider_methods and bool(receiver_tokens & receiver_hints))
        ):
            confidence = "medium"
            basis = (
                "typed_unresolved_receiver_interface_verb"
                if resolution
                in {
                    "parameter_annotation",
                    "annotation",
                    "constructor_assignment",
                    "annotated_constructor_assignment",
                }
                else "unresolved_receiver_interface_verb"
            )
        else:
            continue
        candidates.append(
            {
                "reference": reference,
                "confidence": confidence,
                "basis": basis,
                "resolution": resolution,
                "status": "static_candidate",
            }
        )
    return candidates


def _upstream_paths(
    target_reference: str,
    callers: dict[str, list[str]],
    *,
    max_depth: int = 6,
    max_paths: int = 25,
) -> tuple[list[list[str]], dict[str, Any]]:
    paths: list[list[str]] = []
    path_limit_truncated = False
    depth_limited_paths = 0

    def walk(current: str, path: list[str]) -> None:
        nonlocal depth_limited_paths, path_limit_truncated
        if len(paths) >= max_paths:
            path_limit_truncated = True
            return
        upstream = callers.get(current, [])
        if len(path) >= max_depth or not upstream:
            if len(path) > 1:
                paths.append(list(reversed(path)))
                if upstream:
                    depth_limited_paths += 1
            return
        for caller in upstream:
            if len(paths) >= max_paths:
                path_limit_truncated = True
                break
            if caller in path:
                paths.append(list(reversed([*path, caller])))
            else:
                walk(caller, [*path, caller])

    walk(target_reference, [target_reference])
    complete = not path_limit_truncated and depth_limited_paths == 0
    limitations = []
    if path_limit_truncated:
        limitations.append(
            f"additional caller paths may exist beyond the {max_paths}-path discovery limit"
        )
    if depth_limited_paths:
        limitations.append(
            f"{depth_limited_paths} emitted path(s) reached the {max_depth}-component discovery depth"
        )
    return paths, {
        "max_depth_components": max_depth,
        "max_paths": max_paths,
        "emitted_paths": len(paths),
        "path_limit_truncated": path_limit_truncated,
        "depth_limited_paths": depth_limited_paths,
        "complete_within_static_call_model": complete,
        "limitations": limitations,
        "notice": (
            "Caller-path discovery was complete within the bounded static call model."
            if complete
            else "Caller-path discovery is a bounded projection; "
            + "; ".join(limitations)
            + "."
        ),
    }


def _screening(
    facts: FunctionFacts,
    fan_in: int,
    test_refs: list[str],
    coverage: dict[str, Any] | None,
    critical_context: list[dict[str, Any]],
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    if facts.complexity >= 10:
        score += 3
        reasons.append(f"high decision complexity ({facts.complexity})")
    elif facts.complexity >= 5:
        score += 1
        reasons.append(f"moderate decision complexity ({facts.complexity})")
    weights = {
        "entrypoint": 3,
        "external_interface": 2,
        "persistence": 2,
        "subprocess": 2,
        "concurrency": 2,
        "filesystem": 1,
        "configuration": 1,
        "serialization": 1,
        "timing": 1,
        "calculation": 1,
        "runtime_environment": 2,
        "hardware_interface": 3,
        "state_mutation": 1,
        "internal_interface": 1,
        "module_initialization": 1,
    }
    for signal in sorted(facts.signals):
        weight = weights.get(signal, 0)
        score += weight
        if weight:
            reasons.append(signal.replace("_", " "))
    if fan_in >= 5:
        score += 2
        reasons.append(f"called by {fan_in} scanned components")
    elif fan_in:
        score += 1
        reasons.append(f"called by {fan_in} scanned component(s)")
    if facts.silent_handlers:
        score += 2
        reasons.append("silent exception handling")
    elif facts.broad_handlers:
        score += 1
        reasons.append("broad exception handling")
    if not test_refs:
        reasons.append("no textual test reference found (not proof of missing tests)")
    if coverage and coverage.get("line_percent") is not None:
        reasons.append(f"observed function line coverage {coverage['line_percent']}%")
    if coverage and coverage.get("branch_percent") is not None:
        reasons.append(
            f"observed function branch coverage {coverage['branch_percent']}%"
        )
    if critical_context:
        score += 4
        reasons.extend(
            "project critical function: "
            + entry.get("rationale", entry.get("pattern", ""))
            for entry in critical_context
        )
    label = "high" if score >= 7 else "medium" if score >= 3 else "low"
    return {"priority": label, "score": score, "reasons": reasons}


def _rule(
    rule_id: str,
    guideword: str,
    failure_mode: str,
    trigger: str,
    local_effect: str,
    causes: list[str],
    actions: list[str],
    confidence: str = "medium",
    failure_class: str | None = None,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "guideword": guideword,
        "failure_mode": failure_mode,
        "trigger": trigger,
        "local_effect": local_effect,
        "causes": causes,
        "actions": actions,
        "confidence": confidence,
        "failure_class": failure_class or _failure_class(rule_id),
    }


def _failure_class(rule_id: str) -> str:
    prefix = rule_id.split(".", 1)[0]
    return {
        "storage": "data",
        "configuration": "environment",
        "process": "environment",
        "state": "logic",
    }.get(prefix, prefix)


def _candidate_rules(
    facts: FunctionFacts,
    custom_rules: list[dict[str, Any]] | None = None,
    analysis_rules: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    name = facts.qualname
    if facts.kind == "class_model":
        rules = [
            _rule(
                "data.model_contract",
                "Incorrect / incomplete / incompatible data model",
                f"{name} defines missing, incorrect, ambiguous, incompatible, or insufficiently constrained fields and representation semantics.",
                "A producer, consumer, stored record, or version boundary relies on the declared data contract.",
                "Data is rejected, accepted incorrectly, silently transformed, or interpreted with the wrong meaning.",
                [
                    "Missing or wrong field",
                    "Incorrect type, range, unit, default, or optionality",
                    "Ambiguous enum or discriminator",
                    "Backward/forward compatibility fault",
                ],
                [
                    "Specify field semantics, units, constraints, and compatibility policy",
                    "Test valid, invalid, missing, extra, and version-skewed records",
                    "Trace producers and consumers of the data contract",
                ],
                "high",
            )
        ]
    else:
        rules = [
            _rule(
                "functional.omission",
                "Omission / no function",
                f"{name} fails to execute, terminates early, or produces no required result.",
                "The function is requested under a valid operating condition.",
                "The expected result, state transition, or side effect is absent.",
                [
                    "Unhandled exception",
                    "Incorrect precondition or guard",
                    "Missing or invalid dependency/data",
                ],
                [
                    "Define the required failure response",
                    "Add tests for omitted and interrupted execution",
                    "Add completion monitoring where the effect warrants it",
                ],
                "high" if "entrypoint" in facts.signals else "medium",
            ),
            _rule(
                "functional.incorrect",
                "Incorrect / incomplete function",
                f"{name} produces an incorrect, incomplete, inconsistent, or unintended result.",
                "A valid or boundary-case request follows a faulty logic, calculation, or state path.",
                "A wrong result or state is returned or propagated to the caller.",
                [
                    "Logic or calculation fault",
                    "Unhandled boundary condition",
                    "Incorrect state or assumption",
                ],
                [
                    "Document invariants and acceptance criteria",
                    "Add boundary and property-based tests",
                    "Validate output before propagation",
                ],
            ),
        ]

    if facts.parameters:
        rules.append(
            _rule(
                "data.invalid_input",
                "Missing / wrong / out-of-range data",
                f"{name} accepts missing, malformed, out-of-range, stale, duplicated, or inconsistent input data.",
                "Input violates an unstated or unenforced data assumption.",
                "Invalid data is rejected incorrectly, used in processing, or propagated.",
                [
                    "Missing validation",
                    "Ambiguous units/schema",
                    "Stale or duplicated message",
                    "Unexpected null, range, precision, or encoding",
                ],
                [
                    "Specify input contracts, units, ranges, freshness, and uniqueness",
                    "Add schema and boundary validation",
                    "Test malformed and adversarial input",
                ],
            )
        )
    if "calculation" in facts.signals:
        rules.append(
            _rule(
                "calculation.precision_or_range",
                "Incorrect calculation / precision / range",
                f"{name} calculates a value with an incorrect equation, operand, sign, unit, precision, rounding, convergence, overflow, or underflow behavior.",
                "A valid boundary, magnitude, unit, or numerical representation activates a faulty calculation assumption.",
                "A numerically plausible but incorrect value is returned, stored, displayed, or used for control.",
                [
                    "Wrong operator or operand",
                    "Unit or sign error",
                    "Inappropriate rounding or precision",
                    "Overflow, underflow, or non-convergence",
                ],
                [
                    "Specify units, ranges, precision, and rounding",
                    "Use dimensional and boundary tests",
                    "Check overflow, underflow, NaN, infinity, and convergence where applicable",
                ],
            )
        )
    if "control_logic" in facts.signals and facts.complexity >= 3:
        rules.append(
            _rule(
                "logic.condition_or_sequence",
                "Incorrect condition / branch / sequence",
                f"{name} evaluates a condition incorrectly, selects the wrong branch, omits a path, or performs steps in the wrong sequence.",
                "A boundary combination or state reaches a faulty decision or incomplete path.",
                "The intended operation is skipped, repeated, or replaced by an inappropriate operation.",
                [
                    "Wrong or missing condition",
                    "Incorrect boolean precedence",
                    "Missing sequence or case",
                    "Unreachable or unintended path",
                ],
                [
                    "Define decision tables and invariants",
                    "Use branch, boundary, and state-transition tests",
                    "Review unreachable and dead-code findings",
                ],
            )
        )
    if "state_mutation" in facts.signals:
        rules.append(
            _rule(
                "state.invalid_transition",
                "Incorrect / partial / duplicate state transition",
                f"{name} leaves shared or persistent state in an incorrect, partial, stale, or contradictory condition.",
                "An interruption, retry, concurrent action, or invalid prior state occurs during mutation.",
                "Later behavior observes state that violates the component or subsystem invariant.",
                [
                    "Missing precondition",
                    "Partial update",
                    "Non-idempotent retry",
                    "Shared state overwritten",
                ],
                [
                    "Define permitted states and transitions",
                    "Make transitions atomic or compensatable",
                    "Test interruption, replay, and invalid transition attempts",
                ],
            )
        )
    if "external_interface" in facts.signals:
        rules.extend(
            [
                _rule(
                    "interface.unavailable",
                    "Interface omission / late response",
                    f"An external dependency used by {name} is unavailable, times out, responds late, or disconnects mid-operation.",
                    "A network or service dependency is degraded during the call.",
                    "The operation blocks, aborts, retries unexpectedly, or completes only partially.",
                    [
                        "Timeout absent or too long",
                        "Connection interruption",
                        "Dependency overload/outage",
                        "Unsafe retry behavior",
                    ],
                    [
                        "Define timeouts and bounded retry behavior",
                        "Make partial operations idempotent or compensatable",
                        "Test dependency outage, latency, and recovery",
                    ],
                    "high",
                ),
                _rule(
                    "interface.bad_response",
                    "Incorrect interface data",
                    f"An external dependency returns a successful but wrong, partial, stale, duplicated, or schema-incompatible response to {name}.",
                    "The dependency responds, but its content or semantics violate the consumer's assumptions.",
                    "Incorrect external data is accepted and influences local behavior.",
                    [
                        "Schema/version drift",
                        "Partial response",
                        "Stale cache",
                        "Duplicate response",
                        "Semantic error with success status",
                    ],
                    [
                        "Validate response schema and semantics",
                        "Record provenance and freshness where needed",
                        "Test corrupt, partial, duplicate, and version-skewed responses",
                    ],
                ),
            ]
        )
    if "internal_interface" in facts.signals:
        rules.append(
            _rule(
                "interface.internal_contract",
                "Incorrect internal call / parameter / result contract",
                f"An internal caller or callee of {name} uses the wrong operation, omits the call, supplies invalid parameters, or misinterprets the result.",
                "A valid execution crosses an internal interface whose contract, units, ordering, or error semantics are incomplete or inconsistent.",
                "Incorrect data, control, or failure status propagates between software components.",
                [
                    "Wrong or missing call",
                    "Null, missing, or bad parameter",
                    "Contract or version mismatch",
                    "Error result treated as success",
                ],
                [
                    "Specify preconditions, postconditions, units, and error semantics",
                    "Test both sides of the interface including negative paths",
                    "Trace propagated effects through callers and subsystem boundaries",
                ],
            )
        )
    if {"persistence", "filesystem"} & facts.signals:
        rules.append(
            _rule(
                "storage.partial_or_corrupt",
                "Partial / corrupt / duplicate storage operation",
                f"A storage operation in {name} is lost, partial, duplicated, reordered, or reads inconsistent data.",
                "The process, filesystem, or data store fails between logically related operations.",
                "Persistent state differs from the state assumed by the application.",
                [
                    "Interrupted write",
                    "Missing transaction boundary",
                    "Concurrent update",
                    "Corrupt/incompatible data",
                    "Non-idempotent retry",
                ],
                [
                    "Define atomicity and consistency requirements",
                    "Use transactions or atomic replacement",
                    "Test interruption, retry, corruption, and concurrent update",
                ],
                "high" if "persistence" in facts.signals else "medium",
            )
        )
    if "configuration" in facts.signals:
        rules.append(
            _rule(
                "configuration.missing_or_wrong",
                "Missing / wrong configuration",
                f"{name} runs with missing, malformed, stale, inherited, or environment-inappropriate configuration.",
                "Configuration is absent or resolves to a syntactically valid but unintended value.",
                "The function targets or performs behavior different from the reviewed configuration.",
                [
                    "Unsafe default",
                    "Inherited environment variable",
                    "Unit/type ambiguity",
                    "Secret or endpoint mix-up",
                ],
                [
                    "Fail fast on invalid configuration",
                    "Validate types, ranges, environment, and target identity",
                    "Expose non-secret effective configuration for diagnostics",
                ],
            )
        )
    if "serialization" in facts.signals:
        rules.append(
            _rule(
                "data.serialization",
                "Corrupt / incompatible representation",
                f"{name} serializes or deserializes corrupt, truncated, ambiguous, or version-incompatible data.",
                "Stored or transmitted representation differs from the expected schema or encoding.",
                "Data is rejected, silently changed, or reconstructed incorrectly.",
                [
                    "Schema drift",
                    "Truncated payload",
                    "Encoding/precision loss",
                    "Unsafe or ambiguous deserialization",
                ],
                [
                    "Version schemas and validate before use",
                    "Test forward/backward compatibility and truncation",
                    "Avoid unsafe deserialization formats",
                ],
            )
        )
    if "subprocess" in facts.signals:
        rules.append(
            _rule(
                "process.uncontrolled_failure",
                "External process fails or acts on wrong target",
                f"A process launched by {name} fails, hangs, returns misleading success, or operates on an unintended target.",
                "The executable, arguments, environment, working directory, or process result differs from assumptions.",
                "The requested operation is absent, partial, or applied to the wrong resource.",
                [
                    "Executable/path substitution",
                    "Missing timeout",
                    "Ignored return status",
                    "Unsafe argument construction",
                    "Inherited environment",
                ],
                [
                    "Use explicit executable, arguments, environment, and working directory",
                    "Enforce timeout and validate result",
                    "Test partial failure and wrong-target prevention",
                ],
                "high",
            )
        )
    if "runtime_environment" in facts.signals:
        rules.append(
            _rule(
                "environment.runtime_incompatibility",
                "Incompatible runtime / dependency / tool environment",
                f"{name} behaves incorrectly after a runtime, operating system, package, interpreter, or toolchain change.",
                "The deployed environment differs from the reviewed and verified environment.",
                "The function fails, changes semantics, or uses an incompatible interface.",
                [
                    "Interpreter or operating-system change",
                    "Third-party dependency change",
                    "Build or optimization option change",
                    "Conditional platform behavior",
                ],
                [
                    "Record and reproduce the qualified environment",
                    "Pin and verify dependencies and build options",
                    "Test supported platform and upgrade combinations",
                ],
            )
        )
    if "hardware_interface" in facts.signals:
        rules.append(
            _rule(
                "hardware.abnormal_response",
                "Missing / wrong / untimely hardware response",
                f"Hardware accessed by {name} is absent, degraded, stale, out of range, reset, or responds at the wrong time.",
                "A sensor, actuator, bus, device, interrupt, or computing resource behaves off-nominally.",
                "Software issues an inappropriate command, accepts invalid device data, or fails to reach a safe state.",
                [
                    "Device or bus failure",
                    "Stale or corrupt sensor data",
                    "Wrong register, channel, or command",
                    "Reset, overload, or timing fault",
                ],
                [
                    "Specify off-nominal hardware responses",
                    "Validate range, freshness, identity, and command prerequisites",
                    "Test disconnection, reset, stuck values, overload, and recovery",
                ],
                "high",
            )
        )
    if "concurrency" in facts.signals:
        rules.append(
            _rule(
                "timing.order_or_race",
                "Wrong timing / order / concurrent interaction",
                f"{name} executes too early, too late, more than once, out of sequence, or concurrently with conflicting work.",
                "Scheduling, cancellation, duplicate delivery, or shared-state interleaving violates an ordering assumption.",
                "State or output depends on nondeterministic timing or an incomplete concurrent operation.",
                [
                    "Race condition",
                    "Missing synchronization",
                    "Cancellation leak",
                    "Duplicate task/message",
                    "Unbounded wait",
                ],
                [
                    "Document ordering, atomicity, cancellation, and idempotency",
                    "Add deterministic concurrency tests",
                    "Use deadlines and explicit synchronization where warranted",
                ],
                "high" if facts.mutates_state else "medium",
            )
        )
    elif "timing" in facts.signals:
        rules.append(
            _rule(
                "timing.late_or_early",
                "Wrong timing",
                f"{name} completes too early, too late, or uses an inappropriate time basis.",
                "Clock behavior, workload, or delay differs from the timing assumption.",
                "The result is valid in content but invalid in time.",
                [
                    "Wall-clock used for duration",
                    "Missing deadline",
                    "Blocking delay",
                    "Clock adjustment",
                    "Load-dependent latency",
                ],
                [
                    "Define timing requirements and clock semantics",
                    "Use monotonic deadlines for durations",
                    "Test deadline and overload behavior",
                ],
            )
        )
    circuit_breaker = next(
        (
            value
            for value in facts.detected_controls
            if value.get("kind") == "circuit_breaker"
        ),
        None,
    )
    if circuit_breaker:
        roles = set(circuit_breaker.get("roles", []))
        if roles & {"admission_guard", "failure_recording", "breaker_state_management"}:
            rules.append(
                _rule(
                    "resilience.circuit_breaker_containment",
                    "Circuit breaker fails to contain or trips incorrectly",
                    f"The circuit breaker managed by {name} opens too early, fails to open at the failure threshold, or permits calls while open.",
                    "Dependency calls repeatedly fail, recover, or execute concurrently around the configured trip threshold.",
                    "Failure traffic escapes containment, or healthy traffic is rejected and the affected capability becomes unnecessarily unavailable.",
                    [
                        "Incorrect or non-atomic failure count",
                        "Threshold comparison or reset is wrong",
                        "Open-state check races with dependency admission",
                        "Success clears a failure history at the wrong time",
                    ],
                    [
                        "Verify exact threshold boundary and open-state admission behavior",
                        "Control concurrent failure/success interleavings",
                        "Prove downstream calls are suppressed while open",
                    ],
                    "high",
                    "logic",
                )
            )
        if roles & {"recovery_timer", "success_reset"}:
            rules.append(
                _rule(
                    "resilience.circuit_breaker_recovery",
                    "Circuit breaker recovers at the wrong time or state",
                    f"The circuit breaker managed by {name} remains open too long, closes too early, admits multiple half-open probes, or resets incorrectly after recovery.",
                    "The cooldown expires, the clock changes, or concurrent callers attempt recovery while the dependency is degraded or newly healthy.",
                    "Recovery is delayed, unstable, or causes a renewed burst of calls that propagates dependency failure.",
                    [
                        "Wall-clock adjustment changes elapsed-time behavior",
                        "Half-open state is implicit or not serialized",
                        "Multiple recovery probes execute concurrently",
                        "Success or failure transitions reset the wrong state",
                    ],
                    [
                        "Use a monotonic elapsed-time source",
                        "Define CLOSED, OPEN, and HALF-OPEN transitions explicitly",
                        "Permit and observe a bounded recovery probe",
                        "Test cooldown boundaries, clock shifts, and concurrent probes",
                    ],
                    "high",
                    "timing",
                )
            )
        if circuit_breaker.get("scope_keys"):
            rules.append(
                _rule(
                    "resilience.circuit_breaker_isolation",
                    "Circuit breaker scope or isolation is incorrect",
                    f"The circuit breaker managed by {name} shares, loses, or applies state under the wrong dependency identity.",
                    "Multiple dependencies, tenants, processes, or server identities fail and recover independently.",
                    "One dependency can trip, reset, or bypass another dependency's containment boundary and create a wider cascade.",
                    [
                        "Unstable or colliding breaker key",
                        "Process-local state assumed to be distributed",
                        "State is not bounded or removed",
                        "Dependency identity changes across configuration reloads",
                    ],
                    [
                        "Define the breaker isolation key and lifecycle",
                        "Test independent dependency failures and recoveries",
                        "Document process-local versus shared-state behavior",
                    ],
                    "high",
                    "interface",
                )
            )
        if "degraded_fallback" in roles:
            rules.append(
                _rule(
                    "resilience.circuit_breaker_fallback",
                    "Circuit breaker fallback masks or amplifies failure",
                    f"The fallback selected by {name} is indistinguishable from success, violates the degraded contract, or triggers further unsafe work.",
                    "The breaker is open and the caller receives a placeholder, cached result, default, or explicit degraded response.",
                    "Callers proceed with incomplete capability, repeatedly retry, or fail to detect that the dependency was isolated.",
                    [
                        "Fallback has success-shaped semantics",
                        "Degraded status is not propagated",
                        "Caller retries or performs side effects despite isolation",
                        "Fallback observability lacks dependency identity and breaker state",
                    ],
                    [
                        "Define an explicit degraded response contract",
                        "Trace fallback handling through every caller",
                        "Test prohibited side effects and retry behavior while open",
                    ],
                    "high",
                    "detection",
                )
            )
    if facts.broad_handlers or facts.silent_handlers:
        rules.append(
            _rule(
                "detection.masked_failure",
                "Failure masked / not detected",
                f"{name} catches or suppresses a failure without an adequate safe response, diagnostic, or escalation.",
                "A broad or silent exception handler receives an unexpected failure.",
                "The caller or operator believes processing succeeded or lacks actionable failure information.",
                [
                    "Broad exception catch",
                    "Empty/pass handler",
                    "Fallback indistinguishable from valid result",
                    "Diagnostic context lost",
                ],
                [
                    "Catch specific exceptions",
                    "Define safe fallback and explicit failure result",
                    "Log/measure with sufficient context and test the detection path",
                ],
                "high" if facts.silent_handlers else "medium",
            )
        )
    if facts.loops and facts.complexity >= 6:
        rules.append(
            _rule(
                "resource.exhaustion",
                "Excessive resource use / non-termination",
                f"{name} consumes excessive CPU, memory, handles, requests, or time, or fails to terminate.",
                "Input size, retry count, iteration count, or downstream latency exceeds the implicit bound.",
                "The function or surrounding process becomes unavailable or misses its deadline.",
                [
                    "Unbounded loop/retry",
                    "Unbounded collection",
                    "Algorithmic amplification",
                    "Resource not released",
                ],
                [
                    "Define and enforce resource bounds",
                    "Test worst credible sizes and retry paths",
                    "Measure latency/resource use and fail safely at limits",
                ],
            )
        )
    reference = _component_ref(facts)
    custom_rule_ids = {custom.get("id") for custom in custom_rules or []}
    for custom in custom_rules or []:
        if not fnmatch.fnmatchcase(reference, custom.get("pattern", "")):
            continue
        rules.append(
            _rule(
                custom["id"],
                custom["guideword"],
                custom["failure_mode"],
                custom.get("trigger", "Project-defined initiating condition."),
                custom.get(
                    "local_effect", "Project-defined local effect requires review."
                ),
                list(custom.get("causes", [])),
                list(custom.get("actions", [])),
                custom.get("confidence", "project"),
                custom.get("failure_class") or "custom",
            )
        )
    analysis_rules = analysis_rules or {}
    included = set(analysis_rules.get("included_failure_classes", []))
    excluded = set(analysis_rules.get("excluded_failure_classes", []))
    return [
        rule
        for rule in rules
        if (
            not included
            or rule["failure_class"] in included
            or (rule["rule_id"] in custom_rule_ids and "custom" in included)
        )
        and rule["failure_class"] not in excluded
        and not (rule["rule_id"] in custom_rule_ids and "custom" in excluded)
    ]


def _function_guess(facts: FunctionFacts) -> str:
    return facts.docstring or _humanize(facts.name)


def _component_dict(
    facts: FunctionFacts,
    fan_in: int,
    called_by: list[str],
    test_refs: list[str],
    coverage: dict[str, Any] | None,
    critical_context: list[dict[str, Any]],
    mapping_context: list[dict[str, Any]],
    upstream_paths: list[list[str]],
    upstream_path_analysis: dict[str, Any],
) -> dict[str, Any]:
    component_id = stable_id("CMP", facts.path, facts.qualname, facts.kind)
    return {
        "id": component_id,
        "kind": facts.kind,
        "name": facts.name,
        "qualname": facts.qualname,
        "source": {
            "path": facts.path,
            "line": facts.line,
            "end_line": facts.end_line,
        },
        "signature": facts.signature,
        "docstring_summary": facts.docstring,
        "is_async": facts.is_async,
        "decorators": facts.decorators,
        "parameters": facts.parameters,
        "parameter_contracts": copy.deepcopy(facts.parameter_contracts),
        "calls": sorted(facts.calls),
        "ordered_calls": facts.ordered_calls,
        "call_sites": copy.deepcopy(facts.call_sites),
        "return_values": copy.deepcopy(facts.return_values),
        "alias_bindings": copy.deepcopy(facts.alias_bindings),
        "alias_bindings_omitted": facts.alias_bindings_omitted,
        "exception_raises": copy.deepcopy(facts.exception_raises),
        "exception_handlers": copy.deepcopy(facts.exception_handlers),
        "exception_records_omitted": facts.exception_records_omitted,
        "state_guards": copy.deepcopy(facts.state_guards),
        "state_transitions": copy.deepcopy(facts.state_transitions),
        "state_records_omitted": facts.state_records_omitted,
        "external_call_candidates": copy.deepcopy(facts.external_call_candidates),
        "symbol_types": copy.deepcopy(facts.symbol_types),
        "symbol_type_sources": copy.deepcopy(facts.symbol_type_sources),
        "frameworks": sorted(facts.frameworks),
        "entrypoint_types": sorted(facts.entrypoint_types),
        "interface_endpoints": copy.deepcopy(facts.interface_endpoints),
        "fan_in": fan_in,
        "called_by": called_by,
        "upstream_paths": upstream_paths,
        "upstream_path_analysis": upstream_path_analysis,
        "complexity": facts.complexity,
        "arithmetic_operations": facts.arithmetic_ops,
        "source_fingerprint": facts.source_fingerprint,
        "content_fingerprint": facts.content_fingerprint,
        "context_fingerprint": facts.context_fingerprint,
        "signals": sorted(facts.signals),
        "detected_controls": copy.deepcopy(facts.detected_controls),
        "test_references": test_refs,
        "coverage": coverage,
        "critical_context": critical_context,
        "mapping_context": mapping_context,
        "subsystems": sorted(
            {
                entry.get("subsystem", "")
                for entry in mapping_context
                if entry.get("subsystem")
            }
        ),
        "requirement_ids": sorted(
            {
                requirement
                for entry in mapping_context
                for requirement in entry.get("requirements", [])
            }
        ),
        "interface_ids": sorted(
            {
                interface
                for entry in mapping_context
                for interface in entry.get("interfaces", [])
            }
        ),
        "screening": _screening(facts, fan_in, test_refs, coverage, critical_context),
    }


def _analysis_context_fingerprint(
    component: dict[str, Any], config: dict[str, Any]
) -> str:
    hazard_ids = {
        hazard
        for entry in [
            *component.get("critical_context", []),
            *component.get("mapping_context", []),
        ]
        for hazard in entry.get("hazards", [])
    }
    requirement_ids = set(component.get("requirement_ids", []))
    interface_ids = set(component.get("interface_ids", []))
    material = {
        "project": config.get("project", {}),
        "analysis": config.get("analysis", {}),
        "risk": config.get("risk", {}),
        "critical_context": component.get("critical_context", []),
        "mapping_context": component.get("mapping_context", []),
        "hazards": [
            value
            for value in config.get("hazards", [])
            if value.get("id") in hazard_ids
        ],
        "requirements": [
            value
            for value in config.get("requirements", [])
            if value.get("id") in requirement_ids
        ],
        "system_interfaces": [
            value
            for value in config.get("system_interfaces", [])
            if value.get("id") in interface_ids
        ],
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _item_dict(
    facts: FunctionFacts,
    component: dict[str, Any],
    rule: dict[str, Any],
    hazards: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    item_id = stable_id("SFMEA", component["id"], rule["rule_id"])
    review = empty_review()
    review.update(
        {
            "function": _function_guess(facts),
            "failure_mode": rule["failure_mode"],
            "trigger": rule["trigger"],
            "causes": list(rule["causes"]),
            "local_effect": rule["local_effect"],
            "recommended_actions": list(rule["actions"]),
        }
    )
    linked_hazards = sorted(
        {
            hazard_id
            for entry in [
                *component.get("critical_context", []),
                *component.get("mapping_context", []),
            ]
            for hazard_id in entry.get("hazards", [])
        }
    )
    review["linked_hazards"] = linked_hazards
    review["requirement"] = "\n".join(component.get("requirement_ids", []))
    if len(linked_hazards) == 1:
        hazard = hazards.get(linked_hazards[0], {})
        if hazard.get("end_effect"):
            review["end_effect"] = hazard["end_effect"]
        if isinstance(hazard.get("severity"), int):
            review["severity"] = hazard["severity"]
            review["severity_rationale"] = (
                f"Inherited from project-defined hazard {linked_hazards[0]}; confirm applicability."
            )
        if hazard.get("severity_category"):
            review["severity_category"] = hazard["severity_category"]
            review["severity_rationale"] = (
                f"Inherited from project-defined hazard {linked_hazards[0]}; confirm applicability."
            )
    evidence = [
        f"Source: {facts.path}:{facts.line}",
        f"Scanner rule: {rule['rule_id']}",
    ]
    if component["signals"]:
        evidence.append("Observed code signals: " + ", ".join(component["signals"]))
    if component["test_references"]:
        evidence.append(
            "Textual test references: " + ", ".join(component["test_references"])
        )
    if component.get("coverage"):
        coverage = component["coverage"]
        evidence.append(
            "Coverage.py observed lines in function: "
            f"{coverage.get('covered_lines', 0)} covered, {coverage.get('missing_lines', 0)} missing"
        )
        if coverage.get("branch_percent") is not None:
            evidence.append(
                "Coverage.py observed branches in function: "
                f"{coverage.get('covered_branches', 0)} covered, "
                f"{coverage.get('missing_branches', 0)} missing"
            )
    if component.get("called_by"):
        evidence.append(
            "Observed internal callers: " + ", ".join(component["called_by"][:10])
        )
    for path in component.get("upstream_paths", [])[:5]:
        evidence.append("Observed propagation path: " + " -> ".join(path))
    detected_controls = copy.deepcopy(component.get("detected_controls", []))
    for control in detected_controls:
        if control.get("kind") != "circuit_breaker":
            continue
        evidence.append(
            "Detected circuit-breaker candidate roles: "
            + ", ".join(control.get("roles", []))
        )
        if control.get("threshold_expressions"):
            evidence.append(
                "Circuit-breaker threshold expression(s): "
                + " | ".join(control["threshold_expressions"])
            )
        if control.get("cooldown_expressions"):
            evidence.append(
                "Circuit-breaker cooldown expression(s): "
                + " | ".join(control["cooldown_expressions"])
            )
        evidence.append(str(control.get("notice", "")))
    return {
        "id": item_id,
        "component_id": component["id"],
        "source_status": "active",
        "source_change": "new",
        "source": component["source"],
        "component": {
            "kind": component["kind"],
            "qualname": component["qualname"],
            "signature": component["signature"],
            "subsystems": component.get("subsystems", []),
            "requirement_ids": component.get("requirement_ids", []),
            "interface_ids": component.get("interface_ids", []),
        },
        "scanner": {
            "rule_id": rule["rule_id"],
            "failure_class": rule["failure_class"],
            "source_fingerprint": facts.source_fingerprint,
            "content_fingerprint": facts.content_fingerprint,
            "context_fingerprint": facts.context_fingerprint,
            "analysis_context_fingerprint": component.get(
                "analysis_context_fingerprint", ""
            ),
            "guideword": rule["guideword"],
            "failure_mode": rule["failure_mode"],
            "trigger": rule["trigger"],
            "confidence": rule["confidence"],
            "screening_priority": component["screening"]["priority"],
            "screening_reasons": component["screening"]["reasons"],
            "evidence": evidence,
            "called_by": copy.deepcopy(component.get("called_by", [])[:50]),
            "upstream_paths": copy.deepcopy(component.get("upstream_paths", [])[:25]),
            "upstream_path_analysis": copy.deepcopy(
                component.get("upstream_path_analysis", {})
            ),
            "propagation_notice": (
                "Static caller paths indicate potential exposure, not runtime causality "
                "or confirmed failure-effect propagation."
            ),
            "detected_controls": detected_controls,
            "citations": citations_for_rule(rule["rule_id"]),
        },
        "review": review,
        "review_history": [],
    }


def scan_repository(
    root: str | Path,
    *,
    include_private: bool | None = None,
    include_tests: bool | None = None,
    include_nested: bool | None = None,
    config: dict[str, Any] | None = None,
    coverage_json: str | Path | None = None,
    telemetry: dict[str, Any] | None = None,
    fact_cache: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan *root* and return a new, unmerged SFMEA analysis document.

    ``fact_cache`` is an optional caller-owned, in-memory cache. Entries are keyed
    by the exact source bytes, repository-relative path, and parser options; cached
    facts are deep-copied before downstream enrichment. This keeps reuse
    deterministic and prevents stale metadata-only cache hits.
    """

    scan_started_ns = time.perf_counter_ns()
    phase_started_ns = scan_started_ns
    if telemetry is not None:
        telemetry.clear()
        telemetry.update({"format": "pysfmea-scan-telemetry-1", "phases_seconds": {}})

    def finish_phase(name: str) -> None:
        nonlocal phase_started_ns
        finished_ns = time.perf_counter_ns()
        if telemetry is not None:
            telemetry["phases_seconds"][name] = round(
                (finished_ns - phase_started_ns) / 1_000_000_000,
                6,
            )
        phase_started_ns = finished_ns

    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError(f"repository path is not a directory: {root_path}")

    config = normalize_config(config)
    guidance_profiles = list(config["analysis"]["guidance_profiles"])
    organizational_packs = []
    for configured_path in config["analysis"].get("guidance_packs", []):
        pack_path = Path(configured_path).expanduser()
        if not pack_path.is_absolute():
            pack_path = root_path / pack_path
        pack = load_organizational_guidance_pack(pack_path)
        organizational_packs.append(pack)
        guidance_profiles.append(pack["profile"]["id"])
    guidance_profiles = list(dict.fromkeys(guidance_profiles))
    guidance = guidance_bundle(
        guidance_profiles,
        organizational_packs=organizational_packs,
    )
    guidance_applicability = copy.deepcopy(config.get("guidance_applicability", []))
    apply_guidance_applicability(guidance, guidance_applicability)
    guidance_rule_mappings = copy.deepcopy(config.get("guidance_rule_mappings", []))
    apply_project_guidance_mappings(guidance, guidance_rule_mappings)
    scan_config = config.get("scan", {})
    if include_private is None:
        include_private = bool(scan_config.get("include_private", True))
    if include_tests is None:
        include_tests = bool(scan_config.get("include_tests", False))
    if include_nested is None:
        include_nested = bool(scan_config.get("include_nested", True))
    exclude_patterns = list(scan_config.get("exclude", []))
    test_evidence_include_patterns = list(scan_config.get("test_evidence_include", []))
    boundary_evidence_include_patterns = list(
        scan_config.get("boundary_evidence_include", [])
    )
    focus_patterns = list(scan_config.get("focus", []))
    review_depth = str(scan_config.get("review_depth", "focused"))
    review_queue_max_per_component = int(
        scan_config.get("review_queue_max_per_component", 3)
    )
    review_queue_max_total = int(scan_config.get("review_queue_max_total", 1_000))
    diagnostic_warning_budget = int(
        scan_config.get("diagnostic_warning_budget", 25_000)
    )
    diagnostic_per_rule_budget = int(
        scan_config.get("diagnostic_per_rule_budget", 10_000)
    )
    external_call_prefixes = list(scan_config.get("external_call_prefixes", []))
    external_receiver_hints = list(scan_config.get("external_receiver_hints", []))
    external_method_hints = list(scan_config.get("external_method_hints", []))
    cache_entries: dict[str, Any] | None = None
    cache_hits = 0
    cache_misses = 0
    used_cache_keys: set[str] = set()
    if fact_cache is not None:
        if fact_cache.get("format") != PYTHON_FACT_CACHE_FORMAT:
            fact_cache.clear()
            fact_cache.update({"format": PYTHON_FACT_CACHE_FORMAT, "entries": {}})
        entries = fact_cache.get("entries")
        if not isinstance(entries, dict):
            entries = {}
            fact_cache["entries"] = entries
        cache_entries = entries
    coverage_selection = "cli_argument" if coverage_json is not None else "none"
    if coverage_json is None:
        coverage_json = scan_config.get("coverage_json") or None
        if coverage_json is not None:
            coverage_selection = "configured"
    if coverage_json is None and scan_config.get("coverage_discovery", True):
        for candidate in (
            root_path / "coverage.json",
            root_path / ".artifacts" / "coverage.json",
        ):
            if candidate.exists():
                coverage_json = candidate
                coverage_selection = "conventional_path_discovery"
                break
    finish_phase("configuration_and_guidance")

    warnings: list[dict[str, Any]] = []
    dependency_snapshots: dict[Path, bytes] = {}
    contract_snapshots: dict[Path, bytes] = {}
    dependency_warnings: list[dict[str, Any]] = []
    contract_warnings: list[dict[str, Any]] = []
    # The inventories are independent and read-only. Separate warning/snapshot
    # collections plus fixed-order merging keep the governed result deterministic.
    with ThreadPoolExecutor(
        max_workers=2, thread_name_prefix="pysfmea-inventory"
    ) as executor:
        dependency_future = executor.submit(
            _dependency_inventory,
            root_path,
            dependency_warnings,
            dependency_snapshots,
        )
        contract_future = executor.submit(
            _contract_inventory,
            root_path,
            contract_warnings,
            contract_snapshots,
        )
        dependencies = dependency_future.result()
        contracts = contract_future.result()
    warnings.extend(dependency_warnings)
    warnings.extend(contract_warnings)
    finish_phase("dependency_and_contract_inventory")
    facts_list: list[FunctionFacts] = []
    files = _python_files(
        root_path,
        include_tests=include_tests,
        exclude_patterns=exclude_patterns,
        warnings=warnings,
    )
    finish_phase("python_discovery")
    parsed_python_paths: set[str] = set()
    source_snapshots: dict[Path, bytes] = {}
    source_snapshot_errors: dict[Path, str] = {}
    for file_path in files:
        relative = file_path.relative_to(root_path).as_posix()
        try:
            raw = _read_python_source_bytes_bounded(file_path)
            source_snapshots[file_path] = raw
            cache_key = hashlib.sha256(
                json.dumps(
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "include_private": include_private,
                        "include_nested": include_nested,
                        "python_ast": sys.version_info[:2],
                        "scanner_version": __version__,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            cached = cache_entries.get(cache_key) if cache_entries is not None else None
            if isinstance(cached, list) and all(
                isinstance(value, FunctionFacts) for value in cached
            ):
                facts_list.extend(copy.deepcopy(cached))
                parsed_python_paths.add(relative)
                cache_hits += 1
                used_cache_keys.add(cache_key)
                continue
            source = _decode_python_source(raw)
            tree = ast.parse(source, filename=relative)
        except ValueError as exc:
            if file_path not in source_snapshots:
                source_snapshot_errors[file_path] = str(exc)
            warnings.append(
                {"path": relative, "message": str(exc), "type": "PythonSourceError"}
            )
            continue
        except SyntaxError as exc:
            warnings.append(
                {"path": relative, "message": str(exc), "type": "SyntaxError"}
            )
            continue
        parsed_python_paths.add(relative)
        collector = _ModuleCollector(
            relative,
            include_private=include_private,
            aliases=_module_aliases(tree),
            context_fingerprint=_module_context_fingerprint(tree),
            include_nested=include_nested,
        )
        collector.visit(tree)
        file_facts = list(collector.functions)
        module_facts = _module_initialization_facts(
            relative,
            tree,
            _module_aliases(tree),
            _module_context_fingerprint(tree),
        )
        if module_facts:
            file_facts.append(module_facts)
        facts_list.extend(file_facts)
        if cache_entries is not None:
            cache_entries[cache_key] = copy.deepcopy(file_facts)
            cache_misses += 1
            used_cache_keys.add(cache_key)
    _compose_registered_route_prefixes(
        facts_list, source_snapshots, root_path, warnings
    )
    finish_phase("python_parsing")
    cache_entries_before_prune = len(cache_entries or {})
    if fact_cache is not None and cache_entries is not None:
        pruned_entries = {key: cache_entries[key] for key in sorted(used_cache_keys)}
        fact_cache["entries"] = pruned_entries
        cache_entries = pruned_entries
    if telemetry is not None:
        telemetry["fact_cache"] = {
            "enabled": fact_cache is not None,
            "hits": cache_hits,
            "misses": cache_misses,
            "entries": len(cache_entries or {}),
            "pruned_entries": cache_entries_before_prune - len(cache_entries or {}),
            "authority": "exact_source_bytes_and_parser_options",
        }

    test_evidence_snapshots: dict[Path, bytes] = {}
    test_evidence_errors: dict[Path, str] = {}
    tests = _test_index(
        root_path,
        warnings,
        source_snapshots,
        test_evidence_snapshots,
        test_evidence_errors,
        exclude_patterns,
        test_evidence_include_patterns,
    )
    test_reference_index, test_evidence_analysis = _test_evidence_analysis(tests)
    coverage_snapshots: dict[Path, bytes] = {}
    coverage, coverage_warnings, coverage_provenance = _load_coverage_document(
        coverage_json,
        root_path,
        coverage_snapshots,
    )
    warnings.extend(coverage_warnings)
    repository_inventory = build_repository_inventory(
        root_path,
        selected_python_paths={
            path.relative_to(root_path).as_posix() for path in files
        },
        parsed_python_paths=parsed_python_paths,
        include_tests=include_tests,
        exclude_patterns=exclude_patterns,
        boundary_evidence_include_patterns=boundary_evidence_include_patterns,
        source_snapshots={
            path.relative_to(root_path).as_posix(): raw
            for path, raw in source_snapshots.items()
        },
        test_evidence_snapshots={
            path.relative_to(root_path).as_posix(): raw
            for path, raw in test_evidence_snapshots.items()
        },
        dependency_snapshots={
            path.relative_to(root_path).as_posix(): raw
            for path, raw in dependency_snapshots.items()
        },
        contract_snapshots={
            path.relative_to(root_path).as_posix(): raw
            for path, raw in contract_snapshots.items()
        },
        coverage_snapshots={
            path.relative_to(root_path).as_posix(): raw
            for path, raw in coverage_snapshots.items()
        },
    )
    baseline = _repository_baseline(
        root_path,
        files,
        config,
        dependencies,
        contracts,
        repository_inventory,
        source_snapshots,
        source_snapshot_errors,
        test_evidence_snapshots,
        test_evidence_errors,
    )
    finish_phase("evidence_inventory_and_baseline")

    if focus_patterns:
        facts_list = [
            facts
            for facts in facts_list
            if _matches_pattern(_component_ref(facts), focus_patterns)
        ]

    callers, resolved_calls = _internal_call_resolution(facts_list)
    facts_by_reference = {_component_ref(facts): facts for facts in facts_list}
    for reference, facts in facts_by_reference.items():
        facts.external_call_candidates = _external_call_candidates(
            facts,
            resolved_calls.get(reference, set()),
            configured_prefixes=external_call_prefixes,
            configured_receiver_hints=external_receiver_hints,
            configured_method_hints=external_method_hints,
        )
        if facts.external_call_candidates:
            facts.signals.add("external_interface_candidate")
    for target_reference, caller_references in callers.items():
        if caller_references:
            facts_by_reference[target_reference].signals.add("internal_interface")
        for caller_reference in caller_references:
            facts_by_reference[caller_reference].signals.add("internal_interface")
    interprocedural_data_flow = _interprocedural_data_flow(facts_list)
    alias_object_flow = _alias_object_flow(facts_list)
    concurrency_model = _concurrency_model(facts_list)
    exception_propagation = _exception_propagation_model(facts_list)
    state_machine_model = _state_machine_model(facts_list)
    resilience_semantics = _resilience_semantics_model(facts_list)
    authorization_scope_flow = _authorization_scope_flow(
        facts_list, interprocedural_data_flow
    )
    finish_phase("call_graph_and_interfaces")
    critical_entries = list(config.get("critical_functions", []))
    mapping_entries = list(config.get("component_mappings", []))
    custom_rules = list(config.get("custom_rules", []))
    hazards = {
        hazard["id"]: hazard
        for hazard in config.get("hazards", [])
        if isinstance(hazard, dict) and hazard.get("id")
    }
    components: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    for facts in facts_list:
        called_by = callers.get(_component_ref(facts), [])
        fan_in = len(called_by)
        test_refs = _find_test_references(facts.name, test_reference_index)
        function_coverage = _function_coverage(facts, coverage)
        critical_context = _critical_context(facts, critical_entries)
        mapping_context = _mapping_context(facts, mapping_entries)
        if any(entry.get("interfaces") for entry in mapping_context):
            facts.signals.add("external_interface")
        upstream_paths, upstream_path_analysis = _upstream_paths(
            _component_ref(facts), callers
        )
        component = _component_dict(
            facts,
            fan_in,
            called_by,
            test_refs,
            function_coverage,
            critical_context,
            mapping_context,
            upstream_paths,
            upstream_path_analysis,
        )
        component["analysis_context_fingerprint"] = _analysis_context_fingerprint(
            component, config
        )
        components.append(component)
        items.extend(
            _item_dict(facts, component, rule, hazards)
            for rule in _candidate_rules(
                facts, custom_rules, config.get("analysis", {})
            )
        )

    dependency_element = _dependency_component_and_item(
        dependencies, config.get("analysis", {})
    )
    if dependency_element:
        dependency_component, dependency_item = dependency_element
        components.append(dependency_component)
        items.append(dependency_item)
    for contract_component, contract_item in _contract_components_and_items(
        contracts, config
    ):
        components.append(contract_component)
        items.append(contract_item)
    for common_cause_component, common_cause_item in _common_cause_elements(
        list(config.get("common_causes", [])),
        components,
        hazards,
        config.get("analysis", {}),
    ):
        components.append(common_cause_component)
        items.append(common_cause_item)
    contract_semantics = _contract_semantics_model(contracts, components)
    (
        deployment_topology,
        shared_fate_analysis,
        architecture_hierarchy,
    ) = _architecture_models(
        repository_inventory,
        components,
        [
            str(value)
            for value in config.get("project", {}).get("deployment_environments", [])
        ],
    )
    inbound_flow_ids: dict[str, list[str]] = defaultdict(list)
    outbound_flow_ids: dict[str, list[str]] = defaultdict(list)
    for edge in interprocedural_data_flow["edges"]:
        outbound_flow_ids[str(edge["caller_component_id"])].append(str(edge["id"]))
        inbound_flow_ids[str(edge["callee_component_id"])].append(str(edge["id"]))
    concurrency_operation_ids: dict[str, list[str]] = defaultdict(list)
    concurrency_relation_ids: dict[str, list[str]] = defaultdict(list)
    for operation in concurrency_model["operations"]:
        concurrency_operation_ids[str(operation.get("component_id", ""))].append(
            str(operation["id"])
        )
    for relation in concurrency_model["relations"]:
        concurrency_relation_ids[str(relation.get("component_id", ""))].append(
            str(relation["id"])
        )
    exception_raise_ids: dict[str, list[str]] = defaultdict(list)
    exception_handler_ids: dict[str, list[str]] = defaultdict(list)
    exception_inbound_edge_ids: dict[str, list[str]] = defaultdict(list)
    exception_outbound_edge_ids: dict[str, list[str]] = defaultdict(list)
    for raised in exception_propagation["raises"]:
        exception_raise_ids[str(raised.get("component_id", ""))].append(
            str(raised["id"])
        )
    for handler in exception_propagation["handlers"]:
        exception_handler_ids[str(handler.get("component_id", ""))].append(
            str(handler["id"])
        )
    for edge in exception_propagation["edges"]:
        exception_outbound_edge_ids[str(edge.get("callee_component_id", ""))].append(
            str(edge["id"])
        )
        exception_inbound_edge_ids[str(edge.get("caller_component_id", ""))].append(
            str(edge["id"])
        )
    state_guard_ids: dict[str, list[str]] = defaultdict(list)
    state_transition_ids: dict[str, list[str]] = defaultdict(list)
    for guard in state_machine_model["guards"]:
        state_guard_ids[str(guard.get("component_id", ""))].append(str(guard["id"]))
    for transition in state_machine_model["transitions"]:
        state_transition_ids[str(transition.get("component_id", ""))].append(
            str(transition["id"])
        )
    resilience_operation_ids: dict[str, list[str]] = defaultdict(list)
    for operation in resilience_semantics["operations"]:
        resilience_operation_ids[str(operation.get("component_id", ""))].append(
            str(operation["id"])
        )
    authorization_edge_ids: dict[str, list[str]] = defaultdict(list)
    for edge in authorization_scope_flow["edges"]:
        authorization_edge_ids[str(edge.get("caller_component_id", ""))].append(
            str(edge["id"])
        )
        authorization_edge_ids[str(edge.get("callee_component_id", ""))].append(
            str(edge["id"])
        )
    contract_operation_ids: dict[str, list[str]] = defaultdict(list)
    contract_compatibility_ids: dict[str, list[str]] = defaultdict(list)
    deployment_node_ids: dict[str, list[str]] = defaultdict(list)
    shared_fate_region_ids: dict[str, list[str]] = defaultdict(list)
    architecture_node_ids: dict[str, list[str]] = defaultdict(list)
    component_ids_by_source_path: dict[str, list[str]] = defaultdict(list)
    for component in components:
        component_ids_by_source_path[
            str(component.get("source", {}).get("path", ""))
        ].append(str(component.get("id", "")))
    for operation in contract_semantics["operations"]:
        for component_id in component_ids_by_source_path.get(
            str(operation.get("contract_path", "")), []
        ):
            contract_operation_ids[component_id].append(str(operation["id"]))
    for finding in contract_semantics["compatibility"]:
        for component_id in finding.get("python_component_ids", []):
            contract_compatibility_ids[str(component_id)].append(str(finding["id"]))
    for placement in deployment_topology["placements"]:
        deployment_node_ids[str(placement.get("component_id", ""))].extend(
            str(value) for value in placement.get("node_ids", [])
        )
    for region in shared_fate_analysis["regions"]:
        for component_id in region.get("affected_component_ids", []):
            shared_fate_region_ids[str(component_id)].append(str(region["id"]))
    for membership in architecture_hierarchy["memberships"]:
        architecture_node_ids[str(membership.get("component_id", ""))].extend(
            str(value) for value in membership.get("node_ids", [])
        )
    for component in components:
        component_id = str(component.get("id", ""))
        inbound = inbound_flow_ids.get(component_id, [])
        outbound = outbound_flow_ids.get(component_id, [])
        component["data_flow"] = {
            "inbound_edge_ids": inbound[:1_000],
            "inbound_edges_omitted": max(0, len(inbound) - 1_000),
            "outbound_edge_ids": outbound[:1_000],
            "outbound_edges_omitted": max(0, len(outbound) - 1_000),
            "authority": "references_to_complete_top_level_static_data_flow_projection",
        }
        operation_ids = concurrency_operation_ids.get(component_id, [])
        relation_ids = concurrency_relation_ids.get(component_id, [])
        component["concurrency"] = {
            "operation_ids": operation_ids[:1_000],
            "operations_omitted": max(0, len(operation_ids) - 1_000),
            "relation_ids": relation_ids[:2_000],
            "relations_omitted": max(0, len(relation_ids) - 2_000),
            "authority": "references_to_complete_top_level_static_concurrency_model",
        }
        raise_ids = exception_raise_ids.get(component_id, [])
        handler_ids = exception_handler_ids.get(component_id, [])
        incoming_exception_edges = exception_inbound_edge_ids.get(component_id, [])
        outgoing_exception_edges = exception_outbound_edge_ids.get(component_id, [])
        component["exception_flow"] = {
            "raise_ids": raise_ids[:1_000],
            "raises_omitted": max(0, len(raise_ids) - 1_000),
            "handler_ids": handler_ids[:1_000],
            "handlers_omitted": max(0, len(handler_ids) - 1_000),
            "incoming_edge_ids": incoming_exception_edges[:2_000],
            "incoming_edges_omitted": max(0, len(incoming_exception_edges) - 2_000),
            "outgoing_edge_ids": outgoing_exception_edges[:2_000],
            "outgoing_edges_omitted": max(0, len(outgoing_exception_edges) - 2_000),
            "authority": "references_to_complete_top_level_static_exception_model",
        }
        guard_ids = state_guard_ids.get(component_id, [])
        transition_ids = state_transition_ids.get(component_id, [])
        component["state_machine"] = {
            "guard_ids": guard_ids[:1_000],
            "guards_omitted": max(0, len(guard_ids) - 1_000),
            "transition_ids": transition_ids[:1_000],
            "transitions_omitted": max(0, len(transition_ids) - 1_000),
            "authority": "references_to_complete_top_level_static_state_machine_model",
        }
        resilience_ids = resilience_operation_ids.get(component_id, [])
        component["resilience_semantics"] = {
            "operation_ids": resilience_ids[:2_000],
            "operations_omitted": max(0, len(resilience_ids) - 2_000),
            "authority": "references_to_complete_top_level_static_resilience_semantics",
        }
        auth_ids = authorization_edge_ids.get(component_id, [])
        component["authorization_scope_flow"] = {
            "edge_ids": auth_ids[:2_000],
            "edges_omitted": max(0, len(auth_ids) - 2_000),
            "authority": "references_to_complete_top_level_static_authorization_scope_flow",
        }
        component["contract_semantics"] = {
            "operation_ids": contract_operation_ids.get(component_id, [])[:1_000],
            "compatibility_ids": contract_compatibility_ids.get(component_id, [])[
                :1_000
            ],
            "authority": "references_to_complete_top_level_local_contract_semantics",
        }
        topology_ids = deployment_node_ids.get(component_id, [])
        component["deployment_topology"] = {
            "node_ids": topology_ids[:1_000],
            "nodes_omitted": max(0, len(topology_ids) - 1_000),
            "status": "candidate_placement" if topology_ids else "unplaced",
            "authority": "references_to_top_level_declared_deployment_topology",
        }
        fate_ids = shared_fate_region_ids.get(component_id, [])
        component["shared_fate"] = {
            "region_ids": fate_ids[:1_000],
            "regions_omitted": max(0, len(fate_ids) - 1_000),
            "authority": "references_to_top_level_static_shared_fate_candidates",
        }
        hierarchy_ids = architecture_node_ids.get(component_id, [])
        component["architecture_hierarchy"] = {
            "node_ids": hierarchy_ids[:1_000],
            "nodes_omitted": max(0, len(hierarchy_ids) - 1_000),
            "authority": "references_to_top_level_deterministic_architecture_hierarchy",
        }
    finish_phase("component_and_candidate_generation")

    for item in items:
        scanner = item.setdefault("scanner", {})
        scanner["citations"] = citations_for_rule(
            str(scanner.get("rule_id", "")),
            guidance_profiles,
            catalog=guidance,
        )

    priority_order = {"high": 0, "medium": 1, "low": 2, "manual": 3}
    items.sort(
        key=lambda item: (
            priority_order.get(item["scanner"]["screening_priority"], 9),
            item["source"]["path"],
            item["source"]["line"],
            item["scanner"]["rule_id"],
        )
    )

    priority_counts = {priority: 0 for priority in ("high", "medium", "low")}
    for item in items:
        priority_counts[item["scanner"]["screening_priority"]] += 1
    finish_phase("guidance_and_prioritization")
    analysis: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generator": {
            "name": "PySFMEA",
            "version": __version__,
            "analysis_schema_version": SCHEMA_VERSION,
        },
        "project": {
            "name": config.get("project", {}).get("name") or root_path.name,
            "root": str(root_path),
            "scanned_at": utc_now(),
            "baseline": baseline,
            "settings": {
                "include_private": include_private,
                "include_tests": include_tests,
                "include_nested": include_nested,
                "review_depth": review_depth,
                "review_queue_max_per_component": review_queue_max_per_component,
                "review_queue_max_total": review_queue_max_total,
                "diagnostic_warning_budget": diagnostic_warning_budget,
                "diagnostic_per_rule_budget": diagnostic_per_rule_budget,
                "external_call_prefixes": external_call_prefixes,
                "external_receiver_hints": external_receiver_hints,
                "external_method_hints": external_method_hints,
                "exclude": exclude_patterns,
                "test_evidence_include": test_evidence_include_patterns,
                "boundary_evidence_include": boundary_evidence_include_patterns,
                "focus": focus_patterns,
                "coverage_json": str(coverage_json or ""),
                "coverage_discovery": bool(scan_config.get("coverage_discovery", True)),
                "coverage_selection": coverage_selection,
                "test_evidence_analysis": test_evidence_analysis,
            },
        },
        "context": {
            "project": config.get("project", {}),
            "analysis": config.get("analysis", {}),
            "risk": config.get("risk", {}),
            "quality": config.get("quality", {}),
            "hazards": list(config.get("hazards", [])),
            "fault_trees": list(config.get("fault_trees", [])),
            "requirements": list(config.get("requirements", [])),
            "component_mappings": mapping_entries,
            "system_interfaces": list(config.get("system_interfaces", [])),
            "reviewers": list(config.get("reviewers", [])),
            "dependencies": dependencies,
            "contracts": contracts,
            "common_causes": list(config.get("common_causes", [])),
            "critical_functions": critical_entries,
            "custom_rule_count": len(custom_rules),
            "guidance_applicability": guidance_applicability,
            "guidance_rule_mappings": guidance_rule_mappings,
            "interface_dispositions": copy.deepcopy(
                config.get("interface_dispositions", [])
            ),
        },
        "system_context": build_system_context(config),
        "repository_inventory": repository_inventory,
        "interface_reconciliation": reconcile_cross_stack_interfaces(
            components,
            repository_inventory,
            dispositions=config.get("interface_dispositions", []),
        ),
        "methodology": {
            "name": "Software Failure Modes and Effects Analysis (SFMEA)",
            "basis": selected_sources_from_bundle(guidance),
            "notice": METHODOLOGY_NOTICE,
            "review_checklist": REVIEW_CHECKLIST,
        },
        "guidance": guidance,
        "summary": {
            "python_files": len(files),
            "components": len(components),
            "candidate_failure_modes": len(items),
            "interprocedural_data_flow_edges": interprocedural_data_flow["summary"][
                "resolved_call_edges"
            ],
            "alias_object_flow_bindings": alias_object_flow["summary"][
                "bindings_discovered"
            ],
            "concurrency_operations": concurrency_model["summary"][
                "operations_discovered"
            ],
            "exception_propagation_edges": exception_propagation["summary"][
                "propagation_edges_discovered"
            ],
            "state_transitions": state_machine_model["summary"][
                "transitions_discovered"
            ],
            "resilience_semantic_operations": resilience_semantics["summary"][
                "operations_discovered"
            ],
            "authorization_scope_flow_edges": authorization_scope_flow["summary"][
                "flow_edges_discovered"
            ],
            "contract_semantic_operations": contract_semantics["summary"][
                "operations_discovered"
            ],
            "deployment_topology_nodes": deployment_topology["summary"][
                "nodes_discovered"
            ],
            "shared_fate_regions": shared_fate_analysis["summary"]["regions"],
            "architecture_hierarchy_nodes": architecture_hierarchy["summary"]["nodes"],
            "screening_priorities": priority_counts,
            "warnings": len(warnings),
            "repository_artifacts": repository_inventory.get("summary", {}).get(
                "files", 0
            ),
            "opaque_or_unresolved_artifacts": repository_inventory.get(
                "summary", {}
            ).get("opaque_or_unresolved", 0),
        },
        "components": components,
        "interprocedural_data_flow": interprocedural_data_flow,
        "alias_object_flow": alias_object_flow,
        "concurrency_model": concurrency_model,
        "exception_propagation": exception_propagation,
        "state_machine_model": state_machine_model,
        "resilience_semantics": resilience_semantics,
        "authorization_scope_flow": authorization_scope_flow,
        "contract_semantics": contract_semantics,
        "deployment_topology": deployment_topology,
        "shared_fate_analysis": shared_fate_analysis,
        "architecture_hierarchy": architecture_hierarchy,
        "items": items,
        "warnings": warnings,
        "suggestions": [],
        "generated_summaries": [],
        "runtime_evidence": {"imports": [], "spans": [], "edges": []},
    }
    if coverage_provenance:
        coverage_provenance["selection"] = coverage_selection
        analysis["project"]["settings"]["coverage_evidence"] = coverage_provenance
    refresh_assurance_register(analysis, {})
    analysis["sfta"] = build_sfta(analysis)
    analysis["adapter_runs"] = build_adapter_run_ledger(analysis)
    analysis["run_manifest"] = create_run_manifest(analysis)
    finish_phase("derived_models_and_manifest")
    if telemetry is not None:
        telemetry["total_seconds"] = round(
            (time.perf_counter_ns() - scan_started_ns) / 1_000_000_000,
            6,
        )
        telemetry["authority"] = (
            "derived_performance_observation_not_primary_assurance_evidence"
        )
        telemetry["fresh_downstream_analysis"] = True
        analysis["project"]["settings"]["scan_telemetry"] = copy.deepcopy(telemetry)
        # Bind the final observed execution provenance rather than the pre-telemetry settings.
        analysis["run_manifest"] = create_run_manifest(analysis)
    return analysis
