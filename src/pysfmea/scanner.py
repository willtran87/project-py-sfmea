"""AST-based Python repository inventory and SFMEA candidate generation."""

from __future__ import annotations

import ast
import copy
import fnmatch
import hashlib
import io
import json
import re
import subprocess
import tokenize
import tomllib
from collections.abc import Iterable
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
    citations_for_rule,
    guidance_bundle,
    load_organizational_guidance_pack,
    selected_sources_from_bundle,
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
    "boto3",
    "botocore",
    "grpc",
    "httpx",
    "kafka",
    "pika",
    "redis",
    "requests",
    "socket",
    "urllib",
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
CONFIG_NAMES = {"os.environ", "os.getenv", "dotenv", "argparse", "click", "typer"}
FILESYSTEM_NAMES = {"open", "io.open", "pathlib.Path", "os.remove", "os.rename", "shutil"}
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


def _humanize(name: str) -> str:
    value = name.strip("_").replace("_", " ") or name
    return value[:1].upper() + value[1:]


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
    calls: set[str] = field(default_factory=set)
    ordered_calls: list[str] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    entrypoint_types: set[str] = field(default_factory=set)
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
    explicit = any(token in searchable for token in ("circuit", "breaker", "half-open", "half_open"))
    supporting = sum(
        token in searchable
        for token in ("cooldown", "failure", "threshold", "record_success", "record_failure")
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
    if any(token in searchable for token in ("check_circuit", "circuit_open", "is_open")) or (
        "open" in structural_text
        and any(token in structural_text for token in ("state", "circuit", "breaker"))
    ):
        roles.add("admission_guard")
    if any(token in searchable for token in ("record_failure", "failure_count", "failures")) and any(
        isinstance(value, (ast.Assign, ast.AnnAssign, ast.AugAssign)) for value in assignments
    ):
        roles.add("failure_recording")
    if (
        any(token in searchable for token in ("record_success", "reset", "clear"))
        and bool(assignments)
    ) or any(
        call.endswith((".pop", ".clear")) for call in calls
    ):
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
    if any(token in searchable for token in ("fallback", "placeholder", "skipping", "temporarily unavailable")):
        roles.add("degraded_fallback")
    if any(token in structural_text for token in ("circuit", "breaker")) or (
        "state" in structural_text
        and any(token in structural_text for token in ("closed", "open", "half_open", "half-open"))
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
            isinstance(operator, (ast.Gt, ast.GtE, ast.Eq))
            for operator in value.ops
        ):
            threshold_expressions.append(expression)
        if any(token in lowered for token in ("cooldown", "circuit_open", "breaker")) and any(
            token in lowered for token in ("time", "monotonic", "clock")
        ):
            cooldown_expressions.append(expression)

    clock_sources = sorted(
        call
        for call in calls
        if call.endswith(("time", "monotonic", "perf_counter"))
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
                for token in ("fallback", "placeholder", "skipping", "temporarily unavailable")
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
        if any(token in parameter.casefold() for token in ("server", "dependency", "client", "service", "key", "id"))
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


class _FactVisitor(ast.NodeVisitor):
    def __init__(self, facts: FunctionFacts, aliases: dict[str, str]) -> None:
        self.facts = facts
        self.aliases = aliases

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Do not attribute nested function implementation to its parent.
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        raw = _dotted_name(node.func)
        resolved = self._resolve(raw)
        if resolved:
            self.facts.calls.add(resolved)
            self.facts.ordered_calls.append(resolved)
            self._classify_call(resolved)
        self.generic_visit(node)

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
                self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")

    def visit_If(self, node: ast.If) -> None:
        self.facts.complexity += 1
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.facts.complexity += 1
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.facts.complexity += 1
        self.facts.loops += 1
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.facts.complexity += 1
        self.facts.loops += 1
        self.facts.signals.add("concurrency")
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.facts.complexity += 1
        self.facts.loops += 1
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.facts.complexity += max(1, len(node.values) - 1)
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.facts.complexity += max(1, len(node.cases) - 1)
        self.facts.signals.add("control_logic")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        self.facts.arithmetic_ops += 1
        self.facts.signals.add("calculation")
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
            self.facts.arithmetic_ops += 1
            self.facts.signals.add("calculation")
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.facts.complexity += len(node.handlers)
        for handler in node.handlers:
            if handler.type is None or _dotted_name(handler.type) in {"Exception", "BaseException"}:
                self.facts.broad_handlers += 1
            if not handler.body or all(isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in handler.body):
                self.facts.silent_handlers += 1
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        self.facts.awaits += 1
        self.facts.signals.add("concurrency")
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.facts.raises += 1
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if any(isinstance(target, (ast.Attribute, ast.Subscript)) for target in node.targets):
            self.facts.mutates_state = True
            self.facts.signals.add("state_mutation")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, (ast.Attribute, ast.Subscript)):
            self.facts.mutates_state = True
            self.facts.signals.add("state_mutation")
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, (ast.Attribute, ast.Subscript, ast.Name)):
            self.facts.mutates_state = True
            self.facts.signals.add("state_mutation")
        self.generic_visit(node)

    def _resolve(self, raw: str) -> str:
        if not raw:
            return ""
        head, dot, rest = raw.partition(".")
        mapped = self.aliases.get(head, head)
        return f"{mapped}.{rest}" if dot else mapped

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

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")

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
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            class_context.append(statement)
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                fields.append(statement.target.id)
            elif isinstance(statement, ast.Assign):
                fields.extend(
                    target.id for target in statement.targets if isinstance(target, ast.Name)
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
            or any(value.rsplit(".", 1)[-1] in {"dataclass", "define", "frozen"} for value in decorators)
        )
        if not is_model:
            return
        qualname = ".".join([*self.scope_stack, node.name])
        material = {
            "name": "<class-model>",
            "bases": [ast.dump(value, include_attributes=False) for value in node.bases],
            "decorators": [
                ast.dump(value, include_attributes=False) for value in node.decorator_list
            ],
            "context": [ast.dump(value, include_attributes=False) for value in class_context],
        }
        fingerprint = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        class_doc = ast.get_docstring(node, clean=True) or f"Define the {node.name} data contract."
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
        if any(value.rsplit(".", 1)[-1] in model_markers for value in bases) or decorators:
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
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and isinstance(
            node.value, ast.Lambda
        ):
            self._collect_lambda(node.targets[0].id, node.value)
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
        )
        _FactVisitor(facts, dict(self.aliases)).visit(node.body)
        self.functions.append(facts)

    def _collect_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
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
            _dotted_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
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
        )
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
                "consumer",
                "receiver",
            }
            if any(item.lower().rsplit(".", 1)[-1] in entrypoint_names for item in decorators):
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
                _FactVisitor(facts, self.aliases)._classify_call(resolved)
                leaf = decorator.lower().rsplit(".", 1)[-1]
                if leaf in {"get", "post", "put", "patch", "delete", "route"}:
                    facts.entrypoint_types.add("http_route")
                elif leaf == "task":
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
    return arg.arg if arg.annotation is None else f"{arg.arg}: {ast.unparse(arg.annotation)}"


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
                    aliases[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
    return aliases


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
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
            entries.append(
                {
                    "class": node.name,
                    "bases": [ast.dump(value, include_attributes=False) for value in node.bases],
                    "keywords": [ast.dump(value, include_attributes=False) for value in node.keywords],
                    "decorators": [
                        ast.dump(value, include_attributes=False) for value in node.decorator_list
                    ],
                    "context": [
                        ast.dump(value, include_attributes=False) for value in class_context
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
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
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
        end_line=max(getattr(node, "end_lineno", getattr(node, "lineno", 1)) for node in executable),
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
    facts.signals.add("entrypoint")
    visitor = _FactVisitor(facts, dict(aliases))
    for statement in executable:
        visitor.visit(statement)
    return facts


def _matches_pattern(value: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern.replace("\\", "/")) for pattern in patterns)


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
        raise ValueError("Python source has an invalid or unsupported encoding") from exc


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
        if any(part in DEFAULT_EXCLUDES or part.startswith(".") for part in relative.parts[:-1]):
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


def _test_index(
    root: Path,
    warnings: list[dict[str, Any]] | None = None,
    source_snapshots: dict[Path, bytes] | None = None,
    test_evidence_snapshots: dict[Path, bytes] | None = None,
    test_evidence_errors: dict[Path, str] | None = None,
    exclude_patterns: Iterable[str] = (),
) -> dict[str, str]:
    tests: dict[str, str] = {}
    consumed = 0
    candidates = 0
    for path in sorted(root.rglob("*.py")):
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
                test_evidence_errors[path] = "Test evidence resolves outside the repository"
            continue
        relative = path.relative_to(root)
        is_test = (
            any(part.lower() in {"test", "tests"} for part in relative.parts[:-1])
            or path.name.startswith("test_")
            or path.name.endswith("_test.py")
        )
        if (
            not is_test
            or any(
                part in DEFAULT_EXCLUDES or part.startswith(".")
                for part in relative.parts[:-1]
            )
            or _matches_pattern(relative.as_posix(), exclude_patterns)
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
            warn(display_path(candidate), "Dependency manifest resolves outside the repository")
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
        if not value or value.startswith("#") or value.startswith(("-r", "--requirement")):
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
            include_match = re.match(r"^(?:-r|--requirement|-c|--constraint)[= ]+(.+)$", line)
            if include_match:
                read_requirements(resolved.parent / include_match.group(1).strip(), seen)
            else:
                record(line, resolved.relative_to(root).as_posix())

    pyproject = root / "pyproject.toml"
    if pyproject.exists() or pyproject.is_symlink():
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
                claims.append((value, "pyproject.toml:project.dependencies"))
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
                        (value, f"pyproject.toml:project.optional-dependencies.{group}")
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
                specification = f"{name}{constraint}" if isinstance(constraint, str) else name
                claims.append(
                    (specification, "pyproject.toml:tool.poetry.dependencies")
                )
            for specification, source in claims:
                record(specification, source)
        except UnicodeDecodeError:
            warn("pyproject.toml", "Dependency manifest is not valid UTF-8 TOML")
        except (tomllib.TOMLDecodeError, TypeError):
            warn("pyproject.toml", "Dependency manifest is not valid supported TOML")
        except ValueError:
            pass
    requirement_files = sorted(
        {path for pattern in ("requirements*.txt", "constraints*.txt") for path in root.glob(pattern)}
    )
    seen_requirements: set[Path] = set()
    for requirements in requirement_files:
        read_requirements(requirements, seen_requirements)
    for filename in (
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "pdm.lock",
        "pylock.toml",
        "setup.cfg",
        "uv.lock",
    ):
        candidate = root / filename
        if candidate.exists() or candidate.is_symlink():
            record_file(candidate)
    return sorted(dependencies.values(), key=lambda value: (value["name"].lower(), value["source"]))


def _contract_inventory(
    root: Path,
    warnings: list[dict[str, Any]],
    evidence_snapshots: dict[Path, bytes] | None = None,
) -> list[dict[str, Any]]:
    """Inventory common interface/data contracts without requiring third-party parsers."""

    candidates: list[Path] = []
    seen_candidates: set[Path] = set()
    discovery_truncated = False
    for pattern in (
        "**/openapi*.json",
        "**/openapi*.yaml",
        "**/openapi*.yml",
        "**/swagger*.json",
        "**/swagger*.yaml",
        "**/swagger*.yml",
        "**/*.schema.json",
        "**/*.proto",
    ):
        for path in root.glob(pattern):
            relative = path.relative_to(root)
            if any(
                part in DEFAULT_EXCLUDES or part.startswith(".")
                for part in relative.parts[:-1]
            ):
                continue
            if path in seen_candidates:
                continue
            if len(candidates) >= MAX_CONTRACT_FILES:
                discovery_truncated = True
                break
            candidates.append(path)
            seen_candidates.add(path)
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
        entities_truncated = False

        def retain(target: set[str], value: str) -> bool:
            if value in target:
                return True
            if len(target) >= MAX_CONTRACT_ENTITIES:
                return False
            target.add(value)
            return True

        lower_name = candidate.name.lower()
        kind = "protobuf" if resolved.suffix.lower() == ".proto" else "openapi"
        if lower_name.endswith(".schema.json"):
            kind = "json_schema"
        malformed_structure = False
        json_error = ""
        if (
            text is not None
            and kind in {"openapi", "json_schema"}
            and resolved.suffix.lower() == ".json"
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
                if current_route and method_match and not retain(
                    operations,
                    f"{method_match.group(1).upper()} {current_route}",
                ):
                    entities_truncated = True
                    break
        elif text is not None and kind == "protobuf":
            for match in re.finditer(r"\brpc\s+([A-Za-z_]\w*)\s*\(", text):
                if not retain(operations, match.group(1)):
                    entities_truncated = True
                    break
            for match in re.finditer(r"\bmessage\s+([A-Za-z_]\w*)\s*\{", text):
                if not retain(data_types, match.group(1)):
                    entities_truncated = True
                    break
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
                "bytes": len(raw),
                "sha256": digest,
                "operations": sorted(operations),
                "data_types": sorted(data_types),
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
    content_hash.update(str(repository_inventory.get("inventory_sha256", "")).encode("utf-8"))
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
                ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            vcs = {
                "type": "git",
                "revision": revision.stdout.strip(),
                "dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
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
        "repository_inventory_sha256": repository_inventory.get(
            "inventory_sha256", ""
        ),
        "vcs": vcs,
    }


def _dependency_component_and_item(
    dependencies: list[dict[str, Any]], analysis_rules: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    included = set(analysis_rules.get("included_failure_classes", []))
    excluded = set(analysis_rules.get("excluded_failure_classes", []))
    if not dependencies or "environment" in excluded or (included and "environment" not in included):
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
        "source": {"path": "pyproject.toml / requirements files", "line": "", "end_line": ""},
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
            "screening_reasons": component["screening"]["reasons"],
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
            hazard = next(
                (
                    value
                    for value in config.get("hazards", [])
                    if value.get("id") == linked_hazards[0]
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
                    *(f"Operation: {value}" for value in contract.get("operations", [])[:50]),
                    *(f"Data type: {value}" for value in contract.get("data_types", [])[:50]),
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


def _find_test_references(name: str, tests: dict[str, str]) -> list[str]:
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    return [path for path, content in tests.items() if pattern.search(content)][:5]


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
        accepted = [
            entry
            for entry in supplied
            if isinstance(entry, int) and not isinstance(entry, bool) and entry > 0
        ]
        malformed = malformed or len(accepted) != len(supplied)
        normalized[key] = accepted
    for key in ("executed_branches", "missing_branches"):
        supplied = value.get(key, [])
        if not isinstance(supplied, list):
            supplied = []
            malformed = True
        accepted = [
            entry
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
        malformed = malformed or len(accepted) != len(supplied)
        normalized[key] = accepted
    return normalized, malformed


def _load_coverage_document(
    path: str | Path | None,
    root: Path,
    evidence_snapshots: dict[Path, bytes] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    if not path:
        return {}, [], {}
    coverage_path = Path(path).expanduser().absolute()
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
        return {}, [_coverage_warning(coverage_path, "coverage JSON root must be an object")], {}
    if "files" not in payload:
        return {}, [_coverage_warning(coverage_path, "coverage JSON has no files object")], {}
    files = payload["files"]
    if not isinstance(files, dict):
        return {}, [_coverage_warning(coverage_path, "coverage JSON has no files object")], {}
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
    }
    return indexed, warnings, provenance


def _load_coverage(
    path: str | Path | None, root: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compatibility wrapper for callers that do not consume coverage provenance."""

    indexed, warnings, _provenance = _load_coverage_document(path, root)
    return indexed, warnings


def _function_coverage(facts: FunctionFacts, coverage: dict[str, Any]) -> dict[str, Any] | None:
    file_data = coverage.get(facts.path)
    if not isinstance(file_data, dict):
        return None
    executed = {
        line
        for line in file_data.get("executed_lines", [])
        if facts.line <= line <= facts.end_line
    }
    missing = {
        line
        for line in file_data.get("missing_lines", [])
        if facts.line <= line <= facts.end_line
    }
    relevant = executed | missing
    executed_branches = [
        branch
        for branch in file_data.get("executed_branches", [])
        if isinstance(branch, list)
        and len(branch) == 2
        and facts.line <= branch[0] <= facts.end_line
    ]
    missing_branches = [
        branch
        for branch in file_data.get("missing_branches", [])
        if isinstance(branch, list)
        and len(branch) == 2
        and facts.line <= branch[0] <= facts.end_line
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


def _component_ref(facts: FunctionFacts) -> str:
    return f"{facts.path}:{facts.qualname}"


def _critical_context(facts: FunctionFacts, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reference = _component_ref(facts)
    return [entry for entry in entries if fnmatch.fnmatchcase(reference, entry.get("pattern", ""))]


def _mapping_context(facts: FunctionFacts, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reference = _component_ref(facts)
    return [entry for entry in entries if fnmatch.fnmatchcase(reference, entry.get("pattern", ""))]


def _module_suffixes(path: str) -> list[str]:
    parts = list(Path(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return [".".join(parts[index:]) for index in range(len(parts)) if parts[index:]]


def _internal_callers(facts_list: list[FunctionFacts]) -> dict[str, list[str]]:
    by_file_name: dict[tuple[str, str], list[FunctionFacts]] = {}
    by_full: dict[str, list[FunctionFacts]] = {}
    for target in facts_list:
        by_file_name.setdefault((target.path, target.name), []).append(target)
        for module in _module_suffixes(target.path):
            by_full.setdefault(f"{module}.{target.qualname}", []).append(target)
            by_full.setdefault(f"{module}.{target.name}", []).append(target)

    callers: dict[str, set[str]] = {_component_ref(target): set() for target in facts_list}
    for caller in facts_list:
        caller_ref = _component_ref(caller)
        caller_class = caller.qualname.rsplit(".", 1)[0] if "." in caller.qualname else ""
        for called in caller.calls:
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
            for target in targets:
                target_ref = _component_ref(target)
                if target_ref != caller_ref:
                    callers[target_ref].add(caller_ref)
    return {key: sorted(value) for key, value in callers.items()}


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
            else "Caller-path discovery is a bounded projection; " + "; ".join(limitations) + "."
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
        reasons.append(f"observed function branch coverage {coverage['branch_percent']}%")
    if critical_context:
        score += 4
        reasons.extend(
            "project critical function: " + entry.get("rationale", entry.get("pattern", ""))
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
                ["Unhandled exception", "Incorrect precondition or guard", "Missing or invalid dependency/data"],
                ["Define the required failure response", "Add tests for omitted and interrupted execution", "Add completion monitoring where the effect warrants it"],
                "high" if "entrypoint" in facts.signals else "medium",
            ),
            _rule(
                "functional.incorrect",
                "Incorrect / incomplete function",
                f"{name} produces an incorrect, incomplete, inconsistent, or unintended result.",
                "A valid or boundary-case request follows a faulty logic, calculation, or state path.",
                "A wrong result or state is returned or propagated to the caller.",
                ["Logic or calculation fault", "Unhandled boundary condition", "Incorrect state or assumption"],
                ["Document invariants and acceptance criteria", "Add boundary and property-based tests", "Validate output before propagation"],
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
                ["Missing validation", "Ambiguous units/schema", "Stale or duplicated message", "Unexpected null, range, precision, or encoding"],
                ["Specify input contracts, units, ranges, freshness, and uniqueness", "Add schema and boundary validation", "Test malformed and adversarial input"],
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
                    ["Timeout absent or too long", "Connection interruption", "Dependency overload/outage", "Unsafe retry behavior"],
                    ["Define timeouts and bounded retry behavior", "Make partial operations idempotent or compensatable", "Test dependency outage, latency, and recovery"],
                    "high",
                ),
                _rule(
                    "interface.bad_response",
                    "Incorrect interface data",
                    f"An external dependency returns a successful but wrong, partial, stale, duplicated, or schema-incompatible response to {name}.",
                    "The dependency responds, but its content or semantics violate the consumer's assumptions.",
                    "Incorrect external data is accepted and influences local behavior.",
                    ["Schema/version drift", "Partial response", "Stale cache", "Duplicate response", "Semantic error with success status"],
                    ["Validate response schema and semantics", "Record provenance and freshness where needed", "Test corrupt, partial, duplicate, and version-skewed responses"],
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
                ["Interrupted write", "Missing transaction boundary", "Concurrent update", "Corrupt/incompatible data", "Non-idempotent retry"],
                ["Define atomicity and consistency requirements", "Use transactions or atomic replacement", "Test interruption, retry, corruption, and concurrent update"],
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
                ["Unsafe default", "Inherited environment variable", "Unit/type ambiguity", "Secret or endpoint mix-up"],
                ["Fail fast on invalid configuration", "Validate types, ranges, environment, and target identity", "Expose non-secret effective configuration for diagnostics"],
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
                ["Schema drift", "Truncated payload", "Encoding/precision loss", "Unsafe or ambiguous deserialization"],
                ["Version schemas and validate before use", "Test forward/backward compatibility and truncation", "Avoid unsafe deserialization formats"],
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
                ["Executable/path substitution", "Missing timeout", "Ignored return status", "Unsafe argument construction", "Inherited environment"],
                ["Use explicit executable, arguments, environment, and working directory", "Enforce timeout and validate result", "Test partial failure and wrong-target prevention"],
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
                ["Race condition", "Missing synchronization", "Cancellation leak", "Duplicate task/message", "Unbounded wait"],
                ["Document ordering, atomicity, cancellation, and idempotency", "Add deterministic concurrency tests", "Use deadlines and explicit synchronization where warranted"],
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
                ["Wall-clock used for duration", "Missing deadline", "Blocking delay", "Clock adjustment", "Load-dependent latency"],
                ["Define timing requirements and clock semantics", "Use monotonic deadlines for durations", "Test deadline and overload behavior"],
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
                ["Broad exception catch", "Empty/pass handler", "Fallback indistinguishable from valid result", "Diagnostic context lost"],
                ["Catch specific exceptions", "Define safe fallback and explicit failure result", "Log/measure with sufficient context and test the detection path"],
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
                ["Unbounded loop/retry", "Unbounded collection", "Algorithmic amplification", "Resource not released"],
                ["Define and enforce resource bounds", "Test worst credible sizes and retry paths", "Measure latency/resource use and fail safely at limits"],
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
                custom.get("local_effect", "Project-defined local effect requires review."),
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
        "calls": sorted(facts.calls),
        "ordered_calls": facts.ordered_calls,
        "frameworks": sorted(facts.frameworks),
        "entrypoint_types": sorted(facts.entrypoint_types),
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
            {entry.get("subsystem", "") for entry in mapping_context if entry.get("subsystem")}
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
            value for value in config.get("hazards", []) if value.get("id") in hazard_ids
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
        evidence.append("Textual test references: " + ", ".join(component["test_references"]))
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
        evidence.append("Observed internal callers: " + ", ".join(component["called_by"][:10]))
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
) -> dict[str, Any]:
    """Scan *root* and return a new, unmerged SFMEA analysis document."""

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
    scan_config = config.get("scan", {})
    if include_private is None:
        include_private = bool(scan_config.get("include_private", True))
    if include_tests is None:
        include_tests = bool(scan_config.get("include_tests", False))
    if include_nested is None:
        include_nested = bool(scan_config.get("include_nested", True))
    exclude_patterns = list(scan_config.get("exclude", []))
    focus_patterns = list(scan_config.get("focus", []))
    if coverage_json is None:
        coverage_json = scan_config.get("coverage_json") or None

    warnings: list[dict[str, Any]] = []
    dependency_snapshots: dict[Path, bytes] = {}
    contract_snapshots: dict[Path, bytes] = {}
    dependencies = _dependency_inventory(root_path, warnings, dependency_snapshots)
    contracts = _contract_inventory(root_path, warnings, contract_snapshots)
    facts_list: list[FunctionFacts] = []
    files = _python_files(
        root_path,
        include_tests=include_tests,
        exclude_patterns=exclude_patterns,
        warnings=warnings,
    )
    parsed_python_paths: set[str] = set()
    source_snapshots: dict[Path, bytes] = {}
    source_snapshot_errors: dict[Path, str] = {}
    for file_path in files:
        relative = file_path.relative_to(root_path).as_posix()
        try:
            raw = _read_python_source_bytes_bounded(file_path)
            source_snapshots[file_path] = raw
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
        facts_list.extend(collector.functions)
        module_facts = _module_initialization_facts(
            relative,
            tree,
            _module_aliases(tree),
            _module_context_fingerprint(tree),
        )
        if module_facts:
            facts_list.append(module_facts)

    test_evidence_snapshots: dict[Path, bytes] = {}
    test_evidence_errors: dict[Path, str] = {}
    tests = _test_index(
        root_path,
        warnings,
        source_snapshots,
        test_evidence_snapshots,
        test_evidence_errors,
        exclude_patterns,
    )
    coverage_snapshots: dict[Path, bytes] = {}
    coverage, coverage_warnings, coverage_provenance = _load_coverage_document(
        coverage_json,
        root_path,
        coverage_snapshots,
    )
    warnings.extend(coverage_warnings)
    repository_inventory = build_repository_inventory(
        root_path,
        selected_python_paths={path.relative_to(root_path).as_posix() for path in files},
        parsed_python_paths=parsed_python_paths,
        include_tests=include_tests,
        exclude_patterns=exclude_patterns,
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

    if focus_patterns:
        facts_list = [
            facts for facts in facts_list if _matches_pattern(_component_ref(facts), focus_patterns)
        ]

    callers = _internal_callers(facts_list)
    facts_by_reference = {_component_ref(facts): facts for facts in facts_list}
    for target_reference, caller_references in callers.items():
        if caller_references:
            facts_by_reference[target_reference].signals.add("internal_interface")
        for caller_reference in caller_references:
            facts_by_reference[caller_reference].signals.add("internal_interface")
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
        test_refs = _find_test_references(facts.name, tests)
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
            for rule in _candidate_rules(facts, custom_rules, config.get("analysis", {}))
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
    analysis = {
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
                "exclude": exclude_patterns,
                "focus": focus_patterns,
                "coverage_json": str(coverage_json or ""),
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
        },
        "system_context": build_system_context(config),
        "repository_inventory": repository_inventory,
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
        "items": items,
        "warnings": warnings,
        "suggestions": [],
        "generated_summaries": [],
        "runtime_evidence": {"imports": [], "spans": [], "edges": []},
    }
    if coverage_provenance:
        analysis["project"]["settings"]["coverage_evidence"] = coverage_provenance
    refresh_assurance_register(analysis, {})
    analysis["sfta"] = build_sfta(analysis)
    analysis["adapter_runs"] = build_adapter_run_ledger(analysis)
    analysis["run_manifest"] = create_run_manifest(analysis)
    return analysis
