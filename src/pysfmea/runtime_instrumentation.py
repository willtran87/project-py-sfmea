"""First-party, opt-in runtime trace capture for Python call paths.

The recorder produces the closed simple-span contract consumed by
``pysfmea.runtime.import_runtime_trace``.  It never changes application control
flow: exceptions are recorded and re-raised, and incomplete capture remains an
explicit declaration in the exported instrumentation manifest.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import json
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, cast

from .file_publication import atomic_publish_text
from .runtime import MAX_SPANS_PER_IMPORT, RUNTIME_INSTRUMENTATION_FORMAT

P = ParamSpec("P")
R = TypeVar("R")
MAX_RECORDER_TEXT = 4_096


def _text(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > MAX_RECORDER_TEXT
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError(f"{label} must be bounded printable non-empty text")
    return normalized


def _component_list(values: Sequence[str]) -> list[str]:
    normalized = [_text(value, "expected component") for value in values]
    if not normalized:
        raise ValueError("expected_components must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ValueError("expected_components must be unique")
    return normalized


def _relationship_list(
    values: Sequence[tuple[str, str]],
) -> list[dict[str, str]]:
    normalized = [
        {
            "source": _text(source, "expected relationship source"),
            "target": _text(target, "expected relationship target"),
        }
        for source, target in values
    ]
    keys = {(value["source"], value["target"]) for value in normalized}
    if len(keys) != len(normalized):
        raise ValueError("expected_relationships must be unique")
    return normalized


class RuntimeTraceRecorder:
    """Capture bounded nested sync or async spans for one declared scenario."""

    def __init__(
        self,
        scenario_id: str,
        producer: str,
        *,
        expected_components: Sequence[str],
        expected_relationships: Sequence[tuple[str, str]] = (),
        sampling_policy: str = "always_on",
        clock_domain: str = "process-monotonic",
        max_spans: int = MAX_SPANS_PER_IMPORT,
    ) -> None:
        if sampling_policy not in {
            "always_on",
            "head_sampled",
            "tail_sampled",
            "unknown",
        }:
            raise ValueError("sampling_policy is unsupported")
        if isinstance(max_spans, bool) or not 1 <= max_spans <= MAX_SPANS_PER_IMPORT:
            raise ValueError(f"max_spans must be between 1 and {MAX_SPANS_PER_IMPORT}")
        self.scenario_id = _text(scenario_id, "scenario_id")
        self.producer = _text(producer, "producer")
        self.clock_domain = _text(clock_domain, "clock_domain")
        self.sampling_policy = sampling_policy
        self.expected_components = _component_list(expected_components)
        self.expected_relationships = _relationship_list(expected_relationships)
        self.max_spans = max_spans
        self.trace_id = uuid.uuid4().hex
        self._spans: list[dict[str, Any]] = []
        self._dropped_spans = 0
        self._counter = 0
        self._lock = threading.Lock()
        self._stack: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
            f"pysfmea_runtime_stack_{id(self)}", default=()
        )

    @property
    def captured_span_count(self) -> int:
        return len(self._spans)

    @contextmanager
    def span(
        self,
        component: str,
        *,
        attributes: dict[str, Any] | None = None,
        callsite_line: int | None = None,
    ) -> Iterator[None]:
        with self._capture(component, attributes, callsite_line):
            yield

    @asynccontextmanager
    async def async_span(
        self,
        component: str,
        *,
        attributes: dict[str, Any] | None = None,
        callsite_line: int | None = None,
    ) -> AsyncIterator[None]:
        with self._capture(component, attributes, callsite_line):
            yield

    @contextmanager
    def _capture(
        self,
        component: str,
        attributes: dict[str, Any] | None,
        callsite_line: int | None,
    ) -> Iterator[None]:
        name = _text(component, "component")
        if attributes is not None and not isinstance(attributes, dict):
            raise ValueError("attributes must be an object")
        if callsite_line is not None and (
            isinstance(callsite_line, bool) or callsite_line < 1
        ):
            raise ValueError("callsite_line must be a positive integer")
        with self._lock:
            if len(self._spans) >= self.max_spans:
                self._dropped_spans += 1
                captured = False
                span_id = ""
            else:
                self._counter += 1
                span_id = f"{self._counter:016x}"
                captured = True
        if not captured:
            yield
            return
        stack = self._stack.get()
        token = self._stack.set((*stack, span_id))
        start = time.perf_counter_ns()
        status = "ok"
        try:
            yield
        except BaseException:
            status = "error"
            raise
        finally:
            end = time.perf_counter_ns()
            self._stack.reset(token)
            span_attributes = dict(attributes or {})
            span_attributes["sfmea.component"] = name
            if callsite_line is not None:
                span_attributes["sfmea.caller.callsite.line"] = callsite_line
            record = {
                "trace_id": self.trace_id,
                "span_id": span_id,
                "parent_span_id": stack[-1] if stack else "",
                "name": name,
                "start_time": str(start),
                "end_time": str(end),
                "status": status,
                "attributes": span_attributes,
            }
            with self._lock:
                self._spans.append(record)

    def trace(
        self, component: str | None = None
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorate a sync or async callable while retaining its signature metadata."""

        def decorate(function: Callable[P, R]) -> Callable[P, R]:
            name = component or function.__qualname__
            if inspect.iscoroutinefunction(function):

                @functools.wraps(function)
                async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                    async with self.async_span(name):
                        return await function(*args, **kwargs)

                return cast(Callable[P, R], async_wrapper)

            @functools.wraps(function)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                with self.span(name):
                    return function(*args, **kwargs)

            return wrapper

        return decorate

    def document(self, *, declared_complete: bool = True) -> dict[str, Any]:
        if not isinstance(declared_complete, bool):
            raise ValueError("declared_complete must be boolean")
        with self._lock:
            spans = [dict(span) for span in self._spans]
            dropped = self._dropped_spans
        spans.sort(key=lambda value: (int(value["start_time"]), value["span_id"]))
        return {
            "sfmea_instrumentation": {
                "schema_version": RUNTIME_INSTRUMENTATION_FORMAT,
                "scenario_id": self.scenario_id,
                "producer": self.producer,
                "clock_domain": self.clock_domain,
                "sampling_policy": self.sampling_policy,
                "expected_components": list(self.expected_components),
                "expected_relationships": [
                    dict(value) for value in self.expected_relationships
                ],
                "dropped_spans": dropped,
                "declared_complete": declared_complete,
            },
            "spans": spans,
        }

    def export(
        self, destination: str | Path, *, declared_complete: bool = True
    ) -> Path:
        rendered = (
            json.dumps(
                self.document(declared_complete=declared_complete),
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        )
        return atomic_publish_text(
            destination,
            rendered,
            label="runtime instrumentation trace",
        )
