"""Fuzz pure measurement contracts and ambiguous OTLP ingestion boundaries."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from pysfmea.genai_telemetry import _attributes, _otel_spans
    from pysfmea.json_ingestion import parse_bounded_json_bytes
    from pysfmea.measurement_validity import (
        complete_collection,
        paired_cohort,
        timed_breaker,
    )


def test_one_input(data: bytes) -> None:
    try:
        value = parse_bounded_json_bytes(
            data,
            label="measurement fuzz",
            max_bytes=1048576,
            max_depth=50,
            max_nodes=10000,
        )
    except ValueError:
        return
    for parser in (_attributes, _otel_spans):
        try:
            parser(value)
        except (ValueError, TypeError, AttributeError):
            pass
    if isinstance(value, dict):
        timed_breaker(value)
        paired_cohort(value, value)
        complete_collection(value, value, 1)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
