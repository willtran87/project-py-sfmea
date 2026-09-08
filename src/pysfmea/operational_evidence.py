"""Replay retained measurements and deployment transitions for TEVV decisions."""

from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .genai_telemetry import _otel_spans, import_genai_telemetry
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .measurement_validity import complete_collection, paired_cohort, timed_breaker


def read_evidence(base: Path, reference: str, digest: str | None = None) -> Any:
    path = Path(reference)
    if not path.is_absolute():
        path = base / path
    if path.is_symlink():
        raise ValueError("evidence references must not be symbolic links")
    path = path.resolve()
    if not Path(reference).is_absolute():
        path.relative_to(base.resolve())
    document = load_bounded_json_document(
        path,
        label="retained operational evidence",
        max_bytes=100_000_000,
        max_depth=80,
        max_nodes=3_000_000,
    )
    if digest is not None and hashlib.sha256(document.raw).hexdigest() != digest:
        raise ValueError("retained evidence digest mismatch")
    return document.value


def evidence_bindings(value: dict[str, Any], base: Path) -> dict[str, str | None]:
    refs = [value["baseline"]["evidence_ref"]]
    for window in value["monitoring_windows"]:
        refs.extend(
            [
                window["telemetry_ref"],
                window["evaluation_ref"],
                window["collection_ref"],
            ]
        )
    refs.extend(c["evidence_ref"] for c in value["controls"].values())
    for change in value["change_records"]:
        refs.extend([change["approval_ref"], change["regression_evidence_ref"]])
    result: dict[str, str | None] = {}
    for reference in sorted(set(refs)):
        try:
            result[reference] = canonical_json_sha256(read_evidence(base, reference))
        except (OSError, ValueError, TypeError):
            result[reference] = None
    return result


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("evidence timestamps require a timezone")
    return result


def evaluations(value: Any, version: str, model: str) -> tuple[int, float]:
    if value["format"] != "pysfmea-tevv-evaluation-events-2":
        raise ValueError("unsupported evaluation events")
    if (value["system_version"], value["model_version"]) != (version, model):
        raise ValueError("evaluation deployment identity mismatch")
    cases = value["cases"]
    if (
        not isinstance(cases, list)
        or not cases
        or len({c["id"] for c in cases}) != len(cases)
    ):
        raise ValueError("evaluation case population must be nonempty and unique")
    if any(
        not isinstance(c["id"], str)
        or not c["id"].strip()
        or type(c["passed"]) is not bool
        for c in cases
    ):
        raise ValueError(
            "evaluation events require explicit case identities and boolean outcomes"
        )
    if not paired_cohort(value, value):
        raise ValueError("evaluation dataset and oracle identities are required")
    return len(cases), sum(c["passed"] for c in cases) / len(cases)


def request_events(
    base: Path, window: dict[str, Any], system: dict[str, Any]
) -> list[dict[str, Any]]:
    raw = read_evidence(base, window["telemetry_ref"], window["telemetry_sha256"])
    if window["telemetry_schema"] == "pysfmea-tevv-request-events-1":
        if (
            raw["format"] != window["telemetry_schema"]
            or window["telemetry_schema_version"] != "1"
        ):
            raise ValueError("request-event schema identity mismatch")
        events = raw["events"]
        if not isinstance(events, list):
            raise ValueError("request events must be a list")
        return events
    if window["telemetry_schema"] != "OpenTelemetry GenAI semantic conventions":
        raise ValueError("unsupported TEVV telemetry schema")
    path = Path(window["telemetry_ref"])
    artifact = import_genai_telemetry(
        path if path.is_absolute() else base / path,
        authority="TEVV raw replay",
        convention_version=window["telemetry_schema_version"],
    )
    if artifact["source"]["sha256"] != window["telemetry_sha256"]:
        raise ValueError("OTLP source changed during replay")
    spans = {
        (s["traceId"], s["spanId"]): (s, resource) for s, resource in _otel_spans(raw)
    }
    result = []
    for span in artifact["spans"]:
        source, resource = spans[(span["trace_id"], span["span_id"])]
        if (
            span["service_version"] != window["system_version"]
            or resource.get("pysfmea.model.version") != window["model_version"]
        ):
            raise ValueError("OTLP deployment versions do not match monitoring window")
        if (
            span["request_model"] != system["model"]
            or not span["operation"]
            or not span["provider"]
        ):
            raise ValueError("OTLP model and operation identity is incomplete")
        end = int(source["endTimeUnixNano"])
        if end > int(timestamp(window["ended_at"]).timestamp() * 1_000_000_000):
            raise ValueError("OTLP request crosses the monitoring-window boundary")
        started = datetime.fromtimestamp(
            int(source["startTimeUnixNano"]) / 1_000_000_000, timezone.utc
        )
        result.append(
            {
                "request_id": f"{span['trace_id']}:{span['span_id']}",
                "timestamp": started.isoformat(),
                "system_version": window["system_version"],
                "model_version": window["model_version"],
                "error": span["error"],
                "latency_ms": span["duration_ms"],
            }
        )
    return result


def change_history_consistent(value: dict[str, Any]) -> bool:
    try:
        version = (
            value["baseline"]["system_version"],
            value["baseline"]["model_version"],
        )
        changes = value["change_records"]
        times = [timestamp(c["effective_at"]) for c in changes]
        if times != sorted(set(times)):
            return False
        states = []
        for c, time in zip(changes, times, strict=True):
            if (c["previous_system_version"], c["previous_model_version"]) != version:
                return False
            version = (c["new_system_version"], c["new_model_version"])
            states.append((time, version))
        if version != (value["system"]["version"], value["system"]["model_version"]):
            return False
        for window in value["monitoring_windows"]:
            start, end = timestamp(window["started_at"]), timestamp(window["ended_at"])
            expected = (
                value["baseline"]["system_version"],
                value["baseline"]["model_version"],
            )
            for time, state in states:
                if start < time < end:
                    return False
                if time <= start:
                    expected = state
            if expected != (window["system_version"], window["model_version"]):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def replay_operational_evidence(value: dict[str, Any], base: Path) -> bool:
    """Recompute p95 (nearest rank), error rates and absolute pass-rate drift.

    All request events must lie in their half-open monitoring window. Missing raw
    evidence never becomes eligible merely because an asserted hash is nonzero.
    """
    try:
        baseline = value["baseline"]
        baseline_events = read_evidence(
            base, baseline["evidence_ref"], baseline["evidence_sha256"]
        )
        count, baseline_rate = evaluations(
            baseline_events,
            baseline["system_version"],
            baseline["model_version"],
        )
        if count != baseline["evaluation_count"] or not math.isclose(
            baseline_rate, baseline["evaluation_pass_rate"], abs_tol=1e-12
        ):
            return False
        all_ids: set[str] = set()
        for w in value["monitoring_windows"]:
            events = request_events(base, w, value["system"])
            collection = read_evidence(
                base, w["collection_ref"], w["collection_sha256"]
            )
            if not complete_collection(collection, w, len(events)):
                return False
            if (
                not isinstance(events, list)
                or len(events) != w["requests"]
                or not events
            ):
                return False
            latencies = []
            for event in events:
                identity = event["request_id"]
                if (
                    not isinstance(identity, str)
                    or not identity.strip()
                    or identity in all_ids
                ):
                    return False
                all_ids.add(identity)
                if (
                    not timestamp(w["started_at"])
                    <= timestamp(event["timestamp"])
                    < timestamp(w["ended_at"])
                ):
                    return False
                if (event["system_version"], event["model_version"]) != (
                    w["system_version"],
                    w["model_version"],
                ):
                    return False
                if type(event["error"]) is not bool:
                    return False
                latency = event["latency_ms"]
                if (
                    isinstance(latency, bool)
                    or not isinstance(latency, (float, int))
                    or not math.isfinite(latency)
                    or latency < 0
                ):
                    return False
                latencies.append(latency)
            if sum(e["error"] for e in events) != w["errors"]:
                return False
            p95 = sorted(latencies)[math.ceil(0.95 * len(latencies)) - 1]
            evaluation_events = read_evidence(
                base, w["evaluation_ref"], w["evaluation_sha256"]
            )
            if not paired_cohort(baseline_events, evaluation_events):
                return False
            count, rate = evaluations(
                evaluation_events,
                w["system_version"],
                w["model_version"],
            )
            if count != w["evaluation_count"] or not math.isclose(
                rate, w["evaluation_pass_rate"], abs_tol=1e-12
            ):
                return False
            if not math.isclose(
                p95, w["p95_latency_ms"], abs_tol=1e-9
            ) or not math.isclose(
                abs(rate - baseline_rate), w["drift_score"], abs_tol=1e-12
            ):
                return False
        for kind in ("circuit_breaker", "rollback"):
            if not value["policy"][f"require_{kind}_test"]:
                continue
            control = value["controls"][kind]
            event = read_evidence(base, control["evidence_ref"])
            if (
                event["system_version"] != value["system"]["version"]
                or event["model_version"] != value["system"]["model_version"]
            ):
                return False
            if (
                event["format"] != "pysfmea-tevv-control-events-2"
                or event["control"] != kind
            ):
                return False
            if control["tested"] is not True or event["tested"] is not True:
                return False
            if kind == "circuit_breaker":
                if not timed_breaker(event) or control["activated"] is not True:
                    return False
            else:
                elapsed = (
                    timestamp(event["recovered_at"]) - timestamp(event["started_at"])
                ).total_seconds()
                if (
                    event["succeeded"] is not True
                    or control["succeeded"] is not True
                    or elapsed < 0
                    or not math.isclose(
                        elapsed, control["recovery_seconds"], abs_tol=1e-9
                    )
                ):
                    return False
        for change in value["change_records"]:
            read_evidence(base, change["approval_ref"])
            regression = read_evidence(base, change["regression_evidence_ref"])
            _, rate = evaluations(
                regression, change["new_system_version"], change["new_model_version"]
            )
            if rate < value["policy"]["minimum_evaluation_pass_rate"]:
                return False
        return True
    except (OSError, KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return False
