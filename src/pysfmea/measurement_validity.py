"""Pure fail-closed measurement-population and sequential breaker contracts.

These contracts validate retained observations, not the authenticity of their producer.
Concurrent breaker histories require a separate linearizability-aware model.
"""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any


def instant(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("measurement timestamps must be strings")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("measurement timestamps require timezones")
    return parsed


def paired_cohort(baseline: dict[str, Any], current: dict[str, Any]) -> bool:
    """Only like-for-like case populations may contribute to pass-rate drift."""
    try:
        for name in ("dataset_sha256", "oracle_sha256"):
            digest = baseline[name]
            if (
                not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or digest == "0" * 64
            ):
                return False
            if current[name] != digest:
                return False
        ids = [c["id"] for c in baseline["cases"]]
        other = [c["id"] for c in current["cases"]]
        return (
            bool(ids)
            and all(isinstance(i, str) and i.strip() for i in ids + other)
            and len(ids) == len(set(ids))
            and len(other) == len(set(other))
            and set(ids) == set(other)
        )
    except (KeyError, TypeError, ValueError):
        return False


def complete_collection(
    value: dict[str, Any], window: dict[str, Any], count: int
) -> bool:
    """Require an unsampled, loss-free collection with reconciled request counts."""
    try:
        if set(value) != {
            "format",
            "window_id",
            "started_at",
            "ended_at",
            "telemetry_sha256",
            "expected_requests",
            "dropped_records",
            "sampling_probability",
            "counter_source",
            "population",
        }:
            return False
        return bool(
            value["format"] == "pysfmea-tevv-collection-1"
            and value["window_id"] == window["id"]
            and instant(value["started_at"]) == instant(window["started_at"])
            and instant(value["ended_at"]) == instant(window["ended_at"])
            and value["telemetry_sha256"] == window["telemetry_sha256"]
            and type(value["expected_requests"]) is int
            and value["expected_requests"] == count
            and type(value["dropped_records"]) is int
            and value["dropped_records"] == 0
            and type(value["sampling_probability"]) in (int, float)
            and value["sampling_probability"] == 1
            and value["population"] == "one-span-per-request"
            and isinstance(value["counter_source"], str)
            and value["counter_source"].strip()
            and value["counter_source"] != window["telemetry_ref"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def timed_breaker(value: dict[str, Any]) -> bool:
    """Replay a consecutive-failure, sequential request breaker state machine."""
    try:
        policy = value["breaker_policy"]
        if set(policy) != {
            "failure_threshold",
            "cooldown_seconds",
            "half_open_successes",
        }:
            return False
        threshold, cooldown, probe_count = (
            policy[k]
            for k in ("failure_threshold", "cooldown_seconds", "half_open_successes")
        )
        if (
            type(threshold) is not int
            or not 1 <= threshold <= 10000
            or type(probe_count) is not int
            or not 1 <= probe_count <= 10000
        ):
            return False
        if (
            type(cooldown) not in (int, float)
            or not math.isfinite(cooldown)
            or cooldown <= 0
        ):
            return False
        state, failures, probes = "closed", 0, 0
        opened_at: datetime | None = None
        previous_end: datetime | None = None
        observed: set[str] = set()
        ids: set[str] = set()
        events = value["requests"]
        if not isinstance(events, list) or not 1 <= len(events) <= 100000:
            return False
        for event in events:
            if set(event) != {
                "id",
                "started_at",
                "completed_at",
                "outcome",
                "state_before",
                "state_after",
            }:
                return False
            identity = event["id"]
            if not isinstance(identity, str) or not identity.strip() or identity in ids:
                return False
            ids.add(identity)
            start, end = instant(event["started_at"]), instant(event["completed_at"])
            if end < start or (previous_end is not None and start < previous_end):
                return False
            previous_end = end
            if (
                state == "open"
                and opened_at is not None
                and (start - opened_at).total_seconds() >= cooldown
            ):
                state, probes = "half_open", 0
                observed.add("probe")
            if event["state_before"] != state:
                return False
            outcome = event["outcome"]
            if state == "open":
                if outcome != "rejected":
                    return False
                observed.add("rejected")
            elif outcome not in {"success", "failure"}:
                return False
            elif outcome == "failure":
                failures += 1
                if state == "half_open" or failures >= threshold:
                    state, opened_at, probes = "open", end, 0
                    observed.add("opened")
            elif state == "half_open":
                probes += 1
                if probes >= probe_count:
                    state, failures = "closed", 0
                    observed.add("recovered")
            else:
                failures = 0
            if event["state_after"] != state:
                return False
        return state == "closed" and observed == {
            "opened",
            "rejected",
            "probe",
            "recovered",
        }
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
