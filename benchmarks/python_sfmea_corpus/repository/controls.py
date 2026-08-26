"""Positive and negative static control-detection qualification fixtures."""

from __future__ import annotations

import threading
import time


class CircuitBreaker:
    """A deliberately explicit breaker whose methods expose distinct control roles."""

    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self.state = "CLOSED"
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.last_failure_time = 0.0
        self.lock = threading.Lock()

    def allow_request(self) -> bool:
        with self.lock:
            if self.state == "OPEN":
                if (
                    time.monotonic() - self.last_failure_time
                    >= self.recovery_timeout
                ):
                    self.state = "HALF_OPEN"
                    return True
                return False
            return True

    def record_failure(self) -> None:
        with self.lock:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                self.last_failure_time = time.monotonic()

    def record_success(self) -> None:
        with self.lock:
            self.failure_count = 0
            self.state = "CLOSED"


def describe_circuit_breaker() -> str:
    """Breaker terminology without executable control semantics is not a control."""

    return "A circuit breaker can isolate repeated dependency failures."


def draw_electrical_circuit(switch_is_open: bool) -> str:
    """An electrical topology near-miss with open/closed language."""

    return "open circuit" if switch_is_open else "closed circuit"


def reset_failure_counter(counter: int) -> int:
    """Generic failure accounting alone is insufficient breaker evidence."""

    return 0 if counter > 3 else counter
