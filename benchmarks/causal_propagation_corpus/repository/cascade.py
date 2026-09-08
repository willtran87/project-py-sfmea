from __future__ import annotations

from collections.abc import Callable


class PaymentTimeout(TimeoutError):
    pass


class Breaker:
    def __init__(self, threshold: int = 2) -> None:
        self.failures = 0
        self.threshold = threshold
        self.state = "closed"

    def record_timeout(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.state = "open"

    def probe_succeeded(self) -> None:
        self.failures = 0
        self.state = "closed"


def checkout(charge: Callable[[], None], breaker: Breaker) -> str:
    if breaker.state == "open":
        return "checkout_degraded"
    for _ in range(2):
        try:
            charge()
            breaker.probe_succeeded()
            return "complete"
        except PaymentTimeout:
            breaker.record_timeout()
    return "checkout_degraded"
