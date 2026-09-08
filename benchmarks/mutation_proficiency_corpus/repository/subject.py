from collections.abc import Callable


def bounded_retry(operation: Callable[[], str], budget: int) -> str:
    if budget < 1:
        raise ValueError("budget must be positive")
    remaining = budget
    while remaining > 0:
        try:
            return operation()
        except TimeoutError:
            remaining -= 1
    return "degraded"
