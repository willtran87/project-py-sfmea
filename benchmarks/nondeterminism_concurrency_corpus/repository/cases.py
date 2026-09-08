from __future__ import annotations

import asyncio
import random
import threading
import time
from collections.abc import Callable
from datetime import datetime


def random_branch(source: random.Random) -> str:
    return "primary" if source.random() >= 0.5 else "fallback"


def clock_boundary(now: Callable[[], datetime]) -> str:
    return "expired" if now().hour == 0 else "active"


def thread_race(iterations: int = 100) -> int:
    shared = {"count": 0}

    def increment() -> None:
        for _ in range(iterations):
            current = shared["count"]
            time.sleep(0)
            shared["count"] = current + 1

    workers = [threading.Thread(target=increment) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    return shared["count"]


async def async_order(delays: tuple[float, float]) -> list[str]:
    completed: list[str] = []

    async def work(label: str, delay: float) -> None:
        await asyncio.sleep(delay)
        completed.append(label)

    await asyncio.gather(work("a", delays[0]), work("b", delays[1]))
    return completed


def eventual_read(
    read: Callable[[], str | None], *, deadline_seconds: float = 0.05
) -> str | None:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        value = read()
        if value is not None:
            return value
        time.sleep(0.001)
    return None
