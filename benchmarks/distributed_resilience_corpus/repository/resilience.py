from __future__ import annotations

import asyncio
from collections.abc import Callable


def deliver(send: Callable[[str], None], key: str, attempts: int = 3) -> str:
    if not key:
        raise ValueError("idempotency key required")
    for attempt in range(attempts):
        try:
            send(key)
            return "delivered_once"
        except TimeoutError:
            if attempt + 1 == attempts:
                return "degraded"
    return "degraded"


async def cancel_work(commit: Callable[[], None]) -> str:
    try:
        await asyncio.sleep(0)
    except asyncio.CancelledError:
        return "cancelled_without_commit"
    commit()
    return "committed"
