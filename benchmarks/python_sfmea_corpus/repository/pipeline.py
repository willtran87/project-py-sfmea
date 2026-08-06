"""Static fixture for typed interfaces, internal cascades, and async recovery paths."""

import asyncio

from httpx import AsyncClient, Response


def decode_response(response: Response) -> dict[str, object]:
    return response.json()


async def fetch_job(client: AsyncClient, url: str, retries: int) -> dict[str, object]:
    for attempt in range(retries + 1):
        try:
            response = await client.get(url)
            return decode_response(response)
        except TimeoutError:
            if attempt >= retries:
                raise
            await asyncio.sleep(0)
    raise RuntimeError("retry loop completed without a result")


async def run_pipeline(client: AsyncClient, url: str) -> dict[str, object]:
    task = asyncio.create_task(fetch_job(client, url, retries=2))
    return await task
