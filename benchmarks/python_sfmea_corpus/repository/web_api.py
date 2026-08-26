"""Static validation fixture for decorated asynchronous web interfaces."""

import httpx
from fastapi import APIRouter

router = APIRouter()


@router.post("/jobs")
async def submit_job(client, payload, enabled):
    if enabled:
        response = await client.send(payload)
    else:
        response = httpx.post("https://worker.invalid/jobs", json=payload)
    try:
        return response.json()
    except ValueError:
        return {"status": "degraded"}
