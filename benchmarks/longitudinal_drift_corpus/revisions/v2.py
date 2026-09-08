def fetch(client):
    try:
        return client.get("/inventory", timeout=0.25)
    except TimeoutError:
        return {"status": "degraded", "items": []}
