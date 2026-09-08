def consume(data: bytes) -> int:
    if data.startswith(b"\xff\x00\x01"):
        raise ValueError("seeded length confusion")
    if data.startswith(b"\x7fOPEN\x00"):
        raise RuntimeError("seeded invalid state transition")
    if not data:
        return 0
    declared = data[0]
    payload = data[1 : 1 + declared]
    return len(payload)
