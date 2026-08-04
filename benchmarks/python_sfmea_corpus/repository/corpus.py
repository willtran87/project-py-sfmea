"""Synthetic scanner-validation corpus. The functions are intentionally failure-prone."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.request import urlopen


def divide_measurement(total: float, count: int) -> float:
    return total / count


def parse_external_payload(payload: str) -> dict[str, Any]:
    return json.loads(payload)


def fetch_remote_configuration(url: str) -> bytes:
    return urlopen(url).read()


def persist_state(database: Path, value: str) -> None:
    connection = sqlite3.connect(database)
    connection.execute("insert into state(value) values (?)", (value,))
    connection.commit()


def run_worker(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, capture_output=True, text=True, check=False)


def read_runtime_setting(name: str) -> str | None:
    return os.getenv(name)


def update_shared_state(state: dict[str, int], lock: threading.Lock) -> None:
    with lock:
        state["value"] = state.get("value", 0) + 1


def wait_for_deadline(seconds: float) -> None:
    time.sleep(seconds)


def masked_failure(value: str) -> dict[str, Any]:
    try:
        return json.loads(value)
    except Exception:
        return {}
