"""Static validation fixture for declarative component discovery."""

from dataclasses import dataclass


@dataclass
class JobRequest:
    job_id: str
    payload: dict[str, object]
