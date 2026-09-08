"""Conservative Harbor TrialResult intake for Terminal-Bench binary rewards.

Basis: harbor/models/trial/result.py and harbor/models/verifier/result.py.
Each attempt is a distinct observation. Multi-step and nonbinary scorers require
another explicitly reviewed mapping and are rejected rather than approximated.
"""

from __future__ import annotations

import re
from typing import Any


def trial_observation(trial: dict[str, Any]) -> dict[str, Any]:
    if trial.get("step_results"):
        raise ValueError("multi-step Harbor trials require a dedicated scorer mapping")
    for field in ("task_name", "trial_name", "task_checksum", "id"):
        if not isinstance(trial.get(field), str) or not trial[field].strip():
            raise ValueError(f"Harbor trial requires {field}")
    if not re.fullmatch(r"[0-9a-f]{64}", trial["task_checksum"]):
        raise ValueError("Harbor task checksum must be SHA-256")
    if not isinstance(trial.get("config"), dict) or not trial["config"]:
        raise ValueError("Harbor trial requires retained configuration")
    info = trial.get("agent_info")
    if not isinstance(info, dict) or not info.get("name") or not info.get("version"):
        raise ValueError("Harbor trial requires agent identity and version")
    verifier = trial.get("verifier_result") or {}
    rewards = verifier.get("rewards")
    passed: bool | None = None
    if trial.get("exception_info") is not None:
        outcome = "error"
    elif not trial.get("finished_at"):
        outcome = "incomplete"
    else:
        if not isinstance(rewards, dict) or set(rewards) != {"reward"}:
            raise ValueError("Terminal-Bench requires an explicit single reward scorer")
        reward = rewards["reward"]
        if (
            isinstance(reward, bool)
            or not isinstance(reward, (int, float))
            or reward not in (0, 1)
        ):
            raise ValueError("Terminal-Bench reward must be numeric zero or one")
        passed = reward == 1
        outcome = "success" if passed else "failure"
    return {
        "case_id": f"{trial['task_name']}@{trial['task_checksum']}/{trial['trial_name']}",
        "passed": passed,
        "resolved": passed,
        "outcome": outcome,
    }
