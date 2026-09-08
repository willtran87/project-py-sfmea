"""Supported Inspect run-config projection; basis: inspect_ai/log/_config.py."""

from __future__ import annotations

from typing import Any

OPERATIONAL_FIELDS = frozenset(
    {
        "log_samples",
        "log_realtime",
        "log_images",
        "log_model_api",
        "log_buffer",
        "log_shared",
        "score_display",
        "sandbox_cleanup",
        "sandbox_prebuilt",
        "max_samples",
        "max_dataset_memory",
        "max_tasks",
        "max_subprocesses",
        "max_sandboxes",
    }
)


def expected_run_config(log: dict[str, Any]) -> dict[str, Any]:
    spec = log["eval"]
    task_name = spec.get("task_registry_name") or spec["task"]
    task_ref = (
        f"{spec['task_file']}@{task_name}" if spec.get("task_file") else task_name
    )
    task = {"task": task_ref}
    if spec.get("task_args"):
        task["args"] = spec["task_args"]

    def model_entry(model: dict[str, Any]) -> dict[str, Any]:
        entry = {"model": model["model"]}
        for key in ("base_url", "args", "config"):
            value = model.get(key)
            if isinstance(value, dict):
                value = {k: v for k, v in value.items() if v is not None}
            if value:
                entry[key] = value
        return entry

    result: dict[str, Any] = {
        "task": task,
        "model": model_entry(
            {
                "model": spec["model"],
                "base_url": spec.get("model_base_url"),
                "args": spec.get("model_args"),
                "config": spec.get("model_generate_config"),
            }
        ),
    }
    if spec.get("model_roles"):
        result["model_roles"] = {
            name: [model_entry(m) for m in group]
            if isinstance(group, list)
            else model_entry(group)
            for name, group in spec["model_roles"].items()
        }
    plan_config = (log.get("plan") or {}).get("config") or {}
    generate = {k: v for k, v in plan_config.items() if v is not None}
    if generate:
        result["generate_config"] = generate
    if spec.get("solver"):
        result["solver"] = {"solver": spec["solver"]}
        if spec.get("solver_args"):
            result["solver"]["args"] = spec["solver_args"]
    config = {
        k: v
        for k, v in (spec.get("config") or {}).items()
        if k not in OPERATIONAL_FIELDS and v is not None
    }
    if config:
        result["eval_config"] = config
    sandbox = spec.get("sandbox")
    if isinstance(sandbox, dict):
        sandbox_type, sandbox_config = sandbox["type"], sandbox.get("config")
        if sandbox_config is not None and not isinstance(sandbox_config, str):
            raise ValueError(
                "Inspect sandbox configuration cannot be reproduced from a type alone"
            )
        sandbox = f"{sandbox_type}:{sandbox_config}" if sandbox_config else sandbox_type
    if sandbox is not None:
        if not isinstance(sandbox, str) or not sandbox.strip():
            raise ValueError(
                "Inspect sandbox must be an explicit reproducible specification"
            )
        result["sandbox"] = sandbox
    for key in ("tags", "metadata"):
        if spec.get(key):
            result[key] = spec[key]
    return result


def configuration_matches(log: Any, config: Any) -> bool:
    try:
        return isinstance(config, dict) and config == expected_run_config(log)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
