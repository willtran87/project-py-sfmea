"""Pure, typed sandbox command policy shared by execution providers."""

from __future__ import annotations

import os
import shutil
from pathlib import Path, PurePosixPath
from typing import Callable, cast


def resolve_sandbox_engine(engine: str) -> str:
    """Resolve an explicitly allowed local container engine without pulling software."""

    if engine not in {"auto", "docker", "podman"}:
        raise ValueError("sandbox engine must be auto, docker, or podman")
    names = ("docker", "podman") if engine == "auto" else (engine,)
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    raise ValueError(
        "no Docker or Podman executable is available for sandbox execution"
    )


def _pytest_command(command: list[str]) -> bool:
    names = [Path(value).name.casefold() for value in command[:3]]
    return bool(
        names
        and (
            names[0] in {"pytest", "pytest.exe"}
            or (len(names) >= 3 and names[1:3] == ["-m", "pytest"])
        )
    )


def _sandbox_user() -> str:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if os.name == "posix" and callable(getuid) and callable(getgid):
        uid = cast(Callable[[], int], getuid)()
        gid = cast(Callable[[], int], getgid)()
        return f"{uid}:{gid}"
    return "65534:65534"


def sandbox_command(
    *,
    engine_path: str,
    container_name: str,
    repository: Path,
    evidence_directory: Path,
    image: str,
    command_argv: list[str],
    cpus: float,
    memory_mb: int,
    pids_limit: int,
) -> list[str]:
    """Return a shell-free, network-denied, least-privilege container argv."""

    if not image.strip() or any(character.isspace() for character in image):
        raise ValueError(
            "sandbox image must be a non-empty image reference without whitespace"
        )
    if not 0.1 <= cpus <= 8:
        raise ValueError("sandbox CPU limit must be from 0.1 through 8")
    if not 128 <= memory_mb <= 32768:
        raise ValueError("sandbox memory limit must be from 128 through 32768 MiB")
    if not 16 <= pids_limit <= 1024:
        raise ValueError("sandbox process limit must be from 16 through 1024")
    if not command_argv or not all(
        isinstance(value, str) and value and "\x00" not in value
        for value in command_argv
    ):
        raise ValueError("sandbox command argv must contain non-empty strings")
    command = list(command_argv)
    if _pytest_command(command) and not any(
        value.startswith("--junitxml") for value in command
    ):
        command.append("--junitxml=/evidence/junit.xml")
    engine_name = Path(engine_path).name.casefold()
    security = (
        ["--security-opt", "no-new-privileges"]
        if "podman" in engine_name
        else ["--security-opt", "no-new-privileges:true"]
    )
    pull = ["--pull=never"] if "podman" in engine_name else ["--pull", "never"]
    entrypoint, *arguments = command
    container_temp = PurePosixPath("/") / "tmp"
    return [
        engine_path,
        "run",
        *pull,
        "--name",
        container_name,
        "--rm",
        "--network",
        "none",
        "--ipc",
        "none",
        "--read-only",
        "--user",
        _sandbox_user(),
        "--cpus",
        str(cpus),
        "--memory",
        f"{memory_mb}m",
        "--pids-limit",
        str(pids_limit),
        "--cap-drop",
        "ALL",
        "--ulimit",
        "nofile=1024:1024",
        *security,
        "--mount",
        f"type=bind,src={repository},dst=/workspace,readonly",
        "--mount",
        f"type=bind,src={evidence_directory},dst=/evidence",
        "--tmpfs",
        f"{container_temp}:rw,noexec,nosuid,nodev,size=268435456",
        "--env",
        f"HOME={container_temp}",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONUNBUFFERED=1",
        "--env",
        "PYSFMEA_APPROVED_SANDBOX=1",
        "--workdir",
        "/workspace",
        "--entrypoint",
        entrypoint,
        image,
        *arguments,
    ]
