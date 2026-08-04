"""Controlled assurance-test execution and independent evidence adjudication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, BinaryIO

from .assurance import assurance_summary, ensure_assurance_register
from .model import stable_id, utc_now

EXECUTION_SCHEMA_VERSION = "1.0"
EVIDENCE_REVIEW_DECISIONS = {
    "sufficient",
    "partial",
    "insufficient",
    "test_did_not_exercise_failure",
    "stale",
    "requires_human_review",
}
EXECUTION_STATUSES = {"planned", "passed", "failed", "timeout", "error"}
CRITERION_RESULTS = {"pass", "fail", "insufficient", "not_observed"}
MAX_CAPTURE_BYTES = 2_000_000
MAX_TEST_BYTES = 2_000_000
MAX_TIMEOUT_SECONDS = 7200
MAX_IMPORT_MANIFEST_BYTES = 2_000_000
MAX_IMPORTED_ARTIFACT_BYTES = 100_000_000
MAX_IMPORTED_EVIDENCE_BYTES = 500_000_000


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(root: Path, value: Path) -> bool:
    try:
        value.relative_to(root)
        return True
    except ValueError:
        return False


def _obligation(analysis: dict[str, Any], obligation_id: str) -> dict[str, Any]:
    register = ensure_assurance_register(analysis)
    value = next(
        (
            candidate
            for candidate in register.get("obligations", [])
            if candidate.get("id") == obligation_id
        ),
        None,
    )
    if value is None:
        raise KeyError(obligation_id)
    return value


def _repository_root(analysis: dict[str, Any]) -> Path:
    root = Path(str(analysis.get("project", {}).get("root", ""))).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"analysis repository root is unavailable: {root}")
    return root


def _test_file(root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("assurance test path must be repository-relative")
    path = (root / relative).resolve()
    if not _inside(root, path):
        raise ValueError("assurance test path escapes the repository")
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"assurance test must be a regular non-symlink file: {path}")
    if path.stat().st_size > MAX_TEST_BYTES:
        raise ValueError(f"assurance test exceeds {MAX_TEST_BYTES} bytes: {path}")
    return path


def register_test_implementation(
    analysis: dict[str, Any],
    obligation_id: str,
    *,
    test_path: str,
    author: str,
    origin: str,
    status: str = "implemented",
) -> dict[str, Any]:
    """Bind a proposed/implemented test source to one obligation by content hash."""

    if status not in {"proposed", "implemented"}:
        raise ValueError("test implementation status must be proposed or implemented")
    if origin not in {"human", "llm_generated", "imported"}:
        raise ValueError("test implementation origin must be human, llm_generated, or imported")
    if not author.strip():
        raise ValueError("test implementation requires an author or generating agent identity")
    obligation = _obligation(analysis, obligation_id)
    root = _repository_root(analysis)
    path = _test_file(root, test_path)
    relative = path.relative_to(root).as_posix()
    at = utc_now()
    obligation["automation"].update(
        {
            "implementation_status": status,
            "implemented_test_path": relative,
            "test_sha256": _sha256_file(path),
            "implementation_origin": origin,
            "implemented_by": author.strip(),
            "implemented_at": at,
        }
    )
    obligation["assurance_status"] = (
        "test_proposed" if status == "proposed" else "verification_planned"
    )
    obligation.setdefault("history", []).append(
        {
            "event": "test_implementation_registered",
            "at": at,
            "status": status,
            "test_path": relative,
            "test_sha256": obligation["automation"]["test_sha256"],
            "origin": origin,
            "author": author.strip(),
        }
    )
    ensure_assurance_register(analysis)["summary"] = assurance_summary(
        analysis["assurance"]
    )
    return obligation


def _git_state(root: Path) -> dict[str, Any]:
    try:
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return {"type": "unavailable", "revision": "", "dirty": None}
    return {
        "type": "git",
        "revision": revision.stdout.strip() if revision.returncode == 0 else "",
        "dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
        "status_sha256": hashlib.sha256(status.stdout.encode("utf-8")).hexdigest()
        if status.returncode == 0
        else "",
    }


def _resolve_engine(engine: str) -> str:
    if engine not in {"auto", "docker", "podman"}:
        raise ValueError("sandbox engine must be auto, docker, or podman")
    names = ("docker", "podman") if engine == "auto" else (engine,)
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    raise ValueError("no Docker or Podman executable is available for sandbox execution")


def _pytest_command(command: list[str]) -> bool:
    names = [Path(value).name.casefold() for value in command[:3]]
    return bool(
        names
        and (
            names[0] in {"pytest", "pytest.exe"}
            or (len(names) >= 3 and names[1:3] == ["-m", "pytest"])
        )
    )


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
    """Return a shell-free, locked-down Docker/Podman command argv."""

    if not image.strip() or any(character.isspace() for character in image):
        raise ValueError("sandbox image must be a non-empty image reference without whitespace")
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
        "65534:65534",
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
        "'/tmp:rw,noexec,nosuid,nodev,size=268435456'".strip("'"),
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONUNBUFFERED=1",
        "--workdir",
        "/workspace",
        "--entrypoint",
        entrypoint,
        image,
        *arguments,
    ]


def prepare_sandbox_execution(
    analysis: dict[str, Any],
    obligation_id: str,
    *,
    image: str,
    initiated_by: str,
    engine: str = "auto",
    cpus: float = 1.0,
    memory_mb: int = 1024,
    pids_limit: int = 128,
    timeout_seconds: int = 900,
    allow_dirty: bool = False,
    evidence_directory: str | Path = ".assurance-evidence-preview",
) -> dict[str, Any]:
    """Validate freshness and return the exact execution contract without running it."""

    if not initiated_by.strip():
        raise ValueError("sandbox execution requires an initiating identity")
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"sandbox timeout must be from 1 through {MAX_TIMEOUT_SECONDS} seconds")
    obligation = _obligation(analysis, obligation_id)
    automation = obligation.get("automation", {})
    if automation.get("implementation_status") != "implemented":
        raise ValueError("assurance test must be registered as implemented before execution")
    root = _repository_root(analysis)
    test_path = _test_file(root, str(automation.get("implemented_test_path", "")))
    actual_test_sha = _sha256_file(test_path)
    if actual_test_sha != automation.get("test_sha256"):
        raise ValueError("registered assurance test hash is stale; register the implementation again")
    baseline = analysis.get("project", {}).get("baseline", {})
    if obligation.get("baseline_id") != baseline.get("id"):
        raise ValueError("assurance obligation is stale for the current analysis baseline")
    current_vcs = _git_state(root)
    recorded_vcs = baseline.get("vcs", {})
    if (
        recorded_vcs.get("revision")
        and current_vcs.get("revision") != recorded_vcs.get("revision")
    ):
        raise ValueError("repository revision differs from the analyzed baseline; rescan first")
    if current_vcs.get("dirty") and not allow_dirty:
        raise ValueError(
            "repository is dirty; commit and rescan or use --allow-dirty with an explicit weaker-freshness record"
        )
    engine_path = _resolve_engine(engine)
    image_inspect = subprocess.run(
        [engine_path, "image", "inspect", "--format", "{{.Id}}", image],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if image_inspect.returncode != 0 or not image_inspect.stdout.strip():
        raise ValueError(
            "approved sandbox image is not available locally; PySFMEA will not pull images during execution"
        )
    nonce = uuid.uuid4().hex
    execution_id = stable_id("EXEC", obligation_id, utc_now(), nonce)
    container_name = f"pysfmea-{execution_id.casefold()}"
    evidence = Path(evidence_directory).expanduser().resolve()
    argv = sandbox_command(
        engine_path=engine_path,
        container_name=container_name,
        repository=root,
        evidence_directory=evidence,
        image=image,
        command_argv=list(automation.get("command_argv", [])),
        cpus=cpus,
        memory_mb=memory_mb,
        pids_limit=pids_limit,
    )
    return {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "id": execution_id,
        "obligation_id": obligation_id,
        "finding_id": obligation.get("finding_id", ""),
        "baseline_id": baseline.get("id", ""),
        "repository": {
            "root": str(root),
            "recorded_vcs": recorded_vcs,
            "as_run_vcs": current_vcs,
            "allow_dirty": allow_dirty,
        },
        "test": {
            "path": test_path.relative_to(root).as_posix(),
            "sha256": actual_test_sha,
            "origin": automation.get("implementation_origin", ""),
            "implemented_by": automation.get("implemented_by", ""),
        },
        "sandbox": {
            "engine": Path(engine_path).name,
            "engine_path": engine_path,
            "image": image,
            "image_id": image_inspect.stdout.strip(),
            "container_name": container_name,
            "network": "none",
            "repository_mount": "read_only",
            "capabilities": "dropped_all",
            "no_new_privileges": True,
            "cpus": cpus,
            "memory_mb": memory_mb,
            "pids_limit": pids_limit,
            "timeout_seconds": timeout_seconds,
            "credentials_forwarded": False,
        },
        "command_argv": argv,
        "test_command_argv": list(automation.get("command_argv", [])),
        "initiated_by": initiated_by.strip(),
        "evidence_directory": str(evidence),
        "acceptance_criteria": [
            {"index": index, "text": text, "result": "unassessed", "evidence_ids": []}
            for index, text in enumerate(obligation.get("acceptance_criteria", []), start=1)
        ],
        "stimulus_observed": None,
        "status": "planned",
        "reviews": [],
        "artifacts": [],
    }


class _BoundedCapture:
    def __init__(self, stream: BinaryIO, limit: int = MAX_CAPTURE_BYTES) -> None:
        self.stream = stream
        self.limit = limit
        self.data = bytearray()
        self.total = 0

    def drain(self) -> None:
        while chunk := self.stream.read(65536):
            self.total += len(chunk)
            remaining = self.limit - len(self.data)
            if remaining > 0:
                self.data.extend(chunk[:remaining])

    @property
    def truncated(self) -> bool:
        return self.total > len(self.data)


def _junit_summary(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > 20_000_000:
        return {}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return {"parse_error": True}
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    return {
        "tests": sum(int(value.get("tests", 0)) for value in suites),
        "failures": sum(int(value.get("failures", 0)) for value in suites),
        "errors": sum(int(value.get("errors", 0)) for value in suites),
        "skipped": sum(int(value.get("skipped", 0)) for value in suites),
        "time_seconds": sum(float(value.get("time", 0) or 0) for value in suites),
    }


def _artifact(execution_id: str, kind: str, path: Path, run_directory: Path) -> dict[str, Any]:
    digest = _sha256_file(path)
    return {
        "id": stable_id("EVID", execution_id, kind, digest),
        "execution_id": execution_id,
        "kind": kind,
        "path": path.relative_to(run_directory).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": digest,
        "created_at": utc_now(),
    }


def _write_execution_manifest(contract: dict[str, Any], directory: Path) -> None:
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    contract["execution_manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    (directory / "execution.json").write_text(
        json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _record_collected_execution(
    analysis: dict[str, Any],
    obligation: dict[str, Any],
    contract: dict[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    event: str,
) -> None:
    register = ensure_assurance_register(analysis)
    register.setdefault("executions", []).append(contract)
    register.setdefault("evidence_artifacts", []).extend(artifacts)
    obligation.setdefault("executions", []).append(contract["id"])
    obligation.setdefault("evidence_artifact_ids", []).extend(
        value["id"] for value in artifacts
    )
    obligation["evidence_status"] = "collected_unreviewed"
    obligation["assurance_status"] = "evidence_collected"
    obligation.setdefault("history", []).append(
        {
            "event": event,
            "at": contract["ended_at"],
            "execution_id": contract["id"],
            "status": contract["status"],
        }
    )
    register["summary"] = assurance_summary(register)


def run_sandbox_execution(
    analysis: dict[str, Any],
    obligation_id: str,
    *,
    image: str,
    initiated_by: str,
    evidence_root: str | Path,
    approved: bool,
    engine: str = "auto",
    cpus: float = 1.0,
    memory_mb: int = 1024,
    pids_limit: int = 128,
    timeout_seconds: int = 900,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    """Execute an implemented test in a restricted container and capture immutable evidence."""

    if not approved:
        raise ValueError("sandbox execution requires explicit --approve-execution")
    root = Path(evidence_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    preview = root / f".planning-{uuid.uuid4().hex}"
    contract = prepare_sandbox_execution(
        analysis,
        obligation_id,
        image=image,
        initiated_by=initiated_by,
        engine=engine,
        cpus=cpus,
        memory_mb=memory_mb,
        pids_limit=pids_limit,
        timeout_seconds=timeout_seconds,
        allow_dirty=allow_dirty,
        evidence_directory=preview,
    )
    run_directory = root / contract["id"]
    if run_directory.exists():
        raise ValueError(f"execution evidence destination already exists: {run_directory}")
    preview.mkdir(parents=True, exist_ok=False)
    try:
        os.chmod(preview, 0o777)
    except OSError:
        pass
    # The mount argument embeds the path, so build against the staging destination.
    argv = sandbox_command(
        engine_path=str(contract["sandbox"]["engine_path"]),
        container_name=str(contract["sandbox"]["container_name"]),
        repository=_repository_root(analysis),
        evidence_directory=preview,
        image=image,
        command_argv=list(contract["test_command_argv"]),
        cpus=cpus,
        memory_mb=memory_mb,
        pids_limit=pids_limit,
    )
    started_at = utc_now()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env={
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "WINDIR": os.environ.get("WINDIR", ""),
                "DOCKER_HOST": os.environ.get("DOCKER_HOST", ""),
            },
        )
    except OSError:
        shutil.rmtree(preview, ignore_errors=True)
        raise
    assert process.stdout is not None and process.stderr is not None
    stdout = _BoundedCapture(process.stdout)
    stderr = _BoundedCapture(process.stderr)
    threads = [
        threading.Thread(target=stdout.drain, daemon=True),
        threading.Thread(target=stderr.drain, daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        exit_code = None
        subprocess.run(
            [
                str(contract["sandbox"]["engine_path"]),
                "rm",
                "--force",
                str(contract["sandbox"]["container_name"]),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
    for thread in threads:
        thread.join(timeout=10)
    process.stdout.close()
    process.stderr.close()
    duration = round(time.monotonic() - started, 3)
    (preview / "stdout.log").write_bytes(bytes(stdout.data))
    (preview / "stderr.log").write_bytes(bytes(stderr.data))
    status = "timeout" if timed_out else "passed" if exit_code == 0 else "failed"
    contract.update(
        {
            "status": status,
            "exit_code": exit_code,
            "started_at": started_at,
            "ended_at": utc_now(),
            "duration_seconds": duration,
            "capture": {
                "stdout_total_bytes": stdout.total,
                "stdout_truncated": stdout.truncated,
                "stderr_total_bytes": stderr.total,
                "stderr_truncated": stderr.truncated,
                "capture_limit_bytes": MAX_CAPTURE_BYTES,
            },
            "result": {"junit": _junit_summary(preview / "junit.xml")},
        }
    )
    artifacts = [
        _artifact(contract["id"], "stdout", preview / "stdout.log", preview),
        _artifact(contract["id"], "stderr", preview / "stderr.log", preview),
    ]
    if (preview / "junit.xml").is_file():
        artifacts.append(
            _artifact(contract["id"], "junit", preview / "junit.xml", preview)
        )
    contract["artifacts"] = [value["id"] for value in artifacts]
    contract["evidence_directory"] = str(run_directory)
    _write_execution_manifest(contract, preview)
    os.replace(preview, run_directory)
    try:
        os.chmod(run_directory, 0o700)
    except OSError:
        pass
    obligation = _obligation(analysis, obligation_id)
    _record_collected_execution(
        analysis,
        obligation,
        contract,
        artifacts,
        event="sandbox_execution_collected",
    )
    return contract


def import_execution_evidence(
    analysis: dict[str, Any],
    obligation_id: str,
    *,
    manifest_path: str | Path,
    evidence_root: str | Path,
    initiated_by: str,
) -> dict[str, Any]:
    """Import bounded CI/external execution evidence into a governed local record."""

    if not initiated_by.strip():
        raise ValueError("evidence import requires an initiating identity")
    source_manifest = Path(manifest_path).expanduser().resolve()
    if (
        not source_manifest.is_file()
        or source_manifest.is_symlink()
        or source_manifest.stat().st_size > MAX_IMPORT_MANIFEST_BYTES
    ):
        raise ValueError("evidence manifest must be a regular file within the size limit")
    try:
        supplied = json.loads(source_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence manifest is not valid UTF-8 JSON") from exc
    if not isinstance(supplied, dict) or supplied.get("schema_version") != "1.0":
        raise ValueError("evidence manifest must be an object with schema_version 1.0")
    obligation = _obligation(analysis, obligation_id)
    baseline = analysis.get("project", {}).get("baseline", {})
    if supplied.get("baseline_id") != baseline.get("id"):
        raise ValueError("imported evidence does not identify the current analysis baseline")
    recorded_revision = str(baseline.get("vcs", {}).get("revision", ""))
    supplied_revision = str(supplied.get("repository_revision", ""))
    if recorded_revision and supplied_revision != recorded_revision:
        raise ValueError("imported evidence repository revision differs from the analysis baseline")
    status = str(supplied.get("status", ""))
    if status not in EXECUTION_STATUSES - {"planned"}:
        raise ValueError("imported execution status must be passed, failed, timeout, or error")
    command_argv = supplied.get("command_argv")
    if not isinstance(command_argv, list) or not command_argv or not all(
        isinstance(value, str) and value and "\x00" not in value for value in command_argv
    ):
        raise ValueError("imported command_argv must be a non-empty string array")
    test = supplied.get("test")
    if not isinstance(test, dict) or not isinstance(test.get("path"), str):
        raise ValueError("imported evidence must identify the repository-relative test path")
    root = _repository_root(analysis)
    test_path = _test_file(root, str(test["path"]))
    test_sha = _sha256_file(test_path)
    if test.get("sha256") != test_sha:
        raise ValueError("imported evidence test hash does not match the current test source")
    automation = obligation.get("automation", {})
    if automation.get("implementation_status") != "implemented":
        register_test_implementation(
            analysis,
            obligation_id,
            test_path=test_path.relative_to(root).as_posix(),
            author=initiated_by,
            origin="imported",
        )
        automation = obligation["automation"]
    if (
        automation.get("implemented_test_path") != test_path.relative_to(root).as_posix()
        or automation.get("test_sha256") != test_sha
    ):
        raise ValueError("imported evidence does not match the registered test implementation")
    supplied_artifacts = supplied.get("artifacts")
    if not isinstance(supplied_artifacts, list) or not supplied_artifacts:
        raise ValueError("imported evidence must include at least one artifact")
    source_root = source_manifest.parent.resolve()
    sources: list[tuple[str, Path, str]] = []
    total_bytes = 0
    for index, artifact in enumerate(supplied_artifacts, start=1):
        if not isinstance(artifact, dict):
            raise ValueError(f"artifact {index} must be an object")
        kind = str(artifact.get("kind", ""))
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", kind):
            raise ValueError(f"artifact {index} has an invalid kind")
        relative = Path(str(artifact.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"artifact {index} path must be manifest-relative")
        source = (source_root / relative).resolve()
        if not _inside(source_root, source) or not source.is_file() or source.is_symlink():
            raise ValueError(f"artifact {index} path is missing or unsafe")
        size = source.stat().st_size
        if size > MAX_IMPORTED_ARTIFACT_BYTES:
            raise ValueError(f"artifact {index} exceeds the per-artifact size limit")
        total_bytes += size
        if total_bytes > MAX_IMPORTED_EVIDENCE_BYTES:
            raise ValueError("imported evidence exceeds the total size limit")
        actual_sha = _sha256_file(source)
        claimed_sha = str(artifact.get("sha256", ""))
        if claimed_sha and claimed_sha != actual_sha:
            raise ValueError(f"artifact {index} digest does not match its manifest claim")
        sources.append((kind.casefold(), source, actual_sha))
    supplied_digest = hashlib.sha256(
        json.dumps(supplied, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    execution_id = stable_id("EXEC", obligation_id, baseline.get("id", ""), supplied_digest)
    register = ensure_assurance_register(analysis)
    existing = next(
        (value for value in register.get("executions", []) if value.get("id") == execution_id),
        None,
    )
    if existing is not None:
        return existing
    destination_root = Path(evidence_root).expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    run_directory = destination_root / execution_id
    if run_directory.exists():
        raise ValueError(f"execution evidence destination already exists: {run_directory}")
    preview = destination_root / f".import-{uuid.uuid4().hex}"
    preview.mkdir(parents=True, exist_ok=False)
    artifacts: list[dict[str, Any]] = []
    try:
        for index, (kind, source, actual_sha) in enumerate(sources, start=1):
            suffix = source.suffix[:16] if re.fullmatch(r"\.[A-Za-z0-9._-]+", source.suffix) else ""
            destination = preview / f"artifact-{index:03d}-{kind}{suffix}"
            shutil.copyfile(source, destination)
            if _sha256_file(destination) != actual_sha:
                raise ValueError(f"artifact {index} changed while it was imported")
            artifacts.append(_artifact(execution_id, kind, destination, preview))
        at = utc_now()
        contract: dict[str, Any] = {
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "id": execution_id,
            "obligation_id": obligation_id,
            "finding_id": obligation.get("finding_id", ""),
            "baseline_id": baseline.get("id", ""),
            "execution_mode": "external_import",
            "import_trust": "externally_supplied_unattested",
            "source_manifest_sha256": supplied_digest,
            "repository": {
                "root": str(root),
                "recorded_vcs": baseline.get("vcs", {}),
                "as_run_vcs": {
                    "type": "external_manifest",
                    "revision": supplied_revision,
                    "dirty": supplied.get("repository_dirty"),
                },
            },
            "test": {
                "path": test_path.relative_to(root).as_posix(),
                "sha256": test_sha,
                "origin": automation.get("implementation_origin", "imported"),
                "implemented_by": automation.get("implemented_by", initiated_by),
            },
            "command_argv": command_argv,
            "test_command_argv": command_argv,
            "initiated_by": initiated_by.strip(),
            "environment": supplied.get("environment", {}),
            "dependency_lock": supplied.get("dependency_lock", {}),
            "evidence_directory": str(run_directory),
            "acceptance_criteria": [
                {"index": index, "text": text, "result": "unassessed", "evidence_ids": []}
                for index, text in enumerate(obligation.get("acceptance_criteria", []), start=1)
            ],
            "stimulus_observed": None,
            "status": status,
            "exit_code": supplied.get("exit_code"),
            "started_at": str(supplied.get("started_at", at)),
            "ended_at": str(supplied.get("ended_at", at)),
            "duration_seconds": supplied.get("duration_seconds"),
            "result": supplied.get("result", {}),
            "reviews": [],
            "artifacts": [value["id"] for value in artifacts],
        }
        _write_execution_manifest(contract, preview)
        os.replace(preview, run_directory)
    except Exception:
        shutil.rmtree(preview, ignore_errors=True)
        raise
    _record_collected_execution(
        analysis,
        obligation,
        contract,
        artifacts,
        event="external_execution_evidence_imported",
    )
    return contract


def _verify_execution_manifest(execution: dict[str, Any]) -> tuple[bool, str]:
    """Verify the on-disk execution statement against its recorded canonical digest."""

    directory = Path(str(execution.get("evidence_directory", ""))).resolve()
    manifest = (directory / "execution.json").resolve()
    if not _inside(directory, manifest) or not manifest.is_file() or manifest.is_symlink():
        return False, "execution manifest is missing or unsafe"
    try:
        on_disk = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, "execution manifest is unreadable or invalid JSON"
    expected = str(on_disk.pop("execution_manifest_sha256", ""))
    canonical = json.dumps(on_disk, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    actual = hashlib.sha256(canonical).hexdigest()
    if not expected or expected != actual:
        return False, "execution manifest digest is invalid"
    recorded = str(execution.get("execution_manifest_sha256", ""))
    if expected != recorded:
        return False, "execution manifest does not match the analysis record"
    mutable_after_collection = {"acceptance_criteria", "reviews", "stimulus_observed"}
    for key, value in on_disk.items():
        if key not in mutable_after_collection and execution.get(key) != value:
            return False, "execution manifest content does not match the analysis record"
    return True, ""


def _verify_artifacts(
    register: dict[str, Any], execution: dict[str, Any]
) -> tuple[bool, list[str]]:
    directory = Path(str(execution.get("evidence_directory", ""))).resolve()
    artifacts = {
        value.get("id"): value for value in register.get("evidence_artifacts", [])
    }
    errors = []
    manifest_valid, manifest_error = _verify_execution_manifest(execution)
    if not manifest_valid:
        errors.append(manifest_error)
    for artifact_id in execution.get("artifacts", []):
        artifact = artifacts.get(artifact_id)
        if not artifact:
            errors.append(f"missing artifact record: {artifact_id}")
            continue
        path = (directory / str(artifact.get("path", ""))).resolve()
        if not _inside(directory, path) or not path.is_file() or path.is_symlink():
            errors.append(f"artifact path is missing or unsafe: {artifact_id}")
            continue
        if path.stat().st_size != artifact.get("bytes") or _sha256_file(path) != artifact.get(
            "sha256"
        ):
            errors.append(f"artifact content changed: {artifact_id}")
    return not errors, errors


def review_execution_evidence(
    analysis: dict[str, Any],
    execution_id: str,
    *,
    reviewer: str,
    decision: str,
    rationale: str,
    stimulus_observed: bool,
    criterion_results: dict[int, str],
) -> dict[str, Any]:
    """Independently adjudicate as-run evidence against pre-existing criteria."""

    if decision not in EVIDENCE_REVIEW_DECISIONS:
        raise ValueError("invalid evidence-review decision")
    if not reviewer.strip() or not rationale.strip():
        raise ValueError("evidence review requires a reviewer and rationale")
    register = ensure_assurance_register(analysis)
    execution = next(
        (
            value
            for value in register.get("executions", [])
            if value.get("id") == execution_id
        ),
        None,
    )
    if execution is None:
        raise KeyError(execution_id)
    if reviewer.strip() == str(execution.get("initiated_by", "")).strip():
        raise ValueError("evidence reviewer must be independent from the execution initiator")
    obligation = _obligation(analysis, str(execution.get("obligation_id", "")))
    criteria = obligation.get("acceptance_criteria", [])
    if set(criterion_results) != set(range(1, len(criteria) + 1)):
        raise ValueError("evidence review requires exactly one result for every acceptance criterion")
    if any(value not in CRITERION_RESULTS for value in criterion_results.values()):
        raise ValueError("invalid acceptance-criterion result")
    artifacts_valid, artifact_errors = _verify_artifacts(register, execution)
    current_baseline = analysis.get("project", {}).get("baseline", {}).get("id", "")
    stale = execution.get("baseline_id") != current_baseline
    all_pass = all(value == "pass" for value in criterion_results.values())
    if decision == "sufficient" and (
        execution.get("status") != "passed"
        or not stimulus_observed
        or not all_pass
        or stale
        or not artifacts_valid
    ):
        raise ValueError(
            "sufficient evidence requires a passing execution, observed stimulus, all criteria passing, current baseline, and intact artifacts"
        )
    at = utc_now()
    review = {
        "id": stable_id("EVREV", execution_id, reviewer.strip(), at),
        "reviewer": reviewer.strip(),
        "reviewed_at": at,
        "decision": decision,
        "rationale": rationale.strip(),
        "stimulus_observed": stimulus_observed,
        "criterion_results": [
            {"index": index, "text": criteria[index - 1], "result": criterion_results[index]}
            for index in range(1, len(criteria) + 1)
        ],
        "artifact_integrity_valid": artifacts_valid,
        "artifact_integrity_errors": artifact_errors,
        "baseline_current": not stale,
    }
    execution.setdefault("reviews", []).append(review)
    execution["stimulus_observed"] = stimulus_observed
    execution["acceptance_criteria"] = review["criterion_results"]
    status_map = {
        "sufficient": ("sufficient", "verified"),
        "partial": ("partial", "partially_verified"),
        "insufficient": ("insufficient", "test_proposed"),
        "test_did_not_exercise_failure": ("insufficient", "test_proposed"),
        "stale": ("stale", "reopened"),
        "requires_human_review": ("collected_unreviewed", "evidence_collected"),
    }
    obligation["evidence_status"], obligation["assurance_status"] = status_map[decision]
    obligation["review"] = {
        **obligation.get("review", {}),
        "reviewer": reviewer.strip(),
        "reviewed_at": at,
        "rationale": rationale.strip(),
    }
    obligation.setdefault("history", []).append(
        {
            "event": "execution_evidence_reviewed",
            "at": at,
            "execution_id": execution_id,
            "review_id": review["id"],
            "decision": decision,
            "reviewer": reviewer.strip(),
        }
    )
    register["summary"] = assurance_summary(register)
    return review
