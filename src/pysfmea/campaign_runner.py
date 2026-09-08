"""Shell-free, network-denied execution for governed benchmark and fuzz campaigns."""

from __future__ import annotations

import copy
import hashlib
import math
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .benchmark_adapter import verify_benchmark_adapter
from .benchmark_observations import verify_benchmark_observations
from .file_publication import atomic_publish_text
from .fuzz_campaign import verify_fuzz_campaign
from .governed_artifact import load_json, publish_json, seal
from .industry_benchmarks import verify_benchmark_execution
from .json_ingestion import load_bounded_file_snapshot
from .model import utc_now
from .sandbox_policy import resolve_sandbox_engine, sandbox_command

MAX_SNAPSHOT_FILES = 1_000_000
MAX_SNAPSHOT_BYTES = 20_000_000_000
MAX_CAPTURE_CHARS = 2_000_000
MAX_EVIDENCE_ARTIFACT_BYTES = 256 * 1024 * 1024


def repository_snapshot_sha256(root: str | Path) -> str:
    """Hash a regular, non-symbolic-link directory tree including relative names."""

    repository = Path(root).expanduser().resolve()
    if not repository.is_dir() or repository.is_symlink():
        raise ValueError("campaign source must be a regular directory")
    paths = sorted(
        (
            path
            for path in repository.rglob("*")
            if ".git" not in path.relative_to(repository).parts and path.is_file()
        ),
        key=lambda path: path.relative_to(repository).as_posix(),
    )
    if len(paths) > MAX_SNAPSHOT_FILES:
        raise ValueError("campaign source exceeds the file-count limit")
    digest = hashlib.sha256()
    consumed = 0
    for path in paths:
        if path.is_symlink():
            raise ValueError("campaign source must not contain symbolic-link files")
        relative = path.relative_to(repository).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > MAX_SNAPSHOT_BYTES:
                    raise ValueError("campaign source exceeds the byte limit")
                digest.update(chunk)
    return digest.hexdigest()


def _evidence_directory(value: str | Path) -> Path:
    supplied = Path(value).expanduser()
    if supplied.is_symlink():
        raise ValueError("campaign evidence destination must not be a symbolic link")
    destination = supplied.resolve()
    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise ValueError("campaign evidence destination must be a regular directory")
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _require_fresh_evidence_files(evidence: Path, *names: str) -> None:
    if any(
        (evidence / name).exists() or (evidence / name).is_symlink() for name in names
    ):
        raise ValueError("campaign evidence destination contains prior run outputs")


def _digest(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value)
        and value != "0" * 64
    )


def _governance_complete(authority: Any, roles: tuple[str, ...]) -> bool:
    if not isinstance(authority, dict):
        return False
    values = [authority.get(role) for role in roles]
    return bool(
        all(
            isinstance(value, str) and value.strip() and value != "unassigned"
            for value in values
        )
        and len(set(values)) == len(values)
        and isinstance(authority.get("independence_basis"), str)
        and authority["independence_basis"] != "unassigned"
    )


def _run_container(
    *,
    source: Path,
    evidence: Path,
    image: str,
    command: list[str],
    cpus: float,
    memory_mb: int,
    timeout_seconds: int,
    engine: str,
    label: str,
) -> tuple[int, str, str, str, str, str]:
    engine_path = resolve_sandbox_engine(engine)
    container_name = f"pysfmea-{label}-{uuid.uuid4().hex[:12]}"
    argv = sandbox_command(
        engine_path=engine_path,
        container_name=container_name,
        repository=source,
        evidence_directory=evidence,
        image=image,
        command_argv=command,
        cpus=cpus,
        memory_mb=memory_mb,
        pids_limit=256,
    )
    started = utc_now()
    try:
        process = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
        )
        return (
            process.returncode,
            process.stdout[-MAX_CAPTURE_CHARS:],
            process.stderr[-MAX_CAPTURE_CHARS:],
            started,
            utc_now(),
            Path(engine_path).name,
        )
    except subprocess.TimeoutExpired as exc:
        subprocess.run(
            [engine_path, "rm", "-f", container_name],
            check=False,
            capture_output=True,
            timeout=30,
        )
        stdout = (
            exc.stdout.decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else exc.stdout or ""
        )[-MAX_CAPTURE_CHARS:]
        stderr = (
            exc.stderr.decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else exc.stderr or ""
        )[-MAX_CAPTURE_CHARS:]
        return (
            124,
            stdout,
            stderr + "\nCampaign timed out.",
            started,
            utc_now(),
            Path(engine_path).name,
        )


def _write_logs(evidence: Path, stdout: str, stderr: str) -> tuple[Path, Path]:
    stdout_path = evidence / "stdout.txt"
    stderr_path = evidence / "stderr.txt"
    atomic_publish_text(stdout_path, stdout)
    atomic_publish_text(stderr_path, stderr)
    return stdout_path, stderr_path


def _evidence_ref(path: Path, *, base: Path | None = None) -> str:
    snapshot = load_bounded_file_snapshot(
        path,
        label="campaign evidence artifact",
        max_bytes=MAX_EVIDENCE_ARTIFACT_BYTES,
    )
    relative = path.name
    if base is not None:
        try:
            relative = path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError(
                "campaign evidence artifact escapes its evidence root"
            ) from exc
    return f"sha256:{hashlib.sha256(snapshot.raw).hexdigest()}:{relative}"


def _bound_evidence_artifact(
    evidence: Path, relative: Any, sha256: Any, size: Any
) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or not _digest(sha256)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_EVIDENCE_ARTIFACT_BYTES
    ):
        raise ValueError("campaign evidence artifact binding is invalid")
    path = (evidence / relative).resolve()
    try:
        path.relative_to(evidence)
    except ValueError as exc:
        raise ValueError(
            "campaign evidence artifact escapes the evidence directory"
        ) from exc
    snapshot = load_bounded_file_snapshot(
        path,
        label="campaign evidence artifact",
        max_bytes=MAX_EVIDENCE_ARTIFACT_BYTES,
    )
    if len(snapshot.raw) != size or hashlib.sha256(snapshot.raw).hexdigest() != sha256:
        raise ValueError("campaign evidence artifact byte binding does not match")
    return path


def _artifact_from_ref(
    evidence: Path, reference: Any, *, expected_sha256: str | None = None
) -> Path:
    if not isinstance(reference, str):
        raise ValueError("campaign evidence reference must be text")
    prefix, separator, remainder = reference.partition(":")
    claimed, second_separator, relative = remainder.partition(":")
    if (
        prefix != "sha256"
        or not separator
        or not second_separator
        or not _digest(claimed)
        or (expected_sha256 is not None and claimed != expected_sha256)
    ):
        raise ValueError("campaign evidence reference is not a valid SHA-256 binding")
    path = (evidence / relative).resolve()
    try:
        path.relative_to(evidence)
    except ValueError as exc:
        raise ValueError(
            "campaign evidence reference escapes the evidence directory"
        ) from exc
    snapshot = load_bounded_file_snapshot(
        path,
        label="campaign evidence reference",
        max_bytes=MAX_EVIDENCE_ARTIFACT_BYTES,
    )
    if hashlib.sha256(snapshot.raw).hexdigest() != claimed:
        raise ValueError("campaign evidence reference digest does not match")
    return path


def run_benchmark_campaign(
    receipt_source: str | Path,
    suite_source: str | Path,
    adapter_source: str | Path,
    evidence_directory: str | Path,
    destination: str | Path,
    *,
    engine: str = "auto",
) -> Path:
    """Execute a configured benchmark contract and bind normalized observations."""

    receipt = load_json(receipt_source, label="benchmark execution")
    verdict = verify_benchmark_execution(receipt)
    if not verdict["valid"]:
        raise ValueError("benchmark execution contract is internally invalid")
    adapter = load_json(adapter_source, label="benchmark adapter")
    adapter_verdict = verify_benchmark_adapter(adapter)
    if not adapter_verdict["eligible_for_execution"]:
        raise ValueError("benchmark adapter is not eligible for execution")
    adapter_path = Path(adapter_source).expanduser().resolve()
    if not adapter_path.is_file() or adapter_path.is_symlink():
        raise ValueError("benchmark adapter must be a regular non-link file")
    if (
        receipt["adapter"]["manifest_sha256"] != adapter["content_sha256"]
        or receipt["adapter"]["evidence_ref"] != _evidence_ref(adapter_path)
        or adapter["suite"]
        != {
            "id": receipt["suite"]["id"],
            "revision": receipt["suite"]["revision"],
            "snapshot_sha256": receipt["suite"]["snapshot_sha256"],
            "license_evidence_ref": receipt["suite"]["license_evidence_ref"],
        }
        or adapter["adapter"]["image"] != receipt["execution"]["image"]
        or adapter["adapter"]["command"] != receipt["execution"]["command"]
    ):
        raise ValueError("benchmark execution does not bind the exact reviewed adapter")
    suite = Path(suite_source).expanduser().resolve()
    actual_snapshot = repository_snapshot_sha256(suite)
    if actual_snapshot != receipt["suite"]["snapshot_sha256"]:
        raise ValueError(
            "benchmark suite snapshot does not match the configured SHA-256"
        )
    execution = receipt["execution"]
    if not (
        re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", execution["image"])
        and execution["command"]
        and 1 <= execution["timeout_seconds"] <= 86_400
        and 0.1 <= execution["cpu_limit"] <= 8
        and 128 <= execution["memory_mb"] <= 32_768
    ):
        raise ValueError(
            "benchmark execution image, command, or resource policy is incomplete"
        )
    if not (
        receipt["suite"]["revision"] != "unassigned"
        and receipt["suite"]["license_evidence_ref"] != "unassigned"
        and _governance_complete(
            receipt["authority"],
            (
                "protocol_owner",
                "execution_operator",
                "label_authority",
                "approval_authority",
            ),
        )
    ):
        raise ValueError(
            "benchmark suite provenance or independent governance is incomplete"
        )
    evidence = _evidence_directory(evidence_directory)
    _require_fresh_evidence_files(
        evidence, "benchmark-observations.json", "stdout.txt", "stderr.txt"
    )
    result_path = evidence / "benchmark-observations.json"
    code, stdout, stderr, started, completed, runner = _run_container(
        source=suite,
        evidence=evidence,
        image=execution["image"],
        command=execution["command"],
        cpus=float(execution["cpu_limit"]),
        memory_mb=int(execution["memory_mb"]),
        timeout_seconds=int(execution["timeout_seconds"]),
        engine=engine,
        label="benchmark",
    )
    stdout_path, stderr_path = _write_logs(evidence, stdout, stderr)
    if repository_snapshot_sha256(suite) != actual_snapshot:
        raise ValueError("benchmark suite changed during execution")
    completed_receipt = copy.deepcopy(receipt)
    completed_receipt["execution"].update(
        {
            "runner": runner,
            "started_at": started,
            "completed_at": completed,
            "exit_code": code,
        }
    )
    outcome = completed_receipt["outcome"]
    if code == 0 and result_path.is_file() and not result_path.is_symlink():
        observations = load_json(result_path, label="benchmark observations")
        observation_verdict = verify_benchmark_observations(observations)
        exact = bool(
            observation_verdict["valid"]
            and observations["suite"]
            == {
                "id": receipt["suite"]["id"],
                "revision": receipt["suite"]["revision"],
                "snapshot_sha256": receipt["suite"]["snapshot_sha256"],
            }
            and observations["runner"]
            == {"image": execution["image"], "command": execution["command"]}
            and observations["authority"] == receipt["authority"]["label_authority"]
        )
        if not exact:
            raise ValueError(
                "benchmark observations do not bind the exact configured suite and runner"
            )
        observation_paths: list[Path] = []
        for case in observations["cases"]:
            observation_paths.append(
                _artifact_from_ref(
                    evidence,
                    case["input_evidence_ref"],
                    expected_sha256=case["input_sha256"],
                )
            )
            observation_paths.append(
                _artifact_from_ref(
                    evidence,
                    case["ground_truth_evidence_ref"],
                    expected_sha256=case["ground_truth_sha256"],
                )
            )
            for attempt in case["attempts"]:
                for digest_field, reference_field in (
                    ("output_sha256", "output_evidence_ref"),
                    ("test_artifact_sha256", "test_artifact_evidence_ref"),
                    ("environment_sha256", "environment_evidence_ref"),
                ):
                    observation_paths.append(
                        _artifact_from_ref(
                            evidence,
                            attempt[reference_field],
                            expected_sha256=attempt[digest_field],
                        )
                    )
                for reference_field in (
                    "execution_evidence_ref",
                    "coverage_evidence_ref",
                    "mutation_evidence_ref",
                ):
                    observation_paths.append(
                        _artifact_from_ref(evidence, attempt[reference_field])
                    )
        summary = observations["summary"]
        outcome.update(
            {
                "status": "completed",
                "cases_total": summary["cases"],
                "cases_completed": summary["cases"],
                "metrics": {
                    key: value
                    for key, value in summary.items()
                    if isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and value is not None
                },
                "failures": [
                    case["id"]
                    for case in observations["cases"]
                    if not case["attempts"][0]["passed"]
                ],
                "excluded_cases": [],
            }
        )
        refs = list(
            dict.fromkeys([result_path, *observation_paths, stdout_path, stderr_path])
        )
    else:
        outcome.update(
            {
                "status": "failed" if code != 124 else "aborted",
                "cases_total": 0,
                "cases_completed": 0,
                "metrics": {},
                "failures": ["runner_exit_nonzero_or_result_missing"],
                "excluded_cases": [],
            }
        )
        refs = [stdout_path, stderr_path]
    completed_receipt["evidence_refs"] = [
        _evidence_ref(path, base=evidence) for path in refs
    ]
    completed_receipt = seal(completed_receipt)
    return publish_json(completed_receipt, destination)


def _valid_fuzz_result(value: Any) -> bool:
    try:
        return bool(
            isinstance(value, dict)
            and set(value)
            == {
                "executions",
                "execs_per_second",
                "coverage_observation",
                "corpus",
                "crashes",
            }
            and isinstance(value["executions"], int)
            and value["executions"] > 0
            and isinstance(value["execs_per_second"], (int, float))
            and not isinstance(value["execs_per_second"], bool)
            and math.isfinite(float(value["execs_per_second"]))
            and value["execs_per_second"] > 0
            and isinstance(value["coverage_observation"], dict)
            and set(value["coverage_observation"]) == {"path", "sha256", "bytes"}
            and isinstance(value["coverage_observation"]["path"], str)
            and bool(value["coverage_observation"]["path"])
            and _digest(value["coverage_observation"]["sha256"])
            and isinstance(value["coverage_observation"]["bytes"], int)
            and value["coverage_observation"]["bytes"] > 0
            and isinstance(value["corpus"], dict)
            and set(value["corpus"])
            == {"initial_sha256", "final_sha256", "initial_inputs", "final_inputs"}
            and all(
                _digest(value["corpus"][name])
                for name in ("initial_sha256", "final_sha256")
            )
            and all(
                isinstance(value["corpus"][name], int) and value["corpus"][name] >= 0
                for name in ("initial_inputs", "final_inputs")
            )
            and value["corpus"]["final_inputs"] >= value["corpus"]["initial_inputs"]
            and isinstance(value["crashes"], list)
            and len(value["crashes"]) <= 100_000
            and all(
                isinstance(item, dict)
                and set(item)
                == {
                    "id",
                    "input_sha256",
                    "input_path",
                    "input_bytes",
                    "stack_sha256",
                    "stack_path",
                    "stack_bytes",
                    "reproducer_sha256",
                    "reproducer_path",
                    "reproducer_bytes",
                    "reproduced",
                    "disposition",
                    "finding_ref",
                    "fixed_in_revision",
                }
                and isinstance(item["id"], str)
                and bool(item["id"])
                and _digest(item["input_sha256"])
                and isinstance(item["input_path"], str)
                and bool(item["input_path"])
                and isinstance(item["input_bytes"], int)
                and item["input_bytes"] > 0
                and _digest(item["stack_sha256"])
                and isinstance(item["stack_path"], str)
                and bool(item["stack_path"])
                and isinstance(item["stack_bytes"], int)
                and item["stack_bytes"] > 0
                and _digest(item["reproducer_sha256"])
                and isinstance(item["reproducer_path"], str)
                and bool(item["reproducer_path"])
                and isinstance(item["reproducer_bytes"], int)
                and item["reproducer_bytes"] > 0
                and isinstance(item["reproduced"], bool)
                and item["disposition"]
                in {"open", "fixed", "accepted", "not_reproducible", "duplicate"}
                and isinstance(item["finding_ref"], str)
                and bool(item["finding_ref"].strip())
                and item["finding_ref"] != "unassigned"
                and isinstance(item["fixed_in_revision"], str)
                and (
                    item["disposition"] != "fixed"
                    or bool(item["fixed_in_revision"].strip())
                    and item["fixed_in_revision"] != "unassigned"
                )
                for item in value["crashes"]
            )
            and len({item["id"] for item in value["crashes"]}) == len(value["crashes"])
        )
    except (KeyError, TypeError):
        return False


def run_fuzz_campaign(
    campaign_source: str | Path,
    repository_source: str | Path,
    evidence_directory: str | Path,
    destination: str | Path,
    *,
    engine: str = "auto",
) -> Path:
    """Execute a configured fuzz campaign and bind corpus, coverage, and crash evidence."""

    campaign = load_json(campaign_source, label="fuzz campaign")
    if not verify_fuzz_campaign(campaign)["valid"]:
        raise ValueError("fuzz campaign contract is internally invalid")
    repository = Path(repository_source).expanduser().resolve()
    if (
        repository_snapshot_sha256(repository)
        != campaign["target"]["repository_sha256"]
    ):
        raise ValueError("fuzz target snapshot does not match the configured SHA-256")
    configuration = campaign["engine"]
    isolation = campaign["isolation"]
    if not (
        re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", configuration["image"])
        and configuration["command"]
        and 1 <= isolation["timeout_seconds"] <= 86_400
        and 0.1 <= isolation["cpu_limit"] <= 8
        and 128 <= isolation["memory_mb"] <= 32_768
    ):
        raise ValueError("fuzz image, command, or resource policy is incomplete")
    if not (
        campaign["target"]["repository_revision"] != "unassigned"
        and campaign["target"]["entrypoint"] != "unassigned"
        and configuration["version"] != "unassigned"
        and _digest(configuration["configuration_sha256"])
        and _digest(campaign["corpus"]["initial_sha256"])
        and _governance_complete(
            campaign["authority"],
            (
                "campaign_owner",
                "execution_operator",
                "triage_authority",
                "approval_authority",
            ),
        )
    ):
        raise ValueError(
            "fuzz target, configuration, corpus, or independent governance is incomplete"
        )
    evidence = _evidence_directory(evidence_directory)
    _require_fresh_evidence_files(
        evidence, "fuzz-result.json", "stdout.txt", "stderr.txt"
    )
    result_path = evidence / "fuzz-result.json"
    code, stdout, stderr, started, completed, _runner = _run_container(
        source=repository,
        evidence=evidence,
        image=configuration["image"],
        command=configuration["command"],
        cpus=float(isolation["cpu_limit"]),
        memory_mb=int(isolation["memory_mb"]),
        timeout_seconds=int(isolation["timeout_seconds"]),
        engine=engine,
        label="fuzz",
    )
    stdout_path, stderr_path = _write_logs(evidence, stdout, stderr)
    if (
        repository_snapshot_sha256(repository)
        != campaign["target"]["repository_sha256"]
    ):
        raise ValueError("fuzz target changed during execution")
    completed_campaign = copy.deepcopy(campaign)
    completed_campaign["execution"].update(
        {
            "status": "aborted" if code == 124 else "failed" if code else "completed",
            "started_at": started,
            "completed_at": completed,
            "exit_code": code,
        }
    )
    refs = [stdout_path, stderr_path]
    if code == 0 and result_path.is_file() and not result_path.is_symlink():
        result = load_json(result_path, label="fuzz result")
        if not _valid_fuzz_result(result):
            raise ValueError("fuzz result fields are invalid")
        if (
            result["corpus"]["initial_sha256"] != campaign["corpus"]["initial_sha256"]
            or result["corpus"]["initial_inputs"]
            != campaign["corpus"]["initial_inputs"]
        ):
            raise ValueError("fuzz result does not bind the configured initial corpus")
        coverage = result["coverage_observation"]
        coverage_path = _bound_evidence_artifact(
            evidence, coverage["path"], coverage["sha256"], coverage["bytes"]
        )
        bound_crashes: list[dict[str, Any]] = []
        crash_paths: list[Path] = []
        for crash in result["crashes"]:
            input_path = _bound_evidence_artifact(
                evidence,
                crash["input_path"],
                crash["input_sha256"],
                crash["input_bytes"],
            )
            stack_path = _bound_evidence_artifact(
                evidence,
                crash["stack_path"],
                crash["stack_sha256"],
                crash["stack_bytes"],
            )
            reproducer_path = _bound_evidence_artifact(
                evidence,
                crash["reproducer_path"],
                crash["reproducer_sha256"],
                crash["reproducer_bytes"],
            )
            crash_paths.extend((input_path, stack_path, reproducer_path))
            bound_crashes.append(
                {
                    "id": crash["id"],
                    "input_sha256": crash["input_sha256"],
                    "input_ref": _evidence_ref(input_path, base=evidence),
                    "stack_sha256": crash["stack_sha256"],
                    "stack_ref": _evidence_ref(stack_path, base=evidence),
                    "reproducer_sha256": crash["reproducer_sha256"],
                    "reproducer_ref": _evidence_ref(reproducer_path, base=evidence),
                    "reproduced": crash["reproduced"],
                    "disposition": crash["disposition"],
                    "finding_ref": crash["finding_ref"],
                    "fixed_in_revision": crash["fixed_in_revision"],
                }
            )
        completed_campaign["execution"].update(
            {
                "executions": result["executions"],
                "execs_per_second": result["execs_per_second"],
                "coverage_observation": {
                    "ref": _evidence_ref(coverage_path, base=evidence),
                    "sha256": coverage["sha256"],
                    "bytes": coverage["bytes"],
                },
            }
        )
        completed_campaign["corpus"].update(result["corpus"])
        completed_campaign["crashes"] = bound_crashes
        refs = [result_path, coverage_path, *crash_paths, stdout_path, stderr_path]
    completed_campaign["evidence_refs"] = [
        _evidence_ref(path, base=evidence) for path in refs
    ]
    completed_campaign = seal(completed_campaign)
    return publish_json(completed_campaign, destination)
