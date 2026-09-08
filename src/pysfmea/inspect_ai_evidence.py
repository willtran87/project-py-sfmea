"""Loss-minimizing, exact-byte intake for UK AISI Inspect evaluation logs."""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, publish_json, seal, verify_seal
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now

INSPECT_AI_EVIDENCE_FORMAT = "pysfmea-inspect-ai-evidence-1"
INSPECT_AI_EVIDENCE_VERIFICATION_FORMAT = "pysfmea-inspect-ai-evidence-verification-1"
MAX_BYTES = 500 * 1024 * 1024


def _safe(value: Any, *, depth: int = 0) -> Any:
    if depth > 100:
        return "<depth-limit>"
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, list):
        return [_safe(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe(item, depth=depth + 1) for key, item in value.items()}
    return str(value)


def _hash(value: Any) -> str:
    return canonical_json_sha256(_safe(value))


def _number(value: Any) -> int:
    return (
        int(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        else 0
    )


def _usage(sample: dict[str, Any]) -> dict[str, int]:
    usage = sample.get("model_usage") or sample.get("usage") or {}
    if not isinstance(usage, dict):
        usage = {}
    records = (
        list(usage.values())
        if usage and all(isinstance(v, dict) for v in usage.values())
        else [usage]
    )
    input_tokens = sum(
        _number(item.get("input_tokens", item.get("prompt_tokens", 0)))
        for item in records
        if isinstance(item, dict)
    )
    output_tokens = sum(
        _number(item.get("output_tokens", item.get("completion_tokens", 0)))
        for item in records
        if isinstance(item, dict)
    )
    total_tokens = (
        sum(
            _number(item.get("total_tokens", 0))
            for item in records
            if isinstance(item, dict)
        )
        or input_tokens + output_tokens
    )
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _scores(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ValueError("Inspect sample scores must be an object")
    result = []
    for name in sorted(value):
        score = value[name]
        if isinstance(score, dict):
            result.append(
                {
                    "name": str(name),
                    "value": _safe(score.get("value")),
                    "answer": _safe(score.get("answer")),
                    "explanation": _safe(score.get("explanation")),
                    "metadata_sha256": _hash(score.get("metadata")),
                }
            )
        else:
            result.append(
                {
                    "name": str(name),
                    "value": _safe(score),
                    "answer": None,
                    "explanation": None,
                    "metadata_sha256": _hash(None),
                }
            )
    return result


def _tool_events(sample: dict[str, Any]) -> int:
    count = 0
    for event in (
        sample.get("events", []) if isinstance(sample.get("events"), list) else []
    ):
        if isinstance(event, dict) and str(
            event.get("event", event.get("type", ""))
        ).casefold() in {
            "tool",
            "tool_call",
            "toolcall",
            "tool_event",
        }:
            count += 1
    return count


def import_inspect_ai_log(
    source: str | Path,
    *,
    authority: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Normalize one JSON Inspect log while binding exact bytes and hashing transcripts."""

    document = load_bounded_json_document(
        Path(source).expanduser().resolve(),
        label="Inspect AI JSON log",
        max_bytes=MAX_BYTES,
        max_depth=220,
        max_nodes=8_000_000,
    )
    root = document.value
    if not isinstance(root, dict):
        raise ValueError("Inspect AI log must contain an object")
    eval_record = root.get("eval")
    samples = root.get("samples")
    if not isinstance(eval_record, dict) or not isinstance(samples, list):
        raise ValueError("Inspect AI log requires eval metadata and samples")
    normalized_samples = []
    seen = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError("Inspect AI samples must be objects")
        identifier = sample.get(
            "uuid", sample.get("id", sample.get("sample_id", index))
        )
        sample_id = bounded_text(identifier, "Inspect AI sample id")
        epoch = _number(sample.get("epoch", 1)) or 1
        identity = f"{sample_id}#epoch={epoch}"
        if identity in seen:
            raise ValueError("Inspect AI sample and epoch identities must be unique")
        seen.add(identity)
        usage = _usage(sample)
        error = sample.get("error")
        normalized_samples.append(
            {
                "sample_id": sample_id,
                "epoch": epoch,
                "input_sha256": _hash(sample.get("input")),
                "target_sha256": _hash(sample.get("target")),
                "messages_sha256": _hash(sample.get("messages")),
                "output_sha256": _hash(sample.get("output")),
                "events_sha256": _hash(sample.get("events")),
                "store_sha256": _hash(sample.get("store")),
                "metadata_sha256": _hash(sample.get("metadata")),
                "scores": _scores(sample.get("scores")),
                "tool_events": _tool_events(sample),
                "usage": usage,
                "error": _safe(error),
                "completed": error is None or error == "",
            }
        )
    task = eval_record.get("task", eval_record.get("task_name", "unassigned"))
    model = eval_record.get("model", "unassigned")
    run_id = eval_record.get("run_id", root.get("run_id", "unassigned"))
    eval_id = eval_record.get("eval_id", root.get("eval_id", "unassigned"))
    result = seal(
        {
            "format": INSPECT_AI_EVIDENCE_FORMAT,
            "generated_at": generated_at or utc_now(),
            "authority": bounded_text(authority, "Inspect AI evidence authority"),
            "source": {
                "name": Path(source).name,
                "bytes": document.size,
                "sha256": hashlib.sha256(document.raw).hexdigest(),
                "schema_version": str(root.get("version", "unassigned")),
                "official_schema_command": "inspect log schema",
            },
            "evaluation": {
                "run_id": bounded_text(run_id, "Inspect AI run id"),
                "eval_id": bounded_text(eval_id, "Inspect AI eval id"),
                "task": _safe(task),
                "task_version": _safe(eval_record.get("task_version")),
                "model": _safe(model),
                "status": _safe(root.get("status")),
                "created": _safe(eval_record.get("created", root.get("created"))),
                "completed": _safe(root.get("completed")),
                "sandbox": _safe(eval_record.get("sandbox")),
                "dataset_sha256": _hash(eval_record.get("dataset")),
                "task_args_sha256": _hash(eval_record.get("task_args")),
                "model_args_sha256": _hash(eval_record.get("model_args")),
                "config_sha256": _hash(eval_record.get("config")),
                "plan_sha256": _hash(root.get("plan")),
                "results_sha256": _hash(root.get("results")),
                "stats_sha256": _hash(root.get("stats")),
            },
            "samples": normalized_samples,
            "summary": _summary(normalized_samples),
            "claim_boundary": (
                "This intake preserves exact log identity, execution configuration identities, "
                "sample accounting, scores, tool-event counts, token usage, and transcript hashes. "
                "It does not reinterpret scorer meaning, prove sandbox isolation, validate model "
                "claims, or replace verification against the exact upstream Inspect log schema."
            ),
        }
    )
    if not verify_inspect_ai_evidence(result)["valid"]:
        raise ValueError("Inspect AI evidence failed internal verification")
    return result


def _summary(samples: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "samples": len(samples),
        "completed_samples": sum(item["completed"] for item in samples),
        "error_samples": sum(not item["completed"] for item in samples),
        "scored_samples": sum(bool(item["scores"]) for item in samples),
        "tool_events": sum(item["tool_events"] for item in samples),
        "input_tokens": sum(item["usage"]["input_tokens"] for item in samples),
        "output_tokens": sum(item["usage"]["output_tokens"] for item in samples),
        "total_tokens": sum(item["usage"]["total_tokens"] for item in samples),
    }


def _digest(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _structure(value: dict[str, Any]) -> bool:
    try:
        samples = value["samples"]
        source = value["source"]
        evaluation = value["evaluation"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "source",
                "evaluation",
                "samples",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(source)
            == {"name", "bytes", "sha256", "schema_version", "official_schema_command"}
            and source["bytes"] > 0
            and _digest(source["sha256"])
            and source["official_schema_command"] == "inspect log schema"
            and set(evaluation)
            == {
                "run_id",
                "eval_id",
                "task",
                "task_version",
                "model",
                "status",
                "created",
                "completed",
                "sandbox",
                "dataset_sha256",
                "task_args_sha256",
                "model_args_sha256",
                "config_sha256",
                "plan_sha256",
                "results_sha256",
                "stats_sha256",
            }
            and all(
                _digest(evaluation[name])
                for name in (
                    "dataset_sha256",
                    "task_args_sha256",
                    "model_args_sha256",
                    "config_sha256",
                    "plan_sha256",
                    "results_sha256",
                    "stats_sha256",
                )
            )
            and isinstance(samples, list)
            and bool(samples)
            and len({(item.get("sample_id"), item.get("epoch")) for item in samples})
            == len(samples)
            and all(_sample_structure(item) for item in samples)
            and value["summary"] == _summary(samples)
            and isinstance(value["claim_boundary"], str)
            and bool(value["claim_boundary"])
        )
    except (KeyError, TypeError):
        return False


def _sample_structure(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != {
        "sample_id",
        "epoch",
        "input_sha256",
        "target_sha256",
        "messages_sha256",
        "output_sha256",
        "events_sha256",
        "store_sha256",
        "metadata_sha256",
        "scores",
        "tool_events",
        "usage",
        "error",
        "completed",
    }:
        return False
    return bool(
        isinstance(item["sample_id"], str)
        and bool(item["sample_id"])
        and isinstance(item["epoch"], int)
        and item["epoch"] >= 1
        and all(
            _digest(item[name])
            for name in (
                "input_sha256",
                "target_sha256",
                "messages_sha256",
                "output_sha256",
                "events_sha256",
                "store_sha256",
                "metadata_sha256",
            )
        )
        and isinstance(item["scores"], list)
        and all(
            isinstance(score, dict)
            and set(score)
            == {"name", "value", "answer", "explanation", "metadata_sha256"}
            and _digest(score["metadata_sha256"])
            for score in item["scores"]
        )
        and isinstance(item["tool_events"], int)
        and item["tool_events"] >= 0
        and set(item["usage"]) == {"input_tokens", "output_tokens", "total_tokens"}
        and all(
            isinstance(number, int) and number >= 0 for number in item["usage"].values()
        )
        and isinstance(item["completed"], bool)
    )


def verify_inspect_ai_evidence(
    value: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="Inspect AI evidence", format_value=INSPECT_AI_EVIDENCE_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("Inspect AI evidence structure or accounting is invalid")
    replay: bool | None = None
    if source is not None:
        replay = False
        if structure:
            try:
                replay = (
                    import_inspect_ai_log(
                        source,
                        authority=checked["authority"],
                        generated_at=checked["generated_at"],
                    )
                    == value
                )
            except (OSError, TypeError, ValueError):
                replay = False
        if not replay:
            errors.append("Inspect AI evidence does not exactly replay")
    valid = integrity and structure and replay is not False
    return seal(
        {
            "format": INSPECT_AI_EVIDENCE_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_evaluation_join": valid and replay is True,
            "checks": {
                "content_integrity_and_reconciliation": integrity and structure,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": "Eligibility permits a governed evidence join; it is not a benchmark or model-safety verdict.",
        }
    )


def export_inspect_ai_evidence(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_inspect_ai_evidence(value)["valid"]:
        raise ValueError("Inspect AI evidence is invalid")
    return publish_json(value, destination)


def verify_inspect_ai_evidence_file(
    artifact: str | Path, *, source: str | Path | None = None
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            Path(artifact).expanduser().resolve(),
            label="Inspect AI evidence",
            max_bytes=MAX_BYTES,
            max_depth=220,
            max_nodes=8_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("Inspect AI evidence must contain an object")
        return verify_inspect_ai_evidence(document.value, source=source)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": INSPECT_AI_EVIDENCE_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_evaluation_join": False,
                "checks": {
                    "content_integrity_and_reconciliation": False,
                    "exact_source_replay": False,
                },
                "errors": [str(exc)],
                "notice": "Inspect AI evidence verification failed closed.",
            }
        )
