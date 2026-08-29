"""Fail-closed SARIF 2.1.0 intake and exact analysis fusion.

The importer preserves every producer result, binds the original bytes, and
only creates deterministic clusters from exact coordinates and taxonomies.
It intentionally does not infer that two semantically similar messages are
the same defect.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from .governed_artifact import (
    analysis_binding,
    bounded_text,
    publish_json,
    seal,
    unique_text_list,
    verify_analysis_binding,
    verify_seal,
)
from .json_ingestion import load_bounded_json_document
from .model import utc_now

SARIF_FUSION_FORMAT = "pysfmea-sarif-fusion-1"
SARIF_FUSION_VERIFICATION_FORMAT = "pysfmea-sarif-fusion-verification-1"
MAX_SARIF_BYTES = 100 * 1024 * 1024
MAX_RUNS = 1_000
MAX_RESULTS = 1_000_000


def _path(value: Any) -> str:
    text = bounded_text(value, "SARIF artifact URI").replace("\\", "/")
    parsed = urlparse(text)
    if parsed.scheme and parsed.scheme != "file":
        raise ValueError("SARIF artifact URI must be a relative path or file URI")
    text = unquote(parsed.path if parsed.scheme else text)
    drive = re.match(r"^/?[A-Za-z]:/(.*)$", text)
    if drive:
        text = drive.group(1)
    while text.startswith("./") or text.startswith("/"):
        text = text[2:] if text.startswith("./") else text[1:]
    parts = [part for part in PurePosixPath(text).parts if part not in {"", ".", "/"}]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("SARIF artifact URI is empty or contains parent traversal")
    return "/".join(parts)


def _source_index(analysis: dict[str, Any]) -> list[tuple[str, int, int, str]]:
    result: list[tuple[str, int, int, str]] = []
    for component in analysis.get("components", []):
        if not isinstance(component, dict) or not isinstance(component.get("source"), dict):
            continue
        source = component["source"]
        try:
            path = _path(source.get("path"))
            line = int(source.get("line", 0))
            end = int(source.get("end_line", line))
            identifier = bounded_text(component.get("id"), "analysis component id")
        except (TypeError, ValueError):
            continue
        if line > 0 and end >= line:
            result.append((path, line, end, identifier))
    return result


def _matching_component(
    index: list[tuple[str, int, int, str]], path: str, line: int
) -> tuple[str | None, str]:
    candidates = [
        item
        for item in index
        if (item[0] == path or item[0].endswith("/" + path) or path.endswith("/" + item[0]))
        and item[1] <= line <= item[2]
    ]
    if not candidates:
        return None, "unmapped"
    candidates.sort(key=lambda item: (item[2] - item[1], item[3]))
    narrowest = candidates[0][2] - candidates[0][1]
    best = [item for item in candidates if item[2] - item[1] == narrowest]
    if len(best) != 1:
        return None, "ambiguous"
    return best[0][3], "mapped"


def _message(result: dict[str, Any]) -> str:
    message = result.get("message")
    if not isinstance(message, dict):
        raise ValueError("SARIF result message must be an object")
    return bounded_text(message.get("text") or message.get("markdown"), "SARIF result message")


def _taxa(result: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for taxon in result.get("taxa", []):
        if isinstance(taxon, dict) and taxon.get("id"):
            values.add(bounded_text(taxon["id"], "SARIF taxonomy id"))
    props = result.get("properties", {})
    if isinstance(props, dict):
        for key in ("cwe", "tags"):
            raw = props.get(key, [])
            if isinstance(raw, str):
                raw = [raw]
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, str) and (key != "tags" or "cwe" in item.lower()):
                        values.add(bounded_text(item, "SARIF taxonomy value"))
    return sorted(values)


def _normalize_result(
    result: Any,
    *,
    tool: str,
    source_index: int,
    run_index: int,
    result_index: int,
    index: list[tuple[str, int, int, str]],
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ValueError("SARIF result must be an object")
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        raise ValueError("SARIF result must have a primary physical location")
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict) or not isinstance(physical.get("artifactLocation"), dict):
        raise ValueError("SARIF primary location must identify an artifact")
    path = _path(physical["artifactLocation"].get("uri"))
    region = physical.get("region", {})
    if not isinstance(region, dict):
        raise ValueError("SARIF region must be an object")
    line = region.get("startLine", 1)
    end_line = region.get("endLine", line)
    column = region.get("startColumn", 1)
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in (line, end_line, column)) or end_line < line:
        raise ValueError("SARIF result coordinates are invalid")
    component_id, mapping = _matching_component(index, path, line)
    fingerprints = result.get("partialFingerprints", {})
    if not isinstance(fingerprints, dict):
        fingerprints = {}
    clean_fingerprints = {
        bounded_text(k, "SARIF fingerprint name"): bounded_text(v, "SARIF fingerprint value")
        for k, v in sorted(fingerprints.items())
        if isinstance(k, str) and isinstance(v, str)
    }
    rule_id = bounded_text(result.get("ruleId", "unidentified-rule"), "SARIF rule id")
    stable = f"{tool}\0{source_index}\0{run_index}\0{result_index}\0{path}\0{line}\0{column}\0{rule_id}"
    return {
        "id": "sarif-" + hashlib.sha256(stable.encode()).hexdigest()[:20],
        "tool": tool,
        "source_index": source_index,
        "run_index": run_index,
        "result_index": result_index,
        "rule_id": rule_id,
        "level": bounded_text(result.get("level", "warning"), "SARIF result level"),
        "message": _message(result),
        "location": {"path": path, "start_line": line, "end_line": end_line, "start_column": column},
        "taxa": _taxa(result),
        "fingerprints": clean_fingerprints,
        "component_id": component_id,
        "mapping": mapping,
    }


def sarif_fusion(
    analysis: dict[str, Any],
    sarif_sources: list[str | Path],
    *,
    authority: str,
    evidence_refs: list[str],
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Import bounded SARIF 2.1.0 files and map exact locations to components."""

    if not sarif_sources or len(sarif_sources) > 1_000:
        raise ValueError("one to 1,000 SARIF sources are required")
    refs = unique_text_list(evidence_refs, "SARIF evidence refs")
    if not refs:
        raise ValueError("SARIF evidence refs must not be empty")
    source_index = _source_index(analysis)
    inputs: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    total_runs = 0
    for source_number, source in enumerate(sarif_sources):
        document = load_bounded_json_document(source, label="SARIF", max_bytes=MAX_SARIF_BYTES, max_depth=100, max_nodes=8_000_000)
        raw = document.value
        if not isinstance(raw, dict) or raw.get("version") != "2.1.0" or not isinstance(raw.get("runs"), list):
            raise ValueError("SARIF must be a version 2.1.0 document with runs")
        total_runs += len(raw["runs"])
        if total_runs > MAX_RUNS:
            raise ValueError("SARIF run population exceeds the limit")
        inputs.append({"reference": document.path.name, "bytes": document.size, "sha256": hashlib.sha256(document.raw).hexdigest()})
        for local_run, run in enumerate(raw["runs"]):
            if not isinstance(run, dict) or not isinstance(run.get("tool"), dict) or not isinstance(run["tool"].get("driver"), dict):
                raise ValueError("SARIF run tool driver is missing")
            driver = run["tool"]["driver"]
            tool = bounded_text(driver.get("name"), "SARIF tool name")
            version = bounded_text(driver.get("semanticVersion") or driver.get("version") or "unknown", "SARIF tool version")
            results = run.get("results", [])
            if not isinstance(results, list) or len(normalized) + len(results) > MAX_RESULTS:
                raise ValueError("SARIF result population exceeds the limit")
            tools.append({"source_index": source_number, "run_index": local_run, "name": tool, "version": version, "results": len(results)})
            normalized.extend(
                _normalize_result(item, tool=tool, source_index=source_number, run_index=local_run, result_index=i, index=source_index)
                for i, item in enumerate(results)
            )
    # A cluster is an accounting projection, not deduplication. Every result remains above.
    groups: dict[tuple[Any, ...], list[str]] = {}
    for item in normalized:
        loc = item["location"]
        taxonomy = tuple(item["taxa"]) or (item["rule_id"],)
        key = (loc["path"], loc["start_line"], loc["start_column"], taxonomy)
        groups.setdefault(key, []).append(item["id"])
    clusters = [
        {"id": "cluster-" + hashlib.sha256(repr(key).encode()).hexdigest()[:20], "result_ids": sorted(ids), "multi_tool": len({next(r["tool"] for r in normalized if r["id"] == rid) for rid in ids}) > 1}
        for key, ids in sorted(groups.items(), key=lambda item: repr(item[0]))
    ]
    mapped = sum(item["mapping"] == "mapped" for item in normalized)
    ambiguous = sum(item["mapping"] == "ambiguous" for item in normalized)
    result = {
        "format": SARIF_FUSION_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": bounded_text(authority, "SARIF intake authority"),
        "analysis_binding": analysis_binding(analysis),
        "inputs": inputs,
        "tools": tools,
        "results": normalized,
        "clusters": clusters,
        "summary": {
            "inputs": len(inputs), "runs": len(tools), "tools": len({item["name"] for item in tools}),
            "results": len(normalized), "mapped": mapped, "ambiguous": ambiguous,
            "unmapped": len(normalized) - mapped - ambiguous, "clusters": len(clusters),
            "multi_tool_clusters": sum(1 for item in clusters if item["multi_tool"] is True),
        },
        "evidence_refs": refs,
        "claim_boundary": "This artifact proves bounded SARIF intake, exact-byte provenance, deterministic location mapping, and conservative clustering. It does not prove tool correctness, finding validity, semantic equivalence, completeness, or certification.",
    }
    return seal(result)


def _semantics(value: dict[str, Any]) -> bool:
    try:
        results = value["results"]
        inputs = value["inputs"]
        tools = value["tools"]
        if any(
            not isinstance(item, dict)
            or set(item) != {"reference", "bytes", "sha256"}
            or not isinstance(item["bytes"], int)
            or isinstance(item["bytes"], bool)
            or item["bytes"] < 1
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            for item in inputs
        ):
            return False
        if any(
            not isinstance(item, dict)
            or set(item) != {"source_index", "run_index", "name", "version", "results"}
            or not isinstance(item["source_index"], int)
            or not 0 <= item["source_index"] < len(inputs)
            or not isinstance(item["run_index"], int)
            or item["run_index"] < 0
            or not isinstance(item["results"], int)
            or item["results"] < 0
            for item in tools
        ):
            return False
        ids = [item["id"] for item in results]
        if len(ids) != len(set(ids)):
            return False
        run_counts: dict[tuple[int, int, str], int] = {}
        expected_groups: dict[tuple[Any, ...], list[str]] = {}
        for item in results:
            if not isinstance(item, dict) or set(item) != {
                "id", "tool", "source_index", "run_index", "result_index",
                "rule_id", "level", "message", "location", "taxa",
                "fingerprints", "component_id", "mapping",
            } or item["mapping"] not in {"mapped", "ambiguous", "unmapped"}:
                return False
            source_index = item["source_index"]
            run_index = item["run_index"]
            result_index = item["result_index"]
            if any(not isinstance(number, int) or number < 0 for number in (source_index, run_index, result_index)):
                return False
            tool_key = (source_index, run_index, item["tool"])
            if tool_key not in {(tool["source_index"], tool["run_index"], tool["name"]) for tool in tools}:
                return False
            run_counts[tool_key] = run_counts.get(tool_key, 0) + 1
            location = item["location"]
            if not isinstance(location, dict) or set(location) != {"path", "start_line", "end_line", "start_column"}:
                return False
            path = _path(location["path"])
            line, end_line, column = location["start_line"], location["end_line"], location["start_column"]
            if any(not isinstance(number, int) or number < 1 for number in (line, end_line, column)) or end_line < line:
                return False
            stable = f"{item['tool']}\0{source_index}\0{run_index}\0{result_index}\0{path}\0{line}\0{column}\0{item['rule_id']}"
            if item["id"] != "sarif-" + hashlib.sha256(stable.encode()).hexdigest()[:20]:
                return False
            if not isinstance(item["taxa"], list) or len(item["taxa"]) != len(set(item["taxa"])) or not isinstance(item["fingerprints"], dict):
                return False
            if item["mapping"] == "mapped" and not isinstance(item["component_id"], str):
                return False
            if item["mapping"] != "mapped" and item["component_id"] is not None:
                return False
            taxonomy = tuple(item["taxa"]) or (item["rule_id"],)
            expected_groups.setdefault((path, line, column, taxonomy), []).append(item["id"])
        if any(run_counts.get((tool["source_index"], tool["run_index"], tool["name"]), 0) != tool["results"] for tool in tools):
            return False
        cluster_ids = [rid for cluster in value["clusters"] for rid in cluster["result_ids"]]
        if sorted(cluster_ids) != sorted(ids):
            return False
        expected_clusters = [
            {
                "id": "cluster-" + hashlib.sha256(repr(key).encode()).hexdigest()[:20],
                "result_ids": sorted(group_ids),
                "multi_tool": len({next(result["tool"] for result in results if result["id"] == result_id) for result_id in group_ids}) > 1,
            }
            for key, group_ids in sorted(expected_groups.items(), key=lambda group: repr(group[0]))
        ]
        if value["clusters"] != expected_clusters:
            return False
        mapped = sum(item["mapping"] == "mapped" for item in results)
        ambiguous = sum(item["mapping"] == "ambiguous" for item in results)
        summary = value["summary"]
        return bool(summary == {
            "inputs": len(inputs), "runs": len(tools),
            "tools": len({item["name"] for item in tools}), "results": len(results),
            "mapped": mapped, "ambiguous": ambiguous, "unmapped": len(results) - mapped - ambiguous,
            "clusters": len(value["clusters"]), "multi_tool_clusters": sum(1 for item in value["clusters"] if item["multi_tool"] is True),
        })
    except (KeyError, TypeError):
        return False


def verify_sarif_fusion(
    value: dict[str, Any], *, analysis: dict[str, Any] | None = None,
    sarif_sources: list[str | Path] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = {"format", "generated_at", "authority", "analysis_binding", "inputs", "tools", "results", "clusters", "summary", "evidence_refs", "claim_boundary", "content_sha256"}
    structure = isinstance(value, dict) and set(value) == required
    if not structure:
        errors.append("SARIF fusion fields are invalid")
    try:
        checked = verify_seal(value, label="SARIF fusion", format_value=SARIF_FUSION_FORMAT)
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    semantic = bool(structure and _semantics(checked))
    if not semantic:
        errors.append("SARIF fusion accounting does not reconcile")
    binding: bool | None = None
    if analysis is not None:
        try:
            verify_analysis_binding(checked.get("analysis_binding"), analysis)
            binding = True
        except ValueError as exc:
            binding = False
            errors.append(str(exc))
    regeneration: bool | None = None
    if sarif_sources is not None:
        try:
            if analysis is None:
                raise ValueError("analysis is required for exact SARIF regeneration")
            expected = sarif_fusion(analysis, sarif_sources, authority=checked["authority"], evidence_refs=checked["evidence_refs"], generated_at=checked["generated_at"])
            regeneration = expected == checked
            if not regeneration:
                errors.append("SARIF fusion does not exactly regenerate")
        except (KeyError, OSError, TypeError, ValueError) as exc:
            regeneration = False
            if str(exc) not in errors:
                errors.append(str(exc))
    valid = structure and integrity and semantic and binding is not False and regeneration is not False
    return seal({"format": SARIF_FUSION_VERIFICATION_FORMAT, "valid": valid, "ready_for_triage": bool(valid and checked.get("summary", {}).get("results", 0)), "checks": {"closed_structure": structure, "content_integrity": integrity, "semantic_reconciliation": semantic, "analysis_binding": binding, "exact_regeneration": regeneration}, "errors": errors, "notice": "Verification establishes receipt integrity and accounting, not the correctness or completeness of external analyzers."})


def verify_sarif_fusion_file(source: str | Path, **kwargs: Any) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(source, label="SARIF fusion", max_bytes=64 * 1024 * 1024, max_depth=100, max_nodes=3_000_000)
        if not isinstance(document.value, dict):
            raise ValueError("SARIF fusion must contain an object")
        return verify_sarif_fusion(document.value, **kwargs)
    except (OSError, TypeError, ValueError) as exc:
        return seal({"format": SARIF_FUSION_VERIFICATION_FORMAT, "valid": False, "ready_for_triage": False, "checks": {"closed_structure": False, "content_integrity": False, "semantic_reconciliation": False, "analysis_binding": False if kwargs.get("analysis") is not None else None, "exact_regeneration": False if kwargs.get("sarif_sources") is not None else None}, "errors": [str(exc)], "notice": "SARIF fusion verification failed closed."})


def export_sarif_fusion(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_sarif_fusion(value)["valid"]:
        raise ValueError("SARIF fusion is internally invalid")
    return publish_json(value, destination)
