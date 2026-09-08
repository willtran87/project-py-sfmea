"""Version-pinned MITRE CWE and CAPEC taxonomy evidence.

The importer consumes official XML downloads without network access.  It keeps
source bytes, release identity, entries, relationships, and deprecation state
content-addressed so downstream mappings can name the exact taxonomy used.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_file_snapshot
from .model import utc_now

SECURITY_TAXONOMY_FORMAT = "pysfmea-security-taxonomy-1"
SECURITY_TAXONOMY_VERIFICATION_FORMAT = "pysfmea-security-taxonomy-verification-1"
MAX_XML_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 20_000
KINDS = {"cwe", "capec"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _regular_source(source: str | Path) -> tuple[Path, bytes]:
    snapshot = load_bounded_file_snapshot(
        source, label="taxonomy source", max_bytes=MAX_XML_BYTES
    )
    if not snapshot.raw:
        raise ValueError("taxonomy source size is outside the supported boundary")
    return snapshot.path, snapshot.raw


def _child_text(node: Any, name: str) -> str:
    for child in node:
        if _local(str(child.tag)) == name:
            return " ".join("".join(child.itertext()).split())[:20_000]
    return ""


def _relationships(node: Any, *, kind: str) -> list[dict[str, str]]:
    specifications = (
        (("Related_Weakness", "CWE_ID", "cwe"),)
        if kind == "cwe"
        else (
            ("Related_Attack_Pattern", "CAPEC_ID", "capec"),
            ("Related_Weakness", "CWE_ID", "cwe"),
        )
    )
    values: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for child in node.iter():
        local_name = _local(str(child.tag))
        specification = next(
            (item for item in specifications if item[0] == local_name), None
        )
        if specification is None:
            continue
        _tag, target_attribute, target_kind = specification
        target = str(child.attrib.get(target_attribute, "")).strip()
        nature = str(child.attrib.get("Nature", "related")).strip().casefold()
        view = str(child.attrib.get("View_ID", "")).strip()
        if not target or not target.isdigit():
            continue
        key = (target_kind, nature, target, view)
        if key in seen:
            continue
        seen.add(key)
        values.append(
            {
                "target_kind": target_kind,
                "nature": nature,
                "target_id": target,
                "view_id": view,
            }
        )
    return sorted(
        values,
        key=lambda item: (
            item["target_kind"],
            item["nature"],
            int(item["target_id"]),
            item["view_id"],
        ),
    )


def _parse(raw: bytes) -> tuple[str, str, str, list[dict[str, Any]]]:
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise ValueError(f"taxonomy XML is invalid: {exc}") from exc
    root_name = _local(str(root.tag))
    if root_name == "Weakness_Catalog":
        kind, entry_tag = "cwe", "Weakness"
    elif root_name == "Attack_Pattern_Catalog":
        kind, entry_tag = "capec", "Attack_Pattern"
    else:
        raise ValueError("taxonomy XML must be a MITRE CWE or CAPEC catalog")
    version = str(root.attrib.get("Version", "")).strip()
    release_date = str(root.attrib.get("Date", "")).strip()
    if not version or not release_date:
        raise ValueError("taxonomy XML does not declare a version and release date")
    entries: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for node in root.iter():
        if _local(str(node.tag)) != entry_tag:
            continue
        identifier = str(node.attrib.get("ID", "")).strip()
        name = str(node.attrib.get("Name", "")).strip()
        status = str(node.attrib.get("Status", "")).strip()
        abstraction = str(node.attrib.get("Abstraction", "")).strip()
        if (
            not identifier.isdigit()
            or identifier in identifiers
            or not name
            or not status
        ):
            raise ValueError(
                "taxonomy entry identifiers, names, and statuses must be complete and unique"
            )
        identifiers.add(identifier)
        entries.append(
            {
                "id": identifier,
                "name": name[:20_000],
                "status": status,
                "abstraction": abstraction,
                "description": _child_text(node, "Description"),
                "relationships": _relationships(node, kind=kind),
                "deprecated": status.casefold() in {"deprecated", "obsolete"},
            }
        )
        if len(entries) > MAX_ENTRIES:
            raise ValueError("taxonomy entry count exceeds the supported boundary")
    if not entries:
        raise ValueError("taxonomy XML contains no supported entries")
    entries.sort(key=lambda item: int(item["id"]))
    return kind, version, release_date, entries


def import_security_taxonomy(
    source: str | Path,
    *,
    authority: str,
    expected_kind: str | None = None,
    expected_version: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Import and seal one exact official CWE or CAPEC XML release."""

    path, raw = _regular_source(source)
    kind, version, release_date, entries = _parse(raw)
    if expected_kind is not None and expected_kind not in KINDS:
        raise ValueError("expected taxonomy kind must be cwe or capec")
    if expected_kind is not None and kind != expected_kind:
        raise ValueError("taxonomy kind does not match the expected kind")
    if expected_version is not None and version != expected_version:
        raise ValueError("taxonomy version does not match the expected version")
    result = seal(
        {
            "format": SECURITY_TAXONOMY_FORMAT,
            "generated_at": generated_at or utc_now(),
            "authority": bounded_text(authority, "taxonomy authority"),
            "taxonomy": {
                "kind": kind,
                "version": version,
                "release_date": release_date,
                "source_url": (
                    "https://cwe.mitre.org/data/downloads.html"
                    if kind == "cwe"
                    else "https://capec.mitre.org/data/downloads.html"
                ),
            },
            "source": {
                "filename": path.name,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            },
            "entries": entries,
            "summary": {
                "entries": len(entries),
                "deprecated": sum(bool(item["deprecated"]) for item in entries),
                "relationships": sum(len(item["relationships"]) for item in entries),
            },
            "claim_boundary": "This artifact proves deterministic ingestion of exact supplied taxonomy bytes. Publisher authenticity, release authorization, and the correctness of downstream finding mappings require separate evidence and review.",
        }
    )
    verdict = verify_security_taxonomy(result, source=path)
    if not verdict["valid"]:
        raise ValueError("generated taxonomy artifact failed verification")
    return result


def _structure(value: dict[str, Any]) -> bool:
    try:
        taxonomy = value["taxonomy"]
        source = value["source"]
        entries = value["entries"]
        summary = value["summary"]
        identifiers: list[str] = []
        relationships = 0
        deprecated = 0
        if not (
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "taxonomy",
                "source",
                "entries",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(taxonomy) == {"kind", "version", "release_date", "source_url"}
            and taxonomy["kind"] in KINDS
            and all(
                isinstance(taxonomy[name], str) and taxonomy[name]
                for name in ("version", "release_date", "source_url")
            )
            and set(source) == {"filename", "bytes", "sha256"}
            and isinstance(source["bytes"], int)
            and 0 < source["bytes"] <= MAX_XML_BYTES
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(source["sha256"])))
            and isinstance(entries, list)
            and 0 < len(entries) <= MAX_ENTRIES
        ):
            return False
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "id",
                "name",
                "status",
                "abstraction",
                "description",
                "relationships",
                "deprecated",
            }:
                return False
            identifiers.append(entry["id"])
            if not (
                isinstance(entry["id"], str)
                and entry["id"].isdigit()
                and all(
                    isinstance(entry[name], str)
                    for name in ("name", "status", "abstraction", "description")
                )
                and bool(entry["name"] and entry["status"])
                and isinstance(entry["deprecated"], bool)
                and isinstance(entry["relationships"], list)
            ):
                return False
            for relation in entry["relationships"]:
                if not isinstance(relation, dict) or set(relation) != {
                    "target_kind",
                    "nature",
                    "target_id",
                    "view_id",
                }:
                    return False
                if (
                    relation["target_kind"] not in KINDS
                    or not relation["target_id"].isdigit()
                    or not relation["nature"]
                ):
                    return False
            relationships += len(entry["relationships"])
            deprecated += int(entry["deprecated"])
        return bool(
            identifiers == sorted(identifiers, key=int)
            and len(identifiers) == len(set(identifiers))
            and summary
            == {
                "entries": len(entries),
                "deprecated": deprecated,
                "relationships": relationships,
            }
        )
    except (KeyError, TypeError):
        return False


def verify_security_taxonomy(
    value: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="security taxonomy", format_value=SECURITY_TAXONOMY_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("security taxonomy fields or summary are invalid")
    exact_source = source is None
    regeneration = source is None
    if source is not None and structure:
        try:
            _path, raw = _regular_source(source)
            exact_source = bool(
                len(raw) == checked["source"]["bytes"]
                and hashlib.sha256(raw).hexdigest() == checked["source"]["sha256"]
            )
            kind, version, release_date, entries = _parse(raw)
            regeneration = bool(
                kind == checked["taxonomy"]["kind"]
                and version == checked["taxonomy"]["version"]
                and release_date == checked["taxonomy"]["release_date"]
                and entries == checked["entries"]
            )
        except (OSError, TypeError, ValueError) as exc:
            errors.append(str(exc))
            exact_source = regeneration = False
    if not exact_source:
        errors.append("taxonomy artifact does not bind the supplied XML bytes")
    if not regeneration:
        errors.append("taxonomy entries do not regenerate from the supplied XML")
    valid = integrity and structure and exact_source and regeneration
    return seal(
        {
            "format": SECURITY_TAXONOMY_VERIFICATION_FORMAT,
            "valid": valid,
            "eligible_for_mapping": valid and source is not None,
            "checks": {
                "content_integrity": integrity,
                "closed_structure_and_summary": structure,
                "exact_source_binding": exact_source,
                "exact_regeneration": regeneration,
            },
            "errors": errors,
            "notice": "Eligibility requires the exact XML source; mapping applicability and publisher authenticity remain separately governed.",
        }
    )


def export_security_taxonomy(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_security_taxonomy(value)["valid"]:
        raise ValueError("security taxonomy artifact is internally invalid")
    return publish_json(value, destination)


def verify_security_taxonomy_file(
    artifact: str | Path, *, source: str | Path | None = None
) -> dict[str, Any]:
    try:
        return verify_security_taxonomy(
            load_json(artifact, label="security taxonomy"), source=source
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": SECURITY_TAXONOMY_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_mapping": False,
                "checks": {
                    "content_integrity": False,
                    "closed_structure_and_summary": False,
                    "exact_source_binding": False,
                    "exact_regeneration": False,
                },
                "errors": [str(exc)],
                "notice": "Security-taxonomy verification failed closed.",
            }
        )
