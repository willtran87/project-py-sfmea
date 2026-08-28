"""Conservative ReqIF, SysML v2 JSON, and OSLC JSON-LD lifecycle ingestion.

The normalized model is an evidence-bearing bridge, not a replacement for the
authoritative lifecycle repository.  Only explicit identifiers and references
are linked; names are never treated as proof of allocation or satisfaction.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import (
    BoundedFileSnapshot,
    load_bounded_file_snapshot,
    load_bounded_json_document,
    parse_bounded_json_bytes,
)
from .model import stable_id, utc_now
from .report import analysis_state_sha256

LIFECYCLE_MODEL_FORMAT = "pysfmea-lifecycle-model-bridge-1"
LIFECYCLE_MODEL_VERIFICATION_FORMAT = "pysfmea-lifecycle-model-verification-1"
LIFECYCLE_KINDS = frozenset({"reqif", "sysml2-json", "oslc-jsonld"})
REQIF_NS = "http://www.omg.org/spec/ReqIF/20110401/reqif.xsd"
MAX_SOURCE_BYTES = 100_000_000
MAX_ENTITIES = 250_000
MAX_RELATIONSHIPS = 1_000_000
MAX_PROPERTIES = 100
MAX_TEXT = 20_000


def _bounded(value: Any) -> str:
    text = str(value) if value is not None else ""
    return text[:MAX_TEXT]


def _scalar_properties(value: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for key in sorted(value, key=str):
        if len(properties) >= MAX_PROPERTIES:
            break
        item = value[key]
        if isinstance(item, (str, int, float, bool)) or item is None:
            properties[_bounded(key)] = item
    return properties


def _reference_id(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("@id", "id", "elementId"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
    return ""


def _reference_ids(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return sorted({identifier for item in values if (identifier := _reference_id(item))})


def _local_type(value: Any) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    text = str(value or "")
    return re.split(r"[#/:]", text)[-1]


def _entity_kind(type_name: str) -> str:
    folded = type_name.casefold()
    if "requirement" in folded:
        return "requirement"
    if any(token in folded for token in ("part", "component", "block", "package")):
        return "component"
    if any(token in folded for token in ("port", "interface", "connection")):
        return "interface"
    if any(token in folded for token in ("verification", "testcase", "testresult")):
        return "verification"
    if any(token in folded for token in ("action", "behavior", "activity")):
        return "behavior"
    if "state" in folded:
        return "state"
    if any(token in folded for token in ("constraint", "hazard", "risk")):
        return "constraint"
    if any(token in folded for token in ("relationship", "dependency", "allocation")):
        return "relationship"
    return "lifecycle_element"


def _entity(
    source_id: str,
    type_name: str,
    name: str,
    description: str,
    properties: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": stable_id("LCM", source_id),
        "source_id": _bounded(source_id),
        "kind": _entity_kind(type_name),
        "standard_type": _bounded(type_name or "unspecified"),
        "name": _bounded(name or source_id),
        "description": _bounded(description),
        "properties": properties,
    }


def _relationship(
    kind: str, source_id: str, target_id: str, authority: str
) -> dict[str, Any]:
    return {
        "id": stable_id("LCREL", kind, source_id, target_id),
        "kind": _bounded(kind or "related"),
        "source_id": _bounded(source_id),
        "target_id": _bounded(target_id),
        "authority": authority,
    }


def _reqif(snapshot: BoundedFileSnapshot) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    try:
        root = DefusedET.fromstring(snapshot.raw)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValueError(f"ReqIF source is invalid XML: {exc}") from exc
    if root.tag != f"{{{REQIF_NS}}}REQ-IF":
        raise ValueError("ReqIF source does not use the ReqIF 1.2 namespace")
    definitions: dict[str, str] = {}
    for definition in root.findall(f".//{{{REQIF_NS}}}ATTRIBUTE-DEFINITION-STRING"):
        identifier = definition.get("IDENTIFIER", "")
        if identifier:
            definitions[identifier] = definition.get("LONG-NAME", identifier)
    entities: list[dict[str, Any]] = []
    for node in root.findall(f".//{{{REQIF_NS}}}SPEC-OBJECT")[:MAX_ENTITIES]:
        identifier = node.get("IDENTIFIER", "")
        if not identifier:
            continue
        properties: dict[str, Any] = {}
        for attribute in node.findall(
            f".//{{{REQIF_NS}}}ATTRIBUTE-VALUE-STRING"
        )[:MAX_PROPERTIES]:
            reference = attribute.find(
                f".//{{{REQIF_NS}}}ATTRIBUTE-DEFINITION-STRING-REF"
            )
            key = definitions.get(
                reference.text if reference is not None and reference.text else "",
                reference.text if reference is not None and reference.text else "attribute",
            )
            properties[_bounded(key)] = _bounded(attribute.get("THE-VALUE", ""))
        type_ref = node.find(f".//{{{REQIF_NS}}}SPEC-OBJECT-TYPE-REF")
        type_name = type_ref.text if type_ref is not None and type_ref.text else "SpecObject"
        description = next(
            (
                str(value)
                for key, value in properties.items()
                if any(token in key.casefold() for token in ("description", "text", "statement"))
            ),
            "",
        )
        entities.append(
            _entity(
                identifier,
                type_name,
                node.get("LONG-NAME", identifier),
                description,
                properties,
            )
        )
    relationships: list[dict[str, Any]] = []
    for node in root.findall(f".//{{{REQIF_NS}}}SPEC-RELATION")[:MAX_RELATIONSHIPS]:
        source = node.find(f".//{{{REQIF_NS}}}SOURCE/{{{REQIF_NS}}}SPEC-OBJECT-REF")
        target = node.find(f".//{{{REQIF_NS}}}TARGET/{{{REQIF_NS}}}SPEC-OBJECT-REF")
        type_ref = node.find(f".//{{{REQIF_NS}}}SPEC-RELATION-TYPE-REF")
        if source is not None and source.text and target is not None and target.text:
            relationships.append(
                _relationship(
                    type_ref.text if type_ref is not None and type_ref.text else "related",
                    source.text,
                    target.text,
                    "explicit ReqIF SPEC-RELATION",
                )
            )
    limitations = []
    total_entities = len(root.findall(f".//{{{REQIF_NS}}}SPEC-OBJECT"))
    total_relationships = len(root.findall(f".//{{{REQIF_NS}}}SPEC-RELATION"))
    if total_entities > MAX_ENTITIES:
        limitations.append(f"ReqIF entities truncated from {total_entities} to {MAX_ENTITIES}")
    if total_relationships > MAX_RELATIONSHIPS:
        limitations.append(
            f"ReqIF relationships truncated from {total_relationships} to {MAX_RELATIONSHIPS}"
        )
    return entities, relationships, limitations


def _json_elements(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        raise ValueError("lifecycle JSON root must be an object or array")
    for key in ("@graph", "elements", "data", "items"):
        candidate = value.get(key)
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return [value]


def _sysml2(snapshot: BoundedFileSnapshot) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    value = parse_bounded_json_bytes(
        snapshot.raw,
        label="SysML v2 JSON snapshot",
        max_bytes=MAX_SOURCE_BYTES,
        max_depth=150,
        max_nodes=2_000_000,
    )
    elements = _json_elements(value)
    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    omissions: list[str] = []
    for element in elements[:MAX_ENTITIES]:
        identifier = _reference_id(element)
        if not identifier:
            omissions.append("SysML element without an explicit @id/id was omitted")
            continue
        type_name = _local_type(element.get("@type", element.get("type")))
        properties = _scalar_properties(element)
        entities.append(
            _entity(
                identifier,
                type_name,
                str(
                    element.get("declaredName")
                    or element.get("name")
                    or element.get("shortName")
                    or identifier
                ),
                str(element.get("documentation") or element.get("description") or ""),
                properties,
            )
        )
        source_ids = _reference_ids(
            element.get("source", element.get("sourceId", element.get("owner")))
        )
        target_ids = _reference_ids(
            element.get(
                "target",
                element.get("targetId", element.get("relatedElement")),
            )
        )
        if source_ids and target_ids:
            for source_id in source_ids:
                for target_id in target_ids:
                    if len(relationships) >= MAX_RELATIONSHIPS:
                        break
                    relationships.append(
                        _relationship(
                            type_name or "SysMLRelationship",
                            source_id,
                            target_id,
                            "explicit SysML relationship endpoint",
                        )
                    )
    if len(elements) > MAX_ENTITIES:
        omissions.append(
            f"SysML elements truncated from {len(elements)} to {MAX_ENTITIES}"
        )
    return entities, relationships, sorted(set(omissions))[:1_000]


def _iter_oslc_links(element: dict[str, Any]) -> Iterable[tuple[str, str]]:
    metadata = {
        "@id",
        "@type",
        "id",
        "type",
        "title",
        "description",
        "dcterms:title",
        "dcterms:description",
    }
    for key in sorted(element):
        if key in metadata:
            continue
        for identifier in _reference_ids(element[key]):
            yield key, identifier


def _oslc(snapshot: BoundedFileSnapshot) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    value = parse_bounded_json_bytes(
        snapshot.raw,
        label="OSLC JSON-LD snapshot",
        max_bytes=MAX_SOURCE_BYTES,
        max_depth=150,
        max_nodes=2_000_000,
    )
    elements = _json_elements(value)
    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    omissions: list[str] = []
    for element in elements[:MAX_ENTITIES]:
        identifier = _reference_id(element)
        if not identifier:
            omissions.append("OSLC resource without an explicit @id/id was omitted")
            continue
        type_name = _local_type(element.get("@type", element.get("type")))
        entities.append(
            _entity(
                identifier,
                type_name,
                str(element.get("dcterms:title") or element.get("title") or identifier),
                str(
                    element.get("dcterms:description")
                    or element.get("description")
                    or ""
                ),
                _scalar_properties(element),
            )
        )
        for relationship_kind, target_id in _iter_oslc_links(element):
            if len(relationships) >= MAX_RELATIONSHIPS:
                break
            relationships.append(
                _relationship(
                    relationship_kind,
                    identifier,
                    target_id,
                    "explicit OSLC JSON-LD resource reference",
                )
            )
    if len(elements) > MAX_ENTITIES:
        omissions.append(
            f"OSLC resources truncated from {len(elements)} to {MAX_ENTITIES}"
        )
    return entities, relationships, sorted(set(omissions))[:1_000]


def _component_indexes(analysis: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    by_identity: dict[str, str] = {}
    by_source_qualname: dict[str, str] = {}
    for component in analysis.get("components", []):
        if not isinstance(component, dict):
            continue
        identifier = str(component.get("id", ""))
        if not identifier:
            continue
        by_identity[identifier] = identifier
        source = component.get("source", {})
        path = str(source.get("path", "")) if isinstance(source, dict) else ""
        qualname = str(component.get("qualname", ""))
        if path and qualname:
            by_source_qualname[f"{path}:{qualname}"] = identifier
    return by_identity, by_source_qualname


def _code_links(
    entities: list[dict[str, Any]], analysis: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], list[str]]:
    if analysis is None:
        return [], []
    by_identity, by_source_qualname = _component_indexes(analysis)
    links: list[dict[str, Any]] = []
    unresolved: list[str] = []
    recognized = {
        "component_id",
        "componentId",
        "pysfmea:componentId",
        "qualified_name",
        "qualifiedName",
        "pysfmea:qualifiedName",
    }
    for entity in entities:
        candidates = [
            str(value)
            for key, value in entity["properties"].items()
            if key in recognized and isinstance(value, str) and value
        ]
        matched: set[str] = set()
        for candidate in candidates:
            if candidate in by_identity:
                matched.add(by_identity[candidate])
            if candidate in by_source_qualname:
                matched.add(by_source_qualname[candidate])
        if len(matched) == 1:
            component_id = next(iter(matched))
            links.append(
                {
                    "model_entity_id": entity["id"],
                    "component_id": component_id,
                    "relationship": "explicit_identity_mapping",
                    "authority": "exact declared model property",
                }
            )
        elif candidates:
            unresolved.append(entity["id"])
    return links, sorted(unresolved)


def import_lifecycle_model(
    kind: str,
    source: str | Path,
    *,
    analysis: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Normalize one exact lifecycle snapshot without fuzzy relationship inference."""

    if kind not in LIFECYCLE_KINDS:
        raise ValueError("lifecycle kind must be reqif, sysml2-json, or oslc-jsonld")
    snapshot = load_bounded_file_snapshot(
        source,
        label=f"{kind} lifecycle source",
        max_bytes=MAX_SOURCE_BYTES,
    )
    if kind == "reqif":
        entities, relationships, limitations = _reqif(snapshot)
        standard = "OMG ReqIF 1.2"
    elif kind == "sysml2-json":
        entities, relationships, limitations = _sysml2(snapshot)
        standard = "OMG SysML 2.0 / Systems Modeling API 1.0 JSON snapshot"
    else:
        entities, relationships, limitations = _oslc(snapshot)
        standard = "OASIS OSLC RM/QM/AM JSON-LD snapshot"
    entity_source_ids = {entity["source_id"] for entity in entities}
    dangling = sorted(
        {
            endpoint
            for relationship in relationships
            for endpoint in (relationship["source_id"], relationship["target_id"])
            if endpoint not in entity_source_ids
        }
    )
    code_links, unresolved_links = _code_links(entities, analysis)
    result: dict[str, Any] = {
        "format": LIFECYCLE_MODEL_FORMAT,
        "generated_at": generated_at or utc_now(),
        "source": {
            "kind": kind,
            "standard": standard,
            "reference": snapshot.path.name,
            "bytes": snapshot.size,
            "sha256": hashlib.sha256(snapshot.raw).hexdigest(),
        },
        "analysis_binding": (
            {
                "baseline_id": str(
                    analysis.get("project", {}).get("baseline", {}).get("id", "")
                ),
                "analysis_state_sha256": analysis_state_sha256(analysis),
            }
            if analysis is not None
            else None
        ),
        "entities": sorted(entities, key=lambda item: item["id"]),
        "relationships": sorted(relationships, key=lambda item: item["id"]),
        "code_links": sorted(
            code_links, key=lambda item: (item["model_entity_id"], item["component_id"])
        ),
        "summary": {
            "entities": len(entities),
            "relationships": len(relationships),
            "code_links": len(code_links),
            "dangling_source_ids": dangling,
            "unresolved_explicit_code_link_entity_ids": unresolved_links,
            "complete": not dangling and not limitations and not unresolved_links,
        },
        "limitations": limitations,
        "notice": (
            "Only explicit lifecycle identifiers and references are represented. Name "
            "similarity is not treated as traceability, allocation, satisfaction, or verification."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_lifecycle_model(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    expected = {
        "format",
        "generated_at",
        "source",
        "analysis_binding",
        "entities",
        "relationships",
        "code_links",
        "summary",
        "limitations",
        "notice",
        "content_sha256",
    }
    structure = False
    semantic = False
    try:
        structure = bool(
            set(value) == expected
            and value["format"] == LIFECYCLE_MODEL_FORMAT
            and set(value["source"])
            == {"kind", "standard", "reference", "bytes", "sha256"}
            and value["source"]["kind"] in LIFECYCLE_KINDS
            and isinstance(value["entities"], list)
            and isinstance(value["relationships"], list)
            and isinstance(value["code_links"], list)
            and isinstance(value["limitations"], list)
        )
        entity_ids = [item["id"] for item in value["entities"]]
        source_ids = {item["source_id"] for item in value["entities"]}
        relationship_ids = [item["id"] for item in value["relationships"]]
        dangling = sorted(
            {
                endpoint
                for item in value["relationships"]
                for endpoint in (item["source_id"], item["target_id"])
                if endpoint not in source_ids
            }
        )
        unresolved = value["summary"][
            "unresolved_explicit_code_link_entity_ids"
        ]
        expected_summary = {
            "entities": len(value["entities"]),
            "relationships": len(value["relationships"]),
            "code_links": len(value["code_links"]),
            "dangling_source_ids": dangling,
            "unresolved_explicit_code_link_entity_ids": unresolved,
            "complete": bool(
                not dangling and not value["limitations"] and not unresolved
            ),
        }
        semantic = bool(
            structure
            and len(entity_ids) == len(set(entity_ids))
            and len(relationship_ids) == len(set(relationship_ids))
            and all(
                link["model_entity_id"] in set(entity_ids)
                for link in value["code_links"]
            )
            and value["summary"] == expected_summary
        )
    except (KeyError, TypeError):
        structure = False
        semantic = False
    if not structure:
        errors.append("lifecycle model fields do not match format 1")
    if not semantic:
        errors.append("lifecycle model identities, links, or summary do not reconcile")
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(unsigned) == claimed
    )
    if not integrity:
        errors.append("lifecycle model content digest does not match")
    return {
        "format": LIFECYCLE_MODEL_VERIFICATION_FORMAT,
        "valid": bool(structure and semantic and integrity),
        "complete": bool(structure and semantic and value.get("summary", {}).get("complete")),
        "checks": {
            "closed_structure": structure,
            "content_integrity": integrity,
            "semantic_reconciliation": semantic,
            "source_regeneration": None,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification establishes normalized-model integrity, not authoritative-model completeness or standard conformance.",
    }


def verify_lifecycle_model_file(
    model_source: str | Path,
    *,
    lifecycle_source: str | Path | None = None,
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            model_source,
            label="lifecycle model bridge",
            max_bytes=MAX_SOURCE_BYTES,
            max_depth=150,
            max_nodes=2_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("lifecycle model bridge must contain an object")
        verdict = {"path": str(document.path), **verify_lifecycle_model(document.value)}
        if lifecycle_source is not None:
            regenerated = import_lifecycle_model(
                str(document.value.get("source", {}).get("kind", "")),
                lifecycle_source,
                analysis=analysis,
                generated_at=str(document.value.get("generated_at", "")),
            )
            matches = regenerated == document.value
            verdict["checks"]["source_regeneration"] = matches
            if not matches:
                verdict["valid"] = False
                verdict["complete"] = False
                verdict["errors"].append(
                    "lifecycle model does not regenerate from the supplied sources"
                )
        return verdict
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(model_source).expanduser().absolute()),
            "format": LIFECYCLE_MODEL_VERIFICATION_FORMAT,
            "valid": False,
            "complete": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "semantic_reconciliation": False,
                "source_regeneration": False if lifecycle_source is not None else None,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The lifecycle model bridge could not be safely verified.",
        }


def export_lifecycle_model(value: dict[str, Any], destination: str | Path) -> Path:
    verdict = verify_lifecycle_model(value)
    if not verdict["valid"]:
        raise ValueError("lifecycle model bridge is internally invalid")
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="lifecycle model bridge",
    )
