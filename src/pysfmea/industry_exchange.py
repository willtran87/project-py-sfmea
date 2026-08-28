"""Standards-oriented SACM, SFPM, ReqIF, and SPDX exchange projections.

The XML projections use the official OMG namespace identities and class names,
retain exact PySFMEA source identity, and are independently reconcilable. They
cover the PySFMEA subset documented in each receipt; unsupported metamodel
features are never implied.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .model import stable_id, utc_now
from .report import analysis_state_sha256
from .version import __version__

XMI_NS = "http://www.omg.org/spec/XMI/20131001"
SACM_NS = "http://www.omg.org/spec/SACM/20220301"
SFPM_NS = "http://www.omg.org/spec/SFPM/20220201"
REQIF_NS = "http://www.omg.org/spec/ReqIF/20110401/reqif.xsd"
PY_NS = "https://github.com/willtran87/project-py-sfmea/industry-exchange/1"
SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
MAX_XML_BYTES = 100_000_000

for prefix, namespace in (
    ("xmi", XMI_NS),
    ("sacm", SACM_NS),
    ("sfpm", SFPM_NS),
    ("", REQIF_NS),
    ("pysfmea", PY_NS),
):
    ET.register_namespace(prefix, namespace)


def _xml_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    if not cleaned or not re.match(r"[A-Za-z_]", cleaned):
        cleaned = "id_" + cleaned
    return cleaned


def _source_digest(value: dict[str, Any]) -> str:
    return canonical_json_sha256(value)


def _xml(root: ET.Element) -> str:
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def sacm_xmi(case: dict[str, Any]) -> str:
    """Project a PySFMEA assurance case into its governed SACM 2.3 subset."""

    root = ET.Element(f"{{{XMI_NS}}}XMI")
    package = ET.SubElement(
        root,
        f"{{{SACM_NS}}}AssuranceCasePackage",
        {
            f"{{{XMI_NS}}}id": "ACP_PySFMEA",
            "gid": str(case.get("content_sha256", "")),
            "name": "PySFMEA assurance case",
            f"{{{PY_NS}}}sourceCanonicalSha256": _source_digest(case),
            f"{{{PY_NS}}}coverage": "SACM-2.3-argumentation-and-artifact-subset",
        },
    )
    argument_package = ET.SubElement(
        package,
        "argumentPackage",
        {
            f"{{{XMI_NS}}}type": "sacm:ArgumentPackage",
            f"{{{XMI_NS}}}id": "AP_PySFMEA",
            "gid": "AP-PYSFMEA",
            "name": "PySFMEA claims and arguments",
        },
    )
    artifact_package = ET.SubElement(
        package,
        "artifactPackage",
        {
            f"{{{XMI_NS}}}type": "sacm:ArtifactPackage",
            f"{{{XMI_NS}}}id": "ARTP_PySFMEA",
            "gid": "ARTP-PYSFMEA",
            "name": "PySFMEA exact evidence",
        },
    )
    for claim in case.get("claims", []):
        if not isinstance(claim, dict):
            continue
        element = ET.SubElement(
            argument_package,
            "argumentationElement",
            {
                f"{{{XMI_NS}}}type": "sacm:Claim",
                f"{{{XMI_NS}}}id": _xml_id(str(claim.get("id", "claim"))),
                "gid": str(claim.get("id", "")),
                "name": str(claim.get("title", "")),
                f"{{{PY_NS}}}status": str(claim.get("status", "")),
            },
        )
        ET.SubElement(element, "content").text = str(claim.get("statement", ""))
        for assumption in claim.get("assumptions", []):
            ET.SubElement(element, f"{{{PY_NS}}}assumption").text = str(assumption)
    for argument in case.get("arguments", []):
        if not isinstance(argument, dict):
            continue
        element = ET.SubElement(
            argument_package,
            "argumentationElement",
            {
                f"{{{XMI_NS}}}type": "sacm:ArgumentReasoning",
                f"{{{XMI_NS}}}id": _xml_id(str(argument.get("id", "argument"))),
                "gid": str(argument.get("id", "")),
                "name": str(argument.get("strategy", "")),
                f"{{{PY_NS}}}claim": str(argument.get("claim_id", "")),
                f"{{{PY_NS}}}status": str(argument.get("status", "")),
            },
        )
        ET.SubElement(element, "content").text = str(argument.get("reasoning", ""))
    for evidence in case.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        element = ET.SubElement(
            artifact_package,
            "artifactElement",
            {
                f"{{{XMI_NS}}}type": "sacm:ArtifactReference",
                f"{{{XMI_NS}}}id": _xml_id(str(evidence.get("id", "evidence"))),
                "gid": str(evidence.get("id", "")),
                "name": str(evidence.get("kind", "")),
                f"{{{PY_NS}}}sha256": str(evidence.get("sha256", "")),
                f"{{{PY_NS}}}uri": str(evidence.get("artifact", "")),
            },
        )
        ET.SubElement(element, "content").text = str(evidence.get("description", ""))
    evidence_ids = {
        str(item.get("id")) for item in case.get("evidence", []) if isinstance(item, dict)
    }
    for index, relationship in enumerate(case.get("relationships", []), start=1):
        if not isinstance(relationship, dict):
            continue
        source = str(relationship.get("source", ""))
        target = str(relationship.get("target", ""))
        relation_type = str(relationship.get("type", ""))
        sacm_type = (
            "AssertedEvidence"
            if source in evidence_ids
            else "AssertedContext"
            if relation_type == "in_context_of"
            else "AssertedInference"
        )
        ET.SubElement(
            argument_package,
            "argumentationElement",
            {
                f"{{{XMI_NS}}}type": f"sacm:{sacm_type}",
                f"{{{XMI_NS}}}id": f"REL_{index}",
                "gid": f"REL-{index}",
                "source": _xml_id(source),
                "target": _xml_id(target),
                f"{{{PY_NS}}}relationship": relation_type,
            },
        )
    for defeater in case.get("defeaters", []):
        if not isinstance(defeater, dict):
            continue
        element = ET.SubElement(
            argument_package,
            "argumentationElement",
            {
                f"{{{XMI_NS}}}type": "sacm:Claim",
                f"{{{XMI_NS}}}id": _xml_id(str(defeater.get("id", "defeater"))),
                "gid": str(defeater.get("id", "")),
                "name": "Open defeater",
                f"{{{PY_NS}}}challenges": str(defeater.get("claim_id", "")),
                f"{{{PY_NS}}}status": "asserted",
            },
        )
        ET.SubElement(element, "content").text = str(defeater.get("statement", ""))
    return _xml(root)


def sfpm_xmi(analysis: dict[str, Any]) -> str:
    """Project active SFMEA records into the governed SFPM 1.0 SFP subset."""

    root = ET.Element(f"{{{XMI_NS}}}XMI")
    catalog = ET.SubElement(
        root,
        f"{{{SFPM_NS}}}SFPCatalog",
        {
            f"{{{XMI_NS}}}id": "SFPCatalog_PySFMEA",
            "name": str(analysis.get("project", {}).get("name", "PySFMEA catalog")),
            f"{{{PY_NS}}}analysisStateSha256": analysis_state_sha256(analysis),
            f"{{{PY_NS}}}coverage": "SFPM-1.0-SFP-root-cause-control-and-context-subset",
        },
    )
    for item in analysis.get("items", []):
        if not isinstance(item, dict) or item.get("source_status", "active") != "active":
            continue
        review = item.get("review", {}) if isinstance(item.get("review"), dict) else {}
        scanner = item.get("scanner", {}) if isinstance(item.get("scanner"), dict) else {}
        identifier = str(item.get("id", ""))
        sfp = ET.SubElement(
            catalog,
            "sfp",
            {
                f"{{{XMI_NS}}}type": "sfpm:SFP",
                f"{{{XMI_NS}}}id": _xml_id(identifier),
                "id": identifier,
                "name": str(review.get("failure_mode") or scanner.get("failure_mode") or identifier),
                "description": str(scanner.get("rationale", "")),
                f"{{{PY_NS}}}component": str(item.get("component_id", "")),
                f"{{{PY_NS}}}rule": str(scanner.get("rule_id", "")),
            },
        )
        for cause in review.get("causes") or scanner.get("causes", []):
            section = ET.SubElement(sfp, "section", {f"{{{XMI_NS}}}type": "sfpm:RootCauseSection"})
            ET.SubElement(section, "rootCause", {f"{{{XMI_NS}}}type": "sfpm:RootCause", "description": str(cause)})
        for control in review.get("prevention_controls", []):
            ET.SubElement(sfp, f"{{{PY_NS}}}control", {"kind": "prevention", "description": str(control)})
        for control in review.get("detection_controls", []):
            ET.SubElement(sfp, f"{{{PY_NS}}}control", {"kind": "detection", "description": str(control)})
        context = ET.SubElement(sfp, "section", {f"{{{XMI_NS}}}type": "sfpm:ContextSection"})
        ET.SubElement(context, "contextElement", {f"{{{XMI_NS}}}type": "sfpm:ContextElement", "description": str(review.get("operational_mode", ""))})
    return _xml(root)


def _reqif_value(
    parent: ET.Element, definition: str, value: str
) -> None:
    attribute = ET.SubElement(parent, "ATTRIBUTE-VALUE-STRING", {"THE-VALUE": value[:20000]})
    definition_node = ET.SubElement(attribute, "DEFINITION")
    ET.SubElement(definition_node, "ATTRIBUTE-DEFINITION-STRING-REF").text = definition


def reqif_document(analysis: dict[str, Any], *, generated_at: str | None = None) -> str:
    """Export findings and verification obligations as OMG ReqIF 1.2 XML."""

    timestamp = generated_at or utc_now()
    root = ET.Element(f"{{{REQIF_NS}}}REQ-IF")
    header_container = ET.SubElement(root, "THE-HEADER")
    header = ET.SubElement(header_container, "REQ-IF-HEADER", {"IDENTIFIER": "PYSFMEA-HEADER"})
    ET.SubElement(header, "COMMENT").text = "Governed SFMEA findings and verification obligations; candidate status is preserved."
    ET.SubElement(header, "CREATION-TIME").text = timestamp
    ET.SubElement(header, "REQ-IF-TOOL-ID").text = f"PySFMEA {__version__}"
    ET.SubElement(header, "REQ-IF-VERSION").text = "1.2"
    ET.SubElement(header, "SOURCE-TOOL-ID").text = "PySFMEA"
    ET.SubElement(header, "TITLE").text = str(analysis.get("project", {}).get("name", "PySFMEA analysis"))
    core = ET.SubElement(root, "CORE-CONTENT")
    content = ET.SubElement(core, "REQ-IF-CONTENT")
    datatypes = ET.SubElement(content, "DATATYPES")
    ET.SubElement(datatypes, "DATATYPE-DEFINITION-STRING", {"IDENTIFIER": "DT-TEXT", "LONG-NAME": "Text", "LAST-CHANGE": timestamp, "MAX-LENGTH": "20000"})
    spec_types = ET.SubElement(content, "SPEC-TYPES")
    for type_id, name in (("ST-FINDING", "SFMEA finding"), ("ST-OBLIGATION", "Verification obligation")):
        spec_type = ET.SubElement(spec_types, "SPEC-OBJECT-TYPE", {"IDENTIFIER": type_id, "LONG-NAME": name, "LAST-CHANGE": timestamp})
        attributes = ET.SubElement(spec_type, "SPEC-ATTRIBUTES")
        for suffix, long_name in (("TITLE", "Title"), ("TEXT", "Description"), ("STATUS", "Status"), ("SOURCE", "Source identity")):
            definition = ET.SubElement(attributes, "ATTRIBUTE-DEFINITION-STRING", {"IDENTIFIER": f"AD-{type_id}-{suffix}", "LONG-NAME": long_name, "LAST-CHANGE": timestamp, "IS-EDITABLE": "false"})
            type_node = ET.SubElement(definition, "TYPE")
            ET.SubElement(type_node, "DATATYPE-DEFINITION-STRING-REF").text = "DT-TEXT"
    ET.SubElement(spec_types, "SPEC-RELATION-TYPE", {"IDENTIFIER": "SRT-VERIFIES", "LONG-NAME": "verifies", "LAST-CHANGE": timestamp})
    ET.SubElement(spec_types, "SPECIFICATION-TYPE", {"IDENTIFIER": "ST-SPEC", "LONG-NAME": "PySFMEA exchange", "LAST-CHANGE": timestamp})
    spec_objects = ET.SubElement(content, "SPEC-OBJECTS")
    object_ids: list[str] = []
    for item in analysis.get("items", []):
        if not isinstance(item, dict) or item.get("source_status", "active") != "active":
            continue
        identifier = str(item.get("id", ""))
        reqif_id = "SO-" + _xml_id(identifier)
        object_ids.append(reqif_id)
        obj = ET.SubElement(spec_objects, "SPEC-OBJECT", {"IDENTIFIER": reqif_id, "LONG-NAME": identifier, "LAST-CHANGE": timestamp})
        values = ET.SubElement(obj, "VALUES")
        review = item.get("review", {}) if isinstance(item.get("review"), dict) else {}
        scanner = item.get("scanner", {}) if isinstance(item.get("scanner"), dict) else {}
        _reqif_value(values, "AD-ST-FINDING-TITLE", str(review.get("failure_mode") or scanner.get("failure_mode") or identifier))
        _reqif_value(values, "AD-ST-FINDING-TEXT", str(scanner.get("rationale", "")))
        _reqif_value(values, "AD-ST-FINDING-STATUS", str(review.get("disposition", "unreviewed")))
        _reqif_value(values, "AD-ST-FINDING-SOURCE", f"finding:{identifier};analysis:{analysis_state_sha256(analysis)}")
        type_node = ET.SubElement(obj, "TYPE")
        ET.SubElement(type_node, "SPEC-OBJECT-TYPE-REF").text = "ST-FINDING"
    obligations = [item for item in analysis.get("assurance", {}).get("obligations", []) if isinstance(item, dict)]
    for obligation in obligations:
        identifier = str(obligation.get("id", ""))
        reqif_id = "SO-" + _xml_id(identifier)
        object_ids.append(reqif_id)
        obj = ET.SubElement(spec_objects, "SPEC-OBJECT", {"IDENTIFIER": reqif_id, "LONG-NAME": identifier, "LAST-CHANGE": timestamp})
        values = ET.SubElement(obj, "VALUES")
        _reqif_value(values, "AD-ST-OBLIGATION-TITLE", str(obligation.get("title", identifier)))
        _reqif_value(values, "AD-ST-OBLIGATION-TEXT", str(obligation.get("objective", "")))
        _reqif_value(values, "AD-ST-OBLIGATION-STATUS", str(obligation.get("assurance_status", "planned")))
        _reqif_value(values, "AD-ST-OBLIGATION-SOURCE", f"obligation:{identifier};finding:{obligation.get('finding_id', '')}")
        type_node = ET.SubElement(obj, "TYPE")
        ET.SubElement(type_node, "SPEC-OBJECT-TYPE-REF").text = "ST-OBLIGATION"
    relations = ET.SubElement(content, "SPEC-RELATIONS")
    for obligation in obligations:
        relation = ET.SubElement(relations, "SPEC-RELATION", {"IDENTIFIER": "SR-" + _xml_id(str(obligation.get("id", ""))), "LAST-CHANGE": timestamp})
        source = ET.SubElement(relation, "SOURCE")
        ET.SubElement(source, "SPEC-OBJECT-REF").text = "SO-" + _xml_id(str(obligation.get("id", "")))
        target = ET.SubElement(relation, "TARGET")
        ET.SubElement(target, "SPEC-OBJECT-REF").text = "SO-" + _xml_id(str(obligation.get("finding_id", "")))
        type_node = ET.SubElement(relation, "TYPE")
        ET.SubElement(type_node, "SPEC-RELATION-TYPE-REF").text = "SRT-VERIFIES"
    specifications = ET.SubElement(content, "SPECIFICATIONS")
    specification = ET.SubElement(specifications, "SPECIFICATION", {"IDENTIFIER": "SPEC-PYSFMEA", "LONG-NAME": "PySFMEA findings and obligations", "LAST-CHANGE": timestamp})
    children = ET.SubElement(specification, "CHILDREN")
    for index, object_id in enumerate(object_ids, start=1):
        hierarchy = ET.SubElement(children, "SPEC-HIERARCHY", {"IDENTIFIER": f"SH-{index}", "LAST-CHANGE": timestamp})
        object_node = ET.SubElement(hierarchy, "OBJECT")
        ET.SubElement(object_node, "SPEC-OBJECT-REF").text = object_id
    type_node = ET.SubElement(specification, "TYPE")
    ET.SubElement(type_node, "SPECIFICATION-TYPE-REF").text = "ST-SPEC"
    ET.SubElement(content, "SPEC-RELATION-GROUPS")
    ET.SubElement(root, "TOOL-EXTENSIONS")
    return _xml(root)


def spdx3_document(analysis: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    """Return an SPDX 3.0.1 Core+Software JSON-LD declared inventory."""

    timestamp = generated_at or utc_now()
    project_name = str(analysis.get("project", {}).get("name", "python-project"))
    baseline = str(analysis.get("project", {}).get("baseline", {}).get("id", "unversioned"))
    namespace = f"https://github.com/willtran87/project-py-sfmea/spdx/{hashlib.sha256((project_name + baseline).encode()).hexdigest()[:20]}"
    agent_id = f"{namespace}#agent-pysfmea"
    creation = {"@type": "CreationInfo", "created": timestamp, "createdBy": [agent_id], "specVersion": "3.0.1", "comment": "Static declared-inventory projection; dependency resolution is incomplete."}
    project_id = f"{namespace}#package-project"
    sbom_id = f"{namespace}#sbom"
    document_id = f"{namespace}#document"
    elements: list[dict[str, Any]] = [
        {"@type": "Agent", "spdxId": agent_id, "name": "PySFMEA", "creationInfo": creation},
        {"@type": "Package", "spdxId": project_id, "name": project_name, "packageVersion": baseline, "downloadLocation": "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement", "copyrightText": "NOASSERTION", "creationInfo": creation, "comment": "Root project discovered by static repository analysis."},
    ]
    package_ids: list[str] = []
    for dependency in analysis.get("context", {}).get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("name", "unknown"))
        specification = str(dependency.get("specification", ""))
        package_id = f"{namespace}#package-{_xml_id(stable_id('DEP', name, specification)).lower()}"
        package_ids.append(package_id)
        elements.append({"@type": "Package", "spdxId": package_id, "name": name.removeprefix("manifest:"), "packageVersion": specification or "NOASSERTION", "downloadLocation": "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement", "copyrightText": "NOASSERTION", "creationInfo": creation, "sourceInfo": f"Declared in {dependency.get('source', '')}; not transitively resolved."})
    relationship_id = f"{namespace}#relationship-depends-on"
    elements.append({"@type": "Relationship", "spdxId": relationship_id, "from": project_id, "to": package_ids or ["https://spdx.org/rdf/3.0.1/terms/Core/NoneElement"], "relationshipType": "dependsOn", "completeness": "incomplete", "creationInfo": creation, "comment": "Only statically declared dependencies are represented."})
    elements.append({"@type": "Sbom", "spdxId": sbom_id, "element": [project_id, *package_ids, relationship_id], "rootElement": [project_id], "sbomType": ["design"], "creationInfo": creation})
    document = {
        "@context": SPDX_CONTEXT,
        "@type": "SpdxDocument",
        "spdxId": document_id,
        "name": f"{project_name} PySFMEA declared SBOM",
        "creationInfo": creation,
        "dataLicense": "CC0-1.0",
        "element": [sbom_id, *elements],
        "rootElement": [sbom_id],
        "comment": (
            "PySFMEA analysis state SHA-256: "
            f"{analysis_state_sha256(analysis)}; coverage: declared direct "
            "dependencies only; completeness: incomplete."
        ),
    }
    return document


def verify_exchange(
    kind: str, content: str | bytes | dict[str, Any], source: dict[str, Any]
) -> dict[str, Any]:
    """Reconcile a supported exchange artifact to its exact source object."""

    errors: list[str] = []
    structure = False
    source_binding = False
    counts = False
    try:
        if kind == "sacm":
            root = DefusedET.fromstring(content if isinstance(content, (str, bytes)) else "")
            package = root.find(f"{{{SACM_NS}}}AssuranceCasePackage")
            structure = root.tag == f"{{{XMI_NS}}}XMI" and package is not None
            source_binding = bool(package is not None and package.get(f"{{{PY_NS}}}sourceCanonicalSha256") == _source_digest(source))
            elements = root.findall(".//argumentationElement")
            artifacts = root.findall(".//artifactElement")
            counts = len(elements) == len(source.get("claims", [])) + len(source.get("arguments", [])) + len(source.get("relationships", [])) + len(source.get("defeaters", [])) and len(artifacts) == len(source.get("evidence", []))
        elif kind == "sfpm":
            root = DefusedET.fromstring(content if isinstance(content, (str, bytes)) else "")
            catalog = root.find(f"{{{SFPM_NS}}}SFPCatalog")
            structure = root.tag == f"{{{XMI_NS}}}XMI" and catalog is not None
            source_binding = bool(catalog is not None and catalog.get(f"{{{PY_NS}}}analysisStateSha256") == analysis_state_sha256(source))
            counts = len(root.findall(".//sfp")) == sum(isinstance(item, dict) and item.get("source_status", "active") == "active" for item in source.get("items", []))
        elif kind == "reqif":
            root = DefusedET.fromstring(content if isinstance(content, (str, bytes)) else "")
            structure = root.tag == f"{{{REQIF_NS}}}REQ-IF"
            values = [
                node.get("THE-VALUE", "")
                for node in root.findall(f".//{{{REQIF_NS}}}ATTRIBUTE-VALUE-STRING")
            ]
            source_binding = any(analysis_state_sha256(source) in value for value in values)
            expected = sum(isinstance(item, dict) and item.get("source_status", "active") == "active" for item in source.get("items", [])) + len([item for item in source.get("assurance", {}).get("obligations", []) if isinstance(item, dict)])
            counts = len(root.findall(f".//{{{REQIF_NS}}}SPEC-OBJECT")) == expected
        elif kind == "spdx":
            document = content if isinstance(content, dict) else json.loads(content)
            structure = bool(document.get("@context") == SPDX_CONTEXT and document.get("@type") == "SpdxDocument" and isinstance(document.get("element"), list))
            source_binding = analysis_state_sha256(source) in str(document.get("comment", ""))
            packages = [item for item in document.get("element", []) if isinstance(item, dict) and item.get("@type") == "Package"]
            counts = len(packages) == 1 + len([item for item in source.get("context", {}).get("dependencies", []) if isinstance(item, dict)])
        else:
            raise ValueError("unsupported industry exchange kind")
    except (
        ET.ParseError,
        DefusedXmlException,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        errors.append(str(exc))
    if not structure:
        errors.append("exchange structure or standards identity is invalid")
    if not source_binding:
        errors.append("exchange does not bind the exact source state")
    if not counts:
        errors.append("exchange populations do not reconcile")
    return {
        "format": "pysfmea-industry-exchange-verification-1",
        "kind": kind,
        "valid": structure and source_binding and counts,
        "checks": {"standard_structure": structure, "source_binding": source_binding, "population_reconciliation": counts},
        "errors": errors,
        "notice": "Verification covers the declared PySFMEA standards subset and exact source projection; it does not certify a receiving tool or unsupported standard features.",
    }


def export_exchange(
    kind: str,
    source: dict[str, Any],
    destination: str | Path,
    *,
    generated_at: str | None = None,
) -> Path:
    builders: dict[str, Callable[[], str | dict[str, Any]]] = {
        "sacm": lambda: sacm_xmi(source),
        "sfpm": lambda: sfpm_xmi(source),
        "reqif": lambda: reqif_document(source, generated_at=generated_at),
        "spdx": lambda: spdx3_document(source, generated_at=generated_at),
    }
    if kind not in builders:
        raise ValueError("unsupported industry exchange kind")
    content = builders[kind]()
    verdict = verify_exchange(kind, content, source)
    if not verdict["valid"]:
        raise RuntimeError("generated exchange failed verification: " + "; ".join(verdict["errors"]))
    text = json.dumps(content, indent=2, ensure_ascii=False) + "\n" if isinstance(content, dict) else content
    return atomic_publish_text(destination, text, label=f"{kind} industry exchange")


def verify_exchange_file(
    kind: str, artifact: str | Path, source: dict[str, Any]
) -> dict[str, Any]:
    path = Path(artifact).expanduser().resolve()
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_XML_BYTES:
            raise ValueError("industry exchange exceeds the byte limit")
        content: str | dict[str, Any]
        if kind == "spdx":
            content = json.loads(raw.decode("utf-8"))
        else:
            content = raw.decode("utf-8")
        return {"path": str(path), **verify_exchange(kind, content, source)}
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(path),
            "format": "pysfmea-industry-exchange-verification-1",
            "kind": kind,
            "valid": False,
            "checks": {"standard_structure": False, "source_binding": False, "population_reconciliation": False},
            "errors": [str(exc)],
            "notice": "The industry exchange could not be safely verified.",
        }
