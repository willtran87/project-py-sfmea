"""Portable, dependency-free HTML reporting for SFMEA analyses."""

from __future__ import annotations

import html
import json
import os
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .architecture import architecture_graph
from .assurance import ensure_assurance_register
from .sfta import build_sfta
from .diagrams import build_diagram_models, load_diagram_files
from .guidance import guidance_traceability
from .model import calculate_rpn, utc_now
from .validation import validate_analysis
from .visuals import coverage_metrics, sequence_model
from .version import __version__


MAX_REPORT_RECORDS = 50_000
MAX_NOTES_BYTES = 2_000_000


def _active_items(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in analysis.get("items", [])
        if item.get("source_status", "active") == "active"
    ]


def _text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(entry) for entry in value if entry not in (None, "")]


def _requirement_ids(item: dict[str, Any]) -> list[str]:
    configured = _text_list(item.get("component", {}).get("requirement_ids", []))
    reviewed = [
        part.strip()
        for line in str(item.get("review", {}).get("requirement", "")).splitlines()
        for part in line.split(",")
        if part.strip()
    ]
    return list(dict.fromkeys([*configured, *reviewed]))


def _component_groups(
    component: dict[str, Any], source: dict[str, Any] | None = None
) -> list[str]:
    explicit = _text_list(component.get("subsystems", []))
    if explicit:
        return explicit
    path = str((source or component.get("source", {})).get("path", ""))
    parts = [part for part in path.replace("\\", "/").split("/") if part]
    return [
        "/".join(parts[:2])
        if len(parts) > 1
        else (parts[0] if parts else "Unassigned")
    ]


def _report_record(
    item: dict[str, Any],
    validation_rules: list[str],
    obligations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    scanner = item.get("scanner", {})
    review = item.get("review", {})
    component = item.get("component", {})
    source = item.get("source", {})
    return {
        "id": item.get("id", ""),
        "component_id": item.get("component_id", ""),
        "source_status": item.get("source_status", "active"),
        "source_change": item.get("source_change", ""),
        "change_reasons": _text_list(item.get("change_reasons", [])),
        "path": source.get("path", ""),
        "line": source.get("line", ""),
        "end_line": source.get("end_line", ""),
        "component": component.get("qualname", ""),
        "signature": component.get("signature", ""),
        "kind": component.get("kind", ""),
        "subsystems": _component_groups(component, source),
        "requirements": _requirement_ids(item),
        "interfaces": _text_list(component.get("interface_ids", [])),
        "failure_class": scanner.get("failure_class", "unclassified"),
        "rule_id": scanner.get("rule_id", ""),
        "guideword": scanner.get("guideword", ""),
        "failure_mode": review.get("failure_mode") or scanner.get("failure_mode", ""),
        "trigger": review.get("trigger") or scanner.get("trigger", ""),
        "priority": scanner.get("screening_priority", "unrated"),
        "confidence": scanner.get("confidence", ""),
        "screening_reasons": _text_list(scanner.get("screening_reasons", [])),
        "evidence": [
            *_text_list(scanner.get("evidence", [])),
            *(
                "Guidance citation: "
                f"{link.get('citation_id', '')} [{link.get('relationship', '')}; "
                f"{link.get('applicability', '')}]"
                for link in scanner.get("citations", [])
                if isinstance(link, dict)
            ),
        ],
        "function": review.get("function", ""),
        "causes": _text_list(review.get("causes", [])),
        "local_effect": review.get("local_effect", ""),
        "next_higher_effect": review.get("next_higher_effect", ""),
        "end_effect": review.get("end_effect", ""),
        "severity": review.get("severity"),
        "severity_category": review.get("severity_category", ""),
        "severity_rationale": review.get("severity_rationale", ""),
        "occurrence": review.get("occurrence"),
        "occurrence_rationale": review.get("occurrence_rationale", ""),
        "detection": review.get("detection"),
        "detection_rationale": review.get("detection_rationale", ""),
        "rpn": calculate_rpn(item),
        "prevention_controls": _text_list(review.get("prevention_controls", [])),
        "detection_controls": _text_list(review.get("detection_controls", [])),
        "recommended_actions": _text_list(review.get("recommended_actions", [])),
        "actions_taken": _text_list(review.get("actions_taken", [])),
        "verification_evidence": _text_list(review.get("verification_evidence", [])),
        "post_action_rpn": calculate_rpn(item, post_action=True),
        "linked_hazards": _text_list(review.get("linked_hazards", [])),
        "disposition": review.get("disposition", "unreviewed"),
        "disposition_rationale": review.get("disposition_rationale", ""),
        "status": review.get("status", "draft"),
        "owner": review.get("owner", ""),
        "target_date": review.get("target_date", ""),
        "reviewer": review.get("reviewer", ""),
        "approved_by": review.get("approved_by", ""),
        "approval_date": review.get("approval_date", ""),
        "revalidation_required": bool(review.get("revalidation_required", False)),
        "notes": review.get("notes", ""),
        "validation_rules": validation_rules,
        "citations": [
            dict(link)
            for link in scanner.get("citations", [])
            if isinstance(link, dict)
        ],
        "assurance_obligations": [
            {
                "id": value.get("id", ""),
                "method": value.get("verification_method", ""),
                "status": value.get("assurance_status", ""),
                "evidence_status": value.get("evidence_status", ""),
            }
            for value in (obligations or [])
        ],
    }


def _subsystem_summary(analysis: dict[str, Any], active: list[dict[str, Any]]) -> list[dict[str, Any]]:
    component_groups: dict[str, set[str]] = defaultdict(set)
    mapped_requirements: dict[str, set[str]] = defaultdict(set)
    item_counts: Counter[str] = Counter()
    high_counts: Counter[str] = Counter()

    component_lookup = {
        component.get("id", ""): component for component in analysis.get("components", [])
    }
    for component in component_lookup.values():
        for group in _component_groups(component):
            component_groups[group].add(str(component.get("id", "")))
            mapped_requirements[group].update(_text_list(component.get("requirement_ids", [])))
    for item in active:
        component = component_lookup.get(item.get("component_id", ""), item.get("component", {}))
        for group in _component_groups(component, item.get("source", {})):
            item_counts[group] += 1
            if item.get("scanner", {}).get("screening_priority") == "high":
                high_counts[group] += 1
    return [
        {
            "name": name,
            "components": len(component_groups[name]),
            "candidates": item_counts[name],
            "high_priority": high_counts[name],
            "requirements": sorted(mapped_requirements[name]),
        }
        for name in sorted(
            component_groups,
            key=lambda value: (-item_counts[value], value.casefold()),
        )
    ]


def _catalog_summary(analysis: dict[str, Any], active: list[dict[str, Any]]) -> dict[str, Any]:
    context = analysis.get("context", {})
    items_by_requirement: Counter[str] = Counter()
    items_by_hazard: Counter[str] = Counter()
    components_by_requirement: dict[str, set[str]] = defaultdict(set)
    for component in analysis.get("components", []):
        for requirement_id in _text_list(component.get("requirement_ids", [])):
            components_by_requirement[requirement_id].add(str(component.get("id", "")))
    for item in active:
        for requirement_id in _requirement_ids(item):
            items_by_requirement[requirement_id] += 1
        for hazard_id in _text_list(item.get("review", {}).get("linked_hazards", [])):
            items_by_hazard[hazard_id] += 1
    requirements = []
    for requirement in context.get("requirements", []):
        requirement_id = str(requirement.get("id", ""))
        requirements.append(
            {
                "id": requirement_id,
                "text": requirement.get("text", ""),
                "source": requirement.get("source", ""),
                "hazards": _text_list(requirement.get("hazards", [])),
                "components": len(components_by_requirement[requirement_id]),
                "candidates": items_by_requirement[requirement_id],
            }
        )
    hazards = [
        {
            "id": hazard.get("id", ""),
            "description": hazard.get("description", ""),
            "end_effect": hazard.get("end_effect", ""),
            "severity": hazard.get("severity", ""),
            "candidates": items_by_hazard[str(hazard.get("id", ""))],
        }
        for hazard in context.get("hazards", [])
    ]
    return {"requirements": requirements, "hazards": hazards}


def _sequence_summaries(analysis: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    candidates = [
        component
        for component in analysis.get("components", [])
        if component.get("kind") not in {"environment", "common_cause", "contract"}
    ]
    candidates.sort(
        key=lambda component: (
            -bool(component.get("entrypoint_types")),
            -int(component.get("screening", {}).get("score", 0) or 0),
            -int(component.get("fan_in", 0) or 0),
            str(component.get("source", {}).get("path", "")),
            str(component.get("qualname", "")),
        )
    )
    selected: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for component in candidates:
        path = str(component.get("source", {}).get("path", ""))
        if path in seen_paths and len(selected) < max(2, limit // 2):
            continue
        try:
            model = sequence_model(
                analysis,
                str(component.get("id", "")),
                max_depth=5,
                max_interactions=40,
            )
        except ValueError:
            continue
        if not model.get("interactions"):
            continue
        model["title"] = component.get("qualname", "")
        model["path"] = path
        selected.append(model)
        seen_paths.add(path)
        if len(selected) >= limit:
            break
    return selected


def build_html_report_data(
    analysis: dict[str, Any],
    *,
    max_records: int = 10_000,
    notes_text: str = "",
    custom_diagrams: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the bounded JSON model embedded into a standalone report."""

    if not 1 <= max_records <= MAX_REPORT_RECORDS:
        raise ValueError(f"max_records must be from 1 through {MAX_REPORT_RECORDS}")
    active = _active_items(analysis)
    validation = validate_analysis(analysis)
    rules_by_item: dict[str, list[str]] = defaultdict(list)
    rule_counts: Counter[str] = Counter()
    project_findings: list[dict[str, Any]] = []
    for finding in validation.get("findings", []):
        rule_id = str(finding.get("rule_id", ""))
        rule_counts[rule_id] += 1
        item_id = str(finding.get("item_id", ""))
        if item_id:
            rules_by_item[item_id].append(rule_id)
        elif len(project_findings) < 100:
            project_findings.append(
                {
                    "level": finding.get("level", "information"),
                    "rule_id": rule_id,
                    "message": finding.get("message", ""),
                }
            )

    priority_order = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(
        analysis.get("items", []),
        key=lambda item: (
            item.get("source_status", "active") != "active",
            priority_order.get(item.get("scanner", {}).get("screening_priority", ""), 3),
            item.get("review", {}).get("disposition", "unreviewed") != "unreviewed",
            str(item.get("source", {}).get("path", "")),
            int(item.get("source", {}).get("line", 0) or 0),
            str(item.get("id", "")),
        ),
    )
    selected = ordered[:max_records]
    graph = architecture_graph(analysis)
    edge_counts = Counter(str(edge.get("kind", "unknown")) for edge in graph.get("edges", []))
    context = analysis.get("context", {})
    methodology = analysis.get("methodology", {})
    coverage = coverage_metrics(analysis)
    guidance_trace = guidance_traceability(analysis)
    assurance = ensure_assurance_register(analysis)
    sfta = build_sfta(analysis)
    obligations_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obligation in assurance.get("obligations", []):
        if isinstance(obligation, dict):
            obligations_by_finding[str(obligation.get("finding_id", ""))].append(
                obligation
            )
    selected_obligation_ids = {
        obligation.get("id")
        for item in selected
        for obligation in obligations_by_finding[str(item.get("id", ""))]
    }
    diagrams = [*build_diagram_models(analysis), *(custom_diagrams or [])]
    diagram_ids = [diagram.get("id", "") for diagram in diagrams]
    if len(diagram_ids) != len(set(diagram_ids)):
        raise ValueError("generated and imported diagram IDs must be unique")
    return {
        "report": {
            "generated_at": utc_now(),
            "generator": f"PySFMEA {__version__}",
            "embedded_records": len(selected),
            "total_records": len(ordered),
            "records_truncated": len(selected) < len(ordered),
            "notes": notes_text,
        },
        "project": {
            "name": analysis.get("project", {}).get("name", "Python project"),
            "root": analysis.get("project", {}).get("root", ""),
            "scanned_at": analysis.get("project", {}).get("scanned_at", ""),
            "baseline": analysis.get("project", {}).get("baseline", {}),
            "purpose": context.get("project", {}).get("purpose", ""),
            "boundary": context.get("project", {}).get("boundary", ""),
            "operating_context": context.get("project", {}).get("operating_context", ""),
            "phase": context.get("analysis", {}).get("phase", ""),
            "revision": context.get("analysis", {}).get("revision", ""),
            "ground_rules": _text_list(context.get("analysis", {}).get("ground_rules", [])),
            "assumptions": [
                *_text_list(context.get("project", {}).get("assumptions", [])),
                *_text_list(context.get("analysis", {}).get("fault_tolerance_assumptions", [])),
            ],
        },
        "summary": analysis.get("summary", {}),
        "coverage": coverage,
        "validation": {
            "counts": validation.get("counts", {}),
            "top_rules": [
                {"rule_id": rule_id, "count": count}
                for rule_id, count in rule_counts.most_common(12)
            ],
            "project_findings": project_findings,
        },
        "distributions": {
            "failure_classes": dict(Counter(str(item.get("scanner", {}).get("failure_class", "unclassified")) for item in active)),
            "priorities": dict(Counter(str(item.get("scanner", {}).get("screening_priority", "unrated")) for item in active)),
            "dispositions": dict(Counter(str(item.get("review", {}).get("disposition", "unreviewed")) for item in active)),
            "statuses": dict(Counter(str(item.get("review", {}).get("status", "draft")) for item in active)),
        },
        "records": [
            _report_record(
                item,
                sorted(set(rules_by_item[str(item.get("id", ""))])),
                obligations_by_finding[str(item.get("id", ""))],
            )
            for item in selected
        ],
        "assurance": {
            "schema_version": assurance.get("schema_version", ""),
            "planner_version": assurance.get("planner_version", ""),
            "notice": assurance.get("notice", ""),
            "summary": assurance.get("summary", {}),
            "obligations": [
                obligation
                for item in selected
                for obligation in obligations_by_finding[str(item.get("id", ""))]
            ],
            "executions": [
                execution
                for execution in assurance.get("executions", [])
                if execution.get("obligation_id") in selected_obligation_ids
            ],
            "evidence_artifacts": assurance.get("evidence_artifacts", []),
        },
        "sfta": sfta,
        "run_manifest": analysis.get("run_manifest", {}),
        "subsystems": _subsystem_summary(analysis, active),
        "catalog": _catalog_summary(analysis, active),
        "interfaces": [
            {
                "id": interface.get("id", ""),
                "source": interface.get("source", ""),
                "target": interface.get("target", ""),
                "description": interface.get("description", ""),
                "data": _text_list(interface.get("data", [])),
                "assumptions": _text_list(interface.get("assumptions", [])),
            }
            for interface in context.get("system_interfaces", [])
        ],
        "architecture": {
            "nodes": len(graph.get("nodes", [])),
            "edges": len(graph.get("edges", [])),
            "edge_counts": dict(edge_counts),
            "runtime_imports": len(analysis.get("runtime_evidence", {}).get("imports", [])),
        },
        "sequences": _sequence_summaries(analysis),
        "diagrams": diagrams,
        "guidance": {
            "schema_version": guidance_trace["schema_version"],
            "catalog_version": guidance_trace["catalog_version"],
            "catalog_sha256": guidance_trace["catalog_sha256"],
            "retrieved_at": guidance_trace["retrieved_at"],
            "profiles": guidance_trace.get("profiles", []),
            "active_profiles": guidance_trace.get("active_profiles", []),
            "selection_sha256": guidance_trace.get("selection_sha256", ""),
            "sources": guidance_trace["sources"],
            "citations": guidance_trace["citations"],
            "rule_mappings": guidance_trace["rule_mappings"],
            "coverage": guidance_trace["coverage"],
            "notice": guidance_trace["notice"],
        },
        "methodology": {
            "notice": methodology.get("notice", ""),
            "basis": methodology.get("basis", []),
            "limitations": [
                *coverage.get("limitations", []),
                "Scanner candidates are prompts for engineering review, not confirmed defects or accepted risks.",
                "Static call and sequence evidence is conservative and can omit dynamic dispatch, generated code, runtime wiring, and unobserved paths.",
            ],
        },
    }


def _safe_json(data: dict[str, Any]) -> str:
    return (
        json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def export_html_report(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    title: str | None = None,
    notes: str | Path | None = None,
    max_records: int = 10_000,
    diagrams: Iterable[str | Path] | None = None,
) -> Path:
    """Write an atomic, self-contained, interactive SFMEA HTML report."""

    notes_text = ""
    if notes:
        notes_path = Path(notes).expanduser().resolve()
        if not notes_path.is_file():
            raise ValueError(f"report notes file does not exist: {notes_path}")
        if notes_path.stat().st_size > MAX_NOTES_BYTES:
            raise ValueError(f"report notes file exceeds {MAX_NOTES_BYTES} bytes")
        notes_text = notes_path.read_text(encoding="utf-8")
    custom_diagrams = load_diagram_files(diagrams or [])
    data = build_html_report_data(
        analysis,
        max_records=max_records,
        notes_text=notes_text,
        custom_diagrams=custom_diagrams,
    )
    report_title = title or f"Software FMEA - {data['project']['name']}"
    document = (
        _REPORT_TEMPLATE.replace("__REPORT_TITLE__", html.escape(report_title, quote=True))
        .replace("__REPORT_DATA__", _safe_json(data))
    )
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(document, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


_REPORT_TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>__REPORT_TITLE__</title>
<style>
:root{--ink:#172033;--muted:#647089;--paper:#f5f7fb;--card:#fff;--line:#dce2ec;--brand:#2457d6;--brand2:#163a91;--cyan:#0d8d96;--amber:#a65f00;--red:#b52d3b;--green:#14734a;--violet:#7047b8;--shadow:0 12px 30px rgba(28,42,75,.08);--radius:16px;--mono:ui-monospace,SFMono-Regular,Consolas,monospace;--sans:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
[data-theme="dark"]{--ink:#e8edf8;--muted:#a9b5cb;--paper:#0d1423;--card:#141e31;--line:#2d3a52;--brand:#82a8ff;--brand2:#b7cbff;--cyan:#64d1d2;--amber:#f2b35c;--red:#ff8d9b;--green:#68d3a2;--violet:#c1a3ff;--shadow:0 12px 34px rgba(0,0,0,.25)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 var(--sans)}button,input,select{font:inherit;color:inherit}button{cursor:pointer}.shell{min-height:100vh;display:grid;grid-template-columns:250px minmax(0,1fr)}.sidebar{position:sticky;top:0;height:100vh;padding:24px 16px;background:var(--card);border-right:1px solid var(--line);overflow:auto;z-index:4}.brand{padding:0 10px 22px}.brand-mark{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:12px;color:#fff;background:linear-gradient(135deg,#183f9c,#0c929a);font-weight:900;letter-spacing:-.5px;box-shadow:var(--shadow)}.brand h1{font-size:17px;margin:12px 0 2px;line-height:1.2}.brand p{margin:0;color:var(--muted);font-size:12px}.nav{display:grid;gap:4px}.nav button{border:0;background:transparent;text-align:left;padding:10px 12px;border-radius:10px;color:var(--muted);display:flex;gap:10px;align-items:center}.nav button:hover,.nav button:focus-visible{background:color-mix(in srgb,var(--brand) 8%,transparent);color:var(--ink)}.nav button.active{background:color-mix(in srgb,var(--brand) 13%,transparent);color:var(--brand2);font-weight:700}.nav .icon{width:20px;text-align:center}.side-foot{margin-top:24px;padding:14px 10px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}.main{min-width:0}.topbar{position:sticky;top:0;z-index:3;display:flex;justify-content:space-between;align-items:center;gap:14px;padding:12px 28px;background:color-mix(in srgb,var(--paper) 86%,transparent);backdrop-filter:blur(14px);border-bottom:1px solid color-mix(in srgb,var(--line) 75%,transparent)}.crumb{min-width:0}.crumb strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.crumb span{font-size:12px;color:var(--muted)}.actions{display:flex;gap:8px}.btn{border:1px solid var(--line);background:var(--card);border-radius:10px;padding:8px 11px;font-weight:650}.btn:hover,.btn:focus-visible{border-color:var(--brand);box-shadow:0 0 0 3px color-mix(in srgb,var(--brand) 15%,transparent)}.btn.primary{background:var(--brand2);color:#fff;border-color:transparent}.content{max-width:1520px;margin:auto;padding:26px 30px 70px}.view[hidden]{display:none}.hero{position:relative;overflow:hidden;padding:34px;border-radius:22px;background:linear-gradient(125deg,#102d70 0%,#2457d6 52%,#0a858f 100%);color:#fff;box-shadow:var(--shadow)}.hero:after{content:"";position:absolute;width:380px;height:380px;border:70px solid rgba(255,255,255,.06);border-radius:50%;right:-130px;top:-180px}.eyebrow{text-transform:uppercase;letter-spacing:.13em;font-weight:800;font-size:11px;opacity:.76}.hero h2{font-size:clamp(27px,3.2vw,47px);line-height:1.05;letter-spacing:-.035em;max-width:900px;margin:8px 0 12px}.hero p{max-width:900px;font-size:15px;opacity:.88;margin:0}.hero-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:22px}.hero-meta span{padding:6px 9px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);border-radius:8px;font-size:12px}.notice{margin:18px 0;padding:14px 16px;border:1px solid color-mix(in srgb,var(--amber) 40%,var(--line));border-left:4px solid var(--amber);background:color-mix(in srgb,var(--amber) 8%,var(--card));border-radius:10px}.notice strong{color:var(--amber)}.metrics{display:grid;grid-template-columns:repeat(6,minmax(125px,1fr));gap:12px;margin:18px 0}.metric{padding:17px;background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}.metric b{display:block;font-size:27px;line-height:1.1;letter-spacing:-.04em}.metric span{display:block;color:var(--muted);font-size:12px;margin-top:5px}.metric.danger b{color:var(--red)}.metric.good b{color:var(--green)}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:16px}.grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);min-width:0}.card h3,.section-head h2{margin:0;letter-spacing:-.02em}.card h3{font-size:16px}.card-head{display:flex;justify-content:space-between;align-items:start;gap:12px;margin-bottom:15px}.card-head p,.section-head p{color:var(--muted);margin:4px 0 0}.section-head{display:flex;justify-content:space-between;align-items:end;gap:18px;margin:2px 0 20px}.section-head h2{font-size:29px}.section-head p{max-width:760px}.bars{display:grid;gap:11px}.bar-row{display:grid;grid-template-columns:minmax(90px,1fr) 4fr 52px;gap:10px;align-items:center}.bar-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:12px}.bar-track{height:9px;border-radius:9px;background:color-mix(in srgb,var(--line) 65%,transparent);overflow:hidden}.bar-fill{height:100%;min-width:2px;border-radius:9px;background:linear-gradient(90deg,var(--brand),var(--cyan))}.bar-value{text-align:right;font-variant-numeric:tabular-nums;font-weight:750}.coverage-row{display:grid;grid-template-columns:130px 1fr 65px;gap:12px;align-items:center;margin:12px 0}.coverage-track{height:13px;background:color-mix(in srgb,var(--line) 70%,transparent);border-radius:9px;overflow:hidden}.coverage-fill{height:100%;background:var(--green)}.coverage-value{text-align:right;font-weight:750}.finding{padding:11px 0;border-bottom:1px solid var(--line)}.finding:last-child{border-bottom:0}.finding code,.mono{font-family:var(--mono);font-size:12px}.tag{display:inline-flex;align-items:center;gap:4px;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:760;background:color-mix(in srgb,var(--muted) 12%,transparent);color:var(--muted);white-space:nowrap}.tag.high,.tag.error{color:var(--red);background:color-mix(in srgb,var(--red) 12%,transparent)}.tag.medium,.tag.warning{color:var(--amber);background:color-mix(in srgb,var(--amber) 13%,transparent)}.tag.accepted,.tag.closed,.tag.pass{color:var(--green);background:color-mix(in srgb,var(--green) 12%,transparent)}.tag.info{color:var(--brand);background:color-mix(in srgb,var(--brand) 12%,transparent)}.filter-panel{display:grid;grid-template-columns:minmax(250px,2fr) repeat(5,minmax(120px,1fr));gap:10px;padding:14px;background:var(--card);border:1px solid var(--line);border-radius:var(--radius);margin-bottom:14px}.field label{display:block;color:var(--muted);font-size:11px;font-weight:750;margin:0 0 5px}.field input,.field select{width:100%;border:1px solid var(--line);background:var(--paper);border-radius:9px;padding:9px 10px;outline:0}.field input:focus,.field select:focus{border-color:var(--brand);box-shadow:0 0 0 3px color-mix(in srgb,var(--brand) 13%,transparent)}.table-wrap{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);overflow:auto;box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;min-width:1000px}th{position:sticky;top:0;z-index:1;background:var(--card);text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:12px;border-bottom:1px solid var(--line)}td{padding:12px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr{cursor:pointer}tbody tr:hover,tbody tr:focus-within{background:color-mix(in srgb,var(--brand) 5%,transparent)}td.failure{max-width:430px}.small{font-size:12px;color:var(--muted)}.table-foot{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 4px}.pager{display:flex;gap:7px}.empty{padding:35px;text-align:center;color:var(--muted)}.flow-list{display:grid;gap:12px}.flow{display:grid;grid-template-columns:minmax(120px,1fr) 50px minmax(120px,1fr) 2fr;gap:12px;align-items:center;padding:14px;border:1px solid var(--line);border-radius:12px}.flow-node{padding:10px;border-radius:9px;background:color-mix(in srgb,var(--brand) 9%,var(--paper));font-weight:720;text-align:center}.flow-arrow{font-size:22px;color:var(--cyan);text-align:center}.flow p{margin:0;color:var(--muted)}.subsystem-grid,.catalog-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.subsystem,.catalog-card{border:1px solid var(--line);border-radius:13px;padding:15px;background:var(--card)}.subsystem h3,.catalog-card h3{font-size:14px;margin:0 0 10px;overflow-wrap:anywhere}.compact-metrics{display:flex;gap:14px;flex-wrap:wrap}.compact-metrics b{font-size:20px;display:block}.compact-metrics span{color:var(--muted);font-size:11px}.sequence-select{max-width:620px;width:100%;padding:10px;border:1px solid var(--line);background:var(--card);border-radius:10px}.sequence-meta{margin:14px 0;color:var(--muted)}.sequence-diagram{position:relative;display:grid;gap:8px}.interaction{display:grid;grid-template-columns:42px minmax(150px,1fr) 80px minmax(150px,1fr) 115px;gap:10px;align-items:center;padding:9px 11px;border:1px solid var(--line);border-radius:11px;background:var(--card)}.step{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:var(--brand2);color:#fff;font-weight:800}.actor{font-family:var(--mono);font-size:12px;overflow-wrap:anywhere}.arrow{text-align:center;color:var(--cyan);font-weight:800}.evidence-kind{text-align:right}.trace-row{display:grid;grid-template-columns:minmax(240px,1.25fr) 70px minmax(220px,1fr);gap:12px;align-items:center;padding:13px;border-bottom:1px solid var(--line)}.trace-row:last-child{border-bottom:0}.trace-arrow{text-align:center;color:var(--violet);font-size:20px}.hazard-chips{display:flex;flex-wrap:wrap;gap:6px}.prose{max-width:1000px}.prose h3{margin:24px 0 7px}.prose p{color:var(--muted)}.prose li{margin:6px 0}.notes-content>*:first-child{margin-top:0}.notes-content pre{white-space:pre-wrap;font-family:var(--sans)}dialog{width:min(900px,calc(100vw - 30px));max-height:90vh;padding:0;border:1px solid var(--line);border-radius:18px;background:var(--card);color:var(--ink);box-shadow:0 30px 90px rgba(0,0,0,.35)}dialog::backdrop{background:rgba(8,14,27,.65);backdrop-filter:blur(4px)}.dialog-head{position:sticky;top:0;display:flex;justify-content:space-between;gap:15px;padding:19px 22px;background:var(--card);border-bottom:1px solid var(--line);z-index:1}.dialog-head h2{font-size:20px;margin:0}.dialog-body{padding:22px}.detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.detail{padding:13px;border:1px solid var(--line);border-radius:11px}.detail.wide{grid-column:1/-1}.detail h3{margin:0 0 6px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.detail p{margin:0;white-space:pre-wrap}.detail ul{margin:0;padding-left:18px}.close{border:0;background:transparent;font-size:24px;line-height:1}.muted{color:var(--muted)}.mobile-menu{display:none}
.diagram-toolbar{display:grid;grid-template-columns:minmax(260px,2fr) minmax(160px,1fr) minmax(180px,1fr) auto;gap:10px;align-items:end;margin-bottom:14px}.diagram-workspace{display:grid;grid-template-columns:minmax(0,1fr) 290px;gap:14px;align-items:start}.diagram-stage{position:relative;min-height:570px;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}.diagram-stage svg{display:block;max-width:none}.diagram-node{cursor:pointer;outline:none;transition:opacity .15s}.diagram-node rect{fill:color-mix(in srgb,var(--brand) 9%,var(--card));stroke:color-mix(in srgb,var(--brand) 48%,var(--line));stroke-width:1.5}.diagram-node[data-kind="hazard"] rect,.diagram-node[data-kind="failure_mode"] rect,.diagram-node[data-kind="end_effect"] rect{fill:color-mix(in srgb,var(--red) 10%,var(--card));stroke:color-mix(in srgb,var(--red) 52%,var(--line))}.diagram-node[data-kind="requirement"] rect,.diagram-node[data-kind="prevention_control"] rect,.diagram-node[data-kind="detection_control"] rect,.diagram-node[data-kind="verification_evidence"] rect{fill:color-mix(in srgb,var(--green) 10%,var(--card));stroke:color-mix(in srgb,var(--green) 48%,var(--line))}.diagram-node[data-kind="boundary"] rect,.diagram-node[data-kind="participant"] rect{fill:color-mix(in srgb,var(--cyan) 10%,var(--card));stroke:color-mix(in srgb,var(--cyan) 48%,var(--line))}.diagram-node[data-kind="recommended_action"] rect,.diagram-node[data-kind="next_higher_effect"] rect{fill:color-mix(in srgb,var(--amber) 11%,var(--card));stroke:color-mix(in srgb,var(--amber) 52%,var(--line))}.diagram-node:hover rect,.diagram-node:focus rect,.diagram-node.selected rect{stroke:var(--brand);stroke-width:3}.diagram-node.dim,.diagram-edge.dim{opacity:.12}.diagram-node text{fill:var(--ink);font-family:var(--sans);font-size:12px;font-weight:650;pointer-events:none}.diagram-edge{color:color-mix(in srgb,var(--muted) 75%,transparent);transition:opacity .15s}.diagram-edge path{fill:none;stroke:currentColor;stroke-width:1.5}.diagram-edge.runtime{color:var(--green)}.diagram-edge text{fill:var(--muted);font:11px var(--sans);paint-order:stroke;stroke:var(--card);stroke-width:5px;stroke-linejoin:round}.diagram-lifeline{stroke:var(--line);stroke-width:1;stroke-dasharray:5 5}.diagram-inspector{position:sticky;top:75px;min-height:260px}.diagram-inspector h3{margin:0 0 6px;font-size:16px}.diagram-inspector dl{display:grid;grid-template-columns:78px 1fr;gap:7px 10px;margin:14px 0}.diagram-inspector dt{color:var(--muted);font-size:11px;font-weight:750}.diagram-inspector dd{margin:0;overflow-wrap:anywhere}.diagram-inspector ul{padding-left:18px}.diagram-legend{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.diagram-status{display:flex;flex-wrap:wrap;gap:12px;color:var(--muted);font-size:12px;margin:8px 0 14px}.diagram-zoom{display:flex;gap:5px}.diagram-empty{display:grid;place-items:center;min-height:500px;color:var(--muted);padding:30px;text-align:center}
.citation-card a,.citation-list a,.prose a{color:var(--brand);font-weight:700;text-decoration:none}.citation-card a:hover,.citation-list a:hover,.prose a:hover{text-decoration:underline}.citation-card p{margin:8px 0;color:var(--muted)}.citation-list{display:grid;gap:10px}.citation-entry{padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--paper)}.citation-entry p{margin:5px 0}.citation-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(3,1fr)}.filter-panel{grid-template-columns:repeat(3,1fr)}.field.search{grid-column:span 3}.subsystem-grid,.catalog-grid{grid-template-columns:repeat(2,1fr)}.diagram-workspace{grid-template-columns:1fr}.diagram-inspector{position:static}.diagram-toolbar{grid-template-columns:1fr 1fr}.diagram-toolbar .diagram-picker{grid-column:1/-1}}
@media(max-width:760px){.shell{display:block}.sidebar{position:fixed;left:-270px;width:250px;transition:left .2s;box-shadow:var(--shadow)}body.menu-open .sidebar{left:0}.mobile-menu{display:inline-block}.topbar{padding:10px 14px}.content{padding:18px 14px 60px}.hero{padding:25px}.metrics,.grid,.grid.three{grid-template-columns:1fr 1fr}.filter-panel{grid-template-columns:1fr 1fr}.field.search{grid-column:1/-1}.subsystem-grid,.catalog-grid{grid-template-columns:1fr}.flow{grid-template-columns:1fr 35px 1fr}.flow p{grid-column:1/-1}.interaction{grid-template-columns:35px 1fr 45px 1fr}.evidence-kind{grid-column:2/-1;text-align:left}.trace-row{grid-template-columns:1fr}.trace-arrow{text-align:left;transform:rotate(90deg)}.detail-grid{grid-template-columns:1fr}.detail.wide{grid-column:auto}.diagram-toolbar{grid-template-columns:1fr}.diagram-toolbar .diagram-picker{grid-column:auto}.diagram-stage{min-height:470px}}
@media(max-width:480px){.metrics,.grid,.grid.three{grid-template-columns:1fr}.filter-panel{grid-template-columns:1fr}.field.search{grid-column:auto}.actions .label{display:none}}
@media print{body{background:#fff;color:#111;font-size:10pt}.shell{display:block}.sidebar,.topbar,.filter-panel,.table-foot,.no-print{display:none!important}.content{max-width:none;padding:0}.view[hidden]{display:block!important;break-before:page}.hero{color:#111;background:#fff;border:1px solid #bbb;box-shadow:none}.hero:after{display:none}.hero-meta span{border-color:#bbb;background:#fff}.card,.metric,.table-wrap{box-shadow:none}.citation-list{display:block}.citation-entry{margin-bottom:10px}.metric,.citation-entry,.catalog-card,.finding,.flow,.trace-row{break-inside:avoid;page-break-inside:avoid}[data-view="run-manifest"] .grid{grid-template-columns:1fr}.section-head{margin-top:24px}dialog{display:none}.table-wrap{overflow:visible}table{min-width:0;font-size:8pt}}
</style>
</head>
<body>
<div class="shell">
<aside class="sidebar" aria-label="Report navigation">
  <div class="brand"><span class="brand-mark">SF</span><h1 id="sideProject">Software FMEA</h1><p>Interactive analysis report</p></div>
  <nav class="nav" id="nav">
    <button data-view="run-manifest"><span class="icon">R</span>Run manifest</button>
    <button data-view="sfta"><span class="icon">T</span>Hazards and SFTA</button>
    <button data-view="overview" class="active"><span class="icon">◫</span>Overview</button>
    <button data-view="findings"><span class="icon">◎</span>Review findings</button>
    <button data-view="failure-modes"><span class="icon">≡</span>Failure modes</button>
    <button data-view="assurance"><span class="icon">✓</span>Assurance checklist</button>
    <button data-view="architecture"><span class="icon">◇</span>Architecture</button>
    <button data-view="traceability"><span class="icon">↔</span>Traceability</button>
    <button data-view="sequences"><span class="icon">⇢</span>Sequences</button>
    <button data-view="diagrams"><span class="icon">⌘</span>Diagram explorer</button>
    <button data-view="guidance"><span class="icon">§</span>Guidance citations</button>
    <button data-view="methodology"><span class="icon">i</span>Methodology</button>
  </nav>
  <div class="side-foot"><div id="sideVersion"></div><div id="sideGenerated"></div><div>Offline · self-contained</div></div>
</aside>
<main class="main">
  <header class="topbar"><button class="btn mobile-menu" id="menuButton" aria-label="Open navigation">☰</button><div class="crumb"><strong id="topTitle"></strong><span id="topSubtitle"></span></div><div class="actions"><button class="btn" id="themeButton" aria-label="Toggle color theme">◐ <span class="label">Theme</span></button><button class="btn primary" id="printButton">Print / PDF</button></div></header>
  <div class="content">
    <section class="view" data-view="overview">
      <div class="hero"><div class="eyebrow">Software failure mode and effects analysis</div><h2 id="heroTitle"></h2><p id="heroPurpose"></p><div class="hero-meta" id="heroMeta"></div></div>
      <div class="notice"><strong>Review status:</strong> <span id="methodNotice"></span></div>
      <div class="metrics" id="metrics"></div>
      <div class="grid"><div class="card"><div class="card-head"><div><h3>Review coverage</h3><p>Completion and catalog linkage, not analytical sufficiency.</p></div></div><div id="coverageBars"></div></div><div class="card"><div class="card-head"><div><h3>Candidate priority</h3><p>Automated screening order for engineering review.</p></div></div><div class="bars" id="priorityBars"></div></div></div>
      <div class="grid"><div class="card"><div class="card-head"><div><h3>Failure classes</h3><p>Distribution of active candidate prompts.</p></div></div><div class="bars" id="classBars"></div></div><div class="card"><div class="card-head"><div><h3>Quality-gate findings</h3><p>Most frequent validation rules.</p></div></div><div class="bars" id="validationBars"></div></div></div>
    </section>
    <section class="view" data-view="findings" hidden><div class="section-head"><div><h2>Review findings</h2><p>Project-level quality gates and optional engineering notes supplied with this report.</p></div></div><div class="grid"><div class="card"><div class="card-head"><h3>Project quality gates</h3></div><div id="projectFindings"></div></div><div class="card"><div class="card-head"><h3>Validation distribution</h3></div><div class="bars" id="findingRuleBars"></div></div></div><div class="card" style="margin-top:16px"><div class="card-head"><div><h3>Engineering review notes</h3><p>These notes may contain preliminary leads; confirm each against source and system context.</p></div></div><div class="prose notes-content" id="notesContent"></div></div></section>
    <section class="view" data-view="failure-modes" hidden><div class="section-head"><div><h2>Failure-mode explorer</h2><p>Search, filter, and open any embedded candidate to inspect its evidence, effects, controls, actions, and review state.</p></div><button class="btn no-print" id="csvButton">Export filtered CSV</button></div><div class="filter-panel no-print"><div class="field search"><label for="search">Search</label><input id="search" type="search" placeholder="ID, component, path, failure mode, effect…"></div><div class="field"><label for="priorityFilter">Priority</label><select id="priorityFilter"></select></div><div class="field"><label for="classFilter">Failure class</label><select id="classFilter"></select></div><div class="field"><label for="dispositionFilter">Disposition</label><select id="dispositionFilter"></select></div><div class="field"><label for="hazardFilter">Hazard</label><select id="hazardFilter"></select></div><div class="field"><label for="subsystemFilter">Subsystem</label><select id="subsystemFilter"></select></div></div><div class="table-wrap"><table><thead><tr><th>Priority</th><th>ID / state</th><th>Component / source</th><th>Failure mode</th><th>Class</th><th>Review</th><th>S/O/D · RPN</th></tr></thead><tbody id="recordRows"></tbody></table><div class="empty" id="recordEmpty" hidden>No records match the current filters.</div></div><div class="table-foot"><span id="recordCount"></span><div class="pager"><button class="btn" id="prevPage">Previous</button><button class="btn" id="nextPage">Next</button></div></div></section>
    <section class="view" data-view="assurance" hidden><div class="section-head"><div><h2>Executable assurance checklist</h2><p>Failure-mode verification obligations with explicit stimuli, oracles, acceptance criteria, sandbox commands, and evidence requirements.</p></div></div><div class="notice"><strong>Evidence boundary:</strong> <span id="assuranceNotice"></span></div><div class="metrics" id="assuranceMetrics"></div><div class="card"><div class="card-head"><div><h3>Verification obligation register</h3><p id="assuranceCount"></p></div></div><div class="citation-list" id="assuranceRows"></div></div><div class="card" style="margin-top:16px"><div class="card-head"><div><h3>As-run evidence</h3><p>Sandbox and imported executions remain unreviewed until every original acceptance criterion is adjudicated independently.</p></div></div><div class="citation-list" id="assuranceExecutions"></div></div></section>
    <section class="view" data-view="architecture" hidden><div class="section-head"><div><h2>Architecture and boundaries</h2><p>Configured system interfaces plus source-derived subsystem and call-graph summaries.</p></div></div><div class="metrics" id="architectureMetrics"></div><div class="card"><div class="card-head"><div><h3>System-interface flow</h3><p>Configured boundary statements. Arrow direction follows the supplied source and target.</p></div></div><div class="flow-list" id="interfaceFlows"></div></div><div class="section-head" style="margin-top:28px"><div><h2>Subsystem inventory</h2><p>Explicit subsystem mappings are used where present; otherwise the report groups components by source path.</p></div></div><div class="subsystem-grid" id="subsystemGrid"></div></section>
    <section class="view" data-view="traceability" hidden><div class="section-head"><div><h2>Requirement and hazard traceability</h2><p>Configured requirement-to-hazard relationships with mapped component and candidate counts.</p></div></div><div class="card"><div id="traceRows"></div></div><div class="section-head" style="margin-top:28px"><div><h2>Hazard catalog</h2><p>Candidate counts reflect current record links, not confirmation that a failure contributes to a hazard.</p></div></div><div class="catalog-grid" id="hazardGrid"></div></section>
    <section class="view" data-view="sequences" hidden><div class="section-head"><div><h2>Sequence explorer</h2><p>Bounded, automatically selected call sequences. Static order is approximate; observed edges represent captured execution only.</p></div></div><select class="sequence-select" id="sequenceSelect" aria-label="Select sequence"></select><div class="sequence-meta" id="sequenceMeta"></div><div class="sequence-diagram" id="sequenceDiagram"></div></section>
    <section class="view" data-view="diagrams" hidden><div class="section-head"><div><h2>General diagram explorer</h2><p>Renderer-neutral architecture, interface, traceability, propagation, control, sequence, state, and custom diagram models rendered as local inline SVG.</p></div><button class="btn no-print" id="diagramDownload">Download SVG</button></div><div class="diagram-toolbar no-print"><div class="field diagram-picker"><label for="diagramSelect">Diagram</label><select id="diagramSelect"></select></div><div class="field"><label for="diagramKindFilter">Element type</label><select id="diagramKindFilter"></select></div><div class="field"><label for="diagramSearch">Find an element</label><input id="diagramSearch" type="search" placeholder="Label, ID, source, or tag"></div><div class="diagram-zoom"><button class="btn" id="diagramZoomOut" aria-label="Zoom out">−</button><button class="btn" id="diagramZoomFit">Fit</button><button class="btn" id="diagramZoomIn" aria-label="Zoom in">+</button></div></div><div class="diagram-status" id="diagramStatus"></div><div class="notice" id="diagramNotice"></div><div class="diagram-workspace"><div class="diagram-stage" id="diagramStage" aria-live="polite"></div><aside class="card diagram-inspector" id="diagramInspector"><h3>Diagram details</h3><p class="muted">Select a node to inspect its evidence and relationships.</p><div class="diagram-legend" id="diagramLegend"></div></aside></div></section>
    <section class="view" data-view="guidance" hidden><div class="section-head"><div><h2>Guidance-to-finding traceability</h2><p>Versioned authoritative sources and exact locators connected through curated rules to candidate findings.</p></div></div><div class="notice"><strong>Interpretation:</strong> <span id="guidanceNotice"></span></div><div class="metrics" id="guidanceMetrics"></div><div class="section-head" style="margin-top:28px"><div><h2>Selected applicability profiles</h2><p>Only selected profiles contribute citations to findings. A citation is an analysis aid, not a compliance determination.</p></div></div><div class="catalog-grid" id="guidanceProfiles"></div><div class="section-head" style="margin-top:28px"><div><h2>Source catalog</h2><p>Status, integrity, and applicability are explicit. Legacy or domain-specific material is never presented as universal compliance.</p></div></div><div class="catalog-grid" id="guidanceSources"></div><div class="section-head" style="margin-top:28px"><div><h2>Used citation locators</h2><p>Each locator is curated and versioned; usage counts show how many active findings inherit the relationship.</p></div></div><div class="card"><div class="citation-list" id="guidanceCitations"></div></div></section>
    <section class="view" data-view="methodology" hidden><div class="section-head"><div><h2>Methodology and limitations</h2><p>How to interpret this report and what must remain a human engineering decision.</p></div></div><div class="grid"><div class="card prose"><h3>System boundary</h3><p id="boundaryText"></p><h3>Operating context</h3><p id="operatingText"></p><h3>Ground rules</h3><ul id="groundRules"></ul></div><div class="card prose"><h3>Assumptions</h3><ul id="assumptions"></ul><h3>Limitations</h3><ul id="limitations"></ul></div></div><div class="card prose" style="margin-top:16px"><h3>Guidance basis</h3><div id="guidanceBasis"></div></div></section>
    <section class="view" data-view="sfta" hidden><div class="section-head"><div><h2>Hazard and Software Fault Tree explorer</h2><p>Explicit top-down logical models correlated with bottom-up SFMEA candidates. Placeholder trees expose missing decomposition without inventing causality.</p></div></div><div class="notice"><strong>Interpretation boundary:</strong> <span id="sftaNotice"></span></div><div class="metrics" id="sftaMetrics"></div><div class="grid"><div class="card"><div class="card-head"><div><h3>Fault trees</h3><p>Gate logic is shown only when supplied in the governed system configuration.</p></div></div><div class="citation-list" id="sftaTrees"></div></div><div class="card"><div class="card-head"><div><h3>Bidirectional reconciliation gaps</h3><p>Top-down events without findings and hazard-linked findings without tree events.</p></div></div><div class="citation-list" id="sftaGaps"></div></div></div></section>
    <section class="view" data-view="run-manifest" hidden><div class="section-head"><div><h2>Resolved run manifest</h2><p>Immutable scan inputs, environment, adapter capabilities, health, isolation, and execution provenance.</p></div></div><div class="notice"><strong>Audit boundary:</strong> <span id="runManifestNotice"></span></div><div class="metrics" id="runManifestMetrics"></div><div class="grid"><div class="card prose"><h3>Resolved inputs</h3><div id="resolvedInputs"></div><h3>Repository and environment</h3><div id="runEnvironment"></div></div><div class="card"><div class="card-head"><div><h3>Adapter registry</h3><p>Capabilities unavailable or not invoked remain visible rather than disappearing from coverage claims.</p></div></div><div class="citation-list" id="adapterRegistry"></div></div></div></section>
  </div>
</main>
</div>
<dialog id="detailDialog"><div class="dialog-head"><div><div class="eyebrow" id="detailEyebrow"></div><h2 id="detailTitle"></h2></div><button class="close" id="detailClose" aria-label="Close details">×</button></div><div class="dialog-body" id="detailBody"></div></dialog>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
"use strict";
const data=JSON.parse(document.getElementById("report-data").textContent);
const $=id=>document.getElementById(id);
const text=(tag,value,cls="")=>{const node=document.createElement(tag);if(cls)node.className=cls;node.textContent=value==null||value===""?"—":String(value);return node};
const clear=node=>{while(node.firstChild)node.removeChild(node.firstChild)};
const fmt=n=>new Intl.NumberFormat().format(Number(n||0));
const pct=value=>value==null?"n/a":`${value}%`;
const list=(values,empty="Not recorded")=>{const ul=document.createElement("ul");const entries=(values||[]).filter(Boolean);if(!entries.length)ul.append(text("li",empty,"muted"));else entries.forEach(value=>ul.append(text("li",value)));return ul};
const tag=(value,kind="")=>text("span",value||"unrated",`tag ${kind||String(value||"").toLowerCase()}`);
function metric(value,label,kind=""){const node=document.createElement("div");node.className=`metric ${kind}`;node.append(text("b",value),text("span",label));return node}
function renderBars(target,values,limit=12){const root=$(target);clear(root);const entries=Object.entries(values||{}).sort((a,b)=>b[1]-a[1]).slice(0,limit),max=Math.max(1,...entries.map(x=>x[1]));if(!entries.length){root.append(text("p","No data available.","muted"));return}entries.forEach(([label,value])=>{const row=document.createElement("div");row.className="bar-row";const track=document.createElement("div");track.className="bar-track";const fill=document.createElement("div");fill.className="bar-fill";fill.style.width=`${Math.max(1,value/max*100)}%`;track.append(fill);row.append(text("span",label.replaceAll("_"," "),"bar-label"),track,text("span",fmt(value),"bar-value"));root.append(row)})}
function initHeader(){const p=data.project,r=data.report,b=p.baseline||{};$("sideProject").textContent=p.name;$("sideVersion").textContent=r.generator;$("sideGenerated").textContent=`Generated ${r.generated_at}`;$("topTitle").textContent=p.name;$("topSubtitle").textContent=`${p.phase||"phase not configured"} · ${p.revision||"revision not configured"}`;$("heroTitle").textContent=`${p.name} analysis`;$("heroPurpose").textContent=p.purpose||"No project purpose was configured.";[["Baseline",b.id||"not recorded"],["Scanned",p.scanned_at||"not recorded"],["Lifecycle",p.phase||"not configured"],["Revision",p.revision||"not configured"]].forEach(([a,v])=>$("heroMeta").append(text("span",`${a}: ${v}`)));$("methodNotice").textContent=data.methodology.notice||data.methodology.limitations[0];}
function renderOverview(){const s=data.summary||{},v=data.validation.counts||{},c=data.coverage.failure_modes||{},active=c.active??s.candidate_failure_modes??0;const metrics=$("metrics");metrics.append(metric(fmt(s.components),"components"),metric(fmt(active),"active candidates"),metric(pct(c.review_percent),"review coverage",c.review_percent===100?"good":""),metric(fmt(v.error),"gate errors",v.error?"danger":"good"),metric(fmt(data.catalog.requirements.length),"requirements"),metric(fmt(data.catalog.hazards.length),"hazards"));const rows=[["Failure-mode review",data.coverage.failure_modes.review_percent],["Requirements",data.coverage.requirements.coverage_percent],["Hazards",data.coverage.hazards.coverage_percent],["Interfaces",data.coverage.interfaces.coverage_percent]];rows.forEach(([label,value])=>{const row=document.createElement("div");row.className="coverage-row";const track=document.createElement("div");track.className="coverage-track";const fill=document.createElement("div");fill.className="coverage-fill";fill.style.width=value==null?"0%":`${value}%`;track.append(fill);row.append(text("span",label),track,text("span",pct(value),"coverage-value"));$("coverageBars").append(row)});renderBars("priorityBars",data.distributions.priorities);renderBars("classBars",data.distributions.failure_classes);renderBars("validationBars",Object.fromEntries(data.validation.top_rules.map(x=>[x.rule_id,x.count])))}
function renderFindings(){const root=$("projectFindings");const findings=data.validation.project_findings||[];if(!findings.length)root.append(text("p","No project-level findings were recorded.","muted"));findings.forEach(f=>{const node=document.createElement("div");node.className="finding";node.append(tag(f.level,f.level),text("code",` ${f.rule_id}`),text("div",f.message));root.append(node)});renderBars("findingRuleBars",Object.fromEntries(data.validation.top_rules.map(x=>[x.rule_id,x.count])));renderNotes(data.report.notes)}
function renderNotes(source){const root=$("notesContent");clear(root);if(!source){root.append(text("p","No supplemental engineering notes were included.","muted"));return}let ul=null;source.split(/\r?\n/).forEach(raw=>{const line=raw.trimEnd();if(!line.trim()){ul=null;return}const heading=line.match(/^(#{1,4})\s+(.+)$/);if(heading){ul=null;root.append(text(`h${Math.min(4,heading[1].length+1)}`,heading[2]));return}const bullet=line.match(/^\s*[-*]\s+(.+)$/);if(bullet){if(!ul){ul=document.createElement("ul");root.append(ul)}ul.append(text("li",bullet[1]));return}ul=null;root.append(text("p",line))})}
const filterState={page:1,pageSize:100,search:"",priority:"",failureClass:"",disposition:"",hazard:"",subsystem:""};let filtered=[];
function optionize(id,values,label="All"){const select=$(id);select.append(new Option(label,""));[...new Set(values.filter(Boolean))].sort((a,b)=>String(a).localeCompare(String(b))).forEach(value=>select.append(new Option(String(value).replaceAll("_"," "),value)))}
function searchable(r){return [r.id,r.component,r.path,r.failure_mode,r.trigger,r.local_effect,r.next_higher_effect,r.end_effect,r.rule_id,...r.requirements,...r.linked_hazards,...r.subsystems,...(r.citations||[]).flatMap(c=>[c.citation_id,c.source_id,c.relationship,c.applicability])].join(" ").toLowerCase()}
function applyFilters(){const q=filterState.search.toLowerCase().trim();filtered=data.records.filter(r=>(!q||searchable(r).includes(q))&&(!filterState.priority||r.priority===filterState.priority)&&(!filterState.failureClass||r.failure_class===filterState.failureClass)&&(!filterState.disposition||r.disposition===filterState.disposition)&&(!filterState.hazard||r.linked_hazards.includes(filterState.hazard))&&(!filterState.subsystem||r.subsystems.includes(filterState.subsystem)));const pages=Math.max(1,Math.ceil(filtered.length/filterState.pageSize));filterState.page=Math.min(filterState.page,pages);renderTable()}
function initTable(){optionize("priorityFilter",data.records.map(r=>r.priority),"All priorities");optionize("classFilter",data.records.map(r=>r.failure_class),"All classes");optionize("dispositionFilter",data.records.map(r=>r.disposition),"All dispositions");optionize("hazardFilter",data.catalog.hazards.map(h=>h.id),"All hazards");optionize("subsystemFilter",data.records.flatMap(r=>r.subsystems),"All subsystems");[["priorityFilter","priority"],["classFilter","failureClass"],["dispositionFilter","disposition"],["hazardFilter","hazard"],["subsystemFilter","subsystem"]].forEach(([id,key])=>$(id).addEventListener("change",e=>{filterState[key]=e.target.value;filterState.page=1;applyFilters()}));$("search").addEventListener("input",e=>{filterState.search=e.target.value;filterState.page=1;applyFilters()});$("prevPage").addEventListener("click",()=>{if(filterState.page>1){filterState.page--;renderTable()}});$("nextPage").addEventListener("click",()=>{if(filterState.page*filterState.pageSize<filtered.length){filterState.page++;renderTable()}});applyFilters()}
function renderTable(){const body=$("recordRows");clear(body);const start=(filterState.page-1)*filterState.pageSize,records=filtered.slice(start,start+filterState.pageSize);records.forEach(r=>{const row=document.createElement("tr");row.tabIndex=0;row.setAttribute("aria-label",`Open ${r.id}`);row.addEventListener("click",()=>openRecord(r));row.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();openRecord(r)}});const priority=document.createElement("td");priority.append(tag(r.priority));const identity=document.createElement("td");identity.append(text("div",r.id,"mono"),tag(r.source_change||r.source_status,r.source_change==="changed"?"warning":""));const component=document.createElement("td");component.append(text("div",r.component),text("div",`${r.path}:${r.line}`,"small mono"));const failure=document.createElement("td");failure.className="failure";failure.append(text("div",r.failure_mode),text("div",r.guideword,"small"));const klass=document.createElement("td");klass.append(tag(r.failure_class,"info"));const review=document.createElement("td");review.append(tag(r.disposition),text("div",r.status,"small"));const rating=document.createElement("td");rating.append(text("div",`${r.severity??"–"}/${r.occurrence??"–"}/${r.detection??"–"}`),text("div",`RPN ${r.rpn??"–"}`,"small"));row.append(priority,identity,component,failure,klass,review,rating);body.append(row)});$("recordEmpty").hidden=records.length!==0;const totalPages=Math.max(1,Math.ceil(filtered.length/filterState.pageSize));$("recordCount").textContent=`Showing ${records.length?start+1:0}–${Math.min(start+records.length,filtered.length)} of ${fmt(filtered.length)} embedded records · page ${filterState.page} of ${totalPages}`;$("prevPage").disabled=filterState.page<=1;$("nextPage").disabled=filterState.page>=totalPages}
function detail(root,label,value,wide=false){const box=document.createElement("div");box.className=`detail ${wide?"wide":""}`;box.append(text("h3",label));if(Array.isArray(value))box.append(list(value));else box.append(text("p",value));root.append(box)}
function openRecord(r){$("detailEyebrow").textContent=`${r.id} · ${r.priority} priority · ${r.failure_class}`;$("detailTitle").textContent=r.failure_mode;const root=$("detailBody");clear(root);const grid=document.createElement("div");grid.className="detail-grid";detail(grid,"Component",`${r.component}\n${r.signature}\n${r.path}:${r.line}-${r.end_line}`);detail(grid,"Review state",`Disposition: ${r.disposition}\nStatus: ${r.status}\nReviewer: ${r.reviewer||"not assigned"}\nOwner: ${r.owner||"not assigned"}`);detail(grid,"Function",r.function,true);detail(grid,"Trigger",r.trigger,true);detail(grid,"Causes",r.causes,true);detail(grid,"Local effect",r.local_effect);detail(grid,"Next-higher effect",r.next_higher_effect);detail(grid,"End effect",r.end_effect,true);detail(grid,"Initial risk",`Severity: ${r.severity??"not rated"} ${r.severity_category||""}\nOccurrence: ${r.occurrence??"not rated"}\nDetection: ${r.detection??"not rated"}\nRPN: ${r.rpn??"not calculated"}`);detail(grid,"Rating rationale",`Severity: ${r.severity_rationale||"not recorded"}\nOccurrence: ${r.occurrence_rationale||"not recorded"}\nDetection: ${r.detection_rationale||"not recorded"}`);detail(grid,"Prevention controls",r.prevention_controls);detail(grid,"Detection controls",r.detection_controls);detail(grid,"Recommended actions",r.recommended_actions,true);detail(grid,"Actions taken",r.actions_taken);detail(grid,"Verification evidence",r.verification_evidence);detail(grid,"Assurance obligations",(r.assurance_obligations||[]).map(v=>`${v.id}: ${v.method} · ${v.status} · evidence ${v.evidence_status}`),true);detail(grid,"Trace links",[`Requirements: ${r.requirements.join(", ")||"none"}`,`Hazards: ${r.linked_hazards.join(", ")||"none"}`,`Interfaces: ${r.interfaces.join(", ")||"none"}`],true);detail(grid,"Scanner rationale",r.screening_reasons,true);detail(grid,"Scanner evidence",r.evidence,true);detail(grid,"Quality-gate rules",r.validation_rules,true);detail(grid,"Review notes",r.notes,true);root.append(grid);const dialog=$("detailDialog");if(dialog.showModal)dialog.showModal();else dialog.setAttribute("open","")}
function exportCsv(){const fields=["id","priority","failure_class","disposition","status","component","path","line","failure_mode","end_effect","severity","occurrence","detection","rpn","linked_hazards","requirements","owner","target_date"];const quote=value=>`"${String(Array.isArray(value)?value.join(" | "):(value??"")).replaceAll('"','""')}"`;const csv=[fields.join(","),...filtered.map(r=>fields.map(f=>quote(r[f])).join(","))].join("\r\n");const blob=new Blob(["\ufeff",csv],{type:"text/csv;charset=utf-8"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=`${data.project.name.replace(/[^a-z0-9]+/gi,"-").toLowerCase()}-sfmea-filtered.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),0)}
function renderArchitecture(){const a=data.architecture,m=$("architectureMetrics");m.append(metric(fmt(a.nodes),"graph nodes"),metric(fmt(a.edges),"graph edges"),metric(fmt(a.edge_counts.internal_call),"static calls"),metric(fmt(a.edge_counts.system_interface),"system interfaces"),metric(fmt(a.edge_counts.observed_runtime),"observed edges"),metric(fmt(a.runtime_imports),"runtime imports"));const flows=$("interfaceFlows");if(!data.interfaces.length)flows.append(text("p","No system interfaces were configured.","muted"));data.interfaces.forEach(i=>{const row=document.createElement("div");row.className="flow";row.append(text("div",i.source,"flow-node"),text("div","→","flow-arrow"),text("div",i.target,"flow-node"));const desc=document.createElement("div");desc.append(text("strong",i.id),text("p",i.description));row.append(desc);flows.append(row)});const grid=$("subsystemGrid");data.subsystems.forEach(s=>{const card=document.createElement("article");card.className="subsystem";card.append(text("h3",s.name));const values=document.createElement("div");values.className="compact-metrics";[[s.components,"components"],[s.candidates,"candidates"],[s.high_priority,"high priority"]].forEach(([value,label])=>{const node=document.createElement("div");node.append(text("b",fmt(value)),text("span",label));values.append(node)});card.append(values);if(s.requirements.length)card.append(text("p",`Requirements: ${s.requirements.join(", ")}`,"small"));grid.append(card)})}
function renderTraceability(){const rows=$("traceRows");if(!data.catalog.requirements.length)rows.append(text("p","No requirements were configured.","muted"));data.catalog.requirements.forEach(r=>{const row=document.createElement("div");row.className="trace-row";const requirement=document.createElement("div");requirement.append(text("strong",r.id),text("div",r.text),text("div",`${r.components} components · ${r.candidates} candidates`,"small"));row.append(requirement,text("div","mitigates →","trace-arrow"));const hazards=document.createElement("div");hazards.className="hazard-chips";(r.hazards.length?r.hazards:["No hazard link"]).forEach(h=>hazards.append(tag(h,r.hazards.length?"warning":"")));row.append(hazards);rows.append(row)});const grid=$("hazardGrid");data.catalog.hazards.forEach(h=>{const card=document.createElement("article");card.className="catalog-card";card.append(text("h3",h.id),text("p",h.description),text("p",h.end_effect,"small"),tag(`${h.candidates} linked candidates`,"info"));grid.append(card)})}
function participantLabel(sequence,id){return sequence.participants.find(p=>p.id===id)?.label||id}
function renderSequence(){const sequence=data.sequences[$("sequenceSelect").selectedIndex];const root=$("sequenceDiagram");clear(root);if(!sequence){$("sequenceMeta").textContent="No bounded sequence could be derived.";return}$("sequenceMeta").textContent=`${sequence.path}:${sequence.title} · ${sequence.participants.length} participants · ${sequence.interactions.length} interactions${sequence.truncated?` · truncated by ${sequence.truncation_reasons.join(", ")}`:""}`;sequence.interactions.forEach((i,index)=>{const row=document.createElement("div");row.className="interaction";row.append(text("span",index+1,"step"),text("span",participantLabel(sequence,i.source),"actor"),text("span",i.cycle?"↺":"→","arrow"),text("span",participantLabel(sequence,i.target),"actor"),tag(i.evidence,i.evidence==="observed_runtime"?"accepted":"info"));root.append(row)})}
function renderSequences(){const select=$("sequenceSelect");data.sequences.forEach((s,index)=>select.append(new Option(`${s.path}:${s.title}`,index)));select.addEventListener("change",renderSequence);renderSequence()}
const svgNS="http://www.w3.org/2000/svg";let diagramScale=1,diagramBaseSize={width:900,height:570},activeDiagram=null,selectedDiagramNode="";
function svgElement(name,attributes={}){const node=document.createElementNS(svgNS,name);Object.entries(attributes).forEach(([key,value])=>node.setAttribute(key,String(value)));return node}
function clipped(value,limit=34){const string=String(value||"");return string.length>limit?string.slice(0,limit-1)+"…":string}
function labelLines(value,width=28,maxLines=3){const words=String(value||"").split(/\s+/),lines=[];let current="";words.forEach(word=>{if(lines.length>=maxLines)return;const next=current?`${current} ${word}`:word;if(next.length<=width)current=next;else{if(current)lines.push(current);current=word}});if(current&&lines.length<maxLines)lines.push(current);if(words.join(" ").length>lines.join(" ").length&&lines.length)lines[lines.length-1]=clipped(lines[lines.length-1],width);return lines}
function appendSvgLabel(group,label,x,y,width=28,maxLines=3){const labelNode=svgElement("text",{x,y,"text-anchor":"middle"});labelLines(label,width,maxLines).forEach((line,index)=>{const span=svgElement("tspan",{x,dy:index?17:0});span.textContent=line;labelNode.append(span)});group.append(labelNode)}
function computedGraphLayout(diagram){const nodes=diagram.nodes||[],edges=diagram.edges||[],layers=new Map(nodes.map(node=>[node.id,Number.isInteger(node.layer)?node.layer:0]));if(!nodes.some(node=>Number.isInteger(node.layer))){for(let pass=0;pass<Math.min(nodes.length,10);pass++){let changed=false;edges.forEach(edge=>{if(edge.source===edge.target)return;const next=Math.min(7,(layers.get(edge.source)||0)+1);if(next>(layers.get(edge.target)||0)){layers.set(edge.target,next);changed=true}});if(!changed)break}}const grouped=new Map();nodes.forEach(node=>{const layer=layers.get(node.id)||0;if(!grouped.has(layer))grouped.set(layer,[]);grouped.get(layer).push(node)});const orderedLayers=[...grouped.keys()].sort((a,b)=>a-b),positions=new Map();let xOffset=45,maxRows=1;orderedLayers.forEach(layer=>{const values=grouped.get(layer).sort((a,b)=>(a.order??999999)-(b.order??999999)||a.label.localeCompare(b.label)),columns=Math.max(1,Math.ceil(values.length/10));values.forEach((node,index)=>positions.set(node.id,{x:xOffset+Math.floor(index/10)*230,y:50+(index%10)*100,width:190,height:70}));xOffset+=columns*230+55;maxRows=Math.max(maxRows,Math.min(10,values.length))});return{positions,width:Math.max(900,xOffset+30),height:Math.max(570,100+maxRows*100)}}
function sequenceLayout(diagram){const ordered=[...(diagram.nodes||[])].sort((a,b)=>(a.order??999999)-(b.order??999999)||a.label.localeCompare(b.label)),positions=new Map();ordered.forEach((node,index)=>positions.set(node.id,{x:35+index*190,y:28,width:160,height:58}));return{positions,width:Math.max(900,70+ordered.length*190),height:Math.max(570,145+(diagram.edges||[]).length*58)}}
function makeMarker(svg,diagram){const defs=svgElement("defs"),markerId=`diagram-arrow-${String(diagram.id).replace(/[^A-Za-z0-9]/g,"-")}`,marker=svgElement("marker",{id:markerId,viewBox:"0 0 10 10",refX:9,refY:5,markerWidth:7,markerHeight:7,orient:"auto-start-reverse"}),path=svgElement("path",{d:"M 0 0 L 10 5 L 0 10 z",fill:"var(--muted)"});marker.append(path);defs.append(marker);svg.append(defs);return markerId}
function renderDiagramEdges(svg,diagram,layout,markerId){const edgeLayer=svgElement("g",{"aria-hidden":"true"});const sequence=diagram.type==="sequence";(diagram.edges||[]).forEach((edge,index)=>{const source=layout.positions.get(edge.source),target=layout.positions.get(edge.target);if(!source||!target)return;const group=svgElement("g",{class:`diagram-edge ${edge.evidence==="observed_runtime"?"runtime":""}`});group.dataset.source=edge.source;group.dataset.target=edge.target;let d,labelX,labelY;if(sequence){const y=122+(edge.order??index)*58,sx=source.x+source.width/2,tx=target.x+target.width/2;if(edge.source===edge.target){d=`M ${sx} ${y} C ${sx+75} ${y-22}, ${sx+75} ${y+22}, ${sx} ${y+35}`;labelX=sx+68;labelY=y-5}else{d=`M ${sx} ${y} L ${tx} ${y}`;labelX=(sx+tx)/2;labelY=y-7}}else{const sx=source.x+source.width,sy=source.y+source.height/2,tx=target.x,ty=target.y+target.height/2;if(source.x===target.x){d=`M ${source.x+source.width/2} ${source.y+source.height} C ${source.x+source.width+55} ${sy}, ${target.x+target.width+55} ${ty}, ${target.x+target.width/2} ${target.y}`;labelX=source.x+source.width+42;labelY=(sy+ty)/2}else{const bend=Math.max(35,Math.abs(tx-sx)*.42);d=`M ${sx} ${sy} C ${sx+bend} ${sy}, ${tx-bend} ${ty}, ${tx} ${ty}`;labelX=(sx+tx)/2;labelY=(sy+ty)/2-7}}const path=svgElement("path",{d,"marker-end":`url(#${markerId})`});group.append(path);if(edge.label){const label=svgElement("text",{x:labelX,y:labelY,"text-anchor":"middle"});label.textContent=clipped(edge.label,38);group.append(label)}edgeLayer.append(group)});svg.append(edgeLayer)}
function showDiagramNode(node){selectedDiagramNode=node.id;document.querySelectorAll("#diagramStage .diagram-node").forEach(element=>element.classList.toggle("selected",element.dataset.id===node.id));const root=$("diagramInspector");clear(root);root.append(text("h3",node.label),tag(node.kind,"info"));if(node.description)root.append(text("p",node.description));const dl=document.createElement("dl"),rows=[["ID",node.id],["Group",node.group],["Source",node.source],["Tags",(node.tags||[]).join(", ")]];rows.forEach(([label,value])=>{if(value){dl.append(text("dt",label),text("dd",value))}});root.append(dl);if(Object.keys(node.metrics||{}).length){root.append(text("h3","Metrics"));const metrics=document.createElement("dl");Object.entries(node.metrics).forEach(([key,value])=>metrics.append(text("dt",key.replaceAll("_"," ")),text("dd",value)));root.append(metrics)}const relations=(activeDiagram.edges||[]).filter(edge=>edge.source===node.id||edge.target===node.id);root.append(text("h3",`Relationships (${relations.length})`));root.append(list(relations.slice(0,20).map(edge=>`${edge.source===node.id?"→":"←"} ${edge.label||edge.kind}: ${edge.source===node.id?edge.target:edge.source}`),"No recorded relationships"));root.append(text("h3","Legend"));const legend=document.createElement("div");legend.className="diagram-legend";[...new Set(activeDiagram.nodes.map(value=>value.kind))].sort().forEach(kind=>legend.append(tag(kind.replaceAll("_"," "),"info")));root.append(legend)}
function renderDiagramNodes(svg,diagram,layout){const sequence=diagram.type==="sequence";if(sequence){diagram.nodes.forEach(node=>{const position=layout.positions.get(node.id);if(!position)return;svg.append(svgElement("line",{x1:position.x+position.width/2,y1:position.y+position.height,x2:position.x+position.width/2,y2:layout.height-30,class:"diagram-lifeline"}))})}const nodeLayer=svgElement("g");diagram.nodes.forEach(node=>{const position=layout.positions.get(node.id);if(!position)return;const group=svgElement("g",{class:"diagram-node",transform:`translate(${position.x} ${position.y})`,tabindex:0,role:"button","aria-label":`${node.kind}: ${node.label}`});group.dataset.id=node.id;group.dataset.kind=node.kind;group.dataset.search=[node.id,node.label,node.description,node.source,node.group,...(node.tags||[])].join(" ").toLowerCase();group.append(svgElement("rect",{width:position.width,height:position.height,rx:11,ry:11}));const title=svgElement("title");title.textContent=`${node.kind}: ${node.label}`;group.append(title);appendSvgLabel(group,node.label,position.width/2,sequence?24:24,sequence?22:27,sequence?2:3);group.addEventListener("click",()=>showDiagramNode(node));group.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();showDiagramNode(node)}});nodeLayer.append(group)});svg.append(nodeLayer)}
function updateDiagramHighlights(){const query=$("diagramSearch").value.trim().toLowerCase(),kind=$("diagramKindFilter").value,matched=new Set();document.querySelectorAll("#diagramStage .diagram-node").forEach(node=>{const visible=(!query||node.dataset.search.includes(query))&&(!kind||node.dataset.kind===kind);node.classList.toggle("dim",!visible);if(visible)matched.add(node.dataset.id)});document.querySelectorAll("#diagramStage .diagram-edge").forEach(edge=>edge.classList.toggle("dim",Boolean(query||kind)&&!matched.has(edge.dataset.source)&&!matched.has(edge.dataset.target)))}
function applyDiagramScale(){const svg=$("diagramStage").querySelector("svg");if(!svg)return;svg.style.width=`${Math.round(diagramBaseSize.width*diagramScale)}px`;svg.style.height=`${Math.round(diagramBaseSize.height*diagramScale)}px`}
function renderGenericDiagram(){activeDiagram=data.diagrams[$("diagramSelect").selectedIndex];selectedDiagramNode="";const stage=$("diagramStage"),inspector=$("diagramInspector"),kindSelect=$("diagramKindFilter");clear(stage);clear(inspector);clear(kindSelect);kindSelect.append(new Option("All element types",""));if(!activeDiagram){stage.append(text("div","No diagrams are available.","diagram-empty"));$("diagramStatus").textContent="";$("diagramNotice").textContent="No canonical diagrams were generated or imported.";return}const kinds=[...new Set(activeDiagram.nodes.map(node=>node.kind))].sort();kinds.forEach(kind=>kindSelect.append(new Option(kind.replaceAll("_"," "),kind)));$("diagramSearch").value="";const layout=activeDiagram.type==="sequence"?sequenceLayout(activeDiagram):computedGraphLayout(activeDiagram);diagramBaseSize={width:layout.width,height:layout.height};diagramScale=1;const svg=svgElement("svg",{viewBox:`0 0 ${layout.width} ${layout.height}`,width:layout.width,height:layout.height,role:"img","aria-label":`${activeDiagram.title}: ${activeDiagram.description}`});const title=svgElement("title");title.textContent=activeDiagram.title;const description=svgElement("desc");description.textContent=activeDiagram.description||activeDiagram.notice||"Canonical SFMEA diagram";svg.append(title,description);const markerId=makeMarker(svg,activeDiagram);renderDiagramEdges(svg,activeDiagram,layout,markerId);renderDiagramNodes(svg,activeDiagram,layout);stage.append(svg);stage.scrollTo({left:0,top:0});$("diagramStatus").replaceChildren(text("span",`${activeDiagram.nodes.length} nodes`),text("span",`${activeDiagram.edges.length} relationships`),text("span",activeDiagram.type.replaceAll("_"," ")),text("span",activeDiagram.metadata?.imported_from?`Imported: ${activeDiagram.metadata.imported_from}`:"Generated from analysis"));$("diagramNotice").textContent=activeDiagram.notice||"Select a node to inspect its evidence and relationships.";inspector.append(text("h3",activeDiagram.title),text("p",activeDiagram.description||"No description supplied.","muted"),text("p","Select a node to inspect its evidence and relationships.","muted"));const legend=document.createElement("div");legend.className="diagram-legend";legend.id="diagramLegend";kinds.forEach(kind=>legend.append(tag(kind.replaceAll("_"," "),"info")));inspector.append(legend);applyDiagramScale()}
function downloadDiagramSvg(){const svg=$("diagramStage").querySelector("svg");if(!svg||!activeDiagram)return;const clone=svg.cloneNode(true);clone.setAttribute("xmlns",svgNS);clone.removeAttribute("style");clone.querySelectorAll(".dim,.selected").forEach(node=>{node.classList.remove("dim");node.classList.remove("selected")});const style=svgElement("style");style.textContent=`:root{--ink:#172033;--muted:#647089;--card:#fff;--line:#dce2ec;--brand:#2457d6;--cyan:#0d8d96;--amber:#a65f00;--red:#b52d3b;--green:#14734a}.diagram-node rect{fill:#eef3ff;stroke:#7996dc;stroke-width:1.5}.diagram-node[data-kind="hazard"] rect,.diagram-node[data-kind="failure_mode"] rect,.diagram-node[data-kind="end_effect"] rect{fill:#fbecee;stroke:#cf7c86}.diagram-node[data-kind="requirement"] rect,.diagram-node[data-kind="prevention_control"] rect,.diagram-node[data-kind="detection_control"] rect,.diagram-node[data-kind="verification_evidence"] rect{fill:#eaf6f0;stroke:#68a88b}.diagram-node[data-kind="boundary"] rect,.diagram-node[data-kind="participant"] rect{fill:#e8f6f7;stroke:#69b5b9}.diagram-node[data-kind="recommended_action"] rect,.diagram-node[data-kind="next_higher_effect"] rect{fill:#fff4e4;stroke:#ca9954}.diagram-node text{fill:var(--ink);font:650 12px system-ui,sans-serif}.diagram-edge{color:var(--muted)}.diagram-edge path{fill:none;stroke:currentColor;stroke-width:1.5}.diagram-edge.runtime{color:var(--green)}.diagram-edge text{fill:var(--muted);font:11px system-ui,sans-serif;paint-order:stroke;stroke:var(--card);stroke-width:5px}.diagram-lifeline{stroke:var(--line);stroke-width:1;stroke-dasharray:5 5}`;clone.insertBefore(style,clone.firstChild);const source=`<?xml version="1.0" encoding="UTF-8"?>\n${new XMLSerializer().serializeToString(clone)}`,blob=new Blob([source],{type:"image/svg+xml;charset=utf-8"}),url=URL.createObjectURL(blob),anchor=document.createElement("a");anchor.href=url;anchor.download=`${activeDiagram.id}.svg`;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),0)}
function initDiagrams(){const select=$("diagramSelect");(data.diagrams||[]).forEach((diagram,index)=>select.append(new Option(`${diagram.title} · ${diagram.type.replaceAll("_"," ")}`,index)));select.addEventListener("change",renderGenericDiagram);$("diagramKindFilter").addEventListener("change",updateDiagramHighlights);$("diagramSearch").addEventListener("input",updateDiagramHighlights);$("diagramZoomIn").addEventListener("click",()=>{diagramScale=Math.min(2,diagramScale+.15);applyDiagramScale()});$("diagramZoomOut").addEventListener("click",()=>{diagramScale=Math.max(.35,diagramScale-.15);applyDiagramScale()});$("diagramZoomFit").addEventListener("click",()=>{diagramScale=Math.max(.35,Math.min(1,($("diagramStage").clientWidth-20)/diagramBaseSize.width));applyDiagramScale();$("diagramStage").scrollTo({left:0,top:0})});$("diagramDownload").addEventListener("click",downloadDiagramSvg);renderGenericDiagram()}
function externalLink(label,url){const anchor=document.createElement("a");anchor.textContent=label;anchor.href=url;anchor.target="_blank";anchor.rel="noopener noreferrer";return anchor}
function renderGuidance(){const g=data.guidance,c=g.coverage||{},metrics=$("guidanceMetrics"),active=new Set(g.active_profiles||[]);$("guidanceNotice").textContent=g.notice;metrics.append(metric(pct(c.finding_coverage_percent),"cited findings",c.finding_coverage_percent===100?"good":""),metric(fmt(c.used_sources),"used sources"),metric(fmt(c.used_citations),"used locators"),metric(fmt(g.rule_mappings.length),"curated mappings"),metric(g.catalog_version,"catalog version"),metric(g.retrieved_at,"retrieved"));const profiles=$("guidanceProfiles");(g.profiles||[]).filter(profile=>active.has(profile.id)).forEach(profile=>{const card=document.createElement("article");card.className="catalog-card citation-card";card.append(text("h3",profile.title),text("p",profile.applicability));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(profile.id,"accepted"),tag(profile.status,"info"),tag(profile.compliance_claim?"compliance claim":"no compliance claim",profile.compliance_claim?"warning":"info"));card.append(meta,text("p",profile.tailoring),text("p",profile.verification_semantics,"small"));profiles.append(card)});const uses=c.uses_by_citation||{},selectedSourceIds=new Set((g.profiles||[]).filter(profile=>active.has(profile.id)).flatMap(profile=>profile.source_ids||[])),sources=$("guidanceSources");g.sources.filter(source=>selectedSourceIds.has(source.id)).forEach(source=>{const card=document.createElement("article");card.className="catalog-card citation-card";card.append(externalLink(source.title,source.url),text("p",`${source.publisher} · version ${source.version||"not recorded"}`));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(source.status,source.status.includes("legacy")?"warning":"accepted"),tag(source.applicability,"info"),tag(source.access,"info"));card.append(meta,text("p",source.use),text("p",`Record SHA-256 ${source.record_sha256||"not recorded"}${source.artifact?.sha256?` · artifact ${source.artifact.sha256}`:""}`,"small"));sources.append(card)});const root=$("guidanceCitations"),citationSource=Object.fromEntries(g.sources.map(s=>[s.id,s]));g.citations.filter(citation=>uses[citation.id]).sort((a,b)=>(uses[b.id]||0)-(uses[a.id]||0)||a.id.localeCompare(b.id)).forEach(citation=>{const source=citationSource[citation.source_id]||{},locator=citation.locator||{},entry=document.createElement("div");entry.className="citation-entry";entry.append(externalLink(`${citation.id} — ${locator.heading||locator.section}`,citation.url||source.url||"#"),text("p",citation.summary),text("p",`${source.title||citation.source_id} · section ${locator.section||"not recorded"}${locator.page?` · page ${locator.page}`:""}`,"small"));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(`${uses[citation.id]} finding uses`,"info"),tag(citation.applicability,"info"));const show=document.createElement("button");show.className="btn";show.textContent="Show findings";show.addEventListener("click",()=>{filterState.search=citation.id;filterState.page=1;$("search").value=citation.id;applyFilters();setView("failure-modes")});meta.append(show);entry.append(meta);root.append(entry)});if(!root.children.length)root.append(text("p","No active finding uses a curated citation.","muted"))}
function renderAssurance(){const a=data.assurance||{},s=a.summary||{},root=$("assuranceRows"),metrics=$("assuranceMetrics"),values=(a.obligations||[]).filter(v=>v.source_status==="active"),executions=a.executions||[];$("assuranceNotice").textContent=a.notice||"Generated obligations are planning drafts, not evidence.";metrics.append(metric(fmt(s.active_obligations),"active obligations"),metric(fmt(s.implemented_tests),"implemented tests",s.implemented_tests?"good":""),metric(fmt(s.executions),"recorded executions"),metric(fmt(s.reviewed_executions),"reviewed executions",s.reviewed_executions?"good":""),metric(fmt((s.by_evidence_status||{}).sufficient),"sufficient evidence"),metric(fmt(s.planning_gaps),"planning gaps",s.planning_gaps?"danger":"good"));$("assuranceCount").textContent=`Showing ${fmt(Math.min(values.length,250))} of ${fmt(values.length)} embedded obligations; use the JSON/CSV register for the complete machine-readable checklist.`;values.slice(0,250).forEach(v=>{const entry=document.createElement("article");entry.className="citation-entry";entry.append(text("h3",`${v.id} · ${v.component}`),text("p",v.title),text("p",v.stimulus?.description||"Stimulus requires planning.","small"));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(v.verification_method,"info"),tag(v.assurance_status),tag(`evidence: ${v.evidence_status}`,v.evidence_status==="sufficient"?"accepted":"warning"),tag(v.automation?.implementation_status||"not implemented"));entry.append(meta,text("p",`Proposed: ${v.automation?.proposed_test_path||"not assigned"} · ${v.automation?.command_argv?.join(" ")||"no command"}`,"small"),text("h4","Acceptance criteria"),list(v.acceptance_criteria));const show=document.createElement("button");show.className="btn";show.textContent="Show finding";show.addEventListener("click",()=>{filterState.search=v.finding_id;filterState.page=1;$("search").value=v.finding_id;applyFilters();setView("failure-modes")});entry.append(show);root.append(entry)});if(!values.length)root.append(text("p","No active verification obligations were generated.","muted"));const executionRoot=$("assuranceExecutions");executions.slice().reverse().slice(0,100).forEach(v=>{const entry=document.createElement("article");entry.className="citation-entry";const latest=(v.reviews||[]).at(-1),mode=v.execution_mode||"sandbox",source=mode==="external_import"?`external import · ${v.import_trust||"trust not recorded"}`:`sandbox · ${v.sandbox?.image||"image not recorded"} (${v.sandbox?.image_id||"digest unavailable"})`;entry.append(text("h3",`${v.id} · ${v.status}`),text("p",`${v.test?.path||"test not recorded"} · exit ${v.exit_code??"not available"} · ${v.duration_seconds??"n/a"} seconds`),text("p",`Baseline ${v.baseline_id||"not recorded"} · ${source}`,"small"));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(v.status,v.status==="passed"?"accepted":"warning"),tag(mode,"info"),tag(`${(v.artifacts||[]).length} artifacts`,`info`),tag(latest?latest.decision:"unreviewed",latest?.decision==="sufficient"?"accepted":"warning"),tag(v.repository?.allow_dirty?"dirty baseline allowed":"baseline bound",v.repository?.allow_dirty?"warning":"accepted"));entry.append(meta);if(latest)entry.append(text("p",`${latest.reviewer}: ${latest.rationale}`,"small"));executionRoot.append(entry)});if(!executions.length)executionRoot.append(text("p","No execution evidence has been collected.","muted"))}
function renderRunManifest(){const m=data.run_manifest||{},registry=m.adapters||{},summary=registry.summary||{},metrics=$("runManifestMetrics");$("runManifestNotice").textContent=m.notice||"Run provenance is unavailable.";metrics.append(metric(m.id||"missing","run ID",m.id?"good":"danger"),metric(m.repository?.baseline_id||"missing","baseline",m.repository?.baseline_id?"good":"danger"),metric(fmt(summary.total),"registered adapters"),metric(fmt(summary.available),"available",summary.available?"good":""),metric(fmt(summary.not_configured),"not configured",summary.not_configured?"warning":"good"),metric(fmt(summary.not_invoked),"not invoked",summary.not_invoked?"warning":"good"));const inputRoot=$("resolvedInputs"),inputList=document.createElement("dl");Object.entries(m.resolved_inputs||{}).forEach(([key,value])=>inputList.append(text("dt",key.replaceAll("_"," ")),text("dd",value,"mono")));inputRoot.append(inputList);const environment=$("runEnvironment"),envList=document.createElement("dl"),rows=[["Revision",m.repository?.revision||"not recorded"],["Dirty state",String(m.repository?.dirty??"unknown")],["Python",m.environment?.python||"not recorded"],["Platform",m.environment?.platform||"not recorded"],["Tool",`${m.tool?.name||"PySFMEA"} ${m.tool?.version||"unknown"}`],["Manifest digest",m.manifest_sha256||"missing"]];rows.forEach(([label,value])=>envList.append(text("dt",label),text("dd",value,"mono")));environment.append(envList);const root=$("adapterRegistry");(registry.adapters||[]).forEach(adapter=>{const entry=document.createElement("article");entry.className="citation-entry";entry.append(text("h3",adapter.id),text("p",(adapter.capabilities||[]).join(" · ")||"No capabilities declared."),text("p",`${adapter.input_schema} → ${adapter.output_schema}`,"small"));const meta=document.createElement("div");meta.className="citation-meta";const health=adapter.health?.status||"unknown";meta.append(tag(health,health==="available"?"accepted":"warning"),tag(adapter.category,"info"),tag(adapter.trust_level,"info"),tag(adapter.deterministic?"deterministic":"non-deterministic",adapter.deterministic?"accepted":"warning"),tag(adapter.isolation,"info"));entry.append(meta,text("p",adapter.health?.reason||"Health reason not recorded.","small"));root.append(entry)})}
function renderSfta(){const s=data.sfta||{},r=s.reconciliation||{},m=r.summary||{},metrics=$("sftaMetrics"),treeRoot=$("sftaTrees"),gapRoot=$("sftaGaps");$("sftaNotice").textContent=s.notice||"Fault-tree logic requires explicit engineering input and review.";metrics.append(metric(fmt(m.hazards),"hazards"),metric(fmt(m.explicit_trees),"explicit trees",m.explicit_trees?"good":""),metric(fmt(m.placeholder_trees),"undeveloped trees",m.placeholder_trees?"danger":"good"),metric(fmt(m.findings_correlated_to_events),"correlated findings"),metric(fmt(m.top_down_uncovered_events),"uncovered events",m.top_down_uncovered_events?"danger":"good"),metric(fmt(m.bottom_up_unmapped_findings),"unmapped findings",m.bottom_up_unmapped_findings?"danger":"good"));(s.trees||[]).forEach(tree=>{const entry=document.createElement("article"),events=(tree.nodes||[]).filter(v=>v.kind==="event"),gates=(tree.nodes||[]).filter(v=>v.kind==="gate"),linked=new Set(events.flatMap(v=>v.linked_finding_ids||[]));entry.className="citation-entry";entry.append(text("h3",`${tree.hazard_id} · ${tree.top_event}`),text("p",tree.description||"No description supplied."));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(tree.source==="explicit_configuration"?"explicit logic":"undeveloped placeholder",tree.source==="explicit_configuration"?"accepted":"warning"),tag(`${events.length} events`,`info`),tag(`${gates.length} gates`,`info`),tag(`${linked.size} correlated findings`,`info`));entry.append(meta);const index=(data.diagrams||[]).findIndex(v=>v.metadata?.category==="sfta"&&v.metadata?.tree_id===tree.id);if(index>=0){const show=document.createElement("button");show.className="btn";show.textContent="Open fault-tree diagram";show.addEventListener("click",()=>{$("diagramSelect").selectedIndex=index;renderGenericDiagram();setView("diagrams")});entry.append(show)}treeRoot.append(entry)});if(!treeRoot.children.length)treeRoot.append(text("p","No hazards are configured; no fault trees can be developed.","muted"));const groups=[["Top-down event has no bottom-up finding",r.top_down_uncovered_events||[],"warning"],["Hazard-linked finding has no tree event",r.bottom_up_unmapped_findings||[],"warning"],["Tree correlation conflicts with hazard link",r.hazard_link_mismatches||[],"error"]];groups.forEach(([label,values,kind])=>values.slice(0,250).forEach(value=>{const entry=document.createElement("article");entry.className="citation-entry";entry.append(text("h3",label),text("p",value.description||value.failure_mode||value.finding_id||value.event_id||"Gap requires review."));const meta=document.createElement("div");meta.className="citation-meta";meta.append(tag(kind,kind),tag(value.hazard_id||"hazard not recorded","info"));if(value.tree_id)meta.append(tag(value.tree_id,"info"));if(value.event_id)meta.append(tag(value.event_id,"info"));if(value.finding_id)meta.append(tag(value.finding_id,"info"));entry.append(meta);gapRoot.append(entry)}));if(!gapRoot.children.length)gapRoot.append(text("p","No bidirectional SFTA reconciliation gaps were identified for the configured model.","muted"))}
function renderMethodology(){const p=data.project;$("boundaryText").textContent=p.boundary||"Not configured.";$("operatingText").textContent=p.operating_context||"Not configured.";$("groundRules").append(...(p.ground_rules.length?p.ground_rules:["Not configured."]).map(v=>text("li",v)));$("assumptions").append(...(p.assumptions.length?p.assumptions:["Not configured."]).map(v=>text("li",v)));$("limitations").append(...data.methodology.limitations.map(v=>text("li",v)));const root=$("guidanceBasis");if(!data.methodology.basis.length)root.append(text("p","No methodology sources were recorded.","muted"));data.methodology.basis.forEach(source=>{const item=document.createElement("div");item.className="finding";item.append(externalLink(source.title||"Guidance source",source.url),text("p",source.use||source.url||""));root.append(item)})}
function setView(view){document.querySelectorAll(".view").forEach(node=>node.hidden=node.dataset.view!==view);document.querySelectorAll("#nav button").forEach(button=>button.classList.toggle("active",button.dataset.view===view));const button=document.querySelector(`#nav button[data-view="${view}"]`);$("topSubtitle").textContent=button?button.textContent.trim():"Report";history.replaceState(null,"",`#${view}`);document.body.classList.remove("menu-open");window.scrollTo({top:0,behavior:"smooth"})}
function initNavigation(){document.querySelectorAll("#nav button").forEach(button=>button.addEventListener("click",()=>setView(button.dataset.view)));const initial=location.hash.slice(1);if(document.querySelector(`.view[data-view="${initial}"]`))setView(initial);$("menuButton").addEventListener("click",()=>document.body.classList.toggle("menu-open"));$("themeButton").addEventListener("click",()=>{const root=document.documentElement;root.dataset.theme=root.dataset.theme==="dark"?"light":"dark"});$("printButton").addEventListener("click",()=>window.print());$("detailClose").addEventListener("click",()=>$("detailDialog").close());$("csvButton").addEventListener("click",exportCsv)}
initHeader();renderOverview();renderFindings();initTable();renderAssurance();renderSfta();renderRunManifest();renderArchitecture();renderTraceability();renderSequences();initDiagrams();renderGuidance();renderMethodology();initNavigation();
</script>
</body>
</html>
'''
