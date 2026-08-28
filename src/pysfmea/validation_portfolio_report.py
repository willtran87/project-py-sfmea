"""Self-contained, integrity-verifiable industry-validation portfolio report."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .json_ingestion import load_bounded_file_snapshot, load_bounded_json_document
from .validation_portfolio import verify_validation_portfolio_assessment

VALIDATION_PORTFOLIO_REPORT_FORMAT = "pysfmea-industry-validation-portfolio-report-1"
VALIDATION_PORTFOLIO_REPORT_VERIFICATION_FORMAT = (
    "pysfmea-industry-validation-portfolio-report-verification-1"
)
MAX_REPORT_BYTES = 50 * 1024 * 1024
_DOCUMENT_MARKER = "0" * 64


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _rows(values: list[dict[str, Any]], fields: tuple[str, ...]) -> str:
    if not values:
        return f'<tr><td colspan="{len(fields)}">No records supplied.</td></tr>'
    return "".join(
        "<tr>"
        + "".join(f"<td>{_escape(item.get(field, ''))}</td>" for field in fields)
        + "</tr>"
        for item in values
    )


def validation_portfolio_report_html(
    assessment: dict[str, Any], *, title: str = "Industry validation portfolio"
) -> str:
    verdict = verify_validation_portfolio_assessment(assessment)
    if not verdict["valid"]:
        raise ValueError("portfolio report requires an internally valid assessment")
    payload_bytes = json.dumps(
        assessment, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    payload = base64.b64encode(payload_bytes).decode("ascii")
    payload_sha = hashlib.sha256(payload_bytes).hexdigest()
    checks = assessment["checks"]
    summary = assessment["summary"]
    check_rows = [
        {"name": name, "status": "PASS" if state else "BLOCK", "class": "pass" if state else "block"}
        for name, state in sorted(checks.items())
    ]
    checks_html = "".join(
        f'<tr data-state="{item["class"]}"><td>{_escape(item["name"].replace("_", " ").title())}</td>'
        f'<td><span class="badge {item["class"]}">{item["status"]}</span></td></tr>'
        for item in check_rows
    )
    artifacts = assessment["artifacts"]
    artifact_rows = "".join(
        "<tr>"
        f"<td>{_escape(item.get('kind', ''))}</td>"
        f"<td><code>{_escape(item.get('reference', ''))}</code></td>"
        f"<td>{_escape(item.get('format_id', '—'))}</td>"
        f"<td><span class=\"badge {'pass' if item.get('valid') else 'block'}\">{'valid' if item.get('valid') else 'invalid'}</span></td>"
        f"<td><span class=\"badge {'pass' if item.get('passed') else 'block'}\">{'pass' if item.get('passed') else 'block'}</span></td>"
        f"<td><code>{_escape(str(item.get('sha256', ''))[:16])}…</code></td>"
        "</tr>"
        for item in artifacts
    ) or '<tr><td colspan="6">No referenced machine artifacts.</td></tr>'
    benchmark = assessment["benchmark"]
    interoperability = assessment["interoperability"]
    studies = assessment["usability_studies"]
    formal = assessment["formal_verification"]
    continuity = assessment["continuity_exercises"]
    status_class = "pass" if summary["passed"] else "block"
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="pysfmea-report-format" content="{VALIDATION_PORTFOLIO_REPORT_FORMAT}">
<meta name="pysfmea-payload-sha256" content="{payload_sha}">
<meta name="pysfmea-document-sha256" content="{_DOCUMENT_MARKER}">
<title>{_escape(title)}</title>
<style>
:root{{--ink:#172033;--muted:#657089;--paper:#f4f7fb;--card:#fff;--line:#d9e1ec;--blue:#2357c6;--navy:#102855;--green:#13734a;--green-bg:#e7f6ee;--red:#a52b3a;--red-bg:#fbecef;--shadow:0 12px 28px rgba(24,42,79,.08)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}a{{color:var(--blue)}}
.skip{{position:absolute;left:-9999px;top:8px;background:#fff;padding:10px;z-index:20}}.skip:focus{{left:8px}}header{{background:linear-gradient(125deg,var(--navy),var(--blue));color:#fff;padding:42px clamp(20px,5vw,72px)}}header h1{{font-size:clamp(30px,5vw,52px);line-height:1.08;margin:0 0 10px}}header p{{max-width:900px;margin:6px 0;color:#e5ecff}}
nav{{position:sticky;top:0;z-index:10;display:flex;gap:6px;overflow:auto;padding:10px clamp(12px,4vw,60px);background:rgba(255,255,255,.96);border-bottom:1px solid var(--line)}}nav a{{text-decoration:none;white-space:nowrap;padding:8px 11px;border-radius:8px;font-weight:700}}nav a:hover,nav a:focus{{background:#e9efff}}
main{{max-width:1450px;margin:auto;padding:28px clamp(14px,4vw,58px) 72px}}section{{scroll-margin-top:74px;margin-bottom:28px}}h2{{font-size:clamp(23px,3vw,34px)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}}.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:var(--shadow)}}.metric strong{{display:block;font-size:28px}}.metric span,.muted{{color:var(--muted)}}
.status{{border-left:6px solid;padding:18px 20px;border-radius:12px;font-weight:760}}.status.pass{{color:var(--green);background:var(--green-bg)}}.status.block{{color:var(--red);background:var(--red-bg)}}.badge{{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:760}}.badge.pass{{color:var(--green);background:var(--green-bg)}}.badge.block{{color:var(--red);background:var(--red-bg)}}
.table{{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}}table{{width:100%;border-collapse:collapse;min-width:700px}}th,td{{padding:11px 13px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{background:#edf2ff;color:#26375e;font-size:12px;text-transform:uppercase}}code{{overflow-wrap:anywhere}}ul{{padding-left:22px}}footer{{max-width:1450px;margin:auto;padding:0 clamp(14px,4vw,58px) 42px;color:var(--muted)}}
</style></head><body><a class="skip" href="#main">Skip to report</a>
<header><p class="muted" style="color:#cdd9ff;text-transform:uppercase;letter-spacing:.1em">PySFMEA evidence workbench</p><h1>{_escape(title)}</h1><p>{_escape(assessment['product']['name'])} {_escape(assessment['product']['version'])} · {_escape(assessment['product']['intended_use'])}</p><p>Exact assessment <code>{_escape(assessment['content_sha256'])}</code></p></header>
<nav aria-label="Report sections"><a href="#decision">Decision</a><a href="#checks">Checks</a><a href="#benchmark">Benchmark</a><a href="#artifacts">Artifacts</a><a href="#human">Human factors</a><a href="#scope">Scope</a></nav>
<main id="main"><section id="decision"><h2>Decision readiness</h2><div class="status {status_class}">{_escape(summary['status'].replace('_',' ').title())}: {summary['checks_passed']} of {summary['checks_required']} gates pass.</div><div class="grid" style="margin-top:14px"><div class="card metric"><strong>{len(benchmark['suite_ids'])}</strong><span>external benchmark suites</span></div><div class="card metric"><strong>{len(benchmark['repository_ids'])}</strong><span>benchmark repositories</span></div><div class="card metric"><strong>{len(benchmark['comparator_tools'])}</strong><span>comparator tools</span></div><div class="card metric"><strong>{len(artifacts)}</strong><span>bound machine artifacts</span></div></div></section>
<section id="checks"><h2>Qualification gates</h2><div class="table"><table><thead><tr><th>Gate</th><th>Status</th></tr></thead><tbody>{checks_html}</tbody></table></div></section>
<section id="benchmark"><h2>Composite benchmark</h2><div class="grid"><div class="card"><h3>Suites</h3><ul>{''.join(f'<li><code>{_escape(item)}</code></li>' for item in benchmark['suite_ids']) or '<li>None</li>'}</ul></div><div class="card"><h3>Population types</h3><ul>{''.join(f'<li>{_escape(item)}</li>' for item in benchmark['suite_types']) or '<li>None</li>'}</ul></div><div class="card"><h3>Comparators</h3><ul>{''.join(f'<li>{_escape(item)}</li>' for item in benchmark['comparator_tools']) or '<li>None</li>'}</ul></div><div class="card"><h3>Trace controls</h3><p>External provenance: <b>{benchmark['external_suite_provenance']}</b></p><p>Exact suite/repository trace: <b>{benchmark['exact_suite_repository_trace']}</b></p><p>Independent comparator runners: <b>{benchmark['comparator_independence']}</b></p></div></div></section>
<section id="artifacts"><h2>Exact evidence artifacts</h2><div class="table"><table><thead><tr><th>Kind</th><th>Reference</th><th>Format</th><th>Integrity</th><th>Outcome</th><th>SHA-256</th></tr></thead><tbody>{artifact_rows}</tbody></table></div><div class="card" style="margin-top:14px"><h3>Interoperability</h3><p><b>Required:</b> {_escape(', '.join(interoperability['required_formats']) or 'No formats selected')}</p><p><b>Passing:</b> {_escape(', '.join(interoperability['passing_formats']) or 'No passing round trips supplied')}</p></div></section>
<section id="human"><h2>Human and operational validation</h2><div class="card"><h3>Representative usability</h3><div class="table"><table><thead><tr><th>Study</th><th>Participants</th><th>Task success</th><th>Critical errors</th><th>Status</th></tr></thead><tbody>{_rows(studies, ('id','participant_count','task_success_rate','critical_use_errors','passed'))}</tbody></table></div></div><div class="grid" style="margin-top:14px"><div class="card"><h3>Formal verification</h3><p>{len(formal)} governed record(s); {sum(item['passed'] for item in formal)} pass.</p></div><div class="card"><h3>Continuity exercises</h3><p>{len(continuity)} governed exercise(s); {sum(item['passed'] for item in continuity)} pass.</p></div></div></section>
<section id="scope"><h2>Scope and authority boundary</h2><div class="card"><p><b>Operational scope:</b> {_escape(assessment['product']['operational_scope'])}</p><p><b>Authority:</b> {_escape(assessment['authority']['approval_authority'])}</p><h3>Limitations</h3><ul>{''.join(f'<li>{_escape(item)}</li>' for item in assessment['limitations']) or '<li>No additional limitations recorded.</li>'}</ul><p>{_escape(assessment['notice'])}</p></div></section>
<script id="pysfmea-assessment" type="application/octet-stream">{payload}</script></main><footer>Self-contained evidence projection. Verify with <code>sfmea validation-portfolio-report-verify</code>.</footer></body></html>"""
    digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
    return document.replace(_DOCUMENT_MARKER, digest, 1)


def export_validation_portfolio_report(
    assessment_source: str | Path,
    destination: str | Path,
    *,
    title: str = "Industry validation portfolio",
) -> Path:
    document = load_bounded_json_document(
        assessment_source,
        label="industry validation portfolio assessment",
        max_bytes=100 * 1024 * 1024,
        max_depth=160,
        max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("portfolio assessment must contain an object")
    report = validation_portfolio_report_html(document.value, title=title)
    return atomic_publish_text(destination, report, label="validation portfolio report")


def verify_validation_portfolio_report_file(
    source: str | Path, *, assessment_source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    checks = {
        "report_format": False,
        "payload_present": False,
        "payload_integrity": False,
        "payload_semantics": False,
        "document_integrity": False,
        "assessment_binding": None,
    }
    document_sha256 = ""
    passed = False
    try:
        snapshot = load_bounded_file_snapshot(
            source, label="validation portfolio HTML report", max_bytes=MAX_REPORT_BYTES
        )
        text = snapshot.raw.decode("utf-8")
        format_match = re.search(
            r'<meta name="pysfmea-report-format" content="([^"]+)">', text
        )
        payload_sha_match = re.search(
            r'<meta name="pysfmea-payload-sha256" content="([0-9a-f]{64})">', text
        )
        document_match = re.search(
            r'<meta name="pysfmea-document-sha256" content="([0-9a-f]{64})">', text
        )
        payload_match = re.search(
            r'<script id="pysfmea-assessment" type="application/octet-stream">([^<]+)</script>',
            text,
        )
        checks["report_format"] = bool(
            format_match and format_match.group(1) == VALIDATION_PORTFOLIO_REPORT_FORMAT
        )
        checks["payload_present"] = payload_match is not None
        if not all((payload_sha_match, document_match, payload_match)):
            raise ValueError("report integrity metadata or embedded payload is missing")
        assert payload_sha_match is not None
        assert document_match is not None
        assert payload_match is not None
        payload_bytes = base64.b64decode(payload_match.group(1), validate=True)
        checks["payload_integrity"] = (
            hashlib.sha256(payload_bytes).hexdigest() == payload_sha_match.group(1)
        )
        payload_value = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(payload_value, dict):
            raise ValueError("embedded portfolio assessment must be an object")
        payload_verdict = verify_validation_portfolio_assessment(payload_value)
        checks["payload_semantics"] = payload_verdict["valid"]
        passed = bool(payload_verdict["passed"])
        normalized = text.replace(document_match.group(1), _DOCUMENT_MARKER, 1)
        document_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        checks["document_integrity"] = document_sha256 == document_match.group(1)
        if assessment_source is not None:
            assessment = load_bounded_json_document(
                assessment_source,
                label="industry validation portfolio assessment",
                max_bytes=100 * 1024 * 1024,
                max_depth=160,
                max_nodes=3_000_000,
            ).value
            checks["assessment_binding"] = assessment == payload_value
        if not all(state is not False for state in checks.values()) or not all(
            state for state in checks.values() if state is not None
        ):
            errors.append("report integrity, semantics, or exact binding failed")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    valid = bool(
        checks["report_format"]
        and checks["payload_present"]
        and checks["payload_integrity"]
        and checks["payload_semantics"]
        and checks["document_integrity"]
        and checks["assessment_binding"] is not False
        and not errors
    )
    return {
        "format": VALIDATION_PORTFOLIO_REPORT_VERIFICATION_FORMAT,
        "valid": valid,
        "passed": bool(valid and passed),
        "checks": checks,
        "errors": errors,
        "document_sha256": document_sha256,
        "notice": "Verification proves report and embedded-assessment integrity, not evidence truth, independence, qualification, or certification.",
    }
