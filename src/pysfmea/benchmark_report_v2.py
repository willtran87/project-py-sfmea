"""Self-contained, integrity-bound reviewer report for benchmark format 2."""

from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any

from .benchmark_v2 import verify_benchmark_v2_assessment
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_file_snapshot, load_bounded_json_document
from .version import __version__

BENCHMARK_REPORT_V2_FORMAT = "pysfmea-independent-benchmark-report-2"
BENCHMARK_REPORT_V2_VERIFICATION_FORMAT = "pysfmea-independent-benchmark-report-verification-2"
DOCUMENT_PLACEHOLDER = "__PYSFMEA_DOCUMENT_SHA256__"


def _safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")


def _rows(values: list[tuple[str, str, str]]) -> str:
    return "".join(
        f"<tr><th scope='row'>{html.escape(name)}</th><td>{html.escape(value)}</td><td><span class='{state}'>{html.escape(state.upper())}</span></td></tr>"
        for name, value, state in values
    )


def _template(assessment: dict[str, Any], *, title: str, payload: str, payload_sha: str) -> str:
    summary = assessment["summary"]
    passed = bool(summary["passed"])
    metric_rows = []
    for name, value in assessment["metrics"].items():
        state = "pass" if assessment["metric_checks"][name] else "block"
        metric_rows.append((name, f"recall lower {value['recall']['conservative_lower']}; precision lower {value['precision']['conservative_lower']}", state))
    stratum_rows = []
    for key, state_value in assessment["stratum_metric_checks"].items():
        stratum_rows.append((key, "conservative precision and recall bounds", "pass" if state_value else "block"))
    check_rows = [(name, "governed benchmark gate", "pass" if state else "block") for name, state in assessment["checks"].items()]
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="pysfmea-report-format" content="{BENCHMARK_REPORT_V2_FORMAT}">
<meta name="pysfmea-report-data-sha256" content="{payload_sha}"><meta name="pysfmea-document-sha256" content="{DOCUMENT_PLACEHOLDER}">
<title>{html.escape(title)}</title><style>
:root{{--ink:#172033;--muted:#5d6879;--paper:#f4f7fb;--card:#fff;--line:#d8e0ec;--accent:#2457d6;--pass:#08734a;--passbg:#e7f7ef;--block:#a12d2d;--blockbg:#fff0ef}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}header{{padding:40px clamp(20px,6vw,80px);color:#fff;background:linear-gradient(125deg,#12244f,#2457d6)}}header h1{{margin:0 0 8px;font-size:clamp(28px,4vw,48px)}}header p{{margin:4px 0;color:#e3eaff}}main{{max-width:1400px;margin:auto;padding:28px clamp(15px,5vw,64px) 60px;display:grid;gap:22px}}.status,.card{{border:1px solid var(--line);border-radius:14px;background:var(--card);padding:18px}}.status{{border-left:7px solid}}.status.pass{{border-left-color:var(--pass);background:var(--passbg)}}.status.block{{border-left-color:var(--block);background:var(--blockbg)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}}.metric strong{{display:block;font-size:28px}}.metric span{{color:var(--muted)}}.table{{overflow:auto;border:1px solid var(--line);border-radius:10px}}table{{border-collapse:collapse;width:100%;min-width:700px}}th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line)}}thead th{{background:#eaf0ff}}span.pass,span.block{{display:inline-block;padding:3px 9px;border-radius:999px;font-weight:750;font-size:12px}}span.pass{{color:var(--pass);background:var(--passbg)}}span.block{{color:var(--block);background:var(--blockbg)}}code{{overflow-wrap:anywhere}}.notice{{color:var(--muted)}}@media(prefers-color-scheme:dark){{:root{{--ink:#edf2ff;--muted:#b6c1d4;--paper:#0c1220;--card:#141d2e;--line:#344057}}thead th{{background:#202d47}}}}@media print{{body{{background:#fff}}header{{background:#fff;color:#000;padding:0 0 20px}}header p{{color:#333}}main{{max-width:none;padding:0}}.card{{break-inside:avoid}}}}
</style></head><body><header><p>PySFMEA independent benchmark evidence</p><h1>{html.escape(title)}</h1><p>Protocol {html.escape(str(assessment['protocol']['id']))} · PySFMEA {html.escape(__version__)}</p></header><main>
<section class="status {'pass' if passed else 'block'}" aria-label="Benchmark status"><strong>{'Eligible for authorized independent review' if passed else 'Benchmark evidence incomplete'}</strong><div>This is evidence for review, not tool qualification or certification.</div></section>
<section class="cards" aria-label="Summary"><div class="card metric"><strong>{summary['repositories']}</strong><span>repositories</span></div><div class="card metric"><strong>{summary['metrics_passing']} / {summary['metrics_required']}</strong><span>overall metrics passing</span></div><div class="card metric"><strong>{summary['stratum_metrics_passing']} / {summary['stratum_metrics_required']}</strong><span>stratum metrics passing</span></div><div class="card metric"><strong>{assessment['reviewer_agreement']['alpha']}</strong><span>Krippendorff alpha</span></div><div class="card metric"><strong>{assessment['calibration']['brier_score']}</strong><span>Brier score</span></div><div class="card metric"><strong>{assessment['calibration']['expected_calibration_error']}</strong><span>calibration error</span></div></section>
<section class="card"><h2>Governed gates</h2><div class="table"><table><thead><tr><th>Gate</th><th>Basis</th><th>Result</th></tr></thead><tbody>{_rows(check_rows)}</tbody></table></div></section>
<section class="card"><h2>Overall metric bounds</h2><div class="table"><table><thead><tr><th>Metric</th><th>Conservative bounds</th><th>Result</th></tr></thead><tbody>{_rows(metric_rows)}</tbody></table></div></section>
<section class="card"><h2>Performance inside represented strata</h2><div class="table"><table><thead><tr><th>Stratum and metric</th><th>Basis</th><th>Result</th></tr></thead><tbody>{_rows(stratum_rows)}</tbody></table></div></section>
<section class="card"><h2>Bindings and limits</h2><p><strong>Assessment SHA-256:</strong> <code>{html.escape(str(assessment['content_sha256']))}</code></p><p class="notice">{html.escape(str(assessment['notice']))}</p><p class="notice">The complete machine-readable assessment is embedded below and bound to this document.</p></section>
</main><script id="benchmark-data" type="application/json">{payload}</script></body></html>'''


def export_benchmark_v2_report(
    assessment_source: str | Path, destination: str | Path, *, title: str = "Independent benchmark review"
) -> Path:
    document = load_bounded_json_document(assessment_source, label="benchmark assessment v2", max_bytes=100_000_000, max_depth=150, max_nodes=3_000_000)
    if not isinstance(document.value, dict):
        raise ValueError("benchmark assessment must contain an object")
    verdict = verify_benchmark_v2_assessment(document.value)
    if not verdict["valid"]:
        raise ValueError("benchmark assessment is not structurally and semantically valid")
    payload = _safe_json(document.value)
    payload_sha = canonical_json_sha256(document.value)
    unsigned = _template(document.value, title=title, payload=payload, payload_sha=payload_sha)
    digest = hashlib.sha256(unsigned.encode("utf-8")).hexdigest()
    rendered = unsigned.replace(DOCUMENT_PLACEHOLDER, digest)
    return atomic_publish_text(destination, rendered, label="benchmark v2 HTML report")


def verify_benchmark_v2_report_file(
    source: str | Path, *, assessment_source: str | Path | None = None
) -> dict[str, Any]:
    checks = {"report_format": False, "payload_present": False, "payload_integrity": False, "payload_semantics": False, "document_integrity": False, "assessment_binding": None}
    errors: list[str] = []
    try:
        snapshot = load_bounded_file_snapshot(source, label="benchmark v2 HTML report", max_bytes=50_000_000)
        text = snapshot.raw.decode("utf-8")
        format_match = re.search(r'<meta name="pysfmea-report-format" content="([^"]+)">', text)
        payload_sha_match = re.search(r'<meta name="pysfmea-report-data-sha256" content="([0-9a-f]{64})">', text)
        document_sha_match = re.search(r'<meta name="pysfmea-document-sha256" content="([0-9a-f]{64})">', text)
        payload_match = re.search(r'<script id="benchmark-data" type="application/json">(.*?)</script>', text, re.DOTALL)
        checks["report_format"] = bool(format_match and format_match.group(1) == BENCHMARK_REPORT_V2_FORMAT)
        checks["payload_present"] = payload_match is not None
        value = json.loads(payload_match.group(1)) if payload_match else None
        checks["payload_integrity"] = bool(isinstance(value, dict) and payload_sha_match and canonical_json_sha256(value) == payload_sha_match.group(1))
        checks["payload_semantics"] = bool(isinstance(value, dict) and verify_benchmark_v2_assessment(value)["valid"])
        if document_sha_match:
            unsigned = text.replace(document_sha_match.group(1), DOCUMENT_PLACEHOLDER, 1)
            checks["document_integrity"] = hashlib.sha256(unsigned.encode("utf-8")).hexdigest() == document_sha_match.group(1)
        if assessment_source is not None and isinstance(value, dict):
            assessment, _ = _load_assessment(assessment_source)
            checks["assessment_binding"] = assessment == value
        for name, state in checks.items():
            if state is False:
                errors.append(f"benchmark report check failed: {name}")
        valid = all(state is not False for state in checks.values())
        return {"path": str(snapshot.path), "format": BENCHMARK_REPORT_V2_VERIFICATION_FORMAT, "valid": valid, "passed": bool(valid and isinstance(value, dict) and value.get("summary", {}).get("passed")), "checks": checks, "errors": errors, "document_sha256": hashlib.sha256(snapshot.raw).hexdigest(), "notice": "Verification proves report and payload integrity, not benchmark independence, label truth, qualification, or certification."}
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {"path": str(Path(source).expanduser().absolute()), "format": BENCHMARK_REPORT_V2_VERIFICATION_FORMAT, "valid": False, "passed": False, "checks": checks, "errors": [str(exc)], "document_sha256": "", "notice": "The benchmark report could not be safely verified."}


def _load_assessment(source: str | Path) -> tuple[dict[str, Any], Path]:
    document = load_bounded_json_document(source, label="benchmark assessment v2", max_bytes=100_000_000, max_depth=150, max_nodes=3_000_000)
    if not isinstance(document.value, dict):
        raise ValueError("benchmark assessment must contain an object")
    return document.value, document.path
