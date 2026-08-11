"""Self-contained, integrity-bound qualification campaign reporting."""

from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_file_snapshot, parse_bounded_json_bytes
from .qualification import (
    MAX_QUALIFICATION_RESULT_BYTES,
    load_qualification_campaign_result,
    verify_qualification_campaign,
)
from .version import __version__

QUALIFICATION_REPORT_FORMAT = "pysfmea-qualification-report-1"
QUALIFICATION_REPORT_VERIFICATION_FORMAT = (
    "pysfmea-qualification-report-verification-1"
)
MAX_QUALIFICATION_REPORT_BYTES = 40_000_000
QUALIFICATION_REPORT_CHECKS = (
    "metadata_complete",
    "report_format",
    "payload_present",
    "payload_json",
    "payload_integrity",
    "payload_semantics",
    "document_integrity",
    "result_binding",
)


def _safe_json(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", r"\u0026")
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
    )


def _meta(document: str, name: str) -> str:
    match = re.search(rf'<meta name="{re.escape(name)}" content="([^"]*)">', document)
    return match.group(1) if match else ""


def _template(
    result: dict[str, Any],
    *,
    title: str,
    payload: str,
    payload_sha256: str,
    result_sha256: str,
) -> str:
    summary = result["summary"]
    feature = result["features"]["finding_detection"]
    semantic_feature = result["features"]["semantic_output"]
    eligible = bool(result["eligible_for_independent_review"])
    status_class = "pass" if eligible else "block"
    status_label = (
        "Eligible for independent review"
        if eligible
        else "Qualification evidence incomplete"
    )
    return rf'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Evidence-backed PySFMEA scanner qualification campaign review.">
<meta name="color-scheme" content="light dark">
<meta name="pysfmea-report-format" content="{QUALIFICATION_REPORT_FORMAT}">
<meta name="pysfmea-result-sha256" content="{result_sha256}">
<meta name="pysfmea-report-data-sha256" content="{payload_sha256}">
<meta name="pysfmea-document-sha256" content="__DOCUMENT_SHA__">
<title>{html.escape(title)}</title>
<style>
:root{{--ink:#172033;--muted:#5f6b7c;--paper:#f5f7fb;--card:#fff;--line:#dce2ec;--accent:#2457d6;--accent2:#173c9b;--pass:#12734b;--pass-bg:#e8f7ef;--block:#a12d2d;--block-bg:#fff0ef;--warn:#855a08;--warn-bg:#fff7dc;--shadow:0 12px 30px rgba(23,32,51,.08)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}a{{color:var(--accent)}}.sr-only{{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}}.skip{{position:absolute;left:-9999px;top:8px;background:var(--ink);color:#fff;padding:10px;z-index:20}}.skip:focus{{left:8px}}header{{background:linear-gradient(125deg,#12244f,#2457d6);color:#fff;padding:38px clamp(20px,5vw,72px) 32px}}header h1{{max-width:1100px;margin:0 0 8px;font-size:clamp(28px,4vw,48px);line-height:1.12}}header p{{max-width:900px;margin:6px 0;color:#e4ebff}}.eyebrow{{letter-spacing:.1em;text-transform:uppercase;font-size:12px;font-weight:750}}nav{{position:sticky;top:0;z-index:10;display:flex;gap:6px;overflow:auto;padding:10px clamp(12px,4vw,60px);background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);box-shadow:0 4px 16px rgba(23,32,51,.06)}}nav button{{white-space:nowrap;border:0;background:transparent;color:var(--muted);padding:9px 13px;border-radius:8px;font-weight:700;cursor:pointer}}nav button[aria-selected="true"]{{background:#e9efff;color:var(--accent2)}}button:focus-visible,input:focus-visible,[tabindex]:focus-visible{{outline:3px solid #ffbf47;outline-offset:2px}}main{{max-width:1480px;margin:auto;padding:28px clamp(14px,4vw,58px) 64px}}.view{{display:grid;gap:20px}}.view[hidden]{{display:none}}h2{{font-size:clamp(24px,3vw,34px);margin:0}}h3{{margin:0 0 8px}}.lead{{color:var(--muted);max-width:920px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}}.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:var(--shadow);min-width:0}}.metric strong{{display:block;font-size:28px;line-height:1.2}}.metric span{{color:var(--muted)}}.status{{border-left:6px solid;padding:18px 20px;border-radius:12px;font-weight:750}}.status.pass{{color:var(--pass);background:var(--pass-bg);border-color:var(--pass)}}.status.block{{color:var(--block);background:var(--block-bg);border-color:var(--block)}}.notice{{background:var(--warn-bg);color:#604100;border:1px solid #ead691;border-radius:12px;padding:14px 16px}}.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}}table{{width:100%;border-collapse:collapse;min-width:760px}}th,td{{padding:11px 13px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{position:sticky;top:0;background:#edf2ff;color:#26375e;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}tbody tr:hover{{background:#f7f9fe}}.badge{{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:750}}.badge.pass{{background:var(--pass-bg);color:var(--pass)}}.badge.block{{background:var(--block-bg);color:var(--block)}}.badge.na{{background:#eef1f5;color:#5b6574}}.toolbar{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}input[type="search"]{{min-width:min(100%,340px);padding:10px 12px;border:1px solid #aeb8c8;border-radius:8px;background:var(--card);color:var(--ink)}}.pager{{display:flex;align-items:center;gap:10px}}.pager button{{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:8px 12px;border-radius:8px;cursor:pointer}}.pager button:disabled{{opacity:.45;cursor:not-allowed}}code{{overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:minmax(150px,240px) 1fr;gap:8px 18px}}dt{{font-weight:750}}dd{{margin:0;color:var(--muted)}}footer{{max-width:1480px;margin:auto;padding:0 clamp(14px,4vw,58px) 40px;color:var(--muted)}}
@media(max-width:700px){{header{{padding-top:28px}}main{{padding-top:20px}}dl{{grid-template-columns:1fr;gap:2px}}dd{{margin-bottom:10px}}}}
@media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}*,*::before,*::after{{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}}}
@media(prefers-contrast:more){{:root{{--line:#667085}}.card,.table-wrap{{box-shadow:none}}}}
@media print{{nav,.skip,.toolbar,.pager{{display:none!important}}body{{background:#fff}}header{{background:#fff;color:#000;padding:0 0 20px}}header p{{color:#333}}main{{max-width:none;padding:0}}.view[hidden]{{display:grid!important}}.card{{box-shadow:none;break-inside:avoid}}th{{position:static}}}}
@media(prefers-color-scheme:dark){{:root{{--ink:#edf2ff;--muted:#b5c0d3;--paper:#0c1220;--card:#141d2e;--line:#344057;--accent:#91b2ff;--accent2:#d1ddff;--shadow:none}}nav{{background:rgba(20,29,46,.97)}}nav button[aria-selected="true"]{{background:#273a66}}th{{background:#202d47;color:#edf2ff}}tbody tr:hover{{background:#1b263c}}input[type="search"],.pager button{{background:var(--card);color:var(--ink)}}.notice{{background:#3a2d0d;color:#ffe7a2;border-color:#6f571f}}}}
</style>
</head>
<body>
<a class="skip skip-link" href="#main">Skip to report content</a>
<header><div class="eyebrow">PySFMEA qualification evidence</div><h1>{html.escape(title)}</h1><p>{html.escape(str(result['campaign']['purpose']))}</p><p>Campaign <strong>{html.escape(str(result['campaign']['id']))}</strong> · generated by PySFMEA {html.escape(__version__)}</p></header>
<nav aria-label="Report sections">
<button type="button" data-view="overview" aria-selected="true">Overview</button>
<button type="button" data-view="repositories" aria-selected="false">Repositories</button>
<button type="button" data-view="segments" aria-selected="false">Segments</button>
<button type="button" data-view="rules" aria-selected="false">Rules</button>
<button type="button" data-view="semantics" aria-selected="false">Semantics</button>
<button type="button" data-view="evidence" aria-selected="false">Evidence &amp; authority</button>
</nav>
<main id="main" tabindex="-1">
<noscript><div class="notice"><strong>JavaScript is disabled.</strong> The status summary remains available, but interactive tables require JavaScript. The complete machine result remains embedded in this document.</div></noscript>
<section class="view" id="view-overview" data-view-panel="overview" aria-labelledby="overview-title"><div><h2 id="overview-title" tabindex="-1">Qualification overview</h2><p class="lead">Population-weighted results, evidence gates, and explicit blockers. Passing advances the package to independent review; it is not certification.</p></div>
<div class="status {status_class}" role="status">{html.escape(status_label)}</div>
<div class="cards">
<div class="card metric"><strong>{summary['repository_count']}</strong><span>retained repositories</span></div>
<div class="card metric"><strong>{feature['expected']}</strong><span>expected finding cases</span></div>
<div class="card metric"><strong>{feature['recall'] if feature['recall'] is not None else 'N/A'}</strong><span>finding recall</span></div>
<div class="card metric"><strong>{feature['precision'] if feature['precision'] is not None else 'N/A'}</strong><span>finding precision</span></div>
<div class="card metric"><strong>{semantic_feature['matched']} / {semantic_feature['expected']}</strong><span>exact semantic cases</span></div>
<div class="card metric"><strong>{summary['framework_count']}</strong><span>framework segments</span></div>
<div class="card metric"><strong>{summary['domain_count']}</strong><span>domain segments</span></div>
</div>
<div class="card"><h3>Qualification gates</h3><p class="lead">False blocks eligibility. Not applicable means the population was not required or was absent and receives no accuracy credit.</p><div class="table-wrap" tabindex="0" aria-label="Qualification gate results"><table><caption class="sr-only">Qualification gate results and interpretations</caption><thead><tr><th scope="col">Gate</th><th scope="col">Result</th><th scope="col">Interpretation</th></tr></thead><tbody id="gateRows"></tbody></table></div></div>
<div class="card"><h3>Feature populations</h3><div class="table-wrap" tabindex="0" aria-label="Feature accuracy"><table><caption class="sr-only">Finding, call-resolution, control-detection, and semantic-output accuracy</caption><thead><tr><th scope="col">Feature</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">Matched</th><th scope="col">Recall</th><th scope="col">Precision</th><th scope="col">Repositories</th><th scope="col">Control components positive / negative</th></tr></thead><tbody id="featureRows"></tbody></table></div></div></section>

<section class="view" id="view-repositories" data-view-panel="repositories" aria-labelledby="repositories-title" hidden><div><h2 id="repositories-title" tabindex="-1">Repository evidence</h2><p class="lead">Exact retained inputs, evaluation quality, and repository-level accuracy. Control rows disclose positive and negative evaluated components so precision is not mistaken for positive-only matching.</p></div><div class="table-wrap" tabindex="0" aria-label="Repository evidence"><table><caption class="sr-only">Repository-level qualification evidence and quality</caption><thead><tr><th scope="col">Repository</th><th scope="col">Frameworks / domains</th><th scope="col">Finding recall / precision</th><th scope="col">Call recall / precision</th><th scope="col">Control recall / precision and positive / negative scope</th><th scope="col">Semantic recall / precision</th><th scope="col">Governance</th><th scope="col">Quality</th></tr></thead><tbody id="repositoryRows"></tbody></table></div></section>

<section class="view" id="view-segments" data-view-panel="segments" aria-labelledby="segments-title" hidden><div><h2 id="segments-title" tabindex="-1">Framework and domain segments</h2><p class="lead">Segment metrics make population imbalance visible. Findings must satisfy the configured minimum in every represented framework and domain.</p></div><div class="card"><h3>Frameworks</h3><div class="table-wrap" tabindex="0" aria-label="Framework segment metrics"><table><caption class="sr-only">Framework segment finding metrics</caption><thead><tr><th scope="col">Framework</th><th scope="col">Repositories</th><th scope="col">Finding cases</th><th scope="col">Recall</th><th scope="col">Precision</th></tr></thead><tbody id="frameworkRows"></tbody></table></div></div><div class="card"><h3>Domains</h3><div class="table-wrap" tabindex="0" aria-label="Domain segment metrics"><table><caption class="sr-only">Domain segment finding metrics</caption><thead><tr><th scope="col">Domain</th><th scope="col">Repositories</th><th scope="col">Finding cases</th><th scope="col">Recall</th><th scope="col">Precision</th></tr></thead><tbody id="domainRows"></tbody></table></div></div></section>

<section class="view" id="view-rules" data-view-panel="rules" aria-labelledby="rules-title" hidden><div><h2 id="rules-title" tabindex="-1">Rule-level performance</h2><p class="lead">Searchable population-weighted rule outcomes. Investigate missing or unexpected findings in the exact evaluation artifacts listed under Evidence.</p></div><div class="card"><div class="toolbar"><label for="ruleSearch"><strong>Search rules</strong></label><input id="ruleSearch" type="search" autocomplete="off" placeholder="Rule ID"><span id="ruleCount" aria-live="polite"></span></div><div class="table-wrap" tabindex="0" aria-label="Rule-level metrics"><table><caption class="sr-only">Rule-level finding precision and recall</caption><thead><tr><th scope="col">Rule</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">Matched</th><th scope="col">Recall</th><th scope="col">Precision</th><th scope="col">Repositories</th></tr></thead><tbody id="ruleRows"></tbody></table></div><div class="pager"><button type="button" id="rulePrev">Previous</button><span id="rulePage" aria-live="polite"></span><button type="button" id="ruleNext">Next</button></div></div></section>

<section class="view" id="view-semantics" data-view-panel="semantics" aria-labelledby="semantics-title" hidden><div><h2 id="semantics-title" tabindex="-1">Semantic-output qualification</h2><p class="lead">Exact curated regression claims for deterministic failure-mode text, local effects, assurance methods, citations, adapters, confidence, and priority. Reviewer-owned ratings and system effects remain outside this evidence.</p></div><div class="card"><h3>Accuracy by output field</h3><div class="table-wrap" tabindex="0" aria-label="Semantic accuracy by output field"><table><caption class="sr-only">Semantic-output accuracy by field</caption><thead><tr><th scope="col">Field</th><th scope="col">Expected claims</th><th scope="col">Evaluated claims</th><th scope="col">Matched claims</th><th scope="col">Recall</th><th scope="col">Precision</th><th scope="col">Repositories</th></tr></thead><tbody id="semanticFieldRows"></tbody></table></div></div><div class="card"><h3>Exact cases by rule</h3><div class="table-wrap" tabindex="0" aria-label="Semantic accuracy by rule"><table><caption class="sr-only">Exact semantic cases by rule</caption><thead><tr><th scope="col">Rule</th><th scope="col">Expected cases</th><th scope="col">Evaluated cases</th><th scope="col">Exact cases</th><th scope="col">Recall</th><th scope="col">Precision</th><th scope="col">Repositories</th></tr></thead><tbody id="semanticRuleRows"></tbody></table></div></div></section>

<section class="view" id="view-evidence" data-view-panel="evidence" aria-labelledby="evidence-title" hidden><div><h2 id="evidence-title" tabindex="-1">Evidence, governance, and authority</h2><p class="lead">Content-addressed sources and the limits on what this report can claim.</p></div><div class="notice"><strong>Authority boundary:</strong> {html.escape(str(result['notice']))}</div><div class="cards"><div class="card"><h3>Campaign governance</h3><dl><dt>Independent</dt><dd>{result['governance']['independent']}</dd><dt>Labeled by</dt><dd>{html.escape(str(result['governance']['labeled_by']))}</dd><dt>Approved by</dt><dd>{html.escape(str(result['governance']['approved_by']))}</dd><dt>Approval date</dt><dd>{html.escape(str(result['governance']['approval_date']))}</dd><dt>Selection method</dt><dd>{html.escape(str(result['governance']['selection_method']))}</dd><dt>Representativeness</dt><dd>{html.escape(str(result['governance']['representativeness_rationale']))}</dd></dl></div><div class="card"><h3>Exact bindings</h3><dl><dt>Result SHA-256</dt><dd><code>{result_sha256}</code></dd><dt>Manifest</dt><dd><code>{html.escape(str(result['manifest']['reference']))}</code></dd><dt>Manifest SHA-256</dt><dd><code>{result['manifest']['sha256']}</code></dd><dt>Campaign status</dt><dd>{html.escape(str(result['status']))}</dd></dl></div></div><div class="card"><h3>Retained artifacts</h3><div class="table-wrap" tabindex="0" aria-label="Retained qualification artifacts"><table><caption class="sr-only">Retained analysis, corpus, and evaluation artifacts</caption><thead><tr><th scope="col">Repository</th><th scope="col">Analysis</th><th scope="col">Corpus</th><th scope="col">Evaluation</th><th scope="col">Corpus reviewers</th></tr></thead><tbody id="artifactRows"></tbody></table></div></div></section>
</main>
<footer><p>Self-contained review report · report format {QUALIFICATION_REPORT_FORMAT} · full machine evidence is embedded in this document.</p></footer>
<script id="qualification-data" type="application/json">{payload}</script>
<script>
(()=>{{"use strict";const data=JSON.parse(document.getElementById("qualification-data").textContent);const $=id=>document.getElementById(id);const node=(tag,text,cls)=>{{const e=document.createElement(tag);e.textContent=String(text??"");if(cls)e.className=cls;return e}};const fmt=v=>v===null||v===undefined?"N/A":typeof v==="number"?v.toLocaleString(undefined,{{maximumFractionDigits:4}}):String(v);const label=s=>String(s).replaceAll("_"," ").replace(/\b\w/g,c=>c.toUpperCase());const cell=(tr,v)=>tr.append(node("td",fmt(v)));const badge=v=>node("span",v===true?"PASS":v===false?"BLOCK":"N/A",`badge ${{v===true?"pass":v===false?"block":"na"}}`);
function setView(name,focus=true){{document.querySelectorAll("[data-view-panel]").forEach(p=>p.hidden=p.dataset.viewPanel!==name);document.querySelectorAll("nav [data-view]").forEach(b=>b.setAttribute("aria-selected",String(b.dataset.view===name)));history.replaceState(null,"",`#${{name}}`);if(focus)document.querySelector(`[data-view-panel="${{name}}"] h2`)?.focus?.()}}document.querySelectorAll("nav [data-view]").forEach(b=>b.addEventListener("click",()=>setView(b.dataset.view)));
const explanations={{artifact_bindings:"Every retained artifact is byte and canonical-content bound.",evaluation_regeneration:"Every evaluation exactly regenerated from its retained analysis and corpus.",campaign_governance:"Campaign roles and selection rationale satisfy the declared separation claim.",independent_corpora:"Every repository corpus carries a structurally complete independence claim.",repository_finding_cases_present:"Every repository has labeled finding cases.",call_cases_present:"The campaign contains required call-resolution labels.",control_cases_present:"The campaign contains required detected-control labels.",control_negative_population:"Every control-bearing repository meets the configured minimum negative-component population.",semantic_cases_present:"The campaign contains required exact semantic-output cases."}};
Object.entries(data.checks).sort((a,b)=>({{false:0,true:1,null:2}}[String(a[1])]-{{false:0,true:1,null:2}}[String(b[1])])).forEach(([k,v])=>{{const tr=document.createElement("tr");cell(tr,label(k));const td=document.createElement("td");td.append(badge(v));tr.append(td);cell(tr,v===null?"Not required by the configured threshold or absent; no accuracy credit is assigned.":explanations[k]||"Measured against the governed campaign contract and thresholds.");$("gateRows").append(tr)}});
Object.entries(data.features).forEach(([k,v])=>{{const tr=document.createElement("tr");[label(k),v.expected,v.actual,v.matched,v.recall,v.precision,v.repositories,k==="control_detection"?`${{v.positive_components}} / ${{v.negative_components}} (${{v.evaluated_components}} total)`:"N/A"].forEach(x=>cell(tr,x));$("featureRows").append(tr)}});
data.repositories.forEach(r=>{{const tr=document.createElement("tr"),f=r.features.finding_detection,c=r.features.call_resolution,d=r.features.control_detection,s=r.features.semantic_output,q=r.quality;cell(tr,r.id);cell(tr,`${{r.frameworks.join(", ")||"unclassified"}} / ${{r.domains.join(", ")||"unclassified"}}`);cell(tr,`${{fmt(f.recall)}} / ${{fmt(f.precision)}} (${{f.matched}}/${{f.expected}})`);cell(tr,`${{fmt(c.recall)}} / ${{fmt(c.precision)}} (${{c.matched}}/${{c.expected}})`);cell(tr,`${{fmt(d.recall)}} / ${{fmt(d.precision)}} (${{d.matched}}/${{d.expected}}) · ${{d.positive_components}} / ${{d.negative_components}} (${{d.evaluated_components}} total)`);cell(tr,`${{fmt(s.recall)}} / ${{fmt(s.precision)}} (${{s.matched}}/${{s.expected}})`);const g=document.createElement("td");g.append(badge(r.corpus_governance_qualification_ready));tr.append(g);cell(tr,q.duplicate_count||q.unsupported_verification_claim_count?"Review required":"Clean");$("repositoryRows").append(tr)}});
function renderSegments(values,target){{Object.entries(values).forEach(([name,s])=>{{const f=s.features.finding_detection,tr=document.createElement("tr");[name,s.repository_ids.join(", "),f.expected,f.recall,f.precision].forEach(x=>cell(tr,x));$(target).append(tr)}})}}renderSegments(data.segments.frameworks,"frameworkRows");renderSegments(data.segments.domains,"domainRows");
let rulePage=1,pageSize=100,printRuleState=null;function renderRules(){{const query=$("ruleSearch").value.trim().toLowerCase(),all=Object.entries(data.by_rule).filter(([k])=>k.toLowerCase().includes(query)),pages=Math.max(1,Math.ceil(all.length/pageSize));rulePage=Math.min(rulePage,pages);const shown=all.slice((rulePage-1)*pageSize,rulePage*pageSize);$("ruleRows").replaceChildren();shown.forEach(([k,v])=>{{const tr=document.createElement("tr");[k,v.expected,v.actual,v.matched,v.recall,v.precision,v.repositories].forEach(x=>cell(tr,x));$("ruleRows").append(tr)}});$("ruleCount").textContent=`${{all.length.toLocaleString()}} matching rules`;$("rulePage").textContent=`Page ${{rulePage}} of ${{pages}}`;$("rulePrev").disabled=rulePage===1;$("ruleNext").disabled=rulePage===pages}}$("ruleSearch").addEventListener("input",()=>{{rulePage=1;renderRules()}});$("rulePrev").addEventListener("click",()=>{{rulePage--;renderRules()}});$("ruleNext").addEventListener("click",()=>{{rulePage++;renderRules()}});renderRules();window.addEventListener("beforeprint",()=>{{printRuleState={{query:$("ruleSearch").value,page:rulePage,size:pageSize}};$("ruleSearch").value="";rulePage=1;pageSize=2000;renderRules()}});window.addEventListener("afterprint",()=>{{if(!printRuleState)return;$("ruleSearch").value=printRuleState.query;rulePage=printRuleState.page;pageSize=printRuleState.size;printRuleState=null;renderRules()}});
function renderMetricMap(values,target){{Object.entries(values).forEach(([name,v])=>{{const tr=document.createElement("tr");[label(name),v.expected,v.actual,v.matched,v.recall,v.precision,v.repositories].forEach(x=>cell(tr,x));$(target).append(tr)}})}}renderMetricMap(data.by_semantic_field,"semanticFieldRows");renderMetricMap(data.by_semantic_rule,"semanticRuleRows");
data.repositories.forEach(r=>{{const tr=document.createElement("tr");cell(tr,r.id);cell(tr,r.artifacts.analysis.reference+" · "+r.artifacts.analysis.sha256);cell(tr,r.artifacts.corpus.reference+" · "+r.artifacts.corpus.sha256);cell(tr,r.artifacts.evaluation.reference+" · "+r.artifacts.evaluation.sha256);cell(tr,r.corpus_governance.labeled_by+" / "+r.corpus_governance.approved_by);$("artifactRows").append(tr)}});
const views=["overview","repositories","segments","rules","semantics","evidence"],initial=location.hash.slice(1);setView(views.includes(initial)?initial:"overview",false);window.addEventListener("hashchange",()=>{{const v=location.hash.slice(1);if(views.includes(v))setView(v,false)}});document.documentElement.dataset.ready="true";
}})();
</script>
</body></html>'''


def export_qualification_report(
    result_source: str | Path,
    manifest_source: str | Path,
    destination: str | Path,
    *,
    title: str | None = None,
) -> Path:
    """Publish a complete-reconciliation-only qualification review report."""

    result = load_qualification_campaign_result(result_source)
    verdict = verify_qualification_campaign(result, manifest=manifest_source)
    if not verdict["reconciled"]:
        detail = "; ".join(verdict["errors"][:5]) or "reconciliation failed"
        raise ValueError(
            f"qualification campaign must completely reconcile before reporting: {detail}"
        )
    payload = _safe_json(result)
    result_sha256 = canonical_json_sha256(result)
    document = _template(
        result,
        title=title or str(result["campaign"]["title"]),
        payload=payload,
        payload_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        result_sha256=result_sha256,
    )
    document_sha256 = hashlib.sha256(
        document.replace("__DOCUMENT_SHA__", "").encode("utf-8")
    ).hexdigest()
    document = document.replace("__DOCUMENT_SHA__", document_sha256)

    def verify_stage(staged: Path) -> bool:
        report_verdict = verify_qualification_report_file(
            staged, result_source=result_source
        )
        current_result = load_qualification_campaign_result(result_source)
        campaign_verdict = verify_qualification_campaign(
            current_result, manifest=manifest_source
        )
        return bool(report_verdict["reconciled"] and campaign_verdict["reconciled"])

    return atomic_publish_text(
        destination,
        document,
        max_bytes=MAX_QUALIFICATION_REPORT_BYTES,
        label="qualification HTML report",
        staged_verifier=verify_stage,
    )


def _rejection(message: str, *, path: str = "") -> dict[str, Any]:
    return {
        "format": QUALIFICATION_REPORT_VERIFICATION_FORMAT,
        "valid": False,
        "reconciled": False,
        "mode": "rejected",
        "checks": {name: None for name in QUALIFICATION_REPORT_CHECKS},
        "declared": {
            "report_format": "",
            "result_sha256": "",
            "payload_sha256": "",
            "document_sha256": "",
        },
        "actual": {
            "result_sha256": "",
            "payload_sha256": "",
            "document_sha256": "",
        },
        "errors": [message],
        "notice": "Rejected reports receive no qualification evidence credit.",
        "path": path,
        "source_bytes": 0,
        "source_sha256": "",
    }


def verify_qualification_report_file(
    source: str | Path, *, result_source: str | Path | None = None
) -> dict[str, Any]:
    """Verify standalone HTML integrity and optionally its exact result binding."""

    path = Path(source).expanduser().absolute()
    try:
        snapshot = load_bounded_file_snapshot(
            path,
            label="qualification HTML report",
            max_bytes=MAX_QUALIFICATION_REPORT_BYTES,
        )
        document = snapshot.raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return _rejection(str(exc), path=str(path))
    declared = {
        "report_format": _meta(document, "pysfmea-report-format"),
        "result_sha256": _meta(document, "pysfmea-result-sha256"),
        "payload_sha256": _meta(document, "pysfmea-report-data-sha256"),
        "document_sha256": _meta(document, "pysfmea-document-sha256"),
    }
    payload_match = re.search(
        r'<script id="qualification-data" type="application/json">(.*?)</script>',
        document,
        re.DOTALL,
    )
    payload_text = payload_match.group(1) if payload_match else ""
    payload: Any = None
    payload_error = ""
    if payload_match:
        try:
            payload = parse_bounded_json_bytes(
                payload_text.encode("utf-8"),
                label="qualification report payload",
                max_bytes=MAX_QUALIFICATION_RESULT_BYTES,
                max_depth=80,
                max_nodes=1_000_000,
            )
        except ValueError as exc:
            payload_error = str(exc)
    payload_sha256 = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
    result_sha256 = canonical_json_sha256(payload) if isinstance(payload, dict) else ""
    marker = (
        '<meta name="pysfmea-document-sha256" content="'
        + declared["document_sha256"]
        + '">'
    )
    normalized = document.replace(
        marker, '<meta name="pysfmea-document-sha256" content="">', 1
    )
    document_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    semantic_verdict = (
        verify_qualification_campaign(payload) if isinstance(payload, dict) else None
    )
    digest = re.compile(r"^[0-9a-f]{64}$")
    checks: dict[str, bool | None] = {
        "metadata_complete": all(declared.values()),
        "report_format": declared["report_format"] == QUALIFICATION_REPORT_FORMAT,
        "payload_present": payload_match is not None,
        "payload_json": isinstance(payload, dict),
        "payload_integrity": bool(
            digest.fullmatch(declared["payload_sha256"])
            and payload_sha256 == declared["payload_sha256"]
            and digest.fullmatch(declared["result_sha256"])
            and result_sha256 == declared["result_sha256"]
        ),
        "payload_semantics": bool(semantic_verdict and semantic_verdict["valid"]),
        "document_integrity": bool(
            digest.fullmatch(declared["document_sha256"])
            and document_sha256 == declared["document_sha256"]
        ),
        "result_binding": None,
    }
    errors = []
    if payload_error:
        errors.append(payload_error)
    result_binding: bool | None = None
    if result_source is not None:
        try:
            expected = load_qualification_campaign_result(result_source)
            result_binding = bool(
                isinstance(payload, dict)
                and canonical_json_sha256(expected) == result_sha256
            )
        except (OSError, ValueError) as exc:
            result_binding = False
            errors.append(f"qualification result binding failed: {exc}")
        checks["result_binding"] = result_binding
    for name, value in checks.items():
        if value is False:
            errors.append(f"qualification report check failed: {name}")
    internal_checks = tuple(
        name for name in QUALIFICATION_REPORT_CHECKS if name != "result_binding"
    )
    valid = all(checks[name] is True for name in internal_checks)
    reconciled = bool(valid and result_binding)
    return {
        "format": QUALIFICATION_REPORT_VERIFICATION_FORMAT,
        "valid": valid,
        "reconciled": reconciled,
        "mode": "complete" if result_source is not None else "standalone",
        "checks": checks,
        "declared": declared,
        "actual": {
            "result_sha256": result_sha256,
            "payload_sha256": payload_sha256,
            "document_sha256": document_sha256,
        },
        "errors": errors,
        "notice": (
            "Report verification proves document integrity and exact result binding when "
            "requested. It does not prove corpus representativeness or grant qualification."
        ),
        "path": str(snapshot.path),
        "source_bytes": snapshot.size,
        "source_sha256": hashlib.sha256(snapshot.raw).hexdigest(),
    }
