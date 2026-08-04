"""Local-only browser review application for an SFMEA analysis file."""

from __future__ import annotations

import json
import hashlib
import threading
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .discovery import review_suggestion
from .store import add_manual_item, load_analysis, save_analysis, update_item_review
from .validation import validate_analysis
from .version import __version__


REVIEW_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PySFMEA Review</title>
<style>
:root { --ink:#17231f; --muted:#60706a; --paper:#f4f1e9; --panel:#fffdf8; --line:#d8d5cb; --accent:#176b57; --accent2:#d7eee7; --danger:#a33b2e; --warn:#a76a00; --shadow:0 8px 24px rgba(22,42,35,.08); }
* { box-sizing:border-box; }
body { margin:0; color:var(--ink); background:var(--paper); font:14px/1.45 Inter, ui-sans-serif, system-ui, sans-serif; }
button,input,textarea,select { font:inherit; }
button { cursor:pointer; }
.top { position:sticky; top:0; z-index:4; display:flex; align-items:center; gap:18px; padding:13px 22px; color:white; background:#123c32; box-shadow:var(--shadow); }
.brand { font:700 20px/1.1 Georgia,serif; letter-spacing:.02em; }
.project { opacity:.78; }
.top .spacer { flex:1; }
.btn { border:1px solid transparent; border-radius:7px; padding:8px 12px; background:var(--accent); color:white; }
.btn.secondary { color:var(--ink); background:var(--panel); border-color:var(--line); }
.btn.ghost { color:white; background:transparent; border-color:rgba(255,255,255,.35); }
.layout { display:grid; grid-template-columns:390px minmax(460px,1fr); min-height:calc(100vh - 58px); }
.index { border-right:1px solid var(--line); background:#ebe8df; overflow:auto; height:calc(100vh - 58px); }
.summary { display:grid; grid-template-columns:repeat(5,1fr); gap:6px; padding:16px; }
.metric { padding:11px; border:1px solid var(--line); border-radius:8px; background:var(--panel); }
.metric b { display:block; font-size:19px; }
.metric span { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
.filters { display:grid; grid-template-columns:1fr 120px; gap:8px; padding:0 16px 12px; }
.filters input,.filters select { width:100%; padding:8px; border:1px solid var(--line); border-radius:7px; background:var(--panel); }
.items { padding:0 10px 18px; }
.item { width:100%; margin:4px 0; padding:11px 12px; text-align:left; color:var(--ink); border:1px solid transparent; border-radius:8px; background:transparent; }
.item:hover { background:rgba(255,255,255,.6); }
.item.selected { border-color:#9cbeb4; background:var(--panel); box-shadow:0 3px 12px rgba(22,42,35,.06); }
.item-head { display:flex; gap:8px; align-items:center; }
.item-title { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:700; }
.item-mode { display:-webkit-box; margin-top:5px; overflow:hidden; color:#4f5e58; -webkit-line-clamp:2; -webkit-box-orient:vertical; }
.tag { display:inline-block; padding:2px 6px; border-radius:999px; font-size:10px; text-transform:uppercase; letter-spacing:.04em; background:#dfe4e1; }
.tag.high,.tag.changed,.tag.impacted { color:#7f251b; background:#f5d8d4; }.tag.medium,.tag.new,.tag.moved { color:#754b00; background:#f4e5bf; }.tag.low,.tag.accepted,.tag.unchanged { color:#245c4d; background:#d6ebe4; }.tag.rejected,.tag.removed { color:#6b6760; background:#dedbd4; }.tag.manual { color:#354e78; background:#dce5f5; }
.editor { height:calc(100vh - 58px); overflow:auto; padding:26px clamp(20px,4vw,54px) 60px; }
.empty { max-width:620px; margin:80px auto; padding:36px; background:var(--panel); border:1px solid var(--line); border-radius:12px; box-shadow:var(--shadow); }
.editor-head { max-width:1040px; margin:auto; }
.eyebrow { color:var(--accent); font-weight:700; text-transform:uppercase; letter-spacing:.08em; font-size:11px; }
h1 { margin:5px 0 5px; font:700 clamp(24px,3vw,36px)/1.15 Georgia,serif; }
.source { color:var(--muted); }
.notice { margin:18px 0; padding:12px 14px; border-left:4px solid var(--accent); background:var(--accent2); }
.form { max-width:1040px; margin:20px auto; display:grid; grid-template-columns:1fr 1fr; gap:15px 18px; }
.field { min-width:0; }
.field.wide { grid-column:1/-1; }
label { display:block; margin-bottom:5px; font-weight:700; }
.hint { color:var(--muted); font-size:12px; font-weight:400; }
input,textarea,select { width:100%; border:1px solid #c9c8c0; border-radius:7px; padding:9px 10px; color:var(--ink); background:var(--panel); }
textarea { resize:vertical; min-height:76px; }
input:focus,textarea:focus,select:focus { outline:3px solid rgba(23,107,87,.15); border-color:var(--accent); }
.ratings { grid-column:1/-1; display:grid; grid-template-columns:repeat(3,1fr); gap:12px; padding:14px; border:1px solid var(--line); border-radius:9px; background:#eeece5; }
.rating input { max-width:90px; }
.rpn { align-self:end; padding:9px; color:var(--muted); }
.actions { position:sticky; bottom:0; grid-column:1/-1; display:flex; align-items:center; gap:10px; padding:12px; border:1px solid var(--line); border-radius:9px; background:rgba(255,253,248,.96); box-shadow:var(--shadow); }
.save-state { color:var(--muted); }
dialog { max-width:780px; border:1px solid var(--line); border-radius:12px; padding:0; box-shadow:0 20px 60px rgba(0,0,0,.25); }
dialog::backdrop { background:rgba(13,31,25,.5); }
.dialog-body { padding:24px 28px; }
.dialog-body h2 { font-family:Georgia,serif; }
.dialog-body li { margin:8px 0; }
.dialog-actions { padding:12px 24px; text-align:right; background:#eeece5; }
.health-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin:16px 0; }
.health-grid .metric { background:#f7f5ef; }
@media(max-width:850px){ .layout{grid-template-columns:1fr}.index{height:auto;max-height:43vh;border-right:0;border-bottom:1px solid var(--line)}.editor{height:auto}.form{grid-template-columns:1fr}.field.wide,.ratings,.actions{grid-column:1}.ratings{grid-template-columns:1fr}.top{gap:8px;padding:10px}.top .project{display:none}.top .btn{padding:7px 8px;font-size:12px}.health-grid{grid-template-columns:1fr 1fr} }
</style>
</head>
<body>
<header class="top"><div class="brand">PySFMEA</div><div class="project" id="projectName"></div><div class="spacer"></div><button class="btn ghost" id="healthBtn">Analysis health</button><button class="btn ghost" id="suggestionsBtn">Machine suggestions</button><button class="btn ghost" id="guidanceBtn">Review guide</button><button class="btn secondary" id="addBtn">Add failure mode</button></header>
<main class="layout">
  <aside class="index">
    <div class="summary" id="summary"></div>
    <div class="filters"><input id="search" placeholder="Filter component or failure…"><select id="filter"><option value="active">Active</option><option value="gate_errors">Quality-gate errors</option><option value="new">New</option><option value="changed">Changed</option><option value="impacted">Transitively impacted</option><option value="moved">Moved / renamed</option><option value="revalidation">Needs revalidation</option><option value="unreviewed">Unreviewed</option><option value="accepted">Accepted</option><option value="action_required">Action required</option><option value="removed">Removed</option><option value="all">All</option></select></div>
    <div class="items" id="items"></div>
  </aside>
  <section class="editor" id="editor"><div class="empty"><div class="eyebrow">Review workspace</div><h1>Select a candidate failure mode</h1><p>Confirm the intended function, decide whether the candidate is credible, then trace its local effect to the system/end effect. Scanner priority is only a triage aid—it is not severity.</p></div></section>
</main>
<dialog id="guide"><div class="dialog-body"><h2>Software FMEA review sequence</h2><p id="methodNotice"></p><ol id="checklist"></ol><h3>Guidance basis</h3><div id="sources"></div></div><div class="dialog-actions"><button class="btn" onclick="document.getElementById('guide').close()">Close</button></div></dialog>
<dialog id="suggestions"><div class="dialog-body"><h2>Grounded machine suggestions</h2><p>Suggestions cannot set ratings, approve risk, or overwrite reviewed records. Accepting creates a new unreviewed worksheet item.</p><div id="suggestionList"></div></div><div class="dialog-actions"><button class="btn" onclick="document.getElementById('suggestions').close()">Close</button></div></dialog>
<dialog id="health"><div class="dialog-body"><h2>Analysis health</h2><p>These are completeness and linkage indicators, not evidence that the analysis or controls are correct.</p><div id="healthContent"></div></div><div class="dialog-actions"><button class="btn" onclick="document.getElementById('health').close()">Close</button></div></dialog>
<script>
const state={analysis:null,validation:null,selected:null,dirty:false,listLimit:200};
const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const lines=value=>(value||[]).join('\n');
async function load(){const [a,v]=await Promise.all([fetch('/api/analysis'),fetch('/api/validation')]);state.analysis=await a.json();state.validation=await v.json();$('projectName').textContent=state.analysis.project.name;renderSummary();renderHealth();renderContextGuide();renderSuggestions();renderList();if(state.selected){const match=state.analysis.items.find(x=>x.id===state.selected);if(match){renderEditor(match);renderEvidence(match);}}}
function activeItems(){return state.analysis.items.filter(x=>x.source_status!=='removed');}
function itemFindings(id){return (state.validation?.findings||[]).filter(x=>x.item_id===id);}
function renderSummary(){const a=activeItems(),u=a.filter(x=>x.review.disposition==='unreviewed').length,hi=a.filter(x=>x.scanner.screening_priority==='high').length,rv=a.filter(x=>x.review.revalidation_required).length,ve=state.validation?.counts?.error||0;$('summary').innerHTML=`<div class="metric"><b>${a.length}</b><span>candidates</span></div><div class="metric"><b>${u}</b><span>unreviewed</span></div><div class="metric"><b>${hi}</b><span>high screen</span></div><div class="metric"><b>${rv}</b><span>revalidate</span></div><div class="metric"><b>${ve}</b><span>gate errors</span></div>`;}
function renderHealth(){const a=activeItems(),reviewed=a.filter(x=>x.review.disposition!=='unreviewed').length,c=state.analysis.context||{},components=state.analysis.components||[],runtime=state.analysis.runtime_evidence||{},imports=runtime.imports||[],mapped=imports.reduce((n,x)=>n+Number(x.mapped_span_count||0),0),unmapped=imports.reduce((n,x)=>n+Number(x.unmapped_span_count||0),0),projectFindings=(state.validation?.findings||[]).filter(x=>!x.item_id),pct=(n,d)=>d?Math.round(100*n/d)+'%':'n/a';$('healthContent').innerHTML=`<div class="health-grid"><div class="metric"><b>${pct(reviewed,a.length)}</b><span>review coverage</span></div><div class="metric"><b>${components.filter(x=>(x.requirement_ids||[]).length).length}/${components.length}</b><span>components with requirements</span></div><div class="metric"><b>${components.filter(x=>(x.interface_ids||[]).length).length}/${components.length}</b><span>components with interfaces</span></div><div class="metric"><b>${(c.requirements||[]).length}</b><span>requirements</span></div><div class="metric"><b>${(c.hazards||[]).length}</b><span>hazards</span></div><div class="metric"><b>${(c.contracts||[]).length}</b><span>contracts</span></div><div class="metric"><b>${mapped}</b><span>mapped spans</span></div><div class="metric"><b>${unmapped}</b><span>unmapped spans</span></div><div class="metric"><b>${state.validation?.counts?.error||0}</b><span>gate errors</span></div></div><h3>Project-level findings</h3>${projectFindings.length?`<ul>${projectFindings.slice(0,50).map(x=>`<li><b>${esc(x.level.toUpperCase())}</b> ${esc(x.message)}</li>`).join('')}</ul>`:'<p>No project-level completeness findings.</p>'}`;}
function renderGuide(){const m=state.analysis.methodology,c=state.analysis.context||{},p=c.project||{},risk=c.risk||{};$('methodNotice').innerHTML=`${esc(m.notice)}<hr><b>Purpose:</b> ${esc(p.purpose||'Not configured')}<br><b>Boundary:</b> ${esc(p.boundary||'Not configured')}<br><b>Operating context:</b> ${esc(p.operating_context||'Not configured')}<br><b>Risk method:</b> ${esc(risk.method||'Not configured')}<br><span class="hint">${esc(risk.acceptance_policy||'')}</span>`;$('checklist').innerHTML=m.review_checklist.map(x=>`<li>${esc(x)}</li>`).join('');const hazards=(c.hazards||[]).map(h=>`<p><b>${esc(h.id)}</b> — ${esc(h.description)}<br><span class="hint">${esc(h.end_effect||'')} ${h.severity?'(S='+esc(h.severity)+')':''}</span></p>`).join('');$('sources').innerHTML=(hazards?'<h3>Project hazards</h3>'+hazards:'')+m.basis.map(x=>`<p><a href="${esc(x.url)}" target="_blank">${esc(x.title)}</a><br><span class="hint">${esc(x.use)}</span></p>`).join('');}
function renderContextGuide(){const m=state.analysis.methodology,c=state.analysis.context||{},p=c.project||{},a=c.analysis||{},risk=c.risk||{},list=v=>(v||[]).map(x=>`<li>${esc(typeof x==='string'?x:JSON.stringify(x))}</li>`).join('')||'<li>Not configured</li>';$('methodNotice').innerHTML=`${esc(m.notice)}<hr><b>Purpose:</b> ${esc(p.purpose||'Not configured')}<br><b>Boundary:</b> ${esc(p.boundary||'Not configured')}<br><b>Operating context:</b> ${esc(p.operating_context||'Not configured')}<br><b>Lifecycle phase / revision:</b> ${esc(a.phase||'Not configured')} / ${esc(a.revision||'Not configured')}<br><b>Risk method:</b> ${esc(risk.method||'Not configured')}<br><span class="hint">${esc(risk.acceptance_policy||'')}</span><details><summary>Ground rules and assumptions</summary><ul>${list([...(a.ground_rules||[]),...(p.assumptions||[]),...(a.fault_tolerance_assumptions||[])])}</ul></details>`;$('checklist').innerHTML=m.review_checklist.map(x=>`<li>${esc(x)}</li>`).join('');const hazards=(c.hazards||[]).map(h=>`<p><b>${esc(h.id)}</b> - ${esc(h.description)}<br><span class="hint">${esc(h.end_effect||'')} ${h.severity?'(S='+esc(h.severity)+')':''}</span></p>`).join(''),requirements=(c.requirements||[]).map(r=>`<p><b>${esc(r.id)}</b> - ${esc(r.text)}</p>`).join(''),interfaces=(c.system_interfaces||[]).map(i=>`<p><b>${esc(i.id)}</b> - ${esc(i.source)} to ${esc(i.target)}<br><span class="hint">${esc(i.description||'')}</span></p>`).join(''),reviewers=(c.reviewers||[]).map(r=>`<p><b>${esc(r.name)}</b> - ${esc(r.role||'role not configured')} (${esc(r.organization||'organization not configured')})</p>`).join('');$('sources').innerHTML=(hazards?'<h3>Project hazards</h3>'+hazards:'')+(requirements?'<h3>Requirements</h3>'+requirements:'')+(interfaces?'<h3>System interfaces</h3>'+interfaces:'')+(reviewers?'<h3>Review team</h3>'+reviewers:'')+m.basis.map(x=>`<p><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.title)}</a><br><span class="hint">${esc(x.use)}</span></p>`).join('');}
function renderEvidence(item){const evidence=item.scanner?.evidence||[],header=$('editor').querySelector('.editor-head');if(!evidence.length||!header)return;header.insertAdjacentHTML('beforeend',`<details><summary>Scanner evidence (${evidence.length})</summary><ul>${evidence.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></details>`);}
function renderSuggestions(){const values=(state.analysis.suggestions||[]).sort((a,b)=>(a.status==='proposed'?0:1)-(b.status==='proposed'?0:1)),shown=values.slice(0,200);$('suggestionsBtn').textContent=`Machine suggestions (${values.filter(x=>x.status==='proposed').length})`;$('suggestionList').innerHTML=shown.map(x=>`<div class="notice"><div class="eyebrow">${esc(x.status)} · ${esc(x.confidence)} · ${esc(x.id)}</div><h3>${esc(x.component_reference)}</h3><p>${esc(x.content?.failure_mode||'')}</p><p class="hint">Evidence: ${esc((x.evidence_ids||[]).join(', '))}</p>${x.uncertainties?.length?`<p><b>Uncertainties:</b> ${esc(x.uncertainties.join('; '))}</p>`:''}${x.status==='proposed'?`<button class="btn" onclick="reviewSuggestion('${esc(x.id)}','accept')">Accept into worksheet</button> <button class="btn secondary" onclick="reviewSuggestion('${esc(x.id)}','reject')">Reject</button>`:''}</div>`).join('')||'<p>No machine suggestions have been generated.</p>';if(values.length>shown.length)$('suggestionList').insertAdjacentHTML('beforeend',`<p class="hint">Showing the first ${shown.length} of ${values.length} suggestions. Use the CLI JSON view for the complete collection.</p>`);}
async function reviewSuggestion(id,decision){if(state.dirty&&!window.confirm('Discard unsaved worksheet changes?'))return;const reviewer=window.prompt('Reviewer name');if(!reviewer)return;const rationale=window.prompt('Review rationale');if(!rationale)return;const response=await fetch('/api/suggestions/'+encodeURIComponent(id),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision,reviewer,rationale})});const result=await response.json();if(!response.ok){window.alert(result.error||response.status);return;}state.dirty=false;await load();renderSuggestions();}
function visibleItems(){const q=$('search').value.trim().toLowerCase(),f=$('filter').value,errors=x=>itemFindings(x.id).filter(y=>y.level==='error').length;return state.analysis.items.filter(item=>{const r=item.review,s=item.scanner,hay=[item.id,item.component.qualname,r.function,r.failure_mode,s.guideword,item.source.path,(r.linked_hazards||[]).join(' ')].join(' ').toLowerCase();if(q&&!hay.includes(q))return false;if(f==='active')return item.source_status!=='removed';if(f==='removed')return item.source_status==='removed';if(f==='all')return true;if(f==='gate_errors')return item.source_status!=='removed'&&errors(item)>0;if(f==='action_required')return item.source_status!=='removed'&&r.status==='action_required';if(f==='revalidation')return item.source_status!=='removed'&&r.revalidation_required;if(['new','changed','impacted','moved'].includes(f))return item.source_status!=='removed'&&item.source_change===f;return item.source_status!=='removed'&&r.disposition===f;}).sort((a,b)=>errors(b)-errors(a)||Number(b.review.revalidation_required)-Number(a.review.revalidation_required)||({changed:0,impacted:1,moved:2,new:3,manual:4,unchanged:5,legacy:6,removed:7}[a.source_change]??9)-({changed:0,impacted:1,moved:2,new:3,manual:4,unchanged:5,legacy:6,removed:7}[b.source_change]??9)||({high:0,medium:1,low:2,manual:3}[a.scanner.screening_priority]??9)-({high:0,medium:1,low:2,manual:3}[b.scanner.screening_priority]??9));}
function renderList(){const all=visibleItems(),items=all.slice(0,state.listLimit);$('items').innerHTML=items.map(item=>{const p=item.scanner.screening_priority,r=item.review,change=item.source_change||'',selected=item.id===state.selected?' selected':'',errors=itemFindings(item.id).filter(x=>x.level==='error').length;return `<button class="item${selected}" data-id="${esc(item.id)}"><div class="item-head"><span class="item-title">${esc(item.component.qualname)}</span>${errors?`<span class="tag high">${errors} gate</span>`:''}<span class="tag ${esc(change)}">${esc(change)}</span><span class="tag ${esc(p)}">${esc(p)}</span><span class="tag ${esc(r.disposition)}">${esc(r.disposition)}</span></div><div class="item-mode">${r.revalidation_required?'⚠ Revalidation required · ':''}${esc(r.failure_mode||item.scanner.failure_mode)}</div></button>`;}).join('')||'<p style="padding:18px;color:var(--muted)">No candidates match this filter.</p>';if(all.length>items.length)$('items').insertAdjacentHTML('beforeend',`<button class="item" id="moreItems"><b>Show more</b><div class="item-mode">Showing ${items.length} of ${all.length} matching records</div></button>`);$('items').querySelectorAll('[data-id]').forEach(el=>el.onclick=()=>select(el.dataset.id));if($('moreItems'))$('moreItems').onclick=()=>{state.listLimit+=200;renderList();};}
function select(id){if(id!==state.selected&&state.dirty&&!window.confirm('Discard unsaved changes and open another record?'))return;state.dirty=false;state.selected=id;const item=state.analysis.items.find(x=>x.id===id);renderList();renderEditor(item);renderEvidence(item);}
function field(label,key,value,wide=false,hint='',rows=0,type='text'){const cls=wide?'field wide':'field',bounds=type==='number'?' min="1" max="10" step="1"':'';const control=rows?`<textarea data-field="${key}" rows="${rows}">${esc(value)}</textarea>`:`<input data-field="${key}" type="${type}"${bounds} value="${esc(value)}">`;return `<div class="${cls}"><label>${label}${hint?` <span class="hint">${hint}</span>`:''}</label>${control}</div>`;}
function checkboxField(label,key,value,hint=''){return `<div class="field wide"><label><input data-field="${key}" type="checkbox" style="width:auto;margin-right:8px" ${value?'checked':''}>${label} <span class="hint">${hint}</span></label></div>`;}
function selectField(label,key,value,options){return `<div class="field"><label>${label}</label><select data-field="${key}">${options.map(x=>`<option value="${esc(x)}" ${x===value?'selected':''}>${esc(String(x).replaceAll('_',' '))}</option>`).join('')}</select></div>`;}
function categoryField(label,key,value,categories){return categories.length?selectField(label,key,value,['',...categories]):field(label,key,value,true,'Configure risk.severity_categories to govern categorical values');}
function renderEditor(item){const r=item.review,s=item.scanner,src=item.source,removed=item.source_status==='removed',changed=['changed','impacted','moved'].includes(item.source_change),findings=itemFindings(item.id),gate=findings.length?`<div class="notice"><b>Quality-gate findings:</b><ul>${findings.map(x=>`<li>${esc(x.level.toUpperCase())}: ${esc(x.message)}</li>`).join('')}</ul></div>`:'',history=(item.review_history||[]).map(x=>`<li>${esc(x.at)} — ${esc(x.reviewer)}: ${esc(Object.keys(x.changes||{}).join(', ')||x.event)}</li>`).join(''),categories=state.analysis.context?.risk?.severity_categories||[],reviewers=(state.analysis.context?.reviewers||[]).map(x=>x.name);$('editor').innerHTML=`<div class="editor-head"><div class="eyebrow">${esc(s.guideword)} · ${esc(item.id)}</div><h1>${esc(item.component.qualname)}</h1><div class="source">${esc(src.path)}:${esc(src.line)} · ${esc(item.component.signature)}</div>${removed?'<div class="notice">This source-backed candidate was removed by a later scan. It remains here for traceability.</div>':''}${changed?`<div class="notice"><b>Implementation context changed or was impacted.</b> ${esc((item.change_reasons||[]).join('; '))}. Prior effects, controls, ratings, and closure evidence must be confirmed.</div>`:''}${gate}<div class="notice"><b>Scanner rationale:</b> ${esc((s.screening_reasons||[]).join('; ')||'generic software failure guideword')}. Review this claim against the actual system context.</div>${history?`<details><summary>Review history (${item.review_history.length})</summary><ul>${history}</ul></details>`:''}</div><form class="form" id="reviewForm">
${selectField('Disposition','disposition',r.disposition,['unreviewed','accepted','rejected','needs_information'])}
${selectField('Workflow status','status',r.status,['draft','in_review','action_required','verified','closed'])}
${field('Disposition rationale','disposition_rationale',r.disposition_rationale||'',true,'Explain acceptance, rejection, or information needed',2)}
${reviewers.length?selectField('Current reviewer','reviewer',r.reviewer||'',['',...reviewers]):field('Current reviewer','reviewer',r.reviewer||'',true,'Configure the cross-functional review team in sfmea.toml')}
${field('Intended function','function',r.function,true,'What must this element do?',2)}
${field('Requirement / trace IDs','requirement',r.requirement,true,'One configured ID per line',2)}
${field('Linked hazard IDs','linked_hazards',lines(r.linked_hazards),true,'One per line; must correspond to the configured hazard set',2)}
${field('Failure mode','failure_mode',r.failure_mode||s.failure_mode,true,'How the function fails—not merely the coding defect',3)}
${field('Initiating condition / trigger','trigger',r.trigger||s.trigger,true,'Condition that activates the failure',2)}
${field('Potential causes','causes',lines(r.causes),true,'One per line',4)}
${field('Local effect','local_effect',r.local_effect,false,'At this component',3)}
${field('Next-higher effect','next_higher_effect',r.next_higher_effect,false,'At caller/subsystem',3)}
${field('System / end effect','end_effect',r.end_effect,true,'Consequence to user, mission, safety, data, or service',3)}
<div class="ratings"><div class="rating">${field('Severity (1–10)','severity',r.severity??'',false,'Rate the end effect',0,'number')}</div><div class="rating">${field('Occurrence (1–10)','occurrence',r.occurrence??'',false,'Use a defined scale/evidence',0,'number')}</div><div class="rating">${field('Detection (1–10)','detection',r.detection??'',false,'Rate existing controls',0,'number')}</div><div class="rpn" id="rpn">RPN: ${rpn(r)}</div></div>
${categoryField('Severity category','severity_category',r.severity_category||'',categories)}
${field('Severity rationale','severity_rationale',r.severity_rationale,false,'Why this consequence rating?',2)}
${field('Occurrence rationale','occurrence_rationale',r.occurrence_rationale,false,'Activation/history evidence',2)}
${field('Detection rationale','detection_rationale',r.detection_rationale,true,'How likely are existing controls to detect/prevent escape?',2)}
${field('Existing prevention controls','prevention_controls',lines(r.prevention_controls),false,'One per line; design controls',4)}
${field('Existing detection controls','detection_controls',lines(r.detection_controls),false,'One per line; tests, monitors, validation',4)}
${field('Recommended actions','recommended_actions',lines(r.recommended_actions),false,'One per line',4)}
${field('Verification evidence','verification_evidence',lines(r.verification_evidence),false,'Tests, results, monitoring, review records',4)}
${field('Actions actually taken','actions_taken',lines(r.actions_taken),false,'Implemented changes, one per line',4)}
<div class="ratings"><div class="rating">${field('Post-action Severity','post_action_severity',r.post_action_severity??'',false,'Usually unchanged unless the effect changed',0,'number')}</div><div class="rating">${field('Post-action Occurrence','post_action_occurrence',r.post_action_occurrence??'',false,'After implemented prevention',0,'number')}</div><div class="rating">${field('Post-action Detection','post_action_detection',r.post_action_detection??'',false,'After implemented detection',0,'number')}</div><div class="rpn" id="postRpn">Post-action RPN: ${postRpn(r)}</div></div>
${categoryField('Post-action severity category','post_action_severity_category',r.post_action_severity_category||'',categories)}
${field('Post-action severity rationale','post_action_severity_rationale',r.post_action_severity_rationale,false,'Why did consequence change or remain?',2)}
${field('Post-action occurrence rationale','post_action_occurrence_rationale',r.post_action_occurrence_rationale,false,'Evidence after action',2)}
${field('Post-action detection rationale','post_action_detection_rationale',r.post_action_detection_rationale,true,'Evidence after action',2)}
${field('Owner','owner',r.owner)}${field('Target date','target_date',r.target_date,false,'',0,'date')}
${field('Approved by','approved_by',r.approved_by,false,'Named authorized reviewer')}${field('Approval date','approval_date',r.approval_date,false,'',0,'date')}
${r.revalidation_required?checkboxField('Source-change revalidation complete','revalidation_required',false,'Check only after effects, controls, ratings, actions, and evidence have been confirmed against the current source.'):'<div class="field wide"><span class="hint">No source-change revalidation is pending for this item.</span></div>'}
${field('Notes / assumptions','notes',r.notes,true,'Record scope, assumptions, decisions, and residual concerns',4)}
<div class="actions"><button class="btn" type="submit">Save review</button><button class="btn secondary" id="saveNext" type="button">Save &amp; next</button><span class="save-state" id="saveState">Changes are saved to the local analysis file.</span></div></form>`;
$('reviewForm').onsubmit=save;$('saveNext').onclick=event=>save(event,true);$('reviewForm').querySelectorAll('[data-field]').forEach(x=>x.addEventListener('input',markDirty));$('reviewForm').querySelectorAll('[data-field="severity"],[data-field="occurrence"],[data-field="detection"]').forEach(x=>x.oninput=()=>{$('rpn').textContent='RPN: '+rpn(readForm());});$('reviewForm').querySelectorAll('[data-field="post_action_severity"],[data-field="post_action_occurrence"],[data-field="post_action_detection"]').forEach(x=>x.oninput=()=>{$('postRpn').textContent='Post-action RPN: '+postRpn(readForm());});}
function markDirty(){state.dirty=true;const status=$('saveState');if(status)status.textContent='Unsaved changes — press Ctrl+S to save.';}
function rpn(v){const vals=['severity','occurrence','detection'].map(k=>Number(v[k]));return vals.every(x=>x>=1&&x<=10)?vals.reduce((a,b)=>a*b,1):'—';}
function postRpn(v){const vals=['post_action_severity','post_action_occurrence','post_action_detection'].map(k=>Number(v[k]));return vals.every(x=>x>=1&&x<=10)?vals.reduce((a,b)=>a*b,1):'—';}
function readForm(){const out={};$('reviewForm').querySelectorAll('[data-field]').forEach(el=>{let v=el.type==='checkbox'?!el.checked:el.value;if(['causes','linked_hazards','prevention_controls','detection_controls','recommended_actions','actions_taken','verification_evidence'].includes(el.dataset.field))v=v.split('\n').map(x=>x.trim()).filter(Boolean);if(['severity','occurrence','detection','post_action_severity','post_action_occurrence','post_action_detection'].includes(el.dataset.field))v=v===''?null:Number(v);out[el.dataset.field]=v;});return out;}
async function save(ev,advance=false){ev.preventDefault();const ordered=visibleItems(),position=ordered.findIndex(x=>x.id===state.selected),nextId=position>=0?ordered[position+1]?.id:null,status=$('saveState');status.textContent='Saving…';try{const response=await fetch('/api/items/'+encodeURIComponent(state.selected),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(readForm())});const result=await response.json();if(response.status===409){state.dirty=false;await load();window.alert(result.error);return;}if(!response.ok){status.textContent='Save failed: '+(result.error||response.status);return;}state.dirty=false;await load();if(advance&&nextId&&state.analysis.items.some(x=>x.id===nextId))select(nextId);}catch(error){status.textContent='Save failed: '+error.message;}}
$('healthBtn').onclick=()=>{renderHealth();$('health').showModal();};$('suggestionsBtn').onclick=()=>{renderSuggestions();$('suggestions').showModal();};$('guidanceBtn').onclick=()=>$('guide').showModal();$('addBtn').onclick=async()=>{if(state.dirty&&!window.confirm('Discard unsaved changes before adding a failure mode?'))return;const selected=state.analysis.items.find(x=>x.id===state.selected);const response=await fetch('/api/items',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({component_id:selected?.component_id||null})});const item=await response.json();state.dirty=false;await load();select(item.id);};$('search').oninput=()=>{state.listLimit=200;renderList();};$('filter').onchange=()=>{state.listLimit=200;renderList();};window.addEventListener('beforeunload',event=>{if(state.dirty){event.preventDefault();event.returnValue='';}});document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='s'&&$('reviewForm')){event.preventDefault();$('reviewForm').requestSubmit();}else if((event.ctrlKey||event.metaKey)&&event.key==='Enter'&&$('reviewForm')){event.preventDefault();save(event,true);}else if(event.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){event.preventDefault();$('search').focus();}});load();
</script>
</body></html>"""


class _ReviewState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.analysis = load_analysis(path)
        self.lock = threading.RLock()
        self.file_fingerprint = self._fingerprint()

    def _fingerprint(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def reload_if_changed(self) -> bool:
        fingerprint = self._fingerprint()
        if fingerprint == self.file_fingerprint:
            return False
        self.analysis = load_analysis(self.path)
        self.file_fingerprint = fingerprint
        return True

    def saved(self) -> None:
        self.file_fingerprint = self._fingerprint()


class _ConcurrentUpdateError(RuntimeError):
    pass


def _handler(state: _ReviewState) -> type[BaseHTTPRequestHandler]:
    class ReviewHandler(BaseHTTPRequestHandler):
        server_version = f"PySFMEA/{__version__}"

        def do_GET(self) -> None:  # noqa: N802
            route = urllib.parse.urlparse(self.path).path
            if route == "/":
                self._send_bytes(REVIEW_HTML.encode("utf-8"), "text/html; charset=utf-8")
            elif route == "/api/analysis":
                with state.lock:
                    state.reload_if_changed()
                    self._send_json(state.analysis)
            elif route == "/api/validation":
                with state.lock:
                    state.reload_if_changed()
                    self._send_json(validate_analysis(state.analysis))
            else:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_PUT(self) -> None:  # noqa: N802
            route = urllib.parse.urlparse(self.path).path
            suggestion_prefix = "/api/suggestions/"
            if route.startswith(suggestion_prefix):
                suggestion_id = urllib.parse.unquote(route[len(suggestion_prefix) :])
                try:
                    changes = self._read_json()
                    with state.lock:
                        if state.reload_if_changed():
                            raise _ConcurrentUpdateError(
                                "analysis changed outside this reviewer; reload before reviewing the suggestion"
                            )
                        suggestion = review_suggestion(
                            state.analysis,
                            suggestion_id,
                            decision=changes.get("decision", ""),
                            reviewer=changes.get("reviewer", ""),
                            rationale=changes.get("rationale", ""),
                        )
                        save_analysis(state.path, state.analysis)
                        state.saved()
                    self._send_json(suggestion)
                except _ConcurrentUpdateError as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
                except KeyError:
                    self._send_json({"error": "unknown suggestion"}, HTTPStatus.NOT_FOUND)
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            prefix = "/api/items/"
            if not route.startswith(prefix):
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            item_id = urllib.parse.unquote(route[len(prefix) :])
            try:
                changes = self._read_json()
                with state.lock:
                    if state.reload_if_changed():
                        raise _ConcurrentUpdateError(
                            "analysis changed outside this reviewer; it was reloaded, so review the latest record before saving again"
                        )
                    item = update_item_review(state.analysis, item_id, changes)
                    save_analysis(state.path, state.analysis)
                    state.saved()
                self._send_json(item)
            except _ConcurrentUpdateError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except KeyError:
                self._send_json({"error": "unknown item"}, HTTPStatus.NOT_FOUND)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_POST(self) -> None:  # noqa: N802
            route = urllib.parse.urlparse(self.path).path
            if route != "/api/items":
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            try:
                body = self._read_json()
                with state.lock:
                    if state.reload_if_changed():
                        raise _ConcurrentUpdateError(
                            "analysis changed outside this reviewer; it was reloaded, so try again"
                        )
                    item = add_manual_item(state.analysis, body.get("component_id"))
                    save_analysis(state.path, state.analysis)
                    state.saved()
                self._send_json(item, HTTPStatus.CREATED)
            except _ConcurrentUpdateError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def _read_json(self) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ValueError("Content-Type must be application/json")
            origin = self.headers.get("Origin")
            if origin:
                parsed = urllib.parse.urlparse(origin)
                if parsed.scheme != "http" or parsed.netloc != self.headers.get("Host"):
                    raise ValueError("cross-origin changes are not permitted")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                raise ValueError("request body must be between 1 byte and 1 MB")
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("request body must be a JSON object")
            return value

        def _send_json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            self._send_bytes(
                json.dumps(value, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
                status,
            )

        def _send_bytes(
            self,
            body: bytes,
            content_type: str,
            status: HTTPStatus = HTTPStatus.OK,
        ) -> None:
            self.send_response(status.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "form-action 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            # Keep terminal output concise; unexpected exceptions are still shown by HTTPServer.
            return

    return ReviewHandler


def serve_review(
    analysis_path: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> None:
    path = Path(analysis_path).expanduser().resolve()
    state = _ReviewState(path)
    server = ThreadingHTTPServer((host, port), _handler(state))
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"PySFMEA review is available at {url}")
    print(f"Saving changes to {path}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nReview server stopped.")
    finally:
        server.server_close()
