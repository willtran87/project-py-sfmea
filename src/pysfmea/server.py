"""Local-only browser review application for an SFMEA analysis file."""

from __future__ import annotations

import gzip
import json
import threading
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .assurance import assurance_progress, assurance_work_queue, review_obligation
from .discovery import review_suggestion
from .store import (
    AnalysisRevisionConflictError,
    add_manual_item,
    analysis_file_sha256,
    load_analysis,
    save_analysis,
    update_item_review,
)
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
button:disabled { cursor:not-allowed; opacity:.55; }
button:focus-visible,a:focus-visible { outline:3px solid #f2bd55; outline-offset:3px; }
.skip-link { position:fixed; z-index:10; top:8px; left:8px; padding:9px 12px; border-radius:7px; color:white; background:#123c32; transform:translateY(-160%); }
.skip-link:focus { transform:translateY(0); }
.visually-hidden { position:absolute!important; width:1px!important; height:1px!important; padding:0!important; margin:-1px!important; overflow:hidden!important; clip:rect(0,0,0,0)!important; white-space:nowrap!important; border:0!important; }
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
dialog { width:780px; max-width:calc(100vw - 24px); max-height:calc(100vh - 24px); overflow:auto; border:1px solid var(--line); border-radius:12px; padding:0; box-shadow:0 20px 60px rgba(0,0,0,.25); }
dialog::backdrop { background:rgba(13,31,25,.5); }
.dialog-body { min-width:0; padding:24px 28px; }
.dialog-body h2 { font-family:Georgia,serif; }
.dialog-body li { margin:8px 0; }
.dialog-actions { padding:12px 24px; text-align:right; background:#eeece5; }
.health-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin:16px 0; }
.health-grid .metric { background:#f7f5ef; }
.assurance-list { min-width:0; display:grid; gap:12px; max-height:64vh; overflow:auto; padding-right:5px; }
.assurance-card { min-width:0; overflow-wrap:anywhere; padding:15px; border:1px solid var(--line); border-radius:9px; background:#f7f5ef; }
.assurance-card h3 { margin:3px 0 7px; }
.assurance-meta { display:flex; flex-wrap:wrap; gap:6px; margin:8px 0; }
.assurance-form { display:grid; grid-template-columns:180px 1fr 1fr auto; gap:8px; align-items:end; margin-top:10px; }
.assurance-form textarea { grid-column:2/4; min-height:58px; }
.assurance-form .btn { grid-column:4; grid-row:1/3; align-self:stretch; }
@media(max-width:850px){ .layout{grid-template-columns:1fr}.index{height:auto;max-height:43vh;border-right:0;border-bottom:1px solid var(--line)}.editor{height:auto}.form{grid-template-columns:1fr}.field.wide,.ratings,.actions{grid-column:1}.ratings{grid-template-columns:1fr}.top{gap:8px;padding:10px}.top .project{display:none}.top .btn{padding:7px 8px;font-size:12px}.dialog-body{padding:18px 16px}.dialog-actions{padding:10px 16px}.health-grid{grid-template-columns:1fr 1fr}.assurance-form{grid-template-columns:1fr}.assurance-form textarea,.assurance-form .btn{grid-column:1;grid-row:auto} }
</style>
</head>
<body>
<a class="skip-link" href="#editor">Skip to finding editor</a>
<header class="top" aria-label="Reviewer tools"><div class="brand">PySFMEA</div><div class="project" id="projectName" role="status" aria-live="polite"></div><div class="spacer"></div><button class="btn ghost" id="healthBtn">Analysis health</button><button class="btn ghost" id="assuranceBtn">Assurance plan</button><button class="btn ghost" id="suggestionsBtn">Machine suggestions</button><button class="btn ghost" id="guidanceBtn">Review guide</button><button class="btn secondary" id="addBtn">Add failure mode</button></header>
<main class="layout" aria-label="SFMEA engineering review workspace">
  <aside class="index" aria-label="Failure-mode index">
    <div class="summary" id="summary" aria-label="Analysis summary"></div>
    <div class="filters"><label class="visually-hidden" for="search">Search failure modes</label><input id="search" type="search" placeholder="Filter component or failure…"><label class="visually-hidden" for="filter">Filter failure modes</label><select id="filter"><option value="active">Active</option><option value="gate_errors">Quality-gate errors</option><option value="new">New</option><option value="changed">Changed</option><option value="impacted">Transitively impacted</option><option value="moved">Moved / renamed</option><option value="revalidation">Needs revalidation</option><option value="unreviewed">Unreviewed</option><option value="accepted">Accepted</option><option value="action_required">Action required</option><option value="removed">Removed</option><option value="all">All</option></select></div>
    <div class="hint" id="listStatus" role="status" aria-live="polite" style="padding:0 16px 8px"></div>
    <div class="items" id="items" aria-label="Matching failure modes"></div>
  </aside>
  <section class="editor" id="editor" tabindex="-1" aria-label="Finding editor"><div class="empty"><div class="eyebrow">Review workspace</div><h1>Select a candidate failure mode</h1><p>Confirm the intended function, decide whether the candidate is credible, then trace its local effect to the system/end effect. Scanner priority is only a triage aid—it is not severity.</p></div></section>
</main>
<dialog id="guide" aria-labelledby="guideTitle"><div class="dialog-body"><h2 id="guideTitle">Software FMEA review sequence</h2><p id="methodNotice"></p><ol id="checklist"></ol><h3>Guidance basis</h3><div id="sources"></div></div><div class="dialog-actions"><button class="btn" type="button" onclick="document.getElementById('guide').close()">Close</button></div></dialog>
<dialog id="suggestions" aria-labelledby="suggestionsTitle"><div class="dialog-body"><h2 id="suggestionsTitle">Grounded machine suggestions</h2><p>Suggestions cannot set ratings, approve risk, or overwrite reviewed records. Accepting creates a new unreviewed worksheet item.</p><div id="suggestionList"></div></div><div class="dialog-actions"><button class="btn" type="button" onclick="document.getElementById('suggestions').close()">Close</button></div></dialog>
<dialog id="health" aria-labelledby="healthTitle"><div class="dialog-body"><h2 id="healthTitle">Analysis health</h2><p>These are completeness and linkage indicators, not evidence that the analysis or controls are correct.</p><div id="healthContent"></div></div><div class="dialog-actions"><button class="btn" type="button" onclick="document.getElementById('health').close()">Close</button></div></dialog>
<dialog id="assurancePlan" tabindex="-1" aria-labelledby="assuranceTitle"><div class="dialog-body"><h2 id="assuranceTitle">Accepted-finding assurance plan</h2><p id="assuranceNotice">Planning decisions define the implementation checklist. They cannot verify evidence, close findings, or accept risk.</p><p class="hint" id="assuranceSaveState" role="status" aria-live="polite"></p><div class="health-grid" id="assuranceMetrics"></div><div class="assurance-list" id="assuranceList"></div></div><div class="dialog-actions"><button class="btn" type="button" onclick="closeAssurancePlan()">Close</button></div></dialog>
<script>
const state={analysis:null,validation:null,assurance:null,revision:'',selected:null,dirty:false,assuranceDirty:false,saving:false,assuranceSaving:false,adding:false,suggestionSaving:false,listLimit:200,findingsByItem:new Map(),itemErrors:new Map(),projectFindings:[]};
const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const lines=value=>(value||[]).join('\n');
async function load(){$('projectName').textContent='Loading review workspace…';try{const response=await fetch('/api/workspace'),workspace=await response.json();if(!response.ok)throw new Error(workspace.error||`Workspace request failed (${response.status})`);state.revision=response.headers.get('ETag')||'';state.analysis=workspace.analysis;state.validation=workspace.validation;state.assurance=workspace.assurance;state.assuranceDirty=false;indexValidation();const params=new URLSearchParams(window.location.search),requested=params.get('item');if(!state.selected&&requested&&state.analysis.items.some(x=>x.id===requested))state.selected=requested;$('projectName').textContent=state.analysis.project.name;renderSummary();renderHealth();renderAssurancePlan();renderContextGuide();renderSuggestions();renderList();if(params.get('view')==='assurance')openAssurancePlan();if(state.selected){const match=state.analysis.items.find(x=>x.id===state.selected);if(match){renderEditor(match);renderEvidence(match);}}return true;}catch(error){$('projectName').textContent='Review workspace unavailable';$('editor').innerHTML=`<div class="empty"><div class="eyebrow">Load interrupted</div><h1>Could not load the governed analysis</h1><p>${esc(error.message||error)}</p><p class="hint">The analysis was not modified. Confirm that the file is readable, then retry.</p><button class="btn" id="retryLoad">Retry</button></div>`;const retry=$('retryLoad');if(retry)retry.onclick=()=>load();return false;}}
const mutationHeaders=()=>({'Content-Type':'application/json','If-Match':state.revision});
async function reloadOnConflict(response,result){if(![409,428].includes(response.status))return false;const message=result.error||'The analysis changed after this page was loaded.',reload=window.confirm(message+'\n\nReload the latest revision now? Cancel keeps the current unsaved fields on screen so you can copy or compare them.');if(reload){state.dirty=false;state.assuranceDirty=false;await load();}else{const saveState=$('saveState');if(saveState)saveState.textContent='Save blocked by a newer revision; current edits remain unsaved.';}return true;}
function activeItems(){return state.analysis.items.filter(x=>x.source_status!=='removed');}
function indexValidation(){state.findingsByItem=new Map();state.itemErrors=new Map();state.projectFindings=[];for(const finding of state.validation?.findings||[]){const id=finding.item_id;if(!id){state.projectFindings.push(finding);continue;}if(!state.findingsByItem.has(id))state.findingsByItem.set(id,[]);state.findingsByItem.get(id).push(finding);if(finding.level==='error')state.itemErrors.set(id,(state.itemErrors.get(id)||0)+1);}}
function itemFindings(id){return state.findingsByItem.get(id)||[];}
function renderDerivedState(){indexValidation();renderSummary();renderHealth();renderAssurancePlan();renderList();if(state.selected){const item=state.analysis.items.find(x=>x.id===state.selected);if(item){renderEditor(item);renderEvidence(item);}}}
async function refreshDerived(expectedRevision){try{const [validationResponse,assuranceResponse]=await Promise.all([fetch('/api/validation'),fetch('/api/assurance')]);if(!validationResponse.ok||!assuranceResponse.ok)return false;const revisions=[validationResponse.headers.get('ETag'),assuranceResponse.headers.get('ETag')];if(revisions.some(value=>value!==expectedRevision))return false;const [validation,assurance]=await Promise.all([validationResponse.json(),assuranceResponse.json()]);state.revision=expectedRevision;state.validation=validation;state.assurance=assurance;renderDerivedState();return true;}catch{return false;}}
async function applyItemMutation(item,revision){const index=state.analysis.items.findIndex(value=>value.id===item.id);if(index>=0)state.analysis.items[index]=item;else state.analysis.items.push(item);state.revision=revision||state.revision;if(!revision||!await refreshDerived(state.revision))return await load();return true;}
function renderSummary(){const a=activeItems(),u=a.filter(x=>x.review.disposition==='unreviewed').length,hi=a.filter(x=>x.scanner.screening_priority==='high').length,rv=a.filter(x=>x.review.revalidation_required).length,ve=state.validation?.counts?.error||0;$('summary').innerHTML=`<div class="metric"><b>${a.length}</b><span>candidates</span></div><div class="metric"><b>${u}</b><span>unreviewed</span></div><div class="metric"><b>${hi}</b><span>high screen</span></div><div class="metric"><b>${rv}</b><span>revalidate</span></div><div class="metric"><b>${ve}</b><span>gate errors</span></div>`;}
function renderHealth(){const a=activeItems(),reviewed=a.filter(x=>x.review.disposition!=='unreviewed').length,c=state.analysis.context||{},components=state.analysis.components||[],runtime=state.analysis.runtime_evidence||{},imports=runtime.imports||[],mapped=imports.reduce((n,x)=>n+Number(x.mapped_span_count||0),0),unmapped=imports.reduce((n,x)=>n+Number(x.unmapped_span_count||0),0),projectFindings=state.projectFindings,pct=(n,d)=>d?Math.round(100*n/d)+'%':'n/a';$('healthContent').innerHTML=`<div class="health-grid"><div class="metric"><b>${pct(reviewed,a.length)}</b><span>review coverage</span></div><div class="metric"><b>${components.filter(x=>(x.requirement_ids||[]).length).length}/${components.length}</b><span>components with requirements</span></div><div class="metric"><b>${components.filter(x=>(x.interface_ids||[]).length).length}/${components.length}</b><span>components with interfaces</span></div><div class="metric"><b>${(c.requirements||[]).length}</b><span>requirements</span></div><div class="metric"><b>${(c.hazards||[]).length}</b><span>hazards</span></div><div class="metric"><b>${(c.contracts||[]).length}</b><span>contracts</span></div><div class="metric"><b>${mapped}</b><span>mapped spans</span></div><div class="metric"><b>${unmapped}</b><span>unmapped spans</span></div><div class="metric"><b>${state.validation?.counts?.error||0}</b><span>gate errors</span></div></div><h3>Project-level findings</h3>${projectFindings.length?`<ul>${projectFindings.slice(0,50).map(x=>`<li><b>${esc(x.level.toUpperCase())}</b> ${esc(x.message)}</li>`).join('')}</ul>`:'<p>No project-level completeness findings.</p>'}`;}
function renderGuide(){const m=state.analysis.methodology,c=state.analysis.context||{},p=c.project||{},risk=c.risk||{};$('methodNotice').innerHTML=`${esc(m.notice)}<hr><b>Purpose:</b> ${esc(p.purpose||'Not configured')}<br><b>Boundary:</b> ${esc(p.boundary||'Not configured')}<br><b>Operating context:</b> ${esc(p.operating_context||'Not configured')}<br><b>Risk method:</b> ${esc(risk.method||'Not configured')}<br><span class="hint">${esc(risk.acceptance_policy||'')}</span>`;$('checklist').innerHTML=m.review_checklist.map(x=>`<li>${esc(x)}</li>`).join('');const hazards=(c.hazards||[]).map(h=>`<p><b>${esc(h.id)}</b> — ${esc(h.description)}<br><span class="hint">${esc(h.end_effect||'')} ${h.severity?'(S='+esc(h.severity)+')':''}</span></p>`).join('');$('sources').innerHTML=(hazards?'<h3>Project hazards</h3>'+hazards:'')+m.basis.map(x=>`<p><a href="${esc(x.url)}" target="_blank">${esc(x.title)}</a><br><span class="hint">${esc(x.use)}</span></p>`).join('');}
function renderContextGuide(){const m=state.analysis.methodology,c=state.analysis.context||{},p=c.project||{},a=c.analysis||{},risk=c.risk||{},list=v=>(v||[]).map(x=>`<li>${esc(typeof x==='string'?x:JSON.stringify(x))}</li>`).join('')||'<li>Not configured</li>';$('methodNotice').innerHTML=`${esc(m.notice)}<hr><b>Purpose:</b> ${esc(p.purpose||'Not configured')}<br><b>Boundary:</b> ${esc(p.boundary||'Not configured')}<br><b>Operating context:</b> ${esc(p.operating_context||'Not configured')}<br><b>Lifecycle phase / revision:</b> ${esc(a.phase||'Not configured')} / ${esc(a.revision||'Not configured')}<br><b>Risk method:</b> ${esc(risk.method||'Not configured')}<br><span class="hint">${esc(risk.acceptance_policy||'')}</span><details><summary>Ground rules and assumptions</summary><ul>${list([...(a.ground_rules||[]),...(p.assumptions||[]),...(a.fault_tolerance_assumptions||[])])}</ul></details>`;$('checklist').innerHTML=m.review_checklist.map(x=>`<li>${esc(x)}</li>`).join('');const hazards=(c.hazards||[]).map(h=>`<p><b>${esc(h.id)}</b> - ${esc(h.description)}<br><span class="hint">${esc(h.end_effect||'')} ${h.severity?'(S='+esc(h.severity)+')':''}</span></p>`).join(''),requirements=(c.requirements||[]).map(r=>`<p><b>${esc(r.id)}</b> - ${esc(r.text)}</p>`).join(''),interfaces=(c.system_interfaces||[]).map(i=>`<p><b>${esc(i.id)}</b> - ${esc(i.source)} to ${esc(i.target)}<br><span class="hint">${esc(i.description||'')}</span></p>`).join(''),reviewers=(c.reviewers||[]).map(r=>`<p><b>${esc(r.name)}</b> - ${esc(r.role||'role not configured')} (${esc(r.organization||'organization not configured')})</p>`).join('');$('sources').innerHTML=(hazards?'<h3>Project hazards</h3>'+hazards:'')+(requirements?'<h3>Requirements</h3>'+requirements:'')+(interfaces?'<h3>System interfaces</h3>'+interfaces:'')+(reviewers?'<h3>Review team</h3>'+reviewers:'')+m.basis.map(x=>`<p><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.title)}</a><br><span class="hint">${esc(x.use)}</span></p>`).join('');}
function renderEvidence(item){const evidence=item.scanner?.evidence||[],header=$('editor').querySelector('.editor-head');if(!evidence.length||!header)return;header.insertAdjacentHTML('beforeend',`<details><summary>Scanner evidence (${evidence.length})</summary><ul>${evidence.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></details>`);}
function renderSuggestions(){const values=(state.analysis.suggestions||[]).sort((a,b)=>(a.status==='proposed'?0:1)-(b.status==='proposed'?0:1)),shown=values.slice(0,200);$('suggestionsBtn').textContent=`Machine suggestions (${values.filter(x=>x.status==='proposed').length})`;$('suggestionList').innerHTML=shown.map(x=>`<div class="notice"><div class="eyebrow">${esc(x.status)} · ${esc(x.confidence)} · ${esc(x.id)}</div><h3>${esc(x.component_reference)}</h3><p>${esc(x.content?.failure_mode||'')}</p><p class="hint">Evidence: ${esc((x.evidence_ids||[]).join(', '))}</p>${x.uncertainties?.length?`<p><b>Uncertainties:</b> ${esc(x.uncertainties.join('; '))}</p>`:''}${x.status==='proposed'?`<button class="btn" onclick="reviewSuggestion('${esc(x.id)}','accept')">Accept into worksheet</button> <button class="btn secondary" onclick="reviewSuggestion('${esc(x.id)}','reject')">Reject</button>`:''}</div>`).join('')||'<p>No machine suggestions have been generated.</p>';if(values.length>shown.length)$('suggestionList').insertAdjacentHTML('beforeend',`<p class="hint">Showing the first ${shown.length} of ${values.length} suggestions. Use the CLI JSON view for the complete collection.</p>`);}
async function reviewSuggestion(id,decision){if(state.suggestionSaving)return;if(state.dirty&&!window.confirm('Discard unsaved worksheet changes?'))return;const reviewer=window.prompt('Reviewer name');if(!reviewer)return;const rationale=window.prompt('Review rationale');if(!rationale)return;state.suggestionSaving=true;$('suggestionList').querySelectorAll('button').forEach(button=>button.disabled=true);try{const response=await fetch('/api/suggestions/'+encodeURIComponent(id),{method:'PUT',headers:mutationHeaders(),body:JSON.stringify({decision,reviewer,rationale})}),result=await response.json();if(await reloadOnConflict(response,result))return;if(!response.ok){window.alert(result.error||response.status);return;}state.dirty=false;await load();renderSuggestions();}catch(error){window.alert('Suggestion review failed: '+error.message);}finally{state.suggestionSaving=false;$('suggestionList').querySelectorAll('button').forEach(button=>button.disabled=false);}}
function visibleItems(){const q=$('search').value.trim().toLowerCase(),f=$('filter').value,errors=x=>state.itemErrors.get(x.id)||0;return state.analysis.items.filter(item=>{const r=item.review,s=item.scanner,hay=[item.id,item.component.qualname,r.function,r.failure_mode,s.guideword,item.source.path,(r.linked_hazards||[]).join(' ')].join(' ').toLowerCase();if(q&&!hay.includes(q))return false;if(f==='active')return item.source_status!=='removed';if(f==='removed')return item.source_status==='removed';if(f==='all')return true;if(f==='gate_errors')return item.source_status!=='removed'&&errors(item)>0;if(f==='action_required')return item.source_status!=='removed'&&r.status==='action_required';if(f==='revalidation')return item.source_status!=='removed'&&r.revalidation_required;if(['new','changed','impacted','moved'].includes(f))return item.source_status!=='removed'&&item.source_change===f;return item.source_status!=='removed'&&r.disposition===f;}).sort((a,b)=>errors(b)-errors(a)||Number(b.review.revalidation_required)-Number(a.review.revalidation_required)||({changed:0,impacted:1,moved:2,new:3,manual:4,unchanged:5,legacy:6,removed:7}[a.source_change]??9)-({changed:0,impacted:1,moved:2,new:3,manual:4,unchanged:5,legacy:6,removed:7}[b.source_change]??9)||({high:0,medium:1,low:2,manual:3}[a.scanner.screening_priority]??9)-({high:0,medium:1,low:2,manual:3}[b.scanner.screening_priority]??9));}
function renderList(){const all=visibleItems(),items=all.slice(0,state.listLimit);$('listStatus').textContent=`${all.length} matching record${all.length===1?'':'s'} · showing ${items.length}`;$('items').innerHTML=items.map(item=>{const p=item.scanner.screening_priority,r=item.review,change=item.source_change||'',isSelected=item.id===state.selected,selected=isSelected?' selected':'',errors=state.itemErrors.get(item.id)||0;return `<button class="item${selected}" data-id="${esc(item.id)}" aria-current="${isSelected?'true':'false'}"><div class="item-head"><span class="item-title">${esc(item.component.qualname)}</span>${errors?`<span class="tag high">${errors} gate</span>`:''}<span class="tag ${esc(change)}">${esc(change)}</span><span class="tag ${esc(p)}">${esc(p)}</span><span class="tag ${esc(r.disposition)}">${esc(r.disposition)}</span></div><div class="item-mode">${r.revalidation_required?'⚠ Revalidation required · ':''}${esc(r.failure_mode||item.scanner.failure_mode)}</div></button>`;}).join('')||'<p style="padding:18px;color:var(--muted)">No candidates match this filter.</p>';if(all.length>items.length)$('items').insertAdjacentHTML('beforeend',`<button class="item" id="moreItems"><b>Show more</b><div class="item-mode">Showing ${items.length} of ${all.length} matching records</div></button>`);$('items').querySelectorAll('[data-id]').forEach(el=>el.onclick=()=>select(el.dataset.id));if($('moreItems'))$('moreItems').onclick=()=>{state.listLimit+=200;renderList();};}
function select(id){if(id!==state.selected&&state.dirty&&!window.confirm('Discard unsaved changes and open another record?'))return;state.dirty=false;state.selected=id;const url=new URL(window.location.href);url.searchParams.set('item',id);history.replaceState(null,'',url);const item=state.analysis.items.find(x=>x.id===id);renderList();renderEditor(item);renderEvidence(item);}
function field(label,key,value,wide=false,hint='',rows=0,type='text'){const cls=wide?'field wide':'field',id='review-'+key,bounds=type==='number'?' min="1" max="10" step="1"':'';const control=rows?`<textarea id="${id}" data-field="${key}" rows="${rows}">${esc(value)}</textarea>`:`<input id="${id}" data-field="${key}" type="${type}"${bounds} value="${esc(value)}">`;return `<div class="${cls}"><label for="${id}">${label}${hint?` <span class="hint">${hint}</span>`:''}</label>${control}</div>`;}
function checkboxField(label,key,value,hint=''){const id='review-'+key;return `<div class="field wide"><label for="${id}"><input id="${id}" data-field="${key}" data-invert="true" type="checkbox" style="width:auto;margin-right:8px" ${value?'checked':''}>${label} <span class="hint">${hint}</span></label></div>`;}
function selectField(label,key,value,options){const id='review-'+key;return `<div class="field"><label for="${id}">${label}</label><select id="${id}" data-field="${key}">${options.map(x=>`<option value="${esc(x)}" ${x===value?'selected':''}>${esc(String(x).replaceAll('_',' '))}</option>`).join('')}</select></div>`;}
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
${field('Operational mode','operational_mode',r.operational_mode||'',false,'Mode in which this failure is credible')}
${field('Operational state','operational_state',r.operational_state||'',false,'Pre-failure or transition state')}
${field('Potential causes','causes',lines(r.causes),true,'One per line',4)}
${field('Local effect','local_effect',r.local_effect,false,'At this component',3)}
${field('Next-higher effect','next_higher_effect',r.next_higher_effect,false,'At caller/subsystem',3)}
${field('System / end effect','end_effect',r.end_effect,true,'Consequence to user, mission, safety, data, or service',3)}
${field('Required safe state','required_safe_state',r.required_safe_state||'',false,'Approved state after containment',3)}
${field('Permitted degraded behavior','degraded_behavior',r.degraded_behavior||'',false,'Behavior that remains acceptable while degraded',3)}
${field('Required recovery behavior','recovery_behavior',r.recovery_behavior||'',true,'Detection, containment, restart, rollback, or operator action',3)}
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
${field('Residual risk','residual_risk',r.residual_risk||'',true,'Remaining credible effects, assumptions, limitations, and required acceptance',3)}
${field('Owner','owner',r.owner)}${field('Target date','target_date',r.target_date,false,'',0,'date')}
${field('Approved by','approved_by',r.approved_by,false,'Named authorized reviewer')}${field('Approval date','approval_date',r.approval_date,false,'',0,'date')}
${r.revalidation_required?checkboxField('Source-change revalidation complete','revalidation_required',false,'Check only after effects, controls, ratings, actions, and evidence have been confirmed against the current source.'):'<div class="field wide"><span class="hint">No source-change revalidation is pending for this item.</span></div>'}
${field('Notes / assumptions','notes',r.notes,true,'Record scope, assumptions, decisions, and residual concerns',4)}
<div class="actions"><button class="btn" type="submit">Save review</button><button class="btn secondary" id="saveNext" type="button">Save &amp; next</button><span class="save-state" id="saveState" role="status" aria-live="polite">Changes are saved to the local analysis file.</span></div></form>`;
$('reviewForm').onsubmit=save;$('saveNext').onclick=event=>save(event,true);$('reviewForm').querySelectorAll('[data-field]').forEach(x=>x.addEventListener('input',markDirty));$('reviewForm').querySelectorAll('[data-field="severity"],[data-field="occurrence"],[data-field="detection"]').forEach(x=>x.oninput=()=>{$('rpn').textContent='RPN: '+rpn(readForm());});$('reviewForm').querySelectorAll('[data-field="post_action_severity"],[data-field="post_action_occurrence"],[data-field="post_action_detection"]').forEach(x=>x.oninput=()=>{$('postRpn').textContent='Post-action RPN: '+postRpn(readForm());});}
function markDirty(){state.dirty=true;const status=$('saveState');if(status)status.textContent='Unsaved changes — press Ctrl+S to save.';}
function rpn(v){const vals=['severity','occurrence','detection'].map(k=>Number(v[k]));return vals.every(x=>x>=1&&x<=10)?vals.reduce((a,b)=>a*b,1):'—';}
function postRpn(v){const vals=['post_action_severity','post_action_occurrence','post_action_detection'].map(k=>Number(v[k]));return vals.every(x=>x>=1&&x<=10)?vals.reduce((a,b)=>a*b,1):'—';}
function readForm(){const out={};$('reviewForm').querySelectorAll('[data-field]').forEach(el=>{let v=el.type==='checkbox'?(el.dataset.invert==='true'?!el.checked:el.checked):el.value;if(['causes','linked_hazards','prevention_controls','detection_controls','recommended_actions','actions_taken','verification_evidence'].includes(el.dataset.field))v=v.split('\n').map(x=>x.trim()).filter(Boolean);if(['severity','occurrence','detection','post_action_severity','post_action_occurrence','post_action_detection'].includes(el.dataset.field))v=v===''?null:Number(v);out[el.dataset.field]=v;});return out;}
function setFindingSaving(value){state.saving=value;const form=$('reviewForm');if(form)form.querySelectorAll('button').forEach(button=>button.disabled=value);}
async function save(ev,advance=false){ev.preventDefault();if(state.saving)return;const ordered=visibleItems(),position=ordered.findIndex(x=>x.id===state.selected),nextId=position>=0?ordered[position+1]?.id:null,status=$('saveState');setFindingSaving(true);status.textContent='Saving…';try{const response=await fetch('/api/items/'+encodeURIComponent(state.selected),{method:'PUT',headers:mutationHeaders(),body:JSON.stringify(readForm())});const result=await response.json();if(await reloadOnConflict(response,result))return;if(!response.ok){status.textContent='Save failed: '+(result.error||response.status);return;}state.dirty=false;const ready=await applyItemMutation(result,response.headers.get('ETag'));if(ready&&advance&&nextId&&state.analysis.items.some(x=>x.id===nextId))select(nextId);}catch(error){if(status.isConnected)status.textContent='Save failed: '+error.message;}finally{setFindingSaving(false);}}
const assurancePlanningStatuses=[['candidate','Candidate'],['confirmed','Confirmed'],['control_missing','Control missing'],['control_implemented','Control implemented'],['verification_planned','Verification planned'],['test_proposed','Test proposed'],['reopened','Reopened'],['not_applicable','Not applicable']];
function assuranceMetric(value,label){return `<div class="metric"><b>${esc(value)}</b><span>${esc(label)}</span></div>`;}
function openAssurancePlan(){const dialog=$('assurancePlan');if(!dialog.open)dialog.showModal();dialog.scrollTop=0;dialog.focus({preventScroll:true});}
function closeAssurancePlan(){if(state.assuranceDirty&&!window.confirm('Discard unsaved assurance-plan changes?'))return;state.assuranceDirty=false;$('assurancePlan').close();}
function renderAssurancePlan(){
  const view=state.assurance||{},progress=view.progress||{},values=view.obligations||[];
  $('assuranceBtn').textContent=`Assurance plan (${progress.planning_pending??0})`;
  $('assuranceNotice').textContent=(view.notice||'Each accepted finding has a deterministic assurance obligation.')+' Planning decisions made here cannot record test execution, verify evidence, close a finding, or accept risk.';
  $('assuranceMetrics').innerHTML=assuranceMetric(progress.applicable_findings??0,'accepted findings')+assuranceMetric(progress.planning_ready??0,'plans ready')+assuranceMetric(progress.planning_pending??0,'plans pending')+assuranceMetric(progress.planning_gaps??0,'with definition gaps')+assuranceMetric(progress.work_queue?.implementation_ready??0,'ready to implement')+assuranceMetric(progress.work_queue?.execution_ready??0,'ready to execute')+assuranceMetric(progress.recorded_executions??0,'executions recorded')+assuranceMetric(progress.verified_obligations??0,'verified / resolved');
  const configured=(state.analysis?.context?.reviewers||[]).map(value=>value.name).filter(Boolean);
  $('assuranceList').innerHTML=values.map((value,index)=>{
    const status=value.assurance_status||'candidate',evidence=value.evidence_status||'missing',work=value.work||{},implementation=`${value.automation?.implementation_status||'not_implemented'} · work: ${work.state||'not applicable'} · next: ${work.next_action_id||'none'}`;
    const locked=['partially_verified','accepted_risk','closed','retired'].includes(status);
    const statuses=status==='verified'?[['residual_risk_review','Advance to residual-risk review']]:assurancePlanningStatuses;
    const statusOptions=status==='residual_risk_review'?[['residual_risk_review','Residual-risk review'],...statuses]:statuses;
    const reviewer=value.review?.reviewer||'',owner=value.review?.owner||'';
    const reviewerControl=configured.length?`<select id="assuranceReviewer${index}"><option value="">Select reviewer</option>${configured.map(name=>`<option value="${esc(name)}" ${name===reviewer?'selected':''}>${esc(name)}</option>`).join('')}</select>`:`<input id="assuranceReviewer${index}" value="${esc(reviewer)}" placeholder="Named reviewer">`;
    const gaps=(value.planning_gaps||[]).map(gap=>`<li>${esc(gap)}</li>`).join('');
    const questions=(value.control_review_questions||[]).map(question=>`<li>${esc(question)}</li>`).join('');
    const cascadePaths=(value.cascade_context?.static_upstream_paths||[]).map(path=>`<li>${esc(path.join(' → '))}</li>`).join('');
    const pathAnalysis=value.cascade_context?.static_path_analysis||{};
    const pathLimitations=(pathAnalysis.limitations||[]).map(limit=>`<li>${esc(limit)}</li>`).join('');
    const criteria=(value.acceptance_criteria||[]).map(criterion=>`<li>${esc(criterion)}</li>`).join('');
    const form=locked?`<p class="notice"><b>Governed state:</b> ${esc(status)} can only change through its evidence or approval workflow.</p>`:`<div class="assurance-form"><div><label for="assuranceStatus${index}">Status</label><select id="assuranceStatus${index}">${statusOptions.map(option=>`<option value="${esc(option[0])}" ${option[0]===status?'selected':''}>${esc(option[1])}</option>`).join('')}</select></div><div><label for="assuranceReviewer${index}">Reviewer</label>${reviewerControl}</div><div><label for="assuranceOwner${index}">Owner <span class="hint">optional</span></label><input id="assuranceOwner${index}" value="${esc(owner)}" placeholder="Implementation owner"></div><div><label for="assuranceRationale${index}">Rationale</label><textarea id="assuranceRationale${index}" placeholder="Why is this planning state appropriate?"></textarea></div><button class="btn" id="assuranceSave${index}" type="button" onclick="saveAssurancePlan(${index})">Save plan</button></div>`;
    return `<article class="assurance-card"><div class="eyebrow">${esc(value.id)} · ${esc(value.component)}</div><h3>${esc(value.title)}</h3><div class="assurance-meta"><span class="tag ${esc(value.priority)}">${esc(value.priority||'priority n/a')}</span><span class="tag">${esc(status)}</span><span class="tag">evidence: ${esc(evidence)}</span><span class="tag">implementation: ${esc(implementation)}</span><span class="tag">${esc(value.verification_method||'method pending')}</span>${pathAnalysis.complete_within_static_call_model===false?'<span class="tag medium">bounded caller inventory</span>':''}</div><p><b>Stimulus:</b> ${esc(value.stimulus?.description||'Not defined')}</p>${gaps?`<details open><summary>Planning gaps (${value.planning_gaps.length})</summary><ul>${gaps}</ul></details>`:''}${questions?`<details open><summary>Control model questions (${value.control_review_questions.length})</summary><ul>${questions}</ul></details>`:''}${cascadePaths||pathLimitations?`<details><summary>Cascade observation paths (${value.cascade_context.static_upstream_paths.length})</summary>${cascadePaths?`<ul>${cascadePaths}</ul>`:''}${pathLimitations?`<p class="small"><b>Discovery limits:</b></p><ul>${pathLimitations}</ul>`:''}<p class="small">${esc(value.cascade_context.notice||'Static exposure evidence only.')}</p></details>`:''}<details><summary>Acceptance criteria (${value.acceptance_criteria?.length||0})</summary><ul>${criteria}</ul></details>${form}</article>`;
  }).join('')||'<p>No accepted findings currently require assurance planning. Review and accept credible findings first.</p>';
  if(view.truncated)$('assuranceList').insertAdjacentHTML('beforeend',`<p class="hint">Showing ${view.embedded} of ${view.total} accepted-finding obligations. Use the assurance export for the complete register.</p>`);
  $('assuranceList').querySelectorAll('input,select,textarea').forEach(control=>control.addEventListener('input',()=>{state.assuranceDirty=true;}));
}
async function saveAssurancePlan(index){
  if(state.assuranceSaving)return;
  if(state.dirty&&!window.confirm('Discard unsaved worksheet changes before saving this assurance plan?'))return;
  const value=(state.assurance?.obligations||[])[index];if(!value)return;
  const status=$('assuranceSaveState'),payload={status:$('assuranceStatus'+index).value,reviewer:$('assuranceReviewer'+index).value.trim(),owner:$('assuranceOwner'+index).value.trim(),rationale:$('assuranceRationale'+index).value.trim()};
  if(!payload.reviewer||!payload.rationale){status.textContent='A named reviewer and planning rationale are required.';return;}
  state.assuranceSaving=true;$('assuranceList').querySelectorAll('button').forEach(button=>button.disabled=true);status.textContent='Saving assurance plan…';
  try{const response=await fetch('/api/assurance/'+encodeURIComponent(value.id),{method:'PUT',headers:mutationHeaders(),body:JSON.stringify(payload)}),result=await response.json();if(await reloadOnConflict(response,result))return;if(!response.ok){status.textContent='Assurance save failed: '+(result.error||response.status);return;}state.dirty=false;state.assuranceDirty=false;const revision=response.headers.get('ETag');state.revision=revision||state.revision;if(!revision||!await refreshDerived(state.revision))await load();status.textContent=`Saved assurance plan ${value.id}.`;}catch(error){status.textContent='Assurance save failed: '+error.message;}finally{state.assuranceSaving=false;$('assuranceList').querySelectorAll('button').forEach(button=>button.disabled=false);}
}
async function addManualItem(){if(state.adding)return;if(state.dirty&&!window.confirm('Discard unsaved changes before adding a failure mode?'))return;state.adding=true;$('addBtn').disabled=true;try{const selected=state.analysis.items.find(x=>x.id===state.selected),response=await fetch('/api/items',{method:'POST',headers:mutationHeaders(),body:JSON.stringify({component_id:selected?.component_id||null})}),item=await response.json();if(await reloadOnConflict(response,item))return;if(!response.ok){window.alert(item.error||response.status);return;}state.dirty=false;if(await applyItemMutation(item,response.headers.get('ETag')))select(item.id);}catch(error){window.alert('Adding a failure mode failed: '+error.message);}finally{state.adding=false;$('addBtn').disabled=false;}}
$('healthBtn').onclick=()=>{renderHealth();$('health').showModal();};$('assuranceBtn').onclick=()=>{renderAssurancePlan();openAssurancePlan();};$('suggestionsBtn').onclick=()=>{renderSuggestions();$('suggestions').showModal();};$('guidanceBtn').onclick=()=>$('guide').showModal();$('addBtn').onclick=addManualItem;$('search').oninput=()=>{state.listLimit=200;renderList();};$('filter').onchange=()=>{state.listLimit=200;renderList();};$('assurancePlan').addEventListener('cancel',event=>{if(state.assuranceDirty&&!window.confirm('Discard unsaved assurance-plan changes?'))event.preventDefault();else state.assuranceDirty=false;});window.addEventListener('beforeunload',event=>{if(state.dirty||state.assuranceDirty){event.preventDefault();event.returnValue='';}});document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='s'&&$('reviewForm')){event.preventDefault();$('reviewForm').requestSubmit();}else if((event.ctrlKey||event.metaKey)&&event.key==='Enter'&&$('reviewForm')){event.preventDefault();save(event,true);}else if(event.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){event.preventDefault();$('search').focus();}});load();
</script>
</body></html>"""


class _ReviewState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.analysis = load_analysis(path)
        self.lock = threading.RLock()
        self.file_stamp, self.file_fingerprint = self._revision_snapshot()

    def _stamp(self) -> tuple[int, int]:
        stat = self.path.stat()
        return stat.st_mtime_ns, stat.st_size

    def _fingerprint(self) -> str:
        return analysis_file_sha256(self.path)

    def _revision_snapshot(self) -> tuple[tuple[int, int], str]:
        for _attempt in range(3):
            before = self._stamp()
            fingerprint = self._fingerprint()
            after = self._stamp()
            if before == after:
                return after, fingerprint
        raise RuntimeError("analysis file changed repeatedly while computing its revision")

    def reload_if_changed(self) -> bool:
        try:
            stamp = self._stamp()
            if stamp == self.file_stamp:
                return False
            stamp, fingerprint = self._revision_snapshot()
            if fingerprint == self.file_fingerprint:
                self.file_stamp = stamp
                return False
            analysis = load_analysis(self.path)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise _AnalysisUnavailableError(
                "the governed analysis file is temporarily unreadable; restore a valid "
                "analysis file and retry"
            ) from exc
        self.analysis = analysis
        self.file_stamp = stamp
        self.file_fingerprint = fingerprint
        return True

    def saved(self) -> None:
        self.file_stamp, self.file_fingerprint = self._revision_snapshot()

    def commit(self) -> None:
        """Persist a mutation only if the disk revision is still current.

        Mutating helpers operate on the in-memory analysis. A failed atomic save must
        therefore restore the last governed disk state instead of allowing an
        unpersisted change to leak into later reads or saves.
        """

        try:
            save_analysis(
                self.path,
                self.analysis,
                expected_sha256=self.file_fingerprint,
            )
            self.saved()
        except AnalysisRevisionConflictError as exc:
            try:
                self.analysis = load_analysis(self.path)
                self.file_stamp, self.file_fingerprint = self._revision_snapshot()
            except (OSError, RuntimeError, TypeError, ValueError) as recovery_exc:
                raise _AnalysisUnavailableError(
                    "the analysis changed during save, but the newer governed revision "
                    "is unreadable; restore it before making further changes"
                ) from recovery_exc
            raise _ConcurrentUpdateError(
                "analysis changed while this review update was being prepared; "
                "reload and review the latest record before saving again"
            ) from exc
        except _ConcurrentUpdateError:
            raise
        except Exception as exc:
            try:
                self.analysis = load_analysis(self.path)
                self.file_stamp, self.file_fingerprint = self._revision_snapshot()
            except Exception as recovery_exc:
                raise _PersistenceError(
                    "analysis save failed and the governed disk state could not be "
                    "reloaded; restart the reviewer before making further changes"
                ) from recovery_exc
            raise _PersistenceError(
                "analysis save failed; the attempted in-memory changes were discarded"
            ) from exc

    @property
    def etag(self) -> str:
        return f'"{self.file_fingerprint}"'

    def require_revision(self, supplied: str | None) -> None:
        """Reject missing or stale browser snapshots before applying a mutation."""

        self.reload_if_changed()
        if not supplied:
            raise _PreconditionRequiredError(
                "review changes require the current ETag in the If-Match header"
            )
        if supplied.strip() != self.etag:
            raise _ConcurrentUpdateError(
                "analysis changed after this review snapshot was loaded; reload and "
                "review the latest record before saving again"
            )


class _ConcurrentUpdateError(RuntimeError):
    pass


class _PreconditionRequiredError(RuntimeError):
    pass


class _PersistenceError(RuntimeError):
    pass


class _AnalysisUnavailableError(RuntimeError):
    pass


def _review_analysis_view(analysis: dict[str, Any]) -> dict[str, Any]:
    """Return only data used by the interactive reviewer, never a governed copy."""

    components = [
        {
            "id": value.get("id", ""),
            "requirement_ids": list(value.get("requirement_ids", [])),
            "interface_ids": list(value.get("interface_ids", [])),
        }
        for value in analysis.get("components", [])
        if isinstance(value, dict)
    ]
    runtime = analysis.get("runtime_evidence", {})
    return {
        "format": "pysfmea-review-analysis-view-1",
        "schema_version": analysis.get("schema_version", ""),
        "project": analysis.get("project", {}),
        "context": analysis.get("context", {}),
        "methodology": analysis.get("methodology", {}),
        "components": components,
        "items": analysis.get("items", []),
        "suggestions": analysis.get("suggestions", []),
        "runtime_evidence": {
            "imports": runtime.get("imports", []) if isinstance(runtime, dict) else []
        },
        "projection": {
            "source_format": "pysfmea-analysis",
            "governed_source_unchanged": True,
            "omitted_sections": sorted(
                set(analysis)
                - {
                    "schema_version",
                    "project",
                    "context",
                    "methodology",
                    "components",
                    "items",
                    "suggestions",
                    "runtime_evidence",
                }
            ),
            "notice": (
                "This bounded transport view omits package/report-only collections. "
                "Edits are applied to the complete governed analysis on the server."
            ),
        },
    }


def _assurance_view(analysis: dict[str, Any], *, limit: int = 500) -> dict[str, Any]:
    """Return a bounded browser projection for accepted-finding plan review."""

    progress = assurance_progress(analysis)
    work_by_obligation = {
        str(value.get("obligation_id", "")): value
        for value in assurance_work_queue(analysis)["items"]
        if value.get("obligation_id")
    }
    accepted_ids = {
        str(item.get("id", ""))
        for item in analysis.get("items", [])
        if isinstance(item, dict)
        and item.get("source_status", "active") == "active"
        and item.get("review", {}).get("disposition") == "accepted"
    }
    obligations = [
        {**value, "work": work_by_obligation.get(str(value.get("id", "")), {})}
        for value in analysis.get("assurance", {}).get("obligations", [])
        if isinstance(value, dict)
        and value.get("source_status", "active") == "active"
        and str(value.get("finding_id", "")) in accepted_ids
    ]
    obligations.sort(
        key=lambda value: (
            value.get("assurance_status") not in {"candidate", "reopened"},
            bool(value.get("review", {}).get("reviewer")),
            {"high": 0, "medium": 1, "low": 2}.get(value.get("priority", ""), 3),
            str(value.get("component", "")),
            str(value.get("id", "")),
        )
    )
    return {
        "format": "pysfmea-assurance-review-view-1",
        "notice": analysis.get("assurance", {}).get("notice", ""),
        "progress": progress,
        "total": len(obligations),
        "embedded": min(len(obligations), limit),
        "truncated": len(obligations) > limit,
        "obligations": obligations[:limit],
    }


def _review_workspace_view(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build the complete browser workspace from one governed revision."""

    return {
        "format": "pysfmea-review-workspace-1",
        "analysis": _review_analysis_view(analysis),
        "validation": validate_analysis(analysis),
        "assurance": _assurance_view(analysis),
        "notice": (
            "All embedded views were serialized from one governed analysis revision."
        ),
    }


def _handler(state: _ReviewState) -> type[BaseHTTPRequestHandler]:
    class ReviewHandler(BaseHTTPRequestHandler):
        server_version = f"PySFMEA/{__version__}"

        def do_GET(self) -> None:  # noqa: N802
            if not self._require_local_host():
                return
            route = urllib.parse.urlparse(self.path).path
            if route == "/":
                self._send_bytes(REVIEW_HTML.encode("utf-8"), "text/html; charset=utf-8")
            elif route == "/api/analysis":
                self._send_state_json(lambda analysis: analysis)
            elif route == "/api/reviewer":
                self._send_state_json(_review_analysis_view)
            elif route == "/api/validation":
                self._send_state_json(validate_analysis)
            elif route == "/api/assurance":
                self._send_state_json(_assurance_view)
            elif route == "/api/workspace":
                self._send_state_json(_review_workspace_view)
            else:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def _send_state_json(
            self, build: Callable[[dict[str, Any]], Any]
        ) -> None:
            """Serialize one coherent state under lock, then release it before I/O."""

            try:
                with state.lock:
                    state.reload_if_changed()
                    body = self._encode_json(build(state.analysis))
                    etag = state.etag
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                self._send_json(
                    {"error": f"analysis snapshot is unavailable: {exc}"},
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
                return
            self._send_encoded_json(body, etag=etag)

        def do_PUT(self) -> None:  # noqa: N802
            if not self._require_local_host():
                return
            route = urllib.parse.urlparse(self.path).path
            assurance_prefix = "/api/assurance/"
            if route.startswith(assurance_prefix):
                obligation_id = urllib.parse.unquote(
                    route[len(assurance_prefix) :]
                )
                try:
                    changes = self._read_json()
                    with state.lock:
                        state.require_revision(self.headers.get("If-Match"))
                        target = next(
                            (
                                value
                                for value in state.analysis.get("assurance", {}).get(
                                    "obligations", []
                                )
                                if value.get("id") == obligation_id
                            ),
                            None,
                        )
                        if target is None:
                            raise KeyError(obligation_id)
                        accepted_findings = {
                            str(item.get("id", ""))
                            for item in state.analysis.get("items", [])
                            if isinstance(item, dict)
                            and item.get("source_status", "active") == "active"
                            and item.get("review", {}).get("disposition") == "accepted"
                        }
                        if (
                            target.get("source_status", "active") != "active"
                            or str(target.get("finding_id", ""))
                            not in accepted_findings
                        ):
                            raise ValueError(
                                "browser assurance planning is limited to active, "
                                "accepted findings"
                            )
                        obligation = review_obligation(
                            state.analysis,
                            obligation_id,
                            status=changes.get("status", ""),
                            reviewer=changes.get("reviewer", ""),
                            rationale=changes.get("rationale", ""),
                            owner=changes.get("owner", ""),
                        )
                        state.commit()
                        response_etag = state.etag
                    self._send_json(obligation, etag=response_etag)
                except _PreconditionRequiredError as exc:
                    self._send_json(
                        {"error": str(exc)}, HTTPStatus.PRECONDITION_REQUIRED
                    )
                except _ConcurrentUpdateError as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
                except _PersistenceError as exc:
                    self._send_json(
                        {"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR
                    )
                except _AnalysisUnavailableError as exc:
                    self._send_json(
                        {"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE
                    )
                except KeyError:
                    self._send_json(
                        {"error": "unknown assurance obligation"},
                        HTTPStatus.NOT_FOUND,
                    )
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            suggestion_prefix = "/api/suggestions/"
            if route.startswith(suggestion_prefix):
                suggestion_id = urllib.parse.unquote(route[len(suggestion_prefix) :])
                try:
                    changes = self._read_json()
                    with state.lock:
                        state.require_revision(self.headers.get("If-Match"))
                        suggestion = review_suggestion(
                            state.analysis,
                            suggestion_id,
                            decision=changes.get("decision", ""),
                            reviewer=changes.get("reviewer", ""),
                            rationale=changes.get("rationale", ""),
                        )
                        state.commit()
                        response_etag = state.etag
                    self._send_json(suggestion, etag=response_etag)
                except _PreconditionRequiredError as exc:
                    self._send_json(
                        {"error": str(exc)}, HTTPStatus.PRECONDITION_REQUIRED
                    )
                except _ConcurrentUpdateError as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
                except _PersistenceError as exc:
                    self._send_json(
                        {"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR
                    )
                except _AnalysisUnavailableError as exc:
                    self._send_json(
                        {"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE
                    )
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
                    state.require_revision(self.headers.get("If-Match"))
                    item = update_item_review(state.analysis, item_id, changes)
                    state.commit()
                    response_etag = state.etag
                self._send_json(item, etag=response_etag)
            except _PreconditionRequiredError as exc:
                self._send_json(
                    {"error": str(exc)}, HTTPStatus.PRECONDITION_REQUIRED
                )
            except _ConcurrentUpdateError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except _PersistenceError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            except _AnalysisUnavailableError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE)
            except KeyError:
                self._send_json({"error": "unknown item"}, HTTPStatus.NOT_FOUND)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_POST(self) -> None:  # noqa: N802
            if not self._require_local_host():
                return
            route = urllib.parse.urlparse(self.path).path
            if route != "/api/items":
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            try:
                body = self._read_json()
                with state.lock:
                    state.require_revision(self.headers.get("If-Match"))
                    item = add_manual_item(state.analysis, body.get("component_id"))
                    state.commit()
                    response_etag = state.etag
                self._send_json(item, HTTPStatus.CREATED, etag=response_etag)
            except _PreconditionRequiredError as exc:
                self._send_json(
                    {"error": str(exc)}, HTTPStatus.PRECONDITION_REQUIRED
                )
            except _ConcurrentUpdateError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except _PersistenceError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            except _AnalysisUnavailableError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def _require_local_host(self) -> bool:
            """Reject DNS-rebinding and non-loopback Host headers."""

            supplied = self.headers.get("Host", "")
            try:
                parsed = urllib.parse.urlsplit("//" + supplied)
                expected_port = int(self.server.server_address[1])
                allowed = (
                    parsed.username is None
                    and parsed.password is None
                    and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                    and parsed.port == expected_port
                )
            except (TypeError, ValueError):
                allowed = False
            if not allowed:
                self._send_json(
                    {"error": "local reviewer requests require a loopback Host header"},
                    HTTPStatus.MISDIRECTED_REQUEST,
                )
            return allowed

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

        def _send_json(
            self,
            value: Any,
            status: HTTPStatus = HTTPStatus.OK,
            *,
            etag: str = "",
        ) -> None:
            self._send_encoded_json(self._encode_json(value), status, etag=etag)

        @staticmethod
        def _encode_json(value: Any) -> bytes:
            return json.dumps(value, ensure_ascii=False).encode("utf-8")

        def _send_encoded_json(
            self,
            body: bytes,
            status: HTTPStatus = HTTPStatus.OK,
            *,
            etag: str = "",
        ) -> None:
            self._send_bytes(
                body,
                "application/json; charset=utf-8",
                status,
                headers={"ETag": etag} if etag else None,
            )

        def _send_bytes(
            self,
            body: bytes,
            content_type: str,
            status: HTTPStatus = HTTPStatus.OK,
            *,
            headers: dict[str, str] | None = None,
        ) -> None:
            content_encoding = ""
            if content_type.startswith("application/json") and len(body) >= 4096:
                for choice in self.headers.get("Accept-Encoding", "").split(","):
                    parts = [part.strip() for part in choice.split(";")]
                    if parts[0].lower() != "gzip":
                        continue
                    quality = 1.0
                    for parameter in parts[1:]:
                        if parameter.lower().startswith("q="):
                            try:
                                quality = float(parameter[2:])
                            except ValueError:
                                quality = 0.0
                    if quality > 0:
                        body = gzip.compress(body, compresslevel=1, mtime=0)
                        content_encoding = "gzip"
                    break
            self.send_response(status.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if content_encoding:
                self.send_header("Content-Encoding", content_encoding)
                self.send_header("Vary", "Accept-Encoding")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "form-action 'self'; frame-ancestors 'none'",
            )
            for name, value in (headers or {}).items():
                self.send_header(name, value)
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
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError(
            "the review server is local-only and may bind only to 127.0.0.1 or localhost"
        )
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
