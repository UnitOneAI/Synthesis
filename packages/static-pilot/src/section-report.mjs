import {sectionModel} from './automatic-sections.mjs';
import {systemModel} from './system-model.mjs';
import {decisionPathHtml} from './system-exports.mjs';
import {PRINT_HEADER,PRINT_FOOTER,PRINT_STYLE} from './print-style.mjs';
import {sourceWindow} from './graph-package.mjs';
import {deploymentDecisionQuestions} from './reviewer-questions.mjs';
const e=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const table=(heads,rows,css="")=>`<table class="${css}"><thead><tr>${heads.map(h=>`<th>${e(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(v=>`<td>${e(v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
export async function sectionReport(model,manifest,root,id) {
 const {view,section,completion}=sectionModel(model,id),system=systemModel(view,{matrix:false}),result=model.automaticSections.results[id];
 const files=[...new Map([...(view.aiReview?.batches || []).flatMap(b=>b.evidenceContext?.records || []),...(view.threatValidation?.entries || []).flatMap(t=>[...(t.evidence || []),...(t.engineering?.obligations || []).flatMap(o=>o.citations || []),...(t.engineering?.conditions || []).flatMap(c=>c.citations || [])])].map(r=>[JSON.stringify([r.repository,r.path,r.blobSha256]),r])).values()];
 for(const ref of files)try {await sourceWindow({...ref,line:ref.startLine},manifest,root);}catch {completion.complete=false;completion.blockers.push(`Saved source no longer available unchanged: ${ref.repository} / ${ref.path}`);}
 const threats=system.threats.filter(t=>t.origin==='analysis'),questions=deploymentDecisionQuestions(view);
 const decisionLabel=status=>({'supported-conditional':'Supported conditional path','ruled-out':'Ruled out for this path','no-scenario-identified':'No scenario identified','evidence-gap':'Incomplete evidence'})[status] || status;
 const citations=ref=>`${ref.repository || ''} / ${ref.path || ''}:${ref.startLine ?? ref.line}–${ref.endLine}`;
 const cases=[];
 for(const t of threats) {
  const a=t.validation || {},eng=a.engineering;
  const refs=[...new Map((eng?.obligations || []).flatMap(o=>o.citations || []).map(r=>[JSON.stringify([r.repository,r.path,r.startLine,r.endLine]),r])).values()];
  const snippets=[];
  for(const ref of refs.slice(0,2))try {
   const w=await sourceWindow({...ref,line:ref.startLine},manifest,root);
   const lines=w.lines.filter(l=>l.line>=ref.startLine&&l.line<=ref.endLine).slice(0,24);
   snippets.push(`<h4>${e(citations(ref))}</h4><pre>${e(lines.map(l=>l.line+' '+l.text).join('\n'))}</pre>${lines.at(-1)?.line<ref.endLine?'<p>Excerpt shortened; full cited range remains in the source.</p>':''}`);
  } catch {snippets.push('<p>Current source excerpt unavailable. Saved citations remain; current source applicability requires revalidation.</p>');}
  cases.push(`<article><h3>${e(t.reference)} · ${e(t.outcome?.label || a.assessment)}</h3><p><strong>${e(eng?.conclusion || t.name)}</strong></p><p><strong>Impact:</strong> ${e(a.impact || t.asset)}</p>${decisionPathHtml(t.decisionPath)}<h4>Required action</h4>${table(['Code change','Validation and compatibility'],[[a.remediation?.codeFix || t.mitigation,a.remediation?.validation || 'Review the proposed change against the cited path.']])}${snippets.join('')}</article>`);
 }
 const categoryDetails=completion.categories.map(c=>{
  const groups=new Map();
  for(const o of c.operations)for(const r of o.results){const key=JSON.stringify([r.batchId,r.status,r.rationale,r.citations]);if(!groups.has(key))groups.set(key,{result:r,names:[]});groups.get(key).names.push(o.name);}
  return `<section><h3>${e(c.category)}</h3>${[...groups.values()].map(({result:r,names})=>{
   const batch=view.aiReview.batches.find(b=>b.id===r.batchId);
   const refs=r.citations.map(ref=>{const file=batch.evidenceContext?.records?.find(x=>x.id===ref.recordId);return citations({...ref,...(file?{repository:file.repository,path:file.path}:{})});});
   const label=decisionLabel(r.status);
   return `<h4>${e(names.join(' · '))}</h4><p><strong>${e(label)}</strong> — ${e(r.rationale)}</p><p>${e(refs.join('; '))}</p>${r.deploymentConditions?.length?`<p>Deployment conditions: ${e(r.deploymentConditions.join('; '))}</p>`:''}`;
  }).join('') || '<p>No completed assessment.</p>'}</section>`;
 }).join('');
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'"><title>${e(section.title)} — section threat model</title><style>${PRINT_STYLE}.decision-summary th:first-child{width:16%}.decision-summary th:nth-child(2){width:62%}.decision-summary th:last-child{width:22%}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:10px}article{border-top:1px solid #ccd5df;padding-top:12px}</style></head><body>${PRINT_HEADER}<h1>${e(section.title)}</h1><h2>${completion.complete?'Section static threat model complete':'Section not complete'}</h2><p>${e(completion.interpretation)}</p><p>${section.interfaceIds.length} operations · ${completion.categories.filter(c=>c.complete).length}/6 categories complete · ${completion.supported} supported conditional threats · ${completion.ruledOut} ruled-out paths.</p><h2>Scope and boundary assumptions</h2><p>${e(section.profile)}</p><p>${e(section.basis)} ${e(section.grouping)}</p>${table(['Operation','Source'],section.operations.map(o=>[o.name,o.repository+' / '+o.path]))}<p>Other sections remain separately tracked. Supporting source across all loaded repositories is available for path and control investigation; this is not whole-repository clearance.</p><h2>STRIDE decision matrix</h2>${table(['Category','Operations assessed','Decision'],completion.categories.map(c=>[c.category,c.operations.filter(o=>o.complete).length+'/'+c.operations.length,[...new Set(c.operations.flatMap(o=>o.results.map(r=>decisionLabel(r.status))))].join('; ') || 'Not assessed']))}${completion.blockers.length?`<h2>Items preventing completion</h2><ul>${completion.blockers.map(b=>`<li>${e(b)}</li>`).join('')}</ul>`:''}<h2>Decision summary</h2><p>These are assessed scenarios, not deduplicated vulnerabilities. Related operations can share a root cause. The detailed cases below provide controls, conditions and remediation.</p>${table(['Reference','Code conclusion','Disposition'],threats.map(t=>[t.reference,t.name,t.outcome?.label || t.validation?.assessment]),'decision-summary')}<h2>Actionable threats and ruled-out paths</h2>${cases.join('') || '<p>No scenario was identified in the reviewed operations. The category conclusions and evidence below explain that result; it is not a claim of universal security.</p>'}<h2>Deployment decisions</h2>${questions.length?table(['Question','If yes / if no','Recorded answer'],questions.map(q=>[q.question,`Yes: ${q.ifYes}\nNo: ${q.ifNo}`,q.answer?`${q.answer.answer}: ${q.answer.rationale}`:'Unanswered; threat remains conditional'])):'<p>No additional deployment decision was requested for the assessed paths.</p>'}<h2>Evidence and conclusions for all six categories</h2>${categoryDetails}<h2>Execution record</h2><p>${result.calls || 0} provider attempts · ${result.reportedTokens || 0} reported tokens · ${result.unknownUsageRequests || 0} requests with unknown usage. Static code and collected configuration were reviewed. No target code was executed and effective network reachability was not tested.</p>${PRINT_FOOTER}</body></html>`;
}
