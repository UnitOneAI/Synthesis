import {sha} from './sources.mjs';
import {stableJson} from './local-review-cache.mjs';

export const THREAT_BATCH_VERSION='section-threat-batch-2';
export const THREAT_BATCH_PROMPT=`
BATCH CONTRACT overrides the single-case wire envelope: return {sharedControls, cases}. Each cases item is {caseId, assessmentJson, controlApplications}; assessmentJson is a JSON-encoded string containing the complete original single-case assessment object (assessment, caseDetails, evidenceReview, remediation, engineering). Encode that object once as a JSON string, not markdown. Its full schema is supplied in the assessmentJson description; the application parses and validates every field and source citation independently. Return exactly one item for every supplied caseId, never combine or omit threats. The shared records array supplies hash-checked source. A case may cite records in its recordIds, within each record's exact range. entryRecordIds identify this case's primary operation; supportingRecordIds are additional source from related cases, not proof that their routes or controls apply here. The input trace, established entry and established path-binding must each cite this case's entryRecordIds. Never substitute a sibling route. Merge sharedContext into each case packet.context. Original missing-source gaps remain unless the additional source actually resolves them.
Analyze a common control implementation once in sharedControls (id, conclusion, citations). For each case that uses it, return a separate controlApplications item (controlId, effect, reason, bindingCitations). Binding citations must include that case's entry and actual path binding. A shared function name or repository is not proof of enforcement. Explain route-specific bypasses, identity, configuration and ordering. "enforces" means this control actually applies on this case path, not that every threat is ruled out. "ineffective", "not-applicable", and "unresolved" are distinct. Unresolved applicability must leave a missing applicable-controls obligation. Each assessment must independently cite its entry, sensitive operation, path binding and applicable controls. Shared conclusions do not replace those obligations. If no reusable control is established, use an empty sharedControls array and assess the cases separately. Keep each result concise; do not repeat the source or a common control's full explanation. Never reduce category coverage or invent policy to save tokens.
For the independent challenge, challenge every case and every shared-control applicability from fresh source. The first pass and its shared conclusions are hypotheses, not evidence. Preserve an explicit outcome for every case.`;
const obj=properties=>({type:'object',additionalProperties:false,properties,required:Object.keys(properties)});
const str={type:'string'};
const citation=obj({recordId:str,startLine:{type:'integer'},endLine:{type:'integer'}});
// The local validator enforces enums. Avoid multiplying provider grammar states
// across nested variable-length case/control arrays. No validation is relaxed.
const grammarShape=v=>Array.isArray(v)?v.map(grammarShape):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).filter(([k])=>k!=='enum').map(([k,x])=>[k,grammarShape(x)])):v;
export const batchSchema=assessment=>grammarShape(obj({
 sharedControls:{type:'array',items:obj({id:str,conclusion:str,citations:{type:'array',items:citation}})},
 cases:{type:'array',items:obj({caseId:str,assessmentJson:{type:'string',description:'JSON-encoded assessment object. Required schema: '+JSON.stringify(assessment)},controlApplications:{type:'array',items:obj({controlId:str,effect:{type:'string',enum:['enforces','ineffective','not-applicable','unresolved']},reason:str,bindingCitations:{type:'array',items:citation}})}})},
}));
function parseAssessment(text){if(typeof text!=='string'||text.length>100000)throw Error('Security assessment failed batch validation (bounded assessment JSON required)');try{return JSON.parse(text);}catch{throw Error('Security assessment failed batch validation (invalid assessment JSON)');}}
const mapRefs=(v,map)=>Array.isArray(v)?v.map(x=>mapRefs(x,map)):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,k==='recordId'&&typeof x==='string'?(map.get(x)||x):mapRefs(x,map)])):v;
export function threatBatch(items) {
 const records=new Map(),owners=new Map(),maps=new Map();
 const contexts=items.map(x=>x.packet.context || {}),sharedContext={};
 for(const key of Object.keys(contexts[0] || {}))if(contexts.every(c=>stableJson(c[key])===stableJson(contexts[0][key])))sharedContext[key]=contexts[0][key];
 const cases=items.map(({caseId,packet})=>{
  const map=new Map(),ids=[];
  for(const r of packet.records){const key='r-'+sha(stableJson({...r,id:undefined})).slice(0,24);records.set(key,{...r,id:key});map.set(key,r.id);ids.push(key);if(!owners.has(key))owners.set(key,new Set());owners.get(key).add(caseId);}
  maps.set(caseId,map);
  const {records:_,context,...rest}=packet;
  return {caseId,recordIds:ids,packet:{...rest,context:Object.fromEntries(Object.entries(context || {}).filter(([k])=>!Object.hasOwn(sharedContext,k)))}};
 });
 const validationItems=items.map((item,index)=>{
  const c=cases[index],map=maps.get(item.caseId),originalIds=[...c.recordIds];
  const locations=item.packet.candidate?.locations || [];
  const anchorRecords=item.packet.records.filter(r=>locations.some(l=>l.repository===r.repository&&l.path===r.path&&(!l.blobSha256||l.blobSha256===r.blobSha256)&&l.line>=r.startLine&&l.line<=r.endLine));
  c.entryRecordIds=originalIds.filter(id=>anchorRecords.some(r=>r.id===map.get(id)));
  c.supportingRecordIds=[...records.keys()].filter(id=>!originalIds.includes(id));
  c.recordIds=[...originalIds,...c.supportingRecordIds];
  // Additional context is explicit, hash-checked source already in this request.
  // It can establish a helper's behavior, never replace this case's entry/path.
  const extra=c.supportingRecordIds.map(id=>{map.set(id,id);return {...records.get(id),batchSupportingSource:true};});
  return {...item,entryRecordIds:new Set(anchorRecords.map(r=>r.id)),packet:{...item.packet,records:[...item.packet.records,...extra]}};
 });
 const packet={batchVersion:THREAT_BATCH_VERSION,purpose:'Related threats in one section; individual decisions and binding evidence required',sharedContext,records:[...records.values()],sharedRecordIds:[...owners].filter(([,ids])=>ids.size>1).map(([id])=>id),cases};
 return {packet,maps,items:validationItems,stats:{cases:items.length,originalBytes:items.reduce((n,x)=>n+Buffer.byteLength(JSON.stringify(x.packet)),0),batchBytes:Buffer.byteLength(JSON.stringify(packet)),sharedRecords:packet.sharedRecordIds.length}};
}
function bounded(v,label){if(typeof v!=='string'||!v.trim()||v.length>1600)throw Error('Security assessment failed batch validation ('+label+')');return v;}
function sourceRef(ref,records,sharedRecords=[]){
 // Prefer the original case window when identical bytes have another pooled ID.
 // Otherwise require an explicitly supplied supporting record, never unseen lines.
 const shared=sharedRecords.find(r=>r.id===ref?.recordId);
 const matches=r=>shared&&typeof shared.blobSha256==='string'&&r.repository===shared.repository&&r.path===shared.path&&r.blobSha256===shared.blobSha256&&ref.startLine>=r.startLine&&ref.endLine<=r.endLine;
 const r=records.find(r=>!r.batchSupportingSource&&r.id===ref?.recordId) || records.find(r=>!r.batchSupportingSource&&matches(r)) || records.find(r=>r.id===ref?.recordId);if(!r||!Number.isInteger(ref.startLine)||!Number.isInteger(ref.endLine)||ref.startLine<r.startLine||ref.endLine>r.endLine||ref.endLine<ref.startLine)throw Error('Security assessment failed batch validation (citation outside case-owned source)');if((r.lines||[]).some(l=>l.line>=ref.startLine&&l.line<=ref.endLine&&/\[(?:sensitive assignment|private key) omitted\]/.test(l.text)))throw Error('Security assessment failed batch validation (redacted control evidence)');return {...ref,recordId:r.id,repository:r.repository,path:r.path,blobSha256:r.blobSha256};}
function caseRefs(value,map,records,sharedRecords){
 if(Array.isArray(value))return value.map(v=>caseRefs(v,map,records,sharedRecords));
 if(!value||typeof value!=='object')return value;
 const result=Object.fromEntries(Object.entries(value).map(([k,v])=>[k,k==='recordId'&&typeof v==='string'?(map.get(v)||v):caseRefs(v,map,records,sharedRecords)]));
 if(typeof result.recordId==='string'&&Number.isInteger(result.startLine)&&Number.isInteger(result.endLine))result.recordId=sourceRef(result,records,sharedRecords).recordId;
 return result;
}
const overlaps=(a,b)=>(a.recordId===b.recordId||a.blobSha256&&a.blobSha256===b.blobSha256&&a.repository===b.repository&&a.path===b.path)&&a.startLine<=b.endLine&&b.startLine<=a.endLine;
export function validateThreatBatch(value,batch,validate) {
 if(!value||!Array.isArray(value.cases)||!Array.isArray(value.sharedControls)||value.cases.length>batch.items.length+4||value.sharedControls.length>12)throw Error('Security assessment failed batch validation (invalid envelope)');
 const expected=new Set(batch.items.map(i=>i.caseId));
 if(value.cases.some(c=>!expected.has(c.caseId)))throw Error('Security assessment failed batch validation (unknown case ID)');
 const results=[];
 for(const {caseId,packet,entryRecordIds} of batch.items)try {
  const rows=value.cases.filter(c=>c.caseId===caseId);if(rows.length!==1)throw Error('Security assessment failed batch validation (missing or duplicate case)');
  const row=rows[0],map=batch.maps.get(caseId);
  const review=validate(caseRefs(parseAssessment(row.assessmentJson),map,packet.records,batch.packet.records),packet),applications=[];
  for(const kind of ['entry','path-binding']){
   const obligation=review.engineering?.obligations.find(o=>o.kind===kind);
   if(obligation?.status!=='missing'&&!obligation?.citations.some(c=>entryRecordIds.has(c.recordId)))throw Error('Security assessment failed batch validation (entry and path-binding require this case primary operation)');
  }
  if(review.trace?.some(c=>c.role==='input')&&!entryRecordIds.has(review.trace.find(c=>c.role==='input').recordId))throw Error('Security assessment failed batch validation (input must cite this case primary operation)');
  if(!Array.isArray(row.controlApplications)||row.controlApplications.length>12)throw Error('Security assessment failed batch validation (control applications required)');
  const seen=new Set();
  for(const app of row.controlApplications){
   if(seen.has(app.controlId))throw Error('Security assessment failed batch validation (duplicate control application)');seen.add(app.controlId);
   const controls=value.sharedControls.filter(c=>c.id===app.controlId);if(controls.length!==1)throw Error('Security assessment failed batch validation (unknown or duplicate shared control)');
   const c=controls[0];bounded(c.id,'control ID');bounded(c.conclusion,'control conclusion');bounded(app.reason,'binding reason');
   if(!['enforces','ineffective','not-applicable','unresolved'].includes(app.effect)||!Array.isArray(c.citations)||!c.citations.length||c.citations.length>8||!Array.isArray(app.bindingCitations)||!app.bindingCitations.length||app.bindingCitations.length>8)throw Error('Security assessment failed batch validation (bounded control and binding citations required)');
   const citations=c.citations.map(r=>sourceRef(mapRefs(r,map),packet.records,batch.packet.records)),bindings=app.bindingCitations.map(r=>sourceRef(mapRefs(r,map),packet.records,batch.packet.records));
   const obligations=review.engineering?.obligations || [];
   for(const kind of ['entry','path-binding'])if(!bindings.some(r=>obligations.find(o=>o.kind===kind)?.citations.some(c=>overlaps(r,c))))throw Error('Security assessment failed batch validation (control reuse needs this case entry and path-binding citations)');
   if(app.effect!=='unresolved'&&!citations.some(r=>obligations.find(o=>o.kind==='applicable-controls')?.citations.some(c=>overlaps(r,c))))throw Error('Security assessment failed batch validation (shared control not cited by this case control obligation)');
   if(app.effect==='unresolved'&&(review.assessment!=='needs-context'||obligations.find(o=>o.kind==='applicable-controls')?.status!=='missing'))throw Error('Security assessment failed batch validation (unresolved control cannot settle a case)');
   applications.push({controlId:c.id,conclusion:c.conclusion,effect:app.effect,reason:app.reason,citations,bindingCitations:bindings});
  }
  results.push({caseId,review:{...review,sharedControlApplications:applications}});
 }catch(error){results.push({caseId,error:error.message});}
 return {batchVersion:THREAT_BATCH_VERSION,results};
}
