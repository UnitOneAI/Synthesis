import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs/promises';
import {threatBatch,validateThreatBatch} from '../src/threat-batch.mjs';
import {reviewSectionThreats} from '../src/section-batch-review.mjs';
import {validateThreatAssessment,THREAT_ASSESSMENT_SCHEMA,THREAT_ASSESSMENT_PROMPT,THREAT_CHALLENGE_PROMPT} from '../src/threat-validation.mjs';
import {reportFixture} from './report-fixture.mjs';
import {expandEvidence} from '../src/evidence-transport.mjs';
const rec=(id,path)=>({id,repository:'service',path,blobSha256:'hash-'+path,startLine:1,endLine:2,lines:[{line:1,text:'def entry(): return control()'},{line:2,text:'def control(): return write()'}]});
const packet=n=>({candidate:{id:'case'+n},context:{profile:'fixture'},sectionReview:true,records:[rec('entry'+n,'route'+n+'.py'),rec('control','control.py')],gaps:[],availableFiles:[]});
function assessment(records,status='static-supported'){
 const r=records[0],control=records.at(-1),ref={recordId:r.id,startLine:1,endLine:1,reason:'Fixture entry'},cr={recordId:control.id,startLine:1,endLine:2,reason:'Fixture control'};
 return {assessment:status,caseDetails:{actorKind:'external-attacker',actor:'Caller',initialAccess:'Assumed access',input:'Fixture input',impact:'Fixture persistent write',severityChangeConditions:'Actual exposure'},evidenceReview:{trace:[{...ref,role:'input'},{...ref,role:'sink'}],controls:[cr],counterEvidence:'Fixture controls examined.',followUp:[]},remediation:{codeFix:'Require authorization',interimControl:'Limit exposure',residualRisk:'Deployment unknown',recovery:'Review writes',owner:'unknown',approval:'required',validation:'Test policy',rollback:'Restore config'},engineering:{conditions:[],consistency:{status:'consistent',reason:'Fixture conclusion agrees with controls'},conclusion:'Fixture caller can perform the operation.',obligations:['entry','sensitive-operation','path-binding','applicable-controls'].map(kind=>({kind,status:status==='ruled-out'&&kind==='applicable-controls'?'blocks-attack':'established',reason:'Cited fixture behavior',citations:[kind==='applicable-controls'?cr:ref]})),reviewerQuestions:[]}};
}
function edit(row,fn){const v=JSON.parse(row.assessmentJson);fn(v);row.assessmentJson=JSON.stringify(v);}
function answer(wire){const control=wire.records.find(r=>r.path==='control.py');return {sharedControls:[{id:'shared',conclusion:'Shared control behavior from the cited implementation.',citations:[{recordId:control.id,startLine:1,endLine:2}]}],cases:wire.cases.map(c=>{const records=c.recordIds.map(id=>wire.records.find(r=>r.id===id));return {caseId:c.caseId,assessmentJson:JSON.stringify(assessment(records)),controlApplications:[{controlId:'shared',effect:'ineffective',reason:'This case reaches the cited control.',bindingCitations:[{recordId:records[0].id,startLine:1,endLine:1}]}]};})};}
const response=v=>Response.json({stop_reason:'end_turn',usage:{input_tokens:100,output_tokens:20},content:[{type:'text',text:JSON.stringify(v)}]});
test('shared source is sent once while every case retains its own citation ownership and applicability',()=>{
 const batch=threatBatch([1,2].map(n=>({caseId:'case'+n,packet:packet(n)})));assert.equal(batch.packet.records.length,3);assert.equal(batch.packet.sharedRecordIds.length,1);
 const result=validateThreatBatch(answer(batch.packet),batch,validateThreatAssessment);assert.ok(result.results.every(r=>r.review.assessment==='static-supported'));
 assert.ok(result.results.every(r=>r.review.sharedControlApplications.length===1));assert.equal(result.results[0].review.trace[0].recordId,'entry1');
 const v=answer(batch.packet);edit(v.cases[1],a=>a.evidenceReview.trace[0].recordId=batch.packet.cases[0].recordIds[0]);const mixed=validateThreatBatch(v,batch,validateThreatAssessment);assert.ok(mixed.results[0].review);assert.match(mixed.results[1].error,/validation/);
 const unbound=answer(batch.packet);unbound.cases[0].controlApplications[0].bindingCitations=[{recordId:batch.packet.sharedRecordIds[0],startLine:1,endLine:1}];assert.match(validateThreatBatch(unbound,batch,validateThreatAssessment).results[0].error,/entry and path-binding/);
 const missing=answer(batch.packet);missing.cases.pop();const partial=validateThreatBatch(missing,batch,validateThreatAssessment);assert.ok(partial.results[0].review);assert.match(partial.results[1].error,/missing or duplicate/);
});
test('uncertain controls and cross-case assumptions cannot settle another path',()=>{
 const batch=threatBatch([1,2].map(n=>({caseId:'case'+n,packet:packet(n)}))),v=answer(batch.packet);v.cases[0].controlApplications[0].effect='unresolved';assert.match(validateThreatBatch(v,batch,validateThreatAssessment).results[0].error,/unresolved control/);
 v.cases[0].controlApplications[0].effect='enforces';v.sharedControls[0].citations[0].recordId=batch.packet.cases[0].recordIds[0];const r=validateThreatBatch(v,batch,validateThreatAssessment);assert.match(r.results[0].error,/control obligation/);assert.ok(r.results[1].error);
 const unknown=answer(batch.packet);unknown.cases[0].caseId='invented';assert.throws(()=>validateThreatBatch(unknown,batch,validateThreatAssessment),/unknown case/);
});
async function fixture(t){const f=await reportFixture();t.after(()=>fs.rm(f.dir,{recursive:true,force:true}));const options={sourceRoot:f.root,config:{provider:'anthropic',model:'fixture',apiKey:'fixture-key',compactEvidence:true},candidateIssues:[1,2,3,4].map(n=>({id:'case'+n,sourceId:'case'+n,origin:'analysis',locations:[]})),contextKeyOverride:'fixture-context',systemPrompt:THREAT_ASSESSMENT_PROMPT,challengePrompt:THREAT_CHALLENGE_PROMPT,responseSchema:THREAT_ASSESSMENT_SCHEMA,validateResponse:validateThreatAssessment,packetBuilder:async(m,mf,root,issue)=>packet(Number(issue.id.slice(4))),budget:20};return {...f,options};}
test('four cold cases use two actual calls including independent challenges, with one usage charge per batch',async t=>{
 const f=await fixture(t);let calls=0;await reviewSectionThreats(f.manifest,f.model,{...f.options,fetchImpl:async(_,req)=>{calls++;const body=JSON.parse(req.body);assert.equal(body.max_tokens,16384);return response(answer(expandEvidence(JSON.parse(body.messages[0].content))));}});
 assert.equal(calls,2);assert.equal(f.model.threatValidation.pending,0);assert.ok(f.model.threatValidation.entries.every(e=>e.challengeCompleted&&e.draftAssessment.assessment==='static-supported'));
 assert.equal(f.model.usageLedger.attempts.length,2);assert.equal(f.model.usageLedger.attempts.reduce((n,a)=>n+a.usage.totalTokens,0),240);assert.ok(f.model.threatValidation.entries.every(e=>!e.usage));assert.equal(f.model.threatValidation.batching.caseAssessments,8);
});
test('one invalid case cannot discard siblings, and budget counts requests not cases',async t=>{
 const f=await fixture(t);let calls=0;const send=async(_,req)=>{calls++;const v=answer(expandEvidence(JSON.parse(JSON.parse(req.body).messages[0].content)));if(calls===1)edit(v.cases[0],a=>a.evidenceReview.trace[0].recordId='invented');return response(v);};
 await reviewSectionThreats(f.manifest,f.model,{...f.options,budget:1,fetchImpl:send});assert.equal(calls,1);assert.equal(f.model.threatValidation.entries.filter(e=>e.assessment==='failed').length,1);assert.equal(f.model.threatValidation.entries.filter(e=>e.challengePending).length,3);
 await reviewSectionThreats(f.manifest,f.model,{...f.options,fetchImpl:send});assert.equal(f.model.threatValidation.pending,0);assert.ok(f.model.threatValidation.entries.every(e=>e.challengeCompleted));assert.ok(calls<=4);
});
test('provider failures retain honest pending cases and cancellation stays resumable',async t=>{
 const f=await fixture(t);await reviewSectionThreats(f.manifest,f.model,{...f.options,fetchImpl:async()=>Response.json({}, {status:403})});assert.equal(f.model.threatValidation.callsThisRun,1);assert.equal(f.model.threatValidation.pending,4);assert.equal(f.model.usageLedger.attempts[0].status,'failed');
 const controller=new AbortController();controller.abort();const model=structuredClone(f.model);await reviewSectionThreats(f.manifest,model,{...f.options,signal:controller.signal,fetchImpl:()=>{throw Error('No dispatch');}});assert.equal(model.threatValidation.callsThisRun,0);assert.equal(model.threatValidation.status,'cancelled');
});
test('redacted shared controls and invalid embedded JSON cannot become evidence',()=>{
 const batch=threatBatch([1,2].map(n=>({caseId:'case'+n,packet:packet(n)}))),v=answer(batch.packet);
 v.cases[0].assessmentJson='{broken';assert.match(validateThreatBatch(v,batch,validateThreatAssessment).results[0].error,/invalid assessment JSON/);
 v.cases[0]=answer(batch.packet).cases[0];batch.items[0].packet.records[1].lines[0].text='[private key omitted]';assert.match(validateThreatBatch(v,batch,validateThreatAssessment).results[0].error,/redacted/);
 const enumValue=answer(batch.packet);edit(enumValue.cases[1],a=>a.assessment='confirmed-vulnerability');assert.ok(validateThreatBatch(enumValue,batch,validateThreatAssessment).results[1].error,'Local enum validation remains mandatory despite a small provider grammar');
});
test('oversized and unrelated source bundles split without dropping cases or challenges',async t=>{
 const f=await fixture(t);let calls=0;await reviewSectionThreats(f.manifest,f.model,{...f.options,packetBuilder:async(m,mf,root,issue)=>{const p=packet(Number(issue.id.slice(4)));p.context.large='x'.repeat(85000)+issue.id;return p;},fetchImpl:async(_,req)=>{calls++;const p=expandEvidence(JSON.parse(JSON.parse(req.body).messages[0].content));assert.equal(p.cases.length,1);return response(answer(p));}});
 assert.equal(calls,8);assert.equal(f.model.threatValidation.pending,0);assert.ok(f.model.threatValidation.entries.every(e=>e.challengeCompleted));
});
test('batched cache replays both independent passes without dispatch or fabricated token usage',async t=>{
 const f=await fixture(t),{LocalReviewCache}=await import('../src/local-review-cache.mjs'),initial=structuredClone(f.model),cache=new LocalReviewCache(f.dir+'/batch-cache.sqlite');let calls=0;try {
 const config={...f.options.config,localReviewCache:cache,localReviewContext:'section-fixture'},send=async(_,req)=>{calls++;return response(answer(expandEvidence(JSON.parse(JSON.parse(req.body).messages[0].content))));};
 await reviewSectionThreats(f.manifest,f.model,{...f.options,config,fetchImpl:send});assert.equal(calls,2);
 await reviewSectionThreats(f.manifest,initial,{...f.options,config,fetchImpl:()=>{throw Error('Must reuse');}});assert.equal(initial.threatValidation.callsThisRun,0);assert.equal(initial.threatValidation.pending,0);assert.equal(initial.usageLedger.attempts.length,0);assert.equal(cache.stats.hits,2);
 } finally {cache.close();}
});
test('concise reports keep every prerequisite, action and citation without mutating the saved assessment',async()=>{
 const {threatBriefHtml}=await import('../src/system-exports.mjs');const a=validateThreatAssessment(assessment(packet(1).records),packet(1));const eng={...a.engineering,conditions:[{statement:'The caller can reach this route.',requiredAnswer:'yes'},{statement:'An upstream control enforces admin membership.',requiredAnswer:'no'}]};const t={name:'Original speculative title',validation:{actor:'User',impact:'A persistent write',engineering:eng,remediation:{codeFix:'Enforce authorization at the handler.',validation:'Reject a non-admin caller.'}},decisionPath:{actor:'User',access:'Network access',pathStatus:'Code argument recorded',interpretation:'Static',stages:[],declaredExposure:'Conditional',runtime:'Not tested',consistency:{status:'consistent',reason:'Cited'},boundaries:[],repositories:['service']}};const before=JSON.stringify(t),html=threatBriefHtml(t);
 assert.match(html,/Applies only when all conditions hold/);assert.match(html,/Required: no/);assert.match(html,/Enforce authorization at the handler/);assert.match(html,/Reject a non-admin/);assert.match(html,/Full path, opposing evidence/);assert.match(html,/route1.py:1–1/);assert.ok(!html.includes('Original speculative title'));assert.equal(JSON.stringify(t),before);
});
test('shared control window aliases resolve only to source already owned by the case',()=>{
 const p1=packet(1),p2=packet(2);p2.records[1].reason='A different retrieval role';p2.records[1].id='other-window';const batch=threatBatch([{caseId:'case1',packet:p1},{caseId:'case2',packet:p2}]),v=answer(batch.packet);
 edit(v.cases[1],a=>a.engineering.obligations.find(o=>o.kind==='applicable-controls').citations[0].recordId=v.sharedControls[0].citations[0].recordId);
 const good=validateThreatBatch(v,batch,validateThreatAssessment);assert.ok(good.results.every(r=>r.review));assert.equal(good.results[1].review.sharedControlApplications[0].citations[0].recordId,'other-window');
 p2.records[1].startLine=2;assert.match(validateThreatBatch(v,batch,validateThreatAssessment).results[1].error,/validation/);
});
