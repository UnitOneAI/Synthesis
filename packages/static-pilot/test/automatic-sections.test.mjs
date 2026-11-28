import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs/promises';
import {reportFixture} from './report-fixture.mjs';
import {automaticSectionPlan,sectionReviewPlan,sectionCompletion,sectionModel,automaticSectionSummary,syncAutomaticSectionProjection} from '../src/automatic-sections.mjs';
import {reviewAutomaticSections} from '../src/automatic-section-run.mjs';
import {sectionReport} from '../src/section-report.mjs';
import {verifiedStrideSource,prepareStrideEvidence} from '../src/stride-evidence.mjs';
import {modelConfig} from '../src/model-review.mjs';
import {REPOSITORY_CATEGORIES} from '../src/repository-assessment-summary.mjs';
import {securityFeatureSubject} from '../src/repository-scope.mjs';
import {workspaceStore} from '../src/workspace-store.mjs';
import {serve} from '../src/server.mjs';
const config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'test-key'});
const response=packet=>({summary:'Synthetic test assessment, not a real security conclusion.',threats:[],connections:[],questions:[],explorationRequests:[],categoryReviews:REPOSITORY_CATEGORIES.map(category=>({category,status:'no-scenario-identified',interfaceIds:packet.reviewUnit.primaryInterfaceIds,rationale:'Synthetic fixture source was reviewed.',citations:packet.sourceContext.records.map(r=>({recordId:r.id,line:r.startLine,endLine:r.endLine,role:'context'})),threatIndexes:[],missingEvidence:[],deploymentConditions:['Network placement unverified.'],remediation:''}))});
async function fixture(t){const f=await reportFixture();t.after(()=>fs.rm(f.dir,{recursive:true,force:true}));return f;}
async function run(f,options={}) {let calls=0;const source=await verifiedStrideSource(f.model,f.manifest,f.root);const fetchImpl=async(_,req)=>{calls++;const packet=JSON.parse(JSON.parse(req.body).messages[0].content);return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(response(packet))}],usage:{input_tokens:10,output_tokens:20}});};await reviewAutomaticSections(f.model,f.manifest,config,new Map(),options.fetchImpl||fetchImpl,{sourceRoot:f.root,verifiedSource:source,prepareBatch:b=>prepareStrideEvidence(b.packet,source),concurrency:1,...options});return calls;}
test('automatic catalog partitions every selected security subject once and keeps supporting repositories',async t=>{
 const f=await fixture(t),before=JSON.stringify(f.model.sourceGraph),p=automaticSectionPlan(f.model);
 const ids=p.sections.flatMap(s=>s.interfaceIds);assert.equal(new Set(ids).size,ids.length);assert.deepEqual(ids.sort(),f.model.interfaces.filter(securityFeatureSubject).map(i=>i.id).sort());
 assert.ok(p.sections.every(s=>s.interfaceIds.length<=3));assert.deepEqual(automaticSectionPlan({...f.model,interfaces:[...f.model.interfaces].reverse()}).sections,p.sections);
 assert.equal(JSON.stringify(f.model.sourceGraph),before);assert.throws(()=>automaticSectionPlan(f.model,{repositories:['absent']}),/loaded/);
 const many={...f.model,interfaces:Array.from({length:10000},(_,n)=>({...f.model.interfaces.find(securityFeatureSubject),id:String(n),operation:'GET /items/'+n,connection:{path:'/items/{id}',method:'GET'}}))};
 const large=automaticSectionPlan(many);assert.throws(()=>automaticSectionPlan({...f.model,interfaces:[]}),/No security operations/);assert.equal(large.primaryOperations,10000);assert.equal(large.sections.length,3334);
});
test('automatic sections finish all six categories, persist, export and resume without paid calls',async t=>{
 const f=await fixture(t),graph=JSON.stringify(f.model.sourceGraph),cwe=JSON.stringify(f.model.cweReview);
 const prior={reviewScope:'system',scope:{},status:'partial',threats:[],batches:[],coverage:{completedBatches:0}};f.model.aiReview=prior;
 assert.ok(await run(f)>0);const p=f.model.automaticSections.plan;assert.equal(f.model.automaticSections.run.status,'complete');
 assert.ok(p.sections.every(s=>f.model.automaticSections.results[s.id].completion.complete));assert.equal(await run(f),0);
 assert.deepEqual(f.model.automaticSections.previous.aiReview,prior);assert.equal(JSON.stringify(f.model.sourceGraph),graph);assert.equal(JSON.stringify(f.model.cweReview),cwe);
 const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});const restored=await store.load();await store.close();f.model=restored.model;
 assert.equal(await run(f),0);const html=await sectionReport(f.model,f.manifest,f.root,p.sections[0].id);assert.match(html,/Section static threat model complete/);for(const c of REPOSITORY_CATEGORIES)assert.ok(html.includes(c));assert.match(html,/Confidential/);
 const app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});try{const base=new URL(app.url).origin,headers={'X-Synthesis-Token':app.token};const r=await fetch(base+'/api/sections',{headers});assert.equal(r.status,200);const loaded=await r.json();assert.ok(loaded.sections.every(s=>s.status==='complete'));assert.equal((await fetch(base+'/api/section-report?id='+p.sections[0].id)).status,401);assert.match(await (await fetch(base+'/api/section-report?id='+p.sections[0].id,{headers})).text(),/Section static threat model complete/);}finally{await app.close();}
});
test('completion rejects missing category, unresolved scenario, failed batch and changed context',async t=>{
 const f=await fixture(t);await run(f);const section=f.model.automaticSections.plan.sections[0],result=f.model.automaticSections.results[section.id];
 const good=structuredClone(result.review);const check=()=>sectionCompletion({...f.model,aiReview:result.review},section);
 result.review.batches[0].review.categoryReviews.pop();assert.equal(check().complete,false);result.review=structuredClone(good);
 result.review.batches[0].review.categoryReviews[0].status='evidence-gap';assert.equal(check().complete,false);result.review=structuredClone(good);
 result.review.batches[0].status='failed';assert.equal(check().complete,false);result.review=structuredClone(good);
 result.review.threats=[{id:'unassessed',title:'Candidate',interfaceIds:section.interfaceIds,evidenceIds:[]}];assert.equal(check().complete,false);result.review=good;
 f.model.deploymentContext={profile:'changed'};assert.equal(sectionModel(f.model,section.id).completion.complete,false);assert.equal(automaticSectionSummary(f.model).sections[0].status,'stale');
});
test('provider failures stop dispatch without false completion and preserve saved results',async t=>{
 const f=await fixture(t);let calls=0;await run(f,{fetchImpl:async()=>{calls++;return Response.json({error:'not authorized'},{status:403});}});
 assert.equal(f.model.automaticSections.run.status,'failed');assert.equal(calls,1);const result=Object.values(f.model.automaticSections.results)[0];assert.equal(result.status,'failed');assert.equal(result.completion.complete,false);
});
test('cancelled section run stays resumable without losing graph',async t=>{
 const f=await fixture(t),controller=new AbortController();controller.abort();assert.equal(await run(f,{signal:controller.signal}),0);assert.equal(f.model.automaticSections.run.status,'interrupted');assert.ok(await run(f)>0);assert.equal(f.model.automaticSections.run.status,'complete');
});
test('changed source export refuses complete while preserving the saved assessment',async t=>{
 const f=await fixture(t);await run(f);const s=f.model.automaticSections.plan.sections[0],before=JSON.stringify(f.model.automaticSections);
 await fs.appendFile(f.root+'/service/app.py','\n# changed source\n');
 const html=await sectionReport(f.model,f.manifest,f.root,s.id);assert.match(html,/Section not complete/);assert.match(html,/no longer available unchanged/);assert.equal(JSON.stringify(f.model.automaticSections),before);
});
test('evidence gaps block the section and do not disappear on resume',async t=>{
 const f=await fixture(t);let calls=0;
 const send=async(_,req)=>{calls++;const packet=JSON.parse(JSON.parse(req.body).messages[0].content),r=response(packet);r.categoryReviews[0].status='evidence-gap';r.categoryReviews[0].missingEvidence=['Missing DispatchGateway control implementation'];return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(r)}],usage:{input_tokens:10,output_tokens:20}});};
 await run(f,{fetchImpl:send});const n=calls;assert.ok(n<=4);assert.equal(f.model.automaticSections.run.status,'finished-with-blockers');assert.equal(Object.values(f.model.automaticSections.results)[0].status,'blocked');
 await run(f,{fetchImpl:send});assert.equal(calls,n,'Unchanged exhausted retrieval must not repeatedly spend tokens');
});
test('automatic invalid-response recovery retries without a confirmation and retains both attempt costs',async t=>{
 const f=await fixture(t);let count=0;const send=async(_,req)=>{count++;const p=JSON.parse(JSON.parse(req.body).messages[0].content),value=count===1?{summary:'invalid'}:response(p);return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(value)}],usage:{input_tokens:10,output_tokens:20}});};
 await run(f,{fetchImpl:send,recoveryDelayMs:1});assert.equal(f.model.automaticSections.run.status,'complete');const r=Object.values(f.model.automaticSections.results)[0];assert.equal(count,2);assert.equal(r.calls,2);assert.equal(r.reportedTokens,60);assert.equal(r.completion.complete,true);
});
test('section reports and status cannot use an unchallenged positive to claim completion',async t=>{
 const f=await fixture(t);await run(f);const section=f.model.automaticSections.plan.sections[0],result=f.model.automaticSections.results[section.id];
 const {threatIssue,threatValidationKey}=await import('../src/threat-validation-state.mjs');const {sha}=await import('../src/sources.mjs');
 const i=f.model.interfaces.find(i=>section.interfaceIds.includes(i.id));const threat={id:'t',title:'Conditional',scenario:'Current path',interfaceIds:[i.id],evidenceIds:i.evidence,category:'Tampering'};
 result.review.threats=[threat];const view={...f.model,aiReview:result.review};view.threatValidation={contextKey:threatValidationKey(view),entries:[{sourceId:'t',issueHash:sha(JSON.stringify(threatIssue(view,threat))),assessment:'static-supported',challengeCompleted:false}]};
 assert.equal(sectionCompletion(view,section).complete,false);view.threatValidation.entries[0].challengeCompleted=true;assert.equal(sectionCompletion(view,section).complete,false);
 view.threatValidation.entries[0].draftAssessment={assessment:'static-supported'};
 view.threatValidation.entries[0].engineering={version:2,consistency:{status:'consistent'},obligations:['entry','sensitive-operation','path-binding','applicable-controls'].map(kind=>({kind,status:'established',citations:[{recordId:'fixture'}]}))};
 assert.equal(sectionCompletion(view,section).complete,true);
 view.threatValidation.entries[0].engineering.obligations[3].status='missing';assert.equal(sectionCompletion(view,section).complete,false);
});

test('later engineering rechecks update the saved section instead of retaining a complete label',async t=>{
 const f=await fixture(t);await run(f);const id=f.model.aiReview.scope.poc.id,result=f.model.automaticSections.results[id];
 f.model.aiReview=structuredClone(f.model.aiReview);f.model.aiReview.batches[0].review.categoryReviews[0].status='evidence-gap';
 assert.equal(sectionModel(f.model,id).completion.complete,false);syncAutomaticSectionProjection(f.model);
 assert.equal(result.status,'blocked');assert.equal(automaticSectionSummary(f.model).sections.find(s=>s.id===id).completion.complete,false);
});

test('checkpoint projection preserves interruption and failure so automatic resume can retry',async t=>{
 const f=await fixture(t);await run(f);const id=f.model.aiReview.scope.poc.id,result=f.model.automaticSections.results[id];
 for(const status of ['interrupted','failed']) {result.status=status;f.model.automaticSections.run.status=status;syncAutomaticSectionProjection(f.model);assert.equal(result.status,status);}
});
test('category citation omissions get one bounded repair even when no new source exists',async t=>{
 const f=await fixture(t);let count=0,feedback=[];
 const send=async(_,req)=>{count++;const p=JSON.parse(JSON.parse(req.body).messages[0].content),r=response(p);if(count===1)r.categoryReviews[0].citations=[];else feedback=p.sourceContext.priorReview?.validationCorrections || [];return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(r)}],usage:{input_tokens:10,output_tokens:20}});};
 await run(f,{fetchImpl:send});assert.equal(f.model.automaticSections.run.status,'complete');assert.equal(count,2);assert.ok(feedback.some(s=>/cited|citation/i.test(s)));assert.equal(Object.values(f.model.automaticSections.results)[0].calls,2);
});
test('category closure preserves retained cases and distinguishes optional search candidates from required missing source',async t=>{
 const f=await fixture(t),source=await verifiedStrideSource(f.model,f.manifest,f.root),section=automaticSectionPlan(f.model).sections[0];
 const prepared=await prepareStrideEvidence(sectionReviewPlan(f.model,section).batches[0].packet,source,{sectionEvidence:true}),p=prepared.packet;
 const {validateRepositoryReview,validateCategoryFollowUp,repositoryThreatWire}=await import('../src/repository-assessment.mjs');
 const r=response(p),i=p.records.find(i=>section.interfaceIds.includes(i.id));
 r.threats=[{title:'Synthetic conditional write',category:'Tampering',actor:'Fixture actor',startingAccess:'Fixture access',asset:'Fixture data',scenario:'Synthetic scenario',prerequisites:'Fixture assumptions',controls:'Fixture controls',mitigation:'Fixture fix',interfaceIds:[i.id],evidenceIds:i.evidence.map(e=>e.id)}];
 const initial=validateRepositoryReview(r,p);
 p.sourceContext.priorReview={retainedThreats:initial.threats.map(repositoryThreatWire)};
 const follow=response(p);const closed=validateCategoryFollowUp(follow,p);
 assert.equal(closed.threats.length,1);assert.deepEqual(closed.threats,initial.threats,'No renamed case or changed engineering issue hash');
 assert.equal(closed.categoryReviews.find(c=>c.category==='Tampering').status,'evidence-gap','A clean category cannot hide a retained scenario');
 p.sourceContext.priorReview.retainedThreats=[];p.sourceContext.gaps=[{reason:'source-context-window-limit',required:false}];
 assert.ok(validateCategoryFollowUp(response(p),p).categoryReviews.every(c=>c.status==='no-scenario-identified'));
 p.sourceContext.gaps[0].required=true;assert.ok(validateCategoryFollowUp(response(p),p).categoryReviews.every(c=>c.status==='evidence-gap'));
 const bad=response(p);bad.threats=[{...r.threats[0],interfaceIds:['invented']}];assert.throws(()=>validateCategoryFollowUp(bad,p),/validation/);
});
test('restart after interrupted category replacement restores the last successful paid packet',async t=>{
 const f=await fixture(t);await run(f);const original=structuredClone(f.model.aiReview.batches[0]),id=f.model.aiReview.scope.poc.id;
 f.model.featureEvidenceHistory=[{batchId:original.id,previous:original}];
 f.model.aiReview.batches[0].status='pending';f.model.aiReview.coverage.completedBatches=0;f.model.aiReview.coverage.pendingBatches=1;
 f.model.automaticSections.results[id].status='interrupted';
 assert.equal(await run(f),0);assert.equal(f.model.automaticSections.results[id].status,'complete');
});
test('optional oversized candidates remain visible without hiding required source omissions',async t=>{
 const f=await fixture(t),source=await verifiedStrideSource(f.model,f.manifest,f.root),section=automaticSectionPlan(f.model).sections[0],packet=sectionReviewPlan(f.model,section).batches[0].packet;
 const proxy=Object.create(source);proxy.functionWindow=async ref=>ref.path==='candidate.py'?{id:'candidate',repository:'service',path:'candidate.py',startLine:1,endLine:1,code:'x'.repeat(100000),lines:[],blobSha256:'synthetic'}:source.functionWindow(ref);
 const {validateRepositoryReview}=await import('../src/repository-assessment.mjs');
 for(const required of [false,true]){
  const p=await prepareStrideEvidence(packet,proxy,{sectionEvidence:true,references:[{repository:'service',path:'candidate.py',line:1,required}]});
  assert.equal(p.context.gaps.find(g=>g.path==='candidate.py').required,required);
  assert.ok(validateRepositoryReview(response(p.packet),p.packet).categoryReviews.every(c=>c.status===(required?'evidence-gap':'no-scenario-identified')));
 }
});

test('category closure keeps primary types before broad optional search candidates',async t=>{
 const f=await fixture(t),source=await verifiedStrideSource(f.model,f.manifest,f.root),section=automaticSectionPlan(f.model).sections[0],packet=sectionReviewPlan(f.model,section).batches[0].packet;
 const proxy=Object.create(source);proxy.calledImplementations=()=>({references:[{repository:'service',path:'request-type.py',line:1,required:false}],searches:[],limited:false});
 proxy.functionWindow=async ref=>/^(request-type|candidate-)/.test(ref.path)?{id:ref.path,repository:'service',path:ref.path,startLine:1,endLine:1,code:'1: class Request: pass',lines:[],blobSha256:'synthetic'}:source.functionWindow(ref);
 const refs=Array.from({length:30},(_,n)=>({repository:'service',path:'candidate-'+n+'.py',line:1,required:false}));
 const p=await prepareStrideEvidence(packet,proxy,{sectionEvidence:true,references:refs});
 assert.ok(p.packet.sourceContext.records.some(r=>r.path==='request-type.py'));
 assert.ok(p.context.gaps.some(g=>g.path?.startsWith('candidate-')&&g.required===false));
});

test('automatic categories require a specific gap instead of persisting an unexplained pending disposition',async t=>{
 const f=await fixture(t),source=await verifiedStrideSource(f.model,f.manifest,f.root),section=automaticSectionPlan(f.model).sections[0],packet=sectionReviewPlan(f.model,section).batches[0].packet;
 const prepared=await prepareStrideEvidence(packet,source,{sectionEvidence:true});const value=response(prepared.packet);
 const {validateRepositoryReview}=await import('../src/repository-assessment.mjs');
 value.categoryReviews[0].status='evidence-gap';value.categoryReviews[0].missingEvidence=[];
 assert.throws(()=>validateRepositoryReview(value,prepared.packet),/identifies no missing code/);
 value.categoryReviews[0].missingEvidence=['The invoked policy handler implementation is not supplied.'];
 assert.equal(validateRepositoryReview(value,prepared.packet).categoryReviews[0].status,'evidence-gap');
});
