import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyze } from '../src/engine.mjs';
import { GraphStore, attachGraph } from '../src/graph-store.mjs';
import { GUIDANCE_HASH } from '../src/analysis-guidance.mjs';
import { sha } from '../src/sources.mjs';
import { SYSTEM_PROMPT, modelConfig } from '../src/model-review.mjs';
import { reviewThreatScenarios } from '../src/threat-validation.mjs';
import { threatAssessment } from '../src/threat-validation-state.mjs';
import { editSystem, systemModel } from '../src/system-model.mjs';
import { systemPrintReport } from '../src/system-exports.mjs';
import { workspaceStore } from '../src/workspace-store.mjs';
import { serve } from '../src/server.mjs';
const config = modelConfig('anthropic-gateway','claude-opus-4-6-1',{ CLAUDE_API_KEY: 'test-only' },{baseUrl:'https://gateway.example/anthropic'});
export async function threatFixture(t, extraFiles=[]) {
 const dir=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'threat-validation-'))), root=path.join(dir,'source');
 const manifest={title:'Twelve-service static review',profile:'fixture',repositories:Array.from({length:12},(_,i)=>({name:`repo${i}`}))};
 for(let i=0;i<12;i++) {await fs.mkdir(path.join(root,`repo${i}`),{recursive:true});await fs.writeFile(path.join(root,`repo${i}`,'Api.cs'),`class Api { [HttpPost("/jobs${i}")] public void Create() { PermissionFilter.Check(); } }`);}
 await fs.writeFile(path.join(root,'repo11','PermissionFilter.cs'),'class PermissionFilter { public void Check() { if (!principal.IsAdmin) throw new UnauthorizedAccessException(); } }');
 await fs.writeFile(path.join(root,'repo10','SecondGuard.cs'),'class SecondGuard { public bool Check() { return false; } }');
 for(const [relative,text] of extraFiles) await fs.writeFile(path.join(root,relative),text);
 const file=path.join(dir,'graph.sqlite'), model=await analyze(manifest,{sourceRoot:root,graphDatabase:file});
 const graph=new GraphStore(file,{readOnly:true});attachGraph(model.sourceGraph,graph);
 t.after(async()=>{graph.close();await fs.rm(dir,{recursive:true,force:true});});
 const interfaces=manifest.repositories.map(r=>model.interfaces.find(i=>i.repository===r.name && i.direction==='inbound'));
 assert.ok(interfaces.every(Boolean));
 model.aiReview={guidance:{hash:GUIDANCE_HASH},promptHash:sha(SYSTEM_PROMPT),status:'partial',basedOnRevision:model.modelRevision,mode:'source-excerpts',coverage:{completedBatches:12,totalBatches:20,pendingBatches:8,reviewedInterfaceIds:interfaces.map(i=>i.id)},batches:[],connections:[],questions:[],threats:interfaces.map((i,n)=>({id:`saved-threat-${n}`,title:'Conditional job authorization bypass',category:'Elevation of Privilege',actor:'API caller',startingAccess:'Assumed network access',asset:'Job operations',prerequisites:'Authorization fails',controls:'PermissionFilter exists; implementation must be checked',scenario:'Caller may create a job if PermissionFilter does not enforce its permission',mitigation:'Inspect PermissionFilter',interfaceIds:[i.id],evidenceIds:i.evidence}))};
 return {dir,root,manifest,model,graph};
}
function answer(packet, filename = 'PermissionFilter.cs') {
 const r=packet.records.find(r=>r.path===filename);assert.ok(r,'The named control in the twelfth repository must be retrieved');
 const ref={recordId:r.id,startLine:r.startLine,endLine:r.startLine,reason:'PermissionFilter checks authority on this fixture path'};
 return Response.json({stop_reason:'end_turn',usage:{input_tokens:100,output_tokens:20},content:[{type:'text',text:JSON.stringify({inputEvidence:null,sinkEvidence:null,deploymentAssumptions:[],assessment:'ruled-out',actorKind:'external-attacker',actor:'API caller',initialAccess:'Assumed access',input:'Job request',impact:'Unauthorized job',trace:[{...ref,role:'control'}],controls:[ref],counterEvidence:'Cited permission check rejects unauthorized callers in the fixture.',missingEvidence:[],followUp:[],remediation:{codeFix:'No change for this stated path',interimControl:'Review deployment exposure',residualRisk:'Other callers remain outside this assessment',recovery:'No compromise established',owner:'unknown',approval:'required',validation:'Static fixture',rollback:'Not applicable'},severityChangeConditions:'A caller bypassing the cited filter changes this assessment'})}]});
}
test('saved SQLite graph finds named cross-repository controls, preserves STRIDE, and reuses validated results after restart',async t=>{
 const f=await threatFixture(t), before=JSON.stringify(f.model.aiReview);let calls=0;
 const run=async(model)=>reviewThreatScenarios(f.manifest,model,{sourceRoot:f.root,config,budget:1,runUntilComplete:true,fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}});
 await run(f.model);assert.equal(calls,12);assert.equal(JSON.stringify(f.model.aiReview),before);
 assert.equal(f.model.threatValidation.entries.length,12);assert.ok(f.model.threatValidation.entries.every(e=>e.assessment==='ruled-out'));
 const s=systemModel(f.model);assert.ok(s.threats.filter(t=>t.origin==='analysis').every(t=>t.validation.assessment==='ruled-out' && t.actorIds.length && t.boundaryIds.length));
 assert.ok(s.boundaries.every(b=>b.reviewState!=='accepted'));assert.match(systemPrintReport(f.model),/Counterevidence found/);
 const store=await workspaceStore(f.root,path.join(f.dir,'state'));await store.save({model:f.model,manifest:f.manifest});const restored=(await store.load()).model;await store.close();attachGraph(restored.sourceGraph,f.graph);
 await run(restored);assert.equal(calls,12);
 assert.equal(threatAssessment(f.model,'saved-threat-0').assessment,'ruled-out');
 f.model.aiReview.threats[0].scenario='Different claim';assert.equal(threatAssessment(f.model,'saved-threat-0').assessment,'stale');
});
test('changed cited code cannot clear a saved threat, and bounded request budget is retained',async t=>{
 const f=await threatFixture(t);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:1,fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}});assert.equal(calls,1);
 const id=f.model.threatValidation.entries[0].sourceId;
 await fs.appendFile(path.join(f.root,'repo11','PermissionFilter.cs'),'\n// changed');
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:1,threatIds:[id],fetchImpl:()=>{throw Error('No call should clear changed source');}});
 assert.equal(threatAssessment(f.model,id).assessment,'needs-context');assert.match(threatAssessment(f.model,id).missingEvidence.join(' '),/Source changed/);
});
test('threat validation API requires authenticated access, source consent and saved IDs',async t=>{
 const f=await threatFixture(t),workspace=path.join(f.dir,'http');const store=await workspaceStore(f.root,workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
 await f.graph.backup(path.join(workspace,'graph.sqlite'));
 const app=await serve({sourceRoot:f.root,workspace,persist:true,port:0,quiet:true,modelConfig:config,cweModelFetch:async(_,request)=>answer(JSON.parse(JSON.parse(request.body).messages[0].content))});
 try {const u=new URL(app.url),headers={'X-Synthesis-Token':u.hash.slice(1),'Content-Type':'application/json'},url=u.origin+'/api/threats/validate';
 assert.equal((await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status,401);
 const send=body=>fetch(url,{method:'POST',headers,body:JSON.stringify({modelRevision:f.model.modelRevision,budget:1,...body})});
 assert.equal((await send({includeSourceCode:false})).status,400);
 assert.equal((await send({includeSourceCode:true,threatIds:['invented']})).status,400);
 const before=JSON.stringify(f.model.aiReview);
 assert.equal((await send({includeSourceCode:true,threatIds:['saved-threat-0']})).status,202);
 let state;for(let n=0;n<100;n++){state=await (await fetch(u.origin+'/api/status',{headers})).json();if(state.status!=='running')break;await new Promise(r=>setTimeout(r,20));}
 assert.equal(state.status,'ready');
 const saved=await (await fetch(u.origin+'/api/model',{headers})).json();
 assert.equal(saved.threatValidation.entries[0].assessment,'ruled-out');
 delete saved.aiReview.staleReason; assert.equal(JSON.stringify(saved.aiReview),before);
 }finally{await app.close();}
});


test('missing named controls trigger a bounded additional graph lookup and reassessment', async t => {
 const f=await threatFixture(t);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:4,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
   const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
   if(calls===1){const data=await answer(p).json(),v=JSON.parse(data.content[0].text);v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard before concluding that PermissionFilter covers this operation.'];data.content[0].text=JSON.stringify(v);return Response.json(data);}
   assert.ok(p.retrieval.controlSearches.some(x=>x.symbol==='SecondGuard' && x.matches));
   return answer(p,'SecondGuard.cs');
 }});
 assert.equal(calls,2);assert.equal(threatAssessment(f.model,'saved-threat-0').assessment,'ruled-out');
 assert.equal(f.model.threatValidation.entries[0].history.length,1);
 assert.equal(f.model.usageLedger.attempts.length,2);
});

test('invalid assessment receives one metered correction and does not loop or change STRIDE coverage',async t=>{
 const f=await threatFixture(t), before=JSON.stringify(f.model.aiReview);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:6,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
   const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
   assert.ok(Buffer.byteLength(JSON.stringify(p))<94000);
   const data=await answer(p).json();
   if(calls===1){const v=JSON.parse(data.content[0].text);v.trace[0].endLine=100000;data.content[0].text=JSON.stringify(v);}
   else assert.match(p.previousValidationFailure,/citation must stay/);
   return Response.json(data);
 }});
 assert.equal(calls,2);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
 assert.equal(f.model.usageLedger.attempts.length,2);assert.equal(JSON.stringify(f.model.aiReview),before);
});

test('deployment assumptions do not suppress a cited conditional code concern; missing code still blocks it',async t=>{
 const {validateThreatAssessment}=await import('../src/threat-validation.mjs');
 const r={id:'r',repository:'repo',path:'api.cs',blobSha256:'hash',startLine:1,endLine:5,lines:[{line:1,text:'input'},{line:2,text:'sink'}]};
 const p={records:[r],availableFiles:[],gaps:[]};
 const raw=await answer({records:[{...r,path:'PermissionFilter.cs'}]}).json(),v=JSON.parse(raw.content[0].text);
 v.assessment='static-supported';v.trace=[{recordId:'r',startLine:1,endLine:1,role:'input',reason:'request'},{recordId:'r',startLine:2,endLine:2,role:'sink',reason:'operation'}];
 v.deploymentAssumptions=['Endpoint is reachable in the selected deployment.'];
 assert.equal(validateThreatAssessment(v,p).assessment,'static-supported');
 assert.equal(validateThreatAssessment(v,p).deploymentStatus,'unverified-assumptions');
 v.inputEvidence={recordId:'r',startLine:1,endLine:1,reason:'Entry point'};
 v.sinkEvidence={recordId:'r',startLine:2,endLine:2,reason:'Sensitive operation'};v.trace=[];
 assert.equal(validateThreatAssessment(v,p).assessment,'static-supported');
 assert.equal(validateThreatAssessment(v,p).trace.length,2);
 assert.throws(()=>validateThreatAssessment({...v,inputEvidence:{...v.inputEvidence,recordId:'invented'}},p),/unknown record/);
 v.missingEvidence=['Authorization middleware implementation is unavailable.'];
 assert.equal(validateThreatAssessment(v,p).assessment,'needs-context');
 v.missingEvidence=[];p.gaps=[{reason:'source-hash-mismatch'}];
 assert.equal(validateThreatAssessment(v,p).assessment,'needs-context');
});

test('follow-up retrieves initialization and resource-matched route candidates from the existing graph',async t=>{
 const f=await threatFixture(t,[['repo0/knowledge.py','ENFORCE_AUTH = True\n'+'# context\n'.repeat(120)+'def get_item(item_id):\n return load(item_id)\n'],['repo5/KnowledgeRoute.cs','class Routes { [HttpGet("/knowledge/{id}")] public void Read() { Store.Get(); } }']]);
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const {InvestigationSource}=await import('../src/investigation-source.mjs');
 const source=new InvestigationSource(f.model,f.manifest,f.root),file=source.file('repo0','knowledge.py');
 const p=await threatInvestigationPacket(f.model,f.manifest,f.root,{id:'focused',locations:[{repository:'repo0',path:'knowledge.py',line:123,blobSha256:file.blobSha256}],controls:'',explanation:''},[{repository:'repo0',path:'knowledge.py',line:120}],{},['Inspect initialization before the function and the missing API route caller.']);
 assert.ok(p.records.some(r=>r.path==='knowledge.py'&&r.startLine===1));
 assert.ok(p.records.some(r=>r.path==='knowledge.py'&&r.endLine>=123));
 assert.ok(p.records.some(r=>r.path==='KnowledgeRoute.cs'&&r.basis==='resource-route-candidate'));
 assert.ok(p.retrieval.routeCandidates.length);assert.equal(p.retrieval.fullCallGraph,false);
});

test('initialization window cannot hide the remainder of an overlapping control implementation',async t=>{
 const f=await threatFixture(t,[['repo0/control.py','# config\n'.repeat(94)+'def enforce():\n reject()\n'+'# tail\n'.repeat(60)]]);
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const p=await threatInvestigationPacket(f.model,f.manifest,f.root,{id:'overlap',locations:[{repository:'repo0',path:'control.py',line:60}],controls:'',explanation:''},[{repository:'repo0',path:'control.py',line:79}],{},['Inspect initialization and the full control implementation.']);
 assert.ok(p.records.some(r=>r.path==='control.py'&&r.startLine===1));
 assert.ok(p.records.some(r=>r.path==='control.py'&&r.endLine>=96),'Line 79 inside the preamble must not suppress the window containing the enforcement at line 96');
});

test('failed response retains the requested control context for a bounded retry',async t=>{
 const f=await threatFixture(t);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:3,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  const raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
  if(calls===1){v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard'];v.followUp=[{repository:'repo10',path:'SecondGuard.cs',line:1,reason:'Inspect the other control'}];
    // The follow-up must use a submitted available file. Named lookup discovers it next.
    v.followUp=[];
  }else {assert.ok(p.records.some(r=>r.path==='SecondGuard.cs'));v.trace[0].endLine=100000;}
  raw.content[0].text=JSON.stringify(v);return Response.json(raw);
 }});
 const e=f.model.threatValidation.entries[0];assert.equal(e.assessment,'failed');assert.deepEqual(e.missingEvidence,['Inspect SecondGuard']);
 assert.equal(f.model.threatValidation.assessmentCounts.failed,1);assert.equal(calls,3);
});

test('cited conclusions retain independent assessments and STRIDE coverage, reject invented evidence and expire on claim changes', async t => {
  const {model, manifest, root} = await threatFixture(t);
  const id = model.aiReview.threats[0].id;
  await reviewThreatScenarios(manifest, model, {sourceRoot: root, config, budget: 1, threatIds: [id],
    fetchImpl: async (_, request) => answer(JSON.parse(JSON.parse(request.body).messages[0].content))});
  const current = systemModel(model);
  const evidence = current.threats.find(t => t.id === id).validation.evidence;
  const input = {action: 'source-conclusion', revision: current.revision, subjectId: id, status: 'open',
    statement: 'Caller binding requires review', condition: 'Caller is unknown', nextAction: 'Inspect binding',
    reviewer: 'Fixture reviewer', evidenceIds: [evidence[0].id]};
  assert.throws(() => editSystem(model, {...input, evidenceIds: ['unknown']}), /Unknown source window/);
  const next = editSystem(model, input);
  assert.deepEqual(next.aiReview, model.aiReview);
  assert.deepEqual(next.threatValidation, model.threatValidation);
  const report = systemPrintReport(next);
  assert.match(report, /Caller binding requires review/);
  assert.match(report, /Returned scenarios by STRIDE category/);
  next.aiReview.threats[0].scenario = 'Changed claim';
  assert.doesNotMatch(systemPrintReport(next), /Caller binding requires review/);
});
