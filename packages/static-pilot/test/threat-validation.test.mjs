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
 return Response.json({stop_reason:'end_turn',usage:{input_tokens:100,output_tokens:20},content:[{type:'text',text:JSON.stringify({engineering:{conditions:[],consistency:{status:'consistent',reason:'The cited blocking control is consistent with the narrow conclusion.'},conclusion:'The cited permission control rejects the stated request.',obligations:['entry','sensitive-operation','path-binding','applicable-controls'].map(kind=>({kind,status:kind==='applicable-controls'?'blocks-attack':'established',reason:'Cited fixture behavior for '+kind,citations:[ref]})),reviewerQuestions:[]},inputEvidence:null,sinkEvidence:null,deploymentAssumptions:[],assessment:'ruled-out',actorKind:'external-attacker',actor:'API caller',initialAccess:'Assumed access',input:'Job request',impact:'Unauthorized job',trace:[{...ref,role:'control'}],controls:[ref],counterEvidence:'Cited permission check rejects unauthorized callers in the fixture.',missingEvidence:[],followUp:[],remediation:{codeFix:'No change for this stated path',interimControl:'Review deployment exposure',residualRisk:'Other callers remain outside this assessment',recovery:'No compromise established',owner:'unknown',approval:'required',validation:'Static fixture',rollback:'Not applicable'},severityChangeConditions:'A caller bypassing the cited filter changes this assessment'})}]});
}
test('saved SQLite graph finds named cross-repository controls, preserves STRIDE, and reuses validated results after restart',async t=>{
 const f=await threatFixture(t), before=JSON.stringify(f.model.aiReview);let calls=0;
 const run=async(model)=>reviewThreatScenarios(f.manifest,model,{sourceRoot:f.root,config,budget:1,runUntilComplete:true,fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}});
 await run(f.model);assert.equal(calls,12);assert.equal(JSON.stringify(f.model.aiReview),before);
 assert.equal(f.model.threatValidation.entries.length,12);assert.ok(f.model.threatValidation.entries.every(e=>e.assessment==='ruled-out'));
 const s=systemModel(f.model);assert.ok(s.threats.filter(t=>t.origin==='analysis').every(t=>t.validation.assessment==='ruled-out' && t.actorIds.length && t.boundaryIds.length));
 assert.ok(s.boundaries.every(b=>b.reviewState!=='accepted'));assert.match(systemPrintReport(f.model),/Ruled out for the cited path/);
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

test('retrieval upgrade reopens an exhausted gap once and retains prior paid attempts',async t=>{
 const f=await threatFixture(t);let calls=0;
 const options={sourceRoot:f.root,config,budget:1,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
   const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;const data=await answer(p).json();
   if(calls===1){const v=JSON.parse(data.content[0].text);v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard'];data.content[0].text=JSON.stringify(v);}
   return Response.json(data);
 }};
 await reviewThreatScenarios(f.manifest,f.model,options);
 const prior=f.model.threatValidation.entries[0].attemptId;
 f.model.threatValidation.entries[0].rounds=3;f.model.threatValidation.retrievalVersion='old';
 await reviewThreatScenarios(f.manifest,f.model,options);
 assert.equal(calls,2);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
 assert.ok(f.model.threatValidation.entries[0].history.some(e=>e.attemptId===prior && e.reason==='retrieval-policy-updated'));
 await reviewThreatScenarios(f.manifest,f.model,options);assert.equal(calls,2);
 assert.equal(f.model.usageLedger.attempts.length,2);
});

test('deployment assumptions do not suppress a cited conditional code concern; missing code still blocks it',async t=>{
 const {validateThreatAssessment}=await import('../src/threat-validation.mjs');
 const r={id:'r',repository:'repo',path:'api.cs',blobSha256:'hash',startLine:1,endLine:5,lines:[{line:1,text:'input'},{line:2,text:'sink'}]};
 const p={records:[r],availableFiles:[],gaps:[]};
 const raw=await answer({records:[{...r,path:'PermissionFilter.cs'}]}).json(),v=JSON.parse(raw.content[0].text);
 v.assessment='static-supported';v.engineering.obligations.forEach(o=>o.status='established');v.trace=[{recordId:'r',startLine:1,endLine:1,role:'input',reason:'request'},{recordId:'r',startLine:2,endLine:2,role:'sink',reason:'operation'}];
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
 assert.ok(p.retrieval.coalescedWindows>0);
 assert.equal(new Set(p.records.flatMap(r=>r.lines.map(l=>r.path+':'+l.line))).size,p.records.reduce((n,r)=>n+r.lines.length,0),'Overlapping windows should not repeat source lines');
});

test('explicit missing controls precede repeated scenario windows under the retrieval limit',async t=>{
 const f=await threatFixture(t), {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const issue={id:'many-seeds',locations:Array.from({length:12},(_,i)=>({repository:`repo${i}`,path:'Api.cs',line:1})),controls:'',explanation:''};
 const packet=await threatInvestigationPacket(f.model,f.manifest,f.root,issue,[{repository:'repo11',path:'PermissionFilter.cs',line:1}],{},['Inspect PermissionFilter and SecondGuard implementation before broad initialization context.']);
 assert.equal(packet.records[0].path,'PermissionFilter.cs');
 assert.ok(packet.records.some(r=>r.path==='SecondGuard.cs'));
 assert.ok(packet.gaps.some(g=>g.reason==='required-source-window-limit'));
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
test('POC completion assesses every returned scenario, retains counterevidence and resumes without calls',async t=>{
 const {assessCompletedPoc}=await import('../src/threat-validation.mjs');
 const f=await threatFixture(t);f.model.aiReview.scope={poc:{id:'fixture'}};
 let calls=0;const options={sourceRoot:f.root,config,fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}};
 assert.equal(await assessCompletedPoc(f.manifest,f.model,options),null);assert.equal(calls,0);
 f.model.aiReview.coverage.pendingBatches=0;f.model.aiReview.coverage.failedBatches=0;
 await assessCompletedPoc(f.manifest,f.model,options);assert.equal(calls,12);assert.equal(f.model.threatValidation.assessmentCounts.ruledOut,12);
 await assessCompletedPoc(f.manifest,f.model,options);assert.equal(calls,12);
});


test('requested initialization survives generic framework context under the byte limit',async t=>{
 const padding='# '+ 'x'.repeat(110)+'\n';
 const files=[['repo0/control.py','ENFORCE_AUTH = True\n'+padding.repeat(200)]];
 for(const name of ['Startup','Program','RootController','ConfigureServices','AddAuthorization','UseAuthentication','UseAuthorization'])files.push([`repo0/${name}.cs`,`class ${name} {\n public void Check() {\n`+('// '+ 'x'.repeat(110)+'\n').repeat(100)+'}\n}\n']);
 const f=await threatFixture(t,files),{threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const p=await threatInvestigationPacket(f.model,f.manifest,f.root,{id:'config-first',locations:[{repository:'repo0',path:'control.py',line:125}],controls:'',explanation:''},[{repository:'repo0',path:'control.py',line:125}],{},['Inspect the environment configuration initialization at the top of control.py.']);
 assert.ok(p.records.some(r=>r.path==='control.py'&&r.startLine===1),'Generic control candidates must not displace the requested declaration');
 assert.ok(p.records.some(r=>r.path==='control.py'&&r.endLine>=125));
 assert.ok(p.retrieval.candidateWindowsOmitted>0);
 assert.equal(p.gaps.filter(g=>g.path==='control.py').length,0);
 assert.ok(Buffer.byteLength(JSON.stringify(p.records))<=42000);
});

test('named control retrieval prioritizes production implementations before matching test helpers',async t=>{
 const extras=Array.from({length:8},(_,i)=>[`repo0/fixture_${i}.py`,'def PermissionFilter():\n    return True\n']);
 const f=await threatFixture(t,extras);
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const {threatIssue}=await import('../src/threat-validation-state.mjs');
 const packet=await threatInvestigationPacket(f.model,f.manifest,f.root,threatIssue(f.model,f.model.aiReview.threats[0]),[],{},['Inspect PermissionFilter']);
 const refs=packet.records.filter(r=>r.basis==='requested-definition' || r.basis==='requested-symbol' || r.basis==='combined hash-matched source windows');
 assert.ok(refs.some(r=>r.repository==='repo11' && r.path==='PermissionFilter.cs'));
 const search=packet.retrieval.controlSearches.find(r=>r.symbol==='PermissionFilter');
 assert.ok(search.requested);
 const first=f.graph.node(f.model.sourceGraph.generation,search.nodeIds[0]);
 assert.equal(first.repository,'repo11');
});

test('control lookup follows interface implementation and a registered requirement across the saved graph',async t=>{
 const {controlContext}=await import('../src/control-context.mjs');
 const {InvestigationSource}=await import('../src/investigation-source.mjs');
 const f=await threatFixture(t,[
   ['repo0/Startup.cs','class Startup { public void ConfigureServices() { options.AddPolicy("CanWrite", p => p.AddRequirements(new OwnershipRequirement())); } }'],
   ['repo11/SolutionAccessService.cs','class SolutionAccessService { public bool CanWrite() { return principal.IsAdmin; } }'],
   ['repo10/OwnershipRequirement.cs','class OwnershipRequirement { public bool Check() { return false; } }'],
 ]);
 const source=new InvestigationSource(f.model,f.manifest,f.root);
 const lookup=await controlContext(source,[{repository:'repo0',path:'Api.cs',line:1}],'[Authorize(Policy = "CanWrite")] ISolutionAccessService');
 assert.ok(lookup.references.some(r=>r.path==='SolutionAccessService.cs'));
 assert.ok(lookup.references.some(r=>r.path==='OwnershipRequirement.cs'));
 assert.ok(lookup.searches.some(s=>s.symbol==='OwnershipRequirement' && s.matches));
 assert.ok(lookup.searches.filter(s=>s.matches===0).every(s=>/do not establish absence/.test(s.interpretation)));
 assert.ok(lookup.references.length<=12);
});

test('follow-up rechecks prior cited controls and cannot clear a path after that control changes',async t=>{
 const f=await threatFixture(t);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:2,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  if(calls===1){
   const data=await answer(p).json(),v=JSON.parse(data.content[0].text);
   v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard'];
   v.followUp=[];
   data.content[0].text=JSON.stringify(v);
   await fs.writeFile(path.join(f.root,'repo11','PermissionFilter.cs'),'class PermissionFilter { public void Check() {} }');
   return Response.json(data);
  }
  assert.ok(p.gaps.some(g=>g.path==='PermissionFilter.cs'),'A changed previously cited control must be a required evidence gap');
  return answer(p,'SecondGuard.cs');
 }});
 assert.equal(calls,2);
 assert.equal(f.model.threatValidation.entries[0].assessment,'needs-context',f.model.threatValidation.entries[0].error);
});

test('engineering obligations require exact evidence, preserve code gaps, and separate reviewer decisions',async()=>{
 const {validateThreatAssessment}=await import('../src/threat-validation.mjs');
 const r={id:'r',repository:'repo',path:'PermissionFilter.cs',blobSha256:'hash',startLine:1,endLine:5,lines:[{line:1,text:'entry'},{line:2,text:'write'}]};
 const p={records:[r],availableFiles:[],gaps:[]};
 const data=await answer(p).json(),v=JSON.parse(data.content[0].text);
 v.assessment='static-supported';v.engineering.obligations.forEach(o=>o.status='established');
 v.inputEvidence={recordId:'r',startLine:1,endLine:1,reason:'entry'};v.sinkEvidence={recordId:'r',startLine:2,endLine:2,reason:'write'};
 v.engineering.conditions=[{id:'access',kind:'network-access',statement:'A non-admin can reach this entry.',scope:'write entry',requiredAnswer:'yes',basis:'deployment-only',citations:[]}];
 v.engineering.reviewerQuestions=[{conditionId:'access',question:'Can a non-admin reach this entry?'}];
 v.deploymentAssumptions=['Non-admin can reach the entry.'];
 assert.equal(validateThreatAssessment(v,p).assessment,'static-supported');
 const invalid=structuredClone(v);invalid.engineering.obligations[0].citations[0].recordId='invented';
 assert.throws(()=>validateThreatAssessment(invalid,p),/engineering: citation/);
 const uncited=structuredClone(v);uncited.engineering.obligations[1].citations=[];
 assert.throws(()=>validateThreatAssessment(uncited,p),/requires source citations/);
 const missing=structuredClone(v);missing.engineering.obligations[2]={kind:'path-binding',status:'missing',reason:'Caller to write binding missing',citations:[]};
 const assessed=validateThreatAssessment(missing,p);
 assert.equal(assessed.assessment,'needs-context');assert.ok(assessed.missingEvidence.includes('Caller to write binding missing'));
 const opposed=structuredClone(v);opposed.engineering.obligations[3].status='blocks-attack';
 assert.throws(()=>validateThreatAssessment(opposed,p),/blocking control contradicts/);
 const redacted=structuredClone(p);redacted.records[0].lines[0].text='[sensitive assignment omitted]';
 assert.equal(validateThreatAssessment(v,redacted).assessment,'needs-context');
});

test('a new engineering contract preserves settled paid conclusions and original discovery',async t=>{
 const f=await threatFixture(t);let calls=0;
 const options={sourceRoot:f.root,config,budget:1,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}};
 await reviewThreatScenarios(f.manifest,f.model,options);
 const before=JSON.stringify(f.model.aiReview),attempt=f.model.threatValidation.entries[0].attemptId;
 f.model.threatValidation.key='previous-contract';f.model.threatValidation.promptHash='previous-prompt';
 await reviewThreatScenarios(f.manifest,f.model,options);
 assert.equal(calls,1);assert.equal(f.model.threatValidation.entries[0].attemptId,attempt);
 assert.equal(f.model.threatValidationHistory.at(-1).promptHash,'previous-prompt');
 assert.equal(JSON.stringify(f.model.aiReview),before);
});

test('bootstrap evidence is retrieved before broad control candidates without rebuilding the graph',async t=>{
 const f=await threatFixture(t,[['repo0/api.py','def change():\n    return store.write()\n'],['repo0/server.py','# imports\n'.repeat(140)+'def create_app():\n    app = FastAPI(dependencies=[Depends(require_admin)])\n    app.include_router(settings_router)\n    return app\n']]);
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const p=await threatInvestigationPacket(f.model,f.manifest,f.root,{id:'python',locations:[{repository:'repo0',path:'api.py',line:1}],controls:'',explanation:'Caller changes data'},[],{});
 const startup=p.records.find(r=>r.path==='server.py');assert.ok(startup);
 assert.ok(startup.lines.some(l=>l.text.includes('dependencies=[Depends(require_admin)]')));
 assert.ok(p.retrieval.frameworkControlSearches.some(s=>s.symbol==='create_app'&&s.matches));
});

test('inconsistent settled-code assessment receives a bounded engineering decision review, not automatic promotion',async t=>{
 const f=await threatFixture(t);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:2,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  const raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
  if(calls===1){v.assessment='needs-context';v.engineering.obligations.forEach(o=>o.status='established');v.missingEvidence=['Which network is used in production?'];v.followUp=[];}
  else {assert.ok(p.decisionChallenge,'A settled-code inconsistency must reach the independent critical reviewer');assert.match(p.decisionReview.task,/Independently check/);assert.deepEqual(p.decisionReview.questionsToResolve,['Which network is used in production?']);}
  raw.content[0].text=JSON.stringify(v);return Response.json(raw);
 }});
 assert.equal(calls,2);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
 assert.equal(f.model.threatValidation.entries[0].history[0].assessment,'needs-context');
 assert.equal(f.model.usageLedger.attempts.length,2);
});

test('STRIDE wire contract has one typed code-completeness decision, separate from deployment questions',async()=>{
 const {THREAT_ASSESSMENT_SCHEMA,validateThreatAssessment}=await import('../src/threat-validation.mjs');
 assert.equal(THREAT_ASSESSMENT_SCHEMA.properties.missingEvidence,undefined);
 assert.ok(!THREAT_ASSESSMENT_SCHEMA.required.includes('missingEvidence'));
 const r={id:'r',repository:'repo',path:'PermissionFilter.cs',blobSha256:'hash',startLine:1,endLine:5,lines:[{line:1,text:'request'},{line:2,text:'write'}]};
 const p={records:[r],availableFiles:[],gaps:[]},raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
 delete v.missingEvidence;v.assessment='static-supported';v.engineering.obligations.forEach(o=>o.status='established');
 v.inputEvidence={recordId:'r',startLine:1,endLine:1,reason:'request'};v.sinkEvidence={recordId:'r',startLine:2,endLine:2,reason:'write'};
 v.deploymentAssumptions=['Direct untrusted access without an upstream administrator restriction.'];
 assert.equal(validateThreatAssessment(v,p).assessment,'static-supported');
 v.engineering.obligations[2]={kind:'path-binding',status:'missing',reason:'The route to handler binding is absent from the supplied source.',citations:[]};
 const incomplete=validateThreatAssessment(v,p);
 assert.equal(incomplete.assessment,'needs-context');assert.deepEqual(incomplete.missingEvidence,[v.engineering.obligations[2].reason]);
});

test('positive engineering claims stay unpublished until a metered critical check, and resume without rediscovery',async t=>{
 const f=await threatFixture(t);let calls=0;
 const options={sourceRoot:f.root,config,budget:1,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  const raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
  if(calls===1){
   v.assessment='static-supported';v.engineering.obligations.forEach(o=>o.status='established');
   v.inputEvidence=v.controls[0];v.sinkEvidence=v.controls[0];
  }else {assert.ok(p.decisionChallenge);assert.match(JSON.parse(request.body).system,/critical engineering reviewer/);}
  raw.content[0].text=JSON.stringify(v);return Response.json(raw);
 }};
 const discovery=JSON.stringify(f.model.aiReview);
 await reviewThreatScenarios(f.manifest,f.model,options);
 const draft=f.model.threatValidation.entries[0];
 assert.equal(draft.assessment,'not-assessed');assert.equal(draft.challengePending,true);
 assert.equal(draft.draftAssessment.assessment,'static-supported');
 assert.equal(systemModel(f.model).threats.find(t=>t.id==='saved-threat-0').outcome.kind,'investigation');
 await reviewThreatScenarios(f.manifest,f.model,options);
 assert.equal(calls,2);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
 assert.equal(f.model.threatValidation.entries[0].challengeCompleted,true);
 assert.equal(JSON.stringify(f.model.aiReview),discovery);
 await reviewThreatScenarios(f.manifest,f.model,options);assert.equal(calls,2);
});

test('a positive result on the last evidence round still receives its bounded critical check',async t=>{
 const f=await threatFixture(t);let calls=0;
 const options={sourceRoot:f.root,config,budget:1,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  const raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
  if(calls===1){v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard'];}
  if(calls===2){v.assessment='static-supported';v.engineering.obligations.forEach(o=>o.status='established');v.inputEvidence=v.controls[0];v.sinkEvidence=v.controls[0];}
  if(calls===3)assert.ok(p.decisionChallenge);
  raw.content[0].text=JSON.stringify(v);return Response.json(raw);
 }};
 await reviewThreatScenarios(f.manifest,f.model,options);
 f.model.threatValidation.entries[0].rounds=2;
 await reviewThreatScenarios(f.manifest,f.model,{...options,budget:2});
 assert.equal(calls,3);assert.equal(f.model.threatValidation.entries[0].rounds,4);
 assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
 assert.equal(f.model.threatValidation.entries[0].challengeCompleted,true);
});

test('feature engineering completes a missing-control round before opening the next case',async t=>{
 const f=await threatFixture(t),order=[];let first=true;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:3,finishCaseFirst:true,threatIds:['saved-threat-0','saved-threat-1'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);order.push(p.candidate.id);const data=await answer(p).json();
  if(first){first=false;const v=JSON.parse(data.content[0].text);v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard'];data.content[0].text=JSON.stringify(v);}
  return Response.json(data);
 }});
 assert.deepEqual(order,['saved-threat-0','saved-threat-0','saved-threat-1']);assert.equal(f.model.threatValidation.callsThisRun,3);
});

test('requested implementation outranks repeated call sites and generic control candidates',async()=>{
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const functionNode={id:'z-definition',kind:'function',name:'_resolve_gap',repository:'service',path:'routes.py',line:500,endLine:520};
 const calls=Array.from({length:12},(_,n)=>({...functionNode,id:'a-call-'+n,kind:'call',line:n*25+1,endLine:n*25+1}));
 const source={search:s=>({items:s==='_resolve_gap'?[...calls,functionNode]:[],next:null}),nodes:()=>[],edges:()=>({items:[]}),file:()=>({}),functionWindow:async ref=>({id:String(ref.line),repository:ref.repository,path:ref.path,blobSha256:'hash',startLine:ref.line,endLine:ref.line+20,lines:Array.from({length:21},(_,n)=>({line:ref.line+n,text:ref.line===500?'def _resolve_gap(): pass':'caller()'}))})};
 const issue={locations:[{repository:'service',path:'routes.py',line:1}],controls:'',explanation:''};
 const packet=await threatInvestigationPacket({interfaces:[],evidence:[]},{},'',issue,[],{},['Read _resolve_gap implementation.'],source);
 const search=packet.retrieval.controlSearches.find(s=>s.symbol==='_resolve_gap');
 assert.equal(search.definitionMatches,1);assert.deepEqual(search.nodeIds,['z-definition']);
 assert.ok(packet.records.some(r=>r.startLine===500&&r.endLine===520));
 assert.ok(packet.records.length<4,'Repeated callers must not crowd out the implementation');
});

test('bulk assessment lookup preserves stale and current decisions without a cross-revision cache',async t=>{
 const {threatAssessmentLookup}=await import('../src/threat-validation-state.mjs');
 const f=await threatFixture(t);
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:1,fetchImpl:async(_,r)=>answer(JSON.parse(JSON.parse(r.body).messages[0].content))});
 let lookup=threatAssessmentLookup(f.model);
 for(const threat of f.model.aiReview.threats)assert.deepEqual(threatAssessment(f.model,threat.id,lookup),threatAssessment(f.model,threat.id));
 f.model.modelRevision='changed';lookup=threatAssessmentLookup(f.model);assert.equal(threatAssessment(f.model,'saved-threat-0',lookup).assessment,'stale');
});

test('new named definitions and router declarations survive a full queue of old follow-up windows',async()=>{
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const source={search:s=>({items:s==='_resolve_gap'?[{id:'helper',kind:'function',name:s,repository:'service',path:'routes.py',line:500,endLine:520}]:s==='APIRouter'?[{id:'router',kind:'call',name:s,repository:'service',path:'routes.py',line:400,endLine:400}]:[],next:null}),nodes:()=>[],edges:()=>({items:[]}),file:()=>({}),functionWindow:async ref=>({id:ref.path+ref.line,repository:ref.repository,path:ref.path,blobSha256:'hash',startLine:ref.line,endLine:ref.line+20,lines:Array.from({length:21},(_,n)=>({line:ref.line+n,text:'verified fixture line'}))})};
 const issue={locations:[{repository:'service',path:'routes.py',line:1}],controls:'',explanation:''};
 const prior=Array.from({length:16},(_,n)=>({repository:'service',path:'prior'+n+'.py',line:1}));
 source.findImplementation=async symbols=>{assert.ok(!symbols.includes('APIRouter'),'Local constructor must not trigger a portfolio-wide router text search');return {references:[]};};
 const packet=await threatInvestigationPacket({interfaces:[],evidence:[]},{},'',issue,prior,{},['Read _resolve_gap and APIRouter implementations.'],source);
 assert.ok(packet.records.some(r=>r.path==='routes.py'&&r.startLine===500));
 assert.ok(packet.records.some(r=>r.path==='routes.py'&&r.startLine===400));
 assert.equal(packet.retrieval.controlSearches.find(s=>s.symbol==='APIRouter').declarationMatches,1);
 assert.ok(packet.gaps.some(g=>g.reason==='required-source-window-limit'));
});

test('composed control evidence accepts up to eight citations and validates every added citation',async t=>{
 const f=await threatFixture(t);const {threatInvestigationPacket,validateThreatAssessment}=await import('../src/threat-validation.mjs');
 const {threatIssue}=await import('../src/threat-validation-state.mjs');
 const packet=await threatInvestigationPacket(f.model,f.manifest,f.root,threatIssue(f.model,f.model.aiReview.threats[0]),[],{});
 const response=await answer(packet).json(),value=JSON.parse(response.content[0].text),control=value.engineering.obligations[3];
 control.citations=Array.from({length:8},()=>({...control.citations[0]}));assert.equal(validateThreatAssessment(value,packet).assessment,'ruled-out');
 control.citations[7].recordId='not-submitted';assert.throws(()=>validateThreatAssessment(value,packet),/citation outside submitted source/);
 control.citations=Array.from({length:9},()=>({...value.controls[0]}));assert.throws(()=>validateThreatAssessment(value,packet),/at most eight citations/);
});

test('unbound text-search candidates cannot turn unrelated files into required code dependencies',async()=>{
 const {threatInvestigationPacket}=await import('../src/threat-validation.mjs');
 const source={search:()=>({items:[],next:null}),nodes:()=>[],edges:()=>({items:[]}),file:()=>({}),findImplementation:async()=>({references:Array.from({length:16},(_,n)=>({repository:'service',path:'unrelated'+n+'.py',line:1,required:true})),limited:true}),functionWindow:async ref=>({id:ref.path,repository:ref.repository,path:ref.path,blobSha256:'hash',startLine:1,endLine:20,lines:Array.from({length:20},(_,n)=>({line:n+1,text:'candidate code'}))})};
 const issue={locations:[{repository:'service',path:'routes.py',line:1}],controls:'',explanation:''};
 const packet=await threatInvestigationPacket({interfaces:[],evidence:[]},{},'',issue,[],{},['Inspect REQUIRE_AUTH.'],source);
 assert.ok(packet.retrieval.candidateWindowsOmitted>0);
 assert.equal(packet.gaps.length,0);
 assert.ok(packet.records.some(r=>r.path==='routes.py'));
 assert.equal(packet.retrieval.indexedSourceSearch.limited,true);
});

test('structured conditions reject unbound settings and inconsistent conclusions without promoting them',async()=>{
 const {validateThreatAssessment}=await import('../src/threat-validation.mjs');
 const {questionPresentation}=await import('../src/reviewer-questions.mjs');
 const r={id:'r',repository:'app',path:'routes.py',blobSha256:'hash',startLine:1,endLine:5,lines:[{line:1,text:'entry'},{line:2,text:'read'}]};
 const p={records:[r],availableFiles:[],gaps:[]};
 const v=JSON.parse((await answer(p,'routes.py').json()).content[0].text);
 v.assessment='static-supported';v.engineering.obligations.forEach(o=>o.status='established');
 v.inputEvidence={recordId:'r',startLine:1,endLine:1,reason:'entry'};v.sinkEvidence={recordId:'r',startLine:2,endLine:2,reason:'read'};
 v.engineering.conditions=[{id:'setting',kind:'configuration',statement:'Authentication is disabled.',scope:'GET /gap',requiredAnswer:'yes',binding:'deployment-only'}];
 assert.throws(()=>validateThreatAssessment(v,p),/configuration condition requires a cited code binding/);
 v.engineering.conditions=[{id:'setting',kind:'configuration',statement:'Authentication is disabled.',scope:'GET /gap',requiredAnswer:'yes',basis:'code-dependent',citations:[]}];
 v.engineering.reviewerQuestions=[{conditionId:'setting',question:'Is authentication disabled?'}];
 assert.throws(()=>validateThreatAssessment(v,p),/code-dependent condition requires binding citations/);
 v.engineering.conditions[0].citations=[{recordId:'r',startLine:6,endLine:6}];
 assert.throws(()=>validateThreatAssessment(v,p),/condition citation outside/);
 v.engineering.conditions=[{id:'network',kind:'network-access',statement:'An ordinary caller can reach GET /gap.',scope:'GET /gap',requiredAnswer:'yes',basis:'deployment-only',citations:[]}];
 v.engineering.reviewerQuestions=[{conditionId:'network',question:'Can an ordinary caller reach this route?'}];
 v.engineering.consistency={status:'unresolved',reason:'The prerequisite contradicts the absence of an attached authentication dependency.'};
 const unresolved=validateThreatAssessment(v,p);assert.equal(unresolved.assessment,'needs-context');assert.match(unresolved.missingEvidence.join(' '),/Reconcile the decision/);
 v.engineering.consistency={status:'consistent',reason:'The route-specific code claim requires only the declared caller access.'};
 const a=validateThreatAssessment(v,p);assert.equal(a.assessment,'static-supported');
 const q=questionPresentation(a.engineering,a.engineering.reviewerQuestions[0]);assert.equal(q.question,a.engineering.conditions[0].statement);
 assert.match(q.ifYes,/Other prerequisites/);assert.match(q.ifNo,/other paths and actors are not cleared/);
 assert.doesNotMatch(q.ifYes,/all routes|confirms exploitation/);
 v.engineering.reviewerQuestions[0].conditionId='invented';assert.throws(()=>validateThreatAssessment(v,p),/question must reference/);
 delete v.engineering.conditions;delete v.engineering.consistency;assert.throws(()=>validateThreatAssessment(v,p),/structured conditions/);
});

test('explicit condition recheck challenges one saved case and retains its prior decision and graph',async t=>{
 const f=await threatFixture(t);let calls=0;
 const options={sourceRoot:f.root,config,budget:1,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}};
 await reviewThreatScenarios(f.manifest,f.model,options);
 const before=structuredClone(f.model.threatValidation),graph=JSON.stringify(f.model.sourceGraph),discovery=JSON.stringify(f.model.aiReview);
 await reviewThreatScenarios(f.manifest,f.model,options);assert.equal(calls,1);
 await reviewThreatScenarios(f.manifest,f.model,{...options,recheckConditions:true});assert.equal(calls,2);
 assert.ok(f.model.threatValidationHistory.some(h=>h.entries.some(e=>e.attemptId===before.entries[0].attemptId&&e.assessment==='ruled-out')));
 assert.equal(f.model.threatValidation.entries[0].engineering.version,2);
 assert.equal(JSON.stringify(f.model.sourceGraph),graph);assert.equal(JSON.stringify(f.model.aiReview),discovery);
 await assert.rejects(()=>reviewThreatScenarios(f.manifest,f.model,{...options,threatIds:undefined,recheckConditions:true}),/exactly one/);
});

test('compact native response retains exact entry, operation and condition-binding validation',async()=>{
 const {validateThreatAssessment,THREAT_ASSESSMENT_SCHEMA}=await import('../src/threat-validation.mjs');
 const record={id:'r',repository:'app',path:'PermissionFilter.cs',blobSha256:'hash',startLine:1,endLine:5,lines:[]};
 const packet={records:[record],availableFiles:[],gaps:[]};
 const canonical=JSON.parse((await answer(packet).json()).content[0].text);
 canonical.engineering.conditions=[{id:'policy',kind:'configuration',statement:'The cited admin restriction is enabled.',scope:'admin route',requiredAnswer:'yes',binding:'applicable-controls'}];
 canonical.engineering.reviewerQuestions=['policy'];
 const wire={assessment:canonical.assessment,caseDetails:{},evidenceReview:{},remediation:canonical.remediation,engineering:canonical.engineering};
 for(const key of Object.keys(THREAT_ASSESSMENT_SCHEMA.properties.caseDetails.properties))wire.caseDetails[key]=canonical[key];
 for(const key of Object.keys(THREAT_ASSESSMENT_SCHEMA.properties.evidenceReview.properties))wire.evidenceReview[key]=canonical[key];
 const validated=validateThreatAssessment(wire,packet);assert.equal(validated.assessment,'ruled-out');assert.equal(validated.engineering.conditions[0].citations[0].repository,'app');
 assert.equal(validated.engineering.reviewerQuestions[0].conditionId,'policy');
 wire.engineering.conditions[0].binding='imaginary';assert.throws(()=>validateThreatAssessment(wire,packet),/condition binding/);
 wire.engineering.conditions[0].binding='entry';wire.engineering.obligations[0].status='missing';assert.throws(()=>validateThreatAssessment(wire,packet),/condition binding/);
});
test('requested member uses retrieve local storage and serialization candidates from the saved graph',async t=>{
 const f=await threatFixture(t,[['repo0/Store.py','class Store:\n    def update(self, session, config):\n        session.config = config\n\n    def serialize(self, item):\n        return item.config\n']]);
 const {InvestigationSource}=await import('../src/investigation-source.mjs');
 const source=new InvestigationSource(f.model,f.manifest,f.root);
 const found=await source.findImplementation(['session.config'],[{repository:'repo0',path:'Store.py',line:2}]);
 assert.ok(found.references.some(r=>r.path==='Store.py'&&r.line===3));assert.ok(found.references.some(r=>r.path==='Store.py'&&r.line===6));
 assert.ok(found.references.every(r=>r.basis.includes('binding unproven')));
 await fs.appendFile(path.join(f.root,'repo0','Store.py'),'# changed\n');
 const changed=await source.findImplementation(['session.config'],[{repository:'repo0',path:'Store.py',line:2}]);
 assert.equal(changed.references.filter(r=>r.path==='Store.py').length,0);assert.ok(changed.failures.length);
});

test('requested source survives a later follow-up that asks for a different binding',async t=>{
 const f=await threatFixture(t,[['repo9/ThirdGuard.cs','class ThirdGuard { public bool Check() { return false; } }']]);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:5,contextRounds:5,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  const raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
  if(calls<3){v.assessment='needs-context';v.missingEvidence=calls===1?['Inspect SecondGuard']:[];if(calls===2)v.followUp=[{repository:'repo11',path:'PermissionFilter.cs',line:1,reason:'Inspect ThirdGuard binding before deciding this path'}];}
  if(calls===3){assert.ok(p.records.some(r=>r.path==='SecondGuard.cs'),'Previously requested source must remain available even when it was not cited');assert.ok(p.records.some(r=>r.path==='ThirdGuard.cs'));}
  raw.content[0].text=JSON.stringify(v);return Response.json(raw);
 }});
 assert.equal(calls,3);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
});

test('a later isolated format failure gets bounded correction despite older failure history',async t=>{
 const f=await threatFixture(t);let calls=0;
 await reviewThreatScenarios(f.manifest,f.model,{sourceRoot:f.root,config,budget:5,contextRounds:5,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{
  const p=JSON.parse(JSON.parse(request.body).messages[0].content);calls++;
  const raw=await answer(p).json(),v=JSON.parse(raw.content[0].text);
  if(calls===1||calls===3)v.trace[0].endLine=100000;
  if(calls===2){v.assessment='needs-context';v.missingEvidence=['Inspect SecondGuard'];}
  if(calls===4){assert.match(p.previousValidationFailure,/citation/);assert.ok(p.records.some(r=>r.path==='SecondGuard.cs'));}
  raw.content[0].text=JSON.stringify(v);return Response.json(raw);
 }});
 assert.equal(calls,4);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');assert.equal(f.model.usageLedger.attempts.length,4);
});

test('section retrieval follows indexed primary calls to base and overriding method candidates',async t=>{
 const code='class Base:\n    def persist(self, value):\n        self.value = value\nclass Disk(Base):\n    def persist(self, value):\n        super().persist(value)\ndef write(request):\n    storage.persist(request.value)\n';
 const f=await threatFixture(t,[['repo0/Store.py',code]]),{InvestigationSource}=await import('../src/investigation-source.mjs');
 const source=new InvestigationSource(f.model,f.manifest,f.root),window=await source.functionWindow({repository:'repo0',path:'Store.py',line:7});
 source.search=()=>({items:[],next:'global-page-limit'}); // Global paging must not hide same-file definitions.
 const result=source.calledImplementations([window]);
 assert.ok(result.searches.some(s=>s.symbol==='persist'));
 assert.ok(result.references.some(r=>r.path==='Store.py'&&r.line===2));
 assert.ok(result.references.some(r=>r.path==='Store.py'&&r.line===5));
 assert.ok(result.references.every(r=>r.required===false));assert.match(result.interpretation,/do not establish/);
 const originalNodes=source.nodes.bind(source);source.nodes=options=>options.kind==='function'&&options.limit===129?Array.from({length:129},(_,n)=>({id:String(n),line:1000+n,endLine:1000+n})):originalNodes(options);
 assert.equal((await source.functionWindow(result.references[0])).functionContext.complete,true,'Exact saved function identity bypasses unrelated file-page limits');
 await fs.appendFile(path.join(f.root,'repo0/Store.py'),'# changed');
 await assert.rejects(()=>source.functionWindow(result.references[0]),/changed|hash|match/);
});

test('retrieval upgrade can repair an exhausted evidence validation failure without resetting settled work',async t=>{
 const f=await threatFixture(t);let calls=0;
 const options={sourceRoot:f.root,config,budget:1,threatIds:['saved-threat-0'],fetchImpl:async(_,request)=>{calls++;return answer(JSON.parse(JSON.parse(request.body).messages[0].content));}};
 await reviewThreatScenarios(f.manifest,f.model,options);
 const e=f.model.threatValidation.entries[0];e.assessment='failed';e.error='Security assessment failed schema or evidence validation';e.rounds=5;f.model.threatValidation.retrievalVersion='old';
 await reviewThreatScenarios(f.manifest,f.model,options);assert.equal(calls,2);assert.equal(f.model.threatValidation.entries[0].assessment,'ruled-out');
 await reviewThreatScenarios(f.manifest,f.model,options);assert.equal(calls,2);
});
