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
import { systemModel } from '../src/system-model.mjs';
import { systemPrintReport } from '../src/system-exports.mjs';
import { workspaceStore } from '../src/workspace-store.mjs';
import { serve } from '../src/server.mjs';
const config = modelConfig('anthropic-gateway','claude-opus-4-6-1',{ CLAUDE_API_KEY: 'test-only' },{baseUrl:'https://gateway.example/anthropic'});
export async function threatFixture(t) {
 const dir=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'threat-validation-'))), root=path.join(dir,'source');
 const manifest={title:'Twelve-service static review',profile:'fixture',repositories:Array.from({length:12},(_,i)=>({name:`repo${i}`}))};
 for(let i=0;i<12;i++) {await fs.mkdir(path.join(root,`repo${i}`),{recursive:true});await fs.writeFile(path.join(root,`repo${i}`,'Api.cs'),`class Api { [HttpPost("/jobs${i}")] public void Create() { PermissionFilter.Check(); } }`);}
 await fs.writeFile(path.join(root,'repo11','PermissionFilter.cs'),'class PermissionFilter { public void Check() { if (!principal.IsAdmin) throw new UnauthorizedAccessException(); } }');
 await fs.writeFile(path.join(root,'repo10','SecondGuard.cs'),'class SecondGuard { public bool Check() { return false; } }');
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
 return Response.json({stop_reason:'end_turn',usage:{input_tokens:100,output_tokens:20},content:[{type:'text',text:JSON.stringify({assessment:'ruled-out',actorKind:'external-attacker',actor:'API caller',initialAccess:'Assumed access',input:'Job request',impact:'Unauthorized job',trace:[{...ref,role:'control'}],controls:[ref],counterEvidence:'Cited permission check rejects unauthorized callers in the fixture.',missingEvidence:[],followUp:[],remediation:{codeFix:'No change for this stated path',interimControl:'Review deployment exposure',residualRisk:'Other callers remain outside this assessment',recovery:'No compromise established',owner:'unknown',approval:'required',validation:'Static fixture',rollback:'Not applicable'},severityChangeConditions:'A caller bypassing the cited filter changes this assessment'})}]});
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
