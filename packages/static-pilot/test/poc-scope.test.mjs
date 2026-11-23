import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {analyze} from '../src/engine.mjs';
import {resolvePocScope,pocReviewPlan} from '../src/poc-scope.mjs';
import {controlSymbols,controlContext} from '../src/control-context.mjs';
import {verifiedStrideSource,prepareStrideEvidence} from '../src/stride-evidence.mjs';
import {enrichGraphModel} from '../src/graph-review.mjs';
import {modelConfig} from '../src/model-review.mjs';
import {systemPrintReport} from '../src/system-exports.mjs';
import {workspaceStore} from '../src/workspace-store.mjs';
import {serve} from '../src/server.mjs';
async function fixture(t) {
 const dir=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'poc-')));t.after(()=>fs.rm(dir,{recursive:true,force:true}));const root=path.join(dir,'sources');
 await fs.mkdir(path.join(root,'app','Controllers'),{recursive:true});await fs.mkdir(path.join(root,'support'));
 await fs.writeFile(path.join(root,'app','Controllers','EmailController.cs'),'class EmailController : RootController {\n[HttpPost("/email")]\npublic void Write() { service.Save(); }\n}');
 await fs.writeFile(path.join(root,'app','Controllers','OtherController.cs'),'class OtherController {\n[HttpGet("/other")]\npublic void Read() {}\n}');
 await fs.writeFile(path.join(root,'app','Startup.cs'),'class Startup { void ConfigureServices() { services.AddAuthorization(); } }');
 await fs.writeFile(path.join(root,'support','RootController.cs'),'[Authorize]\nclass RootController { public bool IsAdmin() { return false; } }');
 const manifest={title:'POC fixture',profile:'test',repositories:[{name:'app'},{name:'support'}]};
 const model=await analyze(manifest,{sourceRoot:root});
 model.pocScope={title:'Email external surface',profile:'on-prem assumption',operations:[{repository:'app',pathContains:'EmailController.cs'}]};
 return {root,manifest,model};
}
test('POC selects explicit operations, retains shared evidence, rejects empty and over-broad scope',async t=>{
 const {model,root,manifest}=await fixture(t), before=JSON.stringify(model.sourceGraph);
 const selected=resolvePocScope(model);assert.ok(selected.interfaceIds.length);
 assert.throws(()=>resolvePocScope(model,{...model.pocScope,operations:[{repository:'app',pathContains:'absent.cs'}]}),/No inbound/);
 assert.throws(()=>resolvePocScope(model,{...model.pocScope,maxInterfaces:0}),/1–48/);
 const plan=pocReviewPlan(model);assert.ok(plan.batches.length<=12);assert.ok(plan.scope.deferredInterfaces>0);
 const primary=new Set(plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds));assert.deepEqual([...primary].sort(),selected.interfaceIds);
 const appearances=plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds);
 assert.equal(appearances.length,primary.size,'Incident flows must not repeat primary operation reviews');
 assert.equal(JSON.stringify(model.sourceGraph),before);
 const source=await verifiedStrideSource(model,manifest,root);
 const packet=await prepareStrideEvidence(plan.batches[0].packet,source);
 assert.ok(packet.packet.sourceContext.records.some(r=>r.path==='Startup.cs'));
 assert.ok(packet.packet.sourceContext.records.some(r=>r.path==='RootController.cs'));
 assert.match(JSON.stringify(packet.packet.sourceContext.controlLookup),/not verified enforcement/);
});
test('authorization lookup recognizes single-word attributes and startup and does not claim search misses prove absence',async()=>{
 assert.ok(controlSymbols('Verify [Authorize] and Startup global filters.').includes('Authorize'));
 assert.ok(controlSymbols('Verify [Authorize] and Startup global filters.').includes('Startup'));
 let calls=0;const source={search:()=>{calls++;return {items:[],next:null};}};
 const a=await controlContext(source,[],'[Authorize]');await controlContext(source,[],'[Authorize]');
 assert.equal(calls,a.searches.length);assert.match(a.basis,/not verified/);
});
test('POC saved scope resumes without requests and preserves full-system paid review',async t=>{
 const {model,root,manifest}=await fixture(t);
 const full={reviewScope:'system',runKey:'prior',status:'completed',threats:[],batches:[],scope:{version:'old'}};model.aiReview=structuredClone(full);
 const config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'});let calls=0;
 const fetchImpl=async()=>{calls++;return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify({summary:'All six categories assessed for fixture only.',threats:[],connections:[],questions:[]})}],usage:{input_tokens:2,output_tokens:2}});};
 await enrichGraphModel(model,config,new Map(),fetchImpl,{reviewScope:'poc',runUntilComplete:true});
 assert.deepEqual(model.savedStrideScopes.system,full);assert.equal(model.aiReview.coverage.pendingBatches,0);assert.equal(model.aiReview.coverage.failedBatches,0,JSON.stringify(model.aiReview.batches));
 const count=calls;await enrichGraphModel(model,config,new Map(),fetchImpl,{reviewScope:'poc',runUntilComplete:true});assert.equal(calls,count);
 const store=await workspaceStore(root,path.join(root,'..','state'));await store.save({model,manifest});await store.close();
 const html=systemPrintReport(model);assert.match(html,/Scoped POC/);assert.match(html,/on-prem assumption/);assert.match(html,/STRIDE category obligations/);
});
test('POC scope API saves on the existing graph and refuses unknown selections',async t=>{
 const f=await fixture(t), dir=path.join(f.root,'..','state'),store=await workspaceStore(f.root,dir);await store.save({model:f.model,manifest:f.manifest});await store.close();
 const app=await serve({sourceRoot:f.root,workspace:dir,port:0,quiet:true,persist:true});t.after(()=>app.close());
 const base=app.url.split('/#')[0],headers={'X-Synthesis-Token':app.token,'Content-Type':'application/json'};
 const r=await fetch(base+'/api/poc-scope',{method:'POST',headers,body:JSON.stringify({modelRevision:f.model.modelRevision,scope:f.model.pocScope})});
 assert.equal(r.status,200,await r.clone().text());const m=await r.json();assert.equal(m.sourceGraph.fingerprint,f.model.sourceGraph.fingerprint);
 const preview=await fetch(base+'/api/system-review-plan?scope=poc',{headers});assert.equal(preview.status,200);assert.ok((await preview.json()).scope.poc);
});
test('scope changes create separate saved review identities and unmatched scopes never broaden',async t=>{
 const {model}=await fixture(t),first=resolvePocScope(model);
 const second=resolvePocScope(model,{...model.pocScope,operations:[{repository:'app',pathContains:'OtherController.cs'}]});
 assert.notEqual(first.id,second.id);assert.ok(first.interfaceIds.every(i=>!second.interfaceIds.includes(i)));
 assert.throws(()=>resolvePocScope(model,{...model.pocScope,operations:[{repository:'unknown',pathContains:'.cs'}]}),/Repository not in/);
 assert.throws(()=>resolvePocScope(model,{...model.pocScope,maxInterfaces:1,operations:[{repository:'app',pathContains:'Controller.cs'}]}),/exceeding/);
});
