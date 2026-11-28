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
import {systemModel} from '../src/system-model.mjs';
import {diagramModel} from '../src/diagram-model.mjs';
async function fixture(t) {
 const cleanup=[];
 const dir=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'poc-')));t.after(async()=>{for(const close of cleanup.reverse())await close();await fs.rm(dir,{recursive:true,force:true});});const root=path.join(dir,'sources');
 await fs.mkdir(path.join(root,'app','Controllers'),{recursive:true});await fs.mkdir(path.join(root,'support'));
 await fs.writeFile(path.join(root,'app','Controllers','EmailController.cs'),'class EmailController : RootController {\n[HttpPost("/email")]\npublic void Write() { service.Save(); }\n}');
 await fs.writeFile(path.join(root,'app','Controllers','OtherController.cs'),'class OtherController {\n[HttpGet("/other")]\npublic void Read() {}\n}');
 await fs.writeFile(path.join(root,'app','Startup.cs'),'class Startup { void ConfigureServices() { services.AddAuthorization(); } }');
 await fs.writeFile(path.join(root,'support','RootController.cs'),'[Authorize]\nclass RootController { public bool IsAdmin() { return false; } }');
 const manifest={title:'POC fixture',profile:'test',repositories:[{name:'app'},{name:'support'}]};
 const model=await analyze(manifest,{sourceRoot:root});
 model.pocScope={title:'Email external surface',profile:'on-prem assumption',operations:[{repository:'app',pathContains:'EmailController.cs'}]};
 return {root,manifest,model,cleanup};
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
 const system=systemModel(model), d=diagramModel(system,{interfaceIds:selected.interfaceIds,showUnresolved:true});
 const allowed=new Set(system.flows.filter(f=>f.interfaceIds.some(id=>primary.has(id))).map(f=>f.id));
 assert.ok(d.connections.length);
 assert.ok(d.connections.every(c=>c.flowIds.every(id=>allowed.has(id))),'POC diagram must not show unrelated flows');
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
 const html=systemPrintReport(model);assert.match(html,/Scoped POC/);assert.match(html,/on-prem assumption/);assert.match(html,/STRIDE category review cases/);
});
test('POC scope API saves on the existing graph and refuses unknown selections',async t=>{
 const f=await fixture(t), dir=path.join(f.root,'..','state'),store=await workspaceStore(f.root,dir);await store.save({model:f.model,manifest:f.manifest});await store.close();
 const app=await serve({sourceRoot:f.root,workspace:dir,port:0,quiet:true,persist:true});f.cleanup.push(()=>app.close());
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
 model.pocScope={...model.pocScope,operations:[{repository:'app',pathContains:'Controller.cs'}]};
 const plan=pocReviewPlan(model);
 assert.equal(plan.scope.poc.operationGroups,2);
 assert.equal(plan.batches.length,2,'Distinct operation definitions retain separate review allowances');
});

test('control lookup follows private helpers and acronym-prefixed response types',async()=>{
 const names=['_settings_to_model','_tier_to_out','LLMSettingsResponse','XMLReader','API_KEYS'];
 const found=controlSymbols('Inspect '+names.join(' and '));
 for(const name of names)assert.ok(found.includes(name),name);
 assert.ok(!controlSymbols('Inspect ordinary words for missing evidence').includes('Inspect'));
 const source={search:s=>({items:names.includes(s)?[{id:s,kind:'function',name:s,repository:'service',path:s+'.py',line:10}]:[],next:null})};
 const result=await controlContext(source,[{repository:'service',path:'routes.py'}],names.join(' '));
 for(const name of names)assert.ok(result.references.some(r=>r.path===name+'.py'),name);
});

test('Python control context includes application composition and prefers production startup over fixtures',async()=>{
 const source={search:s=>({items:s==='create_app'?[{id:'test',kind:'function',name:s,repository:'app',path:'tests/app.py',line:1},{id:'real',kind:'function',name:s,repository:'app',path:'api/server.py',line:170}]:[],next:null})};
 const result=await controlContext(source,[{repository:'app',path:'api/routes.py'}],'verify_admin_key');
 assert.ok(result.searches.some(s=>s.symbol==='create_app'));
 assert.equal(result.references[0].path,'api/server.py');
});

test('Python control context retrieves local router dependency declarations before imports or unrelated routers',async()=>{
 const source={search:(s,after)=>({items:s!=='APIRouter'?[]:after?[{kind:'call',name:s,repository:'app',path:'api/routes.py',line:1136}]:[{kind:'interface',name:'Static import-binding APIRouter',repository:'app',path:'api/routes.py',line:41},{kind:'call',name:s,repository:'other',path:'routes.py',line:12}],next:s==='APIRouter'&&!after?'page2':null})};
 const result=await controlContext(source,[{repository:'app',path:'api/routes.py',line:1175}]);
 assert.deepEqual(result.references,[{repository:'app',path:'api/routes.py',line:1136,basis:'application-registration-candidate'}]);
 assert.equal(result.searches.find(s=>s.symbol==='APIRouter').truncated,false);
});

import {validateRepositoryReview,REPOSITORY_CATEGORIES,repositoryAssessmentSummary} from '../src/repository-assessment.mjs';
function categoryResponse(packet){return {summary:'Static category assessment of supplied source.',threats:[],connections:[],questions:[],explorationRequests:[],categoryReviews:REPOSITORY_CATEGORIES.map(category=>({category,status:'no-scenario-identified',interfaceIds:packet.reviewUnit.primaryInterfaceIds,rationale:'The supplied code was reviewed for this category; no scenario was identified in this bounded evidence.',citations:packet.sourceContext.records.map(r=>({recordId:r.id,line:r.startLine,endLine:r.endLine,role:'context'})),threatIndexes:[],missingEvidence:[],deploymentConditions:['Deployed exposure is not verified.'],remediation:''}))};}
test('repository scope has no operation cutoff, retains internal surfaces and keeps supporting source available',async t=>{
 const f=await fixture(t);f.model.pocScope={kind:'repositories',title:'Primary application',profile:'Static declared configuration',repositories:['app']};
 const selected=resolvePocScope(f.model),plan=pocReviewPlan(f.model);
 assert.deepEqual(selected.repositories,['app']);assert.deepEqual(selected.supportingRepositories,['support']);
 assert.ok(selected.interfaceIds.includes(f.model.interfaces.find(i=>i.operation.includes('/other')).id));
 assert.ok(selected.interfaceIds.length>1);assert.ok(plan.scope.repositoryInventory.files.some(f=>f.path==='Startup.cs'));
 const covered=new Set(plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds));assert.deepEqual([...covered].sort(),selected.interfaceIds);
 assert.throws(()=>resolvePocScope(f.model,{...f.model.pocScope,repositories:['missing']}),/not in saved graph/);
 assert.throws(()=>resolvePocScope(f.model,{...f.model.pocScope,repositories:['app','app']}),/unique/);
 const source=await verifiedStrideSource(f.model,f.manifest,f.root);
 const first=await prepareStrideEvidence(plan.batches.find(b=>b.packet.records.some(r=>r.operation.includes('/email'))).packet,source);
 assert.ok(first.packet.sourceContext.records.some(r=>r.repository==='support'));
});
test('repository category contract rejects missing categories, invented source and false negative claims',async t=>{
 const f=await fixture(t);f.model.pocScope={kind:'repositories',title:'Primary application',profile:'Static',repositories:['app']};
 const source=await verifiedStrideSource(f.model,f.manifest,f.root),{packet}=await prepareStrideEvidence(pocReviewPlan(f.model).batches[0].packet,source);
 const value=categoryResponse(packet);assert.equal(validateRepositoryReview(value,packet).categoryReviews.length,6);
 const absent=structuredClone(value);absent.categoryReviews.pop();assert.throws(()=>validateRepositoryReview(absent,packet),/six STRIDE/);
 const fabricated=structuredClone(value);fabricated.categoryReviews[0].citations[0].recordId='invented';assert.throws(()=>validateRepositoryReview(fabricated,packet),/unavailable source/);
 const outside=structuredClone(value);outside.categoryReviews[0].citations[0].endLine=999999;assert.throws(()=>validateRepositoryReview(outside,packet),/unavailable source/);
 const ruled=structuredClone(value);ruled.categoryReviews[0].status='ruled-out';assert.equal(validateRepositoryReview(ruled,packet).categoryReviews[0].status,'evidence-gap');
 const condition=structuredClone(value);condition.categoryReviews[0].status='supported-conditional';assert.equal(validateRepositoryReview(condition,packet).categoryReviews[0].status,'evidence-gap');
 const incomplete=structuredClone(value);incomplete.categoryReviews[0].citations=[];
 assert.equal(validateRepositoryReview(incomplete,packet).categoryReviews[0].status,'evidence-gap');
 const gapPacket=structuredClone(packet);gapPacket.sourceContext.gaps.push({reason:'missing-custom-guard'});
 assert.ok(validateRepositoryReview(value,gapPacket).categoryReviews.every(c=>c.status==='evidence-gap'));
});
test('repository review persists six-category outcomes, reuses completed requests and reports uncovered files',async t=>{
 const f=await fixture(t);f.model.pocScope={kind:'repositories',title:'Primary application',profile:'Static',repositories:['app']};
 const source=await verifiedStrideSource(f.model,f.manifest,f.root),config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'});let calls=0;
 const fetchImpl=async(url,options)=>{calls++;const req=JSON.parse(options.body),packet=JSON.parse(req.messages[0].content);return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(categoryResponse(packet))}],usage:{input_tokens:7,output_tokens:9}});};
 const options={reviewScope:'poc',runUntilComplete:true,concurrency:2,prepareBatch:b=>prepareStrideEvidence(b.packet,source)};
 await enrichGraphModel(f.model,config,new Map(),fetchImpl,options);
 assert.equal(f.model.aiReview.coverage.failedBatches,0,JSON.stringify(f.model.aiReview.batches.map(b=>b.error)));assert.equal(f.model.aiReview.coverage.pendingBatches,0);
 assert.ok(f.model.aiReview.batches.every(b=>b.review.categoryReviews.length===6));
 const prior=calls;await enrichGraphModel(f.model,config,new Map(),fetchImpl,options);assert.equal(calls,prior);
 const summary=repositoryAssessmentSummary(f.model.aiReview);assert.equal(summary.rows.length,6);assert.ok(summary.inventory.files.length);const withGap=structuredClone(f.model.aiReview);withGap.scope.repositoryInventory.gaps.push({repository:'app',path:'unmapped.txt',reason:'no-security-surface-mapping'});assert.equal(repositoryAssessmentSummary(withGap).complete,false,'Unmapped files are not cleared by completed requests');
 const system=systemModel(f.model);assert.equal(system.repositoryAssessment.rows.length,6);
 const report=systemPrintReport(f.model);for(const c of REPOSITORY_CATEGORIES)assert.ok(report.includes(c));assert.match(report,/Selected repository assessment/);assert.match(report,/Primary repositories: app/);assert.match(report,/Supporting repositories: support/);assert.doesNotMatch(report,/deferred to deep code review/);
 const dir=path.join(f.root,'..','state'),store=await workspaceStore(f.root,dir);await store.save({model:f.model,manifest:f.manifest});await store.close();
 const app=await serve({sourceRoot:f.root,workspace:dir,port:0,quiet:true,persist:true});f.cleanup.push(()=>app.close());
 const response=await fetch(app.url.split('/#')[0]+'/api/model',{headers:{'X-Synthesis-Token':app.token}});const restored=await response.json();assert.notEqual(restored.aiReview.status,'stale','Repository prompt provenance survives restart');
});
test('each STRIDE category retains a conditional source conclusion and rejects contradictory absence',async t=>{
 const f=await fixture(t);f.model.pocScope={kind:'repositories',title:'Primary application',profile:'Static',repositories:['app']};
 const source=await verifiedStrideSource(f.model,f.manifest,f.root),{packet}=await prepareStrideEvidence(pocReviewPlan(f.model).batches.find(b=>b.packet.records.some(r=>r.operation.includes('/email'))).packet,source);
 const record=packet.records.find(r=>packet.reviewUnit.primaryInterfaceIds.includes(r.id));
 for(const category of REPOSITORY_CATEGORIES){
  const value=categoryResponse(packet);value.threats=[{title:'Synthetic conditional scenario for '+category,category,actor:'Untrusted caller',startingAccess:'Reachable fixture entry',asset:'Fixture data',scenario:'Conditional misuse of the supplied operation.',prerequisites:'Caller can reach the fixture.',controls:'Fixture controls require review.',mitigation:'Enforce the relevant control.',interfaceIds:[record.id],evidenceIds:record.evidence.map(e=>e.id),analysis:{attackSteps:['Caller supplies input to the operation.'],impact:'Fixture asset affected.',assumptions:['Static fixture only.'],controlEvidenceIds:[],boundaryIds:[],mappings:[]}}];
  const c=value.categoryReviews.find(c=>c.category===category);c.status='supported-conditional';c.threatIndexes=[0];c.remediation='Enforce the relevant control.';
  c.citations.push({...c.citations[0],role:'input'},{...c.citations[0],role:'operation'});
  const result=validateRepositoryReview(value,packet);assert.equal(result.categoryReviews.find(c=>c.category===category).status,'supported-conditional');
  c.status='no-scenario-identified';assert.equal(validateRepositoryReview(value,packet).categoryReviews.find(c=>c.category===category).status,'evidence-gap');
  c.status='ruled-out';c.citations.push({...c.citations[0],role:'counterevidence'});assert.equal(validateRepositoryReview(value,packet).categoryReviews.find(c=>c.category===category).status,'ruled-out');
 }
});
test('repository scope keeps more than twelve units and includes definitions with no routes',async t=>{
 const f=await fixture(t);
 for(let n=0;n<20;n++)await fs.writeFile(path.join(f.root,'app',`helper${n}.py`),`def transform_${n}(value):\n    return value.strip()\n`);
 const model=await analyze(f.manifest,{sourceRoot:f.root});model.pocScope={kind:'repositories',title:'Whole selected repo',profile:'Static',repositories:['app']};
 const plan=pocReviewPlan(model);assert.ok(plan.batches.length>12);
 const expected=model.interfaces.filter(i=>i.repository==='app'&&i.connection?.role==='symbol').map(i=>i.id);
 const planned=new Set(plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds));assert.ok(expected.length>=20);assert.ok(expected.every(id=>planned.has(id)));
});
import {failureDetail} from '../src/diagnostics.mjs';
import {REPOSITORY_SCHEMA} from '../src/repository-assessment.mjs';
import {boundStrideSchema} from '../src/model-review.mjs';
test('repository native schema is reusable and failed category validation triggers the invalid-response guard classification',()=>{
 const packet={reviewFocus:{repositoryAssessment:true}};
 assert.equal(boundStrideSchema(REPOSITORY_SCHEMA,packet),REPOSITORY_SCHEMA);
 assert.equal(REPOSITORY_SCHEMA.properties.connections,undefined);
 try{validateRepositoryReview({},packet);assert.fail('Must reject invalid response');}catch(error){assert.equal(failureDetail(error.message).code,'evidence-validation');}
});
test('repository matrix distinguishes untouched, partially assessed and reviewed-with-gaps',async t=>{
 const f=await fixture(t);f.model.pocScope={kind:'repositories',title:'Selected app',profile:'Static',repositories:['app']};
 const config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'}),source=await verifiedStrideSource(f.model,f.manifest,f.root);
 const fetchImpl=async(url,options)=>{const packet=JSON.parse(JSON.parse(options.body).messages[0].content),response=categoryResponse(packet);response.categoryReviews.forEach(c=>{c.status='evidence-gap';c.missingEvidence=['Named downstream binding is not supplied.'];});return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(response)}],usage:{input_tokens:2,output_tokens:2}});};
 await enrichGraphModel(f.model,config,new Map(),fetchImpl,{reviewScope:'poc',runUntilComplete:true,prepareBatch:b=>prepareStrideEvidence(b.packet,source)});
 assert.equal(systemModel(f.model).analysisStatus.state,'reviewed-with-gaps');
 assert.ok(systemModel(f.model).matrix.flatMap(r=>r.cells).some(c=>c.analysisStatus==='evidence-gap'));
 f.model.aiReview.batches=[];f.model.aiReview.coverage={...f.model.aiReview.coverage,completedBatches:0};
 const cells=systemModel(f.model).matrix.flatMap(r=>r.cells);assert.ok(cells.some(c=>c.analysisStatus==='not-analyzed'));assert.ok(cells.every(c=>c.analysisStatus!=='partially-analyzed'));
});
test('an isolated repository packet failure does not suppress later internal review stages',async t=>{
 const f=await fixture(t);f.model.pocScope={kind:'repositories',title:'Primary app',profile:'Static',repositories:['app']};
 const plan=pocReviewPlan(f.model);assert.ok(plan.batches.length>1);plan.batches.forEach((b,n)=>{b.reviewStage=n?2:1;});
 const first=new Set(plan.batches[0].packet.reviewUnit.primaryInterfaceIds),source=await verifiedStrideSource(f.model,f.manifest,f.root);
 const fetchImpl=async(url,options)=>{const packet=JSON.parse(JSON.parse(options.body).messages[0].content),response=categoryResponse(packet);if(packet.reviewUnit.primaryInterfaceIds.some(id=>first.has(id)))response.categoryReviews[0].citations[0].recordId='unknown';return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(response)}],usage:{input_tokens:2,output_tokens:2}});};
 await enrichGraphModel(f.model,modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'}),new Map(),fetchImpl,{plan,reviewScope:'poc',runUntilComplete:true,concurrency:1,recoveryDelayMs:0,prepareBatch:b=>prepareStrideEvidence(b.packet,source)});
 assert.equal(f.model.aiReview.coverage.failedBatches,1);assert.equal(f.model.aiReview.coverage.pendingBatches,0);assert.ok(f.model.aiReview.batches.some(b=>b.reviewStage===2&&b.status==='completed'));
});
import {citationCoversEvidence,resolveSourceCitation} from '../src/source-citation.mjs';
test('body citations cover only their hash-matched parsed owner, not neighboring handlers',()=>{
 const record={repository:'service',path:'routes.py',blobSha256:'hash',startLine:10,endLine:30,functionContext:{startLine:10,endLine:30,complete:true}};
 const body={line:15,endLine:20},anchor={repository:'service',path:'routes.py',blobSha256:'hash',line:10};
 assert.equal(citationCoversEvidence(body,record,anchor),true);
 assert.equal(citationCoversEvidence(body,record,{...anchor,line:35}),false);
 assert.equal(citationCoversEvidence(body,record,{...anchor,blobSha256:'changed'}),false);
 assert.equal(citationCoversEvidence(body,{...record,functionContext:{...record.functionContext,complete:false}},anchor),false);
 assert.equal(citationCoversEvidence({line:10,endLine:12},record,anchor),true);
});

test('citations spanning supplied windows preserve every line and reject gaps or changed hashes',()=>{
 const a={id:'a',repository:'r',path:'code.py',blobSha256:'hash',startLine:148,endLine:227};
 const b={...a,id:'b',startLine:219,endLine:298};
 const cite={recordId:'a',line:176,endLine:236,role:'input'};
 assert.deepEqual(resolveSourceCitation(cite,new Map([['a',a],['b',b]])),[{...cite,endLine:227},{...cite,recordId:'b',line:228}]);
 for(const other of [{...b,startLine:229},{...b,blobSha256:'changed'},{...b,path:'other.py'},{...b,repository:'other'}])
  assert.equal(resolveSourceCitation(cite,new Map([['a',a],['b',other]])),null);
 assert.equal(resolveSourceCitation({...cite,recordId:'invented'},new Map([['a',a],['b',b]])),null);
 assert.equal(resolveSourceCitation({...cite,endLine:299},new Map([['a',a],['b',b]])),null);
});

import {reviewFeatureCohorts} from '../src/feature-review-run.mjs';
import {featureReviewSummary} from '../src/feature-review.mjs';
import {recordDeploymentAnswer,deploymentDecisionQuestions} from '../src/reviewer-questions.mjs';
import {threatValidationKey,threatIssue} from '../src/threat-validation-state.mjs';
import {sha} from '../src/sources.mjs';
import {InvestigationSource} from '../src/investigation-source.mjs';

test('security features retain all six categories and supporting definitions without changing all-subject scope',async t=>{
 const f=await fixture(t),definition={kind:'repositories',title:'Feature review',profile:'Private ingress assumption',repositories:['app']};
 const all=resolvePocScope(f.model,definition),features=resolvePocScope(f.model,{...definition,reviewDepth:'security-features'});
 assert.ok(features.interfaceIds.length>0);assert.ok(features.interfaceIds.length<all.interfaceIds.length);
 assert.notEqual(features.id,all.id);assert.deepEqual(features.supportingRepositories,['support']);assert.ok(features.contextOnlySubjects>0);
 f.model.pocScope=features;const plan=pocReviewPlan(f.model);
 assert.deepEqual([...new Set(plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds))].sort(),features.interfaceIds);
 assert.ok(plan.batches.every(b=>b.packet.reviewFocus.categories.length===6));
 assert.throws(()=>resolvePocScope(f.model,{...definition,reviewDepth:'invented'}),/depth/);
});

test('feature cohort budgets include discovery and resume without rebuilding or duplicate paid calls',async t=>{
 const f=await fixture(t);f.model.pocScope=resolvePocScope(f.model,{kind:'repositories',title:'Features',profile:'Static',repositories:['app'],reviewDepth:'security-features'});
 const graphBefore=JSON.stringify(f.model.sourceGraph),source=await verifiedStrideSource(f.model,f.manifest,f.root);
 const config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'});let calls=0;
 const send=async(_,request)=>{calls++;const packet=JSON.parse(JSON.parse(request.body).messages[0].content);return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(categoryResponse(packet))}],usage:{input_tokens:2,output_tokens:2}});};
 const options={maxBatches:1,concurrency:1,sourceRoot:f.root,prepareBatch:b=>prepareStrideEvidence(b.packet,source)};
 await reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,options);
 assert.equal(calls,1);assert.equal(f.model.featureReviewRun.calls,1);assert.equal(f.model.featureReviewRun.stopReason,'request-budget');
 const partialSystem=systemModel(f.model),partialHtml=systemPrintReport(f.model);
 const featureSection=partialHtml.split('<h2>Feature decisions across STRIDE</h2>')[1].split('<h2>')[0];
 const reviewedFeatures=partialSystem.featureReview.features.filter(g=>g.categories.some(c=>c.decided||c.incomplete));
 assert.equal((featureSection.match(/<tr>/g)||[]).length,1+Math.min(20,reviewedFeatures.length));
 assert.match(featureSection,/Omitted groups are not cleared/);
 assert.match(partialHtml,/wholly unreviewed component rows are omitted/);
 await reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,{...options,runUntilComplete:true});
 assert.equal(f.model.aiReview.coverage.pendingBatches,0);assert.equal(f.model.aiReview.coverage.failedBatches,0);
 const done=calls;await reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,{...options,runUntilComplete:true});assert.equal(calls,done);
 assert.equal(JSON.stringify(f.model.sourceGraph),graphBefore);
 const s=systemModel(f.model);assert.ok(s.featureReview.features.length);assert.ok(s.featureReview.features.every(g=>g.categories.length===6));
 assert.match(systemPrintReport(f.model),/Feature decisions across STRIDE/);
});

test('feature coverage cannot clear a category with an unresolved scenario or stale source',async t=>{
 const f=await fixture(t),iface=f.model.interfaces.find(i=>i.direction==='inbound');
 f.model.aiReview={status:'partial',basedOnRevision:f.model.modelRevision,scope:{interfaceIds:[iface.id]},batches:[{status:'completed',review:{categoryReviews:REPOSITORY_CATEGORIES.map(category=>({category,status:'no-scenario-identified',interfaceIds:[iface.id]}))}}]};
 const system={components:[],threats:[{id:'x',origin:'analysis',interfaceIds:[iface.id],categories:['Tampering'],outcome:{kind:'investigation'}}]};
 let summary=featureReviewSummary(f.model,system);assert.equal(summary.features[0].categories[1].state,'incomplete code');assert.equal(summary.complete,false);
 assert.equal(summary.features[0].categories[0].state,'decision available');
 f.model.aiReview.status='stale';summary=featureReviewSummary(f.model,system);assert.ok(summary.features[0].categories.every(c=>c.state==='stale'));assert.equal(summary.complete,false);
});

test('deployment questions preserve code outcome and invalidate answers when question or profile changes',async t=>{
 const f=await fixture(t),iface=f.model.interfaces.find(i=>i.direction==='inbound');
 const threat={id:'t',title:'Conditional write',category:'Tampering',interfaceIds:[iface.id],evidenceIds:iface.evidence};
 f.model.aiReview={status:'partial',basedOnRevision:f.model.modelRevision,threats:[threat],scope:{poc:{profile:'Profile A'}}};
 f.model.threatValidation={contextKey:threatValidationKey(f.model),entries:[{sourceId:'t',issueHash:sha(JSON.stringify(threatIssue(f.model,threat))),assessment:'static-supported',engineering:{conclusion:'Ordinary caller can write under the stated conditions',reviewerQuestions:[{question:'Can an ordinary user reach this route?',ifYes:'This access prerequisite applies.',ifNo:'This actor lacks the stated access.'}]}}]};
 const before=JSON.stringify(f.model.threatValidation),q=deploymentDecisionQuestions(f.model)[0];
 let m=recordDeploymentAnswer(f.model,{modelRevision:f.model.modelRevision,questionId:q.id,answer:'no',reviewer:'Owner',rationale:'Ingress permits administrators only'});
 assert.equal(JSON.stringify(m.threatValidation),before);assert.equal(deploymentDecisionQuestions(m)[0].answer.answer,'no');
 m.aiReview.scope.poc.profile='Profile B';assert.equal(deploymentDecisionQuestions(m)[0].answer,null);
 assert.throws(()=>recordDeploymentAnswer(m,{modelRevision:m.modelRevision,questionId:q.id,answer:'yes',reviewer:'x',rationale:'y'}),/no longer current/);
 m.threatValidation.entries[0].assessment='needs-context';assert.equal(deploymentDecisionQuestions(m).length,0);
});

test('missing indexed symbols use verified text fallback and changed source never supplies evidence',async t=>{
 const f=await fixture(t),source=new InvestigationSource(f.model,f.manifest,f.root);
 const result=await source.findImplementation(['IsAdmin'],[{repository:'app',path:'Controllers/EmailController.cs'}]);
 assert.ok(result.references.some(r=>r.repository==='support'&&r.path==='RootController.cs'));
 assert.match(result.interpretation,/no match does not establish/i);
 await fs.appendFile(path.join(f.root,'support','RootController.cs'),'\n// modified');
 const changed=await source.findImplementation(['IsAdmin'],[]);
 assert.equal(changed.references.length,0);assert.ok(changed.failures.some(f=>f.reason==='source-hash-mismatch'));
 const bounded=await source.findImplementation(['MissingControl'],[],{maxFiles:1,maxBytes:2000000});assert.equal(bounded.searchedFiles,1);assert.equal(bounded.limited,true);
});

test('feature cohorts retrieve a named category control before expanding discovery and count the follow-up',async t=>{
 const f=await fixture(t);await fs.writeFile(path.join(f.root,'support','Other.cs'),'class ExtraGuard { public void Verify() { throw new UnauthorizedAccessException(); } }');
 f.model=await analyze(f.manifest,{sourceRoot:f.root});
 f.model.pocScope=resolvePocScope(f.model,{kind:'repositories',title:'Features',profile:'Static',repositories:['app'],reviewDepth:'security-features'});
 const source=await verifiedStrideSource(f.model,f.manifest,f.root),config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'});let calls=0;
 const send=async(_,request)=>{calls++;const packet=JSON.parse(JSON.parse(request.body).messages[0].content),response=categoryResponse(packet);
  if(calls===1){response.categoryReviews[1].status='evidence-gap';response.categoryReviews[1].missingEvidence=['Inspect ExtraGuard implementation before deciding this path.'];}
  else {assert.ok(packet.sourceContext.records.some(r=>r.path==='Other.cs'));assert.match(JSON.stringify(packet.sourceContext.priorReview),/ExtraGuard/);}
  return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(response)}],usage:{input_tokens:2,output_tokens:2}});
 };
 await reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,{sourceRoot:f.root,verifiedSource:source,maxBatches:2,concurrency:1,prepareBatch:b=>prepareStrideEvidence(b.packet,source)});
 assert.equal(calls,2);assert.equal(f.model.featureReviewRun.calls,2);assert.equal(f.model.featureReviewRun.engineeringCalls,1);assert.equal(f.model.featureReviewRun.reportedTokens,8);
 assert.equal(f.model.featureEvidenceHistory.length,1);assert.equal(f.model.featureEvidenceHistory[0].previous.review.categoryReviews[1].status,'evidence-gap');
 assert.ok(f.model.aiReview.coverage.pendingBatches>0);assert.equal(f.model.featureReviewRun.stopReason,'request-budget');
});

test('failed category follow-up preserves the prior paid result and stops provider dispatch',async t=>{
 const f=await fixture(t);await fs.writeFile(path.join(f.root,'support','ExtraGuard.cs'),'class ExtraGuard { public void Verify() { throw new UnauthorizedAccessException(); } }');
 f.model=await analyze(f.manifest,{sourceRoot:f.root});f.model.pocScope=resolvePocScope(f.model,{kind:'repositories',title:'Features',profile:'Static',repositories:['app'],reviewDepth:'security-features'});
 const source=await verifiedStrideSource(f.model,f.manifest,f.root),config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'});let calls=0;
 const send=async(_,request)=>{calls++;if(calls>1)return Response.json({error:{message:'not authorized'}},{status:403});
  const packet=JSON.parse(JSON.parse(request.body).messages[0].content),response=categoryResponse(packet);response.categoryReviews[1].status='evidence-gap';response.categoryReviews[1].missingEvidence=['Inspect ExtraGuard implementation.'];
  return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(response)}],usage:{input_tokens:2,output_tokens:2}});
 };
 await reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,{sourceRoot:f.root,verifiedSource:source,maxBatches:4,concurrency:1,prepareBatch:b=>prepareStrideEvidence(b.packet,source)});
 assert.equal(calls,2);assert.equal(f.model.featureReviewRun.calls,2);assert.equal(f.model.featureReviewRun.stopReason,'provider-failure');
 assert.equal(f.model.aiReview.coverage.completedBatches,1);assert.ok(f.model.featureEvidenceHistory[0].failure);
 assert.equal(f.model.aiReview.batches.find(b=>b.status==='completed').review.categoryReviews[1].status,'evidence-gap');
});

test('feature coordinator requires source consent and cancellation makes no model calls',async t=>{
 const f=await fixture(t);f.model.pocScope=resolvePocScope(f.model,{kind:'repositories',title:'Features',profile:'Static',repositories:['app'],reviewDepth:'security-features'});
 const config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'}),source=await verifiedStrideSource(f.model,f.manifest,f.root);
 const send=()=>{throw Error('Must not call provider');};
 await assert.rejects(reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,{sourceRoot:f.root}),/explicit source sharing/);
 const controller=new AbortController();controller.abort();
 await reviewFeatureCohorts(f.model,f.manifest,config,new Map(),send,{sourceRoot:f.root,verifiedSource:source,signal:controller.signal,prepareBatch:b=>prepareStrideEvidence(b.packet,source)});
 assert.equal(f.model.featureReviewRun.calls,0);assert.equal(f.model.featureReviewRun.stopReason,'cancelled');
});

test('case evidence distinguishes cross-repository controls, unresolved bindings and deployment declarations',async()=>{
 const {decisionPath}=await import('../src/decision-path.mjs');
 const threat={id:'t',boundaryIds:['boundary'],validation:{actor:'Ordinary user',initialAccess:'Can reach the entry',engineering:{obligations:[
  {kind:'entry',status:'established',reason:'Route',citations:[{repository:'api',path:'route.cs',startLine:1,endLine:2}]},
  {kind:'path-binding',status:'missing',reason:'Registration not supplied',citations:[]},
  {kind:'applicable-controls',status:'blocks-attack',reason:'Shared policy rejects ordinary users',citations:[{repository:'policy',path:'policy.cs',startLine:3,endLine:4}]},
  {kind:'sensitive-operation',status:'established',reason:'Write',citations:[{repository:'api',path:'store.cs',startLine:5,endLine:6}]}]}}};
 const system={boundaries:[{id:'boundary',name:'Caller / service',reference:'TB-1',reviewState:'pending'}]},before=JSON.stringify([threat,system]);
 const p=decisionPath(threat,system);assert.deepEqual(p.repositories,['api','policy']);assert.equal(p.pathStatus,'Cited blocking fact');assert.equal(p.stages[1].status,'missing');assert.match(p.runtime,/Not tested/);assert.equal(p.boundaries[0].state,'pending');assert.equal(JSON.stringify([threat,system]),before);
 const legacy=await import('../src/reviewer-questions.mjs');const q=legacy.questionPresentation({}, {question:'Enable auth?',ifYes:'All routes are safe',ifNo:'All routes are accessible'});
 assert.doesNotMatch(q.ifYes,/All routes/);assert.equal(q.originalInterpretation.ifYes,'All routes are safe');
});
