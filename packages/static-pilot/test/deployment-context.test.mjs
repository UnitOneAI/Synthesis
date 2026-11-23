import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyze } from '../src/engine.mjs';
import { systemReviewPlan } from '../src/system-review-units.mjs';
import { deploymentContext, updateDeploymentContext } from '../src/deployment-context.mjs';
import { deploymentArtifact } from '../src/deployment-artifacts.mjs';
import { enrichGraphModel } from '../src/graph-review.mjs';
import { modelConfig } from '../src/model-review.mjs';
import { systemModel } from '../src/system-model.mjs';
import { systemPrintReport } from '../src/system-exports.mjs';
import { verifiedStrideSource, prepareStrideEvidence, STRIDE_EVIDENCE_VERSION } from '../src/stride-evidence.mjs';
import { workspaceStore } from '../src/workspace-store.mjs';
import { serve } from '../src/server.mjs';
async function fixture(t, count = 12) {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'deployment-review-')));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, 'sources'), repositories = [];
  for (let n = 0; n < count; n++) {
    const name = `repo-${n}`; repositories.push({ name });
    const repo = path.join(root, name); await fs.mkdir(repo, { recursive: true });
    await fs.writeFile(path.join(repo, 'Service.cs'), `class Service { [HttpGet("/r${n}/admin")] public void Run() { client.GetAsync("/items"); } }`);
    await fs.writeFile(path.join(repo, 'Worker.cs'), 'class Worker : BackgroundService { void Execute() { var c = new SqlConnection(configuration.GetConnectionString("Main")); } }');
    await fs.writeFile(path.join(repo, 'appsettings.Production.json'), JSON.stringify({ ConnectionStrings: { Main: 'Server=example;Database=data;Integrated Security=true' }, Authentication: { Enabled: true } }));
    await fs.mkdir(path.join(repo, 'tests'));
    await fs.writeFile(path.join(repo, 'tests', 'Fixture.cs'), '[HttpGet("/test")] void Fixture() {}');
  }
  await fs.writeFile(path.join(root, 'repo-0', 'Setup.wxs'), '<Wix><ServiceInstall Account="LocalSystem"/><PermissionEx User="Users" GenericRead="yes"/></Wix>');
  const manifest = { title: 'Static system qualification', profile: 'fixture', repositories };
  return { dir, root, workspace: path.join(dir, 'state'), manifest, model: await analyze(manifest, { sourceRoot: root }) };
}
const config = modelConfig('anthropic-gateway', 'claude-opus-4-6-1', { CLAUDE_API_KEY: 'synthetic', SYNTHESIS_STRUCTURED_OUTPUTS: '1' }, { baseUrl: 'https://gateway.example/anthropic' });
const reply = packet => {
  const r = packet.records.find(r => r.direction === 'inbound');
  return Response.json({ stop_reason: 'end_turn', usage: { input_tokens: 30, output_tokens: 10 }, content: [{ type: 'text', text: JSON.stringify({
    summary: 'Synthetic review for execution qualification.', standardsReviews: [], connections: [], questions: [],
    threats: r ? [{ title: 'Conditional operation authorization gap', category: 'Elevation of Privilege', actor: 'Untrusted caller', startingAccess: 'Assumed network access', asset: 'Administrative operations', scenario: 'If effective authorization is absent, an untrusted caller may invoke the operation.', prerequisites: 'Reachability and missing effective authorization require review.', controls: 'Verify handler enforcement.', mitigation: 'Enforce scoped authorization.', interfaceIds: [r.id], evidenceIds: [r.evidence[0].id], analysis: { attackSteps: ['Reach the operation under the stated access assumption.'], impact: 'Unauthorized operation', assumptions: ['Network access is assumed.'], controlEvidenceIds: [], boundaryIds: [], mappings: [] } }] : [],
  }) }] });
};
test('saved graph builds system scope and optional assumptions across twelve repositories without extraction or model calls', async t => {
  const f = await fixture(t); const before = JSON.stringify(f.model.sourceGraph);
  const context = deploymentContext(f.model), plan = systemReviewPlan(f.model);
  assert.equal(context.profile, 'Unconfirmed source-defined deployment');
  assert.ok(context.profiles.includes('Production'));
  assert.ok(context.questions.length <= 5);
  assert.ok(context.questions.every(q => q.state === 'assumption in use'));
  assert.equal(plan.scope.repositories.length, 12);
  assert.ok(plan.scope.repositories.every(r => r.inScope > 0));
  assert.ok(plan.scope.deferredInterfaces > 0);
  assert.equal(plan.omitted.length, 0);
  assert.equal(JSON.stringify(f.model.sourceGraph), before);
  assert.ok(plan.batches.every(b => b.packet.deploymentContext && b.packet.reviewFocus.phase === 'system-review'));
  assert.ok(plan.batches.some(b => b.packet.records.some(r => /worker|store/i.test(r.operation))));
  assert.ok(context.claims.some(c => c.evidenceBasis.includes('installer')));
  assert.ok(!JSON.stringify(context).includes('runtime-verified"'));
});
test('system STRIDE produces scenarios and matrix before deep coverage, then selectively resumes after an optional answer', async t => {
  const f = await fixture(t); const source = await verifiedStrideSource(f.model, f.manifest, f.root);
  const options = { reviewScope: 'system', runUntilComplete: true, concurrency: 4, evidencePolicy: STRIDE_EVIDENCE_VERSION, prepareBatch: b => prepareStrideEvidence(b.packet, source) };
  let calls = 0;
  const transport = async (_, request) => { calls++; const body = JSON.parse(request.body); assert.equal(body.model, 'claude-opus-4-6-1'); return reply(JSON.parse(body.messages[0].content)); };
  await enrichGraphModel(f.model, config, new Map(), transport, options);
  assert.equal(f.model.aiReview.coverage.pendingBatches, 0);
  assert.equal(f.model.aiReview.coverage.failedBatches, 0);
  const s = systemModel(f.model);
  assert.ok(s.actors.length && s.boundaries.length);
  const candidate = s.threats.find(t => t.origin === 'analysis' && t.candidateFlowIds?.length);
  assert.ok(candidate && candidate.boundaryIds.length, 'Unresolved callers still retain candidate trust crossings');
  assert.ok(candidate.flowIds.every(id => s.flows.find(f => f.id === id).basis !== 'unresolved'));
  assert.match(candidate.boundaryLinkBasis, /unresolved/);
  assert.ok(s.matrix.some(r => r.cells.some(c => c.scenarioCount > 0)));
  assert.ok(s.matrix.every(r => r.cells.every(c => c.analysisStatus !== 'not-analyzed')));
  assert.ok(f.model.aiReview.scope.deferredInterfaces > 0);
  const html = systemPrintReport(f.model);
  assert.match(html, /Deployment assumptions and review scope/);
  assert.match(html, /Conditional operation authorization gap/);
  assert.match(html, /deferred to deep code review/);
  const prior = f.model.aiReview.batches.filter(b => !b.deploymentQuestionIds.includes('exposure')).map(b => b.id);
  assert.ok(prior.length, 'Fixture must exercise unaffected units');
  const context = deploymentContext(f.model);
  let changed = updateDeploymentContext(f.model, { revision: context.revision, action: 'answer', questionId: 'exposure', choice: 1, reviewer: 'Security champion', rationale: 'Management VLAN deployment profile' });
  assert.ok(changed.aiReview.batches.some(b => b.status === 'stale'));
  assert.ok(prior.every(id => changed.aiReview.batches.some(b => b.id === id && b.status === 'completed')));
  assert.equal(f.model.aiReview.batches.filter(b => b.status === 'stale').length, 0, 'Prior model must not be mutated');
  const store = await workspaceStore(f.root, f.workspace); await store.save({ model: changed, manifest: f.manifest }); const restored = await store.load(); await store.close();
  changed = restored.model;
  const executed = [];
  await enrichGraphModel(changed, config, new Map(), transport, { ...options, trace: (event, data) => { if (event === 'review.stage-packet') executed.push(data.batchId); } });
  assert.ok(prior.every(id => !executed.includes(id)), 'Unaffected review units must be reused after saved restart');
  assert.equal(changed.aiReview.coverage.pendingBatches, 0);
  assert.equal(changed.aiReview.coverage.failedBatches, 0);
  assert.match(systemPrintReport(changed), /Management network only/);
  const previousCalls = calls;
  await enrichGraphModel(changed, config, new Map(), transport, options);
  assert.equal(calls, previousCalls, 'Unchanged system review must make no further requests');
});
test('deployment answers are scoped, revision-checked and never approve trust boundaries', async t => {
  const f = await fixture(t, 1), c = deploymentContext(f.model);
  assert.throws(() => updateDeploymentContext(f.model, { revision: 'wrong', action: 'answer' }), /changed/);
  assert.throws(() => updateDeploymentContext(f.model, { revision: c.revision, action: 'answer', questionId: 'exposure', choice: 1 }), /reviewer/);
  const changed = updateDeploymentContext(f.model, { revision: c.revision, action: 'answer', questionId: 'exposure', choice: 1, reviewer: 'Reviewer' });
  assert.equal(changed.modelRevision, f.model.modelRevision);
  assert.ok(systemModel(changed).boundaries.every(b => b.reviewState !== 'accepted'));
  const sourceChanged = { ...changed, evidence: changed.evidence.map(e => ({ ...e, blobSha256: 'changed' })) };
  assert.equal(deploymentContext(sourceChanged).questions.find(q => q.id === 'exposure').answer, null);
  const profiled=updateDeploymentContext(f.model,{revision:c.revision,action:'profile',profile:'Production'});
  const removed={...profiled,evidence:profiled.evidence.filter(e=>!e.path.includes('appsettings.Production'))};
  assert.match(deploymentContext(removed).profileStatus,/no longer supported/);
  assert.equal(deploymentContext(removed).profile,'Unconfirmed source-defined deployment');
});
test('configuration artifacts retain recognized declarations and hashes, never raw values or executable content', () => {
  const result = deploymentArtifact({ name: 'deployment.json', text: JSON.stringify({ Authentication: { Secret: 'do-not-retain-this-secret' }, ConnectionStrings: { Main: 'password=another-secret' } }) });
  assert.equal(result.declarations.length, 2);
  assert.ok(!JSON.stringify(result).includes('secret'));
  assert.ok(result.sha256.length === 64);
  assert.throws(() => deploymentArtifact({ name: 'run.ps1', text: 'Start-Process evil' }), /scripts/);
  assert.throws(() => deploymentArtifact({ name: 'config.xml', text: '<!DOCTYPE x SYSTEM "https://example.test"><x/>' }), /parsed/);
  assert.throws(() => deploymentArtifact({ name: 'config.json', text: 'x'.repeat(300000) }), /256/);
});
test('deployment APIs require workspace access, preserve saved graph, and hash-check code evidence', async t => {
  const f = await fixture(t, 1); const store = await workspaceStore(f.root, f.workspace); await store.save({ model: f.model, manifest: f.manifest }); await store.close();
  const app = await serve({ sourceRoot: f.root, workspace: f.workspace, persist: true, port: 0, quiet: true });
  try {
    const url = new URL(app.url), headers = { 'X-Synthesis-Token': url.hash.slice(1), 'Content-Type': 'application/json' };
    assert.notEqual((await fetch(url.origin + '/api/system-review-plan')).status, 200);
    const plan = await (await fetch(url.origin + '/api/system-review-plan', { headers })).json(); assert.ok(plan.units);
    const current = await (await fetch(url.origin + '/api/model', { headers })).json();
    const context = current.systemModel.deploymentContext;
    const response = await fetch(url.origin + '/api/deployment-context', { method: 'POST', headers, body: JSON.stringify({ revision: context.revision, action: 'answer', questionId: 'exposure', choice: 0 }) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).sourceGraph.fingerprint, f.model.sourceGraph.fingerprint);
    const ref = f.model.evidence.find(e => e.path === 'Service.cs');
    const source = await fetch(url.origin + '/api/deployment-evidence?id=' + ref.id, { headers }); assert.equal(source.status, 200); assert.ok((await source.json()).lines.length);
    assert.equal((await fetch(url.origin + '/api/deployment-evidence?id=../../secret', { headers })).status, 404);
    await fs.appendFile(path.join(f.root, 'repo-0', ref.path), '\n// changed');
    assert.notEqual((await fetch(url.origin + '/api/deployment-evidence?id=' + ref.id, { headers })).status, 200);
  } finally { await app.close(); }
});
test('switching between system and deep scopes preserves both paid-review checkpoints', async t => {
  const f = await fixture(t, 1); let calls=0;
  const fetcher = async (_, request) => { calls++; return reply(JSON.parse(JSON.parse(request.body).messages[0].content)); };
  await enrichGraphModel(f.model, config, new Map(), fetcher, { reviewScope:'system', runUntilComplete:true });
  const systemCount=f.model.aiReview.coverage.completedBatches;
  await enrichGraphModel(f.model, config, new Map(), fetcher, { reviewScope:'deep', maxBatches:1 });
  assert.equal(f.model.savedStrideScopes.system.coverage.completedBatches,systemCount);
  const afterDeep=calls;
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});const restored=(await store.load()).model;await store.close();
  await enrichGraphModel(restored, config, new Map(), fetcher, {reviewScope:'system',runUntilComplete:true});
  assert.equal(calls,afterDeep);assert.equal(restored.aiReview.coverage.completedBatches,systemCount);
  assert.equal(restored.savedStrideScopes.deep.coverage.completedBatches,1);
  await enrichGraphModel(restored,config,new Map(),fetcher,{reviewScope:'deep',maxBatches:1,batchIds:[]});
  assert.equal(calls,afterDeep);assert.equal(restored.aiReview.coverage.completedBatches,1);
});
test('worker routes system scope and checkpoints the other scope before completion', async t => {
  const { Worker } = await import('node:worker_threads');
  const { pathToFileURL } = await import('node:url');
  const f=await fixture(t,1);
  await enrichGraphModel(f.model,config,new Map(),async(_,request)=>reply(JSON.parse(JSON.parse(request.body).messages[0].content)),{maxBatches:1});
  const preload=path.join(f.dir,'fake-provider.mjs');
  await fs.writeFile(preload, `globalThis.fetch=async()=>Response.json({stop_reason:'end_turn',usage:{input_tokens:1,output_tokens:1},content:[{type:'text',text:JSON.stringify({summary:'Synthetic worker qualification',threats:[],connections:[],questions:[],standardsReviews:[]})}]});`);
  const w=new Worker(new URL('../src/worker.mjs',import.meta.url),{execArgv:['--import',pathToFileURL(preload).href],workerData:{mode:'review',model:f.model,manifest:f.manifest,excerpts:[],options:{sourceRoot:f.root,includeSourceExcerpts:true,modelConfig:config,reviewScope:'system',reviewBatches:1}}});
  t.after(()=>w.terminate());
  const checkpoints=[];
  const final=await new Promise((resolve,reject)=>{
    w.on('error',reject);
    w.on('message',m=>{
      if(m.type==='trace') w.postMessage({type:'trace-saved',id:m.id});
      if(m.type==='checkpoint'){checkpoints.push(m);w.postMessage({type:'checkpoint-saved',id:m.id});}
      if(m.type==='error')reject(Error(m.message));
      if(m.type==='done')resolve(m.model);
    });
  });
  assert.equal(final.aiReview.reviewScope,'system');
  assert.equal(final.aiReview.coverage.completedBatches,1);
  assert.ok(final.aiReview.batches[0].evidenceContext.records.length);
  assert.ok(checkpoints.length);
  assert.ok(checkpoints.every(c=>c.savedStrideScopes.deep.coverage.completedBatches===1));
});


test('system review recovers transient failure and invalid citation, retains every attempt, and completes twelve repos', async t => {
  const f = await fixture(t);
  const trace = [];
  let calls = 0;
  const transport = async (_, request) => {
    const packet = JSON.parse(JSON.parse(request.body).messages[0].content);
    calls++;
    if (calls === 1) throw Error('network reset with private details');
    if (calls === 2) {
      const data = await reply(packet).json();
      const value = JSON.parse(data.content[0].text);
      value.threats = [{ ...(value.threats[0] || {}), title: 'Invalid reference', interfaceIds: ['invented'], evidenceIds: ['invented'] }];
      data.content[0].text = JSON.stringify(value);
      return Response.json(data);
    }
    if (calls === 3) assert.match(JSON.parse(request.body).system, /Validation retry:/);
    return reply(packet);
  };
  await enrichGraphModel(f.model, config, new Map(), transport, { reviewScope: 'system', runUntilComplete: true, concurrency: 1, recoveryDelayMs: 0, trace: (e, d) => trace.push({ e, d }) });
  assert.equal(f.model.aiReview.status, 'completed-needs-review');
  assert.equal(f.model.aiReview.coverage.failedBatches, 0);
  assert.equal(f.model.aiReview.coverage.pendingBatches, 0);
  assert.equal(f.model.aiReview.scope.repositories.length, 12);
  assert.equal(f.model.usageLedger.attempts.filter(a => a.status === 'failed').length, 2);
  assert.equal(f.model.usageLedger.attempts.filter(a => a.usage === null).length, 1);
  assert.equal(trace.filter(x => x.e === 'review.retry-scheduled').length, 2);
  assert.ok(!JSON.stringify(f.model.aiReview).includes('private details'));
  const before = calls;
  await enrichGraphModel(f.model, config, new Map(), transport, { reviewScope: 'system', runUntilComplete: true });
  assert.equal(calls, before, 'Completed paid work must be reused');
});

test('system recovery is bounded, honors long gateway cooldowns, and stops immediately on authorization failures', async t => {
  const f = await fixture(t, 1);
  for (const [status, headers, expected] of [[503, {}, 3], [429, { 'Retry-After': '120' }, 1], [403, {}, 1]]) {
    const model = structuredClone(f.model); let calls = 0;
    await enrichGraphModel(model, config, new Map(), async () => { calls++; return new Response('secret provider details', { status, headers }); }, { reviewScope: 'system', runUntilComplete: true, concurrency: 1, recoveryDelayMs: 0 });
    assert.equal(calls, expected);
    assert.equal(model.aiReview.stopReason, 'provider-failure');
    assert.equal(model.aiReview.stopFailure.httpStatus, status);
    assert.equal(model.usageLedger.attempts.length, expected);
    assert.ok(model.usageLedger.attempts.every(a => a.status === 'failed'));
    assert.ok(!JSON.stringify(model).includes('secret provider details'));
  }
});

test('cancellation during STRIDE recovery sends no replacement request', async t => {
  const f = await fixture(t, 1), controller = new AbortController(); let calls = 0;
  await enrichGraphModel(f.model, config, new Map(), async () => { calls++; throw Error('reset'); }, {
    reviewScope: 'system', runUntilComplete: true, concurrency: 1, signal: controller.signal,
    trace: event => { if (event === 'review.retry-scheduled') controller.abort(); },
  });
  assert.equal(calls, 1);
  assert.equal(f.model.aiReview.stopReason, 'cancelled');
  assert.equal(f.model.usageLedger.attempts[0].status, 'failed');
});


test('an isolated invalid system unit does not hide later internal scope or become completed coverage', async t => {
  const f = await fixture(t, 3), plan = systemReviewPlan(f.model);
  const first = plan.batches[0]; first.reviewStage = 1;
  for (const b of plan.batches.slice(1)) b.reviewStage = 2;
  let failedPacket;
  await enrichGraphModel(f.model, config, new Map(), async (_, request) => {
    const packet = JSON.parse(JSON.parse(request.body).messages[0].content);
    failedPacket ||= JSON.stringify(packet);
    if (JSON.stringify(packet) === failedPacket) return Response.json({ stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: 'text', text: 'invalid' }] });
    return reply(packet);
  }, { plan, runUntilComplete: true, concurrency: 1, recoveryDelayMs: 0 });
  assert.equal(f.model.aiReview.coverage.failedBatches, 1);
  assert.equal(f.model.aiReview.coverage.pendingBatches, 0);
  assert.equal(f.model.aiReview.coverage.completedBatches, plan.batches.length - 1);
  assert.equal(f.model.aiReview.status, 'partial');
  assert.equal(f.model.aiReview.stopReason, 'plan-exhausted');
});
