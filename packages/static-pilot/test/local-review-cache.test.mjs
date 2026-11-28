import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {compactEvidence,expandEvidence,EVIDENCE_TRANSPORT_PROMPT} from '../src/evidence-transport.mjs';
import {LocalReviewCache,cacheableReview} from '../src/local-review-cache.mjs';
import {requestReview} from '../src/model-review.mjs';
import {reviewSecurityIssues} from '../src/security-review.mjs';
import {reportFixture} from './report-fixture.mjs';

const record=(id,startLine=1,endLine=100)=>{
 const lines=Array.from({length:endLine-startLine+1},(_,i)=>({line:startLine+i,text:'    await enforce_control(subject, resource, action); // cited source '+(startLine+i)}));
 return {id,repository:'service',path:'auth.py',blobSha256:'hash',startLine,endLine,lines,code:lines.map(l=>`${l.line}: ${l.text}`).join('\n'),required:true};
};
async function fixture(t,limits){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'local-review-'));const file=path.join(dir,'review-cache.sqlite');let cache=new LocalReviewCache(file,limits);t.after(async()=>{cache.close();await fs.rm(dir,{recursive:true,force:true});});return {dir,file,get cache(){return cache;},reopen(){cache.close();cache=new LocalReviewCache(file,limits);return cache;}};}
const valid={assessment:'ruled-out',missingEvidence:[],followUp:[],reason:'The cited guard blocks this specific path.'};
const cfg=cache=>({provider:'anthropic-gateway',model:'fixture-model',baseUrl:'https://gateway.example/anthropic',apiVersion:'2023-06-01',apiKey:'test-secret-key',localReviewContext:'scope-hash',localReviewCache:cache,compactEvidence:true});
const response=value=>Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(value)}],usage:{input_tokens:100,output_tokens:20}});

test('source compaction is lossless across overlapping windows, hashes and repositories',()=>{
 const original={records:[record('a'),record('b',50,120),{...record('c'),repository:'other'},{...record('d'),blobSha256:'different'}],sourceContext:{records:[record('e',20,80)],gaps:[{reason:'missing caller',required:true}]}};
 const before=structuredClone(original),compact=compactEvidence(original);
 assert.ok(compact.metrics.removedBytes>10000);assert.equal(compact.packet.evidenceText.length,3);
 assert.deepEqual(expandEvidence(compact.packet),original);assert.deepEqual(original,before);
 assert.ok(Buffer.byteLength(JSON.stringify(compact.packet))+Buffer.byteLength(EVIDENCE_TRANSPORT_PROMPT)<compact.metrics.originalBytes);
 const tampered=structuredClone(compact.packet);tampered.records[0].repository='invented';assert.throws(()=>expandEvidence(tampered),/ownership/);
});
test('conflicting, sparse and reserved-field records retain their original representation',()=>{
 const a=record('a'),b=record('b');b.lines[4].text='conflicting';b.code=b.lines.map(l=>`${l.line}: ${l.text}`).join('\n');
 const sparse=record('s');sparse.lines.splice(4,1);delete sparse.code;
 const p={records:[a,b,sparse,{...record('r'),textRef:'reserved'}]};assert.deepEqual(compactEvidence(p).packet,p);
 const tiny={records:[{...record('t',1,1),lines:[{line:1,text:'x'}],code:'1: x'}]};assert.equal(compactEvidence(tiny).metrics.removedBytes,0);
 for(const unusual of [{...record('x'),lines:null},{...record('x'),code:null},{...record('x'),lines:[null]},{...record('x'),textRef:'existing'}]){
  const mixed={records:[record('normal'),unusual]};assert.deepEqual(expandEvidence(compactEvidence(mixed).packet),mixed);
 }
 const reserved={records:[record('normal')],evidenceEncoding:''};assert.deepEqual(compactEvidence(reserved).packet,reserved);
});
test('cache persists, rejects corrupt payloads, bounds storage and disallows source-tree files',async t=>{
 const f=await fixture(t,{maxEntries:2});f.cache.put('one',{ok:1});f.reopen();assert.deepEqual(f.cache.get('one'),{ok:1});f.cache.accept('one');assert.equal(f.cache.stats.hits,1);
 f.cache.put('two',{ok:2});f.cache.put('three',{ok:3});assert.equal(f.cache.db.prepare('SELECT COUNT(*) n FROM responses').get().n,2);
 f.cache.db.prepare('UPDATE responses SET payload=? WHERE key=?').run('corrupt','three');assert.equal(f.cache.get('three'),null);assert.equal(f.cache.stats.invalid,1);
 assert.throws(()=>new LocalReviewCache(path.join(f.dir,'unsafe.sqlite'),{sourceRoot:f.dir}),/outside/);
 assert.throws(()=>new LocalReviewCache(f.file,{maxEntries:0}),/limits/);
});
test('identical validated response reuses locally after restart with no provider call or usage event',async t=>{
 const f=await fixture(t),packet={records:[record('a'),record('b')]};let calls=0,usage=0;
 const send=async(_,req)=>{calls++;const body=JSON.parse(req.body);assert.ok(!JSON.stringify(body).includes('cache_control'));assert.deepEqual(expandEvidence(JSON.parse(body.messages[0].content)),packet);return response(valid);};
 const options={validate:(v,p)=>{assert.deepEqual(p,packet);return v;},systemPrompt:'Assess this path',onUsage:()=>usage++};
 const cold=await requestReview(cfg(f.cache),packet,send,options);assert.equal(cold.usage.totalTokens,120);
 f.reopen();const warm=await requestReview(cfg(f.cache),packet,send,options);
 assert.equal(calls,1);assert.equal(usage,1);assert.deepEqual(warm.review,cold.review);assert.equal(warm.usage,null);assert.ok(warm.localReuse);
 const rows=f.cache.db.prepare('SELECT payload FROM responses').all();assert.ok(!JSON.stringify(rows).includes('enforce_control'));assert.ok(!JSON.stringify(rows).includes('test-secret-key'));
});
test('source, scope, model, prompt, contract and validator changes never silently reuse a decision',async t=>{
 const f=await fixture(t),packet={records:[record('a')]};let calls=0;const send=async()=>{calls++;return response(valid);},options={validate:v=>v,systemPrompt:'First assessment'};
 await requestReview(cfg(f.cache),packet,send,options);
 for(const change of [{localReviewContext:'new-scope'},{model:'new-model'},{structuredOutputs:true}])await requestReview({...cfg(f.cache),...change},packet,send,options);
 await requestReview(cfg(f.cache),{records:[{...record('a'),blobSha256:'changed'}]},send,options);
 await requestReview(cfg(f.cache),packet,send,{...options,systemPrompt:'Independent challenge'});
 await requestReview(cfg(f.cache),packet,send,{...options,responseSchema:{type:'object'}});
 await requestReview(cfg(f.cache),packet,send,{...options,validate:v=>({...v,newRule:'current'})});
 assert.equal(calls,8);assert.ok(f.cache.stats.invalid>0);
});
test('unresolved, invalid and secret-bearing responses do not become reusable clearance',async t=>{
 const f=await fixture(t),p={records:[record('a')]},options={validate:v=>v};let calls=0;
 for(const answer of [{...valid,assessment:'needs-context'},{...valid,missingEvidence:['Missing binding']},{...valid,reason:'test-secret-key'}]){
  const send=async()=>{calls++;return response(answer);};await requestReview(cfg(f.cache),p,send,options);await requestReview(cfg(f.cache),p,send,options);
 }
 assert.equal(calls,6);assert.equal(f.cache.stats.hits,0);
 assert.ok(!cacheableReview({...valid,engineering:{obligations:[{status:'missing'}]}}));
 await assert.rejects(requestReview(cfg(f.cache),p,async()=>response(valid),{validate:()=>{throw Error('invalid evidence');}}),/invalid evidence/);
 assert.equal(f.cache.db.prepare('SELECT COUNT(*) n FROM responses').get().n,0);
 const controller=new AbortController();controller.abort();await assert.rejects(requestReview(cfg(f.cache),p,()=>{throw Error('must not dispatch');},{...options,signal:controller.signal}));
});
test('assessment and independent challenge retain separate cache keys and replay without fake provider attempts',async t=>{
 const f=await fixture(t),source=await reportFixture();t.after(()=>fs.rm(source.dir,{recursive:true,force:true}));
 const initial=structuredClone(source.model),issue={id:'fixture-case',sourceId:'fixture-case',origin:'analysis',locations:[{repository:'service',path:'app.py',line:3}],explanation:'Synthetic fixture'};
 const answer={...valid,assessment:'static-supported',impact:'Synthetic fixture impact'};let calls=0;
 const options={sourceRoot:source.root,config:cfg(f.cache),candidateIssues:[issue],budget:4,finishCaseFirst:true,challengePrompt:'Independently challenge this case',packetBuilder:async()=>({records:[record('a')],gaps:[]}),validateResponse:v=>v,fetchImpl:async()=>{calls++;return response(answer);}};
 await reviewSecurityIssues(source.manifest,source.model,options);
 assert.equal(calls,2);assert.equal(source.model.securityReview.entries[0].challengeCompleted,true);assert.equal(source.model.usageLedger.attempts.length,2);
 f.reopen();const fresh=structuredClone(initial);await reviewSecurityIssues(source.manifest,fresh,{...options,config:cfg(f.cache)});
 assert.equal(calls,2);assert.equal(fresh.securityReview.entries[0].challengeCompleted,true);assert.equal(fresh.securityReview.callsThisRun,0);assert.equal(fresh.usageLedger.attempts.length,0);assert.equal(f.cache.stats.hits,2);
});
