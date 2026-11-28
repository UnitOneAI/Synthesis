import {requestReview,redact} from './model-review.mjs';
import {sha} from './sources.mjs';
import {beginUsageRun,beginAttempt,finishAttempt} from './token-usage.mjs';
import {securityContext} from './security-intelligence.mjs';
import {sourceWindow} from './graph-package.mjs';
import {controlSymbols} from './control-context.mjs';
import {threatBatch,batchSchema,validateThreatBatch,THREAT_BATCH_PROMPT,THREAT_BATCH_VERSION} from './threat-batch.mjs';

// One coordinator owns entries and usage. Requests batch cases only inside an
// already planned section. No category, operation or positive challenge is cut.
export async function reviewSectionThreats(manifest,model,options) {
 const {sourceRoot,config,budget=4,contextRounds=5,candidateIssues,contextKeyOverride:contextKey,systemPrompt,challengePrompt,responseSchema,validateResponse,packetBuilder,checkpoint,trace,progress,signal,fetchImpl=fetch}=options;
 if(!Number.isInteger(budget)||budget<1||budget>100||!Number.isInteger(contextRounds)||contextRounds<1||contextRounds>5)throw Error('Invalid section batch budget');
 const maxCases=options.batchSize ?? 4;if(!Number.isInteger(maxCases)||maxCases<1||maxCases>4)throw Error('Section batches allow 1–4 cases');
 const key=sha(JSON.stringify([contextKey,systemPrompt,challengePrompt,config.provider,config.model,config.baseUrl,THREAT_BATCH_VERSION]));
 const previous=model.threatValidation?.contextKey===contextKey?model.threatValidation:null;
 const report={version:1,key,contextKey,basedOnRevision:model.modelRevision,promptHash:sha(systemPrompt),challengePromptHash:sha(challengePrompt),provider:config.provider,model:config.model,outputContract:config.structuredOutputs?'native-json-schema':'prompt-json',staticOnly:true,status:'running',entries:structuredClone(previous?.entries || []),events:[],callsThisRun:0,budget,candidateCount:candidateIssues.length,startedAt:new Date().toISOString(),batching:{version:THREAT_BATCH_VERSION,maxCases,requests:0,caseAssessments:0,sharedControlApplications:0,sharedSourceRecords:0,unbatchedInputBytes:0,batchedInputBytes:0},limits:{contextRounds,maxRequestsPerScenario:contextRounds+2,criticalCheck:true}};
 model.threatValidation=report;beginUsageRun(model);const context=securityContext(model);
 const items=candidateIssues.map(issue=>({issue,hash:sha(JSON.stringify(issue))}));
 const oldFor=item=>report.entries.find(e=>e.issueId===item.issue.id&&e.issueHash===item.hash);
 const save=async()=>{
  const counts={selected:items.length,assessed:0,sourceSupported:0,ruledOut:0,needsCodeContext:0,failed:0,unassessed:0};
  for(const item of items){const entry=oldFor(item),field=({'static-supported':'sourceSupported','ruled-out':'ruledOut','needs-context':'needsCodeContext','failed':'failed'})[entry?.assessment]||'unassessed';counts[field]++;if(['sourceSupported','ruledOut','needsCodeContext'].includes(field))counts.assessed++;}
  report.assessmentCounts=counts;await checkpoint?.(report);
 };
 const event=async(type,data)=>{report.events.push({type,at:new Date().toISOString(),...data});if(report.events.length>500)report.events.shift();await trace?.('security.'+type,data);};
 const terminal=e=>e&&(['static-supported','ruled-out'].includes(e.assessment)||e.stopReason==='source-no-longer-matches'||e.stopReason==='no-new-evidence'||e.rounds>=contextRounds+(e.challengeStarted?1:0)+(e.positiveChallengeRefresh?1:0));
 try {
  // A cache or earlier decision never substitutes for unchanged source evidence.
  for(const item of items){const old=oldFor(item);if(old&&['static-supported','ruled-out'].includes(old.assessment))for(const ref of old.evidence || [])try{await sourceWindow({...ref,line:ref.startLine},manifest,sourceRoot);}catch{old.assessment='needs-context';old.missingEvidence=['Source changed or evidence unavailable; rebuild the graph'];old.followUp=[];old.stopReason='source-no-longer-matches';}}
  await save();
  while(report.callsThisRun<budget&&!signal?.aborted){
   const pending=items.filter(i=>!terminal(oldFor(i)));if(!pending.length)break;
   // Finish the independent challenge cohort before expanding initial assessment.
   pending.sort((a,b)=>Number(!!oldFor(b)?.challengeStarted)-Number(!!oldFor(a)?.challengeStarted));
   const challenge=!!oldFor(pending[0])?.challengeStarted;
   const cohort=pending.filter(i=>!!oldFor(i)?.challengeStarted===challenge);
   const failedRounds=Math.max(0,...cohort.filter(i=>oldFor(i)?.assessment==='failed').map(i=>oldFor(i).rounds));
   const prepared=[];
   for(const item of cohort.slice(0,Math.max(1,Math.floor(maxCases/2**failedRounds)))){
    const old=oldFor(item);
    try {
     const packet=await packetBuilder(model,manifest,sourceRoot,item.issue,old?.followUp || [],context,old?.missingEvidence || [],old);
     if(old?.error)packet.previousValidationFailure=old.error;
     if(challenge)packet.decisionChallenge={priorClaim:old.draftAssessment?.engineering?.conclusion || old.engineering?.conclusion,priorImpact:old.draftAssessment?.impact || old.impact,priorConditions:(old.draftAssessment?.engineering?.conditions || old.engineering?.conditions || []).map(({citations,...c})=>c),priorRemediation:old.draftAssessment?.remediation || old.remediation,instruction:'Independently challenge every case and its control applicability from source. The prior decision is a hypothesis; narrow or reject unsupported impact.'};
     const packetHash=sha(JSON.stringify(packet));
     if(old?.packetHash===packetHash&&old.assessment==='needs-context'&&!old.decisionReviewRequired){old.stopReason='no-new-evidence';continue;}
     if(!packet.records.length){const entry={...old,issueId:item.issue.id,sourceId:item.issue.sourceId,issueHash:item.hash,assessment:'needs-context',missingEvidence:['No hash-matched source context available'],stopReason:'no-new-evidence'};report.entries=report.entries.filter(e=>e.issueId!==entry.issueId);report.entries.push(entry);continue;}
     const next={...item,caseId:item.issue.id,packet,old,packetHash};
     // A common source record is evidence sharing, not policy equivalence. No
     // shared window means a separate batch. Size limits split, never omit cases.
     if(prepared.length){const candidate=threatBatch([...prepared,next]);if(!candidate.packet.sharedRecordIds.length||Buffer.byteLength(JSON.stringify(candidate.packet))>160000)break;}
     prepared.push(next);
    }catch(error){const entry={...old,issueId:item.issue.id,sourceId:item.issue.sourceId,issueHash:item.hash,assessment:'failed',error:redact(error.message).slice(0,600),rounds:contextRounds+2};report.entries=report.entries.filter(e=>e.issueId!==entry.issueId);report.entries.push(entry);}
   }
   if(!prepared.length){await save();continue;}
   const batch=threatBatch(prepared),batchId=sha(JSON.stringify([THREAT_BATCH_VERSION,challenge,prepared.map(i=>[i.caseId,i.packetHash])])).slice(0,24);
   let attempt;
   const entries=batch.items.map(({issue,hash,packet,packetHash,old})=>({issueId:issue.id,sourceId:issue.sourceId,origin:issue.origin,issueHash:hash,contextKey,rounds:(old?.rounds || 0)+1,packetHash,retrieval:packet.retrieval,evidenceGaps:packet.gaps,evidence:packet.records.map(({lines,code,...r})=>r),continuationReferences:packet.continuationReferences,followUp:[],missingEvidence:[],assessment:'not-assessed',batchId,...(old?.challengeStarted?{challengeStarted:true,challengePending:true,draftAssessment:old.draftAssessment,...(old.positiveChallengeRefresh?{positiveChallengeRefresh:true}:{})}:{}),history:[...(old?.history || []),...(old?[{assessment:old.assessment,packetHash:old.packetHash,attemptId:old.attemptId,usage:old.usage}]:[])]}));
   for(const entry of entries){report.entries=report.entries.filter(e=>e.issueId!==entry.issueId);report.entries.push(entry);}
   const dispatch=async(url,request)=>{
    signal?.throwIfAborted();attempt=beginAttempt(model,config,batch.packet,{batchId,phase:'security-validation',retry:prepared.some(i=>i.old?.assessment==='failed')});attempt.caseIds=prepared.map(i=>i.caseId);attempt.reviewStage=challenge?'challenge':'assessment';entries.forEach(e=>{e.attemptId=attempt.id;e.sharedUsage=true;});report.callsThisRun++;
    report.batching.requests++;report.batching.caseAssessments+=prepared.length;report.batching.sharedSourceRecords+=batch.stats.sharedRecords;report.batching.unbatchedInputBytes+=batch.stats.originalBytes;report.batching.batchedInputBytes+=batch.stats.batchBytes;
    progress?.(`Section ${challenge?'challenge':'assessment'}: ${prepared.length} related cases, request ${report.callsThisRun}/${budget}`);await event('batch-started',{batchId,attemptId:attempt.id,caseIds:attempt.caseIds,stage:attempt.reviewStage,sharedRecords:batch.stats.sharedRecords});await save();return fetchImpl(url,request);
   };
   try {
    const response=await requestReview(config,batch.packet,dispatch,{systemPrompt:(challenge?challengePrompt:systemPrompt)+THREAT_BATCH_PROMPT,responseSchema:batchSchema(responseSchema),outputTokens:Math.min(16384,8192*Math.max(1,prepared.length)),validate:v=>validateThreatBatch(v,batch,validateResponse),signal,onUsage:async usage=>{attempt.usage=usage;await save();},onResponse:data=>event('batch-response',{batchId,...data})});
    if(attempt){attempt.caseValidationFailures=response.review.results.filter(r=>r.error).map(r=>r.caseId);finishAttempt(attempt,attempt.caseValidationFailures.length?'failed':'succeeded');}
    for(let n=0;n<prepared.length;n++){
     const {old,packet}=prepared[n],entry=entries[n],result=response.review.results.find(r=>r.caseId===entry.issueId);
     if(result?.error){entry.assessment='failed';entry.error=redact(result.error).slice(0,600);continue;}
     Object.assign(entry,result.review,{responseHash:response.responseHash,...(response.localReuse?{localReuse:response.localReuse}:{})});
     report.batching.sharedControlApplications+=entry.sharedControlApplications.length;
     const refresh=entry.assessment==='static-supported'&&old?.challengeStarted&&old.draftAssessment?.assessment!=='static-supported';
     if((entry.assessment==='static-supported'||entry.decisionReviewRequired)&&(!old?.challengeStarted||refresh)){
      if(refresh)entry.positiveChallengeRefresh=true;entry.draftAssessment=structuredClone(result.review);entry.challengeStarted=true;entry.challengePending=true;if(entry.assessment==='static-supported')entry.assessment='not-assessed';
     }else if(old?.challengeStarted){entry.challengePending=false;entry.challengeCompleted=true;if(packet.challengeBasis)entry.challengeBasis=packet.challengeBasis;}
     if(entry.assessment==='needs-context'&&(!entry.followUp.length&&!entry.decisionReviewRequired&&!entry.missingEvidence.some(s=>controlSymbols(s).length)))entry.stopReason='no-new-evidence';
     await event('assessed',{issueId:entry.issueId,batchId,assessment:entry.assessment,attemptId:attempt?.id,localReuse:!!response.localReuse});
    }
    await event('batch-finished',{batchId,failedCases:entries.filter(e=>e.assessment==='failed').length,settledCases:entries.filter(e=>['static-supported','ruled-out'].includes(e.assessment)).length});
   }catch(error){
    if(attempt)finishAttempt(attempt,signal?.aborted?'interrupted':'failed');
    for(const entry of entries){entry.assessment='failed';entry.error=redact(error.message).slice(0,600);if(signal?.aborted){entry.rounds=Math.max(0,entry.rounds-1);entry.stopReason='interrupted';}}
    await event('batch-failed',{batchId,failure:redact(error.message).slice(0,600)});await save();
    if(signal?.aborted||!/^Security assessment failed|^Model did not return the required JSON|^Provider response exhausted/.test(error.message)){report.stopReason='provider-or-source-failure';break;}
   }
   await save();
  }
  report.pending=items.filter(i=>!['static-supported','ruled-out'].includes(oldFor(i)?.assessment)).length;
  report.status=signal?.aborted?'cancelled':report.pending?'partial':items.length?'assessed-needs-review':'no-candidates';
 }catch(error){report.status=signal?.aborted?'cancelled':'failed';report.error=redact(error.message).slice(0,600);}
 finally{report.finishedAt=new Date().toISOString();await save();}
 return report;
}
