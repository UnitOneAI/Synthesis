import {repositoryThreatWire} from './repository-assessment.mjs';
import { enrichGraphModel } from './graph-review.mjs';
import { reviewThreatScenarios, THREAT_RETRIEVAL_VERSION } from './threat-validation.mjs';
import { pocReviewPlan } from './poc-scope.mjs';
import { controlContext, controlSymbols } from './control-context.mjs';
import { prepareStrideEvidence, verifiedStrideSource } from './stride-evidence.mjs';
import { threatAssessment, threatAssessmentLookup } from './threat-validation-state.mjs';
import { sha } from './sources.mjs';

// Single coordinator owns the mutable workspace. Discovery uses the existing
// bounded pool. Engineering dependencies close before the next cohort starts.
export async function reviewFeatureCohorts(model,manifest,config,excerpts,fetchImpl,options={}) {
  const budget=options.maxBatches ?? 12;
  if(!Number.isInteger(budget)||budget<1||budget>100)throw Error('Choose 1–100 combined model requests');
  if(!options.prepareBatch)throw Error('Security-feature review requires explicit source sharing');
  const plan=options.plan || pocReviewPlan(model,excerpts);
  if(plan.scope?.poc?.reviewDepth!=='security-features')throw Error('Save a security-feature scope before running feature cohorts');
  const continuous=options.runUntilComplete===true;
  const batchesById=new Map(plan.batches.map(b=>[b.id,b]));
  const historyCounts=new Map();for(const h of model.featureEvidenceHistory || [])historyCounts.set(h.key,(historyCounts.get(h.key)||0)+1);
  const source=options.verifiedSource || await verifiedStrideSource(model,manifest,options.sourceRoot,options.progress);
  const run={version:1,scopeId:plan.scope.poc.id,status:'running',phase:'planning',calls:0,discoveryCalls:0,engineeringCalls:0,cohorts:0,startedAt:new Date().toISOString(),budget:continuous?null:budget};
  model.featureReviewRun=run;
  const initialAttempts=new Set((model.usageLedger?.attempts || []).map(a=>a.id));
  const save=()=>{
    const attempts=(model.usageLedger?.attempts || []).filter(a=>!initialAttempts.has(a.id));
    run.reportedTokens=attempts.reduce((n,a)=>n+(a.usage?.totalTokens || 0),0);
    run.unknownUsageRequests=attempts.filter(a=>!a.usage).length;
    return options.checkpoint?.(model.aiReview,model.usageLedger);
  };
  const remaining=()=>continuous?100:Math.max(0,budget-run.calls);
  const followCategoryEvidence=async()=>{
    const current=[...(model.aiReview?.batches || [])];
    for(const previous of current) {
      if(!remaining()||options.signal?.aborted||run.stopReason)break;
      const missing=(previous.review?.categoryReviews || []).filter(c=>c.status==='evidence-gap').flatMap(c=>[...new Set([...(c.modelMissingEvidence || []),...(c.missingEvidence || [])])]);
      const symbols=controlSymbols(missing.join(' '));
      if(previous.status!=='completed'||!missing.length)continue;
      const batch=batchesById.get(previous.id);if(!batch)continue;
      const key=sha(JSON.stringify([model.modelRevision,plan.scope.poc.id,batch.id,...(plan.scope?.poc?.kind==='section'?['section-category-3',THREAT_RETRIEVAL_VERSION]:[])]));
      if((historyCounts.get(key)||0)>=(options.categoryFollowUpLimit || 2))continue;
      const seeds=batch.packet.records.flatMap(r=>r.evidence);
      const primary=new Set(batch.packet.reviewUnit.primaryInterfaceIds);
      const threatIds=new Set((model.aiReview.threats || []).filter(t=>t.interfaceIds.some(id=>primary.has(id))).map(t=>t.id));
      const resolved=(model.threatValidation?.entries || []).filter(t=>threatIds.has(t.sourceId)).flatMap(t=>(t.engineering?.obligations || []).flatMap(o=>o.citations || [])).map(r=>({...r,line:r.startLine}));
      const controls=await controlContext(source,seeds,missing.join(' '));
      const fallback=await source.findImplementation(symbols,seeds);
      const prepared=await prepareStrideEvidence(batch.packet,source,{sectionEvidence:plan.scope?.poc?.kind==='section',references:[...seeds,...resolved.map(r=>({...r,required:true})),...fallback.references.map(r=>({...r,required:false})),...controls.references],priorReview:{...(plan.scope?.poc?.kind==='section'?{retainedThreats:previous.review.threats.map(repositoryThreatWire),engineeringConclusions:(model.threatValidation?.entries || []).filter(t=>threatIds.has(t.sourceId)).map(t=>({sourceId:t.sourceId,assessment:t.assessment,conclusion:t.engineering?.conclusion,basis:'Prior conclusion; fresh source citations must support the category decision.'}))}:{}),previousUnresolvedItems:missing,instruction:'Reassess each previous unresolved item; the earlier classification may be wrong. Resolve implementation questions from the newly supplied source. Keep actual missing bindings in missingEvidence, and effective deployment/access/policy questions in deploymentConditions. Do not copy the earlier unresolved list unchanged. Prior output is a hypothesis, never evidence. Reassess all six categories and preserve unaffected supported conclusions with citations. For EVERY primary operation, cite its handler source in EACH category, including no-scenario and ruled-out decisions. All operations must be covered; a citation to one route does not review its siblings. Code facts are resolved from cited handlers, registration and helpers; effective network exposure and operator policy belong in deploymentConditions, not missingEvidence.'}});
      prepared.context.categoryClosure=plan.scope?.poc?.kind==='section'?{version:'retain-cases-1',retainedIds:previous.review.threats.map(t=>t.id),promptHash:sha(JSON.stringify(prepared.packet.sourceContext.priorReview))}:null;
      const followUpKey=sha(JSON.stringify([prepared.context.fingerprint,missing]));
      if((model.featureEvidenceHistory || []).some(h=>h.key===key&&h.followUpKey===followUpKey))continue;
      // Retain the paid prior result before a forced evidence reassessment.
      model.featureEvidenceHistory=[...(model.featureEvidenceHistory || []),{key,followUpKey,batchId:batch.id,previous,at:new Date().toISOString()}];
      historyCounts.set(key,(historyCounts.get(key)||0)+1);
      run.phase='category evidence';options.progress?.('Following exact missing category controls before expanding discovery');await save();
      await enrichGraphModel(model,config,excerpts,fetchImpl,{...options,plan,runUntilComplete:false,maxBatches:1,concurrency:1,
        batchIds:[batch.id],forceBatchIds:[batch.id],prepareBatch:async()=>prepared,checkpoint:save});
      const count=model.aiReview.coverage.callsThisRun;run.calls+=count;run.engineeringCalls+=count;
      if(['provider-failure','repeated-response-format-failure','cancelled','time-budget'].includes(model.aiReview.stopReason))run.stopReason=model.aiReview.stopReason;
      const attempted=model.aiReview.batches.find(b=>b.id===batch.id);
      if(attempted?.status==='failed') {
        model.featureEvidenceHistory.at(-1).failure={error:attempted.error,attemptId:attempted.attemptId};
        // A failed follow-up does not erase a successful paid discovery result.
        await enrichGraphModel(model,config,excerpts,fetchImpl,{...options,plan,runUntilComplete:false,maxBatches:1,
          recoveredBatches:[previous],batchIds:[],checkpoint:save});
      }
    }
  };
  const settle=async()=>{
    if(!remaining()||!model.aiReview?.coverage?.completedBatches||!model.aiReview.threats?.length)return;
    const assessmentLookup=threatAssessmentLookup(model);
    const threatIds=model.aiReview.threats.filter(t=>{
      const a=threatAssessment(model,t.id,assessmentLookup);
      if(a.assessment==='static-supported'&&!a.challengeCompleted)return true;
      return !['static-supported','ruled-out'].includes(a.assessment) && !(model.threatValidation?.retrievalVersion===THREAT_RETRIEVAL_VERSION && a.assessment==='needs-context' && (a.rounds>=(plan.scope?.poc?.kind==='section'?5:3) || a.stopReason==='no-new-evidence'));
    }).map(t=>t.id);
    if(!threatIds.length)return;
    run.phase='engineering';options.progress?.('Following code and controls before the next discovery cohort');
    const priorEntries=new Map((model.threatValidation?.entries || []).map(e=>[e.sourceId,JSON.stringify(e)]));
    const baseCalls=run.calls,baseEngineering=run.engineeringCalls;
    const engineeringCheckpoint=async()=>{run.calls=baseCalls+(model.threatValidation?.callsThisRun || 0);run.engineeringCalls=baseEngineering+(model.threatValidation?.callsThisRun || 0);await save();};
    const result=await reviewThreatScenarios(manifest,model,{sourceRoot:options.sourceRoot,config,budget:remaining(),runUntilComplete:false,finishCaseFirst:true,contextRounds:plan.scope?.poc?.kind==='section'?5:3,threatIds,
      fetchImpl,signal:options.signal,trace:options.trace,progress:options.progress,checkpoint:engineeringCheckpoint});
    run.engineeringCalls=baseEngineering+result.callsThisRun;run.calls=baseCalls+result.callsThisRun;
    if(result.status==='failed'||result.entries.some(e=>JSON.stringify(e)!==priorEntries.get(e.sourceId) && e.assessment==='failed' && !/^Security assessment failed|^Model did not return the required JSON|^Security packet metadata/.test(e.error || '')))run.stopReason='provider-or-source-failure';
    return result;
  };
  try {
    if(plan.scope?.poc?.kind==='section'&&model.aiReview?.scope?.poc?.id===plan.scope.poc.id) {
      const recoveries=new Map();
      for(const h of [...(model.featureEvidenceHistory || [])].reverse()) {
        const current=model.aiReview.batches.find(b=>b.id===h.batchId),planned=batchesById.get(h.batchId);
        if(current&&current.status!=='completed'&&planned&&h.previous?.status==='completed'&&h.previous.packetHash===planned.packetHash&&!recoveries.has(h.batchId))recoveries.set(h.batchId,h.previous);
      }
      if(recoveries.size)await enrichGraphModel(model,config,excerpts,fetchImpl,{...options,plan,runUntilComplete:false,maxBatches:1,recoveredBatches:[...recoveries.values()],batchIds:[],checkpoint:save});
    }
    // A saved cohort may have completed discovery but not its engineering work.
    if(model.aiReview?.scope?.poc?.id===plan.scope.poc.id){if(plan.scope?.poc?.kind==='section')await settle();if(!run.stopReason)await followCategoryEvidence();if(!run.stopReason)await settle();}
    while(remaining()&&!run.stopReason&&!options.signal?.aborted) {
      const before=model.aiReview?.scope?.poc?.id===plan.scope.poc.id ? model.aiReview?.coverage?.completedBatches || 0 : 0;
      run.phase='discovery';run.cohorts++;
      await enrichGraphModel(model,config,excerpts,fetchImpl,{...options,plan,runUntilComplete:false,
        maxBatches:Math.min(remaining(),options.concurrency || 2,4),recoverFailures:plan.scope?.poc?.kind==='section',checkpoint:save});
      const discoveryCalls=model.aiReview.coverage?.callsThisRun;
      if(!Number.isFinite(discoveryCalls))throw Error('Discovery request accounting unavailable');
      run.calls+=discoveryCalls;run.discoveryCalls+=discoveryCalls;
      const reason=model.aiReview.stopReason;
      if(['provider-failure','repeated-response-format-failure','cancelled','time-budget'].includes(reason)){run.stopReason=reason;break;}
      if(plan.scope?.poc?.kind==='section')await settle();
      if(!run.stopReason)await followCategoryEvidence();if(!run.stopReason)await settle();
      if(!run.stopReason && plan.scope?.poc?.kind==='section'){await followCategoryEvidence();if(!run.stopReason)await settle();}
      await save();
      if(!model.aiReview.coverage.pendingBatches) {
        if(plan.scope?.poc?.kind==='section' && model.aiReview.coverage.failedBatches && run.cohorts<3) {options.progress?.('Retrying failed section packets with validation feedback; successful packets remain saved');continue;}
        if(plan.scope?.poc?.kind==='section')for(let pass=0;pass<3&&!run.stopReason&&remaining()&&!options.signal?.aborted;pass++) {
          const beforeFollow=run.calls;
          await followCategoryEvidence();if(!run.stopReason)await settle();await save();
          if(run.calls===beforeFollow)break;
        }
        run.stopReason ||= model.aiReview.coverage.failedBatches?'discovery-failures':'planned-discovery-finished';break;
      }
      if(model.aiReview.coverage.completedBatches<=before){run.stopReason='no-new-completed-discovery';break;}
    }
    run.stopReason=options.signal?.aborted?'cancelled':run.stopReason||'request-budget';
    run.status=run.stopReason==='planned-discovery-finished'?'discovery-finished':'partial';
  } catch(error) {run.status='failed';run.stopReason='coordinator-failure';run.error=error.message;throw error;}
  finally {run.finishedAt=new Date().toISOString();await save();}
  return model;
}
