import {systemModel} from './system-model.mjs';
import {deploymentContext} from './deployment-context.mjs';
import {interfacePriorities} from './review-order.mjs';
import {automaticSectionPlan,sectionReviewPlan,sectionCompletion,sectionContextKey} from './automatic-sections.mjs';
import {reviewFeatureCohorts} from './feature-review-run.mjs';
import {verifiedStrideSource} from './stride-evidence.mjs';

// One writer; the existing provider pool is shared inside each section. Store
// each section before moving the active projection. No review confirmation gate.
export async function reviewAutomaticSections(model,manifest,config,excerpts,fetchImpl,options={}) {
 if(!options.prepareBatch)throw Error('Automatic section review requires approved source sharing');
 const maxSections=options.maxSections ?? Number.MAX_SAFE_INTEGER;
 if(!Number.isSafeInteger(maxSections)||maxSections<1)throw Error('Invalid section count');
 const plan=automaticSectionPlan(model,options);
 if(model.automaticSections?.plan.id!==plan.id) {
  if(model.automaticSections)model.automaticSectionHistory=[...(model.automaticSectionHistory || []),model.automaticSections].slice(-2);
  model.automaticSections={plan,results:{},previous:{aiReview:model.aiReview,threatValidation:model.threatValidation,pocScope:model.pocScope}};
 }
 const state=model.automaticSections;
 const run={status:'running',activeSection:null,sectionsAttempted:0,completedThisRun:0,blockedThisRun:0,startedAt:new Date().toISOString()};state.run=run;
 const checkpoint=()=>options.checkpoint?.(model.aiReview,model.usageLedger);
 let source;
 try {
  source=options.verifiedSource || await verifiedStrideSource(model,manifest,options.sourceRoot,options.progress);
  const staticSystem=systemModel({...model,aiReview:undefined},{matrix:false});
  const staticContext={system:staticSystem,deployment:deploymentContext(model,staticSystem),priorities:interfacePriorities(model,staticSystem)};
  for(const section of plan.sections) {
   if(options.signal?.aborted){run.status='interrupted';break;}
   if(run.sectionsAttempted>=maxSections)break;
   const saved=state.results[section.id];
   if(saved?.status==='complete') {
    const prior={...model,aiReview:saved.review,threatValidation:saved.validation};
    if(sectionCompletion(prior,section).complete)continue;
   }
   if(saved?.status==='blocked'&&!options.retryBlocked)continue;
   run.activeSection=section.id;run.sectionsAttempted++;
   const result=saved || {status:'pending',calls:0,reportedTokens:0,unknownUsageRequests:0};state.results[section.id]=result;
   const priorReview=model.aiReview;
   if(priorReview && priorReview.scope?.poc?.kind!=='section') {
    const key=priorReview.scope?.poc?'poc:'+priorReview.scope.poc.id:priorReview.reviewScope==='system'?'system':'deep';
    model.savedStrideScopes={...model.savedStrideScopes,[key]:priorReview};
   }
   model.aiReview=result.review;model.threatValidation=result.validation;
   const preparedPlan=sectionReviewPlan(model,section,excerpts,staticContext);
   const beforeAttempts=new Set((model.usageLedger?.attempts || []).map(a=>a.id));
   const save=async()=>{
    result.review=model.aiReview;result.validation=model.threatValidation;result.featureRun=model.featureReviewRun;result.phase=model.featureReviewRun?.phase;
    const ledger=model.usageLedger?.attempts || [];
    const attempts=ledger.filter(a=>!beforeAttempts.has(a.id));
    result.attemptIds=[...new Set([...(result.attemptIds || []),...attempts.map(a=>a.id)])];
    const owned=new Set(result.attemptIds),total=ledger.filter(a=>owned.has(a.id));
    result.calls=total.length;result.reportedTokens=total.reduce((n,a)=>n+(a.usage?.totalTokens || 0),0);result.unknownUsageRequests=total.filter(a=>!a.usage).length;
    result.actionCalls=attempts.length;result.actionTokens=attempts.reduce((n,a)=>n+(a.usage?.totalTokens || 0),0);result.actionUnknown=attempts.filter(a=>!a.usage).length;
    await checkpoint();
   };
   result.status='running';await save();
   options.progress?.(`Section ${run.sectionsAttempted}: ${section.title}. ${section.interfaceIds.length} operations; all six STRIDE categories.`);
   await options.trace?.('section.started',{sectionId:section.id,title:section.title,interfaceIds:section.interfaceIds,contextKey:plan.contextKey});
   await reviewFeatureCohorts(model,manifest,config,excerpts,fetchImpl,{...options,plan:preparedPlan,verifiedSource:source,runUntilComplete:true,maxBatches:100,checkpoint:save,categoryFollowUpLimit:3});
   result.completion=sectionCompletion(model,section);
   const reason=model.featureReviewRun?.stopReason;
   const failure=['provider-failure','provider-or-source-failure','coordinator-failure','repeated-response-format-failure'].includes(reason);
   result.status=result.completion.complete?'complete':failure?'failed':options.signal?.aborted?'interrupted':'blocked';
   result.stopReason=reason;result.finishedAt=new Date().toISOString();
   await save();
   if(result.status==='complete')run.completedThisRun++;else run.blockedThisRun++;
   await options.trace?.('section.finished',{sectionId:section.id,status:result.status,calls:result.actionCalls,reportedTokens:result.actionTokens,unknownUsageRequests:result.actionUnknown,blockerCount:result.completion.blockers.length});
   await checkpoint();
   if(failure){run.status='failed';break;}
  }
  if(run.status==='running')run.status=plan.sections.every(s=>state.results[s.id]?.status==='complete')?'complete':run.sectionsAttempted>=maxSections?'section-limit':'finished-with-blockers';
 } catch(error) {
  run.status='failed';run.error=error.message;
  const result=state.results[run.activeSection];if(result?.status==='running'){result.status='failed';result.error=error.message;result.review=model.aiReview;result.validation=model.threatValidation;}
  throw error;
 } finally {run.finishedAt=new Date().toISOString();run.activeSection=null;await checkpoint();}
 return model;
}
