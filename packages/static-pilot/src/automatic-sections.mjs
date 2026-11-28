import {sha} from './sources.mjs';
import {sourceScope} from './architecture.mjs';
import {securityFeatureSubject} from './repository-scope.mjs';
import {systemReviewPlan} from './system-review-units.mjs';
import {REPOSITORY_CATEGORIES} from './repository-assessment-summary.mjs';
import {threatAssessment,threatAssessmentLookup,threatValidationKey} from './threat-validation-state.mjs';
import {GUIDANCE_HASH} from './analysis-guidance.mjs';

export const SECTION_VERSION='automatic-sections-1';
const profile='Static review assumption: an untrusted caller outside the component boundary, an ordinary authenticated user, and a compromised permitted peer are considered where relevant. Production network exposure and effective privileges are unverified. Assess all six STRIDE categories; trace downstream controls across supporting repositories.';
export const sectionContextKey=model=>sha(JSON.stringify([SECTION_VERSION,model.modelRevision,model.sourceGraph?.fingerprint,threatValidationKey(model),GUIDANCE_HASH]));

// No model calls, graph scans or full portfolio packet construction. Grouping is
// a navigation hint only; every member retains six individual review obligations.
export function automaticSectionPlan(model, options={}) {
 const repositories=[...new Set(options.repositories || (model.pocScope?.kind==='repositories'?model.pocScope.repositories:model.sources.map(s=>s.name)))].sort();
 if(!repositories.length||repositories.some(r=>!model.sources.some(s=>s.name===r)))throw Error('Automatic sections require loaded primary repositories');
 const limit=options.operationsPerSection ?? 3;
 if(!Number.isInteger(limit)||limit<1||limit>4)throw Error('Automatic sections allow 1–4 operations per section');
 const evidence=new Map(model.evidence.map(e=>[e.id,e])),groups=new Map(),selected=new Set(repositories);
 let contextOnly=0;
 for(const i of model.interfaces) {
  if(!selected.has(i.repository))continue;
  if(!securityFeatureSubject(i)){contextOnly++;continue;}
  const refs=i.evidence.map(id=>evidence.get(id)).filter(Boolean);
  const file=refs[0]?.path || 'unmapped-source';
  const production=refs.some(r=>sourceScope(r.path)==='production-candidate');
  const route=i.connection?.path || (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i.exec(i.operation || '')?.[1]);
  const parts=route?.split('/').filter(p=>p&&!/^v\d+$|^api$/i.test(p)) || [];
  const family=parts.filter(p=>!/[{:]/.test(p)).slice(0,2).join('/') || route || i.connection?.role || i.kind;
  const method=i.connection?.method || String(i.operation).split(' ')[0];
  const behavior=/^(GET|HEAD|OPTIONS)$/i.test(method)?'read':route?'change':i.direction;
  const key=JSON.stringify([i.repository,i.component,file,family,behavior,production]);
  if(!groups.has(key))groups.set(key,{repository:i.repository,component:i.component,file,family,behavior,production,members:[]});
  groups.get(key).members.push(i);
 }
 const sections=[];
 for(const g of groups.values()) {
  g.members.sort((a,b)=>String(a.operation).localeCompare(String(b.operation))||a.id.localeCompare(b.id));
  for(let at=0;at<g.members.length;at+=limit) {
   const members=g.members.slice(at,at+limit),ids=members.map(i=>i.id).sort();
   const external=members.some(i=>i.direction==='inbound');
   const sensitive=/auth|login|token|session|admin|setting|config|upload|export|secret|credential/i.test(g.family+' '+members.map(i=>i.operation).join(' '));
   const priority=(g.production?0:100)+(external?0:30)+(sensitive?0:10);
   const title=`${g.repository} · ${g.family} · ${g.behavior}${g.members.length>limit?' · part '+(1+at/limit):''}`;
   sections.push({id:sha(JSON.stringify([SECTION_VERSION,g.repository,g.component,g.file,g.family,g.behavior,ids])).slice(0,24),title,repository:g.repository,sourcePath:g.file,
    interfaceIds:ids,operations:members.map(i=>({id:i.id,name:i.operation || i.name || i.kind,repository:i.repository,path:g.file})),priority,
    basis:external?'Potential entry surface; external reachability is an assumption, not a verified network fact.':'Internal/resource/configuration surface retained for review.',
    grouping:'Shared source owner, route family and operation behavior; common control enforcement must still be established for each operation.',
    profile,sourceScope:g.production?'production-candidate':'supporting/test',status:'pending'});
  }
 }
 if(!sections.length)throw Error('No security operations are available in the selected repository graph; inspect source coverage before review');
 sections.sort((a,b)=>a.priority-b.priority||a.title.localeCompare(b.title)||a.id.localeCompare(b.id));
 const contextKey=sectionContextKey(model);
 return {version:SECTION_VERSION,id:sha(JSON.stringify([contextKey,repositories,limit,sections.map(s=>s.id)])).slice(0,24),contextKey,repositories,operationsPerSection:limit,
  supportingRepositories:model.sources.filter(s=>!selected.has(s.name)).map(s=>s.name),sections,
  primaryOperations:sections.reduce((n,s)=>n+s.interfaceIds.length,0),contextOnly,
  interpretation:'Every planned operation belongs to exactly one section. Other loaded source remains available for control/path investigation. Grouping does not establish equivalent policy. Complete means static assessment of the named operations, not deployment verification or whole-repository clearance.'};
}
export function sectionReviewPlan(model,section,excerpts=new Map(),staticContext) {
 const plan=systemReviewPlan(model,excerpts,{interfaceIds:section.interfaceIds,profile:section.profile,repositoryScope:true,staticContext});
 const covered=new Set(plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds));
 if(section.interfaceIds.some(id=>!covered.has(id))||plan.omitted.length)throw Error('Section operation cannot fit the source packet; no operation was removed');
 plan.scope.poc={kind:'section',id:section.id,title:section.title,profile:section.profile,interfaceIds:section.interfaceIds,operations:section.operations.map(o=>({repository:o.repository,pathContains:o.path})),operationGroups:section.interfaceIds.length,reviewDepth:'security-features',repositories:[section.repository]};
 plan.scope.version+=':'+SECTION_VERSION;
 for(const batch of plan.batches)batch.packet.reviewFocus.sectionBoundary='These primary operations form one automatic review section. Follow their actual controls and downstream operations across repositories. Do not expand discovery to unrelated endpoints or defer an in-scope control because it lives in another repository. Deployment uncertainty is separate from missing implementation.';
 // Packet identity must include the section-specific investigation instructions.
 for(const batch of plan.batches){batch.packetHash=sha(JSON.stringify(batch.packet)); /* IDs remain stable subject IDs; packetHash controls reuse. */}
 return plan;
}
const settledThreat=t=>{
 const e=t.engineering,ob=e?.obligations || [];
 if(e?.version!==2||e.consistency?.status!=='consistent'||ob.length!==4||new Set(ob.map(o=>o.kind)).size!==4)return false;
 if(t.assessment==='static-supported')return t.challengeCompleted===true&&t.draftAssessment?.assessment==='static-supported'&&ob.every(o=>o.status==='established'&&o.citations?.length);
 return t.assessment==='ruled-out'&&ob.some(o=>o.status==='blocks-attack'&&o.citations?.length);
};
export function sectionCompletion(model,section) {
 const review=model.aiReview, blockers=[],categories=[];
 if(!review||review.scope?.poc?.id!==section.id||review.status==='stale'||review.basedOnRevision!==model.modelRevision||JSON.stringify([...(review.scope?.poc?.interfaceIds || [])].sort())!==JSON.stringify([...section.interfaceIds].sort()))blockers.push('No current review for this exact section');
 const batches=review?.batches || [];
 const lookup=threatAssessmentLookup(model);
 const decisions=(review?.threats || []).map(t=>({id:t.id,title:t.title,...threatAssessment(model,t.id,lookup)}));
 for(const t of decisions)if(!settledThreat(t))blockers.push(`Threat ${t.id}: ${t.assessment==='static-supported'?'critical review pending':t.assessment}`);
 for(const category of REPOSITORY_CATEGORIES) {
  const operations=section.interfaceIds.map(id=>{
   const containing=batches.filter(b=>(b.interfaceIds || b.review?.categoryReviews?.flatMap(c=>c.interfaceIds) || []).includes(id));
   const results=containing.flatMap(b=>(b.review?.categoryReviews || []).filter(c=>c.category===category&&c.interfaceIds.includes(id)).map(c=>({...c,batchStatus:b.status,batchId:b.id})));
   const complete=results.length>0&&containing.every(b=>b.status==='completed')&&results.every(r=>['supported-conditional','ruled-out','no-scenario-identified'].includes(r.status)&&!r.missingEvidence?.length&&r.citations?.length>0);
   if(!complete)blockers.push(`${section.operations.find(o=>o.id===id)?.name || id} / ${category}: ${results.flatMap(r=>r.missingEvidence || []).join('; ') || 'cited category assessment pending'}`);
   return {id,name:section.operations.find(o=>o.id===id)?.name || id,complete,results};
  });
  categories.push({category,complete:operations.every(o=>o.complete),operations});
 }
 if(!batches.length||batches.some(b=>b.status!=='completed')||review?.coverage?.pendingBatches||review?.coverage?.failedBatches)blockers.push('Discovery packets are pending or failed');
 return {complete:blockers.length===0&&section.interfaceIds.length>0,blockers:[...new Set(blockers)],categories,
  supported:decisions.filter(t=>t.assessment==='static-supported'&&settledThreat(t)).length,ruledOut:decisions.filter(t=>t.assessment==='ruled-out'&&settledThreat(t)).length,
  pendingThreats:decisions.filter(t=>!settledThreat(t)).length,
  interpretation:'Completion covers code assessments for these operations and all six categories. Conditional deployment prerequisites remain explicit; no runtime test or organizational approval is claimed.'};
}
export function sectionModel(model,id) {
 const state=model.automaticSections,section=state?.plan.sections.find(s=>s.id===id),result=state?.results[id];
 if(!section||!result?.review)throw Error('No saved review for this section');
 const active=model.aiReview?.scope?.poc?.id===id;
 const view={...model,aiReview:active?model.aiReview:result.review,threatValidation:active?model.threatValidation:result.validation,featureReviewRun:result.featureRun};
 const completion=sectionCompletion(view,section);
 if(state.plan.contextKey!==sectionContextKey(model)){completion.complete=false;completion.blockers.unshift('Source, architecture or deployment context changed; revalidation required');}
 return {view,section,completion};
}
export function syncAutomaticSectionProjection(model) {
 const state=model?.automaticSections,id=model?.aiReview?.scope?.poc?.id,result=state?.results[id];
 if(!result||!['complete','blocked'].includes(result.status)||state.run?.status==='running'||!state.plan.sections.some(s=>s.id===id))return;
 result.review=model.aiReview;result.validation=model.threatValidation;
 result.completion=sectionCompletion(model,state.plan.sections.find(s=>s.id===id));
 if(state.plan.contextKey!==sectionContextKey(model))result.status='stale';
 else result.status=result.completion.complete?'complete':'blocked';
}
export function automaticSectionSummary(model) {
 const state=model.automaticSections;if(!state)return null;
 const stale=state.plan.contextKey!==sectionContextKey(model);
 return {...state.plan,sections:state.plan.sections.map(s=>{const r=state.results[s.id];return {...s,status:stale&&r?'stale':r?.status || 'pending',completion:r?.completion?{complete:r.completion.complete,supported:r.completion.supported,ruledOut:r.completion.ruledOut,pendingThreats:r.completion.pendingThreats,blockers:r.completion.blockers,categories:r.completion.categories.map(c=>({category:c.category,complete:c.complete}))}:undefined,phase:r?.phase,calls:r?.calls || 0,reportedTokens:r?.reportedTokens || 0,unknownUsageRequests:r?.unknownUsageRequests || 0};}),run:state.run,stale};
}
export function interruptAutomaticSections(model,reason='interrupted') {
 const state=model?.automaticSections;if(state?.run?.status!=='running')return;
 const result=state.results[state.run.activeSection];
 state.run.status='interrupted';state.run.stopReason=reason;
 if(result?.status==='running'){result.status='interrupted';result.stopReason=reason;result.review=model.aiReview;result.validation=model.threatValidation;}
 state.run.activeSection=null;
}
