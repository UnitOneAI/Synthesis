import { sha } from './sources.mjs';
import { redact } from './model-review.mjs';
import { threatAssessment, threatAssessmentLookup, threatValidationKey } from './threat-validation-state.mjs';

export function deploymentDecisionQuestions(model) {
  const profile=model.aiReview?.scope?.poc?.profile || model.deploymentContext?.profile || 'Unspecified deployment profile';
  const questions=[],assessmentLookup=threatAssessmentLookup(model);
  for(const threat of model.aiReview?.threats || []) {
    const assessment=threatAssessment(model,threat.id,assessmentLookup);
    if(!['static-supported','ruled-out'].includes(assessment.assessment))continue;
    for(const q of assessment.engineering?.reviewerQuestions || []) {
      const id=sha(JSON.stringify([threat.id,threatValidationKey(model),assessment.responseHash,assessment.issueHash,assessment.assessment,q,profile])).slice(0,24);
      const answers=(model.deploymentAnswers || []).filter(a=>a.questionId===id);
      const answer=answers.at(-1);
      questions.push({id,threatId:threat.id,title:assessment.engineering.conclusion,profile,...q,
        answer:answer || null,consequence:answer?.answer==='yes'?q.ifYes:answer?.answer==='no'?q.ifNo:'Deployment condition remains unresolved.'});
    }
  }
  return questions;
}
export function recordDeploymentAnswer(model,input) {
  if(input.modelRevision!==model.modelRevision)throw Error('Refresh the current source snapshot');
  const q=deploymentDecisionQuestions(model).find(q=>q.id===input.questionId);
  if(!q)throw Error('Question is no longer current; refresh the review');
  if(!['yes','no','unknown'].includes(input.answer))throw Error('Choose yes, no or unknown');
  const clean=(v,max)=>{if(typeof v!=='string'||!v.trim()||v.length>max)throw Error('A bounded reviewer name and rationale are required');return redact(v.trim());};
  const entry={questionId:q.id,threatId:q.threatId,answer:input.answer,reviewer:clean(input.reviewer,200),rationale:clean(input.rationale,2000),profile:q.profile,at:new Date().toISOString(),basis:'reviewer declaration; not runtime verification'};
  if((model.deploymentAnswers || []).length>=10000)throw Error('Reviewer answer history limit reached; export and archive before continuing');
  return {...model,deploymentAnswers:[...(model.deploymentAnswers||[]),entry]};
}
