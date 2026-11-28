import { sha } from './sources.mjs';
import { redact } from './model-review.mjs';
import { threatAssessment, threatAssessmentLookup, threatValidationKey } from './threat-validation-state.mjs';

// Consequences are deliberately scoped and deterministic. A declaration is not
// runtime verification, and one answer never establishes the whole attack.
export function questionPresentation(engineering, question) {
  const condition=engineering?.conditions?.find(c=>c.id===question.conditionId);
  if(!condition) return {...question,conditionStatus:'Legacy question; consequences were not consistency-checked',
    ifYes:'Record yes for this question only. Reconcile the original interpretation with the cited path before changing threat applicability.',
    ifNo:'Record no for this question only. This does not clear other actors, routes or controls.',
    originalInterpretation:{ifYes:question.ifYes,ifNo:question.ifNo}};
  const applies=`The declared answer matches the required condition for ${condition.scope}. Other prerequisites and the code assessment still apply; exploitation is not established.`;
  const absent=`The declared answer does not match this prerequisite for ${condition.scope}. This particular conditional scenario is not applicable under that answer; other paths and actors are not cleared.`;
  return {...question,question:condition.statement,scope:condition.scope,condition,
    conditionStatus:engineering.consistency?.status==='consistent'?'Structured condition; model consistency review recorded, not deployment verification':'Condition consistency unresolved',
    ifYes:condition.requiredAnswer==='yes'?applies:absent,ifNo:condition.requiredAnswer==='no'?applies:absent};
}

export function deploymentDecisionQuestions(model) {
  const profile=model.aiReview?.scope?.poc?.profile || model.deploymentContext?.profile || 'Unspecified deployment profile';
  const questions=[],assessmentLookup=threatAssessmentLookup(model);
  for(const threat of model.aiReview?.threats || []) {
    const assessment=threatAssessment(model,threat.id,assessmentLookup);
    if(!['static-supported','ruled-out'].includes(assessment.assessment))continue;
    for(const q of assessment.engineering?.reviewerQuestions || []) {
      const id=sha(JSON.stringify([threat.id,threatValidationKey(model),assessment.responseHash,assessment.issueHash,assessment.assessment,assessment.engineering.conditions ? [q,assessment.engineering.conditions.find(c=>c.id===q.conditionId)] : q,profile])).slice(0,24);
      const answers=(model.deploymentAnswers || []).filter(a=>a.questionId===id);
      const answer=answers.at(-1);
      const presented=questionPresentation(assessment.engineering,q);
      questions.push({id,threatId:threat.id,title:assessment.engineering.conclusion,profile,...presented,
        answer:answer || null,consequence:answer?.answer==='yes'?presented.ifYes:answer?.answer==='no'?presented.ifNo:'Deployment condition remains unresolved.'});
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
