import { validateDeploymentGuidance, guidanceForRepositories } from './deployment-guidance.mjs';
import { deploymentArtifact } from './deployment-artifacts.mjs';
import { sourceScope } from './architecture.mjs';
import { id, sha } from './sources.mjs';
import { redact } from './model-review.mjs';
import { coverageStatus } from './coverage-plan.mjs';
import { reviewStageCoverage } from './review-order.mjs';

const clean = value => redact(String(value ?? '')).replace(/[\u0000-\u001f]/g, ' ').slice(0, 1600);
const unique = values => [...new Set(values)];
export const DEPLOYMENT_AREAS = {
  exposure: { name: 'Network access', question: 'Who can reach the listed network entry points?', assumption: 'Assume an untrusted caller can reach the identified network entry points. Internet exposure is not established.', choices: ['Keep the conservative assumption', 'Management network only', 'Authenticated enterprise users', 'Public network access', 'Mixed or unknown'] },
  caller: { name: 'Caller identity', question: 'How is caller identity established for these interfaces?', assumption: 'Do not assume component-level control declarations protect every route. Trace enforcement for each operation.', choices: ['Keep the conservative assumption', 'Each service authenticates callers', 'Gateway establishes identity; services enforce authorization', 'Mixed or unknown'] },
  execution: { name: 'Service authority', question: 'What authority do these services and workers use?', assumption: 'Assume compromise grants the configured process authority; elevated privileges and delegation are not established.', choices: ['Keep the conservative assumption', 'Dedicated least-privilege accounts', 'Shared service account', 'Administrative or system authority', 'Mixed or unknown'] },
  data: { name: 'Data and messaging', question: 'How is access to these databases and messaging resources scoped?', assumption: 'Treat these resources as sensitive. Shared credentials, tenant isolation and effective grants are not established.', choices: ['Keep the conservative assumption', 'Separate identities and scoped permissions', 'Shared identity or broad permissions', 'Mixed or unknown'] },
  transport: { name: 'Transport protection', question: 'What transport protection is configured on these paths?', assumption: 'Do not assume TLS, peer validation or mutual authentication unless the relevant source/configuration supports it.', choices: ['Keep the conservative assumption', 'TLS with peer validation', 'Mutual TLS', 'TLS terminates at a proxy', 'Mixed or unknown'] },
};
function areas(record) {
  const result = [], role = record.connection?.role || '';
  if (/http|rpc|grpc|websocket|network|endpoint/i.test(record.kind + ' ' + record.protocol)) result.push('exposure', 'caller', 'transport');
  if (/worker|execution-identity|entrypoint|process/.test(role) || record.kind === 'privileged-execution') result.push('execution');
  if (/database|messag|queue|broker/i.test(record.kind + ' ' + record.protocol + ' ' + record.operation) || role === 'store-use') result.push('data');
  if (record.kind === 'control') result.push('caller');
  if (record.protocol === 'installation' || /permission|serviceinstall|serviceconfig/i.test(record.operation || '')) result.push('execution');
  return unique(result);
}
export function deploymentContext(model, system) {
  const evidence = new Map(model.evidence.map(e => [e.id, e]));
  const components = new Map((system?.components || model.components).map(c => [c.id, c.name]));
  const groups = new Map();
  for (const record of model.interfaces.filter(r => r.evidence.some(e => sourceScope(evidence.get(e)?.path || '') === 'production-candidate'))) for (const area of areas(record)) {
    const key = area + ':' + record.component;
    const group = groups.get(key) || { id: id('deployment-claim-v1', key), area, componentId: record.component, component: clean(components.get(record.component) || record.component), interfaceIds: [], evidenceIds: [] };
    group.interfaceIds.push(record.id); group.evidenceIds.push(...record.evidence); groups.set(key, group);
  }
  const claims = [...groups.values()].map(c => ({ ...c, evidenceIds: unique(c.evidenceIds), basis: 'source declaration', deploymentStatus: 'not-established', reviewDecision: 'unreviewed' }));
  const profiles = unique(model.evidence.map(e => e.path.match(/(?:appsettings[.]|web[.])([^/.]+)[.](?:json|config)$/i)?.[1]).filter(Boolean)).sort();
  const stored = model.deploymentContext || { version: 1, answers: [], artifacts: [] };
  const requestedProfile = stored.profile || 'Unconfirmed source-defined deployment';
  const staleProfile = requestedProfile !== 'Unconfirmed source-defined deployment' && !profiles.includes(requestedProfile);
  const profile = staleProfile ? 'Unconfirmed source-defined deployment' : requestedProfile;
  const questions = Object.entries(DEPLOYMENT_AREAS).flatMap(([key, definition]) => {
    const members = claims.filter(c => c.area === key);
    if (!members.length) return [];
    const interfaceIds = unique(members.flatMap(c => c.interfaceIds));
    const evidenceIds = unique(members.flatMap(c => c.evidenceIds));
    const fingerprint = sha(JSON.stringify([key, interfaceIds.sort(), evidenceIds.map(i => [i, evidence.get(i)?.blobSha256]) ]));
    const answer = stored.answers?.find(a => a.id === key && a.fingerprint === fingerprint);
    const stale = stored.answers?.some(a => a.id === key && a.fingerprint !== fingerprint);
    const selected = answer?.choice ?? 0;
    const interfaceSet = new Set(interfaceIds);
    const flowIds = (system?.flows || []).filter(f => f.interfaceIds?.some(i => interfaceSet.has(i))).map(f => f.id);
    const flowSet = new Set(flowIds);
    return [{ id: key, ...definition, fingerprint, componentIds: unique(members.map(c => c.componentId)), interfaceIds, evidenceIds, claimIds: members.map(c => c.id), answer: answer || null,
      state: stale && !answer ? 'stale answer; assumption used' : selected === 0 ? 'assumption in use' : 'reported deployment context',
      statement: selected === 0 ? definition.assumption : definition.choices[selected],
      why: `This affects ${definition.name.toLowerCase()} assumptions for the listed components and their threat scenarios.`,
      flowIds,
      boundaryIds: (system?.boundaries || []).filter(b => b.flowIds?.some(id => flowSet.has(id))).map(b => b.id),
      threatIds: (system?.threats || []).filter(t => t.origin !== 'review checklist' && t.interfaceIds?.some(i => interfaceSet.has(i))).map(t => t.id),
    }];
  });
  for (const claim of claims) {
    const question = questions.find(q => q.id === claim.area);
    if (question?.answer?.choice) claim.deploymentStatus = 'reported context; not runtime-verified';
    claim.evidenceBasis = unique(claim.evidenceIds.map(i => {
      const ref = evidence.get(i);
      return /[.]wxs$|[.]wxi$|installer/i.test(ref?.path || '') ? 'installer' : /[.]json$|[.]xml$|[.]config$/i.test(ref?.path || '') ? 'configuration' : 'code';
    }));
  }
  const profileEvidence = model.evidence.filter(e => /appsettings|web[.]|[.]wxs$|[.]wxi$|installer|docker|compose|deployment/i.test(e.path));
  return { version: 1, revision: sha(JSON.stringify([model.modelRevision, stored])), profile, profileStatus: staleProfile ? 'previous profile no longer supported by current source; unconfirmed assumptions used' : 'analysis selection; deployment not verified', profiles, profileEvidenceIds: profileEvidence.map(e => e.id), claims, questions,
    guidanceProfiles:stored.guidanceProfiles || [],activeGuidanceId:stored.activeGuidanceId || '',
    guidanceInterfaceIds:model.interfaces.filter(i=>stored.guidanceProfiles?.find(p=>p.id===stored.activeGuidanceId)?.repositories.includes(i.repository)).map(i=>i.id),
    guidance:guidanceForRepositories(model,model.sources.map(s=>s.name)),
    artifacts: stored.artifacts || [], assumptions: questions.filter(q => !q.answer?.choice).length,
    interpretation: 'Analysis proceeds under explicit assumptions. Answers are reviewer statements, not runtime verification. No answer is required to run STRIDE.' };
}
export function contextForInterfaces(context, ids) {
  const included = new Set(ids);
  return { profile: context.profile, profileStatus: context.profileStatus,
    ...(context.guidance && context.guidanceInterfaceIds.some(id=>included.has(id)) ? {guidance:context.guidance} : {}),
    assumptions: context.questions.filter(q => q.interfaceIds.some(i => included.has(i))).map(q => ({ id: q.id, statement: q.statement, basis: q.answer?.choice ? 'operator-statement; not runtime-verified' : 'assumption', rationale: q.answer?.rationale || '' })),
    artifacts: context.artifacts.map(a => ({ id: a.id, name: a.name, sha256: a.sha256, declarations: a.declarations })),
  };
}
export function updateDeploymentContext(model, input) {
  const context = deploymentContext(model);
  if (input.revision !== context.revision) throw Error('Deployment context changed; refresh before saving');
  const state = structuredClone(model.deploymentContext || { version: 1, answers: [], artifacts: [] });
  let affected, guidanceRepositories;
  if (input.action === 'answer') {
    const question = context.questions.find(q => q.id === input.questionId);
    if (!question || !Number.isInteger(input.choice) || !question.choices[input.choice]) throw Error('Choose a supplied deployment answer');
    if (input.choice && !String(input.reviewer || '').trim()) throw Error('Enter a reviewer for a deployment statement');
    const answer = { id: question.id, fingerprint: question.fingerprint, choice: input.choice, reviewer: clean(input.reviewer), rationale: clean(input.rationale), at: new Date().toISOString() };
    state.answers = [...state.answers.filter(a => a.id !== answer.id), answer];
    affected = [question.id];
  } else if (input.action === 'profile') {
    if (!['Unconfirmed source-defined deployment', ...context.profiles].includes(input.profile)) throw Error('Choose a discovered configuration profile');
    state.profile = input.profile;
    affected = null;
  } else if (input.action === 'artifact') {
    if (state.artifacts.length >= 8) throw Error('At most eight configuration artifacts can be retained');
    const artifact = deploymentArtifact(input);
    state.artifacts = [...state.artifacts.filter(a => a.id !== artifact.id), artifact];
    affected = null;
  } else if(input.action==='guidance') {
    const profile=validateDeploymentGuidance(input.profile,model);
    if(state.activeGuidanceId===profile.id)return model;
    state.guidanceProfiles ||= [];
    if(state.guidanceProfiles.length>=8&&!state.guidanceProfiles.some(p=>p.id===profile.id))throw Error('At most eight guidance profiles; reuse an existing profile');
    state.guidanceProfiles=[...state.guidanceProfiles.filter(p=>p.id!==profile.id),profile];
    guidanceRepositories=[...new Set([...(context.guidance?.repositories || []),...profile.repositories])];
    state.activeGuidanceId=profile.id;affected=null;
  } else if(input.action==='select-guidance') {
    if((state.activeGuidanceId || '')===(input.id || ''))return model;
    if(input.id && !state.guidanceProfiles?.some(p=>p.id===input.id))throw Error('Choose a saved guidance profile');
    guidanceRepositories=[...new Set([...(context.guidance?.repositories || []),...(state.guidanceProfiles?.find(p=>p.id===input.id)?.repositories || [])])];
    state.activeGuidanceId=input.id || '';affected=null;
  } else throw Error('Unsupported deployment context action');
  const next = { ...model, deploymentContext: state };
  // Reviewer identity alone does not change packet content; rationale can change interpretation.
  const before = contextForInterfaces(context, model.interfaces.map(i => i.id));
  const after = contextForInterfaces(deploymentContext(next), model.interfaces.map(i => i.id));
  if (JSON.stringify(before) !== JSON.stringify(after)) invalidateDeploymentReview(next, affected, guidanceRepositories);
  return next;
}
export function invalidateDeploymentReview(model, questionIds, repositories) {
  if (!model.aiReview) return;
  model.aiReview = structuredClone(model.aiReview);
  const review = model.aiReview;
  if (review.reviewScope !== 'system') return; // Legacy review did not consume deployment assumptions.
  const scopedIds=repositories ? new Set(model.interfaces.filter(i=>repositories.includes(i.repository)).map(i=>i.id)) : null;
  const affected = review.batches.filter(b => (!scopedIds || b.interfaceIds?.some(id=>scopedIds.has(id))) && (questionIds === null || b.deploymentQuestionIds?.some(id => questionIds.includes(id))));
  for (const batch of affected) if (batch.status === 'completed') { batch.status = 'stale'; batch.staleReason = 'Deployment assumption changed'; }
  const current = review.batches.filter(b => b.status === 'completed');
  const validIds = new Set(current.map(b => b.id));
  review.threats = (review.threats || []).filter(t => validIds.has(t.batchId));
  review.connections = (review.connections || []).filter(c => validIds.has(c.batchId));
  review.questions = unique(current.flatMap(b => b.review?.questions || []));
  const ids = unique(current.flatMap(b => b.interfaceIds));
  Object.assign(review.coverage, { completedBatches: current.length, failedBatches: review.batches.filter(b => b.status === 'failed').length, reviewedInterfaceIds: ids, reviewedInterfaces: ids.length });
  const reviewed = new Set(ids);
  review.coverage.unreviewedInterfaces = model.interfaces.length - ids.length;
  review.coverage.repositories = model.sources.map(source => {
    const members = model.interfaces.filter(i => i.repository === source.name);
    const count = members.filter(i => reviewed.has(i.id)).length;
    return { repository: source.name, totalInterfaces: members.length, reviewedInterfaces: count, state: source.status !== 'read' ? 'unavailable' : !members.length ? 'no-interfaces' : count === members.length ? 'submitted' : count ? 'partial' : 'not-reviewed' };
  });
  review.coverage.pendingBatches = review.coverage.totalBatches - review.coverage.completedBatches - review.coverage.failedBatches;
  if (review.plan) review.coverage.obligations = coverageStatus(review.plan, review.batches, { details: false });
  review.reviewOrder.stages = reviewStageCoverage(review.plan.batches, review.batches);
  review.status = current.length ? 'partial' : 'stale';
  review.error = 'Deployment assumptions changed; affected results require review. Other compatible results remain saved.';
  review.responseHash = sha(current.map(b => b.responseHash).join(''));
  review.coverageEvidence = { ...review.coverageEvidence, sourceWindows: current.reduce((n, b) => n + (b.evidenceContext?.records.length || 0), 0), unresolved: current.reduce((n, b) => n + (b.evidenceContext?.gaps.length || 0) + (b.review?.explorationRequests?.length || 0), 0), standards: current.flatMap(b => (b.review?.standardsReviews || []).map(r => ({ ...r, batchId: b.id }))) };
}
