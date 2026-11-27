import { sha } from './sources.mjs';
import { sourceScope } from './architecture.mjs';
export const THREAT_VALIDATION_VERSION = 'threat-control-review-6';
export function threatValidationKey(model) {
  return sha(JSON.stringify([THREAT_VALIDATION_VERSION, model.modelRevision, model.sourceGraph?.fingerprint, model.architecture, model.deploymentContext]));
}
export function threatIssue(model, threat, evidence = new Map(model.evidence.map(e => [e.id, e]))) {
  return {
    id: threat.id, sourceId: threat.id, origin: 'stride', kind: 'security-design', cwe: null,
    title: threat.title, explanation: threat.scenario, preconditions: threat.prerequisites,
    controls: threat.controls, analysis: threat.analysis,
    locations: threat.evidenceIds.map(id => evidence.get(id)).filter(Boolean).map(e => ({ repository: e.repository, path: e.path, line: e.line, blobSha256: e.blobSha256, sourceScope: sourceScope(e.path) })),
    evidenceIds: threat.evidenceIds, interfaceIds: threat.interfaceIds, sourceOnly: true,
  };
}
// Build once per synchronous projection; never retain across model mutations.
export function threatAssessmentLookup(model) {
  return {threats:new Map((model.aiReview?.threats || []).map(t=>[t.id,t])),
    entries:new Map((model.threatValidation?.entries || []).map(e=>[e.sourceId,e])),
    evidence:new Map(model.evidence.map(e=>[e.id,e])),contextKey:threatValidationKey(model)};
}
export function threatAssessment(model, threatId, lookup) {
  const threat = lookup ? lookup.threats.get(threatId) : model.aiReview?.threats?.find(t => t.id === threatId);
  const entry = lookup ? lookup.entries.get(threatId) : model.threatValidation?.entries?.find(e => e.sourceId === threatId);
  if (!entry) return { assessment: 'not-assessed' };
  if (!threat || model.aiReview?.status === 'stale' || (model.aiReview?.basedOnRevision && model.aiReview.basedOnRevision !== model.modelRevision) || model.threatValidation.contextKey !== (lookup?.contextKey || threatValidationKey(model)) || entry.issueHash !== sha(JSON.stringify(threatIssue(model, threat,lookup?.evidence))))
    return { assessment: 'stale', previousAssessment: entry.assessment };
  return entry;
}
