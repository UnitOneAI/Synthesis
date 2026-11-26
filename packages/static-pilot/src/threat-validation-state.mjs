import { sha } from './sources.mjs';
import { sourceScope } from './architecture.mjs';
export const THREAT_VALIDATION_VERSION = 'threat-control-review-6';
export function threatValidationKey(model) {
  return sha(JSON.stringify([THREAT_VALIDATION_VERSION, model.modelRevision, model.sourceGraph?.fingerprint, model.architecture, model.deploymentContext]));
}
export function threatIssue(model, threat) {
  const evidence = new Map(model.evidence.map(e => [e.id, e]));
  return {
    id: threat.id, sourceId: threat.id, origin: 'stride', kind: 'security-design', cwe: null,
    title: threat.title, explanation: threat.scenario, preconditions: threat.prerequisites,
    controls: threat.controls, analysis: threat.analysis,
    locations: threat.evidenceIds.map(id => evidence.get(id)).filter(Boolean).map(e => ({ repository: e.repository, path: e.path, line: e.line, blobSha256: e.blobSha256, sourceScope: sourceScope(e.path) })),
    evidenceIds: threat.evidenceIds, interfaceIds: threat.interfaceIds, sourceOnly: true,
  };
}
export function threatAssessment(model, threatId) {
  const threat = model.aiReview?.threats?.find(t => t.id === threatId);
  const entry = model.threatValidation?.entries?.find(e => e.sourceId === threatId);
  if (!entry) return { assessment: 'not-assessed' };
  if (!threat || model.aiReview?.status === 'stale' || (model.aiReview?.basedOnRevision && model.aiReview.basedOnRevision !== model.modelRevision) || model.threatValidation.contextKey !== threatValidationKey(model) || entry.issueHash !== sha(JSON.stringify(threatIssue(model, threat))))
    return { assessment: 'stale', previousAssessment: entry.assessment };
  return entry;
}
