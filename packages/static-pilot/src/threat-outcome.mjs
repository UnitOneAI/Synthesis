// A category assessment can cover several scenarios. It is not an individual
// finding verdict. Keep this projection separate from saved review data.
export function threatOutcome(t) {
  if (t.reviewState === 'stale')
    return {kind:'historical', label:'Historical — revalidation required'};
  if (t.validation?.assessment === 'stale')
    return {kind:'investigation', label:'Source reassessment required'};
  if (t.validation?.assessment === 'ruled-out')
    return {kind:'ruled-out', label:'Ruled out for the cited path'};
  if (t.sourceConclusion?.status === 'open')
    return {kind:'investigation', label:'Investigation required'};
  if (!t.metadataOnly && !t.followUpKind &&
      (t.validation?.assessment === 'static-supported' || t.sourceConclusion?.status === 'conditional'))
    return {kind:'supported', label:'Supported conditional threat'};
  return {kind:'investigation', label:t.metadataOnly ? 'Implementation review required' : 'Investigation required'};
}

export function investigationAction(t) {
  const missing = [...(t.validation?.missingEvidence || []), ...(t.categoryAssessment?.missingEvidence || [])];
  return [...new Set(missing.filter(Boolean))].join('; ') || t.sourceConclusion?.nextAction ||
    'Trace the cited entry to the sensitive operation, resolve applicable controls and record supporting evidence or counterevidence. No individual source assessment has established this claim.';
}
