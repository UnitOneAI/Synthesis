// A body citation may establish review of its parsed owner without repeating
// the decorator/declaration line. Never transfer it to a neighboring function.
export function citationCoversEvidence(citation, record, evidence) {
  if (
    !record ||
    !evidence ||
    evidence.repository !== record.repository ||
    evidence.path !== record.path ||
    (evidence.blobSha256 && evidence.blobSha256 !== record.blobSha256) ||
    !Number.isInteger(citation.line) ||
    !Number.isInteger(citation.endLine) ||
    citation.line < record.startLine ||
    citation.endLine > record.endLine ||
    citation.endLine < citation.line
  )
    return false;
  if (citation.line <= evidence.line && citation.endLine >= evidence.line)
    return true;
  const owner = record.functionContext;
  return (
    owner?.complete === true &&
    owner.startLine <= evidence.line &&
    owner.endLine >= evidence.line &&
    owner.startLine <= citation.line &&
    owner.endLine >= citation.endLine
  );
}
