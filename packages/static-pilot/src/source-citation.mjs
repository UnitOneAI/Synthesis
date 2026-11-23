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

// Preserve the exact cited range across supplied overlapping/adjacent windows.
// Never fill a gap, change file identity, or accept an unknown starting record.
export function resolveSourceCitation(citation, records) {
  const first = records.get(citation.recordId);
  if (
    !first ||
    !Number.isInteger(citation.line) ||
    !Number.isInteger(citation.endLine) ||
    citation.line < first.startLine ||
    citation.line > first.endLine ||
    citation.endLine < citation.line
  )
    return null;
  if (citation.endLine <= first.endLine) return [{ ...citation }];
  if (!first.blobSha256) return null;
  const windows = [...records.values()].filter(
    (r) =>
      r.repository === first.repository &&
      r.path === first.path &&
      r.blobSha256 === first.blobSha256,
  );
  const resolved = [];
  let line = citation.line,
    window = first;
  while (line <= citation.endLine) {
    const endLine = Math.min(window.endLine, citation.endLine);
    resolved.push({ ...citation, recordId: window.id, line, endLine });
    line = endLine + 1;
    if (line > citation.endLine) return resolved;
    window = windows
      .filter((r) => r.startLine <= line && r.endLine >= line)
      .sort((a, b) => b.endLine - a.endLine || a.id.localeCompare(b.id))[0];
    if (!window) return null;
  }
  return resolved;
}
