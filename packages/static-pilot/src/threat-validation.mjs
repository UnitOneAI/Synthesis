import { InvestigationSource } from './investigation-source.mjs';
import { reviewSecurityIssues, INVESTIGATION_LIMITS } from './security-review.mjs';
import { systemModel } from './system-model.mjs';
import { threatIssue, threatValidationKey } from './threat-validation-state.mjs';

// Literal names only; source/model prose never becomes code, a command or a path.
export function controlSymbols(text) {
  return [...new Set((String(text).match(/\b(?:[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+|[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+|[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*)\b/g) || []).filter(s => s.length >= 5 && s.length <= 100))].slice(0, 16);
}
export async function threatInvestigationPacket(model, manifest, root, issue, followUp, context, missing = []) {
  const source = new InvestigationSource(model, manifest, root);
  const symbols = controlSymbols([...missing, issue.controls, issue.explanation, JSON.stringify(issue.analysis || {})].join(' '));
  const requiredSymbols = new Set(controlSymbols(missing.join(' ')));
  const refs = [], searches = [], gaps = [];
  for (const symbol of symbols) {
    const matches = []; let after = '';
    for (let page = 0; page < 2; page++) {
      const result = source.search(symbol, after);
      matches.push(...result.items.filter(n => n.kind === 'file' || n.name === symbol || n.name?.endsWith('.' + symbol) || n.name?.endsWith('::' + symbol)));
      after = result.next;
      if (!after) break;
    }
    const found = matches.sort((a,b) => Number(a.kind === 'file') - Number(b.kind === 'file')).slice(0, 4);
    searches.push({ symbol, matches: found.length, truncated: Boolean(after), nodeIds: found.map(n => n.id) });
    if (requiredSymbols.has(symbol) && (!found.length || after)) gaps.push({ reason: after ? 'control-search-page-limit' : 'named-control-not-found', symbol });
    for (const n of found) if (refs.length < 16 && !refs.some(r => r.repository === n.repository && r.path === n.path && Math.abs(r.line - (n.line || 1)) < 20))
      refs.push({ repository: n.repository, path: n.path, line: n.line || 1 });
  }
  // A focused claim does not need a repository-wide control catalog. Keep exact
  // seeds and requested controls first, then only nearby candidate call edges.
  const references = [...issue.locations.map(r => ({...r, required:true, basis:'saved-scenario'})), ...followUp.map(r => ({...r, required:true, basis:'requested-control'})), ...refs.map(r => ({...r, basis:'named-control-candidate'}))];
  let neighborhoodLimited = false;
  for (const seed of issue.locations.slice(0,4)) {
    const nodes = source.nodes({repository:seed.repository,path:seed.path,limit:129});
    neighborhoodLimited ||= nodes.length > 128;
    const nearby = nodes.filter(n => n.kind !== 'file' && Math.abs((n.line || 1) - (seed.line || 1)) < 5).slice(0,4);
    for (const node of nearby) {
      const edges=source.edges(node.id);neighborhoodLimited ||= Boolean(edges.next);
      for(const edge of edges.items.filter(e => !/contains|owns|member/.test(e.kind)).slice(0,8)) {
        const peer=source.node(edge.from === node.id ? edge.to : edge.from);
        if(peer?.path) references.push({...peer,basis:'candidate-call-neighbor'});
      }
    }
  }
  const records=[], availableFiles=new Map();let omitted=0;
  for(const ref of references) {
    const key=ref.repository+'\0'+ref.path;
    if(source.file(ref.repository,ref.path)) availableFiles.set(key,{repository:ref.repository,path:ref.path});
    if(records.some(r => r.repository===ref.repository && r.path===ref.path && (ref.line || 1)>=r.startLine && (ref.line || 1)<=r.endLine))continue;
    if(records.length>=12){omitted++;if(ref.required)gaps.push({reason:'required-source-window-limit',repository:ref.repository,path:ref.path});continue;}
    try {
      const {code,...record}=await source.window(ref);
      record.basis=ref.basis;
      if(Buffer.byteLength(JSON.stringify([...records,record]))>42000){omitted++;if(ref.required)gaps.push({reason:'required-source-byte-limit',repository:ref.repository,path:ref.path});continue;}
      records.push(record);
    }catch(error){if(ref.required)gaps.push({reason:error.message,repository:ref.repository,path:ref.path});else omitted++;}
  }
  const packet={purpose:'Independent static assessment of one saved STRIDE scenario',candidate:issue,context,records,availableFiles:[...availableFiles.values()].slice(0,64),gaps,
    citationPolicy:'Each citation must fit entirely inside ONE record startLine/endLine range. Split citations across windows even for the same file. Named matches and graph edges are candidates, not proof of enforcement. Assess this exact actor, operation and conditions. Missing context does not establish absent controls. Describe missing named functions in missingEvidence for a bounded follow-up search.',
    retrieval:{controlSearches:searches,includedWindows:records.length,gapCount:gaps.length,candidateWindowsOmitted:omitted,neighborhoodLimited,fullCallGraph:false}};
  if (Buffer.byteLength(JSON.stringify(packet)) > INVESTIGATION_LIMITS.packetBytes) throw Error('Security packet metadata exceeds size limit');
  return packet;
}
export async function reviewThreatScenarios(manifest, model, options = {}) {
  if (!model.aiReview?.coverage?.completedBatches || model.aiReview.status === 'stale' || (model.aiReview.basedOnRevision && model.aiReview.basedOnRevision !== model.modelRevision)) throw Error('Current completed STRIDE scenarios are required; open the matching saved review first');
  const system = systemModel(model, { matrix: false });
  const priority = new Map(system.threats.map(t => [t.id, t.reviewPriority?.rank ?? 9]));
  const selected = options.threatIds;
  if (selected && (!Array.isArray(selected) || !selected.length || selected.some(id => !model.aiReview.threats.some(t => t.id === id)))) throw Error('Select saved STRIDE threat IDs');
  const issues = model.aiReview.threats.filter(t => !selected || selected.includes(t.id)).map(t => threatIssue(model, t)).sort((a,b) => priority.get(a.id) - priority.get(b.id));
  const report = await reviewSecurityIssues(manifest, model, {
    ...options, followMissingControls: true, retryInvalidAssessment: true, candidateIssues: issues, reportField: 'threatValidation', contextKeyOverride: threatValidationKey(model),
    packetBuilder: (m, mf, root, issue, follow, context, missing) => {
      const projected = system.threats.find(t => t.id === issue.id);
      const compact = r => ({ id: r.id, name: r.name, basis: r.basis, reviewState: r.reviewState, startingAccess: r.startingAccess, before: r.before, after: r.after, enforcement: r.enforcement, source: r.source, target: r.target, evidenceIds: r.evidenceIds?.slice(0,8) });
      const scoped = { ...context, actors: system.actors.filter(a => projected.actorIds.includes(a.id)).slice(0,8).map(compact), boundaries: system.boundaries.filter(b => projected.boundaryIds.includes(b.id)).slice(0,12).map(compact), flows: system.flows.filter(f => [...projected.flowIds, ...(projected.candidateFlowIds || [])].includes(f.id)).slice(0, 12).map(compact) };
      return threatInvestigationPacket(m,mf,root,issue,follow,scoped,missing);
    },
  });
  return report;
}
