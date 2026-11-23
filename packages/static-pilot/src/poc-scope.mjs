import {sourceScope} from './architecture.mjs';
import { sha } from './sources.mjs';
import { systemReviewPlan,operationSignature } from './system-review-units.mjs';
export function resolvePocScope(model, input = model.pocScope) {
  if (!input || typeof input !== 'object' || !Array.isArray(input.operations) || !input.operations.length || input.operations.length > 12)
    throw Error('Import a POC scope with 1–12 operation selectors');
  const text = (v, name) => { if (typeof v !== 'string' || !v.trim() || v.length > 240) throw Error(`Invalid POC ${name}`); return v.trim(); };
  const title = text(input.title, 'title'), profile = text(input.profile, 'profile');
  const evidence = new Map(model.evidence.map(e => [e.id,e]));
  const maxInterfaces = input.maxInterfaces ?? 48;
  if (!Number.isInteger(maxInterfaces) || maxInterfaces < 1 || maxInterfaces > 48) throw Error('POC permits 1–48 primary interfaces; narrow the operation paths');
  const operations = input.operations.map(o => {
    const repository = text(o.repository, 'repository'), pathContains = text(o.pathContains, 'path selector');
    const operationContains = o.operationContains ? text(o.operationContains, 'operation selector') : '';
    if (!model.sources.some(s => s.name === repository)) throw Error(`Repository not in saved graph: ${repository}`);
    const ids = model.interfaces.filter(i => i.repository === repository && i.direction === 'inbound' &&
      (!operationContains || String(i.operation).toLowerCase().includes(operationContains.toLowerCase())) &&
      i.evidence.some(id => { const e=evidence.get(id); return e && sourceScope(e.path)==='production-candidate' && e.path.toLowerCase().includes(pathContains.toLowerCase()); })).map(i => i.id);
    if (!ids.length) throw Error(`No inbound operation matches ${repository} / ${pathContains}; inspect graph paths before starting`);
    return {repository,pathContains,operationContains,interfaceIds:ids};
  });
  const interfaceIds = [...new Set(operations.flatMap(o => o.interfaceIds))].sort();
  if (interfaceIds.length > maxInterfaces) throw Error(`POC matches ${interfaceIds.length} interfaces, exceeding ${maxInterfaces}; narrow selectors. Nothing was silently dropped.`);
  const definition = {title,profile,maxInterfaces,operations:operations.map(({interfaceIds,...o})=>o)};
  const selected=new Set(interfaceIds);
  const operationGroups=new Set(model.interfaces.filter(i=>selected.has(i.id)).map(i=>operationSignature(i,evidence))).size;
  return {...definition, id:sha(JSON.stringify(definition)).slice(0,20),interfaceIds,operationGroups, matches:operations};
}
export function pocReviewPlan(model, excerpts = new Map()) {
  const poc = resolvePocScope(model);
  const plan = systemReviewPlan(model, excerpts, {interfaceIds:poc.interfaceIds,profile:poc.profile});
  if (plan.batches.length > 12) throw Error('POC exceeds 12 review packets; narrow operation selectors');
  const covered = new Set(plan.batches.flatMap(b=>b.packet.reviewUnit.primaryInterfaceIds));
  if (poc.interfaceIds.some(id=>!covered.has(id))) throw Error('POC has an operation that cannot fit a review packet; narrow the scope before running');
  plan.scope.poc = poc;
  plan.scope.version += ':poc-1';
  plan.semantics = 'Selected inbound operations and directly supplied controls only. Other repositories remain available for evidence retrieval, not full review.';
  return plan;
}
