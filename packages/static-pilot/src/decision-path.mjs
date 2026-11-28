// A read-only presentation of saved evidence. Never infer execution or approved
// boundaries from co-located records, names or graph connectivity alone.
const labels={'entry':'Entry point','path-binding':'Path to the operation','applicable-controls':'Controls on this path','sensitive-operation':'Sensitive operation'};
export function decisionPath(threat, system) {
  const a=threat.validation || {}, engineering=a.engineering;
  const stages=['entry','path-binding','applicable-controls','sensitive-operation'].map(kind=>{
    const o=engineering?.obligations?.find(o=>o.kind===kind);
    return {kind,label:labels[kind],status:o?.status || 'not-assessed',
      explanation:o?.reason || 'No individual engineering evidence recorded for this step.',citations:o?.citations || []};
  });
  const repositories=[...new Set(stages.flatMap(s=>s.citations.map(c=>c.repository)))];
  const conditions=engineering?.conditions || [];
  return {
    actor:a.actor || threat.actorRationale?.profiles || 'Actor not established',
    access:a.initialAccess || threat.startingAccess || 'Required access not established',
    stages,repositories,
    pathStatus:stages.some(s=>s.status==='blocks-attack')?'Cited blocking fact':stages.every(s=>s.status==='established')?'Code argument recorded':'Incomplete code argument',
    consistency:engineering?.consistency || {status:'legacy',reason:'Saved assessment predates structured condition consistency review. Original evidence and decisions are retained.'},
    declaredExposure:conditions.filter(c=>c.kind==='network-access').map(c=>c.statement).join('; ') || 'Exposure is conditional; effective network access is not established.',
    runtime:'Not tested; this review is static only.',
    boundaries:(system.boundaries || []).filter(b=>(threat.boundaryIds || []).includes(b.id)).map(b=>({id:b.id,name:b.name,reference:b.reference,state:b.reviewState,enforcement:b.enforcement})),
    interpretation:'These are cited parts of the engineering argument, not a runtime trace. A cited binding must connect the entry to the operation; a graph candidate alone is insufficient. Boundary associations do not approve deployment enforcement.',
  };
}
