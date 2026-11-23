import { id, sha } from './sources.mjs';
import { reviewPacket } from './model-review.mjs';
import { systemModel, interactionContext, CATEGORIES } from './system-model.mjs';
import { sourceScope } from './architecture.mjs';
import { deploymentContext, contextForInterfaces } from './deployment-context.mjs';
import { interfacePriorities, batchStage } from './review-order.mjs';

export const SYSTEM_REVIEW_VERSION = 'system-review-3';
export function systemReviewPlan(model, excerpts = new Map(), selection = null) {
  const system = systemModel({ ...model, aiReview: undefined }, { matrix: false });
  const context = deploymentContext(model, system);
  const evidence = new Map(model.evidence.map(e => [e.id, e]));
  const byId = new Map(model.interfaces.map(i => [i.id, i]));
  const production = i => i.evidence.some(e => sourceScope(evidence.get(e)?.path || '') === 'production-candidate');
  const eligible = i => production(i) && (['inbound', 'outbound', 'resource'].includes(i.direction) && i.kind !== 'connection-config' || ['worker', 'store-use', 'external-use', 'execution-identity', 'entrypoint', 'process'].includes(i.connection?.role));
  const primary = new Set(selection ? selection.interfaceIds : model.interfaces.filter(eligible).map(i => i.id));
  const controls = new Map();
  for (const i of model.interfaces) if (production(i) && (i.kind === 'control' || i.kind === 'connection-config' || ['host-binding', 'proxy-target', 'execution-identity'].includes(i.connection?.role))) {
    if (!controls.has(i.component)) controls.set(i.component, []);
    controls.get(i.component).push(i);
  }
  const indexes = { evidence, components: new Map(model.components.map(c => [c.id, c])) };
  const priorities = interfacePriorities(model, system);
  const batches = [], omitted = [], gaps = [], obligations = [], splits = [];
  const covered = new Set(), flowGroups = new Map();
  const add = (records, flows, label, extraControls = []) => {
    const members = [...new Map(records.map(r => [r.id, r])).values()];
    const memberIds = new Set(members.map(i => i.id));
    const related = [...new Map([...members.flatMap(i => controls.get(i.component) || []), ...extraControls].map(i => [i.id, i])).values()].filter(i => !memberIds.has(i.id));
    const controlRank = r => r.kind === 'control' ? 0 : r.connection?.role === 'execution-identity' ? 1 : 2;
    related.sort((a, b) => controlRank(a) - controlRank(b));
    const memberFiles = new Set(members.flatMap(i => i.evidence.map(id => {
      const e = evidence.get(id);
      return e && JSON.stringify([e.repository, e.path]);
    })));
    // Only source-local controls accompany an operation automatically. Other
    // declarations get their own review units and remain available for follow-up.
    const supportingUnit = members.every(i => i.kind === 'control' || i.kind === 'connection-config');
    const selectedControls = (supportingUnit ? [] : related.filter(i => i.evidence.some(id => {
      const e = evidence.get(id);
      return e && memberFiles.has(JSON.stringify([e.repository, e.path]));
    }))).slice(0, 6);
    const interfaces = [...members, ...selectedControls];
    const packet = reviewPacket({ ...model, interfaces }, excerpts, new Map(), indexes);
    packet.reviewFocus = { phase: 'system-review', scope: label, categories: CATEGORIES, interpretation: 'Review each member operation and the connected path, actors, assets and control enforcement. Grouping does not establish equivalent authorization policies. Source declarations do not establish deployed exposure. State conditional threats under the supplied assumptions; do not treat assumptions as verified facts.' };
    const requiredIds = new Set(flows.map(f => f.id));
    const contextFlows = flows.length
      ? system.flows.filter(f => requiredIds.has(f.id))
      : [];
    packet.systemContext = interactionContext(
      { ...model, interfaces }, interfaces.map(i => i.id),
      { ...system, flows: contextFlows }, undefined, [...requiredIds],
    );
    packet.deploymentContext = contextForInterfaces(context, interfaces.map(i => i.id));
    if (selection) packet.reviewFocus.qualityRules = 'Investigate the current operation, not a hypothetical future change. A static 404 with no data operation is not an authorization bypass. Dependencies without a specific advisory or source-supported attack path are inventory obligations, not vulnerability scenarios. Resolve applicable global, inherited and route-specific controls from sourceContext; name exact missing implementations as questions. Do not infer absence from omitted controls. Assess spoofing, tampering, repudiation, disclosure, availability and privilege separately; no finding is required in every category.';
    if (selection) packet.reviewFocus.selectedProfile = {name:selection.profile,basis:'analysis assumption; not deployment verification'};
    packet.reviewFocus.responseContract = 'Return concise actionable scenarios. Anchor each threat to exactly ONE interfaceId and one or more evidenceIds owned by that interface, copied from the evidenceOwnership table. Do not add evidence from other interfaces to threat.evidenceIds: supporting controls belong in analysis.controlEvidenceIds when supplied and relevant; other path context belongs in narrative with explicit uncertainty. This anchor does not prove the entire connected path. Return connections as [] because static connections are already supplied. Assess all six STRIDE categories; do not invent a scenario to fill a category. Return at most six distinct scenarios and preserve missing evidence as questions.';
    packet.reviewFocus.evidenceOwnership = packet.records.map(r => ({ interfaceId: r.id, evidenceIds: r.evidence.map(e => e.id) }));
    packet.reviewUnit = { flowIds: flows.map(f => f.id), primaryInterfaceIds: members.map(i => i.id), omittedRelatedControls: Math.max(0, related.length - selectedControls.length) };
    const missingFlows = flows.filter(f => !packet.systemContext.flows.some(x => x.id === f.id));
    if (missingFlows.length) throw Error('Required system flow missing from review context');
    if (members.length > 8 || packet.records.length !== interfaces.length || Buffer.byteLength(JSON.stringify(packet)) > 72 * 1024) {
      if (flows.length > 1) {
        const midpoint = Math.ceil(flows.length / 2);
        for (const half of [flows.slice(0, midpoint), flows.slice(midpoint)]) add(half.flatMap(f => f.interfaceIds.filter(i => !selection || primary.has(i)).map(i => byId.get(i)).filter(Boolean)), half, label);
      } else if (!flows.length && members.length > 1) {
        const midpoint = Math.ceil(members.length / 2);
        add(members.slice(0, midpoint), [], label); add(members.slice(midpoint), [], label);
      } else { omitted.push(...members.map(i => i.id)); gaps.push({ reason: 'system-unit-packet-limit', interfaceIds: members.map(i => i.id) }); }
      splits.push({ phase: 'system-review', label, reason: 'packet-budget', records: members.length });
      return;
    }
    const packetHash = sha(JSON.stringify(packet));
    const batch = { id: id(SYSTEM_REVIEW_VERSION, packetHash), phase: 'system-review', label, packetHash, packet, deploymentQuestionIds: packet.deploymentContext.assumptions.map(a => a.id) };
    batch.reviewStage = batchStage(batch, priorities);
    batches.push(batch);
    members.forEach(i => covered.add(i.id));
    if (related.length > selectedControls.length) gaps.push({ reason: 'additional-control-context', batchId: batch.id, count: related.length - selectedControls.length });
    for (const f of flows) {
      if (!packet.systemContext.flows.some(x => x.id === f.id)) gaps.push({ reason: 'flow-context-limit', flowId: f.id });
      obligations.push({ id: id('system-flow-obligation', f.id, [...f.interfaceIds].sort().join(':')), kind: 'system-flow', subject: f.id, interfaceIds: f.interfaceIds, batchIds: packet.systemContext.flows.some(x => x.id === f.id) ? [batch.id] : [] });
    }
    for (const i of members) obligations.push({ id: id('system-interface-obligation', i.id), kind: 'system-interface', subject: i.id, interfaceIds: [i.id], batchIds: [batch.id] });
  };
  for (const flow of system.flows) {
    const ids = (flow.interfaceIds || []).filter(i => byId.has(i) && (!selection || primary.has(i)));
    if (!ids.some(i => primary.has(i))) continue;
    if (!ids.every(i => production(byId.get(i)))) { gaps.push({ reason: 'mixed-production-supporting-flow', flowId: flow.id }); continue; }
    const key = JSON.stringify([flow.source, flow.target, flow.protocol, flow.callerIdentity, flow.calleeIdentity, flow.authorization, flow.transport, flow.controlIds]);
    if (!flowGroups.has(key)) flowGroups.set(key, []);
    // An unresolved peer can represent hundreds of entry points. Review its
    // member segments without claiming one segment covers the entire bundle.
    for (let at = 0; at < ids.length; at += 8)
      flowGroups.get(key).push({ ...flow, interfaceIds: ids.slice(at, at + 8) });
  }
  // For a POC, operations are primary review subjects. Supply their incident
  // flows together instead of reviewing the same handler once for every flow.
  if (selection) {
    const groups = new Map();
    for (const i of model.interfaces.filter(i => primary.has(i.id))) {
      if (!groups.has(i.component)) groups.set(i.component, []);
      groups.get(i.component).push(i);
    }
    for (const group of groups.values()) for (let at = 0; at < group.length; at += 8) {
      const members = group.slice(at, at + 8), ids = new Set(members.map(i => i.id));
      const flows = system.flows.filter(f => f.interfaceIds?.some(i => ids.has(i)))
        .map(f => ({...f, interfaceIds:f.interfaceIds.filter(i => ids.has(i))}));
      add(members, flows, `${indexes.components.get(members[0].component)?.name || members[0].repository} · selected operations`);
    }
  }
  for (const flows of selection ? [] : flowGroups.values()) for (let at = 0; at < flows.length; at += 4) {
    const selected = flows.slice(at, at + 4);
    const names = [...system.components, ...system.entities];
    const label = `${names.find(n => n.id === selected[0].source)?.name || 'Caller'} → ${names.find(n => n.id === selected[0].target)?.name || 'Resource'}`;
    add(selected.flatMap(f => f.interfaceIds.map(i => byId.get(i))), selected, label);
  }
  const remaining = new Map();
  for (const i of model.interfaces.filter(i => primary.has(i.id) && !covered.has(i.id))) {
    const key = [i.component, i.kind, i.direction, i.protocol].join(':');
    if (!remaining.has(key)) remaining.set(key, []);
    remaining.get(key).push(i);
  }
  for (const group of remaining.values()) for (let at = 0; at < group.length; at += 8) add(group.slice(at, at + 8), [], `${indexes.components.get(group[0].component)?.name || group[0].repository} · ${group[0].kind}`);
  // Controls/configuration omitted from initial contexts receive explicit supporting units.
  const included = new Set(batches.flatMap(b => b.packet.records.map(r => r.id)));
  for (const group of selection ? [] : controls.values()) {
    const missing = group.filter(i => !included.has(i.id));
    for (let at = 0; at < missing.length; at += 8) add(missing.slice(at, at + 8), [], `${missing[at].repository} · configuration and controls`);
  }
  // Every supplied interface retains an explicit obligation, including controls.
  for (const batch of batches) for (const record of batch.packet.records)
    obligations.push({ id: id('system-interface-obligation', record.id), kind: 'system-interface', subject: record.id, interfaceIds: [record.id], batchIds: [batch.id] });
  const uniqueObligations = new Map();
  for (const o of obligations) {
    const prior = uniqueObligations.get(o.id);
    uniqueObligations.set(o.id, prior ? { ...o, batchIds: [...new Set([...prior.batchIds, ...o.batchIds])] } : o);
  }
  const scopedIds = [...new Set(batches.flatMap(b => b.packet.records.map(r => r.id)))];
  const scopeSet = new Set(scopedIds);
  const recordCounts = new Map();
  for (const b of batches) for (const r of b.packet.records)
    recordCounts.set(r.id, (recordCounts.get(r.id) || 0) + 1);
  const preview = {
    packets: batches.length,
    packetBytes: batches.reduce((n, b) => n + Buffer.byteLength(JSON.stringify(b.packet)), 0),
    repeatedRecordAppearances: [...recordCounts.values()].reduce((n, count) => n + count - 1, 0),
    blockedObligations: [...uniqueObligations.values()].filter(o => !o.batchIds.length).length,
    flowObligations: [...uniqueObligations.values()].filter(o => o.kind === 'system-flow').length,
    interpretation: 'Metadata bytes before source retrieval. Token cost and duration require provider measurements. All selected operations remain individually cited.',
  };
  return { preview, batches, omitted: [...new Set(omitted)], splits, refinements: [], obligations: [...uniqueObligations.values()], gaps,
    limits: { packetBytes: 72 * 1024, flowsPerUnit: 4, standaloneInterfacesPerUnit: 8 },
    semantics: 'System flows, security interfaces and related configuration/controls. Deep callable and supporting/test-code review is deferred, not completed.',
    reviewScope: 'system', scope: { version: SYSTEM_REVIEW_VERSION, interfaceIds: scopedIds, primaryInterfaces: primary.size, deferredInterfaces: model.interfaces.length - scopeSet.size,
      repositories: model.sources.map(s => ({ repository: s.name, inScope: model.interfaces.filter(i => i.repository === s.name && scopeSet.has(i.id)).length, deferred: model.interfaces.filter(i => i.repository === s.name && !scopeSet.has(i.id)).length, sourceStatus: s.status })),
    },
  };
}
