import { decisionPath } from './decision-path.mjs';
import { deploymentContext } from './deployment-context.mjs';
import { featureReviewSummary } from './feature-review.mjs';
import { deploymentDecisionQuestions } from './reviewer-questions.mjs';
import { addReviewPresentation } from "./review-presentation.mjs";
import { internalTopology } from "./internal-topology.mjs";
import { architectureComponents, sourceScope } from "./architecture.mjs";
import { assessRisk, RISK_FACTORS } from "./analysis-guidance.mjs";
import { id, sha } from "./sources.mjs";
import { redact } from "./model-review.mjs";

export const CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];
export const DIMENSIONS = [
  "identity",
  "privilege",
  "network",
  "execution",
  "data-ownership",
  "third-party",
];
const clean = (v) =>
  redact(String(v ?? ""))
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
    .slice(0, 2000);
const uniq = (a) => [...new Set(a)];
const lists = [
  "components",
  "entities",
  "assets",
  "securityControls",
  "flows",
  "domains",
  "boundaries",
  "actors",
  "threats",
];
const empty = () => ({ version: 1, records: {}, removed: [], decisions: [] });
const fingerprint = (value) => sha(JSON.stringify(value));
const claim = (basis = "source observation") => ({
  basis,
  reviewState: "pending",
});

// Evidence-backed architecture candidates and reviewer annotations; no runtime claims.
export function systemModel(model, { matrix = true } = {}) {
  model = internalTopology(model);
  const w = model.architecture || empty();
  const assignedOwners = new Map();
  for (const c of w.records.components || [])
    for (const iid of c.interfaceIds || []) assignedOwners.set(iid, c.id);
  const sourceInterfaces = model.interfaces.map((i) => ({
    ...i,
    component: assignedOwners.get(i.id) || i.component,
  }));
  const classification = new Map(
    architectureComponents(model).map((c) => [c.id, c]),
  );
  const components = model.components.map((c) => ({
    id: c.id,
    name: c.name,
    type: "source-group",
    repositories: [c.repository],
    interfaceIds: model.interfaces
      .filter((i) => i.component === c.id)
      .map((i) => i.id),
    evidenceIds: uniq(
      model.interfaces
        .filter((i) => i.component === c.id)
        .flatMap((i) => i.evidence),
    ),
    ...claim(
      classification.get(c.id)?.type === "source-group"
        ? "source grouping"
        : "static architecture candidate",
    ),
    description: c.basis,
    ...classification.get(c.id),
  }));
  const entities = [],
    assets = [],
    flows = [],
    boundaries = [],
    domains = [],
    actors = [],
    threats = [];
  const securityControls = sourceInterfaces
    .filter((i) => i.direction === "control" && i.protocol !== "architecture")
    .map((i) => ({
      id: id("control", i.id),
      name: i.operation,
      description:
        "Source control declaration; applicability and enforcement require review.",
      interfaceIds: [i.id],
      evidenceIds: i.evidence,
      flowIds: [],
      ...claim(),
    }));
  const grouped = new Map();
  const declaredSources = new Set(model.flows.map((f) => f.from));
  const discovered = (model.connectionDiscovery?.flows || []).filter(
    (f) => !f.from || !declaredSources.has(f.from),
  );
  entities.push(...(model.connectionDiscovery?.entities || []));
  const connectedFlows = [...model.flows, ...discovered];
  const declared = new Set(connectedFlows.flatMap((f) => [f.from, f.to]));
  for (const i of sourceInterfaces.filter(
    (i) =>
      i.direction !== "control" &&
      i.connection?.kind !== "http-config" &&
      !declared.has(i.id),
  )) {
    const key = [i.component, i.protocol, i.direction].join(":");
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(i);
  }
  for (const [key, items] of grouped) {
    const i = items[0],
      inbound = i.direction === "inbound",
      resource = i.direction === "resource";
    const peer = {
      id: id("peer", key),
      name: inbound
        ? `Unknown ${i.protocol} caller`
        : `Unresolved ${i.protocol} ${resource ? "resource" : "destination"}`,
      type: inbound ? "external" : "unknown",
      repositories: [],
      interfaceIds: items.map((i) => i.id),
      evidenceIds: uniq(items.flatMap((i) => i.evidence)),
      ...claim("unresolved"),
      description:
        "Interface candidates do not establish the remote party, deployed endpoint or effective permissions.",
    };
    entities.push(peer);
    flows.push({
      id: id("candidate-flow", key),
      name: `${items.length} ${i.protocol} interface candidate(s)`,
      source: inbound ? peer.id : i.component,
      target: inbound ? i.component : peer.id,
      protocol: i.protocol,
      data: "Unclassified",
      interfaceIds: items.map((i) => i.id),
      evidenceIds: peer.evidenceIds,
      controls: "Not established",
      ...claim("unresolved"),
    });
  }
  for (const f of connectedFlows)
    flows.push({
      id: f.id,
      name: f.operation,
      source:
        sourceInterfaces.find((i) => i.id === f.from)?.component || f.source,
      target:
        sourceInterfaces.find((i) => i.id === f.to)?.component || f.target,
      protocol:
        f.protocol ||
        model.interfaces.find((i) => i.id === f.from)?.protocol ||
        "Unknown",
      data: f.data,
      transport: f.transport || "unknown",
      controls: f.controls,
      description: f.reason,
      interfaceIds: [f.from, f.to].filter(Boolean),
      evidenceIds: f.evidence,
      reviewer: f.reviewer,
      confidence: f.confidence,
      graphNodeIds: f.graphNodeIds,
      ...claim(f.basis === "declared" ? "reviewer declaration" : f.basis),
    });
  for (const b of model.boundaries)
    boundaries.push({
      id: b.id,
      name: `${b.before} → ${b.after}`,
      dimension: b.dimension,
      before: b.before,
      after: b.after,
      enforcement: b.enforcement,
      flowIds: [b.flow],
      evidenceIds: b.evidence,
      ...claim("reviewer declaration"),
    });
  for (const f of flows.filter((f) => f.protocol === "HTTP")) {
    if (
      !entities.some((n) => n.id === f.source && n.type === "external") &&
      !discovered.some((d) => d.id === f.id)
    )
      continue;
    const controls = sourceInterfaces.filter(
      (i) =>
        i.component === f.target &&
        i.direction === "control" &&
        i.protocol !== "architecture",
    );

    boundaries.push({
      id: id("candidate-boundary", f.id),
      name: "Caller-to-service identity boundary candidate",
      dimension: "identity",
      before: "Caller identity not established",
      after: "Application principal (requires confirmation)",
      enforcement: controls.length
        ? "Control declarations occur in this component; applicability to the entry point is not established."
        : "Identity enforcement is not established in the collected source. Confirm caller identity and service authorization context.",
      flowIds: [f.id],
      evidenceIds: uniq([
        ...f.evidenceIds,
        ...controls.flatMap((i) => i.evidence),
      ]),
      ...claim("inference"),
    });
  }
  for (const f of flows.filter((f) => f.basis !== "unresolved")) {
    const declarations = sourceInterfaces.filter(
      (i) =>
        i.component === f.target && i.connection?.role === "execution-identity",
    );
    if (declarations.length)
      boundaries.push({
        id: id("execution-boundary", f.id),
        name: "Service execution identity boundary candidate",
        dimension: "execution",
        before: "Calling component authority",
        after: "Configured service execution identity (unverified)",
        enforcement:
          "Source declares a service execution identity. Runtime account, credential delegation and effective permissions require review.",
        flowIds: [f.id],
        evidenceIds: uniq([
          ...f.evidenceIds,
          ...declarations.flatMap((i) => i.evidence),
        ]),
        ...claim("inference"),
      });
  }
  const actorEntries = new Map();
  for (const i of model.interfaces) {
    if (!actorEntries.has(i.component))
      actorEntries.set(i.component, new Set());
    actorEntries.get(i.component).add(assignedOwners.get(i.id) || i.component);
  }
  for (const a of model.actors)
    actors.push({
      id: a.id,
      name: a.name,
      startingAccess: a.startingAccess,
      objectives: a.objectives,
      excludedCapabilities: "No additional privileges or compromise assumed",
      entryIds: [...(actorEntries.get(a.component) || [])],
      evidenceIds: uniq(
        sourceInterfaces
          .filter(
            (i) =>
              i.component === a.component ||
              (actorEntries.get(a.component) || new Set()).has(i.component),
          )
          .flatMap((i) => i.evidence),
      ),
      ...claim("assumption"),
    });
  for (const t of model.threats)
    threats.push({
      id: t.id,
      name: t.scenario.split(".")[0].slice(0, 150),
      scenario: t.scenario,
      categories: CATEGORIES.filter((c) =>
        t.category.toLowerCase().includes(c.toLowerCase()),
      ),
      actorIds: [t.actor],
      interfaceIds: [t.interface],
      flowIds: t.path || [],
      boundaryIds: boundaries
        .filter((b) => b.flowIds.some((f) => t.path?.includes(f)))
        .map((b) => b.id),
      asset: t.asset,
      prerequisites: t.prerequisites.join("; "),
      controls: t.controls,
      mitigation: t.mitigation,
      evidenceIds: t.evidence,
      origin: "review checklist",
      ...claim("conditional scenario"),
    });
  for (const t of model.aiReview?.threats || []) {
    const actorId = id("review-actor", t.actor, t.startingAccess);
    if (!actors.some((a) => a.id === actorId))
      actors.push({
        id: actorId,
        name: t.actor,
        startingAccess: t.startingAccess,
        objectives: t.asset,
        excludedCapabilities: "Additional capabilities require review",
        entryIds: uniq(
          sourceInterfaces
            .filter((i) => t.interfaceIds.includes(i.id))
            .map((i) => i.component),
        ),
        evidenceIds: t.evidenceIds,
        ...claim("assumption"),
      });
    threats.push({
      id: t.id,
      name: t.title,
      scenario: t.scenario,
      categories: [t.category],
      actorIds: [actorId],
      interfaceIds: t.interfaceIds,
      flowIds: flows
        .filter(
          (f) =>
            f.interfaceIds.some((i) => t.interfaceIds.includes(i)) &&
            f.basis !== "unresolved",
        )
        .map((f) => f.id),
      boundaryIds: boundaries
        .filter((b) =>
          b.flowIds.some((fid) =>
            flows
              .find((f) => f.id === fid)
              ?.interfaceIds.some((i) => t.interfaceIds.includes(i)),
          ),
        )
        .map((b) => b.id),
      asset: t.asset,
      prerequisites: t.prerequisites,
      controls: t.controls,
      mitigation: t.mitigation,
      evidenceIds: t.evidenceIds,
      origin: "analysis",
      analysis: t.analysis,
      analysisQuality: t.analysisQuality,
      ...claim("inference"),
      ...(model.aiReview.status === "stale" ? { reviewState: "stale" } : {}),
    });
  }
  const result = {
    version: 1,
    title: model.title,
    profile: model.profile,
    sourceRevision: model.modelRevision,
    components,
    entities,
    assets,
    securityControls,
    flows,
    domains,
    boundaries,
    actors,
    threats,
  };
  for (const kind of lists) {
    const map = new Map(result[kind].map((r) => [r.id, r]));
    for (const r of w.records[kind] || []) map.set(r.id, { ...r });
    result[kind] = [...map.values()].filter((r) => !w.removed.includes(r.id));
  }
  const explicitComponents = new Set(
    (w.records.components || []).map((c) => c.id),
  );
  result.components = result.components.filter(
    (c) =>
      explicitComponents.has(c.id) ||
      !c.interfaceIds.length ||
      c.interfaceIds.some((i) => !assignedOwners.has(i)),
  );
  const bound = new Set(
    result.flows
      .filter((f) => f.basis !== "unresolved")
      .flatMap((f) => f.interfaceIds || []),
  );
  const removedCandidates = new Set(
    result.flows
      .filter(
        (f) =>
          f.basis === "unresolved" &&
          f.interfaceIds.length &&
          f.interfaceIds.every((i) => bound.has(i)),
      )
      .map((f) => f.id),
  );
  result.flows = result.flows.filter((f) => !removedCandidates.has(f.id));
  result.boundaries = result.boundaries.filter(
    (b) =>
      !(
        b.basis === "inference" &&
        b.flowIds.every((id) => removedCandidates.has(id))
      ),
  );
  const referencedPeers = new Set([
    ...result.flows.flatMap((f) => [f.source, f.target]),
    ...result.actors.flatMap((a) => a.entryIds || []),
    ...result.domains.flatMap((d) => d.memberIds || []),
  ]);
  result.entities = result.entities.filter(
    (n) => n.basis !== "unresolved" || referencedPeers.has(n.id),
  );
  const nodes = new Set(
    [...result.components, ...result.entities].map((n) => n.id),
  );
  result.flows.forEach((f) => {
    if (!nodes.has(f.source) || !nodes.has(f.target)) f.reviewState = "stale";
  });
  const sourceEvidence = new Map(model.evidence.map((e) => [e.id, e]));
  const sourceInterfaceMap = new Map(model.interfaces.map((i) => [i.id, i]));
  for (const entity of result.entities) {
    const scopes = (entity.evidenceIds || []).map((id) =>
      sourceScope(sourceEvidence.get(id)?.path),
    );
    if (scopes.length)
      entity.scope = scopes.includes("production-candidate")
        ? "production-candidate"
        : scopes[0];
  }
  for (const f of result.flows) {
    const first = sourceInterfaceMap.get(f.interfaceIds?.[0]);
    f.scope =
      f.basis === "reviewer declaration"
        ? "production-candidate"
        : sourceScope(sourceEvidence.get(first?.evidence?.[0])?.path);
  }
  for (const f of result.flows)
    f.boundaryIds = result.boundaries
      .filter((b) => b.flowIds.includes(f.id))
      .map((b) => b.id);
  for (const t of result.threats.filter((t) => t.origin === "analysis")) {
    t.flowIds = result.flows
      .filter(
        (f) =>
          f.basis !== "unresolved" &&
          f.interfaceIds?.some((i) => t.interfaceIds.includes(i)),
      )
      .map((f) => f.id);
    t.candidateFlowIds = result.flows
      .filter(f => f.basis === 'unresolved' && f.interfaceIds?.some(i => t.interfaceIds.includes(i)))
      .map(f => f.id);
    const associatedFlows = new Set([...t.flowIds, ...t.candidateFlowIds]);
    t.boundaryIds = result.boundaries
      .filter((b) => b.flowIds.some((id) => associatedFlows.has(id)))
      .map((b) => b.id);
  }
  const allIds = new Set(lists.flatMap((k) => result[k]).map((r) => r.id));
  const evidenceIds = new Set(model.evidence.map((e) => e.id)),
    interfaceIds = new Set(model.interfaces.map((i) => i.id));
  for (const kind of lists)
    for (const r of result[kind]) {
      r.missingReferences = [
        ...(r.evidenceIds || []).filter((id) => !evidenceIds.has(id)),
        ...(r.interfaceIds || []).filter((id) => !interfaceIds.has(id)),
        ...(r.counterEvidenceIds || []).filter((id) => !evidenceIds.has(id)),
        ...[
          "flowIds",
          "boundaryIds",
          "actorIds",
          "entryIds",
          "memberIds",
          "controlIds",
          "assetIds",
        ].flatMap((key) => (r[key] || []).filter((id) => !allIds.has(id))),
        ...["source", "target", "parentId", "sourceDomainId", "targetDomainId"]
          .map((key) => r[key])
          .filter((id) => id && !allIds.has(id)),
      ];
      if (r.missingReferences.length) r.reviewState = "stale";
      r.fingerprint = fingerprint({
        ...r,
        sourceRevision: model.sources.map((s) => [
          s.name,
          s.snapshot,
          s.status,
        ]),
      });
      const d = w.decisions.find((d) => d.subjectId === r.id);
      if (d) {
        r.decision = { ...d, stale: d.fingerprint !== r.fingerprint };
        r.reviewState =
          r.decision.stale || r.missingReferences.length ? "stale" : d.state;
      }
    }
  result.coverage = {
    architecture: {
      internalUnits: result.components.filter((c) => c.internalRole).length,
      backgroundWorkers: result.components.filter(
        (c) => c.internalRole === "worker",
      ).length,
      logicalResources: result.entities.filter((c) => c.resourceKind).length,
      candidateProcesses: result.components.filter(
        (c) => c.type !== "source-group",
      ).length,
      sourceGroups: result.components.filter((c) => c.type === "source-group")
        .length,
      nonProductionGroups: result.components.filter(
        (c) => c.scope && c.scope !== "production-candidate",
      ).length,
      hostAssociations: result.components.filter((c) => c.hostCandidateId)
        .length,
    },
    repositories: model.sources.length,
    unavailable: model.sources
      .filter((s) => s.status === "unavailable")
      .map((s) => s.name),
    sourceGaps: model.sources
      .filter((s) => s.status !== "read" || s.coverage?.truncated)
      .map((s) => s.name),
    discoveredFlows: discovered.length,
    inferredConnections: discovered.filter(
      (f) => f.basis === "inferred route match",
    ).length,
    connectionGaps: model.connectionDiscovery?.gaps || [],
    unresolvedFlows: result.flows.filter((f) => f.basis === "unresolved")
      .length,
    pendingBoundaries: result.boundaries.filter(
      (b) => b.reviewState === "pending" || b.reviewState === "stale",
    ).length,
    analysis: model.aiReview?.coverage || null,
    graph: model.sourceGraph?.coverage || null,
  };
  result.questions = [
    ...(model.aiReview?.questions || []),
    ...(model.architecture?.rebuildNotice
      ? [model.architecture.rebuildNotice]
      : []),
  ];
  result.revision = fingerprint([
    model.modelRevision,
    w,
    model.sourceConclusions,
    model.aiReview?.responseHash,
    model.aiReview?.status,
    model.deploymentContext,
  ]);
  result.deploymentContext = deploymentContext(model, result);
  result.matrix = matrix ? systemMatrix(result, model, w) : [];
  const presented=addReviewPresentation(result, model);
  for(const threat of presented.threats) if(threat.origin==='analysis') threat.decisionPath=decisionPath(threat,presented);
  presented.featureReview=featureReviewSummary(model,presented);
  presented.deploymentDecisionQuestions=deploymentDecisionQuestions(model);
  return presented;
}

export function systemMatrix(s, model, w = model.architecture || empty()) {
  const reviewed = new Set(
    model.aiReview?.status === "stale"
      ? []
      : model.aiReview?.coverage?.reviewedInterfaceIds || [],
  );
  const scope = model.aiReview?.reviewScope === 'system' ? new Set(model.aiReview.scope.interfaceIds) : null;
  const byFlow = new Map(s.flows.map((f) => [f.id, f]));
  const bySubject = new Map();
  for (const t of s.threats)
    for (const subject of new Set([
      ...(t.flowIds || []),
      ...(t.boundaryIds || []),
      ...(t.interfaceIds || []),
    ])) {
      if (!bySubject.has(subject)) bySubject.set(subject, []);
      bySubject.get(subject).push(t);
    }
  return [
    ...s.components.map((c) => ({ ...c, rowKind: "component" })),
    ...s.flows.map((f) => ({ ...f, rowKind: "flow" })),
    ...s.boundaries.map((b) => ({
      ...b,
      rowKind: "boundary",
      interfaceIds: uniq(
        b.flowIds.flatMap((f) => byFlow.get(f)?.interfaceIds || []),
      ),
    })),
  ].map(r => scope ? { ...r, interfaceIds: (r.interfaceIds || []).filter(i => scope.has(i)) } : r)
  .filter(r => !scope || r.interfaceIds.length)
  .map((r) => ({
    id: r.id,
    name: r.name,
    rowKind: r.rowKind,
    repositories: r.repositories || [],
    interfaceIds: r.interfaceIds || [],
    reviewedInterfaces: (r.interfaceIds || []).filter((i) => reviewed.has(i))
      .length,
    cells: CATEGORIES.map((category) => {
      const items = [
        ...new Set(
          [r.id, ...(r.interfaceIds || [])].flatMap(
            (id) => bySubject.get(id) || [],
          ),
        ),
      ].filter((t) => t.categories.includes(category));
      const key = `cell:${r.id}:${category}`,
        fp = fingerprint([
          model.modelRevision,
          r.id,
          category,
          items.map((t) => t.fingerprint),
        ]),
        decision = w.decisions.find((d) => d.subjectId === key);
      return {
        id: key,
        category,
        threatIds: items.map((t) => t.id),
        scenarioCount: items.filter((t) => t.origin !== "review checklist")
          .length,
        checklistCount: items.filter((t) => t.origin === "review checklist")
          .length,
        fingerprint: fp,
        decision: decision
          ? { ...decision, stale: decision.fingerprint !== fp }
          : null,
        state: decision
          ? decision.fingerprint !== fp
            ? "stale"
            : decision.state
          : model.aiReview?.status === "stale"
            ? "stale"
            : items.some((t) => t.origin !== "review checklist")
              ? "needs-review"
              : r.interfaceIds?.length &&
                  r.interfaceIds.every((i) => reviewed.has(i))
                ? "awaiting-review"
                : r.interfaceIds?.some((i) => reviewed.has(i))
                  ? "partially-reviewed"
                  : "not-analyzed",
      };
    }),
  }));
}

function validate(s, model, previous) {
  const previousRecords = new Map(
    lists.flatMap((k) => previous?.[k] || []).map((r) => [r.id, r]),
  );
  const previousIds = new Set([
    ...previousRecords.keys(),
    ...model.interfaces.map((i) => i.id),
    ...model.evidence.map((e) => e.id),
  ]);
  const all = lists.flatMap((k) => s[k]);
  if (all.length > 50000) throw Error("System model limit exceeded");
  const ids = all.map((r) => r.id);
  if (new Set(ids).size !== ids.length)
    throw Error("Object IDs must be unique");
  const refs = (r, key, valid) => {
    if (
      !Array.isArray(r[key] || []) ||
      (r[key] || []).some(
        (v) =>
          typeof v !== "string" ||
          (!valid.has(v) &&
            !(
              !previousIds.has(v) &&
              previousRecords.get(r.id)?.[key]?.includes(v)
            )),
      )
    )
      throw Error(`Invalid ${key} reference`);
  };
  const nodeIds = new Set([...s.components, ...s.entities].map((r) => r.id)),
    evidence = new Set(model.evidence.map((e) => e.id)),
    interfaces = new Set(model.interfaces.map((i) => i.id)),
    flowIds = new Set(s.flows.map((f) => f.id)),
    domainIds = new Set(s.domains.map((d) => d.id));
  for (const r of all) {
    if (!r.name?.trim()) throw Error("Name is required");
    refs(r, "evidenceIds", evidence);
    refs(r, "counterEvidenceIds", evidence);
    refs(r, "controlIds", new Set(s.securityControls.map((c) => c.id)));
    refs(r, "interfaceIds", interfaces);
  }
  const ownership = new Set();
  for (const c of model.architecture?.records?.components || [])
    for (const iid of c.interfaceIds || []) {
      if (ownership.has(iid))
        throw Error(
          "An interface cannot have multiple declared component owners",
        );
      ownership.add(iid);
    }
  for (const r of s.components) {
    refs(r, "repositories", new Set(model.sources.map((s) => s.name)));
    if (
      !["source-group", "process", "store", "broker", "gateway"].includes(
        r.type,
      )
    )
      throw Error("Invalid component type");
  }
  for (const r of s.entities)
    if (!["external", "unknown", "store", "broker"].includes(r.type))
      throw Error("Invalid external entity type");
  for (const f of s.flows) {
    if (
      (!nodeIds.has(f.source) &&
        (previousRecords.get(f.id)?.source !== f.source ||
          [...(previous?.components || []), ...(previous?.entities || [])].some(
            (n) => n.id === f.source,
          ))) ||
      (!nodeIds.has(f.target) &&
        (previousRecords.get(f.id)?.target !== f.target ||
          [...(previous?.components || []), ...(previous?.entities || [])].some(
            (n) => n.id === f.target,
          )))
    )
      throw Error("Flow endpoints must exist");
    refs(f, "assetIds", new Set(s.assets.map((a) => a.id)));
  }
  for (const c of s.securityControls) refs(c, "flowIds", flowIds);
  for (const b of s.boundaries) {
    for (const key of ["sourceDomainId", "targetDomainId"])
      if (b[key] && !domainIds.has(b[key]))
        throw Error("Unknown boundary domain");
    if (
      !DIMENSIONS.includes(b.dimension) ||
      !b.before?.trim() ||
      !b.after?.trim() ||
      b.before === b.after
    )
      throw Error(
        "Boundary requires distinct authority contexts and a valid dimension",
      );
    refs(b, "flowIds", flowIds);
  }
  for (const d of s.domains) {
    if (!DIMENSIONS.includes(d.dimension))
      throw Error("Invalid domain dimension");
    refs(d, "memberIds", nodeIds);
    if (d.parentId && !domainIds.has(d.parentId))
      throw Error("Unknown parent domain");
    let parent = d,
      seen = new Set();
    while (parent) {
      if (seen.has(parent.id)) throw Error("Domain cycle");
      seen.add(parent.id);
      parent = s.domains.find((p) => p.id === parent.parentId);
    }
    if (
      d.parentId &&
      s.domains.find((p) => p.id === d.parentId).dimension !== d.dimension
    )
      throw Error("Nested domains must share a dimension");
  }
  for (const a of s.actors) {
    refs(a, "entryIds", nodeIds);
    if (!a.startingAccess?.trim())
      throw Error("Initial access assumption is required");
  }
  for (const t of s.threats) {
    refs(t, "actorIds", new Set(s.actors.map((a) => a.id)));
    refs(t, "flowIds", flowIds);
    refs(t, "boundaryIds", new Set(s.boundaries.map((b) => b.id)));
    refs(t, "categories", new Set(CATEGORIES));
  }
}

export function editSystem(model, input) {
  const current = systemModel(model);
  if (input.revision !== current.revision)
    throw Error("System model changed; refresh before saving");
  const next = structuredClone(model);
  if (input.action === "source-conclusion") {
    const threat = current.threats.find(t => t.id === input.subjectId && t.origin === "analysis");
    const evidence = threat?.validation?.evidence || [];
    if (!evidence.length || threat.reviewState === "stale") throw Error("Current source evidence required");
    if (!["conditional", "open"].includes(input.status)) throw Error("Invalid conclusion");
    const { statement, condition, nextAction, reviewer } = input;
    if (![statement, condition, nextAction, reviewer].every(v => typeof v === "string" && v.trim()))
      throw Error("Conclusion, condition, next action and reviewer are required");
    const ids = input.evidenceIds;
    if (!Array.isArray(ids) || !ids.length || ids.length > 24) throw Error("Select supporting source windows");
    const citations = uniq(ids).map(id => {
      const record = evidence.find(e => e.id === id);
      if (!record?.blobSha256) throw Error("Unknown source window");
      const { repository, path, blobSha256, startLine, endLine } = record;
      return { repository, path, blobSha256, startLine, endLine };
    });
    (next.sourceConclusions ||= {})[threat.id] = {
      status: input.status, statement: clean(statement), condition: clean(condition),
      nextAction: clean(nextAction), reviewer: clean(reviewer), citations,
      contextKey: threat.validation.contextKey, issueHash: threat.validation.issueHash,
    };
    return next;
  }
  const w = (next.architecture ||= empty());
  if (input.action === "decision") {
    const item =
      lists.flatMap((k) => current[k]).find((r) => r.id === input.subjectId) ||
      current.matrix
        .flatMap((r) => r.cells)
        .find((c) => c.id === input.subjectId);
    if (!item) throw Error("Unknown review subject");
    if (
      item.missingReferences?.length &&
      ["accepted", "implemented-in-source", "risk-accepted"].includes(
        input.state,
      )
    )
      throw Error("Repair missing references before accepting this record");
    if (
      ![
        "accepted",
        "rejected",
        "needs-investigation",
        "mitigation-planned",
        "implemented-in-source",
        "risk-accepted",
        "not-applicable",
        "reviewed-no-scenario",
      ].includes(input.state)
    )
      throw Error("Invalid review disposition");
    if (
      input.severity &&
      !["unassessed", "low", "medium", "high", "critical"].includes(
        input.severity,
      )
    )
      throw Error("Invalid severity assessment");
    if (!input.rationale?.trim() || !input.reviewer?.trim())
      throw Error("Reviewer and rationale are required");
    if (
      input.state === "reviewed-no-scenario" &&
      (!input.subjectId.startsWith("cell:") || item.threatIds?.length)
    )
      throw Error("No-scenario disposition requires an empty matrix cell");
    let riskAssessment;
    if (input.riskFactors !== undefined) {
      if (
        !input.riskFactors ||
        typeof input.riskFactors !== "object" ||
        Array.isArray(input.riskFactors)
      )
        throw Error("Invalid risk factors");
      const factors = Object.fromEntries(
        Object.entries(RISK_FACTORS).map(([group, keys]) => [
          group,
          Object.fromEntries(
            keys.map((key) => [key, input.riskFactors[group]?.[key] ?? null]),
          ),
        ]),
      );
      riskAssessment = {
        ...assessRisk(factors),
        factors,
        basis: "reviewer estimate",
      };
    }
    w.decisions = w.decisions.filter((d) => d.subjectId !== input.subjectId);
    w.decisions.push({
      subjectId: input.subjectId,
      fingerprint: item.fingerprint,
      state: input.state,
      rationale: clean(input.rationale),
      reviewer: clean(input.reviewer),
      owner: clean(input.owner),
      severity: riskAssessment
        ? riskAssessment.status === "estimate" &&
          riskAssessment.severity !== "note"
          ? riskAssessment.severity
          : "unassessed"
        : clean(input.severity || "unassessed"),
      ...(riskAssessment ? { riskAssessment } : {}),
      at: new Date().toISOString(),
    });
  } else {
    if (!lists.includes(input.kind)) throw Error("Unknown record type");
    if (input.action === "delete") {
      if (!current[input.kind].some((r) => r.id === input.id))
        throw Error("Unknown object");
      w.removed = uniq([...w.removed, input.id]);
      w.records[input.kind] = (w.records[input.kind] || []).filter(
        (r) => r.id !== input.id,
      );
    } else if (input.action === "upsert") {
      const r = input.record;
      if (r?.accessClassification !== undefined &&
          (input.kind !== 'actors' || !['external', 'internal', 'mixed', 'unresolved'].includes(r.accessClassification)))
        throw Error('Invalid actor access classification');
      if (!r || typeof r !== "object" || Array.isArray(r))
        throw Error("Invalid record");
      const allowed = [
        "id",
        "name",
        "type",
        "description",
        "repositories",
        "interfaceIds",
        "evidenceIds",
        "source",
        "target",
        "protocol",
        "data",
        "controls",
        "assetIds",
        "dimension",
        "before",
        "after",
        "enforcement",
        "flowIds",
        "memberIds",
        "parentId",
        "startingAccess",
        "accessClassification",
        "objectives",
        "excludedCapabilities",
        "entryIds",
        "scenario",
        "categories",
        "actorIds",
        "boundaryIds",
        "asset",
        "prerequisites",
        "mitigation",
        "counterEvidenceIds",
        "controlIds",
        "assumptions",
        "callerIdentity",
        "calleeIdentity",
        "credentialType",
        "authorization",
        "sourceDomainId",
        "targetDomainId",
      ];
      if (Object.keys(r).some((k) => !allowed.includes(k)))
        throw Error("Unsupported record field");
      if (
        r.id &&
        !current[input.kind].some((v) => v.id === r.id) &&
        !/^user-[a-f0-9]{16}$/.test(r.id)
      )
        throw Error("Unknown object ID");
      const record = {};
      for (const [k, v] of Object.entries(r)) {
        if (Array.isArray(v)) {
          if (v.length > 10000 || v.some((x) => typeof x !== "string"))
            throw Error("Invalid reference list");
          record[k] = uniq(v);
        } else if (typeof v === "string") record[k] = clean(v);
        else throw Error("Invalid field value");
      }
      for (const key of [
        "repositories",
        "interfaceIds",
        "evidenceIds",
        "flowIds",
        "entryIds",
        "memberIds",
        "actorIds",
        "boundaryIds",
        "assetIds",
        "categories",
        "counterEvidenceIds",
        "controlIds",
      ])
        record[key] ||= [];
      record.id ||= "user-" + sha(JSON.stringify(r) + Date.now()).slice(0, 16);
      Object.assign(record, claim("reviewer declaration"));
      if (input.kind === "threats") record.origin = "reviewer";
      w.removed = w.removed.filter((v) => v !== record.id);
      w.records[input.kind] = [
        ...(w.records[input.kind] || []).filter((v) => v.id !== record.id),
        record,
      ];
    } else throw Error("Unknown edit action");
    validate(systemModel(next), next, current);
    next.analysisRevision ||= model.modelRevision;
    next.modelRevision = fingerprint([
      next.analysisRevision,
      w.records,
      w.removed,
    ]);
    if (next.cweReview) next.cweReview.status = "stale";
    if (next.cweModelReview) next.cweModelReview.status = "stale";
    if (next.aiReview) {
      next.aiReview.status = "stale";
      next.aiReview.error =
        "Architecture changed; repeat the affected analysis.";
    }
  }
  return next;
}

// Only the bounded interaction subjects relevant to submitted interface IDs are sent.
export function interactionFlowIndex(projection) {
  const byInterface = new Map();
  projection.flows.forEach((flow, index) => {
    for (const id of flow.interfaceIds || []) {
      if (!byInterface.has(id)) byInterface.set(id, []);
      byInterface.get(id).push(index);
    }
  });
  return byInterface;
}
export function interactionContext(model, ids, projection, flowIndex, requiredFlowIds = []) {
  const s = projection || systemModel(model, { matrix: false }),
    included = new Set(ids),
    relevant = (f) => f.interfaceIds?.some((i) => included.has(i));
  const relevantFlows = flowIndex
    ? [...new Set(ids.flatMap((id) => flowIndex.get(id) || []))]
        .sort((a, b) => a - b)
        .map((index) => s.flows[index])
    : s.flows.filter(relevant);
  const required = new Set(requiredFlowIds);
  relevantFlows.sort((a, b) => Number(required.has(b.id)) - Number(required.has(a.id)));
  const flows = relevantFlows.slice(0, Math.max(20, required.size)),
    nodes = new Set(flows.flatMap((f) => [f.source, f.target]));
  const allowedEvidence = new Set(
    model.interfaces
      .filter((i) => included.has(i.id))
      .flatMap((i) => i.evidence),
  );
  const trim = (r) =>
    Object.fromEntries(
      Object.entries(r)
        .filter(
          ([k]) =>
            !["decision", "fingerprint", "missingReferences"].includes(k),
        )
        .map(([k, v]) => [
          k,
          k === "interfaceIds"
            ? v.filter((id) => included.has(id))
            : [
                  "evidenceIds",
                  "counterEvidenceIds",
                  "classificationEvidenceIds",
                ].includes(k)
              ? v.filter((id) => allowedEvidence.has(id))
              : v,
        ]),
    );
  return {
    components: [...s.components, ...s.entities]
      .filter((n) => nodes.has(n.id))
      .slice(0, 40)
      .map(trim),
    assets: s.assets
      .filter((a) => flows.some((f) => f.assetIds?.includes(a.id)))
      .slice(0, 20)
      .map(trim),
    controls: s.securityControls.filter(relevant).slice(0, 20).map(trim),
    omittedFlowCount: Math.max(0, relevantFlows.length - flows.length),
    flows: flows.map(trim),
    actors: s.actors
      .filter(
        (a) =>
          a.reviewState !== "rejected" &&
          a.entryIds.some((id) => nodes.has(id)),
      )
      .slice(0, 12)
      .map(trim),
    boundaries: s.boundaries
      .filter((b) => b.flowIds.some((id) => flows.some((f) => f.id === id)))
      .slice(0, 12)
      .map(trim),
    interpretation:
      "Architecture declarations and actor access assumptions require review. They are not runtime observations. Context is bounded; evidence references are restricted to submitted records. Only cite evidence belonging to the interface IDs listed in each returned scenario.",
  };
}
