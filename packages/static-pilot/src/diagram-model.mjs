import { id } from "./sources.mjs";
const unique = (a) => [...new Set(a)].sort();
const usable = (r) => !["rejected", "stale"].includes(r.reviewState);
export function actorPath(s, actorId) {
  const actor = s.actors.find((a) => a.id === actorId && usable(a));
  const reached = new Set(actor?.entryIds || []),
    edges = new Set();
  // Finite graph traversal; no arbitrary six-hop truncation.
  const outgoing = new Map();
  for (const f of s.flows.filter(
    (f) => usable(f) && f.basis !== "unresolved",
  )) {
    if (!outgoing.has(f.source)) outgoing.set(f.source, []);
    outgoing.get(f.source).push(f);
  }
  const queue = [...reached];
  for (let at = 0; at < queue.length; at++)
    for (const f of outgoing.get(queue[at]) || []) {
      edges.add(f.id);
      if (!reached.has(f.target)) {
        reached.add(f.target);
        queue.push(f.target);
      }
    }
  return { flowIds: [...edges], nodeIds: [...reached], conditional: true };
}
export function diagramModel(s, options = {}) {
  const {
    level = "system",
    lens = "identity",
    focus = "",
    actor = "",
    threat = "",
    showUnresolved = false,
    showSupporting = false,
  } = options;
  const limit = Number.isFinite(options.limit)
    ? Math.max(1, Math.min(200, options.limit))
    : 80;
  const path = actorPath(s, actor),
    active = new Set([
      ...path.flowIds,
      ...(s.threats.find((t) => t.id === threat)?.flowIds || []),
    ]);
  const domains = s.domains.filter((d) => d.dimension === lens && usable(d));
  const memberships = (n) =>
    unique(
      domains.filter((d) => d.memberIds?.includes(n)).map((d) => d.id),
    ).join(" ");
  const all = [...s.components, ...s.entities],
    byId = new Map(all.map((n) => [n.id, n]));
  const owners = new Map(all.map((n) => [n.id, n.id]));
  if (level !== "focus")
    for (const n of s.components) {
      const host = byId.get(n.hostCandidateId);
      if (
        host &&
        usable(host) &&
        usable(n) &&
        !n.decision &&
        n.basis !== "reviewer declaration" &&
        memberships(n.id) === memberships(host.id)
      )
        owners.set(n.id, host.id);
    }
  // System view groups logical resources by technology and source owner. This is
  // presentation grouping only, never an assertion of a shared physical database.
  if (level === "system" && !showSupporting) {
    const resourceGroups = new Map();
    for (const n of s.entities.filter(
      (n) =>
        n.resourceKind &&
        usable(n) &&
        !n.decision &&
        n.basis !== "reviewer declaration",
    )) {
      const key = [
        n.parentComponentId,
        n.resourceKind,
        n.scope,
        memberships(n.id),
      ].join(":");
      if (!resourceGroups.has(key)) resourceGroups.set(key, n.id);
      if (!n.decision && n.basis !== "reviewer declaration")
        owners.set(n.id, resourceGroups.get(key));
    }
    for (const n of s.components.filter((n) => n.internalRole && usable(n))) {
      if (
        n.decision ||
        n.basis === "reviewer declaration" ||
        memberships(n.id) !== memberships(n.parentComponentId)
      )
        continue;
      if (n.internalRole === "client-adapter")
        owners.set(n.id, n.parentComponentId);
      if (n.internalRole === "storage-adapter") {
        const destinations = s.flows
          .filter(
            (f) => f.source === n.id && f.protocol === "storage" && usable(f),
          )
          .map((f) => f.target);
        const groups = unique(
          destinations.map((target) => owners.get(target) || target),
        );
        if (
          groups.length === 1 &&
          !byId.get(groups[0])?.decision &&
          memberships(n.id) === memberships(groups[0])
        )
          owners.set(n.id, groups[0]);
      }
    }
  }
  // Resolve presentation ownership transitively (adapter -> library -> host).
  for (const [node, initial] of owners) {
    const seen = new Set([node]);
    let owner = initial;
    while (
      owner !== owners.get(owner) &&
      owners.has(owner) &&
      !seen.has(owner)
    ) {
      seen.add(owner);
      owner = owners.get(owner);
    }
    owners.set(node, seen.has(owner) && owner !== node ? node : owner);
  }
  let nodes = all
    .filter(usable)
    .filter((n) => owners.get(n.id) === n.id)
    .map((n) => {
      const members = all.filter((m) => owners.get(m.id) === n.id);
      return {
        ...n,
        name: n.resourceKind
          ? `${n.resourceKind}${members.filter((m) => m.resourceKind).length > 1 ? ` · ${members.filter((m) => m.resourceKind).length} logical resources` : ""}`
          : n.name,
        memberIds: members.map((m) => m.id),
        evidenceIds: unique(members.flatMap((m) => m.evidenceIds || [])),
        interfaceIds: unique(members.flatMap((m) => m.interfaceIds || [])),
      };
    });
  let flows = s.flows.filter(usable).map((f) => ({
    ...f,
    source: owners.get(f.source) || f.source,
    target: owners.get(f.target) || f.target,
  }));
  flows = flows.filter(
    (f) =>
      f.source !== f.target ||
      s.flows.find((original) => original.id === f.id)?.source ===
        s.flows.find((original) => original.id === f.id)?.target,
  );
  const unresolvedCount = s.flows.filter(
    (f) => f.basis === "unresolved",
  ).length;
  if (!showUnresolved) {
    flows = flows.filter((f) => f.basis !== "unresolved");
    nodes = nodes.filter((n) => n.basis !== "unresolved");
  }
  if (!showSupporting && level !== "focus") {
    const omitted = new Set(
      nodes
        .filter((n) => n.scope && n.scope !== "production-candidate")
        .map((n) => n.id),
    );
    nodes = nodes.filter((n) => !omitted.has(n.id));
    flows = flows.filter(
      (f) =>
        !omitted.has(f.source) &&
        !omitted.has(f.target) &&
        (!f.scope || f.scope === "production-candidate"),
    );
  }
  if (level === "context") {
    const internal = new Set(s.components.map((n) => owners.get(n.id)));
    flows = flows
      .filter((f) => internal.has(f.source) !== internal.has(f.target))
      .map((f) => ({
        ...f,
        source: internal.has(f.source) ? "system-scope" : f.source,
        target: internal.has(f.target) ? "system-scope" : f.target,
      }));
    nodes = [
      {
        id: "system-scope",
        name: s.title,
        type: "process",
        basis: "scope boundary; not a trust boundary",
        memberIds: [...internal],
        evidenceIds: [],
        interfaceIds: [],
      },
      ...nodes.filter((n) => !internal.has(n.id)),
    ];
  } else if (level === "focus" && focus) {
    const neighbors = new Set([focus]);
    for (const f of flows)
      if (f.source === focus || f.target === focus) {
        neighbors.add(f.source);
        neighbors.add(f.target);
      }
    nodes = nodes.filter((n) => neighbors.has(n.id));
    flows = flows.filter((f) => f.source === focus || f.target === focus);
  } else if (!showSupporting) {
    const connected = new Set(flows.flatMap((f) => [f.source, f.target]));
    nodes = nodes.filter(
      (n) =>
        n.type !== "source-group" ||
        connected.has(n.id) ||
        n.basis === "reviewer declaration",
    );
  }
  const filteredFlowCount = s.flows.length - flows.length;
  const available = new Set(nodes.map((n) => n.id));
  flows = flows.filter(
    (f) => available.has(f.source) && available.has(f.target),
  );
  const grouped = new Map();
  for (const f of flows) {
    // Do not erase differences in direction, identity, authority, data or disposition.
    const boundaryIds = unique(
      s.boundaries
        .filter((b) => b.flowIds.includes(f.id) && usable(b))
        .map((b) => b.id),
    );
    // Boundary IDs differ per call; equivalent candidate transitions may share a connector.
    const boundarySemantics = unique(
      s.boundaries
        .filter((b) => boundaryIds.includes(b.id))
        .map((b) =>
          JSON.stringify([
            b.dimension,
            b.before,
            b.after,
            b.enforcement,
            b.reviewState,
            b.basis,
            b.basis === "reviewer declaration" ? b.id : null,
          ]),
        ),
    );
    const key = JSON.stringify([
      f.source,
      f.target,
      f.protocol,
      f.transport || "unknown",
      f.data,
      f.controls,
      f.basis,
      f.reviewState,
      f.callerIdentity,
      f.calleeIdentity,
      f.credentialType,
      f.authorization,
      unique(f.controlIds || []),
      unique(f.assetIds || []),
      boundarySemantics,
    ]);
    if (!grouped.has(key))
      grouped.set(key, {
        ...f,
        id: id("diagram-flow", key),
        flowIds: [],
        interfaceIds: [],
        evidenceIds: [],
        boundaryIds: [],
        active: false,
      });
    const g = grouped.get(key);
    g.flowIds.push(f.id);
    g.interfaceIds.push(...(f.interfaceIds || []));
    g.evidenceIds.push(...(f.evidenceIds || []));
    g.boundaryIds.push(...boundaryIds);
    g.active ||= active.has(f.id);
  }
  let connections = [...grouped.values()].map((g) => ({
    ...g,
    flowIds: unique(g.flowIds),
    interfaceIds: unique(g.interfaceIds),
    evidenceIds: unique(g.evidenceIds),
    boundaryIds: unique(g.boundaryIds),
    name: `${g.protocol || "Data flow"} · ${g.flowIds.length} flow${g.flowIds.length === 1 ? "" : "s"}`,
  }));
  const included = new Set();
  if (available.has(focus)) included.add(focus);
  for (const n of nodes.filter((n) =>
    n.memberIds.some((id) => path.nodeIds.includes(id)),
  ))
    if (included.size < limit) included.add(n.id);
  for (const f of [...connections].sort(
    (a, b) => Number(b.active) - Number(a.active) || a.id.localeCompare(b.id),
  )) {
    const pair = unique([f.source, f.target]);
    if (included.size + pair.filter((id) => !included.has(id)).length <= limit)
      pair.forEach((id) => included.add(id));
  }
  for (const n of nodes) if (included.size < limit) included.add(n.id);
  const totalNodes = nodes.length,
    totalConnections = connections.length;
  nodes = nodes.filter((n) => included.has(n.id));
  connections = connections
    .filter((f) => included.has(f.source) && included.has(f.target))
    .sort(
      (a, b) => Number(b.active) - Number(a.active) || a.id.localeCompare(b.id),
    )
    .slice(0, 240);
  const count = connections.reduce((n, f) => n + f.flowIds.length, 0);
  return {
    level,
    lens,
    nodes,
    connections,
    domains: level === "context" ? [] : domains,
    boundaries: s.boundaries.filter(usable),
    activeNodeIds: nodes
      .filter((n) => n.memberIds.some((id) => path.nodeIds.includes(id)))
      .map((n) => n.id),
    coverage: {
      totalNodes,
      visibleNodes: nodes.length,
      totalConnections,
      visibleConnections: connections.length,
      representedFlows: count,
      filteredFlows: filteredFlowCount,
      nonProductionFlows: s.flows.filter(
        (f) => f.scope && f.scope !== "production-candidate",
      ).length,
      unresolvedRelationships: unresolvedCount,
      hiddenObjects: all.length - nodes.flatMap((n) => n.memberIds).length,
      omittedNodes: totalNodes - nodes.length,
      omittedConnections: totalConnections - connections.length,
    },
    relatedThreatIds: s.threats
      .filter(
        (t) =>
          t.origin !== "review checklist" &&
          (actor ? t.actorIds.includes(actor) : false),
      )
      .map((t) => t.id),
  };
}

// Rank strongly connected components, then order each rank by neighbor position.
// The canvas is bounded before layout; the underlying graph and registers are not.
export function layoutDiagram(d) {
  const outgoing = new Map(d.nodes.map((n) => [n.id, []]));
  for (const f of d.connections) outgoing.get(f.source)?.push(f.target);
  let serial = 0;
  const index = new Map(),
    low = new Map(),
    stack = [],
    onStack = new Set(),
    groups = [],
    groupOf = new Map();
  function visit(v) {
    index.set(v, serial);
    low.set(v, serial++);
    stack.push(v);
    onStack.add(v);
    for (const w of outgoing.get(v) || []) {
      if (!index.has(w)) {
        visit(w);
        low.set(v, Math.min(low.get(v), low.get(w)));
      } else if (onStack.has(w)) low.set(v, Math.min(low.get(v), index.get(w)));
    }
    if (low.get(v) === index.get(v)) {
      const members = [];
      let w;
      do {
        w = stack.pop();
        onStack.delete(w);
        groupOf.set(w, groups.length);
        members.push(w);
      } while (w !== v);
      groups.push(members.sort());
    }
  }
  for (const n of [...d.nodes].sort((a, b) => a.id.localeCompare(b.id)))
    if (!index.has(n.id)) visit(n.id);
  const links = groups.map(() => new Set()),
    indegree = groups.map(() => 0),
    ranks = groups.map(() => 0);
  for (const f of d.connections) {
    const a = groupOf.get(f.source),
      b = groupOf.get(f.target);
    if (a !== b && !links[a].has(b)) {
      links[a].add(b);
      indegree[b]++;
    }
  }
  const queue = indegree.flatMap((v, i) => (v === 0 ? [i] : []));
  for (let at = 0; at < queue.length; at++)
    for (const b of links[queue[at]]) {
      ranks[b] = Math.max(ranks[b], ranks[queue[at]] + 1);
      if (!--indegree[b]) queue.push(b);
    }
  const nodeRank = new Map();
  groups.forEach((members, i) =>
    members.forEach((id, j) =>
      nodeRank.set(id, ranks[i] * 2 + (members.length > 1 ? j % 2 : 0)),
    ),
  );
  const distinct = unique([...nodeRank.values()]).sort((a, b) => a - b);
  for (const [id, r] of nodeRank) nodeRank.set(id, distinct.indexOf(r));
  const positions = new Map(),
    boxes = [],
    assigned = new Set();
  const width = Math.max(950, distinct.length * 420 + 100);
  function lane(members, y) {
    const columns = new Map();
    for (const n of members) {
      const r = nodeRank.get(n.id);
      if (!columns.has(r)) columns.set(r, []);
      columns.get(r).push(n);
    }
    for (const [r, members] of [...columns].sort((a, b) => a[0] - b[0])) {
      const score = (n) => {
        const parents = d.connections
          .filter((f) => f.target === n.id)
          .map((f) => positions.get(f.source)?.y)
          .filter(Number.isFinite);
        return parents.length
          ? parents.reduce((a, b) => a + b, 0) / parents.length
          : 0;
      };
      members
        .sort((a, b) => score(a) - score(b) || a.name.localeCompare(b.name))
        .forEach((n, i) =>
          positions.set(n.id, { x: 45 + r * 420, y: y + i * 150 }),
        );
    }
    return y + Math.max(1, ...[...columns.values()].map((v) => v.length)) * 150;
  }
  const domainIds = new Set(d.domains.map((g) => g.id));
  function region(g, y, depth = 0, seen = new Set()) {
    if (seen.has(g.id)) return y;
    const nextSeen = new Set([...seen, g.id]);
    let end = y + 40;
    for (const child of d.domains.filter((c) => c.parentId === g.id))
      end = region(child, end, depth + 1, nextSeen);
    const members = d.nodes.filter(
      (n) => g.memberIds?.includes(n.id) && !assigned.has(n.id),
    );
    members.forEach((n) => assigned.add(n.id));
    if (members.length) end = lane(members, end);
    if (end > y + 40)
      boxes.push({
        domain: g,
        x: 12 + depth * 7,
        y,
        width: width - 24 - depth * 14,
        height: end - y,
        depth,
      });
    return end + 18;
  }
  let y = 100;
  for (const g of d.domains.filter((g) => !domainIds.has(g.parentId)))
    y = region(g, y);
  const rest = d.nodes.filter((n) => !assigned.has(n.id));
  if (rest.length) y = lane(rest, y);
  return {
    positions,
    boxes: boxes.sort((a, b) => a.depth - b.depth),
    width,
    height: Math.max(320, y + 60),
  };
}
