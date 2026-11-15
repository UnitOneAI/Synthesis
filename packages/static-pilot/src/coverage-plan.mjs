import { graphReader } from "./graph-store.mjs";
import { id } from "./sources.mjs";

export const PLANNER_LIMITS = Object.freeze({
  reachableFunctionsPerRoot: 4096,
  obligations: 50000,
});

// Iterative traversal is recursion over the graph with an explicit visited set.
// One shortest candidate path per endpoint pair; never all possible execution paths.
export function coverageObligations(model, system) {
  const obligations = [],
    gaps = [];
  const disk = graphReader(model.sourceGraph),
    generation = model.sourceGraph?.generation;
  if (model.sourceGraph?.storage === "sqlite" && !disk)
    throw Error("Disk graph reader is required; refusing incomplete review");
  const nodes = disk
    ? {
        get: (key) => disk.node(generation, key),
        values: () => disk.nodes(generation),
      }
    : new Map((model.sourceGraph?.nodes || []).map((n) => [n.id, n]));
  const interfaces = new Map(model.interfaces.map((i) => [i.id, i]));
  const owned = new Map(),
    next = new Map(),
    targets = new Map();
  const seen = new Set();
  let omitted = 0;
  const add = (kind, subject, interfaceIds, extra = {}) => {
    const ids = [...new Set(interfaceIds)].sort();
    const key = id("obligation", kind, subject, ids);
    if (seen.has(key)) return;
    seen.add(key);
    if (obligations.length >= PLANNER_LIMITS.obligations) {
      omitted++;
      return;
    }
    obligations.push({ id: key, kind, subject, interfaceIds: ids, ...extra });
  };
  for (const i of model.interfaces) {
    add("interface", i.id, [i.id]);
    const n = nodes.get(i.id);
    if (!n) {
      gaps.push({ kind: "interface-not-in-graph", subject: i.id });
      continue;
    }
    if (nodes.get(n.parent)?.kind !== "function") continue;
    if (!owned.has(n.parent)) owned.set(n.parent, []);
    owned.get(n.parent).push(i.id);
  }
  for (const e of disk ? [] : model.sourceGraph?.edges || []) {
    if (e.kind !== "candidate-call-target") continue;
    targets.set(e.from, e.to);
    const call = nodes.get(e.from);
    if (!call || nodes.get(call.parent)?.kind !== "function") continue;
    if (!next.has(call.parent)) next.set(call.parent, []);
    next.get(call.parent).push({ to: e.to, call: e.from });
  }
  for (const [root, rootIds] of owned) {
    // Ownership groups bring nearby controls into the same review context.
    if (rootIds.length > 1)
      add("callable-context", root, rootIds, {
        graphNodeIds: [root],
        basis: "same callable; enforcement unverified",
      });
    if (disk) {
      for (const step of disk.walk(
        generation,
        root,
        PLANNER_LIMITS.reachableFunctionsPerRoot,
      )) {
        if (step.done) {
          if (step.limited)
            gaps.push({
              kind: "traversal-limit",
              subject: root,
              visitedFunctions: step.count,
            });
          continue;
        }
        for (const from of rootIds)
          for (const to of owned.get(step.target) || [])
            add(
              "candidate-call-path",
              id(root, step.target, from, to),
              [from, to],
              {
                graphNodeIds: step.path,
                basis:
                  "transitive candidate call targets; dispatch, reachability and enforcement unverified",
              },
            );
      }
    } else {
      const queue = [root],
        previous = new Map([[root, null]]);
      let limited = false;
      for (let cursor = 0; cursor < queue.length; cursor++) {
        const current = queue[cursor];
        for (const edge of next.get(current) || []) {
          if (previous.has(edge.to)) continue;
          if (previous.size >= PLANNER_LIMITS.reachableFunctionsPerRoot) {
            limited = true;
            continue;
          }
          previous.set(edge.to, { from: current, call: edge.call });
          queue.push(edge.to);
        }
        if (current === root || !owned.has(current)) continue;
        const path = [current];
        for (let at = current; previous.get(at); ) {
          const step = previous.get(at);
          path.push(step.call, step.from);
          at = step.from;
        }
        path.reverse();
        for (const from of rootIds)
          for (const to of owned.get(current))
            add(
              "candidate-call-path",
              id(root, current, from, to),
              [from, to],
              {
                graphNodeIds: path,
                basis:
                  "transitive candidate call targets; dispatch, reachability and control enforcement unverified",
              },
            );
      }
      if (limited)
        gaps.push({
          kind: "traversal-limit",
          subject: root,
          visitedFunctions: previous.size,
        });
    }
  }

  for (const f of model.flows || [])
    add(
      "declared-flow",
      f.id,
      [f.from, f.to].filter((x) => interfaces.has(x)),
    );
  for (const f of system.flows) {
    if (
      f.basis === "unresolved" ||
      f.reviewState === "rejected" ||
      f.reviewState === "stale"
    ) {
      gaps.push({ kind: "unresolved-or-inactive-flow", subject: f.id });
      continue;
    }
    const ids = (f.interfaceIds || []).filter((x) => interfaces.has(x));
    if (!ids.length) {
      gaps.push({ kind: "flow-without-source-interfaces", subject: f.id });
      continue;
    }
    add("system-flow", f.id, ids, { contextKind: "flows" });
    for (const b of system.boundaries.filter((b) => b.flowIds.includes(f.id)))
      add("boundary-crossing", b.id + ":" + f.id, ids, {
        contextKind: "boundaries",
        contextId: b.id,
      });
    for (const a of system.actors.filter(
      (a) =>
        a.reviewState !== "rejected" &&
        a.reviewState !== "stale" &&
        a.entryIds.some((x) => x === f.source || x === f.target),
    ))
      add("actor-access", a.id + ":" + f.id, ids, {
        contextKind: "actors",
        contextId: a.id,
      });
  }
  for (const a of system.actors.filter(
    (a) => a.basis === "assumption" && a.reviewState !== "accepted",
  ))
    gaps.push({ kind: "actor-access-needs-confirmation", subject: a.id });
  for (const b of system.boundaries.filter((b) => b.basis === "inference"))
    gaps.push({ kind: "boundary-needs-confirmation", subject: b.id });
  if (!system.actors.length)
    gaps.push({ kind: "actor-assumptions-not-declared" });
  if (!system.boundaries.length)
    gaps.push({ kind: "trust-boundaries-not-declared" });
  const unresolvedCalls = disk
    ? disk.unresolved(generation)
    : [...nodes.values()].filter(
        (n) => n.kind === "call" && !targets.has(n.id),
      );
  // Retain identifiers; names/expressions are unnecessary for diagnosing resolution coverage.
  const unresolvedCounts = new Map();
  let retainedUnresolved = 0;
  for (const n of unresolvedCalls) {
    if (disk && retainedUnresolved++ >= 1000) {
      unresolvedCounts.set(
        n.repository,
        (unresolvedCounts.get(n.repository) || 0) + 1,
      );
      continue;
    }
    gaps.push({
      kind: "unresolved-call-target",
      subject: n.id,
      repository: n.repository,
      path: n.path,
      line: n.line,
    });
  }
  for (const [repository, count] of unresolvedCounts)
    gaps.push({
      kind: "additional-unresolved-call-targets",
      repository,
      count,
      detail:
        "Full identifiers are in reference-resolution.ndjson and the stored graph",
    });
  if (omitted)
    gaps.push({
      kind: "obligation-limit",
      omitted,
      limit: PLANNER_LIMITS.obligations,
    });
  return {
    obligations,
    gaps,
    limits: PLANNER_LIMITS,
    semantics:
      "Submission coverage of collected evidence, not proof of complete analysis. One shortest candidate path per endpoint pair; cycles terminate using visited functions. Alternative paths and dynamic dispatch remain unproven.",
  };
}

export function obligationFits(obligation, batch) {
  const ids = new Set(batch.packet.records.map((r) => r.id));
  if (
    !obligation.interfaceIds.length ||
    !obligation.interfaceIds.every((id) => ids.has(id))
  )
    return false;
  if (
    obligation.graphNodeIds?.length &&
    !batch.packet.graphPaths?.some((p) => p.obligationId === obligation.id)
  )
    return false;
  if (
    obligation.contextKind &&
    !batch.packet.systemContext?.[obligation.contextKind]?.some(
      (x) => x.id === (obligation.contextId || obligation.subject),
    )
  )
    return false;
  return true;
}

export function coverageStatus(plan, completed = []) {
  const successful = new Set(
    completed.filter((b) => b.status === "completed").map((b) => b.id),
  );
  const counts = { total: 0, reviewed: 0, pending: 0, blocked: 0 };
  const byKind = {};
  const obligations = plan.obligations.map((o) => {
    const status = !o.batchIds.length
      ? "blocked"
      : o.batchIds.some((x) => successful.has(x))
        ? "reviewed"
        : "pending";
    const group = (byKind[o.kind] ||= {
      total: 0,
      reviewed: 0,
      pending: 0,
      blocked: 0,
    });
    counts.total++;
    counts[status]++;
    group.total++;
    group[status]++;
    return { ...o, status };
  });
  return {
    ...counts,
    byKind,
    obligations,
    gaps: plan.gaps,
    limits: plan.limits,
    semantics: plan.semantics,
  };
}
