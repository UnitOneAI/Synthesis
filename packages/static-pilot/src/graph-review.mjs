import {
  GUIDANCE_VERSION,
  GUIDANCE_HASH,
  GUIDANCE_SOURCES,
} from "./analysis-guidance.mjs";
import { diskPackets } from "./graph-plan-store.mjs";
import { graphReader } from "./graph-store.mjs";
import { failureDetail } from "./diagnostics.mjs";
import {
  coverageObligations,
  obligationFits,
  coverageStatus,
} from "./coverage-plan.mjs";
import { beginUsageRun, beginAttempt, finishAttempt } from "./token-usage.mjs";
import { interactionContext, systemModel } from "./system-model.mjs";
import {
  reviewPacket,
  requestReview,
  publicModelConfig,
  SYSTEM_PROMPT,
  redact,
} from "./model-review.mjs";
import { graphContexts } from "./source-graph.mjs";
import { id, sha } from "./sources.mjs";

export const STRIDE = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];
export const GRAPH_REVIEW_VERSION = "graph-stride-4";

export function reviewPlan(model, excerpts = new Map()) {
  // Analysis proposals are outputs, not new inputs on each continuation.
  // Explicit reviewer records remain in the workspace and still affect packets.
  const system = systemModel(
    { ...model, aiReview: undefined },
    { matrix: false },
  );
  const disk = graphReader(model.sourceGraph),
    generation = model.sourceGraph?.generation;
  if (model.sourceGraph?.storage === "sqlite" && !disk)
    throw Error("Disk graph reader is required; refusing incomplete review");
  const contexts = disk
    ? disk.contexts(generation)
    : graphContexts(model.sourceGraph);
  // All names are untrusted source metadata, not instructions or established facts.
  for (const [key, value] of disk ? [] : contexts) {
    const clean = (v) =>
      typeof v === "string"
        ? redact(v)
        : Array.isArray(v)
          ? v.map(clean)
          : v && typeof v === "object"
            ? Object.fromEntries(
                Object.entries(v).map(([k, x]) => [k, clean(x)]),
              )
            : v;
    contexts.set(key, clean(value));
  }
  const batches = disk ? diskPackets(disk, generation, [], true, excerpts) : [],
    omitted = [];
  const graphNodes = disk
    ? { get: (key) => disk.node(generation, key) }
    : new Map((model.sourceGraph?.nodes || []).map((n) => [n.id, n]));
  const projectReferences = (
    disk
      ? [...disk.edges(generation, { kind: "project-reference" })]
      : model.sourceGraph?.edges || []
  )
    .filter((e) => e.kind === "project-reference")
    .map((e) => ({
      from: graphNodes.get(e.from),
      to: graphNodes.get(e.to),
      basis: e.basis,
    }));
  const structure = coverageObligations(model, system);
  const splits = [];
  function partition(interfaces, phase, label, obligations = [], depth = 0) {
    if (!interfaces.length) return;
    const packet = reviewPacket({ ...model, interfaces }, excerpts, contexts);
    packet.reviewFocus = {
      phase,
      scope: label,
      categories: STRIDE,
      interpretation:
        "Assess relevant categories; no returned threat does not establish safety. Candidate paths and cross-repository cohorts are hypotheses, not established data flows.",
    };
    packet.systemContext = interactionContext(
      model,
      packet.records.map((r) => r.id),
      system,
    );
    // Focused requests select the relevant declarations before context limits apply.
    for (const o of obligations.filter((o) => o.contextKind)) {
      const focused = {
        ...system,
        flows: system.flows.filter((f) =>
          o.interfaceIds.every((x) => f.interfaceIds?.includes(x)),
        ),
        actors: system.actors.filter(
          (a) => o.contextKind !== "actors" || a.id === o.contextId,
        ),
        boundaries: system.boundaries.filter(
          (b) => o.contextKind !== "boundaries" || b.id === o.contextId,
        ),
      };
      packet.systemContext = interactionContext(
        model,
        packet.records.map((r) => r.id),
        focused,
      );
    }
    packet.graphPaths = obligations
      .filter((o) => o.graphNodeIds)
      .map((o) => ({
        obligationId: o.id,
        interfaceIds: o.interfaceIds,
        nodeIds: o.graphNodeIds,
        nodes: o.graphNodeIds
          .map((id) => graphNodes.get(id))
          .filter(Boolean)
          .map((n) => ({
            id: n.id,
            name: redact(n.name),
            kind: n.kind,
            path: redact(n.path || ""),
            line: n.line,
          })),
        basis: o.basis,
      }));
    const repos = new Set(packet.records.map((r) => r.repository));
    const references = projectReferences.filter(
      (e) => repos.has(e.from?.repository) || repos.has(e.to?.repository),
    );
    packet.projectReferences = references.slice(0, 20).map((e) => ({
      fromRepository: redact(e.from.repository),
      fromFile: redact(e.from.path),
      declaration: redact(e.from.pointer || ""),
      toRepository: redact(e.to.repository),
      toFile: redact(e.to.path),
      basis: e.basis,
    }));
    packet.omittedProjectReferenceCount = Math.max(
      0,
      references.length - packet.projectReferences.length,
    );
    if (
      interfaces.length > 60 ||
      packet.records.length !== interfaces.length ||
      Buffer.byteLength(JSON.stringify(packet)) > 96 * 1024
    ) {
      if (interfaces.length === 1) {
        omitted.push(interfaces[0].id);
        return;
      }
      const middle = Math.ceil(interfaces.length / 2);
      splits.push({
        phase,
        label,
        depth,
        records: interfaces.length,
        reason: "packet-budget",
      });
      // Remove spanning obligations from children; an atomic bridge request is planned below.
      for (const half of [
        interfaces.slice(0, middle),
        interfaces.slice(middle),
      ]) {
        const ids = new Set(half.map((i) => i.id));
        partition(
          half,
          phase,
          label,
          obligations.filter((o) => o.interfaceIds.every((x) => ids.has(x))),
          depth + 1,
        );
      }
      return;
    }
    const packetHash = sha(JSON.stringify(packet));
    batches.push({
      id: id(GRAPH_REVIEW_VERSION, phase, packetHash),
      phase,
      label,
      depth,
      packetHash,
      packet,
    });
  }
  const repositories = new Map();
  for (const i of model.interfaces) {
    if (!repositories.has(i.repository)) repositories.set(i.repository, []);
    repositories.get(i.repository).push(i);
  }
  // Round-robin repository batches so a bounded run does not review only the first repo.
  const local = [];
  for (const [repo, interfaces] of repositories) {
    const start = batches.length;
    partition(interfaces, "repository", repo);
    local.push(batches.splice(start));
  }
  for (let n = 0; local.some((group) => group[n]); n++)
    for (const group of local) if (group[n]) batches.push(group[n]);
  const protocols = new Map();
  for (const i of model.interfaces.filter((i) => i.direction !== "control")) {
    if (!protocols.has(i.protocol)) protocols.set(i.protocol, new Map());
    const repos = protocols.get(i.protocol);
    if (!repos.has(i.repository)) repos.set(i.repository, []);
    repos.get(i.repository).push(i);
  }
  for (const [protocol, repos] of protocols) {
    if (repos.size < 2) continue;
    const groups = [...repos.values()],
      ordered = [];
    for (let n = 0; groups.some((g) => g[n]); n++)
      for (const g of groups) if (g[n]) ordered.push(g[n]);
    partition(ordered, "cross-repository", protocol);
  }
  const byId = new Map(model.interfaces.map((i) => [i.id, i]));
  const neighborhoods = new Map();
  for (const o of structure.obligations.filter((o) => o.graphNodeIds)) {
    const repo = byId.get(o.interfaceIds[0])?.repository || "unknown";
    if (!neighborhoods.has(repo)) neighborhoods.set(repo, []);
    neighborhoods.get(repo).push(o);
  }
  for (const [repo, group] of neighborhoods) {
    for (let offset = 0; offset < group.length; offset += 20) {
      const obligations = group.slice(offset, offset + 20);
      const ids = [...new Set(obligations.flatMap((o) => o.interfaceIds))];
      partition(
        ids.map((x) => byId.get(x)),
        "graph-neighborhood",
        repo,
        obligations,
      );
    }
  }
  // Two invalid responses on the same packet trigger deterministic subdivision on continuation.
  // Persist the parent/child tree so successful children remain reusable after restart.
  const refinements = [];
  const priorRefinements = new Map(
    (model.aiReview?.plan?.refinements || []).map((r) => [r.parentId, r]),
  );
  const failedCounts = new Map();
  for (const a of model.usageLedger?.attempts || [])
    if (
      a.status === "failed" &&
      ["response-format", "evidence-validation", "output-limit"].includes(
        a.failure?.code,
      )
    )
      failedCounts.set(a.batchId, (failedCounts.get(a.batchId) || 0) + 1);
  for (let index = 0; index < batches.length; index++) {
    const batch = batches[index],
      prior = priorRefinements.get(batch.id);
    if (
      !(
        prior?.packetHash === batch.packetHash ||
        (failedCounts.get(batch.id) || 0) >= 2
      ) ||
      batch.packet.records.length <= 2 ||
      (batch.refinementDepth || 0) >= 6
    )
      continue;
    const records = batch.packet.records.map((r) => byId.get(r.id));
    const middle = Math.ceil(records.length / 2),
      children = [];
    for (const half of [records.slice(0, middle), records.slice(middle)]) {
      const ids = new Set(half.map((i) => i.id));
      const relevant = structure.obligations.filter(
        (o) =>
          (batch.packet.graphPaths || []).some(
            (p) => p.obligationId === o.id,
          ) && o.interfaceIds.every((x) => ids.has(x)),
      );
      const start = batches.length;
      partition(half, batch.phase, batch.label, relevant);
      children.push(
        ...batches.splice(start).map((b) => ({
          ...b,
          parentId: batch.id,
          refinementDepth: (batch.refinementDepth || 0) + 1,
        })),
      );
    }
    refinements.push({
      parentId: batch.id,
      packetHash: batch.packetHash,
      childIds: children.map((b) => b.id),
      reason: "repeated-invalid-response",
      depth: (batch.refinementDepth || 0) + 1,
    });
    batches.splice(index, 1, ...children);
    index--;
  }
  // Recursively split large scopes, then explicitly bridge obligations cut by partitions.
  // A relationship is never counted as reviewed merely because its endpoints were reviewed separately.
  const byInterface = new Map();
  let indexed = 0;
  const candidates = (obligation) => {
    while (indexed < batches.length) {
      const b = batches[indexed++];
      for (const r of b.packet.records) {
        if (!byInterface.has(r.id)) byInterface.set(r.id, []);
        byInterface.get(r.id).push(indexed - 1);
      }
    }
    return (byInterface.get(obligation.interfaceIds[0]) || []).map(
      (index) => batches[index],
    );
  };
  for (const obligation of structure.obligations.filter(
    (o) => o.kind !== "interface",
  )) {
    if (candidates(obligation).some((b) => obligationFits(obligation, b)))
      continue;
    partition(
      obligation.interfaceIds.map((x) => byId.get(x)).filter(Boolean),
      obligation.kind,
      obligation.subject,
      [obligation],
    );
  }
  const uniqueBatches = new Set();
  for (let index = batches.length - 1; index >= 0; index--) {
    if (uniqueBatches.has(batches[index].id)) batches.splice(index, 1);
    else uniqueBatches.add(batches[index].id);
  }
  byInterface.clear();
  indexed = 0;
  for (const obligation of structure.obligations) {
    obligation.batchIds = candidates(obligation)
      .filter((b) => obligationFits(obligation, b))
      .map((b) => b.id);
    if (!obligation.batchIds.length)
      structure.gaps.push({
        kind: "obligation-does-not-fit",
        subject: obligation.id,
      });
  }
  return {
    batches,
    omitted: [...new Set(omitted)],
    splits,
    refinements,
    ...structure,
  };
}

export function strideMatrix(model) {
  const completed = new Set(
    model.aiReview?.coverage?.reviewedInterfaceIds ||
      (model.aiReview?.status === "completed-needs-review"
        ? model.aiReview.coverage.interfaceIds
        : []),
  );
  const threats =
    model.aiReview?.status === "stale" ? [] : model.aiReview?.threats || [];
  const rows = [
    ...model.components.map((c) => ({
      ...c,
      rowKind: "component",
      interfaceIds: model.interfaces
        .filter((i) => i.component === c.id)
        .map((i) => i.id),
    })),
    ...model.flows.map((f) => ({
      id: f.id,
      name: f.operation,
      rowKind: "flow",
      repository: "Declared flow",
      interfaceIds: [f.from, f.to],
    })),
  ];
  return rows.map((component) => {
    const interfaces = model.interfaces.filter((i) =>
      component.interfaceIds.includes(i.id),
    );
    const ids = new Set(interfaces.map((i) => i.id));
    const reviewed = [...ids].filter((i) => completed.has(i)).length;
    return {
      id: component.id,
      name: component.name,
      rowKind: component.rowKind,
      repository: component.repository,
      interfaces: interfaces.length,
      reviewed,
      cells: STRIDE.map((category) => {
        const matches = threats.filter(
          (t) =>
            t.category === category && t.interfaceIds.some((i) => ids.has(i)),
        );
        const prompts = model.threats.filter(
          (t) =>
            ids.has(t.interface) &&
            t.category.toLowerCase().includes(category.toLowerCase()),
        );
        return {
          category,
          count: matches.length,
          threatIds: matches.map((t) => t.id),
          promptCount: prompts.length,
          promptIds: prompts.map((t) => t.id),
          status:
            model.aiReview?.status === "stale"
              ? "stale"
              : matches.length
                ? "threats-to-review"
                : !reviewed
                  ? "not-reviewed"
                  : reviewed < ids.size
                    ? "partially-reviewed"
                    : "no-scenario-returned",
        };
      }),
    };
  });
}

export async function enrichGraphModel(
  model,
  config,
  excerpts = new Map(),
  fetchImpl = fetch,
  options = {},
) {
  const maxBatches = options.maxBatches ?? 12;
  if (!Number.isInteger(maxBatches) || maxBatches < 1 || maxBatches > 100)
    throw new Error("Model batch budget must be 1–100 requests");
  const plan = reviewPlan(model, excerpts);
  const provenance = {
    ...publicModelConfig(config),
    promptVersion: GRAPH_REVIEW_VERSION,
    promptHash: sha(SYSTEM_PROMPT),
    guidance: {
      version: GUIDANCE_VERSION,
      hash: GUIDANCE_HASH,
      sources: GUIDANCE_SOURCES,
    },
    basedOnRevision: model.modelRevision,
  };
  const runKey = sha(JSON.stringify(provenance));
  await options.trace?.("review.planned", {
    runKey,
    sourceRevision: model.modelRevision,
    graphFingerprint: model.sourceGraph?.fingerprint,
    guidanceVersion: GUIDANCE_VERSION,
    guidanceHash: GUIDANCE_HASH,
    counts: {
      batches: plan.batches.length,
      obligations: plan.obligations.length,
      gaps: plan.gaps.length,
      splits: plan.splits.length,
      refinements: plan.refinements.length,
    },
    budget: maxBatches,
  });
  const previous =
    model.aiReview?.runKey === runKey ? model.aiReview.batches || [] : [];
  const cached = new Map(
    previous.filter((b) => b.status === "completed").map((b) => [b.id, b]),
  );
  const retained = plan.batches
    .map((b) =>
      cached.get(b.id)?.packetHash === b.packetHash ? cached.get(b.id) : null,
    )
    .filter(Boolean);
  const order = new Map(plan.batches.map((b, index) => [b.id, index]));
  const review = {
    ...provenance,
    runKey,
    status: "pending",
    mode: excerpts.size ? "source-excerpts" : "metadata",
    batches: [...retained],
    threats: [],
    connections: [],
    questions: [],
    summary:
      "Graph-based review in bounded repository and cross-repository batches.",
    coverage: {},
    plan: {
      basedOnRevision: model.modelRevision,
      version: GRAPH_REVIEW_VERSION,
      splits: plan.splits,
      refinements: plan.refinements,
      obligations: plan.obligations,
      gaps: plan.gaps,
      limits: plan.limits,
      semantics: plan.semantics,
      batches: plan.batches.map(({ packet, ...b }) => ({
        ...b,
        interfaceIds: packet.records.map((r) => r.id),
        packetBytes: Buffer.byteLength(JSON.stringify(packet)),
      })),
    },
  };
  beginUsageRun(model);
  model.aiReview = review;
  model.provider = config.provider;
  const submitted = new Set(retained.flatMap((b) => b.interfaceIds)),
    reviewed = new Set(submitted);
  let calls = 0,
    terminalFailure = false;
  const deadline = Date.now() + 24 * 60 * 1000;
  const aggregate = () => {
    // Every checkpoint retains compatible successes, including later plan entries.
    review.batches.sort((a, b) => order.get(a.id) - order.get(b.id));
    review.threats = [];
    review.connections = [];
    review.questions = [];
    const threatKeys = new Set(),
      connectionKeys = new Set();
    for (const b of review.batches.filter((b) => b.status === "completed")) {
      for (const t of b.review.threats) {
        const key = sha(
          JSON.stringify([t.category, [...t.interfaceIds].sort(), t.title]),
        );
        if (!threatKeys.has(key)) {
          threatKeys.add(key);
          review.threats.push({
            ...t,
            id: id("graph-threat", key),
            batchId: b.id,
          });
        }
      }
      for (const c of b.review.connections) {
        const key = sha(JSON.stringify([c.from, c.to, c.reason]));
        if (!connectionKeys.has(key)) {
          connectionKeys.add(key);
          review.connections.push({
            ...c,
            id: id("graph-connection", key),
            batchId: b.id,
          });
        }
      }
      review.questions.push(...b.review.questions);
    }
    review.questions = [...new Set(review.questions)];
    const done = review.batches.filter((b) => b.status === "completed").length;
    const sentBatches = new Set(review.batches.map((b) => b.id));
    const sentPackets = plan.batches.filter((b) => sentBatches.has(b.id));
    review.coverage = {
      obligations: (() => {
        const { obligations, gaps, ...summary } = coverageStatus(
          plan,
          review.batches,
        );
        return { ...summary, gapCount: gaps.length };
      })(),
      totalInterfaces: model.interfaces.length,
      submittedInterfaces: submitted.size,
      omittedInterfaces: model.interfaces.length - submitted.size,
      interfaceIds: [...submitted],
      reviewedInterfaceIds: [...reviewed],
      reviewedInterfaces: reviewed.size,
      unreviewedInterfaces: model.interfaces.length - reviewed.size,
      totalBatches: plan.batches.length,
      completedBatches: done,
      failedBatches: review.batches.filter((b) => b.status === "failed").length,
      pendingBatches:
        plan.batches.length -
        done -
        review.batches.filter((b) => b.status === "failed").length,
      callsThisRun: calls,
      batchBudget: maxBatches,
      oversizedRecords: plan.omitted,
      excerptCount: plan.batches.reduce(
        (n, b) =>
          n +
          b.packet.records.reduce(
            (n, r) => n + r.evidence.filter((e) => e.excerpt).length,
            0,
          ),
        0,
      ),
      packetBytes: plan.batches.reduce(
        (n, b) => n + Buffer.byteLength(JSON.stringify(b.packet)),
        0,
      ),
    };
    review.packetHash = sha(plan.batches.map((b) => b.packetHash).join(""));
    review.coverage.plannedPacketBytes = review.coverage.packetBytes;
    review.coverage.packetBytes = sentPackets.reduce(
      (n, b) => n + Buffer.byteLength(JSON.stringify(b.packet)),
      0,
    );
    review.coverage.excerptCount = new Set(
      sentPackets.flatMap((b) =>
        b.packet.records.flatMap((r) =>
          r.evidence.filter((e) => e.excerpt).map((e) => e.id),
        ),
      ),
    ).size;
    review.responseHash = sha(
      review.batches
        .filter((b) => b.status === "completed")
        .map((b) => b.responseHash)
        .join(""),
    );
  };
  for (const batch of plan.batches) {
    const prior = cached.get(batch.id);
    if (prior?.packetHash === batch.packetHash) {
      await options.trace?.("review.cache-reused", {
        runKey,
        batchId: batch.id,
        packetHash: batch.packetHash,
      });
      continue;
    }
    if (terminalFailure || calls >= maxBatches || Date.now() > deadline)
      continue;
    options.progress?.(
      `STRIDE review ${review.batches.length + 1}/${plan.batches.length}: ${batch.phase} · ${batch.label}`,
    );
    const entry = {
      id: batch.id,
      phase: batch.phase,
      label: batch.label,
      packetHash: batch.packetHash,
      interfaceIds: batch.packet.records.map((r) => r.id),
      status: "pending",
    };
    review.batches.push(entry);
    calls++;
    entry.interfaceIds.forEach((i) => submitted.add(i));
    let attempt;
    try {
      const failed = previous.find(
        (b) =>
          b.id === batch.id &&
          b.packetHash === batch.packetHash &&
          b.status === "failed",
      );
      entry.validationRetry = Boolean(
        failed &&
          /schema or evidence validation|required JSON|output-token budget|request failed or timed out/.test(
            failed.error || "",
          ),
      );
      attempt = beginAttempt(model, config, batch.packet, {
        batchId: batch.id,
        phase: batch.phase,
        retry:
          Boolean(batch.parentId) ||
          model.usageLedger.attempts.some(
            (a) =>
              a.batchId === batch.id &&
              a.provider === config.provider &&
              a.model === config.model &&
              a.status !== "succeeded",
          ),
      });
      if (batch.parentId) attempt.parentBatchId = batch.parentId;
      await options.trace?.("model.request-started", {
        runKey,
        batchId: batch.id,
        attemptId: attempt.id,
        phase: batch.phase,
        packetHash: batch.packetHash,
        counts: {
          records: batch.packet.records.length,
          packetBytes: Buffer.byteLength(JSON.stringify(batch.packet)),
        },
        provider: config.provider,
        model: config.model,
        retry: attempt.retry,
      });
      aggregate();
      await options.checkpoint?.(
        structuredClone(review),
        structuredClone(model.usageLedger),
      );
      const result = await requestReview(config, batch.packet, fetchImpl, {
        validationRetry: entry.validationRetry,
        onResponse: (response) =>
          options.trace?.("model.response-received", {
            runKey,
            batchId: batch.id,
            attemptId: attempt.id,
            ...response,
          }),
        onStop: (response) =>
          options.trace?.("model.stop-reason", {
            runKey,
            batchId: batch.id,
            attemptId: attempt.id,
            ...response,
          }),
        onUsage: async (usage) => {
          attempt.usage = usage;
          await options.trace?.("model.usage-received", {
            runKey,
            batchId: batch.id,
            attemptId: attempt.id,
            usage,
          });
          await options.checkpoint?.(
            structuredClone(review),
            structuredClone(model.usageLedger),
          );
        },
      });
      finishAttempt(attempt, "succeeded");
      Object.assign(entry, {
        status: "completed",
        review: result.review,
        responseHash: result.responseHash,
        requestPromptHash: result.requestPromptHash,
      });
      entry.interfaceIds.forEach((i) => reviewed.add(i));
      await options.trace?.("model.request-completed", {
        runKey,
        batchId: batch.id,
        attemptId: attempt.id,
        responseHash: result.responseHash,
        requestPromptHash: result.requestPromptHash,
      });
    } catch (error) {
      if (attempt) {
        finishAttempt(attempt, "failed");
        attempt.failure = failureDetail(error.message);
      }
      entry.status = "failed";
      entry.error = error.message;
      await options.trace?.("model.request-failed", {
        runKey,
        batchId: batch.id,
        attemptId: attempt?.id,
        failure: failureDetail(error.message),
      });
      terminalFailure = /HTTP (?:401|403|429)|request failed or timed out/.test(
        error.message,
      );
    }
    aggregate();
    await options.checkpoint?.(
      structuredClone(review),
      structuredClone(model.usageLedger),
    );
  }
  aggregate();
  review.status = !plan.batches.length
    ? "skipped"
    : review.coverage.completedBatches === plan.batches.length &&
        !plan.omitted.length &&
        !review.coverage.obligations.blocked
      ? "completed-needs-review"
      : review.coverage.completedBatches
        ? "partial"
        : "failed";
  review.error =
    review.status === "completed-needs-review"
      ? undefined
      : review.batches.find((b) => b.status === "failed")?.error ||
        (!plan.batches.length
          ? "No collected interfaces to review"
          : "Review budget reached; continue to review pending batches. Source and graph coverage gaps remain.");
  await options.trace?.("review.finished", {
    runKey,
    status: review.status,
    counts: {
      completed: review.coverage.completedBatches,
      failed: review.coverage.failedBatches,
      pending: review.coverage.pendingBatches,
      obligations: review.coverage.obligations,
    },
    stopReason: terminalFailure
      ? "provider-failure"
      : calls >= maxBatches
        ? "request-budget"
        : Date.now() > deadline
          ? "time-budget"
          : "plan-exhausted",
  });
  await options.checkpoint?.(
    structuredClone(review),
    structuredClone(model.usageLedger),
  );
  return model;
}
