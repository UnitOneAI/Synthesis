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
export const GRAPH_REVIEW_VERSION = "graph-stride-1";

export function reviewPlan(model, excerpts = new Map()) {
  const contexts = graphContexts(model.sourceGraph);
  // All names are untrusted source metadata, not instructions or established facts.
  for (const [key, value] of contexts) {
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
  const batches = [],
    omitted = [];
  const graphNodes = new Map(
    (model.sourceGraph?.nodes || []).map((n) => [n.id, n]),
  );
  const projectReferences = (model.sourceGraph?.edges || [])
    .filter((e) => e.kind === "project-reference")
    .map((e) => ({
      from: graphNodes.get(e.from),
      to: graphNodes.get(e.to),
      basis: e.basis,
    }));
  function partition(interfaces, phase, label) {
    let pending = interfaces;
    while (pending.length) {
      const packet = reviewPacket(
        { ...model, interfaces: pending.slice(0, 60) },
        excerpts,
        contexts,
      );
      packet.reviewFocus = {
        phase,
        scope: label,
        categories: STRIDE,
        interpretation:
          "Assess relevant categories; no returned threat does not establish safety. Cross-repository cohorts are hypotheses, not data flows.",
      };
      const repos = new Set(packet.records.map((r) => r.repository));
      packet.projectReferences = projectReferences
        .filter(
          (e) => repos.has(e.from?.repository) || repos.has(e.to?.repository),
        )
        .slice(0, 20)
        .map((e) => ({
          fromRepository: redact(e.from.repository),
          fromFile: redact(e.from.path),
          declaration: redact(e.from.pointer || ""),
          toRepository: redact(e.to.repository),
          toFile: redact(e.to.path),
          basis: e.basis,
        }));
      // Reserve room for the phase label in the normal packet size limit.
      while (
        Buffer.byteLength(JSON.stringify(packet)) > 96 * 1024 &&
        packet.records.length
      )
        packet.records.pop();
      const included = new Set(packet.records.map((r) => r.id));
      packet.reviewerDeclarations = packet.reviewerDeclarations.filter(
        (d) => included.has(d.from) && included.has(d.to),
      );
      if (!included.size) {
        omitted.push(pending[0].id);
        pending = pending.slice(1);
        continue;
      }
      const packetHash = sha(JSON.stringify(packet));
      batches.push({
        id: id(GRAPH_REVIEW_VERSION, phase, packetHash),
        phase,
        label,
        packetHash,
        packet,
      });
      pending = pending.filter((i) => !included.has(i.id));
    }
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
  // Always co-review explicitly declared endpoints, even across protocol partitions.
  const byId = new Map(model.interfaces.map((i) => [i.id, i]));
  for (const f of model.flows || []) {
    if (
      !batches.some(
        (b) =>
          b.phase !== "repository" &&
          b.packet.records.some((r) => r.id === f.from) &&
          b.packet.records.some((r) => r.id === f.to),
      )
    ) {
      partition(
        [byId.get(f.from), byId.get(f.to)].filter(Boolean),
        "declared-flow",
        f.id,
      );
    }
  }
  return { batches, omitted };
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
    basedOnRevision: model.modelRevision,
  };
  const runKey = sha(JSON.stringify(provenance));
  const previous =
    model.aiReview?.runKey === runKey ? model.aiReview.batches || [] : [];
  const cached = new Map(
    previous.filter((b) => b.status === "completed").map((b) => [b.id, b]),
  );
  const review = {
    ...provenance,
    runKey,
    status: "pending",
    mode: excerpts.size ? "source-excerpts" : "metadata",
    batches: [],
    threats: [],
    connections: [],
    questions: [],
    summary:
      "Graph-based review in bounded repository and cross-repository batches.",
    coverage: {},
  };
  model.aiReview = review;
  model.provider = config.provider;
  const submitted = new Set(),
    reviewed = new Set();
  let calls = 0,
    terminalFailure = false;
  const deadline = Date.now() + 24 * 60 * 1000;
  const aggregate = () => {
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
      excerptCount: plan.batches
        .flatMap((b) => b.packet.records)
        .reduce((n, r) => n + r.evidence.filter((e) => e.excerpt).length, 0),
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
      review.batches.push(prior);
      batch.packet.records.forEach((r) => {
        submitted.add(r.id);
        reviewed.add(r.id);
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
    try {
      const result = await requestReview(config, batch.packet, fetchImpl);
      Object.assign(entry, {
        status: "completed",
        review: result.review,
        responseHash: result.responseHash,
      });
      entry.interfaceIds.forEach((i) => reviewed.add(i));
    } catch (error) {
      entry.status = "failed";
      entry.error = error.message;
      terminalFailure = /HTTP (?:401|403|429)|request failed or timed out/.test(
        error.message,
      );
    }
    aggregate();
    options.checkpoint?.(structuredClone(review));
  }
  aggregate();
  review.status = !plan.batches.length
    ? "skipped"
    : review.coverage.completedBatches === plan.batches.length &&
        !plan.omitted.length
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
  options.checkpoint?.(structuredClone(review));
  return model;
}
