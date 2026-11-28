import {REPOSITORY_PROMPT,REPOSITORY_SCHEMA,validateRepositoryReview,CATEGORY_FOLLOWUP_PROMPT,validateCategoryFollowUp} from './repository-assessment.mjs';
import {pocReviewPlan} from './poc-scope.mjs';
import { setTimeout as recoveryWait } from 'node:timers/promises';
import { systemReviewPlan } from './system-review-units.mjs';
import { reviewRunControl, updateReviewProgress } from "./review-run.mjs";
import { reviewConcurrency, runReviewPool } from "./review-pool.mjs";
import { interfacePriorities, batchStage, reviewStageCoverage, REVIEW_STAGES } from "./review-order.mjs";
import { STRIDE_RESPONSE_SCHEMA } from "./security-schemas.mjs";
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
  batchCoverage,
  obligationFits,
  coverageStatus,
} from "./coverage-plan.mjs";
import { beginUsageRun, beginAttempt, finishAttempt } from "./token-usage.mjs";
import {
  interactionContext,
  interactionFlowIndex,
  systemModel,
} from "./system-model.mjs";
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

export function reviewPlan(model, excerpts = new Map(), { progress } = {}) {
  const started = performance.now();
  const stage = (name, extra = {}) =>
    progress?.({
      stage: name,
      elapsedMs: Math.round(performance.now() - started),
      ...extra,
    });
  // Analysis proposals are outputs, not new inputs on each continuation.
  // Explicit reviewer records remain in the workspace and still affect packets.
  const system = systemModel(
    { ...model, aiReview: undefined },
    { matrix: false },
  );
  stage("system-context");
  const flowIndex = interactionFlowIndex(system);
  const priorities = interfacePriorities(model, system);
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
  stage("coverage-obligations", { obligations: structure.obligations.length });
  const splits = [];
  let preparedPackets = 0;
  const coverageIndex = new Map();
  const packetIndexes = {
    evidence: new Map(model.evidence.map((e) => [e.id, e])),
    components: new Map(model.components.map((c) => [c.id, c])),
  };
  function split(interfaces, phase, label, obligations, depth) {
    const middle = Math.ceil(interfaces.length / 2);
    splits.push({
      phase,
      label,
      depth,
      records: interfaces.length,
      reason: "packet-budget",
    });
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
  }
  function partition(interfaces, phase, label, obligations = [], depth = 0) {
    if (!interfaces.length) return;
    // Preserve the same split tree without constructing oversized parent packets.
    if (interfaces.length > 60) {
      split(interfaces, phase, label, obligations, depth);
      return;
    }
    const packet = reviewPacket(
      { ...model, interfaces },
      excerpts,
      contexts,
      packetIndexes,
    );
    packet.reviewFocus = {
      phase,
      scope: label,
      categories: STRIDE,
      interpretation:
        "Assess relevant categories; no returned threat does not establish safety. Candidate paths and cross-repository cohorts are hypotheses, not established data flows.",
    };
    packet.systemContext = interactionContext(
      { ...model, interfaces },
      packet.records.map((r) => r.id),
      system,
      flowIndex,
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
        { ...model, interfaces },
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
      split(interfaces, phase, label, obligations, depth);
      return;
    }
    const packetHash = sha(JSON.stringify(packet));
    const batch = {
      id: id(GRAPH_REVIEW_VERSION, phase, packetHash),
      phase,
      label,
      depth,
      packetHash,
      packet,
    };
    batch.reviewStage = batchStage(batch, priorities);
    batches.push(batch);
    preparedPackets++;
    if (preparedPackets % 100 === 0)
      stage("packet-preparation", { preparedPackets });
    coverageIndex.set(batch.id, {
      id: batch.id,
      coverageIndex: batchCoverage(batch),
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
  stage("partitions", { batches: batches.length });
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
  stage("refinements", { batches: batches.length });
  // A relationship is never counted as reviewed merely because its endpoints were reviewed separately.
  const byInterface = new Map();
  let indexed = 0;
  const candidates = (obligation) => {
    while (indexed < batches.length) {
      const b = batches[indexed++];
      for (const r of b.packet.records) {
        if (!byInterface.has(r.id)) byInterface.set(r.id, []);
        byInterface.get(r.id).push(coverageIndex.get(b.id));
      }
    }
    return byInterface.get(obligation.interfaceIds[0]) || [];
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
  stage("coverage-bridges", { batches: batches.length });
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
  stage("completed", {
    batches: batches.length,
    obligations: structure.obligations.length,
  });
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
  const concurrency = reviewConcurrency(options.concurrency);
  const runControl = reviewRunControl(options);
  const continuous = runControl.mode === "until-complete";
  const maxBatches = options.maxBatches ?? 12;
  if (!Number.isInteger(maxBatches) || maxBatches < 1 || maxBatches > 100)
    throw new Error("Model batch budget must be 1–100 requests");
  const planningStarted = performance.now();
  if (!options.plan) {
    options.progress?.(
      "Preparing STRIDE review plan from the saved graph; no model calls yet",
    );
    await options.trace?.("review.planning-started", {
      interfaces: model.interfaces.length,
      repositories: model.sources.length,
    });
  }
  const plan =
    options.plan ||
    (options.reviewScope === 'poc' ? pocReviewPlan(model, excerpts) : options.reviewScope === 'system' ? systemReviewPlan(model, excerpts) : reviewPlan(model, excerpts, {
      progress: (state) =>
        options.progress?.(
          `Preparing STRIDE plan: ${state.stage}${state.preparedPackets ? " · " + state.preparedPackets + " packets prepared" : ""} · ${Math.round(state.elapsedMs / 1000)}s · no model calls yet`,
        ),
    }));
  if(['repositories','section'].includes(plan.scope?.poc?.kind)){
    if(!options.prepareBatch)throw Error('Repository STRIDE requires source evidence; enable source excerpts before review');
    options={...options,systemPrompt:REPOSITORY_PROMPT,responseSchema:REPOSITORY_SCHEMA,validate:validateRepositoryReview,CATEGORY_FOLLOWUP_PROMPT,validateCategoryFollowUp};
  }
  const planningMs = Math.round(performance.now() - planningStarted);
  if (!options.plan)
    await options.trace?.("review.planning-completed", {
      elapsedMs: planningMs,
      batches: plan.batches.length,
      obligations: plan.obligations.length,
      gaps: plan.gaps.length,
    });
  const provenance = {
    ...publicModelConfig(config),
    ...(plan.reviewScope === 'system' ? { reviewScope: 'system' } : {}),
    ...(options.evidencePolicy
      ? { evidencePolicy: options.evidencePolicy }
      : {}),
    ...(config.structuredOutputs
      ? {
          outputContract: "native-json-schema",
          responseSchemaHash: sha(
            JSON.stringify(options.responseSchema || STRIDE_RESPONSE_SCHEMA),
          ),
        }
      : {}),
    promptKind: ['repositories','section'].includes(plan.scope?.poc?.kind) ? "repository-assessment" : options.systemPrompt ? "static-investigation" : "stride",
    promptVersion: GRAPH_REVIEW_VERSION,
    promptHash: sha(options.systemPrompt || SYSTEM_PROMPT),
    guidance: {
      version: GUIDANCE_VERSION,
      hash: GUIDANCE_HASH,
      sources: GUIDANCE_SOURCES,
    },
    basedOnRevision: model.modelRevision,
  };
  const runKey = sha(JSON.stringify(provenance));
  const fallbackPriorities = interfacePriorities(model);
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
    budget: continuous ? null : maxBatches,
    runControl,
    concurrency,
  });
  // Keep the other review scope resumable; switching views must not discard paid work.
  const selectedScope = plan.scope?.poc ? 'poc:' + plan.scope.poc.id : plan.reviewScope === 'system' ? 'system' : 'deep';
  const priorScope = model.aiReview?.scope?.poc ? 'poc:' + model.aiReview.scope.poc.id : model.aiReview?.reviewScope === 'system' ? 'system' : 'deep';
  let activePrior = model.aiReview;
  if (model.aiReview && priorScope !== selectedScope) {
    model.savedStrideScopes = { ...model.savedStrideScopes, [priorScope]: model.aiReview };
    activePrior = model.savedStrideScopes[selectedScope];
    delete model.savedStrideScopes[selectedScope];
  }
  if (activePrior?.reviewScope === 'system' && activePrior.scope?.version !== plan.scope?.version) {
    model.stridePlanHistory = [...(model.stridePlanHistory || []), {
      reason: 'System review planner changed; retained for comparison with the current evidence scope',
      review: activePrior,
    }].slice(-2);
  }
  const previous =
    activePrior?.runKey === runKey ? activePrior.batches || [] : [];
  const cached = new Map(
    [...previous, ...(options.recoveredBatches || [])]
      .filter(
        (b) =>
          b.status === "completed" && !options.forceBatchIds?.includes(b.id),
      )
      .map((b) => [b.id, b]),
  );
  const retained = plan.batches
    .map((b) =>
      cached.get(b.id)?.packetHash === b.packetHash ? cached.get(b.id) : null,
    )
    .filter(Boolean);
  const previousFailures = new Map(previous
    .filter((b) => b.status === "failed")
    .map((b) => [b.id, b]));
  const retainedFailures = plan.batches.flatMap((b) => {
    const failed = previousFailures.get(b.id);
    return failed?.packetHash === b.packetHash && cached.get(b.id)?.packetHash !== b.packetHash
      ? [{ ...failed, reviewStage: b.reviewStage ?? batchStage(b, fallbackPriorities) }]
      : [];
  });
  const order = new Map(plan.batches.map((b, index) => [b.id, index]));
  const review = {
    ...provenance,
    runKey,
    outputContract: config.structuredOutputs
      ? "native-json-schema"
      : "prompt-json",
    status: "pending",
    mode:
      options.prepareBatch || excerpts.size ? "source-excerpts" : "metadata",
    batches: [...retained, ...retainedFailures],
    threats: [],
    connections: [],
    questions: [],
    summary:
      "Graph-based review in bounded repository and cross-repository batches.",
    coverage: {},
    ...(plan.scope ? { scope: plan.scope } : {}),
    plan: {
      ...(plan.scope ? { scope: plan.scope } : {}),
      basedOnRevision: model.modelRevision,
      version: GRAPH_REVIEW_VERSION,
      splits: plan.splits,
      refinements: plan.refinements,
      obligations: plan.obligations,
      gaps: plan.gaps,
      limits: plan.limits,
      semantics: plan.semantics,
      planningMs,
      batches: plan.batches.map(({ packet, ...b }) => ({
        ...b,
        reviewStage: b.reviewStage ?? batchStage({ ...b, packet }, fallbackPriorities),
        interfaceIds: packet.records.map((r) => r.id),
        packetBytes: Buffer.byteLength(JSON.stringify(packet)),
      })),
    },
  };
  review.runControl = runControl;
  review.reviewOrder = { policy: "external-first", interpretation: "Review order is not deployed exposure. Unknown network entry points remain high priority; internal work is retained." };
  review.runId = beginUsageRun(model);
  model.aiReview = review;
  model.provider = config.provider;
  const submitted = new Set(retained.flatMap((b) => b.interfaceIds)),
    reviewed = new Set(submitted);
  let calls = 0,
    terminalFailure = false,
    consecutiveFormatFailures = 0,
    formatFailureStop = false;
  const recentOutcomes = [];
  const recordOutcome = (invalid) => {
    recentOutcomes.push(invalid);
    if (recentOutcomes.length > 12) recentOutcomes.shift();
    consecutiveFormatFailures = invalid ? consecutiveFormatFailures + 1 : 0;
    const invalidResponses = recentOutcomes.filter(Boolean).length;
    formatFailureStop ||=
      consecutiveFormatFailures >= 3 ||
      (recentOutcomes.length === 12 && invalidResponses >= 6);
    review.failureGuard = {
      recentResponses: recentOutcomes.length,
      invalidResponses,
      consecutiveInvalidResponses: consecutiveFormatFailures,
      stopped: formatFailureStop,
      policy:
        "Stop new requests after 3 consecutive invalid responses or 6 invalid responses in the last 12. In-flight requests may finish.",
    };
  };
  const deadline = continuous ? Infinity : Date.now() + 24 * 60 * 1000;
  // Compute immutable packet and repository metadata once, rather than serializing
  // the whole portfolio again at every concurrent request checkpoint.
  const metrics = new Map(
    plan.batches.map((b) => [
      b.id,
      {
        bytes: Buffer.byteLength(JSON.stringify(b.packet)),
        excerpts: b.packet.records.flatMap((r) =>
          r.evidence.filter((e) => e.excerpt).map((e) => e.id),
        ),
      },
    ]),
  );
  const repositoryInterfaces = new Map(
    model.sources.map((source) => [
      source.name,
      model.interfaces
        .filter((i) => i.repository === source.name)
        .map((i) => i.id),
    ]),
  );
  const plannedPacketBytes = [...metrics.values()].reduce(
    (n, m) => n + m.bytes,
    0,
  );
  const totalExcerpts = [...metrics.values()].reduce(
    (n, m) => n + m.excerpts.length,
    0,
  );
  review.packetHash = sha(plan.batches.map((b) => b.packetHash).join(""));
  let effectQueue = Promise.resolve(),
    coordinationFailure;
  const effect = (run) => {
    const pending = effectQueue.then(run);
    effectQueue = pending.catch((error) => {
      coordinationFailure ||= error;
    });
    return pending;
  };
  const emit = (event, data) => effect(() => options.trace?.(event, data));
  const save = () =>
    effect(async () => {
      aggregate();
      await updateReviewProgress(model, review, options.trace, "review");
      await options.checkpoint?.(
        structuredClone(review),
        structuredClone(model.usageLedger),
      );
    });
  const aggregate = () => {
    review.reviewOrder.stages = reviewStageCoverage(review.plan.batches, review.batches);
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
    review.coverageEvidence = {
      sourceWindows: review.batches.reduce(
        (n, b) => n + (b.evidenceContext?.records.length || 0),
        0,
      ),
      unresolved: review.batches.reduce(
        (n, b) =>
          n +
          (b.evidenceContext?.gaps.length || 0) +
          (b.review?.explorationRequests?.length || 0),
        0,
      ),
      standards: review.batches.flatMap((b) =>
        (b.review?.standardsReviews || []).map((r) => ({
          ...r,
          batchId: b.id,
        })),
      ),
      interpretation:
        "Packet completion is not proof of resolved evidence or complete security coverage",
    };
    const done = review.batches.filter((b) => b.status === "completed").length;
    const sentBatches = new Set(
      review.batches.filter((b) => b.status !== "queued").map((b) => b.id),
    );
    // Checkpoints use compact metrics, not deserialized SQLite packet payloads.
    const sentPacketIds = [...metrics.keys()].filter((id) =>
      sentBatches.has(id),
    );
    review.coverage = {
      obligations: (() => {
        const { obligations, gaps, ...summary } = coverageStatus(
          plan,
          review.batches,
          { details: false },
        );
        return { ...summary, gapCount: gaps.length };
      })(),
      totalInterfaces: model.interfaces.length,
      submittedInterfaces: submitted.size,
      omittedInterfaces: model.interfaces.length - submitted.size,
      interfaceIds: [...submitted].sort(),
      reviewedInterfaceIds: [...reviewed].sort(),
      reviewedInterfaces: reviewed.size,
      repositories: model.sources.map((source) => {
        const ids = repositoryInterfaces.get(source.name);
        const count = ids.filter((id) => reviewed.has(id)).length;
        return {
          repository: source.name,
          totalInterfaces: ids.length,
          reviewedInterfaces: count,
          state:
            source.status !== "read"
              ? "unavailable"
              : !ids.length
                ? "no-interfaces"
                : count === ids.length
                  ? "submitted"
                  : count
                    ? "partial"
                    : "not-reviewed",
        };
      }),
      unreviewedInterfaces: model.interfaces.length - reviewed.size,
      totalBatches: plan.batches.length,
      completedBatches: done,
      failedBatches: review.batches.filter((b) => b.status === "failed").length,
      pendingBatches:
        plan.batches.length -
        done -
        review.batches.filter((b) => b.status === "failed").length,
      callsThisRun: calls,
      batchBudget: continuous ? null : maxBatches,
      oversizedRecords: plan.omitted,
      excerptCount: totalExcerpts,
      packetBytes: plannedPacketBytes,
    };
    review.coverage.plannedPacketBytes = plannedPacketBytes;
    review.coverage.packetBytes = sentPacketIds.reduce(
      (n, id) => n + metrics.get(id).bytes,
      0,
    );
    review.coverage.excerptCount = new Set(
      sentPacketIds.flatMap((id) => metrics.get(id).excerpts),
    ).size;
    review.responseHash = sha(
      review.batches
        .filter((b) => b.status === "completed")
        .map((b) => b.responseHash)
        .join(""),
    );
  };
  // The disk plan is a lazy collection. Queue indices, not packet objects, so
  // only the active workers retain source/graph context in memory.
  const pending = [];
  for (let index = 0; index < plan.batches.length; index++) {
    const batch = plan.batches[index];
    const prior = cached.get(batch.id);
    if (prior?.packetHash === batch.packetHash) {
      await emit("review.cache-reused", {
        runKey,
        batchId: batch.id,
        packetHash: batch.packetHash,
      });
    } else if (!options.batchIds || options.batchIds.includes(batch.id))
      pending.push(index);
  }
  pending.sort((a, b) => review.plan.batches[a].reviewStage - review.plan.batches[b].reviewStage || a - b);
  const selected = continuous ? pending : pending.slice(0, maxBatches);
  const shouldStop = () =>
    coordinationFailure
      ? "persistence-failure"
      : formatFailureStop
        ? "repeated-response-format-failure"
        : terminalFailure
          ? "provider-failure"
          : Date.now() > deadline
            ? "time-budget"
            : null;
  const poolResult = await runReviewPool(selected, {
    concurrency,
    stage: (index) => review.plan.batches[index].reviewStage,
    // System review must reach the other components even when an isolated unit
    // remains unresolved. Failed units stay failed; global failure guards still stop.
    shouldAdvanceStage: (stage) => selectedScope === 'system' || ['repositories','section'].includes(plan.scope?.poc?.kind) || !review.batches.some(
      (b) => b.status === "failed" && b.reviewStage <= stage,
    ),
    signal: options.signal,
    shouldStop,
    onState: async (state) => {
      review.execution = state;
      // Packet preparation, dispatch, usage and completion already checkpoint
      // this state. Avoid two extra full-workspace writes per packet.
      await emit("review.agent-pool", state);
    },
    run: async (index, { agentId }) => {
      let batch = plan.batches[index];
      options.progress?.(
        `STRIDE review: ${review.batches.filter(b=>b.status==='completed').length}/${plan.batches.length} packets saved; reviewing ${batch.phase} · ${batch.label}`,
      );
      const entry = {
        id: batch.id,
        phase: batch.phase,
        label: batch.label,
        packetHash: batch.packetHash,
        agentId,
        interfaceIds: batch.packet.records.map((r) => r.id),
        status: "queued",
        reviewStage: review.plan.batches[index].reviewStage,
        ...(batch.deploymentQuestionIds ? { deploymentQuestionIds: batch.deploymentQuestionIds } : {}),
      };
      await emit("review.stage-packet", { batchId: batch.id, stage: entry.reviewStage, label: REVIEW_STAGES[entry.reviewStage].label });
      const priorFailure = review.batches.find((b) => b.id === entry.id && b.status === "failed");
      // Replace only the packet being retried. Other failures must survive
      // bounded actions/restarts so their errors and retry instructions persist.
      review.batches = review.batches.filter((b) => b.id !== entry.id);
      review.batches.push(entry);
      let attempt, retainedThreats;
      const requestStartedAt = performance.now();
      try {
        if (options.prepareBatch) {
          const prepared = await options.prepareBatch(batch);
          batch = { ...batch, packet: prepared.packet };
          entry.evidenceContext = prepared.context;
          retainedThreats = prepared.retainedThreats;
          metrics.set(batch.id, {
            bytes: Buffer.byteLength(JSON.stringify(batch.packet)),
            excerpts: batch.packet.records.flatMap((r) =>
              r.evidence.filter((e) => e.excerpt).map((e) => e.id),
            ),
          });
          await emit("review.source-context", {
            batchId: batch.id,
            ...prepared.context,
          });
        }
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
        await emit("review.agent-prepared", {
          runKey,
          batchId: batch.id,
          agentId,
          packetHash: batch.packetHash,
        });
        await save();
        const dispatch = (url, requestOptions) => {
          if (options.signal?.aborted || shouldStop())
            throw Error("STRIDE dispatch stopped before submission");
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
          attempt.agentId = agentId;
          if (batch.parentId) attempt.parentBatchId = batch.parentId;
          calls++;
          entry.status = "pending";
          entry.interfaceIds.forEach((i) => submitted.add(i));
          let pendingResponse;
          try {
            pendingResponse = Promise.resolve(fetchImpl(url, requestOptions));
          } catch (error) {
            pendingResponse = Promise.reject(error);
          }
          // Persist dispatched usage while the request is in flight. No await
          // occurs between the final cancellation check and fetch invocation.
          const dispatched = emit("model.request-started", {
            runKey,
            batchId: batch.id,
            attemptId: attempt.id,
            phase: batch.phase,
            packetHash: batch.packetHash,
            agentId,
            counts: {
              records: batch.packet.records.length,
              packetBytes: metrics.get(batch.id).bytes,
            },
            provider: config.provider,
            model: config.model,
            retry: attempt.retry,
          }).then(save);
          return Promise.allSettled([pendingResponse, dispatched]).then(
            ([response, saved]) => {
              if (saved.status === "rejected") throw saved.reason;
              if (response.status === "rejected") throw response.reason;
              return response.value;
            },
          );
        };
        const categoryClosure=plan.scope?.poc?.kind==='section'&&Array.isArray(batch.packet.sourceContext?.priorReview?.retainedThreats);
        entry.categoryClosure=categoryClosure;
        const requestOnce = () => requestReview(config, batch.packet, dispatch, {
          validationRetry: entry.validationRetry,
          ...(options.systemPrompt
            ? { systemPrompt: options.systemPrompt }
            : {}),
          ...(options.responseSchema
            ? { responseSchema: options.responseSchema }
            : {}),
          ...(options.validate ? { validate: options.validate } : {}),
          ...(categoryClosure?{systemPrompt:CATEGORY_FOLLOWUP_PROMPT,validate:(value,packet)=>validateCategoryFollowUp(value,packet,retainedThreats)}:{}),
          signal: options.signal,
          onResponseShape: (shape) => {
            entry.responseShape = shape;
            attempt.responseShape = shape;
            return emit("model.response-shape", {
              runKey,
              batchId: batch.id,
              attemptId: attempt.id,
              ...shape,
            });
          },
          onResponse: (response) =>
            emit("model.response-received", {
              runKey,
              batchId: batch.id,
              attemptId: attempt.id,
              ...response,
            }),
          onStop: (response) =>
            emit("model.stop-reason", {
              runKey,
              batchId: batch.id,
              attemptId: attempt.id,
              ...response,
            }),
          onUsage: async (usage) => {
            attempt.usage = usage;
            await emit("model.usage-received", {
              runKey,
              batchId: batch.id,
              attemptId: attempt.id,
              usage,
            });
            await save();
          },
        });
        let result;
        let transportRetries = 0, validationRetries = 0;
        for (;;) {
          try { result = await requestOnce(); break; }
          catch (error) {
            if (!attempt || coordinationFailure) throw error;
            const detail = failureDetail(error.message);
            const invalid = ["response-format", "evidence-validation", "output-limit"].includes(detail.code);
            const transient = /HTTP (408|429|500|502|503|504|529)\b|request failed or timed out/.test(error.message);
            finishAttempt(attempt, options.signal?.aborted ? "interrupted" : "failed");
            attempt.failure = detail;
            recordOutcome(invalid);
            entry.status = "failed";
            entry.error = error.message;
            await emit("model.request-failed", { runKey, batchId: batch.id, attemptId: attempt.id, failure: detail });
            await save();
            // Recovery is bounded and separately metered. A timeout may have consumed
            // provider tokens; never erase that unknown-usage attempt.
            const retry = (continuous || options.recoverFailures === true) && !options.signal?.aborted && !shouldStop() &&
              ((transient && transportRetries < 2) || (invalid && validationRetries < 1));
            const delayMs = Math.max(error.retryAfterMs || 0, options.recoveryDelayMs ?? (transient ? 2000 * 2 ** transportRetries : 1000));
            // Long server cooldowns require a later resume, never an early retry.
            if (!retry || delayMs > 60000) throw error;
            if (transient) transportRetries++;
            else { validationRetries++; entry.validationRetry = true; }
            review.recovery = { batchId: batch.id, reason: detail.code, transportRetries, validationRetries, delayMs, state: "waiting" };
            await emit("review.retry-scheduled", review.recovery);
            options.progress?.(`STRIDE recovery: ${detail.code}; retrying this packet after ${Math.ceil(delayMs / 1000)}s. Completed work is retained.`);
            await save();
            await recoveryWait(delayMs, undefined, { signal: options.signal });
            if (options.signal?.aborted || shouldStop()) throw error;
            delete entry.responseShape;
            review.recovery = { ...review.recovery, state: "retrying" };
          }
        }
        delete entry.error;
        recordOutcome(false);
        finishAttempt(attempt, "succeeded");
        Object.assign(entry, {
          status: "completed",
          review: result.review,
          responseHash: result.responseHash,
          requestPromptHash: result.requestPromptHash,
        });
        entry.interfaceIds.forEach((i) => reviewed.add(i));
        await emit("model.request-completed", {
          runKey,
          batchId: batch.id,
          attemptId: attempt.id,
          responseHash: result.responseHash,
          requestPromptHash: result.requestPromptHash,
        });
      } catch (error) {
        if (!attempt) {
          review.batches = review.batches.filter((b) => b !== entry);
          if (priorFailure) review.batches.push(priorFailure);
          if (coordinationFailure) throw coordinationFailure;
          if (options.signal?.aborted || shouldStop()) {
            await save();
            return { skipped: true };
          }
          throw error;
        }
        if (attempt.status === "in-flight") {
          finishAttempt(attempt, options.signal?.aborted ? "interrupted" : "failed");
          attempt.failure = failureDetail(error.message);
          recordOutcome(["response-format", "evidence-validation", "output-limit"].includes(attempt.failure.code));
          await emit("model.request-failed", { runKey, batchId: batch.id, attemptId: attempt.id, failure: attempt.failure });
        }
        entry.status = "failed";
        entry.error = error.message;
        if (/HTTP \d{3}|request failed or timed out/.test(error.message)) {
          terminalFailure = true;
          review.stopFailure ||= { ...failureDetail(error.message), batchId: batch.id, attemptId: attempt.id };
        }
      }
      if (review.recovery?.batchId === batch.id) review.recovery.state = entry.status === 'completed' ? 'recovered' : 'stopped';
      entry.durationMs = Math.round(performance.now() - requestStartedAt);
      attempt.durationMs = entry.durationMs;
      await emit("review.agent-finished", {
        runKey,
        agentId,
        batchId: batch.id,
        attemptId: attempt.id,
        status: entry.status,
        durationMs: entry.durationMs,
      });
      await save();
      return { failed: entry.status === "failed" };
    },
  });
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
          : continuous
            ? "Review pass finished; inspect failed packets and source or graph coverage gaps."
            : "Review budget reached; continue to review pending batches. Source and graph coverage gaps remain.");
  if (terminalFailure && review.stopFailure)
    review.error = `Provider failure stopped this action: ${review.stopFailure.code}. Completed work is retained; bounded recovery was exhausted or this failure is not retryable.`;
  if (formatFailureStop)
    review.error =
      "Stopped after repeated invalid model responses (3 consecutive or 6 of the last 12). Successful packets and usage are retained. Export errors and resolve the failure before continuing.";
  if (poolResult.stopReason === "priority-stage-incomplete")
    review.error = "The current review stage has failed packets. Later stages remain pending; inspect Export errors and retry the affected stage before continuing.";
  review.stopReason = options.signal?.aborted
    ? "cancelled"
    : formatFailureStop
      ? "repeated-response-format-failure"
      : poolResult.stopReason === "priority-stage-incomplete"
        ? "priority-stage-incomplete"
      : terminalFailure
        ? "provider-failure"
        : !continuous && calls >= maxBatches
          ? "request-budget"
          : Date.now() > deadline
            ? "time-budget"
            : "plan-exhausted";
  await emit("review.finished", {
    runKey,
    status: review.status,
    counts: {
      completed: review.coverage.completedBatches,
      failed: review.coverage.failedBatches,
      pending: review.coverage.pendingBatches,
      obligations: review.coverage.obligations,
    },
    stopReason: review.stopReason,
  });
  await save();
  return model;
}
