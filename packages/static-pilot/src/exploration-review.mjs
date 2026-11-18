import { failureDetail } from "./diagnostics.mjs";
import { ExplorationStore } from "./exploration.mjs";
import { InvestigationFrontier } from "./investigation-frontier.mjs";
import { InvestigationSource } from "./investigation-source.mjs";
import {
  DISCOVERY_PROMPT,
  ASSESSMENT_PROMPT,
  investigationSchema,
  validateInvestigation,
  INVESTIGATION_VERSION,
} from "./investigation-contract.mjs";
import { CWE_FAMILIES } from "./cwe-model.mjs";
import { CODE_TARGETS, CWE_PROFILE, CWE_PROFILE_HASH } from "./cwe-targets.mjs";
import {
  securityIssues,
  securityContext,
  sourceSecurityContextKey,
  SECURITY_REVIEW_PROMPT,
} from "./security-intelligence.mjs";
import { reviewPlan, enrichGraphModel } from "./graph-review.mjs";
import {
  requestReview,
  redact,
  REVIEW_LIMITS,
  SYSTEM_PROMPT,
} from "./model-review.mjs";
import {
  beginUsageRun,
  beginAttempt,
  finishAttempt,
  ensureLedger,
} from "./token-usage.mjs";
import { scanCwe } from "./cwe-scan.mjs";
import { localSource, sha, id } from "./sources.mjs";
const metadata = (r) => {
  const { lines, code, ...rest } = r;
  return rest;
};
const keyOf = (r) =>
  `${r.repository}\0${r.path}\0${r.line || r.startLine || 1}`;
const semanticEdge = (e) =>
  !["contains", "declares", "owns", "member", "has-interface"].includes(e.kind);

export async function exploreStatic(manifest, model, options = {}) {
  const {
    sourceRoot,
    config,
    budget = 12,
    maxTokens = 1000000,
    maxSteps = 1000,
    maxDepth = 12,
    maxSeconds = 600,
    retryFailed = false,
    includeScanner = false,
    scanner,
    signal,
    fetchImpl = fetch,
    trace,
    progress,
    checkpoint,
  } = options;
  if (!config) throw Error("Configure an approved model provider");
  for (const [name, value, min, max] of [
    ["requests", budget, 1, 100],
    ["token budget", maxTokens, 1000, 10000000],
    ["graph steps", maxSteps, 1, 10000],
    ["path depth", maxDepth, 1, 64],
    ["seconds", maxSeconds, 1, 3600],
  ])
    if (!Number.isInteger(value) || value < min || value > max)
      throw Error(`Invalid ${name} budget (${min}–${max})`);
  const ownStore = !options.explorationStore,
    store = options.explorationStore || new ExplorationStore();
  const frontier = new InvestigationFrontier(store),
    source = new InvestigationSource(model, manifest, sourceRoot);
  const selected = manifest.repositories.filter((r) => r.selected !== false);
  const contextKey = sourceSecurityContextKey(model);
  const scope = sha(
    JSON.stringify([
      INVESTIGATION_VERSION,
      contextKey,
      CWE_PROFILE_HASH,
      selected,
      config.provider,
      config.model,
      config.baseUrl,
      config.structuredOutputs,
      DISCOVERY_PROMPT,
      ASSESSMENT_PROMPT,
    ]),
  );
  const meta = frontier.open(scope, model.modelRevision, {
    context: securityContext(model),
    contextKey,
    provider: config.provider,
    model: config.model,
    createdAt: new Date().toISOString(),
  });
  const started = Date.now(),
    deadline = started + maxSeconds * 1000;
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), maxSeconds * 1000);
  const abortSignal = signal
    ? AbortSignal.any([signal, timeout.signal])
    : timeout.signal;
  const run = (model.explorationRun = {
    version: 2,
    mode: "graph-driven",
    scope,
    staticOnly: true,
    basedOnRevision: model.modelRevision,
    status: "running",
    budget,
    maxTokens,
    maxSteps,
    maxDepth,
    maxSeconds,
    callsThisRun: 0,
    chargedTokens: 0,
    reportedTokens: 0,
    unknownUsageRequests: 0,
    stepsThisRun: 0,
    phase: "source-verification",
    startedAt: new Date().toISOString(),
    coverageComplete: false,
  });
  let plan,
    activeTask,
    providerStop = false;
  const event = (name, data = {}) =>
    trace?.(`investigation.${name}`, {
      scope,
      taskId: activeTask?.id,
      ...data,
    });
  const check = () => {
    if (abortSignal.aborted)
      throw Error(
        signal?.aborted
          ? "Investigation cancelled"
          : "Investigation time budget reached",
      );
  };
  const save = async () => {
    run.frontier = frontier.counts();
    run.repositories = frontier.repositories();
    run.elapsedMs = Date.now() - started;
    await checkpoint?.();
  };
  function gap(
    parent,
    reason,
    details = {},
    repo = activeTask?.repository || "",
  ) {
    const taskId = frontier.put(
      "gap",
      [repo, parent, reason, details],
      repo,
      { label: reason, ...details },
      { parent, priority: 100 },
    );
    frontier.state(taskId, "blocked", { reason, ...details });
    return taskId;
  }
  function sourceStep(ref, parent, priority = 10) {
    const file = source.file(ref.repository, ref.path);
    if (!file) {
      gap(
        parent,
        "file-not-indexed",
        { repository: ref.repository, path: ref.path },
        ref.repository,
      );
      return null;
    }
    const start = Math.max(
      1,
      ref.startLine || Math.floor(((ref.line || 1) - 1) / 80) * 80 + 1,
    );
    return frontier.put(
      "source",
      [file.id, file.blobSha256, start],
      file.repository,
      {
        repository: file.repository,
        path: file.path,
        blobSha256: file.blobSha256,
        startLine: start,
        endLine: file.endLine,
        label: `Inspect code · ${file.repository}/${file.path}:${start}`,
      },
      { parent, priority },
    );
  }
  function evidenceStep(ref, parent) {
    const file = source.file(ref.repository, ref.path);
    if (!file) {
      return gap(
        parent,
        "requested-file-not-indexed",
        { repository: ref.repository, path: ref.path },
        ref.repository,
      );
    }
    const taskId = frontier.put(
      "evidence",
      [file.id, file.blobSha256, ref.line || 1],
      file.repository,
      {
        ...ref,
        blobSha256: file.blobSha256,
        label: `Read evidence · ${file.repository}/${file.path}:${ref.line || 1}`,
      },
      { parent, relation: "requires", priority: 2 },
    );
    return taskId;
  }
  function pathStep(node, parent, depth = 0, assessId = null, after = "") {
    return frontier.put(
      "path",
      [node.id, assessId, after],
      node.repository,
      {
        nodeId: node.id,
        depth,
        assessId,
        after,
        repository: node.repository,
        path: node.path,
        label: `Follow static references · ${node.name || node.path}`,
      },
      {
        parent,
        relation: assessId ? "requires" : "follows",
        priority: assessId ? 2 : 20,
      },
    );
  }
  function enqueueRequests(requests, packet, parent, assessId = null) {
    for (const req of requests || []) {
      const seed = packet.records.find((r) => r.id === req.recordId);
      if (req.action === "neighbors") {
        const n = source.node(req.nodeId);
        if (n) pathStep(n, parent, 0, assessId);
      } else
        frontier.put(
          "search",
          [req.symbol, assessId || seed.repository, ""],
          seed.repository,
          {
            symbol: req.symbol,
            after: "",
            assessId,
            seedRecord: metadata(seed),
            reason: req.reason,
            label: `Find indexed evidence · ${req.symbol}`,
          },
          { parent, relation: assessId ? "requires" : "requests", priority: 2 },
        );
    }
  }
  function project() {
    const existing =
      model.cweModelReview?.basedOnRevision === model.modelRevision
        ? model.cweModelReview.findings || []
        : [];
    const findings = new Map(existing.map((f) => [f.id, f])),
      batches = [],
      entries = [],
      planned = [];
    let sourcePending = 0,
      seedPending = 0;
    const gaps = [];
    for (const task of frontier.tasks()) {
      if (task.kind === "repository" && task.state !== "done") seedPending++;
      if (task.kind === "source") {
        planned.push({
          id: task.id,
          repositories: [task.repository],
          recordIds: task.result?.records?.map((r) => r.id) || [],
        });
        if (task.state !== "done") sourcePending++;
        if (task.result?.review) {
          const review = task.result.review;
          batches.push({
            id: task.id,
            status: "completed",
            repositories: [task.repository],
            recordIds: task.result.records.map((r) => r.id),
            targetReviews: review.targetReviews,
            limitations: review.limitations,
            attemptId: task.result.attemptId,
            responseHash: task.result.responseHash,
          });
          for (const f of review.findings) {
            const fid = id(
              "cwe-model-finding",
              f.cwe,
              f.kind,
              f.preconditions,
              ...f.locations.map(
                (l) =>
                  `${l.repository}:${l.path}:${l.blobSha256}:${l.line}:${l.endLine}`,
              ),
            );
            const evidenceIds = model.evidence
              .filter((e) =>
                f.locations.some(
                  (l) =>
                    l.repository === e.repository &&
                    l.path === e.path &&
                    l.blobSha256 === e.blobSha256,
                ),
              )
              .map((e) => e.id);
            findings.set(fid, {
              ...f,
              id: fid,
              batchId: task.id,
              origin: "model source review",
              evidenceIds,
              interfaceIds: model.interfaces
                .filter((i) => i.evidence.some((e) => evidenceIds.includes(e)))
                .map((i) => i.id),
              association:
                "Static source association; runtime reachability is not established",
              ...(findings.get(fid)?.review
                ? {
                    review: findings.get(fid).review,
                    status: findings.get(fid).status,
                  }
                : {}),
            });
          }
        } else if (task.state === "failed")
          batches.push({
            id: task.id,
            status: "failed",
            repositories: [task.repository],
            error: task.result?.error,
          });
        if (task.state === "blocked")
          gaps.push({
            repository: task.repository,
            path: task.data.path,
            reason: task.result?.reason || "source-unavailable",
          });
      }
      if (task.kind === "assessment" && task.result?.review) {
        entries.push({
          ...task.result.review,
          issueId: task.data.issueId,
          issueHash: task.result.issueHash,
          sourceId: task.data.sourceId,
          origin: task.data.origin,
          contextKey,
          rounds: task.attempts,
          packetHash: task.result.packetHash,
          attemptId: task.result.attemptId,
          usage: task.result.usage,
          evidence: task.result.records,
          history: task.result.history || [],
          retrieval: task.result.retrieval,
          stopReason: task.result.reason,
          frontierTaskId: task.id,
        });
      }
    }
    if (seedPending)
      gaps.push({ reason: "source-enumeration-pending", tasks: seedPending });
    const count = planned.length;
    model.cweModelReview = {
      version: 3,
      key: scope,
      mode: "graph-driven",
      basedOnRevision: model.modelRevision,
      graphFingerprint: model.sourceGraph.fingerprint,
      provider: config.provider,
      model: config.model,
      targetProfile: CWE_PROFILE,
      targetProfileHash: CWE_PROFILE_HASH,
      status:
        sourcePending || gaps.length ? "partial" : "completed-needs-review",
      requestedRepositories: selected.map((r) => r.name),
      repositories: selected.map((r) => ({
        name: r.name,
        plannedBatches: planned.filter((p) => p.repositories.includes(r.name))
          .length,
        reviewedSegments: batches.filter(
          (b) => b.status === "completed" && b.repositories.includes(r.name),
        ).length,
        chunks: planned.filter((p) => p.repositories.includes(r.name)).length,
      })),
      plan: planned,
      batches,
      findings: [...findings.values()],
      gaps,
      totalBatches: count,
      completedBatches: batches.filter((b) => b.status === "completed").length,
      pendingBatches: sourcePending,
      totalSegments: count,
      callsThisRun: run.callsThisRun,
      limitations: [
        "Dynamic frontier coverage is incomplete until source enumeration and all inspection steps have outcomes.",
        "Static relationships and symbol matches are hypotheses; no target code is executed.",
      ],
    };
    model.securityReview = {
      version: 2,
      key: scope,
      contextKey,
      contextPolicy: "source-and-declarations",
      basedOnRevision: model.modelRevision,
      promptHash: sha(SECURITY_REVIEW_PROMPT),
      provider: config.provider,
      model: config.model,
      status: "partial",
      entries,
      events: [],
      callsThisRun: run.callsThisRun,
      pending: securityIssues(model).filter(
        (i) =>
          !entries.some(
            (e) =>
              e.issueId === i.id &&
              ["static-supported", "ruled-out"].includes(e.assessment),
          ),
      ).length,
    };
  }
  function seedCandidates() {
    for (const issue of securityIssues(model).filter((i) => !i.stale)) {
      const parent = model.cweModelReview?.findings.find(
        (f) => f.id === issue.sourceId,
      )?.batchId;
      frontier.put(
        "assessment",
        [issue.id, sha(JSON.stringify(issue))],
        issue.locations[0]?.repository,
        {
          issueId: issue.id,
          sourceId: issue.sourceId,
          origin: issue.origin,
          label: `Assess ${issue.cwe || issue.kind} · ${issue.title}`,
        },
        {
          parent: parent && frontier.get(parent) ? parent : undefined,
          priority: issue.locations.every((l) =>
            /(?:test|fixture|spec)/i.test(l.path),
          )
            ? 18
            : 4,
        },
      );
    }
  }
  async function modelRequest(task, packet, assessment = false) {
    const prompt = assessment ? ASSESSMENT_PROMPT : DISCOVERY_PROMPT;
    const reserve =
      Buffer.byteLength(JSON.stringify(packet)) +
      Buffer.byteLength(prompt) +
      REVIEW_LIMITS.outputTokens +
      4096;
    if (run.callsThisRun >= budget || run.chargedTokens + reserve > maxTokens) {
      frontier.state(task.id, "queued", task.result);
      run.stopReason =
        run.callsThisRun >= budget
          ? "request-budget"
          : "token-reservation-budget";
      return null;
    }
    const attempt = beginAttempt(model, config, packet, {
      batchId: task.id,
      phase: assessment ? "graph-assessment" : "graph-source",
      retry: task.attempts > 0,
    });
    frontier.charge(task);
    frontier.attempt(attempt);
    run.callsThisRun++;
    await event("request-started", {
      attemptId: attempt.id,
      reservedTokens: reserve,
      packetHash: sha(JSON.stringify(packet)),
      repositories: attempt.repositories,
    });
    await save();
    try {
      const response = await requestReview(config, packet, fetchImpl, {
        systemPrompt: prompt,
        responseSchema: investigationSchema(assessment),
        validate: (v, p) => validateInvestigation(v, p, assessment),
        signal: abortSignal,
        onUsage: async (usage) => {
          attempt.usage = usage;
          frontier.attempt(attempt);
          await event("usage", { attemptId: attempt.id, usage });
          await save();
        },
        onResponse: (data) =>
          event("response", { attemptId: attempt.id, ...data }),
      });
      finishAttempt(attempt, "succeeded");
      return {
        review: response.review,
        responseHash: response.responseHash,
        attemptId: attempt.id,
        usage: attempt.usage,
      };
    } catch (error) {
      attempt.failure = failureDetail(error.message);
      finishAttempt(attempt, abortSignal.aborted ? "interrupted" : "failed");
      throw error;
    } finally {
      frontier.attempt(attempt);
      const tokens = attempt.usage?.totalTokens;
      if (Number.isFinite(tokens)) {
        run.reportedTokens += tokens;
        run.chargedTokens += tokens;
      } else {
        run.chargedTokens += reserve;
        run.unknownUsageRequests++;
      }
      await event("request-finished", {
        attemptId: attempt.id,
        status: attempt.status,
        usage: attempt.usage,
        chargedTokens: run.chargedTokens,
      });
    }
  }
  async function record(ref) {
    return source.window({
      repository: ref.repository,
      path: ref.path,
      line: ref.line || (ref.startLine ? ref.startLine + 20 : 1),
      blobSha256: ref.blobSha256,
    });
  }
  async function packetFor(task, assessment) {
    const issue = assessment
      ? securityIssues(model).find(
          (i) => i.id === task.data.issueId && !i.stale,
        )
      : null;
    if (assessment && !issue)
      throw Error(
        "Candidate source or disposition changed; start a current investigation",
      );
    const refs = assessment ? [...issue.locations] : [];
    const records = [],
      gaps = [];
    let nextLine = task.data.startLine;
    if (!assessment) {
      for (let n = 0; n < 8 && nextLine <= task.data.endLine; n++) {
        const w = await source.window({ ...task.data, line: nextLine + 20 });
        if (Buffer.byteLength(JSON.stringify([...records, w])) > 60000) {
          if (!records.length) throw Error("source-window-byte-budget");
          break;
        }
        records.push(w);
        nextLine = w.endLine + 1;
      }
    }
    for (const child of frontier.children(task.id)) {
      if (child.kind === "evidence" && child.result?.ref)
        refs.push({
          ...child.result.ref,
          line: child.result.ref.startLine + 20,
        });
      if (["blocked", "failed"].includes(child.state))
        gaps.push({
          reason:
            child.result?.reason ||
            child.result?.error ||
            "evidence-step-failed",
          taskId: child.id,
        });
    }
    for (const ref of refs) {
      try {
        const w = await record(ref);
        if (records.some((r) => r.id === w.id)) continue;
        if (
          records.length >= 16 ||
          Buffer.byteLength(JSON.stringify([...records, w])) > 60000 ||
          (!assessment &&
            new Set([...records, w].map((r) => r.repository)).size > 4)
        ) {
          gaps.push({
            reason: "source-context-budget",
            repository: ref.repository,
            path: ref.path,
          });
          continue;
        }
        records.push(w);
      } catch (error) {
        gaps.push({
          reason: /^source-/.test(error.message)
            ? error.message
            : "source-unavailable",
          repository: ref.repository,
          path: ref.path,
        });
      }
    }
    const catalog = source.catalog(records);
    const packet = {
      purpose: assessment
        ? "static security candidate assessment"
        : "graph-driven static source review",
      context: meta.context,
      records,
      graphNodes: catalog.nodes,
      graphCatalogLimited: catalog.omitted,
      gaps,
      availableFiles: [
        ...new Map(
          records.map((r) => [
            r.repository + "\0" + r.path,
            { repository: r.repository, path: r.path },
          ]),
        ).values(),
      ],
      priorReview: task.result?.review
        ? {
            missingEvidence: task.result.review.missingEvidence,
            limitations: task.result.review.limitations,
            counterEvidence: task.result.review.counterEvidence,
          }
        : null,
    };
    if (assessment) packet.candidate = issue;
    else {
      packet.targets = CODE_TARGETS;
      packet.families = CWE_FAMILIES;
    }
    if (Buffer.byteLength(JSON.stringify(packet)) > 94000)
      throw Error("source-packet-byte-budget");
    return { packet, nextLine, issue };
  }
  async function inspect(task, assessment = false) {
    const { packet, nextLine, issue } = await packetFor(task, assessment);
    if (!packet.records.length) {
      frontier.state(task.id, "blocked", {
        ...task.result,
        reason: "no-verified-source",
      });
      return;
    }
    const evidenceFingerprint = sha(
      JSON.stringify([
        packet.records.map((r) => r.id),
        packet.graphNodes.map((n) => n.id),
        packet.gaps,
        contextKey,
      ]),
    );
    const replay =
      task.result?.review && task.result.expansionComplete === false;
    if (
      !replay &&
      task.result?.review &&
      task.result.evidenceFingerprint === evidenceFingerprint
    ) {
      frontier.state(task.id, "blocked", {
        ...task.result,
        reason: "no-new-evidence",
      });
      return;
    }
    const response = replay
      ? task.result
      : await modelRequest(task, packet, assessment);
    if (!response) return;
    if (
      assessment &&
      (response.review.explorationRequests.length ||
        response.review.followUp.length ||
        packet.gaps.length)
    ) {
      response.review.assessment = "needs-context";
      response.review.missingEvidence = [
        ...response.review.missingEvidence,
        "Requested static follow-up remains to be reviewed",
      ];
    }
    const result = replay
      ? task.result
      : {
          ...response,
          expansionComplete: false,
          records: packet.records.map(metadata),
          packetHash: sha(JSON.stringify(packet)),
          evidenceFingerprint,
          issueHash: issue ? sha(JSON.stringify(issue)) : undefined,
          retrieval: {
            includedWindows: packet.records.length,
            gapCount: packet.gaps.length,
            fullCallGraph: false,
          },
          history: [
            ...(task.result?.history || []),
            ...(task.result?.attemptId
              ? [
                  {
                    assessment: task.result.review?.assessment,
                    attemptId: task.result.attemptId,
                    packetHash: task.result.packetHash,
                    usage: task.result.usage,
                  },
                ]
              : []),
          ],
        };
    // Commit accepted results before materializing legacy reports. Restart replays these results.
    frontier.state(task.id, "done", result);
    if (!assessment) {
      if (nextLine <= task.data.endLine)
        sourceStep({ ...task.data, startLine: nextLine }, task.id);
      frontier.put(
        "file-graph",
        [task.repository, task.data.path, ""],
        task.repository,
        {
          repository: task.repository,
          path: task.data.path,
          after: "",
          label: `Inspect indexed relationships · ${task.data.path}`,
        },
        { parent: task.id, priority: 20 },
      );
    }
    enqueueRequests(
      response.review.explorationRequests,
      packet,
      task.id,
      task.id,
    );
    if (assessment)
      for (const ref of response.review.followUp) evidenceStep(ref, task.id);
    const requested = frontier.children(task.id);
    result.expansionComplete = true;
    frontier.state(task.id, "done", result);
    if (
      (response.review.explorationRequests.length ||
        (assessment && response.review.followUp.length)) &&
      requested.length
    )
      frontier.state(task.id, "waiting", result);
    else if (assessment && response.review.assessment === "needs-context")
      frontier.state(task.id, "blocked", {
        ...result,
        reason: "unresolved-evidence",
      });
    await event("review-recorded", {
      assessment: response.review.assessment,
      findings: response.review.findings?.length,
      requests: requested.length,
      records: result.records,
    });
    project();
    seedCandidates();
  }
  async function execute(task) {
    const d = task.data;
    if (task.kind === "repository") {
      const page = source.files(task.repository, d.after);
      for (const file of page.items)
        sourceStep({ ...file, startLine: 1 }, task.id);
      if (page.next)
        frontier.put(
          "repository",
          [task.repository, page.next],
          task.repository,
          {
            after: page.next,
            label: `Continue repository inventory · ${task.repository}`,
          },
          { parent: task.id, priority: 30 },
        );
      if (!page.items.length && !d.after)
        gap(task.id, "no-indexed-source-files", {}, task.repository);
      frontier.state(task.id, "done", {
        files: page.items.length,
        next: page.next,
      });
      return;
    }
    if (task.kind === "file-graph") {
      const nodes = source.nodes({
        repository: task.repository,
        path: d.path,
        after: d.after,
        limit: 33,
      });
      for (const n of nodes.slice(0, 32))
        if (n.kind !== "file" && n.kind !== "repository") pathStep(n, task.id);
      if (nodes.length > 32)
        frontier.put(
          "file-graph",
          [task.repository, d.path, nodes[31].id],
          task.repository,
          { ...d, after: nodes[31].id },
          { parent: task.id, priority: 20 },
        );
      frontier.state(task.id, "done", {
        nodes: nodes.slice(0, 32).map((n) => n.id),
        remainingPage: nodes.length > 32,
      });
      return;
    }
    if (task.kind === "path") {
      if (d.depth > maxDepth) {
        frontier.state(task.id, "blocked", {
          reason: "depth-budget",
          depth: d.depth,
          maxDepth,
        });
        return;
      }
      const node = source.node(d.nodeId);
      if (!node) {
        frontier.state(task.id, "blocked", {
          reason: "node-not-in-selected-scope",
        });
        return;
      }
      if (d.assessId) {
        const child = evidenceStep(node, d.assessId);
        if (child) frontier.link(task.id, child, "retrieves");
      } else if (node.path) sourceStep(node, task.id, 15);
      const page = source.edges(node.id, d.after),
        traversed = [];
      for (const edge of page.items) {
        if (!semanticEdge(edge)) continue;
        const peer = source.node(edge.from === node.id ? edge.to : edge.from);
        if (!peer) {
          gap(
            task.id,
            "unresolved-static-reference",
            { edgeId: edge.id, kind: edge.kind, target: edge.to || null },
            task.repository,
          );
          continue;
        }
        const child = pathStep(peer, task.id, d.depth + 1, d.assessId);
        if (d.assessId) frontier.link(d.assessId, child, "requires");
        traversed.push({
          edgeId: edge.id,
          kind: edge.kind,
          from: edge.from,
          to: edge.to,
          repository: peer.repository,
          basis: edge.basis || edge.status || "static-candidate",
        });
      }
      if (page.next) {
        const child = pathStep(node, task.id, d.depth, d.assessId, page.next);
        if (d.assessId) frontier.link(d.assessId, child, "requires");
      }
      frontier.state(task.id, "done", {
        nodeId: node.id,
        traversed,
        next: page.next,
        interpretation:
          "Static relationships only; runtime reachability is unverified",
      });
      await event("path-expanded", {
        nodeId: node.id,
        depth: d.depth,
        traversed,
        next: page.next,
      });
      return;
    }
    if (task.kind === "search") {
      const page = source.search(d.symbol, d.after);
      for (const n of page.items) {
        if (d.assessId) {
          const child = evidenceStep(n, d.assessId);
          if (child) frontier.link(task.id, child, "matches");
        } else sourceStep(n, task.id, 5);
      }
      if (page.next) {
        const child = frontier.put(
          "search",
          [d.symbol, d.assessId || task.repository, page.next],
          task.repository,
          { ...d, after: page.next },
          { parent: task.id, relation: "continues", priority: 2 },
        );
        if (d.assessId) frontier.link(d.assessId, child, "requires");
      }
      frontier.state(
        task.id,
        page.items.length || page.next || d.after ? "done" : "blocked",
        {
          reason: page.items.length
            ? "indexed-name-candidates"
            : "no-indexed-evidence-match",
          matches: page.items.map((n) => ({
            id: n.id,
            repository: n.repository,
            path: n.path,
            line: n.line,
          })),
          next: page.next,
          interpretation:
            "Names are retrieval candidates, not proven symbol resolution",
        },
      );
      await event("search-completed", {
        symbol: d.symbol,
        matches: page.items.length,
        repositories: [...new Set(page.items.map((n) => n.repository))],
        next: page.next,
      });
      return;
    }
    if (task.kind === "evidence") {
      try {
        const r = await record(d);
        frontier.state(task.id, "done", { ref: metadata(r) });
        await event("evidence-read", { record: metadata(r) });
      } catch (error) {
        frontier.state(task.id, "blocked", {
          reason: /^source-/.test(error.message)
            ? error.message
            : "source-unavailable",
        });
      }
      return;
    }
    if (task.kind === "source") return inspect(task);
    if (task.kind === "assessment") return inspect(task, true);
    if (task.kind === "stride-plan") {
      plan ||= reviewPlan(model);
      const from = d.offset || 0,
        to = Math.min(plan.batches.length, from + 100);
      for (let n = from; n < to; n++) {
        const b = plan.batches[n];
        const repo = b.packet.records[0]?.repository || selected[0]?.name;
        frontier.put(
          "stride",
          b.id,
          repo,
          { batchId: b.id, label: b.label || "STRIDE review packet" },
          { parent: task.id, priority: 12 },
        );
      }
      if (to < plan.batches.length)
        frontier.put(
          "stride-plan",
          to,
          task.repository,
          { offset: to, label: "Continue STRIDE scope planning" },
          { parent: task.id, priority: 30 },
        );
      if (plan.gaps.length > 100)
        gap(task.id, "additional-planner-gaps", {
          omitted: plan.gaps.length - 100,
        });
      for (const g of (plan.gaps || []).slice(0, 100))
        gap(task.id, g.reason || "stride-planner-gap", g, task.repository);
      frontier.state(task.id, "done", {
        packets: to - from,
        total: plan.batches.length,
        gaps: plan.gaps.length,
      });
      return;
    }
    if (task.kind === "stride") {
      plan ||= reviewPlan(model);
      const batch = plan.batches.find((b) => b.id === d.batchId);
      if (!batch) {
        frontier.state(task.id, "blocked", {
          reason: "stride-packet-not-in-plan",
        });
        return;
      }
      const reserve =
        Buffer.byteLength(JSON.stringify(batch.packet)) +
        Buffer.byteLength(SYSTEM_PROMPT) +
        REVIEW_LIMITS.outputTokens +
        4096;
      if (run.chargedTokens + reserve > maxTokens) {
        frontier.state(task.id, "queued", task.result);
        run.stopReason = "token-reservation-budget";
        return;
      }
      const before = new Set(
        (model.usageLedger?.attempts || []).map((a) => a.id),
      );
      await enrichGraphModel(model, config, new Map(), fetchImpl, {
        plan,
        batchIds: [batch.id],
        maxBatches: 1,
        signal: abortSignal,
        trace: (e, data) => event(e, data),
        progress,
        checkpoint: async () => {
          for (const a of model.usageLedger?.attempts || [])
            if (!before.has(a.id)) frontier.attempt(a);
          await save();
        },
      });
      const attempts = (model.usageLedger?.attempts || []).filter(
        (a) => !before.has(a.id),
      );
      for (const a of attempts) {
        frontier.attempt(a);
        frontier.charge(task);
        run.callsThisRun++;
        const tokens = a.usage?.totalTokens;
        run.chargedTokens += Number.isFinite(tokens) ? tokens : reserve;
        if (Number.isFinite(tokens)) run.reportedTokens += tokens;
        else run.unknownUsageRequests++;
      }
      const result = model.aiReview.batches.find((b) => b.id === batch.id);
      frontier.state(
        task.id,
        result?.status === "completed" ? "done" : "failed",
        { stride: result, reason: result?.error },
      );
      if (model.aiReview.stopReason === "provider-failure") providerStop = true;
      return;
    }
    if (task.kind === "semgrep") {
      const report = await scanCwe(manifest, model, {
        sourceRoot,
        scanner,
        signal: abortSignal,
        trace: (e, data) => event(e, data),
        progress,
        checkpoint: async (report) => {
          model.cweReview = report;
          await save();
        },
      });
      model.cweReview = report;
      frontier.state(
        task.id,
        report.status === "completed" ? "done" : "blocked",
        { reason: report.status, report },
      );
      seedCandidates();
      return;
    }
    frontier.state(task.id, "blocked", { reason: "unsupported-static-step" });
  }
  try {
    // Rehash source inventory without rebuilding the parser graph. A saved index is not
    // evidence that a working tree stayed unchanged between sessions.
    for (const repo of selected) {
      check();
      if (repo.source === "github")
        throw Error(
          "Graph-driven investigation requires selected local clones",
        );
      progress?.(`Verifying unchanged source: ${repo.name}`);
      const snapshot = await localSource(repo, sourceRoot, {
        onEntry: check,
        onFile: async () => check(),
      });
      if (
        snapshot.snapshot !==
        model.sources.find((s) => s.name === repo.name)?.snapshot
      )
        throw Error(
          `Source changed for ${repo.name}; rebuild the graph before continuing`,
        );
      await event("source-verified", {
        repository: repo.name,
        snapshot: snapshot.snapshot,
      });
    }
    frontier.recover({ retryFailed, maxDepth });
    const recoveredStride = [];
    for (const task of frontier.tasks()) {
      if (task.kind === "semgrep" && task.result?.report)
        model.cweReview = task.result.report;
      if (task.kind === "stride" && task.result?.stride?.status === "completed")
        recoveredStride.push(task.result.stride);
    }
    if (recoveredStride.length) {
      plan = reviewPlan(model);
      await enrichGraphModel(model, config, new Map(), fetchImpl, {
        plan,
        batchIds: [],
        recoveredBatches: recoveredStride,
      });
    }
    const ledger = ensureLedger(model);
    const ids = new Set(ledger.attempts.map((a) => a.id));
    for (const a of frontier.attempts())
      if (!ids.has(a.id)) ledger.attempts.push(a);
    beginUsageRun(model);
    for (const repo of selected) {
      frontier.put(
        "repository",
        [repo.name, ""],
        repo.name,
        { after: "", label: `Enumerate indexed source · ${repo.name}` },
        { priority: 0 },
      );
      for (const target of CWE_PROFILE.targets.filter(
        (t) => t.mode !== "code-review",
      ))
        gap(
          null,
          "additional-evidence-required",
          { targetId: target.id, requestedCwes: target.requestedCwes },
          repo.name,
        );
    }
    frontier.put(
      "stride-plan",
      "initial",
      selected[0]?.name,
      { offset: 0, label: "Plan STRIDE review obligations" },
      { priority: 15 },
    );
    if (includeScanner)
      frontier.put(
        "semgrep",
        "baseline",
        selected[0]?.name,
        { label: "Local Semgrep baseline" },
        { priority: 1 },
      );
    project();
    seedCandidates();
    await save();
    while (
      run.stepsThisRun < maxSteps &&
      run.callsThisRun < budget &&
      Date.now() < deadline
    ) {
      check();
      activeTask = frontier.claim();
      if (!activeTask) break;
      run.phase = activeTask.kind;
      run.stepsThisRun++;
      progress?.(
        `Investigating ${activeTask.repository || "scope"}: ${activeTask.data.label} · ${run.callsThisRun}/${budget} model requests`,
      );
      await event("step-started", {
        kind: activeTask.kind,
        repository: activeTask.repository,
        data: activeTask.data,
      });
      await save();
      try {
        await execute(activeTask);
      } catch (error) {
        const message = redact(error.message).slice(0, 600);
        frontier.state(activeTask.id, "failed", {
          ...activeTask.result,
          error: message,
          reason: abortSignal.aborted ? "cancelled" : "step-failed",
        });
        await event("step-failed", { error: message, kind: activeTask.kind });
        if (/HTTP (?:401|403|429)|request failed or timed out/.test(message))
          providerStop = true;
      }
      project();
      seedCandidates();
      await event("step-finished", {
        state: frontier.get(activeTask.id).state,
      });
      await save();
      if (providerStop || run.stopReason) break;
      await new Promise((resolve) => setImmediate(resolve));
    }
    if (signal?.aborted) {
      run.status = "cancelled";
      run.stopReason = "cancelled";
    } else {
      run.frontier = frontier.counts();
      run.stopReason ||= providerStop
        ? "provider-failure"
        : Date.now() >= deadline
          ? "time-budget"
          : run.callsThisRun >= budget
            ? "request-budget"
            : run.stepsThisRun >= maxSteps
              ? "graph-step-budget"
              : "frontier-exhausted";
      run.status =
        run.frontier.queued || run.frontier.waiting || run.frontier.running
          ? "partial"
          : run.frontier.blocked || run.frontier.failed
            ? "awaiting-evidence"
            : "reviewed-needs-human-review";
    }
  } catch (error) {
    run.status = signal?.aborted
      ? "cancelled"
      : timeout.signal.aborted
        ? "partial"
        : "failed";
    run.stopReason = timeout.signal.aborted
      ? "time-budget"
      : "source-or-storage-failure";
    run.error = redact(error.message).slice(0, 600);
  } finally {
    clearTimeout(timer);
    run.finishedAt = new Date().toISOString();
    run.frontier = frontier.counts();
    run.repositories = frontier.repositories();
    try {
      await event("finished", run);
      await save();
    } finally {
      if (ownStore) store.close();
    }
  }
  return run;
}
