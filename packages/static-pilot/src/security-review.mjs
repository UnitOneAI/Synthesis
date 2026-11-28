import {controlSymbols} from './control-context.mjs';
import { graphReader } from "./graph-store.mjs";
import { SECURITY_RESPONSE_SCHEMA } from "./security-schemas.mjs";
import { internalTopology } from "./internal-topology.mjs";
import { sourceWindow } from "./graph-package.mjs";
import { requestReview, redact } from "./model-review.mjs";
import { id, sha } from "./sources.mjs";
import { beginUsageRun, beginAttempt, finishAttempt } from "./token-usage.mjs";
import {
  securityContext,
  securityContextKey,
  securityIssues,
  SECURITY_REVIEW_PROMPT,
  validateSecurityAssessment,
} from "./security-intelligence.mjs";

export const INVESTIGATION_LIMITS = {
  records: 16,
  packetBytes: 94000,
  graphNodesPerFile: 128,
  edgesPerNode: 32,
  contextRounds: 3,
  availableFiles: 256,
  issues: 10000,
  events: 2000,
};
const fileKey = (r) => `${r.repository}\0${r.path}`;

// Read a bounded neighborhood from the existing graph, then hash-check only selected files.
// The model cannot open arbitrary paths or execute tools.
export async function investigationPacket(
  model,
  manifest,
  sourceRoot,
  issue,
  followUp = [],
  sharedContext = securityContext(model),
) {
  const disk = graphReader(model.sourceGraph),
    generation = model.sourceGraph?.generation;
  if (model.sourceGraph?.storage === "sqlite" && !disk)
    throw Error("Saved graph reader unavailable");
  const selected = new Set(
    manifest.repositories
      .filter((s) => s.selected !== false)
      .map((s) => s.name),
  );
  const seeds = issue.locations.filter((r) => selected.has(r.repository));
  const gaps = [],
    refs = [],
    availableFiles = new Map();
  const fileNode = (r) =>
    disk
      ? [
          ...disk.nodes(generation, {
            kind: "file",
            repository: r.repository,
            path: r.path,
            limit: 1,
          }),
        ][0]
      : model.sourceGraph?.nodes?.find(
          (n) => n.kind === "file" && fileKey(n) === fileKey(r),
        );
  const add = (r, basis, required = false) => {
    if (!r?.path || !selected.has(r.repository)) return;
    const file = fileNode(r);
    if (!file) {
      if (required)
        gaps.push({
          reason: "file-not-in-saved-graph",
          repository: r.repository,
          path: r.path,
        });
      return;
    }
    if (r.blobSha256 && r.blobSha256 !== file.blobSha256) {
      gaps.push({
        reason: "candidate-source-not-in-saved-graph",
        repository: r.repository,
        path: r.path,
      });
      return;
    }
    const ref = {
      repository: r.repository,
      path: r.path,
      line: r.line || 1,
      blobSha256: r.blobSha256 || file.blobSha256,
      basis,
    };
    if (availableFiles.size < INVESTIGATION_LIMITS.availableFiles)
      availableFiles.set(fileKey(file), {
        repository: file.repository,
        path: file.path,
      });
    if (
      refs.some(
        (x) => fileKey(x) === fileKey(ref) && Math.abs(x.line - ref.line) < 20,
      )
    )
      return;
    if (refs.length >= INVESTIGATION_LIMITS.records) {
      gaps.push({
        reason: "source-context-limit",
        repository: ref.repository,
        path: ref.path,
      });
      return;
    }
    refs.push(ref);
  };
  seeds.forEach((r) => add(r, "candidate-location", true));
  followUp.forEach((r) => add(r, "requested-follow-up", true));
  const topology = internalTopology(model);
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const seedKeys = new Set(seeds.map(fileKey));
  const relatedFlows = (topology.connectionDiscovery?.flows || []).filter((f) =>
    (f.evidence || []).some((eid) => {
      const e = evidence.get(eid);
      return e && seedKeys.has(fileKey(e));
    }),
  );
  for (const flow of relatedFlows.slice(0, 8))
    for (const eid of flow.evidence || [])
      add(evidence.get(eid), `static-flow-candidate:${flow.id}`);
  if (relatedFlows.length > 8)
    gaps.push({
      reason: "related-flow-limit",
      omitted: relatedFlows.length - 8,
    });
  const nodes = model.sourceGraph?.nodes || [];
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const seenNodes = new Set();
  for (const seed of seeds.slice(0, 4)) {
    const near = disk
      ? [
          ...disk.nodes(generation, {
            repository: seed.repository,
            path: seed.path,
            limit: INVESTIGATION_LIMITS.graphNodesPerFile + 1,
          }),
        ]
      : nodes
          .filter((n) => fileKey(n) === fileKey(seed))
          .slice(0, INVESTIGATION_LIMITS.graphNodesPerFile + 1);
    if (near.length > INVESTIGATION_LIMITS.graphNodesPerFile)
      gaps.push({
        reason: "graph-neighborhood-node-limit",
        repository: seed.repository,
        path: seed.path,
      });
    for (const n of near.slice(0, INVESTIGATION_LIMITS.graphNodesPerFile)) {
      if (seenNodes.has(n.id)) continue;
      seenNodes.add(n.id);
      const edges = disk
        ? [
            ...disk.incidentEdges(
              generation,
              n.id,
              INVESTIGATION_LIMITS.edgesPerNode + 1,
            ),
          ]
        : (model.sourceGraph?.edges || [])
            .filter((e) => e.from === n.id || e.to === n.id)
            .slice(0, INVESTIGATION_LIMITS.edgesPerNode + 1);
      if (edges.length > INVESTIGATION_LIMITS.edgesPerNode)
        gaps.push({ reason: "graph-neighborhood-edge-limit", nodeId: n.id });
      for (const edge of edges.slice(0, INVESTIGATION_LIMITS.edgesPerNode)) {
        if (/contains|owns|member/.test(edge.kind)) continue;
        const peer = disk
          ? disk.node(generation, edge.from === n.id ? edge.to : edge.from)
          : nodeMap.get(edge.from === n.id ? edge.to : edge.from);
        if (peer?.path && fileKey(peer) !== fileKey(seed))
          add(peer, `graph-neighbor:${edge.kind}`);
      }
    }
  }
  // Shared controls are candidates, not assertions that a given path is protected.
  const repos = new Set(seeds.map((r) => r.repository));
  const controls = model.interfaces
    .filter((i) => i.direction === "control")
    .flatMap((i) => i.evidence.map((eid) => evidence.get(eid)))
    .filter((e) => e && repos.has(e.repository));
  for (const control of controls.slice(0, 8))
    add(control, "shared-control-candidate");
  if (controls.length > 8)
    gaps.push({
      reason: "shared-control-catalog-limited",
      omitted: controls.length - 8,
    });
  const files = disk
    ? disk.nodes(generation, { kind: "file" })
    : nodes.filter((n) => n.kind === "file");
  let availableFilesTruncated = false;
  for (const f of files) {
    if (!selected.has(f.repository)) continue;
    if (availableFiles.size >= INVESTIGATION_LIMITS.availableFiles) {
      availableFilesTruncated = true;
      break;
    }
    availableFiles.set(fileKey(f), { repository: f.repository, path: f.path });
  }
  const records = [];
  for (const ref of refs) {
    try {
      const w = await sourceWindow(ref, manifest, sourceRoot);
      const record = {
        id: id(
          "security-source",
          w.repository,
          w.path,
          w.blobSha256,
          w.startLine,
        ),
        ...w,
        basis: ref.basis,
      };
      if (
        Buffer.byteLength(JSON.stringify(records)) +
          Buffer.byteLength(JSON.stringify(record)) >
        58000
      ) {
        gaps.push({
          reason: "source-byte-limit",
          repository: ref.repository,
          path: ref.path,
        });
        continue;
      }
      records.push(record);
    } catch (error) {
      gaps.push({
        reason: /^(source-|local-)/.test(error.message)
          ? error.message
          : "source-read-failed",
        repository: ref.repository,
        path: ref.path,
      });
    }
  }
  const packet = {
    purpose: "static security candidate assessment",
    citationPolicy:
      "Cite only inside one submitted record at a time; split ranges across windows into separate citations, even for the same file.",
    context: sharedContext,
    candidate: issue,
    records,
    availableFiles: [...availableFiles.values()],
    gaps: gaps.slice(0, 64),
    retrieval: {
      seedLocations: seeds.length,
      relatedFlowCandidates: relatedFlows.length,
      examinedNodes: seenNodes.size,
      selectedWindows: refs.length,
      includedWindows: records.length,
      gapCount: gaps.length,
      availableFileLimit: INVESTIGATION_LIMITS.availableFiles,
      availableFilesTruncated,
      catalogEntriesOmittedForBytes: 0,
      sourceWindowsOmittedForBytes: 0,
      fullCallGraph: false,
    },
  };
  const byteLimit = INVESTIGATION_LIMITS.packetBytes - 128;
  const size = () => Buffer.byteLength(JSON.stringify(packet));
  const sourceFiles = new Set(records.map(fileKey));
  // The file catalog is discovery metadata. Preserve cited files, then trim the
  // tail before sacrificing source evidence. All omissions remain explicit.
  for (
    let n = packet.availableFiles.length - 1;
    size() > byteLimit && n >= 0;
    n--
  ) {
    if (sourceFiles.has(fileKey(packet.availableFiles[n]))) continue;
    packet.availableFiles.splice(n, 1);
    packet.retrieval.availableFilesTruncated = true;
    packet.retrieval.catalogEntriesOmittedForBytes++;
  }
  while (size() > byteLimit && packet.records.length) {
    const omitted = packet.records.pop();
    packet.retrieval.sourceWindowsOmittedForBytes++;
    packet.retrieval.gapCount++;
    if (packet.gaps.length < 64)
      packet.gaps.push({
        reason: "source-window-omitted-for-packet-budget",
        repository: omitted.repository,
        path: omitted.path,
      });
  }
  packet.retrieval.includedWindows = packet.records.length;
  if (size() > byteLimit)
    throw Error("Security packet metadata exceeds size limit");
  packet.retrieval.packetBytes = 0;
  packet.retrieval.packetBytes = size();
  packet.retrieval.packetBytes = size();
  return packet;
}

export async function reviewSecurityIssues(
  manifest,
  model,
  {
    sourceRoot,
    config,
    budget = 4,
    candidateIssues,
    followMissingControls = false,
    retryInvalidAssessment = false,
    reportField = 'securityReview',
    contextKeyOverride,
    packetBuilder = investigationPacket,
    systemPrompt = SECURITY_REVIEW_PROMPT,
    responseSchema = SECURITY_RESPONSE_SCHEMA,
    validateResponse = validateSecurityAssessment,
    retainConclusiveOnPromptChange = false,
    challengePrompt,
    finishCaseFirst = false,
    contextRounds = INVESTIGATION_LIMITS.contextRounds,
    runUntilComplete = false,
    signal,
    fetchImpl = fetch,
    checkpoint,
    trace,
    progress,
  } = {},
) {
  if (!config)
    throw Error("Configure an approved provider before security assessment");
  if (!Number.isInteger(budget) || budget < 1 || budget > 100)
    throw Error("Security request budget must be 1–100");
  if(!Number.isInteger(contextRounds)||contextRounds<1||contextRounds>5)throw Error('Choose 1–5 evidence rounds');
  const context = securityContext(model),
    contextKey = contextKeyOverride || securityContextKey(model);
  const key = sha(
    JSON.stringify([
      contextKey,
      sha(systemPrompt),
      config.provider,
      config.model,
      config.baseUrl,
      config.structuredOutputs === true,
      sha(JSON.stringify(responseSchema)),
      ...(challengePrompt ? [sha(challengePrompt)] : []),
    ]),
  );
  const prior = model[reportField]?.key === key ? model[reportField] : null;
  const issues = (candidateIssues || securityIssues(model))
    .filter((i) => !i.stale)
    .slice(0, INVESTIGATION_LIMITS.issues);
  const report = {
    version: 1,
    key,
    contextKey,
    basedOnRevision: model.modelRevision,
    promptHash: sha(systemPrompt),
    ...(challengePrompt ? {challengePromptHash:sha(challengePrompt)} : {}),
    provider: config.provider,
    model: config.model,
    outputContract: config.structuredOutputs
      ? "native-json-schema"
      : "prompt-json",
    staticOnly: true,
    status: "running",
    entries: structuredClone(prior?.entries || (retainConclusiveOnPromptChange && model[reportField]?.contextKey === contextKey
      ? (model[reportField].entries || []).filter(e=>['static-supported','ruled-out'].includes(e.assessment) || e.challengePending) : [])),
    events: structuredClone(prior?.events || []),
    droppedEvents: prior?.droppedEvents || 0,
    callsThisRun: 0,
    budget,
    candidateCount: issues.length,
    startedAt: new Date().toISOString(),
    limits: {...INVESTIGATION_LIMITS,...(reportField==='threatValidation'&&model.aiReview?.scope?.poc?.kind==='section'?{records:24,sourceBytes:66000}:{}),contextRounds,...(challengePrompt?{maxRequestsPerScenario:contextRounds+1,criticalCheck:true}:{})},
  };
  model[reportField] = report;
  const roundLimit=entry=>contextRounds+(challengePrompt && entry?.challengeStarted ? 1 : 0);
  beginUsageRun(model);
  const save = async () => {
    const counts={selected:issues.length,assessed:0,sourceSupported:0,ruledOut:0,needsCodeContext:0,failed:0,unassessed:0};
    for(const issue of issues){
      const entry=report.entries.find(e=>e.issueId===issue.id && e.issueHash===sha(JSON.stringify(issue)));
      const field={'static-supported':'sourceSupported','ruled-out':'ruledOut','needs-context':'needsCodeContext','failed':'failed'}[entry?.assessment] || 'unassessed';
      counts[field]++;if(['sourceSupported','ruledOut','needsCodeContext'].includes(field))counts.assessed++;
    }
    report.assessmentCounts=counts;
    await checkpoint?.(report);
  };
  const event = async (type, data) => {
    report.events.push({ type, at: new Date().toISOString(), ...data });
    if (report.events.length > INVESTIGATION_LIMITS.events) {
      report.events.shift();
      report.droppedEvents++;
    }
    await trace?.(`security.${type}`, data);
  };
  // Breadth first; application-code candidates precede fixtures within each round.
  const queue = issues
    .map((issue) => ({ issue, hash: sha(JSON.stringify(issue)) }))
    .sort((a, b) => {
      const rounds = (x) => {
        const previous = report.entries.find(
          (e) => e.issueId === x.issue.id && e.issueHash === x.hash,
        );
        return previous?.assessment === "failed" && !previous.attemptId
          ? 0
          : previous?.rounds || 0;
      };
      const scopePriority = ({ issue }) => {
        const scopes = issue.locations.map((l) => l.sourceScope);
        if (scopes.includes("production-candidate")) return 0;
        if (scopes.length && scopes.every((s) => s === "test")) return 2;
        return 1;
      };
      return rounds(a) - rounds(b) || scopePriority(a) - scopePriority(b);
    });
  try {
    for (let queueIndex=0;queueIndex<queue.length;queueIndex++) {
      const item=queue[queueIndex];
      if (signal?.aborted) throw Error("Security review cancelled");
      if (!runUntilComplete && report.callsThisRun >= budget) break;
      const old = report.entries.find(
        (e) => e.issueId === item.issue.id && e.issueHash === item.hash,
      );
      if (old && ["static-supported", "ruled-out"].includes(old.assessment)) {
        // Saved assessments can be reused only while their cited files still match.
        for (const ref of old.evidence || []) {
          try {
            await sourceWindow(
              { ...ref, line: ref.startLine },
              manifest,
              sourceRoot,
            );
          } catch {
            old.assessment = "needs-context";
            old.missingEvidence = [
              "Source changed or evidence unavailable; rebuild the graph",
            ];
            old.followUp = [];
            old.stopReason = "source-no-longer-matches";
          }
        }
        await save();
        continue;
      }
      if (
        old &&
        (old.rounds >= roundLimit(old) ||
          (old.assessment === "needs-context" && !old.followUp?.length && !old.decisionReviewRequired && !(followMissingControls && old.missingEvidence?.some(s => controlSymbols(s).length))))
      )
        continue;
      const entry = {
        issueId: item.issue.id,
        sourceId: item.issue.sourceId,
        origin: item.issue.origin,
        issueHash: item.hash,
        contextKey,
        rounds: (old?.rounds || 0) + 1,
        followUp: structuredClone(old?.followUp || []),
        missingEvidence: structuredClone(old?.missingEvidence || []),
        assessment: "not-assessed",
        ...(old?.challengeStarted ? {challengeStarted:true,challengePending:true,draftAssessment:old.draftAssessment} : {}),
        history: [
          ...(old?.history || []),
          ...(old
            ? [
                {
                  assessment: old.assessment,
                  packetHash: old.packetHash,
                  attemptId: old.attemptId,
                  usage: old.usage,
                },
              ]
            : []),
        ],
      };
      report.entries = report.entries.filter(
        (e) => e.issueId !== item.issue.id,
      );
      report.entries.push(entry);
      let attempt;
      try {
        const packet = await packetBuilder(
          model,
          manifest,
          sourceRoot,
          item.issue,
          old?.followUp || [],
          context,
          old?.missingEvidence || [],
          old,
        );
        if (old?.error?.startsWith("Security assessment failed"))
          packet.previousValidationFailure = old.error;
        if(challengePrompt && old?.challengeStarted) packet.decisionChallenge={
          priorClaim:old.draftAssessment?.engineering?.conclusion || old.engineering?.conclusion,
          priorImpact:old.draftAssessment?.impact || old.impact,
          ...((old.draftAssessment?.engineering || old.engineering)?.conditions ? {
            priorConditions:(old.draftAssessment?.engineering || old.engineering).conditions.map(({citations,...c})=>c),
            priorRemediation:old.draftAssessment?.remediation || old.remediation,
            priorConsistency:(old.draftAssessment?.engineering || old.engineering).consistency,
          } : {}),
          instruction:'Challenge this proposed finding against the freshly supplied source. The earlier assessment is a hypothesis, not evidence. Retain only the directly demonstrated impact; narrow unsupported extensions. Return your own complete assessment and deployment questions.',
        };
        if(Buffer.byteLength(JSON.stringify(packet))>INVESTIGATION_LIMITS.packetBytes)throw Error('Security packet metadata exceeds size limit');
        entry.packetHash = sha(JSON.stringify(packet));
        entry.retrieval = packet.retrieval;
        if(packet.continuationReferences)entry.continuationReferences=packet.continuationReferences;
        entry.evidenceGaps = packet.gaps;
        entry.evidence = packet.records.map(({ lines, ...r }) => r);
        if (
          old?.packetHash === entry.packetHash &&
          old.assessment === "needs-context"
        ) {
          Object.assign(entry, old, {
            followUp: [],
            stopReason: "no-new-evidence",
          });
          await event("no-new-evidence", { issueId: item.issue.id });
          await save();
          continue;
        }
        if (!packet.records.length) {
          entry.assessment = "needs-context";
          entry.missingEvidence = ["No hash-matched source context available"];
          await event("context-unavailable", {
            issueId: item.issue.id,
            gaps: packet.gaps,
          });
          await save();
          continue;
        }
        attempt = beginAttempt(model, config, packet, {
          batchId: item.issue.id,
          phase: "security-validation",
          retry: Boolean(old),
        });
        entry.attemptId = attempt.id;
        report.callsThisRun++;
        progress?.(
          `${reportField === 'threatValidation' ? 'Threat validation' : 'Security assessment'}: ${report.callsThisRun}${runUntilComplete ? '' : '/' + budget} requests`,
        );
        await event("request-started", {
          issueId: item.issue.id,
          attemptId: attempt.id,
          packetHash: entry.packetHash,
          retrieval: packet.retrieval,
        });
        await save();
        const response = await requestReview(config, packet, fetchImpl, {
          systemPrompt:old?.challengeStarted && challengePrompt ? challengePrompt : systemPrompt,
          responseSchema,
          validate: validateResponse,
          signal,
          onUsage: async (usage) => {
            attempt.usage = usage;
            entry.usage = usage;
            await save();
          },
          onResponse: (data) =>
            event("response-received", { issueId: item.issue.id, ...data }),
        });
        finishAttempt(attempt, "succeeded");
        Object.assign(entry, response.review, {
          responseHash: response.responseHash,
        });
        if(challengePrompt && (response.review.assessment==='static-supported'||response.review.decisionReviewRequired) && !old?.challengeStarted) {
          entry.draftAssessment=structuredClone(response.review);
          entry.challengeStarted=true;entry.challengePending=true;
          if(response.review.assessment==='static-supported')entry.assessment='not-assessed';
        } else if(old?.challengeStarted) {
          entry.challengePending=false;entry.challengeCompleted=true;
        }
        // Repeating an identical evidence packet is not progress.
        if (
          old?.packetHash === entry.packetHash &&
          entry.assessment === "needs-context"
        ) {
          entry.followUp = [];
          entry.stopReason = "no-new-evidence";
        }
        if (
          entry.rounds >= roundLimit(entry) &&
          entry.assessment === "needs-context"
        )
          entry.stopReason = "context-round-limit";
        await event("assessed", {
          issueId: item.issue.id,
          assessment: entry.assessment,
          attemptId: attempt.id,
          followUps: entry.followUp.length,
          stopReason: entry.stopReason,
        });
      } catch (error) {
        if (attempt)
          finishAttempt(attempt, signal?.aborted ? "interrupted" : "failed");
        entry.assessment = "failed";
        entry.error = redact(error.message).slice(0, 600);
        await event("request-failed", {
          issueId: item.issue.id,
          failure: entry.error,
        });
      }
      await save();
      if (
        entry.assessment === "failed" &&
        !/^Security assessment failed|^Model did not return the required JSON|^Security packet metadata/.test(
          entry.error,
        )
      )
        break;
      if (retryInvalidAssessment && entry.assessment === 'failed' && entry.rounds < contextRounds && old?.assessment!=='failed' && /^Security assessment failed|^Model did not return the required JSON/.test(entry.error)) queue.push(item);
      if (
        (entry.challengePending || (entry.assessment === "needs-context" &&
        (entry.decisionReviewRequired || entry.followUp?.length || (followMissingControls && entry.missingEvidence?.some(s => controlSymbols(s).length))))) &&
        entry.rounds < roundLimit(entry)
      )
        finishCaseFirst ? queue.splice(queueIndex+1,0,item) : queue.push(item);
    }
    report.pending = issues.filter(
      (i) =>
        !report.entries.some(
          (e) =>
            e.issueId === i.id &&
            e.issueHash === sha(JSON.stringify(i)) &&
            ["static-supported", "ruled-out"].includes(e.assessment),
        ),
    ).length;
    report.status = report.pending
      ? "partial"
      : issues.length
        ? "assessed-needs-review"
        : "no-candidates";
  } catch (error) {
    report.status = signal?.aborted ? "cancelled" : "failed";
    report.error = redact(error.message).slice(0, 600);
  } finally {
    report.finishedAt = new Date().toISOString();
    await event("completed", {
      status: report.status,
      calls: report.callsThisRun,
      pending: report.pending,
    });
    await save();
  }
  return report;
}
