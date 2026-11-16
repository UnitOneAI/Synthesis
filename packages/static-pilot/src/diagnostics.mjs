import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { randomUUID } from "node:crypto";
import { zipSync, strToU8 } from "fflate";
import { sha, LIMITS, within } from "./sources.mjs";
import { GRAPH_LIMITS } from "./source-graph.mjs";
import { REVIEW_LIMITS, redact } from "./model-review.mjs";
import { PLANNER_LIMITS, coverageStatus } from "./coverage-plan.mjs";
import { usageSummary, usageCsv } from "./token-usage.mjs";

export const TRACE_VERSION = 1;
const TRACE_FILE_BYTES = 8 * 1024 * 1024;
const EXPORT_TRACE_BYTES = 64 * 1024 * 1024;
const forbidden =
  /^(apiKey|authorization|headers|environment|env|prompt|packet|requestBody|responseBody|sourceText|excerpt|excerpts|localPath|sourceRoot|baseUrl|endpoint|accessLink|token)$/i;
export function safeMetadata(value, secrets = [], roots = []) {
  if (Array.isArray(value))
    return value.map((v) => safeMetadata(v, secrets, roots));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !forbidden.test(key))
        .map(([key, v]) => [key, safeMetadata(v, secrets, roots)]),
    );
  if (typeof value !== "string") return value;
  let result = value;
  for (const secret of secrets.filter((s) => typeof s === "string" && s.length))
    result = result.split(secret).join("[credential omitted]");
  for (const root of roots.filter(Boolean))
    result = result.split(root).join("[local-root]");
  return redact(result);
}
export function failureDetail(message = "") {
  const status = /HTTP (\d{3})/.exec(message)?.[1];
  if (status)
    return {
      code: "provider-http",
      httpStatus: Number(status),
      retryable: Number(status) >= 500,
      action: [401, 403].includes(Number(status))
        ? "Check gateway credentials, deployment name and access policy."
        : Number(status) === 429
          ? "Wait for quota recovery; consult gateway operator."
          : "Consult gateway operator with the timestamp and request identifiers.",
    };
  if (/output-token|truncat/i.test(message))
    return {
      code: "output-limit",
      retryable: true,
      action: "Retry a smaller review scope; inspect output token counts.",
    };
  if (/schema or evidence/i.test(message))
    return {
      code: "evidence-validation",
      retryable: true,
      action:
        "Retry with the validation instructions; evidence requirements are unchanged.",
    };
  if (/JSON|response-format/i.test(message))
    return {
      code: "response-format",
      retryable: true,
      action:
        "Retry a smaller review scope; verify the gateway forwards the Messages response unchanged.",
    };
  if (/timed out|timeout/i.test(message))
    return {
      code: "transport-or-timeout",
      retryable: true,
      action:
        "Check connectivity and gateway timeout. Provider usage may be unknown.",
    };
  if (/checkpoint|persist|disk/i.test(message))
    return {
      code: "checkpoint-write",
      retryable: false,
      action: "Restore workspace write access or disk space before continuing.",
    };
  if (/memory|heap|worker failed/i.test(message))
    return {
      code: "worker-resource",
      retryable: false,
      action:
        "Inspect the last completed stage and reduce selected scope or use a higher-capacity host.",
    };
  if (/cancel|interrupt|stopped/i.test(message))
    return {
      code: "interrupted",
      retryable: true,
      action:
        "Continue pending review; in-flight requests may have unknown usage.",
    };
  if (/limit|budget/i.test(message))
    return {
      code: "budget-or-limit",
      retryable: true,
      action: "Continue pending work or inspect the affected collection limit.",
    };
  return {
    code: "operation-failed",
    retryable: false,
    action: "Inspect the stage, source ledger and last successful checkpoint.",
  };
}

export async function traceStore({ directory, sourceRoot, secrets = [] } = {}) {
  let dir;
  if (directory) {
    // Resolve the existing parent first so a source-root symlink cannot receive output.
    const requested = path.resolve(directory);
    let parent = requested;
    while (true) {
      try {
        parent = await fs.realpath(parent);
        break;
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
        const up = path.dirname(parent);
        if (up === parent) throw e;
        parent = up;
      }
    }
    const root = sourceRoot ? await fs.realpath(sourceRoot) : null;
    if (root && (within(root, requested) || within(root, parent)))
      throw Error("Trace output must be outside the source root");
    await fs.mkdir(requested, { recursive: true, mode: 0o700 });
    dir = await fs.realpath(requested);
    if (root && within(root, dir))
      throw Error("Trace output must be outside the source root");
  }
  const sessionId = randomUUID(),
    memory = [];
  let sequence = 0,
    segment = 0,
    bytes = 0,
    handle,
    pending = Promise.resolve(),
    error;
  const clean = (value) =>
    safeMetadata(value, secrets, [sourceRoot, os.homedir()]);
  const record = (event, data = {}) => {
    const entry = clean({
      traceVersion: TRACE_VERSION,
      sessionId,
      sequence: ++sequence,
      timestamp: new Date().toISOString(),
      event,
      ...data,
      rssBytes: process.memoryUsage().rss,
    });
    const write = async () => {
      const line = JSON.stringify(entry) + "\n";
      if (dir) {
        if (!handle || bytes + Buffer.byteLength(line) > TRACE_FILE_BYTES) {
          await handle?.close();
          handle = await fs.open(
            path.join(
              dir,
              `${sessionId}-${String(segment++).padStart(4, "0")}.ndjson`,
            ),
            "wx",
            0o600,
          );
          bytes = 0;
        }
        await handle.writeFile(line);
        await handle.sync();
        bytes += Buffer.byteLength(line);
      } else {
        memory.push(entry);
        if (memory.length > 10000) memory.shift();
      }
      return entry;
    };
    pending = pending
      .catch(() => {})
      .then(write)
      .catch((e) => {
        error = "Trace output could not be written";
        throw Error(error);
      });
    return pending;
  };
  return {
    sessionId,
    directory: dir,
    record,
    get error() {
      return error;
    },
    async export() {
      await pending.catch(() => {});
      return dir
        ? readTraces(dir, clean)
        : {
            events: memory.map((x) => JSON.stringify(x)).join("\n") + "\n",
            files: [],
            omittedFiles: [],
            retention:
              "Latest 10000 events in memory; start with --workspace to persist traces.",
          };
    },
    async close() {
      await pending.catch(() => {});
      await handle?.close();
    },
  };
}

export async function readTraces(directory, clean = safeMetadata) {
  let names;
  try {
    names = (await fs.readdir(directory))
      .filter((n) => /^[a-f0-9-]+-\d{4}\.ndjson$/.test(n))
      .sort();
  } catch (e) {
    if (e.code === "ENOENT")
      return {
        events: "",
        files: [],
        omittedFiles: [],
        retention: "No trace files available",
      };
    throw e;
  }
  const files = [],
    omittedFiles = [],
    lines = [];
  let bytes = 0;
  // Newest files first under the export budget; all files stay on disk.
  const ordered = await Promise.all(
    names.map(async (name) => ({
      name,
      stat: await fs.lstat(path.join(directory, name)),
    })),
  );
  ordered.sort(
    (a, b) => b.stat.mtimeMs - a.stat.mtimeMs || a.name.localeCompare(b.name),
  );
  for (const { name, stat } of ordered) {
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size > TRACE_FILE_BYTES ||
      bytes + stat.size > EXPORT_TRACE_BYTES
    ) {
      omittedFiles.push({
        name,
        bytes: stat.size,
        reason: "export-budget-or-nonregular",
      });
      continue;
    }
    const raw = await fs.readFile(path.join(directory, name), "utf8");
    bytes += stat.size;
    let invalidLines = 0;
    for (const line of raw.split("\n").filter(Boolean)) {
      try {
        lines.push(JSON.stringify(clean(JSON.parse(line))));
      } catch {
        invalidLines++;
      }
    }
    files.push({ name, bytes: stat.size, invalidLines });
  }
  return {
    events: lines.join("\n") + (lines.length ? "\n" : ""),
    files,
    omittedFiles,
    retention:
      "All trace segments remain on disk. Bundle includes newest segments up to 64 MiB; partial lines are counted, never copied verbatim.",
  };
}

export async function buildIdentity() {
  const folder = new URL("./", import.meta.url);
  const names = (await fs.readdir(folder))
    .filter((n) => n.endsWith(".mjs"))
    .sort();
  const hashes = await Promise.all(
    names.map(async (name) => [
      name,
      sha(await fs.readFile(new URL(name, folder))),
    ]),
  );
  const pkg = JSON.parse(
    await fs.readFile(new URL("../package.json", folder), "utf8"),
  );
  return {
    version: pkg.version,
    codeFingerprint: sha(JSON.stringify(hashes)),
    modules: hashes,
    node: process.version,
    platform: process.platform,
    architecture: process.arch,
  };
}

// A bounded support report, independent of graph export and available even if
// the first build failed. Never include packets, model prose or source text.
export async function errorReport({
  model,
  job,
  traces,
  config,
  secrets = [],
  roots = [],
} = {}) {
  const text = (v) =>
    typeof v === "string"
      ? v.slice(0, 500)
      : typeof v === "number" || typeof v === "boolean"
        ? v
        : undefined;
  const pick = (value, keys) =>
    Object.fromEntries(
      keys
        .filter((k) => value?.[k] !== undefined)
        .map((k) => [k, text(value[k])]),
    );
  const sample = (rows = [], map = (v) => v) => ({
    total: rows.length,
    omitted: Math.max(0, rows.length - 100),
    items: rows.slice(-100).map(map),
  });
  const batch = (b) => ({
    ...pick(b, ["id", "phase", "status"]),
    failure: b.error ? failureDetail(b.error) : null,
  });
  const review = (r) => ({
    ...pick(r, [
      "status",
      "stopReason",
      "completedBatches",
      "pendingBatches",
      "totalBatches",
    ]),
    failure:
      r?.error &&
      (r.status === "failed" || r.batches?.some((b) => b.status === "failed"))
        ? failureDetail(r.error)
        : null,
    batches: sample(
      (r?.batches || []).filter((b) => b.status !== "completed"),
      batch,
    ),
  });
  const events = [];
  for (const line of (traces?.events || "").split("\n")) {
    try {
      const v = JSON.parse(line);
      if (/fail|error|cancel|limit/i.test(v.event || "") || v.failure)
        events.push({
          ...pick(v, [
            "timestamp",
            "event",
            "sessionId",
            "jobId",
            "attemptId",
            "batchId",
            "repository",
          ]),
          failure: v.failure
            ? pick(v.failure, ["code", "httpStatus", "retryable", "action"])
            : undefined,
        });
    } catch {
      /* Partial trace lines are excluded by the trace reader. */
    }
  }
  events.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  const interfaces = new Map((model?.interfaces || []).map((i) => [i.id, i]));
  const evidence = new Map((model?.evidence || []).map((e) => [e.id, e]));
  return safeMetadata(
    {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      identity: pick(await buildIdentity(), [
        "version",
        "codeFingerprint",
        "node",
        "platform",
        "architecture",
      ]),
      modelRevision: model?.modelRevision,
      provider: config?.provider,
      model: config?.model,
      job: pick(job, ["status", "mode", "message"]),
      stride: {
        ...review(model?.aiReview),
        coverage: pick(model?.aiReview?.coverage, [
          "completedBatches",
          "failedBatches",
          "pendingBatches",
          "totalBatches",
          "callsThisRun",
        ]),
        budgetNote:
          "A request-budget stop is pending work, not a failed model request.",
      },
      cweSourceReview: review(model?.cweModelReview),
      semgrep: {
        status: model?.cweReview?.status,
        failure: model?.cweReview?.error
          ? failureDetail(model.cweReview.error)
          : null,
        repositories: sample(model?.cweReview?.repositories, (r) => ({
          ...pick(r, [
            "name",
            "status",
            "scannedFiles",
            "eligibleFiles",
            "unsupportedFiles",
            "matchesGraphSnapshot",
          ]),
          errorCount: r.errors?.length || 0,
          errors: (r.errors || [])
            .slice(0, 10)
            .map((v) => pick(v, ["type", "code", "level", "path"])),
          skippedFiles: r.skipped?.length || 0,
        })),
      },
      connections: {
        coverage: pick(model?.connectionDiscovery?.coverage, [
          "indexedInterfaces",
          "httpClients",
          "httpServers",
          "httpOutboundCandidates",
          "httpInboundCandidates",
          "connectedFlows",
          "unresolvedClients",
          "unresolvedInterfaces",
        ]),
        gaps: sample(model?.connectionDiscovery?.gaps, (g) => {
          const item = interfaces.get(g.interfaceId);
          return {
            ...pick(g, ["interfaceId", "reason", "candidateCount"]),
            ...pick(item, ["repository", "operation", "direction", "protocol"]),
            ...pick(evidence.get(item?.evidence?.[0]), ["path", "line"]),
          };
        }),
      },
      sourceDiagnostics: sample(model?.diagnostics, (d) =>
        pick(d, ["repository", "path", "kind", "message"]),
      ),
      requestOutcomes: sample(model?.usageLedger?.attempts, (a) =>
        pick(a, ["id", "batchId", "phase", "status", "startedAt", "endedAt"]),
      ),
      failureEvents: sample(events),
      traceScope: {
        retention: text(traces?.retention),
        omittedSegments: traces?.omittedFiles?.length || 0,
      },
      privacy:
        "Confidential architecture metadata. No source graph, source excerpts, prompts or model response prose. Lists retain at most 100 entries; each scanner repository retains at most 10 errors. Preserve the full diagnostic bundle for omitted history.",
    },
    secrets,
    roots,
  );
}

export function sourceCoverage(model) {
  return {
    sources: model?.sources || [],
    extractionDiagnostics: model?.diagnostics || [],
    graph: {
      coverage: model?.sourceGraph?.coverage,
      files: model?.sourceGraph?.files || [],
      limitations: model?.sourceGraph?.limitations || [],
    },
    limitations: model?.limitations || [],
  };
}
export function diagnosticCoverage(model, plan) {
  const effective = plan || model?.aiReview?.plan;
  const stale =
    model?.aiReview?.status === "stale" ||
    (effective?.basedOnRevision &&
      effective.basedOnRevision !== model?.modelRevision);
  const review = effective
    ? {
        ...coverageStatus(
          effective,
          stale ? [] : model?.aiReview?.batches || [],
        ),
        stale: Boolean(stale),
      }
    : null;
  return {
    source: sourceCoverage(model),
    review,
    completeness:
      "Source inspection, graph extraction and review submission are separate measures. Successful requests do not prove semantic completeness or deployed security.",
  };
}

export async function diagnosticBundle({
  model,
  plan,
  traces = { events: "", files: [], omittedFiles: [] },
  job,
  config,
  secrets = [],
  roots = [],
} = {}) {
  const clean = (value) => safeMetadata(value, secrets, roots);
  const files = {};
  const json = (name, value) => {
    files[name] = strToU8(JSON.stringify(clean(value), null, 2));
  };
  const identity = await buildIdentity();
  json("summary.json", {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    identity,
    staticOnly: true,
    modelRevision: model?.modelRevision,
    modelCreatedAt: model?.createdAt,
    modelBasis:
      "Last completed model; may precede the latest failed or interrupted scan. Correlate job IDs and source revisions in traces.",
    graphFingerprint: model?.sourceGraph?.fingerprint,
    analysisGuidance:
      model?.aiReview?.guidance || model?.analysisMethod || null,
    job: { status: job?.status, mode: job?.mode },
    reviewStatus: model?.aiReview?.status || "not-started",
    provider: config?.provider || model?.aiReview?.provider || "none",
    model: config?.model || model?.aiReview?.model || null,
    apiVersion: config?.apiVersion || model?.aiReview?.apiVersion || null,
    endpointHash: config?.baseUrl ? sha(config.baseUrl) : null,
    limits: {
      collection: {
        ...LIMITS,
        localStreaming:
          "No aggregate file-count or text-byte cutoff; per-file size and exclusions apply. File-count and total-byte limits apply to GitHub archives and legacy collection.",
      },
      graph: GRAPH_LIMITS,
      review: REVIEW_LIMITS,
      planner: PLANNER_LIMITS,
      requestTimeoutMs: 120000,
      workerHeapMiB: 768,
      workerWallTimeMs: 1800000,
    },
    tokenUsage: usageSummary(
      model?.usageLedger,
      !model?.usageLedger && Boolean(model?.aiReview),
    ),
    privacy:
      "Contains repository paths, symbol names, graph relationships, hashes and usage. No raw source excerpts, prompts, response prose, credentials, gateway URLs or absolute source root are intentionally included. Treat as confidential architecture metadata; inspect before sharing.",
    knownLimitations: [
      "Syntax graph is not compiler binding or runtime observation.",
      "Candidate paths do not prove effective reachability, authentication or control enforcement.",
      "Unsupported languages, dynamic dispatch, alternative execution paths and missing declarations remain gaps.",
      "Provider quota and gateway context limits are unknown unless a response reports failure.",
      "Token totals may be unknown after timeouts or process interruption.",
    ],
  });
  json("coverage.json", diagnosticCoverage(model, plan));
  json(
    "source-graph.json",
    model?.sourceGraph || { status: "no-completed-graph" },
  );
  const effectivePlan = plan || model?.aiReview?.plan;
  json(
    "review-plan.json",
    effectivePlan
      ? {
          ...effectivePlan,
          batches: effectivePlan.batches.map(({ packet, ...b }) => ({
            ...b,
            ...(packet
              ? {
                  interfaceIds: packet.records.map((r) => r.id),
                  packetBytes: Buffer.byteLength(JSON.stringify(packet)),
                }
              : {}),
          })),
        }
      : { status: "not-planned" },
  );
  json("attempts.json", {
    ledger: model?.usageLedger || null,
    batches: (model?.aiReview?.batches || []).map((b) => ({
      id: b.id,
      phase: b.phase,
      packetHash: b.packetHash,
      responseHash: b.responseHash,
      requestPromptHash: b.requestPromptHash,
      status: b.status,
      interfaceIds: b.interfaceIds,
      failure: b.error ? failureDetail(b.error) : null,
    })),
  });
  // Source excerpts and model prose are deliberately excluded; only diagnostic shapes are exported.
  json(
    "cwe-source-review.json",
    model?.cweModelReview
      ? {
          ...model.cweModelReview,
          findings: model.cweModelReview.findings.map((f) => ({
            id: f.id,
            cwe: f.cwe,
            locations: f.locations,
            status: f.status,
          })),
          batches: model.cweModelReview.batches.map(
            ({ limitations, ...b }) => b,
          ),
        }
      : { status: "not-run" },
  );
  json("cwe-review.json", model?.cweReview || { status: "not-run" });
  json(
    "connection-discovery.json",
    model?.connectionDiscovery || { status: "not-run" },
  );
  json("trace-index.json", {
    files: traces.files,
    omittedFiles: traces.omittedFiles,
    retention: traces.retention,
  });
  files["trace.ndjson"] = strToU8(clean(traces.events));
  files["token-usage.csv"] = strToU8(clean(usageCsv(model?.usageLedger)));
  files["README.txt"] = strToU8(
    "Synthesis static-analysis diagnostics\n\nStart with summary.json, then coverage.json. review-plan.json maps obligations to batches. attempts.json and token-usage.csv account for requests. trace.ndjson correlates sessionId, jobId, attemptId and batchId with stages and failures. source-graph.json contains the collected syntax graph, not a complete runtime graph. No target code was executed.\n\nAll architectural metadata may be confidential. Inspect the bundle before transferring it. Missing trace segments and malformed trailing lines are listed in trace-index.json. manifest.json hashes every other file for corruption checks, not authenticity.\n",
  );
  json("manifest.json", {
    version: 1,
    files: Object.entries(files).map(([name, bytes]) => ({
      name,
      bytes: bytes.length,
      sha256: sha(bytes),
    })),
  });
  return zipSync(files, { level: 6 });
}
