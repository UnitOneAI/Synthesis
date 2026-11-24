import {REPOSITORY_PROMPT} from './repository-assessment.mjs';
import {resolvePocScope,pocReviewPlan} from './poc-scope.mjs';
import { reviewThreatScenarios } from './threat-validation.mjs';
import { deploymentContext, updateDeploymentContext } from './deployment-context.mjs';
import { systemReviewPlan } from './system-review-units.mjs';
import { STRIDE_INVESTIGATION_PROMPT } from "./stride-evidence.mjs";
import { reviewRunControl, updateReviewProgress } from "./review-run.mjs";
import { cweEvidenceReport } from "./evidence-report.mjs";
import { cweEvidence } from "./cwe-evidence.mjs";
import { ExplorationStore } from "./exploration.mjs";
import { exploreStatic } from "./exploration-review.mjs";
import { sourceWindow } from "./graph-package.mjs";
import { cweTargetCoverage, cweTargetCsv } from "./cwe-targets.mjs";
import { securityRegister } from "./security-intelligence.mjs";
import { reviewSecurityIssues } from "./security-review.mjs";
import {
  buildGraphPackage,
  graphPackageChoices,
  graphReuse,
} from "./graph-package.mjs";
import { reviewCweCode } from "./cwe-model.mjs";
import { redact } from "./model-review.mjs";
import { scanCwe, cweCsv, cweSarif } from "./cwe-scan.mjs";
import { GUIDANCE_HASH } from "./analysis-guidance.mjs";
import { GraphStore, attachGraph } from "./graph-store.mjs";
import {
  streamGraph,
  streamModel,
  streamDiagnosticBundle,
} from "./graph-stream.mjs";
import path from "node:path";
import {
  traceStore,
  diagnosticBundle,
  errorReport,
  diagnosticCoverage,
  failureDetail,
  staleReviewDetail,
  buildIdentity,
} from "./diagnostics.mjs";
import {
  usageSummary,
  usageCsv,
  interruptUsage,
  mergeUsage,
} from "./token-usage.mjs";
import { systemModel, editSystem } from "./system-model.mjs";
import {
  systemSvg,
  systemMermaid,
  systemReport,
  systemPrintReport,
  registerCsv,
} from "./system-exports.mjs";
import { workspaceStore } from "./workspace-store.mjs";
import http from "node:http";
import fs from "node:fs/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { Worker } from "node:worker_threads";
import { parseInventory, MAX_UPLOAD } from "./inventory.mjs";
import { publicModelConfig, SYSTEM_PROMPT } from "./model-review.mjs";
import { sha } from "./sources.mjs";
import { compose, validateManifest } from "./engine.mjs";
import { reportHtml, diagram } from "./report.mjs";
import { reviewPlan, strideMatrix } from "./graph-review.mjs";
import { dfdMermaid, sourceGraphMermaid, strideCsv } from "./graph-exports.mjs";

// A terminated worker cannot publish its final pool state. Preserve unsettled
// work as retryable without claiming it remains active after a stop or restart.
function interruptReviewExecution(report, reason) {
  const execution = report?.execution;
  if (!execution || !execution.active) return;
  // A crash between provider dispatch and its next checkpoint can leave only
  // the prepared packet. Surface uncertainty without inventing a ledger call.
  execution.dispatchUncertain =
    (execution.dispatchUncertain || 0) +
    (report.batches || []).filter((batch) => batch.status === "queued").length;
  execution.interrupted = (execution.interrupted || 0) + execution.active;
  execution.queued += execution.active;
  execution.active = 0;
  execution.stopped = true;
  execution.stopReason = reason;
  report.stopReason = reason;
}

async function body(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_UPLOAD * 1.4) throw new Error("Request too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
export async function serve({
  sourceRoot,
  workspace,
  traceDirectory,
  persist = false,
  graphStorage = "memory",
  port = 4173,
  githubToken,
  quiet = false,
  initialManifest,
  modelConfig,
  includeSourceExcerpts = false,
  cweScanner = process.env.SYNTHESIS_CWE_SCANNER || "semgrep",
  cweModelFetch = fetch,
}) {
  const root = await fs.realpath(sourceRoot),
    token = randomBytes(32).toString("hex");
  if (initialManifest) validateManifest(initialManifest);
  let job = { status: "idle" },
    worker,
    model,
    manifest = initialManifest,
    timer;
  let cweController, cweTask;
  let reviewExcerpts = [],
    scanPriorManifest;
  let restoredExtractorKeys = [],
    graphExport,
    graphExportBusy = false;
  if (!["memory", "sqlite"].includes(graphStorage))
    throw Error("Graph storage must be memory or sqlite");
  const store = persist ? await workspaceStore(root, workspace) : null;
  if (graphStorage === "sqlite" && !store)
    throw Error("Disk graph requires a persistent workspace");
  const graphDatabase =
    graphStorage === "sqlite"
      ? path.join(store.dir, "graph.sqlite")
      : undefined;
  if (graphDatabase) {
    try {
      const check = new GraphStore(graphDatabase);
      check.close();
    } catch (error) {
      await store.close();
      throw error;
    }
  }
  const withGraph = async (fn) => {
    if (model?.sourceGraph?.storage !== "sqlite") return fn(null);
    const reader = new GraphStore(path.join(store.dir, "graph.sqlite"), {
      readOnly: true,
    });
    attachGraph(model.sourceGraph, reader);
    try {
      return await fn(reader);
    } finally {
      reader.close();
    }
  };
  const queryWorkers = new Set();
  const queryGraph = (data) =>
    new Promise((resolve, reject) => {
      if (queryWorkers.size >= 2) {
        reject(Error("Graph query is busy; retry shortly"));
        return;
      }
      const query = new Worker(
        new URL("./graph-query-worker.mjs", import.meta.url),
        {
          workerData: { file: path.join(store.dir, "graph.sqlite"), ...data },
          resourceLimits: { maxOldGenerationSizeMb: 768 },
        },
      );
      queryWorkers.add(query);
      const deadline = setTimeout(() => {
        query.terminate();
        reject(Error("Graph query time budget reached"));
      }, 120000);
      let response;
      query.once("message", (message) => {
        response = message;
      });
      query.once("error", reject);
      query.once("exit", (code) => {
        clearTimeout(deadline);
        queryWorkers.delete(query);
        // Release the worker slot before another refresh can start a query.
        if (!response || code !== 0) reject(Error("Graph query interrupted"));
        else if (response.error) reject(Error(response.error));
        else resolve(response.result);
      });
    });
  const pendingPlans = new Map();
  let completedPlan;
  const queryPlan = () => {
    const failedAttempts = (model.usageLedger?.attempts || [])
      .filter((a) => a.status === "failed")
      .map(({ batchId, status, failure }) => ({
        batchId,
        status,
        failure: { code: failure?.code },
      }));
    const key = sha(
      JSON.stringify([
        model.modelRevision,
        model.sourceGraph.generation,
        model.architecture,
        model.aiReview?.plan?.refinements,
        failedAttempts,
      ]),
    );
    if (completedPlan?.key === key)
      return Promise.resolve(completedPlan.result);
    if (!pendingPlans.has(key)) {
      const {
        aiReview,
        usageLedger,
        cweReview,
        cweModelReview,
        securityReview,
        explorationRun,
        ...staticModel
      } = model;
      const planningModel = {
        ...staticModel,
        aiReview: { plan: { refinements: aiReview?.plan?.refinements || [] } },
        usageLedger: { attempts: failedAttempts },
      };
      const pending = queryGraph({ operation: "plan", model: planningModel })
        .then((result) => {
          completedPlan = { key, result };
          return result;
        })
        .finally(() => pendingPlans.delete(key));
      pendingPlans.set(key, pending);
    }
    return pendingPlans.get(key);
  };
  let traces;
  try {
    traces = await traceStore({
      directory:
        traceDirectory || (store ? path.join(store.dir, "traces") : undefined),
      sourceRoot: root,
      secrets: [githubToken, modelConfig?.apiKey, token],
    });
  } catch (error) {
    await store?.close();
    throw error;
  }
  try {
    await traces.record("session.started", {
      identity: await buildIdentity(),
      provider: modelConfig?.provider || "none",
      model: modelConfig?.model || null,
    });
  } catch (error) {
    await traces.close();
    await store?.close();
    throw error;
  }
  let persistenceError = null;
  if (store) {
    try {
      const saved = await store.load();
      if (saved) {
        if (
          initialManifest &&
          JSON.stringify(saved.manifest) !== JSON.stringify(initialManifest)
        )
          throw Error(
            "The workspace contains a different manifest; use a separate --workspace folder",
          );
        model = saved.model;
        if (model.sourceGraph?.storage === "sqlite") {
          const reader = new GraphStore(path.join(store.dir, "graph.sqlite"), {
            readOnly: true,
          });
          try {
            reader.validateGeneration(model.sourceGraph);
            restoredExtractorKeys = reader.extractorKeys(
              model.sourceGraph.generation,
            );
          } finally {
            reader.close();
          }
        }
        if (
          model.aiReview &&
          (model.aiReview.guidance?.hash !== GUIDANCE_HASH ||
            model.aiReview.promptHash !==
              sha(
                model.aiReview.promptKind === "repository-assessment" ? REPOSITORY_PROMPT : model.aiReview.promptKind === "static-investigation"
                  ? STRIDE_INVESTIGATION_PROMPT
                  : SYSTEM_PROMPT,
              ))
        ) {
          model.aiReview.status = "stale";
          model.aiReview.error =
            "Analysis methodology changed; previous scenarios are retained for reference. Run review with the current guidance.";
          model.aiReview.staleReason = {
            causes: [
              ...(model.aiReview.guidance?.hash !== GUIDANCE_HASH
                ? ["guidance-changed"]
                : []),
              ...(model.aiReview.promptHash !==
              sha(
                model.aiReview.promptKind === "repository-assessment" ? REPOSITORY_PROMPT : model.aiReview.promptKind === "static-investigation"
                  ? STRIDE_INVESTIGATION_PROMPT
                  : SYSTEM_PROMPT,
              )
                ? ["prompt-changed"]
                : []),
            ],
          };
        }
        await traces.record("workspace.restored", {
          sourceRevision: model.modelRevision,
          priorStatus: model.aiReview?.status,
        });
        if (model.explorationRun?.status === "running")
          model.explorationRun.status = "partial";
        if (model.threatValidation?.status === 'running') model.threatValidation.status = 'partial';
        if (model.securityReview?.status === "running")
          model.securityReview.status = "partial";
        if (model.cweModelReview?.status === "running") {
          model.cweModelReview.status = "partial";
          model.cweModelReview.error =
            "Interrupted model review; continue pending CWE batches.";
        }
        if (model.cweReview?.status === "running") {
          model.cweReview.status = "partial";
          model.cweReview.error = "Interrupted scan; run CWE review again.";
        }
        interruptUsage(model.usageLedger);
        for (const report of [model.aiReview, model.cweModelReview]) {
          interruptReviewExecution(report, "interrupted");
          if (report?.runId) await updateReviewProgress(model, report);
        }
        manifest = saved.manifest;
        validateManifest(manifest);
        if (model.aiReview?.status === "pending") {
          model.aiReview.status = "partial";
          model.aiReview.error =
            "Interrupted review restored; continue pending work.";
        }
        job = {
          status: "ready",
          message:
            "Saved graph restored. Continue review without rebuilding when the clones and selected repositories are unchanged.",
        };
      }
    } catch (error) {
      await traces.close();
      await store.close();
      throw error;
    }
  }
  let exploration;
  try {
    const file = store
      ? path.join(store.dir, "exploration.sqlite")
      : ":memory:";
    if (store) {
      const stat = await fs.lstat(file).catch((e) => {
        if (e.code !== "ENOENT") throw e;
        return null;
      });
      if (stat?.isSymbolicLink())
        throw Error("Exploration database must not be a symbolic link");
    }
    exploration = new ExplorationStore(file);
    if (store) await fs.chmod(file, 0o600);
    if (model) exploration.sync(model);
  } catch (error) {
    await traces.close();
    await store?.close();
    throw error;
  }
  const checkpoint = async () => {
    if (!model) return;
    try {
      exploration.sync(model);
      if (!store) return;
      await store.save({ manifest, model });
      persistenceError = null;
      await traces.record("checkpoint.saved", {
        sourceRevision: model.modelRevision,
        status: model.aiReview?.status,
      });
    } catch (error) {
      persistenceError = error.message;
      await traces
        .record("checkpoint.failed", { failure: failureDetail(error.message) })
        .catch(() => {});
    }
  };
  const outputModel = () => ({
    ...model,
    ...(model.aiReview
      ? {
          aiReview: {
            ...model.aiReview,
            staleReason: staleReviewDetail(model.aiReview, model.modelRevision),
          },
        }
      : {}),
    exploration: exploration.overview(model.modelRevision),
    securityRegister: securityRegister(model),
    cweTargetCoverage: cweTargetCoverage(model),
    strideMatrix: strideMatrix(model),
    systemModel: systemModel(model),
    diagnosticCoverage: diagnosticCoverage(model),
    tokenUsage: usageSummary(
      model.usageLedger,
      !model.usageLedger && Boolean(model.aiReview),
    ),
  });
  const startJob = async (mode, data) => {
    const jobId = randomBytes(12).toString("hex");
    if (mode === "review") scanPriorManifest = null;
    job = {
      status: "running",
      jobId,
      mode,
      message:
        mode === "review"
          ? "Starting graph-based STRIDE review"
          : "Building static source graph",
    };
    try {
      await traces.record("job.started", {
        jobId,
        mode,
        sourceRevision: model?.modelRevision,
      });
    } catch (error) {
      if (mode !== "review" && model && scanPriorManifest)
        manifest = scanPriorManifest;
      job = { status: "failed", message: "Trace output could not be written" };
      throw error;
    }
    const active = new Worker(new URL("./worker.mjs", import.meta.url), {
      workerData: { mode, ...data },
      resourceLimits: { maxOldGenerationSizeMb: 768 },
    });
    worker = active;
    let finishing = false,
      reviewCheckpointReceived = false;
    const stop = (message) => {
      if (worker !== active || job.status !== "running" || finishing) return;
      if (model?.aiReview?.status === "pending") {
        model.aiReview.status = "partial";
        model.aiReview.error = message;
      }
      interruptUsage(model?.usageLedger);
      if (mode === "review" && model?.aiReview) {
        model.aiReview.lastRunFailure = {
          ...failureDetail(message),
          stage: reviewCheckpointReceived
            ? "during-review"
            : "before-review-checkpoint",
          jobId,
          at: new Date().toISOString(),
        };
        interruptReviewExecution(model.aiReview, "worker-failure");
        void updateReviewProgress(model, model.aiReview);
      }
      traces
        .record("job.failed", { jobId, mode, failure: failureDetail(message) })
        .catch(() => {});
      if (mode !== "review" && model && scanPriorManifest)
        manifest = scanPriorManifest;
      checkpoint();
      job = { status: model ? "ready" : "failed", message };
    };
    const activeTimer =
      mode === "review" && data.options?.runUntilComplete
        ? null
        : setTimeout(
            () => {
              stop(
                "Time limit reached; completed batches retained. Continue review to process remaining batches.",
              );
              active.terminate();
            },
            30 * 60 * 1000,
          );
    timer = activeTimer;
    active.on("message", (m) => {
      (async () => {
        if (worker !== active || job.status !== "running") return;
        if (m.type === "progress") job.message = m.message;
        if (m.type === "trace") {
          let failed = false;
          try {
            await traces.record(m.event, { ...m.data, jobId });
          } catch {
            failed = true;
          }
          if (worker === active)
            active.postMessage({
              type: "trace-saved",
              id: m.id,
              error: failed,
            });
        }
        if (m.type === "static-checkpoint") {
          m.model.usageLedger = mergeUsage(
            model?.usageLedger,
            m.model.usageLedger,
            !model?.usageLedger && Boolean(model?.aiReview),
          );
          if (model?.aiReview) {
            m.model.aiReview = structuredClone(model.aiReview);
            if (
              model.modelRevision !== m.model.modelRevision ||
              model.aiReview.guidance?.hash !== GUIDANCE_HASH ||
              model.aiReview.promptHash !==
                sha(
                  model.aiReview.promptKind === "repository-assessment" ? REPOSITORY_PROMPT : model.aiReview.promptKind === "static-investigation"
                    ? STRIDE_INVESTIGATION_PROMPT
                    : SYSTEM_PROMPT,
                )
            ) {
              m.model.aiReview.status = "stale";
              m.model.aiReview.error =
                "Source or analysis methodology changed; prior analysis retained for reference and requires a new review.";
            }
          }
          if (model?.sourceConclusions) m.model.sourceConclusions = structuredClone(model.sourceConclusions);
          if (model?.deploymentContext) m.model.deploymentContext = structuredClone(model.deploymentContext);
          if (model?.architecture) {
            m.model.architecture = structuredClone(model.architecture);
            m.model.architecture.rebuildNotice =
              "Reviewer declarations retained. Recheck references and stale decisions after rebuilding.";
          }
          if (model?.explorationRun)
            m.model.explorationRun = structuredClone(model.explorationRun);
          if (model?.threatValidation) m.model.threatValidation = structuredClone(model.threatValidation);
          if (model?.threatValidationHistory) m.model.threatValidationHistory = structuredClone(model.threatValidationHistory);
          if (model?.securityReview)
            m.model.securityReview = structuredClone(model.securityReview);
          if (model?.cweModelReview) {
            m.model.cweModelReview = structuredClone(model.cweModelReview);
            if (model.cweModelReview.basedOnRevision !== m.model.modelRevision)
              m.model.cweModelReview.status = "stale";
          }
          if (model?.cweReview) {
            m.model.cweReview = structuredClone(model.cweReview);
            if (model.cweReview.basedOnRevision !== m.model.modelRevision)
              m.model.cweReview.status = "stale";
          }
          model = m.model;
          scanPriorManifest = null;
          await checkpoint();
          if (worker === active)
            active.postMessage({
              type: "static-saved",
              id: m.id,
              error: Boolean(persistenceError),
              model,
            });
        }
        if (m.type === "checkpoint" && model) {
          reviewCheckpointReceived = true;
          model.aiReview = m.aiReview;
          model.usageLedger = m.usageLedger;
          if (m.savedStrideScopes) model.savedStrideScopes = m.savedStrideScopes;
          if (m.threatValidation) model.threatValidation = m.threatValidation;
          await checkpoint();
          if (worker === active)
            active.postMessage({
              type: "checkpoint-saved",
              id: m.id,
              error: Boolean(persistenceError),
            });
        }
        if (m.type === "done") {
          finishing = true;
          if (mode !== "review")
            m.model.usageLedger = mergeUsage(
              model?.usageLedger,
              m.model.usageLedger,
              !model?.usageLedger && Boolean(model?.aiReview),
            );
          if (model?.sourceConclusions) m.model.sourceConclusions = structuredClone(model.sourceConclusions);
          if (mode !== "review" && model?.deploymentContext) m.model.deploymentContext = structuredClone(model.deploymentContext);
          if (mode !== "review" && model?.architecture) {
            m.model.architecture = structuredClone(model.architecture);
            m.model.architecture.rebuildNotice =
              "Reviewer declarations retained from the previous snapshot. Recheck source references and stale decisions after rebuilding.";
          }
          await traces.record("job.completed", {
            jobId,
            mode,
            sourceRevision: m.model.modelRevision,
            status: m.model.aiReview?.status || "static-draft",
          });
          model = m.model;
          reviewExcerpts = m.excerpts || [];
          job = {
            status: "ready",
            message:
              model.aiReview?.scope?.poc && model.threatValidation ? `POC packets: ${model.aiReview.coverage.completedBatches}/${model.aiReview.coverage.totalBatches}. Code assessment: ${model.threatValidation.assessmentCounts?.sourceSupported || 0} supported, ${model.threatValidation.assessmentCounts?.ruledOut || 0} ruled out, ${model.threatValidation.assessmentCounts?.needsCodeContext || 0} need context, ${model.threatValidation.assessmentCounts?.failed || 0} failed. Inspect unassessed scenarios and deployment assumptions.` :
              model.aiReview?.status === "failed"
                ? "Graph retained; model review FAILED. See review details."
                : model.aiReview?.status === "partial"
                  ? "Partial review saved. Continue to process remaining batches."
                  : "Draft ready; inspect coverage and unresolved relationships.",
          };
          clearTimeout(activeTimer);
          await checkpoint();
        }
        if (m.type === "error") {
          stop(m.message);
          clearTimeout(activeTimer);
        }
      })().catch(() => {
        finishing = false;
        stop("Trace or checkpoint write failed; operation stopped");
        active.terminate();
        clearTimeout(activeTimer);
      });
    });
    active.on("error", () => {
      stop("Worker failed; any completed review batches were retained.");
      clearTimeout(activeTimer);
    });
    active.on("exit", () => {
      stop("Worker stopped; any completed review batches were retained.");
      clearTimeout(activeTimer);
    });
  };
  const assets = new Map(
    await Promise.all(
      [
        "index.html",
        "print-report.html",
        "print-report.js",
        "app.js",
        "style.css",
        "workspace.js",
        "review-run.js",
        "workspace.css",
        "cwe.js",
        "exploration.js",
        "exploration.css",
      ].map(async (name) => [
        name,
        await fs.readFile(new URL("../public/" + name, import.meta.url)),
      ]),
    ),
  );
  const server = http.createServer(async (req, res) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    const send = (code, value, type = "application/json") => {
      res.writeHead(code, { "Content-Type": type });
      res.end(type === "application/json" ? JSON.stringify(value) : value);
    };
    try {
      if (
        req.headers.host !== new URL(origin).host ||
        (req.headers.origin && req.headers.origin !== origin)
      )
        return send(403, {
          error: "Only the local application origin is allowed",
        });
      const url = new URL(req.url, origin);
      if (!url.pathname.startsWith("/api/")) {
        if (req.method !== "GET")
          return send(405, { error: "Method not allowed" });
        const name =
          url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        if (!assets.has(name)) return send(404, { error: "Not found" });
        if (name === "print-report.html")
          res.setHeader(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
          );
        return send(
          200,
          assets.get(name),
          name.endsWith(".js")
            ? "text/javascript"
            : name.endsWith(".css")
              ? "text/css"
              : "text/html",
        );
      }
      const supplied = String(req.headers["x-synthesis-token"] || "");
      if (
        !/^[a-f0-9]{64}$/.test(supplied) ||
        !timingSafeEqual(Buffer.from(supplied), Buffer.from(token))
      )
        return send(401, {
          error: "Open the access link printed by the local server",
        });
      if (graphExportBusy && req.method === "POST")
        return send(409, {
          error:
            "Wait for the graph package to finish before changing this assessment",
        });
      if (req.method === "GET" && url.pathname === "/api/status")
        return send(200, {
          ...job,
          hasModel: Boolean(model),
          reviewRuns: Object.fromEntries(
            [
              ["stride", model?.aiReview],
              ["cwe", model?.cweModelReview],
            ].map(([key, report]) => [
              key,
              report
                ? {
                    runControl: report.runControl,
                    runProgress: report.runProgress,
                    timing: report.timing
                      ? {
                          state: report.timing.state,
                          sampleSize: report.timing.sampleSize,
                          sampleScope: report.timing.sampleScope,
                          meanSeconds: report.timing.meanSeconds,
                          remainingPackets: report.timing.remainingPackets,
                          workers: report.timing.workers,
                          estimatedSeconds: report.timing.estimatedSeconds,
                          reason: report.timing.reason,
                        }
                      : undefined,
                    execution: report.execution
                      ? {
                          kind: report.execution.kind,
                          concurrency: report.execution.concurrency,
                          active: report.execution.active,
                          queued: report.execution.queued,
                          started: report.execution.started,
                          completed: report.execution.completed,
                          failed: report.execution.failed,
                          interrupted: report.execution.interrupted,
                          dispatchUncertain: report.execution.dispatchUncertain,
                          peakActive: report.execution.peakActive,
                          stopped: report.execution.stopped,
                          stopReason: report.execution.stopReason,
                        }
                      : undefined,
                    coverage: report.coverage
                      ? {
                          completedBatches: report.coverage.completedBatches,
                          totalBatches: report.coverage.totalBatches,
                          pendingBatches: report.coverage.pendingBatches,
                          failedBatches: report.coverage.failedBatches,
                        }
                      : undefined,
                    completedBatches: report.completedBatches,
                    totalBatches: report.totalBatches,
                    pendingBatches: report.pendingBatches,
                    failedBatches: report.failedBatches,
                    stopReason: report.stopReason,
                  }
                : null,
            ]),
          ),
          tokenUsage: usageSummary(
            model?.usageLedger,
            !model?.usageLedger && Boolean(model?.aiReview),
          ),
          persistence: store
            ? {
                enabled: true,
                error: persistenceError,
                traceError: traces.error,
                restored: Boolean(model),
              }
            : { enabled: false },
          graphStorage,
          savedGraph: graphReuse(model, restoredExtractorKeys),
          sourceRoot: root,
          githubConfigured: Boolean(githubToken),
          inference: publicModelConfig(modelConfig),
          defaultSourceExcerpts: includeSourceExcerpts,
        });
      if (
        req.method === "GET" &&
        url.pathname === "/api/graph-package-options"
      ) {
        if (!model)
          return send(409, { error: "Build or restore a source graph first" });
        return send(200, await withGraph(() => graphPackageChoices(model)));
      }
      if (req.method === "POST" && url.pathname === "/api/graph-package") {
        if (!model || ["running", "cancelling"].includes(job.status))
          return send(409, {
            error: "Wait for analysis to finish, then export the saved graph",
          });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, {
            error: "Source snapshot changed; refresh before exporting",
          });
        if (graphExportBusy || ["running", "cancelling"].includes(job.status))
          return send(409, {
            error:
              "Wait for the active operation before preparing another package",
          });
        const snapshot = structuredClone(model),
          scope = structuredClone(manifest);
        graphExportBusy = true;
        try {
          const result = await withGraph((reader) => {
            if (reader) attachGraph(snapshot.sourceGraph, reader);
            return buildGraphPackage(snapshot, scope, {
              kind: input.kind,
              value: input.value,
              includeSource: input.includeSource,
              sourceRoot: root,
              secrets: [githubToken, modelConfig?.apiKey, token],
            });
          });
          graphExport = { ...result, expires: Date.now() + 10 * 60 * 1000 };
          await traces.record("graph-package.created", {
            packageId: result.packageId,
            sourceRevision: result.modelRevision,
            parts: result.parts.length,
            bytes: result.parts.reduce((n, p) => n + p.bytes, 0),
            includeSource: input.includeSource === true,
            omissions: result.coverage.omissions,
          });
          return send(200, {
            ...result,
            bundles: result.bundles.map(({ buffer, ...bundle }, index) => ({
              ...bundle,
              bundle: index + 1,
            })),
            parts: result.parts.map(({ buffer, manifest, ...part }, index) => ({
              ...part,
              part: index + 1,
              uncompressedPayloadBytes: manifest.payload.bytes,
              estimatedTokens: manifest.payload.estimatedTokens,
            })),
          });
        } finally {
          graphExportBusy = false;
        }
      }
      if (req.method === "GET" && url.pathname === "/api/graph-package") {
        if (
          !graphExport ||
          graphExport.expires < Date.now() ||
          url.searchParams.get("id") !== graphExport.packageId
        ) {
          graphExport = undefined;
          return send(410, {
            error:
              "Graph package expired or replaced. Prepare it again from the saved graph.",
          });
        }
        const collection = url.searchParams.has("bundle")
          ? graphExport.bundles
          : graphExport.parts;
        const part = Number(
          url.searchParams.get(
            url.searchParams.has("bundle") ? "bundle" : "part",
          ),
        );
        if (!Number.isInteger(part) || part < 1 || part > collection.length)
          return send(400, { error: "Invalid graph package part" });
        const item = collection[part - 1];
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${item.name}"`,
        );
        return send(200, item.buffer, "application/zip");
      }
      if (req.method === "GET" && url.pathname === "/api/manifest")
        return send(200, manifest || null);
      if (req.method === "POST" && url.pathname === "/api/inventory") {
        const input = await body(req);
        if (
          typeof input.base64 !== "string" ||
          typeof input.filename !== "string"
        )
          throw new Error("Choose an XLSX or CSV inventory");
        return send(
          200,
          parseInventory(Buffer.from(input.base64, "base64"), input.filename),
        );
      }
      if (req.method === "POST" && url.pathname === "/api/analyze") {
        if (["running", "cancelling"].includes(job.status))
          return send(409, { error: "An analysis is already running" });
        const proposedManifest = await body(req);
        validateManifest(proposedManifest);
        if (proposedManifest.analysis?.useModel === true && !modelConfig)
          throw new Error(
            "Start the server with --provider and --model before requesting model review",
          );
        scanPriorManifest = manifest;
        manifest = proposedManifest;
        reviewExcerpts = [];
        await startJob("analyze", {
          manifest,
          options: {
            sourceRoot: root,
            graphDatabase,
            githubToken,
            modelConfig:
              manifest.analysis?.useModel === true ? modelConfig : null,
            includeSourceExcerpts:
              manifest.analysis?.includeSourceExcerpts === true,
          },
        });
        return send(202, job);
      }
      if (req.method === "GET" && url.pathname === "/api/review-plan") {
        if (!model) return send(409, { error: "Build the source graph first" });
        if (url.searchParams.get("summary") === "1") {
          const plan = model.aiReview?.plan;
          return send(200, {
            modelRevision: model.modelRevision,
            status: plan
              ? model.aiReview.status === "stale"
                ? "historical"
                : "prepared"
              : "not-prepared",
            repositories: model.sources.length,
            batches: plan?.batches?.length ?? null,
            obligations: plan?.obligations?.length ?? null,
            gaps: plan?.gaps?.length ?? null,
          });
        }
        if (model.sourceGraph?.storage === "sqlite")
          return send(200, await queryPlan());
        const plan = reviewPlan(model);
        return send(200, {
          modelRevision: model.modelRevision,
          batches: plan.batches.length,
          oversizedRecords: plan.omitted.length,
          repositories: model.sources.length,
          obligations: plan.obligations.length,
          gaps: plan.gaps.length,
          splits: plan.splits.length,
        });
      }
      if (req.method === "POST" && url.pathname === "/api/review") {
        if (["running", "cancelling"].includes(job.status))
          return send(409, { error: "An analysis is already running" });
        if (!model) return send(409, { error: "Build the source graph first" });
        if (!modelConfig)
          return send(400, {
            error: "Configure a provider before model review",
          });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, { error: "Model changed; refresh before review" });
        if (
          !Number.isInteger(input.maxBatches) ||
          input.maxBatches < 1 ||
          input.maxBatches > 100
        )
          throw new Error("Choose 1–100 model requests per review action");
        const runControl = reviewRunControl(input);
        const concurrency =
          input.concurrency === undefined ? 2 : input.concurrency;
        if (
          !Number.isInteger(concurrency) ||
          concurrency < 1 ||
          concurrency > 4
        )
          throw Error("Choose 1–4 parallel review workers");
        if (typeof input.includeSourceExcerpts !== "boolean")
          throw new Error("Choose whether to include source excerpts");
        if (input.reviewScope !== undefined && !['system', 'deep', 'poc'].includes(input.reviewScope)) throw Error('Choose system, deep or scoped POC STRIDE review');
        if (input.reviewScope === 'poc') { resolvePocScope(model); if (!input.includeSourceExcerpts) throw Error('Scoped POC requires source excerpts for control investigation'); }
        // Keep prior successful responses outside the active snapshot before a
        // repacked or changed-method review can replace its current projection.
        await store?.archiveReview(model);
        if (["running", "cancelling"].includes(job.status))
          return send(409, { error: "An analysis is already running" });
        if (input.modelRevision !== model.modelRevision)
          return send(409, { error: "Model changed; refresh before review" });
        await startJob("review", {
          model,
          manifest,
          excerpts: input.includeSourceExcerpts ? reviewExcerpts : [],
          options: {
            modelConfig,
            reviewBatches: input.maxBatches,
            reviewScope: input.reviewScope || 'deep',
            sourceRoot: root,
            includeSourceExcerpts: input.includeSourceExcerpts,
            concurrency,
            runUntilComplete: runControl.mode === "until-complete",
            tokenTarget: runControl.tokenTarget,
            graphDatabase:
              model.sourceGraph?.storage === "sqlite"
                ? path.join(store.dir, "graph.sqlite")
                : undefined,
          },
        });
        return send(202, job);
      }
      if (req.method === "POST" && url.pathname === "/api/cwe") {
        if (!model || ["running", "cancelling"].includes(job.status))
          return send(409, {
            error:
              "Build a source graph and wait for the current operation to finish",
          });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, {
            error: "Source snapshot changed; refresh before scanning",
          });
        cweController = new AbortController();
        const jobId = randomBytes(12).toString("hex");
        job = {
          status: "running",
          mode: "cwe",
          jobId,
          message: "Starting local CWE review",
        };
        const prior = model.cweReview;
        cweTask = scanCwe(manifest, model, {
          sourceRoot: root,
          scanner: cweScanner,
          signal: cweController.signal,
          trace: (event, data) => traces.record(event, { ...data, jobId }),
          progress: (message) => {
            job.message = message;
          },
          checkpoint: async (report) => {
            if (prior?.rulePack.sha256 === report.rulePack.sha256)
              for (const f of report.findings) {
                const previous = prior.findings.find((p) => p.id === f.id);
                if (previous?.review) {
                  f.review = previous.review;
                  f.status = previous.status;
                }
              }
            model.cweReview = structuredClone(report);
            await checkpoint();
            if (persistenceError) throw Error("CWE checkpoint failed");
          },
        })
          .then((report) => {
            job = {
              status: "ready",
              mode: "cwe",
              jobId,
              message: `CWE review ${report.status}: ${report.findings.length} potential weaknesses. Inspect repository coverage.`,
            };
          })
          .catch(() => {
            job = {
              status: "failed",
              mode: "cwe",
              jobId,
              message:
                "CWE review failed; inspect saved coverage and diagnostic traces",
            };
          });
        return send(202, job);
      }
      if (req.method === "POST" && url.pathname === "/api/cwe/model") {
        if (!model || ["running", "cancelling"].includes(job.status))
          return send(409, {
            error:
              "Build a source graph and wait for the current operation to finish",
          });
        if (!modelConfig)
          return send(409, {
            error:
              "Configure an approved provider and model for CWE source review",
          });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, {
            error: "Refresh the current source snapshot before reviewing",
          });
        if (
          input.includeSourceCode !== true ||
          !Number.isInteger(input.budget) ||
          input.budget < 1 ||
          input.budget > 100
        )
          throw Error(
            "Enable source-code review and choose a request budget from 1 to 100",
          );
        const runControl = reviewRunControl(input);
        const concurrency =
          input.concurrency === undefined ? 2 : input.concurrency;
        if (
          !Number.isInteger(concurrency) ||
          concurrency < 1 ||
          concurrency > 4
        )
          throw Error("Choose 1–4 parallel review workers");
        cweController = new AbortController();
        const jobId = randomBytes(12).toString("hex");
        job = {
          status: "running",
          mode: "cwe-model",
          jobId,
          message: "Planning CWE source review",
        };
        cweTask = reviewCweCode(manifest, model, {
          sourceRoot: root,
          config: modelConfig,
          fetchImpl: cweModelFetch,
          budget: input.budget,
          concurrency,
          runUntilComplete: runControl.mode === "until-complete",
          tokenTarget: runControl.tokenTarget,
          signal: cweController.signal,
          trace: (event, data) => traces.record(event, { ...data, jobId }),
          progress: (message) => {
            job.message = message;
          },
          checkpoint: async (report) => {
            model.cweModelReview = structuredClone(report);
            await checkpoint();
            if (persistenceError) throw Error("CWE model checkpoint failed");
          },
        })
          .then((report) => {
            job = {
              status: "ready",
              mode: "cwe-model",
              jobId,
              message: `CWE source review ${report.status}: ${report.findings.length} potential weaknesses. ${report.pendingBatches ?? "Unknown"} packets remain.`,
            };
          })
          .catch(() => {
            job = {
              status: "failed",
              mode: "cwe-model",
              jobId,
              message:
                "CWE source review failed; inspect the saved report and traces",
            };
          });
        return send(202, job);
      }
      if (req.method === "GET" && url.pathname === "/api/exploration") {
        if (!model) return send(409, { error: "Build a source graph first" });
        const revision =
          url.searchParams.get("revision") || model.modelRevision;
        const nid = url.searchParams.get("node");
        if (nid)
          return send(
            200,
            exploration.node(revision, nid) || { error: "Unknown review node" },
          );
        return send(
          200,
          exploration.query(revision, Object.fromEntries(url.searchParams)),
        );
      }
      if (req.method === "GET" && url.pathname === "/api/exploration/source") {
        if (!model) return send(409, { error: "Build a source graph first" });
        const issue = securityRegister(model).issues.find(
          (i) => i.id === url.searchParams.get("issue"),
        );
        const ref = issue?.investigation?.evidence?.find(
          (r) => r.id === url.searchParams.get("record"),
        );
        if (!ref || issue.stale)
          return send(409, {
            error: "Current saved source reference required",
          });
        const window = await sourceWindow(
          { ...ref, line: ref.startLine + 20 },
          manifest,
          root,
        );
        return send(200, window);
      }
      if (req.method === "POST" && url.pathname === "/api/exploration/review") {
        if (!model || ["running", "cancelling"].includes(job.status))
          return send(409, {
            error: "Build a source graph and wait for the current operation",
          });
        if (!modelConfig)
          return send(409, { error: "Configure an approved model provider" });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, { error: "Refresh the current source snapshot" });
        if (
          input.includeSourceCode !== true ||
          !Number.isInteger(input.budget) ||
          input.budget < 1 ||
          input.budget > 100
        )
          return send(400, {
            error: "Enable source sharing and choose 1–100 model requests",
          });
        for (const [name, min, max] of [
          ["maxTokens", 1000, 10000000],
          ["maxSteps", 1, 10000],
          ["maxDepth", 1, 64],
          ["maxSeconds", 1, 3600],
        ]) {
          if (
            input[name] !== undefined &&
            (!Number.isInteger(input[name]) ||
              input[name] < min ||
              input[name] > max)
          )
            return send(400, {
              error: `Invalid ${name} budget (${min}–${max})`,
            });
        }
        cweController = new AbortController();
        const jobId = randomBytes(12).toString("hex");
        job = {
          status: "running",
          mode: "exploration",
          jobId,
          message: "Preparing static exploration",
        };
        cweTask = withGraph(() =>
          exploreStatic(manifest, model, {
            explorationStore: exploration,
            maxTokens: input.maxTokens ?? 1000000,
            maxSteps: input.maxSteps ?? 1000,
            maxDepth: input.maxDepth ?? 12,
            maxSeconds: input.maxSeconds ?? 600,
            retryFailed: input.retryFailed === true,
            includeScanner: input.includeScanner === true,
            scanner: cweScanner,
            sourceRoot: root,
            config: modelConfig,
            budget: input.budget,
            signal: cweController.signal,
            fetchImpl: cweModelFetch,
            trace: (event, data) => traces.record(event, { ...data, jobId }),
            progress: (message) => {
              job.message = message;
            },
            checkpoint: async () => {
              await checkpoint();
              if (persistenceError)
                throw Error("Exploration checkpoint failed");
            },
          }),
        )
          .then((report) => {
            job = {
              status: "ready",
              mode: "exploration",
              jobId,
              message: `Static exploration ${report.status}; ${report.callsThisRun} requests this action.`,
            };
          })
          .catch(() => {
            job = {
              status: "failed",
              mode: "exploration",
              jobId,
              message: "Exploration failed; inspect saved errors and traces",
            };
          });
        return send(202, job);
      }
      if (req.method === 'POST' && url.pathname === '/api/threats/validate') {
        const input = await body(req);
        if (!model || ['running', 'cancelling'].includes(job.status)) return send(409, { error: 'Open the saved graph and wait for the current operation' });
        if (!modelConfig) return send(409, { error: 'Configure an approved model provider' });
        if (input.modelRevision !== model.modelRevision) return send(409, { error: 'Refresh the current source snapshot' });
        if (input.includeSourceCode !== true || !Number.isInteger(input.budget) || input.budget < 1 || input.budget > 100 || (input.runUntilComplete !== undefined && typeof input.runUntilComplete !== 'boolean')) return send(400, { error: 'Enable source sharing and choose 1–100 requests' });
        if (!model.aiReview?.coverage?.completedBatches || model.aiReview.status === 'stale' || (model.aiReview.basedOnRevision && model.aiReview.basedOnRevision !== model.modelRevision)) return send(409, { error: 'Current completed STRIDE results are required' });
        if (input.threatIds !== undefined && (!Array.isArray(input.threatIds) || !input.threatIds.length || input.threatIds.some(id => !model.aiReview.threats.some(t => t.id === id)))) return send(400, { error: 'Select saved threat IDs' });
        cweController = new AbortController();
        const jobId = randomBytes(12).toString('hex');
        job = { status: 'running', mode: 'threat-validation', jobId, message: 'Following saved threat evidence and named controls' };
        cweTask = withGraph(() => reviewThreatScenarios(manifest, model, {
          sourceRoot: root, config: modelConfig, budget: input.budget, runUntilComplete: input.runUntilComplete === true, threatIds: input.threatIds,
          signal: cweController.signal, fetchImpl: cweModelFetch,
          trace: (event, data) => traces.record(event, { ...data, jobId }),
          progress: message => { job.message = message; },
          checkpoint: async () => { await checkpoint(); if (persistenceError) throw Error('Threat validation checkpoint failed'); },
        })).then(report => { job = { status: 'ready', mode: 'threat-validation', jobId, message: `Threat evidence: ${report.assessmentCounts?.assessed || 0} / ${report.candidateCount} selected scenarios assessed; ${report.assessmentCounts?.needsCodeContext || 0} need code evidence; ${report.assessmentCounts?.failed || 0} failed. Deployment assumptions remain separate. Original STRIDE results retained.` }; })
          .catch(() => { job = { status: 'failed', mode: 'threat-validation', jobId, message: 'Threat validation stopped; saved results and traces retained' }; });
        return send(202, job);
      }
      if (req.method === "POST" && url.pathname === "/api/security/review") {
        if (!model || ["running", "cancelling"].includes(job.status))
          return send(409, {
            error: "Build a source graph and wait for the current operation",
          });
        if (!modelConfig)
          return send(409, { error: "Configure an approved model provider" });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, { error: "Refresh the current source snapshot" });
        if (
          input.includeSourceCode !== true ||
          !Number.isInteger(input.budget) ||
          input.budget < 1 ||
          input.budget > 100
        )
          return send(400, {
            error:
              "Enable source sharing and choose a request budget from 1 to 100",
          });
        cweController = new AbortController();
        const jobId = randomBytes(12).toString("hex");
        job = {
          status: "running",
          mode: "cwe-security",
          jobId,
          message: "Preparing static security assessment",
        };
        cweTask = withGraph(() =>
          reviewSecurityIssues(manifest, model, {
            sourceRoot,
            config: modelConfig,
            budget: input.budget,
            signal: cweController.signal,
            fetchImpl: cweModelFetch,
            trace: (event, data) => traces.record(event, { ...data, jobId }),
            progress: (message) => {
              job.message = message;
            },
            checkpoint: async () => {
              await checkpoint();
              if (persistenceError)
                throw Error("Security assessment checkpoint failed");
            },
          }),
        )
          .then((report) => {
            job = {
              status: "ready",
              mode: "cwe-security",
              jobId,
              message: `Security assessment ${report.status}; ${report.pending || 0} candidates remain unresolved.`,
            };
          })
          .catch(() => {
            job = {
              status: "failed",
              mode: "cwe-security",
              jobId,
              message:
                "Security assessment failed; inspect saved errors and traces",
            };
          });
        return send(202, job);
      }
      if (req.method === "GET" && url.pathname === "/api/cwe/evidence") {
        try {
          return send(
            200,
            await cweEvidence(
              model,
              manifest,
              root,
              Object.fromEntries(url.searchParams),
            ),
          );
        } catch (error) {
          return send(409, { error: error.message });
        }
      }
      if (req.method === "POST" && url.pathname === "/api/cwe/decision") {
        if (!model || ["running", "cancelling"].includes(job.status))
          return send(409, { error: "Wait for the scan to finish" });
        const input = await body(req),
          report =
            input.origin === "model" ? model.cweModelReview : model.cweReview;
        if (!report)
          return send(409, { error: "Run the corresponding CWE review first" });
        if (
          input.modelRevision !== model.modelRevision ||
          report.basedOnRevision !== model.modelRevision
        )
          return send(409, {
            error:
              "Rebuild and rescan the current source before recording a decision",
          });
        const f = report.findings.find((f) => f.id === input.id);
        if (
          !f ||
          ![
            "needs-review",
            "confirmed",
            "false-positive",
            "accepted-risk",
          ].includes(input.status) ||
          typeof input.reviewer !== "string" ||
          !input.reviewer.trim() ||
          input.reviewer.length > 200 ||
          typeof input.reason !== "string" ||
          !input.reason.trim() ||
          input.reason.length > 2000
        )
          throw Error(
            "Choose a finding and provide status, reviewer and rationale",
          );
        f.status = input.status;
        f.review = {
          reviewer: redact(input.reviewer),
          reason: redact(input.reason),
          at: new Date().toISOString(),
        };
        await checkpoint();
        return send(200, outputModel());
      }
      if (req.method === "POST" && url.pathname === "/api/cancel") {
        const reviewing = job.mode === "review",
          preserve = Boolean(model);
        if (!reviewing && preserve && scanPriorManifest)
          manifest = scanPriorManifest;
        job.status = "cancelling";
        await traces
          .record("job.cancelled", { jobId: job.jobId, mode: job.mode })
          .catch(() => {});
        cweController?.abort();
        await cweTask;
        await worker?.terminate();
        clearTimeout(timer);
        job = {
          status: preserve ? "ready" : "cancelled",
          message: preserve
            ? "Operation cancelled; previous snapshot and completed batches retained"
            : "Analysis cancelled; no completed model",
        };
        if (reviewing && preserve && model.aiReview) {
          model.aiReview.status = "partial";
          model.aiReview.error =
            "Review cancelled; continue to process remaining batches";
          model.aiReview.stopReason = "cancelled";
          interruptReviewExecution(model.aiReview, "cancelled");
        }
        interruptUsage(model?.usageLedger);
        if (reviewing && model?.aiReview)
          await updateReviewProgress(model, model.aiReview);
        if (!preserve) model = null;
        await checkpoint();
        return send(200, job);
      }
      if (req.method === "GET" && url.pathname === "/api/graph") {
        if (model?.sourceGraph?.storage !== "sqlite")
          return send(409, {
            error: "This workspace uses the in-memory graph",
          });
        return send(
          200,
          await queryGraph({
            operation: "page",
            generation: model.sourceGraph.generation,
            options: {
              kind: url.searchParams.get("kind") || undefined,
              search: url.searchParams.get("search") || "",
              after: url.searchParams.get("after") || "",
              limit: Number(url.searchParams.get("limit") || 100),
            },
          }),
        );
      }
      if (req.method === "GET" && url.pathname === "/api/model")
        return model
          ? send(200, outputModel())
          : send(409, { error: "No completed model" });
      if (req.method === 'POST' && url.pathname === '/api/poc-scope') {
        if (!model || ['running','cancelling'].includes(job.status)) return send(409,{error:'Open the graph and stop review before changing POC scope'});
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision) return send(409,{error:'Refresh the current graph'});
        const scope = resolvePocScope(model,input.scope);
        const candidate = {...model,pocScope:scope};
        const plan = await withGraph(() => pocReviewPlan(candidate));
        if (scope.kind !== 'repositories' && plan.batches.length > 12) throw Error('POC exceeds 12 review packets; narrow operation selectors');
        model.pocScope = scope;
        await checkpoint(); if (persistenceError) throw Error('POC scope could not be saved');
        return send(200,outputModel());
      }
      if (req.method === "GET" && url.pathname === "/api/system-review-plan") {
        if (!model) return send(409, { error: 'Open a saved graph first' });
        const plan = await withGraph(() => url.searchParams.get('scope') === 'poc' ? pocReviewPlan(model) : systemReviewPlan(model));
        return send(200, { reviewScope: 'system', preview: plan.preview, units: plan.batches.length, obligations: plan.obligations.length, gaps: plan.gaps.length, scope: plan.scope, semantics: plan.semantics });
      }
      if (req.method === "GET" && url.pathname === "/api/deployment-evidence") {
        if (!model) return send(409, { error: 'Open a saved graph first' });
        const ref = model.evidence.find(e => e.id === url.searchParams.get('id'));
        if (!ref) return send(404, { error: 'Unknown saved evidence reference' });
        return send(200, await sourceWindow(ref, manifest, root));
      }
      if (req.method === "POST" && url.pathname === "/api/deployment-context") {
        if (!model) return send(409, { error: 'Open a saved graph first' });
        if (['running', 'cancelling'].includes(job.status)) return send(409, { error: 'Stop the current review before changing deployment assumptions' });
        const input = await body(req);
        const changed = updateDeploymentContext(model, input);
        const original = model;
        await store?.archiveReview(original);
        if (model !== original || ['running', 'cancelling'].includes(job.status)) return send(409, { error: 'Workspace changed; refresh before saving deployment context' });
        model = changed;
        await checkpoint();
        return send(200, outputModel());
      }
      if (req.method === "POST" && url.pathname === "/api/system") {
        if (["running", "cancelling"].includes(job.status))
          return send(409, {
            error: "Stop the current analysis before editing the system model",
          });
        if (!model) return send(409, { error: "Build the source graph first" });
        model = editSystem(model, await body(req));
        await checkpoint();
        return send(200, outputModel());
      }
      if (req.method === "GET" && url.pathname === "/api/system-diagram") {
        if (!model) return send(409, { error: "Build the source graph first" });
        return send(
          200,
          systemSvg(model, {
            level: url.searchParams.get("level") || "system",
            lens: url.searchParams.get("lens") || "identity",
            focus: url.searchParams.get("focus") || "",
            actor: url.searchParams.get("actor") || "",
            threat: url.searchParams.get("threat") || "",
            showUnresolved: url.searchParams.get("showUnresolved") === "true",
            showSupporting: url.searchParams.get("showSupporting") === "true",
          }),
          "image/svg+xml",
        );
      }
      if (req.method === "POST" && url.pathname === "/api/bindings") {
        if (["running", "cancelling"].includes(job.status))
          return send(409, {
            error:
              "Wait for or cancel the current review before editing the DFD",
          });
        if (!model) return send(409, { error: "Analyze sources first" });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, {
            error: "Model changed; refresh before saving declarations",
          });
        const revised = structuredClone(model);
        revised.interfaces.forEach((i) => {
          i.resolution = "unresolved";
        });
        compose(revised, { bindings: input.bindings });
        model = revised;
        await checkpoint();
        return send(200, outputModel());
      }
      if (req.method === "GET" && url.pathname === "/api/export") {
        if (url.searchParams.get("format") === "errors") {
          res.setHeader(
            "Content-Disposition",
            'attachment; filename="synthesis-errors.json"',
          );
          return send(
            200,
            await errorReport({
              model,
              job,
              traces: await traces.export(),
              config: modelConfig,
              secrets: [githubToken, modelConfig?.apiKey, token],
              roots: [root],
            }),
          );
        }
        if (url.searchParams.get("format") === "diagnostics") {
          await traces.record("diagnostics.export-started", {
            sourceRevision: model?.modelRevision,
          });
          res.setHeader(
            "Content-Disposition",
            'attachment; filename="synthesis-diagnostics.zip"',
          );
          if (model?.sourceGraph?.storage === "sqlite") {
            res.writeHead(200, { "Content-Type": "application/zip" });
            await withGraph(async (reader) =>
              streamDiagnosticBundle(res, reader, {
                model,
                plan: model.aiReview?.plan ? undefined : reviewPlan(model),
                traces: await traces.export(),
                job,
                config: modelConfig,
                secrets: [githubToken, modelConfig?.apiKey, token],
                roots: [root],
              }),
            );
            await traces.record("diagnostics.export-completed", {
              sourceRevision: model.modelRevision,
              generation: model.sourceGraph.generation,
            });
            return res.end();
          }
          return send(
            200,
            Buffer.from(
              await diagnosticBundle({
                model,
                plan:
                  model && !model.aiReview?.plan
                    ? reviewPlan(model)
                    : undefined,
                traces: await traces.export(),
                job,
                config: modelConfig,
                secrets: [githubToken, modelConfig?.apiKey, token],
                roots: [root],
              }),
            ),
            "application/zip",
          );
        }
        if (!model) return send(409, { error: "No completed model" });
        const format = url.searchParams.get("format");
        const names = {
          "cwe-evidence-html": "cwe-evidence-report.html",
          "security-json": "security-investigations.json",
          "cwe-coverage-json": "cwe-target-coverage.json",
          "cwe-coverage-csv": "cwe-target-coverage.csv",
          "cwe-model-json": "cwe-source-review.json",
          "cwe-json": "cwe-review.json",
          "cwe-csv": "cwe-findings.csv",
          "cwe-sarif": "cwe-findings.sarif",
          html: "threat-model.html",
          "threat-print-html": "threat-model-review.html",
          securityControls: "control-register.csv",
          actors: "actor-register.csv",
          boundaries: "boundary-register.csv",
          threats: "threat-register.csv",
          flows: "flow-register.csv",
          components: "component-register.csv",
          assets: "asset-register.csv",
          svg: "dfd.svg",
          manifest: "reviewed-manifest.json",
          mermaid: "dfd.mmd",
          graph: "source-graph.json",
          "graph-mermaid": "source-graph.mmd",
          stride: "stride-matrix.csv",
          json: "model.json",
          usage: "token-usage.csv",
        };
        if (!Object.hasOwn(names, format))
          return send(400, { error: "Unknown export format" });
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${names[format]}"`,
        );
        if (format === "cwe-evidence-html") {
          if (["running", "cancelling"].includes(job.status))
            return send(409, {
              error:
                "Wait for analysis to finish before exporting code evidence.",
            });
          if (graphExportBusy)
            return send(409, {
              error: "Wait for the active export to finish.",
            });
          graphExportBusy = true;
          try {
            return send(
              200,
              await cweEvidenceReport(model, manifest, root, {
                secrets: [githubToken, modelConfig?.apiKey, token],
              }),
              "text/html; charset=utf-8",
            );
          } finally {
            graphExportBusy = false;
          }
        }
        if (format === "security-json")
          return send(200, securityRegister(model));
        if (format === "cwe-coverage-json")
          return send(200, cweTargetCoverage(model));
        if (format === "cwe-coverage-csv")
          return send(
            200,
            cweTargetCsv(cweTargetCoverage(model)),
            "text/csv; charset=utf-8",
          );
        if (format === "cwe-model-json")
          return model.cweModelReview
            ? send(200, model.cweModelReview)
            : send(409, { error: "Run CWE source review first" });
        if (format.startsWith("cwe-")) {
          if (!model.cweReview)
            return send(409, { error: "Run CWE review first" });
          if (format === "cwe-csv")
            return send(
              200,
              cweCsv(model.cweReview),
              "text/csv; charset=utf-8",
            );
          return send(
            200,
            format === "cwe-sarif"
              ? cweSarif(model.cweReview)
              : model.cweReview,
          );
        }
        if (format === "usage")
          return send(
            200,
            usageCsv(model.usageLedger),
            "text/csv; charset=utf-8",
          );
        if (format === "threat-print-html")
          return send(
            200,
            systemPrintReport(model, {
              accessScope: url.searchParams.get('accessScope') || 'all',
              includeUnresolved: url.searchParams.get('includeUnresolved') !== 'false',
            }),
            "text/html; charset=utf-8",
          );
        if (format === "html")
          return send(200, systemReport(model), "text/html");
        const diagramOptions = {
          level: url.searchParams.get("level") || "system",
          lens: url.searchParams.get("lens") || "identity",
          focus: url.searchParams.get("focus") || "",
          actor: url.searchParams.get("actor") || "",
          threat: url.searchParams.get("threat") || "",
          showUnresolved: url.searchParams.get("showUnresolved") === "true",
          showSupporting: url.searchParams.get("showSupporting") === "true",
        };
        if (format === "svg")
          return send(200, systemSvg(model, diagramOptions), "image/svg+xml");
        if (format === "mermaid")
          return send(200, systemMermaid(model, diagramOptions), "text/plain");
        if (format === "graph-mermaid")
          return withGraph(() =>
            send(200, sourceGraphMermaid(model), "text/plain"),
          );
        if (
          ["graph", "json"].includes(format) &&
          model.sourceGraph?.storage === "sqlite"
        ) {
          res.writeHead(200, { "Content-Type": "application/json" });
          await withGraph((reader) =>
            format === "graph"
              ? streamGraph(res, model.sourceGraph, reader)
              : streamModel(res, outputModel(), reader),
          );
          return res.end();
        }
        if (format === "graph") return send(200, model.sourceGraph);
        if (format === "stride")
          return send(
            200,
            registerCsv(model, "matrix"),
            "text/csv; charset=utf-8",
          );
        if (
          [
            "securityControls",
            "actors",
            "boundaries",
            "threats",
            "flows",
            "components",
            "assets",
          ].includes(format)
        )
          return send(
            200,
            registerCsv(model, format),
            "text/csv; charset=utf-8",
          );
        if (format === "manifest")
          return send(200, { ...manifest, declarations: model.declarations });
        return send(200, outputModel());
      }
      return send(404, { error: "Not found" });
    } catch (error) {
      if (
        req.url?.startsWith("/api/export") ||
        req.url?.startsWith("/api/graph-package")
      )
        await traces
          .record("export.failed", { failure: failureDetail(error.message) })
          .catch(() => {});
      if (res.headersSent) {
        res.destroy(error);
        return;
      }
      return send(400, { error: error.message });
    }
  });
  server.requestTimeout = 30000;
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
  } catch (error) {
    await traces.close();
    await store?.close();
    throw error;
  }
  const url = `http://127.0.0.1:${server.address().port}/#${token}`;
  if (!quiet)
    process.stdout.write(
      `Synthesis static pilot\nSource root: ${root}\nOpen this local access link:\n${url}\nModel: ${modelConfig ? modelConfig.provider + " / " + modelConfig.model : "none"}. Sources are read only. Stop with Ctrl+C.\n`,
    );
  let closing;
  server.on("close", () => {
    clearTimeout(timer);
    const previousStatus = job.status;
    job.status = "closed";
    closing = (async () => {
      cweController?.abort();
      await cweTask;
      await worker?.terminate();
      await Promise.all([...queryWorkers].map((w) => w.terminate()));
      if (model?.aiReview?.status === "pending") {
        model.aiReview.status = "partial";
        model.aiReview.error =
          "Server closed during review; continue pending work.";
      }
      interruptUsage(model?.usageLedger);
      interruptReviewExecution(model?.aiReview, "interrupted");
      if (model?.aiReview?.runId)
        await updateReviewProgress(model, model.aiReview);
      await checkpoint();
      await traces
        .record("session.closed", { status: previousStatus })
        .catch(() => {});
      exploration.close();
      await store?.close();
      await traces.close();
    })();
  });
  return {
    server,
    url,
    token,
    close: async () => {
      if (server.listening)
        await new Promise((resolve) => {
          server.close(resolve);
          server.closeAllConnections();
        });
      await closing;
    },
  };
}
