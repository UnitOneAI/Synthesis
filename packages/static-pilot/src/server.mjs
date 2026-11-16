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
      let completed = false;
      query.once("message", (message) => {
        completed = true;
        clearTimeout(deadline);
        message.error ? reject(Error(message.error)) : resolve(message.result);
      });
      query.once("error", reject);
      query.once("exit", () => {
        clearTimeout(deadline);
        queryWorkers.delete(query);
        if (!completed) reject(Error("Graph query interrupted"));
      });
    });
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
          } finally {
            reader.close();
          }
        }
        if (
          model.aiReview &&
          (model.aiReview.guidance?.hash !== GUIDANCE_HASH ||
            model.aiReview.promptHash !== sha(SYSTEM_PROMPT))
        ) {
          model.aiReview.status = "stale";
          model.aiReview.error =
            "Analysis methodology changed; previous scenarios are retained for reference. Run review with the current guidance.";
        }
        await traces.record("workspace.restored", {
          sourceRevision: model.modelRevision,
          priorStatus: model.aiReview?.status,
        });
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
            "Saved snapshot restored. Rebuild to inspect source changes.",
        };
      }
    } catch (error) {
      await traces.close();
      await store.close();
      throw error;
    }
  }
  const checkpoint = async () => {
    if (!store || !model) return;
    try {
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
    let finishing = false;
    const stop = (message) => {
      if (worker !== active || job.status !== "running" || finishing) return;
      if (model?.aiReview?.status === "pending") {
        model.aiReview.status = "partial";
        model.aiReview.error = message;
      }
      interruptUsage(model?.usageLedger);
      traces
        .record("job.failed", { jobId, mode, failure: failureDetail(message) })
        .catch(() => {});
      if (mode !== "review" && model && scanPriorManifest)
        manifest = scanPriorManifest;
      checkpoint();
      job = { status: model ? "ready" : "failed", message };
    };
    const activeTimer = setTimeout(
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
              model.aiReview.promptHash !== sha(SYSTEM_PROMPT)
            ) {
              m.model.aiReview.status = "stale";
              m.model.aiReview.error =
                "Source or analysis methodology changed; prior analysis retained for reference and requires a new review.";
            }
          }
          if (model?.architecture) {
            m.model.architecture = structuredClone(model.architecture);
            m.model.architecture.rebuildNotice =
              "Reviewer declarations retained. Recheck references and stale decisions after rebuilding.";
          }
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
          model.aiReview = m.aiReview;
          model.usageLedger = m.usageLedger;
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
        "app.js",
        "style.css",
        "workspace.js",
        "workspace.css",
        "cwe.js",
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
      if (req.method === "GET" && url.pathname === "/api/status")
        return send(200, {
          ...job,
          hasModel: Boolean(model),
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
          sourceRoot: root,
          githubConfigured: Boolean(githubToken),
          inference: publicModelConfig(modelConfig),
          defaultSourceExcerpts: includeSourceExcerpts,
        });
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
        if (model.sourceGraph?.storage === "sqlite")
          return send(200, await queryGraph({ operation: "plan", model }));
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
        if (typeof input.includeSourceExcerpts !== "boolean")
          throw new Error("Choose whether to include source excerpts");
        if (input.includeSourceExcerpts && !reviewExcerpts.length)
          return send(400, {
            error:
              "Source excerpts are not retained across restarts. Rebuild with excerpts enabled or review metadata only.",
          });
        await startJob("review", {
          model,
          excerpts: input.includeSourceExcerpts ? reviewExcerpts : [],
          options: {
            modelConfig,
            reviewBatches: input.maxBatches,
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
        }
        interruptUsage(model?.usageLedger);
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
          "cwe-model-json": "cwe-source-review.json",
          "cwe-json": "cwe-review.json",
          "cwe-csv": "cwe-findings.csv",
          "cwe-sarif": "cwe-findings.sarif",
          html: "threat-model.html",
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
      if (req.url?.startsWith("/api/export"))
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
      await checkpoint();
      await traces
        .record("session.closed", { status: previousStatus })
        .catch(() => {});
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
