import {assessCompletedPoc} from './threat-validation.mjs';
import {reviewFeatureCohorts} from './feature-review-run.mjs';
import {
  verifiedStrideSource,
  prepareStrideEvidence,
  STRIDE_EVIDENCE_VERSION,
} from "./stride-evidence.mjs";
import { GraphStore, attachGraph } from "./graph-store.mjs";
import { parentPort, workerData } from "node:worker_threads";
import { analyze } from "./engine.mjs";
import { enrichGraphModel } from "./graph-review.mjs";
let graphStore;
try {
  if (
    workerData.mode === "review" &&
    workerData.model?.sourceGraph?.storage === "sqlite"
  ) {
    // Review only reads the published graph. Traversal and packet scratch tables
    // stay temporary instead of committing each planner operation to the WAL.
    graphStore = new GraphStore(workerData.options.graphDatabase, {
      readOnly: true,
    });
    attachGraph(workerData.model.sourceGraph, graphStore);
  }
  let excerpts = new Map(workerData.excerpts || []);
  const progress = (message) =>
    parentPort.postMessage({ type: "progress", message });
  let checkpointId = 0;
  const checkpoint = (aiReview, usageLedger) =>
    new Promise((resolve, reject) => {
      const id = ++checkpointId;
      const ack = (message) => {
        if (message.type !== "checkpoint-saved" || message.id !== id) return;
        parentPort.off("message", ack);
        message.error
          ? reject(Error("Workspace checkpoint failed; review stopped"))
          : resolve();
      };
      parentPort.on("message", ack);
      parentPort.postMessage({ type: "checkpoint", id, aiReview, usageLedger, savedStrideScopes: workerData.model?.savedStrideScopes, threatValidation: workerData.model?.threatValidation,featureReviewRun:workerData.model?.featureReviewRun,featureEvidenceHistory:workerData.model?.featureEvidenceHistory });
    });
  const trace = (event, data) =>
    new Promise((resolve, reject) => {
      const id = ++checkpointId;
      const ack = (message) => {
        if (message.type !== "trace-saved" || message.id !== id) return;
        parentPort.off("message", ack);
        message.error
          ? reject(
              Error("Trace output could not be written; operation stopped"),
            )
          : resolve();
      };
      parentPort.on("message", ack);
      parentPort.postMessage({
        type: "trace",
        id,
        event,
        data: { ...data, workerHeapUsedBytes: process.memoryUsage().heapUsed },
      });
    });
  const onStaticModel = (model) =>
    new Promise((resolve, reject) => {
      const id = ++checkpointId;
      const ack = (message) => {
        if (message.type !== "static-saved" || message.id !== id) return;
        parentPort.off("message", ack);
        message.error
          ? reject(Error("Workspace checkpoint failed; review stopped"))
          : resolve(message.model);
      };
      parentPort.on("message", ack);
      parentPort.postMessage({ type: "static-checkpoint", id, model });
    });
  await trace("worker.started", { mode: workerData.mode });
  const source =
    workerData.mode === "review" && workerData.options.includeSourceExcerpts
      ? await verifiedStrideSource(
          workerData.model,
          workerData.manifest,
          workerData.options.sourceRoot,
          progress,
        )
      : null;
  const model =
    workerData.mode === "review"
      ? await (workerData.options.reviewScope==='poc' && workerData.model.pocScope?.reviewDepth==='security-features'
          ? (model,config,excerpts,fetchImpl,options)=>reviewFeatureCohorts(model,workerData.manifest,config,excerpts,fetchImpl,{...options,sourceRoot:workerData.options.sourceRoot,verifiedSource:source})
          : enrichGraphModel)(
          workerData.model,
          workerData.options.modelConfig,
          excerpts,
          fetch,
          {
            ...(source
              ? {
                  evidencePolicy: STRIDE_EVIDENCE_VERSION,
                  prepareBatch: (batch) =>
                    prepareStrideEvidence(batch.packet, source),
                }
              : {}),
            reviewScope: workerData.options.reviewScope,
            maxBatches: workerData.options.reviewBatches,
            concurrency: workerData.options.concurrency,
            runUntilComplete: workerData.options.runUntilComplete,
            tokenTarget: workerData.options.tokenTarget,
            progress,
            checkpoint,
            trace,
          },
        )
      : await analyze(workerData.manifest, {
          ...workerData.options,
          progress,
          trace,
          checkpoint,
          onStaticModel,
          onExcerpts: (value) => {
            excerpts = value;
          },
        });
  if (workerData.mode === 'review' && workerData.options.reviewScope === 'poc' && model.pocScope?.kind !== 'repositories' &&
      !model.aiReview.coverage.pendingBatches && !model.aiReview.coverage.failedBatches && model.aiReview.threats.length) {
    progress('POC STRIDE packets saved; assessing scenarios against code and shared controls');
    await assessCompletedPoc(workerData.manifest, model, {
      sourceRoot: workerData.options.sourceRoot, config:workerData.options.modelConfig,
      budget:100, runUntilComplete:true, progress, trace,
      checkpoint:()=>checkpoint(model.aiReview,model.usageLedger),
    });
  }
  parentPort.postMessage({
    type: "done",
    model,
    excerpts: [...excerpts],
  });
} catch (error) {
  parentPort.postMessage({ type: "error", message: error.message });
} finally {
  graphStore?.checkpoint();
  graphStore?.close();
  parentPort.close();
}
