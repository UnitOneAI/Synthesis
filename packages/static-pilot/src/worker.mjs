import { parentPort, workerData } from "node:worker_threads";
import { analyze } from "./engine.mjs";
import { enrichGraphModel } from "./graph-review.mjs";
try {
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
      parentPort.postMessage({ type: "checkpoint", id, aiReview, usageLedger });
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
  const model =
    workerData.mode === "review"
      ? await enrichGraphModel(
          workerData.model,
          workerData.options.modelConfig,
          excerpts,
          fetch,
          {
            maxBatches: workerData.options.reviewBatches,
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
  parentPort.postMessage({
    type: "done",
    model,
    excerpts: [...excerpts],
  });
} catch (error) {
  parentPort.postMessage({ type: "error", message: error.message });
}
