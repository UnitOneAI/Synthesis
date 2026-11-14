import { parentPort, workerData } from "node:worker_threads";
import { analyze } from "./engine.mjs";
import { enrichGraphModel } from "./graph-review.mjs";
try {
  let excerpts = new Map(workerData.excerpts || []);
  const progress = (message) =>
    parentPort.postMessage({ type: "progress", message });
  const checkpoint = (aiReview) =>
    parentPort.postMessage({ type: "checkpoint", aiReview });
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
          },
        )
      : await analyze(workerData.manifest, {
          ...workerData.options,
          progress,
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
