import { parentPort, workerData } from "node:worker_threads";
import { GraphStore, attachGraph } from "./graph-store.mjs";
import { reviewPlan } from "./graph-review.mjs";
let store;
try {
  store = new GraphStore(workerData.file, { readOnly: true });
  let result;
  if (workerData.operation === "page")
    result = store.page(workerData.generation, workerData.options);
  else if (workerData.operation === "plan") {
    const model = workerData.model;
    attachGraph(model.sourceGraph, store);
    const plan = reviewPlan(model);
    result = {
      modelRevision: model.modelRevision,
      batches: plan.batches.length,
      oversizedRecords: plan.omitted.length,
      repositories: model.sources.length,
      obligations: plan.obligations.length,
      gaps: plan.gaps.length,
      splits: plan.splits.length,
    };
  } else throw Error("Unsupported graph query");
  parentPort.postMessage({ result });
} catch (error) {
  parentPort.postMessage({ error: error.message });
} finally {
  store?.close();
  parentPort.close();
}
