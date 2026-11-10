import { parentPort, workerData } from "node:worker_threads";
import { analyze } from "./engine.mjs";
try {
  parentPort.postMessage({
    type: "done",
    model: await analyze(workerData.manifest, {
      ...workerData.options,
      progress: (message) =>
        parentPort.postMessage({ type: "progress", message }),
    }),
  });
} catch (error) {
  parentPort.postMessage({ type: "error", message: error.message });
}
