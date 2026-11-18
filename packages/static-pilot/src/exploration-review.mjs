import { cweTargetCoverage } from "./cwe-targets.mjs";
import { enrichGraphModel } from "./graph-review.mjs";
import { reviewCweCode } from "./cwe-model.mjs";
import { reviewSecurityIssues } from "./security-review.mjs";
import { redact } from "./model-review.mjs";

// Finish the architecture phase before source review: later STRIDE results change
// shared context and would invalidate the source-review plan if interleaved.
export async function exploreStatic(manifest, model, options = {}) {
  const {
    budget = 12,
    signal,
    checkpoint,
    trace,
    progress,
    config,
    sourceRoot,
    fetchImpl = fetch,
  } = options;
  if (!config) throw Error("Configure an approved model provider");
  if (!Number.isInteger(budget) || budget < 1 || budget > 100)
    throw Error("Choose 1–100 requests");
  const run = (model.explorationRun = {
    version: 1,
    staticOnly: true,
    basedOnRevision: model.modelRevision,
    status: "running",
    budget,
    callsThisRun: 0,
    phase: "stride",
    startedAt: new Date().toISOString(),
    phases: [],
    coverageComplete: false,
  });
  const priorAttempts = new Set(
    (model.usageLedger?.attempts || []).map((a) => a.id),
  );
  const used = () =>
    (model.usageLedger?.attempts || []).filter((a) => !priorAttempts.has(a.id))
      .length;
  const save = async () => {
    run.callsThisRun = used();
    await checkpoint?.();
  };
  try {
    for (const phase of ["stride", "cwe", "assessment"]) {
      if (signal?.aborted) {
        run.status = "cancelled";
        break;
      }
      if (run.callsThisRun >= budget) break;
      run.phase = phase;
      await save();
      progress?.(`Static exploration: ${phase}`);
      await trace?.("exploration.phase-started", {
        phase,
        remainingBudget: budget - run.callsThisRun,
      });
      const remaining = budget - run.callsThisRun;
      if (phase === "stride") {
        await enrichGraphModel(model, config, new Map(), fetchImpl, {
          maxBatches: remaining,
          signal,
          trace,
          progress,
          checkpoint: save,
        });
        const c = model.aiReview.coverage;
        run.callsThisRun = used();
        run.phases.push({
          phase,
          status: model.aiReview.status,
          pending: c.totalBatches - c.completedBatches,
        });
        if (c.completedBatches < c.totalBatches) break;
      } else if (phase === "cwe") {
        const report = await reviewCweCode(manifest, model, {
          sourceRoot,
          config,
          budget: remaining,
          signal,
          trace,
          progress,
          checkpoint: save,
          fetchImpl,
        });
        run.callsThisRun = used();
        run.phases.push({
          phase,
          status: report.status,
          pending: report.pendingBatches,
        });
        if (report.status === "failed" || report.pendingBatches !== 0) break;
      } else {
        const report = await reviewSecurityIssues(manifest, model, {
          sourceRoot,
          config,
          budget: remaining,
          signal,
          trace,
          progress,
          checkpoint: save,
          fetchImpl,
        });
        run.callsThisRun = used();
        run.phases.push({
          phase,
          status: report.status,
          pending: report.pending,
        });
        run.unresolvedTargets = cweTargetCoverage(model).rows.filter(
          (r) =>
            ![
              "reviewed-scope",
              "no-relevant-evidence-in-reviewed-scope",
            ].includes(r.modelStatus),
        ).length;
        run.status = report.pending
          ? "partial"
          : run.unresolvedTargets
            ? "reviewed-with-gaps"
            : "reviewed-needs-human-review";
      }
    }
    if (signal?.aborted) run.status = "cancelled";
    else if (run.status === "running") run.status = "partial";
  } catch (e) {
    run.status = signal?.aborted ? "cancelled" : "failed";
    run.error = redact(e.message).slice(0, 600);
  } finally {
    run.finishedAt = new Date().toISOString();
    await trace?.("exploration.finished", run);
    await save();
  }
  return run;
}
