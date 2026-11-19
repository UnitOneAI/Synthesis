// A conditional estimate for the remaining planned scope, never a completion SLA.
// Only successful requests with measured wall-clock durations are samples.
export function reviewTiming(model, report) {
  if (report.status === "stale")
    return { state: "unavailable", reason: "stale-analysis" };
  const coverage = report.coverage || report;
  const total = coverage.totalBatches;
  const completed = coverage.completedBatches;
  if (!Number.isInteger(total) || !Number.isInteger(completed))
    return { state: "unavailable", reason: "planning" };
  const remainingPackets = Math.max(0, total - completed);
  const workers = report.execution?.concurrency || 1;
  if (!remainingPackets)
    return { state: "finished", remainingPackets: 0, workers };
  const cwe = report === model.cweModelReview;
  const phases = new Set(
    cwe
      ? ["cwe-file", "cwe-interaction"]
      : (report.plan?.batches || report.batches || []).map((b) => b.phase),
  );
  const samples = (model.usageLedger?.attempts || [])
    .filter(
      (a) =>
        a.status === "succeeded" &&
        a.provider === report.provider &&
        a.model === report.model &&
        a.sourceRevision === report.basedOnRevision &&
        phases.has(a.phase),
    )
    .map((a) => ({
      runId: a.runId,
      ended: Date.parse(a.endedAt),
      seconds: (Date.parse(a.endedAt) - Date.parse(a.startedAt)) / 1000,
    }))
    .filter(
      (a) => Number.isFinite(a.seconds) && a.seconds > 0 && a.seconds <= 900,
    )
    .sort((a, b) => a.ended - b.ended);
  const current = samples.filter((a) => a.runId === report.runId);
  const sampleScope =
    current.length >= 3 ? "current-action" : "matching-prior-actions";
  const selected = (current.length >= 3 ? current : samples).slice(-20);
  if (selected.length < 3)
    return {
      state: "unavailable",
      reason: "insufficient-timing",
      sampleSize: selected.length,
      remainingPackets,
      workers,
    };
  const meanSeconds =
    selected.reduce((n, a) => n + a.seconds, 0) / selected.length;
  return {
    state: "estimated",
    sampleSize: selected.length,
    sampleScope,
    meanSeconds,
    remainingPackets,
    workers,
    estimatedSeconds: Math.ceil(remainingPackets / workers) * meanSeconds,
  };
}
