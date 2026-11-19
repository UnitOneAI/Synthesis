// Advisory token targets never authorize or stop requests; provider and evidence
// failures still stop continuous runs. These controls are not cache identity.
export function reviewRunControl(input = {}) {
  if (
    input.runUntilComplete !== undefined &&
    typeof input.runUntilComplete !== "boolean"
  )
    throw Error("Run until complete must be a boolean");
  const target = input.tokenTarget ?? null;
  if (target !== null && (!Number.isSafeInteger(target) || target < 1))
    throw Error("Token target must be a positive integer or omitted");
  return {
    mode: input.runUntilComplete === true ? "until-complete" : "bounded",
    tokenTarget: target,
    tokenPolicy: "advisory",
  };
}
export async function updateReviewProgress(model, report, trace, prefix) {
  const attempts = (model.usageLedger?.attempts || []).filter(
    (a) => a.runId === report.runId,
  );
  const priorExceeded = report.runProgress?.targetExceeded;
  const totalTokens = attempts.reduce(
    (n, a) => n + (a.usage?.totalTokens ?? 0),
    0,
  );
  const target = report.runControl?.tokenTarget;
  report.runProgress = {
    requests: attempts.length,
    reportedTokens: totalTokens,
    unknownRequests: attempts.filter((a) => a.usage?.totalTokens == null)
      .length,
    failedRequests: attempts.filter((a) =>
      ["failed", "interrupted"].includes(a.status),
    ).length,
    targetExceeded: target != null && totalTokens >= target,
  };
  if (report.runProgress.targetExceeded && !priorExceeded)
    await trace?.(`${prefix}.token-target-reached`, {
      runId: report.runId,
      tokenTarget: target,
      ...report.runProgress,
      action: "continue",
    });
}
