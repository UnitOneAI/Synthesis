(() => {
  window.SynthesisReviewRun = (run) => {
    if (!run?.runControl) return "";
    const p = run.runProgress || {},
      c = run.coverage || {},
      n = (x) => Number(x || 0).toLocaleString("en-US");
    const done = run.completedBatches ?? c.completedBatches ?? 0;
    const total = run.totalBatches ?? c.totalBatches ?? 0;
    const pending = run.pendingBatches ?? c.pendingBatches;
    const failed = run.failedBatches ?? c.failedBatches ?? 0;
    const target = run.runControl.tokenTarget;
    const x = run.execution;
    const workers = x
      ? ` Workers: ${n(x.active)} active / ${n(x.concurrency)} limit; ${n(x.queued)} queued this action; ${n(x.completed)} completed, ${n(x.failed)} failed this action.${x.interrupted ? ` ${n(x.interrupted)} interrupted packets require retry.` : ""}${x.dispatchUncertain ? ` ${n(x.dispatchUncertain)} prepared ${x.dispatchUncertain === 1 ? "packet has" : "packets have"} uncertain submission; token totals may be incomplete.` : ""}${x.stopped ? (x.active ? " New dispatch stopped; active requests must settle before resume." : " New dispatch stopped; completed work is retained.") : ""}`
      : "";
    return `${run.runControl.mode === "until-complete" ? "Run until complete" : "Bounded run"} · ${n(done)} / ${n(total)} packets completed · ${pending == null ? "Unknown" : n(pending)} pending · ${n(failed)} failed. This action: ${n(p.requests)} calls, ${n(p.reportedTokens)} reported tokens, ${n(p.unknownRequests)} requests with unknown usage.${workers}${target ? ` Token target ${n(target)} (advisory).${p.targetExceeded ? " Target reached (advisory; does not stop the run)." : ""}` : " No token target set."}${run.stopReason ? ` Stop reason: ${run.stopReason}.` : ""} Completion covers planned packets, not proof of complete security coverage.`;
  };
})();
