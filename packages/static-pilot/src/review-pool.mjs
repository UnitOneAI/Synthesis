// A bounded, in-process agent coordinator. Only the supplied static review task
// can run; it does not execute target code or grant agents arbitrary tools.
export function reviewConcurrency(value = 2) {
  if (!Number.isInteger(value) || value < 1 || value > 4)
    throw Error("Choose 1–4 parallel review agents");
  return value;
}
export async function runReviewPool(
  items,
  { concurrency = 2, signal, shouldStop = () => false, run, onState } = {},
) {
  concurrency = reviewConcurrency(concurrency);
  const state = {
    kind: "bounded-agent-pool",
    concurrency,
    active: 0,
    queued: items.length,
    started: 0,
    completed: 0,
    failed: 0,
    peakActive: 0,
    stopped: false,
    stopReason: null,
  };
  let next = 0,
    fatal;
  const publish = () => onState?.({ ...state });
  const stopped = () => signal?.aborted || fatal || shouldStop();
  async function worker(workerIndex) {
    while (next < items.length && !stopped()) {
      const index = next++;
      state.started++;
      state.active++;
      state.queued--;
      state.peakActive = Math.max(state.peakActive, state.active);
      try {
        await publish();
        // Cancellation may arrive while the coordinator is persisting state.
        if (stopped()) {
          state.started--;
          state.queued++;
          break;
        }
        const result = await run(items[index], {
          index,
          agentId: `review-agent-${workerIndex + 1}`,
        });
        if (result?.skipped) {
          state.started--;
          state.queued++;
        } else if (result?.failed) state.failed++;
        else state.completed++;
      } catch (error) {
        state.failed++;
        fatal ||= error;
      } finally {
        state.active--;
        try {
          await publish();
        } catch (error) {
          fatal ||= error;
        }
      }
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, (_, i) =>
      worker(i),
    ),
  );
  state.stopped = Boolean(stopped());
  state.stopReason = signal?.aborted
    ? "cancelled"
    : fatal
      ? "coordinator-failure"
      : shouldStop() || null;
  await publish();
  if (fatal) throw fatal;
  return state;
}
