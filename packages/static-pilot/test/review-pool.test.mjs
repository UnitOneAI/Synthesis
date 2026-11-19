import test from "node:test";
import assert from "node:assert/strict";
import { runReviewPool, reviewConcurrency } from "../src/review-pool.mjs";
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
test("bounded agent pool dispatches each job once with a shared concurrency limit", async () => {
  for (const n of [0, 5, 1.5, "2", null])
    assert.throws(() => reviewConcurrency(n));
  assert.equal(reviewConcurrency(), 2);
  let active = 0,
    peak = 0;
  const ids = [],
    agents = new Set(),
    snapshots = [];
  const state = await runReviewPool(
    Array.from({ length: 17 }, (_, i) => i),
    {
      concurrency: 3,
      onState: (s) => snapshots.push(s),
      run: async (i, { agentId }) => {
        active++;
        peak = Math.max(peak, active);
        ids.push(i);
        agents.add(agentId);
        await delay((i % 3) + 1);
        active--;
      },
    },
  );
  assert.equal(peak, 3);
  assert.equal(agents.size, 3);
  assert.deepEqual(
    ids.sort((a, b) => a - b),
    Array.from({ length: 17 }, (_, i) => i),
  );
  assert.equal(state.completed, 17);
  assert.equal(state.active, 0);
  assert.equal(state.queued, 0);
  assert.ok(snapshots.every((s) => s.active <= 3));
});
test("pool stops dispatch on a terminal result but drains active workers", async () => {
  let stop = null,
    calls = 0,
    drained = false;
  const state = await runReviewPool([0, 1, 2, 3, 4], {
    concurrency: 2,
    shouldStop: () => stop,
    run: async (i) => {
      calls++;
      if (i === 0) {
        await delay(1);
        stop = "provider-failure";
        return { failed: true };
      }
      await delay(15);
      drained = true;
    },
  });
  assert.equal(calls, 2);
  assert.equal(drained, true);
  assert.equal(state.active, 0);
  assert.equal(state.failed, 1);
  assert.equal(state.completed, 1);
  assert.equal(state.queued, 3);
  assert.equal(state.stopReason, "provider-failure");
});
test("pool cancellation and coordinator errors retain undispatched work and drain", async () => {
  const controller = new AbortController();
  let calls = 0,
    drained = false;
  const state = await runReviewPool([0, 1, 2, 3], {
    concurrency: 2,
    signal: controller.signal,
    run: async () => {
      calls++;
      await delay(1);
      controller.abort();
    },
  });
  assert.equal(calls, 2);
  assert.equal(state.queued, 2);
  assert.equal(state.stopReason, "cancelled");
  let errorCalls = 0;
  await assert.rejects(
    runReviewPool([0, 1, 2, 3], {
      concurrency: 2,
      run: async (i) => {
        errorCalls++;
        if (i === 0) {
          await delay(1);
          throw Error("checkpoint failed");
        }
        await delay(10);
        drained = true;
      },
    }),
    /checkpoint failed/,
  );
  assert.equal(errorCalls, 2);
  assert.equal(drained, true);
});
