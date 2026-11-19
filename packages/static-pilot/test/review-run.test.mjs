import test from "node:test";
import assert from "node:assert/strict";
import { reviewRunControl, updateReviewProgress } from "../src/review-run.mjs";
test("run controls validate advisory targets without changing bounded defaults", () => {
  assert.equal(reviewRunControl().mode, "bounded");
  assert.deepEqual(
    reviewRunControl({ runUntilComplete: true, tokenTarget: 1000 }),
    { mode: "until-complete", tokenTarget: 1000, tokenPolicy: "advisory" },
  );
  for (const tokenTarget of [
    -1,
    0,
    1.2,
    "100",
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
  ])
    assert.throws(() => reviewRunControl({ tokenTarget }));
  assert.throws(() => reviewRunControl({ runUntilComplete: "true" }));
});
test("advisory token telemetry retains unknowns and failures and warns once per action", async () => {
  const model = {
    usageLedger: {
      attempts: [
        { runId: "prior", usage: { totalTokens: 9999 } },
        { runId: "new", status: "succeeded", usage: { totalTokens: 12 } },
        { runId: "new", status: "failed", usage: null },
      ],
    },
  };
  const report = {
      runId: "new",
      runControl: reviewRunControl({ runUntilComplete: true, tokenTarget: 10 }),
    },
    events = [];
  await updateReviewProgress(
    model,
    report,
    (event, data) => events.push({ event, data }),
    "review",
  );
  await updateReviewProgress(
    model,
    report,
    (event, data) => events.push({ event, data }),
    "review",
  );
  assert.equal(events.length, 1);
  assert.equal(events[0].data.action, "continue");
  assert.deepEqual(report.runProgress, {
    requests: 2,
    reportedTokens: 12,
    unknownRequests: 1,
    failedRequests: 1,
    targetExceeded: true,
  });
});
