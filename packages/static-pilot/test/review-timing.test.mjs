import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import vm from "node:vm";
import { reviewTiming } from "../src/review-timing.mjs";

function fixture(cwe = false) {
  const report = {
    status: "running",
    runId: "current",
    provider: "anthropic-gateway",
    model: "claude-opus-4-6-1",
    basedOnRevision: "revision",
    execution: { concurrency: 4 },
    ...(cwe
      ? { totalBatches: 5303, completedBatches: 3 }
      : {
          coverage: { totalBatches: 453, completedBatches: 3 },
          plan: { batches: [{ phase: "repository" }] },
        }),
  };
  const model = {
    usageLedger: { attempts: [] },
    ...(cwe ? { cweModelReview: report } : { aiReview: report }),
  };
  const attempt = (seconds, extras = {}) => ({
    status: "succeeded",
    provider: report.provider,
    model: report.model,
    sourceRevision: report.basedOnRevision,
    runId: "current",
    phase: cwe ? "cwe-file" : "repository",
    startedAt: "2026-11-19T12:00:00.000Z",
    endedAt: new Date(
      Date.parse("2026-11-19T12:00:00.000Z") + seconds * 1000,
    ).toISOString(),
    ...extras,
  });
  return { model, report, attempt };
}

test("ETA uses measured successful calls and remaining scope at configured concurrency", () => {
  for (const cwe of [false, true]) {
    const { model, report, attempt } = fixture(cwe);
    model.usageLedger.attempts = [attempt(30), attempt(60), attempt(90)];
    const timing = reviewTiming(model, report);
    assert.equal(timing.meanSeconds, 60);
    assert.equal(timing.remainingPackets, cwe ? 5300 : 450);
    assert.equal(
      timing.estimatedSeconds,
      Math.ceil((cwe ? 5300 : 450) / 4) * 60,
    );
    assert.equal(timing.sampleScope, "current-action");
    assert.equal(timing.sampleSize, 3);
  }
});

test("ETA refuses sparse, invalid, stale and incompatible samples and separates failures", () => {
  const { model, report, attempt } = fixture();
  model.usageLedger.attempts = [
    attempt(60),
    attempt(120, { status: "failed" }),
    attempt(20, { provider: "other" }),
    attempt(30, { sourceRevision: "old" }),
    attempt(30, { phase: "cwe-file" }),
    attempt(30, { endedAt: null }),
    attempt(-1),
  ];
  assert.equal(reviewTiming(model, report).reason, "insufficient-timing");
  assert.equal(reviewTiming(model, report).sampleSize, 1);
  model.usageLedger.attempts.push(
    attempt(30, { runId: "prior" }),
    attempt(90, { runId: "prior" }),
  );
  assert.equal(
    reviewTiming(model, report).sampleScope,
    "matching-prior-actions",
  );
  report.status = "stale";
  assert.equal(reviewTiming(model, report).reason, "stale-analysis");
  report.status = "partial";
  report.coverage.completedBatches = report.coverage.totalBatches;
  assert.equal(reviewTiming(model, report).state, "finished");
});

test("ETA limits recent timing samples and UI labels assumptions without promising completion", async () => {
  const { model, report, attempt } = fixture(true);
  model.usageLedger.attempts = Array.from({ length: 25 }, (_, n) =>
    attempt(n + 1),
  );
  report.timing = reviewTiming(model, report);
  assert.equal(report.timing.sampleSize, 20);
  assert.equal(report.timing.meanSeconds, 15.5);
  report.runControl = { mode: "until-complete" };
  const context = { window: {} };
  vm.runInNewContext(
    await fs.readFile(
      new URL("../public/review-run.js", import.meta.url),
      "utf8",
    ),
    context,
  );
  const text = context.window.SynthesisReviewRun(report);
  assert.match(text, /Estimated remaining scope/);
  assert.match(text, /excludes retries and throttling/);
  assert.match(text, /at 4 workers/);
  report.stopReason = "provider-failure";
  assert.match(context.window.SynthesisReviewRun(report), /scope if resumed/);
});
