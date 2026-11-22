import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyze } from "../../src/engine.mjs";
import { workspaceStore } from "../../src/workspace-store.mjs";
import { serve } from "../../src/server.mjs";
import { modelConfig } from "../../src/model-review.mjs";

const config = modelConfig(
  "anthropic-gateway",
  "claude-opus-4-6-1",
  { CLAUDE_API_KEY: "test-only-key" },
  { baseUrl: "https://gateway.example/anthropic" },
);
const reply = (packet) =>
  Response.json({
    stop_reason: "end_turn",
    usage: { input_tokens: 100, output_tokens: 20 },
    content: [
      {
        type: "text",
        text: JSON.stringify({
          findings: [],
          limitations: [],
          targetReviews: packet.targets.map((t) => ({
            targetId: t.id,
            status: "needs-context",
            rationale: "Synthetic test requires caller context.",
            locations: [
              ...new Map(packet.records.map((r) => [r.repository, r])).values(),
            ].map((r) => ({
              recordId: r.id,
              startLine: r.startLine,
              endLine: r.startLine,
            })),
          })),
        }),
      },
    ],
  });

test("parallel CWE controls validate limits, display active work and aggregate completed results", async ({
  page,
}) => {
  const dir = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-parallel-ui-")),
  );
  const root = path.join(dir, "sources"),
    workspace = path.join(dir, "workspace");
  const manifest = { profile: "test", repositories: [{ name: "service" }] };
  let app;
  try {
    await fs.mkdir(path.join(root, "service"), { recursive: true });
    await fs.writeFile(
      path.join(root, "service", "large.py"),
      Array.from({ length: 4500 }, (_, i) => `# source context ${i}`).join(
        "\n",
      ),
    );
    const model = await analyze(manifest, { sourceRoot: root });
    const store = await workspaceStore(root, workspace);
    await store.save({ manifest, model });
    await store.close();
    let active = 0,
      peak = 0,
      calls = 0,
      auto = false;
    const waiting = [];
    app = await serve({
      sourceRoot: root,
      workspace,
      persist: true,
      port: 0,
      quiet: true,
      modelConfig: config,
      cweModelFetch: async (_, options) => {
        const packet = JSON.parse(JSON.parse(options.body).messages[0].content);
        calls++;
        active++;
        peak = Math.max(peak, active);
        try {
          if (!auto)
            await new Promise((resolve, reject) => {
              waiting.push(resolve);
              options.signal.addEventListener(
                "abort",
                () => reject(Error("cancelled")),
                { once: true },
              );
            });
          return reply(packet);
        } finally {
          active--;
        }
      },
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    const base = app.url.split("/#")[0],
      headers = { "x-synthesis-token": app.token };
    for (const concurrency of [0, 5, "2", null, 1.5]) {
      const invalid = await page.request.post(base + "/api/cwe/model", {
        headers,
        data: {
          modelRevision: model.modelRevision,
          budget: 3,
          includeSourceCode: true,
          concurrency,
        },
      });
      expect(invalid.status()).toBe(400);
      expect((await invalid.json()).error).toContain(
        "1–4 parallel review workers",
      );
    }
    expect(calls).toBe(0);
    await expect(page.locator("#cwe-model-workers")).toHaveValue("2");
    await page.locator("#cwe-model-consent").check();
    await page.locator("#cwe-model-workers").selectOption("3");
    await page.locator("#cwe-model-budget").fill("3");
    await page.locator("#cwe-model-run").click();
    await expect.poll(() => active).toBe(3);
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "3 active / 3 limit",
    );
    await expect(page.locator("#cwe-model-workers")).toBeDisabled();
    expect(calls).toBe(3);
    const status = await (
      await page.request.get(base + "/api/status", { headers })
    ).json();
    expect(status.reviewRuns.cwe.execution.active).toBe(3);
    expect(status.reviewRuns.cwe.execution.concurrency).toBe(3);
    expect(JSON.stringify(status.reviewRuns.cwe.execution)).not.toContain(
      "source context",
    );
    auto = true;
    waiting.splice(0).forEach((resolve) => resolve());
    await expect(page.locator("#cwe-model-run")).toBeEnabled();
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "0 active / 3 limit",
    );
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "3 completed, 0 failed this action",
    );
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "360 reported tokens",
    );
    expect(peak).toBe(3);
    expect(calls).toBe(3);
    const completed = await (
      await page.request.get(base + "/api/model", { headers })
    ).json();
    expect(completed.cweModelReview.completedBatches).toBe(3);
    const completedIds = completed.cweModelReview.batches
      .filter((b) => b.status === "completed")
      .map((b) => b.id);

    // Continue with two active packets, then stop. Previously completed work must survive.
    auto = false;
    await page.locator("#cwe-model-workers").selectOption("2");
    await page.locator("#cwe-model-until-complete").check();
    await page.locator("#cwe-model-run").click();
    await expect.poll(() => active).toBe(2);
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "2 active / 2 limit",
    );
    await page.locator("#cwe-model-stop").click();
    await expect(page.locator("#cwe-model-run")).toBeEnabled();
    await expect(page.locator("#cwe-model-status")).toContainText("cancelled");
    expect(active).toBe(0);
    expect(calls).toBe(5);
    const stopped = await (
      await page.request.get(base + "/api/model", { headers })
    ).json();
    expect(
      stopped.cweModelReview.batches
        .filter((b) => b.status === "completed")
        .map((b) => b.id)
        .sort(),
    ).toEqual(completedIds.sort());
    expect(stopped.cweModelReview.runProgress.unknownRequests).toBe(2);
  } finally {
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("parallel STRIDE controls submit workers and restore interrupted pool state without duplicate counts", async ({
  page,
}) => {
  const { reportFixture } = await import("../report-fixture.mjs");
  const { enrichGraphModel } = await import("../../src/graph-review.mjs");
  const f = await reportFixture();
  let app;
  try {
    await enrichGraphModel(
      f.model,
      config,
      new Map(),
      async () =>
        Response.json({
          stop_reason: "end_turn",
          usage: { input_tokens: 100, output_tokens: 20 },
          content: [
            {
              type: "text",
              text: JSON.stringify({
                summary: "Static fixture",
                threats: [],
                connections: [],
                questions: [],
              }),
            },
          ],
        }),
      { maxBatches: 1 },
    );
    const review = f.model.aiReview;
    review.status = "pending";
    review.runId = "interrupted-test-run";
    review.execution = {
      kind: "bounded-agent-pool",
      concurrency: 3,
      active: 3,
      queued: 3,
      started: 3,
      completed: 0,
      failed: 0,
      peakActive: 3,
      stopped: false,
      stopReason: null,
    };
    for (let i = 0; i < 2; i++)
      f.model.usageLedger.attempts.push({
        id: `interrupted-${i}`,
        runId: review.runId,
        status: "in-flight",
        usage: null,
        repositories: ["service"],
      });
    review.batches.push({
      id: "prepared-uncheckpointed",
      status: "queued",
      interfaceIds: [],
      packetHash: "fixture-prepared",
    });
    const ledgerRequests = f.model.usageLedger.attempts.length;
    const store = await workspaceStore(f.root, f.workspace);
    await store.save({ manifest: f.manifest, model: f.model });
    await store.close();
    const options = {
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      port: 0,
      quiet: true,
      modelConfig: config,
    };
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
      .click();
    await expect(page.getByRole("heading", { name: "External interfaces first" })).toBeVisible();
    await expect(page.locator(".ws-review-order").getByRole("row").filter({ hasText: "Potential external entry points" })).toContainText("1 / 1");
    await expect(page.locator("#ws-review-workers")).toHaveValue("2");
    await expect(page.locator("#ws-run-progress")).toContainText(
      "0 active / 3 limit; 6 queued this action",
    );
    await expect(page.locator("#ws-run-progress")).toContainText(
      "3 interrupted packets require retry",
    );
    await expect(page.locator("#ws-run-progress")).toContainText(
      "2 requests with unknown usage",
    );
    await expect(page.locator("#ws-run-progress")).toContainText(
      "1 prepared packet has uncertain submission; token totals may be incomplete.",
    );
    const base = app.url.split("/#")[0],
      headers = { "x-synthesis-token": app.token };
    for (const concurrency of [0, 5, "2", null, 1.5]) {
      const invalid = await page.request.post(base + "/api/review", {
        headers,
        data: {
          modelRevision: f.model.modelRevision,
          maxBatches: 1,
          includeSourceExcerpts: false,
          concurrency,
        },
      });
      expect(invalid.status()).toBe(400);
      expect((await invalid.json()).error).toContain(
        "1–4 parallel review workers",
      );
    }
    let submitted;
    await page.route("**/api/review", (route) => {
      submitted = route.request().postDataJSON();
      return route.fulfill({ status: 202, json: { status: "ready" } });
    });
    await page.locator("#ws-review-workers").selectOption("4");
    await page.locator("#ws-until-complete").check();
    await page
      .getByRole("button", {
        name: "Run or continue STRIDE analysis",
        exact: true,
      })
      .click();
    await expect.poll(() => submitted?.concurrency).toBe(4);
    expect(submitted.runUntilComplete).toBe(true);
    for (let i = 0; i < 2; i++) {
      const status = await (
        await page.request.get(base + "/api/status", { headers })
      ).json();
      expect(status.reviewRuns.stride.execution.queued).toBe(6);
      expect(status.reviewRuns.stride.execution.interrupted).toBe(3);
      expect(status.reviewRuns.stride.execution.dispatchUncertain).toBe(1);
      expect(status.reviewRuns.stride.runProgress.requests).toBe(2);
      expect(status.reviewRuns.stride.runProgress.reportedTokens).toBe(0);
      expect(status.reviewRuns.stride.runProgress.unknownRequests).toBe(2);
    }
    await app.close();
    app = await serve(options);
    const status = await (
      await page.request.get(app.url.split("/#")[0] + "/api/status", {
        headers: { "x-synthesis-token": app.token },
      })
    ).json();
    expect(status.reviewRuns.stride.execution.active).toBe(0);
    expect(status.reviewRuns.stride.execution.queued).toBe(6);
    expect(status.reviewRuns.stride.execution.interrupted).toBe(3);
    expect(status.reviewRuns.stride.execution.dispatchUncertain).toBe(1);
    expect(status.reviewRuns.stride.runProgress.requests).toBe(2);
    expect(status.reviewRuns.stride.runProgress.reportedTokens).toBe(0);
    expect(status.reviewRuns.stride.runProgress.unknownRequests).toBe(2);
    const restored = await (
      await page.request.get(app.url.split("/#")[0] + "/api/model", {
        headers: { "x-synthesis-token": app.token },
      })
    ).json();
    expect(restored.usageLedger.attempts.length).toBe(ledgerRequests);
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});
