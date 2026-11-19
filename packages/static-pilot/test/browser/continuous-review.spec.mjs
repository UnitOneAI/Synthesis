import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import { reportFixture } from "../report-fixture.mjs";
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
            rationale: "Synthetic test needs caller context.",
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
test("continuous controls preserve consent, report advisory tokens, reuse graph and render source evidence", async ({
  page,
}) => {
  const f = await reportFixture();
  f.model.cweReview.limitations = [];
  f.model.cweReview.repositories = [
    {
      name: "service",
      status: "partial",
      scannedFiles: 1,
      eligibleFiles: 2,
      unsupportedFiles: 1,
      matchesGraphSnapshot: true,
      errors: [{ type: "PartialParsing", path: "app.py" }],
      skipped: ["legacy.CPP"],
    },
  ];
  f.model.cweReview.findings.forEach((f) => {
    f.interfaceIds = [];
    f.evidenceIds = [];
  });
  let app;
  const errors = [];
  let builds = 0,
    calls = 0;
  try {
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
      cweModelFetch: async (_, o) => {
        calls++;
        return reply(JSON.parse(JSON.parse(o.body).messages[0].content));
      },
    };
    app = await serve(options);
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("request", (r) => {
      if (r.method() === "POST" && r.url().endsWith("/api/analyze")) builds++;
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
      .click();
    await page.locator("#ws-until-complete").check();
    await page.locator("#ws-token-target").fill("1");
    await expect(page.locator("#ws-request-budget")).toBeDisabled();
    let submitted;
    await page.route("**/api/review", (route) => {
      submitted = route.request().postDataJSON();
      return route.fulfill({ status: 202, json: { status: "ready" } });
    });
    await page
      .getByRole("button", {
        name: "Run or continue STRIDE analysis",
        exact: true,
      })
      .click();
    await expect.poll(() => submitted?.runUntilComplete).toBe(true);
    expect(submitted.tokenTarget).toBe(1);
    await page.unroute("**/api/review");
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await page.locator("#cwe-coverage summary").click();
    await expect(page.locator("#cwe-coverage")).toContainText(
      "PartialParsing · app.py",
    );
    await expect(page.locator("#cwe-coverage")).toContainText(
      "Skipped · legacy.CPP",
    );
    await expect(page.locator("#cwe-coverage")).toContainText(
      "Unsupported files are outside",
    );
    await page.locator("#cwe-model-until-complete").check();
    await page.locator("#cwe-model-token-target").fill("1");
    await expect(page.locator("#cwe-model-budget")).toBeDisabled();
    const noConsent = page.waitForResponse((r) =>
      r.url().endsWith("/api/cwe/model"),
    );
    await page.locator("#cwe-model-run").click();
    expect((await noConsent).status()).toBe(400);
    expect(calls).toBe(0);
    await page.locator("#cwe-model-consent").check();
    await page.locator("#cwe-model-run").click();
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "Target reached (advisory; does not stop the run).",
      { timeout: 20000 },
    );
    await expect(page.locator("#cwe-run-progress")).toContainText("0 pending");
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "plan-exhausted",
    );
    const base = app.url.split("/#")[0],
      headers = { "x-synthesis-token": app.token };
    const model = await (
      await page.request.get(base + "/api/model", { headers })
    ).json();
    expect(model.cweModelReview.runControl.mode).toBe("until-complete");
    expect(model.cweModelReview.runProgress.reportedTokens).toBe(calls * 120);
    await page.locator('[data-finding="scan"]').click();
    const first = page.locator("#cwe-detail .cwe-code-evidence").first();
    await first.locator("summary").click();
    await expect(first.locator(".cwe-code-body")).toContainText(
      "Read locally; no model call",
    );
    expect(builds).toBe(0);
    expect(errors).toEqual([]);
    const before = calls;
    await app.close();
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await expect(page.locator("#cwe-run-progress")).toContainText("0 pending");
    await page.locator("#cwe-model-consent").check();
    await page.locator("#cwe-model-until-complete").check();
    await page.locator("#cwe-model-run").click();
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "This action: 0 calls",
    );
    expect(calls).toBe(before);
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});

test("continuous CWE Stop interrupts an active provider request and preserves checkpoint", async ({
  page,
}) => {
  const f = await reportFixture();
  f.model.cweReview.limitations = [];
  f.model.cweReview.findings.forEach((f) => {
    f.interfaceIds = [];
    f.evidenceIds = [];
  });
  let app;
  let started = false;
  try {
    const store = await workspaceStore(f.root, f.workspace);
    await store.save({ manifest: f.manifest, model: f.model });
    await store.close();
    app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      port: 0,
      quiet: true,
      modelConfig: config,
      cweModelFetch: async (_, o) => {
        started = true;
        return new Promise((resolve, reject) => {
          o.signal.addEventListener("abort", () => reject(Error("aborted")), {
            once: true,
          });
        });
      },
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await page.locator("#cwe-model-consent").check();
    await page.locator("#cwe-model-until-complete").check();
    await page.locator("#cwe-model-run").click();
    await expect.poll(() => started).toBe(true);
    await expect(page.locator("#cwe-model-stop")).toBeVisible();
    await page.locator("#cwe-model-stop").click();
    await expect(page.locator("#cwe-model-run")).toBeEnabled();
    await expect(page.locator("#cwe-model-status")).toContainText("cancelled");
    await expect(page.locator("#cwe-run-progress")).toContainText(
      "1 requests with unknown usage",
    );
    const data = JSON.parse(
      await fs.readFile(f.workspace + "/snapshot.json", "utf8"),
    );
    expect(data.data.model.cweModelReview.runControl.mode).toBe(
      "until-complete",
    );
    expect(data.data.model.cweModelReview.stopReason).toBe("cancelled");
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});
