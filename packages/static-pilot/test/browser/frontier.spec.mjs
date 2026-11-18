import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { serve } from "../../src/server.mjs";
import { modelConfig } from "../../src/model-review.mjs";
test("graph investigation budgets persist and investigation steps remain browsable after restart", async ({
  page,
}) => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-frontier-ui-"),
  );
  const root = path.join(dir, "repos"),
    workspace = path.join(dir, "state");
  await fs.mkdir(path.join(root, "service"), { recursive: true });
  await fs.writeFile(
    path.join(root, "service", "app.py"),
    "def handler(value):\n    return value\n",
  );
  let calls = 0,
    app;
  const options = {
    sourceRoot: root,
    workspace,
    persist: true,
    quiet: true,
    port: 0,
    modelConfig: modelConfig(
      "anthropic-gateway",
      "claude-opus-4-6-1",
      { CLAUDE_API_KEY: "fixture" },
      { baseUrl: "https://gateway.example/anthropic" },
    ),
    cweModelFetch: async (_, opts) => {
      calls++;
      const body = JSON.parse(opts.body);
      expect(body.model).toBe("claude-opus-4-6-1");
      const p = JSON.parse(body.messages[0].content),
        r = p.records[0];
      return Response.json({
        stop_reason: "end_turn",
        usage: { input_tokens: 100, output_tokens: 20 },
        content: [
          {
            type: "text",
            text: JSON.stringify({
              findings: [],
              limitations: [],
              explorationRequests: [],
              targetReviews: p.targets.map((t) => ({
                targetId: t.id,
                status: "reviewed",
                rationale: "Fixture source inspected",
                locations: [
                  {
                    recordId: r.id,
                    startLine: r.startLine,
                    endLine: r.startLine,
                  },
                ],
              })),
            }),
          },
        ],
      });
    },
  };
  try {
    app = await serve({
      ...options,
      initialManifest: {
        profile: "fixture",
        repositories: [{ name: "service" }],
      },
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Build source graph", exact: true })
      .click();
    await expect(page.locator("#workspace")).toBeVisible({ timeout: 30000 });
    await page
      .getByRole("button", { name: "6 · Exploration", exact: true })
      .click();
    await page.locator("#exploration-consent").check();
    await page.locator("#exploration-tokens").fill("1000");
    await page.locator("#exploration-run").click();
    await expect(page.locator("#exploration-summary")).toContainText(
      "token-reservation-budget",
      { timeout: 15000 },
    );
    expect(calls).toBe(0);
    await page.locator("#exploration-budget").fill("1");
    await page.locator("#exploration-tokens").fill("250000");
    await page.locator("#exploration-run").click();
    await expect(page.locator("#exploration-summary")).toContainText(
      "120 reported",
      { timeout: 15000 },
    );
    expect(calls).toBe(1);
    await page.locator("#exploration-kind").selectOption("investigation-step");
    await expect(
      page.locator("#exploration-svg [data-node]").first(),
    ).toBeVisible();
    await app.close();
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "6 · Exploration", exact: true })
      .click();
    await expect(page.locator("#exploration-summary")).toContainText(
      "120 reported",
    );
    await page.locator("#exploration-kind").selectOption("investigation-step");
    await expect(
      page.locator("#exploration-svg [data-node]").first(),
    ).toBeVisible();
    expect(calls).toBe(1);
  } finally {
    await page.goto("about:blank");
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
