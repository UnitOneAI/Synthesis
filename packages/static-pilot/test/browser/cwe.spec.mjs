import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { serve } from "../../src/server.mjs";
import { sqliteSupported } from "../../src/graph-store.mjs";

test("12 repositories connect automatically and support CWE scan, review, exports and restart", async ({
  page,
}) => {
  test.skip(
    !process.env.SYNTHESIS_TEST_SEMGREP || !sqliteSupported(),
    "Qualified local scanner and SQLite required",
  );
  test.setTimeout(120000);
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-cwe-browser-"),
  );
  const root = path.join(dir, "sources"),
    workspace = path.join(dir, "workspace"),
    repositories = [];
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let app;
  try {
    for (let i = 0; i < 12; i++) {
      const name = "repo" + i;
      repositories.push({ name, selected: true });
      await fs.mkdir(path.join(root, name), { recursive: true });
      await fs.writeFile(
        path.join(root, name, "app.js"),
        `app.get('/service${i}', handler); ${i < 11 ? `fetch('https://host${i + 1}/service${i + 1}');` : ""}`,
      );
      await fs.writeFile(
        path.join(root, name, "settings.json"),
        JSON.stringify({ Kestrel: { Url: `https://host${i}` } }),
      );
      await fs.writeFile(
        path.join(root, name, "bad.py"),
        "import requests\nrequests.get('https://example.test', verify=False)\n",
      );
    }
    const options = {
      sourceRoot: root,
      workspace,
      persist: true,
      graphStorage: "sqlite",
      port: 0,
      quiet: true,
      cweScanner: process.env.SYNTHESIS_TEST_SEMGREP,
      initialManifest: {
        title: "Connected portfolio",
        profile: "test",
        repositories,
      },
    };
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Build source graph", exact: true })
      .click();
    await expect(page.locator("#workspace")).toBeVisible();
    await expect(page.locator(".ws-status")).toContainText(
      "11 discovered connections",
    );
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Export Semgrep JSON", exact: true }),
    ).toBeDisabled();
    await expect(
      page.getByRole("button", {
        name: "Export model CWE review",
        exact: true,
      }),
    ).toBeDisabled();
    await page.locator("#cwe-run").click();
    await expect(page.locator("#cwe-status")).toContainText(
      "completed · 12 potential weaknesses",
      { timeout: 60000 },
    );
    await expect(page.locator("#cwe-coverage tbody tr")).toHaveCount(12);
    await expect(
      page.getByRole("button", { name: "Export Semgrep JSON", exact: true }),
    ).toBeEnabled();
    await expect(
      page.getByRole("button", {
        name: "Export model CWE review",
        exact: true,
      }),
    ).toBeDisabled();
    await expect(page.locator("#cwe-model-status")).toContainText(
      "Semgrep results are separate",
    );
    await page.locator("#cwe-filter").fill("repo0");
    await expect(page.locator("#cwe-findings tbody tr")).toHaveCount(1);
    await page.locator("#cwe-findings button").click();
    await page
      .getByLabel("Reviewer", { exact: true })
      .fill("Security champion");
    await page
      .getByLabel("Rationale", { exact: true })
      .fill("Static test fixture reviewed");
    await page
      .getByLabel("Finding status", { exact: true })
      .selectOption("confirmed");
    await page.getByRole("button", { name: "Save finding decision" }).click();
    await expect(page.locator("#message")).toContainText(
      "Finding decision saved",
    );
    const downloading = page.waitForEvent("download");
    await page
      .locator("#cwe")
      .getByRole("button", { name: "Export Semgrep SARIF", exact: true })
      .click();
    const download = await downloading;
    const contents = JSON.parse(
      await fs.readFile(await download.path(), "utf8"),
    );
    expect(contents.runs[0].results).toHaveLength(12);
    expect(
      contents.runs[0].results.some((r) => r.properties.status === "confirmed"),
    ).toBeTruthy();
    await page.goto("about:blank");
    await app.close();
    app = await serve({ ...options, initialManifest: undefined });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await expect(page.locator("#cwe-status")).toContainText(
      "12 potential weaknesses",
    );
    await page.locator("#cwe-filter").fill("confirmed");
    await expect(page.locator("#cwe-findings tbody tr")).toHaveCount(1);
    expect(errors).toEqual([]);
  } finally {
    await page.close();
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("CWE source review sends consented code, shows partial results and resumes with metered model calls", async ({
  page,
}) => {
  const { modelConfig } = await import("../../src/model-review.mjs");
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-cwe-model-ui-"),
  );
  let app,
    calls = 0;
  const repositories = ["a", "b"].map((name) => ({ name, selected: true }));
  try {
    for (const { name } of repositories) {
      await fs.mkdir(path.join(dir, name));
      await fs.writeFile(
        path.join(dir, name, "query.py"),
        'def query(cursor, value):\n    cursor.execute(f"select * from t where id={value}")\n',
      );
    }
    app = await serve({
      sourceRoot: dir,
      port: 0,
      quiet: true,
      initialManifest: {
        title: "CWE source review",
        profile: "test",
        repositories,
      },
      modelConfig: modelConfig(
        "anthropic-gateway",
        "test-deployment",
        { CLAUDE_API_KEY: "fixture-key" },
        { baseUrl: "https://gateway.example/anthropic" },
      ),
      cweModelFetch: async (url, options) => {
        calls++;
        const packet = JSON.parse(JSON.parse(options.body).messages[0].content),
          r = packet.records[0];
        expect(r.code).toContain("cursor.execute");
        return Response.json({
          stop_reason: "end_turn",
          usage: { input_tokens: 100, output_tokens: 20 },
          content: [
            {
              type: "text",
              text: JSON.stringify({
                findings: [
                  {
                    cwe: "CWE-89",
                    title: "Formatted SQL",
                    explanation: "Input enters SQL text.",
                    preconditions: "Untrusted value reaches the function.",
                    counterEvidence: "Caller validation is not established.",
                    remediation: "Use parameters.",
                    locations: [{ recordId: r.id, startLine: 2, endLine: 2 }],
                  },
                ],
                limitations: [],
              }),
            },
          ],
        });
      },
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Build source graph", exact: true })
      .click();
    await expect(page.locator("#workspace")).toBeVisible();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await page.locator("#cwe-model-budget").fill("1");
    await page.locator("#cwe-model-run").click();
    await expect(page.locator("#message")).toContainText(
      "Enable source-code review",
    );
    expect(calls).toBe(0);
    await page.locator("#cwe-model-consent").check();
    await page.locator("#cwe-model-run").click();
    await expect(page.locator("#cwe-model-status")).toContainText(
      "partial · 1 / 2 packets completed",
    );
    await expect(page.locator("#cwe-model-results")).toContainText("CWE-89");
    expect(calls).toBe(1);
    await page.locator("#cwe-model-run").click();
    await expect(page.locator("#cwe-model-status")).toContainText(
      "completed-needs-review · 2 / 2 packets completed",
    );
    expect(calls).toBe(2);
    const exported = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Export model CWE review", exact: true })
      .click();
    const report = JSON.parse(
      await fs.readFile(await (await exported).path(), "utf8"),
    );
    expect(report.findings).toHaveLength(2);
    expect(JSON.stringify(report)).not.toContain("cursor.execute");
  } finally {
    await page.close();
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
