import { unzipSync, strFromU8 } from "fflate";
import { usageSummary } from "../../src/token-usage.mjs";
import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { serve } from "../../src/server.mjs";
let app, dir, errors;
const root = fileURLToPath(
  new URL("../../fixtures/repositories", import.meta.url),
);
const manifest = {
  title: "Functional security review",
  profile: "test configuration",
  repositories: [
    { name: "frontdoor" },
    { name: "business" },
    { name: "setup" },
  ],
};
test.beforeEach(async ({ page }) => {
  errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && !message.text().includes("404"))
      errors.push(message.text());
  });
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-browser-"));
  app = await serve({
    sourceRoot: root,
    workspace: dir,
    persist: true,
    port: 0,
    quiet: true,
    initialManifest: manifest,
  });
  await page.goto(app.url);
  await page
    .getByRole("button", { name: "Build source graph", exact: true })
    .click();
  await expect(page.locator("#workspace")).toBeVisible();
  await expect(page.locator("#ws-canvas svg")).toBeVisible();
});
test.afterEach(async ({ page }) => {
  await page.close();
  await app?.close();
  expect(errors).toEqual([]);
  await fs.rm(dir, { recursive: true, force: true });
});
const tab = (page, name) =>
  page.locator(".ws-tabs").getByRole("button", { name, exact: true }).click();
const field = (page, name) =>
  page.locator("#ws-record-form").getByLabel(name, { exact: true });

test("DFD context, focus, trust lenses and actor selection show real source evidence", async ({
  page,
}) => {
  await expect(page.locator("#ws-canvas")).toContainText("Static evidence");
  expect((await page.locator("#ws-canvas").boundingBox()).y).toBeLessThan(600);
  await page.getByLabel("View", { exact: true }).selectOption("context");
  await expect(page.locator("#ws-canvas")).toContainText("context");
  await page.getByLabel("View", { exact: true }).selectOption("system");
  await page.getByLabel("Trust lens", { exact: true }).selectOption("network");
  await expect(page.locator("#ws-canvas")).toContainText("network lens");
  await tab(page, "Components");
  await page.locator(".ws-record").first().click();
  await expect(page.locator("#ws-inspector")).toContainText(
    "Supporting evidence",
  );
  await page.getByRole("button", { name: "Show on DFD", exact: true }).click();
  await expect(page.getByLabel("View", { exact: true })).toHaveValue("focus");
  await expect(page.locator("#ws-canvas svg")).toBeVisible();
  await tab(page, "Threat actors");
  await page.locator(".ws-record").first().click();
  await expect(page.locator("#ws-inspector")).toContainText("Initial access");
  await page.getByRole("button", { name: "Show on DFD", exact: true }).click();
  await expect(page.getByLabel("Actor path", { exact: true })).not.toHaveValue(
    "",
  );
  await expect(page.locator("#ws-body")).toContainText("Conditional path");
  await page.setViewportSize({ width: 390, height: 844 });
  await tab(page, "Threat actors");
  await expect(page.locator(".ws-record").first()).toBeVisible();
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth + 1,
    ),
  ).toBeTruthy();
});

test("actor, boundary and domain declarations save, edit and survive restart", async ({
  page,
}) => {
  await tab(page, "Threat actors");
  await page
    .getByRole("button", { name: "Add actor profile", exact: true })
    .click();
  await field(page, "Actor profile").fill("Compromised operator");
  await field(page, "Initial access assumption").fill(
    "Valid low-privilege operator credential",
  );
  await field(page, "Entry points").selectOption({ index: 0 });
  await field(page, "Excluded capabilities").fill("No host administration");
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await page
    .getByRole("button", { name: /Compromised operator Valid low/ })
    .click();
  await page.getByRole("button", { name: "Edit record", exact: true }).click();
  await field(page, "Objectives and targeted assets").fill(
    "Unauthorized operation",
  );
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await tab(page, "Trust boundaries");
  await page
    .getByRole("button", { name: "Add trust boundary", exact: true })
    .click();
  await field(page, "Name").fill("Operator delegation");
  await field(page, "Trust dimension").selectOption("privilege");
  await field(page, "Authority before crossing").fill("Operator principal");
  await field(page, "Authority after crossing").fill("Service account");
  await field(page, "Affected flows").selectOption({ index: 0 });
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await page
    .locator(".ws-record")
    .filter({ hasText: "Operator delegation" })
    .click();
  await page.getByText("Record review decision", { exact: true }).click();
  await page
    .locator("#ws-decision")
    .getByLabel("Reviewer", { exact: true })
    .fill("Security champion");
  await page
    .locator("#ws-decision")
    .getByLabel("Rationale", { exact: true })
    .fill("Architecture declaration reviewed; deployment not verified");
  await page
    .locator("#ws-decision")
    .getByLabel("Disposition")
    .selectOption("needs-investigation");
  await page
    .getByRole("button", { name: "Save review decision", exact: true })
    .click();
  await expect(page.locator("#ws-inspector")).toContainText(
    "Security champion",
  );
  await tab(page, "Trust domains");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Name").fill("Service identity domain");
  await field(page, "Domain members").selectOption({ index: 0 });
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await tab(page, "System DFD");
  await page.getByLabel("Trust lens", { exact: true }).selectOption("identity");
  await expect(page.locator("#ws-canvas")).toContainText(
    "Service identity domain",
  );
  const restartPort = app.server.address().port;
  await app.close();
  app = await serve({
    sourceRoot: root,
    workspace: dir,
    persist: true,
    port: restartPort,
    quiet: true,
  });
  await page.goto(app.url);
  await page
    .getByRole("button", { name: "3 · System model", exact: true })
    .click();
  await tab(page, "Threat actors");
  await expect(
    page.locator(".ws-record").filter({ hasText: "Compromised operator" }),
  ).toBeVisible();
  await tab(page, "Trust boundaries");
  await page
    .locator(".ws-record")
    .filter({ hasText: "Operator delegation" })
    .click();
  await expect(page.locator("#ws-inspector")).toContainText(
    "Security champion",
  );
});

test("STRIDE, threat details, evidence and every register export remain connected", async ({
  page,
}) => {
  await page
    .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
    .click();
  await expect(page.locator("#workspace")).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: "Run or continue STRIDE analysis",
      exact: true,
    }),
  ).toBeDisabled();
  await page.getByLabel("Rows", { exact: true }).selectOption("component");
  await expect(
    page.locator(".ws-matrix th").filter({ hasText: "Elevation of privilege" }),
  ).toBeVisible();
  const data = await (
    await fetch(app.url.split("/#")[0] + "/api/model", {
      headers: { "X-Synthesis-Token": app.token },
    })
  ).json();
  const actorId = data.systemModel.actors[0].id;
  await page.getByLabel("Actor", { exact: true }).selectOption(actorId);
  await page.locator(".ws-matrix button.populated").first().click();
  const visibleIds = await page
    .locator("#ws-inspector section button[data-select]")
    .evaluateAll((nodes) => nodes.map((n) => n.dataset.select));
  expect(visibleIds.length).toBeGreaterThan(0);
  expect(
    visibleIds.every((id) =>
      data.systemModel.threats
        .find((t) => t.id === id)
        .actorIds.includes(actorId),
    ),
  ).toBeTruthy();
  await page.getByLabel("Actor", { exact: true }).selectOption("");
  await page.locator(".ws-matrix button.populated").first().click();
  await expect(page.locator("#ws-inspector")).toContainText("Linked scenarios");
  await expect(
    page.locator(".ws-checklist .ws-linked-record").first(),
  ).not.toBeVisible();
  await page.locator(".ws-checklist summary").click();
  await expect(
    page.locator(".ws-checklist .ws-linked-record small").first(),
  ).toContainText(":");
  await page
    .locator("#ws-inspector section button[data-select]")
    .first()
    .click();
  await expect(page.locator("#ws-inspector")).toContainText("Prerequisites");
  await expect(page.locator("#ws-inspector")).toContainText("Mitigation");
  await expect(page.locator("#ws-inspector .evidence").first()).toBeVisible();
  await page
    .getByRole("button", { name: "Export review package", exact: true })
    .click();
  for (const name of [
    "Complete HTML report",
    "System DFD · SVG",
    "System DFD · Mermaid",
    "Actor register · CSV",
    "Boundary register · CSV",
    "Threat register · CSV",
    "Flow register · CSV",
    "Component register · CSV",
    "Asset register · CSV",
    "Control register · CSV",
    "STRIDE matrix · CSV",
    "Complete model · JSON",
    "Source manifest",
    "Token usage · CSV",
  ]) {
    const pending = page.waitForEvent("download");
    await page
      .locator("#ws-export-panel")
      .getByRole("button", { name, exact: true })
      .click();
    const download = await pending;
    const content = await fs.readFile(await download.path(), "utf8");
    expect(content.length).toBeGreaterThan(15);
    if (name.endsWith("CSV")) expect(content).not.toMatch(/^\{/);
    expect(content).not.toMatch(/AI scenarios|AI finding/);
    // Chromium throttles more than ten downloads per second; pace this bulk-export test.
    await page.waitForTimeout(150);
  }
  await expect(page.locator("#workspace")).not.toContainText("AI scenarios");
  await tab(page, "Threat register");
  await page
    .getByLabel("Threat record type", { exact: true })
    .selectOption("scenarios");
  await expect(page.locator(".ws-record")).toHaveCount(0);
  await page
    .getByLabel("Threat record type", { exact: true })
    .selectOption("checklist");
  await expect(page.locator(".ws-record").first()).toContainText(
    "Review checklist",
  );
  await page
    .getByLabel("STRIDE category", { exact: true })
    .selectOption("Tampering");
  await expect(page.locator("#ws-body")).toContainText("records");
  await page
    .getByLabel("Threat record type", { exact: true })
    .selectOption("all");
});

test("component, external entity, asset, flow and threat editors create linked review records", async ({
  page,
}) => {
  await tab(page, "Components");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Name").fill("Integration service");
  await field(page, "Object type").selectOption("process");
  await field(page, "Source repositories").selectOption({ index: 0 });
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await expect(
    page.locator(".ws-record").filter({ hasText: "Integration service" }),
  ).toBeVisible();
  await tab(page, "Controls");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Name").fill("Operation authorization");
  await field(page, "Control purpose and limitations").fill(
    "Source enforcement requires review",
  );
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await expect(
    page.locator(".ws-record").filter({ hasText: "Operation authorization" }),
  ).toBeVisible();
  await tab(page, "External entities");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Name").fill("Integration client");
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await tab(page, "Data assets");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Name").fill("Operational settings");
  await field(page, "Sensitivity and business impact").fill(
    "Integrity sensitive",
  );
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await tab(page, "Flow register");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Operation").fill("Integration request");
  await field(page, "From component or entity").selectOption({
    label: "Integration client",
  });
  await field(page, "To component or entity").selectOption({
    label: "Integration service",
  });
  await field(page, "Protocol").fill("HTTPS");
  await field(page, "Caller identity").fill("Integration principal");
  await field(page, "Linked controls").selectOption({
    label: "Operation authorization",
  });
  await field(page, "Data assets").selectOption({
    label: "Operational settings",
  });
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await expect(
    page.locator(".ws-record").filter({ hasText: "Integration request" }),
  ).toBeVisible();
  await tab(page, "Threat register");
  await page
    .getByRole("button", { name: "Add threat scenario", exact: true })
    .click();
  await field(page, "Threat title").fill("Unauthorized integration command");
  await field(page, "Threat statement").fill(
    "An integration client may modify settings if authorization is missing.",
  );
  await field(page, "STRIDE categories").selectOption({ label: "Tampering" });
  await field(page, "Threat actors").selectOption({ index: 0 });
  await field(page, "Affected flows").selectOption({
    label: "Integration request",
  });
  await field(page, "Prerequisites").fill(
    "Credential and access to the integration endpoint",
  );
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await page
    .locator(".ws-record")
    .filter({ hasText: "Unauthorized integration command" })
    .click();
  await expect(page.locator("#ws-inspector")).toContainText(
    "Integration request",
  );
});

test("analysis controls submit the chosen budget and cancel without rescanning (mocked provider transport)", async ({
  page,
}) => {
  let running = false,
    submitted,
    cancelled = false,
    scans = 0;
  page.on("request", (r) => {
    if (r.method() === "POST" && new URL(r.url()).pathname === "/api/analyze")
      scans++;
  });
  await page.route("**/api/status", async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    await route.fulfill({
      json: {
        ...status,
        status: running ? "running" : "ready",
        mode: "review",
        inference: { label: "Configured provider", model: "test-model" },
        message: running ? "Review in progress" : "Review stopped",
      },
    });
  });
  await page.route("**/api/review", async (route) => {
    submitted = route.request().postDataJSON();
    running = true;
    await route.fulfill({ status: 202, json: { status: "running" } });
  });
  await page.route("**/api/cancel", async (route) => {
    cancelled = true;
    running = false;
    await route.fulfill({ json: { status: "ready" } });
  });
  await page.reload();
  await page
    .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
    .click();
  await page.getByLabel("Request budget", { exact: true }).fill("1");
  await page
    .getByRole("button", {
      name: "Run or continue STRIDE analysis",
      exact: true,
    })
    .click();
  await expect(
    page
      .locator("#workspace")
      .getByRole("button", { name: "Stop review", exact: true }),
  ).toBeVisible();
  expect(submitted.maxBatches).toBe(1);
  expect(typeof submitted.modelRevision).toBe("string");
  await page
    .locator("#workspace")
    .getByRole("button", { name: "Stop review", exact: true })
    .click();
  await expect(
    page.getByRole("button", {
      name: "Run or continue STRIDE analysis",
      exact: true,
    }),
  ).toBeEnabled();
  expect(cancelled).toBeTruthy();
  expect(scans).toBe(0);
});

test("token meter shows repository and shared totals, unknown usage and live updates", async ({
  page,
}) => {
  const ledger = {
    lastRunId: "run",
    legacyUnmetered: true,
    attempts: [
      {
        id: "a",
        runId: "run",
        batchId: "batch-one",
        model: "approved-opus",
        repositories: ["frontdoor"],
        status: "succeeded",
        usage: {
          inputTokens: 140,
          outputTokens: 20,
          cacheReadTokens: 30,
          cacheWriteTokens: 10,
          totalTokens: 160,
        },
      },
      {
        id: "b",
        runId: "run",
        batchId: "batch-shared",
        model: "approved-opus",
        repositories: ["frontdoor", "business"],
        status: "failed",
        retry: true,
        usage: { inputTokens: 70, outputTokens: 10, totalTokens: 80 },
      },
      {
        id: "c",
        runId: "run",
        batchId: "batch-unknown",
        model: "approved-opus",
        repositories: ["business"],
        status: "interrupted",
        usage: null,
      },
    ],
  };
  await page.route("**/api/status", async (route) => {
    const r = await route.fetch();
    await route.fulfill({
      json: {
        ...(await r.json()),
        status: "running",
        mode: "review",
        tokenUsage: usageSummary(ledger),
      },
    });
  });
  await page.reload();
  await page
    .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
    .click();
  const meter = page.locator("#ws-usage");
  await expect(meter).toContainText("240 reported tokens");
  await expect(meter).toContainText("1 with unknown totals");
  await expect(meter).toContainText("Earlier analysis has no token records");
  await meter
    .getByText("Usage by repository and shared analysis", { exact: true })
    .click();
  await expect(
    meter.getByRole("rowheader", { name: "Shared cross-repository analysis" }),
  ).toBeVisible();
  await meter
    .getByText("Recent requests (last 50; export includes all)", {
      exact: true,
    })
    .click();
  await expect(meter).toContainText("batch-unknown");
  ledger.attempts[2].usage = {
    inputTokens: 10,
    outputTokens: 5,
    totalTokens: 15,
  };
  await expect(meter).toContainText("255 reported tokens");
  await expect(
    meter.getByRole("rowheader", { name: "Shared cross-repository analysis" }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth + 1,
    ),
  ).toBeTruthy();
});

test("coverage and portable diagnostics expose real ledgers and download an inspectable ZIP", async ({
  page,
}) => {
  await page
    .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
    .click();
  await expect(page.locator("#ws-coverage")).toContainText("Analysis coverage");
  await expect(page.locator("#ws-coverage")).toContainText(
    "3 / 3 repositories read",
  );
  const pending = page.waitForEvent("download");
  await page
    .locator("#ws-coverage")
    .getByRole("button", {
      name: "Download diagnostic bundle · ZIP",
      exact: true,
    })
    .click();
  const download = await pending;
  expect(download.suggestedFilename()).toBe("synthesis-diagnostics.zip");
  const files = unzipSync(await fs.readFile(await download.path()));
  const summary = JSON.parse(strFromU8(files["summary.json"]));
  const coverage = JSON.parse(strFromU8(files["coverage.json"]));
  expect(summary.staticOnly).toBe(true);
  expect(coverage.source.sources).toHaveLength(3);
  expect(coverage.review.total).toBeGreaterThan(0);
  expect(strFromU8(files["trace.ndjson"])).toContain("graph.file-completed");
  expect(
    Object.values(files)
      .map((bytes) => strFromU8(bytes))
      .join(""),
  ).not.toContain(app.token);
});

test("pending saves finish before another editor can replace the form", async ({
  page,
}) => {
  await page.route("**/api/system", async (route) => {
    const response = await route.fetch();
    await new Promise((resolve) => setTimeout(resolve, 500));
    await route.fulfill({ response });
  });
  await tab(page, "Components");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Name").fill("Saved before navigation");
  await field(page, "Object type").selectOption("process");
  await page.getByRole("button", { name: "Save record", exact: true }).click();
  await expect(page.locator("#workspace")).toHaveAttribute("aria-busy", "true");
  await expect(page.locator("#workspace")).toHaveAttribute("inert", "");
  await tab(page, "Flow register");
  await expect(page.locator("#workspace")).not.toHaveAttribute("aria-busy");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await field(page, "Operation").fill("Next draft retained");
  await field(page, "To component or entity").selectOption({
    label: "Saved before navigation",
  });
  await expect(field(page, "Operation")).toHaveValue("Next draft retained");
});
