import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { serve } from "../../src/server.mjs";
import { sqliteSupported } from "../../src/graph-store.mjs";

test("service diagram groups calls, exposes evidence/gaps, exports the selected view and survives restart", async ({
  page,
}, testInfo) => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-dfd-browser-"),
  );
  let app;
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const files = {
    "web/Web.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    "web/Caller.cs":
      'class Caller { void Call() { client.BaseAddress = new Uri(configuration["ApiUrl"]); ' +
      Array.from(
        { length: 50 },
        (_, i) => `client.GetAsync("items/${i}");`,
      ).join("\n") +
      " client.GetAsync(destination); } }",
    "web/settings.json": '{"ApiUrl":"https://api/api/"}',
    "api/Api.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    "api/Controller.cs":
      '[Route("api/items")] public class ItemsController { [Authorize] [HttpGet("{id}")] public string Get(int id) => ""; }',
    "api/settings.json": '{"Urls":"https://api"}',
  };
  try {
    for (const [name, text] of Object.entries(files)) {
      const p = path.join(root, "repos", name);
      await fs.mkdir(path.dirname(p), { recursive: true });
      await fs.writeFile(p, text);
    }
    const options = {
      sourceRoot: path.join(root, "repos"),
      workspace: path.join(root, "state"),
      persist: true,
      port: 0,
      quiet: true,
      graphStorage: sqliteSupported() ? "sqlite" : "memory",
      initialManifest: {
        title: "Service architecture",
        profile: "test",
        repositories: [{ name: "web" }, { name: "api" }],
      },
    };
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Build source graph", exact: true })
      .click();
    await expect(page.locator("#ws-canvas svg")).toBeVisible();
    await expect(page.locator("#ws-canvas .dfd-connection")).toHaveCount(1);
    await expect(page.locator("#ws-canvas")).toContainText(
      "representing 50 flows",
    );
    await page.locator("#ws-canvas .dfd-connection").focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#ws-inspector")).toContainText(
      "Grouped connection · 50 flows",
    );
    await expect(page.locator("#ws-inspector")).toContainText("Caller.cs:");
    await page.locator("[data-bundle-member]").nth(2).click();
    await expect(page.locator("#ws-inspector")).toContainText(
      "Supporting evidence",
    );
    const width = (await page.locator("#ws-canvas svg").boundingBox()).width;
    await page.getByRole("button", { name: "Zoom in", exact: true }).click();
    expect(
      (await page.locator("#ws-canvas svg").boundingBox()).width,
    ).toBeGreaterThan(width);
    await page
      .getByRole("button", { name: "Fit diagram", exact: true })
      .click();
    await page.locator("#ws-unresolved summary").click();
    await expect(page.locator("#ws-unresolved")).toContainText(
      "http-client-not-resolved",
    );
    await page.locator("#ws-gap-search").fill("not-a-file");
    await expect(page.locator("#ws-unresolved")).toContainText(
      "0 matching gaps",
    );
    await page.locator("#ws-gap-search").fill("Caller.cs");
    await expect(page.locator("#ws-unresolved")).toContainText(
      "1 matching gaps",
    );
    await page.locator("#ws-show-unresolved").check();
    await expect(page.locator("#ws-canvas .dfd-connection")).toHaveCount(2);
    await page.locator("#ws-show-unresolved").uncheck();
    await page
      .getByLabel("Trust lens", { exact: true })
      .selectOption("network");
    await page.getByLabel("View", { exact: true }).selectOption("focus");
    const focus = await page
      .locator("#ws-focus option")
      .nth(1)
      .getAttribute("value");
    await page
      .getByLabel("Component focus", { exact: true })
      .selectOption(focus);
    const downloaded = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Export this view · Mermaid", exact: true })
      .click();
    const file = await downloaded,
      content = await fs.readFile(await file.path(), "utf8");
    expect(content).toContain("focus; network lens");
    expect(content).toContain("Flow members:");
    await page.getByLabel("View", { exact: true }).selectOption("system");
    await page
      .getByLabel("Trust lens", { exact: true })
      .selectOption("identity");
    const boundaryBadge = page.locator("#ws-canvas").getByRole("button", {
      name: "Caller-to-service identity boundary candidate",
      exact: true,
    });
    await expect(boundaryBadge.locator("text")).toHaveText(
      [/^TB-[A-F0-9]{8} \+49$/, /^pending$/],
    );
    await expect(boundaryBadge.locator("title")).toContainText(
      "Caller identity not established → Application principal (requires confirmation) · inference · pending",
    );
    await page
      .locator("#ws-canvas")
      .screenshot({ path: testInfo.outputPath("architecture-dfd.png") });
    await app.close();
    app = await serve({ ...options, initialManifest: undefined });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "3 · System model", exact: true })
      .click();
    await expect(page.locator("#ws-canvas .dfd-connection")).toHaveCount(1);
    expect(errors).toEqual([]);
  } finally {
    await page.close();
    await app?.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("internal worker and storage evidence, exports and restart", async ({
  page,
}, testInfo) => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-internal-browser-"),
  );
  let app;
  try {
    const repo = path.join(root, "repos", "service");
    await fs.mkdir(repo, { recursive: true });
    await fs.writeFile(
      path.join(repo, "server.py"),
      'from worker import Consumer\nfrom storage import Store\n@app.get("/items")\ndef items():\n    return Store()\nConsumer()\n',
    );
    await fs.writeFile(
      path.join(repo, "worker.py"),
      "import threading\nfrom storage import Store\nclass Consumer:\n    def run(self):\n        Store()\n        threading.Thread(target=self.run)\n",
    );
    await fs.writeFile(
      path.join(repo, "storage.py"),
      "import sqlite3\nclass Store:\n    def open(self):\n        return sqlite3.connect(self.path)\n",
    );
    const options = {
      sourceRoot: path.join(root, "repos"),
      workspace: path.join(root, "state"),
      persist: true,
      port: 0,
      quiet: true,
      initialManifest: {
        title: "Internal architecture",
        profile: "test",
        repositories: [{ name: "service" }],
      },
    };
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Build source graph", exact: true })
      .click();
    await expect(page.locator("#ws-canvas svg")).toBeVisible();
    await expect(page.locator("#ws-canvas")).toContainText("background worker");
    await expect(page.locator("#ws-canvas")).toContainText("SQLite");
    await page
      .locator("#ws-canvas .node")
      .filter({ hasText: "background worker" })
      .click();
    await expect(page.locator("#ws-inspector")).toContainText("worker.py");
    await page.locator("#ws-unresolved summary").click();
    await expect(page.locator("#ws-unresolved")).toContainText(
      "resource-identity-unresolved",
    );
    const download = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Export this view · Mermaid", exact: true })
      .click();
    const exported = await download,
      content = await fs.readFile(await exported.path(), "utf8");
    expect(content).toContain("SQLite");
    expect(content).toContain("background worker");
    await page
      .locator("#ws-canvas")
      .screenshot({ path: testInfo.outputPath("internal-dfd.png") });
    await app.close();
    app = await serve({ ...options, initialManifest: undefined });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "3 · System model", exact: true })
      .click();
    await expect(page.locator("#ws-canvas")).toContainText("SQLite");
    await expect(page.locator("#ws-canvas")).toContainText("background worker");
  } finally {
    await page.close();
    await app?.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});
