import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { reportFixture } from "../report-fixture.mjs";
import { workspaceStore } from "../../src/workspace-store.mjs";
import { serve } from "../../src/server.mjs";

test("CWE and threat model PDF previews show verified evidence and printable registers", async ({
  page,
  context,
}, testInfo) => {
  const f = await reportFixture();
  let app;
  const errors = [];
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
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    const popupPromise = context.waitForEvent("page");
    await page
      .getByRole("button", { name: "CWE evidence · PDF", exact: true })
      .click();
    const report = await popupPromise;
    report.on("pageerror", (error) => errors.push(error.message));
    await expect(
      report.getByRole("button", { name: "Print / Save as PDF", exact: true }),
    ).toBeEnabled();
    expect(report.url()).not.toContain(app.token);
    await expect(report.locator(".code-line.cited").first()).toContainText(
      "verify=False",
    );
    await expect(report.locator("#report-content")).toContainText(
      "1 / 12 packets completed, 11 pending",
    );
    await expect(report.locator("#report-content")).toContainText(
      "Code evidence is unavailable",
    );
    expect(
      await report.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await report.evaluate(() => {
      window.print = () => {
        window.printInvoked = true;
      };
    });
    await report
      .getByRole("button", { name: "Print / Save as PDF", exact: true })
      .click();
    expect(await report.evaluate(() => window.printInvoked)).toBe(true);
    const pdf = await report.pdf({
      path: testInfo.outputPath("cwe-evidence.pdf"),
      printBackground: true,
      preferCSSPageSize: true,
    });
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    await report.screenshot({
      path: testInfo.outputPath("cwe-evidence.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "3 · System model", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Export review package", exact: true })
      .click();
    const threatPromise = context.waitForEvent("page");
    await page
      .getByRole("button", { name: "Threat model · PDF", exact: true })
      .click();
    const threat = await threatPromise;
    await expect(
      threat.getByRole("button", { name: "Print / Save as PDF", exact: true }),
    ).toBeEnabled();
    for (const name of [
      "Overall system DFD",
      "STRIDE matrix",
      "Threat register",
      "Supporting evidence",
    ])
      await expect(
        threat.getByRole("heading", { name, exact: true }),
      ).toBeVisible();
    await threat.pdf({
      path: testInfo.outputPath("threat-model.pdf"),
      printBackground: true,
      preferCSSPageSize: true,
    });
    await report.close();
    await threat.close();
    expect(errors).toEqual([]);
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});
