import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { serve } from "../../src/server.mjs";

test("saved real-source security output is inspectable and exportable without another model call", async ({
  page,
}) => {
  const workspace = process.env.SYNTHESIS_VALIDATION_WORKSPACE;
  const sourceRoot = process.env.SYNTHESIS_VALIDATION_SOURCE_ROOT;
  test.skip(
    !workspace || !sourceRoot,
    "Set an existing validation workspace and source root",
  );
  test.setTimeout(120000);
  const output =
    process.env.SYNTHESIS_VALIDATION_OUTPUT ||
    path.resolve("output/playwright");
  await fs.mkdir(output, { recursive: true });
  const snapshot = JSON.parse(
    await fs.readFile(path.join(workspace, "snapshot.json"), "utf8"),
  );
  const expected =
    (snapshot.data.model.cweReview?.findings?.length || 0) +
    (snapshot.data.model.cweModelReview?.findings?.length || 0);
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const app = await serve({
    sourceRoot,
    workspace,
    persist: true,
    graphStorage: "sqlite",
    port: 0,
    quiet: true,
  });
  try {
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await expect(page.locator("#graph")).toBeVisible();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await expect(page.locator("#security-status")).toContainText(
      `${expected} candidates`,
    );
    await expect(page.locator("#security-run")).toBeDisabled();
    if (
      snapshot.data.model.cweModelReview?.findings?.some((f) =>
        f.locations.some((l) => l.sourceScope === "production-candidate"),
      )
    ) {
      await page.locator("#security-filter").fill("production-candidate");
      await expect(
        page.locator("#security-results summary").first(),
      ).toBeVisible();
    }
    await page
      .getByRole("heading", { name: "Security investigations", exact: true })
      .evaluate((el) => el.scrollIntoView({ block: "start" }));
    await page.screenshot({
      path: path.join(output, "security-investigations.png"),
    });
    const unmapped = page
      .locator("#security-results summary")
      .filter({ hasText: "No CWE mapping" })
      .first();
    const first = (await unmapped.count())
      ? unmapped
      : page.locator("#security-results summary").first();
    if (await first.count()) {
      await first.click();
      await first.evaluate((el) => el.scrollIntoView({ block: "start" }));
      await page.screenshot({
        path: path.join(output, "security-evidence.png"),
      });
    }
    const downloading = page.waitForEvent("download");
    await page
      .getByRole("button", {
        name: "Export security investigations",
        exact: true,
      })
      .click();
    const download = await downloading;
    await download.saveAs(
      path.join(output, "security-investigations-ui-export.json"),
    );
    const data = JSON.parse(
      await fs.readFile(
        path.join(output, "security-investigations-ui-export.json"),
        "utf8",
      ),
    );
    expect(data.issues).toHaveLength(expected);
    expect(data.staticOnly).toBe(true);
    expect(data.coverageComplete).toBe(false);
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page
      .getByRole("button", { name: "6 · Exploration", exact: true })
      .click();
    await expect(page.locator("#exploration-svg [data-node]")).toHaveCount(4);
    await page.locator("#exploration-kind").selectOption("assessment");
    await expect(
      page.locator("#exploration-svg [data-node]").first(),
    ).toBeVisible();
    await page
      .locator("#exploration-svg [data-node]")
      .filter({ hasText: "Assess CWE" })
      .first()
      .click();
    await page.locator("#eg-lineage").click();
    await expect(
      page.locator("#exploration-svg .eg-edges path").first(),
    ).toBeAttached();
    await page.locator("#exploration-fit").click();
    await page
      .locator("#exploration-svg [data-node]")
      .filter({ hasText: "Assess CWE" })
      .first()
      .click();
    await page.locator("#exploration").screenshot({
      path: path.join(output, "static-exploration-lineage.png"),
    });
    const exportGraph = page.waitForEvent("download");
    await page.locator("#exploration-export").click();
    await (
      await exportGraph
    ).saveAs(path.join(output, "static-exploration-lineage.json"));
    expect(errors).toEqual([]);
  } finally {
    await page.goto("about:blank");
    await app.close();
  }
});
