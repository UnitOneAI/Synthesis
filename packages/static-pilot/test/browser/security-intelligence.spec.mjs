import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { serve } from "../../src/server.mjs";
import { modelConfig } from "../../src/model-review.mjs";
import { sqliteSupported } from "../../src/graph-store.mjs";

test("unmapped security concern: consent, discovery, evidence, export and saved-graph restart", async ({
  page,
}) => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-investigation-ui-"),
  );
  const root = path.join(dir, "sources"),
    workspace = path.join(dir, "workspace");
  await fs.mkdir(path.join(root, "service"), { recursive: true });
  await fs.writeFile(
    path.join(root, "service", "app.py"),
    "def run(operator, task):\n    operator.execute(task)\n# <img src=x onerror=alert(1)>\n",
  );
  let calls = 0,
    app;
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const options = {
    sourceRoot: root,
    workspace,
    persist: true,
    graphStorage: sqliteSupported() ? "sqlite" : "memory",
    quiet: true,
    port: 0,
    modelConfig: modelConfig(
      "anthropic-gateway",
      "claude-opus-4-6-1",
      { CLAUDE_API_KEY: "test-key" },
      { baseUrl: "https://gateway.example/anthropic" },
    ),
    cweModelFetch: async (_, request) => {
      calls++;
      const packet = JSON.parse(JSON.parse(request.body).messages[0].content),
        r = packet.records[0];
      const cite = {
        recordId: r.id,
        startLine: r.startLine,
        endLine: r.startLine,
      };
      const review =
        packet.purpose === "static security candidate assessment"
          ? {
              assessment: "static-supported",
              actorKind: "authorized-agent",
              actor: "Task automation",
              initialAccess: "Operator credential",
              input: "Task argument",
              impact: "Authority exceeds task",
              trace: [
                { ...cite, role: "input", reason: "Task parameter" },
                { ...cite, role: "sink", reason: "Operation" },
              ],
              controls: [],
              counterEvidence: "Fixture lacks a task scope check",
              missingEvidence: [],
              followUp: [],
              remediation: {
                codeFix: "Constrain task scope",
                interimControl: "Scoped identity",
                residualRisk: "Other callers",
                recovery: "Review credentials",
                owner: "Unknown",
                approval: "Required",
                validation: "Static regression",
                rollback: "Prior reviewed policy",
              },
              severityChangeConditions: "Identity scope",
            }
          : {
              findings: [
                {
                  cwe: null,
                  kind: "excessive-authority",
                  targetIds: [],
                  title: "Task authority exceeds scope",
                  explanation: "Operator authority inherited",
                  preconditions: "Task can reach operation",
                  counterEvidence: "Identity configuration unknown",
                  remediation: "Use scoped identity",
                  locations: [cite],
                },
              ],
              limitations: [],
              targetReviews: packet.targets.map((t) => ({
                targetId: t.id,
                status: "needs-context",
                rationale: "Fixture scope only",
                locations: [cite],
              })),
            };
      return Response.json({
        stop_reason: "end_turn",
        usage: { input_tokens: 100, output_tokens: 30 },
        content: [{ type: "text", text: JSON.stringify(review) }],
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
    await expect(page.locator("#exploration-home")).toBeDisabled();
    await page
      .getByRole("button", { name: "Build source graph", exact: true })
      .click();
    await expect(page.locator("#workspace")).toBeVisible({ timeout: 30000 });
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await page.locator("#cwe-model-budget").fill("1");
    await page.locator("#security-run").click();
    await expect(page.locator("#message")).toContainText(
      "Enable source sharing",
    );
    expect(calls).toBe(0);
    await page.locator("#cwe-model-consent").check();
    await page.locator("#cwe-model-run").click();
    await expect(page.locator("#cwe-model-status")).toContainText(
      "1 potential weaknesses",
    );
    await expect(page.locator("#security-results")).toContainText(
      "No CWE mapping",
    );
    const finding = page.locator("#cwe-model-results > details").first();
    await finding.locator(":scope > summary").click();
    await finding.locator(".cwe-code-evidence > summary").first().click();
    await expect(finding.locator(".cwe-code-window")).toContainText(
      "operator.execute(task)",
    );
    await expect(finding.locator(".cwe-code-line.cited")).toContainText(
      "def run",
    );
    await expect(finding.locator(".cwe-code-window")).toContainText("<img");
    await expect(finding.locator(".cwe-code-window img")).toHaveCount(0);
    expect(calls).toBe(1);
    await page.locator("#security-run").click();
    await expect(page.locator("#security-status")).toContainText(
      "1 source-supported",
    );
    await page.locator("#security-results > details > summary").click();
    await expect(page.locator("#security-results")).toContainText(
      "authorized-agent",
    );
    await expect(page.locator("#security-results")).toContainText(
      "Evidence path",
    );
    const download = page.waitForEvent("download");
    await page
      .getByRole("button", {
        name: "Export security investigations",
        exact: true,
      })
      .click();
    const json = JSON.parse(
      await fs.readFile(await (await download).path(), "utf8"),
    );
    expect(json.issues[0].cwe).toBeNull();
    expect(json.issues[0].investigation.proofBasis).toBe(
      "static-analysis-unexecuted",
    );
    expect(json.coverageComplete).toBe(false);
    await page.goto("about:blank");
    await app.close();
    app = await serve(options);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    await expect(page.locator("#security-status")).toContainText(
      "1 source-supported",
    );
    await page
      .getByRole("button", { name: "6 · Exploration", exact: true })
      .click();
    await expect(page.locator("#exploration-svg [data-node]")).toHaveCount(4);
    await page.locator("#exploration-run").click();
    await expect(page.locator("#message")).toContainText(
      "Enable source sharing",
    );
    await page.locator("#exploration-kind").selectOption("finding");
    const card = page.locator("#exploration-svg [data-node]").first();
    await expect(card).toBeVisible();
    await card.click();
    await expect(page.locator("#exploration-detail")).toContainText(
      "Task authority exceeds scope",
    );
    await page.locator("#eg-open").click();
    await expect(page.locator("#exploration-svg .eg-edges path")).toHaveCount(
      1,
    );
    await page.locator("#exploration-kind").selectOption("assessment");
    await page.locator("#exploration-svg [data-node]").first().click();
    await page.locator("#eg-open").click();
    const observation = page
      .locator("#exploration-svg [data-node]")
      .filter({ hasText: "OBSERVATION" })
      .first();
    await expect(observation).toBeVisible();
    await observation.click();
    await page.locator("#eg-source").click();
    await expect(page.locator("#eg-code")).toContainText(
      "operator.execute(task)",
    );
    await page.locator("#eg-lineage").click();
    await expect(page.locator("#exploration-svg .eg-edges path")).toHaveCount(
      3,
    );
    const graphDownload = page.waitForEvent("download");
    await page.locator("#exploration-export").click();
    const graph = JSON.parse(
      await fs.readFile(await (await graphDownload).path(), "utf8"),
    );
    expect(graph.nodes.some((n) => n.kind === "observation")).toBe(true);
    expect(graph.coverageComplete).toBe(false);
    await fs.writeFile(path.join(root, "service", "app.py"), "changed");
    await page.locator("#exploration-fit").click();
    await page
      .locator("#exploration-svg [data-node]")
      .filter({ hasText: "OBSERVATION" })
      .first()
      .click();
    await page.locator("#eg-source").click();
    await expect(page.locator("#message")).toContainText("source-");
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    const reopened = page.locator("#cwe-model-results > details").first();
    await reopened.locator(":scope > summary").click();
    await reopened.locator(".cwe-code-evidence > summary").first().click();
    await expect(reopened.locator(".cwe-code-body")).toContainText(
      "Source has changed",
    );
    await expect(reopened.locator(".cwe-code-window")).toHaveCount(0);
    expect(calls).toBe(2);
    expect(errors).toEqual([]);
  } finally {
    await page.goto("about:blank");
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
