import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { reportFixture } from "../report-fixture.mjs";
import { workspaceStore } from "../../src/workspace-store.mjs";
import { modelConfig } from "../../src/model-review.mjs";

const config = modelConfig(
  "anthropic-gateway",
  "claude-opus-4-6-1",
  { CLAUDE_API_KEY: "test-only-key" },
  { baseUrl: "https://gateway.example/anthropic" },
);
test("early STRIDE worker failure preserves stale scenarios and exposes latest failure with historical coverage", async ({
  page,
}) => {
  const f = await reportFixture();
  let app;
  try {
    f.model.cweReview.limitations = [];
    f.model.cweReview.findings.forEach((finding) => {
      finding.interfaceIds = [];
      finding.evidenceIds = [];
    });
    const iid = f.model.interfaces[0].id,
      eid = f.model.evidence[0].id;
    f.model.aiReview = {
      status: "stale",
      promptHash: "old-prompt",
      guidance: { hash: "old-guidance" },
      basedOnRevision: f.model.modelRevision,
      runKey: "old-run",
      error: "Analysis methodology changed; prior results remain historical.",
      threats: [
        {
          id: "historical-threat-001",
          title: "Historical caller identity scenario",
          category: "Spoofing",
          actor: "Untrusted caller",
          startingAccess: "Network access",
          asset: "Application identity",
          scenario: "Conditional identity misuse requires source review.",
          prerequisites: "Missing identity enforcement",
          controls: "Review current controls",
          mitigation: "Verify identity enforcement",
          interfaceIds: [iid],
          evidenceIds: [eid],
        },
      ],
      batches: [{ id: "old-packet", status: "completed", interfaceIds: [iid] }],
      coverage: {
        completedBatches: 1,
        totalBatches: 2,
        pendingBatches: 1,
        failedBatches: 0,
        reviewedInterfaceIds: [iid],
        repositories: [],
      },
      questions: [],
      connections: [],
    };
    const store = await workspaceStore(f.root, f.workspace);
    await store.save({ manifest: f.manifest, model: f.model });
    await store.close();
    const preload = path.join(f.dir, "fail-review-worker.mjs");
    const boot = path.join(f.dir, "server.mjs");
    await fs.writeFile(
      preload,
      "import {isMainThread, workerData} from 'node:worker_threads'; if (!isMainThread && workerData?.mode === 'review') throw Error('synthetic early failure PRIVATE_SENTINEL');\n",
    );
    await fs.writeFile(
      boot,
      `import {serve} from ${JSON.stringify(new URL("../../src/server.mjs", import.meta.url).href)}; const app = await serve(${JSON.stringify({ sourceRoot: f.root, workspace: f.workspace, persist: true, port: 0, quiet: true, modelConfig: config })}); process.stdout.write(JSON.stringify({url: app.url, token: app.token})+"\\n"); process.on("SIGTERM", async () => {await app.close(); process.exit(0);});`,
    );
    const child = spawn(
      process.execPath,
      ["--import", pathToFileURL(preload).href, boot],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const exited = new Promise((resolve) => child.once("exit", resolve));
    app = {
      close: async () => {
        if (child.exitCode === null) child.kill();
        await exited;
      },
    };
    const info = await new Promise((resolve, reject) => {
      let output = "";
      child.once("error", reject);
      child.once("exit", () =>
        reject(Error("Test server exited before startup")),
      );
      child.stdout.on("data", (chunk) => {
        output += chunk;
        if (output.includes("\n")) resolve(JSON.parse(output.split("\n")[0]));
      });
    });
    Object.assign(app, info);
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
      .click();
    await expect(page.locator(".ws-stale-review")).toContainText(
      "Analysis guidance changed; Review prompt changed",
    );
    await expect(page.locator(".ws-stale-review")).toContainText(
      "1 prior threat scenario and 1 previously completed packet",
    );
    await expect(page.locator(".ws-stale-review")).toContainText(
      "Current valid completed packets: 0",
    );
    await page
      .getByRole("button", {
        name: "Run or continue STRIDE analysis",
        exact: true,
      })
      .click();
    await expect(page.locator(".ws-last-review-failure")).toContainText(
      "Latest STRIDE attempt failed before the first review checkpoint",
    );
    await expect(page.locator(".ws-last-review-failure")).toContainText(
      "worker-resource",
    );
    await expect(page.locator(".ws-stale-review")).toContainText(
      "Current valid completed packets: 0",
    );
    const base = app.url.split("/#")[0],
      headers = { "x-synthesis-token": app.token };
    const result = await (
      await page.request.get(base + "/api/model", { headers })
    ).json();
    expect(result.aiReview.status).toBe("stale");
    expect(result.aiReview.threats.map((t) => t.id)).toEqual([
      "historical-threat-001",
    ]);
    expect(result.aiReview.lastRunFailure.stage).toBe(
      "before-review-checkpoint",
    );
    expect(result.aiReview.staleReason.causes).toEqual([
      "guidance-changed",
      "prompt-changed",
    ]);
    expect(
      result.systemModel.threats.find((t) => t.id === "historical-threat-001")
        .reviewState,
    ).toBe("stale");
    const exported = await (
      await page.request.get(base + "/api/export?format=errors", { headers })
    ).json();
    expect(exported.stride.failure.code).toBe("worker-resource");
    expect(exported.stride.lastRunFailure.stage).toBe(
      "before-review-checkpoint",
    );
    expect(exported.stride.staleReason.code).toBe("stale-analysis");
    expect(JSON.stringify(exported)).not.toContain("PRIVATE_SENTINEL");
    expect(JSON.stringify(exported)).not.toContain(
      "Historical caller identity scenario",
    );
    expect(JSON.stringify(exported)).not.toContain("test-only-key");
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});
