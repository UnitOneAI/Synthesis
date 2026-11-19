import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  providerUsage,
  usageSummary,
  usageCsv,
  mergeUsage,
  interruptUsage,
} from "../src/token-usage.mjs";
import { analyze } from "../src/engine.mjs";
import { enrichGraphModel, reviewPlan } from "../src/graph-review.mjs";
import { modelConfig, enrichModel } from "../src/model-review.mjs";
import { workspaceStore } from "../src/workspace-store.mjs";
import { systemReport } from "../src/system-exports.mjs";
import { sha } from "../src/sources.mjs";
const root = fileURLToPath(
  new URL("../fixtures/repositories", import.meta.url),
);
const manifest = {
  profile: "test",
  repositories: [{ name: "frontdoor" }, { name: "business" }],
};
const config = modelConfig("anthropic-gateway", "approved-opus-deployment", {
  CLAUDE_API_KEY: "test-key",
  SYNTHESIS_LLM_BASE_URL: "https://gateway.example/anthropic",
});
const usage = {
  input_tokens: 100,
  output_tokens: 20,
  cache_read_input_tokens: 30,
  cache_creation_input_tokens: 10,
};
const response = (
  text = JSON.stringify({
    summary: "Review",
    threats: [],
    connections: [],
    questions: [],
  }),
) =>
  Response.json({
    usage,
    stop_reason: "end_turn",
    content: [{ type: "text", text }],
  });

test("provider usage counts cache subsets once and preserves unknown counts", () => {
  assert.deepEqual(providerUsage({ usage }, "anthropic-gateway"), {
    inputTokens: 140,
    outputTokens: 20,
    cacheReadTokens: 30,
    cacheWriteTokens: 10,
    totalTokens: 160,
  });
  assert.equal(providerUsage({}, "anthropic").totalTokens, null);
  assert.equal(
    providerUsage(
      { usage: { input_tokens: -1, output_tokens: 5 } },
      "anthropic",
    ).totalTokens,
    null,
  );
  assert.equal(
    providerUsage(
      { usage: { input_tokens: 100, output_tokens: 0 } },
      "anthropic",
    ).totalTokens,
    100,
  );
  assert.deepEqual(
    providerUsage(
      {
        usageMetadata: {
          promptTokenCount: 100,
          candidatesTokenCount: 20,
          thoughtsTokenCount: 5,
          cachedContentTokenCount: 40,
          totalTokenCount: 125,
        },
      },
      "gemini",
    ),
    {
      inputTokens: 100,
      outputTokens: 25,
      cacheReadTokens: 40,
      cacheWriteTokens: null,
      totalTokens: 125,
    },
  );
});

test("rejected output, retries, cache reuse, shared requests and restart retain exact usage", async () => {
  let m = await analyze(manifest, { sourceRoot: root });
  let calls = 0;
  await enrichGraphModel(
    m,
    config,
    new Map(),
    async () => {
      calls++;
      return response("invalid JSON");
    },
    { maxBatches: 1 },
  );
  assert.equal(m.aiReview.status, "failed");
  assert.equal(usageSummary(m.usageLedger).totalTokens, 160);
  assert.equal(m.usageLedger.attempts[0].status, "failed");
  let checkpointSeen = false;
  const preparedPackets = new Set();
  await enrichGraphModel(
    m,
    config,
    new Map(),
    async (_, options) => {
      assert.ok(
        preparedPackets.has(sha(JSON.parse(options.body).messages[0].content)),
        "packet intent must be checkpointed before dispatch",
      );
      calls++;
      return response();
    },
    {
      maxBatches: 100,
      checkpoint: (review, ledger) => {
        for (const batch of review.batches)
          if (batch.status === "queued") preparedPackets.add(batch.packetHash);
        if (ledger.attempts.some((a) => a.status === "in-flight"))
          checkpointSeen = true;
      },
    },
  );
  const planned = reviewPlan(m).batches.length;
  assert.ok(
    checkpointSeen,
    "dispatched attempts must be checkpointed in flight",
  );
  assert.equal(calls, planned + 1);
  let summary = usageSummary(m.usageLedger);
  assert.equal(summary.totalTokens, calls * 160);
  assert.equal(summary.retries, 1);
  assert.equal(summary.failedRequests, 1);
  assert.equal(summary.unknownRequests, 0);
  assert.ok(summary.groups.some((g) => g.shared));
  assert.equal(
    summary.groups.reduce((n, g) => n + g.totalTokens, 0),
    summary.totalTokens,
  );
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "usage-ledger-"));
  let store = await workspaceStore(root, dir);
  try {
    await store.save({ manifest, model: m });
    await store.close();
    store = await workspaceStore(root, dir);
    m = (await store.load()).model;
    await enrichGraphModel(
      m,
      config,
      new Map(),
      async () => {
        throw Error("cached batches must not call provider");
      },
      { maxBatches: 1 },
    );
    summary = usageSummary(m.usageLedger);
    assert.equal(summary.totalTokens, calls * 160);
    assert.equal(summary.lastRun.requests, 0);
    assert.equal(summary.lastRun.totalTokens, 0);
    assert.ok(systemReport(m).includes("Token usage"));
    const csv = usageCsv(m.usageLedger);
    assert.ok(csv.includes('"140","20","30","10","160"'));
    assert.ok(!csv.includes("test-key"));
    assert.equal(
      mergeUsage(m.usageLedger, m.usageLedger).attempts.length,
      calls,
    );
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("timeouts and interrupted requests remain unknown; earlier unmetered history is explicit", async () => {
  const m = await analyze(manifest, { sourceRoot: root });
  m.aiReview = { status: "partial", batches: [] };
  await enrichGraphModel(
    m,
    config,
    new Map(),
    async () => {
      throw Error("network");
    },
    { maxBatches: 1 },
  );
  const s = usageSummary(m.usageLedger);
  assert.equal(s.unknownRequests, 1);
  assert.equal(s.legacyUnmetered, true);
  assert.equal(m.usageLedger.attempts[0].usage, null);
  m.usageLedger.attempts[0].status = "in-flight";
  interruptUsage(m.usageLedger);
  assert.equal(m.usageLedger.attempts[0].status, "interrupted");
  assert.ok(usageCsv(m.usageLedger).includes('"unknown"'));
  assert.deepEqual(
    mergeUsage(m.usageLedger, undefined).attempts,
    m.usageLedger.attempts,
  );
});

test("single-request path records provider tokens before truncated output is rejected", async () => {
  const m = await analyze(manifest, { sourceRoot: root });
  await enrichModel(m, config, new Map(), async () =>
    Response.json({ usage, stop_reason: "max_tokens", content: [] }),
  );
  assert.equal(m.aiReview.status, "failed");
  assert.equal(usageSummary(m.usageLedger).totalTokens, 160);
  assert.equal(m.usageLedger.attempts[0].status, "failed");
});
