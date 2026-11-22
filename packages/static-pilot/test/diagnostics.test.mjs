import { GRAPH_LIMITS } from "../src/source-graph.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { unzipSync, strFromU8 } from "fflate";
import { analyze, extract } from "../src/engine.mjs";
import { localSource, LIMITS, sha } from "../src/sources.mjs";
import { reviewPlan, enrichGraphModel } from "../src/graph-review.mjs";
import { coverageStatus } from "../src/coverage-plan.mjs";
import {
  traceStore,
  diagnosticBundle,
  readTraces,
  diagnosticCoverage,
  failureDetail,
  errorReport,
} from "../src/diagnostics.mjs";
import { modelConfig } from "../src/model-review.mjs";
import { serve } from "../src/server.mjs";
const root = fileURLToPath(
  new URL("../fixtures/repositories/", import.meta.url),
);
const manifest = {
  profile: "diagnostic-test",
  repositories: [{ name: "frontdoor" }, { name: "business" }],
};
const config = modelConfig(
  "anthropic-gateway",
  "fixture-deployment",
  { CLAUDE_API_KEY: "private-key-sentinel" },
  { baseUrl: "https://gateway.example/anthropic" },
);
const fixture = () => analyze(manifest, { sourceRoot: root });
test("compact error report distinguishes budget stops, bounds history and excludes source and secrets", async () => {
  const model = await fixture();
  model.aiReview = {
    status: "partial",
    stopReason: "request-budget",
    error: "Review budget reached",
    batches: [{ id: "done", status: "completed" }],
    coverage: {
      completedBatches: 2,
      totalBatches: 444,
      pendingBatches: 442,
      failedBatches: 0,
    },
  };
  model.cweReview = {
    status: "partial",
    repositories: [
      {
        name: "repo",
        errors: [
          {
            type: "PartialParsing",
            code: 3,
            path: "file.cs",
            message: "RAW_SOURCE_SENTINEL",
          },
        ],
        skipped: [],
      },
    ],
  };
  model.usageLedger = {
    attempts: Array.from({ length: 150 }, (_, i) => ({
      id: String(i),
      status: "failed",
      prompt: "RAW_SOURCE_SENTINEL",
    })),
  };
  const report = await errorReport({
    model,
    job: { message: "private-key-sentinel" },
    secrets: ["private-key-sentinel"],
    traces: {
      events: JSON.stringify({
        event: "model.request-failed",
        timestamp: "2026-11-15",
        failure: { code: "response-format" },
        sourceText: "RAW_SOURCE_SENTINEL",
      }),
    },
  });
  assert.equal(report.stride.failure, null);
  assert.equal(report.stride.coverage.pendingBatches, 442);
  assert.equal(report.requestOutcomes.items.length, 100);
  assert.equal(report.requestOutcomes.omitted, 50);
  assert.equal(
    report.semgrep.repositories.items[0].errors[0].type,
    "PartialParsing",
  );
  assert.equal(report.failureEvents.items[0].failure.code, "response-format");
  assert.doesNotMatch(
    JSON.stringify(report),
    /RAW_SOURCE_SENTINEL|private-key-sentinel/,
  );
  assert.ok(Buffer.byteLength(JSON.stringify(report)) < 1024 * 1024);
});
const reply = (
  text = JSON.stringify({
    summary:
      "Source-bearing response prose must not be exported in diagnostics",
    threats: [],
    connections: [],
    questions: [],
  }),
) =>
  Response.json(
    {
      stop_reason: "end_turn",
      usage: { input_tokens: 100, output_tokens: 20 },
      content: [{ type: "text", text }],
    },
    { headers: { "request-id": "req-fixture-123" } },
  );
const decode = (bytes) =>
  Object.fromEntries(
    Object.entries(unzipSync(bytes)).map(([k, v]) => [k, strFromU8(v)]),
  );

test("recursive planner follows candidate calls through cycles, bridges partitions and never creates runtime flows", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-recursive-"));
  try {
    await fs.mkdir(path.join(dir, "api"));
    await fs.writeFile(
      path.join(dir, "api", "routes.js"),
      'function entry(){ fetch("/entry"); step(); } function step(){ exit(); entry(); } function exit(){ fetch("/exit"); }',
    );
    const m = await analyze(
      { profile: "cycle", repositories: [{ name: "api" }] },
      { sourceRoot: dir },
    );
    const p = reviewPlan(m);
    const paths = p.obligations.filter((o) => o.kind === "candidate-call-path");
    assert.ok(paths.length >= 1);
    assert.ok(paths.some((o) => o.graphNodeIds.length >= 5));
    assert.ok(paths.every((o) => o.batchIds.length));
    assert.equal(m.flows.length, 0);
    const onlyLocal = p.batches
      .filter((b) => b.phase === "repository")
      .map((b) => ({ ...b, status: "completed" }));
    const c = coverageStatus(p, onlyLocal);
    assert.ok(c.byKind.interface.reviewed > 0);
    assert.equal(c.byKind["candidate-call-path"].reviewed, 0);
    for (const b of p.batches)
      assert.ok(Buffer.byteLength(JSON.stringify(b.packet)) <= 96 * 1024);
    const requestPaths = p.batches.flatMap((b) => b.packet.graphPaths || []);
    assert.ok(requestPaths.some((p) => p.nodes.some((n) => n.name === "step")));
    const before = JSON.stringify(p);
    m.aiReview = {
      threats: [{ actor: "Invented external actor" }],
      status: "partial",
    };
    assert.equal(
      JSON.stringify(reviewPlan(m)),
      before,
      "model proposals cannot create new traversal inputs",
    );
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("streamed local collection crosses aggregate limits while retaining per-file exclusions and stable ownership", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-stream-"));
  const prior = { ...LIMITS };
  try {
    await fs.mkdir(path.join(dir, "repo"));
    await fs.writeFile(
      path.join(dir, "repo", "package.json"),
      '{"name":"demo"}',
    );
    for (let i = 0; i < 6; i++)
      await fs.writeFile(
        path.join(dir, "repo", `a${i}.js`),
        'function run(){ fetch("/api"); }',
      );
    LIMITS.files = 2;
    LIMITS.totalBytes = 20;
    const result = await analyze(
      { profile: "stream", repositories: [{ name: "repo" }] },
      { sourceRoot: dir },
    );
    assert.equal(result.sources[0].coverage.inspected, 7);
    assert.equal(result.sources[0].coverage.truncated, false);
    assert.equal(result.sources[0].coverage.mode, "streamed-local");
    assert.equal(result.interfaces.length, 6);
    assert.ok(result.components.every((c) => c.sourceRoot === "package.json"));
    assert.equal(
      new Set(result.sourceGraph.nodes.map((n) => n.id)).size,
      result.sourceGraph.nodes.length,
    );
    const old = await localSource({ name: "repo" }, dir);
    assert.equal(old.coverage.truncated, true);
    const text = Array.from(
      { length: 2505 },
      (_, i) => `fetch("/item/${i}");`,
    ).join("\n");
    const extracted = extract({ name: "repo" }, [
      { path: "large.js", text, hash: sha(text) },
    ]);
    assert.equal(extracted.interfaces.length, 2505);
    assert.ok(!extracted.diagnostics.some((d) => d.kind === "candidate-limit"));
  } finally {
    Object.assign(LIMITS, prior);
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("12 repositories retain more than the previous portfolio candidate cutoff", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-portfolio-"));
  try {
    const repositories = [];
    for (let r = 0; r < 12; r++) {
      const name = `service-${r}`;
      repositories.push({ name });
      await fs.mkdir(path.join(dir, name));
      await fs.writeFile(
        path.join(dir, name, "calls.js"),
        Array.from(
          { length: 850 },
          (_, n) => `fetch("/service-${r}/operation-${n}");`,
        ).join("\n"),
      );
    }
    const m = await analyze(
      { profile: "twelve", repositories },
      { sourceRoot: dir },
    );
    assert.equal(m.interfaces.length, 10200);
    assert.equal(m.sources.filter((s) => s.status === "read").length, 12);
    assert.ok(!m.diagnostics.some((d) => d.kind === "candidate-limit"));
    assert.equal(m.sourceGraph.coverage.limited, 0);
    assert.ok(m.interfaces.some((i) => i.repository === "service-11"));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("durable traces preserve provider correlation, invalid-output usage and cache reuse without prompts or secrets", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-trace-"));
  const trace = await traceStore({
    directory: dir,
    sourceRoot: root,
    secrets: [config.apiKey],
  });
  try {
    const m = await fixture();
    let calls = 0;
    await enrichGraphModel(
      m,
      config,
      new Map([[m.evidence[0].id, { text: "RAW-SOURCE-SENTINEL" }]]),
      async () => {
        calls++;
        return reply("RESPONSE-PROSE-SENTINEL");
      },
      { maxBatches: 1, trace: trace.record },
    );
    assert.equal(m.aiReview.status, "failed");
    assert.equal(m.usageLedger.attempts[0].usage.totalTokens, 120);
    await enrichGraphModel(
      m,
      config,
      new Map(),
      async () => {
        calls++;
        return reply();
      },
      { maxBatches: 100, trace: trace.record },
    );
    const before = calls;
    await enrichGraphModel(
      m,
      config,
      new Map(),
      async () => {
        calls++;
        return reply();
      },
      { maxBatches: 100, trace: trace.record },
    );
    assert.equal(calls, before);
    await trace.record("privacy.probe", {
      apiKey: config.apiKey,
      prompt: "RAW-PROMPT-SENTINEL",
      harmless: config.apiKey,
      endpoint: config.baseUrl,
    });
    m.cweModelReview = {
      basedOnRevision: m.modelRevision,
      findings: [],
      repositories: [],
      batches: [
        {
          id: "cwe-test",
          status: "completed",
          repositories: [],
          limitations: ["RESPONSE-PROSE-SENTINEL"],
          targetReviews: [
            {
              targetId: "server-19",
              status: "needs-context",
              rationale: "RESPONSE-PROSE-SENTINEL",
              locations: [],
            },
          ],
        },
      ],
    };
    const exported = await trace.export();
    const bytes = await diagnosticBundle({
      model: m,
      traces: exported,
      config,
      secrets: [config.apiKey],
      roots: [root],
    });
    const files = decode(bytes),
      rawFiles = unzipSync(bytes);
    const all = Object.values(files).join("\n");
    for (const secret of [
      config.apiKey,
      config.baseUrl,
      "RAW-SOURCE-SENTINEL",
      "RAW-PROMPT-SENTINEL",
      "RESPONSE-PROSE-SENTINEL",
      "Source-bearing response prose must not be exported",
    ])
      assert.ok(!all.includes(secret), secret);
    const events = files["trace.ndjson"].trim().split("\n").map(JSON.parse);
    assert.ok(
      events.some(
        (e) =>
          e.event === "model.response-received" &&
          e.requestIds["request-id"] === "req-fixture-123",
      ),
    );
    assert.ok(
      events.some(
        (e) =>
          e.event === "model.request-failed" &&
          e.failure.code === "response-format",
      ),
    );
    assert.ok(events.some((e) => e.event === "review.cache-reused"));
    assert.ok(
      events.every((e) => e.sequence > 0 && e.sessionId && e.timestamp),
    );
    const manifest = JSON.parse(files["manifest.json"]);
    for (const file of manifest.files)
      assert.equal(sha(rawFiles[file.name]), file.sha256);
    m.aiReview.status = "stale";
    assert.equal(diagnosticCoverage(m).review.reviewed, 0);
    assert.equal(diagnosticCoverage(m).review.stale, true);
  } finally {
    await trace.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("trace export survives missing snapshots and partial lines and rejects output in source", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-trace-recovery-"),
  );
  try {
    await fs.writeFile(
      path.join(dir, "aaaaaaaa-0000.ndjson"),
      '{"event":"started"}\n{"unfinished":',
    );
    const traces = await readTraces(dir);
    assert.equal(traces.files[0].invalidLines, 1);
    const files = decode(await diagnosticBundle({ traces }));
    assert.equal(
      JSON.parse(files["source-graph.json"]).status,
      "no-completed-graph",
    );
    assert.equal(JSON.parse(files["summary.json"]).reviewStatus, "not-started");
    await assert.rejects(
      traceStore({
        directory: path.join(root, "should-not-exist"),
        sourceRoot: root,
      }),
      /outside/,
    );
    assert.equal(
      failureDetail("Provider returned HTTP 403; private body").httpStatus,
      403,
    );
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("diagnostic download works before first scan, requires local access token and remains usable after restart", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-diagnostic-server-"),
  );
  let app;
  try {
    app = await serve({
      sourceRoot: root,
      workspace: dir,
      persist: true,
      port: 0,
      quiet: true,
    });
    const origin = new URL(app.url).origin;
    assert.equal(
      (await fetch(origin + "/api/export?format=errors")).status,
      401,
    );
    const small = await fetch(origin + "/api/export?format=errors", {
      headers: { "X-Synthesis-Token": app.token },
    });
    assert.equal(small.status, 200);
    assert.match(
      small.headers.get("content-disposition"),
      /synthesis-errors.json/,
    );
    assert.equal((await small.json()).sourceDiagnostics.total, 0);
    assert.equal(
      (await fetch(origin + "/api/export?format=diagnostics")).status,
      401,
    );
    const response = await fetch(origin + "/api/export?format=diagnostics", {
      headers: { "X-Synthesis-Token": app.token },
    });
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /zip/);
    const files = decode(new Uint8Array(await response.arrayBuffer()));
    assert.ok(files["trace.ndjson"].includes("session.started"));
    assert.ok(!Object.values(files).join("").includes(app.token));
    await app.close();
    app = null;
    assert.ok(
      (await readTraces(path.join(dir, "traces"))).events.includes(
        "session.closed",
      ),
    );
  } finally {
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("repeated invalid responses recursively refine pending scopes and retain successful children", async () => {
  const m = await fixture();
  const first = reviewPlan(m).batches[0];
  assert.ok(first.packet.records.length > 2);
  for (let n = 0; n < 2; n++)
    await enrichGraphModel(
      m,
      config,
      new Map(),
      async () => reply("not JSON"),
      { maxBatches: 1 },
    );
  const p = reviewPlan(m);
  assert.ok(p.refinements.some((r) => r.parentId === first.id));
  assert.ok(!p.batches.some((b) => b.id === first.id));
  assert.ok(
    p.batches
      .filter((b) => b.parentId === first.id)
      .every((b) => b.packet.records.length < first.packet.records.length),
  );
  await enrichGraphModel(m, config, new Map(), async () => reply(), {
    maxBatches: 100,
  });
  assert.equal(m.aiReview.coverage.obligations.blocked, 0);
  assert.equal(m.aiReview.status, "completed-needs-review");
  assert.ok(
    m.usageLedger.attempts.some((a) => a.parentBatchId === first.id && a.retry),
  );
  const snapshot = structuredClone(m),
    planHash = sha(JSON.stringify(reviewPlan(m)));
  let calls = 0;
  await enrichGraphModel(
    snapshot,
    config,
    new Map(),
    async () => {
      calls++;
      return reply();
    },
    { maxBatches: 100 },
  );
  assert.equal(calls, 0);
  assert.equal(sha(JSON.stringify(reviewPlan(snapshot))), planHash);
});

test("combined scan saves its static graph before inference and checkpoints usage before validating output", async () => {
  let staticSaved = false,
    usageSaved = false,
    calls = 0;
  const model = await analyze(manifest, {
    sourceRoot: root,
    modelConfig: config,
    reviewBatches: 1,
    onStaticModel: async (m) => {
      assert.ok(m.sourceGraph.fingerprint);
      assert.ok(m.interfaces.length);
      staticSaved = true;
    },
    checkpoint: async (_review, ledger) => {
      if (ledger.attempts.some((a) => a.usage?.totalTokens === 120))
        usageSaved = true;
    },
    modelFetch: async () => {
      assert.ok(staticSaved);
      calls++;
      return reply("invalid output");
    },
  });
  assert.equal(calls, 1);
  assert.equal(model.aiReview.status, "failed");
  assert.ok(usageSaved);
  assert.equal(model.usageLedger.attempts[0].usage.totalTokens, 120);
  let blockedCalls = 0;
  await assert.rejects(
    enrichGraphModel(
      await fixture(),
      config,
      new Map(),
      async () => {
        blockedCalls++;
        return reply();
      },
      {
        maxBatches: 1,
        trace: async () => {
          throw Error("Trace output could not be written");
        },
      },
    ),
    /Trace output/,
  );
  assert.equal(blockedCalls, 0);
});

test("graph resource limits enumerate every skipped file and leave missing-interface coverage gaps", async () => {
  const prior = GRAPH_LIMITS.nodes;
  try {
    GRAPH_LIMITS.nodes = 3;
    const m = await fixture();
    const inspected = m.sources.reduce((n, s) => n + s.coverage.inspected, 0);
    assert.equal(m.sourceGraph.files.length, inspected);
    assert.ok(m.sourceGraph.files.some((f) => f.status === "graph-limit"));
    assert.ok(
      m.interfaces.length > 3,
      "extraction continues independently of graph bounds",
    );
    assert.ok(
      reviewPlan(m).gaps.some((g) => g.kind === "interface-not-in-graph"),
    );
  } finally {
    GRAPH_LIMITS.nodes = prior;
  }
});

test("small error export retains historical string failures and current usage without response text", async () => {
  const report = await errorReport({
    model: {
      cweModelReview: {
        status: "failed",
        batches: [
          {
            id: "b",
            status: "failed",
            error: "Model did not return the required JSON object",
            responseShape: {
              format: "prose-or-other",
              textCharacters: 100,
              textBlocks: 1,
              raw: "PRIVATE_RESPONSE_SENTINEL",
            },
          },
        ],
      },
      usageLedger: {
        attempts: [
          {
            id: "a",
            status: "failed",
            usage: { inputTokens: 100, outputTokens: 20, totalTokens: 120 },
            failure: { code: "response-format" },
            responseShape: {
              format: "prose-or-other",
              textCharacters: 100,
              textBlocks: 1,
              raw: "PRIVATE_RESPONSE_SENTINEL",
            },
          },
        ],
      },
    },
    traces: {
      events: JSON.stringify({
        event: "cwe-model.request-failed",
        failure:
          "Model did not return the required JSON object PRIVATE_RESPONSE_SENTINEL",
      }),
    },
  });
  assert.equal(report.failureEvents.items[0].failure.code, "response-format");
  assert.equal(report.requestOutcomes.items[0].usage.totalTokens, 120);
  assert.equal(
    report.cweSourceReview.batches.items[0].responseShape.format,
    "prose-or-other",
  );
  assert.ok(!JSON.stringify(report).includes("PRIVATE_RESPONSE_SENTINEL"));
});

test("stale review diagnostics preserve reason and a later failed attempt without source prose", async () => {
  const model = {
    modelRevision: "current-revision",
    aiReview: {
      status: "stale",
      basedOnRevision: "old-revision",
      error: "Architecture changed PRIVATE_SOURCE_SENTINEL",
      staleReason: { causes: ["prompt-changed", "PRIVATE_REASON_SENTINEL"] },
      batches: [{ id: "prior", status: "completed" }],
      threats: [{ title: "PRIVATE_THREAT_SENTINEL" }],
    },
  };
  const stale = await errorReport({ model });
  assert.equal(stale.stride.failure.code, "stale-analysis");
  assert.deepEqual(stale.stride.staleReason.causes, [
    "prompt-changed",
    "source-or-architecture-changed",
  ]);
  model.aiReview.lastRunFailure = {
    code: "worker-resource",
    action: "Inspect last checkpoint.",
    stage: "before-review-checkpoint",
    at: "2026-01-01T00:00:00.000Z",
    raw: "PRIVATE_FAILURE_SENTINEL",
  };
  const failed = await errorReport({ model });
  assert.equal(failed.stride.status, "stale");
  assert.equal(failed.stride.failure.code, "worker-resource");
  assert.equal(failed.stride.lastRunFailure.stage, "before-review-checkpoint");
  assert.equal(failed.stride.staleReason.code, "stale-analysis");
  assert.ok(!JSON.stringify([stale, failed]).includes("PRIVATE_"));
});

test("compact errors retain planning time and safe failure reasons for the saved STRIDE run only", async () => {
  const model = await fixture();
  model.aiReview = {
    status: "partial",
    runId: "stride-run",
    plan: { planningMs: 5432 },
    failureGuard: { recentResponses: 12, invalidResponses: 6, stopped: true },
    batches: [
      {
        id: "failed",
        status: "failed",
        error:
          "Model response failed schema or evidence validation: evidence must belong to the listed interfaces and support every listed interface",
      },
    ],
  };
  model.usageLedger = {
    attempts: [
      {
        status: "failed",
        runId: "stride-run",
        batchId: "failed",
        failure: { code: "evidence-validation" },
      },
      {
        status: "failed",
        runId: "cwe-run",
        batchId: "cwe",
        failure: { code: "response-format" },
      },
    ],
  };
  const report = await errorReport({ model });
  assert.equal(report.stride.planningMs, 5432);
  assert.equal(report.stride.failureGuard.stopped, true);
  assert.deepEqual(report.stride.failedAttemptCountsForSavedReviewRun, {
    "evidence-validation": 1,
  });
  assert.equal(
    report.stride.batches.items[0].failure.validationRule,
    "evidence-ownership",
  );
  const detail = failureDetail(
    "Model response failed schema or evidence validation: secret source text should not escape",
  );
  assert.equal(detail.validationRule, "schema-or-reference");
  assert.ok(!JSON.stringify(detail).includes("secret source text"));
});

test("incomplete or unsupported provider content is counted as an invalid response", () => {
  for (const message of [
    "Provider response was incomplete or contained unsupported content",
    "Provider response was blocked, incomplete or contained unsupported content",
  ])
    assert.equal(failureDetail(message).code, "response-format");
});
