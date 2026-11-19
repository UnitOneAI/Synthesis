import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { analyze } from "../src/engine.mjs";
import { reviewCweCode, validateCweModel } from "../src/cwe-model.mjs";
import { modelConfig } from "../src/model-review.mjs";
import { usageSummary } from "../src/token-usage.mjs";
const config = modelConfig(
  "anthropic-gateway",
  "claude-opus-4-6-1",
  { CLAUDE_API_KEY: "test-only-key" },
  { baseUrl: "https://gateway.example/anthropic" },
);
const finding = (r) => ({
  cwe: "CWE-89",
  targetIds: ["server-19"],
  title: "Potential SQL injection",
  explanation: "Formatted SQL receives a function argument.",
  preconditions: "Attacker can influence the argument.",
  counterEvidence: "Callers and validation need review.",
  remediation: "Use bound parameters.",
  locations: [{ recordId: r.id, startLine: r.startLine, endLine: r.endLine }],
});
const targetReviews = (packet) =>
  packet.targets.map((t) => ({
    targetId: t.id,
    status: "needs-context",
    rationale: "Caller validation remains unresolved in this fixture.",
    locations: [
      ...new Map(packet.records.map((r) => [r.repository, r])).values(),
    ].map((r) => ({
      recordId: r.id,
      startLine: r.startLine,
      endLine: r.startLine,
    })),
  }));
const response = (value, packet) =>
  Response.json({
    stop_reason: "end_turn",
    usage: { input_tokens: 100, output_tokens: 20 },
    content: [
      {
        type: "text",
        text: JSON.stringify({
          ...value,
          ...(packet ? { targetReviews: targetReviews(packet) } : {}),
        }),
      },
    ],
  });
test("one malformed source-review packet does not hide the rest of the portfolio", async (t) => {
  const { root, manifest, model } = await fixture(t);
  let calls = 0;
  const report = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 2,
    fetchImpl: async (_, options) => {
      calls++;
      const packet = JSON.parse(JSON.parse(options.body).messages[0].content);
      return response(
        {
          findings:
            calls === 1
              ? [finding({ id: "invented", startLine: 1, endLine: 2 })]
              : [],
          limitations: [],
        },
        packet,
      );
    },
  });
  assert.equal(report.callsThisRun, 2);
  assert.equal(report.completedBatches, 1);
  assert.equal(report.batches.filter((b) => b.status === "failed").length, 1);
  assert.equal(report.status, "partial");
  const continued = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl: async (_, options) => {
      const packet = JSON.parse(JSON.parse(options.body).messages[0].content);
      assert.match(packet.previousValidationFailure, /unknown record/);
      return response({ findings: [], limitations: [] }, packet);
    },
  });
  assert.equal(continued.completedBatches, 2);
});
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-cwe-model-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifest = {
    profile: "test",
    repositories: ["one", "two", "three"].map((name) => ({
      name,
      selected: true,
    })),
  };
  for (const r of manifest.repositories) {
    await fs.mkdir(path.join(root, r.name));
    await fs.writeFile(
      path.join(root, r.name, "query.py"),
      'def query(cursor, value):\n    cursor.execute(f"select * from t where id={value}")\n',
    );
  }
  return {
    root,
    manifest,
    model: await analyze(manifest, { sourceRoot: root }),
  };
}
test("model CWE review uses gateway deployment, source evidence, token accounting and resumable portfolio coverage", async (t) => {
  const { root, manifest, model } = await fixture(t);
  const requests = [];
  const fetchImpl = async (url, options) => {
    assert.equal(url, "https://gateway.example/anthropic/v1/messages");
    assert.equal(options.headers["Ocp-Apim-Subscription-Key"], "test-only-key");
    const body = JSON.parse(options.body);
    assert.equal(body.model, "claude-opus-4-6-1");
    const packet = JSON.parse(body.messages[0].content);
    assert.match(packet.records[0].code, /cursor.execute/);
    requests.push(packet);
    return response(
      {
        findings: [finding(packet.records[0])],
        limitations: ["Caller validation is unresolved."],
      },
      packet,
    );
  };
  let r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  assert.equal(r.status, "partial");
  assert.equal(r.completedBatches, 1);
  assert.equal(r.pendingBatches, 2);
  assert.equal(r.findings.length, 1);
  assert.equal(model.usageLedger.attempts[0].usage.totalTokens, 120);
  r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  assert.equal(requests.length, 2);
  assert.notEqual(
    requests[0].records[0].repository,
    requests[1].records[0].repository,
  );
  r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 10,
    fetchImpl,
  });
  assert.equal(r.status, "completed-needs-review");
  assert.equal(r.findings.length, 3);
  assert.equal(requests.length, 3);
  assert.ok(r.repositories.every((r) => r.reviewedSegments === 1));
  assert.doesNotMatch(
    JSON.stringify(model.cweModelReview),
    /cursor.execute|test-only-key/,
  );
  assert.ok(usageSummary(model.usageLedger));
  model.cweModelReview.key = "prior-plan";
  const restarted = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl: async (_, options) =>
      response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(options.body).messages[0].content),
      ),
  });
  assert.equal(restarted.retainedFindingsFromPriorPlan, 3);
  assert.equal(restarted.findings.length, 3);
  assert.equal(restarted.completedBatches, 1);
});
test("CWE validation rejects invented IDs, locations and mappings; failed output still accounts for usage", async (t) => {
  const { root, manifest, model } = await fixture(t);
  const packet = {
    records: [
      {
        id: "known",
        repository: "one",
        path: "query.py",
        blobSha256: "hash",
        startLine: 1,
        endLine: 3,
      },
    ],
  };
  assert.throws(
    () =>
      validateCweModel(
        {
          findings: [finding({ id: "invented", startLine: 1, endLine: 2 })],
          limitations: [],
        },
        packet,
      ),
    /validation/,
  );
  assert.throws(
    () =>
      validateCweModel(
        {
          findings: [
            {
              ...finding({ id: "known", startLine: 1, endLine: 2 }),
              cwe: "CWE-999999",
            },
          ],
          limitations: [],
        },
        packet,
      ),
    /validation/,
  );
  const r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl: async () =>
      response({
        findings: [finding({ id: "invented", startLine: 1, endLine: 2 })],
        limitations: [],
      }),
  });
  assert.equal(r.status, "failed");
  assert.equal(r.findings.length, 0);
  assert.equal(r.batches[0].status, "failed");
  assert.equal(model.usageLedger.attempts[0].usage.totalTokens, 120);
  await fs.writeFile(path.join(root, "one", "query.py"), "changed\n");
  let calls = 0;
  const stale = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    fetchImpl: async () => {
      calls++;
    },
  });
  assert.equal(stale.status, "failed");
  assert.equal(calls, 0);
  assert.match(stale.error, /Source changed/);
});
test("CWE code review plans every segment of a large file and reports a long-line gap", async (t) => {
  const { root, manifest } = await fixture(t);
  manifest.repositories = manifest.repositories.slice(0, 1);
  await fs.writeFile(
    path.join(root, "one", "large.py"),
    "x=1\n".repeat(250) + 'x="' + "a".repeat(21000) + '"\n',
  );
  const model = await analyze(manifest, { sourceRoot: root });
  const r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 100,
    fetchImpl: async (_, options) =>
      response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(options.body).messages[0].content),
      ),
  });
  assert.ok(r.totalSegments >= 5);
  assert.equal(r.status, "partial");
  assert.ok(r.gaps.some((g) => g.reason === "line-exceeds-packet-limit"));
});

test("CWE scope follows implicit manifest selections and preserves explicit exclusions", async (t) => {
  const { root, manifest, model } = await fixture(t);
  delete manifest.repositories[0].selected;
  manifest.repositories[1].selected = false;
  const r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 10,
    fetchImpl: async (_, options) =>
      response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(options.body).messages[0].content),
      ),
  });
  assert.deepEqual(r.requestedRepositories, ["one", "three"]);
  assert.equal(r.completedBatches, 2);
});

test("current Semgrep findings are reviewed first without dropping the remaining source plan", async (t) => {
  const { root, manifest, model } = await fixture(t);
  model.cweReview = {
    basedOnRevision: model.modelRevision,
    rulePack: { sha256: "fixture" },
    findings: [
      {
        id: "scanner-finding",
        repository: "three",
        path: "query.py",
        sourceMatchesGraph: true,
        cwe: "CWE-89",
        line: 2,
        title: "Formatted query",
      },
    ],
  };
  let packet;
  const r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl: async (url, options) => {
      packet = JSON.parse(JSON.parse(options.body).messages[0].content);
      return response({ findings: [], limitations: [] }, packet);
    },
  });
  assert.equal(packet.records[0].repository, "three");
  assert.equal(packet.scannerFindings.length, 1);
  assert.equal(r.priorityBatches, 1);
  assert.equal(r.totalBatches, 3);
  assert.equal(r.pendingBatches, 2);
});

test("CWE review includes internal worker/storage connections and invalidates a prior profile plan", async (t) => {
  const { root, manifest } = await fixture(t);
  manifest.repositories = manifest.repositories.slice(0, 1);
  await fs.writeFile(
    path.join(root, "one", "server.py"),
    "from workers import Consumer\nworker = Consumer()\n",
  );
  await fs.writeFile(
    path.join(root, "one", "workers.py"),
    "from storage import Store\nclass Consumer:\n    def run(self):\n        store = Store()\n",
  );
  await fs.writeFile(
    path.join(root, "one", "storage.py"),
    "import sqlite3\nclass Store:\n    def open(self):\n        return sqlite3.connect(self.path)\n",
  );
  const model = await analyze(manifest, { sourceRoot: root });
  const packets = [];
  const fetchImpl = async (_, options) => {
    const p = JSON.parse(JSON.parse(options.body).messages[0].content);
    packets.push(p);
    return response({ findings: [], limitations: [] }, p);
  };
  let r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 100,
    fetchImpl,
  });
  assert.ok(
    packets.some(
      (p) =>
        p.connection &&
        p.records.some((r) => r.path === "workers.py") &&
        p.records.some((r) => r.path === "storage.py"),
    ),
  );
  assert.ok(packets.every((p) => p.targets.length === 25));
  assert.ok(r.repositories[0].plannedBatches > 1);
  const calls = packets.length;
  r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 100,
    fetchImpl,
  });
  assert.equal(packets.length, calls);
  model.cweModelReview.key = "prior-profile-plan";
  r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  assert.equal(packets.length, calls + 1);
  assert.equal(r.completedBatches, 1);
});

test("repeated gateway prose failures stop before spending the full budget and retain safe diagnostic metadata", async (t) => {
  const { root, manifest, model } = await fixture(t);
  let calls = 0;
  const events = [];
  const report = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 12,
    runUntilComplete: true,
    trace: (event, data) => events.push({ event, ...data }),
    fetchImpl: async () => {
      calls++;
      return Response.json({
        stop_reason: "end_turn",
        usage: { input_tokens: 100, output_tokens: 20 },
        content: [
          {
            type: "text",
            text: "PRIVATE_RESPONSE_SENTINEL prose instead of the requested JSON",
          },
        ],
      });
    },
  });
  assert.equal(calls, 3);
  assert.equal(report.status, "failed");
  assert.equal(report.stopReason, "repeated-response-format-failure");
  assert.equal(report.completedBatches, 0);
  assert.ok(report.pendingBatches >= 3);
  assert.equal(
    model.usageLedger.attempts.reduce((n, a) => n + a.usage.totalTokens, 0),
    360,
  );
  assert.ok(
    model.usageLedger.attempts.every(
      (a) => a.failure.code === "response-format",
    ),
  );
  assert.ok(
    report.batches.every((b) => b.responseShape.format === "prose-or-other"),
  );
  assert.ok(
    events
      .filter((e) => e.event === "cwe-model.request-failed")
      .every((e) => e.failure.code === "response-format"),
  );
  assert.ok(
    !JSON.stringify([report, events, model.usageLedger]).includes(
      "PRIVATE_RESPONSE_SENTINEL",
    ),
  );
  const continued = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl: async (_, o) =>
      response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(o.body).messages[0].content),
      ),
  });
  assert.equal(continued.completedBatches, 1);
  assert.equal(continued.stopReason, "request-budget");
  assert.equal(continued.status, "partial");
});
test("native JSON CWE review sends the exact gateway deployment and records validated target coverage", async (t) => {
  const { root, manifest, model } = await fixture(t);
  const report = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config: { ...config, structuredOutputs: true },
    budget: 1,
    fetchImpl: async (_, o) => {
      const body = JSON.parse(o.body);
      assert.equal(body.model, "claude-opus-4-6-1");
      assert.equal(body.output_config.format.type, "json_schema");
      assert.ok(
        body.output_config.format.schema.required.includes("targetReviews"),
      );
      return response(
        { findings: [], limitations: [] },
        JSON.parse(body.messages[0].content),
      );
    },
  });
  assert.equal(report.outputContract, "native-json-schema");
  assert.equal(report.completedBatches, 1);
  assert.equal(report.batches[0].targetReviews.length, 25);
});

test("continuous CWE reviews over 100 packets across twelve repos with bounded source windows and advisory tokens", async (t) => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-continuous-cwe-"),
  );
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifest = {
    profile: "continuous-test",
    repositories: Array.from({ length: 12 }, (_, i) => ({ name: `repo-${i}` })),
  };
  for (const r of manifest.repositories) {
    await fs.mkdir(path.join(root, r.name));
    await fs.writeFile(
      path.join(root, r.name, "large.py"),
      Array.from(
        { length: 6500 },
        (_, i) => `# static source context ${i}`,
      ).join("\n"),
    );
  }
  const model = await analyze(manifest, { sourceRoot: root });
  let calls = 0;
  const repos = new Set(),
    events = [];
  const fetchImpl = async (_, o) => {
    calls++;
    const packet = JSON.parse(JSON.parse(o.body).messages[0].content);
    packet.records.forEach((r) => repos.add(r.repository));
    assert.ok(packet.records.every((r) => typeof r.code === "string"));
    return response({ findings: [], limitations: [] }, packet);
  };
  const report = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    runUntilComplete: true,
    tokenTarget: 1,
    fetchImpl,
    trace: (event, data) => events.push({ event, ...data }),
  });
  assert.ok(calls > 100);
  assert.equal(calls, report.totalBatches);
  assert.equal(repos.size, 12);
  assert.equal(report.pendingBatches, 0);
  assert.equal(report.failedBatches, 0);
  assert.equal(report.runProgress.reportedTokens, calls * 120);
  assert.equal(report.runProgress.targetExceeded, true);
  assert.equal(
    events.filter((e) => e.event === "cwe-model.token-target-reached").length,
    1,
  );
  const windows = events.filter(
    (e) => e.event === "cwe-model.source-window-loaded",
  );
  assert.ok(windows.length > 1);
  assert.ok(windows.every((w) => w.packets <= 100));
  assert.ok(report.repositories.every((r) => r.reviewedSegments === r.chunks));
  const restored = JSON.parse(JSON.stringify(model)),
    before = calls;
  await reviewCweCode(manifest, restored, {
    sourceRoot: root,
    config,
    runUntilComplete: true,
    fetchImpl,
  });
  assert.equal(calls, before);
  assert.equal(restored.cweModelReview.runProgress.requests, 0);
  assert.ok(
    !JSON.stringify(restored.cweModelReview).includes("static source context"),
  );
});

test("continuous CWE cancellation and source changes keep saved work without uncontrolled calls", async (t) => {
  const { root, manifest, model } = await fixture(t),
    controller = new AbortController();
  let calls = 0;
  await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    runUntilComplete: true,
    signal: controller.signal,
    fetchImpl: async (_, o) => {
      calls++;
      controller.abort();
      return response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(o.body).messages[0].content),
      );
    },
  });
  assert.equal(calls, 1);
  assert.equal(model.cweModelReview.status, "cancelled");
  assert.equal(model.cweModelReview.completedBatches, 1);
  await fs.appendFile(path.join(root, "two", "query.py"), "\n# changed\n");
  await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    runUntilComplete: true,
    fetchImpl: async () => {
      calls++;
      throw Error("must not call");
    },
  });
  assert.equal(calls, 1);
  assert.equal(model.cweModelReview.status, "failed");
  assert.equal(model.cweModelReview.completedBatches, 1);
  assert.match(model.cweModelReview.error, /Source changed/);
});

test("parallel CWE equals serial findings and target coverage with serialized checkpoints and bounded resume", async (t) => {
  const { root, manifest, model } = await fixture(t);
  const parallel = structuredClone(model);
  let active = 0,
    peak = 0,
    saves = 0,
    peakSaves = 0;
  const fetchImpl = async (_, o) => {
    active++;
    peak = Math.max(peak, active);
    const packet = JSON.parse(JSON.parse(o.body).messages[0].content);
    await new Promise((r) =>
      setTimeout(r, packet.records[0].repository === "one" ? 12 : 2),
    );
    active--;
    return response(
      { findings: [finding(packet.records[0])], limitations: [] },
      packet,
    );
  };
  const serial = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    concurrency: 1,
    runUntilComplete: true,
    fetchImpl,
  });
  peak = 0;
  const checkpoint = async (report) => {
    saves++;
    peakSaves = Math.max(peakSaves, saves);
    const before = structuredClone(report);
    await new Promise((r) => setTimeout(r, 1));
    assert.deepEqual(report, before);
    saves--;
  };
  const partial = await reviewCweCode(manifest, parallel, {
    sourceRoot: root,
    config,
    concurrency: 3,
    budget: 2,
    fetchImpl,
    checkpoint,
  });
  assert.equal(partial.callsThisRun, 2);
  assert.equal(partial.completedBatches, 2);
  assert.equal(peak, 2);
  assert.equal(partial.execution.peakActive, 2);
  assert.equal(peakSaves, 1);
  const completedIds = partial.batches.map((b) => b.id);
  const resumed = await reviewCweCode(manifest, parallel, {
    sourceRoot: root,
    config,
    concurrency: 2,
    runUntilComplete: true,
    fetchImpl,
    checkpoint,
  });
  assert.equal(resumed.callsThisRun, 1);
  assert.equal(resumed.completedBatches, 3);
  assert.deepEqual(resumed.findings, serial.findings);
  const coverage = (r) =>
    r.batches.map((b) => ({
      id: b.id,
      status: b.status,
      recordIds: b.recordIds,
      targetReviews: b.targetReviews,
    }));
  assert.deepEqual(coverage(resumed), coverage(serial));
  assert.equal(new Set(resumed.batches.map((b) => b.id)).size, 3);
  assert.ok(
    completedIds.every((id) => resumed.batches.some((b) => b.id === id)),
  );
  assert.ok(
    resumed.batches.every(
      (b) =>
        b.packetBytes > 0 &&
        b.sourceBytes > 0 &&
        b.durationMs >= 0 &&
        b.agentId,
    ),
  );
  assert.equal(parallel.usageLedger.attempts.length, 3);
  assert.equal(
    parallel.usageLedger.attempts.reduce((n, a) => n + a.usage.totalTokens, 0),
    360,
  );
});

test("parallel CWE provider rejection stops dispatch and drains successful siblings before resume", async (t) => {
  const { root, manifest, model } = await fixture(t);
  let calls = 0;
  const r = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    concurrency: 2,
    runUntilComplete: true,
    fetchImpl: async (_, o) => {
      const call = ++calls,
        packet = JSON.parse(JSON.parse(o.body).messages[0].content);
      await new Promise((r) => setTimeout(r, call === 1 ? 2 : 20));
      return call === 1
        ? new Response("", { status: 403 })
        : response({ findings: [], limitations: [] }, packet);
    },
  });
  assert.equal(calls, 2);
  assert.equal(r.stopReason, "provider-failure");
  assert.equal(r.execution.active, 0);
  assert.equal(r.completedBatches, 1);
  assert.equal(r.failedBatches, 1);
  assert.equal(r.pendingBatches, 2);
  assert.ok(model.usageLedger.attempts.every((a) => a.status !== "in-flight"));
  const success = r.batches.find((b) => b.status === "completed").id;
  const resumed = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    concurrency: 2,
    runUntilComplete: true,
    fetchImpl: async (_, o) => {
      calls++;
      return response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(o.body).messages[0].content),
      );
    },
  });
  assert.equal(calls, 4);
  assert.equal(resumed.completedBatches, 3);
  assert.equal(resumed.batches.filter((b) => b.id === success).length, 1);
});

test("parallel CWE checkpoint failure drains active agents and does not dispatch remaining packets", async (t) => {
  const { root, manifest, model } = await fixture(t);
  let calls = 0;
  await assert.rejects(
    reviewCweCode(manifest, model, {
      sourceRoot: root,
      config,
      concurrency: 2,
      runUntilComplete: true,
      checkpoint: async (report) => {
        if (report.batches.some((b) => b.status === "completed"))
          throw Error("CWE checkpoint failed");
      },
      fetchImpl: async (_, o) => {
        calls++;
        await new Promise((r) => setTimeout(r, 5));
        return response(
          { findings: [], limitations: [] },
          JSON.parse(JSON.parse(o.body).messages[0].content),
        );
      },
    }),
    /checkpoint failed/,
  );
  assert.equal(calls, 2);
  assert.equal(model.cweModelReview.status, "failed");
  assert.equal(model.cweModelReview.execution.active, 0);
  assert.equal(
    model.cweModelReview.stopReason,
    "source-or-persistence-failure",
  );
  assert.ok(model.usageLedger.attempts.every((a) => a.status !== "in-flight"));
});

test("CWE cancellation during prepared checkpoint records no provider attempts", async (t) => {
  const { root, manifest, model } = await fixture(t),
    controller = new AbortController();
  let calls = 0;
  const report = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    concurrency: 2,
    runUntilComplete: true,
    signal: controller.signal,
    checkpoint: async (report) => {
      if (report.batches.some((b) => b.status === "queued")) controller.abort();
    },
    fetchImpl: async () => {
      calls++;
      throw Error("must not dispatch");
    },
  });
  assert.equal(calls, 0);
  assert.equal(report.callsThisRun, 0);
  assert.equal(report.runProgress.requests, 0);
  assert.equal(model.usageLedger.attempts.length, 0);
  assert.equal(report.execution.started, 0);
  assert.equal(report.execution.queued, report.totalBatches);
  assert.equal(report.batches.length, 0);
  assert.equal(report.stopReason, "cancelled");
});

test("duplicate CWE findings choose plan priority rather than response completion order", async (t) => {
  const { root, manifest } = await fixture(t);
  manifest.repositories = manifest.repositories.slice(0, 1);
  await fs.writeFile(
    path.join(root, "one", "server.py"),
    "from workers import Consumer\nworker = Consumer()\n",
  );
  await fs.writeFile(
    path.join(root, "one", "workers.py"),
    "from storage import Store\nclass Consumer:\n    def run(self):\n        store = Store()\n",
  );
  await fs.writeFile(
    path.join(root, "one", "storage.py"),
    "import sqlite3\nclass Store:\n    def open(self):\n        return sqlite3.connect(self.path)\n",
  );
  const model = await analyze(manifest, { sourceRoot: root }),
    parallel = structuredClone(model);
  const captures = [];
  const fetchImpl = async (_, o) => {
    const p = JSON.parse(JSON.parse(o.body).messages[0].content),
      r = p.records.find((r) => r.path === "storage.py");
    if (r) captures.push(Boolean(p.connection));
    await new Promise((resolve) => setTimeout(resolve, p.connection ? 15 : 1));
    return response(
      {
        findings: r
          ? [
              {
                ...finding({ ...r, endLine: r.startLine }),
                title: p.connection
                  ? "Graph context finding"
                  : "File context finding",
              },
            ]
          : [],
        limitations: [],
      },
      p,
    );
  };
  const serial = await reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    runUntilComplete: true,
    concurrency: 1,
    fetchImpl,
  });
  const report = await reviewCweCode(manifest, parallel, {
    sourceRoot: root,
    config,
    runUntilComplete: true,
    concurrency: 4,
    fetchImpl,
  });
  assert.ok(captures.includes(true) && captures.includes(false));
  assert.equal(report.findings.length, 1);
  assert.deepEqual(report.findings, serial.findings);
});

test("parallel CWE checkpoints real in-flight attempts before provider responses arrive", async (t) => {
  const { root, manifest, model } = await fixture(t);
  let release,
    observed,
    calls = 0,
    snapshot;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const checkpointed = new Promise((resolve) => {
    observed = resolve;
  });
  const task = reviewCweCode(manifest, model, {
    sourceRoot: root,
    config,
    budget: 2,
    concurrency: 2,
    checkpoint: async (report) => {
      if (report.batches.filter((b) => b.status === "running").length === 2) {
        snapshot = {
          report: structuredClone(report),
          ledger: structuredClone(model.usageLedger),
        };
        observed();
      }
    },
    fetchImpl: async (_, o) => {
      calls++;
      await held;
      return response(
        { findings: [], limitations: [] },
        JSON.parse(JSON.parse(o.body).messages[0].content),
      );
    },
  });
  try {
    await Promise.race([
      checkpointed,
      new Promise((_, reject) => {
        const timer = setTimeout(
          () => reject(Error("in-flight checkpoint missing")),
          1000,
        );
        timer.unref();
      }),
    ]);
    assert.equal(calls, 2);
    assert.equal(snapshot.report.callsThisRun, 2);
    assert.equal(snapshot.report.completedBatches, 0);
    assert.equal(
      snapshot.ledger.attempts.filter((a) => a.status === "in-flight").length,
      2,
    );
    assert.equal(snapshot.report.runProgress.unknownRequests, 2);
    assert.ok(
      snapshot.report.batches.every((b) =>
        snapshot.ledger.attempts.some((a) => a.id === b.attemptId),
      ),
    );
  } finally {
    release();
    await task;
  }
  assert.equal(model.cweModelReview.completedBatches, 2);
});
