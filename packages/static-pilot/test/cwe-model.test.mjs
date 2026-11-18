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
  assert.equal(r.status, "partial");
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
