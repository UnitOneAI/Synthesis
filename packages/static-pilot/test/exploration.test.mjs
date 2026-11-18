import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { ExplorationStore } from "../src/exploration.mjs";
import { exploreStatic } from "../src/exploration-review.mjs";
import { analyze } from "../src/engine.mjs";
import { modelConfig } from "../src/model-review.mjs";
import {
  securityContextKey,
  SECURITY_REVIEW_PROMPT,
  securityIssues,
} from "../src/security-intelligence.mjs";
import { sha } from "../src/sources.mjs";
import { CWE_PROFILE_HASH } from "../src/cwe-targets.mjs";
const config = modelConfig(
  "anthropic-gateway",
  "claude-opus-4-6-1",
  { CLAUDE_API_KEY: "fixture" },
  { baseUrl: "https://gateway.example/anthropic" },
);
async function fixture(t, n = 12) {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-exploration-"),
  );
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const manifest = {
    profile: "static",
    repositories: Array.from({ length: n }, (_, i) => ({ name: `repo${i}` })),
  };
  for (const r of manifest.repositories) {
    await fs.mkdir(path.join(dir, r.name));
    await fs.writeFile(
      path.join(dir, r.name, "app.py"),
      "def query(cursor, value):\n    cursor.execute(value)\n",
    );
  }
  return { dir, manifest, model: await analyze(manifest, { sourceRoot: dir }) };
}
test("twelve repositories retain every requested CWE obligation; graph pagination, lineage and history survive restart", async (t) => {
  const { dir, model } = await fixture(t);
  const db = path.join(dir, "exploration.sqlite");
  let store = new ExplorationStore(db);
  try {
    store.sync(model);
    const goals = store.query(model.modelRevision, {
      kind: "goal",
      limit: 100,
    });
    assert.equal(goals.total, 12 * 29);
    assert.equal(goals.omitted, 248);
    assert.equal(
      store.query(model.modelRevision, { kind: "stride-goal" }).total,
      72,
    );
    assert.equal(new Set(goals.nodes.map((n) => n.id)).size, 100);
    const next = store.query(model.modelRevision, {
      kind: "goal",
      offset: 100,
      limit: 100,
    });
    assert.equal(next.nodes.length, 100);
    assert.ok(!goals.nodes.some((n) => next.nodes.some((x) => x.id === n.id)));
    const g = goals.nodes[0],
      lineage = store.query(model.modelRevision, { focus: g.id });
    assert.equal(lineage.nodes.length, 3);
    assert.equal(lineage.edges.length, 2);
    const before = store.node(model.modelRevision, g.id).transitionCount;
    store.sync(model);
    assert.equal(store.node(model.modelRevision, g.id).transitionCount, before);
    const revision = model.modelRevision;
    model.modelRevision = "new-source";
    store.sync(model);
    assert.equal(store.overview("new-source").revisions.length, 2);
    store.close();
    store = new ExplorationStore(db);
    assert.equal(store.node(revision, g.id).revision, revision);
    assert.equal(store.overview(revision).coverageComplete, false);
  } finally {
    store.close();
  }
});
test("candidate lineage retains packet, exact source reference, controls and context gaps", async (t) => {
  const { model } = await fixture(t, 1);
  model.cweModelReview = {
    key: "plan",
    basedOnRevision: model.modelRevision,
    targetProfileHash: CWE_PROFILE_HASH,
    plan: [{ id: "p", repositories: ["repo0"] }],
    batches: [
      {
        id: "p",
        repositories: ["repo0"],
        status: "completed",
        targetReviews: [],
      },
    ],
    repositories: [],
    findings: [
      {
        id: "f",
        batchId: "p",
        cwe: "CWE-89",
        title: "Query candidate",
        locations: [
          { repository: "repo0", path: "app.py", line: 2, blobSha256: "hash" },
        ],
      },
    ],
  };
  const issue = securityIssues(model)[0];
  model.securityReview = {
    contextKey: securityContextKey(model),
    promptHash: sha(SECURITY_REVIEW_PROMPT),
    entries: [
      {
        issueId: issue.id,
        issueHash: sha(JSON.stringify(issue)),
        attemptId: "attempt1",
        assessment: "needs-context",
        evidence: [
          {
            id: "ref",
            repository: "repo0",
            path: "app.py",
            startLine: 1,
            endLine: 2,
            blobSha256: "hash",
          },
        ],
        controls: [{ recordId: "ref", reason: "Control scope unknown" }],
        counterEvidence: "Shared controls require review",
        missingEvidence: ["Caller unknown"],
        history: [],
      },
    ],
  };
  const s = new ExplorationStore();
  try {
    s.sync(model);
    const obs = s.query(model.modelRevision, { kind: "observation" }).nodes[0];
    assert.equal(obs.recordId, "ref");
    assert.notEqual(obs.id, "ref");
    const lineage = s.query(model.modelRevision, { focus: obs.id });
    assert.deepEqual(
      new Set(lineage.nodes.map((n) => n.kind)),
      new Set([
        "scope",
        "phase",
        "step",
        "finding",
        "assessment",
        "observation",
      ]),
    );
    assert.equal(s.query(model.modelRevision, { kind: "gap" }).total, 1);
    assert.equal(s.query(model.modelRevision, { kind: "control" }).total, 1);
    model.securityReview.entries[0].assessment = "failed";
    s.sync(model);
    assert.equal(
      s.node(
        model.modelRevision,
        s.query(model.modelRevision, { kind: "assessment" }).nodes[0].id,
      ).transitionCount,
      2,
    );
  } finally {
    s.close();
  }
});
test("static planner resumes twelve repositories within one shared request budget without rebuilding graph", async (t) => {
  const { dir, manifest, model } = await fixture(t);
  const fingerprint = model.sourceGraph.fingerprint;
  const explorationStore=new ExplorationStore();t.after(()=>explorationStore.close());
  let calls = 0;
  const fetchImpl = async (_, options) => {
    calls++;
    const body = JSON.parse(options.body);
    assert.equal(body.model, "claude-opus-4-6-1");
    const p = JSON.parse(body.messages[0].content);
    const review = p.targets
      ? {
          findings: [],
          limitations: [],
          targetReviews: p.targets.map((t) => ({
            targetId: t.id,
            status: "not-applicable-to-packet",
            rationale: "No relevant evidence in fixture",
            locations: [
              {
                recordId: p.records[0].id,
                startLine: p.records[0].startLine,
                endLine: p.records[0].startLine,
              },
            ],
          })),
        }
      : {
          summary: "Reviewed fixture",
          threats: [],
          connections: [],
          questions: [],
        };
    return Response.json({
      stop_reason: "end_turn",
      usage: { input_tokens: 10, output_tokens: 10 },
      content: [{ type: "text", text: JSON.stringify(review) }],
    });
  };
  const first = await exploreStatic(manifest, model, {
    sourceRoot: dir,
    explorationStore,
    config,
    budget: 1,
    fetchImpl,
  });
  assert.equal(first.callsThisRun, 1);
  assert.equal(first.status, "partial");
  const second = await exploreStatic(manifest, model, {
    sourceRoot: dir,
    explorationStore,
    config,
    budget: 100,
    fetchImpl,
  });
  assert.ok(second.callsThisRun <= 100);
  assert.equal(calls, 1 + second.callsThisRun);
  assert.equal(model.sourceGraph.fingerprint, fingerprint);
  assert.equal(model.cweModelReview?.requestedRepositories.length, 12);
  assert.equal(model.cweModelReview?.pendingBatches, 0);
  assert.equal(second.coverageComplete, false);
  const before = calls;
  const third = await exploreStatic(manifest, model, {
    sourceRoot: dir,
    explorationStore,
    config,
    budget: 100,
    fetchImpl,
  });
  assert.equal(calls, before);
  assert.equal(third.callsThisRun, 0);
  const controller = new AbortController();
  controller.abort();
  const cancelled = await exploreStatic(manifest, model, {
    sourceRoot: dir,
    explorationStore,
    config,
    budget: 1,
    fetchImpl,
    signal: controller.signal,
  });
  assert.equal(cancelled.status, "cancelled");
  assert.equal(calls, before);
});
