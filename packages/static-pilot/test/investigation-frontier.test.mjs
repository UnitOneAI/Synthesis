import { cleanupAfter } from "./cleanup.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyze } from "../src/engine.mjs";
import { modelConfig } from "../src/model-review.mjs";
import { ExplorationStore } from "../src/exploration.mjs";
import { InvestigationFrontier } from "../src/investigation-frontier.mjs";
import { exploreStatic } from "../src/exploration-review.mjs";
import { validateInvestigation } from "../src/investigation-contract.mjs";
const config = modelConfig(
  "anthropic-gateway",
  "claude-opus-4-6-1",
  { CLAUDE_API_KEY: "test-key" },
  { baseUrl: "https://gateway.example/anthropic" },
);
async function fixture(t, count = 12) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-frontier-"));
  cleanupAfter(t, () => fs.rm(root, { recursive: true, force: true }));
  const manifest = {
    profile: "static-fixture",
    repositories: Array.from({ length: count }, (_, i) => ({
      name: `repo${i}`,
    })),
  };
  for (let i = 0; i < count; i++) {
    await fs.mkdir(path.join(root, `repo${i}`));
    await fs.writeFile(
      path.join(root, `repo${i}`, "app.py"),
      i === count - 1
        ? "def authorize_request(principal):\n    return principal.is_admin\n"
        : `def route${i}(value):\n    return route${i + 1}(value)\n`,
    );
  }
  const model = await analyze(manifest, { sourceRoot: root });
  // An explicitly declared static chain tests traversal, without claiming compiler resolution.
  for (let i = 0; i < count; i++) {
    model.sourceGraph.nodes.push({
      id: `chain-${i}`,
      kind: "function",
      name: i === count - 1 ? "authorize_request" : `route${i}`,
      repository: `repo${i}`,
      path: "app.py",
      line: 1,
    });
    if (i)
      model.sourceGraph.edges.push({
        id: `chain-edge-${i}`,
        kind: "candidate-call",
        from: `chain-${i - 1}`,
        to: `chain-${i}`,
        basis: "fixture-static-contract",
      });
  }
  return { root, manifest, model };
}
function reply(value) {
  return Response.json({
    stop_reason: "end_turn",
    usage: { input_tokens: 100, output_tokens: 20 },
    content: [{ type: "text", text: JSON.stringify(value) }],
  });
}
function discovery(p, { finding = false, search = false } = {}) {
  const refs = [
    ...new Map(
      p.records.map((r) => [
        r.repository,
        { recordId: r.id, startLine: r.startLine, endLine: r.startLine },
      ]),
    ).values(),
  ];
  return {
    findings: finding
      ? [
          {
            cwe: "CWE-862",
            kind: "code-weakness",
            targetIds: p.targets
              .filter((t) => t.findingCwes.includes("CWE-862"))
              .map((t) => t.id),
            title: "Authorization needs inspection",
            explanation: "Follow the caller and downstream control",
            preconditions: "Caller can reach this operation",
            counterEvidence: "A downstream control may apply",
            remediation: "Check authorization on the complete path",
            locations: [
              refs.find(
                (r) =>
                  p.records.find((x) => x.id === r.recordId).repository ===
                  "repo0",
              ),
            ],
          },
        ]
      : [],
    limitations: [],
    targetReviews: p.targets.map((t) => ({
      targetId: t.id,
      status: search ? "needs-context" : "reviewed",
      rationale: "Static fixture review",
      locations: refs,
    })),
    explorationRequests: search
      ? [
          {
            action: "search",
            recordId: p.records[0].id,
            nodeId: "",
            symbol: "authorize_request",
            reason: "Find the downstream authorization control",
          },
        ]
      : [],
  };
}
function assessment(p, follow = false) {
  const r = p.records[0],
    cite = {
      recordId: r.id,
      startLine: r.startLine,
      endLine: r.startLine,
      reason: "Fixture code location",
    };
  return {
    assessment: "needs-context",
    actorKind: "external-attacker",
    actor: "Caller",
    initialAccess: "Unknown exposure",
    input: "Argument",
    impact: "Requires review",
    trace: [{ ...cite, role: "input" }],
    controls: [],
    counterEvidence: "Downstream controls may apply",
    missingEvidence: follow
      ? ["Read downstream source"]
      : ["Deployment exposure is unavailable"],
    followUp: [],
    remediation: {
      codeFix: "Review complete path",
      interimControl: "Restrict exposure",
      residualRisk: "Unknown callers",
      recovery: "Review identities",
      owner: "Unknown",
      approval: "Required",
      validation: "Static regression",
      rollback: "Reviewed policy",
    },
    severityChangeConditions: "Deployment evidence",
    explorationRequests: follow
      ? [
          {
            action: "neighbors",
            recordId: r.id,
            nodeId: "chain-0",
            symbol: "",
            reason: "Follow downstream calls across the selected repositories",
          },
        ]
      : [],
  };
}
test("graph-driven investigation searches missing evidence and follows a twelve-repository path; restart does not resubmit completed work", async (t) => {
  const f = await fixture(t);
  const state = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-frontier-db-"),
  );
  cleanupAfter(t, () => fs.rm(state, { recursive: true, force: true }));
  let store = new ExplorationStore(path.join(state, "exploration.sqlite"));
  cleanupAfter(t, () => store.close());
  const seen = [],
    events = [];
  let calls = 0;
  const fetchImpl = async (_, options) => {
    calls++;
    const body = JSON.parse(options.body);
    assert.equal(body.model, "claude-opus-4-6-1");
    const p = JSON.parse(body.messages[0].content);
    seen.push(p);
    if (p.purpose === "static security candidate assessment")
      return reply(
        assessment(p, !p.records.some((r) => r.repository === "repo11")),
      );
    if (p.targets) {
      const root = p.records[0].repository === "repo0";
      return reply(
        discovery(p, {
          finding: root,
          search: root && !p.records.some((r) => r.repository === "repo11"),
        }),
      );
    }
    return reply({
      summary: "Fixture STRIDE review",
      threats: [],
      connections: [],
      questions: [],
    });
  };
  const options = {
    sourceRoot: f.root,
    config,
    budget: 100,
    maxSteps: 10000,
    maxTokens: 1000000,
    fetchImpl,
    trace: (e, d) => events.push({ e, ...d }),
  };
  const first = await exploreStatic(f.manifest, f.model, {
    ...options,
    budget: 1,
    explorationStore: store,
  });
  assert.equal(first.callsThisRun, 1);
  assert.equal(first.stopReason, "request-budget");
  store.close();
  store = new ExplorationStore(path.join(state, "exploration.sqlite"));
  const second = await exploreStatic(f.manifest, f.model, {
    ...options,
    explorationStore: store,
  });
  assert.ok(
    seen.some(
      (p) =>
        p.targets &&
        p.records.some((r) => r.repository === "repo0") &&
        p.records.some((r) => r.repository === "repo11"),
    ),
    "Missing control search must return its evidence to the originating review",
  );
  assert.ok(
    seen.some(
      (p) =>
        p.purpose === "static security candidate assessment" &&
        new Set(p.records.map((r) => r.repository)).size === 12,
    ),
    "Path evidence must cross all twelve repositories",
  );
  const frontier = new InvestigationFrontier(store);
  frontier.open(second.scope, f.model.modelRevision, {});
  assert.ok(
    [...frontier.tasks()].some(
      (x) => x.kind === "search" && x.state === "done",
    ),
  );
  assert.ok(
    events.some(
      (e) =>
        e.e === "investigation.path-expanded" &&
        e.traversed.some((x) => x.repository === "repo11"),
    ),
  );
  assert.equal(f.model.cweModelReview.requestedRepositories.length, 12);
  assert.equal(f.model.cweModelReview.pendingBatches, 0);
  assert.equal(f.model.securityReview.entries[0].assessment, "needs-context");
  assert.equal(
    [...frontier.tasks()].filter(
      (x) =>
        x.kind === "gap" && x.result?.reason === "additional-evidence-required",
    ).length,
    48,
  );
  const before = calls;
  await exploreStatic(f.manifest, f.model, {
    ...options,
    explorationStore: store,
  });
  assert.equal(calls, before);
  assert.equal(f.model.explorationRun.coverageComplete, false);
});
test("budgets, changed source and graph request validation cannot become silent coverage", async (t) => {
  const f = await fixture(t, 2),
    store = new ExplorationStore();
  cleanupAfter(t, () => store.close());
  let calls = 0;
  const fetchImpl = async (_, options) => {
    calls++;
    const p = JSON.parse(JSON.parse(options.body).messages[0].content);
    return reply(
      p.targets
        ? discovery(p)
        : { summary: "Static", threats: [], connections: [], questions: [] },
    );
  };
  const opts = {
    sourceRoot: f.root,
    config,
    explorationStore: store,
    fetchImpl,
  };
  const tiny = await exploreStatic(f.manifest, f.model, {
    ...opts,
    maxTokens: 1000,
  });
  assert.equal(calls, 0);
  assert.equal(tiny.stopReason, "token-reservation-budget");
  assert.ok(tiny.frontier.queued > 0);
  const steps = await exploreStatic(f.manifest, f.model, {
    ...opts,
    maxSteps: 1,
  });
  assert.equal(steps.stepsThisRun, 1);
  assert.ok(steps.frontier.queued > 0);
  await fs.appendFile(path.join(f.root, "repo0", "app.py"), "# changed\n");
  const before = calls;
  const stale = await exploreStatic(f.manifest, f.model, opts);
  assert.equal(calls, before);
  assert.equal(stale.status, "failed");
  assert.match(stale.error, /Source changed/);
  assert.throws(
    () =>
      validateInvestigation(
        {
          explorationRequests: [
            {
              action: "shell",
              recordId: "r",
              nodeId: "",
              symbol: "",
              reason: "run",
            },
          ],
        },
        { records: [{ id: "r" }], graphNodes: [] },
      ),
    /unsupported action/,
  );
});
test("failed or interrupted model requests retain usage and do not poison other repositories", async (t) => {
  const f = await fixture(t, 2),
    store = new ExplorationStore();
  cleanupAfter(t, () => store.close());
  let calls = 0;
  const run = await exploreStatic(f.manifest, f.model, {
    sourceRoot: f.root,
    config,
    explorationStore: store,
    budget: 2,
    fetchImpl: async (_, options) => {
      calls++;
      if (calls === 1) return reply({ invalid: "response" });
      const p = JSON.parse(JSON.parse(options.body).messages[0].content);
      return reply(discovery(p));
    },
  });
  assert.equal(calls, 2);
  assert.equal(run.reportedTokens, 240);
  assert.equal(run.frontier.failed, 1);
  assert.ok(
    f.model.cweModelReview.batches.some(
      (b) => b.repositories.includes("repo1") && b.status === "completed",
    ),
  );
});

test("saved SQLite graph supplies indexed searches and paginated incident edges", async (t) => {
  const f = await fixture(t, 2);
  const { GraphStore, attachGraph } = await import("../src/graph-store.mjs");
  const { InvestigationSource } = await import(
    "../src/investigation-source.mjs"
  );
  const file = path.join(f.root, "graph.sqlite");
  const model = await analyze(f.manifest, {
    sourceRoot: f.root,
    graphDatabase: file,
  });
  const graph = new GraphStore(file, { readOnly: true });
  cleanupAfter(t, () => graph.close());
  attachGraph(model.sourceGraph, graph);
  const source = new InvestigationSource(model, f.manifest, f.root);
  assert.equal(source.files("repo0").items.length, 1);
  const matches = source.search("authorize_request").items;
  assert.ok(matches.some((n) => n.repository === "repo1"));
  const nodes = source.nodes({ repository: "repo0", limit: 100 });
  let checked = 0;
  for (const n of nodes) {
    const expected = [...graph.edges(model.sourceGraph.generation)].filter(
      (e) => e.from === n.id || e.to === n.id,
    );
    const actual = [];
    let after = "";
    do {
      const page = graph.incidentPage(model.sourceGraph.generation, n.id, {
        after,
        limit: 1,
      });
      actual.push(...page.items);
      after = page.next;
    } while (after);
    assert.deepEqual(
      new Set(actual.map((e) => e.id)),
      new Set(expected.map((e) => e.id)),
    );
    checked += actual.length;
  }
  assert.ok(checked > 0);
});
test("interrupted attempts need explicit retry and persisted completed results survive projection loss", async (t) => {
  const f = await fixture(t, 1),
    store = new ExplorationStore();
  cleanupAfter(t, () => store.close());
  let calls = 0;
  const opts = {
    sourceRoot: f.root,
    config,
    explorationStore: store,
    budget: 1,
    fetchImpl: async (_, options) => {
      calls++;
      const p = JSON.parse(JSON.parse(options.body).messages[0].content);
      return reply(discovery(p));
    },
  };
  const run = await exploreStatic(f.manifest, f.model, opts);
  delete f.model.cweModelReview;
  await exploreStatic(f.manifest, f.model, { ...opts, maxSteps: 1 });
  assert.equal(calls, 1);
  assert.ok(
    f.model.cweModelReview.batches.some((b) => b.status === "completed"),
  );
  const frontier = new InvestigationFrontier(store);
  frontier.open(run.scope, f.model.modelRevision, {});
  const accepted = [...frontier.tasks()].find(
    (t) => t.kind === "source" && t.result?.review,
  );
  frontier.state(accepted.id, "done", {
    ...accepted.result,
    expansionComplete: false,
  });
  await exploreStatic(f.manifest, f.model, { ...opts, maxSteps: 1 });
  assert.equal(
    calls,
    1,
    "Replaying accepted result expansion must not call the provider",
  );
  assert.equal(frontier.get(accepted.id).result.expansionComplete, true);
  const task = frontier.put("source", "interrupted", "repo0", {});
  frontier.state(task, "running");
  frontier.attempt({ id: "interrupted", status: "in-flight" });
  frontier.recover();
  assert.equal(frontier.get(task).state, "failed");
  assert.equal(
    frontier.attempts().find((a) => a.id === "interrupted").status,
    "interrupted",
  );
  frontier.recover({ retryFailed: true });
  assert.equal(frontier.get(task).state, "queued");
});

test("STRIDE retrieves cross-repository control evidence, reassesses, and resumes without repeating completed requests", async (t) => {
  const f = await fixture(t);
  await fs.writeFile(
    path.join(f.root, "repo0", "api.py"),
    "from flask import Flask\napp = Flask(__name__)\n@app.get('/backup')\ndef backup():\n    return authorize_request()\n",
  );
  f.model = await analyze(f.manifest, { sourceRoot: f.root });
  for (let i = 0; i < 12; i++) {
    f.model.sourceGraph.nodes.push({
      id: `stride-chain-${i}`,
      kind: "function",
      name: `chain${i}`,
      repository: `repo${i}`,
      path: i ? "app.py" : "api.py",
      line: 1,
    });
    if (i)
      f.model.sourceGraph.edges.push({
        id: `stride-edge-${i}`,
        kind: "candidate-call",
        from: `stride-chain-${i - 1}`,
        to: `stride-chain-${i}`,
        basis: "fixture-static-contract",
      });
  }
  const store = new ExplorationStore();
  cleanupAfter(t, () => store.close());
  const stridePackets = [];
  let calls = 0;
  const options = {
    sourceRoot: f.root,
    config,
    budget: 100,
    maxSteps: 10000,
    maxTokens: 10000000,
    explorationStore: store,
    fetchImpl: async (_, options) => {
      calls++;
      const p = JSON.parse(JSON.parse(options.body).messages[0].content);
      if (p.targets) return reply(discovery(p));
      if (p.purpose === "static security candidate assessment")
        return reply(assessment(p));
      stridePackets.push(p);
      assert.ok(
        p.sourceContext.records.length,
        "STRIDE must receive verified code after restart",
      );
      const hasControl = p.sourceContext.records.some(
        (r) => r.repository === "repo11",
      );
      return reply({
        summary: hasControl
          ? "Control evidence retrieved; deployment unknown"
          : "Authorization implementation requires inspection",
        threats: [],
        connections: [],
        questions: [],
        explorationRequests: hasControl
          ? []
          : [
              {
                action: p.sourceContext.graphNodes.some(
                  (n) => n.id === "stride-chain-0",
                )
                  ? "neighbors"
                  : "search",
                recordId: p.sourceContext.records[0].id,
                nodeId: p.sourceContext.graphNodes.some(
                  (n) => n.id === "stride-chain-0",
                )
                  ? "stride-chain-0"
                  : "",
                symbol: p.sourceContext.graphNodes.some(
                  (n) => n.id === "stride-chain-0",
                )
                  ? ""
                  : "authorize_request",
                reason: "Locate actual authorization implementation",
              },
            ],
      });
    },
  };
  await exploreStatic(f.manifest, f.model, options);
  const complete = await exploreStatic(f.manifest, f.model, options);
  assert.ok(
    stridePackets.some(
      (p) =>
        p.sourceContext.records.some(
          (r) =>
            r.repository === "repo11" && r.code.includes("principal.is_admin"),
        ) && p.sourceContext.priorReview,
    ),
    "Follow-up source must return to its originating STRIDE investigation",
  );
  const frontier = new InvestigationFrontier(store);
  frontier.open(complete.scope, f.model.modelRevision, {});
  assert.ok(
    stridePackets.some(
      (p) =>
        new Set(p.sourceContext.records.map((r) => r.repository)).size === 12,
    ),
    "STRIDE retains path evidence across twelve selected repositories",
  );
  const steps = [...frontier.tasks()].filter((t) => t.kind === "stride");
  assert.ok(steps.some((t) => t.result.history.length));
  assert.ok(steps.every((t) => t.state === "done"));
  const before = calls;
  await exploreStatic(f.manifest, f.model, options);
  assert.equal(calls, before);
  assert.ok(
    !JSON.stringify(steps).includes("return principal.is_admin"),
    "Persist references, not source text",
  );
});
