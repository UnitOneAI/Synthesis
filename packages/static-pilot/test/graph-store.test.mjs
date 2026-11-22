import { cleanupAfter } from "./cleanup.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Writable } from "node:stream";
import { unzipSync } from "fflate";
import {
  GraphStore,
  attachGraph,
  sqliteSupported,
} from "../src/graph-store.mjs";
import { analyze } from "../src/engine.mjs";
import { reviewPlan } from "../src/graph-review.mjs";
import { graphJson, streamDiagnosticBundle } from "../src/graph-stream.mjs";
import { serve } from "../src/server.mjs";
import { sha } from "../src/sources.mjs";
const diskTest = (name, fn) => test(name, { skip: !sqliteSupported() }, fn);
async function fixture(t) {
  const dir = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-disk-")),
  );
  cleanupAfter(t, () => fs.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, "source"),
    workspace = path.join(dir, "state");
  await fs.mkdir(path.join(root, "one"), { recursive: true });
  await fs.mkdir(path.join(root, "two"));
  await fs.mkdir(workspace);
  await fs.writeFile(
    path.join(root, "one", "a.csproj"),
    '<Project><ItemGroup><ProjectReference Include="../two/b.csproj" /></ItemGroup></Project>',
  );
  await fs.writeFile(path.join(root, "two", "b.csproj"), "<Project />");
  await fs.writeFile(
    path.join(root, "one", "a.js"),
    'function start(){ fetch("/one"); next(); } function next(){fetch("/two");start();}',
  );
  await fs.writeFile(
    path.join(root, "two", "b.js"),
    'function other(){fetch("/other");}',
  );
  return {
    root,
    workspace,
    file: path.join(workspace, "graph.sqlite"),
    manifest: {
      profile: "release",
      repositories: [{ name: "one" }, { name: "two" }],
    },
  };
}
diskTest(
  "disk graph export, unchanged reuse and deleted reference invalidation",
  async (t) => {
    const f = await fixture(t),
      options = { sourceRoot: f.root, graphDatabase: f.file };
    const initial = await analyze(f.manifest, options);
    assert.equal(initial.sourceGraph.storage, "sqlite");
    assert.equal(initial.sourceGraph.nodes.length, 0);
    assert.equal(initial.sourceGraph.reuse.parsedFiles, 4);
    let store = new GraphStore(f.file);
    attachGraph(initial.sourceGraph, store);
    const graph = JSON.parse(
      [...graphJson(initial.sourceGraph, store)].join(""),
    );
    const memory = await analyze(f.manifest, { sourceRoot: f.root });
    assert.deepEqual(
      new Set(graph.nodes.map((n) => n.id)),
      new Set(memory.sourceGraph.nodes.map((n) => n.id)),
    );
    assert.deepEqual(
      new Set(graph.edges.map((n) => n.id)),
      new Set(memory.sourceGraph.edges.map((n) => n.id)),
    );
    assert.equal(graph.nodes.length, initial.sourceGraph.counts.nodes);
    assert.equal(graph.edges.length, initial.sourceGraph.counts.edges);
    assert.equal(
      graph.edges.filter((e) => e.kind === "project-reference").length,
      1,
    );
    const ids = new Set(graph.nodes.map((n) => n.id));
    assert.ok(graph.edges.every((e) => ids.has(e.from) && ids.has(e.to)));
    const plan = reviewPlan(initial);
    assert.ok(plan.obligations.some((o) => o.kind === "candidate-call-path"));
    assert.ok(plan.obligations.every((o) => o.batchIds.length));
    store.close();
    const again = await analyze(f.manifest, options);
    assert.equal(again.sourceGraph.reuse.parsedFiles, 0);
    assert.equal(again.sourceGraph.reuse.reusedFiles, 4);
    assert.equal(
      again.sourceGraph.fingerprint,
      initial.sourceGraph.fingerprint,
    );
    await fs.rm(path.join(f.root, "two", "b.csproj"));
    const removed = await analyze(f.manifest, options);
    store = new GraphStore(f.file);
    assert.equal(
      [
        ...store.edges(removed.sourceGraph.generation, {
          kind: "project-reference",
        }),
      ].length,
      0,
    );
    assert.equal(
      [
        ...store.edges(initial.sourceGraph.generation, {
          kind: "project-reference",
        }),
      ].length,
      1,
    );
    assert.equal(
      store.db
        .prepare(
          "SELECT count(*) AS n FROM links WHERE generation=? AND status='unresolved'",
        )
        .get(removed.sourceGraph.generation).n,
      1,
    );
    store.close();
  },
);
diskTest(
  "transaction rollback, unpublished scan and backup preserve published state",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const store = new GraphStore(f.file);
    const published = store.db
      .prepare("SELECT data FROM meta WHERE key='published'")
      .get().data;
    assert.throws(
      () =>
        store.transaction(() => {
          store.db.prepare("DELETE FROM meta WHERE key='published'").run();
          throw Error("injected");
        }),
      /injected/,
    );
    store.begin(f.manifest, sha(f.root));
    assert.equal(
      store.db.prepare("SELECT data FROM meta WHERE key='published'").get()
        .data,
      published,
    );
    const backup = path.join(f.workspace, "backup.sqlite");
    await store.backup(backup);
    store.close();
    const restored = new GraphStore(backup, { readOnly: true });
    assert.equal(
      restored.summary(model.sourceGraph.generation).nodes,
      model.sourceGraph.counts.nodes,
    );
    assert.equal(
      restored.db.prepare("PRAGMA integrity_check").get().integrity_check,
      "ok",
    );
    restored.close();
  },
);
diskTest(
  "streamed diagnostics contain complete graph, inventory and verified hashes",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const store = new GraphStore(f.file);
    attachGraph(model.sourceGraph, store);
    const chunks = [];
    const out = new Writable({
      highWaterMark: 32,
      write(chunk, encoding, done) {
        chunks.push(Buffer.from(chunk));
        setImmediate(done);
      },
    });
    await streamDiagnosticBundle(out, store, {
      model,
      plan: reviewPlan(model),
    });
    out.end();
    store.close();
    const zip = unzipSync(Buffer.concat(chunks));
    assert.equal(
      JSON.parse(Buffer.from(zip["source-graph.json"])).nodes.length,
      model.sourceGraph.counts.nodes,
    );
    assert.ok(
      Buffer.from(zip["source-inventory.ndjson"]).toString().includes("a.js"),
    );
    for (const entry of JSON.parse(Buffer.from(zip["manifest.json"])).files) {
      assert.equal(zip[entry.name].length, entry.bytes);
      assert.equal(sha(zip[entry.name]), entry.sha256);
    }
  },
);
diskTest(
  "HTTP disk scan, graph pages, streamed export and restart",
  async (t) => {
    const f = await fixture(t);
    let app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      graphStorage: "sqlite",
      port: 0,
      quiet: true,
    });
    cleanupAfter(t, () => app.close());
    const call = async (endpoint, body) =>
      fetch(new URL(endpoint, app.url), {
        headers: {
          "x-synthesis-token": app.token,
          "content-type": "application/json",
        },
        ...(body ? { method: "POST", body: JSON.stringify(body) } : {}),
      });
    assert.equal((await call("/api/analyze", f.manifest)).status, 202);
    let status;
    for (let i = 0; i < 500; i++) {
      status = await (await call("/api/status")).json();
      if (status.status !== "running") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(status.status, "ready", status.message);
    const model = await (await call("/api/model")).json();
    assert.equal(model.sourceGraph.storage, "sqlite");
    const summary = await (await call("/api/review-plan?summary=1")).json();
    assert.equal(summary.status, "not-prepared");
    assert.equal(summary.batches, null, "refresh must not construct a plan");
    assert.equal(summary.repositories, 2);
    const page = await (await call("/api/graph?kind=function&limit=1")).json();
    assert.equal(page.items.length, 1);
    assert.ok(page.next);
    const graph = await (await call("/api/export?format=graph")).json();
    assert.equal(graph.nodes.length, model.sourceGraph.counts.nodes);
    const plan = await (await call("/api/review-plan")).json();
    assert.ok(plan.obligations > 0);
    const concurrentPlans = await Promise.all(
      Array.from({ length: 8 }, () => call("/api/review-plan")),
    );
    assert.deepEqual(
      concurrentPlans.map((r) => r.status),
      Array(8).fill(200),
      "overlapping refreshes must share the same plan query",
    );
    const plans = await Promise.all(concurrentPlans.map((r) => r.json()));
    assert.ok(
      plans.every(
        (p) =>
          p.modelRevision === model.modelRevision &&
          p.obligations === plan.obligations,
      ),
    );

    await app.close();
    app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      graphStorage: "sqlite",
      port: 0,
      quiet: true,
    });
    assert.equal(
      (await (await call("/api/model")).json()).modelRevision,
      model.modelRevision,
    );
  },
);
diskTest(
  "disk review meters rejected output, resumes successful packets and retains deployed model ID",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const { enrichGraphModel } = await import("../src/graph-review.mjs");
    const { modelConfig } = await import("../src/model-review.mjs");
    const config = modelConfig(
      "anthropic-gateway",
      "approved-opus-deployment",
      { CLAUDE_API_KEY: "test-secret" },
      { baseUrl: "https://gateway.example/anthropic" },
    );
    let calls = 0;
    const mocked = async (url, options) => {
      calls++;
      assert.equal(JSON.parse(options.body).model, "approved-opus-deployment");
      return Response.json({
        usage: { input_tokens: 100, output_tokens: 10 },
        content: [
          {
            type: "text",
            text:
              calls === 1
                ? "invalid output"
                : JSON.stringify({
                    summary: "Review requires confirmation.",
                    threats: [],
                    connections: [],
                    questions: [],
                  }),
          },
        ],
        stop_reason: "end_turn",
      });
    };
    let store = new GraphStore(f.file);
    attachGraph(model.sourceGraph, store);
    await enrichGraphModel(model, config, new Map(), mocked, { maxBatches: 1 });
    assert.equal(model.usageLedger.attempts[0].usage.totalTokens, 110);
    assert.equal(model.usageLedger.attempts[0].status, "failed");
    store.close();
    store = new GraphStore(f.file);
    attachGraph(model.sourceGraph, store);
    await enrichGraphModel(model, config, new Map(), mocked, {
      maxBatches: 100,
    });
    assert.ok(model.aiReview.coverage.completedBatches > 0);
    const before = calls;
    await enrichGraphModel(model, config, new Map(), mocked, {
      maxBatches: 100,
    });
    assert.equal(calls, before);
    assert.equal(
      model.usageLedger.attempts.reduce((n, a) => n + a.usage.totalTokens, 0),
      calls * 110,
    );
    store.close();
  },
);
diskTest(
  "disk quotas fail without publishing and published generations reject mutations",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const store = new GraphStore(f.file, { maxBytes: 1 });
    assert.throws(() => store.begin(f.manifest, sha(f.root)), /storage budget/);
    assert.throws(
      () => store.discardSource(model.sourceGraph.generation, "one"),
      /immutable/,
    );
    assert.equal(
      JSON.parse(
        store.db.prepare("SELECT data FROM meta WHERE key='published'").get()
          .data,
      ),
      model.sourceGraph.generation,
    );
    store.close();
  },
);
diskTest(
  "persisted review packets omit source excerpts but requests retain explicitly selected context",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const store = new GraphStore(f.file);
    attachGraph(model.sourceGraph, store);
    const excerpts = new Map([
      [
        model.evidence[0].id,
        {
          text: "private-source-marker-should-not-persist",
          firstLine: 1,
          partial: true,
        },
      ],
    ]);
    const plan = reviewPlan(model, excerpts);
    assert.ok(
      [...plan.batches].some((b) =>
        JSON.stringify(b.packet).includes(
          "private-source-marker-should-not-persist",
        ),
      ),
    );
    for (const row of store.db
      .prepare("SELECT data FROM work WHERE kind='packet'")
      .iterate())
      assert.ok(!row.data.includes("private-source-marker-should-not-persist"));
    store.close();
  },
);
diskTest(
  "unchanged rebuild retains prior analysis; changed evidence retains it as stale",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const { GUIDANCE_HASH } = await import("../src/analysis-guidance.mjs");
    const { SYSTEM_PROMPT } = await import("../src/model-review.mjs");
    const { workspaceStore } = await import("../src/workspace-store.mjs");
    model.aiReview = {
      status: "partial",
      guidance: { hash: GUIDANCE_HASH },
      promptHash: sha(SYSTEM_PROMPT),
      summary: "Prior security review",
      threats: [],
      batches: [],
      coverage: {},
    };
    const saved = await workspaceStore(f.root, f.workspace);
    await saved.save({ manifest: f.manifest, model });
    await saved.close();
    const app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      graphStorage: "sqlite",
      port: 0,
      quiet: true,
    });
    cleanupAfter(t, () => app.close());
    const headers = {
      "x-synthesis-token": app.token,
      "content-type": "application/json",
    };
    const get = async (route) =>
      (await fetch(new URL("/api/" + route, app.url), { headers })).json();
    const rebuild = async () => {
      await fetch(new URL("/api/analyze", app.url), {
        headers,
        method: "POST",
        body: JSON.stringify(f.manifest),
      });
      for (let n = 0; n < 500; n++) {
        if ((await get("status")).status !== "running") return get("model");
        await new Promise((r) => setTimeout(r, 20));
      }
      throw Error("scan timed out");
    };
    const same = await rebuild();
    assert.equal(same.aiReview.summary, "Prior security review");
    assert.equal(same.aiReview.status, "partial");
    await fs.appendFile(
      path.join(f.root, "one", "a.js"),
      '\nfunction added(){fetch("/added");}',
    );
    const changed = await rebuild();
    assert.equal(changed.aiReview.summary, "Prior security review");
    assert.equal(changed.aiReview.status, "stale");
  },
);
diskTest(
  "diagnostic size budget stops an incomplete archive without reporting completion",
  async (t) => {
    const f = await fixture(t),
      model = await analyze(f.manifest, {
        sourceRoot: f.root,
        graphDatabase: f.file,
      });
    const store = new GraphStore(f.file);
    const out = new Writable({
      write(chunk, encoding, done) {
        done();
      },
    });
    await assert.rejects(
      streamDiagnosticBundle(out, store, { model, archiveMaxBytes: 100 }),
      /archive budget/,
    );
    out.destroy();
    store.close();
  },
);

diskTest(
  "restart rejects a snapshot whose graph database was lost",
  async (t) => {
    const f = await fixture(t);
    const model = await analyze(f.manifest, {
      sourceRoot: f.root,
      graphDatabase: f.file,
    });
    const { workspaceStore } = await import("../src/workspace-store.mjs");
    const saved = await workspaceStore(f.root, f.workspace);
    await saved.save({ manifest: f.manifest, model });
    await saved.close();
    await fs.rm(f.file);
    await assert.rejects(
      serve({
        sourceRoot: f.root,
        workspace: f.workspace,
        persist: true,
        graphStorage: "sqlite",
        port: 0,
        quiet: true,
      }),
      /Saved graph generation is missing/,
    );
    await assert.rejects(fs.stat(path.join(f.workspace, "writer.lock")), {
      code: "ENOENT",
    });
  },
);
