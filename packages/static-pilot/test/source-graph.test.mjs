import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  createSourceGraph,
  addSourceGraph,
  finishSourceGraph,
  graphContexts,
} from "../src/source-graph.mjs";
import { analyze, extract, compose } from "../src/engine.mjs";
import { sha } from "../src/sources.mjs";
import {
  reviewPlan,
  enrichGraphModel,
  strideMatrix,
} from "../src/graph-review.mjs";
import { dfdMermaid, strideCsv } from "../src/graph-exports.mjs";
import { modelConfig } from "../src/model-review.mjs";
import { serve } from "../src/server.mjs";
import { spawn } from "node:child_process";
const file = (name, text) => ({ path: name, text, hash: sha(text) });
const config = modelConfig(
  "anthropic-gateway",
  "test-deployment",
  { CLAUDE_API_KEY: "test-only-key" },
  { baseUrl: "https://gateway.example/anthropic" },
);
const response = () =>
  Response.json({
    stop_reason: "end_turn",
    content: [
      {
        type: "text",
        text: JSON.stringify({
          summary: "Partial static review. No scenario established.",
          threats: [],
          connections: [],
          questions: ["Review deployment assumptions."],
        }),
      },
    ],
  });

test("syntax graph parses C#, C++, JS and TS without treating comments or strings as calls", async () => {
  const graph = createSourceGraph();
  const files = [
    file(
      "Controller.cs",
      'class Controller { [HttpGet("/items")] public void Get() { this.Check(); client.SendAsync(); var s = "FakeCall()"; /* FakeCall(); */ } void Check() {} }',
    ),
    file("native.cpp", "void check() {} void run() { check(); }"),
    file("routes.js", 'function run(){ fetch("/api"); }'),
    file(
      "service.ts",
      "class Service { run(): void { this.save(); } save(): void {} }",
    ),
  ];
  const result = extract({ name: "api" }, files);
  await addSourceGraph(graph, { name: "api" }, files, result);
  finishSourceGraph(graph);
  assert.equal(graph.coverage.parsed, 4);
  assert.equal(graph.coverage.failed, 0);
  assert.ok(graph.nodes.some((n) => n.kind === "function" && n.name === "Get"));
  assert.ok(
    !graph.nodes.some((n) => n.kind === "call" && n.name.includes("FakeCall")),
  );
  assert.ok(graph.edges.some((e) => e.kind === "candidate-call-target"));
  const client = graph.nodes.find(
    (n) => n.kind === "call" && n.name === "SendAsync",
  );
  assert.ok(client);
  assert.ok(
    !graph.edges.some(
      (e) => e.from === client.id && e.kind === "candidate-call-target",
    ),
  );
  const inbound = result.interfaces.find((i) => i.direction === "inbound");
  assert.equal(graphContexts(graph).get(inbound.id).owner.name, "Get");
  assert.ok(!JSON.stringify(graph).includes("FakeCall()"));
  const ids = new Set(graph.nodes.map((n) => n.id));
  assert.ok(graph.edges.every((e) => ids.has(e.from) && ids.has(e.to)));
});

test("literal project references link collected projects across repos without creating DFD or trust edges", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-graph-"));
  try {
    await fs.mkdir(path.join(root, "api"));
    await fs.mkdir(path.join(root, "shared"));
    await fs.writeFile(
      path.join(root, "api", "api.csproj"),
      '<Project><ItemGroup><ProjectReference Include="..\\shared\\shared.csproj" /></ItemGroup></Project>',
    );
    await fs.writeFile(
      path.join(root, "shared", "shared.csproj"),
      "<Project />",
    );
    const model = await analyze(
      { profile: "test", repositories: [{ name: "api" }, { name: "shared" }] },
      { sourceRoot: root },
    );
    assert.equal(
      model.sourceGraph.edges.filter((e) => e.kind === "project-reference")
        .length,
      1,
    );
    assert.equal(model.flows.length, 0);
    assert.equal(model.boundaries.length, 0);
    assert.ok(!JSON.stringify(model.sourceGraph).includes(root));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

async function portfolio() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-portfolio-"));
  const repositories = [];
  for (let r = 0; r < 12; r++) {
    const name = `repo-${r}`;
    repositories.push({ name });
    await fs.mkdir(path.join(root, name));
    const methods = Array.from(
      { length: 35 },
      (_, n) =>
        `[HttpGet("/r${r}/operation${n}")] public void Operation${n}() { client.GetAsync("/remote/${n}"); }`,
    ).join("\n");
    await fs.writeFile(
      path.join(root, name, "Service.cs"),
      `class Service {\n${methods}\n}`,
    );
  }
  const model = await analyze(
    { profile: "synthetic-12-repository", repositories },
    { sourceRoot: root },
  );
  return { root, model };
}
test("12 repository graph review covers more than 120 records, resumes batches and never fabricates DFD flows", async () => {
  const { root, model } = await portfolio();
  try {
    assert.equal(model.sources.length, 12);
    assert.ok(model.interfaces.length > 120);
    const plan = reviewPlan(model);
    assert.ok(plan.batches.length > 12);
    const local = plan.batches.filter((b) => b.phase === "repository");
    const ids = local.flatMap((b) => b.packet.records.map((r) => r.id));
    assert.equal(new Set(ids).size, model.interfaces.length);
    assert.equal(ids.length, model.interfaces.length);
    assert.ok(plan.batches.some((b) => b.phase === "cross-repository"));
    assert.ok(
      plan.batches.every(
        (b) => Buffer.byteLength(JSON.stringify(b.packet)) <= 96 * 1024,
      ),
    );
    assert.ok(plan.batches[0].packet.records.some((r) => r.sourceGraph?.owner));
    let calls = 0,
      checkpoints = 0;
    const mock = async () => {
      calls++;
      return response();
    };
    await enrichGraphModel(model, config, new Map(), mock, {
      maxBatches: 2,
      checkpoint: () => checkpoints++,
    });
    assert.equal(calls, 2);
    assert.equal(model.aiReview.status, "partial");
    assert.ok(checkpoints >= 2);
    const first = model.aiReview.batches[0].responseHash;
    await enrichGraphModel(model, config, new Map(), mock, { maxBatches: 100 });
    assert.equal(calls, plan.batches.length);
    assert.equal(model.aiReview.status, "completed-needs-review");
    assert.equal(model.aiReview.batches[0].responseHash, first);
    assert.equal(
      model.aiReview.coverage.reviewedInterfaces,
      model.interfaces.length,
    );
    assert.equal(model.flows.length, 0);
    assert.equal(model.boundaries.length, 0);
    assert.ok(
      strideMatrix(model).every((r) =>
        r.cells.every((c) => c.status === "no-scenario-returned"),
      ),
    );
    const oldCalls = calls;
    model.profile = "different-variant";
    compose(model, model.declarations);
    assert.equal(model.aiReview.status, "stale");
    await enrichGraphModel(model, config, new Map(), mock, { maxBatches: 1 });
    assert.equal(calls, oldCalls + 1);
    assert.equal(model.aiReview.coverage.completedBatches, 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
test("gateway failures preserve completed batches and remain visible in the matrix", async () => {
  const { root, model } = await portfolio();
  try {
    let calls = 0;
    await enrichGraphModel(
      model,
      config,
      new Map(),
      async () =>
        ++calls === 1
          ? response()
          : new Response("secret provider details", { status: 403 }),
      { maxBatches: 100 },
    );
    assert.equal(calls, 2);
    assert.equal(model.aiReview.status, "partial");
    assert.equal(model.aiReview.coverage.failedBatches, 1);
    assert.ok(model.aiReview.coverage.pendingBatches > 0);
    assert.ok(!JSON.stringify(model.aiReview).includes("secret provider"));
    assert.ok(
      strideMatrix(model).some((r) =>
        r.cells.every((c) => c.status === "not-reviewed"),
      ),
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
test("Mermaid and STRIDE exports distinguish unresolved data flows and resist label and CSV injection", async () => {
  const { root, model } = await portfolio();
  try {
    model.components[0].name =
      '=HYPERLINK("evil")\nclick x "https://evil.example"';
    const dfd = dfdMermaid(model);
    assert.match(dfd, /flowchart LR/);
    assert.match(dfd, /unresolved HTTP/);
    assert.ok(!dfd.includes("\nclick "));
    const csv = strideCsv(model);
    assert.match(csv, /"'=HYPERLINK/);
    assert.match(csv, /not-reviewed/);
    assert.match(csv, /rule prompts/);
    const [from, to] = model.interfaces.filter(
      (i) => i.direction !== "control",
    );
    compose(model, {
      bindings: [
        {
          from: from.id,
          to: to.id,
          profile: model.profile,
          reason: "Review declaration",
          dimension: "identity",
          before: "caller",
          after: "service",
        },
      ],
    });
    assert.match(dfdMermaid(model), /trust transition identity/);
    assert.ok(strideMatrix(model).some((r) => r.rowKind === "flow"));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
test("staged API builds a graph without model calls and exports matrix and Mermaid", async () => {
  const { root } = await portfolio();
  const app = await serve({ sourceRoot: root, port: 0, quiet: true });
  try {
    const base = app.url.split("/#")[0];
    const headers = {
      "X-Synthesis-Token": app.token,
      "Content-Type": "application/json",
    };
    let r = await fetch(base + "/api/review", {
      method: "POST",
      headers,
      body: JSON.stringify({ maxBatches: 1 }),
    });
    assert.equal(r.status, 409);
    r = await fetch(base + "/api/analyze", {
      method: "POST",
      headers,
      body: JSON.stringify({
        profile: "test",
        repositories: [{ name: "repo-0" }],
        analysis: { useModel: false },
      }),
    });
    assert.equal(r.status, 202);
    for (let n = 0; n < 100; n++) {
      const s = await (await fetch(base + "/api/status", { headers })).json();
      if (s.status === "ready") break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const model = await (await fetch(base + "/api/model", { headers })).json();
    assert.ok(model.sourceGraph.nodes.length);
    assert.equal(model.aiReview, undefined);
    assert.ok(model.strideMatrix.length);
    for (const format of [
      "mermaid",
      "graph",
      "graph-mermaid",
      "stride",
      "html",
    ]) {
      r = await fetch(base + "/api/export?format=" + format, { headers });
      assert.equal(r.status, 200);
      assert.ok((await r.text()).length > 20);
    }
    r = await fetch(base + "/api/review", {
      method: "POST",
      headers,
      body: JSON.stringify({
        modelRevision: model.modelRevision,
        maxBatches: 1,
        includeSourceExcerpts: false,
      }),
    });
    assert.equal(r.status, 400);
  } finally {
    await new Promise((resolve) => app.server.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
});
test("staged worker reviews and continues an existing graph after source folders are removed", async () => {
  const { root } = await portfolio();
  const harness = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-worker-test-"),
  );
  const preload = path.join(harness, "provider.mjs"),
    boot = path.join(harness, "server.mjs");
  await fs.writeFile(
    preload,
    `globalThis.fetch = async () => Response.json({stop_reason:"end_turn",content:[{type:"text",text:JSON.stringify({summary:"Synthetic test review",threats:[],connections:[],questions:["Review deployment assumptions"]})}]});`,
  );
  await fs.writeFile(
    boot,
    `import {serve} from ${JSON.stringify(new URL("../src/server.mjs", import.meta.url).href)}; const app=await serve({sourceRoot:${JSON.stringify(root)},port:0,quiet:true,modelConfig:${JSON.stringify(config)}}); process.stdout.write(JSON.stringify({url:app.url,token:app.token})+"\\n");`,
  );
  const child = spawn(process.execPath, ["--import", pathToFileURL(preload).href, boot], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  try {
    const info = await new Promise((resolve, reject) => {
      let data = "",
        errors = "";
      const timer = setTimeout(
        () => reject(new Error("Server start timeout")),
        10000,
      );
      child.stderr.on("data", (c) => {
        errors += c;
      });
      child.stdout.on("data", (c) => {
        data += c;
        if (data.includes("\n")) {
          clearTimeout(timer);
          resolve(JSON.parse(data.split("\n")[0]));
        }
      });
      child.on("exit", () => {
        clearTimeout(timer);
        reject(new Error("Server exited: " + errors));
      });
    });
    const base = info.url.split("/#")[0],
      headers = {
        "X-Synthesis-Token": info.token,
        "Content-Type": "application/json",
      };
    const post = (route, body) =>
      fetch(base + "/api/" + route, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
    const wait = async () => {
      for (let i = 0; i < 200; i++) {
        const s = await (await fetch(base + "/api/status", { headers })).json();
        if (s.status === "ready") return;
        if (s.status === "failed") throw new Error(s.message);
        await new Promise((r) => setTimeout(r, 20));
      }
      throw new Error("Worker timeout");
    };
    assert.equal(
      (
        await post("analyze", {
          profile: "test",
          repositories: Array.from({ length: 12 }, (_, i) => ({
            name: `repo-${i}`,
          })),
          analysis: { useModel: false },
        })
      ).status,
      202,
    );
    await wait();
    let model = await (await fetch(base + "/api/model", { headers })).json();
    assert.equal(model.aiReview, undefined);
    await fs.rm(root, { recursive: true, force: true });
    assert.equal(
      (
        await post("review", {
          modelRevision: model.modelRevision,
          maxBatches: 1,
          includeSourceExcerpts: false,
        })
      ).status,
      202,
    );
    await wait();
    model = await (await fetch(base + "/api/model", { headers })).json();
    assert.equal(model.aiReview.coverage.completedBatches, 1);
    assert.equal(model.aiReview.status, "partial");
    assert.equal(
      (
        await post("review", {
          modelRevision: model.modelRevision,
          maxBatches: 1,
          includeSourceExcerpts: false,
        })
      ).status,
      202,
    );
    await wait();
    model = await (await fetch(base + "/api/model", { headers })).json();
    assert.equal(model.aiReview.coverage.completedBatches, 2);
    assert.equal(model.aiReview.coverage.callsThisRun, 1);
  } finally {
    child.kill();
    await new Promise((resolve) =>
      child.exitCode !== null ? resolve() : child.once("exit", resolve),
    );
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(harness, { recursive: true, force: true });
  }
});
