import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { analyze } from "../src/engine.mjs";
import {
  systemModel,
  editSystem,
  interactionContext,
} from "../src/system-model.mjs";
import {
  systemSvg,
  systemMermaid,
  systemReport,
  registerCsv,
  selectedPath,
} from "../src/system-exports.mjs";
import { workspaceStore } from "../src/workspace-store.mjs";
import { serve } from "../src/server.mjs";
import { reviewPlan, enrichGraphModel } from "../src/graph-review.mjs";
import { modelConfig } from "../src/model-review.mjs";
const root = fileURLToPath(
  new URL("../fixtures/repositories", import.meta.url),
);
const manifest = {
  title: "Workspace test",
  profile: "test",
  repositories: [
    { name: "frontdoor" },
    { name: "business" },
    { name: "setup" },
  ],
};
const fixture = () => analyze(manifest, { sourceRoot: root });
const edit = (m, kind, record) =>
  editSystem(m, {
    revision: systemModel(m).revision,
    action: "upsert",
    kind,
    record,
  });
const decide = (m, subjectId, state = "accepted") =>
  editSystem(m, {
    revision: systemModel(m).revision,
    action: "decision",
    subjectId,
    state,
    reviewer: "Security reviewer",
    rationale: "Source and assumptions reviewed",
    owner: "Platform team",
    severity: "medium",
  });
function architecture(m) {
  const s = systemModel(m),
    a = s.components[0],
    b = s.components[1];
  m = edit(m, "flows", {
    name: "Reviewed operation",
    source: a.id,
    target: b.id,
    protocol: "HTTPS",
    data: "Operational data",
    controls: "Operation policy requires review",
    interfaceIds: [a.interfaceIds[0], b.interfaceIds[0]],
    evidenceIds: [a.evidenceIds[0], b.evidenceIds[0]],
  });
  const f = systemModel(m).flows.find((f) => f.name === "Reviewed operation");
  m = edit(m, "boundaries", {
    name: "Caller to service authority",
    dimension: "identity",
    before: "Caller principal",
    after: "Service principal",
    enforcement: "Authorization policy",
    flowIds: [f.id],
    evidenceIds: f.evidenceIds,
  });
  m = edit(m, "domains", {
    name: "Service authority",
    dimension: "identity",
    memberIds: [b.id],
    evidenceIds: b.evidenceIds,
  });
  return m;
}

test("system projection preserves unresolved destinations, source evidence and separate actor assumptions", async () => {
  const m = await fixture(),
    s = systemModel(m);
  assert.equal(s.coverage.repositories, 3);
  assert.ok(s.flows.some((f) => f.basis === "unresolved"));
  assert.ok(s.actors.length);
  assert.ok(s.actors.every((a) => a.basis === "assumption"));
  assert.equal(s.domains.length, 0);
  assert.ok(
    s.entities.every((a) => a.type === "external" || a.type === "unknown"),
  );
  assert.ok(
    s.boundaries.every((b) =>
      ["inference", "reviewer declaration"].includes(b.basis),
    ),
  );
  assert.ok(s.matrix.every((r) => r.cells.length === 6));
  assert.ok(!JSON.stringify(s).includes(root));
});

test("component mappings support cross-repository ownership, retain identity and reject ambiguous ownership", async () => {
  let m = await fixture();
  const before = systemModel(m),
    source = before.components.slice(0, 2),
    record = {
      name: "Combined service",
      type: "process",
      repositories: source.flatMap((c) => c.repositories),
      interfaceIds: source.flatMap((c) => c.interfaceIds),
      evidenceIds: source.flatMap((c) => c.evidenceIds),
    };
  m = edit(m, "components", record);
  const s = systemModel(m),
    c = s.components.find((c) => c.name === record.name);
  assert.equal(c.repositories.length, 2);
  assert.ok(!s.components.some((c) => source.some((v) => v.id === c.id)));
  assert.ok(s.flows.some((f) => f.source === c.id || f.target === c.id));
  assert.throws(
    () => edit(m, "components", { ...record, name: "Duplicate ownership" }),
    /multiple declared/,
  );
  m = edit(m, "components", { ...record, id: c.id, name: "Renamed service" });
  assert.equal(
    systemModel(m).components.find((v) => v.id === c.id).name,
    "Renamed service",
  );
});

test("architecture edits validate references, lens dimensions, nested domains and deletion dependencies", async () => {
  let m = architecture(await fixture());
  let s = systemModel(m);
  const d = s.domains[0];
  m = edit(m, "domains", {
    name: "Nested identity",
    dimension: "identity",
    parentId: d.id,
    memberIds: [],
    evidenceIds: [],
  });
  const child = systemModel(m).domains.find(
    (v) => v.name === "Nested identity",
  );
  assert.throws(
    () =>
      edit(m, "domains", {
        id: d.id,
        name: d.name,
        dimension: "identity",
        parentId: child.id,
        memberIds: [],
      }),
    /cycle/,
  );
  assert.throws(
    () =>
      edit(m, "flows", {
        name: "Invalid",
        source: "missing",
        target: s.components[0].id,
      }),
    /endpoints/,
  );
  assert.throws(
    () => edit(m, "actors", { name: "No starting access", entryIds: [] }),
    /Initial access/,
  );
  assert.throws(
    () =>
      editSystem(m, {
        revision: systemModel(m).revision,
        action: "delete",
        kind: "flows",
        id: s.flows.find((f) => f.name === "Reviewed operation").id,
      }),
    /flowIds/,
  );
  assert.throws(
    () =>
      editSystem(m, {
        revision: "old",
        action: "upsert",
        kind: "actors",
        record: {},
      }),
    /changed/,
  );
  assert.throws(
    () =>
      edit(m, "assets", {
        name: "Fabricated evidence",
        evidenceIds: ["fabricated"],
      }),
    /evidenceIds/,
  );
});

test("review decisions keep basis, owner and rationale and become stale after source or record changes", async () => {
  let m = architecture(await fixture()),
    s = systemModel(m),
    b = s.boundaries.find((b) => b.name === "Caller to service authority");
  m = decide(m, b.id);
  let r = systemModel(m).boundaries.find((v) => v.id === b.id);
  assert.equal(r.basis, "reviewer declaration");
  assert.equal(r.reviewState, "accepted");
  assert.equal(r.decision.owner, "Platform team");
  assert.throws(
    () =>
      editSystem(m, {
        revision: systemModel(m).revision,
        action: "decision",
        subjectId: b.id,
        state: "accepted",
        reviewer: "",
        rationale: "",
      }),
    /Reviewer/,
  );
  m.sources[0].snapshot = "changed";
  assert.equal(
    systemModel(m).boundaries.find((v) => v.id === b.id).reviewState,
    "stale",
  );
});

test("matrix distinguishes analysis, checklist scenarios and explicit human review without false safe states", async () => {
  let m = await fixture(),
    s = systemModel(m);
  assert.ok(
    s.matrix.every((r) => r.cells.every((c) => c.state === "not-analyzed")),
  );
  const empty = s.matrix
    .flatMap((r) => r.cells)
    .find((c) => !c.threatIds.length);
  assert.ok(empty);
  m = decide(m, empty.id, "reviewed-no-scenario");
  assert.equal(
    systemModel(m)
      .matrix.flatMap((r) => r.cells)
      .find((c) => c.id === empty.id).state,
    "reviewed-no-scenario",
  );
  const full = s.matrix.flatMap((r) => r.cells).find((c) => c.threatIds.length);
  assert.throws(
    () => decide(m, full.id, "reviewed-no-scenario"),
    /empty matrix/,
  );
});

test("conditional actor paths follow only represented directional relationships and analysis packets retain context", async () => {
  const m = architecture(await fixture()),
    s = systemModel(m),
    f = s.flows.find((f) => f.name === "Reviewed operation");
  const actor = s.actors.find((a) => a.entryIds.includes(f.source));
  assert.ok(actor);
  assert.ok(selectedPath(s, actor.id).includes(f.id));
  assert.ok(
    selectedPath(s, actor.id).every(
      (id) => s.flows.find((f) => f.id === id).basis !== "unresolved",
    ),
  );
  const context = interactionContext(m, f.interfaceIds);
  assert.ok(
    context.boundaries.some((b) => b.name === "Caller to service authority"),
  );
  const plan = reviewPlan(m);
  for (const batch of plan.batches) {
    const evidence = new Set(
        batch.packet.records.flatMap((r) => r.evidence.map((e) => e.id)),
      ),
      interfaces = new Set(batch.packet.records.map((r) => r.id));
    for (const kind of [
      "components",
      "assets",
      "controls",
      "flows",
      "actors",
      "boundaries",
    ])
      for (const r of batch.packet.systemContext[kind] || []) {
        assert.ok((r.evidenceIds || []).every((id) => evidence.has(id)));
        assert.ok((r.interfaceIds || []).every((id) => interfaces.has(id)));
      }
  }

  assert.ok(
    plan.batches.every(
      (b) => Buffer.byteLength(JSON.stringify(b.packet)) <= 96 * 1024,
    ),
  );
  assert.ok(plan.batches.some((b) => b.packet.systemContext.boundaries.length));
});

test("all exports retain stable IDs, dispositions, gaps and escaped labels with security terminology", async () => {
  let m = architecture(await fixture());
  m = edit(m, "assets", {
    name: '=HYPERLINK("x") <script>alert(1)</script>',
    description: "Sensitive test data",
  });
  const s = systemModel(m);
  const html = systemReport(m);
  assert.ok(!html.includes("<script>alert"));
  assert.ok(html.includes("&lt;script&gt;"));
  for (const k of [
    "actors",
    "boundaries",
    "threats",
    "flows",
    "components",
    "assets",
    "matrix",
  ]) {
    const csv = registerCsv(m, k);
    assert.ok(csv.startsWith("\uFEFF"));
    assert.ok(!/AI scenarios|AI finding/.test(csv));
  }
  assert.ok(registerCsv(m, "assets").includes("'=HYPERLINK"));
  for (const f of s.flows) assert.ok(registerCsv(m, "flows").includes(f.id));
  for (const level of ["context", "system", "focus"])
    assert.ok(
      systemSvg(m, { level, focus: s.components[0].id }).includes("<svg"),
    );
  assert.ok(systemMermaid(m).includes("Service authority"));
  for (const f of s.flows) assert.ok(systemMermaid(m).includes(f.id));
  assert.ok(!/AI scenarios|AI finding/.test(html));
  assert.ok(systemSvg(m, { limit: 1 }).includes("omitted objects"));
});

test("durable store restores exact snapshots, rejects tampering and excludes concurrent writers", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-store-"));
  let store;
  try {
    store = await workspaceStore(root, dir);
    await store.save({ manifest, model: architecture(await fixture()) });
    await assert.rejects(workspaceStore(root, dir), /already open/);
    const saved = await store.load();
    assert.equal(saved.model.profile, "test");
    await store.close();
    store = await workspaceStore(root, dir);
    assert.deepEqual(await store.load(), saved);
    const file = path.join(dir, "snapshot.json"),
      text = await fs.readFile(file, "utf8");
    await fs.writeFile(file, text.replace("Workspace test", "Tampered name"));
    await assert.rejects(store.load(), /validation/);
  } finally {
    await store?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("server persists edit decisions and exports across restart with revision and origin guards", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-server-"));
  let app;
  try {
    app = await serve({
      sourceRoot: root,
      workspace: dir,
      persist: true,
      port: 0,
      quiet: true,
    });
    let base = app.url.split("/#")[0],
      headers = {
        "X-Synthesis-Token": app.token,
        "Content-Type": "application/json",
      };
    const post = (route, data) =>
      fetch(base + "/api/" + route, {
        method: "POST",
        headers,
        body: JSON.stringify(data),
      });
    await post("analyze", manifest);
    for (let i = 0; i < 200; i++) {
      const status = await (
        await fetch(base + "/api/status", { headers })
      ).json();
      if (status.status === "ready") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    let m = await (await fetch(base + "/api/model", { headers })).json();
    assert.ok(m.systemModel);
    let r = await post("system", {
      revision: m.systemModel.revision,
      action: "upsert",
      kind: "actors",
      record: {
        name: "Test operator",
        startingAccess: "Valid operator credential",
        entryIds: [m.systemModel.components[0].id],
        evidenceIds: [],
      },
    });
    assert.equal(r.status, 200);
    m = await r.json();
    const revision = m.systemModel.revision;
    r = await post("system", { revision: "stale", action: "decision" });
    assert.notEqual(r.status, 200);
    for (const format of [
      "actors",
      "boundaries",
      "threats",
      "flows",
      "components",
      "assets",
      "stride",
      "svg",
      "mermaid",
      "html",
      "json",
    ]) {
      r = await fetch(base + "/api/export?format=" + format, { headers });
      assert.equal(r.status, 200);
    }
    r = await fetch(base + "/api/system-diagram?level=context", { headers });
    assert.equal(r.status, 200);
    await app.close();
    app = await serve({
      sourceRoot: root,
      workspace: dir,
      persist: true,
      port: 0,
      quiet: true,
    });
    base = app.url.split("/#")[0];
    headers["X-Synthesis-Token"] = app.token;
    m = await (await fetch(base + "/api/model", { headers })).json();
    assert.equal(m.systemModel.revision, revision);
    assert.ok(m.systemModel.actors.some((a) => a.name === "Test operator"));
    assert.ok(
      !(await fs.readFile(path.join(dir, "snapshot.json"), "utf8")).includes(
        app.token,
      ),
    );
    await post("analyze", manifest);
    for (let i = 0; i < 200; i++) {
      const status = await (
        await fetch(base + "/api/status", { headers })
      ).json();
      if (status.status === "ready") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    m = await (await fetch(base + "/api/model", { headers })).json();
    assert.ok(m.systemModel.actors.some((a) => a.name === "Test operator"));
    assert.ok(m.systemModel.questions.some((q) => q.includes("retained")));
  } finally {
    await app?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("nested trust zones, linked controls, counterevidence and authority fields survive projection and exports", async () => {
  let m = architecture(await fixture()),
    s = systemModel(m),
    parent = s.domains[0];
  m = edit(m, "domains", {
    name: "Privileged service identity",
    dimension: "identity",
    parentId: parent.id,
    memberIds: parent.memberIds,
    evidenceIds: parent.evidenceIds,
  });
  s = systemModel(m);
  assert.ok(systemSvg(m).includes(`data-domain-parent="${parent.id}"`));
  const mermaid = systemMermaid(m);
  assert.ok(
    mermaid.indexOf("Service authority") <
      mermaid.indexOf("Privileged service identity"),
  );
  const control = s.securityControls[0];
  assert.ok(control);
  m = edit(m, "threats", {
    name: "Conditional operation abuse",
    scenario:
      "A caller may cross an authorization boundary if enforcement is absent.",
    categories: ["Tampering"],
    actorIds: [s.actors[0].id],
    controlIds: [control.id],
    counterEvidenceIds: control.evidenceIds,
    assumptions: "Caller has a valid low-privilege credential",
    evidenceIds: control.evidenceIds,
  });
  s = systemModel(m);
  const t = s.threats.find((t) => t.name === "Conditional operation abuse");
  assert.deepEqual(t.controlIds, [control.id]);
  assert.ok(registerCsv(m, "threats").includes(control.id));
  assert.ok(systemReport(m).includes("Counterevidence"));
  assert.throws(
    () =>
      editSystem(m, {
        revision: s.revision,
        action: "delete",
        kind: "securityControls",
        id: control.id,
      }),
    /controlIds/,
  );
});

test("completed model batches persist across restart and continuation reuses their cache", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-progress-"));
  let store;
  const config = modelConfig("anthropic", "test-model", {
    ANTHROPIC_API_KEY: "test-only",
  });
  let calls = 0;
  const response = async () => {
    calls++;
    return Response.json({
      stop_reason: "end_turn",
      content: [
        {
          type: "text",
          text: JSON.stringify({
            summary: "Conditional static review",
            threats: [],
            connections: [],
            questions: ["Confirm the operating assumptions."],
          }),
        },
      ],
    });
  };
  try {
    let m = await enrichGraphModel(
      await fixture(),
      config,
      new Map(),
      response,
      { maxBatches: 1 },
    );
    assert.equal(calls, 1);
    const total = reviewPlan(m).batches.length;
    assert.ok(total > 1);
    store = await workspaceStore(root, dir);
    await store.save({ manifest, model: m });
    await store.close();
    store = await workspaceStore(root, dir);
    m = (await store.load()).model;
    m = await enrichGraphModel(m, config, new Map(), response, {
      maxBatches: 100,
    });
    assert.equal(calls, total);
    assert.equal(m.aiReview.coverage.completedBatches, total);
    assert.equal(m.aiReview.coverage.failedBatches, 0);
  } finally {
    await store?.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
