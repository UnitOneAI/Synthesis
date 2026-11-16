import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyze } from "../src/engine.mjs";
import { systemModel } from "../src/system-model.mjs";
import {
  systemSvg,
  systemMermaid,
  selectedPath,
} from "../src/system-exports.mjs";
import { diagramModel, layoutDiagram } from "../src/diagram-model.mjs";
import { sqliteSupported } from "../src/graph-store.mjs";
async function fixture(t, repos) {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-architecture-"),
  );
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const [repo, files] of Object.entries(repos))
    for (const [name, content] of Object.entries(files)) {
      const file = path.join(root, repo, name);
      await fs.mkdir(path.dirname(file), { recursive: true });
      await fs.writeFile(file, content);
    }
  return {
    root,
    manifest: {
      profile: "test",
      repositories: Object.keys(repos).map((name) => ({
        name,
        selected: true,
      })),
    },
  };
}
test(
  "configured .NET clients connect twelve repositories, retain assignment/config evidence, and reuse disk facts",
  { skip: !sqliteSupported() },
  async (t) => {
    const repos = {};
    for (let i = 0; i < 12; i++)
      repos[`repo${i}`] = {
        "Service.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
        "Controller.cs":
          '[Route("api/items")] public class ItemsController { [HttpGet("{id}")] public string Get(int id) => ""; }',
        "Client.cs":
          i < 11
            ? `class Caller { void Run() { client.BaseAddress = new Uri(configuration["ServiceUrl"]); const string route = "items/42"; client.GetAsync(route); } }`
            : "",
        "appsettings.json": JSON.stringify({
          Urls: `https://host${i}`,
          ServiceUrl: `https://user:PRIVATE@host${i + 1}/api/`,
        }),
      };
    const { root, manifest } = await fixture(t, repos);
    const opts = {
      sourceRoot: root,
      graphDatabase: path.join(root, "graph.sqlite"),
    };
    const m = await analyze(manifest, opts);
    assert.equal(m.connectionDiscovery.flows.length, 11);
    assert.equal(m.connectionDiscovery.coverage.httpClients, 11);
    assert.ok(
      m.connectionDiscovery.flows.every(
        (f) => f.basis === "static endpoint match" && f.evidence.length >= 5,
      ),
    );
    assert.doesNotMatch(JSON.stringify(m), /PRIVATE|user:/);
    const memory = await analyze(manifest, { sourceRoot: root });
    assert.deepEqual(
      memory.connectionDiscovery.flows,
      m.connectionDiscovery.flows,
    );
    const second = await analyze(manifest, opts);
    assert.ok(second.sourceGraph.reuse.reusedFiles >= 48);
    assert.deepEqual(
      second.connectionDiscovery.flows,
      m.connectionDiscovery.flows,
    );
    const d = diagramModel(systemModel(m));
    assert.equal(d.connections.length, 11);
    const positions = layoutDiagram(d).positions;
    assert.ok(
      d.connections.every(
        (f) => positions.get(f.source).x < positions.get(f.target).x,
      ),
    );
  },
);
test("config conflicts, reassignment and unknown destinations remain gaps instead of fabricated edges", async (t) => {
  const { root, manifest } = await fixture(t, {
    web: {
      "Client.cs":
        'class Client { void Call() { client.BaseAddress = new Uri(configuration["ServiceUrl"]); client.GetAsync("items/42"); string route = "/api/items/42"; route = userInput; client.GetAsync(route); } }',
      "appsettings.json": '{"ServiceUrl":"https://a/api/"}',
      "appsettings.Production.json": '{"ServiceUrl":"https://b/api/"}',
    },
    api: {
      "Controller.cs":
        '[Route("api/items")] class ItemsController { [HttpGet("{id}")] public void Get() {} }',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root });
  assert.equal(m.connectionDiscovery.flows.length, 0);
  assert.ok(
    m.connectionDiscovery.gaps.some(
      (g) => g.reason === "ambiguous-configuration",
    ),
  );
  assert.equal(m.connectionDiscovery.coverage.unresolvedClients, 2);
});
test("HttpRequestMessage and XML app settings resolve across files without retaining credentials", async (t) => {
  const { root, manifest } = await fixture(t, {
    web: {
      "Client.cs":
        'class Client { void Call() { client.BaseAddress = new Uri(ConfigurationManager.AppSettings["ApiUrl"]); var request = new HttpRequestMessage(HttpMethod.Post, "items"); client.SendAsync(request); } }',
      "web.config":
        '<configuration><appSettings><add key="ApiUrl" value="https://u:PRIVATE@api/api/" /></appSettings></configuration>',
    },
    api: {
      "Controller.cs":
        '[Route("api")] class ItemsController { [HttpPost("items")] public void Post() {} }',
      "settings.json": '{"Urls":"https://api"}',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root });
  assert.equal(m.connectionDiscovery.flows.length, 1);
  assert.equal(m.connectionDiscovery.flows[0].operation, "POST /api/items");
  assert.doesNotMatch(JSON.stringify(m), /PRIVATE/);
});
test("project facts identify hosts, tests, unique library ownership and preserve source groups", async (t) => {
  const { root, manifest } = await fixture(t, {
    repo: {
      "Host/Host.csproj":
        '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><ProjectReference Include="../Library/Library.csproj" /></ItemGroup></Project>',
      "Host/Program.cs": "var builder = WebApplication.CreateBuilder(args);",
      "Library/Library.csproj": "<Project></Project>",
      "Library/Client.cs": 'client.GetAsync("/items");',
      "Checks/Checks.csproj":
        "<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>",
      "Checks/Tests.cs": 'client.GetAsync("/items");',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m);
  const host = s.components.find((c) => c.name === "Host"),
    library = s.components.find((c) => c.name === "Library"),
    checks = s.components.find((c) => c.name === "Checks");
  assert.equal(host.type, "process");
  assert.ok(host.classificationEvidenceIds.length);
  assert.equal(library.hostCandidateId, host.id);
  assert.equal(checks.scope, "test");
  assert.ok(!diagramModel(s).nodes.some((n) => n.id === checks.id));
  assert.ok(
    diagramModel(s, { showSupporting: true }).nodes.some(
      (n) => n.id === checks.id,
    ),
  );
  assert.ok(
    diagramModel(s)
      .nodes.find((n) => n.id === host.id)
      .memberIds.includes(library.id),
  );
  assert.ok(
    diagramModel(s, { level: "focus", focus: library.id }).nodes.some(
      (n) => n.id === library.id,
    ),
  );
});
function graphModel() {
  const nodes = ["a", "b", "c"].map((id) => ({
    id,
    name: id,
    type: "process",
    basis: "source observation",
    reviewState: "pending",
    interfaceIds: [],
    evidenceIds: [],
  }));
  const flows = Array.from({ length: 200 }, (_, i) => ({
    id: `f${i}`,
    source: "a",
    target: "b",
    protocol: "HTTP",
    name: "GET item",
    basis: "static endpoint match",
    reviewState: "pending",
    interfaceIds: [`i${i}`],
    evidenceIds: [`e${i}`],
  }));
  return {
    title: "Example",
    components: nodes,
    entities: [],
    flows,
    domains: [],
    boundaries: [],
    actors: [{ id: "actor", entryIds: ["a"], reviewState: "pending" }],
    threats: [],
  };
}
test("aggregation preserves all evidence and security distinctions; cycles and actor traversal remain finite", () => {
  const s = graphModel();
  const d = diagramModel(s);
  assert.equal(d.connections.length, 1);
  assert.equal(d.connections[0].flowIds.length, 200);
  assert.equal(d.connections[0].evidenceIds.length, 200);
  s.flows.push(
    { ...s.flows[0], id: "reverse", source: "b", target: "a" },
    { ...s.flows[0], id: "other-controls", controls: "mTLS" },
    {
      ...s.flows[0],
      id: "rejected",
      source: "b",
      target: "c",
      reviewState: "rejected",
    },
  );
  const next = diagramModel(s, { actor: "actor" });
  assert.equal(next.connections.length, 3);
  assert.equal(selectedPath(s, "actor").length, 202);
  const l = layoutDiagram(next);
  assert.equal(l.positions.size, 3);
  assert.ok(
    [...l.positions.values()].every(
      (p) => Number.isFinite(p.x) && Number.isFinite(p.y),
    ),
  );
  const limited = diagramModel(s, { limit: 1 });
  assert.ok(limited.coverage.omittedConnections > 0);
  assert.equal(limited.connections.length, 0);
});
test("unresolved peers are retained in coverage and opt-in views; selected exports preserve member IDs", async (t) => {
  const { root, manifest } = await fixture(t, {
    web: { "app.js": "fetch('/missing');" },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m);
  assert.equal(diagramModel(s).connections.length, 0);
  assert.ok(diagramModel(s).coverage.unresolvedRelationships > 0);
  const d = diagramModel(s, { showUnresolved: true, showSupporting: true });
  assert.equal(d.connections.length, 1);
  assert.ok(systemSvg(m).includes("No matched connections"));
  const mermaid = systemMermaid(m, {
    showUnresolved: true,
    showSupporting: true,
    level: "context",
    lens: "network",
  });
  assert.match(mermaid, /context; network/);
  assert.ok(mermaid.includes(d.connections[0].flowIds[0]));
  assert.doesNotMatch(
    systemMermaid(m),
    /Unknown HTTP caller|Unresolved HTTP destination/,
  );
});

test("shadowed request variables and cross-project configuration do not create links", async (t) => {
  const { root, manifest } = await fixture(t, {
    web: {
      "a.cs":
        'class A { const string route = "/items"; void Call(string route) { client.GetAsync(route); } }',
    },
    api: { "app.js": "app.get('/items', handler);" },
  });
  const m = await analyze(manifest, { sourceRoot: root });
  assert.equal(m.connectionDiscovery.flows.length, 0);
});

test("actor traversal follows more than six hops and excludes stale connections", () => {
  const s = graphModel();
  s.components = Array.from({ length: 10 }, (_, i) => ({
    id: String(i),
    name: `Service ${i}`,
    type: "process",
    interfaceIds: [],
    evidenceIds: [],
  }));
  s.actors = [{ id: "actor", entryIds: ["0"] }];
  s.flows = Array.from({ length: 9 }, (_, i) => ({
    id: `edge${i}`,
    source: String(i),
    target: String(i + 1),
    basis: "static endpoint match",
    reviewState: i === 8 ? "stale" : "pending",
    interfaceIds: [],
    evidenceIds: [],
  }));
  assert.equal(selectedPath(s, "actor").length, 8);
});

test("base assignment after the call remains unresolved; named service configuration resolves", async (t) => {
  const { root, manifest } = await fixture(t, {
    web: {
      "a.cs":
        'client.GetAsync("/items"); client.BaseAddress = new Uri("https://api");',
    },
    other: {
      "a.cs": 'client.GetAsync(configuration["ServiceRoot"] + "items");',
      "settings.json": '{"ServiceRoot":"https://api/"}',
    },
    api: {
      "app.js": "app.get('/items', handler);",
      "settings.json": '{"Urls":"https://api"}',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root });
  assert.equal(m.connectionDiscovery.flows.length, 1);
  assert.ok(
    m.connectionDiscovery.gaps.some(
      (g) => g.reason === "base-address-order-unresolved",
    ),
  );
});
