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

test("HTTP and HTTPS calls retain separate diagram connections and source transport evidence", async (t) => {
  const { root, manifest } = await fixture(t, {
    web: { "a.js": "fetch('http://api/items'); fetch('https://api/items');" },
    api: {
      "app.js": "app.get('/items', handler);",
      "settings.json":
        '{"Kestrel":{"Endpoints":{"Http":{"Url":"http://api"},"Https":{"Url":"https://api"}}}}',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m),
    d = diagramModel(s);
  assert.equal(d.connections.length, 2);
  assert.deepEqual(
    new Set(d.connections.map((f) => f.transport)),
    new Set(["HTTP", "HTTPS"]),
  );
  assert.match(systemSvg(m), /HTTPS/);
  assert.match(systemMermaid(m), /HTTPS in source URL/);
});

test("internal workers, imported storage and SDK use retain evidence without claiming process separation", async (t) => {
  const { root, manifest } = await fixture(t, {
    app: {
      "server.py":
        'from workers import Consumer\nfrom storage import Store\napp.get("/items", handler)\nworker = Consumer()\nstore = Store()\n',
      "workers.py":
        "import threading\nfrom storage import Store\nclass Consumer:\n    def run(self):\n        store = Store()\n        threading.Thread(target=self.run)\n",
      "storage.py":
        "import sqlite3\nclass Store:\n    def open(self):\n        return sqlite3.connect(self.path)\n",
      "client.py":
        "import anthropic\nclient = anthropic.Anthropic(api_key=secret)\n",
      "tests/test_storage.py":
        'import sqlite3\nconn = sqlite3.connect("test.db")\n',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m),
    d = diagramModel(s);
  const worker = s.components.find((n) => n.internalRole === "worker");
  assert.equal(worker.type, "source-group");
  assert.ok(worker.classificationEvidenceIds.length);
  assert.ok(
    s.flows.some((f) => f.target === worker.id && f.protocol === "in-process"),
  );
  assert.ok(
    s.flows.some((f) => f.source === worker.id && f.protocol === "in-process"),
  );
  assert.ok(d.nodes.some((n) => n.name === "SQLite"));
  assert.ok(d.nodes.some((n) => n.name === "Anthropic client"));
  assert.ok(!d.nodes.some((n) => n.scope === "test"));
  assert.ok(d.nodes.every((n) => n.evidenceIds.length));
  const storage = s.components.find((n) => n.sourceRoot === "storage.py");
  assert.ok(
    diagramModel(s, { level: "focus", focus: storage.id }).nodes.some(
      (n) => n.id === storage.id,
    ),
  );
  assert.match(systemMermaid(m), /SQLite/);
  assert.match(systemSvg(m), /in-process worker candidate/);
});

test("Python re-exports resolve unique calls; imports alone, comments and test resources do not become production edges", async (t) => {
  const { root, manifest } = await fixture(t, {
    app: {
      "server.py":
        "from lib import Worker\nfrom unused import Other\nw = Worker()\n",
      "lib/__init__.py": "from .worker import Worker\n",
      "lib/worker.py":
        "import threading\nclass Worker:\n    def run(self):\n        threading.Thread(target=self.run)\n",
      "unused.py":
        "import threading\nclass Other:\n    def run(self):\n        threading.Thread(target=self.run)\n",
      "comments.py":
        '"""threading.Thread(target=run)\nsqlite3.connect(secret)"""\n# anthropic.Anthropic(secret)\n',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m);
  const worker = s.components.find((n) => n.sourceRoot === "lib/worker.py"),
    unused = s.components.find((n) => n.sourceRoot === "unused.py");
  assert.ok(
    s.flows.some((f) => f.target === worker.id && f.evidenceIds.length >= 3),
  );
  assert.ok(!s.flows.some((f) => f.target === unused.id));
  assert.ok(!s.components.some((n) => n.sourceRoot === "comments.py"));
});

test(
  "twelve .NET repositories include hosted workers, shared SQL, RabbitMQ and WCF dependencies with disk parity",
  { skip: !sqliteSupported() },
  async (t) => {
    const repos = {};
    for (let n = 0; n < 12; n++)
      repos["service" + n] = {
        "Service.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
        "Program.cs":
          "var b = WebApplication.CreateBuilder(args); b.Services.AddHostedService<Worker>();",
        "Worker.cs":
          'class Worker : BackgroundService { void Run() { var c = new SqlConnection(configuration["Database"]); } }',
        "Controller.cs":
          '[Route("items")] class ItemsController { [HttpGet("{id}")] public string Get(int id) => ""; }',
        "Client.cs":
          n < 11
            ? `client.BaseAddress = new Uri(configuration["Api"]); client.GetAsync("items/1");`
            : "",
        "settings.json": JSON.stringify({
          Urls: `https://host${n}`,
          Api: `https://host${n + 1}/`,
          ConnectionStrings: {
            Main: "Server=db;Database=shared;Password=PRIVATE",
          },
          Broker: "amqp://u:PRIVATE@broker/shared",
        }),
        "web.config":
          '<configuration><system.serviceModel><client><endpoint address="https://legacy/service" contract="IService" /></client></system.serviceModel></configuration>',
      };
    const { root, manifest } = await fixture(t, repos);
    const memory = await analyze(manifest, { sourceRoot: root });
    const disk = await analyze(manifest, {
      sourceRoot: root,
      graphDatabase: path.join(root, "graph.sqlite"),
    });
    const a = systemModel(memory),
      b = systemModel(disk);
    assert.deepEqual(a.flows, b.flows);
    assert.equal(
      a.components.filter((c) => c.internalRole === "worker").length,
      12,
    );
    assert.equal(a.flows.filter((f) => f.protocol === "in-process").length, 12);
    assert.ok(a.entities.some((e) => e.type === "broker"));
    assert.equal(
      a.entities.filter((e) => e.name.startsWith("SQL store")).length,
      1,
    );
    assert.equal(
      a.entities.filter((e) => e.name.startsWith("WCF endpoint")).length,
      1,
    );
    assert.equal(a.flows.filter((f) => f.protocol === "SOAP").length, 12);
    assert.doesNotMatch(JSON.stringify(a), /PRIVATE/);
    const repeat = await analyze(manifest, {
      sourceRoot: root,
      graphDatabase: path.join(root, "graph.sqlite"),
    });
    assert.deepEqual(systemModel(repeat).flows, b.flows);
  },
);

test("literal deployment commands connect reverse proxy to collected hosts and retain CLI entry points", async (t) => {
  const { root, manifest } = await fixture(t, {
    app: {
      Dockerfile:
        'FROM node AS builder\nWORKDIR /web\nFROM python\nWORKDIR /app\nCOPY . .\nserver {\n proxy_pass http://127.0.0.1:8000;\n proxy_pass http://127.0.0.1:3000;\n}\n[program:api]\ncommand=/bin/uvicorn api.server:app --host 127.0.0.1 --port 8000\n[program:web]\ncommand=/bin/node server.js\ndirectory=/app/web\nenvironment=PORT="3000"\nEOF\n',
      "api/server.py": '@app.get("/items")\ndef items(): return []\n',
      "web/package.json": '{"scripts":{"start":"next start"}}',
      "pyproject.toml":
        '[project.scripts]\nexample = "cli.main:app"\n[project.urls]\n',
      "cli/main.py": "def app():\n    pass\n",
    },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m);
  const gateway = s.components.find((c) => c.internalRole === "gateway");
  assert.ok(gateway);
  assert.equal(gateway.type, "gateway");
  assert.equal(s.flows.filter((f) => f.source === gateway.id).length, 2);
  assert.ok(
    s.flows
      .filter((f) => f.source === gateway.id)
      .every((f) => f.evidenceIds.length === 2 && f.transport === "HTTP"),
  );
  assert.ok(
    s.components.some((c) => c.name === "example CLI" && c.type === "process"),
  );
});

test("shadowed imported constructors do not create internal connections", async (t) => {
  const { root, manifest } = await fixture(t, {
    app: {
      "server.py":
        "from worker import Worker\ndef run(Worker):\n    Worker()\n",
      "worker.py":
        "import threading\nclass Worker:\n    def run(self):\n        threading.Thread(target=self.run)\n",
    },
  });
  const s = systemModel(await analyze(manifest, { sourceRoot: root }));
  const w = s.components.find((c) => c.internalRole === "worker");
  assert.ok(w);
  assert.ok(!s.flows.some((f) => f.target === w.id));
});

test("worker resource bindings require a unique same-project configuration key", async (t) => {
  const { root, manifest } = await fixture(t, {
    service: {
      "Service.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
      "Worker.cs":
        'class Worker : BackgroundService { void Run() { new SqlConnection(configuration.GetConnectionString("Main")); } }',
      "settings.json":
        '{"ConnectionStrings":{"Main":"Server=db;Database=shared;Password=PRIVATE"}}',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root }),
    s = systemModel(m);
  const worker = s.components.find((c) => c.internalRole === "worker"),
    store = s.entities.find((e) => e.name.startsWith("SQL store"));
  assert.ok(
    s.flows.some(
      (f) =>
        f.source === worker.id &&
        f.target === store.id &&
        f.evidenceIds.length >= 2,
    ),
  );
  assert.ok(!s.entities.some((e) => e.resourceKind === "Database"));
  await fs.writeFile(
    path.join(root, "service", "settings.Production.json"),
    '{"ConnectionStrings":{"Main":"Server=other;Database=prod"}}',
  );
  const conflicting = systemModel(
    await analyze(manifest, { sourceRoot: root }),
  );
  assert.ok(
    !conflicting.flows.some(
      (f) => f.source === worker.id && f.target === store.id,
    ),
  );
  assert.ok(
    conflicting.coverage.connectionGaps.some(
      (g) => g.reason === "resource-identity-unresolved",
    ),
  );
});

test("Python local endpoint constants resolve within their function and fetch methods are not browser HTTP", async (t) => {
  const { root, manifest } = await fixture(t, {
    app: {
      "client.py":
        'import requests\ndef first():\n    url = "https://one.example/api"\n    requests.get(url)\ndef second():\n    url = "https://two.example/api"\n    requests.get(url)\ndef dynamic(url):\n    requests.get(url)\nrepository.fetch()\n',
    },
  });
  const m = await analyze(manifest, { sourceRoot: root });
  assert.equal(m.connectionDiscovery.coverage.httpOutboundCandidates, 3);
  assert.equal(m.connectionDiscovery.flows.length, 2);
  assert.ok(
    m.connectionDiscovery.entities.some(
      (e) => e.name === "HTTP endpoint one.example",
    ),
  );
  assert.ok(
    m.connectionDiscovery.entities.some(
      (e) => e.name === "HTTP endpoint two.example",
    ),
  );
  assert.equal(m.connectionDiscovery.coverage.httpClients, 2);
});

test("presentation ownership follows adapters through libraries to their candidate host", () => {
  const s = graphModel();
  s.components.push(
    {
      id: "library",
      name: "Library",
      type: "source-group",
      hostCandidateId: "a",
      interfaceIds: [],
      evidenceIds: [],
    },
    {
      id: "adapter",
      name: "Client",
      type: "source-group",
      internalRole: "client-adapter",
      parentComponentId: "library",
      interfaceIds: [],
      evidenceIds: [],
    },
  );
  s.flows = [
    { ...s.flows[0], id: "adapter-call", source: "adapter", target: "b" },
  ];
  const d = diagramModel(s);
  assert.equal(d.connections.length, 1);
  assert.equal(d.connections[0].source, "a");
  assert.ok(d.nodes.find((n) => n.id === "a").memberIds.includes("adapter"));
});
