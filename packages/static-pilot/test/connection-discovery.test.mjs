import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyze, compose } from "../src/engine.mjs";
import { systemModel } from "../src/system-model.mjs";
import { systemMermaid } from "../src/system-exports.mjs";
import { GraphStore, sqliteSupported } from "../src/graph-store.mjs";
const manifest = (names) => ({
  profile: "server",
  repositories: names.map((name) => ({ name, selected: true })),
});
test("legacy .NET attribute routes and XML configuration correlate without mixing method routes", async (t) => {
  const root = await fixture(t, {
    client: {
      "client.cs":
        'class Caller { void Run() { client.GetAsync("/api/items/42"); client.PostAsync("/api/items/create", body); } }',
    },
    api: {
      "ItemsController.cs":
        '[RoutePrefix("api/items")] public class ItemsController { [HttpGet] [Route("{id}")] public string Get(int id) => ""; [Route("create")] [HttpPost] public void Create() {} }',
      "web.config":
        '<configuration><appSettings><add key="ServiceUrl" value="https://service.example/api" /></appSettings><connectionStrings><add name="Main" connectionString="Server=db;Database=shared;Password=PRIVATE" /></connectionStrings></configuration>',
    },
    other: {
      "settings.json":
        '{"ConnectionStrings":{"Main":"Server=db;Database=shared;Password=OTHER"}}',
    },
  });
  const model = await analyze(manifest(["client", "api", "other"]), {
    sourceRoot: root,
  });
  assert.equal(model.connectionDiscovery.coverage.httpServers, 2);
  assert.equal(
    model.connectionDiscovery.flows.filter((f) => f.protocol === "HTTP").length,
    2,
  );
  assert.equal(
    model.connectionDiscovery.entities.filter(
      (e) => e.repositories.length === 2,
    ).length,
    1,
  );
  assert.ok(model.interfaces.some((i) => i.connection?.kind === "http-config"));
  assert.doesNotMatch(JSON.stringify(model), /PRIVATE|OTHER/);
});
test("unresolved HTTP patterns are counted and ambiguous C# route declarations are not matched", async (t) => {
  const root = await fixture(t, {
    client: {
      "client.cs":
        'class Caller { void Run() { client.GetAsync(destination); client.GetAsync("/api/a"); } }',
    },
    api: {
      "Controller.cs":
        '[Route("api")] class TestController { [Route("a")] [Route("b")] [HttpGet] public string Get() => ""; }',
    },
  });
  const model = await analyze(manifest(["client", "api"]), {
    sourceRoot: root,
  });
  assert.equal(model.connectionDiscovery.flows.length, 0);
  assert.equal(model.connectionDiscovery.coverage.httpOutboundCandidates, 2);
  assert.equal(model.connectionDiscovery.coverage.httpClients, 1);
  assert.equal(
    model.connectionDiscovery.coverage.gapReasons["http-client-not-resolved"],
    1,
  );
  assert.equal(
    model.connectionDiscovery.coverage.gapReasons["http-route-not-resolved"],
    1,
  );
});
async function fixture(t, repos) {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-connections-"),
  );
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  for (const [repo, files] of Object.entries(repos))
    for (const [p, text] of Object.entries(files)) {
      const file = path.join(dir, repo, p);
      await fs.mkdir(path.dirname(file), { recursive: true });
      await fs.writeFile(file, text);
    }
  return dir;
}
test(
  "disk graph connects 12 repositories and retains evidence through cache/restart/export",
  { skip: !sqliteSupported() },
  async (t) => {
    const repos = {};
    for (let i = 0; i < 12; i++)
      repos["repo" + i] = {
        "app.js": `app.get('/service${i}', handler);\n${i < 11 ? `fetch('https://host${i + 1}/service${i + 1}');` : ""}`,
        "appsettings.json": JSON.stringify({
          Kestrel: { Endpoints: { Https: { Url: `https://host${i}` } } },
        }),
      };
    const root = await fixture(t, repos),
      graphDatabase = path.join(root, "graph.sqlite"),
      m = manifest(Object.keys(repos));
    const first = await analyze(m, { sourceRoot: root, graphDatabase });
    assert.equal(first.connectionDiscovery.flows.length, 11);
    assert.ok(
      first.connectionDiscovery.flows.every(
        (f) => f.basis === "static endpoint match" && f.evidence.length >= 3,
      ),
    );
    assert.equal(
      systemModel(first).flows.filter(
        (f) => f.basis === "static endpoint match",
      ).length,
      11,
    );
    assert.match(systemMermaid(first), /static endpoint match/);
    const second = await analyze(m, { sourceRoot: root, graphDatabase });
    assert.equal(second.sourceGraph.reuse.reusedFiles, 24);
    assert.deepEqual(
      first.connectionDiscovery.flows,
      second.connectionDiscovery.flows,
    );
    const db = new GraphStore(graphDatabase, { readOnly: true });
    assert.equal(
      [
        ...db.nodes(second.sourceGraph.generation, { kind: "interface" }),
      ].filter((n) => n.connection?.role === "client").length,
      11,
    );
    db.close();
    await fs.writeFile(
      path.join(root, "repo1", "app.js"),
      "app.get('/renamed', handler); fetch('https://host2/service2');",
    );
    const third = await analyze(m, { sourceRoot: root, graphDatabase });
    assert.equal(
      third.connectionDiscovery.flows.filter((f) => f.to).length,
      10,
    );
    assert.equal(
      third.connectionDiscovery.flows.filter(
        (f) => f.basis === "static endpoint reference",
      ).length,
      1,
    );
  },
);
test("unique routes remain hypotheses; ambiguous routes and wrong hosts never fabricate links", async (t) => {
  const root = await fixture(t, {
    web: {
      "client.js":
        "fetch('/unique'); fetch('/ambiguous'); fetch('https://wrong/no');",
    },
    a: {
      "app.js":
        "app.get('/unique', handler); app.get('/ambiguous', handler); app.get('/no',handler);",
      "appsettings.json": '{"Urls":"https://correct"}',
    },
    b: { "app.js": "app.get('/ambiguous', handler);" },
    c: { "app.js": "fetch('/missing');" },
  });
  const m = await analyze(manifest(["web", "a", "b", "c"]), {
    sourceRoot: root,
  });
  assert.equal(m.connectionDiscovery.flows.length, 2);
  assert.equal(m.connectionDiscovery.flows[0].basis, "inferred route match");
  const endpoint = m.connectionDiscovery.flows.find(
    (f) => f.basis === "static endpoint reference",
  );
  assert.ok(
    m.connectionDiscovery.entities.some(
      (e) => e.id === endpoint.target && e.name === "HTTP endpoint wrong",
    ),
  );
  assert.ok(!endpoint.to); // Never connect the wrong host to a collected server.
  assert.equal(
    m.connectionDiscovery.gaps.find((g) => g.reason === "ambiguous-route")
      .candidateCount,
    2,
  );
  assert.match(systemMermaid(m), /-\.->/);
  const f = m.connectionDiscovery.flows[0];
  compose(m, {
    bindings: [
      {
        from: f.from,
        to: f.to,
        profile: "server",
        reason: "Verified source wiring",
      },
    ],
  });
  assert.equal(
    systemModel(m).flows.filter(
      (v) => v.source === f.source && v.target === f.target,
    ).length,
    1,
  );
});
test("shared stores retain identity without credentials or conflating databases", async (t) => {
  const root = await fixture(t, {
    a: {
      "appsettings.json":
        '{"ConnectionStrings":{"Main":"Server=db;Database=shared;Password=TOPSECRET;User Id=user"}}',
    },
    b: {
      "appsettings.json":
        '{"ConnectionStrings":{"Main":"Server=db;Database=shared;Password=OTHERSECRET"}}',
    },
    c: {
      "appsettings.json":
        '{"ConnectionStrings":{"Main":"Server=db;Database=other"}}',
    },
  });
  const m = await analyze(manifest(["a", "b", "c"]), { sourceRoot: root });
  assert.equal(m.connectionDiscovery.entities.length, 2);
  assert.equal(m.connectionDiscovery.flows.length, 3);
  assert.equal(
    m.connectionDiscovery.entities.find((e) => e.repositories.length === 2)
      .type,
    "store",
  );
  assert.doesNotMatch(JSON.stringify(m), /TOPSECRET|OTHERSECRET/);
});
test("C# controller and Next routes correlate without documents", async (t) => {
  const root = await fixture(t, {
    web: { "client.js": "fetch('/api/Things/42'); fetch('/api/session');" },
    api: {
      "Things.cs":
        '[Route("api/[controller]")] class ThingsController { [HttpGet("{id}")] public string Get(int id) => ""; }',
    },
    next: {
      "src/app/api/session/route.ts":
        "export async function GET() { return Response.json({}); }",
    },
  });
  const m = await analyze(manifest(["web", "api", "next"]), {
    sourceRoot: root,
  });
  assert.equal(m.connectionDiscovery.flows.length, 2);
});
test("literal queues connect producers and consumers only with a shared configured broker", async (t) => {
  const root = await fixture(t, {
    producer: {
      "send.js": "channel.sendToQueue('orders', data);",
      "settings.json": '{"BrokerUri":"amqp://user:secret@rabbit/vhost"}',
    },
    consumer: {
      "receive.js": "channel.consume('orders', callback);",
      "settings.json": '{"BrokerUri":"amqp://rabbit/vhost"}',
    },
    unknown: { "receive.js": "channel.consume('orders', callback);" },
  });
  const m = await analyze(manifest(["producer", "consumer", "unknown"]), {
    sourceRoot: root,
  });
  const s = systemModel(m),
    queue = s.entities.find((e) => e.basis === "static queue candidate");
  assert.ok(queue);
  assert.equal(
    s.flows.filter((f) => f.source === queue.id || f.target === queue.id)
      .length,
    2,
  );
  assert.equal(
    m.connectionDiscovery.gaps[0].reason,
    "broker-identity-unresolved",
  );
  assert.doesNotMatch(JSON.stringify(m.connectionDiscovery), /user:secret/);
});
test(
  "disk AST wrapper calls connect frontend to prefixed Python routes",
  { skip: !sqliteSupported() },
  async (t) => {
    const root = await fixture(t, {
      frontend: {
        "api.ts":
          'async function request<T>(path: string) { const url = `${API_BASE}${path}`; return fetch(url); }\nconst result = request("/issues/42");',
      },
      backend: {
        "routes.py":
          'router = APIRouter(prefix="/issues")\n@router.get("/{id}")\ndef get_issue(id):\n    return {}\n',
      },
    });
    const m = await analyze(manifest(["frontend", "backend"]), {
      sourceRoot: root,
      graphDatabase: path.join(root, "graph.sqlite"),
    });
    assert.equal(m.connectionDiscovery.flows.length, 1);
    const f = m.connectionDiscovery.flows[0];
    assert.notEqual(f.source, f.target);
    assert.equal(
      m.interfaces.find((i) => i.id === f.from).connection.viaGraphNodeIds
        .length,
      2,
    );
  },
);

test("non-default broker exchanges do not masquerade as direct queue connections", async (t) => {
  const root = await fixture(t, {
    producer: {
      "Service.cs":
        'channel.BasicPublish("custom", routingKey: "orders", body: payload);',
      "settings.json": '{"BrokerUri":"amqp://rabbit/vhost"}',
    },
  });
  const m = await analyze(manifest(["producer"]), { sourceRoot: root });
  assert.equal(
    m.connectionDiscovery.flows.filter(
      (f) => f.basis === "static queue candidate",
    ).length,
    0,
  );
});
