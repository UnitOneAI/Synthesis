import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { unzipSync, strFromU8 } from "fflate";
import { analyze } from "../src/engine.mjs";
import {
  GraphStore,
  attachGraph,
  sqliteSupported,
  EXTRACTOR_KEY,
} from "../src/graph-store.mjs";
import {
  buildGraphPackage,
  graphPackageChoices,
  graphReuse,
  PACKAGE_LIMITS,
  transferBundles,
} from "../src/graph-package.mjs";
import { workspaceStore } from "../src/workspace-store.mjs";
import { serve } from "../src/server.mjs";
import { sha } from "../src/sources.mjs";

async function fixture(t, disk = false) {
  const dir = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-package-")),
  );
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, "repos"),
    workspace = path.join(dir, "state");
  await fs.mkdir(path.join(root, "api"), { recursive: true });
  await fs.mkdir(workspace);
  const text =
    'const password = "do-not-transfer-this";\nfunction load(){ return fetch("https://service.example/items"); }\n';
  await fs.writeFile(path.join(root, "api", "app.js"), text);
  const manifest = {
    title: "Review",
    profile: "test",
    repositories: [{ name: "api", source: "local" }],
  };
  const file = path.join(workspace, "graph.sqlite");
  const model = await analyze(manifest, {
    sourceRoot: root,
    ...(disk ? { graphDatabase: file } : {}),
  });
  model.cweReview = {
    findings: [
      {
        id: "finding-one",
        cwe: "CWE-798",
        title: "Potential credential",
        repository: "api",
        path: "app.js",
        line: 1,
        blobSha256: sha(text),
        status: "needs-review",
      },
    ],
  };
  let reader;
  if (disk) {
    reader = new GraphStore(file, { readOnly: true });
    attachGraph(model.sourceGraph, reader);
    t.after(() => reader.close());
  }
  return { dir, root, workspace, file, model, manifest, reader, text };
}
function unpack(result) {
  const records = [];
  let bundled = 0;
  for (const bundle of result.bundles) {
    assert.ok(bundle.bytes <= PACKAGE_LIMITS.zipBytes);
    const zip = unzipSync(bundle.buffer);
    const manifest = JSON.parse(strFromU8(zip["transfer-manifest.json"]));
    for (const part of manifest.parts) {
      assert.equal(sha(zip[part.name]), part.sha256);
      bundled++;
    }
  }
  assert.equal(bundled, result.parts.length);
  for (const part of result.parts) {
    assert.ok(part.buffer.length <= PACKAGE_LIMITS.zipBytes);
    assert.equal(sha(part.buffer), part.sha256);
    const zip = unzipSync(part.buffer),
      manifest = JSON.parse(strFromU8(zip["manifest.json"]));
    assert.ok(zip["manifest.json"].length <= PACKAGE_LIMITS.manifestBytes);
    assert.ok(zip["records.ndjson"].length <= PACKAGE_LIMITS.partBytes);
    assert.equal(sha(zip["records.ndjson"]), manifest.payload.sha256);
    assert.equal(manifest.parts, result.parts.length);
    records.push(
      ...strFromU8(zip["records.ndjson"])
        .trim()
        .split("\n")
        .filter(Boolean)
        .map(JSON.parse),
    );
  }
  return records;
}
for (const disk of [false, true])
  test(
    `focused export preserves evidence and graph endpoints (${disk ? "sqlite" : "memory"})`,
    { skip: disk && !sqliteSupported() },
    async (t) => {
      const f = await fixture(t, disk);
      const choices = graphPackageChoices(f.model);
      for (const [kind, value] of [
        ["repository", "api"],
        ["finding", "finding-one"],
        ["cwe", "CWE-798"],
        ["component", choices.kinds.component[0].id],
        ["flow", choices.kinds.flow[0].id],
        ["system", ""],
      ]) {
        const result = await buildGraphPackage(f.model, f.manifest, {
          kind,
          value,
        });
        const records = unpack(result);
        assert.ok(records.some((r) => r.type === "graph-node"));
        assert.ok(records.some((r) => r.type === "evidence"));
        assert.ok(!records.some((r) => r.type === "source-context"));
        const ids = new Set(
          records.filter((r) => r.type === "graph-node").map((r) => r.data.id),
        );
        for (const { data: e } of records.filter(
          (r) => r.type === "graph-edge",
        ))
          for (const id of [e.from, e.to].filter(Boolean))
            assert.ok(ids.has(id) || e.missingEndpointIds.includes(id));
        assert.equal(
          result.parts[0].manifest.snapshot.modelRevision,
          f.model.modelRevision,
        );
      }
      const records = unpack(
        await buildGraphPackage(f.model, f.manifest, {
          kind: "repository",
          value: "api",
        }),
      );
      assert.ok(records.some((r) => r.type === "flows"));
      assert.ok(records.some((r) => r.type === "actors"));
      assert.ok(records.some((r) => r.type === "boundaries"));
    },
  );

test(
  "disk neighborhood export follows a cross-repository project edge",
  { skip: !sqliteSupported() },
  async (t) => {
    const f = await fixture(t, true);
    await fs.mkdir(path.join(f.root, "worker"));
    await fs.writeFile(
      path.join(f.root, "api", "a.csproj"),
      '<Project><ItemGroup><ProjectReference Include="../worker/b.csproj" /></ItemGroup></Project>',
    );
    await fs.writeFile(path.join(f.root, "worker", "b.csproj"), "<Project />");
    f.manifest.repositories.push({ name: "worker" });
    const model = await analyze(f.manifest, {
      sourceRoot: f.root,
      graphDatabase: f.file,
    });
    attachGraph(model.sourceGraph, f.reader);
    const records = unpack(
      await buildGraphPackage(model, f.manifest, {
        kind: "repository",
        value: "api",
      }),
    );
    assert.ok(
      records.some(
        (r) => r.type === "graph-node" && r.data.repository === "worker",
      ),
    );
    assert.ok(
      records.some(
        (r) =>
          r.type === "graph-edge" &&
          r.data.kind === "project-reference" &&
          !r.data.missingEndpointIds.length,
      ),
    );
  },
);

test("source context is opt-in, redacted, hash checked and rejects paths and symlinks", async (t) => {
  const f = await fixture(t);
  const options = {
    kind: "finding",
    value: "finding-one",
    includeSource: true,
    sourceRoot: f.root,
  };
  const good = unpack(await buildGraphPackage(f.model, f.manifest, options));
  assert.ok(good.some((r) => r.type === "source-context"));
  assert.ok(!JSON.stringify(good).includes("do-not-transfer-this"));
  await fs.writeFile(
    path.join(f.root, "api", "app.js"),
    "CHANGED_FILE_MUST_NOT_EXPORT",
  );
  const changed = await buildGraphPackage(f.model, f.manifest, options);
  assert.ok(
    changed.coverage.omissions.some((o) => o.reason === "source-hash-mismatch"),
  );
  assert.ok(
    !JSON.stringify(unpack(changed)).includes("CHANGED_FILE_MUST_NOT_EXPORT"),
  );
  f.model.cweReview.findings[0].path = "../../outside.js";
  await fs.writeFile(path.join(f.dir, "outside.js"), f.text);
  const rejected = unpack(
    await buildGraphPackage(f.model, f.manifest, options),
  );
  assert.ok(
    rejected.some(
      (r) =>
        r.type === "source-context-gap" &&
        r.data.reason === "source-path-rejected",
    ),
  );
  if (process.platform !== "win32") {
    await fs.symlink(
      path.join(f.dir, "outside.js"),
      path.join(f.root, "api", "link.js"),
    );
    f.model.cweReview.findings[0].path = "link.js";
    assert.ok(
      unpack(await buildGraphPackage(f.model, f.manifest, options)).some(
        (r) => r.data.reason === "source-symlink-rejected",
      ),
    );
  }
});

test("private-key redaction preserves line numbers even when a window starts inside the key", async (t) => {
  const f = await fixture(t);
  const source = [
    "-----BEGIN RSA PRIVATE KEY-----",
    ...Array(100).fill("SECRET_KEY_MATERIAL"),
    "-----END RSA PRIVATE KEY-----",
    "public_tail",
  ].join("\n");
  await fs.writeFile(path.join(f.root, "api", "app.js"), source);
  Object.assign(f.model.cweReview.findings[0], {
    line: 60,
    blobSha256: sha(source),
  });
  const result = unpack(
    await buildGraphPackage(f.model, f.manifest, {
      kind: "finding",
      value: "finding-one",
      includeSource: true,
      sourceRoot: f.root,
    }),
  );
  assert.ok(!JSON.stringify(result).includes("SECRET_KEY_MATERIAL"));
  const window = result.find((r) => r.type === "source-context").data;
  assert.equal(window.startLine, 40);
  assert.equal(window.lines.find((l) => l.text === "public_tail").line, 103);
});

test("incompressible transfer bundles split below the hard cap without losing parts", () => {
  const parts = Array.from({ length: 16 }, (_, i) => {
    const buffer = randomBytes(256 * 1024);
    return {
      name: `part-${i}.zip`,
      buffer,
      bytes: buffer.length,
      sha256: sha(buffer),
    };
  });
  const bundles = transferBundles("test", parts);
  assert.ok(bundles.length > 1);
  const recovered = [];
  for (const bundle of bundles) {
    assert.ok(bundle.buffer.length <= PACKAGE_LIMITS.zipBytes);
    const zip = unzipSync(bundle.buffer),
      m = JSON.parse(strFromU8(zip["transfer-manifest.json"]));
    for (const p of m.parts) {
      assert.equal(sha(zip[p.name]), p.sha256);
      recovered.push(p.name);
    }
  }
  assert.deepEqual(
    recovered,
    parts.map((p) => p.name),
  );
});

test("large graph splits bounded payloads and reports skipped records and traversal limits", async (t) => {
  const f = await fixture(t);
  f.model.sourceGraph.nodes = Array.from(
    { length: PACKAGE_LIMITS.nodes + 2 },
    (_, i) => ({
      id: "node-" + i,
      kind: "function",
      repository: "api",
      path: "app.js",
      name: "symbol-" + i,
      basis: "Evidence ".repeat(80),
    }),
  );
  f.model.sourceGraph.nodes[1].basis = "x".repeat(
    PACKAGE_LIMITS.recordBytes + 1,
  );
  const result = await buildGraphPackage(f.model, f.manifest, {
    kind: "repository",
    value: "api",
  });
  assert.ok(result.parts.length > 1);
  unpack(result);
  assert.ok(
    result.coverage.omissions.some((o) => o.reason === "oversized-graph-node"),
  );
  assert.ok(
    result.coverage.omissions.some(
      (o) => o.reason === "seed-node-limit-scope-incomplete",
    ),
  );
  assert.equal(
    result.coverage.completeness,
    "bounded-selection-with-omissions",
  );
});

test("export validates scope and redacts configured secrets in all exported strings", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    buildGraphPackage(f.model, f.manifest, {
      kind: "repository",
      value: "missing",
    }),
    /not in this snapshot/,
  );
  await assert.rejects(
    buildGraphPackage(f.model, f.manifest, {
      kind: "finding",
      value: "missing",
    }),
    /not in this snapshot/,
  );
  await assert.rejects(
    buildGraphPackage(f.model, f.manifest, {
      kind: "system",
      includeSource: "true",
    }),
    /explicitly/,
  );
  f.model.diagnostics.push({
    message: "configured-sensitive-value at " + f.root,
  });
  const r = await buildGraphPackage(f.model, f.manifest, {
    kind: "system",
    secrets: ["configured-sensitive-value"],
    sourceRoot: f.root,
  });
  const text = JSON.stringify(unpack(r));
  assert.ok(!text.includes("configured-sensitive-value"));
  assert.ok(!text.includes(f.root));
});

test(
  "restart reuses published graph with no source collection; authenticated export needs no rebuild",
  { skip: !sqliteSupported() },
  async (t) => {
    const f = await fixture(t, true);
    const store = await workspaceStore(f.root, f.workspace);
    await store.save({ model: f.model, manifest: f.manifest });
    await store.close();
    // Source folders can be unavailable for saved-graph review. Optional code context must report this gap.
    await fs.rename(path.join(f.root, "api"), path.join(f.root, "offline"));
    const app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      graphStorage: "sqlite",
      port: 0,
      quiet: true,
    });
    t.after(() => app.close());
    const url = new URL(app.url),
      headers = {
        "X-Synthesis-Token": url.hash.slice(1),
        "Content-Type": "application/json",
      };
    const api = (route, data) =>
      fetch(url.origin + "/api/" + route, {
        headers,
        ...(data ? { method: "POST", body: JSON.stringify(data) } : {}),
      });
    const status = await (await api("status")).json();
    assert.equal(status.status, "ready");
    assert.equal(status.savedGraph.generation, f.model.sourceGraph.generation);
    assert.equal(status.savedGraph.extractor, "current");
    assert.equal(status.savedGraph.workingTree, "not-rechecked");
    const originalGenerationCount = f.reader.db
      .prepare("SELECT count(*) AS n FROM generations")
      .get().n;
    assert.equal(
      (await fetch(url.origin + "/api/graph-package-options")).status,
      401,
    );
    assert.equal(
      (await api("graph-package", { modelRevision: "wrong", kind: "system" }))
        .status,
      409,
    );
    const response = await api("graph-package", {
      modelRevision: f.model.modelRevision,
      kind: "repository",
      value: "api",
      includeSource: false,
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.ok(result.parts.length);
    const download = await api(`graph-package?id=${result.packageId}&part=1`);
    assert.equal(download.status, 200);
    assert.equal(
      sha(Buffer.from(await download.arrayBuffer())),
      result.parts[0].sha256,
    );
    assert.equal(
      (await api(`graph-package?id=${result.packageId}&part=999`)).status,
      400,
    );
    assert.equal(
      f.reader.db.prepare("SELECT count(*) AS n FROM generations").get().n,
      originalGenerationCount,
    );
    assert.equal(graphReuse(f.model).extractor, "current");
    assert.equal(
      graphReuse({
        ...f.model,
        sourceGraph: { ...f.model.sourceGraph, extractorKey: "old" },
      }).extractor,
      "older",
    );
    assert.equal(
      graphReuse(
        {
          ...f.model,
          sourceGraph: { ...f.model.sourceGraph, extractorKey: undefined },
        },
        [EXTRACTOR_KEY],
      ).extractor,
      "current",
    );
  },
);
