import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync, strToU8 } from "fflate";
import { parseInventory, parseXml, unzipBounded } from "../src/inventory.mjs";
import { analyze, compose, extract, validateManifest } from "../src/engine.mjs";
import { localSource, githubIdentity, sha } from "../src/sources.mjs";
import { reportHtml, diagram } from "../src/report.mjs";
import { serve } from "../src/server.mjs";

const fixtures = fileURLToPath(new URL("../fixtures/", import.meta.url));
const sourceRoot = path.join(fixtures, "repositories");
const manifest = {
  title: "Synthetic pilot",
  profile: "server",
  repositories: ["frontdoor", "business", "setup"].map((name) => ({
    name,
    selected: true,
  })),
};
const modelFixture = () => analyze(manifest, { sourceRoot });
const file = (name, text) => ({ path: name, text, hash: sha(text) });
function workbook(cells, shared = "") {
  return zipSync({
    "xl/workbook.xml": strToU8(
      '<workbook><sheets><sheet name="Repository Classification" r:id="rId1"/></sheets></workbook>',
    ),
    "xl/_rels/workbook.xml.rels": strToU8(
      '<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>',
    ),
    "xl/worksheets/sheet1.xml": strToU8(
      `<worksheet><sheetData>${cells}</sheetData></worksheet>`,
    ),
    ...(shared ? { "xl/sharedStrings.xml": strToU8(shared) } : {}),
  });
}
test("CSV preserves original selections and reports duplicates independently", () => {
  const result = parseInventory(
    Buffer.from(
      'Repository,Description,Recommended initial set\r\napi,"line one, line two",Yes\r\nworker,,No\r\napi,duplicate,No',
    ),
    "scope.csv",
  );
  assert.deepEqual(result.counts, {
    total: 2,
    selected: 1,
    missingDescriptions: 1,
  });
  assert.equal(result.warnings.length, 1);
  assert.equal(result.repositories[0].description, "line one, line two");
});
test("XLSX resolves sparse cells and shared strings", () => {
  const zip = workbook(
    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="G1" t="s"><v>1</v></c></row><row r="2"><c r="A2" t="s"><v>2</v></c><c r="G2" t="s"><v>3</v></c></row>',
    "<sst><si><t>Repository</t></si><si><t>Recommended initial set</t></si><si><t>api</t></si><si><t>Yes</t></si></sst>",
  );
  assert.equal(
    parseInventory(zip, "scope.xlsx").repositories[0].selected,
    true,
  );
});
test("XLSX rejects formulas rather than trusting cached results", () => {
  assert.throws(
    () =>
      parseInventory(
        workbook('<row><c r="A1"><f>1+1</f><v>2</v></c></row>'),
        "scope.xlsx",
      ),
    /formulas/,
  );
});
test("XML entities and archive expansion are bounded", () => {
  assert.throws(
    () =>
      parseXml(
        '<!DOCTYPE x [<!ENTITY bad SYSTEM "file:///etc/passwd">]><x>&bad;</x>',
      ),
    /DTD/,
  );
  assert.throws(
    () => unzipBounded(zipSync({ large: strToU8("x".repeat(500)) }), 100),
    /limit/,
  );
});
test("inventory supports a large portfolio and independently selected pilot", () => {
  const rows = [
    "Repository,Recommended initial set",
    ...Array.from(
      { length: 213 },
      (_, i) => `repo-${i},${i < 13 ? "Yes" : "No"}`,
    ),
  ];
  const r = parseInventory(Buffer.from(rows.join("\n")), "inventory.csv");
  assert.equal(r.counts.total, 213);
  assert.equal(r.counts.selected, 13);
});
test("manifest rejects duplicate IDs, missing profiles, and unknown source types", () => {
  assert.throws(
    () => validateManifest({ ...manifest, profile: "" }),
    /profile/,
  );
  assert.throws(
    () =>
      validateManifest({
        ...manifest,
        repositories: [{ name: "a" }, { name: "A" }],
      }),
    /unique/,
  );
  assert.throws(
    () =>
      validateManifest({
        ...manifest,
        repositories: [{ name: "a", source: "runtime" }],
      }),
    /Source/,
  );
});
test("only bounded HTTPS GitHub repository URLs are accepted", () => {
  assert.deepEqual(githubIdentity("https://github.com/example/a.git"), {
    owner: "example",
    repo: "a",
  });
  for (const u of [
    "https://evil.test/a/b",
    "http://github.com/a/b",
    "https://user:pass@github.com/a/b",
    "https://github.com/a/b?token=secret",
    "https://github.com/a/b/tree/main",
  ])
    assert.throws(() => githubIdentity(u));
});
test("source collection does not follow symlinks, read secrets or execute hooks", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-test-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "repo"));
  await fs.writeFile(path.join(root, "repo", "Code.cs"), '[HttpGet("/safe")]');
  await fs.writeFile(path.join(root, "repo", ".env"), "TOKEN=private-value");
  await fs.writeFile(path.join(root, "outside.cs"), '[HttpGet("/outside")]');
  try {
    await fs.symlink(
      path.join(root, "outside.cs"),
      path.join(root, "repo", "escape.cs"),
    );
  } catch (e) {
    if (process.platform !== "win32") throw e;
  }
  await fs.mkdir(path.join(root, "repo", ".github"));
  await fs.writeFile(
    path.join(root, "repo", ".github", "workflow.yml"),
    "run: echo NOT_EXECUTED",
  );
  await fs.writeFile(
    path.join(root, "repo", "package.json"),
    JSON.stringify({ scripts: { postinstall: "touch SHOULD_NOT_EXIST" } }),
  );
  const s = await localSource({ name: "repo" }, root);
  assert(s.files.some((f) => f.path === ".github/workflow.yml"));
  assert(!s.files.some((f) => f.path === ".env" || f.path === "escape.cs"));
  assert.equal(s.revision, null);
  await assert.rejects(
    () => localSource({ name: "repo", localPath: "../outside" }, root),
    /outside/,
  );
  await assert.rejects(() =>
    fs.access(path.join(root, "repo", "SHOULD_NOT_EXIST")),
  );
});
test("source content changes invalidate snapshot digests", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-digest-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "repo"));
  const f = path.join(root, "repo", "code.cs");
  await fs.writeFile(f, '[Authorize]\n[HttpGet("/x")]');
  const a = await localSource({ name: "repo" }, root);
  await fs.writeFile(f, '[AllowAnonymous]\n[HttpGet("/x")]');
  const b = await localSource({ name: "repo" }, root);
  assert.notEqual(a.snapshot, b.snapshot);
});
test("extractor separates lexical candidates, structured declarations and controls", () => {
  const r = extract({ name: "api" }, [
    file(
      "Controller.cs",
      '// [HttpGet("/comment")]\n[Authorize]\n[HttpGet("/real")]',
    ),
    file("api.json", '{"openapi":"3.0.0","paths":{"/contract":{"get":{}}}}'),
  ]);
  assert(!r.interfaces.some((i) => i.operation.includes("/comment")));
  assert(r.interfaces.some((i) => i.kind === "control"));
  assert(
    r.interfaces
      .find((i) => i.kind === "http-inbound")
      .basis.startsWith("inferred"),
  );
  assert(
    r.interfaces
      .find((i) => i.kind === "http-contract")
      .basis.startsWith("source-supported"),
  );
  assert.equal(r.evidence.find((e) => e.line === 3).path, "Controller.cs");
});
test("malformed configuration cannot leak content in diagnostics", () => {
  const r = extract({ name: "api" }, [
    file("secret.json", '{"password":"SUPER_PRIVATE", broken}'),
  ]);
  assert(!JSON.stringify(r).includes("SUPER_PRIVATE"));
  assert.equal(r.diagnostics[0].kind, "parse-failed");
});

test("installer package declarations preserve individual identities without command secrets", () => {
  const r = extract({ name: "setup" }, [
    file(
      "Bundle.wxs",
      '<Wix><Bundle><Chain><ExePackage Id="DatabasePrerequisite" InstallArguments="password=PRIVATE"/><ExePackage Id="MessageBroker"/></Chain></Bundle></Wix>',
    ),
  ]);
  assert.equal(r.interfaces.length, 2);
  assert.deepEqual(
    r.dependencies.map((d) => d.name),
    ["DatabasePrerequisite", "MessageBroker"],
  );
  assert(!JSON.stringify(r).includes("PRIVATE"));
  assert(r.evidence.some((e) => e.pointer.endsWith("/1")));
});
test("same names and source categories never fabricate cross-repo flows", async () => {
  const m = await modelFixture();
  assert(m.interfaces.length > 10);
  assert.equal(m.flows.length, 0);
  assert.equal(m.boundaries.length, 0);
  assert(
    m.threats.every((t) => t.severity === "unassessed" && t.path.length === 0),
  );
  assert(m.actors.every((a) => a.basis.includes("assumed")));
});
test("reviewed declarations preserve evidence and distinguish trust from repo boundaries", async () => {
  const m = await modelFixture();
  const from = m.interfaces.find((i) => i.kind === "http-outbound"),
    to = m.interfaces.find((i) => i.kind === "http-contract");
  const binding = {
    from: from.id,
    to: to.id,
    profile: "server",
    reason: "Reviewed fixture binding",
    reviewer: "Test reviewer",
    dimension: "privilege",
    before: "User",
    after: "Service",
  };
  const updated = compose(m, { bindings: [binding] });
  assert.equal(updated.flows[0].basis, "declared");
  assert.equal(updated.boundaries[0].basis, "declared");
  assert(updated.declarations.bindings[0].evidenceFingerprint);
  assert.equal(to.basis.startsWith("source-supported"), true);
  assert.throws(
    () =>
      compose(structuredClone(updated), {
        bindings: [{ ...binding, to: "missing" }],
      }),
    /current interface/,
  );
  assert.throws(
    () =>
      compose(structuredClone(updated), {
        bindings: [{ ...binding, profile: "different" }],
      }),
    /profile/,
  );
  assert.throws(
    () => compose(structuredClone(updated), { bindings: [binding, binding] }),
    /one declared destination/,
  );
  const changed = structuredClone(updated);
  changed.sources[0].snapshot = "changed";
  assert.throws(
    () => compose(changed, updated.declarations),
    /snapshots changed/,
  );
});
test("unavailable repositories remain in scope and cannot produce clean coverage", async () => {
  const m = await analyze(
    { ...manifest, repositories: [{ name: "missing" }] },
    { sourceRoot },
  );
  assert.equal(m.sources[0].status, "unavailable");
  assert.equal(m.status, "draft-with-gaps");
  assert.equal(m.threats.length, 0);
  assert(m.diagnostics.some((d) => d.kind === "source-unavailable"));
});
test("exports escape hostile source labels and preserve every scenario", async () => {
  const m = await modelFixture();
  m.title = "<script>alert(1)</script>";
  const html = reportHtml(m),
    svg = diagram(m);
  assert(!html.includes("<script>"));
  assert(!svg.includes("<script>"));
  for (const t of m.threats) assert(html.includes(t.id));
  for (const i of m.interfaces.filter((i) => i.direction !== "control"))
    assert(svg.includes(i.id));
});
test("local server blocks missing tokens, cross-origin access, and arbitrary paths", async (t) => {
  const s = await serve({ sourceRoot, port: 0, quiet: true });
  t.after(() => new Promise((resolve) => s.server.close(resolve)));
  const base = s.url.split("/#")[0];
  assert.equal((await fetch(base + "/api/status")).status, 401);
  assert.equal(
    (
      await fetch(base + "/api/status", {
        headers: { "X-Synthesis-Token": s.token, Origin: "https://evil.test" },
      })
    ).status,
    403,
  );
  assert.equal((await fetch(base + "/package.json")).status, 404);
  const r = await fetch(base + "/api/status", {
    headers: { "X-Synthesis-Token": s.token },
  });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).status, "idle");
});
test("local UI API completes analysis and rejects stale declaration writes", async (t) => {
  const s = await serve({ sourceRoot, port: 0, quiet: true });
  t.after(() => new Promise((resolve) => s.server.close(resolve)));
  const base = s.url.split("/#")[0];
  const headers = {
    "X-Synthesis-Token": s.token,
    "Content-Type": "application/json",
  };
  assert.equal(
    (
      await fetch(base + "/api/analyze", {
        method: "POST",
        headers,
        body: JSON.stringify(manifest),
      })
    ).status,
    202,
  );
  let status;
  for (let i = 0; i < 100; i++) {
    status = await (await fetch(base + "/api/status", { headers })).json();
    if (status.status !== "running") break;
    await new Promise((r) => setTimeout(r, 30));
  }
  assert.equal(status.status, "ready");
  const m = await (await fetch(base + "/api/model", { headers })).json();
  assert(m.interfaces.length > 0);
  assert.equal(
    (
      await fetch(base + "/api/bindings", {
        method: "POST",
        headers,
        body: JSON.stringify({ modelRevision: "stale", bindings: [] }),
      })
    ).status,
    409,
  );
  for (const format of ["html", "svg", "json", "manifest"])
    assert.equal(
      (await fetch(base + "/api/export?format=" + format, { headers })).status,
      200,
    );
});
