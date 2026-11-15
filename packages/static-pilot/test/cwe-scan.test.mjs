import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyze } from "../src/engine.mjs";
import { scanCwe, scannerProcess, cweCsv, cweSarif } from "../src/cwe-scan.mjs";
import { serve } from "../src/server.mjs";
const scanner = process.env.SYNTHESIS_TEST_SEMGREP;
async function fixture(t, count = 1) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-cwe-test-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifest = { profile: "test", repositories: [] };
  for (let i = 0; i < count; i++) {
    const name = "repo" + i;
    manifest.repositories.push({ name, selected: true });
    await fs.mkdir(path.join(root, name));
    await fs.writeFile(
      path.join(root, name, "bad.py"),
      "import requests\nrequests.get('https://example.test', verify=False)\n",
    );
    await fs.writeFile(
      path.join(root, name, "safe.py"),
      "import requests\nrequests.get('https://example.test', verify=True)\n",
    );
  }
  const model = await analyze(manifest, { sourceRoot: root });
  return { root, manifest, model };
}
test("missing and wrong scanner versions fail explicitly with zero tokens", async (t) => {
  const f = await fixture(t);
  for (const scanner of [
    path.join(f.root, "missing-scanner"),
    process.execPath,
  ]) {
    const r = await scanCwe(f.manifest, f.model, {
      sourceRoot: f.root,
      scanner,
    });
    assert.equal(r.status, "failed");
    assert.equal(r.tokens, 0);
    assert.equal(r.findings.length, 0);
    assert.match(r.error, /could not start|version mismatch/);
  }
});
test("scanner strips provider credentials and obeys cancellation and output limits", async (t) => {
  const f = await fixture(t);
  const previous = process.env.CLAUDE_API_KEY;
  process.env.CLAUDE_API_KEY = "must-not-leak";
  t.after(() => {
    if (previous === undefined) delete process.env.CLAUDE_API_KEY;
    else process.env.CLAUDE_API_KEY = previous;
  });
  const result = await scannerProcess(
    process.execPath,
    ["-e", "process.stdout.write(String(process.env.CLAUDE_API_KEY))"],
    { cwd: f.root, home: f.root },
  );
  assert.equal(result.text, "undefined");
  const controller = new AbortController();
  const task = scannerProcess(
    process.execPath,
    ["-e", "setInterval(()=>{},1000)"],
    { cwd: f.root, home: f.root, signal: controller.signal },
  );
  setTimeout(() => controller.abort(), 150);
  await assert.rejects(task, /cancelled/);
  await assert.rejects(
    scannerProcess(
      process.execPath,
      ["-e", 'process.stdout.write("x".repeat(51*1024*1024))'],
      { cwd: f.root, home: f.root },
    ),
    /output limit/,
  );
});
test("CWE API requires a current graph and exports explicit engine failure", async (t) => {
  const f = await fixture(t),
    app = await serve({
      sourceRoot: f.root,
      port: 0,
      quiet: true,
      cweScanner: process.execPath,
    });
  t.after(() => app.close());
  const base = app.url.split("/#")[0];
  const api = async (route, data) =>
    fetch(base + "/api/" + route, {
      method: data === undefined ? "GET" : "POST",
      headers: {
        "X-Synthesis-Token": app.token,
        "Content-Type": "application/json",
      },
      ...(data === undefined ? {} : { body: JSON.stringify(data) }),
    });
  const wait = async () => {
    for (let i = 0; i < 150; i++) {
      if ((await (await api("status")).json()).status === "ready") return;
      await new Promise((r) => setTimeout(r, 30));
    }
    throw Error("job did not finish");
  };
  assert.equal((await api("cwe", {})).status, 409);
  await api("analyze", f.manifest);
  await wait();
  const model = await (await api("model")).json();
  assert.equal((await api("cwe", { modelRevision: "wrong" })).status, 409);
  assert.equal(
    (await api("cwe", { modelRevision: model.modelRevision })).status,
    202,
  );
  await wait();
  const r = await (await api("model")).json();
  assert.equal(r.cweReview.status, "failed");
  assert.equal((await api("export?format=cwe-sarif")).status, 200);
});
test(
  "qualified engine scans 12 local repositories with hashes, coverage and safe exports",
  { skip: !scanner, timeout: 180000 },
  async (t) => {
    const f = await fixture(t, 12),
      events = [];
    const r = await scanCwe(f.manifest, f.model, {
      sourceRoot: f.root,
      scanner,
      trace: async (e) => events.push(e),
    });
    assert.equal(r.status, "completed", JSON.stringify(r.repositories));
    assert.equal(r.findings.length, 12);
    assert.ok(
      r.repositories.every(
        (r) => r.matchesGraphSnapshot && r.scannedFiles === 2,
      ),
    );
    assert.ok(
      r.findings.every(
        (f) => f.cwe === "CWE-295" && f.path === "bad.py" && f.line === 2,
      ),
    );
    assert.equal(
      events.filter((e) => e === "cwe.repository-completed").length,
      12,
    );
    assert.doesNotMatch(JSON.stringify(r), /verify=False|requests.get/);
    assert.match(cweCsv(r), /CWE-295/);
    assert.equal(cweSarif(r).runs[0].results.length, 12);
    await fs.writeFile(
      path.join(f.root, "repo0", "bad.py"),
      "import pickle\npickle.loads(data)\n",
    );
    f.manifest.repositories = f.manifest.repositories.slice(0, 1);
    const changed = await scanCwe(f.manifest, f.model, {
      sourceRoot: f.root,
      scanner,
    });
    assert.equal(changed.status, "partial");
    assert.equal(changed.repositories[0].matchesGraphSnapshot, false);
  },
);
test(
  "every bundled CWE rule has a positive fixture and safe alternatives do not match",
  { skip: !scanner, timeout: 60000 },
  async (t) => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), "synthesis-rule-test-"),
    );
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    await fs.cp(
      new URL("./fixtures/cwe", import.meta.url),
      path.join(root, "rules"),
      { recursive: true },
    );
    const manifest = {
        profile: "test",
        repositories: [{ name: "rules", selected: true }],
      },
      model = await analyze(manifest, { sourceRoot: root });
    const r = await scanCwe(manifest, model, { sourceRoot: root, scanner });
    assert.equal(r.status, "completed", JSON.stringify(r.repositories));
    assert.ok(r.findings.every((f) => f.path.startsWith("positive.")));
    assert.deepEqual(
      [...new Set(r.findings.map((f) => f.ruleId))].sort(),
      r.rulePack.rules.map((r) => r.id).sort(),
    );
  },
);

test(
  "scanner includes tests and ignores target ignore directives, while parser gaps remain explicit",
  { skip: !scanner, timeout: 60000 },
  async (t) => {
    const f = await fixture(t);
    await fs.mkdir(path.join(f.root, "repo0", "tests"));
    await fs.writeFile(
      path.join(f.root, "repo0", "tests", "bad.py"),
      "import requests\nrequests.get('https://example.test', verify=False) # nosemgrep\n",
    );
    await fs.writeFile(path.join(f.root, "repo0", ".semgrepignore"), "*.py\n");
    const model = await analyze(f.manifest, { sourceRoot: f.root });
    const r = await scanCwe(f.manifest, model, { sourceRoot: f.root, scanner });
    assert.equal(r.status, "completed", JSON.stringify(r.repositories));
    assert.equal(r.findings.length, 2);
    assert.equal(r.repositories[0].scannedFiles, 3);
    await fs.writeFile(
      path.join(f.root, "repo0", "invalid.py"),
      'import requests\nrequests.get("https://example.test", verify=False)\ndef broken(\n',
    );
    const broken = await analyze(f.manifest, { sourceRoot: f.root });
    const report = await scanCwe(f.manifest, broken, {
      sourceRoot: f.root,
      scanner,
    });
    assert.equal(report.status, "partial");
    assert.ok(report.repositories[0].errors.length);
  },
);
