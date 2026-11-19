import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { sha } from "../src/sources.mjs";
import { cweEvidenceReport } from "../src/evidence-report.mjs";
import { systemReport, systemPrintReport } from "../src/system-exports.mjs";
import { workspaceStore } from "../src/workspace-store.mjs";
import { serve } from "../src/server.mjs";

import { reportFixture } from "./report-fixture.mjs";

test("evidence report includes verified scanner/model code, gaps, provenance and incomplete coverage", async (t) => {
  const f = await reportFixture();
  t.after(() => fs.rm(f.dir, { recursive: true, force: true }));
  const html = await cweEvidenceReport(f.model, f.manifest, f.root);
  assert.match(html, /verify=False/);
  assert.match(html, /class="code-line cited"/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /2 candidates/);
  assert.match(html, /1 \/ 12 packets completed, 11 pending/);
  assert.match(html, /2 locations include verified code; 1 unavailable/);
  assert.match(html, /not-assessed/);
  assert.match(html, /missing.py/);
  assert.match(html, /Verify certificates and hostnames/);
  assert.match(html, new RegExp(f.ref.blobSha256));
  assert.match(html, /not deduplicated vulnerabilities/);
  const redacted = await cweEvidenceReport(f.model, f.manifest, f.root, {
    secrets: ["verify=False"],
  });
  assert.doesNotMatch(redacted, /verify=False/);
  assert.match(redacted, /\[REDACTED\]/);
  await fs.writeFile(path.join(f.root, "service", "app.py"), "changed code");
  const changed = await cweEvidenceReport(f.model, f.manifest, f.root);
  assert.doesNotMatch(changed, /verify=False/);
  assert.match(changed, /Source has changed/);
  f.model.cweReview.basedOnRevision = "old";
  const stale = await cweEvidenceReport(f.model, f.manifest, f.root);
  assert.match(stale, /STALE SOURCE REVIEW/);
  assert.match(stale, /older source snapshot/);
  const threat = systemReport(f.model);
  for (const heading of [
    "Overall system DFD",
    "STRIDE matrix",
    "Threat register",
    "Supporting evidence",
  ])
    assert.ok(threat.includes(heading));
  assert.match(threat, /@page\{size:A4/);
});

test("source report export requires workspace access and works with model-only findings", async (t) => {
  const f = await reportFixture();
  t.after(() => fs.rm(f.dir, { recursive: true, force: true }));
  delete f.model.cweReview;
  const store = await workspaceStore(f.root, f.workspace);
  await store.save({ manifest: f.manifest, model: f.model });
  await store.close();
  const app = await serve({
    sourceRoot: f.root,
    workspace: f.workspace,
    persist: true,
    port: 0,
    quiet: true,
  });
  t.after(() => app.close());
  const url = app.url.split("/#")[0] + "/api/export?format=cwe-evidence-html";
  assert.equal((await fetch(url)).status, 401);
  const response = await fetch(url, {
    headers: { "X-Synthesis-Token": app.token },
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);
  const html = await response.text();
  assert.match(html, /1 candidates/);
  assert.match(html, /verify=False/);
  assert.match(html, /Scanner: not run/);
});

test("print projection excludes checklist detail and long code ranges disclose omissions", async (t) => {
  const f = await reportFixture();
  t.after(() => fs.rm(f.dir, { recursive: true, force: true }));
  const source = Array.from(
    { length: 500 },
    (_, n) => `# code line ${n + 1}`,
  ).join("\n");
  await fs.writeFile(path.join(f.root, "service", "app.py"), source);
  Object.assign(f.model.cweReview.findings[0], {
    line: 1,
    endLine: 499,
    blobSha256: sha(source),
  });
  delete f.model.cweModelReview;
  const html = await cweEvidenceReport(f.model, f.manifest, f.root);
  assert.match(html, /four included code windows/);
  assert.match(html, /1 limited by report budgets/);
  assert.doesNotMatch(html, /# code line 499/);
  const printed = systemPrintReport(f.model);
  assert.match(printed, /excludes repeated checklist text/);
  assert.match(printed, /STRIDE analysis has not run/);
  assert.match(printed, /No threat scenarios recorded/);
  assert.match(printed, /Security controls/);
  assert.match(printed, /Trust domains and data assets/);
});

test("portfolio evidence report includes all twelve repositories and findings without a CWE mapping", async (t) => {
  const f = await reportFixture();
  t.after(() => fs.rm(f.dir, { recursive: true, force: true }));
  const bytes = await fs.readFile(path.join(f.root, "service", "app.py"));
  f.model.cweReview.findings = [];
  delete f.model.cweModelReview;
  for (let n = 0; n < 12; n++) {
    const name = `repo${n}`;
    await fs.mkdir(path.join(f.root, name));
    await fs.writeFile(path.join(f.root, name, "app.py"), bytes);
    f.manifest.repositories.push({ name });
    f.model.cweReview.findings.push({
      id: `scan${n}`,
      ...f.ref,
      repository: name,
      cwe: n === 11 ? null : "CWE-295",
      kind: n === 11 ? "control-gap" : "code-weakness",
      title: `Review ${name}`,
      status: "needs-review",
    });
  }
  const html = await cweEvidenceReport(f.model, f.manifest, f.root);
  assert.match(html, /12 candidates/);
  assert.match(html, /12 locations include verified code; 0 unavailable/);
  assert.match(html, /No CWE mapping - Review repo11/);
  for (let n = 0; n < 12; n++)
    assert.ok(html.includes(`repo${n} / app.py:3-3`));
});
