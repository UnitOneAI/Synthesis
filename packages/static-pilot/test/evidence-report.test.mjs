import { cleanupAfter } from "./cleanup.mjs";
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

test("evidence report includes verified scanner/model code, gaps and evidence provenance", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
  const html = await cweEvidenceReport(f.model, f.manifest, f.root);
  assert.match(html, /verify=False/);
  assert.match(html, /class="code-line cited"/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /2 candidates/);
  assert.doesNotMatch(html, /packets completed, 11 pending/);
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
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
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
  cleanupAfter(t, () => app.close());
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
  assert.doesNotMatch(html, /Scanner: not run/);
});

test("print projection excludes checklist detail and long code ranges disclose omissions", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
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
  assert.match(printed, /planning inputs, not completed threat analysis/);
  assert.match(printed, /STRIDE analysis has not run/);
  assert.match(printed, /No current threat scenarios recorded/);
  assert.doesNotMatch(printed, /<h2>Security controls/);
  assert.doesNotMatch(printed, /<h2>Trust domains and data assets/);
});

test("portfolio evidence report includes all twelve repositories and findings without a CWE mapping", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
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

test("partial STRIDE PDFs show results context; stale exports omit findings and planning registers", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
  f.model.aiReview = {
    status: "partial",
    basedOnRevision: f.model.modelRevision,
    stopReason: "request-budget",
    threats: [],
    connections: [],
    questions: [],
    batches: [],
    coverage: {
      completedBatches: 2,
      totalBatches: 450,
      failedBatches: 1,
      pendingBatches: 447,
    },
  };
  const html = systemPrintReport(f.model);
  for (const text of [
    "Partial STRIDE review",
    "2 / 450 STRIDE packets completed; 1 failed; 447 pending",
    "Threat actors",
    "Trust boundaries",
    "Overall system DFD",
    "STRIDE matrix",
    "latest available review checkpoint",
    "Exporting does not stop or restart analysis",
  ])
    assert.ok(html.includes(text), text);
  f.model.aiReview.status = "stale";
  const stale = systemPrintReport(f.model);
  assert.match(stale, /Historical STRIDE review/);
  assert.match(stale, /historical, not current valid coverage/);
  assert.match(stale, /2 \/ 450 STRIDE packets/);
  assert.match(stale, /No current STRIDE results/);
  assert.doesNotMatch(
    stale,
    /<h2>Threat actors|<h2>Trust boundaries|<h2>STRIDE matrix|<h2>Threat details/,
  );
});

test("default shareable reports embed UnitOne branding and omit only requested presentation fields", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
  const omitted = [
    "Community Edition does not provide compiler-level cross-file or cross-repository taint resolution.",
    "Requested CWE coverage and STRIDE review remain separate scope obligations.",
  ];
  f.model.cweReview.limitations = [omitted[0], "Retained scanner limitation."];
  f.model.cweModelReview.limitations = [
    omitted[1],
    "Retained model limitation.",
  ];
  const before = structuredClone({
    scanner: f.model.cweReview,
    review: f.model.cweModelReview,
  });
  const html = await cweEvidenceReport(f.model, f.manifest, f.root);
  const printed = systemPrintReport(f.model);
  const logo = await fs.readFile(
    new URL("../src/assets/unitone-logo.png", import.meta.url),
  );
  for (const report of [html, printed]) {
    assert.ok(
      report.includes("data:image/png;base64," + logo.toString("base64")),
    );
    assert.match(report, /alt="UnitOne logo"/);
    assert.match(report, /Confidential — Do not share/);
    assert.match(report, /img-src data:/);
    assert.doesNotMatch(report, /Generated \d{4}|Finding index/);
  }
  for (const text of [
    ...omitted,
    "Scanner and model records retain separate identities",
    "Missing or changed source is explicitly excluded.",
    "Candidate assessment: not-run",
    "1 / 12 packets completed",
  ])
    assert.ok(!html.includes(text), text);
  assert.match(html, /Retained scanner limitation/);
  assert.match(html, /Retained model limitation/);
  assert.match(
    html,
    /Disposition: needs-review · Evidence assessment: not-assessed/,
  );
  assert.match(html, /Code evidence is unavailable/);
  assert.deepEqual(
    { scanner: f.model.cweReview, review: f.model.cweModelReview },
    before,
  );
});

test("CWE summary counts records once, keeps unmapped issues and counts distinct repositories", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
  f.model.cweModelReview.findings.push({
    ...f.model.cweModelReview.findings[0],
    id: "unmapped",
    cwe: null,
    kind: "control-gap",
    locations: [f.ref, f.ref, { ...f.ref, repository: "other-repository" }],
  });
  const html = await cweEvidenceReport(f.model, f.manifest, f.root);
  const summary = html.match(/<table class="cwe-summary">[\s\S]*?<\/table>/)[0];
  assert.match(
    summary,
    /<td>CWE-295<\/td><td>2<\/td><td>1<\/td><td>1<\/td><td>1<\/td>/,
  );
  assert.match(
    summary,
    /<td>No CWE mapping<\/td><td>1<\/td><td>0<\/td><td>1<\/td><td>2<\/td>/,
  );
  assert.match(
    summary,
    /<td>Total<\/td><td>3<\/td><td>1<\/td><td>2<\/td><td>2<\/td>/,
  );
  assert.match(
    html,
    /Counts describe candidate records, not confirmed vulnerabilities/,
  );
});

test("shareable STRIDE report gates findings on current results and explains source, actor and action", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
  const iface = f.model.interfaces.find((i) => i.kind !== "architecture");
  assert.ok(iface);
  const threat = {
    id: "returned-threat",
    title: "Certificate verification bypass",
    category: "Information Disclosure",
    actor: "Network intermediary",
    startingAccess: "Access to the outbound network path",
    asset: "API response",
    scenario:
      "A network intermediary could alter the response if verification is disabled.",
    prerequisites: "Traffic interception capability",
    controls: "Certificate verification is disabled at the cited call",
    mitigation: "Enable certificate verification",
    interfaceIds: [iface.id],
    evidenceIds: iface.evidence,
  };
  f.model.aiReview = {
    status: "partial",
    basedOnRevision: f.model.modelRevision,
    threats: [threat],
    connections: [],
    questions: [],
    batches: [],
    coverage: {
      completedBatches: 1,
      totalBatches: 12,
      failedBatches: 0,
      pendingBatches: 11,
    },
  };
  f.model.aiReview.reviewOrder = { policy: "external-first", stages: [{ label: "Potential external entry points", completed: 1, total: 12, failed: 0, pending: 11 }] };
  const before = JSON.stringify({
    review: f.model.aiReview,
    actors: f.model.actors,
    boundaries: f.model.boundaries,
  });
  const html = systemPrintReport(f.model);
  assert.match(html, /1 current returned threat scenarios/);
  assert.match(html, /What needs attention/);
  assert.match(html, /Review order and coverage/);
  assert.match(html, /Potential external entry points/);
  assert.match(
    html,
    /<strong>Access and prerequisites:<\/strong> Network intermediary/,
  );
  assert.match(
    html,
    /<strong>Supporting source:<\/strong> service \/ app.py:3/,
  );
  assert.match(html, /Enable certificate verification/);
  assert.match(html, /awaiting reviewer confirmation/);
  assert.doesNotMatch(
    html,
    /Record ID:|<td>Analysis Quality<\/td>|<td>Assumptions<\/td>/,
  );
  assert.equal(
    JSON.stringify({
      review: f.model.aiReview,
      actors: f.model.actors,
      boundaries: f.model.boundaries,
    }),
    before,
    "report cannot approve or mutate evidence",
  );
  for (const status of ["stale", "failed"]) {
    f.model.aiReview.status = status;
    if (status === "failed") f.model.aiReview.coverage.completedBatches = 0;
    const output = systemPrintReport(f.model);
    assert.match(output, /No current STRIDE results/);
    assert.doesNotMatch(
      output,
      /Certificate verification bypass|Network intermediary|<h2>STRIDE matrix|Review order and coverage/,
    );
  }
  f.model.aiReview.status = "partial";
  f.model.aiReview.coverage.completedBatches = 1;
  f.model.aiReview.basedOnRevision = "older-source";
  assert.doesNotMatch(
    systemPrintReport(f.model),
    /Certificate verification bypass/,
  );
});

test("architecture-only STRIDE responses become context questions, not detailed findings", async (t) => {
  const f = await reportFixture();
  cleanupAfter(t, () => fs.rm(f.dir, { recursive: true, force: true }));
  const iface = f.model.interfaces[0];
  iface.kind = "architecture";
  delete iface.connection;
  f.model.aiReview = {
    status: "partial",
    basedOnRevision: f.model.modelRevision,
    coverage: { completedBatches: 1, totalBatches: 2, pendingBatches: 1 },
    batches: [],
    connections: [],
    questions: [],
    threats: [
      {
        id: "metadata-only",
        title: "Unverified architecture concern",
        category: "Information Disclosure",
        actor: "Caller",
        startingAccess: "Unknown",
        interfaceIds: [iface.id],
        evidenceIds: iface.evidence,
        scenario: "Need implementation evidence",
      },
    ],
  };
  const html = systemPrintReport(f.model);
  assert.match(
    html,
    /0 current returned threat scenarios; 1 architecture-only questions/,
  );
  assert.doesNotMatch(html, /Scenarios identified; 0 scenarios/);
  assert.match(html, /Questions requiring implementation evidence/);
  assert.match(html, /Unverified architecture concern/);
  assert.doesNotMatch(html, /<article id=/);
});

test('threat print explains code, declared configuration and unverified runtime separately', async t => {
  const f=await reportFixture();
  cleanupAfter(t,()=>fs.rm(f.dir,{recursive:true,force:true}));
  const html=systemPrintReport(f.model);
  assert.match(html,/Evidence basis · what was analyzed/);
  assert.match(html,/environment-variable reads and defaults/);
  assert.match(html,/Not analyzed\. No target code, requests, exploit attempts or live-system probes/);
  assert.match(html,/model gateway are not evidence of the target deployment/);
});
