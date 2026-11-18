import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { sha } from "../src/sources.mjs";
import { cweEvidence } from "../src/cwe-evidence.mjs";
async function fixture(t) {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-code-evidence-"),
  );
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "service"));
  const code = Array.from({ length: 220 }, (_, i) => `# line ${i + 1}`).join(
    "\n",
  );
  await fs.writeFile(path.join(root, "service", "app.py"), code);
  const ref = {
    repository: "service",
    path: "app.py",
    line: 35,
    endLine: 190,
    blobSha256: sha(code),
  };
  return {
    root,
    code,
    ref,
    manifest: { profile: "static", repositories: [{ name: "service" }] },
    model: {
      modelRevision: "snapshot",
      cweReview: {
        basedOnRevision: "snapshot",
        findings: [{ id: "scanner", ...ref }],
      },
      cweModelReview: {
        basedOnRevision: "snapshot",
        findings: [
          {
            id: "model",
            locations: [ref, { ...ref, line: 200, endLine: 201 }],
          },
        ],
      },
    },
  };
}
const request = (origin = "scanner", extra = {}) => ({
  origin,
  id: origin,
  modelRevision: "snapshot",
  ...extra,
});
test("scanner and model evidence show bounded context, exact cited ranges and additional locations", async (t) => {
  const f = await fixture(t);
  for (const origin of ["scanner", "model"]) {
    const first = await cweEvidence(
      f.model,
      f.manifest,
      f.root,
      request(origin),
    );
    assert.equal(first.startLine, 15);
    assert.equal(first.endLine, 94);
    assert.equal(first.citedStart, 35);
    assert.equal(first.citedEnd, 190);
    assert.equal(first.lines.length, 80);
    assert.equal(first.hasMore, true);
    const last = await cweEvidence(
      f.model,
      f.manifest,
      f.root,
      request(origin, { page: 2 }),
    );
    assert.equal(last.startLine, 175);
    assert.equal(last.hasMore, false);
    await assert.rejects(
      cweEvidence(f.model, f.manifest, f.root, request(origin, { page: 3 })),
      /No further/,
    );
  }
  assert.equal(
    (
      await cweEvidence(
        f.model,
        f.manifest,
        f.root,
        request("model", { location: 1 }),
      )
    ).citedStart,
    200,
  );
});
test("evidence rejects changed files, stale reviews, unknown IDs and invalid request locations", async (t) => {
  const f = await fixture(t);
  for (const value of [
    { origin: "other" },
    { id: "unknown" },
    { location: -1 },
    { location: 1 },
    { page: -1 },
    { page: 1.5 },
    { modelRevision: "old" },
  ])
    await assert.rejects(
      cweEvidence(f.model, f.manifest, f.root, request("scanner", value)),
    );
  f.model.cweReview.basedOnRevision = "old";
  await assert.rejects(
    cweEvidence(f.model, f.manifest, f.root, request()),
    /older source snapshot/,
  );
  f.model.cweReview.basedOnRevision = "snapshot";
  await fs.writeFile(path.join(f.root, "service", "app.py"), "changed");
  await assert.rejects(
    cweEvidence(f.model, f.manifest, f.root, request()),
    /Source has changed/,
  );
});
test("source selection, containment, symlink and redaction checks apply before displaying code", async (t) => {
  const f = await fixture(t);
  f.manifest.repositories[0].selected = false;
  await assert.rejects(
    cweEvidence(f.model, f.manifest, f.root, request()),
    /selected local clone/,
  );
  f.manifest.repositories[0].selected = true;
  f.model.cweReview.findings[0].path = "../elsewhere";
  await assert.rejects(
    cweEvidence(f.model, f.manifest, f.root, request()),
    /cannot be verified/,
  );
  f.model.cweReview.findings[0].path = "link.py";
  await fs.symlink("app.py", path.join(f.root, "service", "link.py"));
  await assert.rejects(
    cweEvidence(f.model, f.manifest, f.root, request()),
    /cannot be verified/,
  );
  const code =
    "# <img src=x onerror=alert(1)>\n-----BEGIN PRIVATE KEY-----\nsensitive-key-material\n-----END PRIVATE KEY-----\n";
  await fs.writeFile(path.join(f.root, "service", "app.py"), code);
  Object.assign(f.model.cweReview.findings[0], {
    path: "app.py",
    line: 1,
    endLine: 1,
    blobSha256: sha(code),
  });
  const result = await cweEvidence(f.model, f.manifest, f.root, request());
  assert.match(result.lines[0].text, /<img/); // The UI must escape source text, not interpret it.
  assert.ok(!JSON.stringify(result).includes("sensitive-key-material"));
  await fs.unlink(path.join(f.root, "service", "app.py"));
  await assert.rejects(
    cweEvidence(f.model, f.manifest, f.root, request()),
    (error) => !error.message.includes(f.root),
  );
});

test("code evidence endpoint requires workspace access and resolves saved findings rather than client paths", async (t) => {
  const f = await fixture(t);
  const { analyze } = await import("../src/engine.mjs");
  const { workspaceStore } = await import("../src/workspace-store.mjs");
  const { serve } = await import("../src/server.mjs");
  const state = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-evidence-state-"),
  );
  t.after(() => fs.rm(state, { recursive: true, force: true }));
  const model = await analyze(f.manifest, { sourceRoot: f.root });
  model.cweReview = {
    ...f.model.cweReview,
    basedOnRevision: model.modelRevision,
  };
  const store = await workspaceStore(await fs.realpath(f.root), state);
  await store.save({ manifest: f.manifest, model });
  await store.close();
  const app = await serve({
    sourceRoot: f.root,
    workspace: state,
    persist: true,
    port: 0,
    quiet: true,
  });
  try {
    const url =
      app.url.split("/#")[0] +
      "/api/cwe/evidence?" +
      new URLSearchParams({
        ...request(),
        modelRevision: model.modelRevision,
        path: "/etc/passwd",
      });
    assert.equal((await fetch(url)).status, 401);
    const res = await fetch(url, {
      headers: { "X-Synthesis-Token": app.token },
    });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).path, "app.py");
    const changed = await fetch(url + "&id=missing", {
      headers: { "X-Synthesis-Token": app.token },
    });
    assert.equal(changed.status, 409);
  } finally {
    await app.close();
    await fs.rm(state, { recursive: true, force: true });
  }
});
