import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadCweSourcePayload } from "../src/cwe-source-reader.mjs";
import { sha, LIMITS } from "../src/sources.mjs";

async function fixture(t) {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-cwe-reader-"),
  );
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifest = {
    repositories: [{ name: "service", localPath: "clones/service" }],
  };
  await fs.mkdir(path.join(root, "clones/service"), { recursive: true });
  const code = "function read() {\n  return request.value;\n}\n";
  await fs.writeFile(path.join(root, "clones/service/app.js"), code);
  const ref = {
    id: "segment-1",
    repository: "service",
    path: "app.js",
    blobSha256: sha(code),
    startLine: 1,
    endLine: 3,
  };
  return { root, manifest, code, ref };
}

test("planned CWE windows read each referenced file once without walking repositories", async (t) => {
  const f = await fixture(t),
    reads = [];
  await fs.writeFile(
    path.join(f.root, "clones/service/unrelated.js"),
    "unrelated",
  );
  t.mock.method(fs, "readdir", async () => {
    throw Error("Repository walk forbidden during payload loading");
  });
  const second = { ...f.ref, id: "segment-2", startLine: 2, endLine: 2 };
  const payload = await loadCweSourcePayload(
    [f.ref, second, f.ref],
    f.manifest,
    f.root,
    { onRead: (r) => reads.push(r) },
  );
  assert.equal(payload.size, 2);
  assert.equal(reads.length, 1);
  assert.equal(reads[0].bytes, Buffer.byteLength(f.code));
  assert.equal(reads[0].path, "app.js");
  assert.equal(payload.get(second.id).code, "2:   return request.value;");
  assert.equal(payload.get(f.ref.id).blobSha256, f.ref.blobSha256);
});

test("planned CWE windows reject changed files and recheck changes between windows", async (t) => {
  const f = await fixture(t);
  await loadCweSourcePayload([f.ref], f.manifest, f.root);
  await fs.writeFile(path.join(f.root, "clones/service/app.js"), "changed\n");
  await assert.rejects(
    loadCweSourcePayload([f.ref], f.manifest, f.root),
    /Source changed/,
  );
});

test("planned CWE reads preserve selected scope, collection types, path containment and valid ranges", async (t) => {
  const f = await fixture(t);
  for (const ref of [
    { ...f.ref, path: "../app.js" },
    { ...f.ref, path: "C:/app.js" },
    { ...f.ref, path: "dir\\app.js" },
    { ...f.ref, path: "/app.js" },
    { ...f.ref, path: ".env" },
    { ...f.ref, path: "node_modules/app.js" },
    { ...f.ref, path: "app.txt" },
    { ...f.ref, startLine: 0 },
    { ...f.ref, endLine: 90 },
    { ...f.ref, endLine: 5 },
    { ...f.ref, blobSha256: "missing" },
    { ...f.ref, repository: "not-selected" },
  ])
    await assert.rejects(
      loadCweSourcePayload([ref], f.manifest, f.root),
      /evidence became unavailable/,
    );
  for (const repository of [
    { ...f.manifest.repositories[0], selected: false },
    { ...f.manifest.repositories[0], source: "github" },
    { ...f.manifest.repositories[0], localPath: "../outside" },
  ])
    await assert.rejects(
      loadCweSourcePayload([f.ref], { repositories: [repository] }, f.root),
      /evidence became unavailable/,
    );
  await assert.rejects(
    loadCweSourcePayload(
      [f.ref, { ...f.ref, startLine: 2 }],
      f.manifest,
      f.root,
    ),
    /evidence became unavailable/,
  );
});

test("planned CWE reads reject symlinks in files, subdirectories and repository roots", async (t) => {
  const f = await fixture(t);
  const dir = path.join(f.root, "clones/service");
  try {
    await fs.symlink("app.js", path.join(dir, "link.js"));
    await fs.symlink(dir, path.join(f.root, "linked-service"), "dir");
    await fs.symlink(dir, path.join(dir, "linked-directory"), "dir");
  } catch (error) {
    if (error.code === "EPERM" || error.code === "EACCES") {
      t.skip("This Windows account cannot create test symlinks");
      return;
    }
    throw error;
  }
  for (const relative of ["link.js", "linked-directory/app.js"]) {
    await assert.rejects(
      loadCweSourcePayload([{ ...f.ref, path: relative }], f.manifest, f.root),
      /evidence became unavailable/,
    );
  }
  await assert.rejects(
    loadCweSourcePayload(
      [f.ref],
      { repositories: [{ name: "service", localPath: "linked-service" }] },
      f.root,
    ),
    /evidence became unavailable/,
  );
});

test("planned CWE reads retain file size and binary restrictions and honor cancellation", async (t) => {
  const f = await fixture(t);
  const oversized = Buffer.alloc(LIMITS.fileBytes + 1, "x"),
    binary = Buffer.from("abc\0def");
  for (const [name, bytes] of [
    ["large.js", oversized],
    ["binary.js", binary],
  ]) {
    await fs.writeFile(path.join(f.root, "clones/service", name), bytes);
    await assert.rejects(
      loadCweSourcePayload(
        [{ ...f.ref, path: name, blobSha256: sha(bytes), endLine: 1 }],
        f.manifest,
        f.root,
      ),
      /evidence became unavailable/,
    );
  }
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    loadCweSourcePayload([f.ref], f.manifest, f.root, {
      signal: controller.signal,
    }),
    /cancelled/,
  );
  const betweenReads = new AbortController(),
    reads = [];
  await fs.writeFile(path.join(f.root, "clones/service/second.js"), f.code);
  await assert.rejects(
    loadCweSourcePayload(
      [f.ref, { ...f.ref, id: "second", path: "second.js" }],
      f.manifest,
      f.root,
      {
        signal: betweenReads.signal,
        onRead: (r) => {
          reads.push(r);
          betweenReads.abort();
        },
      },
    ),
    /cancelled/,
  );
  assert.equal(reads.length, 1);
});

test("planned CWE reads redact complete private-key blocks across excerpt boundaries while preserving line numbers", async (t) => {
  const f = await fixture(t);
  const code = [
    "-----BEGIN PRIVATE KEY-----",
    "should-not-leak",
    "-----END PRIVATE KEY-----",
    'const password = "do-not-send";',
    "use(value);",
  ].join("\n");
  await fs.writeFile(path.join(f.root, "clones/service/app.js"), code);
  const ref = { ...f.ref, blobSha256: sha(code), startLine: 2, endLine: 5 };
  const output = (await loadCweSourcePayload([ref], f.manifest, f.root)).get(
    ref.id,
  ).code;
  assert.equal(
    output,
    "2: [private key omitted]\n3: [private key omitted]\n4: [sensitive assignment omitted]\n5: use(value);",
  );
  assert.ok(!output.includes("should-not-leak"));
});
