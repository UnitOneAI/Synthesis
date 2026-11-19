import fs from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import {
  excludedPath,
  supportedSourcePath,
  within,
  sha,
  LIMITS,
} from "./sources.mjs";
import { redact } from "./model-review.mjs";

// One existing payload window: at most 100 packets, each with eight segments.
// Only excerpts survive each file read; no repository tree or project discovery
// is repeated. The caller drops this map before loading the next window.
const MAX_RECORDS = 800;
const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
const checkCancelled = (signal) => {
  if (signal?.aborted) throw Error("CWE model review cancelled");
};
const invalid = () => Error("Selected CWE source evidence became unavailable");

async function readPlannedFile(realRoot, source, relative, signal) {
  checkCancelled(signal);
  if (
    typeof relative !== "string" ||
    !relative ||
    path.isAbsolute(relative) ||
    /^[A-Za-z]:|\\|\0/.test(relative) ||
    relative.split("/").some((s) => !s || s === "." || s === "..") ||
    excludedPath(relative) ||
    !supportedSourcePath(relative)
  )
    throw invalid();
  const repo = path.resolve(realRoot, source.localPath || source.name),
    file = path.resolve(repo, relative);
  if (!within(realRoot, repo) || !within(repo, file)) throw invalid();
  // Check every segment, including repository ancestors, before opening.
  let walk = realRoot;
  const parts = path.relative(realRoot, file).split(path.sep);
  for (let index = 0; index < parts.length; index++) {
    checkCancelled(signal);
    walk = path.join(walk, parts[index]);
    const stat = await fs.lstat(walk);
    if (
      stat.isSymbolicLink() ||
      (index < parts.length - 1 && !stat.isDirectory())
    )
      throw invalid();
  }
  if (!within(repo, await fs.realpath(file))) throw invalid();
  const before = await fs.lstat(file);
  if (!before.isFile() || before.size > LIMITS.fileBytes) throw invalid();
  checkCancelled(signal);
  const handle = await fs.open(
    file,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  let bytes;
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.size !== before.size ||
      opened.ino !== before.ino ||
      opened.dev !== before.dev
    )
      throw Error("Source changed while preparing CWE evidence");
    bytes = Buffer.alloc(opened.size + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await handle.stat();
    if (
      bytesRead !== opened.size ||
      after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs ||
      after.ctimeMs !== opened.ctimeMs
    )
      throw Error("Source changed while preparing CWE evidence");
    bytes = bytes.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
  checkCancelled(signal);
  if (!within(repo, await fs.realpath(file)) || bytes.includes(0))
    throw invalid();
  return bytes;
}

export async function loadCweSourcePayload(
  records,
  manifest,
  sourceRoot,
  { signal, onRead } = {},
) {
  checkCancelled(signal);
  const unique = new Map();
  for (const r of records) {
    if (
      !r ||
      typeof r.id !== "string" ||
      !r.id ||
      typeof r.repository !== "string" ||
      typeof r.blobSha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(r.blobSha256) ||
      !Number.isInteger(r.startLine) ||
      !Number.isInteger(r.endLine) ||
      r.startLine < 1 ||
      r.endLine < r.startLine ||
      r.endLine - r.startLine >= 80
    )
      throw invalid();
    const previous = unique.get(r.id);
    if (previous && JSON.stringify(previous) !== JSON.stringify(r))
      throw invalid();
    unique.set(r.id, r);
    if (unique.size > MAX_RECORDS)
      throw Error("CWE source payload exceeds 800 segments");
  }
  const groups = new Map();
  for (const r of unique.values()) {
    const key = JSON.stringify([r.repository, r.path]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  const sources = new Map(
    manifest.repositories
      .filter((s) => s.selected !== false && s.source !== "github")
      .map((s) => [s.name, s]),
  );
  const realRoot = await fs.realpath(sourceRoot),
    payload = new Map();
  let payloadBytes = 0;
  for (const group of groups.values()) {
    checkCancelled(signal);
    const first = group[0],
      source = sources.get(first.repository);
    if (!source) throw invalid();
    const bytes = await readPlannedFile(realRoot, source, first.path, signal);
    const hash = sha(bytes);
    if (group.some((r) => r.blobSha256 !== hash))
      throw Error("Source changed while preparing CWE evidence");
    await onRead?.({
      repository: first.repository,
      path: first.path,
      bytes: bytes.length,
    });
    checkCancelled(signal);
    // Track private-key blocks across the whole file, including when a planned
    // window starts inside a key, and preserve source line numbers after redaction.
    let privateKey = false;
    const lines = bytes
      .toString("utf8")
      .split("\n")
      .map((line) => {
        if (/-----BEGIN [^-]*PRIVATE KEY-----/.test(line)) privateKey = true;
        const sensitive = privateKey;
        if (/-----END [^-]*PRIVATE KEY-----/.test(line)) privateKey = false;
        return sensitive ? "[private key omitted]" : redact(line);
      });
    for (const r of group) {
      if (r.endLine > lines.length) throw invalid();
      const code = lines
        .slice(r.startLine - 1, r.endLine)
        .map((line, i) => `${r.startLine + i}: ${line}`)
        .join("\n");
      payloadBytes += Buffer.byteLength(code);
      if (payloadBytes > MAX_PAYLOAD_BYTES)
        throw Error("CWE source payload exceeds 10 MiB");
      payload.set(r.id, { ...r, code });
    }
  }
  return payload;
}
