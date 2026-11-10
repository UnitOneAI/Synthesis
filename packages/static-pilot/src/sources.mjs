import fs from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { unzipBounded } from "./inventory.mjs";

export const sha = (text) => createHash("sha256").update(text).digest("hex");
export const id = (...parts) => sha(JSON.stringify(parts)).slice(0, 20);
export const LIMITS = {
  files: 20000,
  fileBytes: 1024 * 1024,
  totalBytes: 64 * 1024 * 1024,
  archiveBytes: 96 * 1024 * 1024,
};
const excluded = new Set([
  ".git",
  "node_modules",
  "bin",
  "obj",
  "dist",
  "vendor",
  ".next",
  "packages-cache",
]);
const supported =
  /\.(cs|csproj|vbproj|vcxproj|sln|cpp|cc|c|h|hpp|js|mjs|ts|tsx|jsx|json|xml|config|wxs|wxi|wixproj|props|targets|sql|yaml|yml|proto|graphql|ps1|sh|bat|cmd|tf)$/i;
export const excludedPath = (name) =>
  name.split("/").some((x) => excluded.has(x)) ||
  /(^|\/)(\.env(?!\.example$)[^/]*|[^/]*\.(pem|key|pfx|p12|keystore))$/i.test(
    name,
  );
export function within(root, candidate) {
  const rel = path.relative(root, candidate);
  return (
    rel === "" ||
    (!rel.startsWith(".." + path.sep) && rel !== ".." && !path.isAbsolute(rel))
  );
}
function ledger() {
  return {
    discovered: 0,
    inspected: 0,
    excluded: 0,
    unsupported: 0,
    oversized: 0,
    failed: 0,
    rejected: 0,
    bytes: 0,
    truncated: false,
    entries: [],
  };
}
function accept(name, size, coverage) {
  if (excludedPath(name)) return "excluded";
  if (!supported.test(name)) return "unsupported";
  if (size > LIMITS.fileBytes) return "oversized";
  if (coverage.bytes + size > LIMITS.totalBytes) {
    coverage.truncated = true;
    return "budget";
  }
  return "inspect";
}
export async function localSource(source, root) {
  const realRoot = await fs.realpath(root);
  const candidate = path.resolve(realRoot, source.localPath || source.name);
  if (!within(realRoot, candidate))
    throw new Error("Source path is outside the configured source root");
  const stat = await fs.lstat(candidate);
  if (stat.isSymbolicLink() || !stat.isDirectory())
    throw new Error("Source must be a directory, not a symlink");
  const real = await fs.realpath(candidate);
  if (!within(realRoot, real))
    throw new Error("Source path escapes the configured root");
  const coverage = ledger(),
    files = [];
  async function walk(dir) {
    for (const entry of (await fs.readdir(dir, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name, "en"),
    )) {
      if (coverage.discovered >= LIMITS.files) {
        coverage.truncated = true;
        return;
      }
      const file = path.join(dir, entry.name),
        name = path.relative(real, file).split(path.sep).join("/");
      if (entry.isDirectory() && excludedPath(name)) {
        coverage.excluded++;
        coverage.entries.push({
          path: name + "/",
          status: "excluded-directory",
          descendants: "not enumerated",
        });
        continue;
      }
      if (entry.isDirectory()) {
        await walk(file);
        continue;
      }
      coverage.discovered++;
      if (entry.isSymbolicLink() || !entry.isFile()) {
        coverage.rejected++;
        coverage.entries.push({ path: name, status: "rejected-nonregular" });
        continue;
      }
      try {
        const s = await fs.lstat(file),
          status = accept(name, s.size, coverage);
        if (status !== "inspect") {
          if (status in coverage) coverage[status]++;
          coverage.entries.push({ path: name, status });
          continue;
        }
        // Recheck containment immediately before opening; never follow a final symlink.
        const resolved = await fs.realpath(file);
        if (!within(real, resolved)) throw new Error("Path escaped root");
        const handle = await fs.open(
          file,
          constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
        );
        let bytes;
        try {
          const opened = await handle.stat();
          if (
            !opened.isFile() ||
            opened.size > LIMITS.fileBytes ||
            opened.ino !== s.ino ||
            opened.dev !== s.dev
          )
            throw new Error("Source changed during read");
          bytes = Buffer.alloc(opened.size + 1);
          const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
          if (bytesRead !== opened.size)
            throw new Error("Source changed during read");
          bytes = bytes.subarray(0, bytesRead);
        } finally {
          await handle.close();
        }
        if (bytes.includes(0)) {
          coverage.unsupported++;
          coverage.entries.push({ path: name, status: "binary" });
          continue;
        }
        coverage.inspected++;
        coverage.bytes += bytes.length;
        files.push({
          path: name,
          text: bytes.toString("utf8"),
          hash: sha(bytes),
        });
        coverage.entries.push({
          path: name,
          status: "inspected",
          hash: sha(bytes),
        });
      } catch {
        coverage.failed++;
        coverage.entries.push({ path: name, status: "read-failed" });
      }
    }
  }
  await walk(real);
  return {
    files,
    coverage,
    revision: null,
    snapshot: sha(JSON.stringify(coverage.entries)),
    revisionBasis:
      "digest of inspected working-tree files and coverage ledger; not a Git commit or an atomic filesystem snapshot",
  };
}
export function githubIdentity(url) {
  const u = new URL(url);
  const match = u.pathname.match(
    /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/,
  );
  if (
    u.protocol !== "https:" ||
    u.hostname !== "github.com" ||
    u.port ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    !match ||
    match[1] === ".." ||
    match[2] === ".."
  )
    throw new Error(
      "Use an HTTPS github.com owner/repository URL without credentials",
    );
  return { owner: match[1], repo: match[2] };
}
async function boundedFetch(url, token, max, redirects = 0) {
  const u = new URL(url);
  if (
    u.protocol !== "https:" ||
    !["api.github.com", "codeload.github.com"].includes(u.hostname)
  )
    throw new Error("Unapproved source host");
  const response = await fetch(u, {
    redirect: "manual",
    signal: AbortSignal.timeout(120000),
    headers: {
      "User-Agent": "Synthesis-Static-Pilot",
      ...(token && u.hostname === "api.github.com"
        ? { Authorization: `Bearer ${token}` }
        : {}),
    },
  });
  if ([301, 302, 307, 308].includes(response.status)) {
    if (redirects >= 3) throw new Error("Too many source redirects");
    return boundedFetch(
      new URL(response.headers.get("location"), u).href,
      token,
      max,
      redirects + 1,
    );
  }
  if (!response.ok)
    throw new Error(
      `GitHub source acquisition failed (${response.status}); check repository access and rate limits`,
    );
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.length;
    if (total > max) throw new Error("Source download limit exceeded");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
export async function githubSource(source, token) {
  const { owner, repo } = githubIdentity(source.url);
  const base = `https://api.github.com/repos/${owner}/${repo}`;
  const commit = JSON.parse(
    (
      await boundedFetch(
        `${base}/commits/${encodeURIComponent(source.ref || "HEAD")}`,
        token,
        4 * 1024 * 1024,
      )
    ).toString("utf8"),
  );
  if (!/^[0-9a-f]{40}$/.test(commit.sha))
    throw new Error("GitHub did not return a pinned commit");
  const archive = await boundedFetch(
    `${base}/zipball/${commit.sha}`,
    token,
    LIMITS.archiveBytes,
  );
  const zip = unzipBounded(archive, 256 * 1024 * 1024),
    coverage = ledger(),
    files = [];
  for (const key of Object.keys(zip).sort()) {
    if (key.endsWith("/")) continue;
    if (coverage.discovered >= LIMITS.files) {
      coverage.truncated = true;
      break;
    }
    coverage.discovered++;
    const name = key.split("/").slice(1).join("/");
    if (
      !name ||
      name.split("/").includes("..") ||
      name.startsWith("/") ||
      name.includes("\\")
    ) {
      coverage.rejected++;
      coverage.entries.push({
        path: "[invalid archive path]",
        status: "rejected",
      });
      continue;
    }
    const bytes = zip[key],
      status = accept(name, bytes.length, coverage);
    if (status !== "inspect") {
      if (status in coverage) coverage[status]++;
      coverage.entries.push({ path: name, status });
      continue;
    }
    if (bytes.includes(0)) {
      coverage.unsupported++;
      coverage.entries.push({ path: name, status: "binary" });
      continue;
    }
    coverage.inspected++;
    coverage.bytes += bytes.length;
    const hash = sha(bytes);
    files.push({ path: name, hash, text: Buffer.from(bytes).toString("utf8") });
    coverage.entries.push({ path: name, hash, status: "inspected" });
  }
  return {
    files,
    coverage,
    revision: commit.sha,
    snapshot: sha(JSON.stringify(coverage.entries)),
    revisionBasis: "pinned GitHub source archive",
  };
}
