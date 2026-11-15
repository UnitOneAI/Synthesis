import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { localSource, sha, id } from "./sources.mjs";

export const SCANNER_VERSION = "1.185.0";
const ruleFile = fileURLToPath(
  new URL("../rules/cwe-v1.json", import.meta.url),
);
const supported = /\.(py|js|mjs|jsx|ts|tsx|cs|c|h|cpp|cc|hpp)$/i;
const MAX_OUTPUT = 50 * 1024 ** 2,
  MAX_FINDINGS = 10000,
  MAX_STAGE = 2 * 1024 ** 3;
function abortCheck(signal) {
  if (signal?.aborted) throw Error("Scan cancelled");
}
function childEnvironment(home) {
  const env = {};
  for (const key of [
    "PATH",
    "Path",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "TMP",
    "TEMP",
    "TMPDIR",
  ])
    if (process.env[key]) env[key] = process.env[key];
  return {
    ...env,
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: home,
    PYTHONUTF8: "1",
    SEMGREP_SEND_METRICS: "off",
    SEMGREP_ENABLE_VERSION_CHECK: "0",
  };
}
export function scannerProcess(
  executable,
  args,
  { cwd, home, signal, timeout = 15 * 60 * 1000 },
) {
  abortCheck(signal);
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd,
      env: childEnvironment(home),
      shell: false,
      windowsHide: true,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let bytes = 0,
      stdout = [],
      failure,
      killTask;
    const kill = (reason) => {
      if (failure) return;
      failure = reason;
      if (!child.pid) return;
      if (process.platform === "win32")
        killTask = new Promise((done) => {
          const killer = spawn(
            path.join(
              process.env.SystemRoot || "C:/Windows",
              "System32/taskkill.exe",
            ),
            ["/PID", String(child.pid), "/T", "/F"],
            { shell: false, windowsHide: true, stdio: "ignore" },
          );
          killer.once("error", () => {
            child.kill();
            done();
          });
          killer.once("close", done);
        });
      else {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      }
    };
    const timer = setTimeout(
      () => kill("Scanner time limit exceeded"),
      timeout,
    );
    const onAbort = () => kill("Scan cancelled");
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
    child.stdout.on("data", (b) => {
      bytes += b.length;
      if (bytes > MAX_OUTPUT) kill("Scanner output limit exceeded");
      else stdout.push(b);
    });
    // Do not expose stderr: a scanner may echo source code or secret values.
    child.stderr.on("data", (b) => {
      bytes += b.length;
      if (bytes > MAX_OUTPUT) kill("Scanner output limit exceeded");
    });
    child.once("error", () => {
      failure =
        "Scanner could not start. Install the qualified Semgrep version and set --cwe-scanner to its executable.";
    });
    child.once("close", async (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      await killTask;
      if (failure) reject(Error(failure));
      else resolve({ code, text: Buffer.concat(stdout).toString("utf8") });
    });
  });
}
function relative(file, stage) {
  if (typeof file !== "string") return null;
  const p = path.isAbsolute(file) ? path.relative(stage, file) : file;
  const clean = p.replace(/\\/g, "/").replace(/^\.\//, "");
  return clean.startsWith("../") || clean === ".." || path.isAbsolute(clean)
    ? null
    : clean;
}
export async function scanCwe(
  manifest,
  model,
  { sourceRoot, scanner = "semgrep", signal, trace, progress, checkpoint } = {},
) {
  const packText = await fs.readFile(ruleFile, "utf8");
  const rules = JSON.parse(packText).rules,
    byRule = new Map(rules.map((r) => [r.id, r]));
  const report = {
    version: 1,
    startedAt: new Date().toISOString(),
    status: "running",
    basedOnRevision: model.modelRevision,
    graphFingerprint: model.sourceGraph.fingerprint,
    engine: { name: "Semgrep CE", expectedVersion: SCANNER_VERSION },
    rulePack: {
      version: "cwe-v1",
      sha256: sha(packText),
      rules: rules.map((r) => ({
        id: r.id,
        cwe: r.metadata.cwe,
        languages: r.languages,
      })),
    },
    tokens: 0,
    requestedRepositories: manifest.repositories
      .filter((r) => r.selected)
      .map((r) => r.name),
    limits: {
      stagedBytesPerRepository: MAX_STAGE,
      findings: MAX_FINDINGS,
      scannerOutputBytes: MAX_OUTPUT,
      perRuleFileSeconds: 10,
      perRepositorySeconds: 900,
    },
    repositories: [],
    findings: [],
    limitations: [
      "Potential weaknesses require security review; these are not confirmed vulnerabilities.",
      "Local rules cover a subset of CWE classes and languages. A scan with no findings is not proof of security.",
      "Community Edition does not provide compiler-level cross-file or cross-repository taint resolution.",
      "Target source is staged read-only for static scanning. No target code is executed. File collection is not an atomic filesystem snapshot.",
    ],
  };
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-cwe-"));
  await fs.chmod(temp, 0o700);
  const save = async () => {
    await checkpoint?.(report);
  };
  try {
    const version = await scannerProcess(scanner, ["--version"], {
      cwd: temp,
      home: temp,
      signal,
      timeout: 30000,
    });
    if (version.code !== 0 || version.text.trim() !== SCANNER_VERSION)
      throw Error(
        `Scanner version mismatch. Install semgrep==${SCANNER_VERSION}.`,
      );
    report.engine.version = SCANNER_VERSION;
    await trace?.("cwe.started", {
      counts: {
        repositories: manifest.repositories.filter((r) => r.selected).length,
        rules: rules.length,
      },
    });
    await save();
    for (const source of manifest.repositories.filter((r) => r.selected)) {
      abortCheck(signal);
      const repo = {
        name: source.name,
        status: "running",
        eligibleFiles: 0,
        scannedFiles: 0,
        unsupportedFiles: 0,
        findings: 0,
        errors: [],
        skipped: [],
      };
      report.repositories.push(repo);
      if (source.source === "github") {
        repo.status = "unsupported";
        repo.errors.push({ type: "local-clone-required" });
        await save();
        continue;
      }
      progress?.(`CWE review: ${source.name}`);
      await trace?.("cwe.repository-started", { repository: source.name });
      const stage = path.join(temp, "source");
      await fs.mkdir(stage);
      await fs.writeFile(
        path.join(stage, ".semgrepignore"),
        "# Synthesis has already selected the safe static scan scope.\n",
        { mode: 0o600 },
      );
      const files = new Map();
      let bytes = 0;
      try {
        const collected = await localSource(source, sourceRoot, {
          onEntry: () => {},
          onFile: async (f) => {
            abortCheck(signal);
            if (!supported.test(f.path)) {
              repo.unsupportedFiles++;
              return;
            }
            bytes += Buffer.byteLength(f.text);
            if (bytes > MAX_STAGE || files.size >= 100000)
              throw Error("Scanner staging limit exceeded");
            const dest = path.join(stage, f.path);
            await fs.mkdir(path.dirname(dest), { recursive: true });
            await fs.writeFile(dest, f.text, { flag: "wx", mode: 0o400 });
            files.set(f.path, {
              hash: f.hash,
              lines: f.text.split("\n").length,
            });
          },
        });
        repo.collection = collected.coverage;
        repo.snapshot = collected.snapshot;
        repo.matchesGraphSnapshot =
          model.sources.find((s) => s.name === source.name)?.snapshot ===
          collected.snapshot;
        repo.eligibleFiles = files.size;
        if (!files.size) {
          repo.status = "unsupported";
          repo.errors.push({ type: "no-supported-files" });
        } else {
          const result = await scannerProcess(
            scanner,
            [
              "scan",
              "--config",
              ruleFile,
              "--json",
              "--quiet",
              "--metrics=off",
              "--disable-version-check",
              "--oss-only",
              "--no-rewrite-rule-ids",
              "--disable-nosem",
              "--no-git-ignore",
              "--jobs",
              "2",
              "--timeout",
              "10",
              "--max-memory",
              "512",
              "--max-target-bytes",
              "1048576",
              ".",
            ],
            { cwd: stage, home: temp, signal },
          );
          let data;
          try {
            data = JSON.parse(result.text);
          } catch {
            throw Error("Scanner did not return valid JSON");
          }
          if (
            !Array.isArray(data.results) ||
            !Array.isArray(data.errors) ||
            !Array.isArray(data.paths?.scanned)
          )
            throw Error("Scanner response schema is invalid");
          const scanned = new Set(
            data.paths.scanned
              .map((p) => relative(p, stage))
              .filter((p) => files.has(p)),
          );
          repo.scannedFiles = scanned.size;
          repo.skipped = [...files.keys()].filter((p) => !scanned.has(p));
          repo.errors = data.errors.map((e) => ({
            type: /^[\w -]{1,100}$/.test(e.type) ? e.type : "scanner-error",
            path: files.has(relative(e.path, stage))
              ? relative(e.path, stage)
              : undefined,
          }));
          for (const finding of data.results) {
            const rule = byRule.get(finding.check_id),
              p = relative(finding.path, stage),
              f = files.get(p);
            const line = finding.start?.line,
              endLine = finding.end?.line;
            if (
              !rule ||
              !f ||
              !Number.isInteger(line) ||
              !Number.isInteger(endLine) ||
              line < 1 ||
              endLine < line ||
              endLine > f.lines
            ) {
              repo.errors.push({ type: "invalid-finding" });
              continue;
            }
            if (report.findings.length >= MAX_FINDINGS) {
              repo.errors.push({ type: "finding-limit-reached" });
              break;
            }
            const evidenceIds = model.evidence
              .filter(
                (e) =>
                  e.repository === source.name &&
                  e.path === p &&
                  e.blobSha256 === f.hash,
              )
              .map((e) => e.id);
            const interfaceIds = model.interfaces
              .filter((i) => i.evidence.some((e) => evidenceIds.includes(e)))
              .map((i) => i.id);
            const record = {
              id: id("cwe", source.name, p, f.hash, rule.id, line, endLine),
              repository: source.name,
              path: p,
              line,
              endLine,
              blobSha256: f.hash,
              ruleId: rule.id,
              cwe: rule.metadata.cwe,
              title: rule.message,
              remediation: rule.metadata.remediation,
              status: "needs-review",
              evidenceIds,
              interfaceIds,
              association:
                "Same-file static evidence; exploitability and call path are not established",
              sourceMatchesGraph: repo.matchesGraphSnapshot,
            };
            if (!report.findings.some((v) => v.id === record.id)) {
              report.findings.push(record);
              repo.findings++;
            }
          }
          repo.status =
            result.code === 0 &&
            !repo.errors.length &&
            !repo.skipped.length &&
            !collected.coverage.failed &&
            !collected.coverage.oversized &&
            !collected.coverage.truncated &&
            repo.matchesGraphSnapshot
              ? "completed"
              : "partial";
          if (result.code !== 0)
            repo.errors.push({ type: "scanner-exit", code: result.code });
        }
      } catch (error) {
        repo.status = signal?.aborted ? "cancelled" : "failed";
        // All persisted errors are selected local messages, never raw child output or source paths.
        repo.errors.push({
          type: [
            "Scanner staging limit exceeded",
            "Scanner output limit exceeded",
            "Scanner time limit exceeded",
            "Scanner did not return valid JSON",
            "Scanner response schema is invalid",
            "Scan cancelled",
          ].includes(error.message)
            ? error.message
            : "Source collection or scanner failed",
        });
      } finally {
        await fs.rm(stage, { recursive: true, force: true });
      }
      await trace?.("cwe.repository-completed", {
        repository: source.name,
        status: repo.status,
        counts: {
          eligible: repo.eligibleFiles,
          scanned: repo.scannedFiles,
          findings: repo.findings,
          errors: repo.errors.length,
        },
        snapshotMatches: repo.matchesGraphSnapshot,
      });
      await save();
    }
    report.status = signal?.aborted
      ? "cancelled"
      : report.repositories.every((r) => r.status === "completed")
        ? "completed"
        : "partial";
  } catch (error) {
    report.status = signal?.aborted ? "cancelled" : "failed";
    report.error = error.message;
  } finally {
    report.finishedAt = new Date().toISOString();
    await fs.rm(temp, { recursive: true, force: true });
    await trace?.("cwe.completed", {
      status: report.status,
      counts: {
        findings: report.findings.length,
        repositories: report.repositories.length,
      },
      tokens: 0,
    });
    await save();
  }
  return report;
}
export function cweCsv(report) {
  const cell = (v) =>
    '"' +
    String(v ?? "")
      .replace(/^[=+@-]/, "'\u0024&")
      .replace(/"/g, '""') +
    '"';
  return [
    [
      "Repository",
      "File",
      "Line",
      "CWE",
      "Rule",
      "Potential weakness",
      "Status",
      "SHA256",
    ],
    ...(report?.findings || []).map((f) => [
      f.repository,
      f.path,
      f.line,
      f.cwe,
      f.ruleId,
      f.title,
      f.status,
      f.blobSha256,
    ]),
  ]
    .map((r) => r.map(cell).join(","))
    .join("\r\n");
}
export function cweSarif(report) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Synthesis CWE code review",
            version: report?.rulePack.version || "cwe-v1",
            rules: (report?.rulePack.rules || []).map((r) => ({
              id: r.id,
              properties: { tags: [r.cwe] },
            })),
          },
        },
        invocations: [{ executionSuccessful: report?.status === "completed" }],
        results: (report?.findings || []).map((f) => ({
          ruleId: f.ruleId,
          level: "warning",
          message: { text: f.title },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: [f.repository, ...f.path.split("/")]
                    .map(encodeURIComponent)
                    .join("/"),
                },
                region: { startLine: f.line, endLine: f.endLine },
              },
            },
          ],
          partialFingerprints: { synthesis: f.id },
          properties: {
            cwe: f.cwe,
            status: f.status,
            sourceSha256: f.blobSha256,
          },
        })),
      },
    ],
  };
}
