/**
 * Incremental Scanning Support for Synthesis
 *
 * Provides baseline comparison and incremental scanning capabilities.
 * When a baseline is provided, only new/changed threats are reported.
 *
 * Features:
 * - File hash computation to detect changes
 * - Baseline scan result caching
 * - Issue deduplication against baseline
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// ── Types ──

export interface FileHashes {
  [filePath: string]: string;
}

export interface CachedExecution {
  execution_id: string;
  timestamp: number;
  file_hashes: FileHashes;
  issues: Issue[];
}

export interface Issue {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  location: {
    file_path: string;
    line_start?: number;
    line_end?: number;
  };
  metadata: Record<string, unknown>;
}

export interface IncrementalResult {
  issues: Issue[];
  summary: IncrementalSummary;
}

export interface IncrementalSummary {
  mode: "incremental";
  total_current: number;
  new_or_changed: number;
  skipped_existing: number;
  changed_files: number;
  file_changes: {
    added: number;
    modified: number;
    deleted: number;
  };
  baseline_execution_id: string | null;
  current_execution_id: string;
}

// ── Constants ──

// File extensions to include in hash computation (source code files)
const SOURCE_EXTENSIONS = new Set([
  ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
  ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".m",
  ".scala", ".sql", ".sh", ".bash", ".yaml", ".yml", ".json", ".xml",
  ".html", ".css", ".tf", ".hcl",
]);

// Special files without extensions to include
const SPECIAL_FILES = new Set([
  "Dockerfile", "Makefile", "Jenkinsfile", "Vagrantfile",
]);

// Directories to exclude from hash computation
const EXCLUDE_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", "__pycache__", ".pytest_cache",
  "venv", ".venv", "env", ".env", "dist", "build", "target", "vendor",
  ".unitone", ".idea", ".vscode", "coverage", ".nyc_output",
]);

// ── Cache Management ──

/**
 * Get the cache directory for incremental scanning data.
 * Cache is stored in <repo>/.unitone/cache/synthesis/
 */
export function getCacheDir(repoPath: string): string {
  const cacheDir = path.join(repoPath, ".unitone", "cache", "synthesis");
  fs.mkdirSync(cacheDir, { recursive: true });
  return cacheDir;
}

/**
 * Compute SHA-256 hash of a file's contents.
 */
export function computeFileHash(filePath: string): string {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(content).digest("hex");
  } catch {
    return "";
  }
}

/**
 * Compute hashes for all source files in the repository.
 * Only includes files with SOURCE_EXTENSIONS, excludes EXCLUDE_DIRS.
 */
export function computeRepoFileHashes(repoPath: string): FileHashes {
  const hashes: FileHashes = {};

  function walkDir(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(repoPath, fullPath);

      if (entry.isDirectory()) {
        // Skip excluded directories
        if (EXCLUDE_DIRS.has(entry.name)) {
          continue;
        }
        walkDir(fullPath);
      } else if (entry.isFile()) {
        // Check if this file should be included
        const ext = path.extname(entry.name).toLowerCase();
        const isSourceFile = SOURCE_EXTENSIONS.has(ext) || SPECIAL_FILES.has(entry.name);

        if (isSourceFile) {
          const hash = computeFileHash(fullPath);
          if (hash) {
            hashes[relativePath] = hash;
          }
        }
      }
    }
  }

  walkDir(repoPath);
  return hashes;
}

/**
 * Determine which files have changed between two hash sets.
 */
export function getChangedFiles(
  currentHashes: FileHashes,
  baselineHashes: FileHashes
): { added: Set<string>; modified: Set<string>; deleted: Set<string> } {
  const currentFiles = new Set(Object.keys(currentHashes));
  const baselineFiles = new Set(Object.keys(baselineHashes));

  const added = new Set<string>();
  const modified = new Set<string>();
  const deleted = new Set<string>();

  // Find added files (in current but not in baseline)
  for (const file of currentFiles) {
    if (!baselineFiles.has(file)) {
      added.add(file);
    }
  }

  // Find deleted files (in baseline but not in current)
  for (const file of baselineFiles) {
    if (!currentFiles.has(file)) {
      deleted.add(file);
    }
  }

  // Find modified files (hash changed)
  for (const file of currentFiles) {
    if (baselineFiles.has(file) && currentHashes[file] !== baselineHashes[file]) {
      modified.add(file);
    }
  }

  return { added, modified, deleted };
}

/**
 * Save scan results to cache for future incremental scans.
 */
export function saveExecutionCache(
  repoPath: string,
  executionId: string,
  fileHashes: FileHashes,
  issues: Issue[]
): void {
  const cacheDir = getCacheDir(repoPath);
  const cacheFile = path.join(cacheDir, `${executionId}.json`);

  const cacheData: CachedExecution = {
    execution_id: executionId,
    timestamp: Date.now(),
    file_hashes: fileHashes,
    issues: issues,
  };

  try {
    fs.writeFileSync(cacheFile, JSON.stringify(cacheData, null, 2), "utf-8");

    // Update "latest" pointer
    const latestFile = path.join(cacheDir, "latest.json");
    fs.writeFileSync(latestFile, JSON.stringify({ execution_id: executionId }), "utf-8");

    console.error(`[synthesis] Cached ${issues.length} issues for execution ${executionId}`);
  } catch (e) {
    console.error(`[synthesis] Warning: Failed to save cache: ${e}`);
  }
}

/**
 * Load cached scan results.
 * If executionId is null, loads the latest cached execution.
 */
export function loadExecutionCache(
  repoPath: string,
  executionId: string | null = null
): CachedExecution | null {
  const cacheDir = getCacheDir(repoPath);

  // If no execution_id, get the latest
  if (!executionId) {
    const latestFile = path.join(cacheDir, "latest.json");
    if (!fs.existsSync(latestFile)) {
      return null;
    }
    try {
      const latestData = JSON.parse(fs.readFileSync(latestFile, "utf-8"));
      executionId = latestData.execution_id;
    } catch {
      return null;
    }
  }

  if (!executionId) {
    return null;
  }

  const cacheFile = path.join(cacheDir, `${executionId}.json`);
  if (!fs.existsSync(cacheFile)) {
    return null;
  }

  try {
    return JSON.parse(fs.readFileSync(cacheFile, "utf-8")) as CachedExecution;
  } catch {
    return null;
  }
}

/**
 * Generate a unique signature for an issue for deduplication.
 * Based on title + file_path + description hash (first 100 chars).
 */
function issueSignature(issue: Issue): string {
  const filePath = issue.location?.file_path || "";
  const title = issue.title || "";
  const descStart = (issue.description || "").slice(0, 100);
  const descHash = crypto.createHash("md5").update(descStart).digest("hex");
  return `${title}|${filePath}|${descHash}`;
}

/**
 * Filter issues to only include new or changed threats.
 *
 * An issue is considered "new" if:
 * 1. Its file is in the changed files set (added or modified)
 * 2. It doesn't exist in the baseline (based on signature)
 */
export function filterIncrementalIssues(
  currentIssues: Issue[],
  baselineIssues: Issue[],
  changedFiles: Set<string>,
  currentExecutionId: string,
  baselineExecutionId: string | null
): IncrementalResult {
  // Build signature set for baseline issues
  const baselineSignatures = new Set(baselineIssues.map(issueSignature));

  const newIssues: Issue[] = [];
  let skippedExisting = 0;

  for (const issue of currentIssues) {
    const filePath = issue.location?.file_path || "";

    // Issues without file location are always included (repo-level threats)
    if (!filePath) {
      newIssues.push(issue);
      continue;
    }

    // Check if file was changed
    if (changedFiles.has(filePath)) {
      // File changed - include this issue
      newIssues.push(issue);
      continue;
    }

    // File not changed - check if this is a new issue not in baseline
    const sig = issueSignature(issue);
    if (!baselineSignatures.has(sig)) {
      // New issue type, even in unchanged file
      newIssues.push(issue);
    } else {
      skippedExisting++;
    }
  }

  return {
    issues: newIssues,
    summary: {
      mode: "incremental",
      total_current: currentIssues.length,
      new_or_changed: newIssues.length,
      skipped_existing: skippedExisting,
      changed_files: changedFiles.size,
      file_changes: {
        added: 0, // Will be filled in by caller
        modified: 0,
        deleted: 0,
      },
      baseline_execution_id: baselineExecutionId,
      current_execution_id: currentExecutionId,
    },
  };
}

/**
 * Main incremental scanning orchestration.
 * Call this with the full scan results to apply incremental filtering.
 */
export function applyIncrementalFilter(
  repoPath: string,
  allIssues: Issue[],
  currentExecutionId: string,
  baselineExecutionId: string | null,
  incrementalMode: boolean
): { issues: Issue[]; incrementalSummary: IncrementalSummary | null; fileHashes: FileHashes } {
  // If neither baseline nor incremental mode, return all issues
  if (!baselineExecutionId && !incrementalMode) {
    const fileHashes = computeRepoFileHashes(repoPath);
    return { issues: allIssues, incrementalSummary: null, fileHashes };
  }

  console.error("[synthesis] Incremental mode enabled");

  // Compute current file hashes
  console.error("[synthesis] Computing file hashes...");
  const currentHashes = computeRepoFileHashes(repoPath);
  console.error(`[synthesis] Computed hashes for ${Object.keys(currentHashes).length} files`);

  // Load baseline cache
  const baselineCache = loadExecutionCache(repoPath, baselineExecutionId);

  if (!baselineCache) {
    if (baselineExecutionId) {
      console.error(`[synthesis] Warning: Baseline execution ${baselineExecutionId} not found`);
    } else {
      console.error("[synthesis] No previous scan cached, running full analysis");
    }
    return { issues: allIssues, incrementalSummary: null, fileHashes: currentHashes };
  }

  const baselineHashes = baselineCache.file_hashes || {};
  console.error(`[synthesis] Loaded baseline from execution ${baselineCache.execution_id}`);
  console.error(
    `[synthesis] Baseline has ${Object.keys(baselineHashes).length} file hashes, ` +
    `${baselineCache.issues.length} issues`
  );

  // Determine changed files
  const { added, modified, deleted } = getChangedFiles(currentHashes, baselineHashes);
  const changedFiles = new Set([...added, ...modified]);

  console.error(
    `[synthesis] File changes: ${added.size} added, ` +
    `${modified.size} modified, ${deleted.size} deleted`
  );

  // Filter issues
  const result = filterIncrementalIssues(
    allIssues,
    baselineCache.issues,
    changedFiles,
    currentExecutionId,
    baselineCache.execution_id
  );

  // Fill in file change counts
  result.summary.file_changes = {
    added: added.size,
    modified: modified.size,
    deleted: deleted.size,
  };

  console.error(
    `[synthesis] Incremental result: ${result.issues.length} new/changed issues ` +
    `(from ${allIssues.length} total)`
  );

  return {
    issues: result.issues,
    incrementalSummary: result.summary,
    fileHashes: currentHashes,
  };
}
