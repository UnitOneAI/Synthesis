/**
 * @synthesis/core — Incremental Scan Context Expander
 *
 * Implements 1-hop dependency graph expansion for PR threat analysis.
 * When a PR modifies files, this module discovers related files that
 * import or are imported by the changed files, so the threat model
 * can detect when a PR removes a security control that protected
 * existing (unchanged) code.
 *
 * Security controls:
 * - File reads are capped at maxFileSize to prevent memory exhaustion.
 * - Total related files capped at maxRelatedFiles to control API cost.
 * - All file paths are validated via sanitizeFilePath before use.
 */

import type { FileChange } from "./types.js";
import { sanitizeFilePath } from "./analyzer.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ContextExpansion {
  /** Original PR diff files passed in. */
  directChanges: FileChange[];
  /** Files that import or are imported by changed files. */
  relatedFiles: RelatedFile[];
  /** Human-readable log of why each file was included. */
  expansionLog: string[];
}

export interface RelatedFile {
  path: string;
  content: string;
  relationship: "imports-changed" | "imported-by-changed";
  /** Which changed file triggered inclusion of this related file. */
  relatedTo: string;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface ExpandContextOptions {
  /** Maximum number of related files to include. Default: 20. */
  maxRelatedFiles?: number;
  /** Maximum file size in bytes to read. Files larger are skipped. Default: 100KB. */
  maxFileSize?: number;
}

const DEFAULT_MAX_RELATED_FILES = 20;
const DEFAULT_MAX_FILE_SIZE = 100 * 1024; // 100 KB

// ---------------------------------------------------------------------------
// Import extraction
// ---------------------------------------------------------------------------

/**
 * Extract import/require paths from file content based on language.
 *
 * Returns raw import specifiers (e.g. "./utils", "express", "fmt").
 * Handles:
 * - TypeScript/JavaScript: import ... from "...", require("..."), import("...")
 * - Python: import ..., from ... import ...
 * - Go: import "...", import (...)
 * - Java/Kotlin: import ...
 */
export function extractImports(content: string, language: string): string[] {
  const imports: Set<string> = new Set();

  switch (language) {
    case "typescript":
    case "javascript": {
      // Static imports: import ... from "..."  or  import "..."
      const esImportRe = /import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g;
      let match: RegExpExecArray | null;
      while ((match = esImportRe.exec(content)) !== null) {
        if (match[1]) imports.add(match[1]);
      }

      // require("...")
      const requireRe = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
      while ((match = requireRe.exec(content)) !== null) {
        if (match[1]) imports.add(match[1]);
      }

      // Dynamic import: import("...")
      const dynamicImportRe = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
      while ((match = dynamicImportRe.exec(content)) !== null) {
        if (match[1]) imports.add(match[1]);
      }
      break;
    }

    case "python": {
      // from <module> import ...
      const fromImportRe = /^from\s+([\w.]+)\s+import/gm;
      let match: RegExpExecArray | null;
      while ((match = fromImportRe.exec(content)) !== null) {
        if (match[1]) imports.add(match[1]);
      }

      // import <module>[, <module>]
      const importRe = /^import\s+([\w.,\s]+)/gm;
      while ((match = importRe.exec(content)) !== null) {
        if (match[1]) {
          for (const mod of match[1].split(",")) {
            const trimmed = mod.trim().split(/\s+/)[0]; // handle "import os as o"
            if (trimmed) imports.add(trimmed);
          }
        }
      }
      break;
    }

    case "go": {
      // Single import: import "fmt"
      const singleImportRe = /import\s+"([^"]+)"/g;
      let match: RegExpExecArray | null;
      while ((match = singleImportRe.exec(content)) !== null) {
        if (match[1]) imports.add(match[1]);
      }

      // Block import: import ( ... )
      const blockImportRe = /import\s*\(([\s\S]*?)\)/g;
      while ((match = blockImportRe.exec(content)) !== null) {
        if (match[1]) {
          const lineRe = /["']([^"']+)["']/g;
          let lineMatch: RegExpExecArray | null;
          while ((lineMatch = lineRe.exec(match[1])) !== null) {
            if (lineMatch[1]) imports.add(lineMatch[1]);
          }
        }
      }
      break;
    }

    case "java":
    case "kotlin": {
      // import <package.Class>;  or  import <package.Class>
      const javaImportRe = /^import\s+(?:static\s+)?([\w.]+)/gm;
      let match: RegExpExecArray | null;
      while ((match = javaImportRe.exec(content)) !== null) {
        if (match[1]) imports.add(match[1]);
      }
      break;
    }

    default:
      // Unsupported language — return empty set
      break;
  }

  return Array.from(imports);
}

// ---------------------------------------------------------------------------
// Path resolution helpers
// ---------------------------------------------------------------------------

/**
 * Resolve a relative import specifier against the importing file's path
 * to produce a repo-relative file path. Returns candidate paths with
 * common extensions for extensionless imports.
 */
function resolveImportPath(
  importSpecifier: string,
  importerPath: string,
  language: string,
): string[] {
  // Skip bare/package specifiers (no leading dot or slash)
  if (language === "typescript" || language === "javascript") {
    if (!importSpecifier.startsWith(".") && !importSpecifier.startsWith("/")) {
      return [];
    }
  }

  if (language === "python") {
    // Convert dotted module path to filesystem path
    const asPath = importSpecifier.replace(/\./g, "/");
    const importerDir = dirName(importerPath);
    const resolved = joinPath(importerDir, asPath);
    return [
      `${resolved}.py`,
      `${resolved}/__init__.py`,
    ];
  }

  if (language === "go" || language === "java" || language === "kotlin") {
    // These use package-level imports; skip resolution for now as
    // matching requires build-system knowledge beyond regex analysis.
    return [];
  }

  // TypeScript / JavaScript relative resolution
  const importerDir = dirName(importerPath);
  const resolved = joinPath(importerDir, importSpecifier);

  // If the specifier already has an extension, return it as-is
  if (/\.\w+$/.test(importSpecifier)) {
    return [resolved];
  }

  // Otherwise try common extensions
  return [
    `${resolved}.ts`,
    `${resolved}.tsx`,
    `${resolved}.js`,
    `${resolved}.jsx`,
    `${resolved}/index.ts`,
    `${resolved}/index.tsx`,
    `${resolved}/index.js`,
    `${resolved}/index.jsx`,
  ];
}

/** Simple dirname — returns the directory portion of a path. */
function dirName(filePath: string): string {
  const idx = filePath.lastIndexOf("/");
  return idx === -1 ? "" : filePath.slice(0, idx);
}

/** Simple path join that normalizes slashes and resolves single-dot segments. */
function joinPath(base: string, relative: string): string {
  if (relative.startsWith("/")) return normalizePath(relative);
  const combined = base ? `${base}/${relative}` : relative;
  return normalizePath(combined);
}

/** Normalize a path: resolve `.` and `..` segments, collapse multiple slashes. */
function normalizePath(p: string): string {
  const parts = p.split("/").filter(Boolean);
  const resolved: string[] = [];
  for (const part of parts) {
    if (part === ".") continue;
    if (part === "..") {
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }
  return resolved.join("/");
}

// ---------------------------------------------------------------------------
// Context expansion
// ---------------------------------------------------------------------------

/**
 * Given changed files from a PR diff, discover related files via 1-hop
 * import/dependency analysis.
 *
 * @param changedFiles - Files from the PR diff
 * @param readFile - Reads a repo file by path; returns null if not found or too large
 * @param listFiles - Lists all file paths in the repo
 * @param options - Expansion limits
 */
export async function expandContext(
  changedFiles: FileChange[],
  readFile: (path: string) => Promise<string | null>,
  listFiles: () => Promise<string[]>,
  options?: ExpandContextOptions,
): Promise<ContextExpansion> {
  const maxRelatedFiles = options?.maxRelatedFiles ?? DEFAULT_MAX_RELATED_FILES;
  const maxFileSize = options?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;

  const relatedFiles: RelatedFile[] = [];
  const expansionLog: string[] = [];
  const includedPaths = new Set<string>();

  // Track changed file paths for quick lookup
  const changedPaths = new Set(changedFiles.map((f) => f.path));

  // ------------------------------------------------------------------
  // Phase 1: Forward dependencies — files imported by changed files
  // ------------------------------------------------------------------
  expansionLog.push("=== Phase 1: Forward dependencies (imports from changed files) ===");

  for (const file of changedFiles) {
    if (relatedFiles.length >= maxRelatedFiles) break;

    // Read the full content of the changed file (the diff alone may
    // not contain all imports, so we read the full file at HEAD)
    const fullContent = await readFile(file.path);
    const contentToScan = fullContent ?? file.diff;

    const imports = extractImports(contentToScan, file.language);
    if (imports.length === 0) continue;

    for (const imp of imports) {
      if (relatedFiles.length >= maxRelatedFiles) break;

      const candidates = resolveImportPath(imp, file.path, file.language);
      for (const candidate of candidates) {
        if (relatedFiles.length >= maxRelatedFiles) break;

        let safePath: string;
        try {
          safePath = sanitizeFilePath(candidate);
        } catch {
          continue; // Skip invalid paths
        }

        if (changedPaths.has(safePath) || includedPaths.has(safePath)) continue;

        const content = await readFile(safePath);
        if (content === null) continue;
        if (content.length > maxFileSize) {
          expansionLog.push(
            `Skipped ${safePath} (imported by ${file.path}): exceeds max file size (${content.length} > ${maxFileSize})`,
          );
          continue;
        }

        relatedFiles.push({
          path: safePath,
          content,
          relationship: "imports-changed",
          relatedTo: file.path,
        });
        includedPaths.add(safePath);
        expansionLog.push(
          `Included ${safePath} — imported by changed file ${file.path} (via "${imp}")`,
        );
        break; // Found the resolved file, no need to try more candidates
      }
    }
  }

  // ------------------------------------------------------------------
  // Phase 2: Reverse dependencies — repo files that import changed files
  // ------------------------------------------------------------------
  expansionLog.push("=== Phase 2: Reverse dependencies (files importing changed files) ===");

  if (relatedFiles.length < maxRelatedFiles) {
    const allFiles = await listFiles();

    // Build a set of patterns to search for: the basenames and relative
    // paths of changed files that other files might use in import statements.
    const changedFilePatterns: string[] = [];
    for (const cp of changedPaths) {
      // Add the full path
      changedFilePatterns.push(cp);
      // Add the path without extension (for extensionless imports)
      const noExt = cp.replace(/\.\w+$/, "");
      changedFilePatterns.push(noExt);
      // Add just the filename without extension
      const lastSlash = noExt.lastIndexOf("/");
      if (lastSlash !== -1) {
        changedFilePatterns.push(noExt.slice(lastSlash + 1));
      }
    }

    for (const repoFile of allFiles) {
      if (relatedFiles.length >= maxRelatedFiles) break;

      let safePath: string;
      try {
        safePath = sanitizeFilePath(repoFile);
      } catch {
        continue;
      }

      if (changedPaths.has(safePath) || includedPaths.has(safePath)) continue;

      // Only scan source files likely to have imports
      const lang = detectLanguageFromPath(safePath);
      if (!lang) continue;

      const content = await readFile(safePath);
      if (content === null) continue;
      if (content.length > maxFileSize) continue;

      const imports = extractImports(content, lang);
      if (imports.length === 0) continue;

      // Check if any import references a changed file
      for (const imp of imports) {
        const candidates = resolveImportPath(imp, safePath, lang);
        let found = false;
        for (const candidate of candidates) {
          const normalizedCandidate = normalizePath(candidate);
          if (changedPaths.has(normalizedCandidate)) {
            relatedFiles.push({
              path: safePath,
              content,
              relationship: "imported-by-changed",
              relatedTo: normalizedCandidate,
            });
            includedPaths.add(safePath);
            expansionLog.push(
              `Included ${safePath} — imports changed file ${normalizedCandidate} (via "${imp}")`,
            );
            found = true;
            break;
          }
        }
        if (found) break;
      }
    }
  }

  expansionLog.push(
    `=== Context expansion complete: ${relatedFiles.length} related files found ===`,
  );

  return {
    directChanges: changedFiles,
    relatedFiles,
    expansionLog,
  };
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/** Detect language from file path extension. Returns null for non-source files. */
function detectLanguageFromPath(filePath: string): string | null {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx")) return "typescript";
  if (lower.endsWith(".js") || lower.endsWith(".jsx")) return "javascript";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".go")) return "go";
  if (lower.endsWith(".java")) return "java";
  if (lower.endsWith(".kt") || lower.endsWith(".kts")) return "kotlin";
  return null;
}
