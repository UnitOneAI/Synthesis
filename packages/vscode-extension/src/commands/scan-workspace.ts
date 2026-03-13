/**
 * Command: synthesis.scanWorkspace
 *
 * Globs all source files in the workspace (respecting .gitignore), feeds them
 * to the core `generateThreatModel`, and displays results.
 *
 * SECURITY:
 *   - Respects maxFiles configuration to prevent resource exhaustion (DoS)
 *   - Validates workspace folder exists before scanning
 *   - Aborts gracefully on cancellation
 *
 * References:
 *   - STRIDE / Denial of Service — maxFiles guard
 *   - OWASP — resource exhaustion prevention
 */

import * as vscode from "vscode";
import {
  generateThreatModel,
  extractComponents,
  parseDiff,
} from "@synthesis/core";
import type {
  AnalysisInput,
  SynthesisConfig,
  ThreatModel,
  FileChange,
} from "@synthesis/core";
import { SecretStorageManager } from "../utils/secret-storage";

/** File extensions to include in workspace scans. */
const SOURCE_EXTENSIONS = [
  "ts",
  "tsx",
  "js",
  "jsx",
  "py",
  "go",
  "rs",
  "java",
  "kt",
  "cs",
  "rb",
  "php",
  "swift",
  "c",
  "cpp",
  "h",
  "yaml",
  "yml",
  "json",
  "toml",
  "tf",
  "hcl",
  "Dockerfile",
  "sh",
];

export async function scanWorkspace(
  secretStorage: SecretStorageManager,
): Promise<ThreatModel | undefined> {
  // ── Pre-flight checks ──────────────────────────────────────
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showErrorMessage(
      "Synthesis: No workspace folder open. Open a folder first.",
    );
    return undefined;
  }

  const hasKey = await secretStorage.ensureKeyConfigured();
  if (!hasKey) {
    return undefined;
  }

  const config = vscode.workspace.getConfiguration("synthesis");
  const provider = config.get<"anthropic" | "gemini">("provider", "anthropic");
  const frameworks = config.get<string[]>("frameworks", ["STRIDE"]);
  const severityThreshold = config.get<string>("severityThreshold", "low");
  const maxFiles = config.get<number>("maxFiles", 100);

  const apiKey = await secretStorage.getKeyForProvider(provider);
  if (!apiKey) {
    vscode.window.showErrorMessage(
      `Synthesis: No API key found for provider "${provider}".`,
    );
    return undefined;
  }

  // ── Scan with progress ─────────────────────────────────────
  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Synthesis: Scanning workspace...",
      cancellable: true,
    },
    async (progress, token) => {
      const rootUri = workspaceFolders[0]!.uri;

      // Build glob pattern for source files
      const globPattern = `**/*.{${SOURCE_EXTENSIONS.join(",")}}`;

      progress.report({ message: "Discovering files...", increment: 10 });

      const fileUris = await vscode.workspace.findFiles(
        new vscode.RelativePattern(rootUri, globPattern),
        "**/node_modules/**", // exclude
        maxFiles + 1, // fetch one extra to detect truncation
        token,
      );

      if (token.isCancellationRequested) {
        return undefined;
      }

      // SECURITY: enforce maxFiles limit — prevent resource exhaustion
      let truncated = false;
      let urisToProcess = fileUris;
      if (fileUris.length > maxFiles) {
        truncated = true;
        urisToProcess = fileUris.slice(0, maxFiles);
        vscode.window.showWarningMessage(
          `Synthesis: Workspace contains more than ${maxFiles} source files. ` +
            `Scanning the first ${maxFiles}. Increase synthesis.maxFiles to scan more.`,
        );
      }

      progress.report({
        message: `Reading ${urisToProcess.length} files...`,
        increment: 20,
      });

      // Read file contents
      const files: FileChange[] = [];
      for (const uri of urisToProcess) {
        if (token.isCancellationRequested) {
          return undefined;
        }
        try {
          const bytes = await vscode.workspace.fs.readFile(uri);
          const content = Buffer.from(bytes).toString("utf-8");
          const relativePath = vscode.workspace.asRelativePath(uri);
          const ext = relativePath.split(".").pop() || "";
          files.push({
            path: relativePath,
            diff: content, // full content as "diff" for analysis
            language: ext,
          });
        } catch {
          // Skip unreadable files silently
        }
      }

      if (files.length === 0) {
        vscode.window.showInformationMessage(
          "Synthesis: No readable source files found in workspace.",
        );
        return undefined;
      }

      progress.report({
        message: `Analyzing ${files.length} files...`,
        increment: 30,
      });

      const input: AnalysisInput = { files };
      const synthConfig: SynthesisConfig = {
        provider,
        apiKey,
        frameworks: frameworks as SynthesisConfig["frameworks"],
        severityThreshold: severityThreshold as SynthesisConfig["severityThreshold"],
        maxFiles,
      };

      try {
        const model = await generateThreatModel(input, synthConfig);

        progress.report({ message: "Done.", increment: 40 });

        const total = model.threats.length;
        const critCount = model.threats.filter(
          (t) => t.severity === "critical",
        ).length;
        const highCount = model.threats.filter(
          (t) => t.severity === "high",
        ).length;

        vscode.window.showInformationMessage(
          `Synthesis: Scan complete — ${total} threats found` +
            (critCount > 0 ? ` (${critCount} critical)` : "") +
            (highCount > 0 ? ` (${highCount} high)` : "") +
            (truncated ? " [truncated]" : ""),
        );

        return model;
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Unknown error during analysis";
        vscode.window.showErrorMessage(
          `Synthesis: Analysis failed — ${message}`,
        );
        return undefined;
      }
    },
  );
}
