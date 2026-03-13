/**
 * Command: synthesis.scanGitChanges
 *
 * Scans uncommitted git changes (staged + unstaged) by invoking `git diff`
 * through VS Code's built-in git extension API.  Falls back to spawning
 * `git diff` via child_process if the git extension is unavailable.
 *
 * Ideal for pre-commit threat review.
 *
 * SECURITY:
 *   - Git output is sanitized before passing to the AI provider
 *   - Diff size is bounded to prevent resource exhaustion
 *   - No shell interpolation — arguments are passed as array elements
 *
 * References:
 *   - STRIDE / Tampering — validate git output integrity
 *   - STRIDE / Denial of Service — bound diff size
 */

import * as vscode from "vscode";
import { generateThreatModel, parseDiff } from "@synthesis/core";
import type {
  AnalysisInput,
  SynthesisConfig,
  ThreatModel,
} from "@synthesis/core";
import { SecretStorageManager } from "../utils/secret-storage";
import { stripScriptContent } from "../utils/sanitizer";

/** Maximum diff size in bytes (1 MB) to prevent resource exhaustion. */
const MAX_DIFF_BYTES = 1_048_576;

export async function scanGitChanges(
  secretStorage: SecretStorageManager,
): Promise<ThreatModel | undefined> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showErrorMessage(
      "Synthesis: No workspace folder open.",
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

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Synthesis: Scanning git changes...",
      cancellable: true,
    },
    async (progress, token) => {
      progress.report({ message: "Getting diff...", increment: 20 });

      let rawDiff: string;
      try {
        rawDiff = await getGitDiff(workspaceFolders[0]!.uri.fsPath);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to get git diff";
        vscode.window.showErrorMessage(
          `Synthesis: ${message}`,
        );
        return undefined;
      }

      if (token.isCancellationRequested) {
        return undefined;
      }

      if (!rawDiff || rawDiff.trim().length === 0) {
        vscode.window.showInformationMessage(
          "Synthesis: No uncommitted changes found.",
        );
        return undefined;
      }

      // SECURITY: bound diff size to prevent resource exhaustion
      if (Buffer.byteLength(rawDiff, "utf-8") > MAX_DIFF_BYTES) {
        vscode.window.showWarningMessage(
          `Synthesis: Diff exceeds ${MAX_DIFF_BYTES / 1024}KB. Truncating to prevent resource exhaustion.`,
        );
        rawDiff = rawDiff.substring(
          0,
          rawDiff.lastIndexOf("\n", MAX_DIFF_BYTES),
        );
      }

      // SECURITY: sanitize git output — strip any embedded script content
      const sanitizedDiff = stripScriptContent(rawDiff);

      progress.report({ message: "Parsing diff...", increment: 20 });

      const files = parseDiff(sanitizedDiff);

      if (files.length === 0) {
        vscode.window.showInformationMessage(
          "Synthesis: Git diff parsed but contained no file changes.",
        );
        return undefined;
      }

      progress.report({
        message: `Analyzing ${files.length} changed files...`,
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

        progress.report({ message: "Done.", increment: 30 });

        vscode.window.showInformationMessage(
          `Synthesis: ${model.threats.length} threat${model.threats.length === 1 ? "" : "s"} found in git changes.`,
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

// ── Git diff retrieval ──────────────────────────────────────

/**
 * Attempt to get the diff via the VS Code git extension API first.
 * Falls back to spawning git directly if the extension is not available.
 *
 * SECURITY: No shell interpolation — arguments passed as array.
 */
async function getGitDiff(cwd: string): Promise<string> {
  // Try VS Code git extension first
  const gitExtension = vscode.extensions.getExtension<GitExtensionApi>(
    "vscode.git",
  );

  if (gitExtension) {
    const git = gitExtension.isActive
      ? gitExtension.exports
      : await gitExtension.activate();

    const api = git.getAPI(1);
    if (api.repositories.length > 0) {
      const repo = api.repositories[0]!;
      const diff = await repo.diff(true); // include staged
      const unstaged = await repo.diff(false);
      return [diff, unstaged].filter(Boolean).join("\n");
    }
  }

  // Fallback: spawn git directly
  return spawnGitDiff(cwd);
}

/**
 * Spawn `git diff` as a child process.
 * SECURITY: Arguments are passed as an array — no shell interpolation.
 */
function spawnGitDiff(cwd: string): Promise<string> {
  const cp = require("child_process") as typeof import("child_process");

  return new Promise((resolve, reject) => {
    const proc = cp.spawn("git", ["diff", "HEAD"], {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      // SECURITY: no shell — prevents command injection
      shell: false,
      timeout: 30_000, // 30s timeout
    });

    const chunks: Buffer[] = [];
    let totalBytes = 0;

    proc.stdout.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      // SECURITY: bound output size
      if (totalBytes <= MAX_DIFF_BYTES) {
        chunks.push(chunk);
      }
    });

    let stderr = "";
    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf-8").substring(0, 1024);
    });

    proc.on("close", (code: number | null) => {
      if (code === 0 || code === 1) {
        // git diff exits 1 when there are differences — that is normal
        resolve(Buffer.concat(chunks).toString("utf-8"));
      } else {
        reject(
          new Error(
            `git diff exited with code ${code}: ${stderr.substring(0, 200)}`,
          ),
        );
      }
    });

    proc.on("error", (err: Error) => {
      reject(
        new Error(`Failed to spawn git: ${err.message}`),
      );
    });
  });
}

// ── VS Code Git Extension API types (minimal) ──────────────

interface GitExtensionApi {
  getAPI(version: 1): GitApi;
}

interface GitApi {
  repositories: GitRepository[];
}

interface GitRepository {
  diff(staged?: boolean): Promise<string>;
}
