/**
 * Command: synthesis.scanFile
 *
 * Scans a single file — either the active editor or a file selected via the
 * explorer context menu.
 *
 * SECURITY:
 *   - Validates that the target file is within the workspace root (path traversal guard)
 *   - Rejects URIs with non-file schemes
 *
 * References:
 *   - STRIDE / Elevation of Privilege — path traversal prevention
 *   - OWASP — input validation
 */

import * as vscode from "vscode";
import { generateThreatModel } from "@synthesis/core";
import type {
  AnalysisInput,
  SynthesisConfig,
  ThreatModel,
  FileChange,
} from "@synthesis/core";
import { SecretStorageManager } from "../utils/secret-storage";

export async function scanFile(
  secretStorage: SecretStorageManager,
  targetUri?: vscode.Uri,
): Promise<ThreatModel | undefined> {
  // ── Resolve target file ────────────────────────────────────
  let fileUri: vscode.Uri | undefined = targetUri;

  if (!fileUri) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showErrorMessage(
        "Synthesis: No file is open. Open a file or right-click one in the explorer.",
      );
      return undefined;
    }
    fileUri = editor.document.uri;
  }

  // SECURITY: Only allow file:// scheme
  if (fileUri.scheme !== "file") {
    vscode.window.showErrorMessage(
      "Synthesis: Only local files can be scanned (file:// scheme required).",
    );
    return undefined;
  }

  // SECURITY: Validate file is within workspace to prevent path traversal
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showErrorMessage(
      "Synthesis: No workspace folder open.",
    );
    return undefined;
  }

  const path = require("path") as typeof import("path");
  const workspaceRoot = workspaceFolders[0]!.uri.fsPath;
  const normalizedRoot = path.resolve(workspaceRoot) + path.sep;
  const normalizedFile = path.resolve(fileUri.fsPath);

  if (
    !normalizedFile.startsWith(normalizedRoot) &&
    normalizedFile !== path.resolve(workspaceRoot)
  ) {
    vscode.window.showErrorMessage(
      "Synthesis: File is outside the workspace. Only workspace files can be scanned.",
    );
    return undefined;
  }

  // ── Pre-flight: API key ────────────────────────────────────
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

  // ── Read and analyze ───────────────────────────────────────
  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Synthesis: Scanning ${path.basename(fileUri.fsPath)}...`,
      cancellable: true,
    },
    async (progress, token) => {
      progress.report({ message: "Reading file...", increment: 20 });

      let content: string;
      try {
        const bytes = await vscode.workspace.fs.readFile(fileUri);
        content = Buffer.from(bytes).toString("utf-8");
      } catch {
        vscode.window.showErrorMessage(
          `Synthesis: Could not read file ${fileUri.fsPath}`,
        );
        return undefined;
      }

      if (token.isCancellationRequested) {
        return undefined;
      }

      const relativePath = vscode.workspace.asRelativePath(fileUri);
      const ext = relativePath.split(".").pop() || "";

      const files: FileChange[] = [
        { path: relativePath, diff: content, language: ext },
      ];

      progress.report({ message: "Analyzing...", increment: 40 });

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

        vscode.window.showInformationMessage(
          `Synthesis: ${model.threats.length} threat${model.threats.length === 1 ? "" : "s"} found in ${path.basename(fileUri.fsPath)}.`,
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
