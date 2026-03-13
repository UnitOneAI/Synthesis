/**
 * Synthesis Threat Model — VS Code / Cursor Extension
 *
 * Main activation entry point.  Registers all commands, providers, views,
 * and status bar items.  Compatible with both VS Code and Cursor (same
 * extension API).
 *
 * SECURITY ARCHITECTURE:
 *   - API keys stored in VS Code SecretStorage (never settings.json)
 *   - Legacy plaintext keys migrated and cleared on first activation
 *   - All webview content rendered with strict CSP (nonce-based)
 *   - All dynamic strings HTML-sanitized before webview injection
 *   - File paths validated to workspace scope (no traversal)
 *   - Resource limits enforced (maxFiles, diff size caps)
 *
 * References:
 *   - OWASP Secrets Management Cheat Sheet
 *   - STRIDE threat model applied to the extension itself
 *   - NIST SP 800-57 Part 1 Rev 5 (key storage)
 */

import * as vscode from "vscode";
import type { ThreatModel } from "@synthesis/core";

import { SecretStorageManager } from "./utils/secret-storage";
import { scanWorkspace } from "./commands/scan-workspace";
import { scanFile } from "./commands/scan-file";
import { scanGitChanges } from "./commands/scan-git-changes";
import { showThreatPanel, disposeThreatPanel } from "./views/threat-panel";
import {
  ThreatTreeProvider,
  type GroupBy,
} from "./views/threat-tree-provider";
import { ThreatCodeLensProvider } from "./providers/codelens-provider";
import { ThreatDiagnosticsProvider } from "./providers/diagnostics-provider";
import { SynthesisStatusBar } from "./providers/status-bar";

// ── Shared state ─────────────────────────────────────────────

let latestModel: ThreatModel | undefined;

// ── Activation ──────────────────────────────────────────────

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  // ── Secret storage ──────────────────────────────────────────
  const secretStorage = new SecretStorageManager(context.secrets);

  // Migrate any legacy plaintext keys from settings.json → SecretStorage
  await secretStorage.migrateLegacyKeys();

  // Warn if no API key is configured (non-blocking)
  const provider = vscode.workspace
    .getConfiguration("synthesis")
    .get<string>("provider", "anthropic") as "anthropic" | "gemini";
  const existingKey = await secretStorage.getKeyForProvider(provider);
  if (!existingKey) {
    vscode.window.showWarningMessage(
      `Synthesis: No API key configured for "${provider}". ` +
        `Run a scan command to be prompted, or set it via the command palette.`,
    );
  }

  // ── Providers ───────────────────────────────────────────────
  const treeProvider = new ThreatTreeProvider();
  const codeLensProvider = new ThreatCodeLensProvider();
  const diagnosticsProvider = new ThreatDiagnosticsProvider();
  const statusBar = new SynthesisStatusBar();

  // ── Tree view ───────────────────────────────────────────────
  const treeView = vscode.window.createTreeView("synthesis-explorer", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  // ── CodeLens registration (all file types) ─────────────────
  const codeLensDisposable = vscode.languages.registerCodeLensProvider(
    { scheme: "file" },
    codeLensProvider,
  );

  // ── Helper: propagate scan results to all UI surfaces ──────
  function onScanComplete(model: ThreatModel): void {
    latestModel = model;
    treeProvider.setModel(model);
    codeLensProvider.setModel(model);
    statusBar.update(model);

    const workspaceRoot =
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (workspaceRoot) {
      diagnosticsProvider.update(model, workspaceRoot);
    }

    showThreatPanel(context.extensionUri, model);
  }

  // ── Commands ────────────────────────────────────────────────

  const cmdScanWorkspace = vscode.commands.registerCommand(
    "synthesis.scanWorkspace",
    async () => {
      statusBar.setScanning();
      try {
        const model = await scanWorkspace(secretStorage);
        if (model) {
          onScanComplete(model);
        } else {
          statusBar.reset();
        }
      } catch {
        statusBar.reset();
      }
    },
  );

  const cmdScanFile = vscode.commands.registerCommand(
    "synthesis.scanFile",
    async (uri?: vscode.Uri) => {
      statusBar.setScanning();
      try {
        const model = await scanFile(secretStorage, uri);
        if (model) {
          onScanComplete(model);
        } else {
          statusBar.reset();
        }
      } catch {
        statusBar.reset();
      }
    },
  );

  const cmdScanGitChanges = vscode.commands.registerCommand(
    "synthesis.scanGitChanges",
    async () => {
      statusBar.setScanning();
      try {
        const model = await scanGitChanges(secretStorage);
        if (model) {
          onScanComplete(model);
        } else {
          statusBar.reset();
        }
      } catch {
        statusBar.reset();
      }
    },
  );

  const cmdShowThreatModel = vscode.commands.registerCommand(
    "synthesis.showThreatModel",
    () => {
      showThreatPanel(context.extensionUri, latestModel);
    },
  );

  // ── Disposables ─────────────────────────────────────────────
  context.subscriptions.push(
    cmdScanWorkspace,
    cmdScanFile,
    cmdScanGitChanges,
    cmdShowThreatModel,
    codeLensDisposable,
    treeView,
    diagnosticsProvider,
    statusBar,
  );
}

// ── Deactivation ────────────────────────────────────────────

export function deactivate(): void {
  disposeThreatPanel();
}
