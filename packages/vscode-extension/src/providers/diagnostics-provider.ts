/**
 * Maps threat model findings to VS Code Diagnostic entries so they appear
 * in the Problems panel with file/line references.
 *
 * Severity mapping:
 *   critical, high  -> DiagnosticSeverity.Error
 *   medium          -> DiagnosticSeverity.Warning
 *   low             -> DiagnosticSeverity.Information
 *   info            -> DiagnosticSeverity.Hint
 */

import * as vscode from "vscode";
import type { ThreatModel, ThreatEntry } from "@synthesis/core";

const DIAGNOSTIC_SOURCE = "Synthesis";

export class ThreatDiagnosticsProvider {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection =
      vscode.languages.createDiagnosticCollection("synthesis-threats");
  }

  /**
   * Replace all diagnostics with findings from the given model.
   * Existing diagnostics are cleared first.
   */
  update(model: ThreatModel, workspaceRoot: string): void {
    this.clear();

    // Group threats by their best-guess file path
    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const threat of model.threats) {
      const filePath = resolveFilePath(threat, workspaceRoot);
      if (!filePath) {
        continue;
      }

      const uri = vscode.Uri.file(filePath);
      const key = uri.toString();
      const diag = threatToDiagnostic(threat);

      const existing = byFile.get(key);
      if (existing) {
        existing.push(diag);
      } else {
        byFile.set(key, [diag]);
      }
    }

    for (const [uriStr, diagnostics] of byFile) {
      this.collection.set(vscode.Uri.parse(uriStr), diagnostics);
    }
  }

  /**
   * Clear all Synthesis diagnostics.
   */
  clear(): void {
    this.collection.clear();
  }

  dispose(): void {
    this.collection.dispose();
  }
}

// ── Helpers ─────────────────────────────────────────────────

function threatToDiagnostic(threat: ThreatEntry): vscode.Diagnostic {
  // Threats don't carry exact line info — default to line 0
  const range = new vscode.Range(0, 0, 0, 0);

  const severity = mapSeverity(threat.severity);

  const message = `[${threat.stride.toUpperCase()}] ${threat.description}` +
    (threat.mitigation ? `\n\nMitigation: ${threat.mitigation}` : "");

  const diag = new vscode.Diagnostic(range, message, severity);
  diag.source = DIAGNOSTIC_SOURCE;
  diag.code = threat.id;
  return diag;
}

function mapSeverity(
  severity: string,
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Best-effort resolution of a threat's affected component to a workspace file.
 * Returns null if no matching file can be determined.
 *
 * SECURITY: The returned path is validated to be within the workspace root
 * to prevent path traversal.
 */
function resolveFilePath(
  threat: ThreatEntry,
  workspaceRoot: string,
): string | null {
  const path = require("path") as typeof import("path");

  // The component field may contain a file path hint like "AuthService /src/auth.ts"
  const pathMatch = threat.component.match(
    /(?:^|\s)((?:\.\/|\/|src\/)[^\s]+\.\w+)/,
  );
  if (!pathMatch?.[1]) {
    return null;
  }

  const candidate = path.resolve(workspaceRoot, pathMatch[1]);

  // SECURITY: Ensure resolved path is within workspace (prevent path traversal)
  const normalizedRoot = path.resolve(workspaceRoot) + path.sep;
  const normalizedCandidate = path.resolve(candidate);
  if (!normalizedCandidate.startsWith(normalizedRoot) && normalizedCandidate !== path.resolve(workspaceRoot)) {
    return null;
  }

  return normalizedCandidate;
}
