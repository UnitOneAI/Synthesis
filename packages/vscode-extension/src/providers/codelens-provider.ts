/**
 * CodeLens provider — shows inline "N threats identified" annotations above
 * functions and classes that have associated threats from the latest scan.
 *
 * Only active after a scan produces a ThreatModel.  Clicking the lens opens
 * the threat panel filtered to that component.
 */

import * as vscode from "vscode";
import type { ThreatModel, ThreatEntry } from "@synthesis/core";

export class ThreatCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  private model: ThreatModel | undefined;

  /**
   * Update the backing model and refresh all CodeLens decorations.
   */
  setModel(model: ThreatModel): void {
    this.model = model;
    this._onDidChangeCodeLenses.fire();
  }

  clear(): void {
    this.model = undefined;
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken,
  ): vscode.CodeLens[] {
    if (!this.model) {
      return [];
    }

    const lenses: vscode.CodeLens[] = [];
    const text = document.getText();
    const filePath = document.uri.fsPath;

    // Collect threats relevant to this file (by component name match or path)
    const fileThreats = this.model.threats.filter((t) =>
      threatMatchesFile(t, filePath, text),
    );

    if (fileThreats.length === 0) {
      return [];
    }

    // Group by component
    const byComponent = new Map<string, ThreatEntry[]>();
    for (const t of fileThreats) {
      const existing = byComponent.get(t.component);
      if (existing) {
        existing.push(t);
      } else {
        byComponent.set(t.component, [t]);
      }
    }

    // For each component, try to find the line where it is defined/referenced
    for (const [component, threats] of byComponent) {
      const line = findComponentLine(document, component);
      if (line < 0) {
        continue;
      }

      const range = new vscode.Range(line, 0, line, 0);

      const criticalCount = threats.filter(
        (t) => t.severity === "critical",
      ).length;
      const highCount = threats.filter(
        (t) => t.severity === "high",
      ).length;

      let label = `$(shield) ${threats.length} threat${threats.length === 1 ? "" : "s"} identified`;
      if (criticalCount > 0) {
        label += ` (${criticalCount} critical)`;
      } else if (highCount > 0) {
        label += ` (${highCount} high)`;
      }

      lenses.push(
        new vscode.CodeLens(range, {
          title: label,
          command: "synthesis.showThreatModel",
          tooltip: `View ${threats.length} threats for component "${component}"`,
        }),
      );
    }

    return lenses;
  }
}

// ── Helpers ─────────────────────────────────────────────────

/**
 * Check if a threat is associated with the given file.
 * We match on: (a) component name appearing in the file text, or
 * (b) threat.component containing part of the file name.
 */
function threatMatchesFile(
  threat: ThreatEntry,
  filePath: string,
  fileContent: string,
): boolean {
  const componentLower = threat.component.toLowerCase();
  const fileNameLower = filePath.toLowerCase();

  // Component name referenced in the file content
  if (fileContent.toLowerCase().includes(componentLower)) {
    return true;
  }

  // File path contains the component name (e.g., auth-service.ts matches "auth service")
  const normalized = componentLower.replace(/[\s_-]+/g, "");
  const fileNormalized = fileNameLower.replace(/[\s_\-/\\]+/g, "");
  if (fileNormalized.includes(normalized)) {
    return true;
  }

  return false;
}

/**
 * Find the line number where a component is likely defined.
 * Searches for class/function/export declarations matching the component name.
 */
function findComponentLine(
  document: vscode.TextDocument,
  component: string,
): number {
  const searchTerms = component
    .toLowerCase()
    .split(/[\s_-]+/)
    .filter((s) => s.length > 2);

  for (let i = 0; i < document.lineCount; i++) {
    const lineText = document.lineAt(i).text.toLowerCase();
    // Look for class, function, interface, type, export declarations
    const isDeclaration =
      /\b(class|function|interface|type|export|const|module)\b/.test(
        lineText,
      );
    if (
      isDeclaration &&
      searchTerms.some((term) => lineText.includes(term))
    ) {
      return i;
    }
  }

  // Fallback: first line that mentions any search term
  for (let i = 0; i < Math.min(document.lineCount, 200); i++) {
    const lineText = document.lineAt(i).text.toLowerCase();
    if (searchTerms.some((term) => lineText.includes(term))) {
      return i;
    }
  }

  return -1;
}
