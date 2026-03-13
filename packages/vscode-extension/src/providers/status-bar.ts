/**
 * Status bar item showing a summary of the latest scan results.
 *
 * Format: "$(shield) Synthesis: 2C 5H 3M"
 * Colors:
 *   - Red background if any critical threats
 *   - Yellow background if high but no critical
 *   - Default (green text) if clean
 *
 * Click opens the threat panel.
 */

import * as vscode from "vscode";
import type { ThreatModel } from "@synthesis/core";

export class SynthesisStatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100,
    );
    this.item.command = "synthesis.showThreatModel";
    this.item.tooltip = "Synthesis Threat Model — click to view results";
    this.reset();
    this.item.show();
  }

  /**
   * Update the status bar with counts from a completed scan.
   */
  update(model: ThreatModel): void {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const t of model.threats) {
      const sev = t.severity as keyof typeof counts;
      if (sev in counts) {
        counts[sev]++;
      }
    }

    const total =
      counts.critical + counts.high + counts.medium + counts.low;

    if (total === 0) {
      this.item.text = "$(shield) Synthesis: Clean";
      this.item.backgroundColor = undefined;
      this.item.color = new vscode.ThemeColor("testing.iconPassed");
      return;
    }

    const parts: string[] = [];
    if (counts.critical > 0) {
      parts.push(`${counts.critical}C`);
    }
    if (counts.high > 0) {
      parts.push(`${counts.high}H`);
    }
    if (counts.medium > 0) {
      parts.push(`${counts.medium}M`);
    }
    if (counts.low > 0) {
      parts.push(`${counts.low}L`);
    }

    this.item.text = `$(shield) Synthesis: ${parts.join(" ")}`;

    if (counts.critical > 0) {
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground",
      );
      this.item.color = undefined;
    } else if (counts.high > 0) {
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground",
      );
      this.item.color = undefined;
    } else {
      this.item.backgroundColor = undefined;
      this.item.color = undefined;
    }
  }

  /**
   * Show a "scanning..." state.
   */
  setScanning(): void {
    this.item.text = "$(loading~spin) Synthesis: Scanning...";
    this.item.backgroundColor = undefined;
    this.item.color = undefined;
  }

  /**
   * Reset to default idle state.
   */
  reset(): void {
    this.item.text = "$(shield) Synthesis";
    this.item.backgroundColor = undefined;
    this.item.color = undefined;
  }

  dispose(): void {
    this.item.dispose();
  }
}
