/**
 * TreeDataProvider for the Synthesis sidebar — shows threats grouped by
 * STRIDE category, severity, or component.
 *
 * Clicking a leaf node navigates to the associated file/line when available
 * and opens the threat panel filtered to that entry.
 */

import * as vscode from "vscode";
import type { ThreatModel, ThreatEntry, STRIDECategory } from "@synthesis/core";

// ── Grouping modes ──────────────────────────────────────────

export type GroupBy = "stride" | "severity" | "component";

// ── Tree item types ─────────────────────────────────────────

export class ThreatGroupItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly threats: ThreatEntry[],
  ) {
    super(label, vscode.TreeItemCollapsibleState.Collapsed);
    this.description = `${threats.length} threat${threats.length === 1 ? "" : "s"}`;
    this.iconPath = new vscode.ThemeIcon("shield");
  }
}

export class ThreatLeafItem extends vscode.TreeItem {
  constructor(public readonly threat: ThreatEntry) {
    super(threat.id, vscode.TreeItemCollapsibleState.None);
    this.description = `[${threat.severity}] ${threat.component}`;
    this.tooltip = `${threat.stride}: ${threat.description}\n\nMitigation: ${threat.mitigation}`;
    this.iconPath = severityIcon(threat.severity);
    this.command = {
      command: "synthesis.showThreatModel",
      title: "Show Threat Details",
    };
  }
}

type TreeItem = ThreatGroupItem | ThreatLeafItem;

// ── Provider ────────────────────────────────────────────────

export class ThreatTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    TreeItem | undefined | null | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private model: ThreatModel | undefined;
  private groupBy: GroupBy = "stride";

  setModel(model: ThreatModel): void {
    this.model = model;
    this._onDidChangeTreeData.fire();
  }

  setGroupBy(groupBy: GroupBy): void {
    this.groupBy = groupBy;
    this._onDidChangeTreeData.fire();
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeItem): TreeItem[] {
    if (!this.model) {
      return [];
    }

    // Root level — return groups
    if (!element) {
      return this.buildGroups();
    }

    // Group level — return leaf threats
    if (element instanceof ThreatGroupItem) {
      return element.threats.map((t) => new ThreatLeafItem(t));
    }

    return [];
  }

  private buildGroups(): ThreatGroupItem[] {
    if (!this.model) {
      return [];
    }

    const threats = this.model.threats;
    const groups = new Map<string, ThreatEntry[]>();

    for (const threat of threats) {
      let key: string;
      switch (this.groupBy) {
        case "stride":
          key = threat.stride;
          break;
        case "severity":
          key = threat.severity;
          break;
        case "component":
          key = threat.component;
          break;
      }
      const existing = groups.get(key);
      if (existing) {
        existing.push(threat);
      } else {
        groups.set(key, [threat]);
      }
    }

    // Sort groups: for severity use a defined order, otherwise alphabetical
    const entries = [...groups.entries()];
    if (this.groupBy === "severity") {
      const order: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
      };
      entries.sort(
        (a, b) => (order[a[0]] ?? 99) - (order[b[0]] ?? 99),
      );
    } else {
      entries.sort((a, b) => a[0].localeCompare(b[0]));
    }

    return entries.map(
      ([label, items]) => new ThreatGroupItem(label, items),
    );
  }
}

// ── Helpers ─────────────────────────────────────────────────

function severityIcon(
  severity: string,
): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    case "high":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    case "medium":
      return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
    case "low":
      return new vscode.ThemeIcon("pass", new vscode.ThemeColor("testing.iconPassed"));
    default:
      return new vscode.ThemeIcon("circle-outline");
  }
}
