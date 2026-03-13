/**
 * Webview panel for displaying threat model results.
 *
 * SECURITY:
 *   - Strict CSP with nonce-based script loading (no inline eval, no unsafe-inline)
 *   - All dynamic data is HTML-escaped via sanitizer before injection
 *   - Mermaid DFD content is sanitized to prevent directive injection
 *   - Message passing between extension host and webview uses typed protocol
 *
 * References:
 *   - VS Code Webview Security: https://code.visualstudio.com/api/extension-guides/webview#security
 *   - OWASP XSS Prevention Cheat Sheet
 *   - STRIDE / Information Disclosure
 */

import * as vscode from "vscode";
import type { ThreatModel } from "@synthesis/core";
import {
  escapeHtml,
  sanitizeMermaid,
  sanitizeThreatModelForView,
} from "../utils/sanitizer";

/** Messages the webview can send to the extension host. */
export type WebviewToExtensionMessage =
  | { type: "exportMarkdown" }
  | { type: "exportJson" }
  | { type: "filterBySeverity"; severity: string }
  | { type: "ready" };

/** Messages the extension host can send to the webview. */
export type ExtensionToWebviewMessage =
  | { type: "updateModel"; model: ThreatModel }
  | { type: "showError"; message: string };

let currentPanel: vscode.WebviewPanel | undefined;

/**
 * Show (or re-use) the Synthesis threat model webview panel.
 */
export function showThreatPanel(
  extensionUri: vscode.Uri,
  model?: ThreatModel,
): vscode.WebviewPanel {
  const column = vscode.window.activeTextEditor
    ? vscode.window.activeTextEditor.viewColumn
    : undefined;

  if (currentPanel) {
    currentPanel.reveal(column);
    if (model) {
      postModelToPanel(currentPanel, model);
    }
    return currentPanel;
  }

  const panel = vscode.window.createWebviewPanel(
    "synthesisThreatModel",
    "Synthesis Threat Model",
    column || vscode.ViewColumn.One,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [extensionUri],
    },
  );

  currentPanel = panel;

  panel.onDidDispose(() => {
    currentPanel = undefined;
  });

  panel.webview.html = getWebviewContent(panel.webview, extensionUri, model);

  // Handle messages from webview
  panel.webview.onDidReceiveMessage(
    async (msg: WebviewToExtensionMessage) => {
      if (!model) {
        return;
      }
      switch (msg.type) {
        case "exportMarkdown": {
          const { toMarkdown } = await import("@synthesis/core");
          const md = toMarkdown(model);
          const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file("threat-model.md"),
            filters: { Markdown: ["md"] },
          });
          if (uri) {
            await vscode.workspace.fs.writeFile(
              uri,
              Buffer.from(md, "utf-8"),
            );
            vscode.window.showInformationMessage(
              "Threat model exported to Markdown.",
            );
          }
          break;
        }
        case "exportJson": {
          const { toJSON } = await import("@synthesis/core");
          const json = toJSON(model);
          const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file("threat-model.json"),
            filters: { JSON: ["json"] },
          });
          if (uri) {
            await vscode.workspace.fs.writeFile(
              uri,
              Buffer.from(json, "utf-8"),
            );
            vscode.window.showInformationMessage(
              "Threat model exported to JSON.",
            );
          }
          break;
        }
        default:
          break;
      }
    },
  );

  return panel;
}

/**
 * Post an updated model to an existing panel.
 */
function postModelToPanel(
  panel: vscode.WebviewPanel,
  model: ThreatModel,
): void {
  const safeModel = sanitizeThreatModelForView(
    model as unknown as Record<string, unknown>,
  );
  panel.webview.postMessage({
    type: "updateModel",
    model: safeModel,
  } satisfies ExtensionToWebviewMessage);
}

/**
 * Generate the full HTML for the webview with strict CSP.
 */
function getWebviewContent(
  webview: vscode.Webview,
  _extensionUri: vscode.Uri,
  model?: ThreatModel,
): string {
  // Generate a cryptographic nonce for CSP
  const nonce = getNonce();

  // Sanitize model for embedding
  const safeModel = model
    ? sanitizeThreatModelForView(
        model as unknown as Record<string, unknown>,
      )
    : null;

  const summary = safeModel
    ? buildSummaryFromModel(model!)
    : { critical: 0, high: 0, medium: 0, low: 0 };

  const threatsJson = safeModel
    ? escapeHtml(JSON.stringify((safeModel as unknown as ThreatModel).threats))
    : "[]";

  const dfdContent = safeModel
    ? sanitizeMermaid((safeModel as unknown as ThreatModel).dfd || "")
    : "";

  const projectName = safeModel
    ? escapeHtml((safeModel as unknown as ThreatModel).projectName)
    : "No scan results";

  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none';
                 style-src ${webview.cspSource} 'nonce-${nonce}';
                 script-src 'nonce-${nonce}';
                 font-src ${webview.cspSource};
                 img-src ${webview.cspSource} data:;">
  <title>Synthesis Threat Model</title>
  <style nonce="${nonce}">
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --border: var(--vscode-panel-border);
      --critical-bg: #dc262622;
      --critical-fg: #f87171;
      --high-bg: #f9731622;
      --high-fg: #fb923c;
      --medium-bg: #eab30822;
      --medium-fg: #fbbf24;
      --low-bg: #22c55e22;
      --low-fg: #4ade80;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: var(--vscode-font-family); color: var(--fg); background: var(--bg); padding: 16px; }
    h1 { font-size: 1.4em; margin-bottom: 12px; }
    .summary-cards { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
    .card {
      padding: 14px 20px; border-radius: 8px; min-width: 120px; text-align: center;
      border: 1px solid var(--border);
    }
    .card-critical { background: var(--critical-bg); color: var(--critical-fg); }
    .card-high     { background: var(--high-bg);     color: var(--high-fg); }
    .card-medium   { background: var(--medium-bg);   color: var(--medium-fg); }
    .card-low      { background: var(--low-bg);      color: var(--low-fg); }
    .card .count   { font-size: 2em; font-weight: bold; }
    .card .label   { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }

    .toolbar { margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
    .toolbar button {
      padding: 6px 14px; border: 1px solid var(--border); background: var(--bg);
      color: var(--fg); cursor: pointer; border-radius: 4px; font-size: 0.85em;
    }
    .toolbar button:hover { background: var(--border); }

    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 0.9em; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { font-weight: 600; position: sticky; top: 0; background: var(--bg); cursor: pointer; }
    th:hover { text-decoration: underline; }

    .severity-badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;
      font-weight: 600; text-transform: uppercase;
    }
    .sev-critical { background: var(--critical-bg); color: var(--critical-fg); }
    .sev-high     { background: var(--high-bg);     color: var(--high-fg); }
    .sev-medium   { background: var(--medium-bg);   color: var(--medium-fg); }
    .sev-low      { background: var(--low-bg);      color: var(--low-fg); }
    .sev-info     { background: #3b82f622; color: #60a5fa; }

    .mitigation { margin-top: 6px; padding: 8px; background: var(--bg); border-left: 3px solid var(--border); font-size: 0.85em; }
    details summary { cursor: pointer; font-weight: 500; }

    .dfd-section { margin-top: 20px; }
    .dfd-section pre {
      background: var(--bg); border: 1px solid var(--border);
      padding: 12px; overflow-x: auto; font-size: 0.85em; border-radius: 4px;
    }

    .empty-state { text-align: center; padding: 60px 20px; color: var(--fg); opacity: 0.6; }
    .empty-state p { margin-top: 8px; }
  </style>
</head>
<body>
  <h1>Synthesis &mdash; ${projectName}</h1>

  <div class="summary-cards">
    <div class="card card-critical"><div class="count" id="count-critical">${summary.critical}</div><div class="label">Critical</div></div>
    <div class="card card-high"><div class="count" id="count-high">${summary.high}</div><div class="label">High</div></div>
    <div class="card card-medium"><div class="count" id="count-medium">${summary.medium}</div><div class="label">Medium</div></div>
    <div class="card card-low"><div class="count" id="count-low">${summary.low}</div><div class="label">Low</div></div>
  </div>

  <div class="toolbar">
    <button id="btn-all">All</button>
    <button id="btn-critical">Critical</button>
    <button id="btn-high">High</button>
    <button id="btn-medium">Medium</button>
    <button id="btn-low">Low</button>
    <button id="btn-export-md">Export Markdown</button>
    <button id="btn-export-json">Export JSON</button>
  </div>

  <div id="threats-container">
    ${
      safeModel
        ? ""
        : '<div class="empty-state"><h2>No Scan Results</h2><p>Run a Synthesis scan to view threats.</p></div>'
    }
  </div>

  <div class="dfd-section" id="dfd-section" style="${dfdContent ? "" : "display:none"}">
    <h2>Data Flow Diagram</h2>
    <pre id="dfd-content">${dfdContent}</pre>
  </div>

  <script nonce="${nonce}">
    (function() {
      const vscode = acquireVsCodeApi();
      let threats = [];
      try { threats = JSON.parse(${JSON.stringify(threatsJson)}); } catch(e) { threats = []; }
      let currentFilter = 'all';

      function severityBadge(sev) {
        const s = (sev || 'info').toLowerCase();
        return '<span class="severity-badge sev-' + s + '">' + s + '</span>';
      }

      function renderThreats(filter) {
        currentFilter = filter;
        const container = document.getElementById('threats-container');
        if (!threats || threats.length === 0) {
          container.innerHTML = '<div class="empty-state"><h2>No Threats Found</h2><p>Run a scan to see results.</p></div>';
          return;
        }
        const filtered = filter === 'all' ? threats : threats.filter(function(t) { return t.severity === filter; });
        if (filtered.length === 0) {
          container.innerHTML = '<div class="empty-state"><p>No threats at ' + filter + ' severity.</p></div>';
          return;
        }
        let html = '<table><thead><tr>';
        html += '<th>ID</th><th>STRIDE</th><th>Severity</th><th>Component</th><th>Description</th>';
        html += '</tr></thead><tbody>';
        for (let i = 0; i < filtered.length; i++) {
          const t = filtered[i];
          html += '<tr>';
          html += '<td>' + (t.id || '') + '</td>';
          html += '<td>' + (t.stride || '') + '</td>';
          html += '<td>' + severityBadge(t.severity) + '</td>';
          html += '<td>' + (t.component || '') + '</td>';
          html += '<td><details><summary>' + (t.description || '').substring(0, 100) + '</summary>';
          html += '<p>' + (t.description || '') + '</p>';
          html += '<div class="mitigation"><strong>Mitigation:</strong> ' + (t.mitigation || 'None specified') + '</div>';
          html += '<div class="mitigation"><strong>Attack Technique:</strong> ' + (t.attackTechnique || 'N/A') + '</div>';
          html += '</details></td>';
          html += '</tr>';
        }
        html += '</tbody></table>';
        container.innerHTML = html;
      }

      document.getElementById('btn-all').addEventListener('click', function() { renderThreats('all'); });
      document.getElementById('btn-critical').addEventListener('click', function() { renderThreats('critical'); });
      document.getElementById('btn-high').addEventListener('click', function() { renderThreats('high'); });
      document.getElementById('btn-medium').addEventListener('click', function() { renderThreats('medium'); });
      document.getElementById('btn-low').addEventListener('click', function() { renderThreats('low'); });

      document.getElementById('btn-export-md').addEventListener('click', function() {
        vscode.postMessage({ type: 'exportMarkdown' });
      });
      document.getElementById('btn-export-json').addEventListener('click', function() {
        vscode.postMessage({ type: 'exportJson' });
      });

      window.addEventListener('message', function(event) {
        const msg = event.data;
        if (msg.type === 'updateModel' && msg.model) {
          threats = msg.model.threats || [];
          document.getElementById('count-critical').textContent = threats.filter(function(t){ return t.severity === 'critical'; }).length;
          document.getElementById('count-high').textContent = threats.filter(function(t){ return t.severity === 'high'; }).length;
          document.getElementById('count-medium').textContent = threats.filter(function(t){ return t.severity === 'medium'; }).length;
          document.getElementById('count-low').textContent = threats.filter(function(t){ return t.severity === 'low'; }).length;
          var dfdSection = document.getElementById('dfd-section');
          var dfdContent = document.getElementById('dfd-content');
          if (msg.model.dfd) {
            dfdContent.textContent = msg.model.dfd;
            dfdSection.style.display = '';
          } else {
            dfdSection.style.display = 'none';
          }
          renderThreats(currentFilter);
        }
      });

      renderThreats('all');
      vscode.postMessage({ type: 'ready' });
    })();
  </script>
</body>
</html>`;
}

function buildSummaryFromModel(model: ThreatModel): {
  critical: number;
  high: number;
  medium: number;
  low: number;
} {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const t of model.threats) {
    const sev = t.severity as keyof typeof counts;
    if (sev in counts) {
      counts[sev]++;
    }
  }
  return counts;
}

/**
 * Generate a cryptographic nonce for CSP.
 * Uses Node crypto (available in extension host).
 */
function getNonce(): string {
  const crypto = require("crypto") as typeof import("crypto");
  return crypto.randomBytes(16).toString("base64");
}

/**
 * Dispose the current panel if open.
 */
export function disposeThreatPanel(): void {
  if (currentPanel) {
    currentPanel.dispose();
    currentPanel = undefined;
  }
}
