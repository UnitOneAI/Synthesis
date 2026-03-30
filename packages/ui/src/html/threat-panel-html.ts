/**
 * Standalone HTML generator for threat model visualization.
 *
 * This module generates self-contained HTML for displaying threat model results.
 * It can be used in:
 * - VSCode webview panels
 * - Standalone web pages
 * - Electron apps
 * - Any HTML rendering context
 *
 * SECURITY:
 *   - All dynamic data is HTML-escaped via sanitizer
 *   - Mermaid DFD content is sanitized to prevent directive injection
 *   - Supports CSP nonce-based script loading
 */

import type { ThreatModel, Threat } from "@synthesis/core";
import { escapeHtml, sanitizeMermaid, sanitizeThreatModelForView } from "../utils/sanitizer";

export interface ThreatPanelOptions {
  /** CSP nonce for script tags (required for strict CSP) */
  nonce?: string;
  /** Custom CSS source for CSP (e.g., webview.cspSource in VSCode) */
  cspSource?: string;
  /** Base URL for fonts/images */
  baseUrl?: string;
  /** Custom title for the panel */
  title?: string;
  /** Enable dark mode (default: true) */
  darkMode?: boolean;
  /** Callback function name for vscode.postMessage (null for standalone) */
  vsCodeApi?: boolean;
}

export interface ThreatSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/**
 * Build threat summary counts from a threat model.
 */
export function buildThreatSummary(model: ThreatModel): ThreatSummary {
  const counts: ThreatSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const t of model.threats || []) {
    const sev = (t.severity || 'info').toLowerCase() as keyof Omit<ThreatSummary, 'total'>;
    if (sev in counts) {
      counts[sev]++;
    }
    counts.total++;
  }
  return counts;
}

/**
 * Generate a cryptographic nonce for CSP.
 * Uses Node crypto if available, falls back to Math.random.
 */
export function generateNonce(): string {
  try {
    const crypto = require("crypto") as typeof import("crypto");
    return crypto.randomBytes(16).toString("base64");
  } catch {
    // Fallback for browser environments
    const array = new Uint8Array(16);
    if (typeof globalThis.crypto !== 'undefined') {
      globalThis.crypto.getRandomValues(array);
    } else {
      for (let i = 0; i < 16; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
    }
    return btoa(String.fromCharCode.apply(null, Array.from(array)));
  }
}

/**
 * Generate the CSS styles for the threat panel.
 */
export function getThreatPanelStyles(options: ThreatPanelOptions = {}): string {
  return `
    :root {
      --bg: ${options.darkMode !== false ? '#1e1e1e' : '#ffffff'};
      --fg: ${options.darkMode !== false ? '#d4d4d4' : '#333333'};
      --border: ${options.darkMode !== false ? '#3c3c3c' : '#e0e0e0'};
      --critical-bg: #dc262622;
      --critical-fg: #f87171;
      --high-bg: #f9731622;
      --high-fg: #fb923c;
      --medium-bg: #eab30822;
      --medium-fg: #fbbf24;
      --low-bg: #22c55e22;
      --low-fg: #4ade80;
      --info-bg: #3b82f622;
      --info-fg: #60a5fa;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: var(--fg); background: var(--bg); padding: 16px; }
    h1 { font-size: 1.4em; margin-bottom: 12px; }
    h2 { font-size: 1.2em; margin: 16px 0 8px; }
    .summary-cards { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
    .card {
      padding: 14px 20px; border-radius: 8px; min-width: 100px; text-align: center;
      border: 1px solid var(--border);
    }
    .card-critical { background: var(--critical-bg); color: var(--critical-fg); }
    .card-high     { background: var(--high-bg);     color: var(--high-fg); }
    .card-medium   { background: var(--medium-bg);   color: var(--medium-fg); }
    .card-low      { background: var(--low-bg);      color: var(--low-fg); }
    .card-info     { background: var(--info-bg);     color: var(--info-fg); }
    .card .count   { font-size: 2em; font-weight: bold; }
    .card .label   { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }

    .toolbar { margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
    .toolbar button {
      padding: 6px 14px; border: 1px solid var(--border); background: var(--bg);
      color: var(--fg); cursor: pointer; border-radius: 4px; font-size: 0.85em;
    }
    .toolbar button:hover { background: var(--border); }
    .toolbar button.active { background: var(--info-bg); border-color: var(--info-fg); }

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
    .sev-info     { background: var(--info-bg);     color: var(--info-fg); }

    .stride-badge {
      display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.75em;
      font-weight: 600; background: var(--border); color: var(--fg);
    }

    .mitigation { margin-top: 6px; padding: 8px; background: var(--bg); border-left: 3px solid var(--border); font-size: 0.85em; }
    details summary { cursor: pointer; font-weight: 500; }
    details[open] summary { margin-bottom: 8px; }

    .dfd-section { margin-top: 20px; }
    .dfd-section pre {
      background: var(--bg); border: 1px solid var(--border);
      padding: 12px; overflow-x: auto; font-size: 0.85em; border-radius: 4px;
    }

    .empty-state { text-align: center; padding: 60px 20px; color: var(--fg); opacity: 0.6; }
    .empty-state p { margin-top: 8px; }

    .threat-row { cursor: pointer; }
    .threat-row:hover { background: var(--border); }
  `;
}

/**
 * Generate the JavaScript for the threat panel.
 */
export function getThreatPanelScript(options: ThreatPanelOptions = {}): string {
  const vsCodeInit = options.vsCodeApi
    ? `const vscode = acquireVsCodeApi();`
    : `const vscode = { postMessage: function(msg) { console.log('Message:', msg); } };`;

  return `
    (function() {
      ${vsCodeInit}
      let threats = [];
      try { threats = JSON.parse(document.getElementById('threats-data').textContent || '[]'); } catch(e) { threats = []; }
      let currentFilter = 'all';

      function severityBadge(sev) {
        const s = (sev || 'info').toLowerCase();
        return '<span class="severity-badge sev-' + s + '">' + s + '</span>';
      }

      function strideBadge(stride) {
        if (!stride) return '';
        return '<span class="stride-badge">' + stride + '</span>';
      }

      function renderThreats(filter) {
        currentFilter = filter;
        // Update active button
        document.querySelectorAll('.toolbar button').forEach(function(btn) {
          btn.classList.remove('active');
          if (btn.dataset.filter === filter) btn.classList.add('active');
        });

        const container = document.getElementById('threats-container');
        if (!threats || threats.length === 0) {
          container.innerHTML = '<div class="empty-state"><h2>No Threats Found</h2><p>Run a scan to see results.</p></div>';
          return;
        }
        const filtered = filter === 'all' ? threats : threats.filter(function(t) { return (t.severity || '').toLowerCase() === filter; });
        if (filtered.length === 0) {
          container.innerHTML = '<div class="empty-state"><p>No threats at ' + filter + ' severity.</p></div>';
          return;
        }
        let html = '<table><thead><tr>';
        html += '<th>ID</th><th>STRIDE</th><th>Severity</th><th>Component</th><th>Description</th>';
        html += '</tr></thead><tbody>';
        for (let i = 0; i < filtered.length; i++) {
          const t = filtered[i];
          html += '<tr class="threat-row">';
          html += '<td>' + (t.id || i + 1) + '</td>';
          html += '<td>' + strideBadge(t.stride) + '</td>';
          html += '<td>' + severityBadge(t.severity) + '</td>';
          html += '<td>' + (t.component || '') + '</td>';
          html += '<td><details><summary>' + ((t.description || '').substring(0, 100) + (t.description && t.description.length > 100 ? '...' : '')) + '</summary>';
          html += '<p style="margin: 8px 0;">' + (t.description || '') + '</p>';
          if (t.mitigation) {
            html += '<div class="mitigation"><strong>Mitigation:</strong> ' + t.mitigation + '</div>';
          }
          if (t.attackTechnique) {
            html += '<div class="mitigation"><strong>Attack Technique:</strong> ' + t.attackTechnique + '</div>';
          }
          if (t.affectedAssets && t.affectedAssets.length > 0) {
            html += '<div class="mitigation"><strong>Affected Assets:</strong> ' + t.affectedAssets.join(', ') + '</div>';
          }
          html += '</details></td>';
          html += '</tr>';
        }
        html += '</tbody></table>';
        container.innerHTML = html;
      }

      // Filter buttons
      document.querySelectorAll('.toolbar button[data-filter]').forEach(function(btn) {
        btn.addEventListener('click', function() { renderThreats(btn.dataset.filter); });
      });

      // Export buttons
      var exportMd = document.getElementById('btn-export-md');
      if (exportMd) {
        exportMd.addEventListener('click', function() {
          vscode.postMessage({ type: 'exportMarkdown' });
        });
      }
      var exportJson = document.getElementById('btn-export-json');
      if (exportJson) {
        exportJson.addEventListener('click', function() {
          vscode.postMessage({ type: 'exportJson' });
        });
      }

      // Listen for updates from extension host
      window.addEventListener('message', function(event) {
        const msg = event.data;
        if (msg.type === 'updateModel' && msg.model) {
          threats = msg.model.threats || [];
          document.getElementById('count-critical').textContent = threats.filter(function(t){ return (t.severity || '').toLowerCase() === 'critical'; }).length;
          document.getElementById('count-high').textContent = threats.filter(function(t){ return (t.severity || '').toLowerCase() === 'high'; }).length;
          document.getElementById('count-medium').textContent = threats.filter(function(t){ return (t.severity || '').toLowerCase() === 'medium'; }).length;
          document.getElementById('count-low').textContent = threats.filter(function(t){ return (t.severity || '').toLowerCase() === 'low'; }).length;
          var dfdSection = document.getElementById('dfd-section');
          var dfdContent = document.getElementById('dfd-content');
          if (dfdSection && dfdContent && msg.model.dfd) {
            dfdContent.textContent = msg.model.dfd;
            dfdSection.style.display = '';
          } else if (dfdSection) {
            dfdSection.style.display = 'none';
          }
          renderThreats(currentFilter);
        }
      });

      // Initial render
      renderThreats('all');
      vscode.postMessage({ type: 'ready' });
    })();
  `;
}

/**
 * Generate complete HTML for the threat panel.
 *
 * @param model The threat model to display (optional)
 * @param options Rendering options
 * @returns Complete HTML document string
 */
export function generateThreatPanelHTML(
  model?: ThreatModel | null,
  options: ThreatPanelOptions = {}
): string {
  const nonce = options.nonce || generateNonce();
  const cspSource = options.cspSource || "'self'";

  // Sanitize model for embedding
  const safeModel = model
    ? sanitizeThreatModelForView(model as unknown as Record<string, unknown>)
    : null;

  const summary = model ? buildThreatSummary(model) : { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

  const threatsJson = safeModel
    ? JSON.stringify((safeModel as unknown as ThreatModel).threats || [])
    : "[]";

  const dfdContent = safeModel
    ? sanitizeMermaid((safeModel as unknown as ThreatModel).dfd || "")
    : "";

  const projectName = safeModel
    ? escapeHtml((safeModel as unknown as ThreatModel).projectName || "Threat Model")
    : options.title || "No scan results";

  const styles = getThreatPanelStyles(options);
  const script = getThreatPanelScript(options);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none';
                 style-src ${cspSource} 'nonce-${nonce}';
                 script-src 'nonce-${nonce}';
                 font-src ${cspSource};
                 img-src ${cspSource} data:;">
  <title>${escapeHtml(projectName)}</title>
  <style nonce="${nonce}">${styles}</style>
</head>
<body>
  <h1>${escapeHtml(projectName)}</h1>

  <div class="summary-cards">
    <div class="card card-critical"><div class="count" id="count-critical">${summary.critical}</div><div class="label">Critical</div></div>
    <div class="card card-high"><div class="count" id="count-high">${summary.high}</div><div class="label">High</div></div>
    <div class="card card-medium"><div class="count" id="count-medium">${summary.medium}</div><div class="label">Medium</div></div>
    <div class="card card-low"><div class="count" id="count-low">${summary.low}</div><div class="label">Low</div></div>
  </div>

  <div class="toolbar">
    <button data-filter="all" class="active">All (${summary.total})</button>
    <button data-filter="critical">Critical (${summary.critical})</button>
    <button data-filter="high">High (${summary.high})</button>
    <button data-filter="medium">Medium (${summary.medium})</button>
    <button data-filter="low">Low (${summary.low})</button>
    <button id="btn-export-md">Export Markdown</button>
    <button id="btn-export-json">Export JSON</button>
  </div>

  <div id="threats-container">
    ${safeModel ? "" : '<div class="empty-state"><h2>No Scan Results</h2><p>Run a scan to view threats.</p></div>'}
  </div>

  <div class="dfd-section" id="dfd-section" style="${dfdContent ? "" : "display:none"}">
    <h2>Data Flow Diagram</h2>
    <pre id="dfd-content">${escapeHtml(dfdContent)}</pre>
  </div>

  <script id="threats-data" type="application/json">${escapeHtml(threatsJson)}</script>
  <script nonce="${nonce}">${script}</script>
</body>
</html>`;
}
