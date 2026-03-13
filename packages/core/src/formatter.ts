/**
 * @synthesis/core — Output formatting
 *
 * Converts ThreatModel objects into various output formats:
 * - Markdown (GitHub-flavored with collapsible sections)
 * - SARIF v2.1.0 (for GitHub Security tab integration)
 * - JSON (structured output)
 * - Summary (severity counts)
 *
 * SECURITY:
 * - All user-provided strings are escaped in markdown output to prevent
 *   XSS when rendered in browsers or GitHub.
 * - SARIF output conforms to the OASIS SARIF v2.1.0 schema.
 */

import type { ThreatModel, ThreatEntry } from "./types.js";
import type { DeltaReport } from "./baseline.js";

// ---------------------------------------------------------------------------
// HTML/Markdown escaping
// ---------------------------------------------------------------------------

/**
 * Escape a string for safe inclusion in markdown/HTML contexts.
 * Prevents XSS when the output is rendered in a browser.
 */
function escapeMarkdown(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/**
 * Escape pipe characters for markdown table cells.
 */
function escapeTableCell(text: string): string {
  return escapeMarkdown(text).replace(/\|/g, "\\|").replace(/\n/g, " ");
}

// ---------------------------------------------------------------------------
// Severity badge helpers
// ---------------------------------------------------------------------------

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🟢",
  info: "🔵",
};

function severityBadge(severity: string): string {
  const emoji = SEVERITY_EMOJI[severity] ?? "⚪";
  return `${emoji} **${severity.toUpperCase()}**`;
}

// ---------------------------------------------------------------------------
// Markdown formatter
// ---------------------------------------------------------------------------

/**
 * Convert a ThreatModel to GitHub-flavored markdown with collapsible sections.
 */
export function toMarkdown(model: ThreatModel): string {
  const lines: string[] = [];

  // Header
  lines.push(`# Threat Model: ${escapeMarkdown(model.projectName)}`);
  lines.push("");
  lines.push(`**Generated:** ${escapeMarkdown(model.timestamp)}`);
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| ${severityBadge("critical")} | ${model.summary.critical} |`);
  lines.push(`| ${severityBadge("high")} | ${model.summary.high} |`);
  lines.push(`| ${severityBadge("medium")} | ${model.summary.medium} |`);
  lines.push(`| ${severityBadge("low")} | ${model.summary.low} |`);
  lines.push(`| ${severityBadge("info")} | ${model.summary.info} |`);
  lines.push(`| **Total** | **${model.threats.length}** |`);
  lines.push("");

  // Components
  lines.push("## Components");
  lines.push("");
  lines.push("| Name | Type | Trust Boundary | Entry Points |");
  lines.push("|------|------|----------------|-------------|");
  for (const component of model.components) {
    const eps =
      component.entryPoints.length > 0
        ? component.entryPoints.map((e) => `\`${escapeTableCell(e)}\``).join(", ")
        : "—";
    lines.push(
      `| ${escapeTableCell(component.name)} | ${escapeTableCell(component.type)} | ${escapeTableCell(component.trustBoundary ?? "—")} | ${eps} |`,
    );
  }
  lines.push("");

  // Data Flow Diagram
  lines.push("## Data Flow Diagram");
  lines.push("");
  lines.push("```mermaid");
  lines.push(model.dfd);
  lines.push("```");
  lines.push("");

  // Threat Register
  lines.push("## Threat Register");
  lines.push("");

  // Group threats by severity for readability
  const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

  for (const severity of severityOrder) {
    const threatsAtLevel = model.threats.filter((t) => t.severity === severity);
    if (threatsAtLevel.length === 0) continue;

    lines.push(`### ${severityBadge(severity)} (${threatsAtLevel.length})`);
    lines.push("");

    for (const threat of threatsAtLevel) {
      lines.push(
        `<details>`,
      );
      lines.push(
        `<summary><strong>${escapeMarkdown(threat.id)}</strong> — ${escapeMarkdown(threat.description.slice(0, 120))}${threat.description.length > 120 ? "..." : ""}</summary>`,
      );
      lines.push("");
      lines.push(`| Field | Value |`);
      lines.push(`|-------|-------|`);
      lines.push(`| **STRIDE** | ${escapeTableCell(threat.stride)} |`);
      lines.push(`| **Component** | ${escapeTableCell(threat.component)} |`);
      lines.push(
        `| **ATT&CK Technique** | [${escapeTableCell(threat.attackTechnique)}](https://attack.mitre.org/techniques/${encodeURIComponent(threat.attackTechnique.replace(".", "/"))}) |`,
      );
      lines.push(`| **Likelihood** | ${threat.likelihood}/3 |`);
      lines.push(`| **Impact** | ${threat.impact}/3 |`);
      lines.push(`| **Severity** | ${severityBadge(threat.severity)} |`);
      lines.push(`| **Status** | ${escapeTableCell(threat.status)} |`);

      // Show compliance mapping if present
      if (threat.complianceMapping && threat.complianceMapping.length > 0) {
        lines.push(
          `| **Compliance** | ${threat.complianceMapping.map((c) => escapeTableCell(c)).join(", ")} |`,
        );
      }

      lines.push("");
      lines.push(`**Description:** ${escapeMarkdown(threat.description)}`);
      lines.push("");
      lines.push(`**Mitigation:** ${escapeMarkdown(threat.mitigation)}`);

      // Show intent boost explanation if present
      if (threat.intentBoost) {
        lines.push("");
        lines.push(
          `> **Intent Calibration:** ${escapeMarkdown(threat.intentBoost)}`,
        );
      }

      lines.push("");
      lines.push(`</details>`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// SARIF v2.1.0 formatter
// ---------------------------------------------------------------------------

/**
 * SARIF severity level mapping.
 * SARIF uses: error, warning, note, none.
 */
function toSarifLevel(severity: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "none";
  }
}

/**
 * Convert a ThreatModel to SARIF v2.1.0 format for GitHub Security tab.
 *
 * Conforms to the OASIS SARIF v2.1.0 schema:
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
export function toSARIF(model: ThreatModel): object {
  const rules = model.threats.map((threat) => ({
    id: threat.id,
    name: formatRuleName(threat),
    shortDescription: {
      text: threat.description.slice(0, 256),
    },
    fullDescription: {
      text: threat.description,
    },
    help: {
      text: threat.mitigation,
      markdown: `**Mitigation:** ${threat.mitigation}`,
    },
    properties: {
      tags: [
        `stride/${threat.stride}`,
        `mitre-attack/${threat.attackTechnique}`,
        `severity/${threat.severity}`,
      ],
    },
    defaultConfiguration: {
      level: toSarifLevel(threat.severity),
    },
  }));

  const results = model.threats.map((threat) => ({
    ruleId: threat.id,
    level: toSarifLevel(threat.severity),
    message: {
      text: threat.description,
    },
    locations: [
      {
        logicalLocations: [
          {
            name: threat.component,
            kind: "module",
          },
        ],
      },
    ],
    properties: {
      stride: threat.stride,
      attackTechnique: threat.attackTechnique,
      likelihood: threat.likelihood,
      impact: threat.impact,
      severity: threat.severity,
      mitigation: threat.mitigation,
      status: threat.status,
    },
  }));

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Synthesis Threat Modeler",
            version: "0.1.0",
            informationUri: "https://github.com/UnitOneAI/Synthesis",
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: model.timestamp,
          },
        ],
      },
    ],
  };
}

function formatRuleName(threat: ThreatEntry): string {
  const category = threat.stride
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("");
  return `STRIDE/${category}/${threat.attackTechnique}`;
}

// ---------------------------------------------------------------------------
// Delta report formatter
// ---------------------------------------------------------------------------

/**
 * Convert a DeltaReport to GitHub-flavored markdown showing what changed
 * between the current scan and the baseline.
 */
export function toDeltaMarkdown(delta: DeltaReport): string {
  const lines: string[] = [];

  lines.push("## Threat Model Delta Report");
  lines.push("");
  lines.push("| Status | Count |");
  lines.push("|--------|-------|");
  lines.push(`| \u{1F195} New | ${delta.summary.new} |`);
  lines.push(`| \u2705 Resolved | ${delta.summary.resolved} |`);
  lines.push(`| \u{1F504} Changed | ${delta.summary.changed} |`);
  lines.push(`| \u27A1\uFE0F Unchanged | ${delta.summary.unchanged} |`);
  lines.push("");

  // New Threats
  if (delta.newThreats.length > 0) {
    lines.push("### \u{1F195} New Threats");
    lines.push("");
    lines.push("| Severity | Component | STRIDE | ATT&CK | Description | Mitigation |");
    lines.push("|----------|-----------|--------|--------|-------------|------------|");
    for (const threat of delta.newThreats) {
      lines.push(
        `| ${severityBadge(threat.severity)} | ${escapeTableCell(threat.component)} | ${escapeTableCell(threat.stride)} | ${escapeTableCell(threat.attackTechnique)} | ${escapeTableCell(threat.description.slice(0, 120))} | ${escapeTableCell(threat.mitigation.slice(0, 120))} |`,
      );
    }
    lines.push("");
  }

  // Resolved Threats
  if (delta.resolvedThreats.length > 0) {
    lines.push("### \u2705 Resolved Threats");
    lines.push("");
    lines.push("| Severity | Component | STRIDE | ATT&CK | Description |");
    lines.push("|----------|-----------|--------|--------|-------------|");
    for (const entry of delta.resolvedThreats) {
      const t = entry.threat;
      lines.push(
        `| ${severityBadge(t.severity)} | ${escapeTableCell(t.component)} | ${escapeTableCell(t.stride)} | ${escapeTableCell(t.attackTechnique)} | ${escapeTableCell(t.description.slice(0, 120))} |`,
      );
    }
    lines.push("");
  }

  // Changed Threats
  if (delta.changedThreats.length > 0) {
    lines.push("### \u{1F504} Changed Threats");
    lines.push("");
    lines.push("| Component | STRIDE | ATT&CK | Previous Severity | New Severity | Description |");
    lines.push("|-----------|--------|--------|-------------------|--------------|-------------|");
    for (const { previous, current } of delta.changedThreats) {
      lines.push(
        `| ${escapeTableCell(current.component)} | ${escapeTableCell(current.stride)} | ${escapeTableCell(current.attackTechnique)} | ${severityBadge(previous.threat.severity)} | ${severityBadge(current.severity)} | ${escapeTableCell(current.description.slice(0, 120))} |`,
      );
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

/**
 * Convert a ThreatModel to a formatted JSON string.
 */
export function toJSON(model: ThreatModel): string {
  return JSON.stringify(model, null, 2);
}

// ---------------------------------------------------------------------------
// Summary formatter
// ---------------------------------------------------------------------------

/**
 * Extract severity counts from a ThreatModel.
 */
export function toSummary(
  model: ThreatModel,
): { critical: number; high: number; medium: number; low: number } {
  return {
    critical: model.summary.critical,
    high: model.summary.high,
    medium: model.summary.medium,
    low: model.summary.low,
  };
}
