/**
 * @synthesis/core — Data flow diagram generator
 *
 * Generates Mermaid diagram markup from components and data flows.
 * Includes trust boundary subgraphs and risk-based color coding.
 *
 * SECURITY:
 * - All component names and labels are sanitized to prevent Mermaid
 *   injection (e.g., injecting `end` to break subgraphs, or injecting
 *   `click` handlers for XSS in rendered SVG).
 */

import type { Component, DataFlow } from "./types.js";

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

/**
 * Sanitize a string for safe inclusion in Mermaid diagram markup.
 * Removes characters that could break Mermaid syntax or inject
 * script content into rendered SVG diagrams.
 */
function sanitizeMermaidLabel(label: string): string {
  return label
    // Remove Mermaid syntax-breaking characters
    .replace(/[[\]{}()<>|#&;`"'\\]/g, "")
    // Remove newlines and carriage returns
    .replace(/[\r\n]/g, " ")
    // Collapse multiple spaces
    .replace(/\s+/g, " ")
    // Remove potential script injection
    .replace(/click\s/gi, "")
    .replace(/javascript:/gi, "")
    // Prevent breaking out of subgraphs
    .replace(/\bend\b/gi, "end_")
    .trim()
    .slice(0, 128);
}

/**
 * Generate a safe Mermaid node ID from a component name.
 * Node IDs must be alphanumeric with underscores.
 */
function toNodeId(name: string): string {
  return name
    .replace(/[^a-zA-Z0-9]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 64)
    .toLowerCase();
}

// ---------------------------------------------------------------------------
// Node shape helpers
// ---------------------------------------------------------------------------

function nodeShape(id: string, label: string, type: Component["type"]): string {
  const safe = sanitizeMermaidLabel(label);
  switch (type) {
    case "service":
      return `${id}["${safe}"]`;
    case "datastore":
      return `${id}[("${safe}")]`;
    case "external":
      return `${id}("${safe}")`;
    case "gateway":
      return `${id}{{"${safe}"}}`;
    case "queue":
      return `${id}(["${safe}"])`;
  }
}

// ---------------------------------------------------------------------------
// Risk-based styling
// ---------------------------------------------------------------------------

/**
 * Severity-to-color mapping for risk-based visual coding.
 * Uses accessible color choices that work in both light and dark themes.
 */
const RISK_COLORS: Record<string, string> = {
  critical: "#d32f2f",
  high: "#f57c00",
  medium: "#fbc02d",
  low: "#388e3c",
  info: "#1976d2",
  default: "#607d8b",
};

// ---------------------------------------------------------------------------
// DFD generation
// ---------------------------------------------------------------------------

/**
 * Generate a Mermaid flowchart DFD from components and data flows.
 *
 * @param components - Classified components with trust boundaries
 * @param dataFlows - Identified data flows between components
 * @returns Mermaid diagram markup string
 */
export function generateDFD(
  components: Component[],
  dataFlows: DataFlow[],
): string {
  const lines: string[] = ["graph TD"];

  // Group components by trust boundary
  const boundaryGroups = new Map<string, Component[]>();
  for (const component of components) {
    const boundary = component.trustBoundary ?? "unclassified";
    const group = boundaryGroups.get(boundary) ?? [];
    group.push(component);
    boundaryGroups.set(boundary, group);
  }

  // Trust boundary display names and styles
  const boundaryLabels: Record<string, string> = {
    "public-internet": "Public Internet",
    dmz: "DMZ / Edge",
    "internal-network": "Internal Network / VPC",
    "third-party": "Third-Party Services",
    unclassified: "Unclassified",
  };

  // Emit subgraphs for each trust boundary
  for (const [boundary, group] of boundaryGroups) {
    const label = sanitizeMermaidLabel(
      boundaryLabels[boundary] ?? boundary,
    );
    lines.push(`  subgraph ${toNodeId(boundary)}["${label}"]`);

    for (const component of group) {
      const id = toNodeId(component.name);
      lines.push(`    ${nodeShape(id, component.name, component.type)}`);
    }

    lines.push("  end");
  }

  // Emit edges for data flows
  for (const flow of dataFlows) {
    const sourceId = toNodeId(flow.source);
    const destId = toNodeId(flow.destination);
    const label = sanitizeMermaidLabel(
      `${flow.protocol} / ${flow.dataClassification}`,
    );

    if (flow.crossesTrustBoundary) {
      // Dashed line for cross-boundary flows (higher risk)
      lines.push(`  ${sourceId} -. "${label}" .-> ${destId}`);
    } else {
      lines.push(`  ${sourceId} -- "${label}" --> ${destId}`);
    }
  }

  // Emit style definitions for risk coloring
  // Color gateways and externals differently to highlight attack surface
  const styleClasses: string[] = [];
  for (const component of components) {
    const id = toNodeId(component.name);
    let color: string;
    switch (component.type) {
      case "gateway":
        color = RISK_COLORS["high"] ?? RISK_COLORS["default"]!;
        break;
      case "external":
        color = RISK_COLORS["medium"] ?? RISK_COLORS["default"]!;
        break;
      case "datastore":
        color = RISK_COLORS["info"] ?? RISK_COLORS["default"]!;
        break;
      default:
        color = RISK_COLORS["default"]!;
        break;
    }
    styleClasses.push(`  style ${id} fill:${color},color:#fff,stroke:#333`);
  }

  lines.push(...styleClasses);

  return lines.join("\n");
}
