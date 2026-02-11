import type { RepoAnalysis, ComponentInfo, DataFlow, TrustBoundary } from "./repo-analyzer";

/**
 * Generate a Mermaid.js Data Flow Diagram from repository analysis.
 *
 * Output is a Mermaid flowchart string with:
 * - Subgraphs for trust boundaries
 * - Nodes for components (styled by type)
 * - Edges for data flows (labeled with protocol)
 */
export function generateDFD(analysis: RepoAnalysis): string {
  const { components, dataFlows, trustBoundaries } = analysis;

  if (components.length === 0) {
    return `graph LR\n  A[No components detected]`;
  }

  const lines: string[] = ["graph LR"];

  // Assign node IDs
  const nodeIds = new Map<string, string>();
  components.forEach((comp, i) => {
    nodeIds.set(comp.name, `N${i}`);
  });

  // Group components by trust boundary
  const boundaryComponents = new Map<string, string[]>();
  const ungrouped = new Set(components.map((c) => c.name));

  for (const boundary of trustBoundaries) {
    const members: string[] = [];
    for (const compName of boundary.components) {
      if (nodeIds.has(compName)) {
        members.push(compName);
        ungrouped.delete(compName);
      }
    }
    if (members.length > 0) {
      boundaryComponents.set(boundary.name, members);
    }
  }

  // Render trust boundaries as subgraphs
  let subgraphIndex = 0;
  for (const [boundaryName, members] of boundaryComponents) {
    lines.push(`  subgraph ${sanitizeId(`SG${subgraphIndex}`)}["${escapeLabel(boundaryName)}"]`);

    for (const compName of members) {
      const nodeId = nodeIds.get(compName)!;
      const comp = components.find((c) => c.name === compName)!;
      lines.push(`    ${renderNode(nodeId, comp)}`);
    }

    lines.push("  end");
    subgraphIndex++;
  }

  // Render ungrouped components
  for (const compName of ungrouped) {
    const nodeId = nodeIds.get(compName)!;
    const comp = components.find((c) => c.name === compName)!;
    lines.push(`  ${renderNode(nodeId, comp)}`);
  }

  // Render data flows as edges
  for (const flow of dataFlows) {
    const fromId = nodeIds.get(flow.from);
    const toId = nodeIds.get(flow.to);
    if (fromId && toId) {
      const label = flow.protocol || flow.dataType;
      lines.push(`  ${fromId} -->|${escapeLabel(label)}| ${toId}`);
    }
  }

  // Add styling classes
  lines.push("");
  lines.push("  %% Styling");

  const externalNodes = components
    .filter((c) => c.type === "external")
    .map((c) => nodeIds.get(c.name))
    .filter(Boolean);
  if (externalNodes.length > 0) {
    lines.push(
      `  classDef external fill:#dbeafe,stroke:#3b82f6,stroke-width:2px,color:#1e40af`
    );
    lines.push(`  class ${externalNodes.join(",")} external`);
  }

  const apiNodes = components
    .filter((c) => c.type === "api" || c.type === "gateway")
    .map((c) => nodeIds.get(c.name))
    .filter(Boolean);
  if (apiNodes.length > 0) {
    lines.push(
      `  classDef api fill:#dcfce7,stroke:#22c55e,stroke-width:2px,color:#166534`
    );
    lines.push(`  class ${apiNodes.join(",")} api`);
  }

  const dbNodes = components
    .filter((c) => c.type === "database")
    .map((c) => nodeIds.get(c.name))
    .filter(Boolean);
  if (dbNodes.length > 0) {
    lines.push(
      `  classDef db fill:#fef3c7,stroke:#f59e0b,stroke-width:2px,color:#92400e`
    );
    lines.push(`  class ${dbNodes.join(",")} db`);
  }

  const serviceNodes = components
    .filter((c) => c.type === "service")
    .map((c) => nodeIds.get(c.name))
    .filter(Boolean);
  if (serviceNodes.length > 0) {
    lines.push(
      `  classDef service fill:#f3e8ff,stroke:#a855f7,stroke-width:2px,color:#6b21a8`
    );
    lines.push(`  class ${serviceNodes.join(",")} service`);
  }

  const queueNodes = components
    .filter((c) => c.type === "queue")
    .map((c) => nodeIds.get(c.name))
    .filter(Boolean);
  if (queueNodes.length > 0) {
    lines.push(
      `  classDef queue fill:#ffe4e6,stroke:#f43f5e,stroke-width:2px,color:#9f1239`
    );
    lines.push(`  class ${queueNodes.join(",")} queue`);
  }

  return lines.join("\n");
}

function renderNode(nodeId: string, comp: ComponentInfo): string {
  const label = escapeLabel(comp.name);

  switch (comp.type) {
    case "database":
      return `${nodeId}[("${label}")]`; // Cylinder shape
    case "external":
      return `${nodeId}[["${label}"]]`; // Subroutine shape (double border)
    case "queue":
      return `${nodeId}>>"${label}"]`; // Flag shape
    case "gateway":
      return `${nodeId}{{"${label}"}}`; // Hexagon shape
    default:
      return `${nodeId}["${label}"]`; // Rectangle
  }
}

function escapeLabel(text: string): string {
  return text.replace(/"/g, "'").replace(/[[\]{}()#]/g, "");
}

function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_]/g, "_");
}

/**
 * Generate a simplified DFD from a design document description
 * (when no repo analysis is available)
 */
export function generateDFDFromDescription(
  description: string,
  components: { name: string; type: ComponentInfo["type"] }[],
  flows: { from: string; to: string; label: string }[]
): string {
  const lines: string[] = ["graph LR"];

  const nodeIds = new Map<string, string>();
  components.forEach((comp, i) => {
    const id = `N${i}`;
    nodeIds.set(comp.name, id);

    const fakeComp: ComponentInfo = {
      name: comp.name,
      type: comp.type,
      files: [],
      description: "",
    };
    lines.push(`  ${renderNode(id, fakeComp)}`);
  });

  for (const flow of flows) {
    const fromId = nodeIds.get(flow.from);
    const toId = nodeIds.get(flow.to);
    if (fromId && toId) {
      lines.push(`  ${fromId} -->|${escapeLabel(flow.label)}| ${toId}`);
    }
  }

  return lines.join("\n");
}
