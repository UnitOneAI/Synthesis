import { sha } from "./sources.mjs";
import { strideMatrix, STRIDE } from "./graph-review.mjs";

const nid = (value) => "n" + sha(value).slice(0, 16);
const label = (value) =>
  String(value ?? "")
    .slice(0, 180)
    .replace(/[\r\n]/g, " ")
    .replace(/[^\p{L}\p{N} _./:()-]/gu, " ");
export function dfdMermaid(model) {
  const lines = [
    "flowchart LR",
    "%% Static architecture draft. Source groups are not established runtime processes or trust zones.",
    "%% Solid edges: reviewer-declared. Dashed edges: unresolved candidates. No inferred trust zones.",
  ];
  const interfaces = new Map(model.interfaces.map((i) => [i.id, i]));
  for (const c of model.components)
    lines.push(`  ${nid(c.id)}["${label(c.name)} (source group)"]`);
  const declared = new Set(model.flows.flatMap((f) => [f.from, f.to]));
  for (const f of model.flows) {
    const boundary = model.boundaries.find((b) => b.flow === f.id);
    const text = `${interfaces.get(f.from)?.protocol || "flow"}: ${f.operation} - declared${boundary ? `; trust transition ${boundary.dimension}: ${boundary.before} to ${boundary.after}` : "; trust transition unknown"}`;
    lines.push(`  ${nid(f.source)} -->|"${label(text)}"| ${nid(f.target)}`);
  }
  // Aggregate unresolved interfaces by component/protocol/direction; retain every ID in JSON.
  const groups = new Map();
  for (const i of model.interfaces.filter(
    (i) => i.direction !== "control" && !declared.has(i.id),
  )) {
    const key = [i.component, i.protocol, i.direction].join(":");
    if (!groups.has(key)) groups.set(key, { item: i, count: 0 });
    groups.get(key).count++;
  }
  for (const [key, { item: i, count }] of groups) {
    const unknown = nid("unknown:" + key);
    lines.push(
      `  ${unknown}["Unknown ${i.direction === "inbound" ? "caller" : "peer or resource"} (${label(i.protocol)})"]`,
    );
    const from = i.direction === "inbound" ? unknown : nid(i.component),
      to = i.direction === "inbound" ? nid(i.component) : unknown;
    lines.push(
      `  ${from} -.->|"${count} unresolved ${label(i.protocol)} interface(s)"| ${to}`,
    );
  }
  if (!model.components.length)
    lines.push(
      '  empty["No architecture extracted - not evidence of no interfaces"]',
    );
  return lines.join("\n") + "\n";
}
export function sourceGraphMermaid(model) {
  const graph = model.sourceGraph;
  if (!graph) return 'flowchart LR\n  missing["No source graph"]\n';
  const nodes = graph.nodes
    .filter((n) =>
      ["repository", "function", "call", "interface"].includes(n.kind),
    )
    .slice(0, 200);
  const ids = new Set(nodes.map((n) => n.id));
  const lines = [
    "flowchart LR",
    `%% Preview: ${nodes.length} of ${graph.nodes.length} nodes. Full graph is in source-graph.json.`,
    "%% Candidate call targets are not resolved calls or DFD edges.",
  ];
  for (const n of nodes)
    lines.push(`  ${nid(n.id)}["${label(n.kind + ": " + n.name)}"]`);
  for (const e of graph.edges.filter((e) => ids.has(e.from) && ids.has(e.to)))
    lines.push(`  ${nid(e.from)} -.->|"${label(e.kind)}"| ${nid(e.to)}`);
  return lines.join("\n") + "\n";
}
const csv = (value) => {
  let s = String(value ?? "");
  if (/^[\s]*[=+@-]/.test(s)) s = "'" + s;
  return '"' + s.replaceAll('"', '""') + '"';
};
export function strideCsv(model) {
  const rows = [
    [
      "Repository",
      "Component or flow",
      "Row type",
      "Interfaces",
      "Model reviewed interfaces",
      ...STRIDE,
      "Interpretation",
    ],
  ];
  for (const row of strideMatrix(model))
    rows.push([
      row.repository,
      row.name,
      row.rowKind,
      row.interfaces,
      row.reviewed,
      ...row.cells.map(
        (c) =>
          `${c.status}: ${c.count} AI scenarios; ${c.promptCount} rule prompts`,
      ),
      "Draft. No scenario returned is not evidence of safety.",
    ]);
  return "\uFEFF" + rows.map((row) => row.map(csv).join(",")).join("\r\n");
}
