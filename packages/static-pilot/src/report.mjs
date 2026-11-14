import { strideMatrix, STRIDE } from "./graph-review.mjs";
import { dfdMermaid } from "./graph-exports.mjs";

export const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const compact = (s) =>
  String(s ?? "").length > 70 ? String(s).slice(0, 67) + "…" : String(s ?? "");
function text(x, y, value, small = false) {
  return `<text x="${x}" y="${y}" font-family="Arial,sans-serif" font-size="${small ? 12 : 15}" fill="#18302b">${escape(compact(value))}<title>${escape(value)}</title></text>`;
}
export function diagram(model) {
  const components = new Map(model.components.map((c) => [c.id, c]));
  const interfaces = new Map(model.interfaces.map((i) => [i.id, i]));
  const flows = model.flows.map((f) => ({
    ...f,
    label: `${interfaces.get(f.from)?.operation} → ${interfaces.get(f.to)?.operation}`,
    fromLabel: components.get(f.source)?.name,
    toLabel: components.get(f.target)?.name,
  }));
  const linked = new Set(model.flows.flatMap((f) => [f.from, f.to]));
  const unresolved = model.interfaces
    .filter((i) => i.direction !== "control" && !linked.has(i.id))
    .map((i) => ({
      id: i.id,
      label: i.operation,
      basis: "unresolved candidate",
      fromLabel:
        i.direction === "inbound"
          ? "Unknown caller / publisher"
          : components.get(i.component)?.name,
      toLabel:
        i.direction === "inbound"
          ? components.get(i.component)?.name
          : "Unknown target / resource",
    }));
  const rows = [...flows, ...unresolved];
  const height = Math.max(170, 95 + rows.length * 150);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="${height}" viewBox="0 0 1100 ${height}" role="img" aria-label="Static data flow review sheets"><rect width="1100" height="${height}" fill="#f8faf8"/><defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#327a66"/></marker></defs>${text(25, 30, model.title)}${text(25, 52, "Declared flows are solid; unresolved interface candidates are dashed. Nodes are source groupings until reviewed.", true)}${
    rows.length
      ? rows
          .map((f, n) => {
            const y = 85 + n * 150,
              declared = f.basis === "declared";
            const boundary = model.boundaries.find((b) => b.flow === f.id);
            return `<g><title>${escape(f.id)}</title><rect x="20" y="${y}" width="1060" height="135" rx="8" fill="white" stroke="#d1ded6"/>${text(38, y + 23, `${n + 1}. ${f.label}`)}${text(38, y + 43, `${f.id} · ${f.basis}`, true)}<rect x="38" y="${y + 57}" width="440" height="42" rx="5" fill="#edf5f0"/><rect x="620" y="${y + 57}" width="440" height="42" rx="5" fill="#edf5f0"/>${text(50, y + 83, f.fromLabel, true)}${text(632, y + 83, f.toLabel, true)}<line x1="480" y1="${y + 78}" x2="615" y2="${y + 78}" stroke="#327a66" stroke-width="2" ${declared ? "" : 'stroke-dasharray="7 5"'} marker-end="url(#arrow)"/>${text(38, y + 119, boundary ? `Trust transition (${boundary.dimension}): ${boundary.before} → ${boundary.after}; declared` : "Trust transition: unknown / not declared", true)}</g>`;
          })
          .join("")
      : text(
          25,
          110,
          "No interfaces found. This is not evidence that the selected system has no interfaces.",
        )
  }</svg>`;
}
function table(headers, rows) {
  return `<div class="table"><table><thead><tr>${headers.map((h) => `<th>${escape(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${escape(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function graphReport(model) {
  const graph = model.sourceGraph;
  const coverage = model.aiReview?.coverage;
  return `<h2>Source graph coverage</h2>${graph ? `<p>${graph.nodes.length} nodes; ${graph.edges.length} relationships. ${graph.coverage.parsed} parsed files; ${graph.coverage.syntaxErrors} with syntax errors; ${graph.coverage.failed} parse failures; ${graph.coverage.unsupported} without a language parser; ${graph.coverage.limited} graph-limited files.</p><p>Syntax graph only. Call candidates, source groupings and project references do not establish runtime data flows or trust boundaries.</p>` : "<p>No source graph.</p>"}<h2>STRIDE matrix</h2><p>AI scenarios and conditional rule prompts are separate. No scenario returned does not establish safety or non-applicability.</p>${coverage?.totalBatches !== undefined ? `<p>${coverage.completedBatches}/${coverage.totalBatches} batches completed; ${coverage.failedBatches} failed; ${coverage.pendingBatches} pending. ${coverage.reviewedInterfaces}/${coverage.totalInterfaces} interface records reviewed.</p>` : ""}${table(
    ["Component or flow", "Model reviewed / interfaces", ...STRIDE],
    strideMatrix(model).map((r) => [
      r.name,
      `${r.reviewed}/${r.interfaces}`,
      ...r.cells.map(
        (c) =>
          `${c.count} AI scenarios; ${c.promptCount} rule prompts\n${c.status}`,
      ),
    ]),
  )}<details><summary>Mermaid DFD source</summary><pre>${escape(dfdMermaid(model))}</pre></details>`;
}
export function modelReviewHtml(model) {
  const a = model.aiReview;
  if (!a)
    return "<h2>Model review</h2><p>No model requested. Conditional scenarios are rule-based review prompts.</p>";
  const refs = (ids) =>
    ids
      .map((id) => {
        const e = model.evidence.find((e) => e.id === id);
        return e ? `${e.repository}/${e.path}:${e.line} [${id}]` : id;
      })
      .join("; ");
  return (
    `<h2>Model review · ${escape(a.label)} / ${escape(a.model)}</h2><p class="notice">Status: ${escape(a.status)}. Model-inferred suggestions require human review; severity is unassessed. They do not establish source facts or add accepted DFD connections. ${escape(a.error || "")}</p><p>${a.coverage.submittedInterfaces} of ${a.coverage.totalInterfaces} interface records submitted; ${a.coverage.omittedInterfaces} omitted. Mode: ${escape(a.mode)}; ${a.coverage.excerptCount} excerpts; ${a.coverage.packetBytes} packet bytes. Submission is not semantic coverage.</p><p>${escape(a.summary || "")}</p><small>Prompt ${escape(a.promptVersion)} / ${escape(a.promptHash)} · Packet ${escape(a.packetHash)} · Response ${escape(a.responseHash || "unavailable")} · Based on revision ${escape(a.basedOnRevision)}</small>` +
    (a.threats || [])
      .map(
        (t) =>
          `<article><h3>${escape(t.title)}</h3><small>${escape(t.id)} · ${escape(t.category)} · Model-inferred · Needs review</small><p>${escape(t.scenario)}</p><p><strong>Actor / initial access:</strong> ${escape(t.actor)} / ${escape(t.startingAccess)}</p><p><strong>Asset:</strong> ${escape(t.asset)}</p><p><strong>Prerequisites:</strong> ${escape(t.prerequisites)}</p><p><strong>Controls:</strong> ${escape(t.controls)}</p><p><strong>Review and mitigation:</strong> ${escape(t.mitigation)}</p><p><strong>Interfaces:</strong> ${escape(t.interfaceIds.join(", "))}</p><p><strong>Evidence:</strong> ${escape(refs(t.evidenceIds))}</p></article>`,
      )
      .join("") +
    `<h3>Proposed connections · Not accepted DFD edges</h3>` +
    table(
      ["Endpoints", "Rationale", "Possible trust transition", "Evidence"],
      (a.connections || []).map((c) => [
        c.from + " → " + c.to,
        c.reason,
        c.transition
          ? `${c.transition.dimension}: ${c.transition.before} → ${c.transition.after}; ${c.transition.reason}`
          : "Unknown",
        refs(c.evidenceIds),
      ]),
    ) +
    `<h3>Questions for source review</h3><ul>${(a.questions || []).map((q) => `<li>${escape(q)}</li>`).join("")}</ul>`
  );
}
export function reportHtml(model) {
  const interfaces = new Map(model.interfaces.map((i) => [i.id, i]));
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const refs = (ids) =>
    ids
      .map((k) => {
        const e = evidence.get(k);
        return e
          ? `${e.repository}/${e.path}:${e.line}${e.pointer ? " " + e.pointer : ""} [${e.id}]`
          : k;
      })
      .join("\n");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><title>${escape(model.title)}</title><style>body{font:15px/1.55 system-ui,sans-serif;color:#20342e;background:#f7f9f6;margin:0}main{max-width:1200px;margin:auto;padding:40px}h1{font-size:34px}h2{margin-top:36px}small{color:#52645b}.notice{border-left:4px solid #bd862c;padding:16px;background:#fff5dd}table{border-collapse:collapse;width:100%;background:white}th,td{padding:10px;border:1px solid #d6e0d9;text-align:left;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}th{background:#edf3ed}.table{overflow:auto}article{padding:20px;background:white;border:1px solid #d6e0d9;margin:15px 0;break-inside:avoid}svg{width:100%;height:auto}code{overflow-wrap:anywhere}@media print{body{background:white}main{padding:0;max-width:none}table{font-size:10px}h2{break-after:avoid}.table{overflow:visible}svg{display:none}.print-note{display:block}}@media screen{.print-note{display:none}}</style><main><h1>${escape(model.title)}</h1><p>${escape(model.profile)} · Static-only · Draft with gaps · ${escape(model.aiReview ? model.aiReview.label + " / " + model.aiReview.model : "No AI provider")}</p><p class="notice">This is a review draft of selected sources and dependencies. Candidate interfaces and conditional scenarios are not confirmed vulnerabilities or evidence of deployed reachability. No whole-product coverage or security approval is implied.</p><small>Engine ${escape(model.engine)} · Created ${escape(model.createdAt)} · Model revision ${escape(model.modelRevision)}</small>${graphReport(model)}<h2>Scope and coverage</h2><p>${model.sources.length} selected of ${model.inventoryCount} inventory repositories. ${model.interfaces.length} interfaces/control references; ${model.flows.length} declared flows; ${model.boundaries.length} declared trust transitions.</p>${table(
    ["Repository / scope", "Snapshot / revision", "Coverage"],
    model.sources.map((s) => [
      s.name + " / " + s.scope,
      s.revision || s.snapshot || "unavailable",
      s.coverage
        ? `${s.coverage.inspected} inspected; ${s.coverage.unsupported} unsupported; ${s.coverage.oversized} oversized; ${s.coverage.failed} failed; ${s.coverage.excluded} exclusions (excluded directories are not recursively counted); truncated: ${s.coverage.truncated}`
        : "unavailable",
    ]),
  )}<h2>Interpretation limits</h2><ul>${model.limitations.map((l) => `<li>${escape(l)}</li>`).join("")}</ul><h2>DFD review sheets</h2><p>Each sheet preserves a flow or unresolved interface; grouping by source is not a process or trust-boundary assertion. Full labels and evidence are in the registers below.</p><p class="print-note">SVG diagrams are supplied separately; use the complete flow and interface registers below in a printed report.</p>${diagram(model)}${modelReviewHtml(model)}<h2>Declared flows</h2>${table(
    ["ID / operation", "Endpoints", "Data and controls", "Basis"],
    model.flows.map((f) => [
      f.id + "\n" + f.operation,
      `${f.from} → ${f.to}`,
      `${f.data}\n${f.controls}`,
      `${f.basis}: ${f.reason}\nReviewer: ${f.reviewer}`,
    ]),
  )}<h2>Trust boundary register</h2>${table(
    ["ID / flow", "Authority transition", "Enforcement / basis"],
    model.boundaries.map((b) => [
      b.id + "\n" + b.flow,
      `${b.dimension}: ${b.before} → ${b.after}`,
      b.enforcement + "\n" + b.basis,
    ]),
  )}<h2>Actor register</h2>${table(
    ["Actor", "Initial access assumption", "Basis"],
    model.actors.map((a) => [a.id + "\n" + a.name, a.startingAccess, a.basis]),
  )}<h2>Interface and evidence register</h2>${table(
    ["ID / operation", "Direction / protocol", "Basis / status", "Evidence"],
    model.interfaces.map((i) => [
      i.id + "\n" + i.operation,
      i.direction + " / " + i.protocol,
      i.basis + "\n" + i.resolution,
      refs(i.evidence),
    ]),
  )}<h2>Conditional threat register</h2>${model.threats.map((t) => `<article id="${escape(t.id)}"><h3>${escape(t.category)} · ${escape(interfaces.get(t.interface)?.operation)}</h3><small>${escape(t.id)} · Severity: unassessed · Needs review</small><p>${escape(t.scenario)}</p><p><strong>Asset:</strong> ${escape(t.asset)}</p><p><strong>Actor:</strong> ${escape(t.actor)}</p><p><strong>Prerequisites:</strong> ${escape(t.prerequisites.join("; "))}</p><p><strong>Path:</strong> ${escape(t.path.join(", ") || "Unresolved; no cross-component path established")}</p><p><strong>Existing controls:</strong> ${escape(t.controls)}</p><p><strong>Review and mitigation:</strong> ${escape(t.mitigation)}</p><p><strong>Evidence:</strong> ${escape(refs(t.evidence))}</p></article>`).join("")}<h2>Dependencies requiring review</h2>${table(
    ["Repository", "Dependency", "Source"],
    model.dependencies.map((d) => [
      d.repository,
      d.name,
      d.path + " " + d.pointer,
    ]),
  )}<h2>Diagnostics</h2>${table(
    ["Repository / file", "Gap", "Details"],
    model.diagnostics.map((d) => [
      d.repository + (d.path ? "/" + d.path : ""),
      d.kind,
      d.message,
    ]),
  )}<p>Download and retain model.json for the complete per-file ledger and provenance hashes. Review declarations are local author assertions, not authenticated organizational approval.</p></main></html>`;
}
