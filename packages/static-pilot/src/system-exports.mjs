import { PRINT_STYLE } from "./print-style.mjs";
import { diagramModel, layoutDiagram, actorPath } from "./diagram-model.mjs";
import { usageSummary } from "./token-usage.mjs";
import { systemModel, CATEGORIES } from "./system-model.mjs";
import { sha } from "./sources.mjs";
export const escapeHtml = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const e = escapeHtml,
  nid = (v) => "n" + sha(v).slice(0, 16),
  label = (v) =>
    String(v ?? "")
      .replace(/[^\p{L}\p{N} _./:()-]/gu, " ")
      .slice(0, 180);
export function selectedPath(s, actorId) {
  return actorPath(s, actorId).flowIds;
}
export function systemSvg(model, options = {}) {
  const s = systemModel(model, { matrix: false }),
    d = diagramModel(s, options);
  const { positions, boxes, width, height } = layoutDiagram(d);
  const actor = s.actors.find(
    (a) =>
      a.id === options.actor && !["rejected", "stale"].includes(a.reviewState),
  );
  const selectedThreat = s.threats.find((t) => t.id === options.threat);
  const text = (x, y, value, size = 12) =>
    `<text x="${x}" y="${y}" font-size="${size}" fill="#20344c">${e(value)}</text>`;
  const edgeCounts = new Map(),
    edgeIndices = new Map();
  for (const f of d.connections) {
    const key = [f.source, f.target].sort().join(":");
    edgeCounts.set(key, (edgeCounts.get(key) || 0) + 1);
  }
  const incoming = new Map(),
    incomingIndex = new Map();
  for (const f of d.connections)
    incoming.set(f.target, (incoming.get(f.target) || 0) + 1);
  const flowSvg = d.connections
    .map((f) => {
      const a = positions.get(f.source),
        b = positions.get(f.target);
      const key = [f.source, f.target].sort().join(":"),
        ordinal = edgeIndices.get(key) || 0;
      edgeIndices.set(key, ordinal + 1);
      const offset = (ordinal - (edgeCounts.get(key) - 1) / 2) * 28;
      const targetOrdinal = incomingIndex.get(f.target) || 0;
      incomingIndex.set(f.target, targetOrdinal + 1);
      let path, lx, ly;
      if (b.x > a.x) {
        const x1 = a.x + 260,
          x2 = b.x,
          mid = (x1 + x2) / 2;
        if (b.x - a.x > 420) {
          // Skip-rank edges use row/column gutters rather than crossing boxes.
          const corridor = Math.max(a.y, b.y) + 110 + ordinal * 12;
          path = `M${x1} ${a.y + 40} L${x1 + 35} ${a.y + 40} L${x1 + 35} ${corridor} L${x2 - 30} ${corridor} L${x2 - 30} ${b.y + 40} L${x2} ${b.y + 40}`;
        } else
          path = `M${x1} ${a.y + 40} C${mid + offset} ${a.y + 40} ${mid + offset} ${b.y + 40} ${x2} ${b.y + 40}`;
        lx = x2 - 65;
        ly = b.y + 22 + (targetOrdinal - (incoming.get(f.target) - 1) / 2) * 48;
      } else {
        const x1 = a.x + 260,
          x2 = b.x + 260,
          outside = Math.max(x1, x2) + 55 + ordinal * 18;
        const by = f.source === f.target ? b.y + 65 : b.y + 45;
        path = `M${x1} ${a.y + 20} C${outside} ${a.y - 30} ${outside} ${by + 40} ${x2} ${by}`;
        lx = outside - 12;
        ly = (a.y + by) / 2 + offset;
      }
      const boundaries = d.boundaries.filter(
        (b) => f.boundaryIds.includes(b.id) && b.dimension === d.lens,
      );
      const state = boundaries.every((b) => b.reviewState === "accepted")
        ? "reviewed"
        : "pending";
      const dashed =
        f.basis !== "static endpoint match" &&
        f.basis !== "reviewer declaration";
      const label = `${f.transport && f.transport !== "unknown" ? f.transport : f.protocol || "Data"}${f.flowIds.length > 1 ? ` × ${f.flowIds.length}` : ""}`;
      return `<g class="dfd-connection" data-select="${e(f.flowIds[0])}" data-flow-ids="${e(f.flowIds.join(" "))}" data-connection-id="${e(f.id)}" role="button" tabindex="0" aria-label="${e(f.name)}"><title>${e(`${f.name} · ${f.basis} · ${f.reviewState}. Member flows: ${f.flowIds.join(", ")}`)}</title><path d="${path}" fill="none" stroke="transparent" stroke-width="18"/><path d="${path}" fill="none" stroke="${f.active ? "#b56416" : "#61758c"}" stroke-width="${f.active ? 3 : 1.7}" ${dashed ? 'stroke-dasharray="6 4"' : ""} marker-end="url(#system-arrow)"/><rect x="${lx - 43}" y="${ly - 14}" width="95" height="20" rx="4" fill="white"/>${text(lx - 38, ly, label, 11)}${boundaries.length ? `<g data-select="${e(boundaries[0].id)}" role="button" tabindex="0" aria-label="${e(boundaries[0].name)}"><title>${e(boundaries.map((b) => `${b.reference} · ${b.name} · ${b.before} → ${b.after} · ${b.basis} · ${b.reviewState}`).join("; "))}</title><rect x="${lx - 43}" y="${ly + 9}" width="218" height="20" rx="4" fill="#eee8f5" stroke="#8e79a5" ${state === "pending" ? 'stroke-dasharray="3 3"' : ""}/>${text(lx - 38, ly + 23, `${boundaries[0].reference}${boundaries.length > 1 ? " +" + (boundaries.length - 1) : ""}: ${state}`, 10)}</g>` : ""}</g>`;
    })
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" font-family="system-ui,sans-serif" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="${e(s.title)} system data flow diagram"><title>${e(s.title)} · ${e(d.level)} · ${e(d.lens)} lens</title><desc>Static evidence and review declarations. Dashed connections are hypotheses or unresolved relationships. Connectivity does not establish exploitability.</desc><rect width="${width}" height="${height}" fill="#fff"/><defs><marker id="system-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0 0 L7 3 L0 6" fill="#61758c"/></marker></defs>${text(24, 26, `${s.title} · ${d.level} · ${d.lens} lens`, 17)}${text(24, 48, `${d.nodes.length} objects · ${d.connections.length} connections representing ${d.coverage.representedFlows} flows · ${d.coverage.unresolvedRelationships} unresolved relationships in coverage`, 11)}${text(24, 67, `${d.coverage.omittedNodes} omitted objects / ${d.coverage.omittedConnections} omitted connections from canvas limit; ${d.coverage.filteredFlows} flows outside view filters. Full registers retain evidence.`, 11)}${selectedThreat ? text(24, 87, `${selectedThreat.reference}: ${selectedThreat.name} (${selectedThreat.flowIds?.length ? "conditional path" : "no linked flow established"})`.slice(0, 160), 11) : actor ? text(24, 87, `Actor profile: ${actor.name} · conditional access: ${actor.startingAccess}`.slice(0, 150), 11) : ""}${boxes.map(({ domain: g, x, y, width: w, height: h }) => `<g data-select="${e(g.id)}" data-domain-parent="${e(g.parentId || "")}" role="button" tabindex="0" aria-label="${e(g.name)}"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" fill="#f5f8fc" stroke="#8e79a5" ${g.reviewState !== "accepted" ? 'stroke-dasharray="6 5"' : ""}/>${text(x + 12, y + 22, `${g.name} · ${g.basis} · ${g.reviewState}`)}</g>`).join("")}${flowSvg}${d.nodes
    .map((n) => {
      const p = positions.get(n.id),
        active = d.activeNodeIds.includes(n.id);
      const entry = actor?.entryIds?.some((id) => n.memberIds.includes(id));
      const chunks = [""];
      for (const word of n.name.split(/\s+/)) {
        const last = chunks.length - 1;
        if (chunks[last] && chunks[last].length + word.length + 1 > 32)
          chunks.push(word);
        else chunks[last] += (chunks[last] ? " " : "") + word;
      }
      if (chunks.length > 2) {
        chunks.splice(2);
        chunks[1] += "…";
      }
      for (let i = 0; i < chunks.length; i++)
        if (chunks[i].length > 36) chunks[i] = chunks[i].slice(0, 35) + "…";
      return `<g class="node" data-component-type="${e(n.type)}" data-select="${e(n.id)}" role="button" tabindex="0" aria-label="${e(n.name)}"><title>${e(`${n.name} · ${n.classification || n.basis} · ${n.memberIds.length} source component(s)`)}</title><rect x="${p.x}" y="${p.y}" width="260" height="85" rx="${n.type === "external" ? 2 : 10}" fill="white" stroke="${active ? "#b56416" : "#a8bfd8"}" stroke-width="${active ? 3 : 1.4}" ${n.type === "unknown" ? 'stroke-dasharray="5 5"' : ""}/>${n.type === "store" ? `<path d="M${p.x} ${p.y + 5} Q${p.x + 130} ${p.y + 19} ${p.x + 260} ${p.y + 5}" fill="none" stroke="#a8bfd8"/>` : ""}${n.type === "broker" ? `<path d="M${p.x + 6} ${p.y + 8}V${p.y + 77} M${p.x + 254} ${p.y + 8}V${p.y + 77}" stroke="#61758c"/>` : ""}${entry ? `<circle cx="${p.x + 246}" cy="${p.y + 14}" r="5" fill="#b56416"><title>Actor entry point under stated access assumptions</title></circle>` : ""}${chunks.map((line, i) => text(p.x + 12, p.y + 25 + i * 17, line, 13)).join("")}${text(p.x + 12, p.y + 69, `${n.internalRole === "worker" ? "in-process worker candidate" : n.type}${n.type !== "source-group" && n.classification ? " candidate" : ""}${n.memberIds.length > 1 ? ` · ${n.memberIds.length} source members` : ""}`, 10)}</g>`;
    })
    .join(
      "",
    )}${!d.connections.length ? text(24, height - 50, "No matched connections in this view. Inspect unresolved coverage or choose a component.", 12) : ""}${text(24, height - 18, "Dashed: candidate / unresolved. TB: trust boundary in selected lens; pending means unreviewed. Actor and threat paths are conditional.", 11)}</svg>`;
}
export function systemMermaid(model, options = {}) {
  const s = systemModel(model, { matrix: false }),
    d = diagramModel(s, options);
  const lines = [
    "flowchart LR",
    `%% Static architecture DFD: ${d.level}; ${d.lens} lens. Not runtime reachability.`,
    `%% Coverage: ${JSON.stringify(d.coverage)}`,
  ];
  for (const n of d.nodes) {
    lines.push(`%% Object ${n.id}; source members: ${n.memberIds.join(" ")}`);
    const shape = {
      store: ['[("', '")]'],
      broker: ['[["', '"]]'],
      process: ['("', '")'],
      gateway: ['("', '")'],
    }[n.type] || ['["', '"]'];
    lines.push(
      `  ${nid(n.id)}${shape[0]}${label(n.name + " · " + n.basis)}${shape[1]}`,
    );
  }
  const visible = new Set(d.nodes.map((n) => n.id)),
    used = new Set(),
    domainIds = new Set(d.domains.map((g) => g.id));
  function domain(g, seen = new Set()) {
    if (seen.has(g.id)) return;
    lines.push(
      `%% Domain ${g.id}; ${g.reviewState}`,
      `  subgraph ${nid(g.id)}["${label(g.name)}"]`,
    );
    for (const child of d.domains.filter((c) => c.parentId === g.id))
      domain(child, new Set([...seen, g.id]));
    for (const id of g.memberIds || [])
      if (visible.has(id) && !used.has(id)) {
        used.add(id);
        lines.push(`    ${nid(id)}`);
      }
    lines.push("  end");
  }
  d.domains.filter((g) => !domainIds.has(g.parentId)).forEach((g) => domain(g));
  for (const f of d.connections) {
    lines.push(
      `%% Flow members: ${f.flowIds.join(" ")}`,
      `%% Interfaces: ${f.interfaceIds.join(" ")}`,
      `%% Evidence: ${f.evidenceIds.join(" ")}`,
    );
    const boundaries = d.boundaries.filter(
      (b) => f.boundaryIds.includes(b.id) && b.dimension === d.lens,
    );
    lines.push(
      `  ${nid(f.source)} ${["static endpoint match", "reviewer declaration"].includes(f.basis) ? "-->" : "-.->"}|"${label([f.name, f.transport && f.transport !== "unknown" ? `${f.transport} in source URL` : "transport unestablished", f.basis, ...boundaries.map((b) => `${b.dimension}: ${b.before} to ${b.after} (${b.reviewState})`)].join(" · "))}"| ${nid(f.target)}`,
    );
  }
  d.connections.forEach((f, i) => {
    if (f.active)
      lines.push(`  linkStyle ${i} stroke:#b56416,stroke-width:3px`);
  });
  return lines.join("\n") + "\n";
}
const csvCell = (v) => {
  let s = String(v ?? "");
  if (/^[\s]*[=+@-]/.test(s)) s = "'" + s;
  return '"' + s.replaceAll('"', '""') + '"';
};
export function registerCsv(model, kind) {
  const s = systemModel(model, { matrix: kind === "matrix" });
  let rows;
  if (kind === "matrix")
    rows = [
      ["ID", "Subject", "Type", ...CATEGORIES],
      ...s.matrix.map((r) => [
        r.id,
        r.name,
        r.rowKind,
        ...r.cells.map(
          (c) =>
            `${c.analysisLabel}; reviewer state: ${c.state}; ${c.scenarioCount} scenarios; ${c.checklistCount} checklist items; ${c.threatIds.join(" ")}`,
        ),
      ]),
    ];
  else {
    const fields = {
      securityControls: [
        "id",
        "name",
        "description",
        "interfaceIds",
        "flowIds",
        "counterEvidenceIds",
      ],
      actors: [
        "id",
        "name",
        "startingAccess",
        "objectives",
        "excludedCapabilities",
        "entryIds",
      ],
      boundaries: [
        "id",
        "reference",
        "crossings",
        "name",
        "dimension",
        "before",
        "after",
        "enforcement",
        "flowIds",
      ],
      threats: [
        "id",
        "reference",
        "reviewPriority",
        "sourceScopes",
        "name",
        "scenario",
        "origin",
        "categories",
        "actorIds",
        "asset",
        "prerequisites",
        "flowIds",
        "boundaryIds",
        "controls",
        "mitigation",
        "analysis",
        "analysisQuality",
      ],
      flows: [
        "id",
        "reference",
        "name",
        "source",
        "target",
        "protocol",
        "transport",
        "data",
        "controls",
        "assetIds",
      ],
      components: ["id", "name", "type", "repositories", "interfaceIds"],
      assets: ["id", "name", "description"],
    }[kind];
    if (!fields) throw Error("Unknown register");
    rows = [
      [
        ...fields.map(fieldName),
        "Linked controls",
        "Counterevidence",
        "Assumptions",
        "Evidence basis",
        "Disposition",
        "Supporting evidence",
        "Reviewer",
        "Rationale",
        "Mitigation owner",
        "Severity assessment",
        "OWASP technical risk",
      ],
      ...s[kind].map((r) => [
        ...fields.map((k) => display(r[k])),
        (r.controlIds || []).join("; "),
        (r.counterEvidenceIds || []).join("; "),
        r.assumptions,
        r.basis,
        r.reviewState,
        (r.evidenceIds || []).join("; "),
        r.decision?.reviewer,
        r.decision?.rationale,
        r.decision?.owner,
        r.decision?.severity,
        display(r.decision?.riskAssessment),
      ]),
    ];
  }
  return "\uFEFF" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n");
}
const fieldName = (k) =>
  ({
    id: "ID",
    actors: "Threat actors",
    boundaries: "Trust boundaries",
    domains: "Trust domains",
    entities: "External entities",
    assets: "Data assets",
    actorIds: "Threat actors",
    flowIds: "Affected flows",
    boundaryIds: "Trust boundaries",
    evidenceIds: "Supporting evidence",
    counterEvidenceIds: "Counterevidence",
    controlIds: "Linked controls",
    interfaceIds: "Source interfaces",
    memberIds: "Domain members",
    entryIds: "Entry points",
    parentId: "Parent domain",
    sourceDomainId: "Source trust domain",
    targetDomainId: "Destination trust domain",
    securityControls: "Controls",
    reviewState: "Disposition",
    startingAccess: "Initial access",
    decision: "Review decision",
    missingReferences: "References requiring repair",
  })[k] ||
  k.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
const display = (v) =>
  Array.isArray(v)
    ? v.map(display).join("; ")
    : v && typeof v === "object"
      ? Object.entries(v)
          .filter(([k]) => k !== "fingerprint")
          .map(([k, x]) => `${fieldName(k)}: ${display(x)}`)
          .join("; ")
      : String(v ?? "");
export function tokenUsageHtml(model) {
  const u = usageSummary(
    model.usageLedger,
    !model.usageLedger && Boolean(model.aiReview),
  );
  return `<h2>Token usage</h2><p>${u.totalTokens.toLocaleString("en-US")} reported tokens across ${u.requests} recorded requests; ${u.unknownRequests} requests with unknown totals. Latest action: ${u.lastRun.totalTokens.toLocaleString("en-US")} reported tokens / ${u.lastRun.requests} requests.</p><p>Input includes cache reads/writes; those columns are subsets and must not be added again. Failed responses and retries are included. Shared requests are counted once, separately from individual repositories. Token counts are provider-reported usage, not an invoice.</p>${u.legacyUnmetered ? "<p>Earlier analysis has no token records. These subtotals cover metered requests only.</p>" : ""}<table><thead><tr><th>Repository / scope</th><th>Requests</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>Reported total</th><th>Unknown requests</th></tr></thead><tbody>${u.groups.map((g) => `<tr><td>${e(g.label)}</td><td>${g.requests}</td><td>${g.inputTokens}</td><td>${g.outputTokens}</td><td>${g.cacheReadTokens}</td><td>${g.cacheWriteTokens}</td><td>${g.totalTokens}</td><td>${g.unknownRequests}</td></tr>`).join("")}</tbody></table>`;
}
export function systemReport(model) {
  const s = systemModel(model),
    table = (headers, rows) =>
      `<table><thead><tr>${headers.map((v) => `<th>${e(v)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${e(Array.isArray(v) ? v.join("; ") : v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${e(s.title)}</title><style>body{font:14px/1.5 system-ui;color:#1c2e44;margin:32px}table{border-collapse:collapse;width:100%;margin:15px 0;table-layout:fixed}td,th{border:1px solid #ccd5df;padding:7px;text-align:left;overflow-wrap:anywhere;vertical-align:top}svg{width:100%;height:auto}h2{margin-top:32px}article{break-inside:avoid;border-top:1px solid #ccd5df;padding:15px 0}@media print{body{margin:0}table{font-size:10px}h2{break-after:avoid}svg{max-height:800px}}${PRINT_STYLE}</style><h1>${e(s.title)}</h1><p>${e(s.profile)} · Static threat model · Draft</p><p>Revision ${e(s.revision)}. Source observations, assumptions and reviewer declarations are distinguished. Review decisions are local annotations, not authenticated organizational approvals.</p><h2>Scope and coverage</h2>${table(
    ["Repository", "Status", "Snapshot", "Coverage"],
    model.sources.map((r) => [
      r.name,
      r.status,
      r.snapshot,
      display(
        Object.fromEntries(
          Object.entries(r.coverage || {}).filter(([key]) => key !== "entries"),
        ),
      ),
    ]),
  )}<p>${s.coverage.unresolvedFlows} unresolved relationships. ${s.coverage.pendingBoundaries} boundary decisions pending. Provider submission is not human review coverage.</p><h3>Source parsing</h3><p>${e(display(model.sourceGraph?.coverage || { status: "Not built" }))}</p><h3>STRIDE analysis coverage</h3><p>${model.aiReview?.coverage ? `${Number(model.aiReview.coverage.completedBatches || 0)} of ${Number(model.aiReview.coverage.totalBatches || 0)} batches completed; ${Number(model.aiReview.coverage.failedBatches || 0)} failed; ${Number(model.aiReview.coverage.pendingBatches || 0)} pending. Status: ${e(model.aiReview.status)}.` : "Analysis has not run."} Batch completion does not establish semantic completeness or reviewer acceptance.</p>${tokenUsageHtml(model)}<h2>System context</h2>${systemSvg(model, { level: "context" })}<h2>Overall system DFD</h2>${systemSvg(model)}${[
    "actors",
    "boundaries",
    "domains",
    "components",
    "entities",
    "assets",
    "securityControls",
    "flows",
  ]
    .map(
      (k) =>
        `<h2>${e(fieldName(k))} register</h2>${table(
          ["ID / name", "Basis / disposition", "Properties", "Evidence"],
          s[k].map((r) => [
            (r.reference ? r.reference + " (" + r.id + ")" : r.id) +
              " / " +
              r.name,
            r.basis + " / " + r.reviewState,
            display(
              Object.fromEntries(
                Object.entries(r).filter(
                  ([k]) =>
                    ![
                      "id",
                      "name",
                      "fingerprint",
                      "evidenceIds",
                      "basis",
                      "reviewState",
                    ].includes(k),
                ),
              ),
            ),
            (r.evidenceIds || []).join("; "),
          ]),
        )}`,
    )
    .join("")}<h2>STRIDE matrix</h2>${table(
    ["Subject", ...CATEGORIES],
    s.matrix.map((r) => [
      r.name,
      ...r.cells.map(
        (c) =>
          `${c.analysisLabel}; reviewer state ${c.state}: ${c.scenarioCount} scenarios, ${c.checklistCount} checklist items`,
      ),
    ]),
  )}<h2>Threat register</h2><p>${s.threats.filter((t) => t.origin !== "review checklist").length} threat scenarios and ${s.threats.filter((t) => t.origin === "review checklist").length} checklist items. These are conditional review records, not confirmed vulnerabilities.</p>${s.threats
    .slice()
    .sort(
      (a, b) => (a.reviewPriority?.rank ?? 9) - (b.reviewPriority?.rank ?? 9),
    )
    .map(
      (t) =>
        `<article><h3>${e(t.reference || t.id)} · ${e(t.name)}</h3><p>${e(t.id)} · ${t.origin === "review checklist" ? "Review checklist" : "Threat scenario"} · ${e(t.categories.join(", "))} · ${e(t.reviewState)}</p><p>${e(t.scenario)}</p>${table(
          ["Field", "Value"],
          [
            "actorIds",
            "asset",
            "reviewPriority",
            "boundaryLinkBasis",
            "prerequisites",
            "flowIds",
            "boundaryIds",
            "controls",
            "mitigation",
            "analysis",
            "analysisQuality",
            "evidenceIds",
            "decision",
            "counterEvidenceIds",
            "controlIds",
            "assumptions",
          ].map((k) => [fieldName(k), display(t[k])]),
        )}</article>`,
    )
    .join("")}<h2>Supporting evidence</h2>${table(
    ["ID", "Repository", "File", "Line", "Basis"],
    model.evidence.map((r) => [r.id, r.repository, r.path, r.line, r.basis]),
  )}<h2>Assumptions and open questions</h2><ul>${[...model.limitations, ...s.questions].map((v) => `<li>${e(v)}</li>`).join("")}</ul><h2>Collection diagnostics</h2>${table(
    ["Repository", "File", "Type", "Detail"],
    model.diagnostics.map((d) => [d.repository, d.path, d.kind, d.message]),
  )}</html>`;
}

// A review-oriented print projection. Detailed registers remain in the complete
// HTML/JSON/CSV exports; checklist prompts never become threat scenarios.
export function systemPrintReport(model) {
  const s = systemModel(model);
  const scenarios = s.threats
    .filter((t) => t.origin !== "review checklist")
    .sort(
      (a, b) =>
        a.reviewPriority.rank - b.reviewPriority.rank ||
        a.id.localeCompare(b.id),
    );
  const table = (headers, rows) =>
    `<table><thead><tr>${headers.map((h) => `<th>${e(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${e(v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  const boundaryGroups = new Map();
  for (const b of s.boundaries) {
    const key = JSON.stringify([
      b.name,
      b.dimension,
      b.before,
      b.after,
      b.enforcement,
      b.basis,
      b.reviewState,
    ]);
    if (!boundaryGroups.has(key))
      boundaryGroups.set(key, { ...b, members: [] });
    boundaryGroups.get(key).members.push(b.reference);
    boundaryGroups.get(key).crossingDetails = [
      ...(boundaryGroups.get(key).crossingDetails || []),
      ...(b.crossings || []).map(
        (c) =>
          `${b.reference} / ${c.reference}: ${c.from} → ${c.to} (${c.basis}; ${c.reviewState})`,
      ),
    ];
  }
  const d = diagramModel(s, {});
  const nodes = new Map(d.nodes.map((n) => [n.id, n.name]));
  const refs = new Set(scenarios.flatMap((t) => t.evidenceIds || []));
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${e(s.title)} - threat model review</title><style>${PRINT_STYLE}</style></head><body><h1>${e(s.title)}</h1><p>Static threat model review · Draft</p><p class="meta">Generated ${e(new Date().toISOString())} · Revision ${e(s.revision)}</p><h2>Scope and coverage</h2><p>${s.coverage.repositories} repositories; ${s.components.length} components; ${s.actors.length} actor profiles; ${s.boundaries.length} boundary records; ${scenarios.length} threat scenarios. ${s.coverage.unresolvedFlows} unresolved relationships and ${s.coverage.pendingBoundaries} boundary decisions pending.</p><p>${model.aiReview?.coverage ? `${model.aiReview.coverage.completedBatches || 0} / ${model.aiReview.coverage.totalBatches || 0} STRIDE packets completed; ${model.aiReview.coverage.failedBatches || 0} failed; ${model.aiReview.coverage.pendingBatches || 0} pending. Status: ${e(model.aiReview.status)}.` : "STRIDE analysis has not run."} Empty results do not establish absence of threats. Source observations, inferred actors/boundaries and reviewer declarations remain distinct. No target execution or runtime validation.</p><p>This printable review includes all recorded threat scenarios, component STRIDE rows and grouped boundary records. It excludes repeated checklist text, detailed flow properties and the complete evidence ledger. Use Complete HTML report and CSV/JSON exports for those records. ${s.threats.length - scenarios.length} checklist items are not threat scenarios.</p>${table(
    ["Repository", "Status", "Snapshot"],
    model.sources.map((r) => [r.name, r.status, r.snapshot || "not recorded"]),
  )}<h2>System context</h2>${systemSvg(model, { level: "context" })}<h2>Overall system DFD</h2>${systemSvg(model)}<p>Diagram uses the default service view and its disclosed node/connection limits. Unresolved destinations are coverage gaps, not invented connections. Full flow data remains in the flow register export.</p><h2>Connected flow summary</h2>${table(
    ["From", "To", "Protocol / label", "Member flows", "Basis / review"],
    d.connections.map((c) => [
      nodes.get(c.source) || c.source,
      nodes.get(c.target) || c.target,
      c.name || c.protocol || "",
      c.flowIds?.length || 1,
      `${c.basis} / ${c.reviewState}`,
    ]),
  )}<h2>Threat actors</h2>${table(
    ["Actor", "Access / prerequisites", "Basis / review"],
    s.actors.map((a) => [
      a.name,
      a.startingAccess || a.description || "Unspecified",
      `${a.basis} / ${a.reviewState}`,
    ]),
  )}<h2>Trust boundaries</h2><p>${s.boundaries.length} boundary records grouped into ${boundaryGroups.size} equivalent transition descriptions. Every boundary reference maps to the named flow crossing. TB identifies a change in trust, not a repository or automatically verified enforcement. Inferred boundaries require review; repository boundaries do not establish trust boundaries.</p>${table(
    [
      "Boundary / dimension",
      "Transition / enforcement",
      "Basis / review / boundary references",
      "Crossings",
    ],
    [...boundaryGroups.values()].map((b) => [
      `${b.name} (${b.dimension})`,
      `${b.before} → ${b.after}. ${b.enforcement || ""}`,
      `${b.basis} / ${b.reviewState}. Members: ${b.members.join(", ")}`,
      b.crossingDetails.join("; "),
    ]),
  )}<h2>Components</h2>${table(
    ["Component", "Type", "Basis / review"],
    s.components.map((c) => [c.name, c.type, `${c.basis} / ${c.reviewState}`]),
  )}<h2>Trust domains and data assets</h2>${table(["Type", "Name", "Basis / review"], [...s.domains.map((r) => ["Trust domain", r.name, `${r.basis} / ${r.reviewState}`]), ...s.assets.map((r) => ["Data asset", r.name, `${r.basis} / ${r.reviewState}`])])}<h2>Security controls</h2>${table(
    ["Control", "Basis / review", "Evidence IDs"],
    s.securityControls.map((r) => [
      r.name,
      `${r.basis} / ${r.reviewState}`,
      (r.evidenceIds || []).join(", "),
    ]),
  )}<h2>STRIDE matrix</h2><p>Component rows. Each cell reports scenario count and review state; checklist prompts are excluded from scenario counts.</p>${table(
    ["Component", ...CATEGORIES],
    s.matrix
      .filter((r) => r.rowKind === "component")
      .map((r) => [
        r.name,
        ...r.cells.map(
          (c) =>
            `${c.analysisLabel}; ${c.scenarioCount} scenarios${c.failedEvidence ? "; failed packets" : ""}${c.decision ? "; reviewer: " + c.state : ""}`,
        ),
      ]),
  )}<h2>Prioritized threats</h2><p>Review order is explained for each scenario. It is not a severity score or proof of exploitability. Source scope and reviewer decisions affect ordering.</p>${table(
    [
      "Threat reference / scenario",
      "Review priority / reason",
      "Impact / source scope / severity",
    ],
    scenarios.map((t) => [
      `${t.reference} - ${t.name}`,
      `${t.reviewPriority.label}: ${t.reviewPriority.reasons.join(" ")}`,
      `${t.analysis?.impact || t.asset}. ${(t.sourceScopes || []).join(", ")}. Severity: ${!t.decision?.stale ? t.decision?.severity || "unassessed" : "unassessed (stale decision)"}`,
    ]),
  )}<h2>Threat register</h2>${
    scenarios.length
      ? scenarios
          .map(
            (t) =>
              `<article id="${e(t.reference)}"><h3>${e(t.reference)} · ${e(t.name)}</h3><p>Record ID: ${e(t.id)} · ${e(t.categories.join(", "))} · ${e(t.reviewState)}</p><p>${e(t.reviewPriority.label)}: ${e(t.reviewPriority.reasons.join(" "))}</p><p>${e(t.scenario)}</p>${table(
                ["Field", "Detail"],
                [
                  "actorIds",
                  "asset",
                  "prerequisites",
                  "flowIds",
                  "boundaryIds",
                  "controls",
                  "mitigation",
                  "analysis",
                  "analysisQuality",
                  "evidenceStatus",
                  "boundaryLinkBasis",
                  "evidenceIds",
                  "decision",
                  "assumptions",
                ].map((k) => [
                  fieldName(k),
                  ["flowIds", "boundaryIds", "actorIds"].includes(k)
                    ? (t[k] || [])
                        .map((id) => {
                          const r = [
                            ...s.flows,
                            ...s.boundaries,
                            ...s.actors,
                          ].find((r) => r.id === id);
                          return r ? `${r.reference || r.id}: ${r.name}` : id;
                        })
                        .join("; ")
                    : display(t[k]),
                ]),
              )}</article>`,
          )
          .join("")
      : "<p>No threat scenarios recorded. Complete STRIDE review and inspect pending coverage; this is not a clean security assessment.</p>"
  }<h2>Supporting evidence</h2><p>Evidence cited by the threat scenarios above. The complete source evidence ledger is in the full HTML/JSON export.</p>${table(
    ["ID", "Repository", "File / line", "Basis"],
    model.evidence
      .filter((r) => refs.has(r.id))
      .map((r) => [r.id, r.repository, `${r.path}:${r.line}`, r.basis]),
  )}<h2>Assumptions and open questions</h2><ul>${[...model.limitations, ...s.questions].map((q) => `<li>${e(q)}</li>`).join("")}</ul>${tokenUsageHtml(model)}</body></html>`;
}
