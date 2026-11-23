import {matchesAccess, accessFilter} from './threat-access.mjs';
import { PRINT_STYLE, PRINT_HEADER, PRINT_FOOTER } from "./print-style.mjs";
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
            `${c.analysisLabel}; reviewer state: ${c.state}; ${c.scenarioCount} scenarios; ${c.questionCount || 0} architecture questions; ${c.checklistCount} checklist items; ${c.threatIds.join(" ")}`,
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
  return `<h2>Token usage</h2><p>${u.totalTokens.toLocaleString("en-US")} reported tokens across ${u.requests} recorded requests; ${u.unknownRequests} requests with unknown totals. Latest action: ${u.lastRun.totalTokens.toLocaleString("en-US")} reported tokens / ${u.lastRun.requests} requests.</p><p>Input includes cache reads/writes; those columns are subsets and must not be added again. Failed responses and retries are included. Shared requests are counted once, separately from individual repositories. Token counts are provider-reported usage, not an invoice.</p>${u.legacyUnmetered ? "<p>Earlier analysis has no token records. These subtotals cover metered requests only.</p>" : ""}<table class="usage-table"><thead><tr><th>Repository / scope</th><th>Requests</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>Reported total</th><th>Unknown requests</th></tr></thead><tbody>${u.groups.map((g) => `<tr><td>${e(g.label)}</td><td>${g.requests}</td><td>${g.inputTokens}</td><td>${g.outputTokens}</td><td>${g.cacheReadTokens}</td><td>${g.cacheWriteTokens}</td><td>${g.totalTokens}</td><td>${g.unknownRequests}</td></tr>`).join("")}</tbody></table>`;
}
export function systemReport(model) {
  const s = systemModel(model),
    table = (headers, rows) =>
      `<table><thead><tr>${headers.map((v) => `<th>${e(v)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${e(Array.isArray(v) ? v.join("; ") : v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${e(s.title)}</title><style>body{font:14px/1.5 system-ui;color:#1c2e44;margin:32px}table{border-collapse:collapse;width:100%;margin:15px 0;table-layout:fixed}td,th{border:1px solid #ccd5df;padding:7px;text-align:left;overflow-wrap:anywhere;vertical-align:top}svg{width:100%;height:auto}h2{margin-top:32px}article{break-inside:avoid;border-top:1px solid #ccd5df;padding:15px 0}@media print{body{margin:0}table{font-size:10px}h2{break-after:avoid}svg{max-height:800px}}${PRINT_STYLE}.dfd-sheet{break-inside:avoid;margin:16px 0}.dfd-sheet svg{width:100%;height:auto;max-height:850px}</style><h1>${e(s.title)}</h1><p>${e(s.profile)} · Static threat model · Draft</p><p>Revision ${e(s.revision)}. Source observations, assumptions and reviewer declarations are distinguished. Review decisions are local annotations, not authenticated organizational approvals.</p><h2>Scope and coverage</h2>${table(
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
  )}<p>${s.coverage.unresolvedFlows} unresolved relationships. ${s.coverage.pendingBoundaries} boundary decisions pending. Provider submission is not human review coverage.</p><h3>Source parsing</h3><p>${e(display(model.sourceGraph?.coverage || { status: "Not built" }))}</p><h3>STRIDE analysis coverage</h3><p>${model.aiReview?.coverage ? `${Number(model.aiReview.coverage.completedBatches || 0)} of ${Number(model.aiReview.coverage.totalBatches || 0)} batches completed; ${Number(model.aiReview.coverage.failedBatches || 0)} failed; ${Number(model.aiReview.coverage.pendingBatches || 0)} pending. Status: ${e(model.aiReview.status)}.` : "Analysis has not run."} Batch completion does not establish semantic completeness or reviewer acceptance.</p>${model.aiReview?.reviewScope === 'system' ? `<h3>System review scope and deployment assumptions</h3><p>${model.aiReview.scope.interfaceIds.length} system-scope interfaces; ${model.aiReview.scope.deferredInterfaces} interfaces deferred to deep review. Profile: ${e(s.deploymentContext.profile)}. Deployment is not verified.</p>${table(['Area', 'Assumption or reported context', 'Basis'], s.deploymentContext.questions.map(q => [q.name, q.statement, q.state]))}` : ''}${tokenUsageHtml(model)}<h2>System context</h2>${systemSvg(model, { level: "context" })}<h2>Overall system DFD</h2>${systemSvg(model)}${[
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
          `${c.analysisLabel}; reviewer state ${c.state}: ${c.scenarioCount} scenarios, ${c.questionCount || 0} architecture questions, ${c.checklistCount} checklist items`,
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
export function systemPrintReport(model, options = {}) {
  const filter = accessFilter(options.accessScope, options.includeUnresolved);
  const s = systemModel(model),
    review = model.aiReview;
  const stale =
    review?.status === "stale" ||
    (review?.basedOnRevision && review.basedOnRevision !== model.modelRevision);
  const completed = review?.coverage?.completedBatches || 0;
  const hasResults = !stale && completed > 0;
  const allScenarios = s.threats.filter((t) => t.origin === "analysis");
  const current = hasResults
    ? allScenarios.filter((t) => t.reviewState !== "stale")
    : [];
  const metadataOnly = (t) =>
    t.metadataOnly ||
    review?.mode === "metadata" ||
    /metadata.only/i.test(display(t.analysisQuality?.gaps));
  const scenarios = current
    .filter((t) => !metadataOnly(t) && matchesAccess(t, filter.scope, filter.includeUnresolved))
    .sort(
      (a, b) =>
        a.reviewPriority.rank - b.reviewPriority.rank ||
        a.id.localeCompare(b.id),
    );
  const contextQuestions = current.filter(t => metadataOnly(t) && matchesAccess(t, filter.scope, filter.includeUnresolved));
  const currentScenarioIds = new Set(scenarios.map((t) => t.id));
  const questionIds = new Set(contextQuestions.map(t=>t.id));
  const detailed = scenarios.filter(t=>!t.followUpKind).slice(0, 12);
  const table = (headers, rows) =>
    rows.length
      ? `<table><thead><tr>${headers.map((h) => `<th>${e(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${e(v)}</td>`).join("")}</tr>`).join("")}</tbody></table>`
      : "<p>None recorded for the current completed review scope.</p>";
  const evidence = new Map(model.evidence.map((r) => [r.id, r]));
  const records = new Map(
    [...s.actors, ...s.boundaries, ...s.flows].map((r) => [r.id, r]),
  );
  const names = (ids, fallback) =>
    (ids || [])
      .map((id) => {
        const r = records.get(id);
        return r
          ? `${r.reference ? r.reference + ": " : ""}${r.name}`
          : "Unresolved reference";
      })
      .join("; ") || fallback;
  const citations = (t) =>
    (t.evidenceIds || [])
      .map((id) => {
        const r = evidence.get(id);
        return r
          ? `${r.repository} / ${r.path}:${r.line}`
          : "Source reference unavailable";
      })
      .join("; ") || "No source citation recorded";
  const disposition = (r) =>
    r.reviewState === "pending"
      ? `${r.basis}; awaiting reviewer confirmation`
      : `${r.basis}; ${r.reviewState}`;
  const linkedActors = new Set(scenarios.flatMap((t) => t.actorIds || []));
  const linkedBoundaries = new Set(
    scenarios.flatMap((t) => t.boundaryIds || []),
  );
  const threatRefs = (kind, id) => {
    const refs = scenarios
      .filter((t) => t[kind]?.includes(id))
      .map((t) => t.reference);
    return (
      refs.slice(0, 8).join(", ") +
      (refs.length > 8
        ? `; ${refs.length - 8} further links in complete export`
        : "")
    );
  };
  const pending = review?.coverage?.pendingBatches || 0,
    failed = review?.coverage?.failedBatches || 0;
  const partial =
    pending > 0 ||
    failed > 0 ||
    !["completed", "completed-needs-review"].includes(review?.status);
  const state = !hasResults
    ? "No current STRIDE results"
    : partial
      ? "Partial STRIDE review"
      : "STRIDE review snapshot";
  const poc = review?.scope?.poc;
  const assessments = scenarios.reduce((a,t)=>{const k=t.validation?.assessment || 'not-assessed';a[k]=(a[k]||0)+1;return a;},{});
  const pocSummary = poc ? `<section><h2>Scoped POC · ${e(poc.title)}</h2><p>Profile assumption: ${e(poc.profile)}. ${poc.interfaceIds.length} selected inbound interfaces; ${poc.interfaceIds.length * 6} planned STRIDE category review cases. Other source remains evidence context, not whole-repository clearance.</p>${table(['Repository','Operation path'],poc.operations.map(o=>[o.repository,o.pathContains]))}<p>Code conclusions: ${e(Object.entries(assessments).map(([k,n])=>n+' '+k).join('; ') || 'No returned scenarios')}. Packet completion, code conclusions, deployment assumptions and reviewer acceptance are separate. Unassessed or needs-context scenarios are not fully assessed.</p></section>` : '';
  const snapshot = `<section class="review-snapshot"><p>Actor access filter: ${e(filter.scope)} · Unresolved access ${filter.includeUnresolved ? "included" : "excluded"}. External and internal views include mixed actor scenarios. Packet coverage below describes the full review scope. DFDs show bounded system context and focused paths; complete graph exports retain omitted objects.</p><h2>${state}</h2><p>Exported from the latest available review checkpoint. Requests still in progress are not included. Exporting does not stop or restart analysis.</p>${
    stale
      ? `<p>Historical STRIDE review: ${allScenarios.length} saved scenarios and ${completed} completed packets are historical, not current valid coverage. Their details are excluded from this report. Revalidate before relying on them; the complete HTML/JSON export retains the historical records.</p>`
      : !hasResults
        ? "<p>STRIDE analysis has not produced a successful current review checkpoint. Static checklist prompts, candidate actors and inferred boundaries are planning inputs, not completed threat analysis; they are excluded here.</p>"
        : `<p>${scenarios.length} current returned threat scenarios; ${contextQuestions.length} architecture-only questions. These are conditional analysis results, not confirmed vulnerabilities. ${partial ? "Pending, failed and unreviewed areas are not cleared by this report." : "Completion covers planned packets, not proof of complete security coverage."}</p>`
  }
    ${review?.coverage ? `<p>${stale ? "Historical counts: " : ""}${completed} / ${review.coverage.totalBatches || 0} STRIDE packets completed; ${failed} failed; ${pending} pending.</p>` : "<p>STRIDE analysis has not run.</p>"}
    ${review?.stopReason ? `<p>Last recorded stop reason: ${e(review.stopReason)}.</p>` : ""}
    ${review?.lastRunFailure ? `<p>Latest attempt failure: ${e(review.lastRunFailure.code)}. ${e(review.lastRunFailure.action)}</p>` : ""}</section>`;
  const stageCoverage = hasResults && review?.reviewOrder?.stages
    ? `<h2>Review order and coverage</h2><p>External interfaces are reviewed first, followed by their internal paths and remaining internal scope. Unknown exposure is not a declaration of internet reachability. Counts are review packets, not approved actors or boundaries.</p>${table(["Stage", "Completed / planned", "Failed", "Pending"], review.reviewOrder.stages.map((stage) => [stage.label, `${stage.completed} / ${stage.total}`, stage.failed, stage.pending]))}` : "";
  const conclusions = current.filter(t => t.sourceConclusion && matchesAccess(t, filter.scope, filter.includeUnresolved)).sort((a,b) => a.reviewPriority.rank - b.reviewPriority.rank);
  const categoryCounts = hasResults ? `<h3>Returned scenarios by STRIDE category</h3>
    ${table(CATEGORIES, [CATEGORIES.map(category => scenarios.filter(t => t.categories.includes(category)).length)])}
    <p>Each count includes current source-referenced scenarios assigned to that category. Scenarios can overlap. A zero means no scenario returned in the reviewed scope.</p>` : "";
  const conclusionSection = conclusions.length ? `<h2>Source review conclusions</h2>${conclusions.map(t => {
    const c = t.sourceConclusion;
    return `<article><h3>${e(t.reference)} · ${c.status === "open" ? "Open question" : "Conditional threat"}</h3><p>${e(c.statement)}</p><p><b>Condition or missing link</b> · ${e(c.condition)}</p><p><b>Next action</b> · ${e(c.nextAction)}</p><p>Reviewed by ${e(c.reviewer)} · Automated assessment: ${e(t.validation.assessment)}</p><ul>${c.citations.map(r => `<li>${e(r.repository)} / ${e(r.path)}:${e(r.startLine)}–${e(r.endLine)}</li>`).join("")}</ul></article>`;
  }).join("")}` : "";
  const summary = hasResults
    ? `${conclusionSection}${categoryCounts}<h2>Priority threats</h2><p>Highest review priorities from returned scenarios. This order is not a confirmed severity rating.</p>${scenarios.filter(t=>!t.followUpKind && t.validation?.assessment !== 'ruled-out').slice(0, 6).map(t => `<article><h3>${e(t.reference)} · ${e(t.name)}</h3><p><strong>${e(t.reviewPriority.label)}</strong> · Automated assessment: ${e(t.validation?.assessment || 'not-assessed')}</p><p>${e(t.analysis?.impact || t.asset)}</p><p><strong>Actor:</strong> ${e(names(t.actorIds, 'Not established'))}</p><p><strong>Trust crossing:</strong> ${e(names(t.boundaryIds, 'Not established; needs evidence'))}</p><p><strong>Control evidence:</strong> ${e(t.validation?.counterEvidence || t.controls || 'Not established')}</p>${t.validation?.deploymentAssumptions?.length ? `<p><strong>Deployment assumptions — not verified:</strong> ${e(t.validation.deploymentAssumptions.join('; '))}</p>` : ''}<p><strong>Next action:</strong> ${e(t.sourceConclusion?.nextAction || t.validation?.missingEvidence?.join('; ') || t.validation?.remediation?.codeFix || t.mitigation)}</p></article>`).join('')}${stageCoverage}<h2>What needs attention</h2><p>Start with the highest review priority below, check the stated access and controls, then assign a reviewer and remediation owner. Review order is not a severity score. Test-only and architecture-only records do not establish production exposure.</p>${table(
        ["Threat / affected scope", "Why it matters", "Next action"],
        scenarios.map((t) => [
          `${t.reference} — ${t.name}. Source scope: ${(t.sourceScopes || []).join(", ") || "not established"}`,
          `${t.analysis?.impact || t.asset || t.scenario} ${t.reviewPriority.label}: ${t.reviewPriority.reasons.join(" ")}`,
          `${t.mitigation || "Establish controls and applicability."} Severity: ${!t.decision?.stale ? t.decision?.severity || "unassessed" : "unassessed"}. Owner: ${!t.decision?.stale ? t.decision?.owner || "unassigned" : "unassigned"}.`,
        ]),
      )}<h2>System context from static extraction</h2><p>The DFD below is code/configuration context for the analysis. It is not proof that every depicted path was reviewed. Dashed or inferred connections and boundaries require confirmation.</p><h3>Overall system DFD</h3>${printDiagrams(model,s,scenarios)}
  <h2>STRIDE matrix</h2><p>Partially analyzed means some interfaces in the row have been reviewed. Not analyzed means none have. Source conclusions do not advance STRIDE packet coverage. Counts cover returned scenarios. Unreviewed or failed cells are not a clean assessment. The complete HTML/JSON export retains all scope rows.</p>${table(
    ["Component", ...CATEGORIES],
    s.matrix
      .filter(
        (r) =>
          r.rowKind === "component" &&
          (r.reviewedInterfaces || r.cells.some((c) => c.failedEvidence)) &&
          (filter.scope === 'all' || r.cells.some(c => c.threatIds?.some(id => currentScenarioIds.has(id)))),
      )
      .map((r) => [
        r.name,
        ...r.cells.map(
          (c) =>
            `${filter.scope !== 'all' && ['scenarios-identified','context-required','analyzed-no-scenario'].includes(c.analysisStatus) ? 'Reviewed scope' : c.analysisLabel}; ${(c.threatIds || []).filter((id) => currentScenarioIds.has(id)).length} scenarios${c.threatIds.filter(id=>questionIds.has(id)).length ? `; ${c.threatIds.filter(id=>questionIds.has(id)).length} architecture questions` : ''}${c.failedEvidence ? "; failed packets" : ""}`,
        ),
      ]),
  )}<h2>Threat actors linked to returned scenarios</h2><p>Showing up to 20 linked actor profiles; the complete HTML/JSON retains every actor and link. These profiles describe the access assumed by the scenarios. Awaiting reviewer confirmation means the access assumption has not been accepted; it does not mean a model request is still running.</p>${table(
    ["Actor / initial access", "Related threats", "Evidence / review"],
    s.actors
      .filter((a) => linkedActors.has(a.id)).slice(0,20)
      .map((a) => [
        `${a.name}. ${a.startingAccess || "Initial access not established"}`,
        threatRefs("actorIds", a.id),
        disposition(a),
      ]),
  )}<h2>Trust boundaries linked to returned scenarios</h2><p>A boundary describes a change of trust at a flow crossing, not a repository boundary. These links are inferred through shared interfaces; validate their relevance and enforcement for each threat.</p>${table(
    ["Boundary / transition", "Flow crossing", "Enforcement / related threats"],
    s.boundaries
      .filter((b) => linkedBoundaries.has(b.id))
      .flatMap((b) =>
        (b.crossings?.length ? b.crossings : [null]).map((c) => [
          `${b.reference}: ${b.name} (${b.dimension}). ${b.before} → ${b.after}`,
          c
            ? `${c.reference}: ${c.from} → ${c.to}`
            : "No resolved crossing established",
          `${b.enforcement || "Enforcement not established"}. ${c?.basis === 'unresolved' ? 'Candidate crossing: peer/access unresolved. ' : ''}${disposition(b)}. Threats: ${threatRefs("boundaryIds", b.id)}`,
        ]),
      ),
  )}<h2>Threat details</h2><p>${detailed.length} of ${scenarios.length} scenarios shown in detail, ordered by review priority. Every current scenario is in the summary above; complete details remain in the HTML/JSON exports. This report excludes repeated checklist text and empty property rows.</p>${
    detailed.length
      ? detailed
          .map((t) => {
            const paragraphs = [
              ["Independent source assessment", t.validation?.assessment !== 'not-assessed' ? t.validation?.assessment : 'Not assessed'],
              ["Validation counterevidence", t.validation?.counterEvidence],
              ["Missing code evidence", t.validation?.missingEvidence?.join('; ')],
              ["Deployment assumptions — not verified", t.validation?.deploymentAssumptions?.join('; ')],
              ["Recommended code change", t.validation?.remediation?.codeFix],
              ["Validated source path", t.validation?.trace?.map(r => `${r.role}: ${r.repository} / ${r.path}:${r.line} — ${r.reason}`).join('; ')],
              ["Impact", t.analysis?.impact || t.asset],
              [
                "Access and prerequisites",
                `${names(t.actorIds, "Actor not established")}. ${t.prerequisites || "Access prerequisites need confirmation."}`,
              ],
              [
                "Code path",
                t.flowIds.length ? names(t.flowIds) : t.candidateFlowIds?.length
                  ? "Candidate path; peer or deployment unresolved: " + names(t.candidateFlowIds)
                  : "No connected flow established for this scenario",
              ],
              [
                "Trust crossing",
                names(
                  t.boundaryIds,
                  "No trust boundary established for this scenario",
                ),
              ],
              [
                "Controls and counterevidence",
                t.controls || "Control effectiveness is not established",
              ],
              ["Recommended action", t.mitigation],
              ["Supporting source", citations(t)],
              [
                "Evidence limits",
                `${t.evidenceStatus}. ${display(t.analysisQuality?.gaps || "")}`,
              ],
              [
                "Unresolved assumptions",
                display(t.analysis?.assumptions || t.assumptions),
              ],
              [
                "Reviewer decision",
                t.decision && !t.decision.stale
                  ? display(t.decision)
                  : "Awaiting reviewer assessment",
              ],
            ];
            return `<article id="${e(t.reference)}"><h3>${e(t.reference)} · ${e(t.name)}</h3><p class="meta">${e(t.categories.join(", "))} · ${e(t.reviewPriority.label)} · ${e(t.reviewState)}</p><p>${e(t.scenario)}</p>${paragraphs
              .filter(([, v]) => v)
              .map(
                ([label, value]) =>
                  `<p><strong>${label}:</strong> ${e(value)}</p>`,
              )
              .join("")}</article>`;
          })
          .join("")
      : "<p>No current threat scenarios recorded. Completed packets did not establish a scenario; inspect remaining coverage and context questions.</p>"
  }
  ${
    contextQuestions.length
      ? `<h2>Questions requiring implementation evidence</h2><p>These returned records cite architecture metadata only. They are not included in the threat scenario count or presented as implementation findings.</p>${table(
          ["Reference / question", "Evidence needed"],
          contextQuestions.map((t) => [
            `${t.reference}: ${t.name}`,
            `${t.reviewPriority.reasons.join(" ")} Source: ${citations(t)}`,
          ]),
        )}`
      : ""
  }`
    : "<p>No current threat scenarios recorded in this report. Resume a successful STRIDE review before producing a findings report. Historical records and static planning inputs remain available in the workspace and complete exports.</p>";
  const deployment = hasResults && review.reviewScope === 'system'
    ? `<h2>Deployment assumptions and review scope</h2><p>${e(s.deploymentContext.profile)} · ${e(s.deploymentContext.profileStatus)}. ${review.scope.interfaceIds.length} interfaces in system scope; ${review.scope.deferredInterfaces} deferred to deep code review. Deferred scope is not security clearance.</p>${table(['Area', 'Assumption or reported context', 'Basis'], s.deploymentContext.questions.map(q => [q.name, q.statement, q.state]))}<p>Responses are optional. Unconfirmed deployment context remains explicit; completed analysis does not approve actor access or trust boundaries.</p>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${e(s.title)} - threat model review</title><style>${PRINT_STYLE}.dfd-sheet{break-inside:avoid;margin:16px 0}.dfd-sheet svg{width:100%;height:auto;max-height:850px}</style></head><body>${PRINT_HEADER}<h1>${e(s.title)}</h1><p>Static threat model review · Draft</p>${snapshot}${pocSummary}<h2>Scope and coverage</h2><p>${s.coverage.repositories} repositories selected. No target execution or runtime validation. Repository collection status below is not threat analysis coverage.</p>${table(
    ["Repository", "Collection status"],
    model.sources.map((r) => [r.name, r.status]),
  )}${deployment}${summary}${tokenUsageHtml(model)}${PRINT_FOOTER}</body></html>`;
}

function printDiagrams(model, s, scenarios) {
  const interfaces = new Set(model.aiReview?.scope?.poc?.interfaceIds || scenarios.flatMap(t=>t.interfaceIds || []));
  const focus = s.components.filter(c=>c.interfaceIds?.some(id=>interfaces.has(id))).slice(0,6);
  const selection = model.aiReview?.scope?.poc ? {interfaceIds:[...interfaces],showUnresolved:true} : {};
  return `<p>${selection.interfaceIds ? 'Selected POC interface flows only; downstream paths without a selected interface are outside this diagram.' : 'System overview and up to six focused component diagrams.'} Each diagram is capped at eight objects; omitted relationships remain in the complete graph export. Dashed links are unresolved candidates, not proved calls.</p><section class="dfd-sheet">${systemSvg(model,{level:'system',limit:8,...selection})}</section>` + focus.map(c=>`<section class="dfd-sheet"><h3>${e(c.name)} · interface context</h3>${systemSvg(model,{level:'focus',focus:c.id,showUnresolved:true,limit:8,...selection})}</section>`).join('');
}
