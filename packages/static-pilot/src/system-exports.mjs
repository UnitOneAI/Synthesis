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
  const text = (x, y, value, size = 12) =>
    `<text x="${x}" y="${y}" font-size="${size}" fill="#20344c">${e(value)}</text>`;
  const edgeCounts = new Map(),
    edgeIndices = new Map();
  for (const f of d.connections) {
    const key = [f.source, f.target].sort().join(":");
    edgeCounts.set(key, (edgeCounts.get(key) || 0) + 1);
  }
  const flowSvg = d.connections
    .map((f) => {
      const a = positions.get(f.source),
        b = positions.get(f.target);
      const key = [f.source, f.target].sort().join(":"),
        ordinal = edgeIndices.get(key) || 0;
      edgeIndices.set(key, ordinal + 1);
      const offset = (ordinal - (edgeCounts.get(key) - 1) / 2) * 28;
      let path, lx, ly;
      if (b.x > a.x) {
        const x1 = a.x + 260,
          x2 = b.x,
          mid = (x1 + x2) / 2;
        path = `M${x1} ${a.y + 40} C${mid + offset} ${a.y + 40} ${mid + offset} ${b.y + 40} ${x2} ${b.y + 40}`;
        lx = mid;
        ly = (a.y + b.y) / 2 + 30 + offset;
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
      const label = `${f.protocol || "Data"}${f.flowIds.length > 1 ? ` × ${f.flowIds.length}` : ""}`;
      return `<g class="dfd-connection" data-select="${e(f.flowIds[0])}" data-flow-ids="${e(f.flowIds.join(" "))}" data-connection-id="${e(f.id)}" role="button" tabindex="0" aria-label="${e(f.name)}"><title>${e(`${f.name} · ${f.basis} · ${f.reviewState}. Member flows: ${f.flowIds.join(", ")}`)}</title><path d="${path}" fill="none" stroke="transparent" stroke-width="18"/><path d="${path}" fill="none" stroke="${f.active ? "#b56416" : "#61758c"}" stroke-width="${f.active ? 3 : 1.7}" ${dashed ? 'stroke-dasharray="6 4"' : ""} marker-end="url(#system-arrow)"/><rect x="${lx - 43}" y="${ly - 14}" width="95" height="20" rx="4" fill="white"/>${text(lx - 38, ly, label, 11)}${boundaries.length ? `<g data-select="${e(boundaries[0].id)}" role="button" tabindex="0" aria-label="${e(boundaries[0].name)}"><title>${e(boundaries.map((b) => `${b.name} · ${b.basis} · ${b.reviewState}`).join("; "))}</title><rect x="${lx - 43}" y="${ly + 9}" width="126" height="20" rx="4" fill="#eee8f5" stroke="#8e79a5" ${state === "pending" ? 'stroke-dasharray="3 3"' : ""}/>${text(lx - 38, ly + 23, `boundary: ${state}`, 10)}</g>` : ""}</g>`;
    })
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" font-family="system-ui,sans-serif" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="${e(s.title)} system data flow diagram"><title>${e(s.title)} · ${e(d.level)} · ${e(d.lens)} lens</title><desc>Static evidence and review declarations. Dashed connections are hypotheses or unresolved relationships. Connectivity does not establish exploitability.</desc><rect width="${width}" height="${height}" fill="#fff"/><defs><marker id="system-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0 0 L7 3 L0 6" fill="#61758c"/></marker></defs>${text(24, 26, `${s.title} · ${d.level} · ${d.lens} lens`, 17)}${text(24, 48, `${d.nodes.length} objects · ${d.connections.length} connections representing ${d.coverage.representedFlows} flows · ${d.coverage.unresolvedRelationships} unresolved relationships in coverage`, 11)}${text(24, 67, `${d.coverage.omittedNodes} omitted objects / ${d.coverage.omittedConnections} omitted connections from canvas limit; ${d.coverage.filteredFlows} flows outside view filters. Full registers retain evidence.`, 11)}${actor ? text(24, 87, `Actor profile: ${actor.name} · conditional access: ${actor.startingAccess}`.slice(0, 150), 11) : ""}${boxes.map(({ domain: g, x, y, width: w, height: h }) => `<g data-select="${e(g.id)}" data-domain-parent="${e(g.parentId || "")}" role="button" tabindex="0" aria-label="${e(g.name)}"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" fill="#f5f8fc" stroke="#8e79a5" ${g.reviewState !== "accepted" ? 'stroke-dasharray="6 5"' : ""}/>${text(x + 12, y + 22, `${g.name} · ${g.basis} · ${g.reviewState}`)}</g>`).join("")}${flowSvg}${d.nodes
    .map((n) => {
      const p = positions.get(n.id),
        active = d.activeNodeIds.includes(n.id);
      const entry = actor?.entryIds?.some((id) => n.memberIds.includes(id));
      const chunks = (n.name.match(/.{1,32}/gu) || [""]).slice(0, 2);
      return `<g class="node" data-component-type="${e(n.type)}" data-select="${e(n.id)}" role="button" tabindex="0" aria-label="${e(n.name)}"><title>${e(`${n.name} · ${n.classification || n.basis} · ${n.memberIds.length} source component(s)`)}</title><rect x="${p.x}" y="${p.y}" width="260" height="85" rx="${n.type === "external" ? 2 : 10}" fill="white" stroke="${active ? "#b56416" : "#a8bfd8"}" stroke-width="${active ? 3 : 1.4}" ${n.type === "unknown" ? 'stroke-dasharray="5 5"' : ""}/>${n.type === "store" ? `<path d="M${p.x} ${p.y + 12} Q${p.x + 130} ${p.y + 30} ${p.x + 260} ${p.y + 12}" fill="none" stroke="#a8bfd8"/>` : ""}${n.type === "broker" ? `<path d="M${p.x + 6} ${p.y + 8}V${p.y + 77} M${p.x + 254} ${p.y + 8}V${p.y + 77}" stroke="#61758c"/>` : ""}${entry ? `<circle cx="${p.x + 246}" cy="${p.y + 14}" r="5" fill="#b56416"><title>Actor entry point under stated access assumptions</title></circle>` : ""}${chunks.map((line, i) => text(p.x + 12, p.y + 25 + i * 17, line, 13)).join("")}${text(p.x + 12, p.y + 69, `${n.type}${n.type !== "source-group" && n.classification ? " candidate" : ""}${n.memberIds.length > 1 ? ` · ${n.memberIds.length} source groups` : ""}`, 10)}</g>`;
    })
    .join(
      "",
    )}${!d.connections.length ? text(24, height - 50, "No matched connections in this view. Inspect unresolved coverage or choose a component.", 12) : ""}${text(24, height - 18, "Dashed: candidate / unresolved. Boundary badges: selected trust lens. Actor paths are conditional.", 11)}</svg>`;
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
      `  ${nid(f.source)} ${["static endpoint match", "reviewer declaration"].includes(f.basis) ? "-->" : "-.->"}|"${label([f.name, f.basis, ...boundaries.map((b) => `${b.dimension}: ${b.before} to ${b.after} (${b.reviewState})`)].join(" · "))}"| ${nid(f.target)}`,
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
            `${c.state}; ${c.scenarioCount} scenarios; ${c.checklistCount} checklist items; ${c.threatIds.join(" ")}`,
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
        "name",
        "dimension",
        "before",
        "after",
        "enforcement",
        "flowIds",
      ],
      threats: [
        "id",
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
        "name",
        "source",
        "target",
        "protocol",
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
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${e(s.title)}</title><style>body{font:14px/1.5 system-ui;color:#1c2e44;margin:32px}table{border-collapse:collapse;width:100%;margin:15px 0;table-layout:fixed}td,th{border:1px solid #ccd5df;padding:7px;text-align:left;overflow-wrap:anywhere;vertical-align:top}svg{width:100%;height:auto}h2{margin-top:32px}article{break-inside:avoid;border-top:1px solid #ccd5df;padding:15px 0}@media print{body{margin:0}table{font-size:10px}h2{break-after:avoid}svg{max-height:800px}}</style><h1>${e(s.title)}</h1><p>${e(s.profile)} · Static threat model · Draft</p><p>Revision ${e(s.revision)}. Source observations, assumptions and reviewer declarations are distinguished. Review decisions are local annotations, not authenticated organizational approvals.</p><h2>Scope and coverage</h2>${table(
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
            r.id + " / " + r.name,
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
          `${c.state}: ${c.scenarioCount} scenarios, ${c.checklistCount} checklist items`,
      ),
    ]),
  )}<h2>Threat register</h2><p>${s.threats.filter((t) => t.origin !== "review checklist").length} threat scenarios and ${s.threats.filter((t) => t.origin === "review checklist").length} checklist items. These are conditional review records, not confirmed vulnerabilities.</p>${s.threats
    .map(
      (t) =>
        `<article><h3>${e(t.name)}</h3><p>${e(t.id)} · ${t.origin === "review checklist" ? "Review checklist" : "Threat scenario"} · ${e(t.categories.join(", "))} · ${e(t.reviewState)}</p><p>${e(t.scenario)}</p>${table(
          ["Field", "Value"],
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
