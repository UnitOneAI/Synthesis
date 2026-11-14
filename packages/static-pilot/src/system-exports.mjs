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
  const a = s.actors.find((a) => a.id === actorId);
  if (!a) return [];
  let reached = new Set(a.entryIds || []),
    edges = new Set();
  for (let depth = 0; depth < 6; depth++) {
    const next = new Set(reached);
    for (const f of s.flows)
      if (
        reached.has(f.source) &&
        f.basis !== "unresolved" &&
        !["rejected", "stale"].includes(f.reviewState)
      ) {
        edges.add(f.id);
        next.add(f.target);
      }
    if (next.size === reached.size) break;
    reached = next;
  }
  return [...edges];
}
export function systemSvg(
  model,
  {
    level = "system",
    lens = "identity",
    focus = "",
    actor = "",
    threat = "",
    limit = 80,
  } = {},
) {
  const s = systemModel(model, { matrix: false });
  let nodes = [...s.components, ...s.entities],
    flows = s.flows;
  const active = new Set([
    ...selectedPath(s, actor),
    ...(s.threats.find((t) => t.id === threat)?.flowIds || []),
  ]);
  const selectedThreat = s.threats.find((t) => t.id === threat);
  const activeNodes = new Set([
    ...(s.actors.find((a) => a.id === actor)?.entryIds || []),
    ...s.components
      .filter((c) =>
        c.interfaceIds.some((id) => selectedThreat?.interfaceIds.includes(id)),
      )
      .map((c) => c.id),
    ...s.flows
      .filter((f) => active.has(f.id))
      .flatMap((f) => [f.source, f.target]),
  ]);
  if (level === "context") {
    const internal = new Set(s.components.map((c) => c.id));
    nodes = [
      {
        id: "system-scope",
        name: s.title,
        type: "process",
        basis: "scope boundary; not a trust boundary",
      },
      ...s.entities,
    ];
    flows = s.flows
      .filter((f) => internal.has(f.source) !== internal.has(f.target))
      .map((f) => ({
        ...f,
        source: internal.has(f.source) ? "system-scope" : f.source,
        target: internal.has(f.target) ? "system-scope" : f.target,
      }));
  } else if (level === "focus" && focus) {
    const ids = new Set([focus]);
    for (const f of flows)
      if (f.source === focus || f.target === focus) {
        ids.add(f.source);
        ids.add(f.target);
      }
    nodes = nodes.filter((n) => ids.has(n.id));
    flows = flows.filter((f) => ids.has(f.source) && ids.has(f.target));
  }
  if (level === "focus" && focus)
    nodes.sort((a, b) => Number(b.id === focus) - Number(a.id === focus));
  const total = nodes.length;
  nodes = nodes.slice(0, limit);
  const ids = new Set(nodes.map((n) => n.id));
  flows = flows.filter((f) => ids.has(f.source) && ids.has(f.target));
  const domains = s.domains.filter(
    (d) => d.dimension === lens && d.reviewState !== "rejected",
  );
  const domainIds = new Set(domains.map((d) => d.id));
  const groups = new Map(
    domains.map((d) => [d.id, { domain: d, members: [], children: [] }]),
  );
  const roots = [];
  for (const g of groups.values()) {
    if (domainIds.has(g.domain.parentId))
      groups.get(g.domain.parentId).children.push(g);
    else roots.push(g);
  }
  const assigned = new Set();
  function assign(g) {
    for (const child of g.children) assign(child);
    g.members = nodes.filter(
      (n) => g.domain.memberIds?.includes(n.id) && !assigned.has(n.id),
    );
    g.members.forEach((n) => assigned.add(n.id));
  }
  roots.forEach(assign);
  const rest = nodes.filter((n) => !assigned.has(n.id));
  if (rest.length)
    roots.push({
      domain: { name: "Unassigned trust context" },
      members: rest,
      children: [],
    });
  const positions = new Map(),
    boxes = [];
  let y = 65;
  function layout(g, start, depth = 0) {
    const inset = Math.min(depth, 8) * 18,
      x = 20 + inset,
      width = 1010 - inset * 2;
    const box = { g, y: start, height: 0, x, width };
    boxes.push(box);
    let next = start + 45;
    const columns = Math.max(1, Math.floor((width - 30) / 300));
    g.members.forEach((n, i) =>
      positions.set(n.id, {
        x: x + 15 + ((i % columns) * (width - 30)) / columns,
        y: next + Math.floor(i / columns) * 120,
      }),
    );
    next += Math.ceil(g.members.length / columns) * 120;
    for (const child of g.children) next = layout(child, next, depth + 1) + 14;
    box.height = Math.max(55, next - start + 12);
    return start + box.height;
  }
  for (const g of roots) y = layout(g, y) + 22;
  const height = Math.max(200, y + 40);
  const text = (x, y, t, size = 13) =>
    `<text x="${x}" y="${y}" font-size="${size}" fill="#20344c">${e(t)}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" font-family="system-ui,sans-serif" viewBox="0 0 1050 ${height}" width="1050" height="${height}" role="img" aria-label="${e(s.title)} system data flow diagram"><rect width="1050" height="${height}" fill="#fff"/><defs><marker id="system-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0 0 L7 3 L0 6" fill="#61758c"/></marker></defs>${text(24, 25, `${s.title} · ${level} · ${lens} lens`, 17)}${text(24, 46, `${nodes.length}/${total} objects shown. ${total > limit ? "Use component focus or the full registers for omitted objects." : "Static evidence and review declarations; deployment not verified."}`, 11)}${boxes.map(({ g, y, height, x, width }) => `<g data-select="${e(g.domain.id || "")}" data-domain-parent="${e(g.domain.parentId || "")}" role="button" tabindex="0" aria-label="${e(g.domain.name)}"><rect x="${x}" y="${y}" width="${width}" height="${height}" rx="9" fill="#f5f8fc" stroke="#8e79a5" stroke-dasharray="6 5"/>${text(x + 15, y + 23, g.domain.name + (g.domain.id ? " · " + g.domain.basis : ""), 12)}</g>`).join("")}${flows
    .map((f) => {
      const a = positions.get(f.source),
        b = positions.get(f.target),
        same = a.y === b.y;
      const x1 = a.x + 135,
        y1 = a.y + 65,
        x2 = b.x + 135,
        y2 = b.y;
      const crossings = s.boundaries.filter(
        (b) =>
          b.flowIds.includes(f.id) &&
          b.dimension === lens &&
          b.reviewState !== "rejected",
      );
      const path = same
        ? `M${a.x + 270} ${a.y + 32} C${a.x + 300} ${a.y - 25} ${b.x - 30} ${b.y - 25} ${b.x} ${b.y + 32}`
        : `M${x1} ${y1} C${x1} ${y1 + 25} ${x2} ${y2 - 25} ${x2} ${y2}`;
      return `<g data-select="${e(f.id)}" role="button" tabindex="0" aria-label="${e(f.name)}"><title>${e(f.id + " · " + f.name + " · " + f.basis)}</title><path d="${path}" fill="none" stroke="transparent" stroke-width="16"/><path d="${path}" fill="none" stroke="${active.has(f.id) ? "#b56416" : "#61758c"}" stroke-width="${active.has(f.id) ? 3 : 1.5}" ${f.basis === "unresolved" ? 'stroke-dasharray="5 5"' : ""} class="${active.has(f.id) ? "selected" : ""}" marker-end="url(#system-arrow)"/>${text((x1 + x2) / 2 + 4, (y1 + y2) / 2, String(f.protocol || "flow").slice(0, 18), 10)}${crossings.length ? `<g data-select="${e(crossings[0].id)}" role="button" tabindex="0" aria-label="${e(crossings[0].name)}"><title>${e(crossings.map((b) => b.name + " · " + b.basis).join("; "))}</title><rect x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 + 6}" width="112" height="20" rx="4" fill="#eee8f5" stroke="#8e79a5"/>${text((x1 + x2) / 2 + 5, (y1 + y2) / 2 + 20, `${crossings.length} trust crossing${crossings.length > 1 ? "s" : ""}`, 10)}</g>` : ""}</g>`;
    })
    .join("")}${nodes
    .map((n) => {
      const p = positions.get(n.id);
      return `<g class="node" data-select="${e(n.id)}" role="button" tabindex="0" aria-label="${e(n.name)}"><title>${e(n.name + " · " + n.basis)}</title><rect x="${p.x}" y="${p.y}" width="270" height="65" rx="${n.type === "external" ? 1 : 10}" fill="#fff" stroke="${activeNodes.has(n.id) ? "#b56416" : "#b7c7da"}" stroke-width="${activeNodes.has(n.id) ? 3 : 1}" ${n.type === "unknown" ? 'stroke-dasharray="5 5"' : ""}/>${n.type === "store" ? `<line x1="${p.x}" y1="${p.y + 7}" x2="${p.x + 270}" y2="${p.y + 7}" stroke="#b7c7da"/>` : ""}${text(p.x + 12, p.y + 26, n.name.slice(0, 34), 13)}${text(p.x + 12, p.y + 47, `${n.type} · ${n.basis}`.slice(0, 42), 10)}</g>`;
    })
    .join(
      "",
    )}${text(24, height - 12, "Dashed connector: unresolved relationship. Zone outlines: selected trust lens. Full labels and evidence in registers.", 11)}</svg>`;
}
export function systemMermaid(model) {
  const s = systemModel(model, { matrix: false }),
    lines = [
      "flowchart LR",
      "%% Static system model. Evidence basis and decisions remain in the registers.",
    ];
  for (const n of [...s.components, ...s.entities]) {
    lines.push(`%% Object ${n.id} = ${nid(n.id)}`);
    lines.push(
      `  ${nid(n.id)}${n.type === "store" ? '[("' : '["'}${label(n.name + " · " + n.basis)}${n.type === "store" ? '")]' : '"]'}`,
    );
  }
  // Identity lens is the default interchange grouping; other dimensions remain explicit below.
  const used = new Set(),
    domains = s.domains.filter(
      (d) => d.dimension === "identity" && d.reviewState !== "rejected",
    );
  const ids = new Set(domains.map((d) => d.id));
  function domain(d) {
    lines.push(`%% Domain ${d.id} = ${nid(d.id)}`);
    lines.push(`  subgraph ${nid(d.id)}["${label(d.name)}"]`);
    for (const child of domains.filter((c) => c.parentId === d.id))
      domain(child);
    for (const n of d.memberIds || [])
      if (!used.has(n)) {
        used.add(n);
        lines.push(`    ${nid(n)}`);
      }
    lines.push("  end");
  }
  domains.filter((d) => !ids.has(d.parentId)).forEach(domain);
  for (const f of s.flows) {
    lines.push(`%% Flow ${f.id}: ${f.source} -> ${f.target}`);
    const b = s.boundaries.filter((b) => b.flowIds.includes(f.id));
    lines.push(
      `  ${nid(f.source)} ${f.basis === "unresolved" ? "-.->" : "-->"}|"${label([f.protocol, f.name, f.basis, ...b.map((b) => `${b.dimension}: ${b.before} to ${b.after}`)].join(" · "))}"| ${nid(f.target)}`,
    );
  }
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
        ...fields,
        "controlIds",
        "counterEvidenceIds",
        "assumptions",
        "basis",
        "reviewState",
        "evidenceIds",
        "reviewer",
        "rationale",
        "owner",
        "severity",
      ],
      ...s[kind].map((r) => [
        ...fields.map((k) => (Array.isArray(r[k]) ? r[k].join("; ") : r[k])),
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
      ]),
    ];
  }
  return "\uFEFF" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n");
}
const fieldName = (k) =>
  ({
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
    ? v.join("; ")
    : v && typeof v === "object"
      ? Object.entries(v)
          .filter(([k]) => k !== "fingerprint")
          .map(([k, x]) => `${fieldName(k)}: ${display(x)}`)
          .join("; ")
      : String(v ?? "");
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
      display(r.coverage || {}),
    ]),
  )}<p>${s.coverage.unresolvedFlows} unresolved relationships. ${s.coverage.pendingBoundaries} boundary decisions pending. Provider submission is not human review coverage.</p><h2>System context</h2>${systemSvg(model, { level: "context" })}<h2>Overall system DFD</h2>${systemSvg(model)}${[
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
