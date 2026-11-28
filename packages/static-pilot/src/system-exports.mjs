import {investigationAction} from './threat-outcome.mjs';
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
export function decisionPathHtml(path) {
  if(!path)return '';
  return `<section class="decision-path"><h4>Actor-to-operation evidence</h4><p><strong>${e(path.actor)}</strong> · Required access: ${e(path.access)}</p><p>${e(path.pathStatus)}. ${e(path.interpretation)}</p><ol>${path.stages.map(stage=>`<li><strong>${e(stage.label)} · ${e(stage.status)}</strong><p>${e(stage.explanation)}</p>${stage.citations.map(c=>`<small>${e(c.repository)} / ${e(c.path)}:${e(c.startLine)}–${e(c.endLine)}</small>`).join('<br>')}</li>`).join('')}</ol><p><strong>Exposure:</strong> ${e(path.declaredExposure)}<br><strong>Runtime:</strong> ${e(path.runtime)}</p><p><strong>Decision consistency:</strong> ${e(path.consistency.status)} — ${e(path.consistency.reason)}</p><p><strong>Linked boundaries:</strong> ${e(path.boundaries.map(b=>`${b.reference}: ${b.name} (${b.state})`).join('; ') || 'No case-specific boundary established.')} These links do not approve enforcement.</p><p>Evidence repositories: ${e(path.repositories.join(', ') || 'None recorded')}. Multiple repositories alone do not demonstrate a security benefit; the cited control or binding must change the decision.</p></section>`;
}
// Present saved conclusions without another model call or lossy sentence trimming.
// Conditions stay visible; reports also print the full argument in an appendix.
export function threatBriefHtml(t,{includeDetails=true}={}) {
 const a=t.validation || {},eng=a.engineering,path=t.decisionPath;
 const row=(label,value)=>value?`<p class="${label==='Developer action'?'required-action':''}"><strong>${e(label)}:</strong> ${e(value)}</p>`:'';
 const conditions=eng?.conditions || [];
 const refs=[...new Map((eng?.obligations || []).flatMap(o=>o.citations || []).map(c=>[JSON.stringify([c.repository,c.path,c.startLine,c.endLine]),c])).values()];
 const controls=eng?.obligations?.find(o=>o.kind==='applicable-controls');
 const ruled=t.outcome?.kind==='ruled-out'||a.assessment==='ruled-out';
 return `<div class="threat-brief"><p class="conclusion"><strong>Decision:</strong> ${e(t.sourceConclusion?.statement || eng?.conclusion || t.scenario || t.name)}</p>${row('Impact',a.impact)}${row('Actor and required access',[path?.actor || a.actor,path?.access || a.initialAccess].filter(Boolean).join(' — '))}${row(ruled?'Why this path is blocked':'Controls on this path',controls?.reason || a.counterEvidence || t.controls)}${t.sourceConclusion?.condition?row('Condition',t.sourceConclusion.condition):conditions.length?`<p><strong>Applies only when all conditions hold:</strong></p><ul class="conditions">${conditions.map(c=>`<li>${e(c.statement)} <strong>Required: ${e(c.requiredAnswer)}.</strong></li>`).join('')}</ul>`:row('Condition',(a.deploymentAssumptions || []).join('; ') || t.prerequisites)}${row(ruled?'Preserve this protection':'Developer action',t.sourceConclusion?.nextAction || a.remediation?.codeFix || t.mitigation)}${row('Verify the change',a.remediation?.validation)}${row('Owner',t.decision?.stale?'Unassigned':t.decision?.owner || 'Unassigned')}${refs.length?`<p class="evidence-references"><strong>Code evidence:</strong> ${refs.map(c=>`${e(c.repository)} / ${e(c.path)}:${e(c.startLine)}–${e(c.endLine)}`).join('; ')}</p>`:''}${includeDetails?`<details class="supporting-detail"><summary>Full path, opposing evidence and review rationale</summary>${threatSupportingHtml(t)}</details>`:''}</div>`;
}
export function threatSupportingHtml(t) {
 const a=t.validation || {},row=(label,value)=>value?`<p><strong>${e(label)}:</strong> ${e(value)}</p>`:'';
 const refs=items=>(items || []).map(c=>`${c.repository} / ${c.path}:${c.startLine}–${c.endLine}`).join('; ');
 const conditions=a.engineering?.conditions || [];
 const original=t.sourceConclusion?`${row('Automated assessment before reviewer conclusion',a.engineering?.conclusion)}${row('Automated remediation proposal',a.remediation?.codeFix)}<p>The reviewer conclusion appears above. The original automated conditions remain below for traceability; they are not additional reviewer-approved facts.</p>`:'';
 return `${original}${decisionPathHtml(t.decisionPath)}${conditions.length?`<h4>Complete condition scope and evidence</h4>${conditions.map(c=>`${row('Condition',c.statement)}${row('Required answer',c.requiredAnswer)}${row('Applies to',c.scope)}${row('Basis',c.basis==='code-dependent'?'Code-dependent condition; effective deployment remains unverified':'Deployment assumption; not established by static analysis')}${row('Binding evidence',refs(c.citations))}`).join('')}`:''}${row('Opposing evidence considered',a.counterEvidence)}${(a.sharedControlApplications || []).map(c=>row('Shared control — '+c.effect,c.conclusion+' '+c.reason)+row('Control evidence',refs(c.citations))+row('Case binding evidence',refs(c.bindingCitations))).join('')}${row('Interim control',a.remediation?.interimControl)}${row('Residual risk',a.remediation?.residualRisk)}${row('Recovery',a.remediation?.recovery)}${row('Approval',a.remediation?.approval)}${row('Rollback',a.remediation?.rollback)}`;
}
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
        ly = b.y + 22 + (targetOrdinal - (incoming.get(f.target) - 1) / 2) * 56;
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
      // Keep boundary references in the inter-component gutter. A single wide
      // badge previously extended under the target node and hid its status.
      const badgeWidth = b.x > a.x ? Math.min(218, b.x - a.x - 272) : 218;
      const badgeX = b.x > a.x ? b.x - badgeWidth - 8 : lx - 43;
      const dashed =
        f.basis !== "static endpoint match" &&
        f.basis !== "reviewer declaration";
      const label = `${f.transport && f.transport !== "unknown" ? f.transport : f.protocol || "Data"}${f.flowIds.length > 1 ? ` × ${f.flowIds.length}` : ""}`;
      return `<g class="dfd-connection" data-select="${e(f.flowIds[0])}" data-flow-ids="${e(f.flowIds.join(" "))}" data-connection-id="${e(f.id)}" role="button" tabindex="0" aria-label="${e(f.name)}"><title>${e(`${f.name} · ${f.basis} · ${f.reviewState}. Member flows: ${f.flowIds.join(", ")}`)}</title><path d="${path}" fill="none" stroke="transparent" stroke-width="18"/><path d="${path}" fill="none" stroke="${f.active ? "#b56416" : "#61758c"}" stroke-width="${f.active ? 3 : 1.7}" ${dashed ? 'stroke-dasharray="6 4"' : ""} marker-end="url(#system-arrow)"/><rect x="${lx - 43}" y="${ly - 14}" width="95" height="20" rx="4" fill="white"/>${text(lx - 38, ly, label, 11)}${boundaries.length ? `<g data-select="${e(boundaries[0].id)}" role="button" tabindex="0" aria-label="${e(boundaries[0].name)}"><title>${e(boundaries.map((b) => `${b.reference} · ${b.name} · ${b.before} → ${b.after} · ${b.basis} · ${b.reviewState}`).join("; "))}</title><rect class="dfd-boundary-badge" data-connection-id="${e(f.id)}" x="${badgeX}" y="${ly + 9}" width="${badgeWidth}" height="32" rx="4" fill="#eee8f5" stroke="#8e79a5" ${state === "pending" ? 'stroke-dasharray="3 3"' : ""}/>${text(badgeX + 5, ly + 21, `${boundaries[0].reference}${boundaries.length > 1 ? " +" + (boundaries.length - 1) : ""}`, 10)}${text(badgeX + 5, ly + 34, state, 10)}</g>` : ""}</g>`;
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
  return `<h2>Token usage · workspace history</h2><p>This ledger includes historical reviews and other scopes retained in the workspace; it is not the cost of only the selected POC. Latest action may cover only one review phase.</p><p>${u.totalTokens.toLocaleString("en-US")} reported tokens across ${u.requests} recorded requests; ${u.unknownRequests} requests with unknown totals. Latest action: ${u.lastRun.totalTokens.toLocaleString("en-US")} reported tokens / ${u.lastRun.requests} requests.</p><p>Input includes cache reads/writes; those columns are subsets and must not be added again. Failed responses and retries are included. Shared requests are counted once, separately from individual repositories. Token counts are provider-reported usage, not an invoice.</p>${u.legacyUnmetered ? "<p>Earlier analysis has no token records. These subtotals cover metered requests only.</p>" : ""}<table class="usage-table"><thead><tr><th>Repository / scope</th><th>Requests</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>Reported total</th><th>Unknown requests</th></tr></thead><tbody>${u.groups.map((g) => `<tr><td>${e(g.label)}</td><td>${g.requests}</td><td>${g.inputTokens}</td><td>${g.outputTokens}</td><td>${g.cacheReadTokens}</td><td>${g.cacheWriteTokens}</td><td>${g.totalTokens}</td><td>${g.unknownRequests}</td></tr>`).join("")}</tbody></table>`;
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
  const supported = scenarios.filter(t => t.outcome?.kind === 'supported');
  const investigations = [...scenarios, ...contextQuestions].filter(t => t.outcome?.kind === 'investigation');
  const detailed = supported;
  const technical = options.technical === true;
  const registerScenarios=technical?scenarios:scenarios.filter(t=>t.outcome?.kind!=='investigation');
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
  const investigationGroups = [...new Set(investigations.map(investigationAction))].map((action,index)=>({
    reference:`A-${String(index+1).padStart(2,'0')}`, action,
    scenarios:investigations.filter(t=>investigationAction(t)===action),
  }));
  const investigationRefs = new Map(investigationGroups.flatMap(g=>g.scenarios.map(t=>[t.id,g.reference])));
  const disposition = (r) =>
    r.reviewState === "pending"
      ? `${r.basis}; awaiting reviewer confirmation`
      : `${r.basis}; ${r.reviewState}`;
  const linkedActors = new Set(supported.flatMap((t) => t.actorIds || []));
  const linkedBoundaries = new Set(
    supported.flatMap((t) => t.boundaryIds || []),
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
  const repoAssessment=s.repositoryAssessment;
  const repoSummary=repoAssessment ? `<section><h2>Selected repository assessment</h2><p>Primary repositories: ${e(poc.repositories.join(', '))}. Supporting repositories: ${e(poc.supportingRepositories.join(', ')||'None')}. Profile assumption: ${e(poc.profile)}.</p><p>${e(repoAssessment.interpretation)}</p>${table(['STRIDE category','Conclusive cases','Evidence gaps','Pending','Failed','Conditional','Ruled out','No scenario'],repoAssessment.rows.map(r=>[r.category,r.conclusive,r.gaps,r.pending,r.failed,r.supported,r.ruledOut,r.noScenario]))}<h3>File coverage</h3>${table(['Primary repository','Inventory entries','Identified interfaces','File/collection gaps'],(repoAssessment.inventory?.repositories||[]).map(r=>[r.repository,r.files,r.identifiedInterfaces,r.gapCount]))}<p>${repoAssessment.complete?'All planned category cases have cited conclusions and no recorded file gaps.':'Repository assessment remains incomplete where category, file or collection gaps are recorded. Completed requests are not complete repository clearance.'}</p></section>` : '';
  const pocSummary = poc && poc.kind!=='repositories' ? `<section><h2>Scoped POC · ${e(poc.title)}</h2><p>Profile assumption: ${e(poc.profile)}. ${poc.interfaceIds.length} selected inbound interfaces; ${poc.operationGroups || poc.interfaceIds.length} operation definitions; ${(poc.operationGroups || poc.interfaceIds.length) * 6} planned STRIDE category review cases. Other source remains evidence context, not whole-repository clearance.</p>${table(['Repository','Operation path'],poc.operations.map(o=>[o.repository,o.pathContains]))}<p>Automated scenario assessments: ${e(Object.entries(assessments).map(([k,n])=>n+' '+({'not-assessed':'not yet assessed','static-supported':'supported conditional','needs-context':'need code evidence','ruled-out':'ruled out','stale':'require reassessment','failed':'failed'}[k] || k)).join('; ') || 'No returned scenarios')}. Packet completion, code conclusions, deployment assumptions and reviewer acceptance are separate. Unassessed or needs-context scenarios are not fully assessed.</p></section>` : '';
  const snapshot = `<section class="review-snapshot"><p>Actor access filter: ${e(filter.scope)} · Unresolved access ${filter.includeUnresolved ? "included" : "excluded"}. External and internal views include mixed actor scenarios. Coverage below describes the full review scope.</p><h2>${state}</h2><p>Saved review checkpoint; in-flight requests are not included.</p>${
    stale
      ? `<p>Historical STRIDE review: ${allScenarios.length} saved scenarios and ${completed} completed packets are historical, not current valid coverage. Their details are excluded from this report. Revalidate before relying on them; the complete HTML/JSON export retains the historical records.</p>`
      : !hasResults
        ? "<p>STRIDE analysis has not produced a successful current review checkpoint. Static checklist prompts, candidate actors and inferred boundaries are planning inputs, not completed threat analysis; they are excluded here.</p>"
        : `<p>${scenarios.length} current returned threat scenarios; ${contextQuestions.length} architecture-only questions. ${supported.length} supported conditional threats; ${scenarios.filter(t=>t.outcome?.kind === "ruled-out").length} ruled out for the cited path; ${investigations.length} require investigation. Returned hypotheses are not supported threats. ${partial ? "Pending, failed and unreviewed areas are not cleared by this report." : "Completion covers planned packets, not proof of complete security coverage."}</p>`
  }
    ${review?.coverage ? `<p>${stale ? "Historical counts: " : ""}${completed} / ${review.coverage.totalBatches || 0} STRIDE packets completed; ${failed} failed; ${pending} pending.</p>` : "<p>STRIDE analysis has not run.</p>"}
    ${hasResults ? `<p><strong>What ran:</strong> ${scenarios.filter(t=>['static-supported','ruled-out','needs-context'].includes(t.validation?.assessment)).length} of ${scenarios.length} scenarios received a code assessment; ${scenarios.filter(t=>t.validation?.challengeCompleted).length} completed the separate critical check. ${scenarios.filter(t=>!t.validation || ['not-assessed','stale'].includes(t.validation.assessment)).length} have no current completed code assessment. These counts are separate from STRIDE discovery above.</p>` : ''}
    ${review?.stopReason && review.stopReason!=='plan-exhausted' ? `<p>Last recorded stop reason: ${e(review.stopReason)}.</p>` : ""}
    ${review?.lastRunFailure ? `<p>Latest attempt failure: ${e(review.lastRunFailure.code)}. ${e(review.lastRunFailure.action)}</p>` : ""}</section>`;
  const stageCoverage = hasResults && review?.reviewOrder?.stages
    ? `<h2>Review order and coverage</h2><p>External interfaces are reviewed first, followed by their internal paths and remaining internal scope. Unknown exposure is not a declaration of internet reachability. Counts are review packets, not approved actors or boundaries.</p>${table(["Stage", "Completed / planned", "Failed", "Pending"], review.reviewOrder.stages.map((stage) => [stage.label, `${stage.completed} / ${stage.total}`, stage.failed, stage.pending]))}` : "";
  const conclusions = current.filter(t => t.sourceConclusion?.status === 'open' && matchesAccess(t, filter.scope, filter.includeUnresolved)).sort((a,b) => a.reviewPriority.rank - b.reviewPriority.rank);
  const categoryCounts = hasResults ? `<h3>Returned scenarios by STRIDE category</h3>
    ${table(CATEGORIES, [CATEGORIES.map(category => scenarios.filter(t => t.categories.includes(category)).length)])}
    <p>Each count includes current source-referenced scenarios assigned to that category. Scenarios can overlap. A zero means no scenario returned in the reviewed scope.</p>` : "";
  const conclusionSection = conclusions.length ? `<h2>Source review conclusions</h2>${conclusions.map(t => {
    const c = t.sourceConclusion;
    return `<article><h3>${e(t.reference)} · ${c.status === "open" ? "Open question" : "Conditional threat"}</h3><p>${e(c.statement)}</p><p><b>Condition or missing link</b> · ${e(c.condition)}</p><p><b>Next action</b> · ${e(c.nextAction)}</p><p>Reviewed by ${e(c.reviewer)} · Automated assessment: ${e(t.validation.assessment)}</p><ul>${c.citations.map(r => `<li>${e(r.repository)} / ${e(r.path)}:${e(r.startLine)}–${e(r.endLine)}</li>`).join("")}</ul></article>`;
  }).join("")}` : "";
  const featureRows=s.featureReview?.features || [];
  const reviewedFeatures=featureRows.filter(f=>f.categories.some(c=>c.decided||c.incomplete));
  const shownFeatures=technical?featureRows:reviewedFeatures.slice(0,20);
  const scopedMatrix=s.matrix.filter(r=>r.rowKind==='component' && (!review?.scope?.interfaceIds?.length || r.interfaceIds.some(id=>review.scope.interfaceIds.includes(id))) && (filter.scope==='all'||r.cells.some(c=>c.threatIds?.some(id=>currentScenarioIds.has(id)))));
  const shownMatrix=technical?scopedMatrix:scopedMatrix.filter(r=>r.cells.some(c=>!['not-analyzed','outside-scope'].includes(c.analysisStatus)));
  const featureSection=hasResults?`<h2>Feature decisions across STRIDE</h2><p>${e(s.featureReview?.interpretation)} ${technical?'All feature groups shown.':`Showing ${shownFeatures.length} groups with recorded assessments; ${featureRows.length-shownFeatures.length} other groups remain in the complete technical export. Omitted groups are not cleared.`}</p>${table(['Operations / source','Investigation progress',...CATEGORIES],shownFeatures.map(f=>[`${f.name}: ${f.repository} / ${f.path}. Operations: ${f.operations.slice(0,5).map(o=>o.name).join('; ')}${f.operations.length>5?' (additional operations in workspace)':''}`,`${f.reviewedOperations}/${f.interfaceIds.length} operations with review results; ${f.supported} supported threats; ${f.ruledOut} ruled-out paths; ${f.investigations} investigations; ${f.conditions} deployment questions`,...f.categories.map(c=>`${c.state}; ${c.decided}/${c.total} decisions`)]))}`:'';
  const decisionQuestions=(s.deploymentDecisionQuestions || []).filter(q=>currentScenarioIds.has(q.threatId));
  const questionSection=hasResults?`<h2>Deployment decisions</h2><p>Reviewer declarations change the stated deployment condition only. They do not establish runtime behavior or repair missing code evidence. ${technical?'':`Showing up to 12 of ${decisionQuestions.length} questions; all remain in the technical export.`}</p>${table(['Question / profile','If yes / if no','Recorded answer and basis'],(technical?decisionQuestions:decisionQuestions.slice(0,12)).map(q=>[`${q.question} Profile: ${q.profile}. ${q.conditionStatus}`,`Yes: ${q.ifYes} No: ${q.ifNo}`,q.answer?`${q.answer.answer} — ${q.answer.reviewer}: ${q.answer.rationale}. ${q.consequence}`:'Unanswered; retain the stated condition.']))}`:'';
  const threatDetails = `<h2>Threat details</h2><p>${detailed.length} supported threats shown in detail. Unassessed and unresolved scenarios remain in the disposition register; they are not expanded into speculative finding narratives. This report excludes repeated checklist text and empty property rows.</p>${
    detailed.length
      ? detailed
          .map((t) => {
            const paragraphs = [
              ['Original discovery title',technical?t.originalTitle:null],
              ['Review basis',t.sourceConclusion ? `Engineering review by ${t.sourceConclusion.reviewer}. Automated assessment remains ${t.validation.assessment}; this decision does not change automated coverage.` : t.validation?.challengeCompleted ? 'Static engineering review and separate critical check; no runtime validation.' : 'Independent static source assessment; no runtime validation.'],
              ['Who can act and why',t.validation?.engineering ? `${t.decisionPath?.actor || t.validation.actor || 'Actor not established'}. Required access: ${t.decisionPath?.access || t.validation.initialAccess || 'Not established'}` : names(t.actorIds,'Actor not established')],
              ['Condition',t.sourceConclusion?.condition || (t.validation?.deploymentAssumptions || []).join('; ') || t.prerequisites],
              ['Code evidence',t.sourceConclusion
                ? t.sourceConclusion.citations.map(r=>`${r.repository} / ${r.path}:${r.startLine}–${r.endLine}`).join('; ')
                : t.validation?.engineering ? null : t.validation?.trace?.map(r=>`${r.role}: ${r.repository} / ${r.path}:${r.line}–${r.endLine} — ${r.reason}`).join('; ')],
              ['Why existing controls do not resolve this path',t.validation?.counterEvidence || t.controls],
              ['Direct impact',t.validation?.engineering ? t.validation.impact : null],
              ['Required action',t.sourceConclusion?.nextAction || t.validation?.remediation?.codeFix || t.mitigation],
              ['Validation to perform',t.sourceConclusion ? null : t.validation?.remediation?.validation],
              ['Automation still requested',t.sourceConclusion && t.validation.assessment==='needs-context' ? (t.validation.missingEvidence || []).join('; ') : null],
              ['Remediation owner',t.decision?.stale ? 'Unassigned' : t.decision?.owner || 'Unassigned; security champion to assign'],
            ];
            if(!technical)return `<article id="${e(t.reference)}"><h3>${e(t.reference)} · ${e(t.outcome?.label || "Conditional threat")}</h3><p class="meta">${e(t.categories.join(", "))} · ${e(t.reviewPriority.label)}</p>${threatBriefHtml(t,{includeDetails:false})}${(options.snippets?.[t.id] || []).map(w=>w.gap?`<p class="gap">${e(w.gap)}</p>`:`<h4>${e(w.repository)} / ${e(w.path)}:${w.startLine}–${w.endLine}</h4><p class="meta">${e(w.basis)}</p><pre>${w.lines.map(l=>`${l.line} ${e(l.text)}`).join("\n")}</pre>${w.limited?"<p>Excerpt shortened; the full cited range remains in source.</p>":""}`).join("")}</article>`;
            return `<article id="${e(t.reference)}"><h3>${e(t.reference)} · ${e(t.name)}</h3><p class="meta">${e(t.categories.join(", "))} · ${e(t.reviewPriority.label)} · Reviewer decision: ${e(t.reviewState)}</p><p>${e(t.sourceConclusion?.statement || t.validation?.engineering?.conclusion || t.scenario)}</p>${paragraphs
              .filter(([, v]) => v)
              .map(
                ([label, value]) =>
                  `<p><strong>${label}:</strong> ${e(value)}</p>`,
              )
              .join("")}${decisionPathHtml(t.decisionPath)}${(options.snippets?.[t.id] || []).map(w=>w.gap?`<p class="gap">${e(w.gap)}</p>`:`<h4>${e(w.repository)} / ${e(w.path)}:${w.startLine}–${w.endLine}</h4><p>${e(w.basis)}${w.limited?' The cited range is longer than this excerpt; remaining lines are not shown.':''}</p><pre>${w.lines.map(l=>`<span class="code-line ${l.line>=w.startLine&&l.line<=w.endLine?'cited':''}"><span class="line-no">${l.line}</span>${e(l.text)}</span>`).join('')}</pre>`).join('')}${technical && t.validation?.engineering ? `<h4>Evidence supporting the decision</h4>${table(['Check','What the code shows','Source'],t.validation.engineering.obligations.map(o=>[({'entry':'Entry point','sensitive-operation':'Sensitive operation','path-binding':'Connected code path','applicable-controls':'Controls on this path'})[o.kind],o.reason,o.citations.map(c=>`${c.repository} / ${c.path}:${c.startLine}–${c.endLine}`).join('; ')]))}${technical && t.validation.engineering.reviewerQuestions.length ? `<h4>Decisions for the deployment reviewer</h4><p>Each answer resolves only the condition asked. All conditions for the stated attack must hold together. Record the deployment and rationale with the review decision; answers are reviewer statements, not runtime verification.</p>${decisionQuestions.filter(q=>q.threatId===t.id).map(q=>`<p><strong>${e(q.question)}</strong><br>Yes: ${e(q.ifYes)}<br>No: ${e(q.ifNo)}</p>`).join('')}` : ''}` : ''}</article>`;
          })
          .join("")
      : "<p>No individually supported threat details to publish. Inspect the disposition register and remaining review coverage.</p>"
  }`;
  const ruledOutCases=scenarios.filter(t=>t.outcome?.kind==='ruled-out');
  const ruledOutSection=ruledOutCases.length?`<h2>Ruled-out paths and decisive controls</h2><p>These are assessed attack paths that a cited fact blocks. This is not clearance of the component or other actors. Showing ${Math.min(technical?ruledOutCases.length:3,ruledOutCases.length)} of ${ruledOutCases.length} cases; the disposition register retains all.</p>${(technical?ruledOutCases:ruledOutCases.slice(0,3)).map(t=>`<article><h3>${e(t.reference)} · ${e(t.name)}</h3><p>${e(t.validation?.engineering?.conclusion || t.validation?.counterEvidence)}</p>${decisionPathHtml(t.decisionPath)}</article>`).join('')}`:'';
  const summary = hasResults
    ? `${conclusionSection}${categoryCounts}<h2>Priority threats</h2><p>Only current individual source assessments or evidence-linked reviewer conclusions appear here. Category-level conclusions alone do not validate each returned scenario. Deployment conditions remain explicit.</p>${supported.length ? table(['Threat','Decision basis','Remediation'],supported.map(t=>[`${t.reference} — ${t.name}`,t.sourceConclusion ? 'Evidence-linked engineering conclusion; automated assessment: '+t.validation.assessment : 'Independent static source assessment',t.sourceConclusion?.nextAction || t.validation?.remediation?.codeFix || t.mitigation])) : '<p>No current individually supported threats. The review has produced analysis leads, not an established remediation list.</p>'}${threatDetails}${ruledOutSection}${stageCoverage}<h2>${technical?"Complete scenario disposition register":"Decided paths"}</h2><p>${technical?"Every returned scenario is retained below.":`${scenarios.length-registerScenarios.length} unresolved hypotheses are omitted from this decision report. Export the complete technical review from STRIDE for every hypothesis and analysis task.`} IDs track the original review; they are not vulnerability counts. Investigation tasks are analysis work for Synthesis, not requests for a reviewer to find source code.</p>${table(
    ['Reference / scenario','Outcome','Evidence and next action'], registerScenarios.map(t=>[
      `${t.reference} — ${t.name}`,
      `${t.outcome?.label || 'Investigation required'}${t.decision && !t.decision.stale ? '; reviewer decision: '+t.reviewState : ''}`,
      `${citations(t)}. ${t.outcome?.kind === 'investigation' ? 'Analysis task '+investigationRefs.get(t.id) : t.validation?.remediation?.codeFix || t.sourceConclusion?.nextAction || t.validation?.counterEvidence || 'See source assessment.'}`,
    ]))}
  <h2>Focused investigation work</h2><p>Follow missing code, bindings and controls in the saved graph before asking deployment questions. A missing search result is not proof that a control is absent. These tasks do not count as fully analyzed threats. Matching requests are grouped for readability; every path still requires its own assessment. A- references identify tasks in this export only. ${technical?"All tasks shown.":`Showing ${Math.min(5,investigationGroups.length)} of ${investigationGroups.length} task groups. The full technical export retains the remainder.`}</p>${table(['Analysis task','Related scenarios','Starting source'], (technical?investigationGroups:investigationGroups.slice(0,5)).map(g=>{
    return [g.reference+': '+g.action,(technical?g.scenarios:g.scenarios.slice(0,3)).map(t=>t.reference).join(', ')+(g.scenarios.length>3&&!technical?`; ${g.scenarios.length-3} more in technical export`:''),[...new Set((technical?g.scenarios:g.scenarios.slice(0,3)).map(citations))].join('; ')];
  }))}
  <h2>System context from static extraction</h2><p>Named connections below are static context, not runtime reachability or proof of complete review. Unresolved peers stay in the connection worklist instead of appearing as unknown HTTP boxes.</p><h3>Overall system DFD</h3>${printDiagrams(model,s,technical?scenarios:supported,technical)}
  <h2>STRIDE matrix</h2><p>Partially analyzed means some interfaces in the row have been reviewed. Not analyzed means none have. Source conclusions do not advance STRIDE packet coverage. Counts cover returned scenarios. Unreviewed or failed cells are not a clean assessment. ${scopedMatrix.length-shownMatrix.length} wholly unreviewed component rows are omitted here and retained in the complete technical export; they are not cleared.</p>${table(
    ["Component", ...CATEGORIES],
    shownMatrix
      .map((r) => [
        r.name,
        ...r.cells.map(
          (c) =>
            `${filter.scope !== 'all' && ['scenarios-identified','context-required','analyzed-no-scenario'].includes(c.analysisStatus) ? 'Reviewed scope' : c.analysisLabel}; ${(c.threatIds || []).filter((id) => currentScenarioIds.has(id)).length} scenarios${c.threatIds.filter(id=>questionIds.has(id)).length ? `; ${c.threatIds.filter(id=>questionIds.has(id)).length} architecture questions` : ''}${c.failedEvidence ? "; failed packets" : ""}`,
        ),
      ]),
  )}<h2>Threat actors linked to supported threats</h2><p>Showing up to 20 linked actor profiles; the complete HTML/JSON retains every actor and link. These profiles describe the access assumed by the scenarios. Awaiting reviewer confirmation means the access assumption has not been accepted; it does not mean a model request is still running.</p>${table(
    ["Actor / initial access", "Related threats", "Evidence / review"],
    s.actors
      .filter((a) => linkedActors.has(a.id)).slice(0,20)
      .map((a) => [
        `${a.name}. ${a.startingAccess || "Initial access not established"}`,
        threatRefs("actorIds", a.id),
        disposition(a),
      ]),
  )}<h2>Trust boundaries linked to supported threats</h2><p>A boundary describes a change of trust at a flow crossing, not a repository boundary. Only resolved crossings linked to supported threats are listed. Shared-interface associations alone do not prove that a boundary enforces this path; confirm relevance and enforcement. Unresolved candidates remain in the workspace.</p>${table(
    ["Boundary / transition", "Flow crossing", "Enforcement / related threats"],
    s.boundaries
      .filter((b) => linkedBoundaries.has(b.id))
      .flatMap((b) =>
        (b.crossings || []).filter(c=>c.basis !== 'unresolved' && supported.some(t=>t.flowIds?.includes(c.id))).map((c) => [
          `${b.reference}: ${b.name} (${b.dimension}). ${b.before} → ${b.after}`,
          c
            ? `${c.reference}: ${c.from} → ${c.to}`
            : "No resolved crossing established",
          `${b.enforcement || "Enforcement not established"}. ${c?.basis === 'unresolved' ? 'Candidate crossing: peer/access unresolved. ' : ''}${disposition(b)}. Threats: ${threatRefs("boundaryIds", b.id)}`,
        ]),
      ),
  )}
  ${
    contextQuestions.length && technical
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
  const guide=s.deploymentContext.guidance;
  const guidanceSection=hasResults&&guide?`<h2>Declared deployment guidance</h2><p>${e(guide.title)} · ${e(guide.mode)} · ${e(guide.document)} (${e(guide.documentVersion)}). ${e(guide.basis)}</p>${table(['Area','Intended deployment','Guide reference'],guide.statements.map(r=>[r.area,r.statement,r.reference]))}<p>${e(guide.instruction)}</p>`:'';
  const deployment = hasResults && review.reviewScope === 'system'
    ? `${guidanceSection}<h2>Deployment assumptions and review scope</h2><p>${e(s.deploymentContext.profile)} · ${e(s.deploymentContext.profileStatus)}. ${repoAssessment ? `${review.scope.interfaceIds.length} selected primary subjects are planned. Import/call records and supporting repositories remain available as navigation and evidence context. Completion and gaps are reported above.` : `${review.scope.interfaceIds.length} interfaces in system scope; ${review.scope.deferredInterfaces} deferred to deep code review. Deferred scope is not security clearance.`}</p>${table(['Area', 'Assumption or reported context', 'Basis'], s.deploymentContext.questions.map(q => [q.name, q.statement, q.state]))}<p>Responses are optional. Unconfirmed deployment context remains explicit; completed analysis does not approve actor access or trust boundaries.</p>` : '';
  // Opaque provenance and cost ledgers remain in saved/diagnostic exports. The
  // reviewer needs the scope and decision, not machine identifiers in the PDF.
  const receipt = `<h2>Review scope</h2><p>Primary repositories: ${e((poc?.repositories || review?.scope?.repositories || []).map(r=>typeof r === 'string' ? r : r.repository || r.name || 'Unnamed repository').join(', ') || 'See repository inventory below')}.</p><p>Read Priority threats for supported attack paths and required fixes. Each threat states its access conditions and the code supporting the decision. Deployment questions explain how the reviewer’s answer changes the risk. Investigations are unfinished analysis, not established vulnerabilities. Source identity and request history remain in the diagnostic exports.</p>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${e(s.title)} - threat model review</title><style>${PRINT_STYLE}.dfd-sheet{break-inside:avoid;margin:16px 0}.dfd-sheet svg{width:100%;height:auto;max-height:850px}</style></head><body>${PRINT_HEADER}<h1>${e(s.title)}</h1><p>Static threat model review · Draft</p>${snapshot}${receipt}${summary}${featureSection}${questionSection}${repoSummary}${pocSummary}${repoAssessment && technical ? `<details><summary>Category conclusions and specific evidence gaps</summary>${table(['Batch / category','Outcome','Conclusion','Evidence','Missing evidence / conditions'],(review.batches||[]).filter(b=>b.status==='completed').flatMap(b=>(b.review?.categoryReviews||[]).map(c=>[c.category,c.status,c.rationale,c.citations.map(ref=>{const source=b.evidenceContext?.records?.find(r=>r.id===ref.recordId);return source ? source.repository+' / '+source.path+':'+ref.line+'–'+ref.endLine+' ('+ref.role+')' : ref.recordId+':'+ref.line+'–'+ref.endLine;}).join('; '),[...c.missingEvidence,...c.deploymentConditions].join('; ')])))}</details>` : ''}<h2>Scope and coverage</h2><p>${s.coverage.repositories} repositories ${repoAssessment?'loaded for source and supporting context; primary review scope is listed above':'selected'}. No target execution or runtime validation. Repository collection status below is not threat analysis coverage.</p>${table(
    ["Repository", "Collection status"],
    model.sources.map((r) => [r.name, r.status]),
  )}<h2>Evidence basis · what was analyzed</h2>${table(['Area','Basis and limits'],[
    ['Code and saved graph','Selected operation definitions and bounded, hash-checked source windows; named callers and controls are followed through the saved graph. Exact citations and missing links appear in each threat. This is not a compiler-complete execution trace.'],
    ['Declared configuration','Repository configuration, environment-variable reads and defaults, installer or deployment definitions may support a conclusion when collected and cited. A setting in source is intended configuration, not proof of its effective value. Uncited configuration remains unverified.'],
    ['Deployment profile','The selected profile is an explicit assumption. Actual ingress, network reachability, service identities, permissions and overrides have not been verified.'],
    ['Runtime','Not analyzed. No target code, requests, exploit attempts or live-system probes are executed. The scanner host environment and model gateway are not evidence of the target deployment.'],
  ])}${deployment}${!technical&&detailed.length?`<section class="supporting-appendix"><h2>Appendix · full threat evidence and rationale</h2><p>Supporting detail for the decisions above. No prerequisites or evidence have been removed from this report.</p>${detailed.map(t=>`<article><h3>${e(t.reference)} · supporting evidence</h3>${threatSupportingHtml(t)}</article>`).join('')}</section>`:''}${PRINT_FOOTER}</body></html>`;
}

function printDiagrams(model, s, scenarios, technical=false) {
  const scope = technical ? model.aiReview?.scope?.interfaceIds || scenarios.flatMap(t=>t.interfaceIds || []) : [...new Set(scenarios.flatMap(t=>t.interfaceIds || []))];
  const selected = new Set(scope);
  const flows = s.flows.filter(f => f.basis !== 'unresolved' && !['rejected','stale'].includes(f.reviewState) && f.interfaceIds?.some(id=>selected.has(id)));
  if (!flows.length) return '<p>No resolved component-to-component path is available for this reviewed scope. No overview diagram is published. Use the cited source paths and resolve caller/destination bindings in Connection declarations; this does not imply that the components are disconnected.</p>';
  const seenViews=new Set();
  const focus = s.components.filter(c=>{
    const connected=flows.filter(f=>f.source===c.id || f.target===c.id);if(!connected.length)return false;
    const key=connected.map(f=>f.id).sort().join('|');
    if(!technical&&seenViews.has(key))return false;seenViews.add(key);return true;
  }).slice(0,technical?6:2);
  return `<p>${flows.length} resolved static flow records ${technical?'in the selected scope':'linked to the supported threat interfaces'}. Up to ${technical?'six':'two'} component views show at most 24 objects each; omitted relationships remain in the complete graph export. Static connections do not establish deployed reachability.</p>` + focus.map(c=>`<section class="dfd-sheet"><h3>${e(c.name)} · connected paths</h3>${systemSvg(model,{level:'focus',focus:c.id,showUnresolved:false,limit:24,interfaceIds:scope})}</section>`).join('');
}
