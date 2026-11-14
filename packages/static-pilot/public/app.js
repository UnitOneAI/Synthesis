const $ = (id) => document.getElementById(id);
let token =
  location.hash.slice(1) || sessionStorage.getItem("synthesis-token") || "";
if (token) {
  sessionStorage.setItem("synthesis-token", token);
  history.replaceState(null, "", "/");
}
let repositories = [],
  model,
  manifestDeclarations = { bindings: [] },
  onlySelected = false,
  page = 0,
  polling,
  diagramUrl,
  inferenceInitialized = false;
let providerAvailable = false;
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const message = (text, error = false) => {
  $("message").textContent = text;
  $("message").className = error ? "error" : "";
};
async function api(route, data) {
  const response = await fetch("/api/" + route, {
    method: data === undefined ? "GET" : "POST",
    headers: { "X-Synthesis-Token": token, "Content-Type": "application/json" },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
  if (!response.ok)
    throw new Error((await response.json()).error || "Request failed");
  return response.json();
}
function tab(name) {
  document
    .querySelectorAll(".panel")
    .forEach((p) => (p.hidden = p.id !== name));
  document
    .querySelectorAll("[data-tab]")
    .forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
}
document
  .querySelectorAll("[data-tab]")
  .forEach((b) => (b.onclick = () => tab(b.dataset.tab)));
document
  .querySelectorAll("[data-go]")
  .forEach((b) => (b.onclick = () => tab(b.dataset.go)));
function renderRepos() {
  const term = $("repo-search").value.toLowerCase();
  $("counts").textContent =
    `${repositories.filter((r) => r.selected).length} selected / ${repositories.length} inventory repositories`;
  $("repositories").innerHTML = repositories
    .map((r, i) => ({ r, i }))
    .filter(
      ({ r }) =>
        (!onlySelected || r.selected) &&
        (r.name + " " + r.description).toLowerCase().includes(term),
    )
    .map(
      ({ r, i }) =>
        `<tr><td><input type="checkbox" data-i="${i}" data-field="selected" aria-label="Include ${esc(r.name)}" ${r.selected ? "checked" : ""}></td><td class="repo-name">${esc(r.name)}<span class="sub">${r.originalSelection ? "Initially selected" : "Not initially selected"} · ${esc(r.category || "Role unverified")}</span></td><td><select data-i="${i}" data-field="scope" aria-label="Scope for ${esc(r.name)}"><option value="primary" ${r.scope !== "supporting" ? "selected" : ""}>Primary</option><option value="supporting" ${r.scope === "supporting" ? "selected" : ""}>Supporting</option></select></td><td><select data-i="${i}" data-field="source" aria-label="Source for ${esc(r.name)}"><option value="local" ${r.source !== "github" ? "selected" : ""}>Local clone</option><option value="github" ${r.source === "github" ? "selected" : ""}>GitHub</option></select></td><td><input data-i="${i}" data-field="${r.source === "github" ? "url" : "localPath"}" aria-label="Location for ${esc(r.name)}" value="${esc(r.source === "github" ? r.url : r.localPath || r.name)}"></td><td><input data-i="${i}" data-field="ref" aria-label="GitHub revision for ${esc(r.name)}" value="${esc(r.ref || "")}" placeholder="Default branch" ${r.source !== "github" ? "disabled" : ""}></td></tr>`,
    )
    .join("");
}
$("repositories").onchange = (event) => {
  const el = event.target;
  if (!el.dataset.field) return;
  repositories[Number(el.dataset.i)][el.dataset.field] =
    el.type === "checkbox" ? el.checked : el.value;
  renderRepos();
};
$("repo-search").oninput = renderRepos;
$("selected-only").onclick = () => {
  onlySelected = !onlySelected;
  $("selected-only").textContent = onlySelected ? "Show all" : "Show selected";
  renderRepos();
};
$("inventory").onchange = async (event) => {
  try {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 12 * 1024 * 1024)
      throw new Error("Inventory must be under 12 MiB");
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (let i = 0; i < bytes.length; i += 8192)
      binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    const result = await api("inventory", {
      filename: file.name,
      base64: btoa(binary),
    });
    repositories = result.repositories;
    manifestDeclarations = { bindings: [] };
    renderRepos();
    message(
      `Imported ${result.counts.total} unique repositories; ${result.counts.selected} initially selected. ${result.warnings.join(" ")}`,
    );
  } catch (e) {
    message(e.message, true);
  }
  event.target.value = "";
};
$("add-form").onsubmit = (event) => {
  event.preventDefault();
  const name = $("repo-name").value.trim(),
    location = $("repo-location").value.trim();
  if (repositories.some((r) => r.name.toLowerCase() === name.toLowerCase()))
    return message(
      "This repository is already in the inventory; select its row.",
      true,
    );
  repositories.push({
    name,
    localPath: location.startsWith("https://") ? name : location,
    url: location.startsWith("https://") ? location : "",
    source: location.startsWith("https://") ? "github" : "local",
    selected: true,
    originalSelection: false,
    scope: "primary",
    description: "",
  });
  renderRepos();
  event.target.reset();
};
async function status() {
  const s = await api("status");
  $("root").textContent = s.sourceRoot;
  if (!inferenceInitialized) {
    inferenceInitialized = true;
    providerAvailable = Boolean(s.inference);
    $("model-config").textContent = s.inference
      ? `${s.inference.label} · ${s.inference.model}.${s.inference.endpoint ? ` Destination: ${s.inference.endpoint} (API ${s.inference.apiVersion}).` : ""} Model and key are configured on this machine.`
      : "Static discovery only. To enable Claude or Gemini, restart with --provider and --model and the provider key in the environment.";
    $("use-model").disabled = !s.inference;
    $("use-model").checked = Boolean(s.inference);
    $("source-excerpts").disabled = !s.inference;
    $("source-excerpts").checked = Boolean(
      s.inference && s.defaultSourceExcerpts,
    );
  }
  $("analyze").disabled = s.status === "running";
  $("cancel").hidden = s.status !== "running";
  $("cancel-review").hidden = s.status !== "running" || s.mode !== "review";
  if (s.status === "running") $("run-review").disabled = true;
  if (s.status === "running") message(s.message);
  if (["failed", "cancelled"].includes(s.status)) {
    clearInterval(polling);
    polling = null;
    message(s.message, s.status === "failed");
  }
  if (s.status === "ready" && polling) {
    clearInterval(polling);
    polling = null;
    await refresh();
    tab(model?.aiReview ? "stride" : "graph");
    message(s.message);
  }
  return s;
}
$("analyze").onclick = async () => {
  try {
    await api("analyze", {
      title: $("title").value,
      profile: $("profile").value,
      repositories,
      declarations: manifestDeclarations,
      analysis: {
        useModel: false,
        includeSourceExcerpts:
          $("use-model").checked && $("source-excerpts").checked,
      },
    });
    model = null;
    $("analyze").disabled = true;
    $("cancel").hidden = false;
    message("Starting static source analysis…");
    clearInterval(polling);
    polling = setInterval(
      () =>
        status().catch((e) => {
          clearInterval(polling);
          message(e.message, true);
        }),
      1500,
    );
  } catch (e) {
    message(e.message, true);
  }
};
$("cancel").onclick = async () => {
  try {
    await api("cancel", {});
    await status();
  } catch (e) {
    message(e.message, true);
  }
};
async function refresh() {
  model = await api("model");
  manifestDeclarations = model.declarations;
  page = 0;
  renderModel();
  const plan = await api("review-plan");
  $("review-plan").textContent =
    `${plan.repositories} repositories · ${plan.batches} planned batches (metadata estimate)`;
}
$("refresh").onclick = () => refresh().catch((e) => message(e.message, true));
function renderModel() {
  renderGraph();
  renderMatrix();
  $("run-review").disabled = !providerAvailable || !$("use-model").checked;
  $("run-review").textContent =
    model.aiReview?.coverage?.pendingBatches ||
    model.aiReview?.coverage?.failedBatches
      ? "Continue STRIDE review"
      : "Run STRIDE review";
  const coverage = model.aiReview?.coverage;
  $("review-progress").textContent =
    coverage?.totalBatches !== undefined
      ? `${coverage.completedBatches}/${coverage.totalBatches} batches completed · ${coverage.failedBatches} failed · ${coverage.pendingBatches} pending · ${coverage.reviewedInterfaces}/${coverage.totalInterfaces} interface records reviewed. ${model.aiReview.error || ""}`
      : "No graph-based model review yet. Building the source graph makes no model calls.";
  $("summary").innerHTML = [
    [model.sources.length, "Selected sources"],
    [model.interfaces.length, "Interface / control records"],
    [model.flows.length, "Declared flows"],
    [model.boundaries.length, "Declared trust transitions"],
  ]
    .map(
      ([n, s]) =>
        `<div class="stat"><strong>${n}</strong><span>${s}</span></div>`,
    )
    .join("");
  $("coverage").innerHTML =
    '<p class="hint">Draft with gaps · No whole-product coverage claim · No confirmed vulnerabilities</p>' +
    model.sources
      .map(
        (s) =>
          `<div class="card"><strong>${esc(s.name)}</strong> <span class="badge">${esc(s.scope)}</span><span class="badge unknown">${esc(s.status)}</span><p>${s.coverage ? `${s.coverage.inspected} files inspected · ${s.coverage.unsupported} unsupported · ${s.coverage.failed} failed · ${s.coverage.oversized} oversized · ${s.coverage.excluded} exclusions · ${s.coverage.truncated ? "TRUNCATED" : "within collection limits"}` : "Source unavailable; this repository has not been assessed."}</p><div class="evidence">${esc(s.revision || s.snapshot || "")}<br>${esc(s.revisionBasis || "")}</div></div>`,
      )
      .join("");
  renderAIReview();
  renderInterfaces();
  $("threats").innerHTML =
    `<p>${model.threats.length} conditional scenarios. Showing the first 50; all scenarios are included in exports.</p>` +
    model.threats
      .slice(0, 50)
      .map(
        (t) =>
          `<div class="card"><h3>${esc(t.category)}</h3><p>${esc(t.scenario)}</p><p><strong>Starting assumptions:</strong> ${esc(t.prerequisites.join("; "))}</p><p><strong>Review:</strong> ${esc(t.mitigation)}</p><span class="badge unknown">Severity unassessed</span><span class="sub">${esc(t.id)}</span></div>`,
      )
      .join("");
  $("diagnostics").innerHTML =
    `<p>${model.diagnostics.length} diagnostics. First 100 shown; full ledger in JSON.</p>` +
    model.diagnostics
      .slice(0, 100)
      .map(
        (d) =>
          `<div class="card"><strong>${esc(d.repository)} / ${esc(d.path)}</strong><p>${esc(d.kind)}: ${esc(d.message)}</p></div>`,
      )
      .join("");
  const options =
    '<option value="">Choose an interface</option>' +
    model.interfaces
      .filter((i) => i.direction !== "control")
      .map(
        (i) =>
          `<option value="${esc(i.id)}">${esc(i.repository + " · " + i.operation + " · " + i.id.slice(0, 6))}</option>`,
      )
      .join("");
  $("from").innerHTML = options;
  $("to").innerHTML = options;
  $("bindings").innerHTML = model.flows
    .map(
      (f, n) =>
        `<div class="card"><strong>${esc(f.operation)}</strong><p>${esc(f.reason)} · ${esc(f.reviewer)}</p><button class="secondary" data-remove="${n}">Remove declaration</button></div>`,
    )
    .join("");
  updateDiagram().catch((e) => message(e.message, true));
  fetch("/api/export?format=mermaid", {
    headers: { "X-Synthesis-Token": token },
  })
    .then((r) => (r.ok ? r.text() : "DFD unavailable"))
    .then((text) => {
      $("mermaid-preview").textContent = text;
    })
    .catch(() => {});
}
$("use-model").onchange = () => {
  $("source-excerpts").disabled = !$("use-model").checked;
  $("run-review").disabled =
    !providerAvailable || !model || !$("use-model").checked;
};
function renderGraph() {
  const graph = model?.sourceGraph;
  if (!graph) return;
  $("graph-summary").innerHTML = [
    [
      graph.nodes.filter((n) => n.kind === "function").length,
      "Functions and methods",
    ],
    [graph.nodes.filter((n) => n.kind === "call").length, "Call sites"],
    [
      graph.edges.filter((e) => e.kind === "project-reference").length,
      "Project references",
    ],
    [
      graph.coverage.failed +
        graph.coverage.syntaxErrors +
        graph.coverage.limited,
      "Files with graph gaps",
    ],
  ]
    .map(
      ([n, label]) =>
        `<div class="stat"><strong>${n}</strong><span>${esc(label)}</span></div>`,
    )
    .join("");
  $("graph-coverage").innerHTML =
    `<p>${graph.coverage.parsed} files parsed · ${graph.coverage.syntaxErrors} with syntax errors · ${graph.coverage.failed} failed or timed out · ${graph.coverage.unsupported} without a language parser · ${graph.coverage.limited} limited.</p><p class="hint">Syntax evidence does not resolve dependency injection, overloads, dynamic dispatch or deployed trust. Source collection limits still apply. Full file coverage is in the JSON export.</p>`;
  const term = $("graph-search").value.toLowerCase();
  const nodes = graph.nodes.filter(
    (n) =>
      n.kind === $("graph-kind").value &&
      `${n.name} ${n.repository} ${n.path}`.toLowerCase().includes(term),
  );
  $("graph-nodes").innerHTML =
    `<p>${nodes.length} matching nodes · first 100 shown</p><table><thead><tr><th>Symbol or reference</th><th>Repository</th><th>Evidence</th><th>Interpretation</th></tr></thead><tbody>${nodes
      .slice(0, 100)
      .map(
        (n) =>
          `<tr><td>${esc(n.name)}</td><td>${esc(n.repository)}</td><td>${esc(n.path)}:${n.line}</td><td>${esc(n.basis || "Syntax declaration")}</td></tr>`,
      )
      .join("")}</tbody></table>`;
}
$("graph-kind").onchange = renderGraph;
$("graph-search").oninput = renderGraph;
function renderMatrix() {
  const rows = model?.strideMatrix || [];
  const selected = $("matrix-repository").value;
  $("matrix-repository").innerHTML =
    '<option value="">All repositories</option>' +
    [...new Set(rows.map((r) => r.repository))]
      .map((r) => `<option value="${esc(r)}">${esc(r)}</option>`)
      .join("");
  $("matrix-repository").value = selected;
  const filtered = rows.filter(
    (r) =>
      r.rowKind === $("matrix-kind").value &&
      (!selected || r.repository === selected),
  );
  const categories = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information disclosure",
    "Denial of service",
    "Elevation of privilege",
  ];
  $("stride-matrix").innerHTML =
    `<table class="stride-table"><thead><tr><th>Component / flow</th>${categories.map((c, i) => `<th><span class="stride-letter">${"STRIDE"[i]}</span>${c}</th>`).join("")}<th>Model coverage</th></tr></thead><tbody>${filtered
      .slice(0, 100)
      .map(
        (r) =>
          `<tr><th scope="row">${esc(r.name)}<span class="sub">${esc(r.repository)}</span></th>${r.cells.map((c, i) => `<td><button class="matrix-cell ${c.count ? "has-threats" : ""}" data-matrix-row="${esc(r.id)}" data-category="${i}" aria-label="${esc(r.name + ", " + c.category + ", " + c.status)}"><strong>${c.status === "stale" ? "Stale" : c.count ? `● ${c.count}` : c.status === "not-reviewed" ? "—" : "?"}</strong><span>${c.count ? "AI scenarios" : c.status === "partially-reviewed" ? "Partial review" : c.status === "not-reviewed" ? "Not reviewed" : c.status === "stale" ? "Rerun review" : "No scenario"}</span>${c.promptCount ? `<small>○ ${c.promptCount} rule prompts</small>` : ""}</button></td>`).join("")}<td>${r.reviewed} / ${r.interfaces}<span class="sub">interface records</span></td></tr>`,
      )
      .join(
        "",
      )}</tbody></table><p class="hint">${filtered.length} rows · first 100 shown · all rows included in export.</p>`;
}
$("matrix-repository").onchange = renderMatrix;
$("matrix-kind").onchange = renderMatrix;
$("stride-matrix").onclick = (event) => {
  const button = event.target.closest("[data-matrix-row]");
  if (!button) return;
  const row = model.strideMatrix.find((r) => r.id === button.dataset.matrixRow),
    cell = row.cells[Number(button.dataset.category)];
  const items = [
    ...(model.aiReview?.threats || [])
      .filter((t) => cell.threatIds.includes(t.id))
      .map((t) => ({
        ...t,
        source: "AI scenario · Needs review",
        evidence: t.evidenceIds,
      })),
    ...model.threats
      .filter((t) => cell.promptIds.includes(t.id))
      .map((t) => ({
        ...t,
        title: "Conditional rule prompt",
        source: "Rule prompt · Not an AI finding",
      })),
  ];
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  $("stride-detail").innerHTML =
    `<h3>${esc(row.name)} · ${esc(cell.category)}</h3><p>${cell.count} AI scenarios · ${cell.promptCount} rule prompts · ${esc(cell.status.replaceAll("-", " "))}</p>${
      items.length
        ? items
            .slice(0, 20)
            .map(
              (t) =>
                `<article class="card"><span class="badge unknown">${esc(t.source)}</span><h3>${esc(t.title)}</h3><p>${esc(t.scenario)}</p><p><strong>Actor:</strong> ${esc(model.actors.find((a) => a.id === t.actor)?.name || t.actor)}</p><p><strong>Prerequisites:</strong> ${esc(Array.isArray(t.prerequisites) ? t.prerequisites.join("; ") : t.prerequisites)}</p><p><strong>Controls:</strong> ${esc(t.controls)}</p><p><strong>Next review:</strong> ${esc(t.mitigation)}</p><div class="evidence">${t.evidence
                  .map((k) => {
                    const e = evidence.get(k);
                    return e
                      ? `${esc(e.repository)}/${esc(e.path)}:${e.line} · ${esc(e.basis)}`
                      : esc(k);
                  })
                  .join("<br>")}</div></article>`,
            )
            .join("")
        : "<p>No scenario is available for this cell. This does not establish safety or non-applicability.</p>"
    }`;
};
$("run-review").onclick = async () => {
  try {
    await api("review", {
      modelRevision: model.modelRevision,
      maxBatches: Number($("review-budget").value),
      includeSourceExcerpts: $("source-excerpts").checked,
    });
    $("run-review").disabled = true;
    $("cancel-review").hidden = false;
    clearInterval(polling);
    polling = setInterval(
      () =>
        status().catch((e) => {
          clearInterval(polling);
          message(e.message, true);
        }),
      1500,
    );
    message("Reviewing the existing graph and DFD. No source rescan.");
  } catch (e) {
    message(e.message, true);
  }
};
$("cancel-review").onclick = async () => {
  await api("cancel", {});
  await status();
  $("cancel-review").hidden = true;
};
function renderAIReview() {
  const a = model.aiReview;
  if (!a) {
    $("ai-review").textContent =
      "No model requested. Conditional scenarios below are rule-based review prompts.";
    return;
  }
  const refs = (ids) =>
    ids
      .map((id) => {
        const e = model.evidence.find((e) => e.id === id);
        return e ? `${e.repository}/${e.path}:${e.line} [${id}]` : id;
      })
      .join("; ");
  const label = (id) => {
    const i = model.interfaces.find((i) => i.id === id);
    return i ? `${i.repository} · ${i.operation} [${id}]` : id;
  };
  $("ai-review").innerHTML =
    `<div class="card"><strong>${esc(a.label)} · ${esc(a.model)} · ${esc(a.status)}</strong><p>${a.coverage.submittedInterfaces} of ${a.coverage.totalInterfaces} records submitted; ${a.coverage.omittedInterfaces} omitted. Mode: ${esc(a.mode)}; ${a.coverage.excerptCount} excerpts. Submission does not imply complete analysis.</p><p>${esc(a.error || a.summary || "")}</p><p class="hint">Model inferences are conditional and unverified. Severity remains unassessed. Suggestions do not alter the DFD. ${a.status === "stale" ? "These suggestions are stale; rerun analysis before using them." : ""}</p></div>` +
    (a.threats || [])
      .map(
        (t) =>
          `<div class="card"><h3>${esc(t.title)}</h3><span class="badge unknown">Model-inferred · Needs review · ${esc(t.category)}</span><p>${esc(t.scenario)}</p><p><strong>Actor / starting access:</strong> ${esc(t.actor)} / ${esc(t.startingAccess)}</p><p><strong>Asset:</strong> ${esc(t.asset)}</p><p><strong>Prerequisites:</strong> ${esc(t.prerequisites)}</p><p><strong>Controls:</strong> ${esc(t.controls)}</p><p><strong>Review and mitigation:</strong> ${esc(t.mitigation)}</p><p class="evidence">${esc(refs(t.evidenceIds))}</p></div>`,
      )
      .join("") +
    (a.connections || [])
      .map(
        (c) =>
          `<div class="card"><h3>Proposed connection · Not in DFD</h3><p>${esc(label(c.from))} → ${esc(label(c.to))}</p><p>${esc(c.reason)}</p>${c.transition ? `<p><strong>Possible ${esc(c.transition.dimension)} transition:</strong> ${esc(c.transition.before)} → ${esc(c.transition.after)}. ${esc(c.transition.reason)}</p>` : "<p>Trust transition not established.</p>"}<p class="evidence">${esc(refs(c.evidenceIds))}</p><p>Inspect the cited source, then use Connect and export to declare a justified connection.</p></div>`,
      )
      .join("") +
    (a.questions || [])
      .map((q) => `<p class="hint">Review question: ${esc(q)}</p>`)
      .join("");
}
function renderInterfaces() {
  if (!model) return;
  const term = $("interface-search").value.toLowerCase(),
    items = model.interfaces.filter((i) =>
      JSON.stringify(i).toLowerCase().includes(term),
    );
  page = Math.max(0, Math.min(page, Math.ceil(items.length / 25) - 1));
  $("interfaces").innerHTML =
    items
      .slice(page * 25, page * 25 + 25)
      .map(
        (i) =>
          `<div class="card"><h3>${esc(i.operation)}</h3><span class="badge">${esc(i.repository)}</span><span class="badge">${esc(i.protocol)} · ${esc(i.direction)}</span><span class="badge unknown">${esc(i.resolution)}</span><p>${esc(i.basis)}</p><div class="evidence">${i.evidence
            .map((k) => {
              const e = model.evidence.find((e) => e.id === k);
              return e
                ? `${esc(e.repository)}/${esc(e.path)}:${e.line} ${esc(e.pointer || "")}<br>SHA-256 ${esc(e.blobSha256)}`
                : esc(k);
            })
            .join(
              "<br>",
            )}</div><span class="sub">Interface ${esc(i.id)} · Effective identity and exposure: unknown</span></div>`,
      )
      .join("") ||
    "<p>No matching interface records. This is not evidence of absence.</p>";
  $("page-count").textContent =
    `${items.length ? page + 1 : 0} / ${Math.ceil(items.length / 25)} · ${items.length} records`;
  $("prev").disabled = page === 0;
  $("next").disabled = (page + 1) * 25 >= items.length;
}
$("interface-search").oninput = () => {
  page = 0;
  renderInterfaces();
};
$("prev").onclick = () => {
  page--;
  renderInterfaces();
};
$("next").onclick = () => {
  page++;
  renderInterfaces();
};
async function saveBindings(bindings) {
  model = await api("bindings", {
    modelRevision: model.modelRevision,
    bindings,
  });
  manifestDeclarations = model.declarations;
  renderModel();
  message(
    "Connection declarations saved for this model revision. Export the manifest to retain them.",
  );
}
$("binding-form").onsubmit = async (event) => {
  event.preventDefault();
  try {
    if (!model) throw new Error("Analyze sources first");
    const b = { profile: model.profile };
    for (const key of [
      "from",
      "to",
      "reason",
      "reviewer",
      "data",
      "controls",
      "dimension",
      "before",
      "after",
    ])
      b[key] = $(key).value;
    await saveBindings([...(model.declarations.bindings || []), b]);
  } catch (e) {
    message(e.message, true);
  }
};
$("bindings").onclick = async (event) => {
  if (event.target.dataset.remove === undefined) return;
  try {
    await saveBindings(
      model.declarations.bindings.filter(
        (_, i) => i !== Number(event.target.dataset.remove),
      ),
    );
  } catch (e) {
    message(e.message, true);
  }
};
async function download(format, preview = false) {
  const r = await fetch("/api/export?format=" + format, {
    headers: { "X-Synthesis-Token": token },
  });
  if (!r.ok) throw new Error((await r.json()).error);
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  if (preview) return url;
  const a = document.createElement("a");
  a.href = url;
  a.download = {
    html: "threat-model.html",
    svg: "dfd.svg",
    manifest: "reviewed-manifest.json",
    mermaid: "dfd.mmd",
    graph: "source-graph.json",
    "graph-mermaid": "source-graph.mmd",
    stride: "stride-matrix.csv",
    json: "model.json",
  }[format];
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function updateDiagram() {
  if (diagramUrl) URL.revokeObjectURL(diagramUrl);
  diagramUrl = await download("svg", true);
  $("diagram").replaceChildren(
    Object.assign(document.createElement("img"), {
      src: diagramUrl,
      alt: "Declared flows and unresolved interface review sheets",
    }),
  );
}
document
  .querySelectorAll("[data-export]")
  .forEach(
    (b) =>
      (b.onclick = () =>
        download(b.dataset.export).catch((e) => message(e.message, true))),
  );
$("manifest-file").onchange = async (event) => {
  try {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 12 * 1024 * 1024) throw new Error("Manifest too large");
    const m = JSON.parse(await file.text());
    if (!Array.isArray(m.repositories))
      throw new Error("Manifest needs repositories");
    repositories = m.repositories.map((r) => ({
      ...r,
      selected: r.selected !== false,
    }));
    $("title").value = m.title || "Static system threat model";
    $("profile").value = m.profile || "";
    manifestDeclarations = m.declarations || { bindings: [] };
    renderRepos();
    tab("sources");
    message(
      "Manifest loaded. Reanalyze its sources; changed interface IDs require renewed declarations.",
    );
  } catch (e) {
    message(e.message, true);
  }
  event.target.value = "";
};
status()
  .then(async (s) => {
    const m = await api("manifest");
    if (m) {
      repositories = m.repositories.map((r) => ({
        ...r,
        selected: r.selected !== false,
      }));
      $("title").value = m.title || "Static system threat model";
      $("profile").value = m.profile || "";
      manifestDeclarations = m.declarations || { bindings: [] };
      renderRepos();
    }
    if (s.status === "ready") await refresh();
    if (s.status === "running")
      polling = setInterval(
        () => status().catch((e) => message(e.message, true)),
        1500,
      );
  })
  .catch((e) => message(e.message, true));
