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
    $("model-config").textContent = s.inference
      ? `${s.inference.label} · ${s.inference.model}. Model and key are configured on this machine.`
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
  if (s.status === "running") message(s.message);
  if (["failed", "cancelled"].includes(s.status)) {
    clearInterval(polling);
    message(s.message, s.status === "failed");
  }
  if (s.status === "ready" && polling) {
    clearInterval(polling);
    polling = null;
    await refresh();
    tab("model");
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
        useModel: $("use-model").checked,
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
}
$("refresh").onclick = () => refresh().catch((e) => message(e.message, true));
function renderModel() {
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
}
$("use-model").onchange = () => {
  $("source-excerpts").disabled = !$("use-model").checked;
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
  a.download =
    format === "html"
      ? "threat-model.html"
      : format === "svg"
        ? "dfd.svg"
        : format === "manifest"
          ? "reviewed-manifest.json"
          : "model.json";
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
