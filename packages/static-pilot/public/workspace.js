/* Local static threat-model workspace. All source and reviewer text is escaped. */
(() => {
  const e = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  let model,
    api,
    download,
    notify,
    update,
    s,
    startReview,
    stopReview,
    providerAvailable = false,
    jobState = { status: "idle" },
    requestBudget = 12,
    threatIndex = new Map(),
    selected = "",
    view = "system",
    level = "system",
    lens = "identity",
    focus = "",
    actor = "",
    query = "",
    threatType = "all",
    categoryFilter = "",
    dispositionFilter = "",
    page = 0,
    diagramSequence = 0;
  const root = document.getElementById("workspace");
  const kinds = [
    "components",
    "entities",
    "assets",
    "securityControls",
    "flows",
    "domains",
    "boundaries",
    "actors",
    "threats",
  ];
  const titles = {
    components: "Components",
    entities: "External entities",
    assets: "Data assets",
    securityControls: "Control register",
    flows: "Data flows",
    domains: "Trust domains",
    boundaries: "Trust boundaries",
    actors: "Threat actors",
    threats: "Threat register",
  };
  const fields = {
    components: {
      name: "Name",
      type: ["source-group", "process", "store", "broker", "gateway"],
      description: "Description",
      repositories: "@repositories",
      interfaceIds: "@interfaces",
      evidenceIds: "@evidence",
    },
    entities: {
      name: "Name",
      type: ["external", "unknown"],
      description: "Description",
      interfaceIds: "@interfaces",
      evidenceIds: "@evidence",
    },
    assets: {
      name: "Name",
      description: "Sensitivity and business impact",
      evidenceIds: "@evidence",
    },
    securityControls: {
      name: "Name",
      description: "Control purpose and limitations",
      interfaceIds: "@interfaces",
      flowIds: "@flows",
      evidenceIds: "@evidence",
      counterEvidenceIds: "@evidence",
    },
    flows: {
      name: "Operation",
      source: "@node",
      target: "@node",
      protocol: "Protocol",
      callerIdentity: "Caller identity",
      calleeIdentity: "Callee identity",
      credentialType: "Credential type",
      authorization: "Authorization decision",
      assumptions: "Assumptions",
      controlIds: "@securityControls",
      data: "Data transferred",
      controls: "Controls and enforcement",
      interfaceIds: "@interfaces",
      assetIds: "@assets",
      evidenceIds: "@evidence",
    },
    domains: {
      name: "Name",
      dimension: [
        "identity",
        "privilege",
        "network",
        "execution",
        "data-ownership",
        "third-party",
      ],
      description: "Trust assumptions",
      memberIds: "@nodes",
      parentId: "@domain",
      evidenceIds: "@evidence",
    },
    boundaries: {
      name: "Name",
      dimension: [
        "identity",
        "privilege",
        "network",
        "execution",
        "data-ownership",
        "third-party",
      ],
      sourceDomainId: "@domain",
      targetDomainId: "@domain",
      before: "Authority before crossing",
      after: "Authority after crossing",
      enforcement: "Enforcement location and limitations",
      flowIds: "@flows",
      evidenceIds: "@evidence",
    },
    actors: {
      name: "Actor profile",
      startingAccess: "Initial access assumption",
      objectives: "Objectives and targeted assets",
      excludedCapabilities: "Excluded capabilities",
      entryIds: "@nodes",
      evidenceIds: "@evidence",
    },
    threats: {
      name: "Threat title",
      scenario: "Threat statement",
      categories: "@categories",
      actorIds: "@actors",
      interfaceIds: "@interfaces",
      flowIds: "@flows",
      boundaryIds: "@boundaries",
      asset: "Targeted asset and impact",
      prerequisites: "Prerequisites",
      controls: "Existing controls and counterevidence",
      mitigation: "Mitigation",
      assumptions: "Assumptions",
      counterEvidenceIds: "@evidence",
      controlIds: "@securityControls",
      evidenceIds: "@evidence",
    },
  };
  const refLabels = {
    type: "Object type",
    dimension: "Trust dimension",
    controlIds: "Linked controls",
    counterEvidenceIds: "Counterevidence",
    sourceDomainId: "Source trust domain",
    targetDomainId: "Destination trust domain",
    repositories: "Source repositories",
    interfaceIds: "Interfaces",
    evidenceIds: "Supporting evidence",
    source: "From component or entity",
    target: "To component or entity",
    memberIds: "Domain members",
    parentId: "Parent trust domain",
    entryIds: "Entry points",
    flowIds: "Affected flows",
    actorIds: "Threat actors",
    boundaryIds: "Trust boundaries",
    assetIds: "Data assets",
    categories: "STRIDE categories",
  };
  function all() {
    return kinds.flatMap((k) => s[k].map((r) => ({ ...r, kind: k })));
  }
  function find(id) {
    return (
      all().find((r) => r.id === id) ||
      s.matrix
        .flatMap((r) =>
          r.cells.map((c) => ({
            ...c,
            name: r.name + " · " + c.category,
            kind: "cell",
          })),
        )
        .find((c) => c.id === id)
    );
  }
  function refs(ids) {
    return (ids || []).map((id) => {
      const v = model.evidence.find((v) => v.id === id);
      return v ? `${v.repository}/${v.path}:${v.line} · ${v.basis}` : id;
    });
  }
  function names(ids) {
    return (ids || []).map((id) => find(id)?.name || id).join("; ");
  }
  const option = (id, label, chosen) =>
    `<option value="${e(id)}" ${chosen ? "selected" : ""}>${e(label)}</option>`;
  function render() {
    if (!model) {
      root.innerHTML =
        "<h2>System model</h2><p>Build the source graph to review the system architecture.</p>";
      return;
    }
    root.innerHTML = `<div class="section-title"><div><p class="eyebrow">SYSTEM THREAT MODEL</p><h2>${e(s.title)}</h2><p>${e(s.profile)} · ${s.coverage.repositories} selected repositories · Static analysis</p></div><button id="ws-export">Export review package</button></div><div class="ws-status"><span>Draft</span><span>${s.flows.length} flows / candidates</span><span>${s.coverage.unresolvedFlows} unresolved relationships</span><span>${s.coverage.pendingBoundaries} boundary decisions pending</span>${s.coverage.unavailable.length ? `<strong>Unavailable: ${e(s.coverage.unavailable.join(", "))}</strong>` : ""}</div><nav class="ws-tabs" aria-label="System model views">${[
      ["system", "System DFD"],
      ["actors", "Threat actors"],
      ["boundaries", "Trust boundaries"],
      ["matrix", "STRIDE matrix"],
      ["threats", "Threat register"],
      ["components", "Components"],
      ["domains", "Trust domains"],
      ["entities", "External entities"],
      ["assets", "Data assets"],
      ["securityControls", "Controls"],
      ["flows", "Flow register"],
    ]
      .map(
        ([key, label]) =>
          `<button data-view="${key}" class="${key === view ? "active" : ""}" aria-pressed="${key === view}">${label}</button>`,
      )
      .join(
        "",
      )}</nav><div id="ws-export-panel" hidden></div><div id="ws-editor" hidden></div><div class="ws-layout"><div class="ws-main"><div id="ws-body"></div></div><aside class="ws-inspector" id="ws-inspector" aria-live="polite"></aside></div>`;
    renderBody();
    renderInspector();
  }
  function renderBody() {
    const body = root.querySelector("#ws-body");
    if (view === "system") {
      const nodes = [...s.components, ...s.entities];
      body.innerHTML = `<div class="toolbar"><label>View<select aria-label="View" id="ws-level">${[
        ["context", "Context"],
        ["system", "Overall system"],
        ["focus", "Component detail"],
      ]
        .map(([k, n]) => option(k, n, k === level))
        .join(
          "",
        )}</select></label><label>Trust lens<select aria-label="Trust lens" id="ws-lens">${["identity", "privilege", "network", "execution", "data-ownership", "third-party"].map((k) => option(k, k, k === lens)).join("")}</select></label><label>Component focus<select aria-label="Component focus" id="ws-focus"><option value="">Choose a component</option>${nodes.map((n) => option(n.id, n.name, n.id === focus)).join("")}</select></label><label>Actor path<select aria-label="Actor path" id="ws-actor"><option value="">No actor overlay</option>${s.actors.map((a) => option(a.id, a.name, a.id === actor)).join("")}</select></label></div><p class="hint">${actor ? "Conditional path under the selected access assumptions. Connectivity does not establish exploitability." : "Select a component, flow or domain to inspect its evidence."} Trust zones appear only after a domain declaration. Repository boundaries do not imply trust boundaries.</p><div id="ws-canvas" class="ws-canvas"><p>Loading system diagram…</p></div><div class="toolbar"><button data-new="flows">Declare flow</button><button data-new="boundaries">Add trust boundary</button><button data-new="domains">Add trust domain</button><button data-new="actors">Add actor profile</button></div><p class="hint">The overview shows up to 80 objects. Use component focus and the full registers for larger models; nothing is removed from the export.</p>`;
      loadDiagram();
      return;
    }
    if (view === "matrix") {
      const review = model.aiReview,
        c = review?.coverage;
      body.innerHTML = `<div class="ws-analysis"><div><strong>${c ? `${c.completedBatches || 0} / ${c.totalBatches || 0} batches completed · ${c.failedBatches || 0} failed · ${c.pendingBatches || 0} pending` : "Analysis has not run"}</strong><p>${e(review?.error || "Review the selected source evidence and declared interactions. Completed requests do not establish semantic completeness.")}</p>${!providerAvailable ? "<p>Start Synthesis with a configured provider and key to enable analysis. Connection details are shown in Sources.</p>" : ""}</div><div class="toolbar"><label>Request budget<input id="ws-request-budget" type="number" min="1" max="100" value="${requestBudget}"></label><button data-start-review ${!providerAvailable || jobState.status === "running" ? "disabled" : ""}>Run or continue STRIDE analysis</button><button data-stop-review ${jobState.status === "running" && jobState.mode === "review" ? "" : "hidden"}>Stop review</button></div></div><div class="toolbar"><label>Rows<select aria-label="Rows" id="ws-row-kind">${["boundary", "flow", "component"].map((k) => option(k, k, k === (window.wsRowKind || "boundary"))).join("")}</select></label><label>Actor<select aria-label="Actor" id="ws-matrix-actor"><option value="">All actors</option>${s.actors.map((a) => option(a.id, a.name, a.id === actor)).join("")}</select></label></div><p class="hint">Scenario counts and checklist items are separate. Empty results require a review decision. Actor filtering does not change full-model coverage.</p><div class="table-wrap"><table class="ws-matrix"><thead><tr><th>Review subject</th>${["Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service", "Elevation of privilege"].map((c, i) => `<th><b>${"STRIDE"[i]}</b><small>${c}</small></th>`).join("")}</tr></thead><tbody>${s.matrix
        .filter((r) => r.rowKind === (window.wsRowKind || "boundary"))
        .map(
          (r) =>
            `<tr><th>${e(r.name)}</th>${r.cells
              .map((c) => {
                const ts = c.threatIds
                  .map((id) => threatIndex.get(id))
                  .filter((t) => t && (!actor || t.actorIds.includes(actor)));
                const scenarios = ts.filter(
                    (t) => t.origin !== "review checklist",
                  ).length,
                  checklist = ts.length - scenarios;
                return `<td><button data-select="${e(c.id)}" class="${ts.length ? "populated" : ""}"><b>${scenarios || "—"}</b>${checklist ? `<small>${checklist} checklist items</small>` : ""}<small>${e(c.state.replaceAll("-", " "))}</small></button></td>`;
              })
              .join("")}</tr>`,
        )
        .join(
          "",
        )}</tbody></table></div>${!s.matrix.some((r) => r.rowKind === (window.wsRowKind || "boundary")) ? "<p>No subjects of this type. Declare supported boundaries or select component / flow rows.</p>" : ""}`;
      return;
    }
    let rows = s[view] || [];
    const filtered = rows.filter(
      (r) =>
        JSON.stringify(r).toLowerCase().includes(query.toLowerCase()) &&
        (!dispositionFilter || r.reviewState === dispositionFilter) &&
        (view !== "threats" ||
          ((threatType === "all" ||
            (threatType === "checklist") ===
              (r.origin === "review checklist")) &&
            (!categoryFilter || r.categories.includes(categoryFilter)))),
    );
    page = Math.max(0, Math.min(page, Math.ceil(filtered.length / 50) - 1));
    body.innerHTML = `<div class="toolbar"><h3>${titles[view]}</h3><input id="ws-search" type="search" aria-label="Search register" placeholder="Search names, access, evidence…" value="${e(query)}"><button data-new="${view}">Add ${view === "actors" ? "actor profile" : view === "boundaries" ? "trust boundary" : view === "threats" ? "threat scenario" : "record"}</button></div><div class="toolbar"><label>Disposition<select id="ws-disposition" aria-label="Register disposition">${[["", "All dispositions"], ...[...new Set(rows.map((r) => r.reviewState))].map((v) => [v, v.replaceAll("-", " ")])].map(([k, l]) => option(k, l, k === dispositionFilter)).join("")}</select></label>${
      view === "threats"
        ? `<label>Record type<select id="ws-threat-type" aria-label="Threat record type">${[
            ["all", "All records"],
            ["scenarios", "Threat scenarios"],
            ["checklist", "Review checklist"],
          ]
            .map(([k, l]) => option(k, l, k === threatType))
            .join(
              "",
            )}</select></label><label>Category<select id="ws-category" aria-label="STRIDE category"><option value="">All categories</option>${choices(
            "categories",
          )
            .map(([k, l]) => option(k, l, k === categoryFilter))
            .join("")}</select></label>`
        : ""
    }</div><p>${filtered.length} of ${rows.length} records · page ${page + 1} of ${Math.max(1, Math.ceil(filtered.length / 50))}</p><div class="ws-records">${
      filtered
        .slice(page * 50, page * 50 + 50)
        .map(
          (r) =>
            `<button class="ws-record" data-select="${e(r.id)}" aria-pressed="${selected === r.id}"><strong>${e(r.name)}</strong><span>${e(r.startingAccess || (r.before && `${r.dimension}: ${r.before} → ${r.after}`) || r.scenario || r.description || r.type || "")}</span><small>${r.origin ? e(r.origin === "review checklist" ? "Review checklist" : "Threat scenario") + " · " : ""}${e(r.basis)} · ${e(r.reviewState)}${r.decision?.owner ? " · Owner: " + e(r.decision.owner) : ""}</small></button>`,
        )
        .join("") ||
      "<p>No records. Add an evidence-supported declaration or an explicit assumption.</p>"
    }</div><div class="toolbar"><button id="ws-prev" ${page === 0 ? "disabled" : ""}>Previous</button><button id="ws-next" ${(page + 1) * 50 >= filtered.length ? "disabled" : ""}>Next</button></div>`;
  }
  async function loadDiagram() {
    const seq = ++diagramSequence;
    try {
      const q = new URLSearchParams({
        level,
        lens,
        focus,
        actor,
        threat: selected,
      });
      const response = await fetch("/api/system-diagram?" + q, {
        headers: { "X-Synthesis-Token": window.synthesisAccessToken },
      });
      if (!response.ok) throw Error((await response.json()).error);
      const svg = await response.text();
      if (
        seq === diagramSequence &&
        view === "system" &&
        root.querySelector("#ws-canvas")
      )
        root.querySelector("#ws-canvas").innerHTML = svg;
    } catch (error) {
      notify(error.message, true);
    }
  }
  function renderInspector() {
    const out = root.querySelector("#ws-inspector"),
      r = find(selected);
    if (!r) {
      out.innerHTML =
        "<h3>Review context</h3><p>Select a diagram object or register entry to inspect its access assumptions, controls and evidence.</p><p>Legitimate external entities and threat-actor profiles are separate records.</p>";
      return;
    }
    const visibleThreatIds = (r.threatIds || []).filter(
      (id) => !actor || threatIndex.get(id)?.actorIds.includes(actor),
    );
    const linked = visibleThreatIds.map((id) => threatIndex.get(id)).filter(Boolean);
    const scenarios = linked.filter((t) => t.origin !== "review checklist");
    const checklist = linked.filter((t) => t.origin === "review checklist");
    const linkedButton = (t) => `<button class="ws-linked-record" data-select="${e(t.id)}"><strong>${e(t.name)}</strong><small>${e((refs(t.evidenceIds)[0] || t.id).split(" · ")[0])}</small></button>`;
    const linkedSection = r.kind === "cell"
      ? `<section><h4>Linked scenarios (${scenarios.length})</h4>${scenarios.map(linkedButton).join("") || "<p>No scenario identified. Record a conclusion and rationale after review.</p>"}${checklist.length ? `<details class="ws-checklist"><summary>Review checklist (${checklist.length} items)</summary>${checklist.map(linkedButton).join("")}</details>` : ""}</section>`
      : "";
    const field = (title, v) =>
      v ? `<section><h4>${e(title)}</h4><p>${e(v)}</p></section>` : "";
    out.innerHTML = `<p class="eyebrow">${e(titles[r.kind] || "STRIDE review")}</p><h3>${e(r.name)}</h3><span class="badge">${e(r.basis || r.state)} · ${e(r.reviewState || "review required")}</span>${field("Threat statement", r.scenario)}${field("Initial access", r.startingAccess)}${field("Objectives / impact", r.objectives || r.asset)}${field("Excluded capabilities", r.excludedCapabilities)}${field("Prerequisites", r.prerequisites)}${field("Trust transition", r.before ? `${r.dimension}: ${r.before} → ${r.after}` : "")}${field("Controls and enforcement", r.enforcement || r.controls)}${field("Description", r.description)}${field("Source repositories", (r.repositories || []).join(", "))}${field("Threat actors", names(r.actorIds))}${field("Entry points", names(r.entryIds))}${field("Flows", names(r.flowIds))}${field("Trust boundaries", names(r.boundaryIds))}${field("Data", r.data)}${field("Mitigation", r.mitigation)}${field("Caller identity", r.callerIdentity)}${field("Callee identity", r.calleeIdentity)}${field("Credential type", r.credentialType)}${field("Authorization decision", r.authorization)}${field("Assumptions", r.assumptions)}${field("Linked controls", names(r.controlIds))}${field("Counterevidence", refs(r.counterEvidenceIds).join("; "))}${field("References requiring repair", (r.missingReferences || []).join(", "))}${linkedSection}<section><h4>Supporting evidence</h4>${
      refs(r.evidenceIds)
        .map((v) => `<p class="evidence">${e(v)}</p>`)
        .join("") ||
      "<p>No source evidence attached; this claim requires review.</p>"
    }</section>${r.decision ? field("Review decision", `${r.decision.state}${r.decision.stale ? " (stale)" : ""} · ${r.decision.reviewer}: ${r.decision.rationale}`) : ""}<div class="toolbar"><button data-trace="${e(r.id)}">Show on DFD</button>${r.kind !== "cell" ? `<button data-edit="${e(r.id)}">Edit record</button><button data-delete="${e(r.id)}">Remove record</button>` : ""}</div><details><summary>Record review decision</summary><form id="ws-decision"><label>Disposition<select aria-label="Disposition" name="state">${["needs-investigation", "accepted", "rejected", "mitigation-planned", "implemented-in-source", "risk-accepted", "not-applicable", ...(r.kind === "cell" ? ["reviewed-no-scenario"] : [])].map((k) => option(k, k.replaceAll("-", " "), false)).join("")}</select></label><label>Reviewer<input name="reviewer" required maxlength="200"></label><label>Rationale<textarea name="rationale" required maxlength="2000"></textarea></label><label>Mitigation owner<input name="owner" maxlength="200"></label><label>Severity assessment<select aria-label="Severity assessment" name="severity">${["unassessed", "low", "medium", "high", "critical"].map((k) => option(k, k, false)).join("")}</select></label><button type="submit">Save review decision</button></form><p class="hint">Local reviewer annotation. Implementation evidence does not establish runtime effectiveness.</p></details>`;
  }
  function choices(type) {
    switch (type) {
      case "repositories":
        return model.sources.map((v) => [v.name, v.name]);
      case "interfaces":
        return model.interfaces.map((v) => [
          v.id,
          `${v.repository} · ${v.operation}`,
        ]);
      case "evidence":
        return model.evidence.map((v) => [
          v.id,
          `${v.repository}/${v.path}:${v.line}`,
        ]);
      case "node":
      case "nodes":
        return [...s.components, ...s.entities].map((v) => [v.id, v.name]);
      case "domain":
        return s.domains.map((v) => [v.id, v.name]);
      case "categories":
        return [
          "Spoofing",
          "Tampering",
          "Repudiation",
          "Information Disclosure",
          "Denial of Service",
          "Elevation of Privilege",
        ].map((v) => [v, v]);
      default:
        return (s[type] || []).map((v) => [v.id, v.name]);
    }
  }
  function editor(kind, record = {}) {
    const panel = root.querySelector("#ws-editor");
    panel.hidden = false;
    panel.innerHTML = `<h3>${record.id ? "Edit" : "Add"} ${e(titles[kind])}</h3><form id="ws-record-form" data-kind="${kind}" data-id="${e(record.id || "")}"><div class="grid">${Object.entries(
      fields[kind],
    )
      .map(([key, type]) => {
        const label = e(
          refLabels[key] ||
            (typeof type === "string" && !type.startsWith("@") ? type : key),
        );
        let control;
        if (Array.isArray(type))
          control = `<select aria-label="${label}" name="${key}">${type.map((v) => option(v, v, v === record[key])).join("")}</select>`;
        else if (type.startsWith("@")) {
          const single = [
            "source",
            "target",
            "parentId",
            "sourceDomainId",
            "targetDomainId",
          ].includes(key);
          control = `<select aria-label="${label}" name="${key}" ${single ? "" : 'multiple size="4"'}>${single ? '<option value="">Choose</option>' : ""}${choices(
            type.slice(1),
          )
            .map(([id, name]) =>
              option(
                id,
                name,
                single ? record[key] === id : (record[key] || []).includes(id),
              ),
            )
            .join("")}</select>`;
        } else
          control = ["name", "protocol", "before", "after"].includes(key)
            ? `<input name="${key}" value="${e(record[key] || "")}" ${key === "name" ? "required" : ""} maxlength="2000">`
            : `<textarea name="${key}" maxlength="2000">${e(record[key] || "")}</textarea>`;
        return `<label>${e(refLabels[key] || (typeof type === "string" && !type.startsWith("@") ? type : key))}${control}</label>`;
      })
      .join(
        "",
      )}</div><p class="hint">Hold Ctrl (Windows) or Command (Mac) to select multiple references. All edits remain reviewer declarations with their supporting evidence.</p><div class="toolbar"><button type="submit">Save record</button><button type="button" id="ws-close-editor">Cancel</button></div></form>`;
    panel.scrollIntoView({ block: "nearest" });
  }
  async function save(payload) {
    try {
      const result = await api("system", { revision: s.revision, ...payload });
      update(result);
      notify(
        "System model saved. Review dependent assumptions and stale decisions.",
      );
    } catch (error) {
      notify(error.message, true);
    }
  }
  root.addEventListener("click", async (event) => {
    const b = event.target.closest("button,[data-select]");
    if (!b) return;
    if (b.dataset.view) {
      view = b.dataset.view;
      query = "";
      dispositionFilter = "";
      page = 0;
      render();
    } else if (b.dataset.select) {
      selected = b.dataset.select;
      renderInspector();
    } else if (b.dataset.new) editor(b.dataset.new);
    else if (b.dataset.edit) {
      const r = find(b.dataset.edit);
      editor(r.kind, r);
    } else if (b.dataset.delete) {
      const r = find(b.dataset.delete);
      if (
        confirm(`Remove ${r.name}? Referenced records must be updated first.`)
      )
        await save({ action: "delete", kind: r.kind, id: r.id });
    } else if (b.dataset.trace) {
      const r = find(b.dataset.trace);
      view = "system";
      if (r.kind === "actors") actor = r.id;
      else if (["components", "entities"].includes(r.kind)) {
        focus = r.id;
        level = "focus";
      } else if (r.kind === "threats") {
        actor = "";
        focus = "";
        level = "system";
      } else if (r.kind === "flows") {
        focus = r.source;
        level = "focus";
      } else if (r.kind === "boundaries") {
        focus = s.flows.find((f) => r.flowIds.includes(f.id))?.source || "";
        level = focus ? "focus" : "system";
        lens = r.dimension;
      }
      render();
    } else if (b.id === "ws-close-editor")
      root.querySelector("#ws-editor").hidden = true;
    else if (b.id === "ws-prev") {
      page--;
      renderBody();
    } else if (b.id === "ws-next") {
      page++;
      renderBody();
    } else if (b.hasAttribute("data-start-review")) {
      try {
        b.disabled = true;
        requestBudget = Number(root.querySelector("#ws-request-budget").value);
        await startReview(requestBudget);
      } catch (error) {
        notify(error.message, true);
      }
    } else if (b.hasAttribute("data-stop-review")) {
      try {
        await stopReview();
      } catch (error) {
        notify(error.message, true);
      }
    } else if (b.id === "ws-export") {
      const panel = root.querySelector("#ws-export-panel");
      panel.hidden = !panel.hidden;
      panel.innerHTML = `<h3>Full review package</h3><p>Exports contain the complete selected scope and revision, regardless of current filters. Open the HTML report and choose Print → Save as PDF for a printable copy.</p><div class="toolbar">${[
        ["html", "Complete HTML report"],
        ["svg", "System DFD · SVG"],
        ["mermaid", "System DFD · Mermaid"],
        ["actors", "Actor register · CSV"],
        ["boundaries", "Boundary register · CSV"],
        ["threats", "Threat register · CSV"],
        ["flows", "Flow register · CSV"],
        ["components", "Component register · CSV"],
        ["assets", "Asset register · CSV"],
        ["securityControls", "Control register · CSV"],
        ["stride", "STRIDE matrix · CSV"],
        ["json", "Complete model · JSON"],
        ["manifest", "Source manifest"],
      ]
        .map(([k, l]) => `<button data-ws-export="${k}">${l}</button>`)
        .join("")}</div>`;
    } else if (b.dataset.wsExport)
      download(b.dataset.wsExport).catch((error) =>
        notify(error.message, true),
      );
  });
  root.addEventListener("keydown", (event) => {
    if (
      ["Enter", " "].includes(event.key) &&
      event.target.matches("[data-select]:not(button)")
    ) {
      event.preventDefault();
      selected = event.target.dataset.select;
      renderInspector();
    }
  });
  root.addEventListener("input", (event) => {
    if (event.target.id === "ws-search") {
      query = event.target.value;
      page = 0;
      const pos = event.target.selectionStart;
      renderBody();
      const input = root.querySelector("#ws-search");
      input.focus();
      input.setSelectionRange(pos, pos);
    }
  });
  root.addEventListener("change", (event) => {
    const id = event.target.id;
    if (id === "ws-request-budget") {
      requestBudget = Number(event.target.value);
      return;
    }
    if (id === "ws-level") level = event.target.value;
    if (id === "ws-lens") lens = event.target.value;
    if (id === "ws-focus") {
      focus = event.target.value;
      level = "focus";
    }
    if (id === "ws-actor" || id === "ws-matrix-actor")
      actor = event.target.value;
    if (id === "ws-row-kind") window.wsRowKind = event.target.value;
    if (id === "ws-disposition") dispositionFilter = event.target.value;
    if (id === "ws-threat-type") threatType = event.target.value;
    if (id === "ws-category") categoryFilter = event.target.value;
    if (id.startsWith("ws-")) renderBody();
    if (id === "ws-matrix-actor") renderInspector();
  });
  root.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target,
      fd = new FormData(form);
    if (form.id === "ws-decision")
      await save({
        action: "decision",
        subjectId: selected,
        ...Object.fromEntries(fd),
      });
    if (form.id === "ws-record-form") {
      const record = {};
      if (form.dataset.id) record.id = form.dataset.id;
      for (const [key, type] of Object.entries(fields[form.dataset.kind])) {
        const value =
          typeof type === "string" &&
          type.startsWith("@") &&
          ![
            "source",
            "target",
            "parentId",
            "sourceDomainId",
            "targetDomainId",
          ].includes(key)
            ? fd.getAll(key)
            : fd.get(key) || "";
        record[key] = value;
      }
      await save({ action: "upsert", kind: form.dataset.kind, record });
    }
  });
  window.SynthesisWorkspace = {
    render(value, callbacks) {
      model = value;
      s = value.systemModel;
      threatIndex = new Map((s?.threats || []).map((t) => [t.id, t]));
      ({
        api,
        download,
        notify,
        update,
        startReview,
        stopReview,
        providerAvailable,
      } = callbacks);
      if (s) render();
    },
    setStatus(value) {
      jobState = value;
      const run = root.querySelector("[data-start-review]"),
        stop = root.querySelector("[data-stop-review]");
      if (run) run.disabled = !value.inference || value.status === "running";
      if (stop)
        stop.hidden = !(value.status === "running" && value.mode === "review");
    },
    showMatrix() {
      view = "matrix";
      render();
    },
  };
})();
