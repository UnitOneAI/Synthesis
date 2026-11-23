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
    validateThreats,
    stopReview,
    openExploration,
    providerAvailable = false,
    jobState = { status: "idle" },
    requestBudget = 12,
    reviewScope = 'system',
    showAllDeploymentQuestions = false,
    deploymentClaimCount = 20,
    reviewWorkers = 2,
    runUntilComplete = false,
    tokenTarget = "",
    threatIndex = new Map(),
    selected = "",
    view = "system",
    level = "system",
    lens = "identity",
    focus = "",
    actor = "",
    query = "",
    threatType = "scenarios",
    categoryFilter = "",
    dispositionFilter = "",
    page = 0,
    saving = false,
    diagramSequence = 0,
    showUnresolved = false,
    showSupporting = false,
    bundleIds = [],
    diagramZoom = 0,
    gapQuery = "";
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
    return (ids || [])
      .map(
        (id) =>
          (find(id)?.reference ? find(id).reference + " · " : "") +
          (find(id)?.name || id),
      )
      .join("; ");
  }
  const option = (id, label, chosen) =>
    `<option value="${e(id)}" ${chosen ? "selected" : ""}>${e(label)}</option>`;
  function render() {
    if (!model) {
      root.innerHTML =
        "<h2>System model</h2><p>Build the source graph to review the system architecture.</p>";
      return;
    }
    root.innerHTML = `<div class="section-title"><div><p class="eyebrow">SYSTEM THREAT MODEL</p><h2>${e(s.title)}</h2><p>${e(s.profile)} · ${s.coverage.repositories} selected repositories · Static analysis</p></div><button id="ws-export">Export review package</button></div><div class="ws-status"><span>Draft</span><span>${s.flows.length} flows / candidates</span><span>${s.coverage.discoveredFlows || 0} discovered connections (${s.coverage.inferredConnections || 0} route hypotheses)</span><span>${s.coverage.unresolvedFlows} unresolved relationships</span><span>${s.coverage.pendingBoundaries} boundary decisions pending</span>${s.coverage.unavailable.length ? `<strong>Unavailable: ${e(s.coverage.unavailable.join(", "))}</strong>` : ""}</div><nav class="ws-tabs" aria-label="System model views">${[
      ["system", "System DFD"],
      ["actors", "Threat actors"],
      ["boundaries", "Trust boundaries"],
      ["deployment", "Deployment context"],
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
      )}</nav><div id="ws-export-panel" hidden></div><div id="ws-editor" hidden></div><div class="ws-layout${view === "matrix" ? " ws-matrix-layout" : ""}"><div class="ws-main"><div id="ws-body"></div></div><aside class="ws-inspector" id="ws-inspector" aria-live="polite"></aside></div>`;
    renderBody();
    renderInspector();
  }
  let deploymentReviewer = '';
  async function saveDeployment(payload) {
    if (saving) return;
    deploymentReviewer = root.querySelector('#dc-reviewer')?.value || deploymentReviewer;
    saving = true; root.inert = true;
    try {
      const value = await api('deployment-context', { revision: s.deploymentContext.revision, ...payload });
      update(value); notify('Deployment context saved. Affected results require review; compatible results remain saved.');
    } catch (error) { notify(error.message, true); }
    finally { saving = false; root.inert = false; }
  }
  function renderDeployment(body) {
    const context = s.deploymentContext;
    if (!context) { body.textContent = 'Refresh to load deployment context.'; return; }
    const evidenceButton = id => { const item = model.evidence.find(e => e.id === id); return item ? `<button class="dc-evidence" data-deployment-evidence="${e(id)}">${e(item.repository + '/' + item.path + ':' + (item.line || item.pointer || 1))}</button>` : ''; };
    const cards = (showAllDeploymentQuestions ? context.questions : context.questions.slice(0, 3)).map(q => `<article class="dc-question"><span class="badge">${e(q.state)}</span><h3>${e(q.question)}</h3><p><strong>Current assumption or statement:</strong> ${e(q.statement)}</p><p>${e(q.why)} Affects ${q.componentIds.length} components, ${q.flowIds.length} flows, ${q.boundaryIds.length} candidate boundaries and ${q.threatIds.length} current scenarios.</p><fieldset><legend>Optional review response</legend>${q.choices.map((choice, index) => `<label class="dc-choice"><input type="radio" name="dc-${e(q.id)}" value="${index}" ${index === (q.answer?.choice || 0) ? 'checked' : ''}>${e(choice)}</label>`).join('')}</fieldset><label>Rationale or scope clarification (optional)<textarea id="dc-rationale-${e(q.id)}">${e(q.answer?.rationale || '')}</textarea></label><button data-deployment-answer="${e(q.id)}">Save response</button><details><summary>Evidence and affected conclusions</summary>${q.evidenceIds.slice(0, 3).map(evidenceButton).join('')}<p>${e(q.evidenceIds.length)} evidence references retained.</p>${[...q.threatIds.slice(0, 3), ...q.boundaryIds.slice(0, 3), ...q.flowIds.slice(0, 2)].map(id => `<button data-select="${e(id)}">${e(find(id)?.reference || find(id)?.name || id)}</button>`).join('')}</details></article>`).join('');
    body.innerHTML = `<section class="dc-header"><p class="eyebrow">ASSUMPTIONS FIRST · STATIC ONLY</p><h2>Deployment context</h2><p>Review can proceed now. These optional responses refine the model; they do not block analysis.</p><div class="toolbar"><label>Configuration profile<select id="dc-profile">${['Unconfirmed source-defined deployment', ...context.profiles].map(p => option(p, p, p === context.profile)).join('')}</select></label><button id="dc-run-system">Review system threat model</button></div><p>${e(context.profileStatus)}. Profile selection is context, not proof of deployment or a filter that hides alternative configurations.</p></section><h3>Questions affecting risk</h3><p>${context.assumptions} assumptions in use. Showing ${Math.min(showAllDeploymentQuestions ? context.questions.length : 3, context.questions.length)} of ${context.questions.length} optional questions. You can review them after STRIDE returns results.</p><label>Reviewer (required only when reporting deployment facts)<input id="dc-reviewer" autocomplete="name" value="${e(deploymentReviewer)}"></label>${cards || '<p>No deployment questions derived from collected interfaces.</p>'}${context.questions.length > 3 ? `<button id="dc-show-all">${showAllDeploymentQuestions ? 'Show fewer questions' : 'Show all questions'}</button>` : ''}<details class="dc-question"><summary>Optional configuration evidence</summary><p>Import a small JSON/XML configuration. Only recognized declaration names and its hash are retained; raw values and credentials are discarded. Imported configuration does not prove deployed settings.</p><input id="dc-artifact" type="file" accept=".json,.xml,.config,.wxs,.wxi"><button id="dc-import-artifact">Import declarations</button>${context.artifacts.map(a => `<p>${e(a.name)} · ${e(a.declarations.map(d => d.key).join(', '))}<br><small>SHA256: ${e(a.sha256)}</small></p>`).join('')}</details><h3>Source evidence</h3><p>Source declarations, deployment status and reviewer decisions are separate. A control in a component does not prove enforcement on every route.</p><div class="table-wrap"><table><thead><tr><th>Area / component</th><th>Evidence</th><th>Deployment</th><th>Review</th></tr></thead><tbody>${context.claims.slice(0, deploymentClaimCount).map(c => `<tr><td>${e(c.area)}<br>${e(c.component)}</td><td>${c.evidenceIds.slice(0, 2).map(evidenceButton).join('')}<small>${c.evidenceIds.length} references · ${e(c.evidenceBasis?.join(', ') || c.basis)}</small></td><td>${e(c.deploymentStatus)}</td><td>${e(c.reviewDecision)}</td></tr>`).join('')}</tbody></table></div><p>Showing ${Math.min(deploymentClaimCount, context.claims.length)} of ${context.claims.length} evidence groups.</p>${context.claims.length > deploymentClaimCount ? '<button id="dc-more-evidence">Show more evidence</button>' : ''}<section id="dc-code" aria-live="polite"></section>`;
  }
  function renderBody() {
    const body = root.querySelector("#ws-body");
    if (view === 'deployment') { renderDeployment(body); return; }
    if (view === "system") {
      const nodes = [...s.components, ...s.entities];
      body.innerHTML = `<div class="toolbar"><label>View<select aria-label="View" id="ws-level">${[
        ["context", "Context"],
        ["system", "Service DFD"],
        ["focus", "Component detail"],
      ]
        .map(([k, n]) => option(k, n, k === level))
        .join(
          "",
        )}</select></label><label>Trust lens<select aria-label="Trust lens" id="ws-lens">${["identity", "privilege", "network", "execution", "data-ownership", "third-party"].map((k) => option(k, k, k === lens)).join("")}</select></label><label>Component focus<select aria-label="Component focus" id="ws-focus"><option value="">Choose a component</option>${nodes.map((n) => option(n.id, n.name, n.id === focus)).join("")}</select></label><label>Actor path<select aria-label="Actor path" id="ws-actor"><option value="">No actor overlay</option>${s.actors.map((a) => option(a.id, a.name, a.id === actor)).join("")}</select></label></div><p class="hint">${actor ? "Conditional path under the selected access assumptions. Connectivity does not establish exploitability." : "Select a component, flow or domain to inspect its evidence."} Trust zones appear only after a domain declaration. Repository boundaries do not imply trust boundaries.</p><p id="ws-connection-status" role="status">${s.coverage.discoveredFlows ? "Matched connections are grouped by direction, protocol and security context. Select a connector to inspect its member flows." : "Incomplete DFD: no service or resource connections were matched. Inspect unresolved coverage below. Rebuild the source graph after updating to collect the new endpoint facts."}</p>${model.connectionDiscovery?.coverage ? `<p class="hint">HTTP calls with matchable destinations: ${model.connectionDiscovery.coverage.httpClients || 0} / ${model.connectionDiscovery.coverage.httpOutboundCandidates ?? "unknown"}. Matchable routes: ${model.connectionDiscovery.coverage.httpServers ?? "unknown"} / ${model.connectionDiscovery.coverage.httpInboundCandidates ?? "unknown"}.</p>` : ""}<div class="toolbar dfd-tools"><button id="ws-zoom-out" aria-label="Zoom out">−</button><button id="ws-fit">Fit diagram</button><button id="ws-zoom-in" aria-label="Zoom in">+</button><label><input id="ws-show-unresolved" type="checkbox" ${showUnresolved ? "checked" : ""}>Show unresolved peers</label><label><input id="ws-show-supporting" type="checkbox" ${showSupporting ? "checked" : ""}>Include supporting source groups</label><button data-dfd-export="svg">Export this view · SVG</button><button data-dfd-export="mermaid">Export this view · Mermaid</button></div><div id="ws-canvas" class="ws-canvas" tabindex="0" aria-label="Diagram canvas; scroll to pan"><p>Loading system diagram…</p></div>${connectionCoverageHtml()}${
        actor
          ? `<section><h3>Actor-related threats</h3>${
              s.threats
                .filter(
                  (t) =>
                    t.origin !== "review checklist" &&
                    t.actorIds.includes(actor),
                )
                .map(
                  (t) =>
                    `<button data-select="${e(t.id)}">${e(t.name)}</button>`,
                )
                .join("") ||
              "<p>No returned threat scenarios linked to this actor.</p>"
            }</section>`
          : ""
      }<div class="toolbar"><button data-new="flows">Declare flow</button><button data-new="boundaries">Add trust boundary</button><button data-new="domains">Add trust domain</button><button data-new="actors">Add actor profile</button></div><p class="hint">Scroll the canvas to pan; use zoom for labels or Fit diagram for the full view. The canvas shows up to 80 objects and 240 grouped connections. Counts disclose omissions. View exports match these filters; the complete model and registers retain all source evidence and relationships.</p>`;
      loadDiagram();
      return;
    }
    if (view === "matrix") {
      const review = model.aiReview,
        c = review?.coverage;
      const stale = review?.status === "stale";
      const reasonLabels = {
        "guidance-changed": "Analysis guidance changed",
        "prompt-changed": "Review prompt changed",
        "source-or-architecture-changed":
          "Source or architecture revision changed",
        "architecture-changed": "Architecture declarations changed",
        "methodology-changed": "Analysis methodology changed",
        "reason-not-recorded":
          "The earlier run did not record a specific stale reason",
      };
      const staleNotice = stale
        ? `<section class="ws-stale-review" role="status"><strong>Stale analysis · historical results</strong><p>${e((review.staleReason?.causes || ["reason-not-recorded"]).map((code) => reasonLabels[code] || reasonLabels["reason-not-recorded"]).join("; "))}.</p><p>${(review.threats || []).length} prior threat scenario${(review.threats || []).length === 1 ? "" : "s"} and ${c?.completedBatches || 0} previously completed packet${c?.completedBatches === 1 ? "" : "s"} are retained for reference. Current valid completed packets: 0. Historical scenarios are not current coverage; run STRIDE to revalidate them.</p></section>`
        : "";
      const lastFailure = review?.lastRunFailure;
      const failureNotice = lastFailure
        ? `<section class="ws-last-review-failure" role="alert"><strong>Latest STRIDE attempt failed${lastFailure.stage === "before-review-checkpoint" ? " before the first review checkpoint" : ""}</strong><p>${e(lastFailure.code)} · ${e(lastFailure.action)}</p><p>Saved prior results remain below. Export errors for the failure stage and timestamp.</p></section>`
        : "";
      const stageRows = !stale && review?.reviewOrder?.stages;
      const stagePanel = `<section class="ws-review-order"><h3>External interfaces first</h3><p>Review declared external interfaces, potential external entry points, their internal paths, remaining internal actors and boundaries, then supporting/test code. Unknown exposure stays high priority without being labeled internet-facing. ${review?.reviewScope === "system" ? "System stages proceed in priority order. Isolated failed units remain visible while later stages are reviewed; repeated failures still stop the run." : "Each stage settles before the next starts; failed stages keep later work pending."}</p>${stageRows ? `<table><thead><tr><th>Review stage</th><th>Completed / planned</th><th>Failed</th><th>Pending</th></tr></thead><tbody>${stageRows.map((stage) => `<tr><th>${e(stage.label)}<small>${e(stage.description)}</small></th><td>${stage.completed} / ${stage.total}</td><td>${stage.failed}</td><td>${stage.pending}</td></tr>`).join("")}</tbody></table><p>Counts are packets, not confirmed exposure or approved trust boundaries. Shared packets can include supporting context.</p>` : `<p>Current stage coverage is not available yet. Start a review to prepare the plan; historical counts are not current coverage.</p>`}</section>`;
      body.innerHTML = `${failureNotice}${staleNotice}<p class="callout">System threat modeling reviews connected flows, entry points, workers, stores and controls first. Deployment assumptions let review proceed without answering questions. Deep code-path coverage remains separately selectable.</p><p class="hint">${model.aiReview ? `Saved results shown: ${model.aiReview.reviewScope === 'system' ? 'System threat model' : 'Deep code-path STRIDE'}.` : 'No saved STRIDE results.'} The scope selector controls the next action. Each scope retains its compatible completed work.</p><div id="ws-scope-preview">${model.aiReview?.reviewScope === 'system' ? `${model.aiReview.scope.interfaceIds.length} system-scope interfaces; ${model.aiReview.scope.deferredInterfaces} interfaces deferred to deep review. This is not whole-codebase clearance.` : ''}</div>${priorityThreatsHtml()}${stagePanel}<div class="ws-analysis"><div><strong>${stale ? "Historical packet counts · " : ""}${s.analysisStatus?.state === "failed" ? "STRIDE analysis failed · " : s.analysisStatus?.state === "partially-analyzed" ? "Partial STRIDE analysis · " : ""}${c ? `${c.completedBatches || 0} / ${c.totalBatches || 0} batches completed · ${c.failedBatches || 0} failed · ${c.pendingBatches || 0} pending` : "Analysis has not run"}</strong><p>${e(review?.stopReason === "request-budget" && !c?.failedBatches ? "Request limit reached successfully. Continue STRIDE analysis to review the remaining packets; completed results are retained." : review?.error || "Review the selected source evidence and declared interactions. Completed requests do not establish semantic completeness.")}</p>${!providerAvailable ? "<p>Start Synthesis with a configured provider and key to enable analysis. Connection details are shown in Sources.</p>" : ""}</div><div class="toolbar"><label>Review scope<select id="ws-review-scope" ${['running', 'cancelling'].includes(jobState.status) ? 'disabled' : ''}><option value="system" ${reviewScope === 'system' ? 'selected' : ''}>System threat model</option><option value="deep" ${reviewScope === 'deep' ? 'selected' : ''}>Deep code-path STRIDE</option></select></label><button id="ws-preview-scope">Preview system scope</button><label>Request budget<input id="ws-request-budget" type="number" min="1" max="100" value="${requestBudget}" ${runUntilComplete ? "disabled" : ""}></label><label>Parallel review workers<select id="ws-review-workers" ${["running", "cancelling"].includes(jobState.status) ? "disabled" : ""}>${[1, 2, 3, 4].map((v) => option(v, v, v === reviewWorkers)).join("")}</select></label><label><input id="ws-until-complete" type="checkbox" ${runUntilComplete ? "checked" : ""}>Run until complete</label><label>Token target this action (advisory)<input id="ws-token-target" type="number" min="1" step="1" placeholder="No target" value="${e(tokenTarget)}"></label><button data-start-review ${!providerAvailable || jobState.status === "running" ? "disabled" : ""}>Run or continue STRIDE analysis</button><button data-stop-review ${jobState.status === "running" && jobState.mode === "review" ? "" : "hidden"}>Stop review</button></div></div><p id="ws-run-progress" role="status">${e(window.SynthesisReviewRun?.(model.aiReview) || "")}</p>${model.aiReview?.coverageEvidence ? `<div class="callout" role="status"><strong>Source and control review</strong><p>${e(model.aiReview.coverageEvidence.sourceWindows)} code windows supplied; ${e(model.aiReview.coverageEvidence.unresolved)} unresolved evidence items. Use Exploration to follow missing callers, controls and configuration across repositories.</p><p>ASVS requirement assessments: ${e((model.aiReview.coverageEvidence.standards || []).filter((r) => r.status === "source-supported").length)} source-supported, ${e((model.aiReview.coverageEvidence.standards || []).filter((r) => r.status === "needs-context").length)} need context, ${e((model.aiReview.coverageEvidence.standards || []).filter((r) => r.status === "not-reviewed").length)} not reviewed, ${e((model.aiReview.coverageEvidence.standards || []).filter((r) => r.status === "not-applicable").length)} marked not applicable. Counts are per packet and requirement; they do not establish ASVS compliance.</p></div>` : ""}<div class="toolbar"><button data-ws-export="pdf">Export STRIDE review · PDF</button><span class="hint">Exports the latest saved review snapshot, including partial results, threat actors and trust boundaries. In-flight requests are not included until saved.</span></div><p class="hint">Parallel workers review separate packets using the same model; they reduce waiting, not total token usage. Reduce workers if the gateway limits concurrent requests. The limit does not increase automatically. Run until complete reviews pending packets across the saved repository scope without the 100-call or elapsed-time stop. Token targets are advisory and never stop a run. Stop at any time; provider failures and repeated invalid responses require attention. In bounded mode, request budget is the maximum number of model calls for this action. A budget of 1 reviews one evidence packet, not one complete repository or the whole system. Continue to process pending packets without losing completed analysis.</p><div class="toolbar"><label>Rows<select aria-label="Rows" id="ws-row-kind">${["boundary", "flow", "component"].map((k) => option(k, k, k === (window.wsRowKind || "component"))).join("")}</select></label><label>Actor<select aria-label="Actor" id="ws-matrix-actor"><option value="">All actors</option>${s.actors.map((a) => option(a.id, a.name, a.id === actor)).join("")}</select></label></div><p class="hint">Partial means some interfaces in this row have completed STRIDE review; not analyzed means none have. Following a saved threat checks its evidence but does not complete the remaining STRIDE packets. Cells count returned threat scenarios. Checklist prompts are available in the cell details and do not count as threats. Empty results require a review decision. Actor filtering does not change full-model coverage.</p><div class="table-wrap ws-matrix-scroll" role="region" aria-label="STRIDE matrix scroll area" tabindex="0"><table class="ws-matrix"><thead><tr><th>Review subject</th>${["Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service", "Elevation of privilege"].map((c, i) => `<th><b>${"STRIDE"[i]}</b><small>${c}</small></th>`).join("")}</tr></thead><tbody>${s.matrix
        .filter((r) => r.rowKind === (window.wsRowKind || "component"))
        .map(
          (r) =>
            `<tr><th>${e(r.name)}<small>${r.reviewedInterfaces || 0} / ${r.interfaceIds.length} interfaces reviewed</small></th>${r.cells
              .map((c) => {
                const ts = c.threatIds
                  .map((id) => threatIndex.get(id))
                  .filter((t) => t && (!actor || t.actorIds.includes(actor)));
                const scenarios = ts.filter(
                    (t) => t.origin !== "review checklist" && !t.metadataOnly,
                  ).length,
                  checklist = ts.length - scenarios;
                return `<td><button data-select="${e(c.id)}" class="${scenarios ? "populated" : ""}"><b>${scenarios || (c.analysisStatus === "analyzed-no-scenario" ? "0" : "—")}</b>${scenarios ? `<small>threat scenario${scenarios === 1 ? "" : "s"}</small>` : ""}<small>${actor && !scenarios && c.scenarioCount ? "No scenarios for selected actor · " : ""}${e(c.analysisLabel || c.state.replaceAll("-", " "))}</small>${c.questionCount ? `<small>${c.questionCount} architecture questions</small>` : ''}${c.failedEvidence ? "<small>Failed packets</small>" : ""}${c.decision ? `<small>Review: ${e(c.state)}</small>` : ""}</button></td>`;
              })
              .join("")}</tr>`,
        )
        .join(
          "",
        )}</tbody></table></div>${!s.matrix.some((r) => r.rowKind === (window.wsRowKind || "component")) ? "<p>No subjects of this type. Component rows show analysis results without requiring boundary declarations.</p>" : ""}`;
      body.insertAdjacentHTML(
        "beforeend",
        `<h3>${stale ? "Historical repository review progress" : model.aiReview?.reviewScope === 'system' ? "Repository system-review progress" : "Repository review progress"}</h3>${model.aiReview?.reviewScope === 'system' ? `<p>${model.aiReview.scope.deferredInterfaces} interfaces are deferred to deep review, outside the counts below.</p>` : ''}<table><thead><tr><th>Repository</th><th>Reviewed interfaces</th><th>State</th></tr></thead><tbody>${(c?.repositories || model.sources.map((source) => ({ repository: source.name, reviewedInterfaces: 0, totalInterfaces: model.interfaces.filter((i) => i.repository === source.name).length, state: "not-reviewed" }))).map((r) => {
          const scoped = model.aiReview?.reviewScope === 'system' ? model.aiReview.scope.repositories.find(x => x.repository === r.repository) : null;
          const total = scoped ? scoped.inScope : r.totalInterfaces;
          const state = scoped && r.state !== 'unavailable' ? !total ? 'no system interfaces' : r.reviewedInterfaces === total ? 'submitted' : r.reviewedInterfaces ? 'partial' : 'not-reviewed' : r.state;
          return `<tr><td>${e(r.repository)}</td><td>${r.reviewedInterfaces} / ${total}</td><td>${e(state)}</td></tr>`;
        }).join("")}</tbody></table>`,
      );
      body.insertAdjacentHTML(
        "beforeend",
        `<section id="ws-coverage">${coverageHtml(model)}</section><section id="ws-usage">${usageHtml(jobState.tokenUsage || model.tokenUsage)}</section>`,
      );
      return;
    }
    let rows = s[view] || [];
    if (view === "threats")
      rows = [...rows].sort(
        (a, b) =>
          (a.reviewPriority?.rank ?? 9) - (b.reviewPriority?.rank ?? 9) ||
          a.id.localeCompare(b.id),
      );
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
    body.innerHTML = `${view === 'threats' ? priorityThreatsHtml() : ''}<div class="toolbar"><h3>${titles[view]}</h3>${["actors", "boundaries"].includes(view) ? "<p>Candidate profiles and boundaries are static inputs or analysis assumptions. Pending means awaiting reviewer confirmation, not a running model request. A successful STRIDE response does not automatically approve access assumptions or enforcement.</p>" : ""}${view === "threats" ? "<p>Sorted by explained review priority. Priority is not severity; deployment and exploitability require review.</p>" : ""}<input id="ws-search" type="search" aria-label="Search register" placeholder="Search names, access, evidence…" value="${e(query)}"><button data-new="${view}">Add ${view === "actors" ? "actor profile" : view === "boundaries" ? "trust boundary" : view === "threats" ? "threat scenario" : "record"}</button></div><div class="toolbar"><label>Disposition<select id="ws-disposition" aria-label="Register disposition">${[["", "All dispositions"], ...[...new Set(rows.map((r) => r.reviewState))].map((v) => [v, v.replaceAll("-", " ")])].map(([k, l]) => option(k, l, k === dispositionFilter)).join("")}</select></label>${
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
            `<button class="ws-record" data-select="${e(r.id)}" aria-pressed="${selected === r.id}"><strong>${e(r.reference ? r.reference + " · " + r.name : r.name)}</strong>${r.reviewPriority ? `<small><b>${e(r.reviewPriority.label)}</b> · ${e(r.sourceScopes.join(", "))}</small><small>${e(r.reviewPriority.reasons.join(" "))}</small>` : ""}<span>${e(r.startingAccess || (r.before && `${r.dimension}: ${r.before} → ${r.after}`) || r.scenario || r.description || r.type || "")}</span><small>${r.origin ? e(r.origin === "review checklist" ? "Review checklist" : "Threat scenario") + " · " : ""}${e(r.basis)} · ${e(r.reviewState)}${r.decision?.owner ? " · Owner: " + e(r.decision.owner) : ""}</small></button>`,
        )
        .join("") ||
      "<p>No records. Add an evidence-supported declaration or an explicit assumption.</p>"
    }</div><div class="toolbar"><button id="ws-prev" ${page === 0 ? "disabled" : ""}>Previous</button><button id="ws-next" ${(page + 1) * 50 >= filtered.length ? "disabled" : ""}>Next</button></div>`;
  }
  function priorityThreatsHtml() {
    const current = (s.threats || []).filter(t => t.origin === 'analysis' && t.reviewState !== 'stale' && !t.metadataOnly).sort((a,b) => a.reviewPriority.rank - b.reviewPriority.rank || a.id.localeCompare(b.id));
    if (!current.length) return '';
    const busy = ['running','cancelling'].includes(jobState.status);
    return `<section class="ws-priority-panel"><h3>Priority threats</h3><p>Source-supported concerns and open control questions. Review priority is not a confirmed severity rating.</p><div class="ws-priority-cards">${current.slice(0,6).map(t => `<button class="ws-priority-card" data-select="${e(t.id)}"><strong>${e(t.reference)} · ${e(t.name)}</strong><span class="ws-validation-badge">${e(t.sourceConclusion?.status || t.validation?.assessment || 'not-assessed')}</span><p>${e(t.sourceConclusion?.statement || t.analysis?.impact || t.asset)}</p><small>Actor: ${e((t.actorIds || []).map(id => s.actors.find(a => a.id === id)?.name).filter(Boolean).join(', '))}</small><small>${t.boundaryIds?.length || 0} candidate trust crossings · ${t.evidenceIds?.length || 0} source references</small></button>`).join('')}</div><details><summary>Validate saved threats against code and controls</summary><p>Reuses the saved graph. Searches named controls across selected repositories, reads hash-checked source windows and records counterevidence. Original STRIDE results stay intact. Each scenario has at most three assessment rounds; unresolved facts remain gaps.</p><label><input type="checkbox" id="ws-validation-source">Send redacted source windows to the configured provider</label><label>Scenario scope<select id="ws-validation-scope"><option value="priority">Top six priorities</option><option value="all">All current source-referenced scenarios</option></select></label><label>Model requests<input id="ws-validation-budget" type="number" min="1" max="100" value="6"></label><label><input id="ws-validation-continuous" type="checkbox">Continue across saved scenarios (maximum three rounds each)</label><button data-validate-threats="all" ${busy || !providerAvailable ? 'disabled' : ''}>Validate saved threats</button><button data-stop-validation ${busy && jobState.mode === 'threat-validation' ? '' : 'hidden'}>Stop validation</button><p>${e(model.threatValidation ? `${model.threatValidation.callsThisRun} requests in last action · ${model.threatValidation.assessmentCounts?.assessed ?? 'unknown'} / ${model.threatValidation.candidateCount} selected scenarios assessed · ${model.threatValidation.assessmentCounts?.needsCodeContext ?? 'unknown'} need code evidence · ${model.threatValidation.assessmentCounts?.failed ?? 0} failed. Deployment assumptions remain separate from code conclusions.` : 'No independent threat validation has run.')}</p></details></section>`;
  }
  function connectionCoverageHtml() {
    const gaps =
      s.coverage.connectionGaps || model.connectionDiscovery?.gaps || [];
    const byInterface = new Map(model.interfaces.map((i) => [i.id, i]));
    const byEvidence = new Map(model.evidence.map((v) => [v.id, v]));
    const rows = gaps.map((g) => {
      const i = byInterface.get(g.interfaceId),
        ev = byEvidence.get(i?.evidence?.[0]);
      return {
        ...g,
        item: i
          ? {
              ...i,
              component:
                s.components.find((c) => c.interfaceIds.includes(i.id))?.id ||
                i.component,
            }
          : i,
        location: ev ? `${ev.repository}/${ev.path}:${ev.line}` : g.interfaceId,
      };
    });
    const filtered = rows.filter((g) =>
      `${g.location} ${g.reason}`
        .toLowerCase()
        .includes(gapQuery.toLowerCase()),
    );
    const counts = s.coverage.architecture || {};
    return `<details id="ws-unresolved"><summary>Connection coverage · ${gaps.length} resolution gaps · ${s.coverage.unresolvedFlows} unresolved relationships</summary><p>${counts.candidateProcesses || 0} candidate processes/resources · ${counts.sourceGroups || 0} source groups · ${counts.nonProductionGroups || 0} test/generated groups · ${counts.hostAssociations || 0} candidate host associations · ${counts.backgroundWorkers || 0} background worker candidates · ${counts.logicalResources || 0} logical resources. These labels do not prove deployment.</p><label>Filter unresolved locations<input id="ws-gap-search" type="search" value="${e(gapQuery)}" placeholder="Repository, file or reason"></label><p>${filtered.length} matching gaps; first 100 shown. Export errors provides a bounded diagnostic sample; complete model JSON retains all gaps.</p><div class="table-wrap"><table><thead><tr><th>Source location</th><th>Unresolved reason</th><th>Component</th></tr></thead><tbody>${filtered
      .slice(0, 100)
      .map(
        (g) =>
          `<tr><td>${e(g.location)}</td><td>${e(g.reason)}</td><td>${g.item ? `<button data-select="${e(g.item.component)}">Inspect component</button>` : "Unknown"}</td></tr>`,
      )
      .join(
        "",
      )}</tbody></table></div><p>Unknown peers remain in the flow register. Source files and test code remain in scan coverage even when excluded from this canvas.</p></details>`;
  }
  function applyZoom() {
    const canvas = root.querySelector("#ws-canvas"),
      svg = canvas?.querySelector("svg");
    if (!svg) return;
    svg.style.width = diagramZoom
      ? `${diagramZoom * 100}%`
      : `max(100%, ${svg.viewBox.baseVal.width * 0.75}px)`;
    svg.style.minWidth = "0";
    svg.style.height = "auto";
  }
  function diagramOptions() {
    return {
      level,
      lens,
      focus,
      actor,
      threat: selected,
      showUnresolved: String(showUnresolved),
      showSupporting: String(showSupporting),
    };
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
        showUnresolved: String(showUnresolved),
        showSupporting: String(showSupporting),
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
      ) {
        root.querySelector("#ws-canvas").innerHTML = svg;
        applyZoom();
      }
    } catch (error) {
      notify(error.message, true);
    }
  }
  function coverageHtml(m) {
    const c = m.diagnosticCoverage,
      review = c?.review;
    const source = c?.source?.sources || m.sources || [];
    const graph = m.sourceGraph?.coverage || {};
    return `<h3>Analysis coverage</h3>${m.analysisMethod ? `<p>Method: ${e(m.analysisMethod.version)} · STRIDE, actor access, control evidence and pinned OWASP guidance. Framework mappings require review.</p>` : ""}<p>${source.filter((s) => s.status === "read").length} / ${source.length} repositories read · ${source.reduce((n, s) => n + (s.coverage?.inspected || 0), 0)} files inspected · ${graph.parsed || 0} files parsed · ${graph.unsupported || 0} unsupported files · ${(graph.failed || 0) + (graph.syntaxErrors || 0) + (graph.limited || 0)} syntax errors, parser failures or limits.</p>${
      review
        ? `<p><strong>${review.reviewed} / ${review.total} review obligations submitted successfully</strong> · ${review.pending} pending · ${review.blocked} blocked</p><div class="table-wrap"><table><thead><tr><th>Review subject</th><th>Reviewed</th><th>Pending</th><th>Blocked</th></tr></thead><tbody>${Object.entries(
            review.byKind,
          )
            .map(
              ([kind, count]) =>
                `<tr><th>${e(kind.replaceAll("-", " "))}</th><td>${count.reviewed} / ${count.total}</td><td>${count.pending}</td><td>${count.blocked}</td></tr>`,
            )
            .join(
              "",
            )}</tbody></table></div><p>${review.gaps.length} gap records (some group multiple occurrences). ${Object.entries(
            review.gaps.reduce((counts, gap) => {
              counts[gap.kind] =
                (counts[gap.kind] || 0) +
                (gap.kind === "additional-unresolved-call-targets"
                  ? gap.count
                  : 1);
              return counts;
            }, {}),
          )
            .map(([kind, count]) => `${count} ${e(kind.replaceAll("-", " "))}`)
            .join(
              " · ",
            )}. Unresolved calls may include library calls; they are not vulnerability findings. Full locations are in the diagnostic bundle.</p>`
        : "<p>Run STRIDE analysis to create the review worklist.</p>"
    }<p class="hint">Review coverage measures submitted evidence. It does not prove that every threat was identified. Syntax paths do not establish deployed reachability or effective controls.</p><button data-ws-export="diagnostics">Download diagnostic bundle · ZIP</button><p class="hint">Includes graph metadata, source coverage, request failures and token counts. No raw source excerpts or model prose. Inspect confidential architecture metadata before sharing.</p>`;
  }
  function usageHtml(u) {
    if (!u)
      return "<h3>Token usage</h3><p>No token records available for this snapshot.</p>";
    const n = (v) =>
      v == null ? "Unknown" : Number(v).toLocaleString("en-US");
    return `<h3>Token usage</h3><p><strong>${n(u.totalTokens)} reported tokens</strong> · ${u.requests} requests · ${u.unknownRequests} with unknown totals</p><p>Latest action: ${n(u.lastRun.totalTokens)} reported tokens / ${u.lastRun.requests} requests. Includes failed responses and retries; locally reused batches make no new request.</p>${u.legacyUnmetered ? "<p>Earlier analysis has no token records. Totals cover metered requests only.</p>" : ""}<p class="hint">Input includes cache reads and writes. Cache columns are subsets. Shared requests are counted once, separately from individual repositories. Unknown usage is not zero. These are reported subtotals, not an invoice.</p><details data-usage-details="repositories"><summary>Usage by repository and shared analysis</summary><div class="table-wrap"><table><thead><tr><th>Scope</th><th>Requests</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>Total</th><th>Unknown</th></tr></thead><tbody>${u.groups.map((g) => `<tr><th>${e(g.label)}</th><td>${g.requests}</td><td>${n(g.inputTokens)}</td><td>${n(g.outputTokens)}</td><td>${n(g.cacheReadTokens)}</td><td>${n(g.cacheWriteTokens)}</td><td>${n(g.totalTokens)}</td><td>${g.unknownRequests}</td></tr>`).join("")}</tbody></table></div></details><details data-usage-details="attempts"><summary>Recent requests (last 50; export includes all)</summary><div class="table-wrap"><table><thead><tr><th>Batch / model</th><th>Repositories</th><th>Status</th><th>Input</th><th>Output</th><th>Total</th></tr></thead><tbody>${u.recentAttempts.map((a) => `<tr><td>${e(a.batchId)}<br>${e(a.model)}</td><td>${e(a.repositories.join(", "))}</td><td>${e(a.status)}${a.retry ? " · retry" : ""}</td><td>${n(a.usage?.inputTokens)}</td><td>${n(a.usage?.outputTokens)}</td><td>${n(a.usage?.totalTokens)}</td></tr>`).join("")}</tbody></table></div></details><button data-ws-export="usage">Token usage · CSV</button>`;
  }
  function renderInspector() {
    const out = root.querySelector("#ws-inspector"),
      r = find(selected);
    if (!r) {
      out.innerHTML =
        "<h3>Review context</h3><p>Select a diagram object or register entry to inspect its access assumptions, controls and evidence.</p><p>Legitimate external entities and threat-actor profiles are separate records.</p>";
      return;
    }
    const relatedIds =
      r.threatIds ||
      s.threats
        .filter(
          (t) =>
            t.origin !== "review checklist" &&
            (t.flowIds?.some((id) => id === r.id || bundleIds.includes(id)) ||
              t.boundaryIds?.includes(r.id) ||
              t.interfaceIds?.some((id) => r.interfaceIds?.includes(id))),
        )
        .map((t) => t.id);
    const visibleThreatIds = relatedIds.filter(
      (id) => !actor || threatIndex.get(id)?.actorIds.includes(actor),
    );
    const linked = visibleThreatIds
      .map((id) => threatIndex.get(id))
      .filter(Boolean);
    const scenarios = linked.filter((t) => t.origin !== "review checklist");
    const checklist = linked.filter((t) => t.origin === "review checklist");
    const linkedButton = (t) =>
      `<button class="ws-linked-record" data-select="${e(t.id)}"><strong>${e(t.reference ? t.reference + " · " + t.name : t.name)}</strong><small>${e((refs(t.evidenceIds)[0] || t.id).split(" · ")[0])}</small></button>`;
    const linkedSection =
      r.kind === "cell" || linked.length > 0
        ? `<section><h4>Linked scenarios (${scenarios.length})</h4>${scenarios.map(linkedButton).join("") || `<p>${r.analysisStatus === "analyzed-no-scenario" ? "No scenario identified in analyzed evidence; reviewer assessment is still required." : "No completed scenario for this selection. Check analysis status and pending or failed packets; this is not a clean result."}</p>`}${checklist.length ? `<details class="ws-checklist"><summary>Review checklist (${checklist.length} items)</summary>${checklist.map(linkedButton).join("")}</details>` : ""}</section>`
        : "";
    const investigations = (model.securityRegister?.issues || []).filter(
      (i) =>
        i.interfaceIds.some((id) => r.interfaceIds?.includes(id)) ||
        i.evidenceIds.some((id) => r.evidenceIds?.includes(id)),
    );
    const investigationSection = investigations.length
      ? `<section><h4>Related security investigations</h4><p>Source association; this does not prove reachability along this flow.</p>${investigations
          .slice(0, 20)
          .map(
            (i) =>
              `<p><strong>${e(i.title)}</strong><br>${e(i.cwe || i.kind)} · ${e(i.assessment)}<br>${e(i.investigation?.counterEvidence || "Evidence assessment pending")}<br><button data-explore-issue="${e(i.id)}">Explore review history</button></p>`,
          )
          .join(
            "",
          )}<p>Open CWE code review → Security investigations for full evidence and exports.</p></section>`
      : "";
    const field = (title, v) =>
      v ? `<section><h4>${e(title)}</h4><p>${e(v)}</p></section>` : "";
    out.innerHTML = `${
      bundleIds.length > 1
        ? `<section><h3>Grouped connection · ${bundleIds.length} flows</h3><p>Each member retains its interfaces, source evidence and review decision.</p><div class="ws-bundle">${bundleIds
            .map((id) => s.flows.find((f) => f.id === id))
            .filter(Boolean)
            .map(
              (f) =>
                `<button data-bundle-member="${e(f.id)}">${e(f.name)}</button>`,
            )
            .join("")}</div></section>`
        : ""
    }<p class="eyebrow">${e(titles[r.kind] || "STRIDE review")}</p><h3>${e(r.reference ? r.reference + " · " + r.name : r.name)}</h3>${r.reviewPriority ? field("Review priority", r.reviewPriority.label + ": " + r.reviewPriority.reasons.join(" ") + " " + r.reviewPriority.interpretation) : ""}${r.analysisLabel ? field("Analysis status", r.analysisLabel + (r.failedEvidence ? ". Failed packets affect this subject." : "")) : ""}<span class="badge">${e(r.basis || r.state)} · ${e(r.reviewState || "review required")}</span>${field("Evidence strength", r.evidenceStatus)}${r.validation ? field('Independent source assessment', r.validation.assessment) + field('Validation counterevidence', r.validation.counterEvidence) + field('Missing code evidence', r.validation.missingEvidence?.join('; ')) + field('Deployment assumptions — not verified', r.validation.deploymentAssumptions?.join('; ')) + field('Recommended code change', r.validation.remediation?.codeFix) + field('Validated source path', r.validation.trace?.map(x => `${x.role}: ${x.repository} / ${x.path}:${x.line} — ${x.reason}`).join('; ')) : ''}${field("Threat statement", r.scenario)}${field("Initial access", r.startingAccess)}${field("Objectives / impact", r.objectives || r.asset)}${field("Excluded capabilities", r.excludedCapabilities)}${field("Prerequisites", r.prerequisites)}${r.crossings?.length ? `<section><h4>Boundary crossings</h4>${r.crossings.map((c) => `<button data-select="${e(c.id)}">${e(c.reference)} · ${e(c.from)} → ${e(c.to)}</button>`).join("")}<p>Candidate crossing; the transition and enforcement require evidence review.</p></section>` : ""}${field("Trust transition", r.before ? `${r.dimension}: ${r.before} → ${r.after}` : "")}${field("Controls and enforcement", r.enforcement || r.controls)}${field("Description", r.description)}${field("Architecture classification", r.classification)}${field("Source scope", r.scope)}${field("Candidate host", r.hostCandidateId ? names([r.hostCandidateId]) : "")}${
      s.components.some((c) => c.hostCandidateId === r.id)
        ? `<section><h4>Associated source groups</h4><p>Unique project-reference ownership; deployment requires review.</p>${s.components
            .filter((c) => c.hostCandidateId === r.id)
            .map(
              (c) => `<button data-select="${e(c.id)}">${e(c.name)}</button>`,
            )
            .join("")}</section>`
        : ""
    }${field("Source repositories", (r.repositories || []).join(", "))}${field("Threat actors", names(r.actorIds))}${field("Entry points", names(r.entryIds))}${[
      ["Affected flows", r.flowIds],
      ["Trust boundaries", r.boundaryIds],
    ]
      .map(([label, ids]) =>
        ids?.length
          ? `<section><h4>${e(label)}</h4>${ids.map((id) => `<button data-select="${e(id)}">${e(names([id]))}</button>`).join("")}</section>`
          : "",
      )
      .join(
        "",
      )}${field("Transport", r.transport ? `${r.transport} in source URL; enforcement requires review` : "")}${field("Data", r.data)}${field("Boundary association", r.boundaryLinkBasis)}${field("Mitigation", r.mitigation)}${field("Attack steps", r.analysis?.attackSteps?.join(" → "))}${field("Conditional impact", r.analysis?.impact)}${field("Analysis assumptions", r.analysis?.assumptions?.join("; "))}${field("Framework mappings", r.analysis?.mappings?.map((m) => `${m.framework} ${m.id}: ${m.name} — ${m.rationale} (proposed)`).join("; "))}${field("Analysis quality", r.analysisQuality?.gaps?.join("; ") || r.analysisQuality?.semantics)}${field("Caller identity", r.callerIdentity)}${field("Callee identity", r.calleeIdentity)}${field("Credential type", r.credentialType)}${field("Authorization decision", r.authorization)}${field("Assumptions", r.assumptions)}${field("Linked controls", names(r.controlIds))}${field("Counterevidence", refs(r.counterEvidenceIds).join("; "))}${field("References requiring repair", (r.missingReferences || []).join(", "))}${linkedSection}${investigationSection}<section><h4>Supporting evidence</h4>${
      refs(r.evidenceIds)
        .map((v) => `<p class="evidence">${e(v)}</p>`)
        .join("") ||
      "<p>No source evidence attached; this claim requires review.</p>"
    }</section>${r.decision?.riskAssessment ? field("OWASP technical risk", `${r.decision.riskAssessment.status} · ${r.decision.riskAssessment.severity || "unassessed"} · ${r.decision.riskAssessment.missing?.length || 0} unknown factors · reviewer estimate`) : ""}${r.decision ? field("Review decision", `${r.decision.state}${r.decision.stale ? " (stale)" : ""} · ${r.decision.reviewer}: ${r.decision.rationale}`) : ""}<div class="toolbar"><button data-trace="${e(r.id)}">Show on DFD</button>${r.kind !== "cell" ? `<button data-edit="${e(r.id)}">Edit record</button><button data-delete="${e(r.id)}">Remove record</button>` : ""}</div>${r.sourceConclusion ? field("Source review", r.sourceConclusion.statement) + field("Condition or missing link", r.sourceConclusion.condition) + field("Next action", r.sourceConclusion.nextAction) + field("Reviewed by", r.sourceConclusion.reviewer) : ""}${r.validation?.evidence?.length ? `<details><summary>Record a cited source conclusion</summary><form id="ws-source-conclusion"><label>Conclusion<select name="status"><option value="conditional">Conditional threat</option><option value="open">Open question</option></select></label><label>What the source shows<textarea required name="statement"></textarea></label><label>Deployment condition or missing link<textarea required name="condition"></textarea></label><label>Next action<textarea required name="nextAction"></textarea></label><label>Reviewer<input required name="reviewer"></label><fieldset><legend>Supporting source windows</legend>${r.validation.evidence.map(x => `<label><input type="checkbox" name="evidenceIds" value="${e(x.id)}">${e(x.repository)} / ${e(x.path)}:${e(x.startLine)}–${e(x.endLine)}</label>`).join('')}</fieldset><button>Save source conclusion</button></form></details>` : ''}<details><summary>Record review decision</summary><form id="ws-decision"><label>Disposition<select aria-label="Disposition" name="state">${["needs-investigation", "accepted", "rejected", "mitigation-planned", "implemented-in-source", "risk-accepted", "not-applicable", ...(r.kind === "cell" ? ["reviewed-no-scenario"] : [])].map((k) => option(k, k.replaceAll("-", " "), false)).join("")}</select></label><label>Reviewer<input name="reviewer" required maxlength="200"></label><label>Rationale<textarea name="rationale" required maxlength="2000"></textarea></label><label>Mitigation owner<input name="owner" maxlength="200"></label><label>Severity assessment<select aria-label="Severity assessment" name="severity">${["unassessed", "low", "medium", "high", "critical"].map((k) => option(k, k, false)).join("")}</select></label><details><summary>OWASP technical risk factors (optional)</summary><label><input type="checkbox" name="useRiskFactors">Calculate from these factors</label><p>Leave unknown values blank. A partial assessment remains unassessed; estimates do not establish exploitability.</p>${Object.entries(
      {
        likelihood: [
          "skillLevel",
          "motive",
          "opportunity",
          "size",
          "easeOfDiscovery",
          "easeOfExploit",
          "awareness",
          "intrusionDetection",
        ],
        impact: [
          "confidentiality",
          "integrity",
          "availability",
          "accountability",
        ],
      },
    )
      .map(([group, keys]) =>
        keys
          .map(
            (key) =>
              `<label>${e(group + " · " + key.replace(/([A-Z])/g, " $1").toLowerCase())}<input type="number" min="0" max="9" step="any" name="risk.${group}.${key}" placeholder="Unknown"></label>`,
          )
          .join(""),
      )
      .join(
        "",
      )}</details><button type="submit">Save review decision</button></form><p class="hint">Local reviewer annotation. Implementation evidence does not establish runtime effectiveness.</p></details>`;
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
    if (saving) return;
    saving = true;
    root.inert = true;
    root.setAttribute("aria-busy", "true");
    notify("Saving system model…");
    try {
      const result = await api("system", { revision: s.revision, ...payload });
      update(result);
      notify(
        "System model saved. Review dependent assumptions and stale decisions.",
      );
    } catch (error) {
      notify(error.message, true);
    } finally {
      saving = false;
      root.inert = false;
      root.removeAttribute("aria-busy");
    }
  }
  root.addEventListener("click", async (event) => {
    const b = event.target.closest("button,[data-select]");
    if (!b) return;
    if (b.hasAttribute('data-validate-threats')) {
      try {
        const candidates = s.threats.filter(t => t.origin === 'analysis' && t.reviewState !== 'stale' && !t.metadataOnly).sort((a,b) => a.reviewPriority.rank - b.reviewPriority.rank || a.id.localeCompare(b.id));
        const ids = b.dataset.validateThreats === 'all' ? (root.querySelector('#ws-validation-scope')?.value === 'all' ? candidates : candidates.slice(0,6)).map(t => t.id) : [b.dataset.validateThreats];
        const includeSourceCode = root.querySelector('#ws-validation-source')?.checked === true;
        await validateThreats({ threatIds: ids, includeSourceCode, budget: Number(root.querySelector('#ws-validation-budget')?.value || 6), runUntilComplete: root.querySelector('#ws-validation-continuous')?.checked === true });
      } catch (error) { notify(error.message, true); }
    } else if (b.id === 'dc-show-all') {
      showAllDeploymentQuestions = !showAllDeploymentQuestions; renderBody();
    } else if (b.id === 'dc-import-artifact') {
      const file = root.querySelector('#dc-artifact').files[0];
      if (!file || file.size > 256 * 1024) { notify('Choose a configuration file no larger than 256 KiB', true); return; }
      await saveDeployment({ action: 'artifact', name: file.name, text: await file.text() });
    } else if (b.id === 'dc-more-evidence') { deploymentClaimCount += 20; renderBody();
    } else if (b.id === 'dc-run-system') { view = 'matrix'; reviewScope = 'system'; render();
    } else if (b.id === 'ws-preview-scope') {
      try { const plan = await api('system-review-plan'); const panel = root.querySelector('#ws-scope-preview');
        if (panel) panel.textContent = `${plan.units} system review units · ${plan.scope.interfaceIds.length} in-scope interfaces · ${plan.scope.deferredInterfaces} deferred to deep review · ${plan.gaps} explicit context gaps. No model call was made.`;
      } catch (error) { notify(error.message, true); }
    } else if (b.dataset.deploymentAnswer) {
      const key = b.dataset.deploymentAnswer;
      const choice = Number(root.querySelector(`input[name="dc-${key}"]:checked`).value);
      await saveDeployment({ action: 'answer', questionId: key, choice, reviewer: root.querySelector('#dc-reviewer').value, rationale: root.querySelector(`#dc-rationale-${key}`).value });
    } else if (b.dataset.deploymentEvidence) {
      try {
        const window = await api('deployment-evidence?id=' + encodeURIComponent(b.dataset.deploymentEvidence));
        const panel = root.querySelector('#dc-code');
        if (panel) { panel.innerHTML = `<h3>Verified source evidence</h3><p>Hash-checked local source; sensitive values are redacted where recognized. No model call.</p><pre>${e(window.lines.map(l => `${l.line ?? l.number}: ${l.text}`).join('\n'))}</pre>`; panel.scrollIntoView({ block: 'nearest' }); }
      } catch (error) { notify(error.message, true); }
    } else if (b.dataset.dfdExport) {
      download(b.dataset.dfdExport, false, diagramOptions()).catch((error) =>
        notify(error.message, true),
      );
    } else if (["ws-fit", "ws-zoom-in", "ws-zoom-out"].includes(b.id)) {
      const canvas = root.querySelector("#ws-canvas"),
        svg = canvas?.querySelector("svg");
      const current =
        diagramZoom ||
        Math.max(
          1,
          ((svg?.viewBox.baseVal.width || 950) * 0.75) /
            (canvas?.clientWidth || 900),
        );
      diagramZoom =
        b.id === "ws-fit"
          ? 1
          : Math.min(
              12,
              Math.max(0.5, current * (b.id === "ws-zoom-in" ? 1.25 : 0.8)),
            );
      applyZoom();
    } else if (b.dataset.bundleMember) {
      selected = b.dataset.bundleMember;
      renderInspector();
    } else if (b.dataset.view) {
      view = b.dataset.view;
      query = "";
      dispositionFilter = "";
      page = 0;
      render();
    } else if (b.dataset.select) {
      selected = b.dataset.select;
      bundleIds = (b.dataset.flowIds || "").split(" ").filter(Boolean);
      renderInspector();
      if (view === "matrix" && window.matchMedia("(max-width: 1200px)").matches)
        root.querySelector("#ws-inspector").scrollIntoView({ block: "start" });
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
        lens =
          s.boundaries.find((b) => r.boundaryIds?.includes(b.id))?.dimension ||
          lens;
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
        await startReview(requestBudget, {
          concurrency: reviewWorkers,
          reviewScope,
          runUntilComplete,
          tokenTarget: tokenTarget === "" ? null : Number(tokenTarget),
        });
      } catch (error) {
        notify(error.message, true);
      }
    } else if (b.hasAttribute("data-stop-review") || b.hasAttribute('data-stop-validation')) {
      try {
        await stopReview();
      } catch (error) {
        notify(error.message, true);
      }
    } else if (b.id === "ws-export") {
      const panel = root.querySelector("#ws-export-panel");
      panel.hidden = !panel.hidden;
      panel.innerHTML = `<h3>Full review package</h3><p>Registers and model exports contain the complete selected scope and revision. These diagram exports use the default service view; use Export this view on the canvas to preserve current filters. PDF opens a review report with threat scenarios, component STRIDE rows and grouped boundary records. Complete HTML retains the detailed registers and checklist prompts. Choose Print / Save as PDF to save it locally.</p><div class="toolbar">${[
        ["pdf", "Threat model · PDF"],
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
        ["usage", "Token usage · CSV"],
        ["diagnostics", "Diagnostic bundle · ZIP"],
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
      bundleIds = (event.target.dataset.flowIds || "")
        .split(" ")
        .filter(Boolean);
      selected = event.target.dataset.select;
      renderInspector();
    }
  });
  root.addEventListener("input", (event) => {
    if (event.target.id === "ws-gap-search") {
      gapQuery = event.target.value;
      const pos = event.target.selectionStart;
      root.querySelector("#ws-unresolved").outerHTML = connectionCoverageHtml();
      root.querySelector("#ws-unresolved").open = true;
      const input = root.querySelector("#ws-gap-search");
      input.focus();
      input.setSelectionRange(pos, pos);
    }
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
    if (event.target.id === 'ws-review-scope') { reviewScope = event.target.value; return; }
    if (event.target.id === 'dc-profile') { saveDeployment({ action: 'profile', profile: event.target.value }); return; }

    const id = event.target.id;
    if (id.startsWith("ws-validation-")) return;
    if (id === "ws-gap-search" || id === "ws-search") return;
    if (id === "ws-review-workers") {
      reviewWorkers = Number(event.target.value);
      return;
    }
    if (id === "ws-until-complete") {
      runUntilComplete = event.target.checked;
      root.querySelector("#ws-request-budget").disabled = runUntilComplete;
      return;
    }
    if (id === "ws-token-target") {
      tokenTarget = event.target.value;
      return;
    }
    if (id === "ws-request-budget") {
      requestBudget = Number(event.target.value);
      return;
    }
    if (id === "ws-show-unresolved") showUnresolved = event.target.checked;
    if (id === "ws-show-supporting") showSupporting = event.target.checked;
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
    if (form.id === "ws-source-conclusion") {
      await save({ ...Object.fromEntries(fd), action: "source-conclusion", subjectId: selected,
        evidenceIds: fd.getAll("evidenceIds") });
    }
    if (form.id === "ws-decision") {
      const riskFactors = {};
      if (fd.has("useRiskFactors"))
        for (const [key, value] of fd)
          if (key.startsWith("risk.")) {
            const [, group, factor] = key.split(".");
            (riskFactors[group] ||= {})[factor] =
              value === "" ? null : Number(value);
          }
      const decision = Object.fromEntries(
        [...fd].filter(
          ([key]) => !key.startsWith("risk.") && key !== "useRiskFactors",
        ),
      );
      await save({
        action: "decision",
        subjectId: selected,
        ...decision,
        ...(fd.has("useRiskFactors") ? { riskFactors } : {}),
      });
    }
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
  root.addEventListener("click", (event) => {
    const b = event.target.closest("[data-explore-issue]");
    if (b)
      openExploration?.(b.dataset.exploreIssue).catch((error) =>
        notify(error.message, true),
      );
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
        validateThreats,
        stopReview,
        openExploration,
        providerAvailable,
      } = callbacks);
      if (s) render();
    },
    setStatus(value) {
      jobState = value;
      const progress = root.querySelector("#ws-run-progress");
      if (progress)
        progress.textContent =
          window.SynthesisReviewRun?.(
            value.reviewRuns?.stride || model.aiReview,
          ) || "";
      const meter = root.querySelector("#ws-usage");
      if (meter && value.tokenUsage) {
        const html = usageHtml(value.tokenUsage);
        if (meter.dataset.signature !== JSON.stringify(value.tokenUsage)) {
          const open = [...meter.querySelectorAll("details[open]")].map(
            (d) => d.dataset.usageDetails,
          );
          meter.innerHTML = html;
          meter.querySelectorAll("details").forEach((d) => {
            d.open = open.includes(d.dataset.usageDetails);
          });
          meter.dataset.signature = JSON.stringify(value.tokenUsage);
        }
      }
      const run = root.querySelector("[data-start-review]"),
        stop = root.querySelector("[data-stop-review]");
      if (run)
        run.disabled =
          !value.inference || ["running", "cancelling"].includes(value.status);
      for (const button of root.querySelectorAll('[data-validate-threats]')) button.disabled = !value.inference || ['running','cancelling'].includes(value.status);
      const validationStop = root.querySelector('[data-stop-validation]');
      if (validationStop) validationStop.hidden = !(value.status === 'running' && value.mode === 'threat-validation');
      const workers = root.querySelector("#ws-review-workers");
      if (workers)
        workers.disabled = ["running", "cancelling"].includes(value.status);
      if (stop)
        stop.hidden = !(value.status === "running" && value.mode === "review");
    },
    showReferences(anchors = []) {
      const interfaceIds = new Set(
        anchors.filter((a) => a.kind === "interface").map((a) => a.id),
      );
      const component = s?.components.find(
        (c) =>
          (c.interfaceIds || []).some((i) => interfaceIds.has(i)) ||
          anchors.some((a) => a.kind === "component" && a.id === c.id),
      );
      view = "system";
      selected = component?.id || "";
      focus = component?.id || "";
      render();
    },
    showMatrix() {
      view = "matrix";
      render();
    },
  };
})();
