(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (v) =>
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
  let model, actions, current;
  const remediationLabels = {
    codeFix: "Durable code fix",
    interimControl: "Interim control",
    residualRisk: "Residual exposure",
    recovery: "Recovery considerations",
    owner: "Owner",
    approval: "Approval",
    validation: "Proposed validation",
    rollback: "Rollback plan",
  };
  function investigations() {
    const register = model?.securityRegister;
    const term = $("security-filter").value.toLowerCase();
    const issues = (register?.issues || []).filter((i) =>
      JSON.stringify([
        i.kind,
        i.cwe,
        i.title,
        i.assessment,
        i.locations.map((l) => l.repository),
        i.locations.map((l) => l.sourceScope),
      ])
        .toLowerCase()
        .includes(term),
    );
    $("security-status").textContent = register
      ? `${register.executionStatus} · ${register.issues.length} candidates · ${register.counts["static-supported"]} source-supported · ${register.counts["ruled-out"]} ruled out · ${register.counts["needs-context"]} need context · ${register.counts["not-assessed"]} not assessed · ${register.counts["failed"]} failed. Candidate assessment does not establish complete source coverage.${register.staleReview ? " Previous assessments are stale." : ""}`
      : "Build the source graph, then scan or review source to identify candidates.";
    $("security-results").innerHTML =
      `<p>${issues.length} matching candidates; showing up to 200. Export includes all candidates.</p>` +
      issues
        .slice(0, 200)
        .map((i) => {
          const a = i.investigation;
          const loc = (l) =>
            `${esc(l.repository)} / ${esc(l.path)}:${l.line}–${l.endLine || l.line}${l.sourceScope ? ` · ${esc(l.sourceScope)}` : ""}`;
          return `<details><summary>${esc(i.title)} · ${esc(i.kind)} · ${esc(i.cwe || "No CWE mapping")} · ${esc(i.assessment)} · ${esc([...new Set(i.locations.map((l) => l.sourceScope || "unclassified"))].join(", "))}</summary><p>Disposition: ${esc(i.disposition)}${i.stale ? " · Stale source" : ""}. Origin: ${esc(i.origin)}.</p><ul>${i.locations.map((l) => `<li>${loc(l)}</li>`).join("")}</ul>${
            a
              ? `<p>Proof basis: static analysis, unexecuted. Human security review required.</p><p>Actor: ${esc(a.actorKind)} · ${esc(a.actor)}. Initial access: ${esc(a.initialAccess)}</p><p>Input: ${esc(a.input)}</p><p>Impact: ${esc(a.impact)}</p><h4>Evidence path</h4><ol>${(a.trace || []).map((t) => `<li>${esc(t.role)} · ${loc(t)} · ${esc(t.reason)}</li>`).join("")}</ol><h4>Controls and counterevidence</h4><p>${esc(a.counterEvidence)}</p><ul>${(a.controls || []).map((c) => `<li>${loc(c)} · ${esc(c.reason)}</li>`).join("")}</ul><h4>Unresolved evidence</h4><ul>${[...(a.missingEvidence || []), ...(a.evidenceGaps || []).map((g) => g.reason)].map((g) => `<li>${esc(g)}</li>`).join("")}</ul><p>${esc(a.error || a.stopReason || "")}</p><h4>Remediation and residual exposure</h4><dl>${Object.entries(
                  a.remediation || {},
                )
                  .map(
                    ([k, v]) =>
                      `<dt>${esc(remediationLabels[k] || k)}</dt><dd>${esc(v)}</dd>`,
                  )
                  .join(
                    "",
                  )}</dl><p>Assessment change conditions: ${esc(a.severityChangeConditions)}</p><p>${a.rounds} assessment rounds. Source windows: ${a.retrieval?.includedWindows || 0}. Recommendations do not authorize production changes.</p>`
              : "<p>No independent evidence assessment has run.</p>"
          }</details>`;
        })
        .join("");
  }
  function targetCoverage() {
    const coverage = model?.cweTargetCoverage;
    const selected = $("cwe-target-repository").value;
    const rows = (coverage?.rows || []).filter(
      (r) => !selected || r.repository === selected,
    );
    const label = (v) => String(v || "").replaceAll("-", " ");
    $("cwe-target-summary").textContent = coverage
      ? `${coverage.targetCount} requested areas · ${coverage.requestedIdentifierCount} original CWE identifiers · ${coverage.additionalFindings.length} additional or unassigned findings retained. Four areas require dependency, lifecycle or policy evidence. Model counts are completed assessments / planned packets.`
      : "Build a source graph to see requested coverage.";
    $("cwe-target-coverage").innerHTML = coverage
      ? `<table><thead><tr><th>Repository / requested area</th><th>Local pattern checks</th><th>Model source review</th><th>Findings</th></tr></thead><tbody>${rows.map((r) => `<tr><td><strong>${esc(r.name)}</strong><br>${esc(r.repository)}<br><small>${esc(r.requestedCwes.join(", "))}</small><details><summary>Scope and mapping</summary><p>${esc(r.mappingNote)}</p><p>Finding IDs: ${esc(r.findingCwes.join(", ") || "Requires a specific underlying weakness")}</p><p>${esc(r.limitations)}</p></details></td><td>${esc(label(r.scannerStatus))}<br><small>${r.ruleIds.length} dedicated rules · ${esc(r.scannerLanguages.join(", "))}</small></td><td>${esc(label(r.modelStatus))}<br>${r.reviewedPackets} / ${r.plannedPackets} packets${r.needsContextPackets ? `<br>${r.needsContextPackets} need context` : ""}</td><td>${r.potentialFindings} potential<br>${r.dismissedFindings} dismissed</td></tr>`).join("")}</tbody></table>`
      : "";
  }
  function list() {
    const report = model?.cweReview,
      term = $("cwe-filter").value.toLowerCase();
    const filtered = (report?.findings || []).filter((f) =>
      [f.repository, f.cwe, f.path, f.status]
        .join(" ")
        .toLowerCase()
        .includes(term),
    );
    $("cwe-findings").innerHTML =
      `<p>${filtered.length} matching findings. Showing up to 200; use filters or export the full report.</p><table><thead><tr><th>CWE</th><th>Repository / file</th><th>Potential weakness</th><th>Status</th></tr></thead><tbody>${filtered
        .slice(0, 200)
        .map(
          (f) =>
            `<tr><td><button data-finding="${esc(f.id)}">${esc(f.cwe)}</button></td><td>${esc(f.repository)}<br>${esc(f.path)}:${f.line}<br><small>${esc(f.sourceScope || "Source scope unclassified")}</small></td><td>${esc(f.title)}</td><td>${esc(f.status)}</td></tr>`,
        )
        .join("")}</tbody></table>`;
    $("cwe-findings")
      .querySelectorAll("[data-finding]")
      .forEach((b) => (b.onclick = () => detail(b.dataset.finding)));
  }
  function detail(id) {
    current = id;
    const f = model?.cweReview?.findings.find((f) => f.id === id);
    if (!f) {
      $("cwe-detail").innerHTML = "";
      return;
    }
    $("cwe-detail").innerHTML =
      `<h3>${esc(f.cwe)} · ${esc(f.title)}</h3><p>${esc(f.repository)} / ${esc(f.path)}:${f.line}–${f.endLine}</p><p>${esc(f.remediation)}</p><p>Mapping: ${esc(f.mappingStatus || "requires review")}</p><p>${esc(f.association)}. ${f.interfaceIds.length} associated interfaces. File SHA256: <code>${esc(f.blobSha256)}</code></p><form id="cwe-decision"><label>Finding status <select name="status" aria-label="Finding status">${["needs-review", "confirmed", "false-positive", "accepted-risk"].map((v) => `<option ${v === f.status ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Reviewer <input name="reviewer" required maxlength="200" value="${esc(f.review?.reviewer)}"></label><label>Rationale <textarea name="reason" required maxlength="2000">${esc(f.review?.reason)}</textarea></label><button>Save finding decision</button></form>`;
    $("cwe-decision").onsubmit = async (event) => {
      event.preventDefault();
      try {
        const data = Object.fromEntries(new FormData(event.target));
        actions.update(
          await actions.api("cwe/decision", {
            ...data,
            id,
            modelRevision: model.modelRevision,
          }),
        );
        actions.notify("Finding decision saved");
      } catch (e) {
        actions.notify(e.message, true);
      }
    };
  }
  window.SynthesisCwe = {
    render(value, callbacks) {
      model = value;
      actions = callbacks;
      $("security-filter").oninput = investigations;
      $("security-run").onclick = () =>
        actions
          .startSecurity(
            Number($("cwe-model-budget").value),
            $("cwe-model-consent").checked,
          )
          .catch((e) => actions.notify(e.message, true));
      $("security-stop").onclick = () =>
        actions.stop().catch((e) => actions.notify(e.message, true));
      document.querySelector('[data-export="security-json"]').disabled = !model;
      investigations();
      const r = model?.cweReview;
      const selectedRepository = $("cwe-target-repository").value;
      $("cwe-target-repository").innerHTML =
        '<option value="">All repositories</option>' +
        (model?.sources || [])
          .map((r) => `<option value="${esc(r.name)}">${esc(r.name)}</option>`)
          .join("");
      $("cwe-target-repository").value = selectedRepository;
      $("cwe-target-repository").onchange = targetCoverage;
      for (const format of ["cwe-coverage-json", "cwe-coverage-csv"])
        document.querySelector(`[data-export="${format}"]`).disabled = !model;
      targetCoverage();
      for (const format of ["cwe-json", "cwe-csv", "cwe-sarif"])
        document.querySelector(`[data-export="${format}"]`).disabled = !r;
      $("cwe-run").disabled = !model;
      $("cwe-status").textContent = r
        ? `${r.status} · ${r.findings.length} potential weaknesses · ${r.rulePack.rules.length} rules · ${r.tokens} model tokens${r.error ? " · " + r.error : ""}`
        : "Ready to scan the repositories in this source graph.";
      $("cwe-coverage").innerHTML = r
        ? `<table><thead><tr><th>Repository</th><th>Status</th><th>Scanned / eligible</th><th>Unsupported</th><th>Gaps</th><th>Graph snapshot</th></tr></thead><tbody>${r.repositories.map((v) => `<tr><td>${esc(v.name)}</td><td>${esc(v.status)}</td><td>${v.scannedFiles} / ${v.eligibleFiles}</td><td>${v.unsupportedFiles}</td><td>${esc(v.errors.map((e) => e.type).join(", "))}${v.skipped.length ? " · " + v.skipped.length + " skipped" : ""}</td><td>${v.matchesGraphSnapshot ? "Matches" : "Unverified or changed"}</td></tr>`).join("")}</tbody></table><p>${r.limitations.map(esc).join(" ")}</p>`
        : "";
      $("cwe-run").onclick = () =>
        actions.start().catch((e) => actions.notify(e.message, true));
      $("cwe-stop").onclick = () =>
        actions.stop().catch((e) => actions.notify(e.message, true));
      $("cwe-filter").oninput = list;
      const review = model?.cweModelReview;
      document.querySelector('[data-export="cwe-model-json"]').disabled =
        !review;
      $("cwe-model-run").onclick = () =>
        actions
          .startModel(
            Number($("cwe-model-budget").value),
            $("cwe-model-consent").checked,
          )
          .catch((e) => actions.notify(e.message, true));
      $("cwe-model-stop").onclick = () =>
        actions.stop().catch((e) => actions.notify(e.message, true));
      $("cwe-model-status").textContent = review
        ? `${review.status} · ${review.completedBatches || 0} / ${review.totalBatches || 0} packets completed · ${review.pendingBatches ?? "Unknown"} pending · ${review.findings.length} potential weaknesses${review.error ? " · " + review.error : review.batches?.find((b) => b.status === "failed")?.error ? " · " + review.batches.find((b) => b.status === "failed").error : ""}`
        : "Model CWE source review has not run. Semgrep results are separate: use Export Semgrep JSON, CSV or SARIF above. To add model review, enable source sharing and select Run or continue CWE source review.";
      $("cwe-model-results").innerHTML = review
        ? `<p>${esc(review.provider)} / ${esc(review.model)} · Scanner findings are reviewed first, then graph interactions and remaining source. Token usage is included in the workspace token meter and export.</p><table><thead><tr><th>Repository</th><th>Reviewed / planned segments</th></tr></thead><tbody>${review.repositories.map((r) => `<tr><td>${esc(r.name)}</td><td>${r.reviewedSegments || 0} / ${r.chunks}</td></tr>`).join("")}</tbody></table>${review.gaps.length ? `<p>${review.gaps.length} coverage gaps. Inspect the export before accepting coverage.</p>` : ""}${review.findings
            .slice(0, 200)
            .map(
              (f) =>
                `<details><summary>${esc(f.cwe || f.kind || "Security concern")} · ${esc(f.title)} · ${esc(f.status)}</summary><p>${esc(f.explanation)}</p><p>Mapping: ${esc(f.mappingStatus || "requires review")}</p><p>Prerequisites: ${esc(f.preconditions)}</p><p>Counterevidence: ${esc(f.counterEvidence)}</p><p>Remediation: ${esc(f.remediation)}</p><ul>${f.locations.map((l) => `<li>${esc(l.repository)} / ${esc(l.path)}:${l.line}–${l.endLine} · ${esc(l.sourceScope || "Source scope unclassified")}</li>`).join("")}</ul><form data-model-decision="${esc(f.id)}"><label>Disposition <select name="status" aria-label="CWE source finding status">${["needs-review", "confirmed", "false-positive", "accepted-risk"].map((v) => `<option ${v === f.status ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Reviewer <input name="reviewer" required maxlength="200" value="${esc(f.review?.reviewer)}"></label><label>Rationale <textarea name="reason" required maxlength="2000">${esc(f.review?.reason)}</textarea></label><button>Save CWE source decision</button></form></details>`,
            )
            .join("")}`
        : "";
      $("cwe-model-results")
        .querySelectorAll("[data-model-decision]")
        .forEach(
          (form) =>
            (form.onsubmit = async (event) => {
              event.preventDefault();
              try {
                const data = Object.fromEntries(new FormData(form));
                actions.update(
                  await actions.api("cwe/decision", {
                    ...data,
                    id: form.dataset.modelDecision,
                    origin: "model",
                    modelRevision: model.modelRevision,
                  }),
                );
                actions.notify("CWE source decision saved");
              } catch (e) {
                actions.notify(e.message, true);
              }
            }),
        );
      list();
      detail(current);
    },
    setStatus(s) {
      $("security-run").disabled =
        !s.hasModel ||
        !s.inference ||
        ["running", "cancelling"].includes(s.status);
      $("security-stop").hidden =
        s.status !== "running" || s.mode !== "cwe-security";
      if (s.status === "running" && s.mode === "cwe-security")
        $("security-status").textContent = s.message;
      $("cwe-run").disabled =
        !s.hasModel || s.status === "running" || s.status === "cancelling";
      $("cwe-model-run").disabled =
        !s.hasModel ||
        !s.inference ||
        ["running", "cancelling"].includes(s.status);
      $("cwe-model-stop").hidden =
        s.status !== "running" || s.mode !== "cwe-model";
      if (s.status === "running" && s.mode === "cwe-model")
        $("cwe-model-status").textContent = s.message;
      $("cwe-stop").hidden = s.status !== "running" || s.mode !== "cwe";
      if (s.status === "running" && s.mode === "cwe")
        $("cwe-status").textContent = s.message;
    },
  };
})();
