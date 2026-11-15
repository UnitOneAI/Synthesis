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
            `<tr><td><button data-finding="${esc(f.id)}">${esc(f.cwe)}</button></td><td>${esc(f.repository)}<br>${esc(f.path)}:${f.line}</td><td>${esc(f.title)}</td><td>${esc(f.status)}</td></tr>`,
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
      `<h3>${esc(f.cwe)} · ${esc(f.title)}</h3><p>${esc(f.repository)} / ${esc(f.path)}:${f.line}–${f.endLine}</p><p>${esc(f.remediation)}</p><p>${esc(f.association)}. ${f.interfaceIds.length} associated interfaces. File SHA256: <code>${esc(f.blobSha256)}</code></p><form id="cwe-decision"><label>Finding status <select name="status" aria-label="Finding status">${["needs-review", "confirmed", "false-positive", "accepted-risk"].map((v) => `<option ${v === f.status ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Reviewer <input name="reviewer" required maxlength="200" value="${esc(f.review?.reviewer)}"></label><label>Rationale <textarea name="reason" required maxlength="2000">${esc(f.review?.reason)}</textarea></label><button>Save finding decision</button></form>`;
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
      const r = model?.cweReview;
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
        ? `${review.status} · ${review.completedBatches || 0} / ${review.totalBatches || 0} packets completed · ${review.pendingBatches ?? "Unknown"} pending · ${review.findings.length} potential weaknesses${review.error ? " · " + review.error : ""}`
        : "No source review has run.";
      $("cwe-model-results").innerHTML = review
        ? `<p>${esc(review.provider)} / ${esc(review.model)} · Source and interaction evidence. Token usage is included in the workspace token meter and export.</p><table><thead><tr><th>Repository</th><th>Reviewed / planned segments</th></tr></thead><tbody>${review.repositories.map((r) => `<tr><td>${esc(r.name)}</td><td>${r.reviewedSegments || 0} / ${r.chunks}</td></tr>`).join("")}</tbody></table>${review.gaps.length ? `<p>${review.gaps.length} coverage gaps. Inspect the export before accepting coverage.</p>` : ""}${review.findings
            .slice(0, 200)
            .map(
              (f) =>
                `<details><summary>${esc(f.cwe)} · ${esc(f.title)} · ${esc(f.status)}</summary><p>${esc(f.explanation)}</p><p>Prerequisites: ${esc(f.preconditions)}</p><p>Counterevidence: ${esc(f.counterEvidence)}</p><p>Remediation: ${esc(f.remediation)}</p><ul>${f.locations.map((l) => `<li>${esc(l.repository)} / ${esc(l.path)}:${l.line}–${l.endLine}</li>`).join("")}</ul><form data-model-decision="${esc(f.id)}"><label>Disposition <select name="status" aria-label="CWE source finding status">${["needs-review", "confirmed", "false-positive", "accepted-risk"].map((v) => `<option ${v === f.status ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Reviewer <input name="reviewer" required maxlength="200" value="${esc(f.review?.reviewer)}"></label><label>Rationale <textarea name="reason" required maxlength="2000">${esc(f.review?.reason)}</textarea></label><button>Save CWE source decision</button></form></details>`,
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
