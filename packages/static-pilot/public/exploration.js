(() => {
  const $ = (id) => document.getElementById(id),
    esc = (v) =>
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
    callbacks,
    graph,
    selected,
    query = {},
    history = [],
    busy = false,
    available = false,
    signature = "",
    serial = 0;
  let viewport = { x: 0, y: 0, w: 1200, h: 600 },
    drag,
    foldedMembers = [],
    expandedGroups = false;
  const colors = {
    scope: "#163b65",
    phase: "#275fa7",
    goal: "#007c78",
    step: "#43618f",
    finding: "#b05f14",
    assessment: "#6a4c91",
    observation: "#41735b",
    control: "#41735b",
    counterevidence: "#6a4c91",
    gap: "#ac493e",
  };
  const invoke = (fn) => async () => {
    try {
      await fn();
    } catch (e) {
      callbacks.notify(e.message, true);
    }
  };
  function download(name, text, type = "application/json") {
    if (new Blob([text]).size > 3 * 1024 * 1024)
      throw Error("Selected export exceeds 3 MiB. Open a smaller branch.");
    const u = URL.createObjectURL(new Blob([text], { type })),
      a = document.createElement("a");
    a.href = u;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(u), 1000);
  }
  async function load(next = {}, remember = true) {
    if ($("exploration-snapshot").value)
      next = { revision: $("exploration-snapshot").value, ...next };
    const n = ++serial;
    const data = await api("exploration?" + new URLSearchParams(next));
    if (n !== serial) return;
    if (remember) history.push(query);
    query = next;
    graph = data;
    selected = null;
    expandedGroups = false;
    draw();
    $("exploration-detail").innerHTML =
      "<h3>Review evidence</h3><p>Select a card to inspect its evidence, coverage and history. Open its branch to follow subsequent steps.</p>";
  }
  function viewBox() {
    $("exploration-svg").setAttribute(
      "viewBox",
      `${viewport.x} ${viewport.y} ${viewport.w} ${viewport.h}`,
    );
  }
  function draw() {
    if (!graph) return;
    let visible = graph;
    foldedMembers = graph.nodes.filter((n) => n.kind === "goal");
    if (query.focus && foldedMembers.length > 4 && !expandedGroups) {
      const ids = new Set(foldedMembers.map((n) => n.id));
      const mapped = graph.edges.map((e) => ({
        ...e,
        source: ids.has(e.source) ? "folded-goals" : e.source,
        target: ids.has(e.target) ? "folded-goals" : e.target,
      }));
      const seen = new Set();
      visible = {
        ...graph,
        nodes: [
          ...graph.nodes.filter((n) => !ids.has(n.id)),
          {
            id: "folded-goals",
            kind: "goal",
            label: `${foldedMembers.length} requested CWE checks`,
            status: "Expand to inspect each obligation",
            children: foldedMembers.length,
          },
        ],
        edges: mapped.filter((e) => {
          const k = [e.source, e.target, e.kind].join(":");
          if (seen.has(k)) return false;
          seen.add(k);
          return true;
        }),
      };
    }
    const crumbs = query.focus
      ? visible.nodes.filter(
          (n) => ["scope", "phase"].includes(n.kind) || n.id === "folded-goals",
        )
      : [];
    crumbs.sort(
      (a, b) =>
        (({ scope: 0, phase: 1, goal: 2 })[a.kind] ?? 3) -
        ({ scope: 0, phase: 1, goal: 2 }[b.kind] ?? 3),
    );
    const crumbIds = new Set(crumbs.map((n) => n.id));
    $("exploration-breadcrumb").innerHTML = crumbs
      .map(
        (n) =>
          `<button class="secondary" data-crumb="${esc(n.id)}">${esc(n.label)}</button>`,
      )
      .join("<span>›</span>");
    $("exploration-breadcrumb")
      .querySelectorAll("[data-crumb]")
      .forEach((b) => (b.onclick = invoke(() => details(b.dataset.crumb))));
    if (crumbs.length)
      visible = {
        ...visible,
        nodes: visible.nodes.filter((n) => !crumbIds.has(n.id)),
        edges: visible.edges.filter(
          (e) => !crumbIds.has(e.source) && !crumbIds.has(e.target),
        ),
      };
    $("exploration-svg").classList.toggle(
      "focused-lineage",
      Boolean(query.focus),
    );
    $("exploration-svg").setAttribute("preserveAspectRatio", "xMidYMin meet");
    const depth = new Map(visible.nodes.map((n) => [n.id, 0]));
    // Cycle-safe bounded relaxation. Investigation edges are not source call edges.
    for (let round = 0; round < 8; round++)
      for (const e of visible.edges)
        if (depth.has(e.source) && depth.has(e.target))
          depth.set(
            e.target,
            Math.min(8, Math.max(depth.get(e.target), depth.get(e.source) + 1)),
          );
    const counts = {},
      positions = new Map();
    for (const n of visible.nodes) {
      const d = depth.get(n.id);
      const row = counts[d] || 0;
      counts[d] = row + 1;
      positions.set(n.id, { x: 30 + d * 340, y: 30 + row * 108 });
    }
    const width = Math.max(
        800,
        ...[...positions.values()].map((p) => p.x + 320),
      ),
      height = Math.max(440, ...[...positions.values()].map((p) => p.y + 105));
    const lines = visible.edges
      .map((e) => {
        const a = positions.get(e.source),
          b = positions.get(e.target);
        return `<path marker-end="url(#eg-arrow)" d="M${a.x + 290} ${a.y + 38} C${a.x + 320} ${a.y + 38},${b.x - 30} ${b.y + 38},${b.x} ${b.y + 38}"/><text text-anchor="middle" x="${(a.x + b.x + 290) / 2}" y="${(a.y + b.y) / 2 - 8}">${esc(e.kind.replaceAll("_", " "))}</text>`;
      })
      .join("");
    const cards = visible.nodes
      .map((n) => {
        const p = positions.get(n.id),
          label = n.label || n.kind;
        return `<g data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(label)}" transform="translate(${p.x},${p.y})"><title>${esc(label)} · ${esc(n.status)}</title><rect width="290" height="96" rx="9"/><rect width="5" height="96" fill="${colors[n.kind] || "#43618f"}"/><text class="eg-kind" x="15" y="19">${esc(n.kind.toUpperCase())}${n.children ? ` · ${n.children} linked records` : ""}</text><text class="eg-label" x="15" y="40">${esc(label.slice(0, 36))}</text><text class="eg-label" x="15" y="57">${esc(label.slice(36, 72))}${label.length > 72 ? "…" : ""}</text><text x="15" y="78">${esc(n.status)}${n.repository ? " · " + esc(n.repository.slice(0, 19)) : ""}</text></g>`;
      })
      .join("");
    $("exploration-svg").innerHTML =
      `<defs><marker id="eg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 Z" fill="#95abc0"/></marker></defs><g class="eg-edges">${lines}</g><g class="eg-cards">${cards}</g>`;
    $("exploration-minimap").setAttribute("viewBox", `0 0 ${width} ${height}`);
    $("exploration-minimap").innerHTML = visible.nodes
      .map((n) => {
        const p = positions.get(n.id);
        return `<rect x="${p.x}" y="${p.y}" width="290" height="96" fill="${colors[n.kind] || "#43618f"}"/>`;
      })
      .join("");
    $("exploration-fit").onclick = () => {
      viewport = { x: 0, y: 0, w: width, h: height };
      viewBox();
    };
    // Start readable; fit remains available for a large branch.
    viewport = {
      x: 0,
      y: 0,
      w: Math.min(width, 1500),
      h: query.focus ? 350 : 600,
    };
    viewBox();
    $("exploration-page").textContent =
      `${visible.nodes.length} cards · ${graph.offset + 1}–${Math.min(graph.offset + graph.limit, graph.total)} of ${graph.total} records (scope and grouped obligations above) · ${graph.omitted} further records. Entire review: ${graph.overview.nodes} nodes, ${graph.overview.edges} links.`;
    $("exploration-next").disabled = !graph.omitted;
    $("exploration-back").disabled = !history.length;
    $("exploration-svg")
      .querySelectorAll("[data-node]")
      .forEach((el) => {
        el.onclick = invoke(() => details(el.dataset.node));
        el.ondblclick = invoke(() =>
          el.dataset.node === "folded-goals"
            ? details(el.dataset.node)
            : load({ parent: el.dataset.node }),
        );
        el.onkeydown = (event) => {
          if (event.key === "Enter") el.onclick();
        };
      });
  }
  async function details(nid) {
    if (nid === "folded-goals") {
      $("exploration-detail").innerHTML =
        `<h3>${foldedMembers.length} requested CWE checks</h3><p>Visual grouping only. Each obligation and its original outcome remain available.</p><button id="eg-unfold">Expand group</button><ul>${foldedMembers.map((n) => `<li><button class="secondary" data-member="${esc(n.id)}">${esc(n.label)}</button> · ${esc(n.status)}</li>`).join("")}</ul>`;
      $("eg-unfold").onclick = () => {
        expandedGroups = true;
        draw();
      };
      $("exploration-detail")
        .querySelectorAll("[data-member]")
        .forEach((b) => (b.onclick = invoke(() => details(b.dataset.member))));
      return;
    }
    const n = await api(
      "exploration?" +
        new URLSearchParams({ node: nid, revision: graph.revision }),
    );
    selected = n;
    const prose = [
      "explanation",
      "counterEvidence",
      "error",
      "stopReason",
      "preconditions",
      "initialAccess",
      "impact",
    ];
    $("exploration-detail").innerHTML =
      `<p class="eyebrow">${esc(n.kind)} · ${esc(n.status)}</p><h3>${esc(n.label)}</h3><div class="toolbar"><button id="eg-open">Open branch</button><button id="eg-lineage" class="secondary">Show lineage</button></div>
      ${n.repository ? `<p>Repository: ${esc(n.repository)}</p>` : ""}
      ${n.stepKind ? `<p>Step: ${esc(n.stepKind)} · ${n.attempts || 0} model attempts</p>` : ""}
      ${n.result?.reason || n.result?.error ? `<h4>Outcome</h4><p>${esc(n.result.error || n.result.reason)}</p>` : ""}
      ${n.result?.traversed ? `<p>${n.result.traversed.length} indexed relationships followed. These are static candidates.</p>` : ""}
      ${n.result?.matches ? `<p>${n.result.matches.length} indexed evidence matches.</p>` : ""}
      ${n.requestedCwes ? `<p>Requested: ${esc(n.requestedCwes.join(", "))}</p><p>Model: ${esc(n.modelStatus)} · Scanner: ${esc(n.scannerStatus)} · ${n.reviewedPackets}/${n.plannedPackets} packets</p>` : ""}
      ${prose
        .filter((k) => n[k])
        .map(
          (k) =>
            `<h4>${esc({ counterEvidence: "Counterevidence", initialAccess: "Starting access", impact: "Impact", preconditions: "Prerequisites", error: "Review failure", stopReason: "Stop reason", explanation: "Explanation" }[k] || k)}</h4><p>${esc(n[k])}</p>`,
        )
        .join("")}
      ${n.missingEvidence?.length ? `<h4>Missing evidence</h4><ul>${n.missingEvidence.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>` : ""}
      ${n.issueId && n.recordId ? '<button id="eg-source">Read cited source</button><pre id="eg-code"></pre>' : ""}
      ${n.anchors?.length ? `<h4>Source and system references</h4><ul>${n.anchors.map((a) => `<li>${esc(a.kind)}: ${esc(a.id)}</li>`).join("")}</ul><button id="eg-system" class="secondary">Open system DFD</button>` : ""}
      <p>${n.transitionCount} recorded changes. ${n.transitionCount > 20 ? "Showing the latest 20." : ""}</p>
      <details><summary>Record and history</summary><pre>${esc(JSON.stringify(n, null, 2))}</pre></details>`;
    $("eg-open").onclick = invoke(() => load({ parent: n.id }));
    $("eg-lineage").onclick = invoke(() => load({ focus: n.id }));
    if ($("eg-system"))
      $("eg-system").onclick = () => callbacks.openSystem(n.anchors);
    if ($("eg-source"))
      $("eg-source").onclick = invoke(async () => {
        const s = await api(
          "exploration/source?" +
            new URLSearchParams({ issue: n.issueId, record: n.recordId }),
        );
        $("eg-code").textContent = Array.isArray(s.lines)
          ? s.lines.map((l) => `${l.line}: ${l.text}`).join("\n")
          : s.lines;
      });
  }
  function svgExport() {
    const svg = $("exploration-svg").cloneNode(true);
    const style = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "style",
    );
    style.textContent =
      ".eg-cards rect:first-of-type{fill:white;stroke:#bbcddd}.eg-edges path{fill:none;stroke:#95abc0}text{font:11px sans-serif;fill:#193653}.eg-label{font-size:13px;font-weight:bold}.eg-kind{font-size:9px}";
    svg.prepend(style);
    return new XMLSerializer().serializeToString(svg);
  }
  function setup() {
    $("exploration-snapshot").onchange = invoke(async () => {
      history = [];
      const revision = $("exploration-snapshot").value;
      const roots = await api(
        "exploration?" + new URLSearchParams({ kind: "scope", revision }),
      );
      await load({ revision, parent: roots.nodes[0]?.id }, false);
    });
    $("exploration-kind").onchange = invoke(() =>
      load({ kind: $("exploration-kind").value }),
    );
    $("exploration-back").onclick = invoke(() => {
      const prev = history.pop() || {};
      return load(prev, false);
    });
    $("exploration-next").onclick = invoke(() =>
      load({ ...query, offset: graph.offset + graph.limit }),
    );
    $("exploration-home").onclick = invoke(async () => {
      const roots = await api("exploration?kind=scope");
      await load({ parent: roots.nodes[0]?.id });
    });
    $("exploration-refresh").onclick = invoke(() => load(query, false));
    $("exploration-zoom-in").onclick = () => {
      viewport.w *= 0.8;
      viewport.h *= 0.8;
      viewBox();
    };
    $("exploration-zoom-out").onclick = () => {
      viewport.w *= 1.25;
      viewport.h *= 1.25;
      viewBox();
    };
    $("exploration-export").onclick = invoke(() =>
      download(
        "static-exploration.json",
        JSON.stringify(
          { staticOnly: true, ...graph, selected, coverageComplete: false },
          null,
          2,
        ),
      ),
    );
    $("exploration-svg-export").onclick = invoke(() =>
      download("static-exploration.svg", svgExport(), "image/svg+xml"),
    );
    $("exploration-run").onclick = invoke(() =>
      callbacks.start(
        Number($("exploration-budget").value),
        $("exploration-consent").checked,
        {
          maxTokens: Number($("exploration-tokens").value),
          maxSteps: Number($("exploration-steps").value),
          maxDepth: Number($("exploration-depth").value),
          maxSeconds: Number($("exploration-seconds").value),
          retryFailed: $("exploration-retry").checked,
          includeScanner: $("exploration-scanner").checked,
        },
      ),
    );
    $("exploration-stop").onclick = invoke(() => callbacks.stop());
    const svg = $("exploration-svg");
    svg.onpointerdown = (e) => {
      if (e.target.closest("[data-node]")) return;
      drag = { x: e.clientX, y: e.clientY, v: { ...viewport } };
      svg.setPointerCapture(e.pointerId);
    };
    svg.onpointermove = (e) => {
      if (!drag) return;
      const box = svg.getBoundingClientRect();
      viewport.x = drag.v.x - ((e.clientX - drag.x) * viewport.w) / box.width;
      viewport.y = drag.v.y - ((e.clientY - drag.y) * viewport.h) / box.height;
      viewBox();
    };
    svg.onpointerup = () => (drag = null);
    $("exploration-minimap").onclick = (e) => {
      const box = e.currentTarget.getBoundingClientRect(),
        vb = e.currentTarget.viewBox.baseVal;
      viewport.x =
        ((e.clientX - box.x) / box.width) * vb.width - viewport.w / 2;
      viewport.y =
        ((e.clientY - box.y) / box.height) * vb.height - viewport.h / 2;
      viewBox();
    };
  }
  setup();
  $("exploration")
    .querySelectorAll("button,input,select")
    .forEach((el) => (el.disabled = true));
  window.SynthesisExploration = {
    async showIssue(issue) {
      const result = await api(
        "exploration?" + new URLSearchParams({ kind: "finding", issue }),
      );
      if (result.nodes[0]) await load({ focus: result.nodes[0].id });
    },
    setStatus(s) {
      available = Boolean(s.inference);
      busy = ["running", "cancelling"].includes(s.status);
      $("exploration-run").disabled = busy || !model || !s.inference;
      $("exploration-stop").hidden = !busy || s.mode !== "exploration";
    },
    render(m, cb) {
      model = m;
      callbacks = cb;
      api = cb.api;
      if (!m) return;
      $("exploration")
        .querySelectorAll("button,input,select")
        .forEach((el) => (el.disabled = false));
      $("exploration-back").disabled = !history.length;
      $("exploration-next").disabled = !graph?.omitted;
      $("exploration-run").disabled = busy || !available;
      const prior = $("exploration-snapshot").value;
      $("exploration-snapshot").innerHTML = (m.exploration?.revisions || [])
        .map(
          (r) =>
            `<option value="${esc(r.revision)}">${esc(r.revision.slice(0, 12))}${r.revision === m.modelRevision ? " · current" : " · previous"}</option>`,
        )
        .join("");
      $("exploration-snapshot").value = (m.exploration?.revisions || []).some(
        (r) => r.revision === prior,
      )
        ? prior
        : m.modelRevision;
      const next = JSON.stringify([m.modelRevision, m.exploration]);
      $("exploration-summary").textContent =
        `${m.sources.length} repositories · ${m.cweTargetCoverage?.targetCount || 29} requested weakness targets per repository · ${m.explorationRun?.status || "Ready to explore"}. Review gaps remain visible; no runtime testing.`;
      if (m.explorationRun?.mode === "graph-driven") {
        const r = m.explorationRun,
          f = r.frontier || {};
        $("exploration-summary").textContent +=
          ` ${f.done || 0} completed steps · ${f.queued || 0} queued · ${f.waiting || 0} waiting · ${f.blocked || 0} evidence gaps · ${f.failed || 0} failed. Stop: ${r.stopReason || "running"}. Tokens: ${r.reportedTokens || 0} reported / ${r.chargedTokens || 0} charged against this action budget; ${r.unknownUsageRequests || 0} requests with unknown usage.`;
      }
      if (next !== signature) {
        signature = next;
        if (!graph)
          invoke(async () => {
            const root = await api("exploration?kind=scope");
            await load({ parent: root.nodes[0]?.id }, false);
          })();
      }
    },
  };
})();
