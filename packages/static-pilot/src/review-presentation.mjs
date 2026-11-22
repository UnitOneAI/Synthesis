import { sourceScope } from "./architecture.mjs";

// Display references never replace saved IDs or enter review fingerprints.
export function addReviewPresentation(s, model) {
  for (const [kind, prefix] of [
    ["threats", "T"],
    ["boundaries", "TB"],
    ["flows", "F"],
  ]) {
    const counts = new Map();
    for (const r of s[kind]) {
      const key = r.id.slice(0, 8).toUpperCase();
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    for (const r of s[kind])
      r.reference = `${prefix}-${(counts.get(r.id.slice(0, 8).toUpperCase()) > 1 ? r.id : r.id.slice(0, 8)).toUpperCase()}`;
  }
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const interfaces = new Map((model.interfaces || []).map((i) => [i.id, i]));
  const nodes = new Map([...s.components, ...s.entities].map((n) => [n.id, n]));
  const flows = new Map(s.flows.map((f) => [f.id, f]));
  for (const b of s.boundaries)
    b.crossings = (b.flowIds || [])
      .map((id) => flows.get(id))
      .filter(Boolean)
      .map((f) => ({
        id: f.id,
        reference: f.reference,
        from: nodes.get(f.source)?.name || f.source,
        to: nodes.get(f.target)?.name || f.target,
        basis: f.basis,
        reviewState: f.reviewState,
      }));
  for (const t of s.threats) {
    if (t.origin === "review checklist") continue;
    const refs = (t.evidenceIds || [])
      .map((id) => evidence.get(id))
      .filter(Boolean);
    const scopes = [...new Set(refs.map((e) => sourceScope(e.path)))];
    t.sourceScopes = scopes;
    t.metadataOnly = Boolean(
      t.interfaceIds?.length &&
        t.interfaceIds.every(
          (id) =>
            interfaces.get(id)?.kind === "architecture" &&
            interfaces.get(id)?.connection?.role !== "symbol-call",
        ),
    );
    t.boundaryLinkBasis = t.candidateFlowIds?.length
      ? "Candidate boundaries associated through shared interfaces. Some flow peers remain unresolved; access, crossing relevance and enforcement are assumptions requiring review."
      : "Boundaries associated through shared interfaces; verify relevance to this scenario.";
    const reasons = [];
    let rank = 3,
      label = "Establish context";
    const severity = !t.decision?.stale ? t.decision?.severity : null;
    if (t.reviewState === "stale") {
      rank = 5;
      label = "Revalidate";
      reasons.push("The source or review decision is stale.");
    } else if (
      ["rejected", "not-applicable", "risk-accepted"].includes(t.reviewState)
    ) {
      rank = 5;
      label = "Decision recorded";
      reasons.push(`Reviewer disposition: ${t.reviewState}.`);
    } else if (
      scopes.length &&
      scopes.every((x) => x !== "production-candidate")
    ) {
      rank = 4;
      label = "Verify applicability";
      reasons.push(
        "Citations are confined to test or generated/vendor code; establish deployment applicability.",
      );
    } else if (severity && severity !== "unassessed") {
      rank = ["high", "critical"].includes(severity)
        ? 0
        : severity === "medium"
          ? 2
          : 3;
      label = rank === 0 ? "Review first" : "Review next";
      reasons.push(`Reviewer-assessed severity: ${severity}.`);
    } else if (t.metadataOnly) {
      rank = 3;
      label = "Establish code path";
      reasons.push(
        "Citations support architecture or import references only; the claimed implementation and caller path are not established.",
      );
    } else if (scopes.includes("production-candidate")) {
      const authority = t.categories.some((c) =>
        ["Spoofing", "Elevation of Privilege"].includes(c),
      );
      rank = authority ? 1 : 2;
      label = authority ? "Review first" : "Review next";
      reasons.push(
        "Citations include production-candidate source; deployed exposure is unverified.",
      );
      reasons.push(
        authority
          ? "The scenario concerns identity or privilege misuse."
          : "Assess the stated impact and prerequisites against effective controls.",
      );
    } else reasons.push("No usable source citations establish applicability.");
    t.reviewPriority = {
      rank,
      label,
      reasons,
      interpretation:
        "Review order, not a vulnerability severity or confirmation of exploitability.",
    };
    t.evidenceStatus = t.metadataOnly
      ? "Architecture references only; implementation path unverified"
      : t.analysisQuality?.status === "incomplete"
        ? "Limited analysis context"
        : "Source-referenced scenario; exploitability unverified";
  }
  const review = model.aiReview,
    coverage = review?.coverage;
  s.analysisStatus = {
    state:
      review?.status === "stale"
        ? "stale"
        : !review
          ? "not-analyzed"
          : coverage?.completedBatches
            ? coverage.pendingBatches || coverage.failedBatches
              ? "partially-analyzed"
              : "analyzed"
            : review.status === "failed"
              ? "failed"
              : "not-analyzed",
    completed: coverage?.completedBatches || 0,
    pending: coverage?.pendingBatches || 0,
    failed: coverage?.failedBatches || 0,
    total: coverage?.totalBatches || 0,
  };
  const failed = new Set(
    (review?.batches || [])
      .filter((b) => b.status === "failed")
      .flatMap((b) => b.interfaceIds || []),
  );
  const threatById = new Map(s.threats.map((t) => [t.id, t]));
  for (const row of s.matrix || [])
    for (const cell of row.cells) {
      const hasFailed = row.interfaceIds.some((id) => failed.has(id));
      cell.analysisStatus =
        review?.status === "stale"
          ? "stale"
          : row.interfaceIds.length &&
              row.reviewedInterfaces === row.interfaceIds.length
            ? cell.scenarioCount
              ? "scenarios-identified"
              : "analyzed-no-scenario"
            : row.reviewedInterfaces
              ? "partially-analyzed"
              : hasFailed
                ? "failed"
                : "not-analyzed";
      cell.analysisLabel = {
        stale: "Stale analysis",
        "scenarios-identified": "Scenarios identified",
        "analyzed-no-scenario": "Analyzed — no scenario identified",
        "partially-analyzed": "Partially analyzed",
        failed: "Analysis failed",
        "not-analyzed": "Not analyzed",
      }[cell.analysisStatus];
      cell.failedEvidence = hasFailed;
      cell.scenarioReferences = cell.threatIds
        .map((id) => threatById.get(id))
        .filter((t) => t && t.origin !== "review checklist")
        .map((t) => t.reference);
    }
  return s;
}
