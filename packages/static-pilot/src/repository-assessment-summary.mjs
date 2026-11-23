export const REPOSITORY_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];
export function repositoryAssessmentSummary(review) {
  if (review?.scope?.poc?.kind !== "repositories") return null;
  const stale = review.status === "stale",
    rows = REPOSITORY_CATEGORIES.map((category) => ({
      category,
      conclusive: 0,
      gaps: 0,
      pending: 0,
      failed: 0,
      supported: 0,
      ruledOut: 0,
      noScenario: 0,
      total: review.coverage?.totalBatches || review.batches?.length || 0,
    }));
  for (const row of rows) {
    for (const b of review.batches || []) {
      const c =
        !stale &&
        b.status === "completed" &&
        b.review?.categoryReviews?.find((c) => c.category === row.category);
      if (c) {
        if (c.status === "evidence-gap") row.gaps++;
        else {
          row.conclusive++;
          if (c.status === "supported-conditional") row.supported++;
          else if (c.status === "ruled-out") row.ruledOut++;
          else if (c.status === "no-scenario-identified") row.noScenario++;
        }
      } else if (!stale && b.status === "failed") row.failed++;
    }
    row.pending = Math.max(
      0,
      row.total - row.conclusive - row.gaps - row.failed,
    );
  }
  const inventory = review.scope.repositoryInventory;
  return {
    rows,
    stale,
    inventory,
    complete:
      rows.every((r) => r.total > 0 && !r.pending && !r.failed && !r.gaps) &&
      inventory?.gaps?.length === 0,
    interpretation:
      "Category conclusions are model source assessments, not independent validation or deployment approval. File, parser and retrieval gaps remain incomplete. Supporting repositories are evidence context, not fully reviewed repositories.",
  };
}
