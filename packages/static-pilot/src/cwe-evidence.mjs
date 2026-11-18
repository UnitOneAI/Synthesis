import { sourceWindow } from "./graph-package.mjs";

// Resolve only saved finding locations. The client cannot choose a filesystem path.
export async function cweEvidence(model, manifest, root, request) {
  if (!model || request.modelRevision !== model.modelRevision)
    throw Error(
      "Source snapshot changed. Refresh the review before opening code evidence.",
    );
  if (!["scanner", "model"].includes(request.origin))
    throw Error("Unknown finding origin.");
  const report =
    request.origin === "scanner" ? model.cweReview : model.cweModelReview;
  if (!report || report.basedOnRevision !== model.modelRevision)
    throw Error(
      "This finding belongs to an older source snapshot. Re-run its review before opening code evidence.",
    );
  const finding = report.findings.find((f) => f.id === request.id);
  if (!finding) throw Error("Finding is not available in this review.");
  if (finding.sourceMatchesGraph === false)
    throw Error(
      "Finding source does not match the saved graph. Rebuild and review the current source.",
    );
  const index = Number(request.location ?? 0),
    page = Number(request.page ?? 0);
  const locations = finding.locations || [finding];
  if (
    !Number.isInteger(index) ||
    index < 0 ||
    index >= locations.length ||
    !Number.isInteger(page) ||
    page < 0
  )
    throw Error("Invalid code evidence location or page.");
  const ref = locations[index],
    first = ref.line,
    last = ref.endLine || first;
  if (
    !Number.isInteger(first) ||
    !Number.isInteger(last) ||
    first < 1 ||
    last < first
  )
    throw Error("This finding has no valid cited line range.");
  const start = Math.max(1, first - 20) + page * 80;
  if (start > last) throw Error("No further cited lines in this finding.");
  try {
    const window = await sourceWindow(
      { ...ref, line: start + 20 },
      manifest,
      root,
    );
    if (last > window.endLine && window.lines.length < 80)
      throw Error("source-line-out-of-range");
    return {
      ...window,
      origin: request.origin,
      findingId: finding.id,
      location: index,
      page,
      citedStart: first,
      citedEnd: last,
      hasMore: window.endLine < last,
      sourceVerified: true,
      staticOnly: true,
      note: "Source matches the reviewed file. Highlighted lines are cited evidence, not confirmation of exploitability. Sensitive values are redacted where recognized.",
    };
  } catch (error) {
    if (/hash-mismatch|changed-during-read/.test(error.message))
      throw Error(
        "Source has changed since this finding was recorded. Rebuild and review the current source; the old code is not displayed.",
      );
    if (error.message === "local-source-unavailable")
      throw Error(
        "Code evidence requires the selected local clone on the Synthesis machine.",
      );
    throw Error(
      "Code evidence is unavailable or cannot be verified. Check that the unchanged local clone is present; source paths and symlinks must remain within the selected repository.",
    );
  }
}
