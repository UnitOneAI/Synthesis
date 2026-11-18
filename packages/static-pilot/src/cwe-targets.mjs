import fs from "node:fs";
import { sha } from "./sources.mjs";
export const CWE_PROFILE = JSON.parse(
  fs.readFileSync(
    new URL("../rules/server-weakness-profile.json", import.meta.url),
    "utf8",
  ),
);
export const CWE_MAPPING = JSON.parse(
  fs.readFileSync(
    new URL("../rules/cwe-mapping-status.json", import.meta.url),
    "utf8",
  ),
);
export const cweMapping = (cwe) => CWE_MAPPING.entries[cwe];
export const cweFindingAllowed = (cwe) => {
  const entry = cweMapping(cwe);
  return (
    entry?.kind === "Weakness" &&
    entry.status !== "Deprecated" &&
    entry.mappingUsage !== "Prohibited"
  );
};
export const CWE_PROFILE_HASH = sha(JSON.stringify([CWE_PROFILE, CWE_MAPPING]));
export const CODE_TARGETS = CWE_PROFILE.targets.filter(
  (t) => t.mode === "code-review",
);
export const TARGET_CWES = [
  ...new Set(CODE_TARGETS.flatMap((t) => t.findingCwes)),
];
const ruleText = fs.readFileSync(
  new URL("../rules/cwe-v2.json", import.meta.url),
  "utf8",
);
const rules = JSON.parse(ruleText).rules;
export const CURRENT_CWE_RULE_HASH = sha(ruleText);
const direct = (target, cwe) => target.findingCwes.includes(cwe);
const belongs = (target, f) =>
  Array.isArray(f.targetIds)
    ? f.targetIds.includes(target.id) && direct(target, f.cwe)
    : direct(target, f.cwe) &&
      CWE_PROFILE.targets.filter((t) => direct(t, f.cwe)).length === 1;
export function cweTargetCoverage(model) {
  const scan = model.cweReview,
    review = model.cweModelReview;
  const freshScan = Boolean(
    scan && scan.basedOnRevision === model.modelRevision,
  );
  const freshReview =
    review &&
    review.basedOnRevision === model.modelRevision &&
    review.targetProfileHash === CWE_PROFILE_HASH;
  const repos = model.sources?.map((r) => r.name) || [];
  const allFindings = [
    ...(freshScan ? scan.findings || [] : []),
    ...(review && review.basedOnRevision === model.modelRevision
      ? review.findings || []
      : []),
  ];
  const rows = [];
  for (const repository of repos)
    for (const target of CWE_PROFILE.targets) {
      const applicable = rules.filter((r) =>
        r.metadata.targetIds?.includes(target.id),
      );
      const scanned = scan?.repositories?.find((r) => r.name === repository);
      const ruleStatus = !applicable.length
        ? "no-dedicated-rule"
        : !scan
          ? "not-run"
          : !freshScan
            ? "stale"
            : scan.rulePack?.sha256 !== CURRENT_CWE_RULE_HASH
              ? "outdated-rule-pack"
              : !scanned
                ? "not-run"
                : scanned.languages?.length &&
                    !applicable.some((rule) =>
                      rule.languages.some((l) => scanned.languages.includes(l)),
                    )
                  ? "no-applicable-collected-language"
                  : scanned.status === "completed" &&
                      scanned.matchesGraphSnapshot
                    ? "patterns-reviewed"
                    : "partial-or-failed";
      const planned =
        review?.repositories?.find((r) => r.name === repository)
          ?.plannedBatches || 0;
      const batches = freshReview
        ? (review.batches || []).filter(
            (b) =>
              b.status === "completed" && b.repositories.includes(repository),
          )
        : [];
      const acknowledgements = batches.flatMap((b) =>
        (b.targetReviews || []).filter((r) => r.targetId === target.id),
      );
      const context = acknowledgements.filter(
        (a) => a.status === "needs-context",
      ).length;
      const relevant = acknowledgements.filter(
        (a) => a.status === "reviewed",
      ).length;
      const modelStatus =
        target.mode === "additional-evidence"
          ? "additional-evidence-required"
          : !review
            ? "not-run"
            : !freshReview
              ? "stale-or-prior-profile"
              : !acknowledgements.length
                ? "not-reviewed"
                : acknowledgements.length < planned ||
                    review.gaps?.length ||
                    review.status !== "completed-needs-review"
                  ? "partial"
                  : context
                    ? "needs-context"
                    : relevant
                      ? "reviewed-scope"
                      : "no-relevant-evidence-in-reviewed-scope";
      const findings = allFindings.filter(
        (f) =>
          belongs(target, f) &&
          (f.repository === repository ||
            f.locations?.some((l) => l.repository === repository)),
      );
      rows.push({
        repository,
        targetId: target.id,
        name: target.name,
        requestedCwes: target.requestedCwes,
        findingCwes: target.findingCwes,
        mappingNote: target.mappingNote,
        ruleIds: applicable.map((r) => r.id),
        scannerStatus: ruleStatus,
        scannerLanguages: [...new Set(applicable.flatMap((r) => r.languages))],
        modelStatus,
        reviewedPackets: acknowledgements.length,
        plannedPackets: planned,
        needsContextPackets: context,
        findingIds: findings.map((f) => f.id),
        potentialFindings: findings.filter((f) => f.status !== "false-positive")
          .length,
        dismissedFindings: findings.filter((f) => f.status === "false-positive")
          .length,
        limitations: target.guidance,
      });
    }
  return {
    profile: CWE_PROFILE.id,
    profileHash: CWE_PROFILE_HASH,
    requestedIdentifierCount: new Set(
      CWE_PROFILE.targets.flatMap((t) => t.requestedCwes),
    ).size,
    targetCount: CWE_PROFILE.targets.length,
    basedOnRevision: model.modelRevision,
    rows,
    additionalFindings: allFindings
      .filter((f) => !CWE_PROFILE.targets.some((t) => belongs(t, f)))
      .map((f) => ({
        id: f.id,
        cwe: f.cwe,
        status: f.status,
        repository: f.repository,
        locations: f.locations,
      })),
    interpretation:
      "Coverage describes performed checks in collected source. No findings is not proof of absence. Grouping IDs and deprecated entries are report references, not vulnerability mappings.",
  };
}
export function cweTargetCsv(coverage) {
  const columns = [
    "repository",
    "targetId",
    "name",
    "requestedCwes",
    "findingCwes",
    "scannerStatus",
    "ruleIds",
    "scannerLanguages",
    "modelStatus",
    "reviewedPackets",
    "plannedPackets",
    "needsContextPackets",
    "potentialFindings",
    "dismissedFindings",
    "findingIds",
    "mappingNote",
    "limitations",
  ];
  const cell = (v) =>
    '"' +
    String(Array.isArray(v) ? v.join("; ") : (v ?? ""))
      .replace(/^[\t\r\n=+@-]/, "'$&")
      .replaceAll('"', '""') +
    '"';
  return [
    columns.join(","),
    ...coverage.rows.map((r) => columns.map((c) => cell(r[c])).join(",")),
  ].join("\r\n");
}
