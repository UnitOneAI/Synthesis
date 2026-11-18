import test from "node:test";
import assert from "node:assert/strict";
import {
  CWE_PROFILE,
  CWE_PROFILE_HASH,
  CODE_TARGETS,
  TARGET_CWES,
  CURRENT_CWE_RULE_HASH,
  cweTargetCoverage,
  cweTargetCsv,
} from "../src/cwe-targets.mjs";
import { validateCweModel } from "../src/cwe-model.mjs";
const packet = {
  targets: CODE_TARGETS,
  records: [
    {
      id: "a",
      repository: "one",
      path: "source.cs",
      blobSha256: "hash",
      startLine: 2,
      endLine: 9,
    },
    {
      id: "b",
      repository: "two",
      path: "source.cs",
      blobSha256: "hash2",
      startLine: 3,
      endLine: 10,
    },
  ],
};
const response = () => ({
  findings: [],
  limitations: [],
  targetReviews: CODE_TARGETS.map((t) => ({
    targetId: t.id,
    status: "needs-context",
    rationale: "Caller control must be resolved before a finding.",
    locations: packet.records.map((r) => ({
      recordId: r.id,
      startLine: r.startLine,
      endLine: r.startLine,
    })),
  })),
});
const model = () => ({
  modelRevision: "rev",
  sources: [{ name: "one" }, { name: "two" }],
  cweReview: {
    basedOnRevision: "rev",
    rulePack: { sha256: CURRENT_CWE_RULE_HASH },
    repositories: [
      {
        name: "one",
        status: "completed",
        matchesGraphSnapshot: true,
        languages: ["csharp"],
      },
    ],
    findings: [
      {
        id: "sql",
        repository: "one",
        cwe: "CWE-89",
        targetIds: ["server-19"],
        status: "needs-review",
      },
      {
        id: "tls",
        repository: "one",
        cwe: "CWE-295",
        targetIds: [],
        status: "needs-review",
      },
    ],
  },
});
test("requested profile preserves all 29 areas and 52 original identifiers without emitting grouping or deprecated IDs", () => {
  assert.equal(CWE_PROFILE.targets.length, 29);
  assert.equal(CODE_TARGETS.length, 25);
  assert.equal(
    new Set(CWE_PROFILE.targets.flatMap((t) => t.requestedCwes)).size,
    52,
  );
  for (const id of [545, 633, 1436, 1437, 1438, 1439, 1440, 1441, 1443, 1444])
    assert.ok(!TARGET_CWES.includes(`CWE-${id}`));
  assert.ok(TARGET_CWES.includes("CWE-470"));
  assert.ok(TARGET_CWES.includes("CWE-1021"));
});
test("model target acknowledgements require every target, valid citations and every repository; they are not confirmed findings", () => {
  const valid = validateCweModel(response(), packet);
  assert.equal(valid.targetReviews.length, 25);
  assert.equal(valid.targetReviews[0].locations[1].repository, "two");
  assert.equal(
    valid.targetReviews[0].locations[0].sourceScope,
    "production-candidate",
  );
  const variants = [
    (r) => delete r.targetReviews,
    (r) => r.targetReviews.pop(),
    (r) => r.targetReviews.push(r.targetReviews[0]),
    (r) => (r.targetReviews[1].targetId = r.targetReviews[0].targetId),
    (r) => (r.targetReviews[0].status = "passed"),
    (r) => r.targetReviews[0].locations.pop(),
    (r) => (r.targetReviews[0].locations[0].recordId = "invented"),
    (r) => (r.targetReviews[0].locations[0].endLine = 100),
    (r) => (r.targetReviews[0].rationale = ""),
  ];
  for (const mutate of variants) {
    const r = response();
    mutate(r);
    assert.throws(() => validateCweModel(r, packet), /validation/);
  }
});
test("finding mappings reject grouping IDs and incompatible target assignments", () => {
  const base = {
    cwe: "CWE-89",
    targetIds: ["server-19"],
    title: "Query",
    explanation: "Input reaches SQL structure.",
    preconditions: "Untrusted caller reaches function.",
    counterEvidence: "Caller checks not established.",
    remediation: "Use parameters.",
    locations: [{ recordId: "a", startLine: 2, endLine: 3 }],
  };
  let r = response();
  r.findings = [base];
  assert.equal(validateCweModel(r, packet).findings[0].status, "needs-review");
  for (const cwe of ["CWE-1436", "CWE-545", "CWE-633", "CWE-613", "CWE-377"]) {
    r = response();
    r.findings = [{ ...base, cwe }];
    assert.throws(() => validateCweModel(r, packet), /validation/);
  }
  r = response();
  r.findings = [{ ...base, targetIds: ["server-09"] }];
  assert.throws(() => validateCweModel(r, packet), /validation/);
  r = response();
  r.findings = [{ ...base, cwe: "CWE-295", targetIds: [] }];
  assert.equal(validateCweModel(r, packet).findings[0].cwe, "CWE-295");
});
test("coverage never promotes scanner success, old model output, or partial review into completed target coverage", () => {
  const m = model();
  let c = cweTargetCoverage(m);
  const row = () =>
    c.rows.find((r) => r.repository === "one" && r.targetId === "server-19");
  assert.equal(c.rows.length, 58);
  assert.equal(row().scannerStatus, "patterns-reviewed");
  assert.equal(row().modelStatus, "not-run");
  assert.equal(row().potentialFindings, 1);
  assert.equal(c.additionalFindings[0].id, "tls");
  assert.equal(
    c.rows.find((r) => r.targetId === "server-01").modelStatus,
    "additional-evidence-required",
  );
  m.cweModelReview = {
    basedOnRevision: "rev",
    targetProfileHash: "old",
    batches: [],
    repositories: [],
    findings: [],
  };
  c = cweTargetCoverage(m);
  assert.equal(row().modelStatus, "stale-or-prior-profile");
  m.cweModelReview = {
    basedOnRevision: "rev",
    targetProfileHash: CWE_PROFILE_HASH,
    status: "partial",
    gaps: [],
    repositories: [{ name: "one", plannedBatches: 2 }],
    batches: [
      {
        status: "completed",
        repositories: ["one", "two"],
        targetReviews: validateCweModel(response(), packet).targetReviews,
      },
    ],
    findings: [],
  };
  c = cweTargetCoverage(m);
  assert.equal(row().modelStatus, "partial");
  assert.equal(row().reviewedPackets, 1);
  m.cweModelReview.repositories[0].plannedBatches = 1;
  m.cweModelReview.status = "completed-needs-review";
  c = cweTargetCoverage(m);
  assert.equal(row().modelStatus, "needs-context");
  m.cweModelReview.batches[0].targetReviews.forEach(
    (r) => (r.status = "not-applicable-to-packet"),
  );
  c = cweTargetCoverage(m);
  assert.equal(row().modelStatus, "no-relevant-evidence-in-reviewed-scope");
  m.cweModelReview.gaps.push({ reason: "unresolved-graph-relationships" });
  c = cweTargetCoverage(m);
  assert.equal(row().modelStatus, "partial");
  m.cweReview.rulePack.sha256 = "old";
  c = cweTargetCoverage(m);
  assert.equal(row().scannerStatus, "outdated-rule-pack");
  m.modelRevision = "new";
  c = cweTargetCoverage(m);
  assert.equal(row().scannerStatus, "stale");
  assert.equal(row().potentialFindings, 0);
});
test("ambiguous CWE identifiers do not attach findings to unrelated areas; exports resist spreadsheet formulas", () => {
  const m = model();
  m.cweReview.findings.push({
    id: "encrypt",
    repository: "one",
    cwe: "CWE-311",
    targetIds: ["server-04"],
    status: "needs-review",
  });
  const c = cweTargetCoverage(m);
  assert.equal(
    c.rows.find((r) => r.repository === "one" && r.targetId === "server-08")
      .potentialFindings,
    0,
  );
  assert.equal(
    c.rows.find((r) => r.repository === "one" && r.targetId === "server-04")
      .potentialFindings,
    1,
  );
  c.rows[0].repository = '=HYPERLINK("https://example.invalid")';
  assert.match(cweTargetCsv(c), /"'=HYPERLINK/);
});

test("current JWT signature mapping is accepted and broad mappings require refinement", () => {
  const base = {
    targetIds: ["server-08"],
    title: "Signature validation",
    explanation: "Signature verification is bypassed.",
    preconditions: "Untrusted token used for authorization.",
    counterEvidence: "Other validation remains unresolved.",
    remediation: "Verify the signature.",
    locations: [{ recordId: "a", startLine: 2, endLine: 3 }],
  };
  const r = response();
  r.findings = [{ ...base, cwe: "CWE-347" }];
  assert.equal(validateCweModel(r, packet).findings[0].mappingUsage, "Allowed");
  r.findings = [{ ...base, cwe: "CWE-20", targetIds: ["server-05"] }];
  assert.equal(
    validateCweModel(r, packet).findings[0].mappingStatus,
    "needs-more-specific-mapping",
  );
});

test("valid additional weaknesses outside both the requested profile and curated families are accepted", () => {
  const r = response();
  r.findings = [
    {
      cwe: "CWE-732",
      targetIds: [],
      title: "Resource permissions",
      explanation: "The resource is created with permissive access.",
      preconditions: "An unauthorized principal can access this resource.",
      counterEvidence: "Effective deployment permissions remain unresolved.",
      remediation: "Restrict permissions to intended principals.",
      locations: [{ recordId: "a", startLine: 2, endLine: 3 }],
    },
  ];
  assert.equal(validateCweModel(r, packet).findings[0].cwe, "CWE-732");
  r.findings[0].cwe = "CWE-999999";
  assert.throws(() => validateCweModel(r, packet), /validation/);
});
