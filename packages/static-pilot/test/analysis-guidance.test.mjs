import test from "node:test";
import assert from "node:assert/strict";
import {
  analysisGuidance,
  GUIDANCE_HASH,
  GUIDANCE_VERSION,
  assessRisk,
  RISK_FACTORS,
} from "../src/analysis-guidance.mjs";
import {
  reviewPacket,
  validateReview,
  SYSTEM_PROMPT,
} from "../src/model-review.mjs";
import { systemModel } from "../src/system-model.mjs";
import { systemReport, registerCsv } from "../src/system-exports.mjs";
import { analyze } from "../src/engine.mjs";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(
  new URL("../fixtures/repositories", import.meta.url),
);
async function fixture() {
  return analyze(
    {
      profile: "test",
      repositories: [
        { name: "frontdoor" },
        { name: "business" },
        { name: "setup" },
      ],
    },
    { sourceRoot: root },
  );
}
test("bundled methodology preserves STRIDE, actor and control review and selects evidence-relevant domain checks", () => {
  const g = analysisGuidance([
    { protocol: "HTTP", evidence: [{ path: "Controller.cs" }] },
    { protocol: "messaging" },
    { protocol: "installation" },
  ]);
  assert.equal(g.hash, GUIDANCE_HASH);
  assert.equal(g.version, GUIDANCE_VERSION);
  for (const id of [
    "actor-access",
    "authority-transition",
    "stride-per-element",
    "control-counterevidence",
    "attack-chain",
    "api-authorization",
    "dotnet-controls",
    "messaging",
    "installation-privilege",
  ])
    assert.ok(
      g.checks.some((c) => c.id === id),
      id,
    );
  assert.ok(!g.checks.some((c) => c.id === "device-boundary"));
  assert.ok(
    SYSTEM_PROMPT.includes(
      "Never fill missing OWASP risk factors with defaults",
    ),
  );
  assert.ok(
    g.sources.some(
      (s) => s.revision === "70bc259bb01abb3015ad2ad859ad5253cbf0bcab",
    ),
  );
});
test("structured reasoning retains taxonomy rationale in UI projection and exports, rejects invented references", async () => {
  const model = await fixture(),
    packet = reviewPacket(model),
    record = packet.records[0];
  packet.systemContext = { boundaries: [{ id: "declared-boundary" }] };
  const value = {
    summary: "Conditional assessment.",
    connections: [],
    questions: [],
    threats: [
      {
        title: "Conditional unauthorized operation",
        category: "Elevation of Privilege",
        actor: "Authenticated caller",
        startingAccess: "Assumed valid account",
        asset: "Operation authority",
        scenario:
          "If object authorization is missing, a caller could alter another account.",
        prerequisites: "Confirm object ownership checks on the call path.",
        controls: "Enforcement is not established.",
        mitigation: "Verify object-level checks before data modification.",
        interfaceIds: [record.id],
        evidenceIds: [record.evidence[0].id],
        analysis: {
          attackSteps: [
            "Use an assumed valid account",
            "Attempt an operation on another owner’s object",
          ],
          impact: "Unauthorized modification if checks are absent.",
          assumptions: ["The interface is active in the selected profile."],
          controlEvidenceIds: [],
          boundaryIds: ["declared-boundary"],
          mappings: [
            {
              framework: "OWASP Web 2021",
              id: "A01:2021",
              rationale:
                "The conditional failure concerns object access authorization.",
            },
          ],
        },
      },
    ],
  };
  const review = validateReview(value, packet);
  assert.equal(review.threats[0].severity, "unassessed");
  assert.equal(review.threats[0].analysis.mappings[0].status, "proposed");
  model.aiReview = { ...review, status: "partial" };
  assert.equal(
    systemModel(model).threats.find((t) => t.origin === "analysis").analysis
      .mappings[0].id,
    "A01:2021",
  );
  assert.ok(systemReport(model).includes("A01:2021"));
  assert.ok(registerCsv(model, "threats").includes("A01:2021"));
  for (const mutate of [
    (v) => (v.threats[0].analysis.mappings[0].id = "A99:2021"),
    (v) => (v.threats[0].analysis.boundaryIds = ["fabricated"]),
    (v) => (v.threats[0].analysis.controlEvidenceIds = [record.evidence[0].id]),
  ]) {
    const bad = structuredClone(value);
    mutate(bad);
    assert.throws(() => validateReview(bad, packet), /validation/);
  }
  const legacy = structuredClone(value);
  delete legacy.threats[0].analysis;
  assert.equal(
    validateReview(legacy, packet).threats[0].analysisQuality.status,
    "incomplete",
  );
});
test("OWASP risk retains unknown factors and calculates the existing technical-risk matrix only from complete input", () => {
  assert.equal(assessRisk().status, "unassessed");
  assert.equal(assessRisk().missing.length, 12);
  const factors = Object.fromEntries(
    Object.entries(RISK_FACTORS).map(([g, keys]) => [
      g,
      Object.fromEntries(keys.map((k) => [k, 7])),
    ]),
  );
  assert.equal(assessRisk(factors).severity, "critical");
  factors.likelihood.skillLevel = null;
  assert.equal(assessRisk(factors).status, "unassessed");
  factors.likelihood.skillLevel = 99;
  assert.throws(() => assessRisk(factors), /0 to 9/);
});
test("reviewer risk assessment computes severity on the server and becomes stale with evidence", async () => {
  const { editSystem } = await import("../src/system-model.mjs");
  const model = await fixture(),
    system = systemModel(model);
  const input = {
    action: "decision",
    revision: system.revision,
    subjectId: system.threats[0].id,
    state: "needs-investigation",
    reviewer: "Security champion",
    rationale:
      "Conditional risk estimate; confirm the specified prerequisites.",
    severity: "low",
    riskFactors: Object.fromEntries(
      Object.entries(RISK_FACTORS).map(([g, keys]) => [
        g,
        Object.fromEntries(keys.map((k) => [k, 7])),
      ]),
    ),
  };
  const assessed = editSystem(model, input);
  assert.equal(assessed.architecture.decisions[0].severity, "critical");
  assert.equal(
    assessed.architecture.decisions[0].riskAssessment.basis,
    "reviewer estimate",
  );
  const partial = editSystem(model, {
    ...input,
    severity: "critical",
    riskFactors: { likelihood: { skillLevel: 7 } },
  });
  assert.equal(partial.architecture.decisions[0].severity, "unassessed");
  assessed.sources[0].snapshot = "changed";
  assert.equal(
    systemModel(assessed).threats.find((t) => t.id === input.subjectId).decision
      .stale,
    true,
  );
});
