import test from "node:test";
import assert from "node:assert/strict";
import { addReviewPresentation } from "../src/review-presentation.mjs";
function fixture() {
  return {
    s: {
      components: [{ id: "api", name: "API" }],
      entities: [{ id: "client", name: "Client" }],
      flows: [
        {
          id: "f123456789",
          source: "client",
          target: "api",
          basis: "inference",
          reviewState: "pending",
        },
      ],
      boundaries: [
        {
          id: "b123456789",
          flowIds: ["f123456789"],
          before: "Caller",
          after: "Application",
        },
      ],
      threats: [
        {
          id: "a123456789",
          origin: "analysis",
          categories: ["Elevation of Privilege"],
          evidenceIds: ["e1"],
          reviewState: "pending",
        },
        {
          id: "c123456789",
          origin: "analysis",
          categories: ["Elevation of Privilege"],
          evidenceIds: ["e2"],
          reviewState: "pending",
        },
      ],
      matrix: [
        {
          interfaceIds: ["i1"],
          reviewedInterfaces: 0,
          cells: [{ state: "not-analyzed", scenarioCount: 0, threatIds: [] }],
        },
      ],
    },
    m: {
      evidence: [
        { id: "e1", path: "src/auth.py" },
        { id: "e2", path: "tests/fixture.py" },
      ],
    },
  };
}
test("references preserve saved IDs and connect boundary crossings with explained review priority", () => {
  const { s, m } = fixture();
  addReviewPresentation(s, m);
  assert.equal(s.threats[0].id, "a123456789");
  assert.equal(s.threats[0].reference, "T-A1234567");
  assert.equal(s.boundaries[0].crossings[0].reference, "F-F1234567");
  assert.equal(s.boundaries[0].crossings[0].from, "Client");
  assert.equal(s.threats[0].reviewPriority.label, "Review first");
  assert.equal(s.threats[1].reviewPriority.label, "Verify applicability");
  assert.ok(
    s.threats[0].reviewPriority.reasons.some((r) => r.includes("unverified")),
  );
  const before = s.threats[0].reference;
  s.threats.reverse();
  addReviewPresentation(s, m);
  assert.equal(s.threats[1].reference, before);
});
test("STRIDE separates failed, partial, unanalyzed, completed-empty and scenario-bearing cells from reviewer decisions", () => {
  const { s, m } = fixture();
  const cell = s.matrix[0].cells[0];
  addReviewPresentation(s, m);
  assert.equal(cell.analysisStatus, "not-analyzed");
  m.aiReview = {
    status: "failed",
    batches: [{ status: "failed", interfaceIds: ["i1"] }],
  };
  addReviewPresentation(s, m);
  assert.equal(cell.analysisStatus, "failed");
  s.matrix[0].interfaceIds.push("i2");
  s.matrix[0].reviewedInterfaces = 1;
  addReviewPresentation(s, m);
  assert.equal(cell.analysisStatus, "partially-analyzed");
  s.matrix[0].reviewedInterfaces = 2;
  addReviewPresentation(s, m);
  assert.equal(cell.analysisStatus, "analyzed-no-scenario");
  cell.scenarioCount = 1;
  cell.threatIds = ["a123456789"];
  cell.state = "accepted";
  cell.decision = { state: "accepted" };
  addReviewPresentation(s, m);
  assert.equal(cell.analysisStatus, "scenarios-identified");
  assert.equal(cell.state, "accepted");
  assert.deepEqual(cell.scenarioReferences, ["T-A1234567"]);
  m.aiReview.status = "stale";
  addReviewPresentation(s, m);
  assert.equal(cell.analysisStatus, "stale");
});

test("architecture-only threats require a code path before implementation claims", () => {
  const { s, m } = fixture();
  m.interfaces = [{ id: "import", kind: "architecture" }];
  s.threats[0].interfaceIds = ["import"];
  addReviewPresentation(s, m);
  assert.equal(s.threats[0].reviewPriority.label, "Establish code path");
  assert.match(s.threats[0].evidenceStatus, /implementation path unverified/);
  assert.equal(s.threats[0].sourceScopes[0], "production-candidate");
  m.interfaces[0].connection = { role: "symbol-call" };
  addReviewPresentation(s, m);
  assert.equal(s.threats[0].metadataOnly, false);
  assert.match(s.threats[0].evidenceStatus, /exploitability unverified/);
});

test("short reference collisions expand without altering original record IDs", () => {
  const { s, m } = fixture();
  s.threats.push({ ...s.threats[0], id: "a1234567different" });
  addReviewPresentation(s, m);
  assert.equal(s.threats[0].reference, "T-A123456789");
  assert.equal(s.threats[2].reference, "T-A1234567DIFFERENT");
});


test('matrix labels and counts use the same source scenarios, separating architecture questions', () => {
 const {s,m}=fixture();m.interfaces=[{id:'architecture',kind:'architecture'},{id:'code',kind:'http-route'}];
 m.aiReview={status:'partial',mode:'source-excerpts',batches:[],coverage:{completedBatches:1}};
 s.threats[0].interfaceIds=['architecture'];s.threats[1].interfaceIds=['code'];
 s.matrix[0].reviewedInterfaces=1;s.matrix[0].cells[0].threatIds=[s.threats[0].id];
 addReviewPresentation(s,m);let c=s.matrix[0].cells[0];
 assert.equal(c.scenarioCount,0);assert.equal(c.questionCount,1);assert.equal(c.analysisStatus,'context-required');
 c.threatIds.push(s.threats[1].id);addReviewPresentation(s,m);
 assert.equal(c.scenarioCount,1);assert.equal(c.questionCount,1);assert.equal(c.analysisStatus,'scenarios-identified');
 assert.deepEqual(c.scenarioReferences,[s.threats[1].reference]);
});
