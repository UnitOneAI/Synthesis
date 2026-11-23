import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { analyze } from "../src/engine.mjs";
import { reviewPlan, enrichGraphModel } from "../src/graph-review.mjs";
import { modelConfig } from "../src/model-review.mjs";
import {
  verifiedStrideSource,
  prepareStrideEvidence,
  STRIDE_EVIDENCE_VERSION,
  validateStrideInvestigation,
} from "../src/stride-evidence.mjs";
import {
  ASVS_PROFILE,
  analysisGuidance,
  TAXONOMY,
} from "../src/analysis-guidance.mjs";
import { validateReview } from "../src/model-review.mjs";

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "stride-source-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "service"));
  await fs.writeFile(
    path.join(root, "service", "app.py"),
    "from flask import Flask\napp = Flask(__name__)\n@app.get('/backup')\ndef backup():\n    return authorize_request()\n",
  );
  const manifest = { profile: "fixture", repositories: [{ name: "service" }] };
  return {
    root,
    manifest,
    model: await analyze(manifest, { sourceRoot: root }),
  };
}
const response = () => ({
  summary: "Static review",
  threats: [],
  connections: [],
  questions: [],
});
test("saved STRIDE graph retrieves current hashed code, retains gaps, and never persists source text", async (t) => {
  const { root, model, manifest } = await fixture(t);
  const source = await verifiedStrideSource(model, manifest, root);
  const plan = reviewPlan(model);
  assert.ok(plan.batches.length);
  const prepared = await prepareStrideEvidence(plan.batches[0].packet, source);
  assert.ok(
    prepared.packet.sourceContext.records.some((r) =>
      r.code.includes("authorize_request"),
    ),
  );
  assert.ok(
    !JSON.stringify(prepared.context).includes("return authorize_request"),
  );
  const oversizedMetadata = structuredClone(plan.batches[0].packet);
  for (const r of oversizedMetadata.records)
    r.sourceGraph = { repeatedNeighborhood: "x".repeat(96000) };
  const compact = await prepareStrideEvidence(oversizedMetadata, source);
  assert.ok(compact.packet.sourceContext.records.length);
  assert.ok(compact.packet.records.every((r) => !r.sourceGraph));
  assert.ok(Buffer.byteLength(JSON.stringify(compact.packet)) < 96 * 1024);
  const catalog = source.catalog.bind(source);
  source.catalog = (records) => ({
    nodes: Array.from({ length: 2000 }, (_, i) => ({
      id: `fixture-${i}`,
      name: "n".repeat(100),
      repository: "service",
    })),
    omitted: false,
  });
  const bounded = await prepareStrideEvidence(plan.batches[0].packet, source);
  assert.ok(
    bounded.context.gaps.some(
      (g) => g.reason === "source-graph-context-byte-limit",
    ),
  );
  assert.ok(Buffer.byteLength(JSON.stringify(bounded.packet)) <= 96 * 1024);
  source.catalog = catalog;

  const bad = await prepareStrideEvidence(plan.batches[0].packet, source, {
    references: [{ repository: "other", path: "secret.py", line: 1 }],
  });
  assert.ok(bad.context.gaps.length);
  const config = modelConfig("anthropic", "claude-opus-4-6", {
    ANTHROPIC_API_KEY: "fixture",
  });
  let calls = 0;
  const fetchImpl = async (_, options) => {
    calls++;
    const packet = JSON.parse(JSON.parse(options.body).messages[0].content);
    assert.ok(packet.sourceContext.records.length);
    return Response.json({
      stop_reason: "end_turn",
      content: [{ type: "text", text: JSON.stringify(response()) }],
      usage: { input_tokens: 10, output_tokens: 10 },
    });
  };
  const options = {
    maxBatches: 1,
    evidencePolicy: STRIDE_EVIDENCE_VERSION,
    prepareBatch: (b) => prepareStrideEvidence(b.packet, source),
  };
  await enrichGraphModel(model, config, new Map(), fetchImpl, options);
  assert.equal(calls, 1);
  assert.equal(
    model.aiReview.batches[0].status,
    "completed",
    model.aiReview.batches[0].error,
  );
  assert.ok(model.aiReview.coverageEvidence.sourceWindows);
  assert.equal(model.aiReview.mode, "source-excerpts");
  assert.ok(
    !JSON.stringify(model.aiReview).includes("return authorize_request"),
  );
  const first = model.aiReview.batches[0].id;
  await enrichGraphModel(model, config, new Map(), fetchImpl, {
    ...options,
    batchIds: [first],
  });
  assert.equal(calls, 1, "unchanged source-backed batch reused");
  await fs.appendFile(path.join(root, "service", "app.py"), "# changed\n");
  await assert.rejects(
    verifiedStrideSource(model, manifest, root),
    /Source changed/,
  );
});
test("STRIDE evidence requests cannot execute tools or cite invented context", () => {
  const packet = {
    records: [],
    sourceContext: {
      records: [{ id: "source-1" }],
      graphNodes: [{ id: "node-1" }],
    },
  };
  const request = {
    action: "search",
    recordId: "source-1",
    nodeId: "",
    symbol: "authorize_request",
    reason: "Find control",
  };
  assert.equal(
    validateStrideInvestigation(
      { ...response(), explorationRequests: [request] },
      packet,
    ).explorationRequests.length,
    1,
  );
  assert.throws(
    () =>
      validateStrideInvestigation(
        {
          ...response(),
          explorationRequests: [{ ...request, action: "shell" }],
        },
        packet,
      ),
    /unsupported action/,
  );
  assert.throws(
    () =>
      validateStrideInvestigation(
        {
          ...response(),
          explorationRequests: [{ ...request, recordId: "invented" }],
        },
        packet,
      ),
    /invalid evidence/,
  );
});
test("versioned standards preserve the old baseline and never turn missing assessments into compliance", () => {
  assert.ok(TAXONOMY.some((r) => r.id === "A01:2021"));
  assert.ok(TAXONOMY.some((r) => r.id === "A10:2025"));
  assert.ok(TAXONOMY.some((r) => r.id === "CAPEC-63"));
  assert.equal(ASVS_PROFILE.requirements.length, 11);
  const packet = { records: [], analysisGuidance: analysisGuidance([]) };
  assert.ok(
    validateReview(response(), packet).standardsReviews.every(
      (r) => r.status === "not-reviewed",
    ),
  );
  assert.throws(
    () =>
      validateReview(
        {
          ...response(),
          standardsReviews: [
            {
              id: "V8.2.1",
              status: "source-supported",
              rationale: "Name alone",
              evidenceIds: [],
            },
          ],
        },
        packet,
      ),
    /requires submitted evidence/,
  );
  assert.throws(
    () =>
      validateReview(
        {
          ...response(),
          standardsReviews: [
            {
              id: "V99.1.1",
              status: "needs-context",
              rationale: "Invented",
              evidenceIds: [],
            },
          ],
        },
        packet,
      ),
    /unknown or duplicated/,
  );
});

test('POC source uses the parsed handler range, excluding a neighboring write handler',async t=>{
 const {root,manifest}=await fixture(t);
 await fs.writeFile(path.join(root,'service','app.py'),"from flask import Flask\napp=Flask(__name__)\n@app.get('/settings')\ndef read_settings():\n    return read_config()\n\n@app.patch('/settings')\ndef write_settings():\n"+'    # padding\n'.repeat(85)+"    persist_config()\n");
 const model=await analyze(manifest,{sourceRoot:root});const source=await verifiedStrideSource(model,manifest,root);
 const read=await source.functionWindow({repository:'service',path:'app.py',line:3});
 assert.equal(read.startLine,3);assert.equal(read.endLine,5);assert.match(read.code,/read_config/);assert.doesNotMatch(read.code,/persist_config|patch/);
 const write=await source.functionWindow({repository:'service',path:'app.py',line:7});
 assert.match(write.code,/persist_config/);assert.equal(write.functionContext.complete,true);assert.doesNotMatch(write.code,/read_config/);
 assert.equal(write.lines.length,write.endLine-write.startLine+1);assert.ok(write.lines.length<=200);
 await fs.appendFile(path.join(root,'service','app.py'),'# changed\n');
 await assert.rejects(()=>source.functionWindow({repository:'service',path:'app.py',line:7}),/source-hash-mismatch/);
});
