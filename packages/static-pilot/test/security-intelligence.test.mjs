import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { unzipSync, strFromU8 } from "fflate";
import { buildGraphPackage } from "../src/graph-package.mjs";
import { analyze } from "../src/engine.mjs";
import { modelConfig } from "../src/model-review.mjs";
import { SECURITY_RESPONSE_SCHEMA } from "../src/security-schemas.mjs";
import { validateCweModel } from "../src/cwe-model.mjs";
import { CODE_TARGETS } from "../src/cwe-targets.mjs";
import {
  securityIssues,
  securityRegister,
  securityContextKey,
  validateSecurityAssessment,
} from "../src/security-intelligence.mjs";
import {
  investigationPacket,
  reviewSecurityIssues,
  INVESTIGATION_LIMITS,
} from "../src/security-review.mjs";
import { sha } from "../src/sources.mjs";
const config = modelConfig(
  "anthropic-gateway",
  "claude-opus-4-6-1",
  { CLAUDE_API_KEY: "fixture-key" },
  { baseUrl: "https://gateway.example/anthropic" },
);
const response = (review) =>
  Response.json({
    stop_reason: "end_turn",
    usage: { input_tokens: 110, output_tokens: 30 },
    content: [{ type: "text", text: JSON.stringify(review) }],
  });
export function assessment(packet, status = "static-supported") {
  const r = packet.records[0];
  const ref = {
    recordId: r.id,
    startLine: r.startLine,
    endLine: r.startLine,
    reason: "Fixture evidence on the candidate path",
  };
  return {
    assessment: status,
    actorKind: "authorized-agent",
    actor: "Automation using inherited authority",
    initialAccess: "Task-scoped access",
    input: "Task argument",
    impact: "Operation outside intended task",
    trace: [
      { ...ref, role: "input" },
      { ...ref, role: "sink" },
    ],
    controls: status === "ruled-out" ? [ref] : [],
    counterEvidence: "Shared control inspected; applicability requires review",
    missingEvidence: [],
    followUp: [],
    remediation: {
      codeFix: "Constrain the operation",
      interimControl: "Restrict the service identity",
      residualRisk: "Other callers require review",
      recovery: "Review credential scope and rotation",
      owner: "Unknown",
      approval: "Required, not granted",
      validation: "Static regression fixtures",
      rollback: "Restore reviewed prior policy",
    },
    severityChangeConditions:
      "Deployment identity and caller reachability evidence",
  };
}
async function fixture(t, count = 2) {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-intelligence-"),
  );
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifest = {
    profile: "static fixtures",
    repositories: Array.from({ length: count }, (_, i) => ({
      name: `repo${i}`,
      selected: true,
    })),
  };
  for (const repo of manifest.repositories) {
    await fs.mkdir(path.join(root, repo.name));
    await fs.writeFile(
      path.join(root, repo.name, "app.py"),
      "def run(cursor, value):\n    cursor.execute(value)\n",
    );
    await fs.writeFile(
      path.join(root, repo.name, "control.py"),
      "def guard(principal):\n    return principal.is_admin\n",
    );
  }
  const model = await analyze(manifest, { sourceRoot: root });
  model.cweReview = {
    basedOnRevision: model.modelRevision,
    findings: manifest.repositories.map((r, i) => ({
      id: `candidate-${i}`,
      cwe: "CWE-89",
      title: "Untrusted query candidate",
      repository: r.name,
      path: "app.py",
      line: 2,
      endLine: 2,
      blobSha256: sha("def run(cursor, value):\n    cursor.execute(value)\n"),
      status: "needs-review",
      interfaceIds: [],
      evidenceIds: [],
    })),
  };
  return { root, manifest, model };
}
test("security findings need not have CWE; invalid mappings are still rejected", () => {
  const packet = {
    records: [
      {
        id: "r",
        repository: "repo",
        path: "app.py",
        blobSha256: "hash",
        startLine: 1,
        endLine: 3,
      },
    ],
  };
  const finding = {
    cwe: null,
    kind: "excessive-authority",
    targetIds: [],
    title: "Task runner inherits operator authority",
    explanation: "Task and credential scope differ",
    preconditions: "Agent may invoke this operation",
    counterEvidence: "Deployment identity unknown",
    remediation: "Use task-scoped authority",
    locations: [{ recordId: "r", startLine: 1, endLine: 2 }],
  };
  const value = validateCweModel(
    { findings: [finding], limitations: [] },
    packet,
  );
  assert.equal(value.findings[0].cwe, null);
  assert.equal(value.findings[0].mappingStatus, "not-mapped");
  const scopedPacket = { ...packet, targets: CODE_TARGETS };
  assert.throws(() =>
    validateCweModel({ findings: [finding], limitations: [] }, scopedPacket),
  );
  const sql = CODE_TARGETS.find((t) => t.findingCwes.includes("CWE-89"));
  assert.ok(sql);
  const scoped = validateCweModel(
    {
      findings: [
        finding,
        {
          ...finding,
          kind: "code-weakness",
          cwe: "CWE-89",
          targetIds: [sql.id],
        },
      ],
      limitations: [],
      targetReviews: CODE_TARGETS.map((t) => ({
        targetId: t.id,
        status: "needs-context",
        rationale: "Requested target requires additional evidence",
        locations: finding.locations,
      })),
    },
    scopedPacket,
  );
  assert.equal(scoped.targetReviews.length, CODE_TARGETS.length);
  assert.equal(scoped.findings[1].cwe, "CWE-89");
  assert.deepEqual(scoped.findings[1].targetIds, [sql.id]);
  assert.ok(scoped.targetReviews.every((t) => t.status === "needs-context"));
  assert.throws(() =>
    validateCweModel(
      { findings: [{ ...finding, cwe: "CWE-999999" }], limitations: [] },
      packet,
    ),
  );
  assert.throws(() =>
    validateCweModel(
      { findings: [{ ...finding, kind: "invented" }], limitations: [] },
      packet,
    ),
  );
});

test("native JSON is explicit, preserves the gateway deployment, and still rejects invented references", async (t) => {
  const { root, manifest, model } = await fixture(t, 1);
  const native = modelConfig(
    "anthropic-gateway",
    "claude-opus-4-6-1",
    { CLAUDE_API_KEY: "test-key", SYNTHESIS_STRUCTURED_OUTPUTS: "1" },
    { baseUrl: "https://gateway.example/anthropic" },
  );
  const report = await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config: native,
    budget: 1,
    fetchImpl: async (_, options) => {
      const body = JSON.parse(options.body),
        packet = JSON.parse(body.messages[0].content);
      assert.equal(body.model, "claude-opus-4-6-1");
      assert.deepEqual(
        body.output_config.format.schema,
        SECURITY_RESPONSE_SCHEMA,
      );
      const value = assessment(packet);
      value.trace[0].recordId = "invented";
      return response(value);
    },
  });
  assert.equal(report.entries[0].assessment, "failed");
  assert.equal(report.outputContract, "native-json-schema");
  assert.equal(model.usageLedger.attempts.length, 1);
  assert.throws(
    () =>
      modelConfig("anthropic", "claude-opus-4-6", {
        ANTHROPIC_API_KEY: "test",
        SYNTHESIS_STRUCTURED_OUTPUTS: "typo",
      }),
    /must be 0 or 1/,
  );
  assert.throws(
    () =>
      modelConfig("gemini", "gemini-test", {
        GOOGLE_GEMINI_API_KEY: "test",
        SYNTHESIS_STRUCTURED_OUTPUTS: "1",
      }),
    /Anthropic-compatible provider/,
  );
});
test("assessment checks source references, requires path/control evidence, and preserves uncertainty", async (t) => {
  const { root, manifest, model } = await fixture(t, 1);
  const packet = await investigationPacket(
    model,
    manifest,
    root,
    securityIssues(model)[0],
  );
  assert.ok(packet.records.length);
  assert.equal(
    validateSecurityAssessment(assessment(packet), packet).proofBasis,
    "static-analysis-unexecuted",
  );
  assert.throws(() =>
    validateSecurityAssessment(
      {
        ...assessment(packet),
        trace: [{ ...assessment(packet).trace[0], recordId: "invented" }],
      },
      packet,
    ),
  );
  assert.throws(() =>
    validateSecurityAssessment({ ...assessment(packet), trace: [] }, packet),
  );
  assert.throws(
    () =>
      validateSecurityAssessment(
        {
          ...assessment(packet),
          remediation: {
            ...assessment(packet).remediation,
            codeFix: "x".repeat(1601),
          },
        },
        packet,
      ),
    /remediation\.codeFix must be nonempty text of at most 1600 characters/,
  );
  assert.throws(() =>
    validateSecurityAssessment(
      { ...assessment(packet), assessment: "ruled-out", controls: [] },
      packet,
    ),
  );
  const missing = validateSecurityAssessment(
    {
      ...assessment(packet, "ruled-out"),
      missingEvidence: ["Caller not supplied"],
    },
    packet,
  );
  assert.equal(missing.assessment, "needs-context");
  assert.equal(
    validateSecurityAssessment(assessment(packet), {
      ...packet,
      gaps: [{ reason: "source-hash-mismatch" }],
    }).assessment,
    "needs-context",
  );
  assert.throws(() =>
    validateSecurityAssessment(
      {
        ...assessment(packet),
        followUp: [
          {
            repository: "repo0",
            path: "../outside.py",
            line: 1,
            reason: "read",
          },
        ],
      },
      packet,
    ),
  );
});
test("12 repositories retain independent candidates, token usage and resume without repeat calls", async (t) => {
  const { root, manifest, model } = await fixture(t, 12);
  model.cweReview.findings[0].sourceScope = "test";
  model.cweReview.findings[1].sourceScope = "production-candidate";
  let calls = 0;
  const fetchImpl = async (url, options) => {
    assert.equal(url, "https://gateway.example/anthropic/v1/messages");
    assert.equal(options.headers["Ocp-Apim-Subscription-Key"], "fixture-key");
    const body = JSON.parse(options.body),
      packet = JSON.parse(body.messages[0].content);
    assert.equal(body.model, "claude-opus-4-6-1");
    assert.ok(packet.context.actors);
    calls++;
    return response(assessment(packet));
  };
  let report = await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 2,
    fetchImpl,
  });
  assert.equal(report.callsThisRun, 2);
  assert.equal(report.entries[0].sourceId, "candidate-1");
  assert.equal(report.pending, 10);
  assert.equal(securityRegister(model).counts["static-supported"], 2);
  report = await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 20,
    fetchImpl,
  });
  assert.equal(report.status, "assessed-needs-review");
  assert.equal(calls, 12);
  await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 20,
    fetchImpl,
  });
  assert.equal(calls, 12);
  assert.equal(
    model.usageLedger.attempts.reduce((n, a) => n + a.usage.totalTokens, 0),
    1680,
  );
  assert.equal(securityRegister(model).coverageComplete, false);
  assert.doesNotMatch(JSON.stringify(report), /cursor.execute|fixture-key/);
  const exportedAssessment = async () => {
    const pkg = await buildGraphPackage(model, manifest, {
      kind: "finding",
      value: "candidate-0",
      sourceRoot: root,
    });
    return pkg.parts
      .flatMap((part) =>
        strFromU8(unzipSync(part.buffer)["records.ndjson"])
          .trim()
          .split("\n")
          .map(JSON.parse),
      )
      .find((record) => record.type === "security-investigation").data;
  };
  assert.equal((await exportedAssessment()).stale, false);
  const key = securityContextKey(model);
  model.architecture = {
    version: 1,
    records: {},
    removed: [],
    decisions: [{ state: "accepted" }],
  };
  assert.notEqual(key, securityContextKey(model));
  assert.equal(securityRegister(model).counts["static-supported"], 0);
  assert.equal((await exportedAssessment()).stale, true);
});
test("large evidence packets trim catalog metadata first and report source omissions", async (t) => {
  const { root, manifest, model } = await fixture(t, 1);
  const issue = securityIssues(model)[0];
  const base = await investigationPacket(model, manifest, root, issue, [], {});
  for (let n = 0; n < 220; n++)
    model.sourceGraph.nodes.push({
      id: `catalog-${n}`,
      kind: "file",
      repository: "repo0",
      path: `catalog/${"x".repeat(300)}-${n}.py`,
    });
  const packet = await investigationPacket(model, manifest, root, issue, [], {
    padding: "x".repeat(40000),
  });
  assert.ok(
    Buffer.byteLength(JSON.stringify(packet)) <=
      INVESTIGATION_LIMITS.packetBytes,
  );
  assert.equal(
    packet.retrieval.packetBytes,
    Buffer.byteLength(JSON.stringify(packet)),
  );
  assert.ok(packet.retrieval.catalogEntriesOmittedForBytes > 0);
  assert.equal(packet.retrieval.sourceWindowsOmittedForBytes, 0);
  assert.equal(packet.records.length, base.records.length);
  const sourcePaths = new Set(base.records.map((r) => r.path));
  const skeleton = {
    ...base,
    records: [],
    availableFiles: base.availableFiles.filter((f) => sourcePaths.has(f.path)),
  };
  const padding =
    INVESTIGATION_LIMITS.packetBytes -
    128 -
    Buffer.byteLength(JSON.stringify(skeleton)) -
    250;
  const reduced = await investigationPacket(model, manifest, root, issue, [], {
    padding: "x".repeat(padding),
  });
  assert.ok(
    Buffer.byteLength(JSON.stringify(reduced)) <=
      INVESTIGATION_LIMITS.packetBytes,
  );
  assert.ok(reduced.retrieval.sourceWindowsOmittedForBytes > 0);
  assert.ok(
    reduced.gaps.some(
      (g) => g.reason === "source-window-omitted-for-packet-budget",
    ),
  );
});
test("follow-up retrieves indexed controls and preserves prior assessment history", async (t) => {
  const { root, manifest, model } = await fixture(t, 1);
  let calls = 0;
  const fetchImpl = async (_, options) => {
    const packet = JSON.parse(JSON.parse(options.body).messages[0].content);
    calls++;
    if (calls === 1)
      return response({
        ...assessment(packet, "needs-context"),
        missingEvidence: ["Need shared guard"],
        followUp: [
          {
            repository: "repo0",
            path: "control.py",
            line: 1,
            reason: "Inspect caller guard",
          },
        ],
      });
    assert.ok(
      packet.records.some(
        (r) => r.path === "control.py" && r.basis === "requested-follow-up",
      ),
    );
    const value = assessment(packet, "ruled-out"),
      control = packet.records.find((r) => r.path === "control.py");
    value.controls = [
      {
        recordId: control.id,
        startLine: 1,
        endLine: 2,
        reason: "Fixture control on the stated path",
      },
    ];
    return response(value);
  };
  await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  const report = await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  assert.equal(report.entries[0].assessment, "ruled-out");
  assert.equal(report.entries[0].history[0].assessment, "needs-context");
  assert.equal(report.entries[0].history[0].usage.totalTokens, 140);
  assert.equal(report.entries[0].usage.totalTokens, 140);
  assert.equal(model.cweReview.findings[0].status, "needs-review");
  const exported = await buildGraphPackage(model, manifest, {
    kind: "finding",
    value: "candidate-0",
    sourceRoot: root,
    includeSource: true,
  });
  const records = exported.parts.flatMap((part) =>
    strFromU8(unzipSync(part.buffer)["records.ndjson"])
      .trim()
      .split("\n")
      .map(JSON.parse),
  );
  assert.ok(
    records.some(
      (r) => r.type === "source-context" && r.data.path === "control.py",
    ),
  );
});

test("investigation follows statically connected services across repositories", async (t) => {
  const { root, manifest } = await fixture(t, 2);
  const source =
    "app.get('/service0', handler); fetch('https://host1/service1');";
  await fs.writeFile(path.join(root, "repo0/app.js"), source);
  await fs.writeFile(
    path.join(root, "repo1/app.js"),
    "app.get('/service1', handler);",
  );
  for (let i = 0; i < 2; i++)
    await fs.writeFile(
      path.join(root, `repo${i}/settings.json`),
      JSON.stringify({ Kestrel: { Url: `https://host${i}` } }),
    );
  const model = await analyze(manifest, { sourceRoot: root });
  model.cweReview = {
    basedOnRevision: model.modelRevision,
    findings: [
      {
        id: "cross-service",
        cwe: "CWE-918",
        repository: "repo0",
        path: "app.js",
        line: 1,
        endLine: 1,
        blobSha256: sha(source),
        title: "Outbound request candidate",
      },
    ],
  };
  const packet = await investigationPacket(
    model,
    manifest,
    root,
    securityIssues(model)[0],
  );
  assert.ok(packet.retrieval.relatedFlowCandidates > 0);
  assert.ok(
    packet.records.some(
      (r) =>
        r.repository === "repo1" &&
        r.basis.startsWith("static-flow-candidate:"),
    ),
  );
});

test("saved conclusive assessments lose support when cited source changes", async (t) => {
  const { root, manifest, model } = await fixture(t, 1);
  let calls = 0;
  const fetchImpl = async (_, options) => {
    calls++;
    return response(
      assessment(JSON.parse(JSON.parse(options.body).messages[0].content)),
    );
  };
  await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  await fs.writeFile(path.join(root, "repo0/app.py"), "changed\n");
  const report = await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl,
  });
  assert.equal(calls, 1);
  assert.equal(report.entries[0].assessment, "needs-context");
  assert.equal(report.entries[0].stopReason, "source-no-longer-matches");
  assert.equal(report.status, "partial");
});
test("changed source and symlinks cannot supply evidence; malformed model output is metered", async (t) => {
  const { root, manifest, model } = await fixture(t, 1);
  const issue = securityIssues(model)[0];
  await fs.writeFile(path.join(root, "repo0/app.py"), "changed\n");
  let packet = await investigationPacket(model, manifest, root, issue);
  assert.ok(packet.gaps.some((g) => g.reason === "source-hash-mismatch"));
  await fs.rm(path.join(root, "repo0/app.py"));
  await fs.symlink(
    path.join(root, "repo0/control.py"),
    path.join(root, "repo0/app.py"),
  );
  packet = await investigationPacket(model, manifest, root, issue);
  assert.ok(packet.gaps.some((g) => g.reason === "source-symlink-rejected"));
  await fs.rm(path.join(root, "repo0/app.py"));
  await fs.writeFile(
    path.join(root, "repo0/app.py"),
    "def run(cursor, value):\n    cursor.execute(value)\n",
  );
  const report = await reviewSecurityIssues(manifest, model, {
    sourceRoot: root,
    config,
    budget: 1,
    fetchImpl: async () => response({ assessment: "confirmed", trace: [] }),
  });
  assert.equal(report.entries[0].assessment, "failed");
  assert.equal(report.status, "partial");
  assert.equal(model.usageLedger.attempts[0].usage.totalTokens, 140);
  assert.equal(model.usageLedger.attempts[0].status, "failed");
});
