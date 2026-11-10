import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import {
  modelConfig,
  publicModelConfig,
  reviewPacket,
  validateReview,
  requestReview,
  enrichModel,
  collectExcerpts,
  redact,
  REVIEW_LIMITS,
} from "../src/model-review.mjs";
import { analyze, compose } from "../src/engine.mjs";
import { reportHtml, diagram } from "../src/report.mjs";
import { serve } from "../src/server.mjs";
const sourceRoot = fileURLToPath(
  new URL("../fixtures/repositories/", import.meta.url),
);
const manifest = {
  profile: "server",
  repositories: ["frontdoor", "business", "setup"].map((name) => ({ name })),
};
const config = modelConfig("anthropic", "approved-model", {
  ANTHROPIC_API_KEY: "synthetic-provider-key",
});
const fixture = () => analyze(manifest, { sourceRoot });
function suggestion(packet) {
  const [a, b] = packet.records.filter((r) => r.direction !== "control");
  return {
    summary: "Partial review; controls unknown.",
    threats: [
      {
        title: "Conditional misuse",
        category: "Elevation of Privilege",
        actor: "Authenticated caller",
        startingAccess: "Assumed operation access",
        asset: "Service authority",
        scenario:
          "If authorization is absent, a caller might invoke a privileged operation.",
        prerequisites: "Verify routing and authorization scope.",
        controls: "Unknown",
        mitigation: "Review authorization at the effective handler.",
        interfaceIds: [a.id],
        evidenceIds: [a.evidence[0].id],
      },
    ],
    connections: [
      {
        from: a.id,
        to: b.id,
        reason: "Hypothesis; inspect binding configuration.",
        evidenceIds: [a.evidence[0].id, b.evidence[0].id],
        transition: {
          dimension: "identity",
          before: "Caller identity assumed",
          after: "Service identity assumed",
          reason: "Review effective identity.",
        },
      },
    ],
    questions: ["Which configuration selects these operations?"],
  };
}
const responseFor = (provider, result, finish) =>
  Response.json(
    provider === "anthropic"
      ? {
          stop_reason: finish || "end_turn",
          content: [{ type: "text", text: JSON.stringify(result) }],
        }
      : {
          candidates: [
            {
              finishReason: finish || "STOP",
              content: { parts: [{ text: JSON.stringify(result) }] },
            },
          ],
        },
  );
test("model configuration requires explicit supported provider, model and key; public configuration excludes key", () => {
  assert.equal(modelConfig(), null);
  assert.throws(() => modelConfig("unknown", "model"), /Provider must/);
  assert.throws(() => modelConfig("anthropic"), /approved/);
  assert.throws(() => modelConfig("gemini", "../evil", {}), /approved/);
  assert.throws(
    () => modelConfig("gemini", "approved-model", {}),
    /GOOGLE_GEMINI_API_KEY/,
  );
  assert.deepEqual(publicModelConfig(config), {
    provider: "anthropic",
    model: "approved-model",
    label: "Claude",
  });
});
test("metadata packets are bounded, balanced across repositories, and omit source excerpts and local root", async () => {
  const model = await fixture(),
    packet = reviewPacket(model);
  assert.equal(new Set(packet.records.map((i) => i.repository)).size, 3);
  assert.ok(packet.records.every((r) => r.evidence.every((e) => !e.excerpt)));
  assert.ok(!JSON.stringify(packet).includes(sourceRoot));
  model.interfaces = Array.from({ length: 2000 }, (_, n) => ({
    ...model.interfaces[n % model.interfaces.length],
    id: "large-" + n,
    operation: "x".repeat(300),
  }));
  const bounded = reviewPacket(model);
  assert.ok(bounded.records.length <= REVIEW_LIMITS.interfaces);
  assert.ok(
    Buffer.byteLength(JSON.stringify(bounded)) <= REVIEW_LIMITS.packetBytes,
  );
});
test("transient source excerpts redact common credentials and preserve bounded context", () => {
  const excerpts = new Map();
  collectExcerpts(
    { evidence: [{ id: "e", path: "code.cs", line: 4 }] },
    [
      {
        path: "code.cs",
        text: 'void handler() {\nvar password = "do-not-send";\nvar url = "https://user:credential@host/path?token=private-token";\nfetch(url);\n}',
      },
    ],
    excerpts,
  );
  const snippet = excerpts.get("e");
  assert.equal(snippet.firstLine, 1);
  assert.ok(snippet.text.includes("fetch(url)"));
  for (const secret of ["do-not-send", "credential@", "private-token"])
    assert.ok(!snippet.text.includes(secret));
  assert.equal(redact("Bearer abc123"), "Bearer [redacted]");
  assert.ok(
    !redact(
      "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
    ).includes("abc123"),
  );
});
test("Claude and Gemini adapters use configured models, fixed hosts, header keys, no redirects or tools", async () => {
  const packet = reviewPacket(await fixture());
  for (const provider of ["anthropic", "gemini"]) {
    let calls = 0;
    const result = await requestReview(
      { ...config, provider },
      packet,
      async (url, options) => {
        calls++;
        assert.equal(options.redirect, "error");
        assert.equal(options.method, "POST");
        assert.ok(options.signal instanceof AbortSignal);
        assert.ok(!url.includes(config.apiKey));
        const body = JSON.parse(options.body);
        assert.ok(!options.body.includes(config.apiKey));
        assert.equal(body.tools, undefined);
        if (provider === "anthropic") {
          assert.equal(url, "https://api.anthropic.com/v1/messages");
          assert.equal(body.model, "approved-model");
          assert.equal(options.headers["x-api-key"], config.apiKey);
          assert.equal(body.max_tokens, REVIEW_LIMITS.outputTokens);
          assert.deepEqual(JSON.parse(body.messages[0].content), packet);
        } else {
          assert.equal(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/approved-model:generateContent",
          );
          assert.equal(options.headers["x-goog-api-key"], config.apiKey);
          assert.equal(
            body.generationConfig.responseMimeType,
            "application/json",
          );
          assert.deepEqual(JSON.parse(body.contents[0].parts[0].text), packet);
        }
        return responseFor(provider, suggestion(packet));
      },
    );
    assert.equal(calls, 1);
    assert.equal(result.review.threats[0].severity, "unassessed");
    assert.equal(result.responseHash.length, 64);
  }
});
test("model schemas reject invented or unrelated evidence, duplicate endpoints and asserted approval", async () => {
  const packet = reviewPacket(await fixture());
  const edits = [
    (x) => (x.threats[0].interfaceIds = ["invented"]),
    (x) => (x.threats[0].evidenceIds = ["invented"]),
    (x) => (x.threats[0].evidenceIds = [packet.records[1].evidence[0].id]),
    (x) => (x.threats[0].severity = "critical"),
    (x) => (x.threats[0].status = "approved"),
    (x) => (x.threats[0].category = "confirmed vulnerability"),
    (x) => (x.connections[0].to = x.connections[0].from),
    (x) => x.connections[0].evidenceIds.pop(),
    (x) =>
      (x.connections[0].transition.after = x.connections[0].transition.before),
    (x) => (x.questions = Array(21).fill("too many")),
    (x) => (x.summary = "x".repeat(3001)),
  ];
  for (const edit of edits) {
    const value = suggestion(packet);
    edit(value);
    assert.throws(() => validateReview(value, packet), /validation/);
  }
});
test("failure, truncation, malformed JSON, tools and oversized outputs fail without fallback or error-body disclosure", async () => {
  const model = await fixture(),
    packet = reviewPacket(model);
  const cases = [
    () => new Response("secret-provider-body", { status: 401 }),
    () => {
      throw new Error("secret-request-context");
    },
    () => responseFor("anthropic", suggestion(packet), "max_tokens"),
    () =>
      Response.json({
        stop_reason: "end_turn",
        content: [{ type: "text", text: "not JSON secret-provider-body" }],
      }),
    () =>
      Response.json({
        stop_reason: "end_turn",
        content: [{ type: "tool_use", name: "exec" }],
      }),
    () => new Response("x".repeat(REVIEW_LIMITS.responseBytes + 1)),
  ];
  for (const mock of cases) {
    let calls = 0;
    const m = structuredClone(model);
    await enrichModel(m, config, new Map(), async () => {
      calls++;
      return mock();
    });
    assert.equal(calls, 1);
    assert.equal(m.aiReview.status, "failed");
    assert.ok(!JSON.stringify(m).includes("secret-"));
    assert.deepEqual(m.flows, model.flows);
  }
  await assert.rejects(
    requestReview({ ...config, provider: "gemini" }, packet, async () =>
      responseFor("gemini", suggestion(packet), "MAX_TOKENS"),
    ),
    /incomplete/,
  );
});
test("analysis preserves source evidence and DFD, exports model provenance and marks revised declarations stale", async () => {
  const baseline = await fixture();
  const model = await analyze(manifest, {
    sourceRoot,
    modelConfig: config,
    includeSourceExcerpts: true,
    modelFetch: async (_, options) =>
      responseFor(
        "anthropic",
        suggestion(JSON.parse(JSON.parse(options.body).messages[0].content)),
      ),
  });
  assert.ok(model.aiReview.coverage.excerptCount > 0);
  assert.equal(model.aiReview.mode, "source-excerpts");
  assert.equal(model.aiReview.status, "completed-needs-review");
  for (const key of ["flows", "boundaries", "actors", "evidence", "threats"])
    assert.deepEqual(model[key], baseline[key]);
  assert.equal(diagram(model), diagram(baseline));
  assert.ok(!JSON.stringify(model).includes(config.apiKey));
  assert.ok(!JSON.stringify(model).includes("firstLine"));
  model.aiReview.threats[0].title = "<script>alert(1)</script>";
  const html = reportHtml(model);
  assert.ok(html.includes("Claude / approved-model"));
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(!html.includes("<script>alert(1)</script>"));
  const [from, to] = model.interfaces.filter((i) => i.direction !== "control");
  compose(model, {
    bindings: [
      {
        from: from.id,
        to: to.id,
        reason: "Synthetic review declaration",
        reviewer: "Tester",
        profile: manifest.profile,
      },
    ],
  });
  assert.equal(model.aiReview.status, "stale");
  assert.ok(reportHtml(model).includes("Status: stale"));
});
test("empty discovery skips provider and no-model runs have no inference result", async () => {
  const model = await fixture();
  assert.equal(model.provider, "none");
  assert.equal(model.aiReview, undefined);
  model.interfaces = [];
  await enrichModel(model, config, new Map(), async () => {
    assert.fail("must not call provider");
  });
  assert.equal(model.aiReview.status, "skipped");
});
test("server exposes configured model without key and refuses requested inference without provider", async (t) => {
  for (const configured of [false, true]) {
    const { server, url, token } = await serve({
      sourceRoot,
      port: 0,
      quiet: true,
      modelConfig: configured ? config : null,
    });
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const base = new URL(url).origin,
      headers = {
        "X-Synthesis-Token": token,
        "Content-Type": "application/json",
      };
    const status = await (
      await fetch(base + "/api/status", { headers })
    ).json();
    assert.ok(!JSON.stringify(status).includes(config.apiKey));
    assert.equal(
      status.inference?.provider,
      configured ? "anthropic" : undefined,
    );
    if (!configured) {
      const response = await fetch(base + "/api/analyze", {
        method: "POST",
        headers,
        body: JSON.stringify({ ...manifest, analysis: { useModel: true } }),
      });
      assert.equal(response.status, 400);
      assert.match((await response.json()).error, /provider/);
    }
  }
});

test("connection proposals allow cited supporting context but reject control records as endpoints", async () => {
  const packet = reviewPacket(await fixture());
  const value = suggestion(packet);
  const control = packet.records.find((r) => r.direction === "control");
  assert.ok(control);
  value.connections[0].evidenceIds.push(control.evidence[0].id);
  assert.equal(validateReview(value, packet).connections.length, 1);
  value.connections[0].to = control.id;
  assert.throws(() => validateReview(value, packet), /validation/);
});

test("review packets include only bounded reviewer declarations whose endpoints were submitted", async () => {
  const model = await fixture();
  const [from, to] = model.interfaces.filter((i) => i.direction !== "control");
  compose(model, {
    bindings: [
      {
        from: from.id,
        to: to.id,
        profile: manifest.profile,
        reviewer: "Tester",
        reason: "Synthetic binding",
        controls: "Unknown",
        dimension: "identity",
        before: "Caller",
        after: "Service",
      },
    ],
  });
  const packet = reviewPacket(model);
  assert.equal(packet.reviewerDeclarations.length, 1);
  assert.equal(
    packet.reviewerDeclarations[0].basis,
    "reviewer-declared; not source-proven",
  );
  assert.equal(packet.reviewerDeclarations[0].transition.before, "Caller");
  assert.ok(
    Buffer.byteLength(JSON.stringify(packet)) <= REVIEW_LIMITS.packetBytes,
  );
});

test("Claude reasoning blocks are excluded from review and exports, while token exhaustion remains explicit", async () => {
  const packet = reviewPacket(await fixture());
  const result = await requestReview(config, packet, async () =>
    Response.json({
      stop_reason: "end_turn",
      content: [
        { type: "thinking", thinking: "internal reasoning omitted" },
        { type: "redacted_thinking", data: "opaque" },
        { type: "text", text: JSON.stringify(suggestion(packet)) },
      ],
    }),
  );
  assert.ok(!JSON.stringify(result).includes("internal reasoning"));
  assert.equal(result.review.threats.length, 1);
  await assert.rejects(
    requestReview(config, packet, async () =>
      responseFor("anthropic", suggestion(packet), "max_tokens"),
    ),
    /output-token budget/,
  );
});

test("model execution and excerpt choices require booleans, not truthy strings", async () => {
  await assert.rejects(
    analyze({ ...manifest, analysis: { useModel: "false" } }, { sourceRoot }),
    /true or false/,
  );
  await assert.rejects(
    analyze(
      { ...manifest, analysis: { includeSourceExcerpts: "yes" } },
      { sourceRoot },
    ),
    /true or false/,
  );
});
