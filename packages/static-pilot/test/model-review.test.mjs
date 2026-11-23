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
const gatewayConfig = () =>
  modelConfig("anthropic-gateway", "example-deployment-v1", {
    CLAUDE_API_KEY: "synthetic-gateway-key",
    ANTHROPIC_API_KEY: "different-direct-key",
    SYNTHESIS_LLM_BASE_URL: "https://test-gateway.example/anthropic/",
  });
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
  const signature = 'async def verify_admin_key(api_key: Optional[str] = Security(api_key_header)) -> bool:';
  assert.equal(redact(signature), signature);
  assert.ok(!redact('def verify(api_key: str = "secret-literal"):').includes('secret-literal'));
  assert.ok(!redact(signature + ' password = "secret-literal"').includes('secret-literal'));
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
test("direct Claude, gateway and Gemini accept whole-response JSON fences without weakening validation", async () => {
  const packet = reviewPacket(await fixture());
  const json = JSON.stringify(suggestion(packet));
  for (const cfg of [
    config,
    gatewayConfig(),
    { ...config, provider: "gemini" },
  ]) {
    for (const text of [
      json,
      `\uFEFF ${json}\n`,
      `\`\`\`json\n${json}\n\`\`\``,
      `\`\`\`\r\n${json}\r\n\`\`\``,
      ` \`\`\`JSON\n${json}\n\`\`\`\n`,
    ]) {
      let calls = 0;
      const result = await requestReview(cfg, packet, async () => {
        calls++;
        return Response.json(
          cfg.provider === "gemini"
            ? {
                candidates: [
                  { finishReason: "STOP", content: { parts: [{ text }] } },
                ],
              }
            : {
                stop_reason: "end_turn",
                content: [
                  { type: "text", text: text.slice(0, 20) },
                  { type: "text", text: text.slice(20) },
                ],
              },
        );
      });
      assert.equal(calls, 1);
      assert.equal(result.review.threats[0].status, "needs-review");
      assert.deepEqual(
        result.review,
        validateReview(suggestion(packet), packet),
      );
    }
  }
});
test("gateway format errors remain safe and ambiguous or invalid responses are rejected", async () => {
  const packet = reviewPacket(await fixture());
  const json = JSON.stringify(suggestion(packet));
  const invalidEvidence = suggestion(packet);
  invalidEvidence.threats[0].evidenceIds = ["invented"];
  const cases = [
    ["", /empty text/],
    ["private-source-content", /text outside/],
    [`Here is the review: ${json}`, /text outside/],
    [`${json}\n${json}`, /invalid or incomplete/],
    [`\`\`\`json\n${json}\n\`\`\`\nExplanation`, /text outside/],
    [
      `\`\`\`json\n${json}\n\`\`\`\n\`\`\`json\n${json}\n\`\`\``,
      /invalid JSON inside/,
    ],
    [
      '```json\n{"summary":"private-source-content",}\n```',
      /invalid JSON inside/,
    ],
    [
      `\`\`\`json\n${JSON.stringify(invalidEvidence)}\n\`\`\``,
      /schema or evidence/,
    ],
    ["```json\n[]\n```", /schema or evidence/],
  ];
  for (const [text, expected] of cases) {
    let calls = 0;
    await assert.rejects(
      requestReview(gatewayConfig(), packet, async () => {
        calls++;
        return Response.json({
          stop_reason: "end_turn",
          content: [{ type: "text", text }],
        });
      }),
      (error) => {
        assert.match(error.message, expected);
        assert.ok(!error.message.includes("private-source-content"));
        return true;
      },
    );
    assert.equal(calls, 1);
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
  for (const configured of [null, config, gatewayConfig()]) {
    const { server, url, token } = await serve({
      sourceRoot,
      port: 0,
      quiet: true,
      modelConfig: configured,
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
    assert.ok(!JSON.stringify(status).includes("synthetic-gateway-key"));
    assert.equal(status.inference?.provider, configured?.provider);
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

test("gateway configuration separates credentials, validates destinations and permits explicit overrides", () => {
  const gateway = gatewayConfig();
  assert.equal(gateway.apiKey, "synthetic-gateway-key");
  assert.equal(gateway.apiVersion, "2023-06-01");
  assert.equal(gateway.baseUrl, "https://test-gateway.example/anthropic");
  assert.equal(
    publicModelConfig(gateway).endpoint,
    "https://test-gateway.example/anthropic/v1/messages",
  );
  assert.ok(
    !JSON.stringify(publicModelConfig(gateway)).includes(gateway.apiKey),
  );
  assert.throws(
    () =>
      modelConfig("anthropic-gateway", "example-deployment-v1", {
        ANTHROPIC_API_KEY: "wrong-key",
      }),
    /CLAUDE_API_KEY/,
  );
  for (const baseUrl of [
    undefined,
    "http://test.example/anthropic",
    "https://user:secret@test.example/anthropic",
    "https://test.example/path?key=secret",
    "https://test.example/#secret",
    "https://test.example/%2e%2e/path",
    "https://test.example/v1/messages",
    "https://test.example/anthropic/v1",
    "https://test.example\\evil",
  ]) {
    assert.throws(
      () =>
        modelConfig(
          "anthropic-gateway",
          "example-deployment-v1",
          { CLAUDE_API_KEY: "key" },
          { baseUrl },
        ),
      /Gateway requires|base URL/,
    );
  }
  assert.throws(
    () =>
      modelConfig(
        "anthropic-gateway",
        "example-deployment-v1",
        { CLAUDE_API_KEY: "key" },
        { baseUrl: gateway.baseUrl, apiVersion: "2023-06-01\r\nx: y" },
      ),
    /API version/,
  );
  assert.throws(
    () =>
      modelConfig(
        "anthropic",
        "approved-model",
        { ANTHROPIC_API_KEY: "key" },
        { baseUrl: gateway.baseUrl },
      ),
    /require --provider/,
  );
  const explicit = modelConfig(
    "anthropic-gateway",
    "example-deployment-v1",
    {
      CLAUDE_API_KEY: "key",
      SYNTHESIS_LLM_BASE_URL: "https://environment.example",
      SYNTHESIS_LLM_API_VERSION: "2023-01-01",
    },
    { baseUrl: "https://explicit.example/prefix", apiVersion: "2023-06-01" },
  );
  assert.equal(explicit.baseUrl, "https://explicit.example/prefix");
  assert.equal(explicit.apiVersion, "2023-06-01");
  assert.equal(
    modelConfig("anthropic", "approved-model", {
      ANTHROPIC_API_KEY: "direct",
      SYNTHESIS_LLM_BASE_URL: gateway.baseUrl,
    }).baseUrl,
    undefined,
  );
});

test("APIM gateway matches the supplied Messages contract and retains safe provenance", async () => {
  const model = await fixture();
  const gateway = gatewayConfig();
  let calls = 0;
  await enrichModel(model, gateway, new Map(), async (url, options) => {
    calls++;
    assert.equal(url, "https://test-gateway.example/anthropic/v1/messages");
    assert.equal(options.method, "POST");
    assert.equal(options.redirect, "error");
    assert.deepEqual(options.headers, {
      "Content-Type": "application/json",
      "Ocp-Apim-Subscription-Key": "synthetic-gateway-key",
      "anthropic-version": "2023-06-01",
    });
    const body = JSON.parse(options.body);
    assert.equal(body.model, "example-deployment-v1");
    assert.equal(body.max_tokens, REVIEW_LIMITS.outputTokens);
    assert.equal(body.tools, undefined);
    assert.ok(!options.body.includes(gateway.apiKey));
    return responseFor(
      "anthropic",
      suggestion(JSON.parse(body.messages[0].content)),
    );
  });
  assert.equal(calls, 1);
  assert.equal(model.aiReview.status, "completed-needs-review");
  assert.equal(
    model.aiReview.endpoint,
    "https://test-gateway.example/anthropic/v1/messages",
  );
  assert.equal(model.aiReview.apiVersion, "2023-06-01");
  assert.equal(model.flows.length, 0);
  assert.ok(!JSON.stringify(model).includes(gateway.apiKey));
  assert.ok(!reportHtml(model).includes(gateway.apiKey));
});

test("gateway policy errors and redirects fail visibly without fallback or credential disclosure", async () => {
  for (const status of [403, 302]) {
    const model = await fixture();
    let calls = 0;
    await enrichModel(
      model,
      gatewayConfig(),
      new Map(),
      async (url, options) => {
        calls++;
        assert.equal(options.redirect, "error");
        assert.ok(url.startsWith("https://test-gateway.example/"));
        return new Response(
          "private gateway diagnostic synthetic-gateway-key",
          { status, headers: { Location: "https://another.example/" } },
        );
      },
    );
    assert.equal(calls, 1);
    assert.equal(model.aiReview.status, "failed");
    assert.match(model.aiReview.error, new RegExp(`HTTP ${status}`));
    assert.ok(!JSON.stringify(model).includes("private gateway diagnostic"));
    assert.ok(!JSON.stringify(model).includes("synthetic-gateway-key"));
    assert.ok(model.interfaces.length > 0);
  }
});

test("CLI supports gateway flags and environment configuration end to end", async (t) => {
  const { sqliteSupported } = await import("../src/graph-store.mjs");
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const path = await import("node:path");
  const { pathToFileURL } = await import("node:url");
  const { execFileSync } = await import("node:child_process");
  const temporary = await fs.mkdtemp(
    path.join(os.tmpdir(), "synthesis-gateway-"),
  );
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const manifestFile = path.join(temporary, "scope.json");
  const mockFile = path.join(temporary, "mock.mjs");
  await fs.writeFile(manifestFile, JSON.stringify(manifest));
  await fs.writeFile(
    mockFile,
    `import assert from 'node:assert/strict';
    globalThis.fetch = async (url, options) => {
      assert.equal(url, 'https://test-gateway.example/anthropic/v1/messages');
      assert.equal(options.headers['Ocp-Apim-Subscription-Key'], 'synthetic-gateway-key');
      assert.equal(options.headers['anthropic-version'], '2023-06-01');
      assert.equal(JSON.parse(options.body).model, 'example-deployment-v1');
      return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify({summary:'Synthetic protocol test only.',threats:[],connections:[],questions:[]})}]});
    };`,
  );
  for (const mode of ["flags", "environment"]) {
    const out = path.join(temporary, mode);
    const env = {
      ...process.env,
      CLAUDE_API_KEY: "synthetic-gateway-key",
      SYNTHESIS_LLM_PROVIDER: "anthropic-gateway",
      SYNTHESIS_LLM_MODEL: "example-deployment-v1",
      SYNTHESIS_LLM_BASE_URL: "https://test-gateway.example/anthropic",
      SYNTHESIS_LLM_API_VERSION: "2023-06-01",
    };
    const flags =
      mode === "flags"
        ? [
            "--provider",
            "anthropic-gateway",
            "--model",
            "example-deployment-v1",
            "--base-url",
            env.SYNTHESIS_LLM_BASE_URL,
            "--api-version",
            "2023-06-01",
          ]
        : [];
    if (mode === "flags") {
      env.SYNTHESIS_LLM_PROVIDER = "none";
      env.SYNTHESIS_LLM_BASE_URL = "https://unused.example";
      env.SYNTHESIS_LLM_MODEL = "unused-model";
      env.SYNTHESIS_LLM_API_VERSION = "2023-01-01";
    }
    const output = execFileSync(
      process.execPath,
      [
        "--import",
        pathToFileURL(mockFile).href,
        fileURLToPath(new URL("../src/cli.mjs", import.meta.url)),
        "analyze",
        "--source-root",
        sourceRoot,
        "--manifest",
        manifestFile,
        "--out",
        out,
        ...(sqliteSupported() ? [] : ["--graph-storage", "memory"]),
        ...flags,
      ],
      { env, encoding: "utf8", timeout: 30000 },
    );
    assert.ok(!output.includes(env.CLAUDE_API_KEY));
    const model = JSON.parse(
      await fs.readFile(path.join(out, "model.json"), "utf8"),
    );
    assert.equal(model.aiReview.status, "completed-needs-review");
    assert.equal(model.aiReview.model, "example-deployment-v1");
    assert.equal(model.aiReview.apiVersion, "2023-06-01");
    assert.ok(!JSON.stringify(model).includes(env.CLAUDE_API_KEY));
  }
});

test("native STRIDE gateway schema preserves deployment and still rejects invented evidence", async () => {
  const { STRIDE_RESPONSE_SCHEMA } = await import(
    "../src/security-schemas.mjs"
  );
  const native = {
    ...gatewayConfig(),
    model: "claude-opus-4-6-1",
    structuredOutputs: true,
  };
  const model = await fixture();
  const packet = reviewPacket(model);
  const result = suggestion(packet);
  result.threats[0].analysis = {
    attackSteps: [
      "Caller reaches an operation whose authorization needs verification.",
    ],
    impact: "Potential service authority misuse.",
    assumptions: ["Caller can reach the operation."],
    controlEvidenceIds: [],
    boundaryIds: [],
    mappings: [],
  };
  const transport = async (url, options) => {
    const body = JSON.parse(options.body);
    assert.equal(url, "https://test-gateway.example/anthropic/v1/messages");
    assert.equal(body.model, "claude-opus-4-6-1");
    assert.equal(options.headers["anthropic-version"], "2023-06-01");
    assert.equal(
      options.headers["Ocp-Apim-Subscription-Key"],
      "synthetic-gateway-key",
    );
    assert.equal(body.output_config.format.type, "json_schema");
    assert.ok(
      !JSON.stringify(body.output_config.format.schema).includes('"maxItems"'),
      "Native response schema must not use unsupported array constraints",
    );
    const constrained =
      body.output_config.format.schema.properties.threats.items.properties;
    assert.deepEqual(
      constrained.interfaceIds.items.enum,
      packet.records.map((r) => r.id),
    );
    assert.deepEqual(
      new Set(constrained.evidenceIds.items.enum),
      new Set(packet.records.flatMap((r) => r.evidence.map((e) => e.id))),
    );
    assert.equal(
      STRIDE_RESPONSE_SCHEMA.properties.threats.items.properties.evidenceIds
        .items.enum,
      undefined,
      "Shared schema must remain unchanged",
    );
    assert.ok(
      body.output_config.format.schema.properties.threats.items.required.includes(
        "analysis",
      ),
    );
    return responseFor("anthropic", result);
  };
  const reviewed = await requestReview(native, packet, transport);
  assert.equal(reviewed.review.threats.length, 1);
  result.threats[0].evidenceIds = ["invented-evidence"];
  await assert.rejects(requestReview(native, packet, transport), /evidence/i);
  result.threats[0].evidenceIds = suggestion(packet).threats[0].evidenceIds;
  result.threats[0].analysis.boundaryIds = ["invented-boundary"];
  await assert.rejects(
    requestReview(native, packet, transport),
    /outside the supplied context/i,
  );
  result.threats[0].analysis.boundaryIds = [];
  await enrichModel(model, native, new Map(), transport);
  assert.equal(model.aiReview.outputContract, "native-json-schema");
  assert.equal(model.aiReview.responseShape.format, "object-prefix");
  await requestReview(gatewayConfig(), packet, async (_, options) => {
    assert.equal(JSON.parse(options.body).output_config, undefined);
    return responseFor("anthropic", result);
  });
});

test("STRIDE validation retry excludes optional connections without relaxing evidence validation", async () => {
  const packet = reviewPacket(await fixture());
  await requestReview(
    config,
    packet,
    async (_, options) => {
      assert.match(
        JSON.parse(options.body).system,
        /connections as an empty array exactly/,
      );
      return responseFor("anthropic", {
        summary: "Review still requires source assessment.",
        threats: [],
        connections: [],
        questions: [],
      });
    },
    { validationRetry: true },
  );
  const result = suggestion(packet);
  result.threats[0].evidenceIds = ["invented"];
  await assert.rejects(
    requestReview(
      config,
      packet,
      async () => responseFor("anthropic", result),
      { validationRetry: true },
    ),
    /evidence/,
  );
});

test("STRIDE failed retry supplies exact security-control and boundary references without weakening validation", async () => {
  const packet = reviewPacket(await fixture());
  packet.records.push({
    id: "security-control",
    kind: "control",
    direction: "control",
    evidence: [{ id: "control-evidence" }],
  });
  packet.records.push({
    id: "deployment-binding",
    kind: "architecture",
    direction: "control",
    evidence: [{ id: "architecture-evidence" }],
  });
  packet.systemContext = { boundaries: [{ id: "boundary-one" }] };
  const result = suggestion(packet);
  result.connections = [];
  result.threats[0].analysis = {
    attackSteps: [
      "If caller access is granted, inspect the privileged operation.",
    ],
    impact: "Potential service authority misuse.",
    assumptions: [],
    controlEvidenceIds: ["control-evidence"],
    boundaryIds: ["boundary-one"],
    mappings: [],
  };
  let normal;
  await requestReview(config, packet, async (_, options) => {
    normal = JSON.parse(options.body).system;
    return responseFor("anthropic", result);
  });
  assert.doesNotMatch(normal, /Retry reference contract/);
  await requestReview(
    config,
    packet,
    async (_, options) => {
      const system = JSON.parse(options.body).system;
      assert.ok(system.startsWith(normal));
      assert.match(system, /Retry reference contract/);
      assert.match(system, /"controlEvidenceIds":\[[^\]]*"control-evidence"/);
      assert.match(system, /"boundaryIds":\["boundary-one"\]/);
      assert.doesNotMatch(system, /"architecture-evidence"/);
      assert.match(system, /connections exactly \[\]/);
      return responseFor("anthropic", result);
    },
    { validationRetry: true },
  );
  for (const bad of ["architecture-evidence", "security-control", "invented"]) {
    result.threats[0].analysis.controlEvidenceIds = [bad];
    assert.throws(
      () => validateReview(result, packet),
      /controlEvidenceIds references are outside/,
    );
  }
  result.threats[0].analysis.controlEvidenceIds = ["control-evidence"];
  result.threats[0].analysis.boundaryIds = ["invented"];
  assert.throws(
    () => validateReview(result, packet),
    /boundaryIds references are outside/,
  );
  const empty = structuredClone(packet);
  empty.records = empty.records.filter((r) => r.kind !== "control");
  delete empty.systemContext;
  await requestReview(
    config,
    empty,
    async (_, options) => {
      assert.match(
        JSON.parse(options.body).system,
        /"controlEvidenceIds":\[\],"boundaryIds":\[\]/,
      );
      return responseFor("anthropic", {
        summary: "Context requires review.",
        threats: [],
        connections: [],
        questions: [],
      });
    },
    { validationRetry: true },
  );
});

test("packet byte accounting preserves the exact UTF-8 boundary with shared indexes", () => {
  const model = {
    profile: "Unicode packet",
    limitations: [],
    components: [{ id: "c", name: "Service" }],
    flows: [],
    boundaries: [],
    interfaces: [],
    evidence: [],
  };
  for (let n = 0; n < 40; n++) {
    model.interfaces.push({
      id: `i${n}`,
      component: "c",
      repository: "repo",
      kind: "http-inbound",
      direction: "inbound",
      protocol: "HTTP",
      operation: '入口"\\'.repeat(300),
      evidence: [`e${n}`],
    });
    model.evidence.push({
      id: `e${n}`,
      repository: "repo",
      path: `Service${n}.cs`,
      line: 1,
      basis: "source",
    });
  }
  const packet = reviewPacket(model);
  assert.ok(packet.records.length > 0 && packet.records.length < 40);
  assert.ok(
    Buffer.byteLength(JSON.stringify(packet)) <= REVIEW_LIMITS.packetBytes,
  );
  const next = reviewPacket({
    ...model,
    interfaces: [model.interfaces[packet.records.length]],
  }).records[0];
  assert.ok(
    Buffer.byteLength(
      JSON.stringify({ ...packet, records: [...packet.records, next] }),
    ) > REVIEW_LIMITS.packetBytes,
  );
  assert.deepEqual(
    reviewPacket(model, new Map(), new Map(), {
      evidence: new Map(model.evidence.map((e) => [e.id, e])),
      components: new Map(model.components.map((c) => [c.id, c])),
    }),
    packet,
  );
});

test("STRIDE native contract restricts connections and standards without changing shared schemas", async () => {
  const { boundStrideSchema } = await import("../src/model-review.mjs");
  const { STRIDE_RESPONSE_SCHEMA } = await import("../src/security-schemas.mjs");
  const { STRIDE_INVESTIGATION_SCHEMA } = await import("../src/stride-evidence.mjs");
  const packet = reviewPacket(await fixture());
  packet.records.push({ id: "control-only", kind: "control", direction: "control",
    evidence: [{ id: "control-proof" }] });
  packet.analysisGuidance = { ...packet.analysisGuidance,
    requirements: [{ id: "required-check" }] };
  for (const schema of [STRIDE_RESPONSE_SCHEMA, STRIDE_INVESTIGATION_SCHEMA]) {
    const original = JSON.stringify(schema);
    const bounded = boundStrideSchema(schema, packet);
    const connection = bounded.properties.connections.items.properties;
    const eligible = packet.records.filter((r) => r.direction !== "control").map((r) => r.id);
    assert.deepEqual(connection.from.enum, [...new Set(eligible)]);
    assert.deepEqual(connection.to.enum, [...new Set(eligible)]);
    assert.ok(!connection.from.enum.includes("control-only"));
    assert.ok(connection.evidenceIds.items.enum.includes("control-proof"), "Controls remain supporting evidence");
    const standards = bounded.properties.standardsReviews.items.properties;
    assert.deepEqual(standards.id.enum, ["required-check"]);
    assert.match(standards.evidenceIds.description, /not-applicable requires supporting evidence/);
    assert.match(bounded.properties.threats.items.properties.evidenceIds.description, /EVERY selected interface/);
    assert.equal(bounded.properties.threats.items.properties.title.enum, undefined, "Endpoint and requirement restrictions must not leak into prose fields");
    assert.equal(JSON.stringify(schema), original);
    for (const records of [[], [packet.records.at(-1)]]) {
      const empty = boundStrideSchema(schema, { records });
      assert.match(empty.properties.connections.description, /empty array/);
      assert.match(empty.properties.standardsReviews.description, /empty array/);
      assert.ok(!JSON.stringify(empty).includes('"enum":[]'));
    }
  }
  await requestReview({ ...gatewayConfig(), structuredOutputs: true }, packet, async (_, options) => {
    const schema = JSON.parse(options.body).output_config.format.schema;
    assert.ok(!schema.properties.connections.items.properties.from.enum.includes("control-only"));
    assert.deepEqual(schema.properties.standardsReviews.items.properties.id.enum, ["required-check"]);
    return responseFor("anthropic", suggestion(packet));
  });
  const invalidConnection = suggestion(packet);
  invalidConnection.connections[0].to = "control-only";
  invalidConnection.connections[0].evidenceIds.push("control-proof");
  assert.throws(() => validateReview(invalidConnection, packet), /connection endpoints cannot be control records/);
  const wrongOwner = suggestion(packet);
  wrongOwner.threats[0].evidenceIds = ["control-proof"];
  assert.throws(() => validateReview(wrongOwner, packet), /evidence must belong/);
  const standards = suggestion(packet);
  standards.standardsReviews = [{ id: "required-check", status: "not-applicable", rationale: "Needs supporting context", evidenceIds: [] }];
  assert.throws(() => validateReview(standards, packet), /standards assessment requires submitted evidence/);
  standards.standardsReviews[0].status = "needs-context";
  assert.doesNotThrow(() => validateReview(standards, packet));
});


test('provider deadline is configurable, bounded, and defaults to five minutes', async () => {
  assert.equal(config.requestTimeoutMs, 300000);
  for (const value of ['no', '0', '600001', '1.5']) assert.throws(() => modelConfig('anthropic', 'model', { ANTHROPIC_API_KEY: 'test', SYNTHESIS_REQUEST_TIMEOUT_MS: value }), /SYNTHESIS_REQUEST_TIMEOUT_MS/);
  const short = modelConfig('anthropic', 'model', { ANTHROPIC_API_KEY: 'test', SYNTHESIS_REQUEST_TIMEOUT_MS: '1000' });
  const model = await fixture();
  const packet = reviewPacket(model);
  const started = Date.now();
  await assert.rejects(requestReview(short, packet, async (_, { signal }) => new Promise((resolve, reject) => {
    const keepAlive = setTimeout(resolve, 5000);
    signal.addEventListener('abort', () => { clearTimeout(keepAlive); reject(signal.reason); }, { once: true });
  })), /request failed or timed out/);
  assert.ok(Date.now() - started < 3000);
});

test('POC rejects a write scenario anchored to the neighboring read operation', async () => {
 const packet=reviewPacket(await fixture()),a=packet.records.find(r=>r.direction!=='control');
 a.operation='GET /settings';packet.reviewFocus={selectedProfile:{name:'Network caller'}};packet.reviewUnit={primaryInterfaceIds:[a.id]};
 const value=suggestion(packet);value.connections=[];value.threats[0].scenario='Caller sends PATCH /settings to change a sensitive setting.';
 assert.throws(()=>validateReview(value,packet),/different HTTP operation/);
 value.threats[0].scenario='Caller sends GET /settings to read a sensitive setting.';
 assert.equal(validateReview(value,packet).threats.length,1);
 packet.reviewUnit.primaryInterfaceIds=[];
 assert.throws(()=>validateReview(value,packet),/selected primary operation/);
});
