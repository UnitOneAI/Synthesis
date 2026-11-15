#!/usr/bin/env node
import { createWriteStream } from "node:fs";
import { finished } from "node:stream/promises";
import { GraphStore, attachGraph } from "./graph-store.mjs";
import {
  streamGraph,
  streamModel,
  streamDiagnosticBundle,
} from "./graph-stream.mjs";
import {
  traceStore,
  diagnosticBundle,
  readTraces,
  failureDetail,
} from "./diagnostics.mjs";
import { sha } from "./sources.mjs";
import { usageCsv, usageSummary } from "./token-usage.mjs";
import { systemModel } from "./system-model.mjs";
import {
  systemSvg,
  systemMermaid,
  systemReport,
  registerCsv,
} from "./system-exports.mjs";
import fs from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import { analyze } from "./engine.mjs";
import { parseInventory } from "./inventory.mjs";
import { serve } from "./server.mjs";
import { reportHtml, diagram } from "./report.mjs";
import { modelConfig } from "./model-review.mjs";
import { within } from "./sources.mjs";
import { dfdMermaid, strideCsv } from "./graph-exports.mjs";
import { strideMatrix, reviewPlan } from "./graph-review.mjs";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    workspace: { type: "string" },
    "graph-storage": { type: "string" },
    "trace-dir": { type: "string" },
    "cwe-scanner": { type: "string" },
    "source-root": { type: "string" },
    port: { type: "string" },
    inventory: { type: "string" },
    manifest: { type: "string" },
    out: { type: "string" },
    profile: { type: "string" },
    add: { type: "string", multiple: true },
    provider: { type: "string" },
    model: { type: "string" },
    "base-url": { type: "string" },
    "api-version": { type: "string" },
    "include-source-excerpts": { type: "boolean" },
    "review-batches": { type: "string" },
    help: { type: "boolean" },
  },
});
const [command] = positionals;
let trace, graphStore;
async function writeStreamFile(file, write) {
  const temporary = file + ".partial";
  const stream = createWriteStream(temporary, { flags: "wx", mode: 0o600 });
  const completion = finished(stream);
  completion.catch(() => {});
  try {
    await write(stream);
    stream.end();
    await completion;
    await fs.link(temporary, file);
    await fs.unlink(temporary);
  } catch (error) {
    stream.destroy();
    await completion.catch(() => {});
    await fs.rm(temporary, { force: true });
    throw error;
  }
}
async function main() {
  if (values.help || !command) {
    console.log(
      'Synthesis static pilot (current Node.js 24 recommended for disk storage)\n\nserve --source-root <folder> [--workspace <folder-outside-source-root>] [--port 4173] [--graph-storage sqlite|memory] [--cwe-scanner <semgrep-executable>]\nimport --inventory <xlsx|csv> --profile <name> --out <manifest.json> [--add <repository>]\nanalyze --manifest <json> --source-root <folder> --out <new-report-folder>\n\ndiagnostics --workspace <folder> --out <new-file.zip> [--trace-dir <folder>]\n\nGitHub sources use source: "github", url, and optional ref in the manifest.\nGITHUB_TOKEN is optional for public sources and required for private sources.\nNo target execution. Optional: --provider anthropic|anthropic-gateway|gemini --model <approved-model-id> [--include-source-excerpts]. Gateway: --base-url <https-base> [--api-version 2023-06-01]. Keys: ANTHROPIC_API_KEY, CLAUDE_API_KEY (gateway), or GOOGLE_GEMINI_API_KEY (environment only).',
    );
    return;
  }
  if (command === "diagnostics") {
    if (!values.workspace || !values.out)
      throw Error("Diagnostics requires --workspace and --out <new-file.zip>");
    const file = path.join(path.resolve(values.workspace), "snapshot.json");
    let model;
    try {
      if ((await fs.stat(file)).size > 180 * 1024 * 1024)
        throw Error("Workspace snapshot exceeds size limit");
      const envelope = JSON.parse(await fs.readFile(file, "utf8"));
      if (
        envelope.version !== 1 ||
        envelope.digest !== sha(JSON.stringify(envelope.data))
      )
        throw Error("Workspace snapshot validation failed");
      model = envelope.data.model;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    const traces = await readTraces(
      values["trace-dir"] || path.join(values.workspace, "traces"),
    );
    if (model?.sourceGraph?.storage === "sqlite") {
      graphStore = new GraphStore(
        path.join(path.resolve(values.workspace), "graph.sqlite"),
        { readOnly: true },
      );
      attachGraph(model.sourceGraph, graphStore);
      await writeStreamFile(values.out, (stream) =>
        streamDiagnosticBundle(stream, graphStore, {
          model,
          plan: model.aiReview?.plan ? undefined : reviewPlan(model),
          traces,
        }),
      );
      graphStore.close();
      graphStore = null;
      console.log(
        `Diagnostic bundle written to ${values.out}. Contains confidential architecture metadata.`,
      );
      return;
    }
    const bundle = await diagnosticBundle({
      model,
      plan: model && !model.aiReview?.plan ? reviewPlan(model) : undefined,
      traces,
    });
    await fs.writeFile(values.out, bundle, { flag: "wx", mode: 0o600 });
    console.log(
      `Diagnostic bundle written to ${values.out}. Inspect confidential architecture metadata before sharing.`,
    );
    return;
  }
  if (
    values["graph-storage"] &&
    !["sqlite", "memory"].includes(values["graph-storage"])
  )
    throw Error("Graph storage must be sqlite or memory");
  const inference =
    command === "import"
      ? null
      : modelConfig(
          values.provider || process.env.SYNTHESIS_LLM_PROVIDER || "none",
          values.model || process.env.SYNTHESIS_LLM_MODEL,
          process.env,
          { baseUrl: values["base-url"], apiVersion: values["api-version"] },
        );
  if (values["include-source-excerpts"] && !inference)
    throw new Error(
      "Source excerpts require an explicitly configured provider",
    );
  if (command === "serve") {
    if (!values["source-root"])
      throw new Error("Specify --source-root explicitly");
    const port = Number(values.port || 4173);
    if (!Number.isInteger(port) || port < 0 || port > 65535)
      throw new Error("Invalid port");
    await serve({
      sourceRoot: values["source-root"],
      port,
      persist: true,
      graphStorage: values["graph-storage"] || "sqlite",
      workspace: values.workspace,
      traceDirectory: values["trace-dir"],
      cweScanner: values["cwe-scanner"],
      githubToken: process.env.GITHUB_TOKEN,
      modelConfig: inference,
      includeSourceExcerpts: Boolean(values["include-source-excerpts"]),
      initialManifest: values.manifest
        ? JSON.parse(
            (await fs.readFile(values.manifest, "utf8")).replace(/^\uFEFF/, ""),
          )
        : undefined,
    });
    return;
  }
  if (command === "import") {
    if (!values.inventory || !values.out || !values.profile)
      throw new Error("Import requires --inventory, --profile and --out");
    const inventory = parseInventory(
      await fs.readFile(values.inventory),
      values.inventory,
    );
    for (const name of values.add || []) {
      const r = inventory.repositories.find((r) => r.name === name);
      if (!r)
        throw new Error(
          `Additional repository is absent from the inventory: ${name}`,
        );
      r.selected = true;
    }
    await fs.writeFile(
      values.out,
      JSON.stringify(
        {
          title: "Static system threat model",
          profile: values.profile,
          repositories: inventory.repositories,
          declarations: { bindings: [] },
        },
        null,
        2,
      ),
      { flag: "wx" },
    );
    console.log(
      `${inventory.repositories.length} inventory repositories; ${inventory.repositories.filter((r) => r.selected).length} selected. Manifest written to ${values.out}`,
    );
    for (const w of inventory.warnings) console.warn(w);
    return;
  }
  if (command === "analyze") {
    if (!values.manifest || !values.out || !values["source-root"])
      throw new Error("Analyze requires --manifest, --source-root and --out");
    const root = await fs.realpath(values["source-root"]),
      output = path.resolve(values.out);
    if (within(root, output))
      throw new Error("Report output must be outside the source root");
    await fs.mkdir(output, { recursive: false });
    trace = await traceStore({
      directory: values["trace-dir"] || path.join(output, "traces"),
      sourceRoot: root,
      secrets: [inference?.apiKey, process.env.GITHUB_TOKEN],
    });
    await trace.record("cli.started", {
      mode: "analyze",
      provider: inference?.provider || "none",
      model: inference?.model,
    });
    const model = await analyze(
      JSON.parse(
        (await fs.readFile(values.manifest, "utf8")).replace(/^\uFEFF/, ""),
      ),
      {
        sourceRoot: root,
        graphDatabase:
          values["graph-storage"] === "memory"
            ? undefined
            : path.join(output, "graph.sqlite"),
        githubToken: process.env.GITHUB_TOKEN,
        modelConfig: inference,
        includeSourceExcerpts: Boolean(values["include-source-excerpts"]),
        reviewBatches: values["review-batches"]
          ? Number(values["review-batches"])
          : undefined,
        progress: console.log,
        trace: trace.record,
      },
    );
    if (model.sourceGraph?.storage === "sqlite") {
      graphStore = new GraphStore(path.join(output, "graph.sqlite"), {
        readOnly: true,
      });
      attachGraph(model.sourceGraph, graphStore);
    }
    const exported = {
      ...model,
      strideMatrix: strideMatrix(model),
      systemModel: systemModel(model),
      tokenUsage: usageSummary(
        model.usageLedger,
        !model.usageLedger && Boolean(model.aiReview),
      ),
    };
    if (graphStore)
      await writeStreamFile(path.join(output, "model.json"), (stream) =>
        streamModel(stream, exported, graphStore),
      );
    else
      await fs.writeFile(
        path.join(output, "model.json"),
        JSON.stringify(exported, null, 2),
      );
    await fs.writeFile(
      path.join(output, "threat-model.html"),
      systemReport(model),
    );
    await fs.writeFile(
      path.join(output, "token-usage.csv"),
      usageCsv(model.usageLedger),
    );
    await fs.writeFile(path.join(output, "dfd.svg"), systemSvg(model));
    await fs.writeFile(path.join(output, "dfd.mmd"), systemMermaid(model));
    if (graphStore)
      await writeStreamFile(path.join(output, "source-graph.json"), (stream) =>
        streamGraph(stream, model.sourceGraph, graphStore),
      );
    else
      await fs.writeFile(
        path.join(output, "source-graph.json"),
        JSON.stringify(model.sourceGraph, null, 2),
      );
    await fs.writeFile(
      path.join(output, "stride-matrix.csv"),
      registerCsv(model, "matrix"),
    );
    for (const kind of [
      "securityControls",
      "actors",
      "boundaries",
      "threats",
      "flows",
      "components",
      "assets",
    ])
      await fs.writeFile(
        path.join(output, kind + ".csv"),
        registerCsv(model, kind),
      );
    const diagnosticOptions = {
      model,
      plan: !model.aiReview?.plan ? reviewPlan(model) : undefined,
      traces: await trace.export(),
      config: inference,
      secrets: [inference?.apiKey, process.env.GITHUB_TOKEN],
      roots: [root],
    };
    if (graphStore)
      await writeStreamFile(
        path.join(output, "synthesis-diagnostics.zip"),
        (stream) =>
          streamDiagnosticBundle(stream, graphStore, diagnosticOptions),
      );
    else
      await fs.writeFile(
        path.join(output, "synthesis-diagnostics.zip"),
        await diagnosticBundle(diagnosticOptions),
      );
    graphStore?.close();
    graphStore = null;
    await trace.close();
    console.log(
      `Draft with gaps: ${model.interfaces.length} interface/control candidates, ${model.flows.length} declared flows. Reports: ${output}`,
    );
    if (["failed", "partial"].includes(model.aiReview?.status)) {
      console.error(
        "Model review failed: " +
          model.aiReview.error +
          ". Static draft exported.",
      );
      process.exitCode = 3;
    } else if (model.sources.some((s) => s.status === "unavailable"))
      process.exitCode = 2;
    return;
  }
  throw new Error("Unknown command; use --help");
}
main().catch(async (error) => {
  await trace
    ?.record("cli.failed", { failure: failureDetail(error.message) })
    .catch(() => {});
  await trace?.close();
  graphStore?.close();
  console.error(error.message);
  process.exitCode = 1;
});
