#!/usr/bin/env node
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
import { strideMatrix } from "./graph-review.mjs";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
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
async function main() {
  if (values.help || !command) {
    console.log(
      'Synthesis static pilot (Node.js 22+)\n\nserve --source-root <folder> [--port 4173]\nimport --inventory <xlsx|csv> --profile <name> --out <manifest.json> [--add <repository>]\nanalyze --manifest <json> --source-root <folder> --out <new-report-folder>\n\nGitHub sources use source: "github", url, and optional ref in the manifest.\nGITHUB_TOKEN is optional for public sources and required for private sources.\nNo target execution. Optional: --provider anthropic|anthropic-gateway|gemini --model <approved-model-id> [--include-source-excerpts]. Gateway: --base-url <https-base> [--api-version 2023-06-01]. Keys: ANTHROPIC_API_KEY, CLAUDE_API_KEY (gateway), or GOOGLE_GEMINI_API_KEY (environment only).',
    );
    return;
  }
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
      githubToken: process.env.GITHUB_TOKEN,
      modelConfig: inference,
      includeSourceExcerpts: Boolean(values["include-source-excerpts"]),
      initialManifest: values.manifest
        ? JSON.parse(await fs.readFile(values.manifest, "utf8"))
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
    const model = await analyze(
      JSON.parse(await fs.readFile(values.manifest, "utf8")),
      {
        sourceRoot: root,
        githubToken: process.env.GITHUB_TOKEN,
        modelConfig: inference,
        includeSourceExcerpts: Boolean(values["include-source-excerpts"]),
        reviewBatches: values["review-batches"]
          ? Number(values["review-batches"])
          : undefined,
        progress: console.log,
      },
    );
    await fs.writeFile(
      path.join(output, "model.json"),
      JSON.stringify({ ...model, strideMatrix: strideMatrix(model) }, null, 2),
    );
    await fs.writeFile(
      path.join(output, "threat-model.html"),
      reportHtml(model),
    );
    await fs.writeFile(path.join(output, "dfd.svg"), diagram(model));
    await fs.writeFile(path.join(output, "dfd.mmd"), dfdMermaid(model));
    await fs.writeFile(
      path.join(output, "source-graph.json"),
      JSON.stringify(model.sourceGraph, null, 2),
    );
    await fs.writeFile(
      path.join(output, "stride-matrix.csv"),
      strideCsv(model),
    );
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
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
