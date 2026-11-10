import http from "node:http";
import fs from "node:fs/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { Worker } from "node:worker_threads";
import { parseInventory, MAX_UPLOAD } from "./inventory.mjs";
import { publicModelConfig } from "./model-review.mjs";
import { compose, validateManifest } from "./engine.mjs";
import { reportHtml, diagram } from "./report.mjs";

async function body(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_UPLOAD * 1.4) throw new Error("Request too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
export async function serve({
  sourceRoot,
  port = 4173,
  githubToken,
  quiet = false,
  initialManifest,
  modelConfig,
  includeSourceExcerpts = false,
}) {
  const root = await fs.realpath(sourceRoot),
    token = randomBytes(32).toString("hex");
  if (initialManifest) validateManifest(initialManifest);
  let job = { status: "idle" },
    worker,
    model,
    manifest = initialManifest,
    timer;
  const assets = new Map(
    await Promise.all(
      ["index.html", "app.js", "style.css"].map(async (name) => [
        name,
        await fs.readFile(new URL("../public/" + name, import.meta.url)),
      ]),
    ),
  );
  const server = http.createServer(async (req, res) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    const send = (code, value, type = "application/json") => {
      res.writeHead(code, { "Content-Type": type });
      res.end(type === "application/json" ? JSON.stringify(value) : value);
    };
    try {
      if (
        req.headers.host !== new URL(origin).host ||
        (req.headers.origin && req.headers.origin !== origin)
      )
        return send(403, {
          error: "Only the local application origin is allowed",
        });
      const url = new URL(req.url, origin);
      if (!url.pathname.startsWith("/api/")) {
        if (req.method !== "GET")
          return send(405, { error: "Method not allowed" });
        const name =
          url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        if (!assets.has(name)) return send(404, { error: "Not found" });
        return send(
          200,
          assets.get(name),
          name.endsWith(".js")
            ? "text/javascript"
            : name.endsWith(".css")
              ? "text/css"
              : "text/html",
        );
      }
      const supplied = String(req.headers["x-synthesis-token"] || "");
      if (
        !/^[a-f0-9]{64}$/.test(supplied) ||
        !timingSafeEqual(Buffer.from(supplied), Buffer.from(token))
      )
        return send(401, {
          error: "Open the access link printed by the local server",
        });
      if (req.method === "GET" && url.pathname === "/api/status")
        return send(200, {
          ...job,
          sourceRoot: root,
          githubConfigured: Boolean(githubToken),
          inference: publicModelConfig(modelConfig),
          defaultSourceExcerpts: includeSourceExcerpts,
        });
      if (req.method === "GET" && url.pathname === "/api/manifest")
        return send(200, manifest || null);
      if (req.method === "POST" && url.pathname === "/api/inventory") {
        const input = await body(req);
        if (
          typeof input.base64 !== "string" ||
          typeof input.filename !== "string"
        )
          throw new Error("Choose an XLSX or CSV inventory");
        return send(
          200,
          parseInventory(Buffer.from(input.base64, "base64"), input.filename),
        );
      }
      if (req.method === "POST" && url.pathname === "/api/analyze") {
        if (job.status === "running")
          return send(409, { error: "An analysis is already running" });
        manifest = await body(req);
        validateManifest(manifest);
        if (manifest.analysis?.useModel === true && !modelConfig)
          throw new Error(
            "Start the server with --provider and --model before requesting model review",
          );
        model = null;
        job = { status: "running", message: "Starting static source analysis" };
        worker = new Worker(new URL("./worker.mjs", import.meta.url), {
          workerData: {
            manifest,
            options: {
              sourceRoot: root,
              githubToken,
              modelConfig:
                manifest.analysis?.useModel === true ? modelConfig : null,
              includeSourceExcerpts:
                manifest.analysis?.includeSourceExcerpts === true,
            },
          },
          resourceLimits: { maxOldGenerationSizeMb: 768 },
        });
        const active = worker;
        const activeTimer = setTimeout(
          () => {
            active.terminate();
            job = {
              status: "failed",
              message:
                "Analysis exceeded the 30 minute limit; reduce scope and retry",
            };
          },
          30 * 60 * 1000,
        );
        timer = activeTimer;
        worker.on("message", (m) => {
          if (worker !== active || job.status !== "running") return;
          if (m.type === "progress") job.message = m.message;
          if (m.type === "done") {
            model = m.model;
            job = {
              status: "ready",
              message:
                model.aiReview?.status === "failed"
                  ? "Static draft ready; model review FAILED. See model review details."
                  : "Draft ready for review; coverage gaps remain",
            };
            clearTimeout(activeTimer);
          }
          if (m.type === "error") {
            job = { status: "failed", message: m.message };
            clearTimeout(activeTimer);
          }
        });
        worker.on("error", () => {
          if (worker === active && job.status === "running")
            job = {
              status: "failed",
              message:
                "Analysis worker failed; reduce scope or inspect source limits",
            };
          clearTimeout(activeTimer);
        });
        worker.on("exit", () => {
          if (worker === active && job.status === "running")
            job = {
              status: "failed",
              message: "Analysis worker exited before completion",
            };
          clearTimeout(activeTimer);
        });
        return send(202, job);
      }
      if (req.method === "POST" && url.pathname === "/api/cancel") {
        await worker?.terminate();
        clearTimeout(timer);
        job = {
          status: "cancelled",
          message: "Analysis cancelled; no completed model",
        };
        model = null;
        return send(200, job);
      }
      if (req.method === "GET" && url.pathname === "/api/model")
        return model
          ? send(200, model)
          : send(409, { error: "No completed model" });
      if (req.method === "POST" && url.pathname === "/api/bindings") {
        if (!model) return send(409, { error: "Analyze sources first" });
        const input = await body(req);
        if (input.modelRevision !== model.modelRevision)
          return send(409, {
            error: "Model changed; refresh before saving declarations",
          });
        const revised = structuredClone(model);
        revised.interfaces.forEach((i) => {
          i.resolution = "unresolved";
        });
        compose(revised, { bindings: input.bindings });
        model = revised;
        return send(200, model);
      }
      if (req.method === "GET" && url.pathname === "/api/export") {
        if (!model) return send(409, { error: "No completed model" });
        const format = url.searchParams.get("format");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${format === "html" ? "threat-model.html" : format === "svg" ? "dfd.svg" : format === "manifest" ? "reviewed-manifest.json" : "model.json"}"`,
        );
        if (format === "html") return send(200, reportHtml(model), "text/html");
        if (format === "svg") return send(200, diagram(model), "image/svg+xml");
        if (format === "manifest")
          return send(200, { ...manifest, declarations: model.declarations });
        return send(200, model);
      }
      return send(404, { error: "Not found" });
    } catch (error) {
      return send(400, { error: error.message });
    }
  });
  server.requestTimeout = 30000;
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const url = `http://127.0.0.1:${server.address().port}/#${token}`;
  if (!quiet)
    process.stdout.write(
      `Synthesis static pilot\nSource root: ${root}\nOpen this local access link:\n${url}\nModel: ${modelConfig ? modelConfig.provider + " / " + modelConfig.model : "none"}. Sources are read only. Stop with Ctrl+C.\n`,
    );
  server.on("close", () => {
    clearTimeout(timer);
    worker?.terminate();
  });
  return { server, url, token };
}
