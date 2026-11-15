import { createHash } from "node:crypto";
import { once } from "node:events";
import { Zip, ZipPassThrough, unzipSync } from "fflate";
import { diagnosticBundle, safeMetadata } from "./diagnostics.mjs";

export function* jsonArray(values, clean = (value) => value) {
  yield "[";
  let comma = "";
  for (const value of values) {
    yield comma + JSON.stringify(clean(value));
    comma = ",";
  }
  yield "]";
}
export function* graphJson(graph, store, clean = (value) => value) {
  const { nodes, edges, files, ...metadata } = graph;
  yield JSON.stringify(clean({ ...metadata, preview: undefined })).slice(0, -1);
  yield ',"nodes":';
  yield* jsonArray(store.nodes(graph.generation), clean);
  yield ',"edges":';
  yield* jsonArray(store.edges(graph.generation), clean);
  yield ',"files":';
  yield* jsonArray(store.files(graph.generation), clean);
  yield "}";
}
export async function writeChunks(writable, chunks) {
  for await (const chunk of chunks) {
    if (writable.destroyed) throw Error("Export cancelled");
    if (!writable.write(chunk)) await once(writable, "drain");
  }
}
export async function streamGraph(writable, graph, store) {
  await writeChunks(writable, graphJson(graph, store));
}
export async function streamModel(writable, model, store) {
  const { sourceGraph, ...rest } = model;
  await writeChunks(writable, [
    JSON.stringify(rest).slice(0, -1),
    ',"sourceGraph":',
  ]);
  await streamGraph(writable, sourceGraph, store);
  await writeChunks(writable, ["}"]);
}
// Archive records are emitted in bounded chunks. The graph is never buffered as a JSON string or ZIP entry.
export async function streamDiagnosticBundle(writable, store, options) {
  const clean = (value) =>
    safeMetadata(value, options.secrets || [], options.roots || []);
  const small = unzipSync(await diagnosticBundle(options));
  const manifest = [];
  let archiveBytes = 0;
  const archiveMaxBytes = options.archiveMaxBytes ?? 2 * 1024 ** 3;
  let pendingDrain = false,
    zipError;
  const zip = new Zip((error, chunk) => {
    if (error) {
      zipError = error;
      return;
    }
    archiveBytes += chunk.length;
    if (archiveBytes > archiveMaxBytes) {
      zipError = Error(
        "Diagnostic ZIP exceeds its 2 GiB archive budget; export the complete graph separately as JSON.",
      );
      return;
    }
    if (writable.destroyed) {
      zipError = Error("Export cancelled");
      return;
    }
    if (!writable.write(chunk)) pendingDrain = true;
  });
  async function flush() {
    if (zipError) throw zipError;
    if (writable.destroyed) throw Error("Export cancelled");
    if (pendingDrain) {
      if (writable.writableNeedDrain) await once(writable, "drain");
      pendingDrain = false;
    }
  }
  async function entry(name, chunks) {
    const hash = createHash("sha256");
    let bytes = 0;
    const file = new ZipPassThrough(name);
    zip.add(file);
    await flush();
    for await (const input of chunks) {
      const data = typeof input === "string" ? Buffer.from(input) : input;
      // Bound downstream chunks even for an existing metadata entry.
      for (let offset = 0; offset < data.length; offset += 65536) {
        const part = data.subarray(offset, offset + 65536);
        hash.update(part);
        bytes += part.length;
        file.push(part, false);
        await flush();
      }
    }
    file.push(new Uint8Array(), true);
    await flush();
    manifest.push({ name, bytes, sha256: hash.digest("hex") });
  }
  try {
    for (const [name, data] of Object.entries(small))
      if (!["source-graph.json", "manifest.json"].includes(name))
        await entry(name, [data]);
    if (options.model?.sourceGraph?.storage === "sqlite") {
      const g = options.model.sourceGraph;
      await entry("source-graph.json", graphJson(g, store, clean));
      await entry(
        "source-inventory.ndjson",
        (function* () {
          for (const r of store.db
            .prepare(
              "SELECT repository,data FROM inventory WHERE generation=? ORDER BY repository,path",
            )
            .iterate(g.generation))
            yield JSON.stringify(
              clean({ repository: r.repository, ...JSON.parse(r.data) }),
            ) + "\n";
        })(),
      );
      await entry(
        "reference-resolution.ndjson",
        (function* () {
          for (const r of store.db
            .prepare("SELECT data FROM links WHERE generation=? ORDER BY id")
            .iterate(g.generation))
            yield JSON.stringify(clean(JSON.parse(r.data))) + "\n";
          for (const n of store.unresolved(g.generation))
            yield JSON.stringify(
              clean({
                id: n.id,
                kind: "call",
                status: "unresolved",
                repository: n.repository,
                path: n.path,
                line: n.line,
              }),
            ) + "\n";
        })(),
      );
    }
    await entry("manifest.json", [
      JSON.stringify({ schemaVersion: 1, files: manifest }),
    ]);
    zip.end();
    await flush();
  } catch (error) {
    zip.terminate();
    throw error;
  }
}
