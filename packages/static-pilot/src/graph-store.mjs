import { DatabaseSync, backup } from "node:sqlite";
import { createHash, randomUUID } from "node:crypto";
import { statfsSync, statSync, lstatSync, chmodSync } from "node:fs";
import path from "node:path";
import { id, sha } from "./sources.mjs";
import { redact } from "./model-review.mjs";

export const GRAPH_SCHEMA = 1;
export const EXTRACTOR_KEY = "disk-graph-7-internal-topology";
const bindings = new WeakMap();
const json = JSON.stringify;
const parse = (row) => (row ? JSON.parse(row.data) : undefined);
export function sqliteSupported() {
  const [a, b, c] = (process.versions.sqlite || "0.0.0").split(".").map(Number);
  return a > 3 || (a === 3 && (b > 51 || (b === 51 && c >= 3)));
}
export function graphReader(graph) {
  const reader = graph && bindings.get(graph);
  if (reader && !reader.db) {
    bindings.delete(graph);
    return undefined;
  }
  return reader;
}
export function attachGraph(graph, store) {
  if (graph?.storage === "sqlite") bindings.set(graph, store);
  return graph;
}
export class GraphStore {
  constructor(
    file,
    {
      readOnly = false,
      minFreeBytes = 256 * 1024 * 1024,
      maxBytes = 64 * 1024 ** 3,
    } = {},
  ) {
    if (!sqliteSupported())
      throw Error(
        "Disk graph requires SQLite 3.51.3 or newer. Install a current Node.js 24 release; use --graph-storage memory only for the existing bounded mode.",
      );
    this.file = file;
    this.readOnly = readOnly;
    this.minFreeBytes = minFreeBytes;
    this.maxBytes = maxBytes;
    for (const candidate of [file, file + "-wal", file + "-shm"]) {
      try {
        if (lstatSync(candidate).isSymbolicLink())
          throw Error("Graph database and journals must not be symbolic links");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    this.db = new DatabaseSync(file, { readOnly });
    if (!readOnly) chmodSync(file, 0o600);
    this.db.exec(
      "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA cache_size=-16384; PRAGMA temp_store=FILE;",
    );
    const version = this.db.prepare("PRAGMA user_version").get().user_version;
    if (version > GRAPH_SCHEMA || (readOnly && version !== GRAPH_SCHEMA)) {
      this.close();
      throw Error("Unsupported graph database schema");
    }
    if (!readOnly) {
      this.db.exec(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=1000;",
      );
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS generations (id TEXT PRIMARY KEY, state TEXT NOT NULL, manifest_hash TEXT NOT NULL, created TEXT NOT NULL, data TEXT);
        CREATE TABLE IF NOT EXISTS versions (id TEXT PRIMARY KEY, repository TEXT NOT NULL, path TEXT NOT NULL, hash TEXT NOT NULL, extractor TEXT NOT NULL, result TEXT NOT NULL, ledger TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS members (generation TEXT NOT NULL REFERENCES generations(id), repository TEXT NOT NULL, path TEXT NOT NULL, version TEXT NOT NULL REFERENCES versions(id), PRIMARY KEY(generation,repository,path));
        CREATE INDEX IF NOT EXISTS members_version ON members(version,generation);
        CREATE TABLE IF NOT EXISTS nodes (version TEXT NOT NULL REFERENCES versions(id), id TEXT NOT NULL, kind TEXT NOT NULL, parent TEXT, name TEXT, repository TEXT NOT NULL, path TEXT, data TEXT NOT NULL, PRIMARY KEY(version,id));
        CREATE INDEX IF NOT EXISTS nodes_id ON nodes(id,version);
        CREATE INDEX IF NOT EXISTS nodes_parent ON nodes(parent,version,kind);
        CREATE INDEX IF NOT EXISTS nodes_kind ON nodes(kind,version,id);
        CREATE TABLE IF NOT EXISTS edges (version TEXT NOT NULL REFERENCES versions(id), id TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(version,id));
        CREATE INDEX IF NOT EXISTS edges_source ON edges(source,version,kind);
        CREATE INDEX IF NOT EXISTS edges_target ON edges(target,version,kind);
        CREATE TABLE IF NOT EXISTS links (generation TEXT NOT NULL REFERENCES generations(id), id TEXT NOT NULL, source TEXT NOT NULL, target TEXT, kind TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(generation,id));
        CREATE INDEX IF NOT EXISTS links_source ON links(generation,source,kind);
        CREATE INDEX IF NOT EXISTS links_target ON links(generation,target,kind);
        CREATE TABLE IF NOT EXISTS inventory (generation TEXT NOT NULL REFERENCES generations(id), repository TEXT NOT NULL, path TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(generation,repository,path));
        CREATE TABLE IF NOT EXISTS traversal (job TEXT NOT NULL, node TEXT NOT NULL, predecessor TEXT, call TEXT, processed INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL, PRIMARY KEY(job,node));
        CREATE INDEX IF NOT EXISTS traversal_queue ON traversal(job,processed,seq);
        CREATE TABLE IF NOT EXISTS work (generation TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(generation,kind,id));
        PRAGMA user_version=1;
      `);
    }
  }
  close() {
    this.db?.close();
    this.db = null;
  }
  transaction(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  capacity() {
    const fs = statfsSync(path.dirname(this.file));
    const freeBytes = fs.bavail * fs.bsize;
    const databaseBytes = statSync(this.file).size;
    let walBytes = 0;
    try {
      walBytes = statSync(this.file + "-wal").size;
    } catch {}
    if (
      freeBytes < this.minFreeBytes ||
      databaseBytes + walBytes > this.maxBytes
    )
      throw Error(
        "Disk graph storage budget reached; free local space or increase the explicit storage budget before resuming. Last published generation retained.",
      );
    return {
      freeBytes,
      databaseBytes,
      walBytes,
      sqliteVersion: process.versions.sqlite,
      schema: GRAPH_SCHEMA,
    };
  }
  begin(manifest, rootHash) {
    const priorRoot = parse(
      this.db.prepare("SELECT data FROM meta WHERE key='root'").get(),
    );
    if (priorRoot && priorRoot !== rootHash)
      throw Error("Graph workspace belongs to a different source root");
    this.capacity();
    const generation = randomUUID();
    this.transaction(() => {
      this.db
        .prepare("INSERT OR IGNORE INTO meta VALUES('root',?)")
        .run(json(rootHash));
      this.db
        .prepare("INSERT INTO generations VALUES(?,?,?,?,NULL)")
        .run(
          generation,
          "working",
          sha(json(manifest)),
          new Date().toISOString(),
        );
    });
    return generation;
  }
  cacheKey(source, file, projectPaths = []) {
    return sha(
      json([EXTRACTOR_KEY, source.name, file.path, file.hash, projectPaths]),
    );
  }
  assertWorking(generation) {
    if (
      this.db
        .prepare("SELECT state FROM generations WHERE id=?")
        .get(generation)?.state !== "working"
    )
      throw Error("Published graph generations are immutable");
  }
  reuse(generation, source, file, key) {
    this.assertWorking(generation);
    const row = this.db
      .prepare("SELECT result FROM versions WHERE id=?")
      .get(key);
    if (!row) return null;
    this.db
      .prepare("INSERT OR REPLACE INTO members VALUES(?,?,?,?)")
      .run(generation, source.name, file.path, key);
    return JSON.parse(row.result);
  }
  commitFile(generation, source, file, key, graph, result) {
    this.assertWorking(generation);
    this.capacity();
    this.transaction(() => {
      this.db
        .prepare("INSERT OR IGNORE INTO versions VALUES(?,?,?,?,?,?,?)")
        .run(
          key,
          source.name,
          file.path,
          file.hash,
          EXTRACTOR_KEY,
          json(result),
          json(graph.files[0]),
        );
      const node = this.db.prepare(
        "INSERT OR IGNORE INTO nodes VALUES(?,?,?,?,?,?,?,?)",
      );
      for (const n of graph.nodes.filter((n) => n.kind !== "repository"))
        node.run(
          key,
          n.id,
          n.kind,
          n.parent || null,
          n.name || "",
          n.repository,
          n.path || null,
          json(n),
        );
      const edge = this.db.prepare(
        "INSERT OR IGNORE INTO edges VALUES(?,?,?,?,?,?)",
      );
      for (const e of graph.edges)
        edge.run(key, e.id, e.from, e.to, e.kind, json(e));
      this.db
        .prepare("INSERT OR REPLACE INTO members VALUES(?,?,?,?)")
        .run(generation, source.name, file.path, key);
    });
  }
  discardSource(generation, repository) {
    this.assertWorking(generation);
    this.db
      .prepare("DELETE FROM members WHERE generation=? AND repository=?")
      .run(generation, repository);
  }
  inventory(generation, repository, entry) {
    this.assertWorking(generation);
    this.db
      .prepare("INSERT OR REPLACE INTO inventory VALUES(?,?,?,?)")
      .run(generation, repository, entry.path, json(entry));
  }
  *rows(
    table,
    generation,
    {
      kind,
      parent,
      repository,
      path: filePath,
      after = "",
      limit = Number.MAX_SAFE_INTEGER,
    } = {},
  ) {
    if (!["nodes", "edges"].includes(table))
      throw Error("Invalid graph collection");
    const alias = table === "nodes" ? "n" : "e";
    const filters = [`m.generation=?`, `${alias}.id>?`];
    const args = [generation, after];
    if (kind) {
      filters.push(`${alias}.kind=?`);
      args.push(kind);
    }
    if (parent !== undefined && table === "nodes") {
      filters.push("n.parent=?");
      args.push(parent);
    }
    if (repository) {
      filters.push("m.repository=?");
      args.push(repository);
    }
    if (filePath) {
      filters.push("m.path=?");
      args.push(filePath);
    }
    const index =
      table === "nodes" && parent !== undefined
        ? " INDEXED BY nodes_parent"
        : "";
    const sql = `SELECT ${alias}.data FROM ${table} ${alias}${index} CROSS JOIN members m ON m.version=${alias}.version WHERE ${filters.join(" AND ")} ORDER BY ${alias}.id LIMIT ?`;
    for (const row of this.db.prepare(sql).iterate(...args, limit))
      yield parse(row);
  }
  *nodes(generation, options) {
    if (
      !options ||
      (!options.kind && options.parent === undefined) ||
      options.kind === "repository"
    ) {
      for (const row of this.db
        .prepare(
          "SELECT DISTINCT repository FROM members WHERE generation=? ORDER BY repository",
        )
        .iterate(generation)) {
        const n = {
          id: id("graph-repo", row.repository),
          kind: "repository",
          repository: row.repository,
          name: row.repository,
        };
        if (
          (!options?.repository || options.repository === row.repository) &&
          (!options?.after || n.id > options.after)
        )
          yield n;
      }
    }
    yield* this.rows("nodes", generation, options);
  }
  *edges(generation, options) {
    yield* this.rows("edges", generation, options);
    const args = [generation];
    let filter = "";
    if (options?.kind) {
      filter = " AND kind=?";
      args.push(options.kind);
    }
    for (const row of this.db
      .prepare(
        `SELECT data FROM links WHERE generation=? AND status='candidate'${filter} ORDER BY id`,
      )
      .iterate(...args))
      yield parse(row);
  }
  node(generation, nodeId) {
    return parse(
      this.db
        .prepare(
          "SELECT n.data FROM nodes n INDEXED BY nodes_id CROSS JOIN members m ON m.version=n.version WHERE m.generation=? AND n.id=? LIMIT 1",
        )
        .get(generation, nodeId),
    );
  }
  *incidentEdges(generation, nodeId, limit = 1000) {
    let remaining = limit;
    for (const [column, index] of [
      ["source", "edges_source"],
      ["target", "edges_target"],
    ]) {
      for (const row of this.db
        .prepare(
          `SELECT e.data FROM edges e INDEXED BY ${index} CROSS JOIN members m ON m.version=e.version WHERE e.${column}=? AND m.generation=? ORDER BY e.id LIMIT ?`,
        )
        .iterate(nodeId, generation, remaining)) {
        yield parse(row);
        if (--remaining === 0) return;
      }
    }
    for (const column of ["source", "target"]) {
      for (const row of this.db
        .prepare(
          `SELECT data FROM links WHERE generation=? AND ${column}=? ORDER BY id LIMIT ?`,
        )
        .iterate(generation, nodeId, remaining)) {
        yield parse(row);
        if (--remaining === 0) return;
      }
    }
  }
  incidentPage(generation, nodeId, { after = "", limit = 32 } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500)
      throw Error("Invalid edge page size");
    const rows = this.db
      .prepare(
        `SELECT id,data FROM (
      SELECT e.id,e.data FROM edges e INDEXED BY edges_source JOIN members m ON m.version=e.version WHERE m.generation=? AND e.source=?
      UNION SELECT e.id,e.data FROM edges e INDEXED BY edges_target JOIN members m ON m.version=e.version WHERE m.generation=? AND e.target=?
      UNION SELECT id,data FROM links WHERE generation=? AND (source=? OR target=?)
    ) WHERE id>? ORDER BY id LIMIT ?`,
      )
      .all(
        generation,
        nodeId,
        generation,
        nodeId,
        generation,
        nodeId,
        nodeId,
        after,
        limit + 1,
      )
      .map(parse);
    return {
      items: rows.slice(0, limit),
      next: rows.length > limit ? rows[limit - 1].id : null,
    };
  }
  extractorKeys(generation) {
    return this.db
      .prepare(
        "SELECT DISTINCT v.extractor FROM versions v JOIN members m ON m.version=v.id WHERE m.generation=?",
      )
      .all(generation)
      .map((r) => r.extractor);
  }
  *inventoryEntries(generation) {
    for (const r of this.db.prepare("SELECT repository,data FROM inventory WHERE generation=? ORDER BY repository,path").iterate(generation))
      yield {...parse(r), repository:r.repository};
  }
  *files(generation) {
    for (const r of this.db
      .prepare(
        "SELECT v.ledger AS data FROM versions v JOIN members m ON m.version=v.id WHERE m.generation=? ORDER BY m.repository,m.path",
      )
      .iterate(generation))
      yield parse(r);
  }
  resolveProjects(generation, selected, root) {
    this.assertWorking(generation);
    // Literal paths only; there is no project evaluation, target execution or dependency download.
    const sources = new Map(selected.map((s) => [s.name, s]));
    const normalize = (p) =>
      process.platform === "win32" ? p.toLowerCase() : p;
    this.db.exec(
      "CREATE TEMP TABLE IF NOT EXISTS project_paths(path TEXT PRIMARY KEY,node TEXT NOT NULL); DELETE FROM project_paths;",
    );
    const insert = this.db.prepare(
      "INSERT OR IGNORE INTO project_paths VALUES(?,?)",
    );
    for (const f of this.nodes(generation, { kind: "file" })) {
      const s = sources.get(f.repository);
      if (s?.source !== "github")
        insert.run(
          normalize(path.resolve(root, s.localPath || s.name, f.path)),
          f.id,
        );
    }
    this.db.prepare("DELETE FROM links WHERE generation=?").run(generation);
    const link = this.db.prepare("INSERT INTO links VALUES(?,?,?,?,?,?,?)");
    for (const n of this.nodes(generation, { kind: "dependency" })) {
      if (!n.pointer?.includes("ProjectReference")) continue;
      const source = sources.get(n.repository);
      const candidate =
        source?.source !== "github" && !n.name.includes("$(")
          ? this.db
              .prepare("SELECT node FROM project_paths WHERE path=?")
              .get(
                normalize(
                  path.resolve(
                    root,
                    source.localPath || source.name,
                    path.posix.dirname(n.path),
                    n.name.replaceAll("\\", "/"),
                  ),
                ),
              )
          : null;
      const e = {
        id: id("project-reference", n.id, candidate?.node || "unresolved"),
        from: n.id,
        to: candidate?.node || null,
        kind: "project-reference",
        basis:
          "literal project path; build conditions and runtime use unverified",
        status: candidate ? "candidate" : "unresolved",
      };
      link.run(generation, e.id, e.from, e.to, e.kind, e.status, json(e));
    }
  }
  summary(generation) {
    const count = (table) =>
      this.db
        .prepare(
          `SELECT count(*) AS n FROM ${table} x JOIN members m ON m.version=x.version WHERE m.generation=?`,
        )
        .get(generation).n;
    const byKind = Object.fromEntries(
      this.db
        .prepare(
          "SELECT n.kind,count(*) AS n FROM nodes n JOIN members m ON m.version=n.version WHERE m.generation=? GROUP BY n.kind",
        )
        .all(generation)
        .map((r) => [r.kind, r.n]),
    );
    const edgeKinds = Object.fromEntries(
      this.db
        .prepare(
          "SELECT e.kind,count(*) AS n FROM edges e JOIN members m ON m.version=e.version WHERE m.generation=? GROUP BY e.kind",
        )
        .all(generation)
        .map((r) => [r.kind, r.n]),
    );
    for (const r of this.db
      .prepare(
        "SELECT kind,count(*) AS n FROM links WHERE generation=? AND status='candidate' GROUP BY kind",
      )
      .all(generation))
      edgeKinds[r.kind] = (edgeKinds[r.kind] || 0) + r.n;
    const coverage = {
      parsed: 0,
      syntaxErrors: 0,
      unsupported: 0,
      failed: 0,
      limited: 0,
    };
    for (const r of this.db
      .prepare(
        "SELECT json_extract(v.ledger,'$.status') AS status,count(*) AS n FROM versions v JOIN members m ON m.version=v.id WHERE m.generation=? GROUP BY status",
      )
      .all(generation)) {
      const k = {
        parsed: "parsed",
        "syntax-errors": "syntaxErrors",
        "unsupported-language": "unsupported",
        "graph-limit": "limited",
        "parse-failed-or-timed-out": "failed",
      }[r.status];
      if (k) coverage[k] += r.n;
    }
    const repositories = this.db
      .prepare(
        "SELECT count(DISTINCT repository) AS n FROM members WHERE generation=?",
      )
      .get(generation).n;
    byKind.repository = repositories;
    return {
      nodes: count("nodes") + repositories,
      edges: Object.values(edgeKinds).reduce((a, b) => a + b, 0),
      files: this.db
        .prepare("SELECT count(*) AS n FROM members WHERE generation=?")
        .get(generation).n,
      byKind,
      edgeKinds,
      coverage,
    };
  }
  publish(generation, sourceGraph) {
    this.assertWorking(generation);
    const hash = createHash("sha256");
    for (const r of this.db
      .prepare(
        "SELECT repository,path,version FROM members WHERE generation=? ORDER BY repository,path",
      )
      .iterate(generation))
      hash.update(json(r));
    for (const r of this.db
      .prepare("SELECT data FROM links WHERE generation=? ORDER BY id")
      .iterate(generation))
      hash.update(r.data);
    const stats = this.summary(generation);
    const graph = {
      ...sourceGraph,
      storage: "sqlite",
      extractorKey: EXTRACTOR_KEY,
      generation,
      fingerprint: hash.digest("hex"),
      nodes: [],
      edges: [],
      files: [],
      counts: stats,
      coverage: stats.coverage,
      limits: { ...sourceGraph.limits, nodes: null, edges: null },
      preview: { nodes: 0, edges: 0, files: 0, complete: false },
      runtime: { schema: GRAPH_SCHEMA, sqlite: process.versions.sqlite },
    };
    this.transaction(() => {
      this.db
        .prepare(
          "UPDATE generations SET state='published',data=? WHERE id=? AND state='working'",
        )
        .run(json(graph), generation);
      this.db
        .prepare("INSERT OR REPLACE INTO meta VALUES('published',?)")
        .run(json(generation));
    });
    return attachGraph(graph, this);
  }
  validateGeneration(graph) {
    const row = this.db
      .prepare("SELECT state,data FROM generations WHERE id=?")
      .get(graph.generation);
    if (
      row?.state !== "published" ||
      JSON.parse(row.data).fingerprint !== graph.fingerprint
    )
      throw Error(
        "Saved graph generation is missing or does not match the workspace. Restore the complete workspace backup, or use a new workspace and rebuild.",
      );
  }
  page(generation, { kind, after = "", limit = 100, search = "" } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500)
      throw Error("Graph page size must be 1–500");
    const filter = ["m.generation=?", "n.id>?"];
    const args = [generation, after];
    if (kind) {
      filter.push("n.kind=?");
      args.push(kind);
    }
    if (search) {
      filter.push(
        "instr(lower(n.name || ' ' || coalesce(n.path,'') || ' ' || n.repository),?)>0",
      );
      args.push(search.toLowerCase().slice(0, 200));
    }
    const rows = this.db
      .prepare(
        `SELECT n.data FROM nodes n JOIN members m ON m.version=n.version WHERE ${filter.join(" AND ")} ORDER BY n.id LIMIT ?`,
      )
      .all(...args, limit + 1)
      .map(parse);
    return {
      generation,
      items: rows.slice(0, limit),
      next: rows.length > limit ? rows[limit - 1].id : null,
    };
  }
  contexts(generation) {
    const nodes = new Map(),
      owners = new Map();
    const remember = (cache, key, value) => {
      if (cache.size >= 2000) cache.delete(cache.keys().next().value);
      cache.set(key, value);
      return value;
    };
    const node = (key) =>
      nodes.has(key)
        ? nodes.get(key)
        : remember(nodes, key, this.node(generation, key));
    return {
      has: (key) => node(key)?.kind === "interface",
      get: (key) => {
        const n = node(key);
        if (!n) return undefined;
        if (owners.has(n.parent)) return owners.get(n.parent);
        const owner = node(n.parent);
        const peers = this.rows("nodes", generation, { parent: n.parent });
        const calls = [],
          interfaces = [];
        let callCount = 0,
          interfaceCount = 0;
        for (const p of peers) {
          if (p.kind === "call" && owner?.kind === "function") {
            callCount++;
            if (calls.length < 12)
              calls.push({
                id: p.id,
                name: redact(p.name),
                line: p.line,
                target: "unresolved",
              });
          }
          if (p.kind === "interface") {
            interfaceCount++;
            if (interfaces.length < 12) interfaces.push(p.id);
          }
        }
        return remember(owners, n.parent, {
          owner: owner
            ? {
                id: owner.id,
                kind: owner.kind,
                name: redact(owner.name),
                path: redact(owner.path),
                line: owner.line,
              }
            : null,
          calls,
          nearbyInterfaceIds: interfaces,
          omittedCalls: Math.max(0, callCount - 12),
          omittedNearbyInterfaces: Math.max(0, interfaceCount - 12),
          basis:
            "syntax association; dispatch, enforcement and data flow unverified",
        });
      },
    };
  }
  *targets(generation, owner) {
    const sql = `SELECT e.target,n.id AS call FROM nodes n INDEXED BY nodes_parent CROSS JOIN members m ON m.version=n.version JOIN edges e ON e.version=n.version AND e.source=n.id AND e.kind='candidate-call-target' WHERE m.generation=? AND n.parent=? AND n.kind='call' ORDER BY e.target`;
    yield* this.db.prepare(sql).iterate(generation, owner);
  }
  *unresolved(generation) {
    for (const row of this.db
      .prepare(
        "SELECT n.data FROM nodes n JOIN members m ON m.version=n.version WHERE m.generation=? AND n.kind='call' AND NOT EXISTS(SELECT 1 FROM edges e WHERE e.version=n.version AND e.source=n.id AND e.kind='candidate-call-target')",
      )
      .iterate(generation))
      yield parse(row);
  }
  *walk(generation, root, limit = 4096) {
    if (this.readOnly)
      this.db.exec(
        "CREATE TEMP TABLE IF NOT EXISTS traversal (job TEXT NOT NULL,node TEXT NOT NULL,predecessor TEXT,call TEXT,processed INTEGER NOT NULL DEFAULT 0,seq INTEGER NOT NULL,PRIMARY KEY(job,node)); CREATE INDEX IF NOT EXISTS temp.traversal_queue ON traversal(job,processed,seq);",
      );
    const job = id(generation, root);
    this.db.prepare("DELETE FROM traversal WHERE job=?").run(job);
    const add = this.db.prepare(
      "INSERT OR IGNORE INTO traversal VALUES(?,?,?,?,0,?)",
    );
    add.run(job, root, null, null, 0);
    let count = 1,
      limited = false;
    for (;;) {
      const current = this.db
        .prepare(
          "SELECT * FROM traversal WHERE job=? AND processed=0 ORDER BY seq LIMIT 1",
        )
        .get(job);
      if (!current) break;
      for (const e of this.targets(generation, current.node)) {
        if (
          this.db
            .prepare("SELECT 1 FROM traversal WHERE job=? AND node=?")
            .get(job, e.target)
        )
          continue;
        if (count >= limit) {
          limited = true;
          continue;
        }
        add.run(job, e.target, current.node, e.call, count++);
      }
      this.db
        .prepare("UPDATE traversal SET processed=1 WHERE job=? AND node=?")
        .run(job, current.node);
      if (current.node !== root) {
        const path = [current.node];
        let at = current;
        while (at.predecessor) {
          path.push(at.call, at.predecessor);
          at = this.db
            .prepare("SELECT * FROM traversal WHERE job=? AND node=?")
            .get(job, at.predecessor);
        }
        yield { target: current.node, path: path.reverse() };
      }
    }
    yield { done: true, limited, count };
    this.db.prepare("DELETE FROM traversal WHERE job=?").run(job);
  }
  async backup(destination) {
    await backup(this.db, destination);
  }
  checkpoint() {
    if (!this.readOnly) this.db.exec("PRAGMA wal_checkpoint(PASSIVE)");
  }
}
