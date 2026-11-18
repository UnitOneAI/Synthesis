import { graphReader } from "./graph-store.mjs";
import { sourceWindow } from "./graph-package.mjs";
import { id } from "./sources.mjs";
import { sourceScope } from "./architecture.mjs";
export class InvestigationSource {
  constructor(model, manifest, root) {
    this.model = model;
    this.manifest = manifest;
    this.root = root;
    this.graph = model.sourceGraph;
    this.disk = graphReader(this.graph);
    this.generation = this.graph?.generation;
    if (this.graph?.storage === "sqlite" && !this.disk)
      throw Error("Saved source graph reader unavailable");
    this.selected = new Set(
      manifest.repositories
        .filter((r) => r.selected !== false)
        .map((r) => r.name),
    );
    this.memoryNodes = this.graph?.nodes || [];
    this.byId = new Map(this.memoryNodes.map((n) => [n.id, n]));
  }
  nodes(options = {}) {
    if (this.disk) return [...this.disk.nodes(this.generation, options)];
    return this.memoryNodes
      .filter(
        (n) =>
          (!options.kind || n.kind === options.kind) &&
          (!options.repository || n.repository === options.repository) &&
          (!options.path || n.path === options.path) &&
          (!options.after || n.id > options.after),
      )
      .sort((a, b) => a.id.localeCompare(b.id))
      .slice(0, options.limit || 100);
  }
  node(nid) {
    const n = this.disk
      ? this.disk.node(this.generation, nid)
      : this.byId.get(nid);
    return n && this.selected.has(n.repository) ? n : null;
  }
  file(repository, path) {
    if (!this.selected.has(repository)) return null;
    return this.nodes({ kind: "file", repository, path, limit: 1 })[0] || null;
  }
  files(repository, after = "") {
    const rows = this.nodes({ kind: "file", repository, after, limit: 33 });
    return {
      items: rows.slice(0, 32),
      next: rows.length > 32 ? rows[31].id : null,
    };
  }
  search(symbol, after = "") {
    let rows, next;
    if (this.disk) {
      const page = this.disk.page(this.generation, {
        search: symbol,
        after,
        limit: 32,
      });
      rows = page.items;
      next = page.next;
    } else {
      const matched = this.memoryNodes
        .filter(
          (n) =>
            n.id > after &&
            `${n.name || ""} ${n.path || ""}`
              .toLowerCase()
              .includes(symbol.toLowerCase()),
        )
        .sort((a, b) => a.id.localeCompare(b.id));
      rows = matched.slice(0, 32);
      next = matched.length > 32 ? rows.at(-1).id : null;
    }
    return {
      items: rows.filter((n) => this.selected.has(n.repository) && n.path),
      next,
    };
  }
  edges(nid, after = "") {
    if (this.disk)
      return this.disk.incidentPage(this.generation, nid, { after, limit: 32 });
    const rows = (this.graph.edges || [])
      .filter((e) => (e.from === nid || e.to === nid) && e.id > after)
      .sort((a, b) => a.id.localeCompare(b.id));
    return {
      items: rows.slice(0, 32),
      next: rows.length > 32 ? rows[31].id : null,
    };
  }
  async window(ref) {
    const f = this.file(ref.repository, ref.path);
    if (!f || (ref.blobSha256 && ref.blobSha256 !== f.blobSha256))
      throw Error("source-not-in-current-index");
    const w = await sourceWindow(
      { ...ref, blobSha256: f.blobSha256 },
      this.manifest,
      this.root,
    );
    return {
      id: id(
        "investigation-record",
        w.repository,
        w.path,
        w.blobSha256,
        w.startLine,
        w.endLine,
      ),
      ...w,
      sourceScope: sourceScope(w.path),
      code: w.lines.map((l) => `${l.line}: ${l.text}`).join("\n"),
    };
  }
  catalog(records) {
    const map = new Map();
    let omitted = false;
    for (const r of records) {
      const nodes = this.nodes({
        repository: r.repository,
        path: r.path,
        limit: 129,
      });
      if (nodes.length > 128) omitted = true;
      for (const n of nodes.slice(0, 128))
        if (n.line >= r.startLine && n.line <= r.endLine)
          map.set(n.id, {
            id: n.id,
            kind: n.kind,
            name: n.name,
            repository: n.repository,
            path: n.path,
            line: n.line,
          });
    }
    return {
      nodes: [...map.values()].slice(0, 128),
      omitted: omitted || map.size > 128,
    };
  }
}
