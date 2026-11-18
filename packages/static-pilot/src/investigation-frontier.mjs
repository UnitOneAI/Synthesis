// Durable work is represented by graph nodes and dependency edges, not a phase loop.
import { id } from "./sources.mjs";
export class InvestigationFrontier {
  constructor(store) {
    this.store = store;
    this.db = store.db;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS investigations(scope TEXT PRIMARY KEY, revision TEXT NOT NULL, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS investigation_tasks(seq INTEGER PRIMARY KEY, scope TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, repository TEXT NOT NULL, state TEXT NOT NULL, priority INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, result TEXT, UNIQUE(scope,id));
      CREATE INDEX IF NOT EXISTS investigation_ready ON investigation_tasks(scope,state,repository,priority,seq);
      CREATE TABLE IF NOT EXISTS investigation_links(scope TEXT,parent TEXT,child TEXT,relation TEXT,PRIMARY KEY(scope,parent,child,relation));
      CREATE TABLE IF NOT EXISTS investigation_fairness(scope TEXT,repository TEXT,calls INTEGER DEFAULT 0,served INTEGER DEFAULT 0,PRIMARY KEY(scope,repository));
      CREATE TABLE IF NOT EXISTS investigation_attempts(scope TEXT,id TEXT,data TEXT,PRIMARY KEY(scope,id));`);
  }
  open(scope, revision, data) {
    this.scope = scope;
    this.revision = revision;
    this.db
      .prepare("INSERT OR IGNORE INTO investigations VALUES(?,?,?)")
      .run(scope, revision, JSON.stringify(data));
    this.db
      .prepare(
        "UPDATE nodes SET active=CASE WHEN json_extract(data,'$.scope')=? THEN 1 ELSE 0 END WHERE revision=? AND kind='investigation-step'",
      )
      .run(scope, revision);
    this.db
      .prepare(
        "UPDATE edges SET active=0 WHERE revision=? AND kind LIKE 'investigation:%'",
      )
      .run(revision);
    for (const task of this.tasks()) this.project(task);
    for (const e of this.db
      .prepare("SELECT * FROM investigation_links WHERE scope=?")
      .iterate(scope))
      this.projectLink(e.parent, e.child, e.relation);
    return JSON.parse(
      this.db
        .prepare("SELECT data FROM investigations WHERE scope=?")
        .get(scope).data,
    );
  }
  get(taskId) {
    const r = this.db
      .prepare("SELECT * FROM investigation_tasks WHERE scope=? AND id=?")
      .get(this.scope, taskId);
    return r
      ? {
          ...r,
          data: JSON.parse(r.data),
          result: r.result ? JSON.parse(r.result) : null,
        }
      : null;
  }
  *tasks(state) {
    const query =
      "SELECT * FROM investigation_tasks WHERE scope=?" +
      (state ? " AND state=?" : "") +
      " ORDER BY seq";
    for (const r of this.db
      .prepare(query)
      .iterate(...(state ? [this.scope, state] : [this.scope])))
      yield {
        ...r,
        data: JSON.parse(r.data),
        result: r.result ? JSON.parse(r.result) : null,
      };
  }
  put(
    kind,
    key,
    repository,
    data,
    { parent, relation = "spawns", priority = 10 } = {},
  ) {
    const taskId = id("investigation", kind, key);
    this.db
      .prepare(
        "INSERT OR IGNORE INTO investigation_tasks(scope,id,kind,repository,state,priority,data) VALUES(?,?,?,?,?,?,?)",
      )
      .run(
        this.scope,
        taskId,
        kind,
        repository || "",
        "queued",
        priority,
        JSON.stringify(data),
      );
    this.db
      .prepare(
        "INSERT OR IGNORE INTO investigation_fairness(scope,repository) VALUES(?,?)",
      )
      .run(this.scope, repository || "");
    const old = this.get(taskId);
    if (kind === "path" && data.depth < old.data.depth) {
      this.db
        .prepare(
          "UPDATE investigation_tasks SET data=?,state=? WHERE scope=? AND id=?",
        )
        .run(JSON.stringify(data), "queued", this.scope, taskId);
    }
    if (parent) this.link(parent, taskId, relation);
    this.project(this.get(taskId));
    return taskId;
  }
  link(parent, child, relation = "spawns") {
    if (parent === child) return;
    this.db
      .prepare("INSERT OR IGNORE INTO investigation_links VALUES(?,?,?,?)")
      .run(this.scope, parent, child, relation);
    this.projectLink(parent, child, relation);
  }
  nodeId(taskId) {
    return id("frontier-node", this.scope, taskId);
  }
  projectLink(parent, child, relation) {
    this.db
      .prepare("INSERT OR REPLACE INTO edges VALUES(?,?,?,?,?,1)")
      .run(
        this.revision,
        id("frontier-edge", this.scope, parent, child, relation),
        this.nodeId(parent),
        this.nodeId(child),
        "investigation:" + relation,
      );
  }
  project(task) {
    const value = {
      id: this.nodeId(task.id),
      kind: "investigation-step",
      revision: this.revision,
      scope: this.scope,
      taskId: task.id,
      label:
        task.data.label ||
        `${task.kind} · ${task.data.path || task.data.symbol || task.repository || "selected scope"}`,
      status: task.state,
      repository: task.repository,
      stepKind: task.kind,
      attempts: task.attempts,
      ...task.data,
      result: task.result,
    };
    // IDs/status remain program-owned even when labels originate in source metadata.
    Object.assign(value, {
      id: this.nodeId(task.id),
      kind: "investigation-step",
      status: task.state,
      scope: this.scope,
    });
    const json = JSON.stringify(value),
      previous = this.db
        .prepare("SELECT data FROM nodes WHERE revision=? AND id=?")
        .get(this.revision, value.id);
    if (previous?.data !== json)
      this.db
        .prepare(
          "INSERT INTO transitions(revision,node_id,at,data) VALUES(?,?,?,?)",
        )
        .run(this.revision, value.id, new Date().toISOString(), json);
    this.db
      .prepare("INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,1)")
      .run(this.revision, value.id, value.kind, task.repository, json);
    const root = id("exploration", "root");
    if (
      !this.db
        .prepare(
          "SELECT 1 FROM investigation_links WHERE scope=? AND child=? LIMIT 1",
        )
        .get(this.scope, task.id)
    )
      this.db
        .prepare("INSERT OR REPLACE INTO edges VALUES(?,?,?,?,?,1)")
        .run(
          this.revision,
          id("frontier-root", this.scope, task.id),
          root,
          value.id,
          "investigation:plans",
        );
  }
  state(taskId, state, result, data) {
    if (data)
      this.db
        .prepare("UPDATE investigation_tasks SET data=? WHERE scope=? AND id=?")
        .run(JSON.stringify(data), this.scope, taskId);
    this.db
      .prepare(
        "UPDATE investigation_tasks SET state=?,result=? WHERE scope=? AND id=?",
      )
      .run(state, JSON.stringify(result ?? null), this.scope, taskId);
    this.project(this.get(taskId));
  }
  children(taskId) {
    return this.db
      .prepare(
        "SELECT t.* FROM investigation_links l JOIN investigation_tasks t ON t.scope=l.scope AND t.id=l.child WHERE l.scope=? AND l.parent=? AND l.relation=? ORDER BY t.seq",
      )
      .all(this.scope, taskId, "requires")
      .map((r) => ({
        ...r,
        data: JSON.parse(r.data),
        result: r.result ? JSON.parse(r.result) : null,
      }));
  }
  claim() {
    // Waiting steps become runnable only after their requested evidence has an outcome.
    for (const t of this.tasks("waiting"))
      if (
        this.children(t.id).every((c) =>
          ["done", "blocked", "failed"].includes(c.state),
        )
      )
        this.state(t.id, "queued", t.result);
    const row = this.db
      .prepare(
        `SELECT t.id FROM investigation_tasks t JOIN investigation_fairness f ON f.scope=t.scope AND f.repository=t.repository
      WHERE t.scope=? AND t.state='queued' AND NOT EXISTS(SELECT 1 FROM investigation_links l JOIN investigation_tasks d ON d.scope=l.scope AND d.id=l.child WHERE l.scope=t.scope AND l.parent=t.id AND l.relation='requires' AND d.state IN ('queued','running','waiting'))
      ORDER BY f.calls,f.served,t.priority,t.seq LIMIT 1`,
      )
      .get(this.scope);
    if (!row) return null;
    const task = this.get(row.id);
    this.db
      .prepare(
        "UPDATE investigation_fairness SET served=(SELECT coalesce(max(served),0)+1 FROM investigation_fairness WHERE scope=?) WHERE scope=? AND repository=?",
      )
      .run(this.scope, this.scope, task.repository);
    this.state(task.id, "running", task.result);
    return this.get(task.id);
  }
  charge(task) {
    this.db
      .prepare(
        "UPDATE investigation_tasks SET attempts=attempts+1 WHERE scope=? AND id=?",
      )
      .run(this.scope, task.id);
    this.db
      .prepare(
        "UPDATE investigation_fairness SET calls=calls+1 WHERE scope=? AND repository=?",
      )
      .run(this.scope, task.repository);
  }
  attempt(attempt) {
    this.db
      .prepare("INSERT OR REPLACE INTO investigation_attempts VALUES(?,?,?)")
      .run(this.scope, attempt.id, JSON.stringify(attempt));
  }
  attempts() {
    return this.db
      .prepare("SELECT data FROM investigation_attempts WHERE scope=?")
      .all(this.scope)
      .map((r) => JSON.parse(r.data));
  }
  recover({ retryFailed = false, maxDepth = 12 } = {}) {
    for (const a of this.attempts())
      if (a.status === "in-flight") {
        a.status = "interrupted";
        this.attempt(a);
      }
    for (const task of this.tasks()) {
      if (task.result?.review && task.result.expansionComplete === false)
        this.state(task.id, "queued", task.result);
      else if (task.state === "running")
        this.state(task.id, "failed", {
          ...task.result,
          reason: "interrupted-request-outcome-unknown",
        });
      else if (
        task.state === "blocked" &&
        task.result?.reason === "depth-budget" &&
        task.data.depth <= maxDepth
      )
        this.state(task.id, "queued", task.result);
      else if (retryFailed && task.state === "failed" && task.attempts < 3)
        this.state(task.id, "queued", task.result);
    }
  }
  counts() {
    return Object.fromEntries(
      this.db
        .prepare(
          "SELECT state,count(*) AS n FROM investigation_tasks WHERE scope=? GROUP BY state",
        )
        .all(this.scope)
        .map((r) => [r.state, r.n]),
    );
  }
  repositories() {
    return this.db
      .prepare(
        "SELECT repository,state,count(*) AS count FROM investigation_tasks WHERE scope=? GROUP BY repository,state",
      )
      .all(this.scope);
  }
}
