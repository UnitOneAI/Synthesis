// Static review lineage. This graph records investigations, never runtime reachability.
import { DatabaseSync } from "node:sqlite";
import { id, sha } from "./sources.mjs";
import { cweTargetCoverage } from "./cwe-targets.mjs";
import { securityRegister } from "./security-intelligence.mjs";

export class ExplorationStore {
  constructor(file = ":memory:") {
    this.db = new DatabaseSync(file);
    this.db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS nodes(revision TEXT,id TEXT,kind TEXT,repository TEXT,data TEXT,active INTEGER,PRIMARY KEY(revision,id));
      CREATE TABLE IF NOT EXISTS edges(revision TEXT,id TEXT,source TEXT,target TEXT,kind TEXT,active INTEGER,PRIMARY KEY(revision,id));
      CREATE TABLE IF NOT EXISTS transitions(sequence INTEGER PRIMARY KEY,revision TEXT,node_id TEXT,at TEXT,data TEXT);
      CREATE INDEX IF NOT EXISTS edge_source ON edges(revision,source,active);
      CREATE INDEX IF NOT EXISTS edge_target ON edges(revision,target,active);
      CREATE TABLE IF NOT EXISTS anchors(revision TEXT,node_id TEXT,kind TEXT,object_id TEXT,PRIMARY KEY(revision,node_id,kind,object_id));`);
  }
  sync(model) {
    if (!model) return;
    const revision = model.modelRevision,
      now = new Date().toISOString();
    const prior = this.db.prepare(
      "SELECT data FROM nodes WHERE revision=? AND id=?",
    );
    const insert = this.db.prepare(
      "INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,1)",
    );
    const edge = this.db.prepare(
      "INSERT OR REPLACE INTO edges VALUES(?,?,?,?,?,1)",
    );
    const anchor = this.db.prepare(
      "INSERT OR IGNORE INTO anchors VALUES(?,?,?,?)",
    );
    const node = (key, kind, label, status, data = {}, repository = "") => {
      const nid = id("exploration", key);
      const value = {
        ...data,
        id: nid,
        kind,
        label,
        status,
        repository,
        revision,
      };
      const json = JSON.stringify(value);
      if (prior.get(revision, nid)?.data !== json)
        this.db
          .prepare(
            "INSERT INTO transitions(revision,node_id,at,data) VALUES(?,?,?,?)",
          )
          .run(revision, nid, now, json);
      insert.run(revision, nid, kind, repository, json);
      for (const a of value.anchors || [])
        anchor.run(revision, nid, a.kind, a.id);
      return nid;
    };
    const link = (from, to, kind) =>
      edge.run(
        revision,
        id("exploration-edge", from, to, kind),
        from,
        to,
        kind,
      );
    this.db.exec("BEGIN");
    try {
      this.db
        .prepare(
          "UPDATE nodes SET active=0 WHERE revision=? AND kind!='investigation-step'",
        )
        .run(revision);
      this.db
        .prepare(
          "UPDATE edges SET active=0 WHERE revision=? AND kind NOT LIKE 'investigation:%'",
        )
        .run(revision);
      this.db.prepare("DELETE FROM anchors WHERE revision=?").run(revision);
      const root = node(
        "root",
        "scope",
        model.system || "Selected review scope",
        "open",
        {
          staticOnly: true,
          execution: model.explorationRun || null,
          explanation:
            "Investigation lineage, not executable attack paths. Completed requests do not establish absence of vulnerabilities.",
        },
      );
      const roots = {};
      for (const [key, label] of [
        ["stride", "STRIDE review"],
        ["cwe", "Requested CWE review"],
        ["assessment", "Candidate assessment"],
      ]) {
        roots[key] = node(key, "phase", label, "open");
        link(root, roots[key], "spawns");
      }
      for (const repo of model.sources || [])
        for (const category of [
          "Spoofing",
          "Tampering",
          "Repudiation",
          "Information disclosure",
          "Denial of service",
          "Elevation of privilege",
        ]) {
          const ids = (model.interfaces || [])
            .filter((i) => i.repository === repo.name)
            .map((i) => i.id);
          const reviewed = new Set(
            model.aiReview?.basedOnRevision === revision
              ? model.aiReview?.coverage?.reviewedInterfaceIds || []
              : [],
          );
          const count = ids.filter((i) => reviewed.has(i)).length;
          const goal = node(
            `stride-goal:${repo.name}:${category}`,
            "stride-goal",
            category,
            count ? "partial-needs-review" : "pending",
            {
              category,
              reviewedInterfaces: count,
              totalInterfaces: ids.length,
              explanation:
                "Interface submission does not establish complete review of this threat category.",
              anchors: [{ kind: "repository", id: repo.name }],
            },
            repo.name,
          );
          link(roots.stride, goal, "spawns");
        }
      const coverage = cweTargetCoverage(model),
        goals = new Map();
      for (const row of coverage.rows) {
        const key = `${row.repository}:${row.targetId}`;
        const goal = node(
          key,
          "goal",
          `${row.requestedCwes.join(", ")} · ${row.name}`,
          row.modelStatus,
          { ...row, anchors: [{ kind: "repository", id: row.repository }] },
          row.repository,
        );
        goals.set(key, goal);
        link(roots.cwe, goal, "spawns");
      }
      const batches = new Map();
      const cwe = model.cweModelReview;
      for (const b of cwe?.plan || cwe?.batches || []) {
        const result = cwe.batches?.find((r) => r.id === b.id);
        const current = cwe.basedOnRevision === revision;
        const step = node(
          `cwe:${cwe.key}:${b.id}`,
          "step",
          `Source review · ${(b.repositories || result?.repositories || []).join(", ")}`,
          current ? result?.status || "pending" : "stale",
          {
            ...b,
            ...result,
            phase: "cwe",
            packetId: b.id,
            planKey: cwe.key,
            provider: cwe.provider,
            model: cwe.model,
            anchors: (b.repositories || result?.repositories || []).map(
              (r) => ({ kind: "repository", id: r }),
            ),
          },
          (b.repositories || result?.repositories || []).join(", "),
        );
        batches.set(b.id, step);
        link(roots.cwe, step, "spawns");
        for (const r of result?.targetReviews || [])
          for (const repo of result.repositories || []) {
            const goal = goals.get(`${repo}:${r.targetId}`);
            if (goal) link(goal, step, "reviewed_by");
          }
      }
      const stride = model.aiReview;
      const strideSteps = new Map();
      for (const b of stride?.plan?.batches || stride?.batches || []) {
        const result = stride.batches?.find((r) => r.id === b.id);
        const step = node(
          `stride:${stride.runKey}:${b.id}`,
          "step",
          b.label || `STRIDE packet ${b.id}`,
          stride.basedOnRevision === revision
            ? result?.status || "pending"
            : "stale",
          {
            ...b,
            ...result,
            phase: "stride",
            provider: stride.provider,
            model: stride.model,
            anchors: (b.interfaceIds || result?.interfaceIds || []).map(
              (i) => ({ kind: "interface", id: i }),
            ),
          },
        );
        strideSteps.set(b.id, step);
        link(roots.stride, step, "spawns");
      }
      for (const t of stride?.threats || []) {
        const finding = node(
          `threat:${t.id}`,
          "finding",
          t.title,
          "needs-review",
          {
            ...t,
            anchors: (t.interfaceIds || []).map((i) => ({
              kind: "interface",
              id: i,
            })),
          },
        );
        link(strideSteps.get(t.batchId) || roots.stride, finding, "produces");
      }
      for (const [phase, report] of [
        ["cwe", cwe],
        ["stride", stride?.plan],
      ]) {
        for (const [n, g] of (report?.gaps || []).entries()) {
          const gap = node(
            `gap:${phase}:${sha(JSON.stringify(g))}:${n}`,
            "gap",
            g.reason || g.message || "Review coverage gap",
            "needs-context",
            g,
            g.repository,
          );
          link(roots[phase], gap, "needs_evidence");
        }
      }
      const register = securityRegister(model);
      for (const issue of register.issues) {
        const source = [
          ...(cwe?.findings || []),
          ...(model.cweReview?.findings || []),
        ].find((f) => f.id === issue.sourceId);
        const finding = node(
          `issue:${issue.id}`,
          "finding",
          `${issue.cwe || "Security concern"} · ${issue.title}`,
          issue.stale ? "stale" : issue.assessment,
          {
            ...issue,
            investigation: undefined,
            issueId: issue.id,
            anchors: [
              ...issue.interfaceIds.map((i) => ({ kind: "interface", id: i })),
              ...issue.evidenceIds.map((i) => ({ kind: "evidence", id: i })),
              ...issue.locations.map((l) => ({
                kind: "file",
                id: `${l.repository}:${l.path}`,
              })),
            ],
          },
          issue.locations[0]?.repository,
        );
        link(
          batches.get(source?.batchId) || roots.assessment,
          finding,
          "produces",
        );
        const entry = issue.investigation;
        if (!entry) continue;
        const assessment = node(
          `assessment:${entry.attemptId || entry.packetHash || issue.id}`,
          "assessment",
          `Assess ${issue.cwe || issue.kind}`,
          entry.assessment,
          {
            ...entry,
            issueId: issue.id,
            provider: model.securityReview?.provider,
            model: model.securityReview?.model,
          },
          issue.locations[0]?.repository,
        );
        link(finding, assessment, "assessed_by");
        for (const [n, ref] of (entry.evidence || []).entries()) {
          const obs = node(
            `observation:${assessment}:${ref.id || n}`,
            "observation",
            `${ref.path}:${ref.startLine}–${ref.endLine}`,
            "source-reference",
            {
              ...ref,
              issueId: issue.id,
              recordId: ref.id,
              anchors: [{ kind: "file", id: `${ref.repository}:${ref.path}` }],
            },
            ref.repository,
          );
          link(assessment, obs, "cites");
        }
        for (const [n, control] of (entry.controls || []).entries()) {
          const ctrl = node(
            `control:${assessment}:${n}`,
            "control",
            control.reason,
            "assessed",
            { ...control, issueId: issue.id },
          );
          link(assessment, ctrl, "considers");
        }
        if (entry.counterEvidence) {
          const counter = node(
            `counter:${assessment}`,
            "counterevidence",
            "Counterevidence considered",
            "assessed",
            { explanation: entry.counterEvidence },
          );
          link(assessment, counter, "considers");
        }
        for (const [n, g] of (entry.missingEvidence || []).entries()) {
          const gap = node(
            `missing:${assessment}:${n}`,
            "gap",
            g,
            "needs-context",
            { followUp: entry.followUp || [] },
          );
          link(assessment, gap, "needs_evidence");
        }
        for (const [n, h] of (entry.history || []).entries()) {
          const history = node(
            `history:${issue.id}:${h.attemptId || n}`,
            "assessment",
            `Previous assessment ${n + 1}`,
            h.assessment,
            { ...h, historical: true },
          );
          link(finding, history, "assessed_by");
          link(history, assessment, "followed_by");
        }
      }
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
    return this.overview(revision);
  }
  overview(revision) {
    return {
      revision,
      staticOnly: true,
      semantics: "Review lineage, not runtime reachability",
      nodes: this.db
        .prepare(
          "SELECT count(*) AS n FROM nodes WHERE revision=? AND active=1",
        )
        .get(revision).n,
      edges: this.db
        .prepare(
          "SELECT count(*) AS n FROM edges WHERE revision=? AND active=1",
        )
        .get(revision).n,
      groups: this.db
        .prepare(
          "SELECT kind,count(*) AS count FROM nodes WHERE revision=? AND active=1 GROUP BY kind",
        )
        .all(revision),
      revisions: this.db
        .prepare(
          "SELECT revision,count(*) AS nodes FROM nodes GROUP BY revision",
        )
        .all(),
      coverageComplete: false,
    };
  }
  node(revision, nid) {
    const row = this.db
      .prepare("SELECT data,active FROM nodes WHERE revision=? AND id=?")
      .get(revision, nid);
    if (!row) return null;
    return {
      ...JSON.parse(row.data),
      historical: JSON.parse(row.data).historical || !row.active,
      transitions: this.db
        .prepare(
          "SELECT sequence,at,data FROM transitions WHERE revision=? AND node_id=? ORDER BY sequence DESC LIMIT 20",
        )
        .all(revision, nid)
        .map((t) => ({ ...t, data: JSON.parse(t.data) })),
      transitionCount: this.db
        .prepare(
          "SELECT count(*) AS n FROM transitions WHERE revision=? AND node_id=?",
        )
        .get(revision, nid).n,
    };
  }
  query(
    revision,
    {
      parent,
      focus,
      issue,
      kind = "",
      repository = "",
      offset = 0,
      limit = 60,
    } = {},
  ) {
    limit = Math.min(100, Math.max(1, Number(limit) || 60));
    offset = Math.max(0, Number(offset) || 0);
    let sql = "SELECT n.data FROM nodes n WHERE n.revision=? AND n.active=1",
      args = [revision];
    if (focus) {
      // UNION prevents cycles and retains every ancestor; pagination bounds the response.
      sql = `WITH RECURSIVE lineage(id) AS (SELECT ? UNION SELECT e.source FROM edges e JOIN lineage l ON e.target=l.id WHERE e.revision=? AND e.active=1)
        SELECT n.data FROM nodes n JOIN lineage l ON n.id=l.id WHERE n.revision=? AND n.active=1`;
      args = [focus, revision, revision];
    } else if (parent) {
      sql +=
        " AND n.id IN (SELECT target FROM edges WHERE revision=? AND source=? AND active=1)";
      args.push(revision, parent);
    }
    if (issue) {
      sql += " AND json_extract(n.data,'$.issueId')=?";
      args.push(issue);
    }
    if (kind) {
      sql += " AND n.kind=?";
      args.push(kind);
    }
    if (repository) {
      sql +=
        " AND (n.repository=? OR n.id IN (SELECT node_id FROM anchors WHERE revision=? AND kind='repository' AND object_id=?))";
      args.push(repository, revision, repository);
    }
    const total = this.db
      .prepare(`SELECT count(*) AS n FROM (${sql})`)
      .get(...args).n;
    const nodes = this.db
      .prepare(sql + " ORDER BY n.kind,n.id LIMIT ? OFFSET ?")
      .all(...args, limit, offset)
      .map((r) => JSON.parse(r.data));
    if (parent) {
      const p = this.node(revision, parent);
      if (p) nodes.unshift(p);
    }
    const ids = nodes.map((n) => n.id),
      set = new Set(ids),
      edges = [];
    for (const nid of ids)
      for (const e of this.db
        .prepare(
          "SELECT id,source,target,kind FROM edges WHERE revision=? AND source=? AND active=1",
        )
        .all(revision, nid))
        if (set.has(e.target)) edges.push(e);
    for (const n of nodes)
      n.children = this.db
        .prepare(
          "SELECT count(*) AS n FROM edges WHERE revision=? AND source=? AND active=1",
        )
        .get(revision, n.id).n;
    return {
      revision,
      nodes,
      edges,
      total,
      offset,
      limit,
      omitted: Math.max(0, total - offset - limit),
      overview: this.overview(revision),
    };
  }
  close() {
    this.db.close();
  }
}
