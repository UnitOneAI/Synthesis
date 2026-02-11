import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

const DB_PATH =
  process.env.THREAT_MODEL_DB_PATH ||
  path.join(process.cwd(), "data", "threats.db");

// Ensure the data directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

let _db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!_db) {
    _db = new Database(DB_PATH);
    _db.pragma("journal_mode = WAL");
    _db.pragma("foreign_keys = ON");
    initSchema(_db);
  }
  return _db;
}

function initSchema(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      category TEXT NOT NULL,
      is_secret INTEGER DEFAULT 0,
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      source TEXT CHECK(source IN ('design-doc', 'github-repo')),
      source_ref TEXT,
      framework TEXT DEFAULT 'STRIDE',
      status TEXT DEFAULT 'Processing',
      dfd_mermaid TEXT,
      project_id TEXT REFERENCES projects(id),
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS threats (
      id TEXT PRIMARY KEY,
      session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      stride_category TEXT,
      severity TEXT CHECK(severity IN ('Critical','High','Medium','Low')),
      status TEXT DEFAULT 'Identified',
      threat_source TEXT,
      prerequisites TEXT,
      threat_action TEXT,
      threat_impact TEXT,
      impacted_assets TEXT,
      trust_boundary TEXT,
      assumptions TEXT,
      related_cve TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS mitigations (
      id TEXT PRIMARY KEY,
      threat_id TEXT REFERENCES threats(id) ON DELETE CASCADE,
      description TEXT NOT NULL,
      status TEXT DEFAULT 'Proposed',
      code_file TEXT,
      code_line INTEGER,
      code_original TEXT,
      code_fixed TEXT,
      jira_key TEXT,
      jira_summary TEXT,
      jira_status TEXT
    );

    CREATE TABLE IF NOT EXISTS design_reviews (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK(type IN ('enhancement', 'risk', 'context-layer')),
      content TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_threats_session ON threats(session_id);
    CREATE INDEX IF NOT EXISTS idx_mitigations_threat ON mitigations(threat_id);
    CREATE INDEX IF NOT EXISTS idx_design_reviews_session ON design_reviews(session_id);
  `);

  // Migration: add project_id column if missing (for existing databases)
  try {
    db.exec(`ALTER TABLE sessions ADD COLUMN project_id TEXT REFERENCES projects(id)`);
  } catch {
    // Column already exists
  }
  // Create index after column is guaranteed to exist
  db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project_id)`);

  // Migration: add document_content column if missing
  try {
    db.exec(`ALTER TABLE sessions ADD COLUMN document_content TEXT`);
  } catch {
    // Column already exists
  }
}

// ── Session CRUD ──

export interface SessionRow {
  id: string;
  name: string;
  description: string | null;
  source: "design-doc" | "github-repo";
  source_ref: string;
  framework: string;
  status: string;
  dfd_mermaid: string | null;
  project_id: string | null;
  document_content: string | null;
  created_at: string;
  updated_at: string;
}

export function createSession(session: {
  id: string;
  name: string;
  description?: string;
  source: "design-doc" | "github-repo";
  sourceRef: string;
  framework?: string;
  projectId?: string;
  documentContent?: string;
}): SessionRow {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO sessions (id, name, description, source, source_ref, framework, project_id, document_content)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    session.id,
    session.name,
    session.description || null,
    session.source,
    session.sourceRef,
    session.framework || "STRIDE",
    session.projectId || null,
    session.documentContent || null
  );
  return getSession(session.id)!;
}

export function getSession(id: string): SessionRow | null {
  const db = getDb();
  return (
    (db
      .prepare("SELECT * FROM sessions WHERE id = ?")
      .get(id) as SessionRow) || null
  );
}

export function listSessions(projectId?: string): SessionRow[] {
  const db = getDb();
  if (projectId) {
    return db
      .prepare("SELECT * FROM sessions WHERE project_id = ? ORDER BY created_at DESC")
      .all(projectId) as SessionRow[];
  }
  return db
    .prepare("SELECT * FROM sessions ORDER BY created_at DESC")
    .all() as SessionRow[];
}

export function updateSession(
  id: string,
  updates: Partial<{
    name: string;
    description: string;
    status: string;
    dfd_mermaid: string;
  }>
): void {
  const db = getDb();
  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.name !== undefined) {
    fields.push("name = ?");
    values.push(updates.name);
  }
  if (updates.description !== undefined) {
    fields.push("description = ?");
    values.push(updates.description);
  }
  if (updates.status !== undefined) {
    fields.push("status = ?");
    values.push(updates.status);
  }
  if (updates.dfd_mermaid !== undefined) {
    fields.push("dfd_mermaid = ?");
    values.push(updates.dfd_mermaid);
  }

  if (fields.length === 0) return;

  fields.push("updated_at = datetime('now')");
  values.push(id);

  db.prepare(`UPDATE sessions SET ${fields.join(", ")} WHERE id = ?`).run(
    ...values
  );
}

export function deleteSession(id: string): void {
  const db = getDb();
  db.prepare("DELETE FROM sessions WHERE id = ?").run(id);
}

// ── Threat CRUD ──

export interface ThreatRow {
  id: string;
  session_id: string;
  title: string;
  stride_category: string;
  severity: string;
  status: string;
  threat_source: string;
  prerequisites: string | null;
  threat_action: string;
  threat_impact: string;
  impacted_assets: string | null;
  trust_boundary: string;
  assumptions: string | null; // JSON array
  related_cve: string | null;
  created_at: string;
}

export function createThreat(threat: {
  id: string;
  sessionId: string;
  title: string;
  strideCategory: string;
  severity: string;
  threatSource: string;
  prerequisites?: string;
  threatAction: string;
  threatImpact: string;
  impactedAssets?: string[];
  trustBoundary: string;
  assumptions?: string[];
  relatedCve?: string;
}): ThreatRow {
  const db = getDb();
  db.prepare(
    `INSERT INTO threats (id, session_id, title, stride_category, severity, threat_source, prerequisites, threat_action, threat_impact, impacted_assets, trust_boundary, assumptions, related_cve)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    threat.id,
    threat.sessionId,
    threat.title,
    threat.strideCategory,
    threat.severity,
    threat.threatSource,
    threat.prerequisites || null,
    threat.threatAction,
    threat.threatImpact,
    threat.impactedAssets ? JSON.stringify(threat.impactedAssets) : null,
    threat.trustBoundary,
    threat.assumptions ? JSON.stringify(threat.assumptions) : null,
    threat.relatedCve || null
  );
  return getThreat(threat.id)!;
}

export function getThreat(id: string): ThreatRow | null {
  const db = getDb();
  return (
    (db.prepare("SELECT * FROM threats WHERE id = ?").get(id) as ThreatRow) ||
    null
  );
}

export function listThreats(sessionId: string): ThreatRow[] {
  const db = getDb();
  return db
    .prepare(
      "SELECT * FROM threats WHERE session_id = ? ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 END"
    )
    .all(sessionId) as ThreatRow[];
}

export function updateThreat(
  id: string,
  updates: Partial<{ status: string; severity: string }>
): void {
  const db = getDb();
  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.status !== undefined) {
    fields.push("status = ?");
    values.push(updates.status);
  }
  if (updates.severity !== undefined) {
    fields.push("severity = ?");
    values.push(updates.severity);
  }

  if (fields.length === 0) return;
  values.push(id);

  db.prepare(`UPDATE threats SET ${fields.join(", ")} WHERE id = ?`).run(
    ...values
  );
}

// ── Mitigation CRUD ──

export interface MitigationRow {
  id: string;
  threat_id: string;
  description: string;
  status: string;
  code_file: string | null;
  code_line: number | null;
  code_original: string | null;
  code_fixed: string | null;
  jira_key: string | null;
  jira_summary: string | null;
  jira_status: string | null;
}

export function createMitigation(mitigation: {
  id: string;
  threatId: string;
  description: string;
  status?: string;
  codeFile?: string;
  codeLine?: number;
  codeOriginal?: string;
  codeFixed?: string;
}): MitigationRow {
  const db = getDb();
  db.prepare(
    `INSERT INTO mitigations (id, threat_id, description, status, code_file, code_line, code_original, code_fixed)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    mitigation.id,
    mitigation.threatId,
    mitigation.description,
    mitigation.status || "Proposed",
    mitigation.codeFile || null,
    mitigation.codeLine || null,
    mitigation.codeOriginal || null,
    mitigation.codeFixed || null
  );
  return getMitigation(mitigation.id)!;
}

export function getMitigation(id: string): MitigationRow | null {
  const db = getDb();
  return (
    (db
      .prepare("SELECT * FROM mitigations WHERE id = ?")
      .get(id) as MitigationRow) || null
  );
}

export function listMitigations(threatId: string): MitigationRow[] {
  const db = getDb();
  return db
    .prepare("SELECT * FROM mitigations WHERE threat_id = ?")
    .all(threatId) as MitigationRow[];
}

export function updateMitigation(
  id: string,
  updates: Partial<{
    status: string;
    codeFixed: string;
    jiraKey: string;
    jiraSummary: string;
    jiraStatus: string;
  }>
): void {
  const db = getDb();
  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.status !== undefined) {
    fields.push("status = ?");
    values.push(updates.status);
  }
  if (updates.codeFixed !== undefined) {
    fields.push("code_fixed = ?");
    values.push(updates.codeFixed);
  }
  if (updates.jiraKey !== undefined) {
    fields.push("jira_key = ?");
    values.push(updates.jiraKey);
  }
  if (updates.jiraSummary !== undefined) {
    fields.push("jira_summary = ?");
    values.push(updates.jiraSummary);
  }
  if (updates.jiraStatus !== undefined) {
    fields.push("jira_status = ?");
    values.push(updates.jiraStatus);
  }

  if (fields.length === 0) return;
  values.push(id);

  db.prepare(`UPDATE mitigations SET ${fields.join(", ")} WHERE id = ?`).run(
    ...values
  );
}

// ── Aggregation ──

export function getSessionStats(sessionId: string) {
  const db = getDb();
  const threats = listThreats(sessionId);
  const total = threats.length;
  const critical = threats.filter((t) => t.severity === "Critical").length;
  const high = threats.filter((t) => t.severity === "High").length;
  const medium = threats.filter((t) => t.severity === "Medium").length;
  const low = threats.filter((t) => t.severity === "Low").length;
  const mitigated = threats.filter((t) => t.status === "Mitigated").length;

  return { total, critical, high, medium, low, mitigated };
}

export function getFullSession(sessionId: string) {
  const session = getSession(sessionId);
  if (!session) return null;

  const threats = listThreats(sessionId);
  const threatsWithMitigations = threats.map((t) => ({
    ...t,
    assumptions: t.assumptions ? JSON.parse(t.assumptions) : [],
    impacted_assets: t.impacted_assets
      ? JSON.parse(t.impacted_assets)
      : [],
    mitigations: listMitigations(t.id),
  }));

  return {
    ...session,
    threats: threatsWithMitigations,
    stats: getSessionStats(sessionId),
  };
}

// ── Project CRUD ──

export interface ProjectRow {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export function createProject(project: {
  id: string;
  name: string;
  description?: string;
}): ProjectRow {
  const db = getDb();
  db.prepare(
    `INSERT INTO projects (id, name, description) VALUES (?, ?, ?)`
  ).run(project.id, project.name, project.description || null);
  return getProject(project.id)!;
}

export function getProject(id: string): ProjectRow | null {
  const db = getDb();
  return (
    (db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as ProjectRow) ||
    null
  );
}

export function listProjects(): ProjectRow[] {
  const db = getDb();
  return db
    .prepare("SELECT * FROM projects ORDER BY created_at DESC")
    .all() as ProjectRow[];
}

export function updateProject(
  id: string,
  updates: Partial<{ name: string; description: string }>
): void {
  const db = getDb();
  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.name !== undefined) {
    fields.push("name = ?");
    values.push(updates.name);
  }
  if (updates.description !== undefined) {
    fields.push("description = ?");
    values.push(updates.description);
  }

  if (fields.length === 0) return;

  fields.push("updated_at = datetime('now')");
  values.push(id);

  db.prepare(`UPDATE projects SET ${fields.join(", ")} WHERE id = ?`).run(
    ...values
  );
}

export function deleteProject(id: string): void {
  const db = getDb();
  // Unlink sessions from this project first
  db.prepare("UPDATE sessions SET project_id = NULL WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM projects WHERE id = ?").run(id);
}

// ── Settings CRUD ──

export interface SettingRow {
  key: string;
  value: string;
  category: string;
  is_secret: number;
  updated_at: string;
}

export function maskSecret(value: string): string {
  if (value.length <= 7) return "***";
  return value.slice(0, 4) + "***" + value.slice(-3);
}

export function getSetting(key: string): SettingRow | null {
  const db = getDb();
  return (
    (db
      .prepare("SELECT * FROM settings WHERE key = ?")
      .get(key) as SettingRow) || null
  );
}

export function getSettingValue(key: string): string | null {
  const setting = getSetting(key);
  return setting ? setting.value : null;
}

export function getSettings(): SettingRow[] {
  const db = getDb();
  return db
    .prepare("SELECT * FROM settings ORDER BY category, key")
    .all() as SettingRow[];
}

export function getSettingsByCategory(category: string): SettingRow[] {
  const db = getDb();
  return db
    .prepare("SELECT * FROM settings WHERE category = ? ORDER BY key")
    .all(category) as SettingRow[];
}

export function upsertSetting(setting: {
  key: string;
  value: string;
  category: string;
  isSecret?: boolean;
}): void {
  const db = getDb();
  db.prepare(
    `INSERT INTO settings (key, value, category, is_secret, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, category = excluded.category, is_secret = excluded.is_secret, updated_at = datetime('now')`
  ).run(setting.key, setting.value, setting.category, setting.isSecret ? 1 : 0);
}

export function deleteSetting(key: string): void {
  const db = getDb();
  db.prepare("DELETE FROM settings WHERE key = ?").run(key);
}

// ── Design Review CRUD ──

export interface DesignReviewRow {
  id: string;
  session_id: string;
  type: "enhancement" | "risk" | "context-layer";
  content: string;
  created_at: string;
}

export function createDesignReview(review: {
  id: string;
  sessionId: string;
  type: "enhancement" | "risk" | "context-layer";
  content: string;
}): DesignReviewRow {
  const db = getDb();
  db.prepare(
    `INSERT INTO design_reviews (id, session_id, type, content) VALUES (?, ?, ?, ?)`
  ).run(review.id, review.sessionId, review.type, review.content);
  return db
    .prepare("SELECT * FROM design_reviews WHERE id = ?")
    .get(review.id) as DesignReviewRow;
}

export function getDesignReviews(
  sessionId: string,
  type?: string
): DesignReviewRow[] {
  const db = getDb();
  if (type) {
    return db
      .prepare(
        "SELECT * FROM design_reviews WHERE session_id = ? AND type = ? ORDER BY created_at"
      )
      .all(sessionId, type) as DesignReviewRow[];
  }
  return db
    .prepare(
      "SELECT * FROM design_reviews WHERE session_id = ? ORDER BY created_at"
    )
    .all(sessionId) as DesignReviewRow[];
}
