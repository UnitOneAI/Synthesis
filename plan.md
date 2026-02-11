# Unitone Sentinel — Threat Modeling Module: Implementation Plan

> **Status: IMPLEMENTATION COMPLETE** (Build verified: `next build` passes)
> Last updated: 2026-02-09

## Three-Agent Perspective

This plan is authored from three perspectives working in concert:

| Role | Perspective |
|------|------------|
| **Agent 1 — Principal Security Review Engineer** | Defines the security spec, threat grammar, frameworks, and acceptance criteria |
| **Agent 2 — Principal SDE** | Designs the system architecture, APIs, data models, and writes the automation code |
| **Agent 3 — Customer Engineer** | Submits a real GitHub repo and validates the end-to-end flow as a user |

---

## Agent 1: Security Specification

### 1.1 Objective

Build an automated threat modeling pipeline that accepts a GitHub repository URL (or a design document) and produces:

1. **Data Flow Diagram (DFD)** — visual representation of components, trust boundaries, data stores, and external entities
2. **Threat List** — structured threat statements using AWS Threat Grammar, mapped to STRIDE categories
3. **Insights Dashboard** — quality metrics (STRIDE coverage, mitigation rate, severity distribution)
4. **Threat Detail with Mitigations** — when a repo is the source, generate code-level fixes; when a doc is the source, generate prose-based mitigation suggestions
5. **Apply Fix** — a button that applies the generated code fix (creates a PR or applies locally), and transitions the threat status from "Identified" to "Mitigated"

### 1.2 Threat Grammar (AWS Threat Composer)

Every generated threat statement MUST follow this grammar:

```
A [threat source] with [prerequisites] can [threat action],
which leads to [threat impact], negatively impacting [impacted assets].
```

**Fields per threat:**
| Field | Description | Example |
|-------|-------------|---------|
| `threatSource` | The entity performing the threat | "An authenticated tenant user" |
| `prerequisites` | Conditions that make the threat viable | "with access to the API and knowledge of building IDs" |
| `threatAction` | The action taken | "can modify the building_id parameter in HVAC setpoint API calls" |
| `threatImpact` | The direct result | "leading to unauthorized temperature manipulation in critical facilities" |
| `impactedAssets` | What is negatively affected | "HVAC Control Plane, Tenant Data Isolation" |
| `strideCategory` | STRIDE classification | "Elevation of Privilege" |

### 1.3 STRIDE Framework Mapping

The system must classify each threat into exactly one STRIDE category:

| Category | Security Property | Detection Pattern |
|----------|------------------|-------------------|
| **S**poofing | Authentication | Hardcoded creds, missing auth checks, session fixation |
| **T**ampering | Integrity | Missing input validation, no message signing, unsigned artifacts |
| **R**epudiation | Non-Repudiation | Missing audit logs, mutable log storage, no action attribution |
| **I**nformation Disclosure | Confidentiality | Exposed secrets, verbose errors, missing encryption, debug endpoints |
| **D**enial of Service | Availability | Missing rate limits, unbounded queries, resource exhaustion |
| **E**levation of Privilege | Authorization | Missing RBAC, IDOR, broken access control, privilege escalation |

### 1.4 OWASP Top 10 Mapping (Secondary Framework)

When "OWASP Top 10" is selected as the framework, map threats to:

| ID | Category | Relevant Threat Patterns |
|----|----------|--------------------------|
| A01 | Broken Access Control | IDOR, missing function-level access control, CORS misconfiguration |
| A02 | Cryptographic Failures | Weak algorithms, hardcoded keys, plaintext storage |
| A03 | Injection | SQLi, XSS, command injection, LDAP injection |
| A04 | Insecure Design | Missing threat model, no defense in depth, business logic flaws |
| A05 | Security Misconfiguration | Default creds, unnecessary features, missing headers |
| A06 | Vulnerable Components | Outdated dependencies, known CVEs in deps |
| A07 | Auth Failures | Credential stuffing, weak passwords, missing MFA |
| A08 | Software & Data Integrity | Unsigned updates, insecure CI/CD, deserialization flaws |
| A09 | Logging & Monitoring | Missing audit trails, no alerting, insufficient logging |
| A10 | SSRF | Unvalidated URL fetches, internal service exposure |

### 1.5 Acceptance Criteria (from Security Reviewer)

- [ ] Each threat MUST have a structured threat statement following AWS Threat Grammar
- [ ] Each threat MUST be classified into a STRIDE category (or OWASP A01-A10 if that framework is selected)
- [ ] Each threat MUST have a severity (Critical/High/Medium/Low) with rationale
- [ ] Each threat from a repo source MUST have at least one code-level mitigation with before/after diff
- [ ] Each threat from a doc source MUST have at least one prose mitigation suggestion
- [ ] The DFD MUST show trust boundaries, data flows, processes, and external entities
- [ ] The "Apply Fix" action MUST create a branch and PR (or apply locally via VS Code)
- [ ] Mitigated threats MUST transition status from "Identified" → "Mitigated"

---

## Agent 2: Technical Implementation Plan

### 2.1 System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     FRONTEND (Next.js 16)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Session   │  │ DFD      │  │ Threat   │  │ Threat Detail │  │
│  │ Manager   │  │ Viewer   │  │ List     │  │ + Apply Fix   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬────────┘  │
│       │              │             │               │            │
│       └──────────────┴─────────────┴───────────────┘            │
│                           │  API Calls                          │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                     API LAYER (Next.js Route Handlers)          │
│  POST /api/threat-model/sessions         — Create session       │
│  GET  /api/threat-model/sessions/:id     — Get session + threats│
│  POST /api/threat-model/sessions/:id/analyze — Trigger analysis │
│  GET  /api/threat-model/sessions/:id/dfd — Get DFD data        │
│  POST /api/threat-model/threats/:id/apply-fix — Apply fix       │
│  PATCH /api/threat-model/threats/:id     — Update threat status │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                     BACKEND SERVICES                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │ Repo Analyzer   │  │ Threat Engine   │  │ Fix Generator  │  │
│  │ (GitHub Clone   │  │ (LLM-powered    │  │ (Code Patch    │  │
│  │  + AST Parse)   │  │  STRIDE/OWASP)  │  │  + PR Create)  │  │
│  └────────┬────────┘  └────────┬────────┘  └───────┬────────┘  │
│           │                    │                    │            │
│  ┌────────┴────────┐  ┌───────┴────────┐  ┌───────┴────────┐  │
│  │ DFD Generator   │  │ Insight Engine │  │ Git Service    │  │
│  │ (Architecture   │  │ (Quality       │  │ (Branch + PR   │  │
│  │  → Mermaid DFD) │  │  Metrics)      │  │  via GitHub)   │  │
│  └─────────────────┘  └────────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                     DATA / EXTERNAL                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │ GitHub API      │  │ Claude/LLM API  │  │ Local SQLite   │  │
│  │ (Repo access,   │  │ (Threat gen,    │  │ (Session &     │  │
│  │  PR creation)   │  │  DFD gen,       │  │  threat store) │  │
│  │                 │  │  fix gen)       │  │                │  │
│  └─────────────────┘  └─────────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Implementation Phases

#### Phase 1: Backend API & Data Layer

**Files to create:**
```
app/api/threat-model/
├── sessions/
│   ├── route.ts                    — POST (create), GET (list all)
│   └── [id]/
│       ├── route.ts                — GET (session detail), PATCH (update)
│       └── analyze/
│           └── route.ts            — POST (trigger analysis pipeline)
├── threats/
│   └── [id]/
│       ├── route.ts                — PATCH (update status)
│       └── apply-fix/
│           └── route.ts            — POST (apply code fix, create PR)
lib/
├── threat-engine/
│   ├── repo-analyzer.ts            — Clone repo, extract file structure, identify architecture
│   ├── threat-generator.ts         — LLM-powered STRIDE analysis, produce threat statements
│   ├── dfd-generator.ts            — Generate Mermaid DFD from repo architecture
│   ├── insight-engine.ts           — Compute quality metrics from threat list
│   ├── fix-generator.ts            — Generate code-level fixes for each threat
│   └── git-service.ts              — GitHub API: clone, branch, commit, PR
├── threat-data.ts                  — (existing) Types + mock data
└── db.ts                           — SQLite session/threat persistence
```

**Database schema (SQLite via better-sqlite3):**
```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  source TEXT CHECK(source IN ('design-doc', 'github-repo')),
  source_ref TEXT,
  framework TEXT DEFAULT 'STRIDE',
  status TEXT DEFAULT 'Processing',
  dfd_mermaid TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE threats (
  id TEXT PRIMARY KEY,
  session_id TEXT REFERENCES sessions(id),
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
  assumptions TEXT,  -- JSON array
  related_cve TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE mitigations (
  id TEXT PRIMARY KEY,
  threat_id TEXT REFERENCES threats(id),
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
```

#### Phase 2: Repo Analyzer Pipeline

The `repo-analyzer.ts` service will:

1. **Clone the repo** — use `git clone --depth=1` via child_process into a temp directory
2. **Inventory the codebase** — walk the file tree, identify:
   - Languages used (by file extension)
   - Framework detection (package.json, requirements.txt, go.mod, etc.)
   - Entry points (main files, route definitions, API handlers)
   - Configuration files (env, yaml, json configs)
   - Infrastructure-as-code (Terraform, CloudFormation, Docker)
3. **Extract architecture signals** — read key files to identify:
   - External APIs called
   - Database connections
   - Authentication mechanisms
   - Message queues / pub-sub (MQTT, Kafka, SQS)
   - File upload endpoints
   - Secret management patterns
4. **Produce a structured architecture summary** — JSON object describing components, data flows, and trust boundaries

```typescript
interface RepoAnalysis {
  repoUrl: string;
  languages: string[];
  frameworks: string[];
  components: {
    name: string;
    type: 'api' | 'service' | 'database' | 'queue' | 'gateway' | 'external';
    files: string[];
    description: string;
  }[];
  dataFlows: {
    from: string;
    to: string;
    protocol: string;
    dataType: string;
  }[];
  trustBoundaries: {
    name: string;
    components: string[];
  }[];
  securityFindings: {
    file: string;
    line: number;
    pattern: string;  // e.g., "hardcoded_secret", "missing_auth", "sql_concat"
    snippet: string;
  }[];
}
```

#### Phase 3: LLM-Powered Threat Generation

The `threat-generator.ts` will use the Claude API (or configurable LLM) with a structured prompt:

**System Prompt (Security Engineer persona):**
```
You are a Principal Security Review Engineer performing a STRIDE-based threat model.
Given a repository architecture analysis, generate structured threat statements
following the AWS Threat Grammar:

"A [threat source] with [prerequisites] can [threat action],
which leads to [threat impact], negatively impacting [impacted assets]."

For each threat:
1. Classify into exactly one STRIDE category
2. Assign severity (Critical/High/Medium/Low) with justification
3. Identify the trust boundary being crossed
4. List assumptions
5. Propose at least one mitigation

If source code is available, provide specific file paths and line numbers
for both the vulnerable code and the proposed fix.

Output as structured JSON matching the Threat[] schema.
```

**Input:** `RepoAnalysis` JSON from Phase 2
**Output:** `Threat[]` array matching the existing data model

#### Phase 4: DFD Generator

The `dfd-generator.ts` will:

1. Take the `RepoAnalysis.components`, `dataFlows`, and `trustBoundaries`
2. Generate a Mermaid.js flowchart diagram string
3. The frontend already has a static DFD — we will make it dynamic by rendering the Mermaid string

**Frontend enhancement:** Add `mermaid` npm package to render DFD diagrams dynamically instead of the current hardcoded component layout.

#### Phase 5: Fix Generator & Apply Fix

The `fix-generator.ts` will:

1. **For repo sources:**
   - Read the identified vulnerable file from the cloned repo
   - Use LLM to generate a specific code fix (before/after diff)
   - Validate the fix compiles/parses (language-specific AST check)

2. **For doc sources:**
   - Generate a prose mitigation suggestion
   - No code diff, just descriptive guidance

The `git-service.ts` handles the "Apply Fix" flow:

1. Fork or create a branch from the source repo (requires GitHub token)
2. Apply the code change to the target file
3. Commit with message: `fix: [threat-id] - [threat-title]`
4. Open a PR against the default branch
5. Return the PR URL to the frontend
6. Update threat status to "Mitigated"

```typescript
interface ApplyFixResult {
  success: boolean;
  prUrl?: string;
  branch?: string;
  commitSha?: string;
  error?: string;
}
```

#### Phase 6: Frontend Enhancements

**Changes to existing `app/threat-modeling/page.tsx`:**

1. **Connect to real API** — replace `mockSession` with API calls
2. **New Session Dialog** — wire up to `POST /api/threat-model/sessions` → `POST .../analyze`
3. **Processing State** — poll session status via SSE or polling until analysis complete
4. **DFD Tab** — render Mermaid diagram from API response instead of static layout
5. **Threat Detail Panel** — add "Apply Fix" button with:
   - Loading state while PR is being created
   - Success state showing PR URL
   - Threat status badge auto-updates to "Mitigated"
6. **Insights Tab** — compute from real threat data instead of hardcoded values

**New frontend components needed:**
```
components/unitone/
├── mermaid-diagram.tsx     — Renders Mermaid DFD with zoom/pan
├── apply-fix-button.tsx    — Apply Fix button with PR creation flow
└── threat-status-badge.tsx — Reactive status badge that updates on mitigation
```

### 2.3 Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| API | Next.js Route Handlers | Already in the stack, zero new infra |
| Database | SQLite (better-sqlite3) | Zero-config, file-based, sufficient for sessions |
| Git Operations | simple-git + Octokit | Clone repos, create PRs via GitHub API |
| LLM | Anthropic Claude API | Best code understanding for threat analysis |
| DFD Rendering | Mermaid.js | Already referenced in mock data, standard diagramming |
| File Analysis | Custom + tree-sitter (optional) | Walk repo, detect patterns |

### 2.4 New Dependencies

```json
{
  "better-sqlite3": "^11.0.0",
  "simple-git": "^3.27.0",
  "@octokit/rest": "^21.0.0",
  "@anthropic-ai/sdk": "^0.39.0",
  "mermaid": "^11.4.0",
  "uuid": "^11.0.0"
}
```

### 2.5 Environment Variables Required

```env
GITHUB_TOKEN=ghp_...                    # GitHub PAT for repo cloning and PR creation
ANTHROPIC_API_KEY=sk-ant-...            # Claude API key for threat generation
THREAT_MODEL_DB_PATH=./data/threats.db  # SQLite database file path
```

---

## Agent 3: Customer Engineer Test Plan

### 3.1 Test Scenario

**As an engineer on the JCI Smart Building team, I want to submit a GitHub repo and get a full threat model.**

### 3.2 End-to-End Test Flow

#### Test 1: GitHub Repo → Full Threat Model

1. Navigate to `/threat-modeling`
2. Click "New Session"
3. Select "GitHub Repo"
4. Enter: `https://github.com/juice-shop/juice-shop` (OWASP Juice Shop — intentionally vulnerable app)
5. Select framework: "STRIDE"
6. Click "Generate Threat Model"
7. **Verify:** Processing animation shows all 6 steps completing
8. **Verify:** Session appears with status "Review"
9. **Verify DFD tab:** Shows components (Express API, Angular SPA, SQLite DB, etc.) with trust boundaries
10. **Verify Threat List:** At least 5 threats generated, each with:
    - Structured threat statement
    - STRIDE category
    - Severity
    - At least one mitigation with code diff
11. Click on a Critical threat (e.g., SQL injection)
12. **Verify:** Slide-over shows before/after code diff with file path and line number
13. Click "Apply Fix"
14. **Verify:** PR is created on a fork/branch
15. **Verify:** Threat status changes to "Mitigated"

#### Test 2: Design Document → Prose Mitigations

1. Click "New Session"
2. Select "Design Doc"
3. Upload a sample architecture markdown document
4. Select framework: "OWASP Top 10"
5. Click "Generate Threat Model"
6. **Verify:** Threats are generated without code diffs
7. **Verify:** Mitigations are prose suggestions (not code patches)
8. **Verify:** No "Apply Fix" button appears (only "Accept Risk" and "Create Jira Ticket")

#### Test 3: Mitigation Status Lifecycle

1. Open a session with identified threats
2. Click on a threat → verify status is "Identified"
3. Click "Apply Fix" → verify status changes to "Mitigated"
4. Go back to threat list → verify the badge now shows "Mitigated" (green)
5. Check Insights tab → verify mitigation rate percentage increased

### 3.3 Edge Cases to Validate

| Scenario | Expected Behavior |
|----------|-------------------|
| Private repo without token | Error: "GitHub token required for private repos" |
| Very large repo (>1GB) | Use `--depth=1` shallow clone, analyze only key files |
| Repo with no code (docs only) | Generate threats from README/docs, no code diffs |
| Invalid GitHub URL | Validation error in form |
| LLM rate limit hit | Queue analysis, show "Processing" with retry |
| Repo with no security issues | Return fewer threats, insights show high coverage |

---

## Implementation Order

| Step | Description | Dependencies | Status |
|------|-------------|-------------|--------|
| 1 | Set up SQLite database schema and `db.ts` service | None | DONE |
| 2 | Build `repo-analyzer.ts` — clone + file inventory + architecture extraction | Step 1 | DONE |
| 3 | Build `threat-generator.ts` — LLM-powered STRIDE analysis | Step 2 | DONE |
| 4 | Build `dfd-generator.ts` — Mermaid DFD from architecture | Step 2 | DONE |
| 5 | Build `fix-generator.ts` — code-level mitigation generation | Step 3 | DONE |
| 6 | Build `git-service.ts` — GitHub clone, branch, commit, PR | Step 5 | DONE |
| 7 | Build `insight-engine.ts` — quality metrics computation | Step 3 | DONE |
| 8 | Build API route handlers (all endpoints) | Steps 1-7 | DONE |
| 9 | Build `mermaid-diagram.tsx` frontend component | Step 4 | DONE |
| 10 | Wire frontend to real APIs, add Apply Fix button | Steps 8-9 | DONE |
| 11 | End-to-end testing with OWASP Juice Shop | Step 10 | NEEDS API KEYS |
| 12 | Polish: error handling, loading states, edge cases | Step 11 | DONE |

> **Build verified:** `next build` compiles successfully with all routes registered.

---

## File Change Summary

### New Files (Backend)
- `app/api/threat-model/sessions/route.ts`
- `app/api/threat-model/sessions/[id]/route.ts`
- `app/api/threat-model/sessions/[id]/analyze/route.ts`
- `app/api/threat-model/threats/[id]/route.ts`
- `app/api/threat-model/threats/[id]/apply-fix/route.ts`
- `lib/threat-engine/repo-analyzer.ts`
- `lib/threat-engine/threat-generator.ts`
- `lib/threat-engine/dfd-generator.ts`
- `lib/threat-engine/insight-engine.ts`
- `lib/threat-engine/fix-generator.ts`
- `lib/threat-engine/git-service.ts`
- `lib/db.ts`

### New Files (Frontend)
- `components/unitone/mermaid-diagram.tsx`
- `components/unitone/apply-fix-button.tsx`

### Modified Files
- `app/threat-modeling/page.tsx` — connect to real APIs, dynamic DFD, Apply Fix flow
- `lib/threat-data.ts` — add new types for API request/response shapes
- `package.json` — add new dependencies

### Configuration
- `.env.local` — add GITHUB_TOKEN, ANTHROPIC_API_KEY
