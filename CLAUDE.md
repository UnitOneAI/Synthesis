# Synthesis Threat Modeling Engine

## Project Overview
Multi-surface, AI-powered STRIDE threat modeling platform. Monorepo with three packages:
- **@synthesis/core** — Core engine (analyzer, LLM provider, threat engine, DFD generator, formatter)
- **@synthesis/github-action** — GitHub Actions CI/CD integration (PR comments, SARIF upload)
- **synthesis-threat-model** — VS Code/Cursor extension (scan workspace/file/git, inline annotations)

## Architecture
- TypeScript monorepo managed with pnpm workspaces
- Zod schemas enforce type safety at every boundary
- LLM providers: Anthropic (claude-sonnet-4-5-20250514), Google (gemini-2.5-flash)
- STRIDE framework with MITRE ATT&CK technique correlation
- OWASP Risk Rating severity matrix (likelihood x impact, always server-side recalculated)
- Outputs: Markdown, SARIF v2.1.0, JSON, Mermaid DFD

## Security Posture
- Prompt injection barriers with instruction-hierarchy boundaries
- Input sanitization on all LLM inputs and outputs
- Path traversal prevention, Mermaid injection prevention, HTML escaping
- VS Code SecretStorage for API keys (never plaintext)
- Strict CSP with nonce-based script/style loading in webviews
- Diff size caps (1MB), file count limits, component name sanitization

## Features

### Intent Capture (B1-B5)
Business context system that makes threat modeling domain-aware via `synthesis.intent.json`.
- **Intent Schema** (`core/src/intent.ts`) — Zod-validated project declaration: domain, capabilities, data sensitivity (PCI/PII/PHI), threat actors, compliance frameworks, critical assets, infrastructure
- **Intent-Aware Prompts** (B1) — `buildIntentContext()` injects business context into LLM prompts so threats are calibrated to the system's actual risk profile (e.g., PAN exposure in a payment system is critical, not medium)
- **Severity Calibration** (B2) — Post-LLM severity adjustment: critical asset matches boost likelihood +1, PCI/PHI data sensitivity boosts impact +1 for information_disclosure threats. `intentBoost` field explains each adjustment
- **Compliance Mapping** (B3) — Static STRIDE-to-control mappings for PCI DSS v4.0, SOC 2, HIPAA, GDPR. Each threat gets `complianceMapping: string[]` with real control IDs
- **Threat Actor Contextualization** (B4) — Declared threat actors are injected into prompts to calibrate threat generation (script kiddies vs nation-state actors produce different threat profiles)
- **Data Flow Classification** (B5) — `classifyDataFlowsWithIntent()` upgrades data flow classifications to PCI when components match payment-related keywords and intent declares PCI sensitivity

### Threat Baseline & Delta Reporting (A1)
Eliminates reviewer fatigue by showing only what changed between scans.
- **Fingerprinting** (`core/src/baseline.ts`) — SHA-256 hash of `component|stride|attackTechnique` for stable threat identity across scans
- **Delta Comparison** — `compareWithBaseline()` categorizes threats as new, resolved, changed (severity shift), or unchanged
- **Baseline Management** — `createBaseline()`, `updateBaseline()`, `loadBaseline()`, `serializeBaseline()` for lifecycle management
- **Delta Markdown** — `toDeltaMarkdown()` renders "3 new | 1 resolved | 12 unchanged" with detail tables; full report in collapsible `<details>`
- **GitHub Action** — Reads `synthesis-baseline.json` from repo root, writes updated baseline to artifacts; sets `new-threat-count` output

### Incremental Scan with Context Window (A2)
Catches threats from removed security controls by analyzing 1-hop dependencies.
- **Context Expander** (`core/src/context-expander.ts`) — Two-phase expansion:
  - Forward: extracts imports from changed files and reads those dependencies
  - Reverse: scans repo for files that import changed files
- **Import Extraction** — `extractImports()` supports TypeScript/JavaScript (`import`/`require`/dynamic), Python (`import`/`from`), Go (single/block), Java/Kotlin
- **GitHub Integration** — `getFileContent()` (Contents API) and `listRepoFiles()` (Trees API, single call) added to github-client
- **Capped Expansion** — Max 20 related files, 100KB per file, non-fatal on failure
- **Action Input** — `expand-context` (default: true)

### Threat Trend Tracking (A3)
Visibility into whether the codebase is getting more or less secure over time.
- **Trend Schema** (`core/src/trend.ts`) — Per-PR entries with severity breakdown, new/resolved counts, capped at 100 entries
- **Trend Markdown** — `toTrendMarkdown()` renders PR-by-PR table with trend icons, direction percentage, avg new/resolved per PR, critical-free streak
- **GitHub Action** — Reads `synthesis-trend.json` from repo root, appends current scan, writes updated trend to artifacts, adds collapsible trend summary to PR comment and job summary
- **Action Input** — `trend-tracking` (default: true)

### PR-Level Threat Acceptance (A5)
Allows reviewers to accept/suppress threats directly from PR comments with audit trail.
- **Comment Commands** (`github-action/src/acceptance.ts`) — `@synthesis accept|mitigate|transfer TM-NNN reason: ...`
- **Acceptance Parsing** — `parseAcceptanceCommands()` fetches PR comments, strict regex matching, filters bot comments, sanitizes reason text and usernames
- **Status Update** — `applyAcceptances()` updates matching threat statuses; returns applied and unmatched lists
- **Audit Log** — `formatAcceptanceLog()` renders markdown table with threat, action, user, reason, date
- **Threshold Exclusion** — Only `status: "open"` threats count toward the failure threshold; accepted/mitigated/transferred are excluded
- **Action Input** — `process-acceptances` (default: true)

### Enhanced PR Pipeline Flow
```
PR opened → Fetch diff → Expand context (1-hop) → Generate threats (intent-aware)
  → Compare baseline (delta) → Process acceptances (@synthesis accept)
  → Track trends → Post delta report → Enforce threshold (open threats only)
```

## Key Files
- `packages/core/src/types.ts` — All schemas, enums, severity matrix, intentBoost/complianceMapping fields
- `packages/core/src/analyzer.ts` — Diff parsing, component extraction, trust boundaries, intent-aware data flow classification
- `packages/core/src/threat-engine.ts` — Main orchestration pipeline with intent calibration
- `packages/core/src/prompts.ts` — STRIDE system prompt, ATT&CK mappings, few-shot examples, intent context builder
- `packages/core/src/llm-provider.ts` — Anthropic/Gemini abstraction, rate limiter
- `packages/core/src/dfd-generator.ts` — Mermaid flowchart generation
- `packages/core/src/formatter.ts` — Markdown, SARIF, JSON, delta markdown output formatters
- `packages/core/src/intent.ts` — Intent schema, loader, compliance control mappings
- `packages/core/src/baseline.ts` — Threat fingerprinting, baseline comparison, delta reporting
- `packages/core/src/context-expander.ts` — 1-hop dependency graph expansion, import extraction
- `packages/core/src/trend.ts` — Threat trend tracking, per-PR metrics, trend markdown
- `packages/github-action/src/index.ts` — GitHub Action main entry (full enhanced pipeline)
- `packages/github-action/src/acceptance.ts` — PR comment acceptance parsing, audit log
- `packages/github-action/src/github-client.ts` — PR diff, comments, file content, repo tree APIs
- `packages/vscode-extension/src/extension.ts` — VS Code activation and command registration

## Development
- `pnpm install` — Install dependencies
- Build/test commands are per-package
- Tests use Vitest

## Security Skills Integration
This project references skills from https://github.com/unitoneai/SecuritySkills for enhanced threat analysis.

### Embedded Skills Reference

**Threat Modeling (appsec/threat-modeling)**
- STRIDE-per-element methodology with 9-step process
- Asset & entry point identification, threat actor profiling
- Data flow & trust boundary mapping
- MITRE ATT&CK correlation and risk quantification
- Use: `/skill threat-modeling <target>`

**Secure Code Review (appsec/secure-code-review)**
- OWASP ASVS 4.0.3 and CWE Top 25 (2024) aligned
- 8-step methodology: input validation, auth, crypto, error handling, data protection
- Use: `/skill secure-code-review <target>`

**Agentic AI Top 10 (ai-security/agentic-top-10)**
- OWASP Agentic AI Top 10 assessment (AG01-AG10)
- Covers excessive agency, tool misuse, privilege escalation, memory poisoning
- Trust boundary violations, data exfiltration, cascading failures
- Use: `/skill agentic-top-10 <target>`

**Pipeline Security (devsecops/pipeline-security)**
- SLSA v1.0 build maturity (L1-L3) and OWASP Top 10 CI/CD Risks
- Flow control, dependency management, artifact integrity
- Use: `/skill pipeline-security <target>`

**LLM Top 10 (ai-security/llm-top-10)**
- OWASP Top 10 for LLM Applications assessment
- Prompt injection, data poisoning, supply chain, output handling
- Use: `/skill llm-top-10 <target>`

**Prompt Injection (ai-security/prompt-injection)**
- Prompt injection vulnerability assessment
- Direct/indirect injection, jailbreak detection
- Use: `/skill prompt-injection <target>`

### Additional Relevant Skills (from SecuritySkills repo)
- `appsec/api-security` — API security assessment
- `appsec/owasp-top-10-web` — OWASP Top 10 web assessment
- `appsec/dependency-scanning` — Dependency vulnerability scanning
- `devsecops/sast-config` — SAST configuration
- `devsecops/dast-config` — DAST configuration
- `devsecops/secrets-management` — Secrets management review
- `compliance/soc2-gap` — SOC 2 gap analysis
- `compliance/nist-csf-assessment` — NIST CSF assessment
- `compliance/iso27001-gap` — ISO 27001 gap analysis
- `vuln-management/cve-triage` — CVE triage with CISA KEV
- `vuln-management/sbom-analysis` — SBOM analysis
- `identity/iam-review` — IAM review
- `identity/zero-trust-assessment` — Zero trust assessment
- `cloud/` — Cloud security skills (AWS, Azure, GCP)
- `incident-response/` — IR playbooks
- `secops/` — Security operations

## Conventions
- All threat severity is server-side calculated (never trust LLM scores)
- MITRE ATT&CK IDs must match format: T####(.NNN)?
- Component names: alphanumeric + underscore only
- Fail-closed on malformed LLM responses
- Strict Zod validation on all external inputs
