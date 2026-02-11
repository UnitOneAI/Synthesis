import { callLLM, getLLMConfig } from "@/lib/llm-provider";

// ── Types ──

export interface DesignEnhancement {
  section: string;
  gap: string;
  suggestion: string;
  rationale: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  strideCategory: string;
}

export interface PreCodeRisk {
  title: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  component: string;
  designDecision: string;
  recommendation: string;
  implementationPhase: "pre-code" | "during-code";
}

export type Framework = "STRIDE" | "OWASP Top 10" | "AWS Threat Grammar";

// ── Prompt Templates ──

const DESIGN_ENHANCEMENTS_SYSTEM_PROMPT = `You are a Principal Security Architect reviewing a design document BEFORE any code is written.
Identify 5-15 security gaps in the design itself:
- Missing security controls
- Ambiguous requirements
- Absent trust boundaries
- Missing encryption/auth specs
- Missing operational security (logging, monitoring, incident response)

For each gap provide:
- section: the section of the document where the gap exists
- gap: description of the security gap
- suggestion: specific actionable suggestion to address the gap
- rationale: why this gap matters from a security perspective
- severity: Critical | High | Medium | Low
- strideCategory: the most relevant STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege)

Output ONLY valid JSON array. No markdown, no explanation, just the JSON array.`;

const PRE_CODE_RISKS_SYSTEM_PROMPT = `You are a Principal Security Architect performing pre-implementation risk analysis.
Identify ARCHITECTURAL RISKS — design decisions and omissions that create systemic vulnerabilities. NOT runtime threats.

Focus on:
- Unnecessary attack surface
- Component coupling preventing security isolation
- Data flow exposing sensitive data
- Missing defense in depth
- Scalability decisions affecting security
- Technology choices with security implications
- Missing operational requirements (key rotation, cert management)
- Compliance gaps

For each risk provide:
- title: concise risk title
- category: STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege)
- severity: Critical | High | Medium | Low
- component: the specific component or area affected
- designDecision: the design decision or omission that creates this risk
- recommendation: actionable recommendation to mitigate
- implementationPhase: "pre-code" (must be addressed before coding) or "during-code" (can be addressed during implementation)

Output ONLY valid JSON array. No markdown, no explanation, just the JSON array.`;

const CONTEXT_LAYER_SYSTEM_PROMPT = `You are a Principal Security Architect generating a security context file that will be consumed by an AI coding agent (Claude Code, Cursor, GitHub Copilot).

The file must be structured Markdown usable as CLAUDE.md, AGENTS.md, or .cursorrules.
Use imperative tone (rules, not suggestions). Be specific to the actual components described.

Required sections:
1. Project Security Overview (2-3 sentences)
2. Security Requirements (MUST/MUST NOT numbered list)
3. Trust Boundaries (each boundary, crossing rules, validation)
4. Authentication & Authorization Patterns
5. Data Handling Rules (classification table, masking, retention)
6. Input Validation Requirements
7. Error Handling & Security
8. Logging & Audit Requirements
9. Dependency & Configuration Security
10. Security Testing Requirements

Output ONLY the raw Markdown. Do NOT wrap in code blocks. Do NOT include any preamble or explanation.`;

// ── Helper: JSON Parsing with Truncation Recovery ──

function parseJsonResponse<T>(text: string): T[] {
  let jsonStr = text.trim();

  // If wrapped in markdown code blocks, extract
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1].trim();
  }

  // If there's text before the array, find the array
  const arrayStart = jsonStr.indexOf("[");
  const arrayEnd = jsonStr.lastIndexOf("]");
  if (arrayStart !== -1 && arrayEnd !== -1) {
    jsonStr = jsonStr.substring(arrayStart, arrayEnd + 1);
  } else if (arrayStart !== -1) {
    // Truncated response — no closing bracket
    jsonStr = jsonStr.substring(arrayStart);
  }

  // First try: parse as-is
  try {
    const parsed = JSON.parse(jsonStr);
    if (!Array.isArray(parsed)) {
      throw new Error("Expected JSON array");
    }
    return parsed as T[];
  } catch (firstError) {
    // Second try: repair truncated JSON by finding last complete object
    console.log("[design-review-engine] JSON parse failed, attempting truncated JSON recovery...");
    try {
      const repaired = repairTruncatedJsonArray(jsonStr);
      const parsed = JSON.parse(repaired);
      if (!Array.isArray(parsed)) {
        throw new Error("Expected JSON array after repair");
      }
      console.log(`[design-review-engine] Recovered ${parsed.length} items from truncated response`);
      return parsed as T[];
    } catch (repairError) {
      console.error("Failed to parse LLM response:", firstError);
      console.error("Repair also failed:", repairError);
      console.error("Raw text:", text.substring(0, 500));
      throw new Error(`Failed to parse design review response: ${firstError}`);
    }
  }
}

function repairTruncatedJsonArray(jsonStr: string): string {
  let depth = 0;
  let inString = false;
  let escape = false;
  let lastCompleteObjectEnd = -1;

  for (let i = 0; i < jsonStr.length; i++) {
    const ch = jsonStr[i];
    if (escape) { escape = false; continue; }
    if (ch === "\\") { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;

    if (ch === "[" || ch === "{") depth++;
    if (ch === "]" || ch === "}") {
      depth--;
      // If we're back to depth 1 (inside the top-level array), we just closed an object
      if (depth === 1 && ch === "}") {
        lastCompleteObjectEnd = i;
      }
    }
  }

  if (lastCompleteObjectEnd > 0) {
    return jsonStr.substring(0, lastCompleteObjectEnd + 1) + "]";
  }

  throw new Error("Could not find any complete objects in truncated JSON");
}

// ── Helper: Validation ──

const VALID_SEVERITIES = ["Critical", "High", "Medium", "Low"];
const VALID_STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];

function validateSeverity(value: unknown): DesignEnhancement["severity"] {
  return VALID_SEVERITIES.includes(value as string)
    ? (value as DesignEnhancement["severity"])
    : "Medium";
}

function validateStrideCategory(value: unknown): string {
  return VALID_STRIDE_CATEGORIES.includes(value as string)
    ? (value as string)
    : "Information Disclosure";
}

function validateImplementationPhase(value: unknown): PreCodeRisk["implementationPhase"] {
  return value === "pre-code" || value === "during-code"
    ? value
    : "pre-code";
}

function validateEnhancement(raw: Record<string, unknown>): DesignEnhancement | null {
  try {
    return {
      section: String(raw.section || "General"),
      gap: String(raw.gap || "Unspecified gap"),
      suggestion: String(raw.suggestion || "No suggestion provided"),
      rationale: String(raw.rationale || "No rationale provided"),
      severity: validateSeverity(raw.severity),
      strideCategory: validateStrideCategory(raw.strideCategory),
    };
  } catch {
    return null;
  }
}

function validateRisk(raw: Record<string, unknown>): PreCodeRisk | null {
  try {
    return {
      title: String(raw.title || "Untitled Risk"),
      category: validateStrideCategory(raw.category),
      severity: validateSeverity(raw.severity),
      component: String(raw.component || "Unspecified component"),
      designDecision: String(raw.designDecision || "Unspecified decision"),
      recommendation: String(raw.recommendation || "No recommendation provided"),
      implementationPhase: validateImplementationPhase(raw.implementationPhase),
    };
  } catch {
    return null;
  }
}

// ── Demo Fallbacks ──

function generateDemoEnhancements(docName: string): DesignEnhancement[] {
  return [
    {
      section: "Authentication",
      gap: "No multi-factor authentication requirement specified",
      suggestion: "Add mandatory MFA for all user accounts, with hardware key support for administrative roles",
      rationale: "Single-factor authentication is insufficient for protecting sensitive resources; credential stuffing and phishing attacks can bypass password-only authentication",
      severity: "Critical",
      strideCategory: "Spoofing",
    },
    {
      section: "Data Storage",
      gap: "Encryption at rest not specified for sensitive data stores",
      suggestion: "Require AES-256 encryption at rest for all data stores containing PII or sensitive business data, with key management via a dedicated KMS",
      rationale: "Unencrypted data at rest is vulnerable to exposure through backup theft, disk imaging, or unauthorized physical access to storage media",
      severity: "High",
      strideCategory: "Information Disclosure",
    },
    {
      section: "Operational Security",
      gap: "No centralized logging or monitoring architecture defined",
      suggestion: "Define a centralized logging pipeline with structured log format, retention policies, real-time alerting for security events, and tamper-proof storage",
      rationale: "Without centralized logging, security incidents cannot be detected, investigated, or attributed, and compliance audit requirements cannot be met",
      severity: "High",
      strideCategory: "Repudiation",
    },
    {
      section: "API Design",
      gap: "Input validation requirements not specified for API endpoints",
      suggestion: "Define input validation schemas for all API endpoints using a schema validation library, with allowlists for expected values and strict type checking",
      rationale: "Missing input validation is the root cause of injection attacks, buffer overflows, and business logic bypass vulnerabilities",
      severity: "High",
      strideCategory: "Tampering",
    },
    {
      section: "Error Handling",
      gap: "No error handling strategy or error response format defined",
      suggestion: "Define a standardized error response format that returns safe error codes to clients without exposing stack traces, internal paths, or system details",
      rationale: "Verbose error messages leak implementation details that attackers use for reconnaissance and to craft targeted exploits",
      severity: "Medium",
      strideCategory: "Information Disclosure",
    },
  ];
}

function generateDemoRisks(docName: string): PreCodeRisk[] {
  return [
    {
      title: "No Encryption-at-Rest Strategy for Data Stores",
      category: "Information Disclosure",
      severity: "Critical",
      component: "Data Storage Layer",
      designDecision: "The design specifies database storage for sensitive data but does not mandate encryption at rest or define key management procedures",
      recommendation: "Mandate AES-256 encryption at rest for all data stores, integrate with a KMS for key lifecycle management, and define key rotation schedules before implementation begins",
      implementationPhase: "pre-code",
    },
    {
      title: "Authentication Service Tightly Coupled to Application Logic",
      category: "Spoofing",
      severity: "High",
      component: "Authentication Module",
      designDecision: "Authentication logic is embedded within the application layer rather than isolated as an independent service behind a trust boundary",
      recommendation: "Extract authentication into a dedicated service with its own trust boundary, implement token-based communication with the application layer, and enforce strict interface contracts",
      implementationPhase: "pre-code",
    },
    {
      title: "No API Rate Limiting or Throttling Architecture",
      category: "Denial of Service",
      severity: "High",
      component: "API Gateway",
      designDecision: "The design does not include rate limiting, throttling, or circuit breaker patterns for public-facing API endpoints",
      recommendation: "Design a tiered rate limiting strategy (per-IP, per-user, per-endpoint) at the API gateway layer, implement circuit breakers for downstream service calls, and define backpressure mechanisms",
      implementationPhase: "pre-code",
    },
    {
      title: "No Secret Management Architecture Defined",
      category: "Information Disclosure",
      severity: "High",
      component: "Configuration Management",
      designDecision: "The design does not specify how secrets (API keys, database credentials, encryption keys) will be stored, rotated, or accessed at runtime",
      recommendation: "Integrate a secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager), define secret rotation policies, eliminate hardcoded secrets, and implement least-privilege access to secrets",
      implementationPhase: "pre-code",
    },
    {
      title: "Audit Logging Not Designed as a First-Class Concern",
      category: "Repudiation",
      severity: "Medium",
      component: "Logging Infrastructure",
      designDecision: "Audit logging is not mentioned as a design requirement, risking incomplete coverage of security-relevant events and compliance gaps",
      recommendation: "Design an audit logging framework as a cross-cutting concern: define which events are logged, structured log schema, tamper-proof storage, retention policies, and integration with SIEM before writing application code",
      implementationPhase: "during-code",
    },
  ];
}

function generateDemoContextLayer(docName: string): string {
  return `# Security Context — ${docName}

## 1. Project Security Overview

This document defines the mandatory security requirements for the application described in ${docName}. All code contributions MUST comply with these rules. Violations will be flagged during security review and must be remediated before merge.

## 2. Security Requirements

1. MUST authenticate all API requests using short-lived JWT tokens (max 15-minute expiry) with refresh token rotation.
2. MUST enforce role-based access control (RBAC) on every endpoint and data access operation.
3. MUST encrypt all data at rest using AES-256 and all data in transit using TLS 1.2+.
4. MUST validate and sanitize all user input at the API boundary before processing.
5. MUST NOT log sensitive data (passwords, tokens, PII, payment info) in any log stream.
6. MUST NOT expose stack traces, internal paths, or system details in error responses.
7. MUST implement rate limiting on all public-facing endpoints.
8. MUST use parameterized queries for all database operations — no string concatenation.
9. MUST store secrets in a dedicated secrets manager — never in code, config files, or environment variables in plaintext.
10. MUST generate a unique correlation ID for each request and propagate it through all service calls.

## 3. Trust Boundaries

### External Client → API Gateway
- All requests MUST be authenticated and authorized before crossing this boundary.
- Input validation MUST occur at this boundary before data reaches internal services.
- Rate limiting and WAF rules are enforced at this boundary.

### API Gateway → Internal Services
- Internal services MUST verify the request originated from the gateway (mutual TLS or signed tokens).
- Service-to-service communication MUST use TLS 1.2+.
- Each service MUST independently validate authorization claims.

### Application → Data Store
- All database queries MUST use parameterized statements.
- Database credentials MUST be retrieved from the secrets manager at runtime.
- Connection pooling MUST enforce maximum connection limits.

## 4. Authentication & Authorization Patterns

- Use OAuth 2.0 with PKCE for user authentication flows.
- Issue JWTs with \`sub\`, \`roles\`, \`exp\`, \`iat\`, \`jti\` claims.
- Validate JWT signature, expiration, and issuer on every request.
- Implement refresh token rotation — each refresh token is single-use.
- Enforce MFA for administrative operations and sensitive data access.
- RBAC roles: \`viewer\`, \`editor\`, \`admin\`, \`super-admin\`. Default to \`viewer\`.
- Authorization checks MUST occur at the service layer, not only at the API gateway.

## 5. Data Handling Rules

| Classification | Examples | Storage | Transit | Logging | Retention |
|---------------|----------|---------|---------|---------|-----------|
| Restricted | Passwords, keys, tokens | AES-256, KMS-managed keys | TLS 1.2+ | NEVER log | Minimum necessary |
| Confidential | PII, email, phone | AES-256 | TLS 1.2+ | Mask all fields | Per privacy policy |
| Internal | Business logic data | Encrypted at rest | TLS 1.2+ | Redact sensitive fields | Per retention policy |
| Public | Marketing content | Standard storage | HTTPS | Allowed | No restriction |

- PII MUST be masked in all log output (e.g., \`email: j***@example.com\`).
- Database backups MUST be encrypted with a separate key from the primary data store.

## 6. Input Validation Requirements

- Validate all input at the API boundary using schema validation (JSON Schema or equivalent).
- Use allowlists for enumerated values — never denylists.
- Enforce maximum length limits on all string inputs.
- Reject requests with unexpected fields (strict mode).
- Sanitize HTML content using a trusted library before storage or rendering.
- Validate file uploads: check MIME type, file extension, file size, and scan for malware.

## 7. Error Handling & Security

- Return standardized error responses: \`{ "error": { "code": "ERR_CODE", "message": "Safe message" } }\`.
- MUST NOT include stack traces, file paths, SQL queries, or internal identifiers in error responses.
- Log the full error details server-side with the correlation ID.
- Use distinct error codes for client errors (4xx) and server errors (5xx).
- Implement a global exception handler that catches unhandled errors and returns a generic 500 response.

## 8. Logging & Audit Requirements

- Log all authentication events (login, logout, failed attempts, token refresh).
- Log all authorization failures with the requesting user, resource, and attempted action.
- Log all state-changing operations (create, update, delete) with actor identity and timestamp.
- Use structured JSON logging with fields: \`timestamp\`, \`correlationId\`, \`userId\`, \`action\`, \`resource\`, \`outcome\`, \`ip\`.
- Ship logs to a centralized, append-only log store.
- Retain security logs for a minimum of 12 months.
- MUST NOT log request/response bodies containing sensitive data.

## 9. Dependency & Configuration Security

- Pin all dependency versions — do not use floating version ranges.
- Run automated dependency vulnerability scanning in CI (e.g., \`npm audit\`, Snyk, Dependabot).
- Review and approve all new dependencies before adding them.
- MUST NOT use dependencies with known critical vulnerabilities.
- Store all configuration in environment-specific config — never hardcode values.
- Secrets MUST be injected at runtime from the secrets manager, not baked into container images.

## 10. Security Testing Requirements

- Run SAST (static analysis) on every pull request — block merge on critical findings.
- Run dependency vulnerability scanning on every build.
- Implement integration tests for all authentication and authorization flows.
- Test all input validation rules with boundary values and known attack payloads.
- Perform penetration testing before each major release.
- Verify error responses do not leak sensitive information.
- Test rate limiting behavior under load.
`;
}

// ── Function 1: Generate Design Enhancements ──

export async function generateDesignEnhancements(
  docContent: string,
  docName: string,
  framework: Framework = "STRIDE"
): Promise<DesignEnhancement[]> {
  const config = await getLLMConfig();
  if (!config) {
    console.log("[design-review-engine] No LLM API key configured — using demo mode for design enhancements");
    return generateDemoEnhancements(docName);
  }

  const userPrompt = `## Design Document: ${docName}

## Framework: ${framework}

## Document Content
${docContent.substring(0, 15000)}

## Instructions
Review this design document and identify 5-15 security gaps in the design itself. For each gap provide: section, gap, suggestion, rationale, severity, and strideCategory. Output ONLY the JSON array.`;

  const text = await callLLM(DESIGN_ENHANCEMENTS_SYSTEM_PROMPT, userPrompt, config, 4096);

  const enhancements = parseJsonResponse<DesignEnhancement>(text);
  return enhancements.map(validateEnhancement).filter(Boolean) as DesignEnhancement[];
}

// ── Function 2: Generate Pre-Code Risks ──

export async function generatePreCodeRisks(
  docContent: string,
  docName: string,
  framework: Framework = "STRIDE"
): Promise<PreCodeRisk[]> {
  const config = await getLLMConfig();
  if (!config) {
    console.log("[design-review-engine] No LLM API key configured — using demo mode for pre-code risks");
    return generateDemoRisks(docName);
  }

  const userPrompt = `## Design Document: ${docName}

## Framework: ${framework}

## Document Content
${docContent.substring(0, 15000)}

## Instructions
Perform a pre-implementation risk analysis on this design document. Identify 5-12 architectural risks — design decisions and omissions that create systemic vulnerabilities. For each risk provide: title, category, severity, component, designDecision, recommendation, and implementationPhase. Output ONLY the JSON array.`;

  const text = await callLLM(PRE_CODE_RISKS_SYSTEM_PROMPT, userPrompt, config, 4096);

  const risks = parseJsonResponse<PreCodeRisk>(text);
  return risks.map(validateRisk).filter(Boolean) as PreCodeRisk[];
}

// ── Function 3: Generate Context Layer ──

export async function generateContextLayer(
  docContent: string,
  docName: string,
  threats: Array<{ title: string; strideCategory: string; severity: string }>,
  enhancements: DesignEnhancement[],
  risks: PreCodeRisk[]
): Promise<string> {
  const config = await getLLMConfig();
  if (!config) {
    console.log("[design-review-engine] No LLM API key configured — using demo mode for context layer");
    return generateDemoContextLayer(docName);
  }

  // Build summaries for the prompt
  const threatSummary = threats
    .map((t) => `- ${t.title} [${t.strideCategory}] (${t.severity})`)
    .join("\n");

  const enhancementSummary = enhancements
    .map((e) => `- [${e.section}] ${e.gap} → ${e.suggestion}`)
    .join("\n");

  const riskSummary = risks
    .map((r) => `- ${r.title} [${r.component}] → ${r.recommendation}`)
    .join("\n");

  const userPrompt = `## Design Document: ${docName}

## Document Content
${docContent.substring(0, 10000)}

## Identified Threats
${threatSummary || "No threats identified yet."}

## Design Enhancements
${enhancementSummary || "No enhancements identified yet."}

## Pre-Code Risks
${riskSummary || "No risks identified yet."}

## Instructions
Generate a security context file based on the design document and the identified threats, enhancements, and risks above. The file must be structured Markdown with all 10 required sections. Use imperative tone and be specific to the actual components described in the document. Output ONLY the raw Markdown.`;

  const text = await callLLM(CONTEXT_LAYER_SYSTEM_PROMPT, userPrompt, config, 4096);

  // For the context layer, the response is raw Markdown, not JSON
  // Strip any accidental code block wrapping
  let markdown = text.trim();
  const codeBlockMatch = markdown.match(/^```(?:markdown|md)?\s*\n([\s\S]*?)\n```$/);
  if (codeBlockMatch) {
    markdown = codeBlockMatch[1].trim();
  }

  return markdown;
}
