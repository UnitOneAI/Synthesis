import type { RepoAnalysis } from "./repo-analyzer";
import { callLLM, getLLMConfig } from "@/lib/llm-provider";
import {
  type OwaspLikelihood,
  type OwaspImpact,
  calculateRiskRating,
} from "./owasp-risk-engine";

// ── Types ──

export interface GeneratedThreat {
  title: string;
  strideCategory:
    | "Spoofing"
    | "Tampering"
    | "Repudiation"
    | "Information Disclosure"
    | "Denial of Service"
    | "Elevation of Privilege";
  severity: "Critical" | "High" | "Medium" | "Low";
  threatSource: string;
  prerequisites: string;
  threatAction: string;
  threatImpact: string;
  impactedAssets: string[];
  trustBoundary: string;
  assumptions: string[];
  mitigations: {
    description: string;
    codeFile?: string;
    codeLine?: number;
    codeOriginal?: string;
    codeFixed?: string;
  }[];
  relatedCve?: string;
  owaspLikelihood?: OwaspLikelihood;
  owaspImpact?: OwaspImpact;
}

export type Framework = "STRIDE" | "OWASP Top 10" | "AWS Threat Grammar";

// ── Prompt Templates ──

const SYSTEM_PROMPT = `You are a Principal Security Review Engineer performing a threat model.
You produce structured threat statements following the AWS Threat Grammar:

"A [threat source] with [prerequisites] can [threat action], which leads to [threat impact], negatively impacting [impacted assets]."

Rules:
1. Each threat MUST have a structured threat statement with all fields populated.
2. Classify each threat into exactly one STRIDE category: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege.
3. For EACH threat, estimate OWASP Risk Rating factors following the OWASP Risk Rating Methodology. Rate each likelihood and impact factor on a 0-9 scale. The severity field should reflect your assessment but will be recalculated from the OWASP risk matrix.
4. Identify the specific trust boundary being crossed.
5. List realistic assumptions.
6. Propose at least one mitigation per threat.
7. If source code files and security findings are provided, reference specific files, line numbers, and include code-level original/fixed snippets in mitigations.
8. Be specific and actionable — avoid generic threats. Reference actual components from the architecture.
9. Generate between 5 and 12 threats depending on the complexity of the architecture.
10. Do NOT invent file paths or line numbers that aren't in the provided data.

OWASP Likelihood Factors (rate each 0-9):
- skillLevel: 1=no skills, 3=some, 5=advanced, 6=network/programming, 9=security penetration
- motive: 1=low/no reward, 4=possible reward, 9=high reward
- opportunity: 0=full access required, 4=special access, 7=some access, 9=no access needed
- size: 2=developers/sysadmins, 4=intranet, 5=partners, 6=authenticated, 9=anonymous internet
- easeOfDiscovery: 1=impossible, 3=difficult, 7=easy, 9=automated tools
- easeOfExploit: 1=theoretical, 3=difficult, 5=easy, 9=automated tools
- awareness: 1=unknown, 4=hidden, 6=obvious, 9=public knowledge
- intrusionDetection: 1=active detection, 3=logged+reviewed, 8=logged only, 9=not logged

OWASP Technical Impact Factors (rate each 0-9):
- confidentiality: 2=minimal non-sensitive, 6=minimal critical or extensive non-sensitive, 7=extensive critical, 9=all data
- integrity: 1=minimal slight, 3=minimal serious, 5=extensive slight, 7=extensive serious, 9=all corrupt
- availability: 1=minimal secondary, 5=minimal primary or extensive secondary, 7=extensive primary, 9=all lost
- accountability: 1=fully traceable, 7=possibly traceable, 9=anonymous

Output ONLY valid JSON matching the schema below. No markdown, no explanation, just the JSON array.`;

const OWASP_SYSTEM_ADDENDUM = `

Additionally, map each threat to the most relevant OWASP Top 10:2021 category:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery

Include the OWASP category in the threat title prefix (e.g., "[A03] SQL Injection in User Search").
Still classify into STRIDE categories as the primary framework.`;

const OUTPUT_SCHEMA = `
Output JSON Schema (array of objects):
[
  {
    "title": "string — concise threat title",
    "strideCategory": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",
    "severity": "Critical | High | Medium | Low",
    "threatSource": "string — who/what is the threat actor",
    "prerequisites": "string — conditions required for the threat",
    "threatAction": "string — the specific action taken",
    "threatImpact": "string — the direct consequence",
    "impactedAssets": ["string — affected assets"],
    "trustBoundary": "string — which boundary is crossed",
    "assumptions": ["string — assumptions about the system"],
    "mitigations": [
      {
        "description": "string — mitigation description",
        "codeFile": "string (optional) — file path if code fix available",
        "codeLine": "number (optional)",
        "codeOriginal": "string (optional) — original vulnerable code",
        "codeFixed": "string (optional) — fixed code"
      }
    ],
    "relatedCve": "string (optional) — related CVE ID if applicable",
    "owaspLikelihood": {
      "skillLevel": "number 0-9",
      "motive": "number 0-9",
      "opportunity": "number 0-9",
      "size": "number 0-9",
      "easeOfDiscovery": "number 0-9",
      "easeOfExploit": "number 0-9",
      "awareness": "number 0-9",
      "intrusionDetection": "number 0-9"
    },
    "owaspImpact": {
      "confidentiality": "number 0-9",
      "integrity": "number 0-9",
      "availability": "number 0-9",
      "accountability": "number 0-9"
    }
  }
]`;

// ── Demo fallback threats (when no API key) ──

function generateDemoThreats(analysis: RepoAnalysis): GeneratedThreat[] {
  const threats: GeneratedThreat[] = [];
  const categories: GeneratedThreat["strideCategory"][] = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
  ];

  // Generate threats based on actual security findings
  for (const finding of analysis.securityFindings.slice(0, 6)) {
    const strideCat = categories[threats.length % 6];
    const severityMap: Record<string, GeneratedThreat["severity"]> = {
      high: "Critical", medium: "High", low: "Medium",
    };
    threats.push({
      title: `${strideCat}: ${finding.pattern.replace(/_/g, " ")} in ${finding.file.split("/").pop()}`,
      strideCategory: strideCat,
      severity: severityMap[finding.severity] || "Medium",
      threatSource: "An external attacker",
      prerequisites: `Access to the ${finding.file.includes("api") ? "API endpoint" : "application input"} that reaches this code path`,
      threatAction: `can exploit ${finding.pattern.replace(/_/g, " ")} at ${finding.file}:${finding.line}`,
      threatImpact: `which leads to ${strideCat === "Information Disclosure" ? "exposure of sensitive data" : strideCat === "Tampering" ? "unauthorized data modification" : strideCat === "Spoofing" ? "identity impersonation" : strideCat === "Elevation of Privilege" ? "unauthorized access to privileged operations" : strideCat === "Denial of Service" ? "service unavailability" : "inability to trace malicious actions"}`,
      impactedAssets: [finding.file, ...(analysis.components.slice(0, 2).map(c => c.name))],
      trustBoundary: analysis.trustBoundaries[0]?.name || "External → Internal",
      assumptions: [
        "Application is internet-facing",
        "Input validation is incomplete",
        `The code in ${finding.file} is reachable from external requests`,
      ],
      mitigations: [{
        description: `Fix the ${finding.pattern.replace(/_/g, " ")} vulnerability by applying secure coding practices`,
        codeFile: finding.file,
        codeLine: finding.line,
        codeOriginal: finding.snippet,
        codeFixed: `// FIXED: ${finding.pattern} remediated\n${finding.snippet.replace(/eval\(/, "safeEval(").replace(/\+\s*req\./, "+ sanitize(req.").replace(/cors\(\)/, 'cors({ origin: allowedOrigins })')}`,
      }],
      relatedCve: undefined,
    });
  }

  // Add architecture-level threats from components/data flows
  const archThreats: { title: string; cat: GeneratedThreat["strideCategory"]; sev: GeneratedThreat["severity"]; boundary: string }[] = [
    { title: "Insufficient Authentication on API Gateway", cat: "Spoofing", sev: "High", boundary: "Client → API" },
    { title: "Missing Rate Limiting on Public Endpoints", cat: "Denial of Service", sev: "High", boundary: "External → Internal" },
    { title: "Insecure Data Transmission Between Services", cat: "Information Disclosure", sev: "Medium", boundary: "Service → Service" },
    { title: "Missing Audit Logging for Administrative Actions", cat: "Repudiation", sev: "Medium", boundary: "Admin → System" },
    { title: "Improper Input Validation at Trust Boundary", cat: "Tampering", sev: "High", boundary: "External → Internal" },
    { title: "Overly Permissive Role-Based Access Controls", cat: "Elevation of Privilege", sev: "Critical", boundary: "User → Admin" },
  ];

  for (const at of archThreats.slice(0, Math.max(2, 8 - threats.length))) {
    const comp = analysis.components[threats.length % Math.max(analysis.components.length, 1)];
    threats.push({
      title: at.title,
      strideCategory: at.cat,
      severity: at.sev,
      threatSource: "An authenticated or unauthenticated user",
      prerequisites: `Network access to the ${comp?.name || "application"} component`,
      threatAction: `can exploit ${at.title.toLowerCase()} at the ${at.boundary} boundary`,
      threatImpact: `which leads to ${at.cat === "Spoofing" ? "unauthorized identity assumption" : at.cat === "Denial of Service" ? "resource exhaustion and service degradation" : at.cat === "Information Disclosure" ? "leakage of sensitive business data" : at.cat === "Repudiation" ? "inability to audit security-relevant events" : at.cat === "Tampering" ? "unauthorized modification of application state" : "privilege escalation to administrative functions"}`,
      impactedAssets: comp ? comp.files.slice(0, 3) : ["Application"],
      trustBoundary: at.boundary,
      assumptions: [
        `The ${comp?.name || "system"} component handles sensitive operations`,
        "Standard security controls may be incomplete",
      ],
      mitigations: [{
        description: `Implement ${at.cat === "Spoofing" ? "multi-factor authentication and token validation" : at.cat === "Denial of Service" ? "rate limiting with exponential backoff" : at.cat === "Information Disclosure" ? "TLS 1.3 for all inter-service communication" : at.cat === "Repudiation" ? "comprehensive audit logging with tamper-proof storage" : at.cat === "Tampering" ? "strict input validation and schema enforcement" : "least-privilege RBAC with regular access reviews"}`,
      }],
      relatedCve: undefined,
    });
  }

  return threats;
}

function generateDemoThreatsFromDoc(docName: string): GeneratedThreat[] {
  return [
    {
      title: "Insufficient Authentication in Proposed Architecture",
      strideCategory: "Spoofing",
      severity: "High",
      threatSource: "An external attacker",
      prerequisites: "Access to the public-facing endpoints described in the design",
      threatAction: "can forge authentication tokens or bypass identity verification",
      threatImpact: "which leads to unauthorized access to protected resources",
      impactedAssets: ["Authentication Service", "User Data Store", "API Gateway"],
      trustBoundary: "External → Internal",
      assumptions: ["The system is internet-facing", "Authentication relies on bearer tokens"],
      mitigations: [{ description: "Implement OAuth 2.0 with PKCE flow, enforce MFA for sensitive operations, use short-lived JWTs with refresh token rotation" }],
    },
    {
      title: "Data Tampering in Message Queue Processing",
      strideCategory: "Tampering",
      severity: "High",
      threatSource: "A malicious insider or compromised service",
      prerequisites: "Access to the internal message bus or queue system",
      threatAction: "can inject or modify messages in the processing pipeline",
      threatImpact: "which leads to corrupted business data and incorrect processing outcomes",
      impactedAssets: ["Message Queue", "Processing Pipeline", "Data Store"],
      trustBoundary: "Service → Service",
      assumptions: ["Inter-service communication is not end-to-end encrypted", "Message integrity is not verified"],
      mitigations: [{ description: "Implement message signing with HMAC-SHA256, validate message integrity before processing, use TLS for all internal communication" }],
    },
    {
      title: "Missing Audit Trail for Critical Operations",
      strideCategory: "Repudiation",
      severity: "Medium",
      threatSource: "An authenticated user with elevated privileges",
      prerequisites: "Valid credentials with administrative access",
      threatAction: "can perform destructive actions without generating an audit trail",
      threatImpact: "which leads to inability to investigate security incidents or prove compliance",
      impactedAssets: ["Admin Console", "Configuration Store", "All System Components"],
      trustBoundary: "Admin → System",
      assumptions: ["The design does not specify comprehensive logging", "Audit logs are stored locally"],
      mitigations: [{ description: "Implement centralized, append-only audit logging with tamper detection, log all state-changing operations with actor identity and timestamp" }],
    },
    {
      title: "Sensitive Data Exposure in API Responses",
      strideCategory: "Information Disclosure",
      severity: "Critical",
      threatSource: "An external attacker or authorized user exceeding their access level",
      prerequisites: "Ability to call API endpoints and inspect responses",
      threatAction: "can extract sensitive information from verbose API responses or error messages",
      threatImpact: "which leads to exposure of PII, credentials, or internal system details",
      impactedAssets: ["REST API", "User Data", "System Configuration"],
      trustBoundary: "External → API",
      assumptions: ["API responses may include more data than the caller needs", "Error responses expose stack traces"],
      mitigations: [{ description: "Implement response field filtering based on caller authorization, sanitize all error responses, use DTOs to control API response shape" }],
    },
    {
      title: "Resource Exhaustion via Unthrottled API Calls",
      strideCategory: "Denial of Service",
      severity: "High",
      threatSource: "An external attacker or compromised client",
      prerequisites: "Network access to public API endpoints",
      threatAction: "can send a high volume of requests to exhaust server resources",
      threatImpact: "which leads to service degradation or complete unavailability for legitimate users",
      impactedAssets: ["API Gateway", "Application Servers", "Database"],
      trustBoundary: "External → Internal",
      assumptions: ["No rate limiting is described in the design", "Auto-scaling has finite limits"],
      mitigations: [{ description: "Implement tiered rate limiting (per-IP, per-user, global), deploy WAF rules, use circuit breakers, configure auto-scaling with spending caps" }],
    },
    {
      title: "Privilege Escalation Through Insecure Direct Object References",
      strideCategory: "Elevation of Privilege",
      severity: "Critical",
      threatSource: "An authenticated low-privilege user",
      prerequisites: "Valid authentication credentials for any role",
      threatAction: "can manipulate resource identifiers to access or modify resources belonging to other users or roles",
      threatImpact: "which leads to unauthorized access to administrative functions and other users' data",
      impactedAssets: ["Authorization Service", "User Management", "All Protected Resources"],
      trustBoundary: "User → Admin",
      assumptions: ["Authorization checks rely on client-provided resource IDs", "Role hierarchy enforcement may be incomplete"],
      mitigations: [{ description: "Implement server-side authorization checks for every resource access, use indirect object references (UUIDs), enforce role-based access control at the data layer" }],
    },
  ];
}

// ── Main Generator ──

export async function generateThreats(
  analysis: RepoAnalysis,
  framework: Framework = "STRIDE"
): Promise<GeneratedThreat[]> {
  const config = await getLLMConfig();
  if (!config) {
    console.log("[threat-generator] No LLM API key configured — using demo mode with realistic mock threats");
    return generateDemoThreats(analysis);
  }

  // Build the user prompt with architecture data
  const userPrompt = buildUserPrompt(analysis, framework);

  // Build system prompt
  let systemPrompt = SYSTEM_PROMPT;
  if (framework === "OWASP Top 10") {
    systemPrompt += OWASP_SYSTEM_ADDENDUM;
  }
  systemPrompt += "\n" + OUTPUT_SCHEMA;

  const text = await callLLM(systemPrompt, userPrompt, config, 16384);

  // Parse JSON response — handle possible truncation if stop_reason is max_tokens
  const threats = parseThreatsResponse(text);
  return threats;
}

function buildUserPrompt(
  analysis: RepoAnalysis,
  framework: Framework
): string {
  const sections: string[] = [];

  sections.push(`## Repository: ${analysis.repoUrl}`);
  sections.push(`## Framework: ${framework}`);

  sections.push(`\n## Languages Detected\n${analysis.languages.join(", ")}`);
  sections.push(
    `\n## Frameworks Detected\n${analysis.frameworks.join(", ") || "None specifically detected"}`
  );

  // Components
  sections.push(`\n## Architecture Components (${analysis.components.length})`);
  for (const comp of analysis.components) {
    sections.push(
      `- **${comp.name}** (${comp.type}): ${comp.description}\n  Files: ${comp.files.slice(0, 5).join(", ")}${comp.files.length > 5 ? ` (+${comp.files.length - 5} more)` : ""}`
    );
  }

  // Data Flows
  sections.push(`\n## Data Flows (${analysis.dataFlows.length})`);
  for (const flow of analysis.dataFlows) {
    sections.push(
      `- ${flow.from} → ${flow.to} [${flow.protocol}] (${flow.dataType})`
    );
  }

  // Trust Boundaries
  sections.push(
    `\n## Trust Boundaries (${analysis.trustBoundaries.length})`
  );
  for (const boundary of analysis.trustBoundaries) {
    sections.push(
      `- **${boundary.name}**: ${boundary.components.join(", ")}`
    );
  }

  // Security Findings (the most important input)
  sections.push(
    `\n## Security Findings from Code Scan (${analysis.securityFindings.length})`
  );
  if (analysis.securityFindings.length === 0) {
    sections.push(
      "No specific patterns detected by static scan — analyze architecture for design-level threats."
    );
  } else {
    for (const finding of analysis.securityFindings.slice(0, 30)) {
      sections.push(
        `- **${finding.pattern}** [${finding.severity}] in \`${finding.file}:${finding.line}\`\n  \`${finding.snippet}\``
      );
    }
  }

  // Entry Points
  sections.push(`\n## Entry Points\n${analysis.entryPoints.slice(0, 15).join("\n")}`);

  sections.push(
    `\n## Instructions\nGenerate a comprehensive threat model for this repository. For each security finding above, map it to a specific threat with a code-level mitigation. For each trust boundary crossing, assess relevant ${framework} threats. Output ONLY the JSON array.`
  );

  return sections.join("\n");
}

function parseThreatsResponse(text: string): GeneratedThreat[] {
  // Try to extract JSON from the response
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
    return parsed.map(validateThreat).filter(Boolean) as GeneratedThreat[];
  } catch (firstError) {
    // Second try: repair truncated JSON by finding last complete object
    console.log("[threat-generator] JSON parse failed, attempting truncated JSON recovery...");
    try {
      const repaired = repairTruncatedJsonArray(jsonStr);
      const parsed = JSON.parse(repaired);
      if (!Array.isArray(parsed)) {
        throw new Error("Expected JSON array after repair");
      }
      console.log(`[threat-generator] Recovered ${parsed.length} threats from truncated response`);
      return parsed.map(validateThreat).filter(Boolean) as GeneratedThreat[];
    } catch (repairError) {
      console.error("Failed to parse LLM response:", firstError);
      console.error("Repair also failed:", repairError);
      console.error("Raw text:", text.substring(0, 500));
      throw new Error(`Failed to parse threat model response: ${firstError}`);
    }
  }
}

function repairTruncatedJsonArray(jsonStr: string): string {
  // Find the last complete JSON object in the array by looking for },{ or },\n{ patterns
  // then close the array
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

  // Couldn't find a complete object — give up
  throw new Error("Could not find any complete objects in truncated JSON");
}

function validateThreat(raw: Record<string, unknown>): GeneratedThreat | null {
  try {
    const validStride = [
      "Spoofing",
      "Tampering",
      "Repudiation",
      "Information Disclosure",
      "Denial of Service",
      "Elevation of Privilege",
    ];

    const strideCategory = validStride.includes(raw.strideCategory as string)
      ? (raw.strideCategory as GeneratedThreat["strideCategory"])
      : "Information Disclosure";

    // Parse OWASP factors from LLM output
    const owaspLikelihood = raw.owaspLikelihood as
      | Partial<OwaspLikelihood>
      | undefined;
    const owaspImpact = raw.owaspImpact as
      | Partial<OwaspImpact>
      | undefined;

    // Calculate OWASP risk rating — this determines severity
    const riskRating = calculateRiskRating(owaspLikelihood, owaspImpact);
    const severity = (
      riskRating.riskSeverity === "Note"
        ? "Low"
        : riskRating.riskSeverity
    ) as GeneratedThreat["severity"];

    return {
      title: String(raw.title || "Untitled Threat"),
      strideCategory,
      severity,
      threatSource: String(raw.threatSource || "Unknown actor"),
      prerequisites: String(raw.prerequisites || "None specified"),
      threatAction: String(raw.threatAction || "Unknown action"),
      threatImpact: String(raw.threatImpact || "Unknown impact"),
      impactedAssets: Array.isArray(raw.impactedAssets)
        ? raw.impactedAssets.map(String)
        : ["Application"],
      trustBoundary: String(raw.trustBoundary || "Unknown boundary"),
      assumptions: Array.isArray(raw.assumptions)
        ? raw.assumptions.map(String)
        : [],
      mitigations: Array.isArray(raw.mitigations)
        ? raw.mitigations.map((m: Record<string, unknown>) => ({
            description: String(m.description || "No description"),
            codeFile: m.codeFile ? String(m.codeFile) : undefined,
            codeLine: typeof m.codeLine === "number" ? m.codeLine : undefined,
            codeOriginal: m.codeOriginal
              ? String(m.codeOriginal)
              : undefined,
            codeFixed: m.codeFixed ? String(m.codeFixed) : undefined,
          }))
        : [],
      relatedCve: raw.relatedCve ? String(raw.relatedCve) : undefined,
      owaspLikelihood: riskRating.likelihood,
      owaspImpact: riskRating.impact,
    };
  } catch {
    return null;
  }
}

// ── Document-based threat generation (no repo) ──

export async function generateThreatsFromDocument(
  documentContent: string,
  documentName: string,
  framework: Framework = "STRIDE"
): Promise<GeneratedThreat[]> {
  const config = await getLLMConfig();
  if (!config) {
    console.log("[threat-generator] No LLM API key configured — using demo mode for document analysis");
    return generateDemoThreatsFromDoc(documentName);
  }

  let systemPrompt = SYSTEM_PROMPT.replace(
    "If source code files and security findings are provided, reference specific files, line numbers, and include code-level original/fixed snippets in mitigations.",
    "Since this is a design document (not source code), provide prose-based mitigations without code snippets."
  );

  if (framework === "OWASP Top 10") {
    systemPrompt += OWASP_SYSTEM_ADDENDUM;
  }
  systemPrompt += "\n" + OUTPUT_SCHEMA;

  const userPrompt = `## Design Document: ${documentName}

## Framework: ${framework}

## Document Content
${documentContent.substring(0, 15000)}

## Instructions
Generate a comprehensive threat model based on this design document. Since no source code is available, provide architectural-level threats with prose-based mitigation suggestions. Do NOT include codeFile, codeLine, codeOriginal, or codeFixed in mitigations. Output ONLY the JSON array.`;

  const text = await callLLM(systemPrompt, userPrompt, config, 16384);

  return parseThreatsResponse(text);
}
