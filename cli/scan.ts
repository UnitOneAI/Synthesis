#!/usr/bin/env npx ts-node
/**
 * Synthesis Threat Model Scanner CLI
 *
 * A standalone CLI that can be invoked by UnitoneController to perform
 * threat modeling on a repository.
 *
 * Usage:
 *   npx ts-node cli/scan.ts <repo-url-or-path> [--json]
 *
 * Output:
 *   JSON array of threats in UnitoneController Issue format
 */

import { analyzeRepo, type RepoAnalysis } from "../lib/threat-engine/repo-analyzer";
import { generateThreats, type GeneratedThreat, type Framework } from "../lib/threat-engine/threat-generator";
import { v4 as uuidv4 } from "uuid";

// ── Issue format compatible with UnitoneController ──

interface Issue {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  location: {
    file_path: string;
    line_start?: number;
    line_end?: number;
  };
  metadata: Record<string, unknown>;
}

// ── Severity mapping ──

function mapSeverity(severity: GeneratedThreat["severity"]): Issue["severity"] {
  const mapping: Record<GeneratedThreat["severity"], Issue["severity"]> = {
    Critical: "critical",
    High: "high",
    Medium: "medium",
    Low: "low",
  };
  return mapping[severity] || "medium";
}

// ── Convert GeneratedThreat to Issue ──

function threatToIssue(threat: GeneratedThreat, repoUrl: string): Issue {
  // Find the primary file from mitigations or impacted assets
  const primaryFile = threat.mitigations[0]?.codeFile
    || (threat.impactedAssets[0]?.includes("/") ? threat.impactedAssets[0] : "")
    || "";

  const primaryLine = threat.mitigations[0]?.codeLine;

  return {
    id: uuidv4(),
    title: `[${threat.strideCategory}] ${threat.title}`,
    description: buildDescription(threat),
    severity: mapSeverity(threat.severity),
    category: "threat-model",
    location: {
      file_path: primaryFile,
      line_start: primaryLine,
      line_end: primaryLine,
    },
    metadata: {
      stride_category: threat.strideCategory,
      threat_source: threat.threatSource,
      prerequisites: threat.prerequisites,
      threat_action: threat.threatAction,
      threat_impact: threat.threatImpact,
      impacted_assets: threat.impactedAssets,
      trust_boundary: threat.trustBoundary,
      assumptions: threat.assumptions,
      mitigations: threat.mitigations,
      related_cve: threat.relatedCve,
      owasp_likelihood: threat.owaspLikelihood,
      owasp_impact: threat.owaspImpact,
      source_repo: repoUrl,
      scanner: "synthesis",
    },
  };
}

function buildDescription(threat: GeneratedThreat): string {
  const parts = [
    `**Threat Statement**: A ${threat.threatSource} with ${threat.prerequisites} can ${threat.threatAction}, which leads to ${threat.threatImpact}.`,
    `\n**Trust Boundary**: ${threat.trustBoundary}`,
    `\n**Impacted Assets**: ${threat.impactedAssets.join(", ")}`,
  ];

  if (threat.assumptions.length > 0) {
    parts.push(`\n**Assumptions**: ${threat.assumptions.join("; ")}`);
  }

  if (threat.mitigations.length > 0) {
    parts.push(`\n**Mitigations**:`);
    for (const m of threat.mitigations) {
      parts.push(`\n- ${m.description}`);
      if (m.codeFile && m.codeLine) {
        parts.push(` (${m.codeFile}:${m.codeLine})`);
      }
    }
  }

  return parts.join("");
}

// ── Scanner Output ──

interface ScannerOutput {
  tool_id: string;
  tool_version: string;
  issues: Issue[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  output_data: {
    analysis: {
      languages: string[];
      frameworks: string[];
      components: number;
      data_flows: number;
      security_findings: number;
    };
  };
}

// ── Main ──

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.error(`
Synthesis Threat Model Scanner

Usage:
  npx ts-node cli/scan.ts <repo-url-or-path> [options]

Options:
  --framework <STRIDE|OWASP Top 10>  Threat framework (default: STRIDE)
  --json                              Output as JSON (default)
  --help, -h                          Show this help

Examples:
  npx ts-node cli/scan.ts https://github.com/owner/repo
  npx ts-node cli/scan.ts /path/to/local/repo --framework "OWASP Top 10"
`);
    process.exit(args.includes("--help") || args.includes("-h") ? 0 : 1);
  }

  const repoUrl = args[0];
  const frameworkIndex = args.indexOf("--framework");
  const framework: Framework = (frameworkIndex !== -1 && args[frameworkIndex + 1])
    ? args[frameworkIndex + 1] as Framework
    : "STRIDE";

  const sessionId = uuidv4();

  try {
    // Step 1: Analyze repository
    console.error(`[synthesis] Analyzing repository: ${repoUrl}`);
    const analysis: RepoAnalysis = await analyzeRepo(repoUrl, sessionId);
    console.error(`[synthesis] Found ${analysis.components.length} components, ${analysis.securityFindings.length} security findings`);

    // Step 2: Generate threats
    console.error(`[synthesis] Generating ${framework} threat model...`);
    const threats = await generateThreats(analysis, framework);
    console.error(`[synthesis] Generated ${threats.length} threats`);

    // Step 3: Convert to Issue format
    const issues = threats.map((t) => threatToIssue(t, repoUrl));

    // Step 4: Build summary
    const summary = {
      total: issues.length,
      critical: issues.filter((i) => i.severity === "critical").length,
      high: issues.filter((i) => i.severity === "high").length,
      medium: issues.filter((i) => i.severity === "medium").length,
      low: issues.filter((i) => i.severity === "low").length,
      info: issues.filter((i) => i.severity === "info").length,
    };

    // Step 5: Build output
    const output: ScannerOutput = {
      tool_id: "synthesis",
      tool_version: "1.0.0",
      issues,
      summary,
      output_data: {
        analysis: {
          languages: analysis.languages,
          frameworks: analysis.frameworks,
          components: analysis.components.length,
          data_flows: analysis.dataFlows.length,
          security_findings: analysis.securityFindings.length,
        },
      },
    };

    // Output JSON to stdout
    console.log(JSON.stringify(output, null, 2));
    process.exit(0);

  } catch (error) {
    console.error(`[synthesis] Error: ${error instanceof Error ? error.message : error}`);
    process.exit(1);
  }
}

main();
