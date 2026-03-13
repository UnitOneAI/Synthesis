/**
 * SARIF v2.1.0 output builder for Synthesis threat models.
 *
 * Produces a Standards-compliant SARIF (Static Analysis Results Interchange
 * Format) document from a ThreatModel. This enables integration with GitHub
 * Code Scanning, Azure DevOps, and other SARIF consumers.
 *
 * Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 *
 * Security controls applied:
 * - All threat descriptions are treated as data, never evaluated (ASVS V5.1.1)
 * - Output conforms strictly to SARIF v2.1.0 schema (no arbitrary fields)
 * - File paths are normalized to prevent path traversal in location references
 */

import type { ThreatModel, ThreatEntry, SeverityLevel, STRIDECategory } from "@synthesis/core";

// ---------------------------------------------------------------------------
// SARIF type definitions (subset of v2.1.0 relevant to our output)
// ---------------------------------------------------------------------------

interface SARIFLog {
  $schema: string;
  version: "2.1.0";
  runs: SARIFRun[];
}

interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SARIFRule[];
    };
  };
  results: SARIFResult[];
}

interface SARIFRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  defaultConfiguration: {
    level: "error" | "warning" | "note" | "none";
  };
  properties: {
    tags: string[];
  };
}

interface SARIFResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: SARIFLocation[];
  properties: {
    "threat-id": string;
    component: string;
    "attack-technique": string;
    likelihood: number;
    impact: number;
  };
}

interface SARIFLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId: "%SRCROOT%";
    };
    region?: {
      startLine: number;
    };
  };
}

// ---------------------------------------------------------------------------
// STRIDE rule definitions
// ---------------------------------------------------------------------------

const STRIDE_RULES: Record<STRIDECategory, { name: string; description: string }> = {
  spoofing: {
    name: "Spoofing",
    description:
      "An attacker may impersonate another user, component, or system to gain unauthorized access.",
  },
  tampering: {
    name: "Tampering",
    description:
      "An attacker may modify data in transit or at rest to alter system behavior or corrupt integrity.",
  },
  repudiation: {
    name: "Repudiation",
    description:
      "A user may deny performing an action when the system lacks adequate audit trails.",
  },
  information_disclosure: {
    name: "Information Disclosure",
    description:
      "Sensitive data may be exposed to unauthorized actors through leaks, errors, or side channels.",
  },
  denial_of_service: {
    name: "Denial of Service",
    description:
      "An attacker may exhaust system resources to degrade or prevent legitimate access.",
  },
  elevation_of_privilege: {
    name: "Elevation of Privilege",
    description:
      "An attacker may gain higher access rights than intended through authorization flaws.",
  },
};

// ---------------------------------------------------------------------------
// Severity to SARIF level mapping
// ---------------------------------------------------------------------------

function severityToSARIFLevel(
  severity: SeverityLevel
): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    case "info":
      return "none";
    default:
      return "warning";
  }
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

/**
 * Normalizes a file path for use in SARIF location URIs.
 *
 * Security: Strips leading slashes and parent-directory traversals to prevent
 * path confusion in SARIF consumers (CWE-22 defense-in-depth).
 */
function normalizePath(filePath: string): string {
  return filePath
    .replace(/\\/g, "/") // Normalize Windows separators
    .replace(/^\/+/, "") // Strip leading slashes (SARIF uses relative URIs)
    .replace(/\.\.\/*/g, "") // Remove parent-directory traversals
    .replace(/\/+/g, "/"); // Collapse duplicate slashes
}

/**
 * Attempts to extract a file path from a threat's component or description.
 * Returns a normalized path or a fallback generic location.
 */
function extractLocationFromThreat(threat: ThreatEntry): string {
  // Look for file path patterns in the component name
  const filePattern = /[\w\-./]+\.\w{1,10}/;
  const match =
    threat.component.match(filePattern) ||
    threat.description.match(filePattern);

  if (match) {
    return normalizePath(match[0]);
  }

  // Fallback: use the component name as a synthetic path
  const safeName = threat.component
    .replace(/[^a-zA-Z0-9_\-./]/g, "_")
    .toLowerCase();
  return `components/${safeName}`;
}

// ---------------------------------------------------------------------------
// SARIF builder
// ---------------------------------------------------------------------------

/**
 * Builds a SARIF v2.1.0 compliant log from a ThreatModel.
 *
 * Each STRIDE category becomes a SARIF rule. Each threat becomes a result
 * referencing its STRIDE category rule. This maps cleanly onto GitHub Code
 * Scanning's rule/result model.
 */
export function buildSARIF(model: ThreatModel): SARIFLog {
  // Build rule definitions for each STRIDE category present in the threats
  const usedCategories = new Set<STRIDECategory>();
  for (const threat of model.threats) {
    usedCategories.add(threat.stride);
  }

  const rules: SARIFRule[] = [];
  const ruleIndexMap = new Map<STRIDECategory, number>();

  for (const category of Object.keys(STRIDE_RULES) as STRIDECategory[]) {
    if (usedCategories.has(category)) {
      ruleIndexMap.set(category, rules.length);
      const ruleInfo = STRIDE_RULES[category];
      rules.push({
        id: `STRIDE/${category}`,
        name: ruleInfo.name,
        shortDescription: { text: `STRIDE: ${ruleInfo.name}` },
        fullDescription: { text: ruleInfo.description },
        helpUri: "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
        defaultConfiguration: {
          level: "warning",
        },
        properties: {
          tags: ["security", "threat-model", "stride", category],
        },
      });
    }
  }

  // Build results from threats
  const results: SARIFResult[] = model.threats.map((threat) => {
    const ruleIndex = ruleIndexMap.get(threat.stride) ?? 0;
    const location = extractLocationFromThreat(threat);

    return {
      ruleId: `STRIDE/${threat.stride}`,
      ruleIndex,
      level: severityToSARIFLevel(threat.severity),
      message: {
        text: `${threat.description}\n\nAttack technique: ${threat.attackTechnique}\nMitigation: ${threat.mitigation}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: location,
              uriBaseId: "%SRCROOT%" as const,
            },
            region: {
              startLine: 1,
            },
          },
        },
      ],
      properties: {
        "threat-id": threat.id,
        component: threat.component,
        "attack-technique": threat.attackTechnique,
        likelihood: threat.likelihood,
        impact: threat.impact,
      },
    };
  });

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Synthesis Threat Model",
            version: "1.0.0",
            informationUri: "https://github.com/UnitOneAI/synthesis-action",
            rules,
          },
        },
        results,
      },
    ],
  };
}
