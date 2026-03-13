/**
 * @synthesis/core — Intent Schema & Loader
 *
 * Defines the project intent declaration schema for context-aware threat
 * modeling. When a `synthesis.intent.json` file is present in the project
 * root, the engine uses it to calibrate threat severity, map compliance
 * controls, and prioritize critical assets.
 *
 * SECURITY:
 * - All fields are validated with strict Zod schemas.
 * - String lengths are capped to prevent resource exhaustion.
 * - File reading is wrapped in try/catch to fail safely.
 */

import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const IntentDomain = z.enum([
  "financial-services",
  "healthcare",
  "e-commerce",
  "saas",
  "iot",
  "government",
  "social-media",
  "gaming",
  "infrastructure",
  "other",
]);
export type IntentDomain = z.infer<typeof IntentDomain>;

export const DataSensitivityType = z.enum([
  "PCI",
  "PII",
  "PHI",
  "FERPA",
  "classified",
  "internal",
  "public",
]);
export type DataSensitivityType = z.infer<typeof DataSensitivityType>;

export const CloudProvider = z.enum([
  "aws",
  "azure",
  "gcp",
  "on-prem",
  "hybrid",
]);
export type CloudProvider = z.infer<typeof CloudProvider>;

export const EnvironmentType = z.enum([
  "kubernetes",
  "serverless",
  "vm",
  "container",
  "bare-metal",
]);
export type EnvironmentType = z.infer<typeof EnvironmentType>;

// ---------------------------------------------------------------------------
// Sub-schemas
// ---------------------------------------------------------------------------

export const DataSensitivityEntrySchema = z.object({
  type: DataSensitivityType,
  elements: z.array(z.string().min(1).max(256)).min(1),
  retention: z.string().min(1).max(512),
});
export type DataSensitivityEntry = z.infer<typeof DataSensitivityEntrySchema>;

export const CriticalAssetSchema = z.object({
  name: z.string().min(1).max(256),
  why: z.string().min(1).max(1024),
});
export type CriticalAsset = z.infer<typeof CriticalAssetSchema>;

export const InfrastructureSchema = z.object({
  cloud: CloudProvider,
  regions: z.array(z.string().min(1).max(64)).default([]),
  environment: EnvironmentType,
  public_facing: z.boolean(),
});
export type Infrastructure = z.infer<typeof InfrastructureSchema>;

// ---------------------------------------------------------------------------
// Intent schema
// ---------------------------------------------------------------------------

export const IntentSchema = z.object({
  project: z.object({
    name: z.string().min(1).max(256),
    description: z.string().min(1).max(2048),
  }),
  intent: z.object({
    domain: IntentDomain,
    capabilities: z.array(z.string().min(1).max(512)).min(1),
    data_sensitivity: z.array(DataSensitivityEntrySchema).default([]),
    threat_actors: z.array(z.string().min(1).max(256)).default([]),
    compliance: z.array(z.string().min(1).max(128)).default([]),
    critical_assets: z.array(CriticalAssetSchema).default([]),
    infrastructure: InfrastructureSchema.optional(),
  }),
});
export type Intent = z.infer<typeof IntentSchema>;

// ---------------------------------------------------------------------------
// Loader functions
// ---------------------------------------------------------------------------

/**
 * Parse and validate a JSON string as an Intent declaration.
 *
 * @param jsonContent - Raw JSON string from synthesis.intent.json
 * @returns Validated Intent object
 * @throws {z.ZodError} if the content does not conform to the schema
 * @throws {SyntaxError} if the content is not valid JSON
 */
export function loadIntent(jsonContent: string): Intent {
  const raw: unknown = JSON.parse(jsonContent);
  return IntentSchema.parse(raw);
}

/**
 * Load an Intent declaration from a file on disk.
 * Returns null if the file does not exist or cannot be parsed.
 *
 * @param filePath - Absolute or relative path to synthesis.intent.json
 * @returns Validated Intent object, or null if the file is not found
 */
export function loadIntentFromFile(filePath: string): Intent | null {
  try {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      return null;
    }
    const content = fs.readFileSync(resolved, "utf-8");
    return loadIntent(content);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Compliance control mappings (static, per framework × STRIDE category)
// ---------------------------------------------------------------------------

/**
 * Static mapping of compliance framework controls to STRIDE categories.
 * These are real control IDs from PCI DSS v4.0, SOC 2 (TSC), and HIPAA.
 */
export const COMPLIANCE_STRIDE_MAP: Record<string, Record<string, string[]>> = {
  "PCI DSS v4.0": {
    spoofing: ["Req 8.2", "Req 8.3", "Req 8.4"],
    tampering: ["Req 6.2", "Req 6.3", "Req 6.4"],
    repudiation: ["Req 10.2", "Req 10.3", "Req 10.4"],
    information_disclosure: ["Req 3.3", "Req 3.4", "Req 3.5", "Req 4.2"],
    denial_of_service: ["Req 6.4", "Req 11.4"],
    elevation_of_privilege: ["Req 7.2", "Req 7.3", "Req 8.6"],
  },
  "PCI DSS": {
    spoofing: ["Req 8.2", "Req 8.3", "Req 8.4"],
    tampering: ["Req 6.2", "Req 6.3", "Req 6.4"],
    repudiation: ["Req 10.2", "Req 10.3", "Req 10.4"],
    information_disclosure: ["Req 3.3", "Req 3.4", "Req 3.5", "Req 4.2"],
    denial_of_service: ["Req 6.4", "Req 11.4"],
    elevation_of_privilege: ["Req 7.2", "Req 7.3", "Req 8.6"],
  },
  "SOC 2 Type II": {
    spoofing: ["CC6.1", "CC6.2"],
    tampering: ["CC6.1", "CC7.2", "CC8.1"],
    repudiation: ["CC7.2", "CC7.3"],
    information_disclosure: ["CC6.1", "CC6.5", "CC6.7"],
    denial_of_service: ["CC7.2", "CC7.5", "A1.2"],
    elevation_of_privilege: ["CC6.1", "CC6.3"],
  },
  "SOC 2": {
    spoofing: ["CC6.1", "CC6.2"],
    tampering: ["CC6.1", "CC7.2", "CC8.1"],
    repudiation: ["CC7.2", "CC7.3"],
    information_disclosure: ["CC6.1", "CC6.5", "CC6.7"],
    denial_of_service: ["CC7.2", "CC7.5", "A1.2"],
    elevation_of_privilege: ["CC6.1", "CC6.3"],
  },
  "HIPAA": {
    spoofing: ["§164.312(d)", "§164.312(a)(1)"],
    tampering: ["§164.312(c)(1)", "§164.312(e)(2)"],
    repudiation: ["§164.312(b)", "§164.308(a)(1)(ii)(D)"],
    information_disclosure: ["§164.312(a)(1)", "§164.312(e)(1)", "§164.502"],
    denial_of_service: ["§164.308(a)(7)", "§164.310(a)(2)(i)"],
    elevation_of_privilege: ["§164.312(a)(1)", "§164.308(a)(4)"],
  },
  "GDPR": {
    spoofing: ["Art. 32(1)(b)"],
    tampering: ["Art. 5(1)(f)", "Art. 32(1)(b)"],
    repudiation: ["Art. 5(2)", "Art. 30"],
    information_disclosure: ["Art. 5(1)(f)", "Art. 32(1)(a)", "Art. 33", "Art. 34"],
    denial_of_service: ["Art. 32(1)(b)", "Art. 32(1)(c)"],
    elevation_of_privilege: ["Art. 5(1)(f)", "Art. 25", "Art. 32(1)(b)"],
  },
};

/**
 * Resolve compliance control IDs for a given STRIDE category based on
 * the frameworks declared in the project intent.
 *
 * @param strideCategory - The STRIDE category of the threat
 * @param complianceFrameworks - Frameworks declared in intent.compliance
 * @returns Array of formatted compliance control strings (e.g. "PCI DSS v4.0 Req 8.2")
 */
export function resolveComplianceControls(
  strideCategory: string,
  complianceFrameworks: string[],
): string[] {
  const controls: string[] = [];

  for (const framework of complianceFrameworks) {
    const mapping = COMPLIANCE_STRIDE_MAP[framework];
    if (!mapping) continue;

    const categoryControls = mapping[strideCategory];
    if (!categoryControls) continue;

    for (const control of categoryControls) {
      controls.push(`${framework} ${control}`);
    }
  }

  return controls;
}
