/**
 * @synthesis/core — Shared types and Zod schemas
 *
 * All types used across the Synthesis threat modeling engine.
 * Every configuration boundary is validated with Zod to enforce
 * correctness at runtime (defense-in-depth per OWASP guidelines).
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Enums and literal unions
// ---------------------------------------------------------------------------

export const ThreatFramework = z.enum(["STRIDE", "OWASP", "AWS_THREAT_GRAMMAR"]);
export type ThreatFramework = z.infer<typeof ThreatFramework>;

export const SeverityLevel = z.enum(["critical", "high", "medium", "low", "info"]);
export type SeverityLevel = z.infer<typeof SeverityLevel>;

export const STRIDECategory = z.enum([
  "spoofing",
  "tampering",
  "repudiation",
  "information_disclosure",
  "denial_of_service",
  "elevation_of_privilege",
]);
export type STRIDECategory = z.infer<typeof STRIDECategory>;

export const ComponentType = z.enum([
  "service",
  "datastore",
  "external",
  "gateway",
  "queue",
]);
export type ComponentType = z.infer<typeof ComponentType>;

export const ThreatStatus = z.enum([
  "open",
  "mitigated",
  "accepted",
  "transferred",
]);
export type ThreatStatus = z.infer<typeof ThreatStatus>;

// ---------------------------------------------------------------------------
// Data flow
// ---------------------------------------------------------------------------

export const DataFlowSchema = z.object({
  source: z.string().min(1),
  destination: z.string().min(1),
  protocol: z.string().min(1),
  dataClassification: z.string().min(1),
  crossesTrustBoundary: z.boolean(),
});
export type DataFlow = z.infer<typeof DataFlowSchema>;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const ComponentSchema = z.object({
  name: z.string().min(1).max(256),
  type: ComponentType,
  entryPoints: z.array(z.string()).default([]),
  dataFlows: z.array(DataFlowSchema).default([]),
  trustBoundary: z.string().optional(),
});
export type Component = z.infer<typeof ComponentSchema>;

// ---------------------------------------------------------------------------
// Threat entry
// ---------------------------------------------------------------------------

/**
 * MITRE ATT&CK technique ID pattern: T followed by 4 digits, optional
 * sub-technique (.NNN). We validate format but do not maintain a full
 * enumeration — the LLM is prompted with real IDs only (see prompts.ts).
 */
const MitreAttackIdPattern = /^T\d{4}(\.\d{3})?$/;

export const ThreatEntrySchema = z.object({
  id: z.string().min(1).max(32),
  stride: STRIDECategory,
  description: z.string().min(1).max(4096),
  component: z.string().min(1).max(256),
  attackTechnique: z
    .string()
    .regex(MitreAttackIdPattern, "Must be a valid MITRE ATT&CK ID (e.g. T1078, T1195.001)"),
  likelihood: z.number().int().min(1).max(3),
  impact: z.number().int().min(1).max(3),
  severity: SeverityLevel,
  mitigation: z.string().min(1).max(4096),
  status: ThreatStatus.default("open"),
  /** Explains why severity was adjusted due to project intent context. */
  intentBoost: z.string().max(512).optional(),
  /** Mapped compliance control IDs based on declared compliance frameworks. */
  complianceMapping: z.array(z.string().max(128)).optional(),
});
export type ThreatEntry = z.infer<typeof ThreatEntrySchema>;

// ---------------------------------------------------------------------------
// Threat model (top-level output)
// ---------------------------------------------------------------------------

export const ThreatModelSchema = z.object({
  projectName: z.string().min(1).max(256),
  timestamp: z.string().datetime(),
  components: z.array(ComponentSchema),
  threats: z.array(ThreatEntrySchema),
  dfd: z.string().max(65536),
  summary: z.object({
    critical: z.number().int().min(0),
    high: z.number().int().min(0),
    medium: z.number().int().min(0),
    low: z.number().int().min(0),
    info: z.number().int().min(0),
  }),
});
export type ThreatModel = z.infer<typeof ThreatModelSchema>;

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export const FileChangeSchema = z.object({
  path: z.string().min(1).max(1024),
  diff: z.string().max(1_000_000), // 1 MB cap to prevent DoS
  language: z.string().min(1).max(64),
});
export type FileChange = z.infer<typeof FileChangeSchema>;

export const AnalysisInputSchema = z
  .object({
    files: z.array(FileChangeSchema).optional(),
    repoContent: z.string().max(10_000_000).optional(), // 10 MB cap
    designDoc: z.string().max(1_000_000).optional(),
  })
  .refine(
    (data) => data.files !== undefined || data.repoContent !== undefined || data.designDoc !== undefined,
    { message: "At least one of files, repoContent, or designDoc must be provided" },
  );
export type AnalysisInput = z.infer<typeof AnalysisInputSchema>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export const LLMProvider = z.enum(["anthropic", "gemini"]);
export type LLMProviderName = z.infer<typeof LLMProvider>;

export const SynthesisConfigSchema = z.object({
  provider: LLMProvider,
  apiKey: z
    .string()
    .min(1, "API key must not be empty")
    .refine(
      (key) => !key.includes("sk-ant-") || key.length > 20,
      "API key appears malformed",
    ),
  frameworks: z.array(ThreatFramework).min(1).default(["STRIDE"]),
  severityThreshold: SeverityLevel.default("low"),
  maxFiles: z.number().int().min(1).max(500).default(100),
  maxConcurrentRequests: z.number().int().min(1).max(20).default(5),
});
export type SynthesisConfig = z.infer<typeof SynthesisConfigSchema>;

// ---------------------------------------------------------------------------
// LLM response schemas (used by threat-engine to validate LLM output)
// ---------------------------------------------------------------------------

export const LLMThreatResponseSchema = z.object({
  threats: z.array(ThreatEntrySchema),
});
export type LLMThreatResponse = z.infer<typeof LLMThreatResponseSchema>;

export const LLMComponentResponseSchema = z.object({
  components: z.array(ComponentSchema),
});
export type LLMComponentResponse = z.infer<typeof LLMComponentResponseSchema>;

// ---------------------------------------------------------------------------
// Severity calculation helper
// ---------------------------------------------------------------------------

/**
 * Calculate severity from likelihood x impact using OWASP Risk Rating.
 *
 * Matrix (likelihood rows x impact cols):
 *   L=1, I=1 → info   | L=1, I=2 → low    | L=1, I=3 → medium
 *   L=2, I=1 → low    | L=2, I=2 → medium  | L=2, I=3 → high
 *   L=3, I=1 → medium | L=3, I=2 → high    | L=3, I=3 → critical
 */
export function calculateSeverity(likelihood: number, impact: number): SeverityLevel {
  const score = likelihood * impact;
  if (score >= 9) return "critical";
  if (score >= 6) return "high";
  if (score >= 3) return "medium";
  if (score >= 2) return "low";
  return "info";
}
