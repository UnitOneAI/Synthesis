/**
 * @synthesis/core — Core STRIDE threat analysis engine
 *
 * Orchestrates the threat modeling pipeline:
 * 1. Parse input (diffs, design docs, repo content)
 * 2. Extract and classify components
 * 3. Identify data flows and trust boundaries
 * 4. Send structured prompts to LLM for STRIDE analysis
 * 5. Validate LLM output with Zod schemas
 * 6. Calculate risk scores and generate the threat model
 *
 * SECURITY:
 * - All LLM output is validated against strict Zod schemas.
 * - Malformed LLM responses are rejected, not silently coerced.
 * - Risk scores are calculated server-side, not trusted from LLM.
 */

import { z } from "zod";
import type { LLMProviderInterface } from "./llm-provider.js";
import {
  type AnalysisInput,
  type Component,
  type DataFlow,
  type SynthesisConfig,
  type ThreatEntry,
  type ThreatModel,
  AnalysisInputSchema,
  SynthesisConfigSchema,
  LLMThreatResponseSchema,
  ThreatModelSchema,
  calculateSeverity,
} from "./types.js";
import {
  extractComponents,
  classifyTrustBoundaries,
  identifyEntryPoints,
  identifyDataFlows,
  classifyDataFlowsWithIntent,
} from "./analyzer.js";
import { generateDFD } from "./dfd-generator.js";
import {
  SYSTEM_PROMPT,
  buildThreatGenerationPrompt,
  buildComponentAnalysisPrompt,
  buildIntentContext,
  THREAT_FEW_SHOT_EXAMPLE,
} from "./prompts.js";
import type { Intent } from "./intent.js";
import { resolveComplianceControls } from "./intent.js";

// ---------------------------------------------------------------------------
// JSON extraction helper
// ---------------------------------------------------------------------------

/**
 * Extract a JSON object from an LLM response string.
 * LLMs may wrap JSON in markdown code fences — strip them.
 */
function extractJSON(text: string): string {
  // Strip markdown code fences (```json ... ``` or ``` ... ```)
  const fencePattern = /```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/;
  const match = fencePattern.exec(text);
  if (match?.[1]) {
    return match[1].trim();
  }

  // Try to find a raw JSON object
  const jsonStart = text.indexOf("{");
  const jsonEnd = text.lastIndexOf("}");
  if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd > jsonStart) {
    return text.slice(jsonStart, jsonEnd + 1);
  }

  return text.trim();
}

// ---------------------------------------------------------------------------
// Threat model generation
// ---------------------------------------------------------------------------

/**
 * Generate a complete threat model from the provided input.
 *
 * @param input - Analysis input (files, repo content, or design doc)
 * @param config - Validated synthesis configuration
 * @param provider - LLM provider instance
 * @param intent - Optional project intent declaration for context-aware analysis
 * @returns A fully validated ThreatModel
 */
export async function generateThreatModel(
  input: AnalysisInput,
  config: SynthesisConfig,
  provider: LLMProviderInterface,
  intent?: Intent | null,
): Promise<ThreatModel> {
  // Validate inputs at the boundary
  const validatedInput = AnalysisInputSchema.parse(input);
  const validatedConfig = SynthesisConfigSchema.parse(config);

  // Step 1: Extract components from available inputs
  let components: Component[] = [];
  let allEntryPoints: string[] = [];

  if (validatedInput.files && validatedInput.files.length > 0) {
    const limitedFiles = validatedInput.files.slice(0, validatedConfig.maxFiles);
    components = extractComponents(limitedFiles);
    allEntryPoints = identifyEntryPoints(limitedFiles);
  }

  // If we have design docs or repo content but few/no components from code,
  // use the LLM to extract components
  if (
    components.length === 0 &&
    (validatedInput.designDoc || validatedInput.repoContent)
  ) {
    const content = validatedInput.designDoc ?? validatedInput.repoContent ?? "";
    components = await extractComponentsViaLLM(content, provider);
  }

  if (components.length === 0) {
    throw new Error(
      "No components could be extracted from the input. " +
        "Provide code files with recognizable patterns, a design document, or repository content.",
    );
  }

  // Step 2: Classify trust boundaries
  components = classifyTrustBoundaries(components);

  // Merge LLM-discovered entry points with code-detected ones
  for (const component of components) {
    for (const ep of allEntryPoints) {
      if (!component.entryPoints.includes(ep)) {
        component.entryPoints.push(ep);
      }
    }
  }

  // Step 3: Identify data flows
  let dataFlows = identifyDataFlows(components);

  // Step 3b: Classify data flows with intent context (if available)
  if (intent) {
    dataFlows = classifyDataFlowsWithIntent(dataFlows, components, intent);
  }

  // Step 4: Generate threats via LLM (with optional intent context)
  const intentContext = intent ? buildIntentContext(intent) : undefined;
  const threats = await generateThreatsViaLLM(
    components,
    dataFlows,
    provider,
    intentContext,
  );

  // Step 5: Recalculate severity (never trust LLM-provided severity)
  let calibratedThreats = threats.map((threat) => ({
    ...threat,
    severity: calculateSeverity(threat.likelihood, threat.impact),
  }));

  // Step 5b: Apply intent-driven calibration (boost severity for critical assets / sensitive data)
  if (intent) {
    calibratedThreats = applyIntentCalibration(calibratedThreats, intent);
  }

  // Step 6: Filter by severity threshold
  const severityOrder: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  const thresholdValue = severityOrder[validatedConfig.severityThreshold] ?? 1;
  const filteredThreats = calibratedThreats.filter(
    (t) => (severityOrder[t.severity] ?? 0) >= thresholdValue,
  );

  // Step 7: Generate DFD
  const dfd = generateDFD(components, dataFlows);

  // Step 8: Build summary counts
  const summary = {
    critical: filteredThreats.filter((t) => t.severity === "critical").length,
    high: filteredThreats.filter((t) => t.severity === "high").length,
    medium: filteredThreats.filter((t) => t.severity === "medium").length,
    low: filteredThreats.filter((t) => t.severity === "low").length,
    info: filteredThreats.filter((t) => t.severity === "info").length,
  };

  // Step 9: Assemble and validate the complete threat model
  const threatModel: ThreatModel = {
    projectName: deriveProjectName(validatedInput),
    timestamp: new Date().toISOString(),
    components,
    threats: filteredThreats,
    dfd,
    summary,
  };

  // Final validation — reject if the model doesn't conform
  return ThreatModelSchema.parse(threatModel);
}

// ---------------------------------------------------------------------------
// LLM-assisted component extraction
// ---------------------------------------------------------------------------

async function extractComponentsViaLLM(
  content: string,
  provider: LLMProviderInterface,
): Promise<Component[]> {
  // Truncate content to avoid exceeding token limits
  const truncated = content.slice(0, 100_000);
  const prompt = buildComponentAnalysisPrompt(truncated);

  const response = await provider.analyze(prompt, SYSTEM_PROMPT);
  const jsonStr = extractJSON(response);

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error(
      "LLM returned invalid JSON for component analysis. " +
        "The response could not be parsed.",
    );
  }

  // Validate with a lenient schema — individual components may fail
  const schema = z.object({
    components: z.array(z.unknown()),
  });

  const envelope = schema.parse(parsed);
  const validComponents: Component[] = [];

  for (const raw of envelope.components) {
    const result = z
      .object({
        name: z.string().min(1).max(256),
        type: z.enum(["service", "datastore", "external", "gateway", "queue"]),
        entryPoints: z.array(z.string()).default([]),
        dataFlows: z.array(z.unknown()).default([]),
        trustBoundary: z.string().optional(),
      })
      .safeParse(raw);

    if (result.success) {
      validComponents.push({
        ...result.data,
        dataFlows: [],
      });
    }
  }

  return validComponents;
}

// ---------------------------------------------------------------------------
// LLM-assisted threat generation
// ---------------------------------------------------------------------------

async function generateThreatsViaLLM(
  components: Component[],
  dataFlows: DataFlow[],
  provider: LLMProviderInterface,
  intentContext?: string,
): Promise<ThreatEntry[]> {
  const componentSummary = JSON.stringify(
    components.map((c) => ({
      name: c.name,
      type: c.type,
      entryPoints: c.entryPoints,
      trustBoundary: c.trustBoundary,
    })),
    null,
    2,
  );

  const flowSummary = JSON.stringify(dataFlows, null, 2);

  const boundaryMap = new Map<string, string[]>();
  for (const c of components) {
    const boundary = c.trustBoundary ?? "unclassified";
    const existing = boundaryMap.get(boundary) ?? [];
    existing.push(c.name);
    boundaryMap.set(boundary, existing);
  }
  const boundarySummary = JSON.stringify(Object.fromEntries(boundaryMap), null, 2);

  const prompt =
    THREAT_FEW_SHOT_EXAMPLE +
    "\n\n" +
    buildThreatGenerationPrompt(componentSummary, flowSummary, boundarySummary, intentContext);

  const response = await provider.analyze(prompt, SYSTEM_PROMPT);
  const jsonStr = extractJSON(response);

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error(
      "LLM returned invalid JSON for threat generation. " +
        "The response could not be parsed.",
    );
  }

  // Validate with the strict schema
  const result = LLMThreatResponseSchema.safeParse(parsed);

  if (result.success) {
    return result.data.threats;
  }

  // If strict validation fails, try to salvage individual threats
  const looseSchema = z.object({
    threats: z.array(z.unknown()),
  });
  const loose = looseSchema.safeParse(parsed);

  if (!loose.success) {
    throw new Error(
      "LLM response does not contain a 'threats' array. " +
        `Validation error: ${result.error.message}`,
    );
  }

  const validThreats: ThreatEntry[] = [];
  for (const raw of loose.data.threats) {
    const threatResult = z
      .object({
        id: z.string().min(1).max(32),
        stride: z.enum([
          "spoofing",
          "tampering",
          "repudiation",
          "information_disclosure",
          "denial_of_service",
          "elevation_of_privilege",
        ]),
        description: z.string().min(1).max(4096),
        component: z.string().min(1).max(256),
        attackTechnique: z.string().regex(/^T\d{4}(\.\d{3})?$/),
        likelihood: z.number().int().min(1).max(3),
        impact: z.number().int().min(1).max(3),
        severity: z.enum(["critical", "high", "medium", "low", "info"]),
        mitigation: z.string().min(1).max(4096),
        status: z.enum(["open", "mitigated", "accepted", "transferred"]).default("open"),
      })
      .safeParse(raw);

    if (threatResult.success) {
      validThreats.push(threatResult.data);
    }
  }

  if (validThreats.length === 0) {
    throw new Error(
      "LLM response contained no valid threat entries after schema validation. " +
        `Original validation error: ${result.error.message}`,
    );
  }

  return validThreats;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Intent-driven calibration (B2, B3, B5)
// ---------------------------------------------------------------------------

/**
 * Apply intent-driven severity calibration to threats.
 *
 * - If a threat's component matches a declared critical_asset, boost
 *   likelihood by 1 (capped at 3) and recalculate severity.
 * - If the intent declares PCI or PHI data sensitivity and the threat
 *   is information_disclosure, boost impact by 1 (capped at 3).
 * - Map compliance controls based on STRIDE category and declared frameworks.
 *
 * @param threats - Calibrated threat entries (severity already recalculated)
 * @param intent - Validated project intent declaration
 * @returns Threats with intent-based adjustments applied
 */
function applyIntentCalibration(
  threats: ThreatEntry[],
  intent: Intent,
): ThreatEntry[] {
  const criticalAssetNames = intent.intent.critical_assets.map((a) =>
    a.name.toLowerCase(),
  );

  const hasSensitiveData = intent.intent.data_sensitivity.some(
    (ds) => ds.type === "PCI" || ds.type === "PHI",
  );

  const complianceFrameworks = intent.intent.compliance;

  return threats.map((threat) => {
    let { likelihood, impact } = threat;
    let intentBoost: string | undefined;

    // B2: Critical asset boost — increase likelihood for threats targeting critical assets
    const componentLower = threat.component.toLowerCase();
    const matchedAsset = intent.intent.critical_assets.find((a) =>
      componentLower.includes(a.name.toLowerCase()),
    );
    if (matchedAsset) {
      const originalLikelihood = likelihood;
      likelihood = Math.min(likelihood + 1, 3) as 1 | 2 | 3;
      if (likelihood !== originalLikelihood) {
        intentBoost = `Likelihood boosted (${originalLikelihood} -> ${likelihood}): component matches critical asset "${matchedAsset.name}" — ${matchedAsset.why}`;
      }
    }

    // B3: Sensitive data boost — increase impact for information disclosure when PCI/PHI present
    if (hasSensitiveData && threat.stride === "information_disclosure") {
      const originalImpact = impact;
      impact = Math.min(impact + 1, 3) as 1 | 2 | 3;
      if (impact !== originalImpact) {
        const boostMsg = `Impact boosted (${originalImpact} -> ${impact}): information disclosure threat in system handling PCI/PHI data`;
        intentBoost = intentBoost ? `${intentBoost}; ${boostMsg}` : boostMsg;
      }
    }

    // Recalculate severity after boosts
    const severity = calculateSeverity(likelihood, impact);

    // B5: Compliance mapping
    let complianceMapping: string[] | undefined;
    if (complianceFrameworks.length > 0) {
      const controls = resolveComplianceControls(
        threat.stride,
        complianceFrameworks,
      );
      if (controls.length > 0) {
        complianceMapping = controls;
      }
    }

    return {
      ...threat,
      likelihood,
      impact,
      severity,
      ...(intentBoost ? { intentBoost } : {}),
      ...(complianceMapping ? { complianceMapping } : {}),
    };
  });
}

function deriveProjectName(input: AnalysisInput): string {
  if (input.files && input.files.length > 0 && input.files[0]) {
    // Use the top-level directory name
    const parts = input.files[0].path.split("/");
    if (parts.length > 1 && parts[0]) {
      return parts[0];
    }
  }
  return "Synthesis Threat Model";
}
