/**
 * @synthesis/core — Public API
 *
 * Barrel export for the Synthesis threat modeling engine core package.
 * All public types, schemas, and functions are re-exported from here.
 */

// ---------------------------------------------------------------------------
// Types and Zod schemas
// ---------------------------------------------------------------------------

export {
  // Enum schemas (usable as both types and runtime validators)
  ThreatFramework,
  SeverityLevel,
  STRIDECategory,
  ComponentType,
  ThreatStatus,
  LLMProvider,

  // Object schemas
  DataFlowSchema,
  ComponentSchema,
  ThreatEntrySchema,
  ThreatModelSchema,
  FileChangeSchema,
  AnalysisInputSchema,
  SynthesisConfigSchema,
  LLMThreatResponseSchema,
  LLMComponentResponseSchema,

  // Inferred TypeScript types
  type DataFlow,
  type Component,
  type ThreatEntry,
  type ThreatModel,
  type FileChange,
  type AnalysisInput,
  type SynthesisConfig,
  type LLMProviderName,
  type LLMThreatResponse,
  type LLMComponentResponse,

  // Utility functions
  calculateSeverity,
} from "./types.js";

// ---------------------------------------------------------------------------
// LLM provider
// ---------------------------------------------------------------------------

export {
  type LLMProviderInterface,
  AnthropicProvider,
  GeminiProvider,
  createProvider,
  sanitizeInput,
} from "./llm-provider.js";

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export {
  parseDiff,
  extractComponents,
  classifyTrustBoundaries,
  identifyEntryPoints,
  identifyDataFlows,
  classifyDataFlowsWithIntent,
  sanitizeFilePath,
} from "./analyzer.js";

// ---------------------------------------------------------------------------
// Threat engine
// ---------------------------------------------------------------------------

export { generateThreatModel } from "./threat-engine.js";

// ---------------------------------------------------------------------------
// DFD generator
// ---------------------------------------------------------------------------

export { generateDFD } from "./dfd-generator.js";

// ---------------------------------------------------------------------------
// Context expander
// ---------------------------------------------------------------------------

export {
  expandContext,
  extractImports,
  type ContextExpansion,
  type RelatedFile,
  type ExpandContextOptions,
} from "./context-expander.js";

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

export { toMarkdown, toSARIF, toJSON, toSummary, toDeltaMarkdown } from "./formatter.js";

// ---------------------------------------------------------------------------
// Baseline & delta reporting
// ---------------------------------------------------------------------------

export {
  generateThreatFingerprint,
  compareWithBaseline,
  createBaseline,
  updateBaseline,
  loadBaseline,
  serializeBaseline,
  ThreatBaselineSchema,
  BaselineThreatEntrySchema,
  BaselineStatusSchema,
  type ThreatBaseline,
  type BaselineThreatEntry,
  type BaselineStatus,
  type DeltaReport,
} from "./baseline.js";

// ---------------------------------------------------------------------------
// Trend tracking
// ---------------------------------------------------------------------------

export {
  // Zod schemas
  TrendSummarySchema,
  TrendEntrySchema as TrendEntryZodSchema,
  ThreatTrendSchema,

  // Inferred TypeScript types
  type TrendSummary,
  type TrendEntry as TrendEntryData,
  type ThreatTrend,

  // Functions
  createTrend,
  addTrendEntry,
  loadTrend,
  serializeTrend,
  toTrendMarkdown,
} from "./trend.js";

// ---------------------------------------------------------------------------
// Prompt templates (exported for extensibility / testing)
// ---------------------------------------------------------------------------

export {
  SYSTEM_PROMPT,
  buildComponentAnalysisPrompt,
  buildThreatGenerationPrompt,
  buildIntentContext,
  buildDFDPrompt,
  THREAT_FEW_SHOT_EXAMPLE,
} from "./prompts.js";

// ---------------------------------------------------------------------------
// Intent schema and loader
// ---------------------------------------------------------------------------

export {
  // Zod schemas
  IntentSchema,
  IntentDomain,
  DataSensitivityType,
  CloudProvider,
  EnvironmentType,
  DataSensitivityEntrySchema,
  CriticalAssetSchema,
  InfrastructureSchema,

  // Inferred TypeScript types
  type Intent,
  type DataSensitivityEntry,
  type CriticalAsset,
  type Infrastructure,

  // Loader functions
  loadIntent,
  loadIntentFromFile,

  // Compliance mapping
  COMPLIANCE_STRIDE_MAP,
  resolveComplianceControls,
} from "./intent.js";
