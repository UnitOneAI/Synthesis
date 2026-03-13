/**
 * Input validation for Synthesis GitHub Action.
 *
 * Security controls applied:
 * - All inputs validated with Zod schemas before use (ASVS V5.1.1)
 * - API keys are masked immediately via @actions/core.setSecret() (OWASP Secrets Mgmt)
 * - Never log or expose secret values in error messages (ASVS V7.1.1)
 * - Fail-closed: invalid inputs halt execution with a clear, non-sensitive error (ASVS V7.4.3)
 */

import * as core from "@actions/core";
import { z } from "zod";
import type { SeverityLevel, ThreatFramework, SynthesisConfig } from "@synthesis/core";

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const VALID_FRAMEWORKS = ["stride", "owasp", "aws_threat_grammar"] as const;

const FRAMEWORK_MAP: Record<string, ThreatFramework> = {
  stride: "STRIDE",
  owasp: "OWASP",
  aws_threat_grammar: "AWS_THREAT_GRAMMAR",
};

const SeveritySchema = z.enum(VALID_SEVERITIES);

const FrameworkListSchema = z
  .string()
  .transform((val) =>
    val
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  )
  .pipe(
    z
      .array(z.enum(VALID_FRAMEWORKS))
      .min(1, "At least one valid framework must be specified.")
  );

const MaxFilesSchema = z
  .string()
  .transform((val) => {
    const parsed = Number.parseInt(val, 10);
    if (Number.isNaN(parsed)) {
      throw new Error("max-files must be a valid integer.");
    }
    return parsed;
  })
  .pipe(
    z
      .number()
      .int()
      .min(1, "max-files must be at least 1.")
      .max(500, "max-files must not exceed 500.")
  );

const BooleanStringSchema = z
  .string()
  .transform((val) => val.toLowerCase() === "true");

// ---------------------------------------------------------------------------
// Validated inputs type
// ---------------------------------------------------------------------------

export interface ValidatedInputs {
  provider: "anthropic" | "gemini";
  apiKey: string;
  severityThreshold: SeverityLevel;
  frameworks: ThreatFramework[];
  postComment: boolean;
  failOnThreshold: boolean;
  maxFiles: number;
  sarifUpload: boolean;
}

// ---------------------------------------------------------------------------
// Validation entry point
// ---------------------------------------------------------------------------

/**
 * Reads, validates, and returns all action inputs.
 *
 * Security: API keys are masked via core.setSecret() the moment they are read,
 * before any other processing. This ensures they cannot leak in logs even if a
 * later step throws an unhandled error.
 */
export function validateInputs(): ValidatedInputs {
  // ---- Read raw inputs ----
  const rawAnthropicKey = core.getInput("anthropic-api-key");
  const rawGeminiKey = core.getInput("gemini-api-key");
  const rawSeverity = core.getInput("severity-threshold") || "high";
  const rawFrameworks = core.getInput("frameworks") || "stride";
  const rawPostComment = core.getInput("post-comment") || "true";
  const rawFailOnThreshold = core.getInput("fail-on-threshold") || "true";
  const rawMaxFiles = core.getInput("max-files") || "50";
  const rawSarifUpload = core.getInput("sarif-upload") || "false";

  // ---- SECURITY: Mask secrets immediately (CICD-SEC-6, OWASP Secrets Mgmt) ----
  if (rawAnthropicKey) {
    core.setSecret(rawAnthropicKey);
  }
  if (rawGeminiKey) {
    core.setSecret(rawGeminiKey);
  }

  // ---- Determine provider ----
  let provider: "anthropic" | "gemini";
  let apiKey: string;

  if (rawAnthropicKey && rawGeminiKey) {
    // Both provided: prefer Anthropic, log the choice
    core.info("Both API keys provided. Using Anthropic as the primary provider.");
    provider = "anthropic";
    apiKey = rawAnthropicKey;
  } else if (rawAnthropicKey) {
    provider = "anthropic";
    apiKey = rawAnthropicKey;
  } else if (rawGeminiKey) {
    provider = "gemini";
    apiKey = rawGeminiKey;
  } else {
    throw new Error(
      "No API key provided. Set either 'anthropic-api-key' or 'gemini-api-key' input. " +
        "Keys should be stored as GitHub Actions secrets, never hardcoded."
    );
  }

  // ---- Validate severity ----
  const severityResult = SeveritySchema.safeParse(rawSeverity.toLowerCase());
  if (!severityResult.success) {
    throw new Error(
      `Invalid severity-threshold '${rawSeverity}'. ` +
        `Must be one of: ${VALID_SEVERITIES.join(", ")}.`
    );
  }
  const severityThreshold = severityResult.data as SeverityLevel;

  // ---- Validate frameworks ----
  const frameworksResult = FrameworkListSchema.safeParse(rawFrameworks);
  if (!frameworksResult.success) {
    throw new Error(
      `Invalid frameworks '${rawFrameworks}'. ` +
        `Must be a comma-separated list of: ${VALID_FRAMEWORKS.join(", ")}. ` +
        `Error: ${frameworksResult.error.issues.map((i) => i.message).join("; ")}`
    );
  }
  const frameworks: ThreatFramework[] = frameworksResult.data.map(
    (f) => FRAMEWORK_MAP[f]
  );

  // ---- Validate max-files ----
  const maxFilesResult = MaxFilesSchema.safeParse(rawMaxFiles);
  if (!maxFilesResult.success) {
    throw new Error(
      `Invalid max-files '${rawMaxFiles}'. ` +
        `Must be an integer between 1 and 500. ` +
        `Error: ${maxFilesResult.error.issues.map((i) => i.message).join("; ")}`
    );
  }
  const maxFiles = maxFilesResult.data;

  // ---- Validate booleans ----
  const postComment = BooleanStringSchema.parse(rawPostComment);
  const failOnThreshold = BooleanStringSchema.parse(rawFailOnThreshold);
  const sarifUpload = BooleanStringSchema.parse(rawSarifUpload);

  return {
    provider,
    apiKey,
    severityThreshold,
    frameworks,
    postComment,
    failOnThreshold,
    maxFiles,
    sarifUpload,
  };
}

// ---------------------------------------------------------------------------
// Severity comparison utility
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Returns true if `severity` meets or exceeds the given `threshold`.
 */
export function meetsThreshold(
  severity: SeverityLevel,
  threshold: SeverityLevel
): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
