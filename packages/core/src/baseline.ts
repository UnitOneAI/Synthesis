/**
 * @synthesis/core — Threat Baseline & Delta Reporting
 *
 * Provides threat fingerprinting and baseline comparison so that
 * successive scans can report only what changed (new / resolved /
 * changed threats) instead of dumping the full threat register
 * every time.
 *
 * Fingerprinting uses SHA-256 of `component|stride|attackTechnique`
 * so the same class of threat on the same component always produces
 * the same fingerprint regardless of description wording.
 *
 * SECURITY:
 * - Baseline JSON is validated with Zod on load (defense-in-depth).
 * - Fingerprints are deterministic and non-reversible.
 */

import { createHash } from "node:crypto";
import { z } from "zod";

import {
  ThreatEntrySchema,
  type ThreatEntry,
  type ThreatModel,
} from "./types.js";

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

/**
 * Generate a stable SHA-256 fingerprint for a threat.
 *
 * The hash is derived from `component|stride|attackTechnique` so that
 * two threats targeting the same component via the same STRIDE category
 * and ATT&CK technique always collide, even if description text differs.
 */
export function generateThreatFingerprint(threat: ThreatEntry): string {
  const input = `${threat.component}|${threat.stride}|${threat.attackTechnique}`;
  return createHash("sha256").update(input).digest("hex");
}

// ---------------------------------------------------------------------------
// Baseline types & Zod schemas
// ---------------------------------------------------------------------------

/** Status tracking for a threat that has been recorded in the baseline. */
export const BaselineStatusSchema = z.enum([
  "open",
  "mitigated",
  "accepted",
  "transferred",
]);
export type BaselineStatus = z.infer<typeof BaselineStatusSchema>;

export const BaselineThreatEntrySchema = z.object({
  fingerprint: z.string().min(1),
  threat: ThreatEntrySchema,
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  status: BaselineStatusSchema,
  acceptedBy: z.string().optional(),
  acceptedReason: z.string().optional(),
});
export type BaselineThreatEntry = z.infer<typeof BaselineThreatEntrySchema>;

export const ThreatBaselineSchema = z.object({
  version: z.string().default("1.0"),
  timestamp: z.string().datetime(),
  projectName: z.string().min(1).max(256),
  threats: z.record(z.string(), BaselineThreatEntrySchema),
});
export type ThreatBaseline = z.infer<typeof ThreatBaselineSchema>;

// ---------------------------------------------------------------------------
// Delta report
// ---------------------------------------------------------------------------

export interface DeltaReport {
  /** Threats present in the current scan but not in the baseline. */
  newThreats: ThreatEntry[];
  /** Threats present in the baseline but absent from the current scan. */
  resolvedThreats: BaselineThreatEntry[];
  /** Threats present in both with no severity change. */
  unchangedThreats: BaselineThreatEntry[];
  /** Threats present in both but with a different severity. */
  changedThreats: { previous: BaselineThreatEntry; current: ThreatEntry }[];
  /** Convenience counts. */
  summary: {
    total: number;
    new: number;
    resolved: number;
    unchanged: number;
    changed: number;
  };
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Compare a freshly generated threat model against an existing baseline.
 */
export function compareWithBaseline(
  currentModel: ThreatModel,
  baseline: ThreatBaseline,
): DeltaReport {
  const currentFingerprints = new Map<string, ThreatEntry>();
  for (const threat of currentModel.threats) {
    const fp = generateThreatFingerprint(threat);
    currentFingerprints.set(fp, threat);
  }

  const newThreats: ThreatEntry[] = [];
  const resolvedThreats: BaselineThreatEntry[] = [];
  const unchangedThreats: BaselineThreatEntry[] = [];
  const changedThreats: { previous: BaselineThreatEntry; current: ThreatEntry }[] = [];

  // Walk the current scan — identify new vs. unchanged/changed
  for (const [fp, threat] of currentFingerprints) {
    const baselineEntry = baseline.threats[fp];
    if (!baselineEntry) {
      newThreats.push(threat);
    } else if (baselineEntry.threat.severity !== threat.severity) {
      changedThreats.push({ previous: baselineEntry, current: threat });
    } else {
      unchangedThreats.push(baselineEntry);
    }
  }

  // Walk the baseline — anything not in current scan is resolved
  for (const [fp, entry] of Object.entries(baseline.threats)) {
    if (!currentFingerprints.has(fp)) {
      resolvedThreats.push(entry);
    }
  }

  const total = currentModel.threats.length;

  return {
    newThreats,
    resolvedThreats,
    unchangedThreats,
    changedThreats,
    summary: {
      total,
      new: newThreats.length,
      resolved: resolvedThreats.length,
      unchanged: unchangedThreats.length,
      changed: changedThreats.length,
    },
  };
}

/**
 * Create a fresh baseline from a threat model (first scan).
 */
export function createBaseline(model: ThreatModel): ThreatBaseline {
  const now = new Date().toISOString();
  const threats: Record<string, BaselineThreatEntry> = {};

  for (const threat of model.threats) {
    const fp = generateThreatFingerprint(threat);
    threats[fp] = {
      fingerprint: fp,
      threat,
      firstSeen: now,
      lastSeen: now,
      status: threat.status ?? "open",
    };
  }

  return {
    version: "1.0",
    timestamp: now,
    projectName: model.projectName,
    threats,
  };
}

/**
 * Merge a delta report back into an existing baseline to produce
 * an updated baseline that reflects the latest scan.
 */
export function updateBaseline(
  existing: ThreatBaseline,
  delta: DeltaReport,
): ThreatBaseline {
  const now = new Date().toISOString();
  const threats: Record<string, BaselineThreatEntry> = {};

  // Carry forward unchanged threats (update lastSeen)
  for (const entry of delta.unchangedThreats) {
    threats[entry.fingerprint] = {
      ...entry,
      lastSeen: now,
    };
  }

  // Add changed threats with updated severity (update lastSeen)
  for (const { previous, current } of delta.changedThreats) {
    threats[previous.fingerprint] = {
      ...previous,
      threat: current,
      lastSeen: now,
    };
  }

  // Add new threats
  for (const threat of delta.newThreats) {
    const fp = generateThreatFingerprint(threat);
    threats[fp] = {
      fingerprint: fp,
      threat,
      firstSeen: now,
      lastSeen: now,
      status: threat.status ?? "open",
    };
  }

  // Resolved threats are intentionally dropped from the new baseline

  return {
    version: existing.version,
    timestamp: now,
    projectName: existing.projectName,
    threats,
  };
}

/**
 * Parse and validate a baseline from its JSON string representation.
 * Throws a ZodError if the content does not conform to the schema.
 */
export function loadBaseline(jsonContent: string): ThreatBaseline {
  const raw: unknown = JSON.parse(jsonContent);
  return ThreatBaselineSchema.parse(raw);
}

/**
 * Serialize a baseline to a formatted JSON string suitable for storage.
 */
export function serializeBaseline(baseline: ThreatBaseline): string {
  return JSON.stringify(baseline, null, 2);
}
