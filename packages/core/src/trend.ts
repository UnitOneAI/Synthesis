/**
 * @synthesis/core — Threat trend tracking
 *
 * Tracks threat model results across PRs to surface directional trends.
 * Each scan appends a TrendEntry; the data is capped at 100 entries to
 * prevent unbounded growth in the persisted JSON file.
 *
 * SECURITY:
 * - All inputs are validated with Zod schemas (ASVS V5.1.1)
 * - No user-provided strings are interpolated unsafely into markdown
 * - Trend data never contains secrets — only severity counts and PR metadata
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

/** Severity count summary for a single scan. */
export const TrendSummarySchema = z.object({
  critical: z.number().int().min(0),
  high: z.number().int().min(0),
  medium: z.number().int().min(0),
  low: z.number().int().min(0),
  info: z.number().int().min(0),
  total: z.number().int().min(0),
});
export type TrendSummary = z.infer<typeof TrendSummarySchema>;

/** A single trend data point corresponding to one PR scan. */
export const TrendEntrySchema = z.object({
  timestamp: z.string().datetime(),
  prNumber: z.number().int().min(1),
  prTitle: z.string().max(512),
  commitSha: z.string().min(1).max(64),
  summary: TrendSummarySchema,
  newThreats: z.number().int().min(0),
  resolvedThreats: z.number().int().min(0),
});
export type TrendEntry = z.infer<typeof TrendEntrySchema>;

/** Top-level trend container persisted as `synthesis-trend.json`. */
export const ThreatTrendSchema = z.object({
  version: z.literal("1.0"),
  projectName: z.string().min(1).max(256),
  entries: z.array(TrendEntrySchema),
});
export type ThreatTrend = z.infer<typeof ThreatTrendSchema>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of trend entries to retain. */
const MAX_ENTRIES = 100;

// ---------------------------------------------------------------------------
// Markdown escaping (local copy to avoid circular imports)
// ---------------------------------------------------------------------------

function escapeMarkdown(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create an empty ThreatTrend for a given project.
 */
export function createTrend(projectName: string): ThreatTrend {
  return {
    version: "1.0",
    projectName,
    entries: [],
  };
}

/**
 * Add a new entry to the trend, capping at `maxEntries` most recent entries.
 *
 * Returns a new ThreatTrend object (immutable update).
 */
export function addTrendEntry(
  trend: ThreatTrend,
  entry: TrendEntry,
  maxEntries: number = MAX_ENTRIES,
): ThreatTrend {
  const updatedEntries = [...trend.entries, entry];

  // Keep only the most recent entries to prevent unbounded growth
  const trimmed =
    updatedEntries.length > maxEntries
      ? updatedEntries.slice(updatedEntries.length - maxEntries)
      : updatedEntries;

  return {
    ...trend,
    entries: trimmed,
  };
}

/**
 * Load a ThreatTrend from a JSON string, validating with Zod.
 *
 * @throws ZodError if the JSON does not conform to the schema
 */
export function loadTrend(jsonContent: string): ThreatTrend {
  const parsed: unknown = JSON.parse(jsonContent);
  return ThreatTrendSchema.parse(parsed);
}

/**
 * Serialize a ThreatTrend to a formatted JSON string.
 */
export function serializeTrend(trend: ThreatTrend): string {
  return JSON.stringify(trend, null, 2);
}

/**
 * Generate a markdown summary of the threat trend.
 *
 * @param trend  - The trend data to render
 * @param lastN  - Number of recent entries to include (default: 10)
 */
export function toTrendMarkdown(trend: ThreatTrend, lastN: number = 10): string {
  const lines: string[] = [];
  const entries = trend.entries.slice(-lastN);

  if (entries.length === 0) {
    lines.push(`## Threat Trend (Last ${lastN} PRs)`);
    lines.push("");
    lines.push("_No trend data available yet._");
    return lines.join("\n");
  }

  lines.push(`## Threat Trend (Last ${Math.min(lastN, entries.length)} PRs)`);
  lines.push("");

  // Table header
  lines.push("| PR | Date | Critical | High | Medium | Low | Total | New | Resolved | Trend |");
  lines.push("|----|------|----------|------|--------|-----|-------|-----|----------|-------|");

  // Table rows (most recent first for readability)
  const reversed = [...entries].reverse();
  for (let i = 0; i < reversed.length; i++) {
    const entry = reversed[i];
    const date = formatShortDate(entry.timestamp);
    const trendIcon = getTrendIcon(reversed, i);

    lines.push(
      `| #${entry.prNumber} ` +
        `| ${date} ` +
        `| ${entry.summary.critical} ` +
        `| ${entry.summary.high} ` +
        `| ${entry.summary.medium} ` +
        `| ${entry.summary.low} ` +
        `| ${entry.summary.total} ` +
        `| +${entry.newThreats} ` +
        `| -${entry.resolvedThreats} ` +
        `| ${trendIcon} |`,
    );
  }

  lines.push("");

  // Trend summary section
  lines.push("### Trend Summary");

  const direction = calculateDirection(entries);
  const avgNew = entries.length > 0
    ? (entries.reduce((sum, e) => sum + e.newThreats, 0) / entries.length).toFixed(1)
    : "0.0";
  const avgResolved = entries.length > 0
    ? (entries.reduce((sum, e) => sum + e.resolvedThreats, 0) / entries.length).toFixed(1)
    : "0.0";
  const criticalFreeStreak = calculateCriticalFreeStreak(entries);

  lines.push(`- **Direction**: ${direction}`);
  lines.push(`- **Avg new threats per PR**: ${avgNew}`);
  lines.push(`- **Avg resolved per PR**: ${avgResolved}`);
  lines.push(`- **Critical threat-free streak**: ${criticalFreeStreak} PRs`);

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Format an ISO datetime to a short date string (e.g. "Mar 12").
 */
function formatShortDate(isoTimestamp: string): string {
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  const date = new Date(isoTimestamp);
  return `${months[date.getUTCMonth()]} ${date.getUTCDate()}`;
}

/**
 * Determine trend icon by comparing current entry total to the next older entry.
 * In the reversed array (most recent first), the "previous" scan is at index+1.
 */
function getTrendIcon(reversedEntries: TrendEntry[], index: number): string {
  if (index >= reversedEntries.length - 1) {
    // Oldest entry in the window — no comparison available
    return "\u2014"; // em-dash
  }

  const current = reversedEntries[index].summary.total;
  const previous = reversedEntries[index + 1].summary.total;

  if (current < previous) return "\ud83d\udcc9"; // chart decreasing (improving)
  if (current > previous) return "\ud83d\udcc8"; // chart increasing (worsening)
  return "\u27a1\ufe0f"; // right arrow (unchanged)
}

/**
 * Calculate trend direction by comparing the first and last entries in the window.
 * Uses simple percentage change of total threat count.
 */
function calculateDirection(entries: TrendEntry[]): string {
  if (entries.length < 2) {
    return "Insufficient data (need at least 2 scans)";
  }

  const oldest = entries[0].summary.total;
  const newest = entries[entries.length - 1].summary.total;

  if (oldest === 0 && newest === 0) {
    return "Stable (no threats detected)";
  }

  if (oldest === 0) {
    return `Worsening (threat count increased from 0 to ${newest})`;
  }

  const pctChange = ((newest - oldest) / oldest) * 100;
  const absPct = Math.abs(Math.round(pctChange));

  if (pctChange < -5) {
    return `Improving (threat count decreased ${absPct}% over last ${entries.length} PRs)`;
  }
  if (pctChange > 5) {
    return `Worsening (threat count increased ${absPct}% over last ${entries.length} PRs)`;
  }
  return `Stable (threat count changed less than 5% over last ${entries.length} PRs)`;
}

/**
 * Count consecutive PRs from the most recent that have zero critical threats.
 */
function calculateCriticalFreeStreak(entries: TrendEntry[]): number {
  let streak = 0;
  // Walk backwards from the most recent entry
  for (let i = entries.length - 1; i >= 0; i--) {
    if (entries[i].summary.critical === 0) {
      streak++;
    } else {
      break;
    }
  }
  return streak;
}
