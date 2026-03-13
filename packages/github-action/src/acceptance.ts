/**
 * PR-Level Threat Acceptance (A5) for Synthesis.
 *
 * Allows reviewers to accept, mitigate, or transfer specific threats
 * directly from PR comments, with full audit trail.
 *
 * Command format:
 *   @synthesis accept TM-003 reason: accepted per SOC2 exception #12
 *   @synthesis mitigate TM-001 reason: fixed in this PR, added rate limiting
 *   @synthesis transfer TM-005 reason: infrastructure team owns this risk
 *
 * Security controls applied:
 * - Strict regex parsing — only exact command patterns are matched (ASVS V5.1.1)
 * - All comment content is sanitized before processing (CWE-79, ASVS V5.2.1)
 * - Bot comments are filtered out to prevent automated injection
 * - Reason text is length-capped and sanitized to prevent log injection
 */

import * as core from "@actions/core";
import type { ThreatModel } from "@synthesis/core";
import { getPRComments } from "./github-client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatAcceptance {
  threatId: string;
  action: "accept" | "mitigate" | "transfer";
  reason: string;
  acceptedBy: string;
  timestamp: string;
  prNumber: number;
  commentId: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Strict regex for acceptance commands.
 *
 * Matches: @synthesis (accept|mitigate|transfer) (TM-NNN) reason: (text)
 * - Case-insensitive on the action keyword
 * - Threat ID must match TM- followed by one or more digits
 * - Reason text captures the rest of the line
 * - The 'g' and 'm' flags allow matching multiple commands in one comment
 */
const ACCEPTANCE_PATTERN =
  /^@synthesis\s+(accept|mitigate|transfer)\s+(TM-\d+)\s+reason:\s*(.+)$/gim;

/** Maximum allowed length for a reason string. */
const MAX_REASON_LENGTH = 1024;

// ---------------------------------------------------------------------------
// Content sanitization
// ---------------------------------------------------------------------------

/**
 * Sanitizes a reason string extracted from a PR comment.
 *
 * Strips control characters, HTML tags, and caps the length to prevent
 * injection via the audit log or downstream markdown rendering.
 */
function sanitizeReason(raw: string): string {
  return (
    raw
      // Strip HTML tags
      .replace(/<[^>]*>/g, "")
      // Strip control characters except normal whitespace
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      // Collapse whitespace
      .replace(/\s+/g, " ")
      .trim()
      .substring(0, MAX_REASON_LENGTH)
  );
}

/**
 * Sanitizes a GitHub username. Only allows alphanumeric, hyphens, and
 * underscores (the characters GitHub permits in usernames).
 */
function sanitizeUsername(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_-]/g, "").substring(0, 39);
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Parses PR comments looking for @synthesis acceptance commands.
 *
 * Fetches all comments on the PR, filters out bot comments, and extracts
 * validated ThreatAcceptance objects from matching command patterns.
 */
export async function parseAcceptanceCommands(
  octokit: any,
  context: any,
): Promise<ThreatAcceptance[]> {
  const prNumber = context.payload.pull_request?.number;
  if (!prNumber) {
    core.debug("No PR context for acceptance commands.");
    return [];
  }

  const comments = await getPRComments(octokit, context);
  const acceptances: ThreatAcceptance[] = [];

  for (const comment of comments) {
    // Skip bot comments to prevent automated injection
    if (comment.userType === "Bot") {
      continue;
    }

    // Reset regex state for each comment (global flag)
    ACCEPTANCE_PATTERN.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = ACCEPTANCE_PATTERN.exec(comment.body)) !== null) {
      const action = match[1].toLowerCase() as "accept" | "mitigate" | "transfer";
      const threatId = match[2].toUpperCase();
      const rawReason = match[3];

      const reason = sanitizeReason(rawReason);
      if (!reason) {
        core.warning(
          `Skipping acceptance command in comment ${comment.id}: empty reason after sanitization.`
        );
        continue;
      }

      acceptances.push({
        threatId,
        action,
        reason,
        acceptedBy: sanitizeUsername(comment.user),
        timestamp: new Date().toISOString(),
        prNumber,
        commentId: comment.id,
      });
    }
  }

  core.info(`Found ${acceptances.length} acceptance command(s) in PR comments.`);
  return acceptances;
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

/** Maps acceptance actions to ThreatStatus values. */
const ACTION_TO_STATUS: Record<ThreatAcceptance["action"], "accepted" | "mitigated" | "transferred"> = {
  accept: "accepted",
  mitigate: "mitigated",
  transfer: "transferred",
};

/**
 * Applies acceptance commands to a threat model, updating the status
 * of matching threats.
 *
 * Returns the updated model, the list of successfully applied acceptances,
 * and any acceptances that did not match a known threat ID.
 */
export function applyAcceptances(
  model: ThreatModel,
  acceptances: ThreatAcceptance[],
): { model: ThreatModel; applied: ThreatAcceptance[]; unmatched: ThreatAcceptance[] } {
  const applied: ThreatAcceptance[] = [];
  const unmatched: ThreatAcceptance[] = [];

  // Build a lookup of threat IDs for efficient matching
  const threatIds = new Set(model.threats.map((t) => t.id.toUpperCase()));

  for (const acceptance of acceptances) {
    const normalizedId = acceptance.threatId.toUpperCase();

    if (!threatIds.has(normalizedId)) {
      unmatched.push(acceptance);
      core.warning(
        `Acceptance command for '${acceptance.threatId}' does not match any threat in the model.`
      );
      continue;
    }

    // Update the status of the matching threat
    for (const threat of model.threats) {
      if (threat.id.toUpperCase() === normalizedId) {
        threat.status = ACTION_TO_STATUS[acceptance.action];
        applied.push(acceptance);
        core.info(
          `Threat ${acceptance.threatId} ${acceptance.action}ed by @${acceptance.acceptedBy}: ${acceptance.reason}`
        );
        break; // Each acceptance applies to the first matching threat
      }
    }
  }

  return { model, applied, unmatched };
}

// ---------------------------------------------------------------------------
// Audit log formatting
// ---------------------------------------------------------------------------

/**
 * Generates a markdown-formatted audit log table for threat acceptances.
 *
 * Includes both applied and unmatched acceptances (unmatched are marked).
 */
export function formatAcceptanceLog(acceptances: ThreatAcceptance[]): string {
  if (acceptances.length === 0) {
    return "";
  }

  const lines: string[] = [
    "",
    "---",
    "",
    "### Acceptance Audit Log",
    "",
    "| Threat | Action | By | Reason | Date |",
    "|--------|--------|----|--------|------|",
  ];

  for (const a of acceptances) {
    // Sanitize values for safe markdown table rendering
    const date = a.timestamp.substring(0, 10);
    const escapedReason = a.reason
      .replace(/\|/g, "\\|")
      .replace(/\n/g, " ");
    lines.push(
      `| ${a.threatId} | ${a.action}ed | @${a.acceptedBy} | ${escapedReason} | ${date} |`
    );
  }

  return lines.join("\n");
}

/**
 * Generates the acceptance commands help section appended to every
 * threat model PR comment.
 */
export function formatAcceptanceHelp(): string {
  return [
    "",
    "---",
    "",
    "### Threat Acceptance Commands",
    "",
    "To accept or manage threats, comment on this PR:",
    "- `@synthesis accept TM-001 reason: your justification here`",
    "- `@synthesis mitigate TM-002 reason: fixed by adding input validation`",
    "- `@synthesis transfer TM-003 reason: assigned to infrastructure team`",
    "",
    "Re-run the action after posting acceptance commands to update the report.",
  ].join("\n");
}
