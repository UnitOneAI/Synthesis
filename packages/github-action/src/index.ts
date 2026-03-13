/**
 * Synthesis Threat Model -- GitHub Action entrypoint.
 *
 * Orchestrates the full threat modeling pipeline:
 * 1. Validate all inputs (fail-closed on invalid config)
 * 2. Verify PR context exists (graceful skip if not a PR event)
 * 3. Fetch the PR diff via GitHub API
 * 4. Parse the diff and run AI-powered threat analysis via @synthesis/core
 * 5. Format results as Markdown and optionally SARIF
 * 6. Post PR comment and/or upload SARIF to Code Scanning
 * 7. Set action outputs (threat counts, report path)
 * 8. Fail the action if threats exceed the configured severity threshold
 *
 * Security controls applied throughout:
 * - CICD-SEC-2: Least-privilege GITHUB_TOKEN usage
 * - CICD-SEC-4: No expression injection (all inputs read via @actions/core)
 * - CICD-SEC-6: API keys masked immediately, never logged
 * - ASVS V5.1.1: All inputs validated with Zod schemas before use
 * - ASVS V7.1.1: No secrets in logs
 * - ASVS V7.4.3: Error handlers deny by default
 * - CWE-79: Markdown output sanitized before posting as PR comments
 */

import * as core from "@actions/core";
import * as github from "@actions/github";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  generateThreatModel,
  parseDiff,
  expandContext,
  toMarkdown,
  toSARIF,
  toSummary,
  toDeltaMarkdown,
  compareWithBaseline,
  createBaseline,
  updateBaseline,
  loadBaseline,
  serializeBaseline,
  createTrend,
  addTrendEntry,
  loadTrend,
  serializeTrend,
  toTrendMarkdown,
} from "@synthesis/core";
import type {
  SynthesisConfig,
  SeverityLevel,
  ThreatModel,
  ThreatBaseline,
  DeltaReport,
  ThreatTrend,
  TrendEntryData,
} from "@synthesis/core";

import { validateInputs, meetsThreshold } from "./validators";
import { getPRDiff, postComment, uploadSARIF, getFileContent, listRepoFiles } from "./github-client";
import { buildSARIF } from "./sarif";
import {
  parseAcceptanceCommands,
  applyAcceptances,
  formatAcceptanceLog,
  formatAcceptanceHelp,
} from "./acceptance";
import type { ThreatAcceptance } from "./acceptance";

// ---------------------------------------------------------------------------
// Severity ordering used for threshold comparison
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run(): Promise<void> {
  // ------------------------------------------------------------------
  // Step 1: Validate inputs
  // ------------------------------------------------------------------
  core.info("Validating action inputs...");
  const inputs = validateInputs();
  core.info(
    `Configuration: provider=${inputs.provider}, threshold=${inputs.severityThreshold}, ` +
      `frameworks=${inputs.frameworks.join(",")}, maxFiles=${inputs.maxFiles}`
  );

  // ------------------------------------------------------------------
  // Step 2: Verify PR context
  // ------------------------------------------------------------------
  const prNumber = github.context.payload.pull_request?.number;
  if (!prNumber) {
    core.warning(
      "This action was not triggered by a pull_request event. " +
        "Skipping threat analysis. To use this action, configure it with " +
        "'on: pull_request' or 'on: pull_request_target' triggers."
    );
    // Set zero outputs so downstream steps don't break
    core.setOutput("threat-count", "0");
    core.setOutput("critical-count", "0");
    core.setOutput("high-count", "0");
    core.setOutput("new-threat-count", "0");
    core.setOutput("report-path", "");
    return;
  }

  core.info(`Analyzing PR #${prNumber}: ${github.context.payload.pull_request?.title ?? ""}`);

  // ------------------------------------------------------------------
  // Step 3: Initialize GitHub client and fetch diff
  // ------------------------------------------------------------------
  const token = core.getInput("github-token") || process.env.GITHUB_TOKEN || "";
  if (token) {
    core.setSecret(token); // SECURITY: mask the token in logs
  }

  const octokit = github.getOctokit(token);
  const diff = await getPRDiff(octokit, github.context);

  // ------------------------------------------------------------------
  // Step 4: Parse diff and generate threat model
  // ------------------------------------------------------------------
  core.info("Parsing diff and analyzing for threats...");

  const fileChanges = parseDiff(diff);
  core.info(`Parsed ${fileChanges.length} file changes from the diff.`);

  // Enforce max-files limit to control cost and runtime
  const filesToAnalyze = fileChanges.slice(0, inputs.maxFiles);
  if (fileChanges.length > inputs.maxFiles) {
    core.warning(
      `PR contains ${fileChanges.length} changed files but max-files is set to ${inputs.maxFiles}. ` +
        `Only the first ${inputs.maxFiles} files will be analyzed.`
    );
  }

  // ------------------------------------------------------------------
  // Step 4a: Expand context (1-hop dependency analysis)
  // ------------------------------------------------------------------
  const expandContextEnabled =
    (core.getInput("expand-context") || "true").toLowerCase() === "true";

  let repoContent: string | undefined;

  if (expandContextEnabled && filesToAnalyze.length > 0) {
    core.info("Expanding analysis context via 1-hop dependency graph...");

    try {
      const expansion = await expandContext(
        filesToAnalyze,
        (filePath: string) => getFileContent(octokit, github.context, filePath),
        () => listRepoFiles(octokit, github.context),
        { maxRelatedFiles: 20, maxFileSize: 100 * 1024 },
      );

      if (expansion.relatedFiles.length > 0) {
        // Build repoContent string: concatenate related file contents with path headers
        const sections = expansion.relatedFiles.map(
          (rf) =>
            `--- File: ${rf.path} (${rf.relationship} ${rf.relatedTo}) ---\n${rf.content}`,
        );
        repoContent = sections.join("\n\n");

        core.info(
          `Context expansion included ${expansion.relatedFiles.length} related file(s).`
        );

        // Log expansion details at debug level
        for (const logEntry of expansion.expansionLog) {
          core.debug(logEntry);
        }
      } else {
        core.info("Context expansion found no related files.");
      }
    } catch (error) {
      // Non-fatal: if context expansion fails, proceed with diff-only analysis
      const message = error instanceof Error ? error.message : "unknown error";
      core.warning(
        `Context expansion failed: ${message}. Proceeding with diff-only analysis.`
      );
    }
  } else if (!expandContextEnabled) {
    core.info("Context expansion is disabled. Analyzing diff only.");
  }

  const config: SynthesisConfig = {
    provider: inputs.provider,
    apiKey: inputs.apiKey,
    frameworks: inputs.frameworks,
    severityThreshold: inputs.severityThreshold,
    maxFiles: inputs.maxFiles,
  };

  const analysisInput: { files: typeof filesToAnalyze; repoContent?: string } = {
    files: filesToAnalyze,
  };
  if (repoContent) {
    analysisInput.repoContent = repoContent;
  }

  const model: ThreatModel = await generateThreatModel(
    analysisInput,
    config
  );

  core.info(
    `Threat analysis complete: ${model.threats.length} threats identified ` +
      `across ${model.components.length} components.`
  );

  // ------------------------------------------------------------------
  // Step 4b: Baseline comparison (if baseline exists)
  // ------------------------------------------------------------------
  let baseline: ThreatBaseline | null = null;
  let delta: DeltaReport | null = null;
  const baselinePath = path.join(
    process.env.GITHUB_WORKSPACE || process.cwd(),
    "synthesis-baseline.json"
  );

  try {
    const baselineContent = fs.readFileSync(baselinePath, "utf-8");
    baseline = loadBaseline(baselineContent);
    core.info(`Loaded threat baseline from ${baselinePath} with ${Object.keys(baseline.threats).length} entries.`);
    delta = compareWithBaseline(model, baseline);
    core.info(
      `Delta: ${delta.summary.new} new, ${delta.summary.resolved} resolved, ` +
        `${delta.summary.changed} changed, ${delta.summary.unchanged} unchanged.`
    );
  } catch (err: unknown) {
    if (err instanceof SyntaxError || (err instanceof Error && err.name === "ZodError")) {
      core.warning(`Threat baseline at ${baselinePath} is malformed — ignoring. Error: ${(err as Error).message}`);
    } else {
      core.info("No existing threat baseline found. Full report will be generated.");
    }
  }

  // Write updated baseline to artifacts directory
  const reportDir = process.env.RUNNER_TEMP || "/tmp";
  const updatedBaseline = baseline && delta
    ? updateBaseline(baseline, delta)
    : createBaseline(model);
  const updatedBaselinePath = path.join(reportDir, "synthesis-baseline.json");
  fs.writeFileSync(updatedBaselinePath, serializeBaseline(updatedBaseline), "utf-8");
  core.info(`Updated baseline written to ${updatedBaselinePath}`);

  // ------------------------------------------------------------------
  // Step 4c: Process threat acceptance commands from PR comments
  // ------------------------------------------------------------------
  const processAcceptances =
    (core.getInput("process-acceptances") || "true").toLowerCase() === "true";

  let allAcceptances: ThreatAcceptance[] = [];
  let appliedAcceptances: ThreatAcceptance[] = [];
  let unmatchedAcceptances: ThreatAcceptance[] = [];

  if (processAcceptances) {
    core.info("Scanning PR comments for threat acceptance commands...");
    try {
      allAcceptances = await parseAcceptanceCommands(octokit, github.context);

      if (allAcceptances.length > 0) {
        const result = applyAcceptances(model, allAcceptances);
        appliedAcceptances = result.applied;
        unmatchedAcceptances = result.unmatched;

        core.info(
          `Acceptance processing: ${appliedAcceptances.length} applied, ` +
            `${unmatchedAcceptances.length} unmatched.`
        );

        if (unmatchedAcceptances.length > 0) {
          core.warning(
            `${unmatchedAcceptances.length} acceptance command(s) did not match any threat: ` +
              unmatchedAcceptances.map((a) => a.threatId).join(", ")
          );
        }
      }
    } catch (error) {
      // Non-fatal: if acceptance parsing fails, proceed without it
      const message = error instanceof Error ? error.message : "unknown error";
      core.warning(
        `Failed to process acceptance commands: ${message}. ` +
          "Proceeding without acceptance processing."
      );
    }
  } else {
    core.info("Acceptance processing is disabled.");
  }

  // ------------------------------------------------------------------
  // Step 4d: Trend tracking (if enabled)
  // ------------------------------------------------------------------
  const trendTrackingEnabled =
    (core.getInput("trend-tracking") || "true").toLowerCase() === "true";

  let trendMarkdown = "";

  if (trendTrackingEnabled) {
    const trendFilePath = path.join(
      process.env.GITHUB_WORKSPACE || process.cwd(),
      "synthesis-trend.json"
    );

    let trend: ThreatTrend;
    try {
      const trendContent = fs.readFileSync(trendFilePath, "utf-8");
      trend = loadTrend(trendContent);
      core.info(`Loaded trend data from ${trendFilePath} with ${trend.entries.length} entries.`);
    } catch (err: unknown) {
      if (err instanceof SyntaxError || (err instanceof Error && err.name === "ZodError")) {
        core.warning(`Trend file at ${trendFilePath} is malformed — starting fresh. Error: ${(err as Error).message}`);
      } else {
        core.info("No existing trend file found. Creating new trend.");
      }
      trend = createTrend(model.projectName);
    }

    // Build the trend entry from current scan results and PR context
    const prTitle = github.context.payload.pull_request?.title ?? "";
    const commitSha = github.context.sha || "";
    const previousEntry = trend.entries.length > 0
      ? trend.entries[trend.entries.length - 1]
      : null;

    // Calculate new vs resolved threats compared to previous scan
    const currentTotal = model.threats.length;
    const previousTotal = previousEntry ? previousEntry.summary.total : 0;
    const totalDiff = currentTotal - previousTotal;
    const newThreats = totalDiff > 0 ? totalDiff : 0;
    const resolvedThreats = totalDiff < 0 ? Math.abs(totalDiff) : 0;

    const trendEntry: TrendEntryData = {
      timestamp: model.timestamp,
      prNumber,
      prTitle,
      commitSha,
      summary: {
        critical: model.summary.critical,
        high: model.summary.high,
        medium: model.summary.medium,
        low: model.summary.low,
        info: model.summary.info,
        total: currentTotal,
      },
      newThreats,
      resolvedThreats,
    };

    trend = addTrendEntry(trend, trendEntry);
    core.info(`Trend updated: ${trend.entries.length} total entries.`);

    // Write updated trend JSON to artifacts directory
    const updatedTrendPath = path.join(reportDir, "synthesis-trend.json");
    fs.writeFileSync(updatedTrendPath, serializeTrend(trend), "utf-8");
    core.info(`Updated trend written to ${updatedTrendPath}`);

    // Generate trend markdown for inclusion in PR comment and job summary
    trendMarkdown = toTrendMarkdown(trend, 10);
  } else {
    core.info("Trend tracking is disabled.");
  }

  // ------------------------------------------------------------------
  // Step 5: Format results
  // ------------------------------------------------------------------
  let markdown: string;
  if (delta) {
    // Delta mode: show delta summary with full report in collapsible section
    const deltaMarkdown = toDeltaMarkdown(delta);
    const fullMarkdown = toMarkdown(model);
    markdown =
      deltaMarkdown +
      "\n" +
      "<details>\n" +
      "<summary><strong>Full Threat Model Report</strong></summary>\n\n" +
      fullMarkdown +
      "\n</details>\n";
  } else {
    markdown = toMarkdown(model);
  }
  const summary = toSummary(model);

  // Append acceptance help section and audit log to the markdown comment
  markdown += formatAcceptanceHelp();
  if (appliedAcceptances.length > 0) {
    markdown += formatAcceptanceLog(appliedAcceptances);
  }

  // Append trend summary as a collapsible section (if available)
  if (trendMarkdown) {
    markdown +=
      "\n<details>\n" +
      "<summary>\uD83D\uDCCA Threat Trend (last 10 PRs)</summary>\n\n" +
      trendMarkdown +
      "\n\n</details>\n";
  }

  // Write the markdown report to a file for artifact upload
  const reportPath = path.join(reportDir, "synthesis-threat-model.md");
  fs.writeFileSync(reportPath, markdown, "utf-8");
  core.info(`Report written to ${reportPath}`);

  // Optionally build SARIF
  let sarifPayload: object | null = null;
  if (inputs.sarifUpload) {
    sarifPayload = buildSARIF(model);

    // Also write SARIF to disk for artifact upload
    const sarifPath = path.join(reportDir, "synthesis-threat-model.sarif");
    fs.writeFileSync(sarifPath, JSON.stringify(sarifPayload, null, 2), "utf-8");
    core.info(`SARIF report written to ${sarifPath}`);
  }

  // ------------------------------------------------------------------
  // Step 6: Post results
  // ------------------------------------------------------------------
  if (inputs.postComment) {
    await postComment(octokit, github.context, markdown);
  } else {
    core.info("Comment posting is disabled. Skipping PR comment.");
  }

  if (inputs.sarifUpload && sarifPayload) {
    await uploadSARIF(octokit, github.context, sarifPayload);
  }

  // ------------------------------------------------------------------
  // Step 7: Set outputs
  // ------------------------------------------------------------------
  const totalThreats = model.threats.length;
  core.setOutput("threat-count", totalThreats.toString());
  core.setOutput("critical-count", summary.critical.toString());
  core.setOutput("high-count", summary.high.toString());
  core.setOutput("report-path", reportPath);
  core.setOutput("new-threat-count", delta ? delta.summary.new.toString() : totalThreats.toString());

  // Write job summary
  core.summary
    .addHeading("Synthesis Threat Model", 2)
    .addTable([
      [
        { data: "Severity", header: true },
        { data: "Count", header: true },
      ],
      ["Critical", summary.critical.toString()],
      ["High", summary.high.toString()],
      ["Medium", summary.medium.toString()],
      ["Low", summary.low.toString()],
    ])
    .addRaw(
      `\n\n**Total threats:** ${totalThreats} | **Threshold:** ${inputs.severityThreshold}`
    );

  // Add trend summary to job summary (if available)
  if (trendMarkdown) {
    core.summary.addRaw("\n\n" + trendMarkdown);
  }

  await core.summary.write();

  // ------------------------------------------------------------------
  // Step 8: Threshold enforcement
  // ------------------------------------------------------------------
  if (inputs.failOnThreshold) {
    // Only "open" threats count toward the threshold — threats that have been
    // accepted, mitigated, or transferred via PR comments are excluded.
    const threatsAboveThreshold = model.threats.filter(
      (t) => t.status === "open" && meetsThreshold(t.severity, inputs.severityThreshold)
    );

    if (threatsAboveThreshold.length > 0) {
      const breakdown = threatsAboveThreshold.reduce(
        (acc, t) => {
          acc[t.severity] = (acc[t.severity] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>
      );

      const breakdownStr = Object.entries(breakdown)
        .sort(([a], [b]) => SEVERITY_ORDER[b as SeverityLevel] - SEVERITY_ORDER[a as SeverityLevel])
        .map(([sev, count]) => `${count} ${sev}`)
        .join(", ");

      core.setFailed(
        `Threat analysis found ${threatsAboveThreshold.length} threat(s) at or above ` +
          `'${inputs.severityThreshold}' threshold: ${breakdownStr}. ` +
          "Review the threat model report for details and mitigations."
      );
    } else {
      core.info(
        `No threats at or above '${inputs.severityThreshold}' severity. Action passed.`
      );
    }
  } else {
    core.info("Threshold enforcement is disabled. Action completed without status check.");
  }
}

// ---------------------------------------------------------------------------
// Entry point with top-level error handling
// ---------------------------------------------------------------------------

run().catch((error: unknown) => {
  // SECURITY: Ensure we never leak the full error if it contains secret material.
  // Only log the message, not the full stack which may include env vars or tokens.
  if (error instanceof Error) {
    core.setFailed(`Synthesis Threat Model failed: ${error.message}`);
    // Log stack trace at debug level only (visible only when ACTIONS_STEP_DEBUG=true)
    if (error.stack) {
      core.debug(error.stack);
    }
  } else {
    core.setFailed("Synthesis Threat Model failed with an unexpected error.");
  }
});
