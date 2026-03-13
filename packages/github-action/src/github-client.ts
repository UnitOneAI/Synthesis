/**
 * GitHub API interaction layer for Synthesis.
 *
 * Security controls applied:
 * - Uses GITHUB_TOKEN with minimum required permissions (CICD-SEC-2, CICD-SEC-5)
 * - Sanitizes all markdown content before posting to prevent injection (ASVS V5.2.1, CWE-79)
 * - Uses marker comments to update rather than spam PR threads
 * - Handles pagination and rate limiting gracefully (CICD-SEC-10)
 * - Never logs token values or response bodies containing secrets
 */

import * as core from "@actions/core";
import * as github from "@actions/github";
import type { GitHub } from "@actions/github/lib/utils";

type Octokit = InstanceType<typeof GitHub>;

// Marker used to identify and update existing Synthesis comments rather than
// creating duplicates on every push. This prevents PR comment spam.
const COMMENT_MARKER = "<!-- synthesis-threat-model-report -->";

// Maximum comment body length enforced by GitHub API
const MAX_COMMENT_LENGTH = 65536;

// ---------------------------------------------------------------------------
// Content sanitization
// ---------------------------------------------------------------------------

/**
 * Sanitizes user-controlled content before embedding it in a PR comment.
 *
 * Threat: Code diffs may contain markdown syntax, HTML tags, or script injection
 * payloads that render in the PR comment UI. This function neutralizes those
 * vectors while keeping the report readable.
 *
 * Controls: ASVS V5.2.1, V5.3.1 (output encoding), CWE-79 (XSS prevention)
 */
function sanitizeForMarkdown(content: string): string {
  return (
    content
      // Strip HTML tags that could render in GitHub markdown
      .replace(/<script[\s\S]*?<\/script>/gi, "[removed script]")
      .replace(/<iframe[\s\S]*?<\/iframe>/gi, "[removed iframe]")
      .replace(/<object[\s\S]*?<\/object>/gi, "[removed object]")
      .replace(/<embed[\s\S]*?\/?>/gi, "[removed embed]")
      .replace(/<link[\s\S]*?\/?>/gi, "[removed link]")
      .replace(/<style[\s\S]*?<\/style>/gi, "[removed style]")
      .replace(/<form[\s\S]*?<\/form>/gi, "[removed form]")
      // Neutralize HTML event handlers (onerror, onclick, etc.)
      .replace(/\bon\w+\s*=/gi, "data-removed=")
      // Neutralize javascript: and data: URI schemes in markdown links
      .replace(/\[([^\]]*)\]\(javascript:[^)]*\)/gi, "[$1](removed)")
      .replace(/\[([^\]]*)\]\(data:[^)]*\)/gi, "[$1](removed)")
      // Neutralize bare javascript: URIs
      .replace(/javascript\s*:/gi, "javascript-removed:")
  );
}

/**
 * Truncates content to fit within the GitHub comment size limit,
 * appending a notice if truncation occurred.
 */
function truncateToLimit(content: string): string {
  // Reserve space for the truncation notice
  const reservedBytes = 200;
  const maxBody = MAX_COMMENT_LENGTH - reservedBytes;

  if (content.length <= MAX_COMMENT_LENGTH) {
    return content;
  }

  const truncated = content.substring(0, maxBody);
  return (
    truncated +
    "\n\n---\n" +
    "> **Note:** This report was truncated because it exceeded GitHub's comment " +
    "size limit. Review the full report artifact for complete results."
  );
}

// ---------------------------------------------------------------------------
// PR Diff retrieval
// ---------------------------------------------------------------------------

/**
 * Fetches the unified diff for the pull request that triggered this action.
 *
 * Security: Only reads the diff content. The GITHUB_TOKEN only needs
 * `contents: read` permission for this operation.
 */
export async function getPRDiff(
  octokit: Octokit,
  context: typeof github.context
): Promise<string> {
  const { owner, repo } = context.repo;
  const pullNumber = context.payload.pull_request?.number;

  if (!pullNumber) {
    throw new Error(
      "No pull request context found. This action must be triggered by a " +
        "pull_request or pull_request_target event."
    );
  }

  core.info(`Fetching diff for PR #${pullNumber} in ${owner}/${repo}`);

  // Request the diff using the media type header. This returns the raw unified
  // diff as a string rather than the JSON file list, which is more efficient
  // for large PRs and preserves the full context needed for threat analysis.
  const response = await octokit.rest.pulls.get({
    owner,
    repo,
    pull_number: pullNumber,
    mediaType: {
      format: "diff",
    },
  });

  // The response.data is a string when using the diff media type
  const diff = response.data as unknown as string;

  if (!diff || typeof diff !== "string") {
    throw new Error(
      `Failed to retrieve diff for PR #${pullNumber}. ` +
        "The response was empty or in an unexpected format."
    );
  }

  core.info(`Retrieved diff: ${diff.length} bytes`);
  return diff;
}

// ---------------------------------------------------------------------------
// PR Comment posting
// ---------------------------------------------------------------------------

/**
 * Posts or updates a threat model report as a PR comment.
 *
 * Uses a hidden HTML marker to find and update an existing comment rather
 * than creating a new one on every push. This prevents PR comment spam
 * while still reflecting the latest analysis.
 *
 * Security: Content is sanitized before posting. The GITHUB_TOKEN needs
 * `pull-requests: write` permission for this operation.
 */
export async function postComment(
  octokit: Octokit,
  context: typeof github.context,
  markdown: string
): Promise<void> {
  const { owner, repo } = context.repo;
  const pullNumber = context.payload.pull_request?.number;

  if (!pullNumber) {
    core.warning("Skipping comment: no pull request context available.");
    return;
  }

  // SECURITY: Sanitize analyzed code content before posting (CWE-79, ASVS V5.2.1)
  const sanitizedBody = sanitizeForMarkdown(markdown);
  const commentBody = truncateToLimit(`${COMMENT_MARKER}\n${sanitizedBody}`);

  // Search for an existing Synthesis comment to update
  let existingCommentId: number | null = null;

  try {
    // Paginate through comments to find our marker.
    // Limit to 10 pages (300 comments) to avoid excessive API calls.
    const iterator = octokit.paginate.iterator(
      octokit.rest.issues.listComments,
      {
        owner,
        repo,
        issue_number: pullNumber,
        per_page: 30,
      }
    );

    let pageCount = 0;
    const maxPages = 10;

    for await (const { data: comments } of iterator) {
      pageCount++;
      for (const comment of comments) {
        if (comment.body?.includes(COMMENT_MARKER)) {
          existingCommentId = comment.id;
          break;
        }
      }
      if (existingCommentId || pageCount >= maxPages) {
        break;
      }
    }
  } catch (error) {
    // Non-fatal: if we cannot find an existing comment, we will create a new one
    core.warning(
      `Could not search for existing comments: ${error instanceof Error ? error.message : "unknown error"}. ` +
        "A new comment will be created."
    );
  }

  try {
    if (existingCommentId) {
      core.info(`Updating existing comment ${existingCommentId} on PR #${pullNumber}`);
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingCommentId,
        body: commentBody,
      });
    } else {
      core.info(`Creating new comment on PR #${pullNumber}`);
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: pullNumber,
        body: commentBody,
      });
    }

    core.info("Threat model report posted to PR.");
  } catch (error) {
    // Log the error but do not fail the entire action for a comment posting failure
    const message = error instanceof Error ? error.message : "unknown error";
    core.warning(
      `Failed to post comment to PR #${pullNumber}: ${message}. ` +
        "Verify that the GITHUB_TOKEN has 'pull-requests: write' permission."
    );
  }
}

// ---------------------------------------------------------------------------
// PR Comments retrieval
// ---------------------------------------------------------------------------

/**
 * Fetches all comments on the pull request.
 *
 * Used by the acceptance module to scan for @synthesis commands.
 * Paginates through comments (up to 10 pages / 300 comments)
 * to ensure we find all acceptance commands.
 *
 * Security: Only reads comment data. The GITHUB_TOKEN needs
 * `pull-requests: read` permission for this operation.
 */
export async function getPRComments(
  octokit: Octokit,
  context: typeof github.context
): Promise<Array<{ id: number; body: string; user: string; userType: string }>> {
  const { owner, repo } = context.repo;
  const pullNumber = context.payload.pull_request?.number;

  if (!pullNumber) {
    core.debug("No pull request context for fetching comments.");
    return [];
  }

  core.info(`Fetching comments for PR #${pullNumber}`);

  const results: Array<{ id: number; body: string; user: string; userType: string }> = [];

  try {
    const iterator = octokit.paginate.iterator(
      octokit.rest.issues.listComments,
      {
        owner,
        repo,
        issue_number: pullNumber,
        per_page: 30,
      }
    );

    let pageCount = 0;
    const maxPages = 10;

    for await (const { data: comments } of iterator) {
      pageCount++;
      for (const comment of comments) {
        results.push({
          id: comment.id,
          body: comment.body ?? "",
          user: comment.user?.login ?? "unknown",
          userType: comment.user?.type ?? "User",
        });
      }
      if (pageCount >= maxPages) {
        core.info(
          `Reached maximum page limit (${maxPages}) when fetching PR comments. ` +
            "Some older comments may not have been processed."
        );
        break;
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    core.warning(
      `Failed to fetch PR comments: ${message}. ` +
        "Acceptance commands will not be processed."
    );
    return [];
  }

  core.info(`Retrieved ${results.length} comment(s) from PR #${pullNumber}`);
  return results;
}

// ---------------------------------------------------------------------------
// File content retrieval (for context expansion)
// ---------------------------------------------------------------------------

/**
 * Reads a single file from the repository at the PR's head SHA.
 *
 * Uses the GitHub Contents API. Returns the decoded UTF-8 content,
 * or null if the file does not exist or cannot be read.
 *
 * Security: Only reads file content. The GITHUB_TOKEN needs
 * `contents: read` permission for this operation.
 */
export async function getFileContent(
  octokit: Octokit,
  context: typeof github.context,
  filePath: string
): Promise<string | null> {
  const { owner, repo } = context.repo;
  const ref = context.payload.pull_request?.head?.sha || context.sha;

  try {
    const response = await octokit.rest.repos.getContent({
      owner,
      repo,
      path: filePath,
      ref,
    });

    // The Contents API returns an object with a `content` field for files
    // (base64-encoded) and an array for directories.
    const data = response.data;
    if (Array.isArray(data)) {
      // Path points to a directory, not a file
      return null;
    }

    if (!("content" in data) || typeof data.content !== "string") {
      return null;
    }

    // Decode base64 content
    return Buffer.from(data.content, "base64").toString("utf-8");
  } catch (error) {
    // 404 = file doesn't exist at this ref; other errors are also non-fatal
    core.debug(
      `Could not read file ${filePath}: ${error instanceof Error ? error.message : "unknown error"}`
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// Repository file listing (for context expansion)
// ---------------------------------------------------------------------------

/**
 * Lists all file paths in the repository using the Git Trees API
 * with `recursive: true` for efficiency (single API call).
 *
 * Returns an array of file paths (blobs only, no directories).
 *
 * Security: Only reads the tree structure. The GITHUB_TOKEN needs
 * `contents: read` permission for this operation.
 */
export async function listRepoFiles(
  octokit: Octokit,
  context: typeof github.context
): Promise<string[]> {
  const { owner, repo } = context.repo;
  const ref = context.payload.pull_request?.head?.sha || context.sha;

  try {
    const response = await octokit.rest.git.getTree({
      owner,
      repo,
      tree_sha: ref,
      recursive: "true",
    });

    // Filter to blobs only (files, not directories/submodules)
    return response.data.tree
      .filter((item) => item.type === "blob" && item.path)
      .map((item) => item.path as string);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    core.warning(
      `Failed to list repository files: ${message}. Context expansion will be skipped.`
    );
    return [];
  }
}

// ---------------------------------------------------------------------------
// SARIF Upload
// ---------------------------------------------------------------------------

/**
 * Uploads a SARIF report to GitHub Code Scanning.
 *
 * Security: The GITHUB_TOKEN needs `security-events: write` permission.
 * The SARIF payload is gzip-compressed and base64-encoded per the API spec.
 */
export async function uploadSARIF(
  octokit: Octokit,
  context: typeof github.context,
  sarif: object
): Promise<void> {
  const { owner, repo } = context.repo;
  const commitSha =
    context.payload.pull_request?.head?.sha || context.sha;
  const ref =
    context.payload.pull_request?.head?.ref
      ? `refs/heads/${context.payload.pull_request.head.ref}`
      : context.ref;

  core.info(`Uploading SARIF report for commit ${commitSha.substring(0, 7)}`);

  // The code-scanning API expects a gzip+base64 encoded SARIF string.
  // We use Node built-ins to avoid additional dependencies.
  const { gzipSync } = await import("node:zlib");
  const sarifString = JSON.stringify(sarif);
  const compressed = gzipSync(Buffer.from(sarifString, "utf-8"));
  const encoded = compressed.toString("base64");

  try {
    await octokit.rest.codeScanning.uploadSarif({
      owner,
      repo,
      commit_sha: commitSha,
      ref,
      sarif: encoded,
    });

    core.info("SARIF report uploaded to GitHub Code Scanning.");
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    core.warning(
      `Failed to upload SARIF: ${message}. ` +
        "Verify that the GITHUB_TOKEN has 'security-events: write' permission " +
        "and that GitHub Advanced Security is enabled for this repository."
    );
  }
}
