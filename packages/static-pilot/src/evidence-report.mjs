import { cweEvidence } from "./cwe-evidence.mjs";
import { securityRegister } from "./security-intelligence.mjs";
import { escapeHtml as e, tokenUsageHtml } from "./system-exports.mjs";

import {
  PRINT_STYLE as REPORT_STYLE,
  PRINT_HEADER,
  PRINT_FOOTER,
} from "./print-style.mjs";

const field = (label, value) =>
  value
    ? `<h4>${e(label)}</h4><p>${e(typeof value === "string" ? value : JSON.stringify(value))}</p>`
    : "";

function cweSummary(issues) {
  const groups = new Map();
  const repositories = new Set();
  for (const issue of issues) {
    const key = issue.cwe || "No CWE mapping";
    if (!groups.has(key))
      groups.set(key, {
        cwe: key,
        candidates: 0,
        scanner: 0,
        model: 0,
        repositories: new Set(),
      });
    const group = groups.get(key);
    group.candidates++;
    if (issue.origin === "scanner") group.scanner++;
    else group.model++;
    for (const location of issue.locations || []) {
      if (!location.repository) continue;
      group.repositories.add(location.repository);
      repositories.add(location.repository);
    }
  }
  const rows = [...groups.values()].sort(
    (a, b) =>
      b.candidates - a.candidates ||
      a.cwe.localeCompare(b.cwe, "en", { numeric: true }),
  );
  const cells = (label, total, scanner, model, repos) =>
    `<tr><td>${e(label)}</td><td>${total}</td><td>${scanner}</td><td>${model}</td><td>${repos}</td></tr>`;
  return `<h2>CWE summary</h2><p>Grouped by recorded CWE. Repository counts are distinct within each row. Counts describe candidate records, not confirmed vulnerabilities.</p><table class="cwe-summary"><thead><tr><th>CWE</th><th>Candidate records</th><th>Scanner</th><th>Model</th><th>Repositories</th></tr></thead><tbody>${rows.map((r) => cells(r.cwe, r.candidates, r.scanner, r.model, r.repositories.size)).join("")}${cells(
    "Total",
    issues.length,
    rows.reduce((n, r) => n + r.scanner, 0),
    rows.reduce((n, r) => n + r.model, 0),
    repositories.size,
  )}</tbody></table>`;
}

// Source text is retrieved only from saved finding IDs through the existing hash,
// selection, containment, symlink and redaction checks. No model calls or target execution.
export async function cweEvidenceReport(model, manifest, root, options = {}) {
  const register = securityRegister(model);
  let remainingWindows = 1000,
    remainingCharacters = 4 * 1024 * 1024;
  let verified = 0,
    unavailable = 0,
    limited = 0;
  const articles = [];
  for (const issue of register.issues) {
    const report =
      issue.origin === "scanner" ? model.cweReview : model.cweModelReview;
    const original = report.findings.find((f) => f.id === issue.sourceId);
    const locations = [];
    for (const [index, ref] of issue.locations.entries()) {
      let code = "",
        gap = "",
        more = false;
      for (let page = 0; page < 4; page++) {
        if (remainingWindows <= 0 || remainingCharacters <= 0) {
          gap =
            "Report source budget reached; this location is not fully included. Open code evidence in the workspace.";
          limited++;
          break;
        }
        remainingWindows--;
        try {
          const window = await cweEvidence(model, manifest, root, {
            origin: issue.origin,
            id: issue.sourceId,
            location: index,
            page,
            modelRevision: model.modelRevision,
          });
          const lines = window.lines.filter(
            (l) =>
              l.line >= window.citedStart - 3 && l.line <= window.citedEnd + 3,
          );
          const chars = lines.reduce(
            (n, l) => n + Buffer.byteLength(l.text, "utf8"),
            0,
          );
          if (chars > remainingCharacters) {
            gap =
              "Report source budget reached; code omitted for this location.";
            limited++;
            break;
          }
          remainingCharacters -= chars;
          code += lines
            .map(
              (l) =>
                `<span class="code-line${l.line >= window.citedStart && l.line <= window.citedEnd ? " cited" : ""}"><span class="line-no">${l.line}</span>${e(l.text)}</span>`,
            )
            .join("");
          more = window.hasMore;
          if (!more) break;
        } catch (error) {
          code = "";
          gap = error.message;
          unavailable++;
          break;
        }
      }
      if (code) verified++;
      if (more && !gap) {
        gap =
          "Cited range continues beyond the four included code windows. Open code evidence in the workspace for remaining lines.";
        limited++;
      }
      locations.push(
        `<section><h4>${e(ref.repository)} / ${e(ref.path)}:${e(ref.line)}-${e(ref.endLine || ref.line)}</h4><p class="meta">Source scope: ${e(ref.sourceScope || "unknown")} · SHA-256: ${e(ref.blobSha256 || "not recorded")}</p>${code ? `<p class="meta">Source hash verified. Highlighted lines are cited evidence; surrounding lines provide context. Recognized secrets are redacted.</p><pre><code>${code}</code></pre>` : ""}${gap ? `<p class="gap">${e(gap)}</p>` : ""}</section>`,
      );
    }
    articles.push(
      `<article id="finding-${e(issue.id)}"><h2>${e(issue.cwe || "No CWE mapping")} - ${e(issue.title)}</h2><p class="meta">Finding ${e(issue.sourceId)} · Origin: ${e(issue.origin)} · Type: ${e(issue.kind)}<br>Disposition: ${e(issue.disposition)} · Evidence assessment: ${e(issue.assessment)}${issue.stale ? " · STALE SOURCE REVIEW" : ""}</p>${field("Finding", issue.explanation)}${field("Prerequisites", issue.preconditions)}${field("Counterevidence", original.counterEvidence || issue.investigation?.counterEvidence)}${field("Recommended remediation", original.remediation || original.recommendation || issue.investigation?.remediation)}${field("Reviewer decision", issue.review)}${field("Evidence assessment", issue.investigation)}${locations.join("")}</article>`,
    );
  }
  const review = model.cweModelReview;
  const scanner = model.cweReview;
  const repos = (model.sources || [])
    .map(
      (r) =>
        `<tr><td>${e(r.name)}</td><td>${/^[a-f0-9]{64}$/i.test(r.snapshot || "") ? e(r.snapshot.slice(0, 32)) + "<br>" + e(r.snapshot.slice(32)) : e(r.snapshot || "not recorded")}</td><td>${e(r.status)}</td></tr>`,
    )
    .join("");
  // Presentation-only omissions requested for the shareable report. The source
  // reports, target coverage and diagnostics keep their original limitations.
  const omittedLimitations = new Set([
    "Community Edition does not provide compiler-level cross-file or cross-repository taint resolution.",
    "Requested CWE coverage and STRIDE review remain separate scope obligations.",
  ]);
  const limitations = [
    ...(scanner?.limitations || []),
    ...(review?.limitations || []),
    ...register.limitations,
  ].filter((value) => !omittedLimitations.has(value));
  let html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>CWE and security evidence report</title><style>${REPORT_STYLE}</style></head><body>${PRINT_HEADER}<h1>CWE and security evidence report</h1><p>Static source review · ${e(model.title || model.profile || "Selected repositories")}</p><h2>Review summary</h2><p>${register.issues.length} candidates. Counts are not deduplicated vulnerabilities.</p><p>Static evidence does not establish deployed reachability or exploitability. No target code was executed.</p><p>${verified} locations include verified code; ${unavailable} unavailable; ${limited} limited by report budgets. Snippet retrieval makes no model calls.</p><ul>${limitations.map((x) => `<li>${e(x)}</li>`).join("")}</ul>${cweSummary(register.issues)}<h2>Repository snapshots</h2><table class="snapshot-table"><thead><tr><th>Repository</th><th>Snapshot</th><th>Status</th></tr></thead><tbody>${repos}</tbody></table>${tokenUsageHtml(model)}${articles.join("") || "<p>No candidates recorded. This does not establish absence of weaknesses.</p>"}${PRINT_FOOTER}</body></html>`;
  for (const secret of options.secrets || [])
    if (secret) html = html.split(e(secret)).join("[REDACTED]");
  if (Buffer.byteLength(html) > 24 * 1024 * 1024)
    throw Error(
      "Evidence report exceeds 24 MiB. Export JSON and use individual code evidence instead.",
    );
  return html;
}
