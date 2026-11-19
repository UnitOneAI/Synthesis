import { cweEvidence } from "./cwe-evidence.mjs";
import { securityRegister } from "./security-intelligence.mjs";
import { escapeHtml as e, tokenUsageHtml } from "./system-exports.mjs";

import { PRINT_STYLE as REPORT_STYLE } from "./print-style.mjs";

const field = (label, value) =>
  value
    ? `<h4>${e(label)}</h4><p>${e(typeof value === "string" ? value : JSON.stringify(value))}</p>`
    : "";

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
  const counts = Object.entries(register.counts)
    .map(([k, v]) => `${v} ${k}`)
    .join("; ");
  const review = model.cweModelReview;
  const scanner = model.cweReview;
  const repos = (model.sources || [])
    .map(
      (r) =>
        `<tr><td>${e(r.name)}</td><td>${e(r.snapshot || "not recorded")}</td><td>${e(r.status)}</td></tr>`,
    )
    .join("");
  let html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>CWE and security evidence report</title><style>${REPORT_STYLE}</style></head><body><h1>CWE and security evidence report</h1><p>Static source review · ${e(model.title || model.profile || "Selected repositories")}</p><p class="meta">Generated ${e(new Date().toISOString())} · Revision ${e(model.modelRevision)}</p><h2>Review summary</h2><p>${register.issues.length} candidates: ${e(counts)}. Scanner and model records retain separate identities and can describe the same issue. Counts are not deduplicated vulnerabilities.</p><p>Static evidence does not establish deployed reachability or exploitability. No target code was executed. Missing or changed source is explicitly excluded.</p><p>Scanner: ${e(scanner?.status || "not run")}. Model source review: ${e(review?.status || "not run")}; ${review?.completedBatches || 0} / ${review?.totalBatches || 0} packets completed, ${review?.pendingBatches || 0} pending. Candidate assessment: ${e(register.executionStatus)}. ${review?.gaps?.length || 0} model source coverage gaps.</p><p>${verified} locations include verified code; ${unavailable} unavailable; ${limited} limited by report budgets. Snippet retrieval makes no model calls.</p><ul>${[...(scanner?.limitations || []), ...(review?.limitations || []), ...register.limitations].map((x) => `<li>${e(x)}</li>`).join("")}</ul><h2>Repository snapshots</h2><table><thead><tr><th>Repository</th><th>Snapshot</th><th>Status</th></tr></thead><tbody>${repos}</tbody></table>${tokenUsageHtml(model)}<h2>Finding index</h2><table><thead><tr><th>CWE / type</th><th>Finding</th><th>Origin</th><th>Assessment / disposition</th></tr></thead><tbody>${register.issues.map((i) => `<tr><td>${e(i.cwe || i.kind)}</td><td><a href="#finding-${e(i.id)}">${e(i.title)}</a></td><td>${e(i.origin)}</td><td>${e(i.assessment)} / ${e(i.disposition)}</td></tr>`).join("")}</tbody></table>${articles.join("") || "<p>No candidates recorded. This does not establish absence of weaknesses.</p>"}</body></html>`;
  for (const secret of options.secrets || [])
    if (secret) html = html.split(e(secret)).join("[REDACTED]");
  if (Buffer.byteLength(html) > 24 * 1024 * 1024)
    throw Error(
      "Evidence report exceeds 24 MiB. Export JSON and use individual code evidence instead.",
    );
  return html;
}
