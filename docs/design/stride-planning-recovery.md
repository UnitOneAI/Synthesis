# Reliable STRIDE planning and review reports

## Problem

The JCI screenshots showed a graph-query timeout, a STRIDE attempt that failed before its first checkpoint, historical results, and a prior action with 410 failed packets and more than 25 million reported tokens. A screenshot does not establish that the preview-query timeout caused the review-worker failure, or explain the model validation failures. The small error export is required to distinguish those causes.

## Changes

- UI refresh reads saved plan counts. It never starts a second full planner while the review is preparing or running. Explicit full-plan queries share an in-flight request and cache the successful summary until source generation, revision, architecture, refinement history or failed-attempt inputs change.
- Review workers open the immutable source graph read-only. Traversal and packet scratch tables use SQLite temporary storage instead of committing planner operations individually to the persistent WAL. Review checkpoints remain durable in the workspace.
- Partition oversized scopes before building their packets. Reuse evidence/component indexes, bounded graph-owner caches and compact coverage membership indexes. Preserve packet identity, split decisions, evidence contracts and explicit coverage gaps.
- Progress checkpoints use packet metrics already in memory. They do not reread all pending disk packet payloads or clone every coverage obligation merely to count progress. Active requests still load their own packets lazily.
- Before paid calls, emit planning-started/planning-completed events and elapsed planning time. Small error exports include planning time, invalid-response guard state, saved-review-run failure counts and safe validation-rule classifications, without source or model prose.
- Stop dispatch after three consecutive invalid responses or six invalid responses among the last twelve. Count JSON, evidence/schema and output-limit failures. Let already active requests settle and persist successes, failures and usage. Existing provider/authentication/transport stops remain. Run-until-complete does not override this guard. A human must resolve the error before continuing.

This patch does not change the STRIDE prompt, guidance version or graph extractor. Compatible successful packets remain reusable. Responses already stale because an earlier update changed methodology are not silently promoted to current coverage. Four workers reduce elapsed waiting, not the number of model tokens required for the same packets. No claim is made that these changes guarantee a specific gateway throughput or complete vulnerability detection.

## Shareable report contract

The default threat-model PDF is a current-results report. A successful current checkpoint is required before findings, the result matrix, or linked actor/boundary registers appear. With no successful current checkpoint, show collection scope, run state, failure information and usage; explicitly state that there are no current results. Stale records remain in the workspace and complete exports, but their prose is not printed as current findings.

Current partial results remain exportable. Order scenarios by existing explained review priority, not an invented severity. Start with affected scope, impact and action. Link actors and trust crossings to those scenarios; distinguish inferred access/enforcement from accepted reviewer decisions. Pending means awaiting reviewer confirmation, not a running model call. Architecture-only or metadata-only records become questions requiring implementation evidence. They do not enter the detailed findings count.

Show all current scenarios in the summary and at most twelve in detailed narrative form. Explicitly disclose that detail limit and retain complete records in the HTML/JSON exports. Use source paths and line numbers instead of opaque evidence IDs; omit empty rows and flattened internal objects. The DFD is clearly labeled static context, not evidence that all depicted paths were analyzed. UnitOne branding and the confidentiality notice remain.

## Remaining limits

Static extraction, ambiguous calls, graph traversal bounds and the 50,000-obligation cap remain explicit. The change does not add compiler-level resolution or runtime verification. User decisions about deployment reachability, identity and boundary enforcement cannot be inferred as approved simply because a model returned JSON. The JCI gateway must be checked using its actual error export and a small successful source-backed request before another unattended run.
