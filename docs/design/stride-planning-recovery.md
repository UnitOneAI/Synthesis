# Reliable STRIDE planning and review reports

## Problem

Large portfolio runs exposed preview-query timeouts, review attempts failing before their first checkpoint, historical results presented alongside current scope, and excessive spending on invalid responses. A screenshot does not establish whether a preview timeout caused a review-worker failure. Compact error exports are required to distinguish planning, worker and provider failures.

## Changes

- UI refresh reads saved plan counts. It never starts a second full planner while the review is preparing or running. Explicit full-plan queries share an in-flight request and cache the successful summary until source generation, revision, architecture, refinement history or failed-attempt inputs change.
- Review workers open the immutable source graph read-only. Traversal and packet scratch tables use SQLite temporary storage instead of committing planner operations individually to the persistent WAL. Review checkpoints remain durable in the workspace.
- Partition oversized scopes before building their packets. Reuse evidence/component indexes, bounded graph-owner caches and compact coverage membership indexes. Pure lookup optimizations preserve packet identity and split decisions. Restrict component classification citation IDs to evidence actually submitted in each packet; otherwise repository-wide citation lists inflate context, force excessive splitting and expose ineligible IDs to the model. Repacking this context can change packet IDs, while preserving coverage obligations and explicit gaps.
- Progress checkpoints use packet metrics already in memory. They do not reread all pending disk packet payloads or clone every coverage obligation merely to count progress. Active requests still load their own packets lazily.
- Before paid calls, emit planning-started/planning-completed events and elapsed planning time. Small error exports include planning time, invalid-response guard state, saved-review-run failure counts and safe validation-rule classifications, without source or model prose.
- Stop dispatch after three consecutive invalid responses or six invalid responses among the last twelve. Count JSON, evidence/schema and output-limit failures. Let already active requests settle and persist successes, failures and usage. Existing provider/authentication/transport stops remain. Run-until-complete does not override this guard. A human must resolve the error before continuing.

This patch does not change the STRIDE prompt, guidance version or graph extractor. Successful packets remain reusable when their hashes and review contract still match. The citation-scope correction repacks some scopes, so affected packets must be reviewed under their new context; do not promise zero repeated model work. Before a persistent server starts another STRIDE action, it archives the prior successful review checkpoint under `review-history/stride-<digest>.json`. Identical checkpoints are deduplicated, writes are atomic, and corrupted archives stop the action rather than silently overwriting history. These are historical response archives, not full workspace backups or current coverage. Responses already stale because an earlier update changed methodology are not silently promoted to current coverage. Four workers reduce elapsed waiting, not the number of model tokens required for the same packets. No claim is made that these changes guarantee a specific gateway throughput or complete vulnerability detection.

## Shareable report contract

The default threat-model PDF is a current-results report. A successful current checkpoint is required before findings, the result matrix, or linked actor/boundary registers appear. With no successful current checkpoint, show collection scope, run state, failure information and usage; explicitly state that there are no current results. Stale records remain in the workspace and complete exports, but their prose is not printed as current findings.

Current partial results remain exportable. Order scenarios by existing explained review priority, not an invented severity. Start with affected scope, impact and action. Link actors and trust crossings to those scenarios; distinguish inferred access/enforcement from accepted reviewer decisions. Pending means awaiting reviewer confirmation, not a running model call. Architecture-only or metadata-only records become questions requiring implementation evidence. They do not enter the detailed findings count.

Show all current scenarios in the summary and at most twelve in detailed narrative form. Explicitly disclose that detail limit and retain complete records in the HTML/JSON exports. Use source paths and line numbers instead of opaque evidence IDs; omit empty rows and flattened internal objects. The DFD is clearly labeled static context, not evidence that all depicted paths were analyzed. UnitOne branding and the confidentiality notice remain.

## Remaining limits

Static extraction, ambiguous calls, graph traversal bounds and the 50,000-obligation cap remain explicit. The change does not add compiler-level resolution or runtime verification. User decisions about deployment reachability, identity and boundary enforcement cannot be inferred as approved simply because a model returned JSON. The configured gateway must be checked using its actual error export and a small successful source-backed request before another unattended run.
