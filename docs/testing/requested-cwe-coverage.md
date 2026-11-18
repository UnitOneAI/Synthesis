# Requested CWE coverage verification

## Acceptance checks

1. Catalog preserves 29 requested areas and 52 original identifiers, with 25 explicit code-review targets and four additional-evidence areas. Grouping/deprecated IDs cannot be returned as vulnerability mappings.
2. Every bundled Semgrep rule matches its positive fixture and none matches the safe alternatives. All original detections remain; 12-repository scanner coverage and evidence hashes remain valid.
3. Model responses missing any target assessment, duplicating targets, using unknown status/IDs or citing absent/out-of-range evidence fail validation. Cross-repository packets require citations from each repository.
4. Model findings must map to precise allowed CWEs and compatible explicit targets. Additional findings remain valid. A broad shared CWE must not inflate unrelated target counts.
5. Budget continuation retains completed assessments, findings and token usage. A new profile invalidates previous packet completion while preserving current-source findings. Source changes reject review until rebuilding.
6. Internal worker/storage evidence appears in model interaction packets. Unresolved graph relationships and source collection gaps keep coverage partial.
7. Coverage cannot be inferred from scanner success, a prior profile or an empty finding list. It distinguishes unrun, stale, partial, missing context, collected scope and external evidence requirements.
8. UI shows 29 target rows per selected repository, allows filtering, and exports complete JSON/CSV with correct filenames. Export before scanning works. CSV values cannot introduce spreadsheet formulas.
9. Diagnostic bundles retain coverage metadata while omitting model assessment prose and raw source. Small errors retain compact profile/status counts.
10. Scan the real local open-autofix checkout without building or executing it. Inspect DFD and target-coverage UI; distinguish fixture findings from production candidates. Do not claim an actual customer run from synthetic tests.

## Commands

From `packages/static-pilot`, run `npm run check`, `npm test`, and `npm run test:ui`. Set `SYNTHESIS_TEST_SEMGREP` to the qualified Semgrep executable to enable real-engine tests. Install Playwright Chromium for browser testing if needed. Unit tests exercise model transport using controlled responses; they do not measure a live model's detection accuracy.

CI includes Windows/Linux/macOS unit jobs and Windows/Linux browser and real-Semgrep jobs. A local macOS pass is not a Windows execution result; inspect CI before using a review build for VM qualification.

## Local qualification, 17 November 2026

The real open-autofix checkout yielded 505 inspected files. Semgrep scanned all 457 eligible source files with 22 rules and returned three CWE-89 candidates, all under test fixtures. No scanner errors or skipped scanner files were reported; the overall status remains partial because the collector excluded one oversized file. Unsupported and deliberately excluded files remain reported. These results do not establish that the production code is free of the requested weaknesses.

The actual default DFD had 13 visible objects, 15 grouped connections and 174 represented underlying flows. Internal workers/storage appear; unresolved relationships remain explicit. The qualification run made no model calls and executed no target code. Actual customer clones and gateway credentials were unavailable locally; those checks must run in the customer environment. Private output artifacts are kept outside this public repository.
