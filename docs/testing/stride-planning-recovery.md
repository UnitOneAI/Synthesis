# STRIDE planning recovery verification

## Required checks

1. Compare a saved open-autofix plan before and after the optimization: packet IDs/hashes, split decisions, obligation assignments and gaps must be identical. Do not make provider calls for this benchmark.
2. Exercise a larger disk-backed portfolio, with an explicit count of interfaces, obligations, omitted scope and planner elapsed time. Synthetic scale evidence does not qualify the JCI gateway or establish language coverage on JCI source.
3. Check continuous review stops on repeated JSON, schema/evidence and output-limit failures, including alternating failures. Successful parallel requests settle and usage is retained.
4. Check progress checkpoints do not deserialize every pending packet. Keep active packet retention bounded by worker count. Verify UTF-8 packet size accounting at the exact byte boundary and indexed context equivalence.
5. Confirm saved-graph refresh uses summary metadata rather than creating another planner. Existing graph restart, cache reuse, refinement and invalidation tests must pass.
6. Export reports with no run, failed-before-first-result, current partial results and stale results. Only current successful analysis supplies findings. Architecture-only responses become context questions. Preserve confidentiality branding, linked source locations, reviewer status, partial coverage and usable printing.
7. Run backend and browser suites, including Windows Node 22/24 and Windows browser checks in CI. Local passing tests alone do not qualify Windows.

## Local evidence

Saved open-autofix graph: 10,437 interfaces, 867 planned packets, 18,866 review obligations. Baseline planner at `8c64efb`: 33.3 seconds. Optimized run: 5.1 seconds on the same Mac. Packet hashes, obligation assignments, gaps and split hashes are identical. Measurements are local single-run observations, not an SLA or a JCI VM estimate. No provider requests were made.

Backend suite: 224 passed, 3 conditional scanner tests skipped. Existing qualified Semgrep CI covers scanner-enabled cases. New tests cover invalid-response guard behavior, in-flight preservation, checkpoint read counts, exact UTF-8 sizing, indexed context equivalence, privacy-safe diagnostics and report gating. PDF browser checks pass for unrun and partial-current cases.

A six-page report preview was rendered using the saved November 20 open-autofix response (four scenarios). It is labeled as saved-response layout validation, not a fresh scan. The source data and preview remain outside this public repository. Source code, model output and customer artifacts are not committed.

Fresh JCI error JSON and a successful small JCI gateway review remain necessary to diagnose and qualify that environment. Screenshots do not identify every model validation failure, gateway policy or deployed control.
