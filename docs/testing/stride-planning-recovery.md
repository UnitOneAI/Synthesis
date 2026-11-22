# STRIDE planning recovery verification

## Required checks

1. Compare a saved open-autofix plan before and after the optimization: pure indexing changes must preserve packet IDs/hashes and split decisions. After the citation-scope correction, repacking is expected; obligation identities and gaps must remain intact. Do not make provider calls for this benchmark.
2. Exercise a larger disk-backed portfolio, with an explicit count of interfaces, obligations, omitted scope and planner elapsed time. Synthetic scale evidence does not qualify the customer gateway or establish language coverage on customer source.
3. Check continuous review stops on repeated JSON, schema/evidence and output-limit failures, including alternating failures. Successful parallel requests settle and usage is retained.
4. Check progress checkpoints do not deserialize every pending packet. Keep active packet retention bounded by worker count. Verify UTF-8 packet size accounting at the exact byte boundary and indexed context equivalence.
5. Confirm saved-graph refresh uses summary metadata rather than creating another planner. Existing graph restart, cache reuse, refinement and invalidation tests must pass.
6. Export reports with no run, failed-before-first-result, current partial results and stale results. Only current successful analysis supplies findings. Architecture-only responses become context questions. Preserve confidentiality branding, linked source locations, reviewer status, partial coverage and usable printing.
7. Run backend and browser suites, including Windows Node 22/24 and Windows browser checks in CI. Local passing tests alone do not qualify Windows.

## Local evidence

Saved open-autofix graph: 10,437 interfaces and 18,866 review obligations. Baseline planner at `8c64efb`: 33.3 seconds / 867 packets. Pure indexing optimizations: 5.1 seconds with identical packet hashes, obligation assignments, gaps and splits. The final citation-scope correction: 4.7 seconds / 844 packets, unchanged obligation count and gap hash. Packet identities change where context is repacked.

Synthetic scale fixture: 13 repositories, 208 C# files, 20,800 methods, 41,808 interfaces and 83,837 graph nodes. Before bounding classification citation lists (with the other optimizations already applied): 27,699 packets / 142.8 seconds. After: 2,266 packets / 22.7 seconds. Both retain 50,000 obligations, 1,079 gaps and zero omitted interfaces. Direct before/after coverage comparison also produced identical obligation-identity and coverage-gap hashes. A second optimized run under the review worker’s 768 MB JavaScript heap limit completed in 27.0 seconds. The existing obligation cap is still explicit; this is not complete security coverage. Packet reduction is not a measured token discount, since packet sizes change. These are local observations, not an SLA or customer VM/gateway estimates. No provider calls were made.

Backend suite: 226 passed, 3 conditional scanner tests skipped. Existing qualified Semgrep CI covers scanner-enabled cases. New tests cover invalid-response guard behavior, in-flight preservation, checkpoint read counts, exact UTF-8 sizing, indexed context equivalence, privacy-safe diagnostics, historical-review archive integrity and report gating. Full local browser suite: 28 passed, 2 conditional integration skips. PDF checks include unrun and partial-current cases. Additional invalid-content diagnostics tests pass.

A six-page report preview was rendered using the saved November 20 open-autofix response (four scenarios). It is labeled as saved-response layout validation, not a fresh scan. The source data and preview remain outside this public repository. Source code, model output and customer artifacts are not committed.

Fresh customer error JSON and a successful small customer gateway review remain necessary to diagnose and qualify that environment. Screenshots do not identify every model validation failure, gateway policy or deployed control.
