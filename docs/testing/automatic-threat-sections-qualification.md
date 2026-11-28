# Automatic section qualification — 2026-11-28

## Acceptance result

The automatic planner's first section on the existing open-autofix graph completed: **three operations, all six STRIDE categories, six independently challenged supported conditional scenarios, zero completion blockers**. This is a completed static section, not whole-repository clearance or verified runtime exposure.

Section: `open-autofix · analyze/sessions · change · part 1` (`93ed2e0e2ba045d6e41b1eef`). The primary handlers are POST `/sessions`, PATCH `/sessions/{session_id}` and DELETE `/sessions/{session_id}` in `openaf/api/analyze_routes.py`. The reviewed application mounts their router at `/analyze`. Supporting retrieval followed application composition, authentication helpers, request types, storage implementations and application logging. No target code was executed or modified.

The saved graph fingerprint remained `d244d50a8089a338e439ebce111574456dec4d2a4dd0c33067a05875fe21ee80`. The automatic catalog has 1,158 sections covering 1,755 primary subjects; only this first section is claimed complete by this qualification. No operations were hand-picked or removed to obtain completion.

| Category | Operations with cited decisions | Result |
| --- | --- | --- |
| Spoofing | 3/3 | Supported conditional paths |
| Tampering | 3/3 | Supported conditional paths |
| Repudiation | 3/3 | Supported conditional application-audit path |
| Information Disclosure | 3/3 | No scenario identified in reviewed scope |
| Denial of Service | 3/3 | Supported conditional resource-exhaustion path |
| Elevation of Privilege | 3/3 | Supported conditional privileged-write paths |

The six scenario records cover unauthenticated session creation, unauthorized mutation, cascading deletion, arbitrary configuration persistence/data pollution, unbounded session creation and missing caller attribution in application logs. These are not six deduplicated vulnerabilities. Shared access-control causes appear in several consequences. Speculative RCE/SSRF impacts were narrowed away where the source did not establish them. External access, intended ownership policy and effective compensating deployment controls remain explicit conditions.

The generated 20-page PDF has a scope and matrix, decision summary, engineering conclusions, actor-to-operation evidence, controls/counterevidence, remediation, code excerpts, deployment questions and category evidence. It was regenerated from the saved result using current-source hash checks. Source changes or unavailable source prevent the complete headline. The actual PDF was shown in the task before main merge.

## Cost and reproducibility

Provider: direct Anthropic `claude-opus-4-6`, native structured outputs, existing graph, two bounded workers. This qualification was resumed during development and includes failed/corrected attempts. It is **not** a clean latency or cost benchmark.

- Cumulative completed qualification: **92 provider attempts, 2,942,727 reported tokens, one request with unknown usage**.
- Final continuation: six calls, 195,604 reported tokens, 433 seconds. This is not the total cost or duration of the section.
- Separate fresh-run trials are accounted separately; their costs must not be hidden in comparisons.
- No percentage token/time savings are claimed. The implemented benefit demonstrated here is independent section completion and reuse, with bounded retrieval and honest coverage.

## Verification

Local complete regression suite: 359 tests; **356 passed, zero failed, three scanner-dependent skips**. Browser suite: **36 passed**, three environment-dependent skips. Focused automatic-section tests pass. GitHub checks run Node 22/24 on Windows, macOS and Ubuntu, browser tests on Windows/Ubuntu, and real Semgrep checks on Windows/Ubuntu. All checks must pass at the merge head.

Tests cover exact scope partitioning, all-six-category closure, no false completion, interrupted/resumed checkpoints, no-paid-call reuse, changed-source export refusal, stale/corrupt citations, independent positive challenges, retained-case/category digests, explicit reopening on counterevidence, deployment assumptions versus code-bound configuration, provider failure and bounded invalid-response recovery. Existing STRIDE/CWE tests remain required.

## Qualification limits

JCI's Windows machine and gateway were not available to this local live run. Cross-platform tests are not a claim that the JCI gateway has been live-tested. A 403 or unsupported provider option must stop dispatch; it cannot be repaired by spending more model calls. The existing workspace checkpoint size limit still applies. Genuine missing implementations or unresolved bindings remain blocked and cannot be labeled complete. Other independent sections continue without a confirmation step.

The known failure modes from the previous workflow are recorded in the design acceptance criteria and regression tests. No claim is made that feedback was submitted to OpenAI's internal product team.
