# Deployment context and system threat model qualification

Branch: `codex/deployment-system-review`. Static only. No target builds, installers, services or attacks are executed. A completed unit is a validated model response, not proof of deployed control enforcement.

## Required checks

| Behavior | Verification |
| --- | --- |
| Reuse a saved twelve-repository graph without extraction or inference | Source graph unchanged; all repositories represented; five topic assumptions; no mandatory answers. |
| Review system scope before deep code | Connected flow/interface units include workers, stores and controls; deferred interfaces counted separately; no packet-budget omissions in the twelve-repository fixture. |
| Complete a system STRIDE pass | Simulated source-backed model reviews all fixture units, returns cited scenarios, populates actors, boundaries and matrix, exports current results. This is functional qualification, not a live finding. |
| Optional response and resumption | Changing exposure preserves unrelated completed units, stales affected scenarios and recomputes coverage; restart resumes only changed units; unchanged rerun makes zero requests. |
| Distinguish source and deployment | Answers never approve boundaries; profile selection does not prove deployment; changed evidence invalidates saved answers. |
| Configuration artifacts | Reject unsupported/executable content, oversized input and DTDs; save recognized declaration names and hash, not values, credentials or raw filenames. |
| Evidence access | Workspace token required; lookup saved IDs, no arbitrary client path; current code hash required before showing source. |
| Scope switching | System/deep checkpoints survive switching and restart; valid completed results in either scope are reused. |
| Browser flow | Saved graph opens, system scope previews and submits with no answers, cards display source, save an answer, import metadata and survive restart without rebuilding. |
| Existing product behavior | Full backend and browser regressions include source-backed STRIDE, validation guards, continuous/parallel execution, matrix and print exports. |

Local verification: **242 backend tests passed, three conditional scanner tests skipped; 29 browser tests passed, two conditional tests skipped (scanner qualification and the opt-in saved-output fixture).** The full browser suite is rerun after the display changes. Code syntax checks passed. A worker protocol test verifies scope routing and checkpoint preservation before completion.

Files: `packages/static-pilot/test/deployment-context.test.mjs` and `test/browser/deployment-context.spec.mjs`. Run `npm test`, `npm run check`, `npm run test:ui` from the package.

## Open-autofix saved graph benchmark

The qualification graph contains 10,437 interfaces. The prior deep planner produced 844 packets. The system planner produces 219 units covering 1,465 interfaces; 8,972 remain deferred to deep review. Zero system interfaces were omitted by packet-size limits in this benchmark. The smaller plan is a different explicit scope, not a claim to have compressed exhaustive review into equivalent coverage.

The planner records 372 context-gap entries, including additional component controls and mixed supporting/production flow groups. These are not 372 verified vulnerabilities. Context windows and unresolved binding remain bounded. Controls are prioritized before general configuration when composing units, but finding a component control does not establish enforcement on every member interface.

Final live Claude Opus 4.6 qualification completed **3 selected source-backed units with zero failures**, returning **12 conditional scenario records** and **117,652 reported tokens** (106,369 input and 11,283 output). The complete system plan has 219 units, so 216 remain pending in that demonstration. These records may overlap and are not deduplicated confirmed vulnerabilities. A preliminary smaller-group attempt exposed an evidence-ownership validation rejection; the system packet contract now includes an explicit ownership table and focused citation instructions. Local ownership validation remains unchanged. All live attempts retain separate trace and token records; preliminary failures are not counted as successful coverage. The final report is generated from actual successful responses, not the synthetic fixture. Limited live qualification must not be reported as full portfolio completion or qualification of a customer's Azure gateway. Customer-specific source, paths, gateways, reports and raw results are kept outside the public repository.

The report projection also preserves source-associated candidate boundaries for unresolved flow peers, without labeling those flows connected or approved. Four of the twelve live scenario records now retain candidate boundary links; eight retain candidate paths. Resuming the unchanged final review reused all three successful units with **zero new model calls**.

## Remaining limits

Deployment declarations are indexed, not a compiler-level effective configuration model. Profile conflicts are not automatically resolved. Five topic-level optional questions apply to their listed scope; heterogeneous deployments should keep conservative assumptions or select mixed/unknown. No runtime validation occurs. Native Windows behavior is covered by existing CI when the branch is published; local macOS execution alone does not constitute a Windows pass.

## Continuous-review recovery qualification

- Twelve-repository system fixture: an initial transport failure followed by invalid evidence recovers, completes all planned system units, meters both failed attempts and performs zero requests on unchanged resume.
- Transient service failures have a two-retry ceiling; long Retry-After values and HTTP 403 do not loop.
- Cancellation during recovery sends no replacement request.
- An isolated invalid system unit remains failed while later stages run; final status remains partial.
- Provider deadline defaults to 300 seconds and accepts a bounded process setting; a timed test confirms cancellation.
- Diagnostic export identifies system/deep scope and the exact stopping failure rather than the first older invalid response.
- These deterministic provider simulations do not establish live customer gateway throughput or customer scan completion.

Local recovery verification: 248 backend tests passed, three conditional scanner skips; 29 browser tests passed, two conditional skips. Reopening the previously saved live open-autofix system result retained all three completed units with zero provider calls. Its remaining 216 system units were not run by this recovery check. Customer gateway completion has not been verified from the development environment.

## Saved threat validation acceptance tests

- Saved SQLite graph over twelve repositories resolves a named control in another repository; original STRIDE scenarios and coverage remain byte-for-byte unchanged in the engine.
- Hash-matched assessments survive persistence and resume with zero additional provider calls. Changed source or scenario text cannot silently reuse a favorable conclusion.
- An explicit missing control triggers another bounded indexed search and reassessment. Per-action budgets and the three-round ceiling remain enforced.
- HTTP action rejects missing authentication, source consent and invented IDs; successful assessment is checkpointed and leaves STRIDE results intact.
- Architecture-only cells display zero source scenarios and a separate question count; mixed cells retain the source-scenario count and matching status.
- Browser priority cards open the associated threat details. Assessment source consent defaults off. Existing matrix scrolling, actor/boundary navigation and partial PDF export remain regression gates.
- All provider responses in these tests are controlled fixtures, not live security findings. Live saved-source qualification is reported separately.
