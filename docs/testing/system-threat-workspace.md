# System threat workspace: functional test specification

Version: static pilot 0.4.1. This is the acceptance contract for the local Windows/macOS/Linux application, with an explicit distinction between deterministic product verification and customer-source qualification.

## Automated acceptance cases

Run `npm run check`, `npm test`, then `npx playwright install chromium` and `npm run test:ui` from `packages/static-pilot`. Tests use synthetic inputs and mocked provider responses unless a live qualification run is explicitly selected. The CI matrix runs Node 22/24 on Windows, Linux and macOS, plus Chromium functional tests on Windows and Linux.

| ID | Requirement and expected result | Executable evidence |
| --- | --- | --- |
| SRC-01 | Select local clones or GitHub sources; missing/unsupported/truncated scope remains visible; no target execution | `pilot.test.mjs`, `source-graph.test.mjs` |
| SRC-02 | C#, C/C++, JS, TS and Python syntax owners/calls retain evidence; comments/docstrings do not become Python routes | `source-graph.test.mjs` |
| SYS-01 | Initial system model preserves unknown endpoints, separates external entities and actor assumptions, never equates repo and trust boundary | `system-workspace.test.mjs`: system projection |
| SYS-02 | Components map across repositories with stable identity; conflicting interface ownership is rejected | component mappings test; browser component editor |
| SYS-03 | Whole system, context and focused diagrams share IDs; all six trust lenses render; actor overlay is explicitly conditional | browser DFD test; export and conditional-path tests |
| SYS-04 | Nested same-lens domains render in SVG and Mermaid; cycles and invalid dimensions fail | architecture validation and nested zones tests |
| ACT-01 | Actor CRUD retains initial access, objectives, exclusions and entry points across restart | browser actor/boundary/domain test |
| BND-01 | Boundary requires distinct authority contexts, dimension, valid flow references; reviewer/rationale survive restart | architecture validation; browser boundary decision test |
| CTL-01 | Control declarations and reviewer controls retain evidence, linked threats and counterevidence; referenced controls cannot be deleted | linked controls test; browser control editor |
| THR-01 | Flow and threat editors link actual actors, assets, controls, interfaces and boundaries; invalid references fail | architecture validation; browser linked records test |
| STR-01 | Component/flow/boundary rows expose all six categories; scenarios and checklist items remain separate | projection, matrix-state and browser STRIDE tests |
| STR-02 | Empty results do not mean safe; reviewed-no-scenario requires an empty cell and explicit reviewer/rationale | matrix-state test |
| STR-03 | Matrix → scenario → inspector → DFD selection retains evidence and assumptions; actor filtering preserves scope | browser DFD and STRIDE tests |
| MOD-01 | Bounded review packets contain graph/architecture context; declared interactions get endpoint review; 12-repository scheduling includes every eligible record | source graph portfolio test; conditional paths/packet test |
| MOD-03 | Explicit continuation retries failed validation batches with stricter instructions, retaining successful batches and bounded requests | source graph validation-retry test |
| MOD-04 | The matrix submits the chosen request budget; Stop preserves completed work and does not rescan sources | browser analysis controls test; worker cancellation test |
| MOD-02 | Strict JSON and evidence validation rejects invented IDs, malformed/truncated output and unsafe redirects; gateway sends exact model/header configuration | `model-review.test.mjs`, `source-graph.test.mjs` |
| REV-01 | Review annotations preserve claim basis and capture disposition, owner, severity, reviewer and rationale; source changes mark decisions stale | review-decision staleness test |
| REV-02 | Concurrent edits fail revision guard; referenced deletions fail rather than orphaning live records | architecture validation and server integration |
| SAV-01 | Atomic local snapshot restores exact model; corrupted snapshot and concurrent writer are rejected; credentials/access tokens excluded | durable store and server restart tests |
| SAV-02 | Completed model batches survive restart; continuing does not repeat compatible completed requests | persisted batch continuation test |
| SAV-03 | Rebuilding retains reviewer declarations; interrupted review preserves completed work, including later cached batches, and can continue | server rebuild test; worker cancellation test; retry checkpoint test |
| EXP-01 | Every advertised export downloads and preserves complete scope, stable IDs, uncertainty and dispositions | browser export loop; export unit tests; server export routes |
| EXP-02 | HTML/SVG escape untrusted labels, CSV neutralizes formula prefixes, Mermaid sanitizes text; no AI-branded findings | export tests; existing security tests |
| USG-01 | Failed/invalid responses retain provider usage; input/cache totals do not double count; missing usage stays unknown | `token-usage.test.mjs` |
| USG-02 | Retries retain prior attempts; shared requests count once; cache reuse adds zero tokens | token accounting continuation test |
| USG-03 | In-flight attempts checkpoint before dispatch; cancellation/rebuild/restart preserve the ledger | staged worker and token persistence tests |
| USG-04 | Live meter, unknown history, scope breakdown, CSV/JSON/HTML exports remain consistent | browser token meter and export tests; token report tests |
| UX-01 | Keyboard-selectable diagram objects, labeled controls, narrow layout without page overflow; no script/CSP errors | browser DFD and per-test console assertions |

The HTML report supports browser Print → Save as PDF. Native PDF pagination and visual equivalence across every printer are not asserted by the automated suite. PDF output requires a quick visual check of the chosen scope.

## Live repository qualification procedure

Use a read-only clone and keep evidence outside the public checkout:

1. Record repository URL, commit, dirty working-tree status, source configuration, tool commit/version and provider/model. Hashes represent the inspected working tree, not only HEAD.
2. Build from the UI; verify selected repository count and collection/parse coverage against the exported model. Inspect at least one Python and one TypeScript interface where applicable.
3. Inspect context/system/focused views, actor initial access and candidate boundary uncertainty. The initial source grouping is not a reviewed deployment architecture.
4. Run the configured provider with metadata only or explicitly selected excerpts. Record completed/failed/pending batches, reviewed interface IDs and validation errors. Do not substitute mocked responses for a live result.
5. Export the model, HTML, DFD and registers. Reconcile counts/IDs. Review sample scenarios against their cited source; structured validation alone does not establish threat quality.
6. Stop/restart; compare revision and completed batches. Continue any incomplete work. Inspect the report and narrow UI layout visually.
7. Capture screenshots and a private qualification record. Do not commit source-derived threat details or customer endpoints to the public repository.

## Limits of acceptance

The synthetic 12-repository case verifies scheduling and recovery, not performance or semantic completeness on twelve large customer repositories. Qualification on the actual selected customer clones still requires their files, coverage inspection, critical-flow reference cases and security-champion review. Gateway protocol mocks do not establish access from a customer Windows host.

Collectors are bounded and framework-specific. They do not perform compiler-wide call resolution, evaluate every deployment conditional, automatically prove cross-repository endpoints, or verify runtime reachability/enforcement. The system records declarations and unresolved references so reviewers can supply the architecture supported by the available source. No runtime tests or probes are part of this workflow.


## Recursive review and diagnostics (0.5.0)

| ID | Acceptance | Automated evidence |
| --- | --- | --- |
| COV-01 | Traverse multi-hop candidate calls, terminate cycles, keep source-supported path context, never invent runtime flows | `diagnostics.test.mjs` recursive planner |
| COV-02 | Do not count endpoints in different requests as a covered relationship; keep packets within byte/record limits | Recursive planner + 12-repository source graph tests |
| COV-03 | Stream local files beyond old aggregate bounds, retain project ownership and all lexical candidates including same-line occurrences | Streamed collection test |
| COV-04 | Extract 10,200 interfaces across all 12 synthetic clones without portfolio cutoff | Portfolio test |
| COV-05 | After repeated invalid output, refine pending scopes; restart reuses successful children with zero extra requests | Recursive refinement test |
| OBS-01 | Correlate provider request IDs, attempts, response failure, token usage and cache reuse | Durable trace test |
| OBS-02 | Exclude active credentials, access tokens, raw excerpts, prompts, endpoint URLs and response prose; verify ZIP hashes | Privacy/integrity test |
| OBS-03 | Export without a completed snapshot, preserve valid lines after interruption, reject trace output in source root | Trace recovery test |
| OBS-04 | Require local access token for ZIP; retain disk traces after restart/close | Diagnostic server test |
| OBS-05 | Show separate coverage counts and download a valid ZIP through the UI | Browser diagnostic test |
| OBS-06 | Invalidate successful obligation counts after model revision becomes stale | Durable trace test |
| OBS-07 | Save the static graph before combined inference; checkpoint usage before rejecting output; do not dispatch when required tracing fails | Combined scan test |
| OBS-08 | Retain every inspected file in the graph ledger when graph resource limits are reached | Graph resource test |
| UX-05 | Wait for a pending save before opening another editor; delayed responses cannot replace a new draft | Delayed-save browser test |

Real qualification remains source-only against the operator-selected repository. Record source revision, inspected files/bytes, graph nodes/edges, parser statuses, worklist size, gap categories, token totals and observed provider errors. Synthetic scale tests establish collector/scheduler behavior, not complete language/framework semantics or live gateway qualification.
