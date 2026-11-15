# Recursive static review and portable diagnostics

Status: implemented in static-pilot 0.5.0, with the limitations below. Supersedes the fixed candidate cutoffs in the 0.4 source-graph design. The scope is source-only analysis; neither collection nor validation runs target builds, installers, tests or services.

## Problem and acceptance criteria

A completed request is not a completed threat model. A repository may have unreadable files, unsupported formats, unresolved call targets, unreviewed interfaces or declared relationships whose endpoints were split into different requests. The operator needs to distinguish these conditions and carry enough evidence from an isolated Windows environment to diagnose failures elsewhere.

1. Do not stop local interface extraction merely because an earlier repository consumed an aggregate quota.
2. Recursively subdivide large review scopes, preserve all collected interface obligations, and explicitly co-review supported relationships cut by a partition.
3. Traverse candidate calls beyond direct neighbors; terminate on cycles and disclose traversal limits.
4. Keep actor access assumptions, trust-boundary declarations and source evidence separate. Source graphs and protocol matches must never silently create DFD flows.
5. Persist a correlated event trail outside source repositories. Capture stage, request, response shape, token usage, failure category and checkpoint outcome without recording prompts, raw source or model-response prose.
6. Export a single inspectable ZIP, including after a failure before the first completed model. Retain successful review batches across continuation and restart.

## Collection and graph design

Local analysis discovers project ownership paths, then streams one eligible file at a time into lexical extraction and syntax parsing. It does not retain an entire repository's text. The former local 20,000-entry / 64 MiB aggregate collection bounds and 100-per-file / 2,000-per-repository / 10,000-portfolio candidate cutoffs no longer apply to the analysis path. Candidates on the same source line have distinct offset-based identities.

The 1 MiB file limit, excluded dependency/build/credential directories and nonregular-file rejection still apply. Excluded directory descendants are not enumerated. GitHub archives retain their compressed/expanded, file-count and inspected-byte limits; use local clones for larger portfolios. Keep clones stationary: snapshots are working-tree hashes, not atomic filesystem snapshots.

The retained syntax graph still has 100,000-node, 200,000-edge and 5,000-emitted-node-per-file limits, plus parser time limits. Every inspected file skipped by the graph limit receives a file-ledger entry. Interface extraction continues independently of graph truncation. Graph-free interfaces remain reviewable but have explicit missing-graph obligations. The UI worker retains its 768 MiB heap and 30-minute wall-clock limits; checkpoint snapshots retain their 180 MiB limit.

These safeguards are not a claim of unlimited codebase support. Full disk-backed syntax-graph shards, compiler-aware cross-file resolution and out-of-core traversal are **not implemented**. The diagnostic ledger identifies when they are required. A run reaching a graph or process limit cannot be described as full graph coverage.

The proposed [disk-backed static graph architecture](disk-backed-static-graph.md) specifies persistent graph storage, incremental resolution, disk-backed traversal, streaming exports, delivery gates and single-VM deployment. It is a future implementation contract, not a change to the limits above.

## Recursive review worklist

The planner is deterministic for a source/system revision, packet content and planner version. Generated scenarios and actor proposals are outputs; they do not recursively expand source inputs.

- Create an obligation for each collected interface.
- Group interfaces sharing a callable, bringing nearby controls into the review.
- Traverse unique same-file candidate call targets using a queue and visited-function set. This is recursive graph exploration without dependence on the JavaScript call stack. Record one shortest candidate path per reachable interface pair, with graph-node references and source locations. It does not enumerate all execution paths or resolve dynamic dispatch.
- Add obligations for explicit endpoint bindings, represented system flows, actor access and boundary crossings. Rejected/stale/unresolved flows do not establish active paths. Missing source references remain gaps.
- Group neighborhood obligations and recursively bisect packets until both the 60-record and 96 KiB limits hold. Preserve repository round-robin coverage and cross-repository protocol cohorts.
- After partitioning, create focused bridge requests for obligations whose endpoints/context were separated. An obligation with no fitting atomic packet is blocked, never counted as covered by separate endpoint reviews.
- Record partition depth, reason, packet hash, interface IDs and obligation-to-batch mappings. Bound traversal to 4,096 visited functions per root and worklist to 50,000 obligations, with explicit limit records. No unresolved target is guessed into a data-flow edge.

`reviewed` means that one successful, schema-validated response received the required records and relationship context together. It does not mean that every applicable STRIDE scenario was returned, that a control is effective or that a reviewer accepted the conclusion. The interface, callable, path, flow, actor and boundary counts are separate.

Continuation reuses compatible completed batches. Failed JSON/evidence responses receive stricter validation instructions on explicit retry. After two invalid format/evidence/output-limit responses on the same packet, continuation recursively subdivides non-atomic scopes (more than two records), preserving the parent/child tree and successful children across restarts. Refinement stops at six levels; atomic relationship requests and remaining failures stay visible. No automatic provider fallback, model substitution or unlimited retries are introduced. Request budgets and the 24-minute review-action deadline still apply. A changed planner/prompt version invalidates old review caches; previous token expenditure stays in the usage ledger.

## Observability contract

Trace location defaults to `<workspace>/traces` for the server and `<output>/traces` for CLI analysis. `--trace-dir` selects another directory outside the source root. Files are newline-delimited JSON with schema version, session UUID, monotonically increasing session sequence, timestamp and process RSS. Trace segments rotate at 8 MiB; old segments are not deleted automatically.

| Stage | Events and diagnostic evidence |
| --- | --- |
| Session / job | Application version, module fingerprint, Node/platform/architecture; job ID; start, restore, cancel, failure and close |
| Collection | Repository start, snapshot digest, inspected bytes/files, unavailable source, aggregate completion |
| Parsing | File start/completion, relative path and blob hash, parse status, symbol/call counts; last started file survives worker loss |
| Planning | Source revision, graph fingerprint, run key, request budget, batch/obligation/gap/split counts; complete plan in bundle |
| Model request | Attempt and batch IDs, phase, packet hash/bytes, record count, configured provider/model, retry state |
| Provider response | HTTP status; allowlisted request IDs; recognized stop reason; normalized usage before JSON/evidence validation |
| Completion / failure | Response and prompt hashes; structured failure category/action; cache reuse; budget/deadline stop reason |
| Persistence | Checkpoint success/failure; worker trace acknowledgement only after append and file synchronization |

HTTP policy failures, transport/timeout failures, invalid response format, invalid evidence, output limits, checkpoint failures, resource failures and interruption have distinct diagnostic codes. Error bodies and arbitrary network exception strings are excluded. Missing usage remains unknown. Requests stopped in flight may have incurred provider charges even if no usage was returned.

Traces and checkpoint acknowledgements are awaited before dispatch. Failure to write required traces stops work rather than silently continuing unobservable requests. A diagnostic export does not require a completed model. The trace writer is in the parent process, so worker termination leaves preceding events on disk. A hard OS/disk failure can still lose an unfinished final line; export reports invalid trailing lines.

## Portable diagnostic bundle

| File | Purpose |
| --- | --- |
| `summary.json` | Build/runtime identity, model deployment ID, endpoint hash (not URL), known limits, token totals and limitations |
| `coverage.json` | Source inventory and per-file ledger, parser ledger, extraction diagnostics, obligation status and unresolved references |
| `source-graph.json` | Retained syntax graph, fingerprint, limits and coverage; not an unlimited or runtime graph |
| `review-plan.json` | Recursive splits, packet metadata, obligation-to-batch mapping and blocked work; no prompts |
| `attempts.json` | Metered attempts and batch outcomes; failure classification; no generated scenario prose |
| `token-usage.csv` | Full request ledger, including retries, failed output, shared requests and unknown totals |
| `trace.ndjson` / `trace-index.json` | Durable events, included segments, omitted segments and malformed-line counts |
| `manifest.json` | SHA-256 and byte count for every other entry; corruption checking, not an authenticity signature |
| `README.txt` | Interpretation and handling instructions |

Export includes the newest trace segments up to 64 MiB; the index lists omissions and all segments remain on disk. No secrets, endpoint URLs, source excerpts, prompts, response prose or absolute source root are intentionally included. Known active credentials and local roots are scrubbed and arbitrary response bodies are never captured. Repository paths, symbol names, deployment identifiers, hashes and graph relationships remain confidential architecture metadata; redaction is not a general data-loss-prevention guarantee. Inspect the ZIP before sharing it.

The server exposes an authenticated download before or after analysis. The CLI can produce a bundle from the atomic workspace snapshot and trace directory without needing a model API key or a running server. Export is a local file operation; Synthesis never sends diagnostics anywhere automatically.

## Functional verification

`test/diagnostics.test.mjs` covers transitive traversal/cycles, partition coverage, source streaming beyond aggregate cutoffs, more than 10,000 candidates across 12 repositories, same-line identities, provider correlation and failure usage, cache reuse, stale coverage, ZIP hashes/privacy, recovery with no model/partial trace lines, and authenticated exports. Existing worker/cancel/restart tests remain required. Browser checks cover the coverage panel and actual ZIP download. A read-only `open-autofix` qualification records real counts separately from the synthetic scale test.

A direct Opus validation does not qualify a customer's gateway, quotas or deployment-specific context limit. That requires a request through their environment. The bundle is the evidence for diagnosing that run without access to their runtime systems.
