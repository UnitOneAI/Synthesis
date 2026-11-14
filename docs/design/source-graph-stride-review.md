# Source graph to STRIDE review

## Product behavior

An analyst supplies existing local clones or GitHub sources, chooses one product profile, and builds a static source graph. Graph construction does not call a model. The analyst reviews the DFD, declares justified connections and authority transitions, then starts bounded model review from a STRIDE matrix. No customer code, build, installer, test, hook or runtime endpoint is executed.

The workflow has five views:

| View | Main decision | Primary action |
| --- | --- | --- |
| Sources | Which repositories and product variant are in scope? | Build source graph |
| Source graph | What was parsed, and where are the gaps? | Review data flows |
| Data flows | Which interfaces connect, and whose authority changes? | Declare connection or export Mermaid |
| STRIDE matrix | Which scenarios and unreviewed areas require attention? | Inspect a cell or continue review |
| Evidence and details | What supports the scenario, and what is still unknown? | Inspect referenced source locally |

## Matrix design

Rows are source components or reviewer-declared flows. Columns are the six named STRIDE categories. Each cell distinguishes AI scenarios from conditional rule prompts. A cell opens the associated scenarios, actor/access assumptions, prerequisites, control uncertainty, mitigation questions and file/line references. The HTML and CSV exports use the same matrix computation as the UI.

Cell states are **not reviewed**, **partially reviewed**, **AI scenarios to review**, **no scenario returned**, and **stale**. No green safe state, false zero-risk implication, or automatic not-applicable determination is introduced. An empty model result is an open review question. Counts are scenarios, not confirmed findings. Interface submission and batch completion are not semantic coverage metrics.

The interactive design proposal uses a compact matrix with a persistent detail panel; data-flow selection opens the corresponding authority transition and related STRIDE context. It uses sample data explicitly labeled illustrative. The shipped pilot supplies functional views, cell drill-down and exports; the proposal's system-zone layout does not imply automatically established runtime trust zones.

## Graph contract

Tree-sitter WebAssembly grammars parse C#, C/C++, JavaScript and TypeScript without target compilation. Nodes represent repositories, files, type/function declarations, call sites, collected security interfaces and dependency declarations. Relationships record containment, declaration, call-site ownership, candidate same-scope call targets, and literal project references to collected local projects.

Graph nodes retain repository, relative path, source offsets/lines and content hashes where applicable. Exact source offsets associate interface candidates with enclosing functions; line-only association is insufficient when several methods occupy one line. Declarations, source-supported call sites and unresolved target bindings remain different concepts. Syntax errors, unsupported languages, parser timeouts and limits are recorded. Method overloading, dependency injection, inherited controls, dynamic dispatch, macros, build conditions and effective identity remain unproven.

The source graph is separate from the architecture DFD. A project reference or call-site candidate must never automatically become a network flow or trust boundary. Reviewer-declared connections retain rationale, endpoint evidence, profile and source fingerprints. A declaration is not authenticated risk acceptance.

## Review pipeline

1. Snapshot and inspect the selected sources under the collection limits.
2. Extract security-interface candidates and structured configuration declarations.
3. Build and fingerprint the syntax graph.
4. Compose reviewer-declared DFD connections and trust transitions.
5. Plan repository batches in repository round-robin order, cross-repository protocol cohorts, and explicit declared-flow endpoint batches.
6. Send each bounded packet with source graph ownership/call context and the applicable evidence. Shared protocol membership is explicitly not proof of a connection.
7. Validate model JSON and evidence references before aggregating scenarios. Deduplicate exact category/interface/title combinations; do not merge distinct scenarios merely because their categories match.
8. Populate the STRIDE matrix and retain failed/pending batch coverage.

Each graph-review packet is at most 60 records and 96 KiB. The user selects 1–100 requests per action, with 12 as the UI default. Requests are sequential, use the configured provider only, and do not automatically retry. Each request retains the existing 120-second and output-size/token limits. Authentication, quota and transport failures stop additional requests in that action. The scheduler stops starting requests after 24 minutes; the worker has a 30-minute guard.

Successful batches are retained in the current local server session. Continue reuses results only when model revision, provider settings, prompt and packet hashes match. Changes to declarations/profile/source graph invalidate incompatible results. Explicit continuation retries failed or pending batches; it does not reread source. Disk changes require rebuilding. Cancellation, timeouts and worker failures preserve completed review checkpoints when available.

## Persistence and exports

Full model JSON contains the graph, threat register, batch provenance and matrix. Additional exports are source graph JSON, a 200-node graph-preview Mermaid file, architecture DFD Mermaid, matrix CSV, SVG review sheets, HTML report and reusable source/declaration manifest. CSV cells are guarded against formula injection; Mermaid labels are sanitized and IDs are generated independently of source labels. Reports contain architectural metadata and possibly model-paraphrased source and should be handled as confidential.

Source snippets are retained only transiently when explicitly selected. They do not appear as raw fields in browser model JSON or report exports. Provider keys remain server-side. No raw provider error body is disclosed. Pending or completed batches are not durable across server restart; exports are review artifacts, not trusted restart checkpoints.

## Qualification and remaining work

The test portfolio contains 12 synthetic repositories and 840 extracted interface records. It verifies partition coverage beyond 120 records, continuation, invalidation, failure retention, no source rescan during staged review, matrix states, source provenance and export safety with mocked provider responses. This is not a large-codebase throughput benchmark or a live model-quality evaluation.

Collection limits remain 20,000 discovered files and 64 MiB of inspected content per repository, with a 1 MiB per-file limit. Interface extraction remains bounded at 100 candidates per file and 2,000 per repository, with a portfolio guard before starting additional extraction after 10,000 candidates. The graph caps at 100,000 nodes and 200,000 edges. These limits must remain visible; increasing them without measuring memory and model cost is not qualification.

Further qualification requires representative customer source sizes, confirmation of unsupported languages/encodings, critical-flow reference cases from a security champion, parser/extraction coverage measurement, runtime and memory measurement, and live gateway review. Compiler-level symbol resolution, configuration-bound endpoint matching, durable checkpoints, richer actor/data-store semantics, automated architecture inference and organization-authenticated review decisions remain separate work.
