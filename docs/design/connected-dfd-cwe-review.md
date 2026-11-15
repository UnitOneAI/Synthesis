# Connected DFD and CWE source review

Implemented in static-pilot 0.7.0. This extends the disk graph and security-review workspace; it does not run the target product.

## Product behavior and use cases

A security champion selects existing local clones, builds the source graph, and receives a connected candidate DFD without supplying a connection workbook or architectural documents. The champion inspects evidence and corrects uncertain links. Repository membership alone never establishes a process, connection, trust boundary or attacker capability.

A champion can run two complementary CWE checks on the same scope: a local Semgrep rule scan and model-assisted source review through the configured Claude, enterprise gateway or Gemini provider. Static means that target code is not executed; it does not exclude model analysis. Source review explicitly sends redacted code segments to the configured provider. It does not fall back to a different provider or model.

A reviewer can stop with a small model request budget, inspect returned threat scenarios immediately, and continue later. A budget of one means one model request, not one repository, one STRIDE category or a complete system review. Completed analysis remains visible alongside pending scope.

## Connection discovery

`engine.mjs` extracts literal HTTP routes, client arguments and structured endpoint/resource configuration. `source-graph.mjs` associates these facts with file/function/interface nodes. The disk cache stores them in immutable graph generations. `connection-discovery.mjs` correlates interface nodes from the published generation and projects findings into `system-model.mjs`.

Supported cases include literal HTTP calls and route declarations; single C# controller route prefixes; Next route handlers; local FastAPI router prefixes; simple uniquely resolved same-file HTTP wrappers; configured SQL/URI stores; and literal queue calls with a unique configured broker identity. Queue names and store identities are hashed. Credentials and URL query values are not retained in connection facts.

| Evidence | DFD treatment |
| --- | --- |
| Client/listener origin, method and route agree | Static endpoint match; deployment still unverified |
| Method and route match only one component | Dashed route hypothesis; host identity and mounts require review |
| Several destination components match | Unresolved, with candidate count; no arbitrary choice |
| Configurations reference the same store identity | Shared store candidate with configuration references |
| Literal queue and configured broker identity agree | Producer/queue/consumer candidates; actual broker use requires review |
| Only repository names, protocol or project references agree | No data-flow edge |

Each flow retains source evidence IDs and graph-node IDs. Manual declarations override automatic outgoing candidates for the same source interface. A rebuild recomputes discovery; incompatible cached extraction is invalidated. Existing graph files are reparsed once after the extractor upgrade.

Caller identity boundaries are automatically proposed around HTTP interactions, including when control evidence is missing. Actor profiles include initial-access assumptions and source evidence. These are candidates, not approved boundaries or demonstrated actor access. Confirmed zones still require supported authority information; source component groupings do not prove runtime isolation.

## STRIDE output

The matrix defaults to component rows so returned scenarios remain visible without manual boundary declarations. Flow and boundary rows remain available. Cells count threat scenarios; checklist prompts are available separately in the cell inspector. Partial, unreviewed, stale and no-scenario-returned states remain distinct. A repository progress table shows how many interfaces were submitted successfully. Completed packets do not establish semantic completeness.

## Local CWE scanner

`cwe-scan.mjs` runs qualified Semgrep CE 1.185.0 with the bundled `rules/cwe-v1.json`. The initial 12 rules cover seven CWE classes across C#, Python, JavaScript/TypeScript and C/C++. This small deterministic pack is not described as comprehensive.

The coordinator copies only safely collected files into a private temporary folder. It does not run target scripts, target scanner configuration or hooks. It supplies its own ignore configuration, disables target suppressions, metrics, version checks, remote rule fetching and proprietary engine selection, and does not pass provider keys to the scanner. Cancellation and shutdown terminate the child process tree and clean the staging folder. Abrupt machine termination may leave temporary files for local cleanup.

Results retain rule ID, CWE, repository, file, line range and file hash, with same-file graph/interface references. Raw scanner output and code snippets are not saved. Unsupported languages, collection exclusions, skipped files, parser errors, stale source snapshots, failures and limits are reported separately. Scanner completion describes the selected rules, not absence of vulnerabilities. Local scans consume zero model tokens.

Current guards: 1 MiB collected file limit, 2 GiB staging and 100,000 staged files per repository, 50 MiB scanner output, 10,000 findings, 10-second per-rule/file timeout, 512 MiB scanner memory setting, two scanner workers and a 15-minute repository timeout. Source collector exclusions still apply. The report records limits.

## Model CWE review

`cwe-model.mjs` builds a coverage plan from every safely collected local file, including configuration. The first pass retains segment metadata and hashes, not code. Segments contain up to 80 lines/20 KB with 10-line overlap. Up to eight segments are grouped into a source packet with a 60 KB estimated code budget. Packets containing current Semgrep findings are reviewed first, followed by graph interactions and remaining source. Repositories are interleaved within each priority group. Scanner evidence participates in cache invalidation. Additional packets review discovered interactions using up to four source segments and their evidence basis.

The configured model reviews injection, access control, filesystem, memory/concurrency, cryptography/secrets, deserialization/parsing and outbound/isolation families. These are review obligations and proposed CWE mappings, not a claim that every CWE is covered or that model recall is complete. Findings must cite submitted record IDs and valid file line ranges, include prerequisites, counterevidence and remediation, and use an allowed CWE identifier. Invalid evidence or output is rejected. Severity remains unassessed until review.

A second static read prepares only the next selected packets and verifies file hashes. Redacted code is transient; checkpoints contain packet hashes, findings, coverage and usage, not source segments. Continuation invalidates caches when source revision, model/provider, prompt or planner changes. A request budget is 1–100 calls per action. File planning is capped at 100,000 segments, packets at 96 KB serialized, model findings at 10,000; oversized lines and limited interaction context are explicit gaps. Cross-file and cross-repository context is evidence-assisted review, not compiler-resolved taint analysis.

Provider response usage is recorded before output validation, so failed responses still account for billed tokens where supplied. Unknown usage stays unknown. The existing usage ledger distinguishes `cwe-file`, `cwe-interaction` and STRIDE phases. A local scanner report, model CWE report and STRIDE review have independent completion states.

## Persistence, observability and exports

The existing authenticated loopback server serializes scan/review jobs and checkpoints results. Source changes retain previous results with stale state. CWE decisions record reviewer and rationale; these are local annotations, not authenticated organization approvals.

Exports include local scanner JSON/CSV/SARIF, detailed model CWE JSON, system DFD SVG/Mermaid, STRIDE and architecture registers, usage and diagnostics. The diagnostic bundle adds connection-discovery metadata, normalized CWE scanner results and model CWE coverage/attempt references. It omits model CWE narrative and source segments. Architecture and file metadata remain confidential.

## Remaining gaps

Dynamic configuration, proxy rewrites, multi-router mounts, non-default broker routing, DI and compiler-level cross-file bindings may remain unresolved. Same-file wrapper recognition is deliberately narrow. The DFD remains a candidate static model. Model review can miss weaknesses or produce false positives. Native scanner rules do not cover every language or CWE; model support does not remove that uncertainty. Disk storage does not remove parser, planner, metadata or provider limits.

References: [Semgrep CLI](https://docs.semgrep.dev/cli-reference), [Semgrep ignore behavior](https://docs.semgrep.dev/ignoring-files-folders-code), [CWE mapping guidance](https://cwe.mitre.org/documents/cwe_usage/guidance.html).
