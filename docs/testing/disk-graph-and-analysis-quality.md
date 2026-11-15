# Disk graph and analysis quality acceptance

Scope: static-pilot 0.6.0. These checks distinguish storage capacity, evidence submission and threat-model quality. A large stored graph or schema-valid response is not a complete threat assessment.

| ID | Required outcome | Automated evidence |
| --- | --- | --- |
| DISK-01 | Stored nodes/edges export completely, with valid endpoints and indexed pages | `graph-store.test.mjs`: graph export and HTTP tests |
| DISK-02 | An unchanged scan reparses no files; deleted targets disappear only from the new generation | Cache and deleted-reference test |
| DISK-03 | Failed transactions/unfinished scans retain the prior generation; published facts reject mutation | Rollback, quota and immutability tests |
| DISK-04 | Consistent database backup restores counts and passes integrity checking | Backup test |
| DISK-05 | ZIP graph/inventory counts are complete and each entry matches its manifest hash | Streaming diagnostic test with downstream backpressure |
| DISK-06 | Restart restores a model pinned to its graph; search and export use the same generation | HTTP restart and browser graph tests |
| DISK-07 | Failed output retains returned tokens; continuation reuses successful packets | Disk review test |
| DISK-08 | Optional source excerpts reach the selected request but are absent from persisted packets | Packet privacy test |
| DISK-09 | Prior compatible analysis survives rebuilding; changed evidence marks it stale | Prior-analysis rebuild test |
| DISK-10 | Missing graph generations and oversized archives fail explicitly | Lost-database restart and archive-budget tests |
| QUAL-01 | Actor/access, authority transitions, all STRIDE categories, control counterevidence and attack-chain checks reach review | `analysis-guidance.test.mjs`: bundled methodology test |
| QUAL-02 | HTTP, database, messaging, installation, certificate, device and .NET guidance is selected by evidence | Domain selection fixtures; irrelevant checks are excluded |
| QUAL-03 | Invented mapping IDs, boundary IDs and control evidence are rejected | Structured analysis validation test |
| QUAL-04 | Attack reasoning and proposed framework mappings survive projection, HTML and CSV | Structured analysis projection/export test |
| QUAL-05 | Missing risk factors remain unknown; complete factors use the existing OWASP technical-risk matrix | Risk tests and browser optional assessment test |
| QUAL-06 | Risk estimates require a reviewer/rationale and become stale when supporting evidence changes | Reviewer risk assessment test |
| UI-01 | DFD, actor/boundary editing, STRIDE drill-down, review cancellation, usage and all exports still work | Full browser workspace suite against the disk backend on supported SQLite engines |

Run `npm run check`, `npm test`, and `npm run test:ui` from `packages/static-pilot`. Use a qualified current Node 24 runtime for disk tests. Node 22 compatibility covers the existing memory backend when its embedded SQLite is too old; production disk mode refuses an unqualified engine rather than silently falling back.

## Scale and real-source qualification

The private qualification fixture inserts one million function records plus twelve repository nodes and five million edges, spread over twelve synthetic repositories. Measure insertion/publication time, combined RSS, database/WAL sizes, complete export counts and hashes. This is a storage/export benchmark, not a parser-quality or end-to-end threat-model benchmark.

Use the authorized `open-autofix` checkout read-only for real-source qualification. Record inspected/parsed/unsupported files, graph counts, interfaces, unresolved references, reused files, model request/usage outcomes and browser/export behavior. Never execute target scripts. A direct Claude request validates that adapter and the chosen evidence packet; it does not qualify a customer gateway or complete all review obligations.

Semantic evaluation remains a security-review activity: check whether a returned scenario has a plausible actor and access, a supported or explicitly conditional path, relevant counterevidence, a concrete impact and an actionable mitigation. Record unsupported claims and omissions. Do not equate a present framework ID, full STRIDE column set or an empty response with analytical quality or safety.

## Recorded storage qualification

On Node 24.22.1 / SQLite 3.54.1, the synthetic fixture stored 1,000,012 nodes and 5,000,000 edges across twelve repository namespaces. Insertion and publication took 44.68 seconds; sampled insertion RSS peaked at 127.45 MiB. The database was 3,550,502,912 bytes, with a 7,873,352-byte WAL at measurement. Complete JSON export emitted all nodes, edges and 1,000 file ledgers (724,299,158 bytes) in 23.96 seconds; sampled export RSS peaked at 136.17 MiB. These are observations from one local machine, not VM guarantees or a full parser/planner/model benchmark. The insertion memory sample does not cover publication peak memory.
