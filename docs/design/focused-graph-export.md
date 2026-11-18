# Focused graph review packages and saved graph reuse

## Saved assessment

Restart with the same source root and persistent workspace. The saved model and published SQLite generation restore without collecting or parsing clones. **Open saved graph** opens that snapshot. DFD inspection, graph export and metadata-based STRIDE review need no rebuild. CWE source review still reads current source and checks its relationship to the saved snapshot; it does not rebuild the graph.

Rebuild when source contents, repository selection or extraction rules change, or when deliberately refreshing incomplete extraction. Version 0.10.0 does not change extraction rules and can reuse a 0.9.0 graph. Compatibility uses the saved extractor key, including legacy SQLite version rows. This is not a working-tree freshness check: source changes and new untracked files are not detected automatically on restart.

The earlier STRIDE option to include transient excerpts is distinct: excerpts are not checkpointed. After restart metadata-only STRIDE works immediately; that existing optional excerpt mode still requires recollection. Focused export code windows are independently read and hash-checked on demand without rebuilding.

## Export contract

Source graph → Export graph review package offers repository, component, flow, finding (CWE or STRIDE), CWE with findings, and bounded system overview. For a CWE without findings, select the relevant repository/component and use the separate requested-CWE coverage report.

Each review-part ZIP contains `manifest.json` and `records.ndjson`: selected graph nodes and one-hop incident relationships, related architecture/actors/boundaries/controls/threats, CWE candidates, evidence paths/hashes, coverage, diagnostics and unresolved connections. Static candidates are not promoted to verified reachability or vulnerabilities.

The manifest identifies model revision, graph generation/fingerprint, source snapshots, selection, limits, included counts, omissions, part number/count and payload SHA-256. ZIP hashes appear in the preparation response. All numbered parts are required for the exported selection. Graph edges list missing endpoints; other model references may point outside the selection. This is not a full assessment backup.

For transfer, review parts are grouped into one or more transfer ZIPs, each also capped at 3 MiB. A transfer manifest lists part hashes and bundle numbers. The UI offers transfer downloads first, with individual parts in an expandable list. This keeps many small review contexts manageable to move.

## Bounds

- Final ZIP: hard 3 MiB cap per part.
- Uncompressed payload: 256 KiB per part; manifest: 64 KiB. Estimated tokens are payload UTF-8 bytes / 4, not provider token accounting or a tokenizer guarantee.
- Total selected payload: 8 MiB; individual record: 48 KiB. Oversized graph records are explicitly omitted, never cut in half. Large architecture records may instead emit a clearly named summary with 64 references per long list and original/included counts.
- Up to 4,000 nodes, 8,000 incident edges, 2,000 context records (100 per kind, except 400 evidence, 300 interface and 250 source-coverage records) and 64 source windows of up to 80 lines each.
- Larger selections split at record boundaries. Traversal/budget caps explicitly mark incomplete selection. Omission counts are skipped records/windows or limit events, not a count of every unvisited record. Narrow the scope to investigate omitted work.
- SQLite uses generation-scoped file/repository queries and indexed incident-edge reads. The full graph is not copied into memory. One prepared export is retained per server, replaced by the next preparation and unavailable for download after ten minutes.

## Code context and transfer

Source text is off by default. Optional context reads selected local files only. It rejects path escapes, excluded secret files, nonregular files, symlinks and oversized files. Opened-file identity, size and timestamps are checked; SHA-256 must match saved evidence before text is included. Missing, changed or remote-only source produces a context-gap record. No target code, build, hook or runtime API executes.

Configured credentials and source-root prefixes are removed from strings. Source redaction preserves line numbers, including multiline private keys. Redaction is best effort, not a data-loss prevention guarantee. Paths, names and code can remain confidential. Inspect and transfer manually; preparation makes no model call or automatic upload. Repository text is explicitly identified as untrusted evidence, never instructions.

Authenticated localhost endpoints: `GET /api/graph-package-options`, `POST /api/graph-package` with current `modelRevision`, scope and explicit source choice, then `GET /api/graph-package?id=…&part=…`. Mutations are blocked during preparation. Traces record ID, revision, sizes, part counts and omission summaries without code. Findings import and automatic approval are outside this release.
