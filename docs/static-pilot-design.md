# Static portfolio pilot design

The pilot at `packages/static-pilot` supplies a local review workflow while the shared multi-repository engine is developed. It never calls the existing demo/heuristic threat pipeline.

## Product and use cases

- Import inventory, retain initial selection, add primary/supporting scope, and map local clones or pinned GitHub sources without requiring documentation.
- Review referenced security libraries and installer sources as supporting evidence. No name-only flow or silent source-access expansion is permitted.
- Model installation authority separately from normal service authority under a named product/release profile.
- Inspect interface evidence; declare justified connections, data and authority transitions; export a draft with all gaps.
- Reuse a saved manifest, detect changed source snapshots, and require renewed declarations.

Role, evidence basis and review status remain separate. A repository is not a process or a trust boundary. Each candidate has a content hash and source location. Coverage failures cannot become clean-security results. Threat scenarios state assumed initial access, protected asset, conditional control failure and review criteria; severity is unassessed. No organizational risk acceptance is implemented.

## Components and contracts

`inventory.mjs` parses bounded XLSX/CSV, rejects formulas/entities and retains row provenance. `sources.mjs` reads contained local files or pinned GitHub archives without running target code or creating executable checkouts. `engine.mjs` groups projects, collects declarations/candidates, composes explicit bindings and generates conditional scenarios. `report.mjs` escapes all output and renders standalone HTML/SVG. `server.mjs` protects a loopback UI with an unpredictable token and Host/Origin checks and runs analysis in a bounded worker. `cli.mjs` supplies import, serve and analyze commands.

The versioned JSON model contains snapshots/coverage, source components, interfaces, evidence, dependencies, flows, actors, boundaries, threats and diagnostics. Interface IDs identify source locations and operations; evidence IDs include content hashes. Review declarations carry a fingerprint of selected snapshots. Changed evidence requires renewed review even when endpoints remain unchanged.

Structured parsing establishes source declarations; lexical extraction proposes candidates. Effective identity, exposure and control enforcement remain unknown. A reviewer can declare a connection but cannot turn it into source-supported proof. Public fixtures are synthetic; customer data remains local/private.

## Verification and remaining work

Tests cover portfolio parsing, evidence separation, containment, secret exclusion, archive limits, no name-only flows, stale declarations, missing-source coverage, output escaping and local-server authorization. They never execute modeled code.

Full product qualification still requires semantic adapters, configured resource resolution, effective-control association, reviewed asset/data classification, richer actor editing, layered process/store DFDs, authenticated decisions, incremental invalidation, customer-source benchmarks and shared-engine integration. A runnable pilot does not satisfy those gates by itself.
