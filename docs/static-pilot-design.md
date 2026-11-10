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

Structured parsing establishes source declarations; lexical extraction proposes candidates. Effective identity, exposure and control enforcement remain unknown. A reviewer can declare a connection but cannot turn it into source-supported proof. Public fixtures are synthetic. Source collection stays local or uses pinned GitHub downloads; optional model review sends bounded evidence to the explicitly configured provider. Customer data is never included in public fixtures or repository commits.

## Verification and remaining work

Tests cover portfolio parsing, evidence separation, containment, secret exclusion, archive limits, no name-only flows, stale declarations, missing-source coverage, output escaping and local-server authorization. They never execute modeled code.

Full product qualification still requires semantic adapters, configured resource resolution, effective-control association, reviewed asset/data classification, richer actor editing, layered process/store DFDs, authenticated decisions, incremental invalidation, customer-source benchmarks and shared-engine integration. A runnable pilot does not satisfy those gates by itself.

## Optional model review (pilot 0.2)

**Use case:** An operator selects Claude or Gemini plus an approved model ID on server startup, imports a portfolio, chooses a single installation profile, and runs static discovery. The run screen discloses the provider/model and offers metadata-only or optional partial source excerpts. The reviewer inspects cited suggestions alongside deterministic evidence, declares justified connections and exports both the model-inferred review and the declared DFD.

`model-review.mjs` implements the provider-neutral packet, prompt, strict output validator, redaction and fixed-host adapters. The same `analyze` pipeline serves UI workers and the CLI. Keys are server-environment configuration, never client/manifest input. Collection completes before inference; the provider receives no tools, executable capability or runtime destination. One request is limited to 120 interface records / 96 KiB, 8,192 output tokens, 120 seconds and 1 MiB response. Round-robin selection and explicit submitted IDs and omitted counts prevent silent whole-portfolio coverage claims. Code excerpts are transient, partial and opt-in. No fallback provider or automatic retry is permitted.

The JSON `aiReview` field is separate from source interfaces, actors, boundaries and deterministic scenarios. It records provider, requested model, prompt version/hash, packet/response hashes, based-on revision, coverage, status, threats, connection hypotheses and open questions. Each threat includes a named actor and starting-access assumption. Connections can propose authority transitions; both endpoints must have valid evidence citations. All generated conclusions remain model-inferred and require review. Valid citations do not prove a conclusion. Generated prose may contain confidential source details even though raw packets and credentials are not persisted.

State transitions: no model requested → absent review; configured request → completed-needs-review, failed, or skipped (no records); declarations changed → stale. Provider failure preserves the static result and CLI exit 3. Binding mutations cannot silently make old suggestions current. Model outputs never mutate accepted flows/boundaries or receive approval status. New source snapshots require fresh analysis. Adapters currently cover direct Anthropic/Gemini APIs only; enterprise broker authentication and comprehensive multi-pass portfolio review remain future work.

Acceptance checks include both request protocols, no credential disclosure, packet bounds, excerpt redaction, schema/citation rejection, provider errors, truncation, no fabricated accepted edges, stale review invalidation and escaped exports. Live-provider verification uses synthetic sources only and is reported separately from mocked adapter tests and customer qualification.

## Competitive release gates

The [SD Elements comparison and Synthesis release gates](sd-elements-comparison.md) define COMP-01 through COMP-09, a fair comparison against SD Elements and the wider Devici workflow, and the evidence required before claiming superiority. The immediate priorities are source-backed cross-repository resolution, qualified adapters, actor/authority analysis, complete model-review accounting, layered DFDs and change impact. Those capabilities remain proposed work; pilot 0.2 is not yet a qualified replacement for an enterprise requirements platform.
