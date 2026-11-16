# Architecture DFD implementation plan

Status: implemented on `codex/architecture-dfd`; release candidate static-pilot 0.8.0. CI and merge verification pending.

## Problem and outcome

The source graph contains code structure, not a deployment architecture. Project-per-box rendering and one connector per interface obscure the system. Literal-only destination extraction leaves configuration-driven clients unresolved. A graph must remain honest about missing wiring while making evidenced relationships readable.

## Implementation sequence

1. Preserve the source graph, stable component/interface IDs, original flows, evidence and review decisions. Add candidate component classification from collected project, entry-point and installer facts. Classify test/generated/vendor scope separately; never infer deployment or trust from a repository name. Classification is a hypothesis, not confirmed topology. Libraries without host ownership stay source groups.
2. Retain bounded symbolic HTTP facts in graph interface records. Resolve literal constants, request messages, base addresses and configuration references with explicit scope and evidence. Resolve across files only when configuration identity is unambiguous in the same project; correlate resulting endpoints across repositories. Keep ambiguity and unsupported expressions as gaps. Do not execute configuration, constructors, installers or target programs.
3. Introduce a diagram projection distinct from the review model. Context, service and focused views use the same projection for SVG and Mermaid. Aggregate equivalent directed flows, preserving every member flow/interface/evidence ID and distinct security semantics. Hide unresolved peers and non-production source groups from the default canvas but expose them through a searchable coverage panel and explicit toggles.
4. Replace the grid with deterministic directional layout. Route cycles and parallel edges separately; retain full labels in accessible titles and the inspector. Provide fit/zoom, aggregate drill-down, source evidence, related STRIDE findings and review state. Apply trust lens and actor overlays consistently to both diagram and export.
5. Derive identity-boundary candidates from source authentication declarations and entry points; show execution/identity configuration as candidate evidence, without inventing network zones or effective permissions. Preserve reviewer-declared domains. Actor overlays show conditional reachable paths and linked threats, not asserted exploitation.
6. Extend compact diagnostics with architecture counts, resolution gaps and diagram omissions. Document rebuild/migration and Windows update steps. Test memory/disk parity, cache reuse, stale evidence, ambiguous cases, exports and browser controls. Validate against open-autofix without executing its code or sending source to a model.

## Acceptance tests

- Twelve repositories form an evidence-backed chain through literal or configured endpoints; disk cache/restart retains the same IDs and flows.
- Same-project configuration references resolve across files. Conflicting environment overrides, multiple assignments, unknown wrappers and ambiguous destinations do not create certain connections.
- Component roles have file evidence; test projects are not production services by default. Source groups remain available, and missing classification is counted.
- Hundreds of equivalent calls between a pair of components become one connector. Opposite directions, different protocols, controls, data classifications, review states and boundary sets remain distinct. Inspector lists member flows and linked threats.
- Unresolved interfaces remain visible in coverage with source locations and reasons. Zero connections produces an explicit incomplete-model state, not invented edges.
- Actor paths exclude rejected/stale flows and remain conditional. Inferred boundary candidates and reviewed domain declarations are visually distinct.
- SVG/Mermaid exports reflect the selected view and retain member IDs. Full review JSON/registers retain all underlying evidence and unresolved relationships.
- Existing review decisions survive view changes and restart. New source facts invalidate affected decisions through fingerprints.
- Functional browser tests cover selection, aggregation, coverage filtering, zoom, actor/boundary overlays and selected-view exports. Run existing suites to detect regressions.

## Limits and rollout

This increment does not implement whole-program compilation, arbitrary DI/container interpretation, environment selection, every proxy rewrite, non-default broker binding resolution, or installer execution. Unresolved cases remain explicit and traceable. No runtime reachability claim is made. Existing graph caches need a rebuild to collect new facts; views can open older models without deleting state. Save exports before rebuilding. No customer data, endpoints, credentials or diagnostics belong in this public repository.

## Verification record

Local verification on 16 November 2026:

- Automated suite: 117 tests passed with the real Semgrep checks enabled. CI results are recorded in the pull request.
- Browser suite: 17 tests passed, including the grouped-flow interaction, selected-view exports and restart.
- Read-only open-autofix validation: 503 files inspected, 228 route-match candidates, 67 unresolved interfaces. The default service DFD shows two candidate applications and one grouped connection representing 92 production-candidate calls. 136 test-related flows and five unresolved relationship groups remain outside the default canvas and available in filters/registers. No target code or model calls ran.
- No browser errors in the real-repository validation. SVG, Mermaid and compact error exports succeeded. Customer source, screenshots and validation artifacts are not included in the public repository.

JCI-specific connection coverage cannot be certified without rebuilding against the customer clones. The resolver is deliberately bounded: arbitrary cross-file symbols, inheritance, DI, generated clients, interpolated URLs and non-default broker bindings remain gaps. Existing narrow JavaScript wrapper and literal queue adapters are retained, not replaced by a general interprocedural resolver. Trust candidates do not establish effective authority or deployment zones.
