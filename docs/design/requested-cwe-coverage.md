# Requested weakness coverage

Implemented in static-pilot 0.9.0. See the verification specification for qualification boundaries.

## Product behavior

A security champion needs to reconcile an assigned weakness checklist with actual source review across a portfolio, while retaining findings outside that checklist. A completed scanner process is not complete weakness coverage, and an empty finding list is not a pass.

The **Requested weakness coverage** panel in **CWE code review** lists the bundled Server weakness baseline for every selected repository. The baseline contains 29 areas and preserves 52 original CWE identifiers. Twenty-five areas receive model source review. Four areas (SBOM visibility, third-party ingestion, automatic security updates, and patching/library lifecycle) remain explicitly dependent on additional evidence. This feature does not implement SCA/advisory lookup or organizational policy verification.

Use cases:

1. Before scanning, export the requested coverage matrix to establish scope. Rows show not run, no dedicated rule, or additional evidence required.
2. Run Semgrep locally. Inspect supported languages, file collection, rule execution and findings. A pattern check does not complete a model assessment.
3. Run consented model source review against collected source and supported graph interactions. Continue within the user's request budget. Each completed packet must include an assessment for every code-review target, with source references from each participating repository.
4. Inspect requested areas with missing context or pending packets. Review potential findings and counterevidence. Record dispositions; no finding is automatically confirmed.
5. Retain additional findings such as TLS verification and unsafe deserialization. Export original report IDs, precise finding IDs, coverage statuses and findings together for reconciliation.

## Taxonomy and evidence

`rules/server-weakness-profile.json` stores stable target IDs, original report CWE references, precise permitted finding CWEs, review guidance and mapping notes. OWASP grouping IDs are retained as report references, not emitted as vulnerability mappings. Deprecated CWE-545 and CWE-633 remain traceable but require an appropriate current underlying weakness. This is not a blanket one-to-one replacement: the source evidence determines the correct mapping. CWE-1021 can represent a supported framing weakness; CWE-470 can represent supported unsafe reflection.

Mapping eligibility is checked against bundled mapping eligibility from MITRE CWE 5.0 (28 October 2026), verified against the official XML on 18 November 2026. The archive URL and XML hash are recorded in `rules/cwe-mapping-status.json`; VM scans do not contact MITRE. Deprecated existing mappings 377 and 613 are excluded from new findings, with supported current temporary-file and session weaknesses available. Broad mappings marked discouraged remain potential findings with `needs-more-specific-mapping`; they are not silently presented as precise confirmed mappings. JWT review also permits the specific signature-verification CWE-347 when supported.

Additional model findings may use any of the 899 eligible weakness identifiers in that catalog, including IDs outside both the requested baseline and the curated review families. The prompt's priority list is guidance, not a validator allowlist. This expands valid reporting scope; it does not mean that 899 independent detectors or exhaustive assessments exist. The explicit per-target coverage contract applies to the 25 requested code-review areas. Unknown IDs, groupings and prohibited/deprecated mappings remain rejected.

The target list is a bundled baseline, not an arbitrary PDF import feature. Grouping references do not imply that every member of an entire OWASP category has been exhaustively checked. See the catalog's MITRE source links and the scope guidance for each area.

Findings associate with explicit target IDs, validated against each target's permitted CWE mappings. A shared broad identifier must not attach a finding to unrelated areas (for example, encryption in transit does not automatically establish a JWT issue). Legacy findings are associated automatically only where the identifier is unambiguous; others remain unassigned. Findings outside the requested targets remain available.

Source references include repository, file, SHA256 and line ranges. File-path scope classification distinguishes test fixtures, generated/vendor code and production candidates; it does not establish deployed reachability. Matching an actual line prevents invented locations but does not prove that the model's interpretation is correct. Security review remains required for attacker control, source-to-sink paths, relevant controls, counterevidence and applicability.

## Components and execution

- `cwe-scan.mjs` runs pinned Semgrep CE 1.185.0 with `rules/cwe-v2.json`: 22 rules, including all original rules and new targeted patterns. It scans staged source files, not the stored graph. New patterns cover selected C# LDAP, connection-string, SSRF, reflection, XML, debug fault and password cases, JavaScript/TypeScript DOM and storage cases, and C/C++ unbounded copy calls. Positive and safe-alternative fixtures qualify every rule. These patterns are deliberately narrower than whole CWE classes.
- `cwe-model.mjs` plans bounded source packets and evidence-supported graph interactions, including internal worker/storage connections derived by `internalTopology`. It sends all 25 code-review targets with every packet, plus allowed CWE identifiers and additional weakness families. No target code is executed.
- `validateCweModel` requires one `targetReviews` assessment per supplied target. Status is `reviewed`, `needs-context`, or `not-applicable-to-packet`. Each assessment must have a nonempty rationale and valid line references covering every repository in the packet. Missing, duplicate or invented IDs/locations reject the response. A packet-level applicability statement cannot establish repository-wide absence.
- Profile and prompt hashes enter the resume key. Old completed packets cannot count as current-profile coverage. Current-revision findings and their decisions are retained when starting a new review plan; stale-source findings are not promoted into current coverage. Token accounting includes unsuccessful attempts where the provider returns usage.
- `cwe-targets.mjs` derives repository-by-target coverage from current scan results and validated model assessments. Stale revisions, old rule packs, incomplete plans and graph/collection gaps remain visible.
- The UI offers a repository filter and JSON/CSV coverage exports. Exports are available after graph construction, even before either scanner or model review has run. Scanner findings and model findings keep separate exports.
- Small error exports include target profile identity and aggregate model coverage statuses. Full diagnostic bundles include `cwe-target-coverage.json`. Diagnostic model assessments omit rationale prose; the explicit model-review export retains it for security review.

## Coverage interpretation

| Status | Meaning |
| --- | --- |
| Patterns reviewed | Applicable bundled rules ran over the collected supported-language scope, without reported scanner/collection gaps. Not exhaustive CWE coverage. |
| No dedicated rule | This target has no dedicated bundled Semgrep pattern. Model review may still inspect it. |
| No applicable collected language | Dedicated patterns exist, but their languages were not among the collected scanner files. Not a product-level exemption. |
| Partial | Pending packets, collection/graph gaps, interrupted or failed review remain. |
| Needs context | Submitted scope was assessed, but at least one assessment requires more context. |
| Reviewed scope | All planned packets completed without recorded gaps; the model supplied relevant assessments. Findings and completeness still require review. |
| No relevant evidence in reviewed scope | All completed assessments marked the target inapplicable to their packets. This does not prove absence elsewhere. |
| Additional evidence required | A source-only review cannot establish the requested lifecycle, inventory or policy property. |

## Limits and upgrade

Static collection exclusions, maximum file/packet sizes, the 100,000-segment planner cap, 10,000-finding cap, bounded graph metadata, parser coverage and model output limits remain. Interaction packets retain up to four source segments. General compiler-level cross-file taint resolution, arbitrary dependency injection, dynamic resource identities and runtime verification are not implemented. Graph gaps prevent a completed-coverage claim even if every submitted packet returns successfully.

The larger explicit checklist increases input/output tokens per packet. Opus through an approved Anthropic-compatible gateway is sufficient to use the protocol; exact deployment compatibility must be tested in the customer's environment. There is no silent model fallback. The output cap remains 8,192 tokens; truncated responses are failed attempts, not completed assessments. Use a small initial request budget and inspect errors before continuing.

Back up the stopped workspace and save prior exports. Update the review build, rebuild the source graph once for the internal topology extractors, rerun Semgrep, then start model review. The new profile invalidates prior packet completion; old reviews did not explicitly assess this target list. Rebuilding changed source can invalidate earlier reviews. Keep the same workspace to retain history and token usage.
