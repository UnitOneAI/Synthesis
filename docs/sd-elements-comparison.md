# SD Elements comparison and Synthesis release gates

Reviewed 10 November 2026. Synthesis baseline: static pilot 0.2, commit `eb63644`. Status: competitive requirements defined; superiority not demonstrated.

Synthesis should compete on the accuracy and review effort of a **single static security model spanning multiple repositories**. The current pilot provides source intake, evidence records and model-assisted suggestions, but does not yet establish that advantage. A successful synthetic run is not a comparative benchmark.

## Documented competitor baseline

Compare SD Elements itself and the wider SD Elements plus Devici workflow separately. Feature availability depends on release, configuration and licensing. These are first-party documented capabilities, not results of an instrumented product trial. A feature absent from these pages is unverified, not necessarily absent from the product.

| Area | Documented capability | Implication for Synthesis |
| --- | --- | --- |
| Repository and AI workflows | SD Elements describes repository-derived surveys and AI static countermeasure checks with evidence and selectable models. [Workflow documentation](https://docs.sdelements.com/release/2026.8.2/guide/docs/agentic_ai_workflow/workflow_prompts.html) | Source intake, AI support and static verification are not sufficient differentiation. |
| Visual modeling | SD Elements has editable diagrams, nested trust zones and threat/countermeasure views. Its native diagram guide says zones and connections do not affect threats, weaknesses or countermeasures; that statement must not be generalized to Devici. [Diagram documentation](https://docs.sdelements.com/release/2026.8.2/guide/docs/threat_modeling/diagrams.html) | A better-looking diagram alone is insufficient. Authority transitions must affect analysis and remain traceable. |
| Code-derived architecture | Devici Code Genius documents local deterministic analysis, metadata transfer, C#/.NET and C++ among supported languages, and OTM processes, stores, entities, flows and boundaries. [Code Genius overview](https://docs.devici.com/latest/guides/integrations/codegenius/) | Local static collection and language labels are not unique advantages. Measure actual adapter accuracy. |
| Multiple repositories | Code Genius lists one repository per run and no multi-repository aggregation. [CLI limitations](https://docs.devici.com/latest/guides/integrations/codegenius-cli/) | This is a specific opportunity for source-backed cross-repository composition, not proof of superiority today. |
| System reporting | SD Elements System View groups projects and aggregates countermeasure/compliance status. [System View](https://docs.sdelements.com/master/guide/docs/system_view/) | Distinguish cross-project reporting from evidence-backed cross-repository data flows. Do not claim the competitor has no system view. |
| Contextual threats | Devici derives threat relevance from attributes together with flows and boundaries and supports mitigation review. [Threats and mitigations](https://docs.devici.com/latest/guides/modeling/threats-and-mitigations/) | Compare the complete suite when assessing threat and boundary analysis. |
| Evidence and delivery | SD Elements has chronological verification notes, outcomes and evidence; its product workflow connects requirements to developer delivery. [Verification notes](https://docs.sdelements.com/release/2026.8.2/guide/docs/integrations/security_tools/overview/verification_notes.html), [connected workflow](https://www.securitycompass.com/lp/product/the-last-mile/) | A JSON report and informal reviewer name do not match governed requirement delivery and audit history. |

## Required advantage and implementation order

All targets below are engineering requirements, not achieved performance. P0 gates qualify the proposed multi-repository advantage; P1 work makes the result useful inside an established security program. Do not represent the pilot as a replacement for a requirements/governance platform.

| ID | Priority and requirement | Pilot 0.2 status | Acceptance evidence |
| --- | --- | --- | --- |
| COMP-01 | P0: One revisioned graph across explicitly selected repositories and supporting dependencies | Multiple inputs supported; connections are manual declarations | Resolve caller/configuration/contract/receiver chains with source anchors on both ends; preserve conflicting targets and unknowns; never link by matching names alone. |
| COMP-02 | P0: Qualified static adapters for routes, authorization, WCF, broker resources, SQL, certificates and installer authority | Bounded lexical recognizers and selected structured declarations | Positive and negative fixtures verify conditional configuration, inherited control scope, broker identity and installer/service identity separately. No target build, restore or execution. |
| COMP-03 | P0: Explicit actors and authority transitions | Actor assumptions and manually declared transitions exist | Each material scenario identifies actor capability, initial access, asset, path, authority before/after, enforcement evidence and unresolved assumptions. Same-repository privilege changes count; separate repositories sharing authority do not automatically form a boundary. |
| COMP-04 | P0: Complete analysis accounting beyond one model packet | One model request, at most 120 records / 96 KiB | Budgeted per-repository passes plus cross-repository resolution and threat synthesis. Every eligible record has analyzed, failed, deferred or unsupported status and reason; omissions cannot be labeled complete. Resume without redoing completed work. |
| COMP-05 | P0: Linked context, process/store and detailed DFD views | Flat source-group/flow review sheets | Stable IDs across views and exports; distinct external entities/processes/stores; identity and data annotations; visible uncertainty; select an edge to inspect its evidence, boundary and threats. Diagram edits change the graph, not merely its drawing. |
| COMP-06 | P0: Change-aware threat review | Snapshot fingerprints invalidate declarations; no impact graph | Removing authorization without changing topology reopens affected claims. Missing files or a partial scan never close threats. Unaffected decisions survive; changed evidence is marked stale. |
| COMP-07 | P1: Threat-to-requirement-to-evidence traceability | Mitigation prose only | Versioned requirement IDs, applicability rationale, owner, source evidence, review history and static verification criteria. Keep required/planned controls separate from implemented controls and reviewed sufficiency. |
| COMP-08 | P1: Interoperability with existing security workflows | No SD Elements connector or requirement mapping | Preview import/export mappings for project and countermeasure IDs; preserve original decisions and unknown statuses; idempotent synchronization, conflict handling and explicit authorization for external writes. Unmapped content remains visible. |
| COMP-09 | P1: Controlled enterprise model access and review | Direct Claude/Gemini APIs; local token; no organizational approval | Configurable approved provider gateways, source-data policy, retention, resource-scoped authorization and attributable review decisions. Imported source/agent files remain data, not executable instructions. |

The existing 31 automated tests validate pilot contracts. They do not measure cross-repository link precision, threat recall, comparative reviewer time or customer-source correctness.

## Benchmark and claim policy

Run a locked, human-reviewed static corpus through (A) Synthesis, (B) the available SD Elements workflow, and (C) SD Elements plus Devici/Code Genius where licensed. Record versions, feature flags, source snapshots, model IDs, prompts, exclusions, operator experience, cost and elapsed/reviewer time. Use identical source inputs and one declared profile; provide no architecture documents in the primary task. Permit each tool's ordinary supported workflow and count required manual modeling. Report a separate existing-model maintenance task; do not mix it with cold-start results. Unavailable competitor access means comparison pending, not a win.

Begin with at least 50 true cross-repository links, 50 confusing non-links, 20 authority transitions, and 12 critical threat scenarios with secure and insecure variants. Include HTTP ingress, token audience/issuer, authorization inheritance, queue publisher/consumer permissions, SQL access, certificate trust, installer privileges, shared libraries and conditional product variants. Add a scope with more than 120 interface records and a multi-repository system fixture. Keep the holdout set separate from prompt/rule tuning. Customer-owned code and licenses stay outside the public repository; no customer upload is part of this benchmark specification.

| Gate | Proposed threshold and denominator |
| --- | --- |
| Link correctness | At least 95% precision among asserted links and 90% recall against independently adjudicated resolvable links. Unknowns count as misses for recall; report unsupported cases separately and in an all-case coverage view. Score automatic suggestions and reviewer-approved results separately. |
| Critical coverage | Every seeded critical scenario and boundary is either correctly represented or explicitly unresolved. Report the actual resolution rate as well; marking everything unknown cannot qualify as better. |
| Evidence integrity | Every material source claim resolves to the supplied snapshot and is reviewed for whether the cited text supports it. Zero fabricated references or unsupported claims marked verified. Valid IDs alone do not pass this gate. |
| Actor and boundary quality | Every accepted critical scenario has the capability/access/asset/path/transition/control fields required by COMP-03, with each fact classified as supported, declared, inferred or unknown. No confirmed real-world actor attribution is inferred from source alone. |
| DFD usability | Reviewers can trace ingress to protected asset and inspect each trust crossing without reading raw JSON. At least 90% correct answers on a predefined task set; measure context and detailed views separately. |
| Lifecycle correctness | All seeded control-removal, profile-switch and partial-scan cases produce the expected review state; no silent threat closure. |
| Comparative improvement | Meet the absolute quality gates and demonstrate either at least 25% less median reviewer time at equal-or-better adjudicated accuracy, or at least five percentage points higher critical-path recall with no increase in false positives and no slower median review. These are proposed targets, not observed results. |
| Static-only operation | No target execution, target dependency installation or runtime probing. Provider/source-host traffic is separately declared. A code review outcome is never labeled deployed-control verification. |

Use at least two independent reviewers with an adjudication record. Repeat nondeterministic model runs at least three times on unchanged inputs; use a representative human task set with counterbalanced order for timing. Report sample sizes, denominators, disagreements, unresolved rates, distributions and uncertainty. Do not publish a superiority claim from a tiny or inconclusive comparison.

A qualified claim must name the task, evaluated scope, versions and measured result. “Better than SD Elements” without those qualifications is not an approved release claim. Until the gates pass, describe Synthesis as a static multi-repository discovery and review pilot.

## Architecture contracts for the next implementation slices

Keep deterministic extraction, model inference, review decisions and presentation separate. Introduce a resource-identity resolver and an evidence-dependency index before attempting automatic multi-repository composition. Every proposed link retains endpoint evidence, binding evidence, profile applicability, alternatives and resolution status. A trust transition is a relation over identities, privileges or resource ownership with enforcement evidence, not a repository grouping.

Replace single-packet enrichment with persisted bounded work items: source snapshot → per-repository extraction/review → resource resolution → cross-repository hypotheses → scenario synthesis → validation → human review. Carry reviewed-record denominators and prompt/provider provenance through each stage. Cancellation, provider failure and budget exhaustion produce resumable coverage gaps. Providers remain tool-free; no target code is executed.

Add a requirement registry with versioned control mappings, an applicability explanation and a scoped verification claim. The evidence graph is snapshot-bound; requirements can be shared, but implementation evidence must be re-established for each consuming configuration. Treat external requirements and risk decisions as separately owned records. A future SD Elements adapter imports authorized content and exports a reviewed mapping plan before any synchronization; it does not copy proprietary libraries into the public product or overwrite existing dispositions.

The reviewer interface should progress through Scope, System map, Actors and boundaries, Threats and requirements, and Changes and exports. A persistent coverage banner distinguishes inspected files, extracted interfaces, model-submitted records and human-reviewed claims. The side panel explains each conclusion's evidence and uncertainty. Keep product variant, installation phase and operational phase explicit throughout.
