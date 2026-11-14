# System threat model workspace

Status: accepted design, implemented as the v0.4.0 static workspace. See [functional acceptance specification](../testing/system-threat-workspace.md) for executable verification and qualification limits. The original interactive companion uses invented examples, not customer findings.

## Decision

Keep the staged Sources → Source graph → System model → STRIDE → Review and export flow. Make the system DFD the main architectural review surface. Actors, trust boundaries, threats and source evidence must be linked views of one model, rather than disconnected tables. A source graph is evidence for the architecture; it is not itself a DFD.

## What the repository already has

The richer UI was not deleted. It remains in the main Next.js application while the Windows workflow runs a separate application in packages/static-pilot.

| Existing location | Capability to recover | Qualification |
| --- | --- | --- |
| app/threat-modeling/page.tsx, DataFlowDiagramPanel | Rendered overall Mermaid DFD | The visible Edit DFD button has no editing handler in this component. Do not describe it as a functioning editor. |
| components/unitone/mermaid-diagram.tsx | Mermaid rendering and failure fallback | Reuse strict rendering and accessible export concepts; architecture identity must live outside the Mermaid string. |
| components/unitone/threat-detail-full.tsx | Actor, prerequisites, action, asset, impact, trust boundary, assumptions and mitigations | Restore this context in the main review experience, not only deep in a detail view. |
| lib/threat-engine/dfd-generator.ts | Boundary subgraphs and distinct component shapes | Render a shared structured model instead of making the diagram the source of truth. |
| packages/core/src/dfd-generator.ts | Boundary grouping and protocol/data classification labels | Component-type colors are not risk evidence. Keep risk separate from type and provenance. |
| lib/threat-engine/repo-analyzer.ts, extractArchitecture | Automatic component, flow and boundary assembly | Currently inserts End User, connects detected component types, and groups architectural tiers as boundaries. These are hypotheses, not proven connections or trust transitions. |
| packages/static-pilot | Bounded static graph, gateway adapters, review batches, provenance and STRIDE exports | Preserve these guarantees while restoring richer views. |

The product regression is a separation of applications and presentation models. Fix it with a shared architecture model and coordinated views, not by copying the older heuristic assumptions into the pilot.

## Research and design implications

Research uses public product documentation, not hands-on benchmark claims. Features below are documented capabilities; this review does not establish comparative accuracy or completeness.

| Reference | Useful pattern | Synthesis decision |
| --- | --- | --- |
| [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-feature-overview) | Design and analysis views; selected threats highlight their interaction and expose properties; HTML reporting | Bidirectional selection between DFD and threat register; preserve selection when switching views. |
| [IriusRisk diagram construction](https://www.iriusrisk.com/documentation/create-a-diagram-from-scratch) | Trust zones, components, flows and data assets are explicit diagram objects | Make zones and data assets editable structured objects. Show evidence and uncertainty alongside membership. |
| [IriusRisk threat details](https://www.iriusrisk.com/documentation/threat-details) | Threat properties, countermeasures, risk and test state | Separate scenario assessment, mitigation proposal, implementation evidence and review decision. Static code presence does not establish effective deployment. |
| [Devici flows and boundaries](https://docs.devici.com/latest/guides/modeling/data-flows-and-trust-boundaries/) | Model identity/control changes; avoid boundaries based only on architectural layers | Boundary records explain what changes, where it is enforced, and what remains assumed. |
| [SD Elements datasheet](https://www.securitycompass.com/Datasheets/SD-Elements-Threat-Modeling-Datasheet.pdf) | Diagram input connected to threats, countermeasures and developer guidance | Export a review package with mitigations, ownership and evidence, not just a matrix. |
| [OWASP Threat Dragon](https://github.com/owasp/threat-dragon/blob/main/docs/usage/diagrams.md) | Familiar DFD shapes, explicit boundaries, highlighting open threats and SVG/PNG export | Keep notation readable and let users export the view they reviewed. |
| [OWASP threat modeling guidance](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) | High-level system views plus component detail; explicit entities, stores, flows and boundaries | Use context, system and focused component views derived from the same model. |

Our proposed differentiation is verifiable static provenance across repositories: every architectural claim can show its source, inference, reviewer decision and unresolved conditions. This is a product goal, not a claim that competitors lack those capabilities or that Synthesis is already better.

## Primary workflow

1. Select the local clones, product configuration and scope. Docs and inventory workbooks remain optional.
2. Build the static source graph. Report every missing repository, unsupported language, truncation and parse gap.
3. Compose a draft system model from source interfaces, configuration and dependency evidence. Group deployment components across repositories; a repository can contribute several components and a component can span repositories.
4. Open the overall system DFD immediately. Resolve important unknown destinations, component mappings and actor/boundary assumptions in place.
5. Review actors and trust crossings before running or continuing STRIDE. Incomplete models can run, but their unanswered questions remain visible and exported.
6. Analyze bounded architecture slices containing actors, assets, flows, trust transitions and relevant source evidence. Perform a separate portfolio pass over cross-repository interactions and unresolved seams.
7. Review threats in the DFD, matrix or register; record decisions, mitigation ownership and evidence. Export one consistent model revision.

## System DFD

The initial view is the whole system at a readable level: external entities, major processes, stores, brokers and external dependencies. Twelve repositories must not become twelve arbitrary boxes. Show repository attribution as a secondary label and expandable mapping.

Three levels share stable IDs:

- Context: system under consideration, external people/systems, key inputs and outputs, scope boundary. A scope boundary is explicitly not a trust boundary.
- System: major processes, stores, queues, data flows and selected trust-domain lens.
- Focus: expand one component or interaction into relevant interfaces and code ownership. Keep a breadcrumb and the same selection ID.

Default overlays: trust crossings and unresolved connections. Optional overlays: actor entry points, selected threat path, data sensitivity, source repositories. Do not draw every AST node on the system canvas.

Use rectangles for external entities, rounded processes, store notation for data stores and a distinct broker shape. Label directed flows with ID, data purpose and protocol; show the opposite direction separately when its identity or data differs. Show unresolved targets as explicit unknown nodes. Selecting a flow reveals caller/callee identity, authorization decision, credential type, data assets, source evidence and crossed boundaries.

Trust zones may be nested within one lens. Network, identity, privilege, administration and data sensitivity can overlap; do not force them into a single containment tree. Switch lenses or show crossing badges when simultaneous polygons would become misleading. Solid connectors mean a represented relationship, not that production behavior was observed; every flow also has a textual evidence status. Dashed connectors denote proposed or unresolved relationships only.

## Actor view

Keep legitimate external entities and adversarial profiles separate. A user or service account is a system principal; a compromised account is a threat-actor scenario using that principal.

Each actor profile has an ID, starting access, credentials/privileges, capability assumptions, objective, targeted assets, entry points, reachable proposed paths, excluded capabilities, evidence and review state. Candidate profiles include unauthenticated network caller, authenticated low-privilege user, compromised integration client, compromised service, privileged insider, device-side attacker and software supplier. Applicability is selected for the actual product profile; these are not automatically asserted as present.

Selecting an actor highlights only applicable entry points. A proposed attack path is a conditional hypothesis with prerequisites at every hop. Never claim exploitability or reachability merely because graph nodes connect. Distinguish role existence supported by code from attacker possession of that role, which is an assumption.

## Boundary view

Every boundary records the trust dimension, source and destination domains, changing assumption, enforcement location, affected flows, evidence, uncertainty, reviewer and applicable product profile. Example: user authorization context → service identity at a proxy hop, with delegation and operation-level authorization unresolved.

The boundary inspector answers: who is trusted before/after, what privilege changes, which data crosses, where enforcement is declared, which controls are visible statically, and what requires confirmation. Candidate boundaries can be accepted, revised or rejected with a reason. Review decisions are local annotations unless authenticated identity is implemented; never imply signed approval.

A folder, repository, package or application tier alone is not evidence of a trust boundary. Installer declarations can establish that software is installed; they cannot by themselves establish that the application talks to that software. Separate SQL, broker and graph-store dependencies from connected runtime components until supporting static evidence exists.

## STRIDE and threat review

Rows can be components, flows or boundary crossings; an actor filter restricts applicable scenarios without hiding the full scope denominator. Columns show the six full STRIDE category names. Cell detail lists the scenarios, rule prompts and review rationale separately. Click a scenario to highlight its exact diagram objects.

Distinguish not analyzed, model analysis complete awaiting human review, scenario identified, reviewed with no scenario identified, not applicable with rationale, and stale. AI output with no scenario is not equivalent to completed human review. Count unique threat IDs; a threat linked to two components is not two portfolio threats. A rejected scenario and an accepted risk are distinct decisions.

Threat records contain actor/access, action, targeted asset, impact, prerequisites, flow/boundary references, source evidence, counterevidence, assumptions, mitigation, owner, rationale and revision. Risk assessment is separate from confidence in evidence. Avoid a single green coverage percentage derived from category presence or request completion.

## Static collection and synthesis

Use existing parsing plus framework-aware static collectors for routes/clients, OpenAPI/protobuf contracts, message producers/consumers, datastore accesses, service accounts, authorization policies, reverse-proxy configuration, service manifests, ACL declarations and installer configuration. Use explicit environment profiles and retain unresolved variables.

Cross-repository linking requires compatible protocol and direction plus discriminating evidence such as literal endpoint resolution, service-name configuration, matching queue/topic identity or contract identity. Record the matching rule and competing candidates. Shared protocol, similar names or a package reference alone cannot establish a flow. Record unresolved candidates rather than silently choosing one.

The model may propose actor profiles, component groupings, boundaries and scenarios using supplied evidence IDs. Validate references and schema before adding proposals. It cannot promote its own output to a reviewer decision, fabricate source locations, or execute target software. Source, comments and docs are untrusted analysis input. Model calls go only to the selected configured provider/gateway.

Static evidence supports declared configuration and code paths. It does not prove production reachability, effective identity, malicious actor presence, exploitability or runtime control effectiveness. The UI must make those limits visible at the relevant claim, not hide them in a report disclaimer.

## Shared model and implementation design

Add versioned entities: SystemModel, Component, ExternalEntity, DataAsset, Flow, TrustDomain, TrustBoundary, ActorProfile, ThreatScenario, Control, EvidenceRef, ReviewDecision and CoverageRecord. Each uses a stable ID, applicable profile and source snapshot. Claims carry two independent dimensions: basis (source observation, inference, assumption or reviewer declaration) and review state (pending, accepted, rejected or stale). Accepted inference remains an inference.

Relationships include component-to-repository mappings, directed flow endpoints, actor entry points, boundary crossings, scenario subjects and evidence supports/contradicts links. Never key identities by display labels. Record unknowns explicitly. Exported views are projections of this shared model; Mermaid is a generated interchange view, not the editable canonical database.

Extend the local worker pipeline with architecture composition and validation before threat-review planning. Packets prioritize complete security interactions instead of arbitrary groups of same-protocol interfaces. Large interactions use referenced summaries and bounded evidence slices with explicit omitted-context records. Track structural coverage separately from model submission, human review and source parsing.

Extend server routes for model/actor/boundary edits using revision guards. Persist snapshots and completed batches locally with atomic writes, schema validation and no provider keys. Source changes mark dependent claims and decisions stale; importing an old report never silently approves it. A restart must restore the exact accepted snapshot or clearly require rebuilding. Durable recovery is required before describing large portfolio analysis as operationally reliable.

Keep the existing Windows static server for the first delivery. Reuse the richer web application's visual hierarchy and threat detail contract, without importing its heuristic architecture conclusions or its full server dependency stack. Use one layout/model adapter so DFD, matrix, registers and exports agree. Select a canvas renderer through a spike that tests compound zones, stable layout, keyboard selection, offline assets and exports; do not make a library choice a prerequisite for reviewing this design.

## Export package

Include an executive summary, scope and revision, context/system/focused DFDs, actor register, boundary register, threat register, STRIDE matrix, mitigations, assumptions, exclusions and source/review coverage. Preserve IDs between diagrams, CSVs and JSON. Offer SVG and Mermaid for diagrams, CSV for registers/matrix, HTML for the full report, and print-to-PDF layout. Print-to-PDF is available through the self-contained HTML report. Native PDF generation and printer-specific pagination are not implemented. Clearly mark view-filtered exports versus the full model.

Exports must retain draft and stale status, evidence basis, missing repositories and unanswered questions. Avoid secrets and raw local root paths. Sanitize diagram labels and spreadsheet cells. Export must not convert an unreviewed area into a zero finding count.

## Delivery sequence and acceptance

1. Restore system visibility: shared architecture schema, whole-system DFD, context/focus navigation, unknown endpoints, consistent exports. Fixture: multiple repositories per component, multiple components per repository, duplicate names and missing dependencies.
2. Make actors and boundaries first-class: registers, inspectors, lenses, review decisions and evidence linkage. Fixture: same-host privilege crossing, cross-repository call without trust change, external dependency without source, conflicting deployment configurations.
3. Coordinate analysis: architecture-aware review packets, actor-scoped paths, boundary/flow STRIDE matrix, threat/DFD cross-selection, deduplication and staleness. Test invented model IDs and unsupported claims are rejected.
4. Make portfolio work recoverable: durable local checkpoints, cancellation/restart, export round-trip integrity, memory/time benchmarks on a representative static source set. Qualify on all 12 customer repositories with security-champion reference cases; no target execution or runtime probes are needed.

Release acceptance requires: readable overall DFD; no silent missing repositories; each flow and boundary inspectable; evidence and assumptions visible; all six STRIDE categories reviewable with meaningful state; persistent progress; matching export IDs/counts; keyboard access and readable narrow layouts; and gateway failures that retain already completed work. Visual polish alone does not meet these criteria.


## Implementation boundaries in 0.4.0

The shared model, editable registries, nested trust lenses, coordinated DFD/matrix/inspectors, local review decisions, source-reference staleness, durable batch checkpoints and complete exports are implemented in `packages/static-pilot`. Diagram layout is deterministic SVG with offline assets. Large overviews show 80 objects with explicit omission notices; complete registers and model exports retain scope.

Architecture composition starts with syntax-derived source groupings and unresolved peers. Reviewers declare deployment components and discriminating cross-repository flow evidence. This release does not automatically prove service topology, deployment conditions, credentials or control enforcement. Framework extraction is the bounded collector set documented in the package README; broad contract/ACL/identity-provider semantic coverage remains qualification work. There is no blanket claim that every named framework in the product direction is fully parsed.

A control is a source declaration or reviewer record with references; enforcement remains a separate review question. Counterevidence, assumptions and local risk decisions are recorded explicitly. Actor overlays follow represented directional flows up to six hops and exclude unresolved/rejected edges. They are inspection aids, not exploitability proofs or automated attack simulations.

The real-repository validation records stay outside the public checkout. Twelve customer repositories and the customer's live gateway must be qualified in that environment; synthetic success is not substituted for that evidence.
