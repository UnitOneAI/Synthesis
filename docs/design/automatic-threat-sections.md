# Automatic threat-model sections

The user starts an automatic review once. Scope preview is explanatory, never an approval gate. The coordinator uses the existing graph and selected primary repositories, or all loaded repositories when none are selected. Supporting repositories remain available for evidence retrieval.

## Completion contract

A section is a stable set of named primary operations under explicit actor/access and boundary assumptions. Each primary operation needs a cited disposition in all six STRIDE categories. Every returned scenario needs a current source-supported, independently challenged conditional decision or a cited ruled-out path. Missing source, incomplete bindings, pending requests and failed assessments prevent completion. Deployment declarations remain separate from completion of the static code assessment.

Completion must be computed from saved evidence, never the provider's summary or a zero pending-packet count. Sections cannot become complete by dropping a difficult operation, unanswered category or unsuccessful investigation. A blocked section retains its original membership and precise unresolved items. A transient provider failure stops dispatch and preserves progress. Cancel/restart resumes compatible checkpoints. No retry loop runs forever.

## Planning and execution

Use deterministic metadata to group operations by repository/component, route family, read/write behavior and source ownership. These are planning hints, not inferred identical controls or approved boundaries. Rank production entry points first; retain internal workers, stores, outbound calls and configuration as later sections. Test/supporting subjects remain visible and separately scoped. Split large groups into explicit numbered sections with a stable small operation count. Never build thousands of model packets before the first section.

Materialize one section, verify source, retrieve applicable controls, assess all six categories, investigate returned threats and retrieve category gaps. Reassess gaps using fresh citations and preserved prior evidence. Evaluate the completion contract and checkpoint the result. Publish each section independently before advancing. Bound repeated unchanged retrieval and report specific blockers instead of asking the user to choose operations.

Maintain source/context/provider provenance, exact members, saved review and engineering history per section. A changed graph, scope or deployment context cannot reuse a completion claim. Existing STRIDE, CWE and manual POC modes remain available. No code is executed, deployed or changed in target repositories.

## Acceptance and prior workflow failures

- A run cannot require JSON operation selection or confirmation clicks between sections.
- All selected primary subjects occur exactly once in the automatic catalog; supporting traversal does not imply whole-repository review.
- Model calls are paced by completed section investigations, not a growing portfolio of unresolved hypotheses.
- All six categories appear with evidence and disposition in the section report.
- No false completion on a missing category, blocked source, stale context, unchallenged threat, provider error, cancellation or restart.
- Completion of one section does not claim completion of other sections or verified deployment.
- Existing graph and paid legacy results are retained. Exports make no model calls.
- Real qualification uses the automatic planner's first section, not a hand-selected easy endpoint. Record rejected attempts, total tokens and duration.
- Cross-platform regression and real scanner checks pass before merge. JCI instructions start from the saved graph.

## Resource and recovery behavior

The planner partitions metadata without traversing the full call graph or materializing all review packets. It builds static architecture/deployment context once per automatic action, then materializes one section at a time. Completed sections retain their own report and paid validation. Request attempts, including rejected responses and unknown usage, are attached to the section and retained through interruption.

Transport recovery follows bounded provider retry/backoff; access errors stop the run. A failed section packet can receive a bounded validation-feedback retry. Category code gaps get at most three changed-context follow-ups; missing code is never converted into a deployment assumption to force completion. No-progress or exhausted evidence retrieval leaves a blocked section, and the coordinator proceeds to independent sections. Unchanged blocked sections are not repeatedly resubmitted on ordinary resume. A changed graph/context creates a new catalog and retains the previous results as history.

The first release stores the section catalog/results in the existing checkpoint with the existing workspace size limit. Checkpoint failure stops dispatch rather than losing work or claiming success. Parallelism remains bounded to the existing provider pool (maximum four); engineering has a single writer. This is a time-to-completed-section improvement, not a claim that total portfolio token cost is reduced.

## Follow-up integrity

Category follow-up retains the existing candidate records unchanged and adds only new scenarios. Previously assessed paths keep their identity and issue hash. A category cannot hide an existing scenario with a no-scenario result. An interrupted replacement restores the last successful packet; the interrupted request remains metered with unknown usage where applicable.

Primary source and established code bindings are required evidence. Unread optional search candidates stay in retrieval metadata and are not automatically treated as missing applicable controls. The reviewer must still name every unresolved relevant binding. Source windows remain bounded and hash checked. Section follow-up can use up to 24 source windows within the existing packet byte limit; engineering uses at most 24 source windows within 66,000 source bytes and the existing 94,000-byte overall packet limit. Selected section investigations allow five evidence rounds plus a separate critical pass, with unchanged-context termination. Other review modes retain their existing default rounds.

Requested qualified field uses (for example `session.config`) are searched in indexed source, including local receiver aliases. These are retrieval candidates, not proven data-flow links. Exact same-file definitions and member uses precede unrelated framework matches; a nearby class declaration is not replaced by its constructor. Neither a search miss nor an omitted candidate proves a safe path.

Follow-up retrieval reads implementation names from both explicit missing-code items and the model's follow-up reason. A requested line may point at a wrapper while its question asks for the base method or request type. The next packet resolves those names, retains the already retrieved required references, and re-reads them with hash verification. A later question cannot silently discard that context. Isolated format failures receive bounded correction even if an older investigation attempt failed; consecutive failures and the overall evidence-round limit still stop retries.

The category closure prompt treats earlier unresolved items as hypotheses rather than declaring them all missing code. It must independently separate effective deployment/access policy from an unread implementation, provide input/operation roles where required, and cite every primary operation. The validator still refuses missing code, invalid source citations and incomplete categories.

Before global name search, resolve same-file definitions through the saved index. Common names on early global pages must not hide a base method in the current file. Same-file implementations take priority; unbound matches in other files remain optional candidates. Initial section source preparation also follows one bounded indexed call hop from the actual primary handlers. Limits and ambiguous dispatch stay explicit. Category closure waits for existing case investigations to settle, avoiding repeated category requests that cannot yet finish.

A needs-context response that establishes all four code obligations without source gaps is a decision inconsistency. It receives an independent critical review, just as a proposed positive does, instead of another identical discovery pass. The reviewer may narrow, rule out, support, or name missing code. No status is promoted automatically, and source/citation validation remains unchanged.

Engineering follow-up also follows one indexed call hop from its primary source windows. Current requested evidence and established citations remain required. Earlier unbound search candidates remain available when space permits, but do not acquire mandatory status merely by surviving a prior round. This prevents accumulating irrelevant dependencies; the current reviewer must still name any missing implementation on the path.
