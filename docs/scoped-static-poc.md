# Scoped static threat-model POC

For whole selected repositories, use [Selected-repository STRIDE review](selected-repository-review.md). The operation-only mode documented below remains narrower and has different limits.

The POC reviews named inbound operations using the existing graph. It is an analysis scope, unlike the External actor display filter. Other selected clones remain available for supporting evidence, without scheduling a complete review of them.

## Scope and preservation

Import a JSON definition in STRIDE → Advanced: select individual operations (JSON) → Save POC scope:

```json
{
  "title": "External configuration API",
  "profile": "Untrusted network caller; upstream authentication not verified",
  "maxInterfaces": 12,
  "operations": [
    {"repository": "service", "pathContains": "SettingsController.cs"}
  ]
}
```

Selectors are case-insensitive literal substrings of saved source paths, optionally restricted by `operationContains` (for example `POST`). They select inbound interface records only, not arbitrary code execution or filenames supplied by a model. Every selector must match. At most 12 selectors, 48 primary interfaces and 12 STRIDE packets are allowed. Over-broad and empty selections are rejected, never silently truncated. Preview reports selected IDs, deferred interfaces and packet counts before provider calls.

Scope identity includes the title, profile and selectors. Existing full-system/deep reviews are saved separately; changing POC scope does not rebuild or change the source graph. Compatible POC packets resume by their packet hash and review provenance. The profile is an analysis assumption, not a deployed fact. All selected clones are still checked for source changes before source-backed STRIDE.

Each selected operation definition gets a review unit with its incident flows, so a handler is not re-reviewed once per connection. Duplicate interface records with the same operation and source location share that unit; distinct operations do not share the six-scenario response allowance. Oversized units may still split to preserve every selected operation and required flow; the preview exposes that cost. Five to eight operations provide 30–48 STRIDE category review cases, not a promised number of vulnerabilities. Do not pad findings to reach a target count.

## Investigation

POC source preparation reads hash-checked entry-point windows and searches the saved graph for framework, attribute, policy and inherited-controller candidates. Single-word names such as Authorize and Startup, private helpers such as _settings_to_model, and acronym-prefixed types such as LLMSettingsResponse are supported. Python application factories/lifecycle and rate-limit setup are searched alongside framework controls; production implementations rank before same-named fixtures. Searches favor the entry-point project/repository and also consult supporting repositories. Search results are cached within a source-reader lifetime; source windows still undergo integrity checks. Explicit requested controls precede repeated seed windows. Overlapping windows from the same hash-matched file are combined, up to 200 contiguous lines, within the existing packet byte limit. Search pagination and window/byte bounds are reported; a miss is not proof that a control is absent. A retrieval-policy upgrade can reopen an exhausted needs-context gap once, retaining prior attempts; conclusive assessments remain reusable and the same policy never resets the round limit repeatedly.

The initial assessment considers all six STRIDE categories. It must not turn hypothetical future changes, manifest inventory or absent excerpts into confirmed current vulnerabilities. After all selected STRIDE packets complete successfully, the POC automatically independently assesses returned scenarios and follows missing controls, up to three rounds per scenario. Completed assessment results are retained. Provider failures and cancellation retain checkpoints. Run until complete removes the user request-count stop, not evidence or provider failure guards.

Code conclusions, deployment assumptions and reviewer decisions remain separate. Source-supported and ruled-out are code conclusions about a particular path. Needs-context, failed and not-assessed are not fully assessed. Zero returned scenarios is not proof of security. Completing review packets does not approve actors, boundaries or deployment facts.

## Reports

The report identifies the selected profile/operations and deferred scope, shows packet coverage separately from code conclusions, and carries the actor-access display filter. Filtered cells use filtered scenario and architecture-question counts; completed full-scope coverage is labeled Reviewed scope rather than asserting a hidden scenario is visible. Future-change and generic dependency hypotheses are retained as follow-ups and removed from priority cards. Ruled-out scenarios remain in the record but leave priority cards. Reusable report context comprises an eight-object overview and up to six focused component diagrams, with explicit omitted-object counts. POC diagrams include only flows associated with selected interfaces; further downstream paths remain outside that diagram. The actor summary shows up to 20 profiles; complete HTML/JSON retains every record and link.

## Qualification

Tests cover explicit selection, over-broad/empty rejection, shared control retrieval across repositories, single-word authorization lookup, source hash checking, saved-review reuse and preservation, authenticated scope import, restart, PDF/UI filter consistency and pipeline completion. Existing STRIDE/CWE/runtime-isolation regression suites remain required. Real-source qualification uses an unchanged open-autofix graph and an approved provider; customer deployment permissions are not inferred from that test.

### Security review contract

A threat actor is a capability profile for a stated scenario, not attribution to a real person or proof of malicious intent. For each returned scenario the UI and PDF explain the initial access, why that capability is relevant, the proposed misuse path, independently assessed entry citations (or their absence), opposing controls, missing evidence and proposed action. An ordinary user is not inherently an attacker: the scenario must identify misuse, compromised credentials or another relevant condition. Boundary links inferred through shared interfaces remain candidates until the crossing and enforcement are supported.

The evidence basis distinguishes selected code and saved-graph context, declared configuration (including environment-variable reads/defaults and collected installer definitions), an assumed deployment profile, and runtime. Runtime is not examined. The model never executes target code or probes the target. Configuration in a repository cannot establish the effective deployed environment, identity, ingress policy or overrides. The scanner host's environment is not target evidence.

Acceptance requires every selected operation to appear in the plan; successful packet completion for all six STRIDE categories; a separately visible assessment for each returned scenario; exact source references or explicit evidence gaps; and a populated matrix and readable report. Completed packets do not automatically mean all scenarios are source-supported. Failed assessments, exhausted follow-up context and unverified deployment facts remain visible. A supported conditional concern can be actionable without pretending its deployment condition has been verified. The scope does not clear excluded operations or the entire portfolio.

For POC operation evidence, the saved graph's parsed function range is used when it is unambiguous and at most 200 lines. This includes a complete parsed handler body without accidentally treating the adjacent handler as that operation. Oversized or unresolved ranges remain bounded partial windows. Explicit HTTP-method contradictions against the cited primary interface are rejected; this is a consistency check, not proof of semantic correctness. A write scenario must not be attached to a neighboring read operation. Requested declaration windows and named controls precede generic graph neighbors during follow-up.

Conditional code assessment evaluates a stated configuration branch using its cited entry, guard and sensitive operation. Effective deployment values and upstream network controls remain assumptions. Missing custom guards or call bindings remain code gaps. Retrieval improvements retain prior attempts and do not invalidate the saved STRIDE discovery packets. Cited engineering conclusions remain separate from automated assessments and reviewer approval.
