# Scoped static threat-model POC

The POC reviews named inbound operations using the existing graph. It is an analysis scope, unlike the External actor display filter. Other selected clones remain available for supporting evidence, without scheduling a complete review of them.

## Scope and preservation

Import a JSON definition in STRIDE → Scoped POC → Save POC scope:

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

Selected operations are grouped with their incident flows so a handler is not re-reviewed once per connection. Oversized units may still split to preserve every selected operation and required flow; the preview exposes that cost. Five to eight operations provide 30–48 STRIDE category review cases, not a promised number of vulnerabilities. Do not pad findings to reach a target count.

## Investigation

POC source preparation reads hash-checked entry-point windows and searches the saved graph for framework, attribute, policy and inherited-controller candidates. Single-word names such as Authorize and Startup are supported. Searches favor the entry-point project/repository and also consult supporting repositories. Search results are cached within a source-reader lifetime; source windows still undergo integrity checks. Search pagination and window/byte bounds are reported; a miss is not proof that a control is absent.

The initial assessment considers all six STRIDE categories. It must not turn hypothetical future changes, manifest inventory or absent excerpts into confirmed current vulnerabilities. After all selected STRIDE packets complete successfully, the POC automatically independently assesses returned scenarios and follows missing controls, up to three rounds per scenario. Completed assessment results are retained. Provider failures and cancellation retain checkpoints. Run until complete removes the user request-count stop, not evidence or provider failure guards.

Code conclusions, deployment assumptions and reviewer decisions remain separate. Source-supported and ruled-out are code conclusions about a particular path. Needs-context, failed and not-assessed are not fully assessed. Zero returned scenarios is not proof of security. Completing review packets does not approve actors, boundaries or deployment facts.

## Reports

The report identifies the selected profile/operations and deferred scope, shows packet coverage separately from code conclusions, and carries the actor-access display filter. Filtered cells use filtered scenario and architecture-question counts; completed full-scope coverage is labeled Reviewed scope rather than asserting a hidden scenario is visible. Future-change and generic dependency hypotheses are retained as follow-ups and removed from priority cards. Ruled-out scenarios remain in the record but leave priority cards. Reusable report context comprises an eight-object overview and up to six focused component diagrams, with explicit omitted-object counts. POC diagrams include only flows associated with selected interfaces; further downstream paths remain outside that diagram. The actor summary shows up to 20 profiles; complete HTML/JSON retains every record and link.

## Qualification

Tests cover explicit selection, over-broad/empty rejection, shared control retrieval across repositories, single-word authorization lookup, source hash checking, saved-review reuse and preservation, authenticated scope import, restart, PDF/UI filter consistency and pipeline completion. Existing STRIDE/CWE/runtime-isolation regression suites remain required. Real-source qualification uses an unchanged open-autofix graph and an approved provider; customer deployment permissions are not inferred from that test.
