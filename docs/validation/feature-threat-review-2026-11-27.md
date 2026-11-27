# Feature threat review qualification — 27 November 2026

Release candidate: static-pilot 0.12.0. This record distinguishes automated fixtures, preserved real findings, new live model work, and work that still requires the JCI machine. It does not certify whole-repository security or superiority over MDASH.

## Implemented and exercised

* Generic primary repository selection with explicit security-feature versus all-subject review depth; supporting repositories remain searchable.
* All six STRIDE category obligations, with discovery coverage separate from engineering decisions and deployment declarations.
* Small parallel discovery cohorts followed by bounded code/control investigation and a separate critical check before further discovery.
* Combined request accounting, token tracking, checkpoint/resume, cancellation, provider failure and preservation of prior paid results.
* Definition-first retrieval, exact private-helper lookup, inherited/application controls, local router constructor declarations, bounded indexed-file fallback and retained source anchors across rounds.
* Reviewer yes/no/unknown declarations with identity, rationale and context invalidation; declarations cannot approve missing code.
* Branded human report with supported decisions and source snippets; complete technical export retains the hypothesis register and unresolved work.

## Saved open-autofix graph

The existing SQLite graph was opened read-only. Source windows were checked against saved hashes. No target code, target test, build, server or attack was executed. Live model work used direct Anthropic `claude-opus-4-6`, not the JCI Azure gateway.

For the same primary repository selection, all-subject planning produced 4,341 primary subjects and 1,254 packets. Security-feature planning produced 1,755 primary subjects and 506 packets, retaining 2,586 helper/import subjects as context. This is an explicit change of primary review depth, **not an equal-coverage token/time speedup**. It is not a measurement for JCI's graph.

The preserved November 26 review was rendered through the new report path: 4/4 sample discovery packets, 14 scenarios, two previously assessed and critical-checked conditional threats, twelve unassessed scenarios. The final PDF is 14 pages, retains all supported findings, displays verified source excerpts and has no horizontal overflow. Those two findings concern settings writes under default authentication configuration and ordinary API keys receiving administrative authority when the admin-key set is absent. Reformatting does not constitute a new assessment.

## New live qualification and defects found

The initial bounded cohort used six combined model requests, 178,500 reported tokens and 562 seconds. It completed one discovery packet and generated two hypotheses but no new completed engineering decision. This was not accepted as proof that the workflow produced an actionable finding.

Follow-up qualification of the gap-read path exposed and corrected:

1. Repeated `_resolve_gap` call sites outranked the implementation.
2. Retrieving another missing control could drop a previously read helper from the next packet.
3. Handler inspection omitted the router's own dependency declaration.
4. A local `APIRouter` request expanded into unrelated routers across the portfolio.
5. Unbound text-search matches were treated as mandatory dependencies; omitted unrelated candidates incorrectly made a case incomplete. Explicit requested locations remain required, while unbound candidates retain truncation/search metadata.
6. The model confused an absent control with absent evidence. The prompt now distinguishes them, without weakening source citations or automatically changing any finding status.
7. A composed control argument could exceed the previous four-citation limit. The bounded limit is eight; every added citation is checked, and unsupported citations still fail.

A four-request qualification before the final router-packing correction took 318 seconds. Its critical check retained `needs-context` because router-level enforcement was not yet supplied. The draft was not promoted. This is a useful guard result, not a completed threat review.

## Automated verification

The unit/integration suite and browser suite exercise fixtures. The browser suite covers saved scope, resume, questions, report exports, source consent, stale state and failure handling. Linux, Windows and macOS CI also qualify the platform-specific persistence and source handling; the real Semgrep jobs are separate from the locally skipped engine-dependent cases.

Final check counts and the final live case result are recorded in the release closeout below. A passing fixture is not labeled as a live JCI finding.

## Remaining qualification

* On JCI, run a small cohort using the existing graph and approved gateway. Verify exact implementations for the previously unresolved `ApplyAuthorization`, `TryRevokeAccess` and `SolutionAuthorizationHandler` path before another long run.
* Confirm the intended deployment profile and answer the report's exposure/access questions. Source and reviewer declarations do not establish effective runtime configuration.
* Large-scale graph partitioning, proven-control reuse across independent cases, independently configured critical-review models and parallel engineering leases remain follow-on design work.
* No equal-scope cost benchmark or MDASH comparison has been completed. No whole-JCI completion, runtime reachability or exploitability is claimed.

## Release closeout

The new live gap-read case reached `static-supported` with `challengeCompleted: true`, no missing evidence and no recorded source gaps after the local router declaration was retrieved. That final bounded follow-up used **2 calls, 57,915 reported tokens and 169 seconds**. These figures exclude earlier debugging/qualification calls and must not be advertised as end-to-end savings. The discovery scope still has **1/506 packets completed**, two returned scenarios and one unassessed scenario; the full repository was not rerun.

The supported conclusion is narrowly conditional unauthorized read of gap details, insights, root-cause analysis and proposed fixes through `/analyze/gaps/{gap_id}` and its insights route when a caller can reach the application without an applicable upstream restriction. The route constructor, application registration, handler and `_resolve_gap` are cited. No write or execution is demonstrated. The need for per-user/object isolation depends on the intended user model. Deployment-question consequences are model-authored review advice, not verified facts or automatic risk acceptance.

A local read-only engineering inspection confirmed the router constructor has no dependency argument and `_resolve_gap` receives the caller-supplied identifier. Additional inspection of `_require_gap_storage` found an availability check, and the in-memory/file-backed storage implementations retrieve by identifier without a caller-identity argument. That additional inspection was not represented as another model call. The default report includes exact source excerpts and the separate critical-check status. It now omits wholly unreviewed feature/component rows from the main narrative with explicit counts, and limits diagrams to interfaces of supported threats. Full scope and unresolved work remain in the technical export. The resulting live report is **9 pages**, one detailed finding and two source windows, with no horizontal overflow. The larger preserved report remains available separately.

Local syntax checks passed. The final full local suite passed **320 tests**, with three scanner-dependent cases skipped and no failures. The last report changes also passed four targeted browser cases. The complete browser suite passed **35 tests**, with three optional integration cases skipped. Final-head CI is the merge gate for all OS/Node combinations, browser checks and real Semgrep jobs; inspect PR #30's final commit checks rather than an earlier green commit.
