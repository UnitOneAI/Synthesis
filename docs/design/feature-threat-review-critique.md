# Principal engineering and security architecture review

Perspective: enterprise threat-model review informed by AWS and Azure guidance. This is an internal design critique, not an endorsement by either company.

| Initial weakness | Consequence | Design correction | Release evidence |
|---|---|---|---|
| Packet count treated as progress | Thousands of calls can yield few decisions | Separate discovery, engineering closure, deployment declarations and acceptance | Cohort/resume tests; distinct counters |
| Repository scope inflated by helper definitions | Small POC still has thousands of primary subjects | Explicit security-feature mode with full deferred inventory; retain all-subject mode | Compare saved-graph plans without dropping category obligations |
| Breadth-first hypotheses before control retrieval | Budget exhausted before actionable findings | Finish bounded missing-code rounds before expanding discovery | Ordering and combined-budget tests |
| Name index treated as sufficient retrieval | Available authorization helper remains unread | Safe indexed-file fallback; exact function windows; explicit truncation | Cross-repository missing-index fixture |
| Call sites mistaken for definitions; prior helper lost on follow-up | Available implementations remain unread or are repeatedly requested | Rank actual definitions first; retain typed obligation citations across rounds | Reproduced on saved open-autofix graph; bounded packing regression |
| Missing control confused with missing evidence | Correctly identified control absence stays pending | Define obligation status as evidence availability; preserve strict citations and critical check | Prompt distinction; no automatic promotion |
| Handler inspected without router dependencies | Handler-only inspection can overstate absent authentication | Retrieve the local router constructor alongside application composition; exclude import bindings | Real saved-graph reproduction and paginated constructor regression |
| Shared context interpreted as shared policy | One route's control can incorrectly clear another | Per-operation/category evidence and route applicability | Distinct-policy negative case |
| Same model's second pass called independent proof | Correlated model error remains possible | Separate critical role; label provider independence honestly | Retain challenge identity and cited counterevidence |
| Deployment assumptions used to excuse missing code | Unsupported conclusions look complete | Four code obligations and separate reviewer declarations | Missing binding cannot close via yes/no |
| Private-network assumption dismisses risk | Authenticated insider/peer misuse disappears | Explicit actor capabilities and bypass-path conditions | Internal and external actor tests |
| Trust boundary inferred from repo | Architecture becomes meaningless | Trust transition based on identity/authority/data; candidate basis visible | No autoapproval and no fabricated connection |
| Huge report mixes hypotheses and findings | Reviewer cannot decide what to fix | Concise decision report; full technical export with counts | Saved-report rendering and no hidden findings |
| Schema repair can weaken evidence | Invalid output becomes accepted finding | Preserve evidence validation; metered correction only | Invalid citations remain failed/incomplete |
| “Run until complete” ignores cost of closure | Unbounded spend or stalled case loop | Per-case limits, no-new-evidence stop, checkpoint and provider guards | Cancellation/resume/no-duplicate tests |
| Competitive ambition lacks benchmark | Unsupported marketing claim | Labeled static threat-model benchmark and expert adjudication | No “beats MDASH” claim before evaluation |

## Release decision

The architecture is suitable for an incremental vertical implementation on the existing graph. Approval to implement is not approval to claim complete JCI coverage. Release claims must match a checked-in validation record. The first release must improve retrieval and decisions without weakening citation validation, existing CWE coverage, or historical-result preservation.

## Stress cases that must remain honest

* The graph contains only an interface declaration: retrieve concrete registration and implementation, or retain the exact missing binding.
* An installer declares an ACL: report declared protection. A reviewer can identify the deployed profile; no runtime ACL verification is implied.
* An authorization method exists: existence alone does not establish that this route calls it with the correct object and identity.
* A log call exists: it does not establish durable audit collection, attribution or tamper protection without the supporting implementation/configuration.
* A retry exists: it can improve availability or amplify load. Examine bounds and failure behavior.
* The model finds no issue: report only the actually reviewed category/subjects, not a clean repository.
* No live JCI graph is locally available: qualify mechanics on saved open-autofix and fixtures, then require Windows evidence for JCI-specific conclusions.

## Benchmark design

Use a frozen corpus with known positive, blocked and unresolved paths across all six STRIDE categories, including cross-repository controls. Have security reviewers adjudicate blinded outputs. Compare equal source access, scope and cost envelope, and publish precision/recall only for labeled cases. Record elapsed time, billed/reported tokens, unresolved-rate, unsupported-impact rate and reviewer time. MDASH's runtime-assisted or proprietary findings are not an apples-to-apples static-only benchmark. The product can outperform a baseline in reviewer usefulness without claiming superior vulnerability discovery across all languages.
