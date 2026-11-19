# Threat references, boundary crossings and STRIDE status

## Compatibility

The existing STRIDE planner, provider contract, evidence validation, call budgets, persistence and resume remain in place. Invalid connection endpoint and trust-transition errors now name the schema violation. The existing validation retry requests an empty optional connections array while retaining threat analysis; evidence checks remain strict. Presentation fields are derived after existing record fingerprints and reviewer decisions have been computed. Saved IDs, decision subjects and snapshot identity are unchanged.

## References and review priority

Threats, boundaries and flows display short T-, TB- and F- references derived from saved IDs. These are not new records or sequence numbers that shift on sorting. Prefix collisions in a projection expand to full IDs. The UI, PDF/HTML and corresponding CSV registers share the references; original IDs remain available for audit and integrations.

Actual scenarios sort by an explained review order. Fresh reviewer severity is retained; production-candidate identity/privilege scenarios receive early review, followed by other production-candidate scenarios. Test/vendor-only citations require applicability review. Architecture-only references are labeled Establish code path, rather than treated as implementation evidence. Stale, rejected/not-applicable and risk-accepted records retain their explicit disposition. Priority is not severity, reachability proof or a confirmed vulnerability. Unknown severity stays unassessed. Conditional impact, prerequisites and cited controls remain visible.

Trust-boundary records name the affected source/destination and flow references, the trust dimension, before/after transition, enforcement evidence and review status. Threat-to-boundary associations derived through shared interfaces are labeled as associations requiring relevance review. DFD badges show TB references for the selected lens; clicking and the inspector retain the existing selection/trace workflow. Candidate boundaries are not automatically accepted or converted into deployed trust zones.

## Matrix

`state` and reviewer decisions retain their original behavior. Separate `analysisStatus`, `analysisLabel`, `failedEvidence` and `scenarioReferences` distinguish not analyzed, failed, partially analyzed, stale, scenarios identified, and analyzed with no scenario identified. Partial/failed review is not rendered as a clean zero. A reviewed-no-scenario disposition remains a human decision distinct from model submission.

## Acceptance checks

- Existing system workspace, STRIDE, gateway, evidence-validation, cache/resume and decision-fingerprint tests continue to pass.
- `review-presentation.test.mjs`: references and saved IDs, boundary endpoints, applicability and explained priority, failed/partial/stale/empty/scenario states, preservation of reviewer decisions.
- Browser tests retain actor/boundary editing, threat selection, matrix navigation, printable output and full exports; add short-reference and priority checks in the existing returned-STRIDE-scenario flow.
- Run live STRIDE against open-autofix using the approved configured provider. Publish actual scenario titles, source references, call/token accounting and completed/failed/pending counts. A bounded verification run must not be called a complete portfolio assessment. No target execution, dependency installation or network probing.
