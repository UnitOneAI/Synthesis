# STRIDE disk-plan recovery verification

## Confirmed defects and fixes

The parallel scheduler introduced an eager pending array that held every disk-backed packet payload. A regression with 450 SQLite packets observed 450 live payload objects at first dispatch. The scheduler now queues numeric indices and loads payloads only inside active workers; the same test observes at most four live payloads at concurrency four. Packet content, identities, requested scope and cache keys are unchanged.

An early worker failure could leave the previous stale review explanation as the primary message. The server now preserves historical results and stale status while separately recording the latest failed run's safe reason and stage. The matrix distinguishes historical completions from current valid coverage. Small error exports retain explicit stale causes and latest-attempt failure metadata without source or model prose.

The UI also estimates remaining scope from measured successful request durations. It requires three valid samples, uses at most the latest twenty, matches provider/model/source revision and review phases, prefers current-action samples, and accounts for configured worker concurrency. It excludes failed/in-flight requests from the latency sample and labels assumptions about steady throughput, retries and throttling. An estimate is not a completion guarantee; a stopped action is labeled “if resumed.”

## Scope of diagnosis

The supplied older JCI error export records stale STRIDE analysis with 12 historical completed packets, 438 pending and zero failed packets. It does not prove that the newly reproduced memory regression caused the latest JCI symptom. No literal “stale packet” error exists in the current source. Changed source/architecture revisions or guidance/prompt identity can legitimately invalidate prior results. These guards remain enabled.

## Checks

- 450-packet SQLite retention regression: failed before, passed after the queue fix.
- Actual worker integration across twelve repositories with disk storage: two active requests, cancellation, unknown usage, saved graph reuse and resumed continuous completion without recollecting source.
- Early-worker-failure browser regression: retained stale scenario, explicit latest failure, historical/current coverage distinction, safe error export.
- Timing tests: sparse/invalid/incompatible samples, failed calls, historical/current sampling, worker count and conditional display.
- Failed-response retry tests: exact allowed control/boundary references, empty reference sets, initial-call behavior unchanged, and rejection of architecture evidence as a security control.
- Browser suite: 28 passed; one optional saved-output fixture skipped.
- Full Node suite: 212 passed, zero failed or skipped.

## Live provider check

Two selected repository packets from the saved open-autofix disk graph were sent to direct Claude Opus 4.6 using native structured output. The initial calls failed evidence/reference validation. Explicit retries with the strengthened reference guide completed both packets, returning eight conditional threat scenarios. The matrix reported partially analyzed: two completed, zero failed, 846 pending of 848 planned. Source revision was unchanged. The successful retry action reported 67,615 tokens across two calls, with no unknown usage; the initial failed action also consumed tokens (67,632 reported).

This was saved-graph metadata review, not a full source-code investigation or complete portfolio run. Returned scenarios still require control/counterevidence review. No target application was executed, and direct-provider success does not qualify the customer gateway. Live outputs remain outside the public repository.

Local live-provider and browser validation details are recorded with the release runbook. JCI gateway availability and its latest stale reason require evidence from that environment; local tests do not establish either.
