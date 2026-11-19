# Continuous static review

## User contract

STRIDE and CWE source review each offer an opt-in **Run until complete** control across the repository scope in the saved model. Existing bounded actions remain the default. There is no 100-request stop or elapsed-time stop in continuous STRIDE. CWE already has no elapsed-time action limit; continuous mode removes its request-count stop. Local Semgrep scanning already visits every selected local repository and requires no continuous model mode.

A token target is optional, applies to the current action, and is advisory. Input/output/cache usage and unknown usage are retained in the existing ledger; failed calls count. Reaching the target emits a trace event and warning but does not stop. The workspace-wide token meter and CSV retain history across actions. A target is not a spending cap or cost estimate.

The browser starts a server-side operation. It need not remain open. Only one analysis operation runs at a time. Closing/stopping the server interrupts the operation; after restart, open the saved graph and explicitly resume. Completed compatible packets are retained, and unknown usage from an interrupted request stays unknown. No automatic provider calls occur merely from restarting the server.

## Termination and coverage

Run until complete attempts the remaining planned packets once during an action. It is not an infinite retry loop. Stop, provider/authentication failures, repeated invalid-format responses, source changes, checkpoint/trace failures and existing resource safeguards remain meaningful stopping conditions. A finished pass with failed packets or coverage gaps is partial, never a clean completed assessment. Fix the cause and resume to retry failed packets. Semantic evidence validation remains mandatory.

Saved IDs, evidence hashes, analysis prompts, model schemas, graph extraction and cache keys are unchanged by mode or token target. Switching between bounded and continuous mode reuses compatible successes. The JCI gateway deployment contract is unchanged.

## Implementation

- `review-run.mjs`: validates run controls, derives current-action usage and records advisory target crossings without changing provider budgets.
- `graph-review.mjs` / worker / server: propagate mode, remove the normal time/request stops only for continuous review, checkpoint progress and retain cancellation. The server's 30-minute worker watchdog is bypassed only for continuous STRIDE; per-provider request timeouts remain.
- `cwe-model.mjs`: constructs the existing metadata plan once and loads transient code for at most 100 selected packets at a time. Later windows reread local source and verify hashes; the graph is not rebuilt. No source excerpts enter checkpoints. Metadata/parser/planner limits remain.
- Status API: returns compact per-mode progress, counts and advisory usage. UI controls preserve source-sharing consent and display persisted results after reload. Source evidence still resolves saved locations with hash/path checks.
- Scanner coverage now expands into actual recorded error types and file paths, with full details in the scanner JSON export. Unsupported extensions are explained separately from parsing failures.

## Tests

- Continuous STRIDE crosses 100 calls across twelve repositories and a simulated 24/30-minute boundary; all planned packets complete, token target crossings do not stop, and restart/resume does not repeat successes.
- Existing worker integration exercises bounded runs, continuous cancellation, resume without source recollection, continuous completion and status-token reporting.
- Continuous CWE crosses 100 packets across twelve repositories. Source windows stay at or below 100 packets, all repositories progress, token targets are advisory, and compatible restart performs no new calls.
- Cancellation, source changes, provider rejection and repeated invalid output retain saved work and stop safely. Invalid controls/targets are rejected.
- Browser tests exercise both controls, request payloads, actual CWE API execution with a deterministic provider, source-sharing consent, live usage, Stop, saved workspace reuse and verified code evidence. No target code is executed.

Synthetic provider responses test orchestration and accounting, not real-world finding accuracy or JCI gateway availability. Existing live open-autofix output remains separate from these regression fixtures.

## Validation results

- Syntax checks: passed.
- Full Node suite: 187 passed, 0 failed, 0 skipped, including the qualified Semgrep 1.185.0 integration tests.
- Selected browser regressions: 7 passed, covering continuous controls and cancellation, twelve-repository scanning/review/restart, PDF code evidence, actor/boundary declarations and STRIDE presentation.
- Model calls used deterministic test responses. No live customer gateway calls or target execution were performed for this change.

Run the engine suite with `SYNTHESIS_TEST_SEMGREP` pointing to the qualified scanner and `npm test -- --test-concurrency=1 --test-timeout=120000`. The browser selection is `npm run test:ui -- --grep 'continuous|CWE and threat model PDF|actor, boundary and domain|STRIDE, threat details|partial STRIDE results|12 repositories connect automatically'`.
