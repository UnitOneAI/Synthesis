# Parallel review verification

## Contracts tested

- A shared coordinator dispatches each packet once per action, with 1–4 concurrent workers and a default of two.
- STRIDE and CWE request limits apply to the whole action, not each worker; continuous review still crosses 100 requests across twelve repositories.
- Serial and out-of-order parallel completion produce equivalent threat/CWE findings and coverage. Duplicate CWE findings follow deterministic plan priority, not response arrival order.
- Completed compatible packets survive worker-count changes and explicit resume without new calls for those packets.
- Prepared packet intent is checkpointed before dispatch. Actual in-flight attempts are saved while responses are pending. Known cancellation before dispatch does not invent a provider call or token usage.
- Provider failures, cancellation and persistence errors stop new dispatch and settle active work. Serialized checkpoint copies cannot mutate while a save is in progress.
- Interrupted worker state is normalized after Stop/restart; polling and repeated restore do not duplicate counters. Prepared submissions that cannot be resolved after interruption are separately labeled uncertain, without inventing calls or tokens.
- The source reader visits only planned files, groups repeated records, checks hashes and containment, rejects symlinks/invalid paths/binary or oversized files, honors cancellation, and redacts private-key blocks across excerpt boundaries.
- Browser tests cover both controls, actual parallel CWE dispatch, status, cancellation, restored STRIDE state, existing DFD/trust-boundary presentation, code evidence and reports.

## Results

- Syntax checks passed.
- Full Node suite: **206 passed, zero failed, zero skipped**, including qualified Semgrep integration.
- Browser coverage: **27 passed after correcting a stale boundary-label test assertion; one optional saved-real-output fixture skipped**. The production DFD was unchanged by that assertion correction. Targeted interruption/parallel browser checks were rerun after the final recovery-state changes.
- Direct source retrieval was also exercised against the local open-autofix checkout. No target code was executed and no live provider requests were made for these new orchestration checks.

See [architecture and measured scope](../architecture/parallel-static-review.md) for local read and controlled-latency measurements. Tests establish execution and accounting correctness; they do not establish live JCI gateway capacity or guarantee vulnerability detection.

## Commands

Run from `packages/static-pilot`. Set `SYNTHESIS_TEST_SEMGREP` to the installed, qualified Semgrep executable to include scanner integration tests.

```text
npm run check
npm test -- --test-concurrency=1 --test-timeout=120000
npm run test:ui
```

The optional saved-output browser test additionally requires `SYNTHESIS_VALIDATION_WORKSPACE` and `SYNTHESIS_VALIDATION_SOURCE_ROOT`. Windows accounts that cannot create symlinks may skip the corresponding fixture with an explicit reason; that is not a successful symlink-rejection test on that host.
