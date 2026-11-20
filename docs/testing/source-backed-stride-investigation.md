# Source-backed STRIDE acceptance

- Saved graph: read current code without recollecting or reparsing the graph; reject changed source before cached review reuse.
- Context integrity: reject unselected sources and invented retrieval references; permit only indexed searches/neighbors; retain missing-source and context-limit gaps.
- Twelve repositories: STRIDE requests an authorization implementation in another repository, receives verified code, reassesses the same packet and preserves history. Restart does not repeat completed model calls.
- Confidentiality: persisted review and traces retain source references/hashes, not raw code windows. Existing redaction, path-containment and symlink tests remain applicable.
- Standards: retain versioned OWASP 2021 mappings, add 2025 and curated CAPEC; all omitted ASVS assessments remain not-reviewed. Reject unsupported requirement IDs and unsupported source claims.
- Regression: existing parallel/continuous STRIDE, coverage, gateway protocol, budgets, cancellation, requested CWEs, PDF exports and browser workflows must continue to pass.
- Real repository: inspect a saved open-autofix graph and submit a bounded source-backed packet to the approved provider when available. Record scope, failures, token usage and unresolved context without calling it a full portfolio assessment.

The native structured-output schema now restricts STRIDE identifiers to those in the submitted packet. This reduces identifier confusion but does not replace interface/evidence ownership validation. Gateways retain the existing prompt-only contract unless native schema mode is explicitly enabled. Failed live responses remain failures and consume recorded tokens; they are never repaired into accepted findings by loosening citation rules.

## Verification, 2026-11-20

- `npm test`: 216 passed, 3 skipped, 0 failures (219 tests).
- `npm run test:ui`: 28 passed, 2 skipped, 0 failures. Covers existing DFD, STRIDE, source-consent, parallel/continuous runs and export workflows.
- `npm run check` and `git diff --check`: passed.
- Twelve-repository follow-up uses a synthetic static graph and mocked model responses. It proves retrieval, reassessment, context retention and continuation mechanics, not vulnerability-detection accuracy on JCI code.
- Live direct-Claude testing exposed identifier confusion and unsupported native `maxItems`. The native schema now constrains nonempty identifier sets, describes empty sets, and leaves evidence ownership and empty-set enforcement to the existing local validators. A regression test rejects unsupported array constraints in the outbound native schema.
- JCI gateway and JCI PR before/after qualification remain outstanding; no live gateway result is implied by protocol fixture tests.

### Bounded live open-autofix result

Direct Anthropic `claude-opus-4-6` accepted one prepared repository packet using the stricter validation-retry contract and native structured output. This was one of 867 planned packets, not a complete repository review. Four hash-checked source windows were supplied; 26 source/context gaps remained explicit. Usage for this accepted request was 37,849 input plus 3,738 output tokens (41,587 total). Earlier rejected attempts are separate and are not included in that figure.

The response returned four conditional scenarios: filesystem-path access, authentication coverage, job ownership and synchronous-operation resource exhaustion. All remain needs-review. Ten ASVS requirements were `needs-context`; one was `not-applicable` to the supplied API packet. No requirement was marked source-supported. Structural acceptance verifies the response contract and citation ownership, not factual correctness or exploitability. Adaptive twelve-repository reassessment was verified by the fixture above; it was not live-qualified against JCI in this run.

Native schema compatibility follows the [Anthropic structured-output contract](https://platform.claude.com/docs/en/build-with-claude/structured-outputs). Empty-reference enforcement remains local because the provider rejected `maxItems` in the outbound schema during live testing.
