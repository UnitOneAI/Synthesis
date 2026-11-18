# Static security intelligence verification

## Acceptance cases

1. A source-grounded excessive-authority candidate with no CWE survives validation, UI rendering and JSON export. Unknown CWE identifiers and unsupported issue kinds fail validation.
2. Invented records, invalid line ranges, uncited input/sink arguments, and ruled-out conclusions without control citations fail. Missing evidence downgrades proposed conclusive assessments.
3. Twelve synthetic repositories retain independent candidates. Small budgets resume across repositories, completed assessments do not repeat model calls, and every provider-reported token is accounted for.
4. A missing-control request retrieves only indexed, selected source. The next assessment preserves the prior outcome and references. No target code, build, dependency restore, shell command or network probe executes.
5. Changed source, path escapes, symlinks and unavailable files cannot provide trusted evidence. Model failures remain visible and metered; unresolved context remains partial.
6. Source, architecture and methodology changes invalidate assessment reuse. Human decisions remain separate from model assessments.
7. Browser flow: source build → model discovery → evidence assessment → investigation inspection → JSON export → restart. Consent and model configuration are required for source transmission.
8. Open-autofix: run the real bundled Semgrep rules and bounded real model source review/assessment. Preserve actual outputs, usage, coverage and limitations outside the public repository. Compare working-tree state before/after. Do not use fixture responses as evidence of actual detections.
9. Requested CWE IDs remain explicit: unmapped concerns cannot replace required target assessments. Mapped findings retain their target IDs and per-CWE coverage. Extra concerns never mark a requested target complete.
10. Oversized investigation packets trim catalog metadata before source windows. Every omission is counted, evidence gaps remain visible, and requests stay within the byte cap. Native JSON mode must not claim provider-side schema enforcement on an unsupported provider.

## Commands

From `packages/static-pilot`:

```text
npm run check
npm test
npm run test:ui
```

Set `SYNTHESIS_TEST_SEMGREP` to the qualified scanner executable to include scanner integration and browser cases. Provider contract tests use synthetic responses; the separate open-autofix run records the live model/deployment and bounded scope. A local provider run does not validate a customer's gateway or unavailable customer repositories.

## Review evidence

The delivery record must state test results, actual scanner findings, model candidates, investigation outcomes, tokens, pending scope and any live-provider failures. A main-branch push is withheld until the user has seen the requested output. No quality claim is based solely on finding count or a successful HTTP response.


## Exploration acceptance

`test/exploration.test.mjs` covers all 348 requested target obligations over twelve repositories, the 72 STRIDE category obligations, pagination with explicit omissions, ancestor lineage, source/control/gap relationships, append-only state changes, retained source revisions, reopening SQLite, a shared provider-call budget, completed packet reuse, source-graph fingerprint stability and cancellation.

The browser investigation test also covers source-sharing consent, typed graph navigation, group folding, candidate lineage, redacted hash-checked source retrieval, rejection after a file changes, export and restart. The saved open-autofix browser test renders actual retained model/scanner output, captures the exploration graph and exports its selected lineage without additional model calls. These are static tests; real JCI repositories and gateway must be validated inside JCI.

## Inline CWE code evidence

`test/cwe-evidence.test.mjs` checks scanner/model locations, context limits and pagination, all locations in a multi-file finding, source hashes and stale revisions, selected-source containment and symlink rejection, secret redaction, authenticated access, and rejection of arbitrary client-selected paths. Browser checks exercise both Semgrep and model code panels, highlighted citations, source text escaping, changed-file rejection, and zero additional model calls. The saved open-autofix test captures `cwe-code-evidence.png` from a real candidate's source.
