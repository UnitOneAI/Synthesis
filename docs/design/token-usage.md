# Token accounting for static threat modeling

Implemented in static pilot 0.4.1. The STRIDE workspace reports provider-returned consumption for the current action and the saved workspace, with repository-local and shared cross-repository totals.

## Accounting contract

- Record one ledger entry per request attempt, with a unique ID, action ID, provider, exact deployment/model, source revision, batch ID, phase, participating repositories, timestamps, status and normalized usage.
- Capture usage before validating response content. A response rejected for malformed JSON, invalid evidence or output truncation still consumes its reported tokens.
- Input tokens include cache reads and cache writes. Anthropic reports these separately; add them to ordinary input once. Gemini prompt counts already include cached content; do not add cache reads again. Gemini output includes reported thinking tokens. The cache columns are subsets, not additions to the input total.
- Record absent/invalid usage as unknown. Timeouts, interrupted requests and HTTP failures may have consumed tokens without returning a usable usage object. Report known subtotals and unknown request counts; never substitute zero or a byte/character estimate for unknown consumption.
- Assign each single-repository request to that repository. Put multi-repository requests in one shared-analysis bucket, with all participating repositories on the request record. Do not charge the complete shared request to every repository or invent an exact per-repository allocation.
- Preserve attempts across retries, provider/model changes, source rebuilds and restart within the same workspace. Reusing a locally completed batch creates no new request and adds no tokens. Source collection itself uses zero model tokens.
- Checkpoint an in-flight attempt before graph-review dispatch, then checkpoint provider usage before response validation. The worker waits for the local server's persistence acknowledgement. Interrupted attempts retain any known usage; otherwise they remain unknown. An abrupt failure outside the application's acknowledged checkpoint boundary still requires reconciliation with gateway accounting.
- Old snapshots display an unmetered-history notice. Earlier token consumption cannot be reconstructed from batch counts, source size, or response hashes. Totals cover recorded attempts only.

## Presentation and export

In **STRIDE matrix → Token usage**, show workspace reported totals, current action totals, recorded/unknown request counts, a repository/shared table, and the latest 50 request records. Progress updates preserve expanded panels. Use **Token usage · CSV** for the full attempt ledger; complete JSON includes the ledger and summary, and the HTML report includes accounting totals and scope breakdown. CLI analysis also writes `token-usage.csv`.

The ledger stores no raw request/response bodies or credentials. Source names and model/deployment provenance remain private metadata. Token counts are not a currency estimate or invoice: gateway pricing, quotas and billing reconciliation remain customer-specific. This release does not add automatic prompt caching, a token spending cap, or preflight token estimation; the existing request budget remains the scheduling control.

## Model compatibility

The same single configured Anthropic Messages-compatible deployment handles all batches. Repository count does not require multiple models. The operator's exact deployment name is passed unchanged; no model or provider fallback occurs. The application currently bounds packets to 60 records / 96 KiB and outputs to 8,192 tokens, with a 120-second request timeout. Gateway quotas and limits may be lower and require environment qualification.

## Verification

`token-usage.test.mjs` covers provider normalization, cache accounting, rejected output, retries, local cache reuse, shared-scope totals, persistence, missing usage and interruptions. The staged worker integration test verifies persisted usage, cancellation and preservation after a source rebuild. Browser coverage verifies live totals, shared scope, unknowns, preserved expansion, narrow layout and CSV download. All existing workspace/export tests remain required.

References: [Anthropic context and usage](https://platform.claude.com/docs/en/build-with-claude/context-windows), [Anthropic caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching), [Gemini usage metadata](https://ai.google.dev/api/generate-content#UsageMetadata).
