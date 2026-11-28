# Local assessment cache qualification — 2026-11-28

## Measured result

The saved open-autofix graph was opened read-only. One previously supported threat concerning unauthenticated session creation was reassessed from source and independently challenged, with an empty workspace cache. A fresh model projection and reopened SQLite cache then repeated the same investigation without a provider request.

| Measurement | Empty cache | Reopened local cache |
| --- | ---: | ---: |
| Actual provider requests | 2 | 0 |
| Reported input tokens | 52,306 | 0 |
| Reported output tokens | 6,428 | 0 |
| Total reported tokens | 58,734 | 0 |
| Elapsed time, including retrieval and validation | 162.1 seconds | 4.5 seconds |
| Locally reused validated assessments | 0 | 2 |
| Conclusion | Supported conditional | Supported conditional |
| Independent challenge complete | Yes | Yes |

Provider: direct Anthropic `claude-opus-4-6`, native structured output. Cache-read and cache-write usage reported by the provider were both zero. The application cache supplied the warm result; the warm test transport deliberately rejected any provider dispatch. The graph file hash remained unchanged.

This is a **one-case repeat-investigation benchmark**, not a claim that a new JCI section finishes in 4.5 seconds. The report retains the other seven assessed scenarios and all six category conclusions from the completed baseline. The resulting section remains complete with three operations, eight supported conditional scenarios and no completion blockers. A warm cache is not evidence of newly tested runtime behavior.

## First-request payload reduction

Using the actual graph-derived packets, round-trip expansion preserved every original field, source line, citation range and explicit gap:

| Packet | Original JSON | Compact JSON plus extra instructions | Net reduction |
| --- | ---: | ---: | ---: |
| First engineering assessment | 72,382 bytes | 60,835 bytes | 16.0% |
| Section discovery | 82,469 bytes | 82,469 bytes | 0% |

Discovery compaction initially saved only 0.5% including instruction overhead; the implementation now skips compaction below five percent. The two live engineering requests avoided 24,162 duplicate input bytes in total. These are byte measurements, not a measured token or latency comparison against an uncompressed live run. No extra paid baseline call was made just to manufacture a percentage.

The prior completed section's 29 calls and 921,524 reported tokens include development retries and continuation. They are not a clean cold-run baseline. This change does not claim a reduction from that total to 58,734 tokens: only one case was newly assessed here.

## Regression verification

- Full static suite: 367 tests, 364 passed, zero failed, three scanner-dependent skips.
- Focused cache tests cover exact-match persistence, corruption, bounded storage, forbidden source-tree paths, redaction, code/scope/model/prompt/schema/validator invalidation, independent challenge separation and zero fake usage on cache hits.
- Automatic section tests restore all six category decisions from a fresh projection using the cache and reject changed source.
- Full browser suite: 36 passed, zero failed, three environment-dependent skips. Verification shows local reuse separately from provider requests and retains completed-section export.
- Existing STRIDE, CWE, source collection, evidence and report tests remain in the release gate. Windows and real Semgrep checks must pass in CI before release.

## Reproduction artifacts

Local validation directory: `validation-system-workspace/local-cache-2026-11-28/` outside the repository. It contains `payload-measurement.json`, `live-measurement.json`, separate cold/warm snapshots and regenerated HTML reports. No credentials or cache database are committed. The reports distinguish cumulative prior paid work from the isolated measurement above.
