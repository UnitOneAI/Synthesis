# Connected DFD, STRIDE results and CWE verification

## Acceptance cases

1. Build a disk graph for 12 synthetic local repositories. Eleven caller/listener matches connect them without declarations. Warm rebuild, database reopen and Mermaid export retain evidence. Changing a route removes its prior automatic connection.
2. A unique route-only match remains a hypothesis. Ambiguous destinations, wrong literal hosts and protocol/name coincidences do not become established links. Distinct store identities remain distinct; credentials do not appear in retained connection metadata.
3. C# controller, Next route, Python prefix, same-file AST wrapper and configured queue cases resolve with evidence. A queue without a broker identity remains unresolved.
4. Run STRIDE with request budget one. Exactly one call occurs, returned scenarios populate component cells, pending repositories remain visible, and actors/boundary candidates exist before manual declarations. Checklist items never increment scenario counts.
5. With qualified Semgrep, scan 12 repositories. All positive cases are reported, safe alternatives are not, file hashes match the graph snapshot, and every bundled rule has a positive fixture. Test-folder code and nosemgrep directives cannot silently remove selected scope.
6. Missing/wrong scanner, parser gaps, source changes, process cancellation and output limits produce explicit outcomes. Provider credentials do not reach the scanner subprocess.
7. Model CWE review submits real source segments to the configured gateway contract, validates record/line references and CWE IDs, counts response usage even on rejected findings, resumes completed packets and visits other repositories under repeated small budgets. Source drift prevents calls.
8. Browser: build 12-repository DFD, scan CWE, filter, save a reviewer decision, export SARIF and reopen the persisted workspace. Check original DFD/actor/boundary/STRIDE/register workflows for regressions.
9. Read-only qualification against a real local repository. Record graph counts, candidate connections, scanner coverage, model sample/remaining scope and token usage. No target code is executed. A live model sample is not a complete audit.

## Commands

From `packages/static-pilot`:

```powershell
npm ci --ignore-scripts
npm run check
npm test
$env:SYNTHESIS_TEST_SEMGREP = 'C:/Tools/SynthesisScanner/Scripts/semgrep.exe'
node --test test/cwe-scan.test.mjs test/cwe-model.test.mjs test/connection-discovery.test.mjs
npx playwright install chromium
npm run test:ui
```

Without `SYNTHESIS_TEST_SEMGREP`, real-engine cases are explicitly skipped. CI runs Node 22/24 on Windows/Linux/macOS, browser tests on Windows/Linux, and pinned real-engine tests plus the 12-repository browser workflow on Windows/Linux. Run browser invocations sequentially because they share the test artifact directory.

Synthetic scanner fixtures are intentionally unsafe source text. Tests inspect them statically; they do not execute them. Provider transport tests are mocked and must not be described as live customer-gateway validation.
