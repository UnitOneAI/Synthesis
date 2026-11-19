# Windows: static system threat modeling

## Current update: 0.10.0 — reuse and focused exports

Keep the same `--source-root`, `--workspace` and `--graph-storage sqlite` when restarting. A saved 0.9.0 graph can be reused by 0.10.0 without rebuilding: this release does not change extraction rules. In Sources, use **Open saved graph**. Rebuild only for changed source, repository scope, older extraction rules or a deliberate extraction refresh. Restart does not verify current file contents. Historical upgrade sections below describe one-time migrations, not an instruction to rebuild on every start.

Open **Source graph → Export graph review package**. Choose repository/component/flow/finding/CWE with findings/system overview. Leave source context off for architecture-only review; enable it when code evidence is needed. Click **Prepare graph package**, then download each numbered transfer ZIP. The transfer ZIPs contain the small review parts. Each ZIP is at most 3 MiB. Its manifest records snapshot IDs, omissions, hashes and scope. Changed source is excluded from optional windows and reported as a gap. This neither rebuilds the graph nor calls a model.

Save downloaded parts under your exports folder outside the clones. Browser downloads use the browser's configured directory; this feature does not silently write them to the trace folder. Inspect the ZIPs before transferring. All numbered parts describe one selected scope; no whole-graph backup is required. The previous full graph and diagnostic exports remain available separately.

Continue STRIDE with metadata from the saved graph. The older optional STRIDE transient-excerpt mode still requires recollection after restart; its excerpts were never persisted. CWE source review reads source again for code validation but reuses the graph. See [export architecture and limits](../design/focused-graph-export.md) and [test specifications](../testing/focused-graph-export.md).

Requires a current Node.js 24 release, Git, a current Edge/Chrome browser, and readable local clones. No target application, build, installer, database, container or runtime service is started. Keep the source root, Synthesis checkout, workspace and exports in separate folders.

This can run inside a Windows VM. Open the browser inside that VM (including through Remote Desktop) using the printed local access link. Model review requires outbound access to the configured provider; static collection and manual review do not. The [disk-backed graph and VM architecture](../design/disk-backed-static-graph.md) documents the 0.6.0 implementation and remaining metadata/parser/planner limits. Local SSD storage is required; keep the workspace off network shares and synchronized folders.

## Install or update

For a new checkout:

```powershell
git clone https://github.com/UnitOneAI/Synthesis.git C:/Tools/Synthesis
Set-Location C:/Tools/Synthesis
```

For an existing checkout, stop Synthesis with Ctrl+C and back up its workspace first. Commit or preserve any local changes, then:

```powershell
Set-Location C:/Tools/Synthesis
git switch main
git pull --ff-only origin main
Set-Location packages/static-pilot
node --version
node -p "process.versions.sqlite"
npm ci --ignore-scripts
npm run check
npm test
```

Browser verification is optional on a restricted customer machine and required on the development machine:

```powershell
npx playwright install chromium
npm run test:ui
```

Run each command only after the preceding command succeeds. The test suite uses synthetic source; it does not execute any customer repository.

If the console title starts with **Select**, press **Esc** to leave text-selection mode and allow output to continue. Wait for the final test summary. On Windows, creating a symbolic-link fixture can fail with `EPERM` when the account lacks that privilege. The code-evidence suite reports only that subtest as skipped; selection, containment, hash and redaction checks still run. This skip means symlink rejection was not verified on that machine, not that production checks were disabled. Other failures must still be investigated. To capture the detailed code-evidence failure, run `node --test --test-reporter=spec test/cwe-evidence.test.mjs 2>&1 | Tee-Object -FilePath C:/SynthesisState/Exports/cwe-evidence-test.txt` from `packages/static-pilot` after creating the export folder.

## Disk graph requirements and backup

Disk mode is the CLI default and requires SQLite 3.51.3 or newer embedded in Node. Qualification used Node 24.22.1 / SQLite 3.54.1. The application checks the actual engine at startup. If it rejects the installed runtime, update Node 24. To deliberately use the prior capped backend, append `--graph-storage memory`; there is no automatic fallback.

The workspace contains `graph.sqlite`, its active journal files, `snapshot.json` and `traces`. Back up the **whole workspace after stopping Synthesis** with Ctrl+C. Do not copy only a live database file. Retain both the database and snapshot together; losing the database loses the graph referenced by the snapshot. A rebuild of unchanged clones reuses parsed files after hashing them. Graph-driven continuation verifies source hashes without rebuilding the parser graph.

Start VM qualification around 4–8 vCPU, 16 GiB RAM and SSD space sufficient for clones, graph, journals, traces and exports; these are planning estimates, not capacity guarantees. The storage guard pauses before disk exhaustion. Existing metadata, parser, traversal and review budgets still apply; inspect coverage and the diagnostic bundle.

## Supply existing clones without a workbook

Suppose the selected clones are `C:/Source/Product/repo-one`, `repo-two`, and so on. The source root is their parent, **not `C:/`**. Windows forward slashes are accepted.

```powershell
node src/cli.mjs serve --source-root "C:/Source/Product" --workspace "C:/SynthesisState/Product"
```

Open the complete access link printed in PowerShell. In **Sources**, enter the system name and one release/configuration profile. Select **Add repository** for each clone, keep **Local clone**, and set its location to its folder name relative to the source root. Select the repositories in scope. An XLSX/CSV inventory is optional.

To prepare all immediate child clones in PowerShell instead of entering them individually:

```powershell
$sourceRoot = "C:/Source/Product"
$scopeFile = "C:/SynthesisState/product-scope.json"
New-Item -ItemType Directory -Force (Split-Path $scopeFile) | Out-Null
$repos = @(Get-ChildItem -LiteralPath $sourceRoot -Directory | Where-Object {
    Test-Path -LiteralPath (Join-Path $_.FullName '.git')
} | ForEach-Object {
    @{ name = $_.Name; source = 'local'; localPath = $_.Name; selected = $true; scope = 'primary' }
})
if ($repos.Count -eq 0) { throw 'No immediate child Git clones found.' }
@{ title = 'Product static threat model'; profile = 'Intended release and configuration'; repositories = $repos } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $scopeFile -Encoding utf8
node src/cli.mjs serve --source-root $sourceRoot --workspace "C:/SynthesisState/Product" --manifest $scopeFile
```

Review the selection before scanning: this includes every immediate child clone, not an approved subset automatically. Use a fresh workspace when starting a separate product/profile. A conflicting startup manifest is rejected rather than replacing a saved workspace silently.

## Configure Claude through an enterprise gateway

The key is set in the environment of the same PowerShell window that starts Synthesis. It is not entered in the browser or saved in the manifest.

```powershell
$gatewaySecret = Read-Host 'Gateway subscription key' -AsSecureString
$env:CLAUDE_API_KEY = [System.Net.NetworkCredential]::new('', $gatewaySecret).Password
$gatewayBase = Read-Host 'Approved gateway base URL, ending in /anthropic'
$deployment = Read-Host 'Exact approved model deployment name'
node src/cli.mjs serve --source-root "C:/Source/Product" --workspace "C:/SynthesisState/Product" --provider anthropic-gateway --base-url $gatewayBase --model $deployment --api-version 2023-06-01
```

Use the exact deployment name from the provisioning notice. The gateway adapter sends `Ocp-Apim-Subscription-Key`, `anthropic-version` and the selected model to `{base}/v1/messages`. Customer endpoints and deployment defaults are not embedded in the public repository. Direct Claude uses `--provider anthropic` and `ANTHROPIC_API_KEY`; Gemini uses `--provider gemini` and `GOOGLE_GEMINI_API_KEY`. There is no silent provider fallback.

After stopping, remove the key from the current shell if finished:

```powershell
Remove-Item Env:CLAUDE_API_KEY -ErrorAction SilentlyContinue
Remove-Variable gatewaySecret -ErrorAction SilentlyContinue
```

## Review and export

1. **Build source graph**. Inspect selected/missing repositories, unsupported files, parsing errors and extraction limits. Building the graph makes no model calls.
2. **System model → System DFD** shows context, overall system or component detail. Unknown peers stay visible. Use **Components** to declare process/store/broker mappings across repositories, supported by interface and evidence references.
3. Review **Threat actors**, **Trust boundaries**, **Trust domains**, **Controls**, **Data assets** and **Flow register**. Record initial access, authority before/after, enforcement limitations and source support. Select a trust lens; nested domains belong to the same lens. Actor paths are conditional represented paths, not proof of exploitability.
4. **STRIDE matrix** provides the request budget and **Run or continue STRIDE analysis** controls in the same view. Start with a small request budget to validate gateway access, then continue. Metadata goes to the configured destination; source excerpts are optional. HTTP/authentication/JSON failures remain visible and completed batches remain saved. **Continue STRIDE review** reuses successful batches; a previously failed schema/evidence batch is retried with stricter response instructions, within the selected request budget. This is explicit continuation, not a hidden retry loop.
5. Inspect matrix cells and threat details. Record reviewer, rationale, disposition, mitigation owner and severity. A blank cell is not a safe result. A local acceptance annotation is not an authenticated organizational approval.
6. **Export review package** provides the complete model, registers, DFD and report. Filters do not reduce export scope. Open HTML and Print → Save as PDF. Keep SVG/Mermaid for detailed diagrams.
7. Stop and restart with the same source root/workspace. Open the new access link. Saved records and completed batches return. Rebuild to inspect changed source; raw excerpts require rebuilding because they are never checkpointed. Review stale references after rebuilding.

## Push and verify a development change

From the repository root, after the tests pass:

```powershell
git status --short
git add packages/static-pilot docs/design/system-threat-model-workspace.md docs/testing/system-threat-workspace.md docs/runbooks/windows-static-workspace.md .github/workflows/static-pilot.yml .gitignore
git commit -m "Add system threat model workspace and verification"
git push -u origin HEAD
gh pr create --base main --fill
gh pr checks --watch
```

Review the staged diff before committing. Never stage customer source, workbooks, manifests, snapshots, reports or credentials. Merge the reviewed PR after required checks pass, then update the Windows checkout using the commands above.

## Inspect token consumption (0.4.1)

Open **STRIDE matrix** and scroll to **Token usage**. The meter shows reported workspace totals, the latest action, repository-local usage and shared cross-repository work. Expand recent requests to inspect batch/model, participating repositories, outcome and input/output totals. **Token usage · CSV** exports every recorded attempt; the complete JSON and HTML report also retain accounting.

Rejected responses and retries count when the provider returns usage. Unknown usage is shown explicitly for missing fields, timeouts and interrupted requests. Input already includes cache reads/writes; do not add those columns again. Reusing completed local batches adds zero requests/tokens. The meter updates when the provider returns usage, not for every generated token.

Old reviews cannot be backfilled: an unmetered-history notice means totals cover only newly recorded requests. Keep the same workspace to retain the history through restart and source rebuilds. Customer gateway usage/billing logs are the reconciliation source for requests whose usage was not returned. No change to the configured model deployment or key is needed for this feature.

## Collect portable diagnostics (0.5.0)

Update Synthesis, then restart using the same source root, workspace and configured provider/deployment. Rebuild the source graph once to use streamed local extraction. This version changes the planner and source identities: previous request results may need review again, while their token history remains in the workspace.

Traces are enabled automatically under `<workspace>/traces`. To put them elsewhere, append `--trace-dir "C:/SynthesisState/ProductTraces"` to the existing `serve` command. Keep that directory outside the analyzed clones. No additional model key or model is required. The original provider, exact deployment name and gateway version header remain unchanged.

1. Build the source graph. In **Sources** and **Source graph**, inspect unavailable, oversized, unsupported, malformed and limited files.
2. Run or continue STRIDE analysis. In **Analysis coverage**, inspect each obligation kind separately. A completed interface request does not cover a relationship split between requests.
3. If a provider response fails, continue pending work. After two format/evidence/output-limit failures on the same packet, eligible requests are subdivided automatically on the next continuation. Authentication, policy, quota and transport failures stop the action; resolve those before continuing. Successful compatible requests are reused.
4. Select **Download diagnostic bundle** (also available in **Export review package**). Save `synthesis-diagnostics.zip` outside the source root. This works even when the first scan failed.
5. Inspect `summary.json`, `coverage.json`, `trace-index.json` and the ZIP contents before transfer. They contain confidential repository paths, symbol names, graph relationships and deployment metadata. Raw source excerpts, prompts, response prose and keys are intentionally excluded. Transfer only through the approved channel; no diagnostic upload is automatic.

If the browser or server is unavailable, export from disk in PowerShell. This command does not require an API key:

```powershell
Set-Location C:/Tools/Synthesis/packages/static-pilot
$workspace = "C:/SynthesisState/Product"
$exportFolder = "C:/SynthesisState/Exports"
New-Item -ItemType Directory -Force $exportFolder | Out-Null
$bundle = Join-Path $exportFolder ("synthesis-diagnostics-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip')
node src/cli.mjs diagnostics --workspace $workspace --out $bundle
if ($LASTEXITCODE -ne 0) { throw 'Diagnostic export failed; preserve the workspace and traces.' }
Get-FileHash -Algorithm SHA256 -LiteralPath $bundle
```

If you selected a custom trace directory, also pass `--trace-dir "C:/SynthesisState/ProductTraces"` to `diagnostics`. The command reads the latest atomic snapshot and traces; stopping the server first gives a stable cutoff. If no snapshot was completed, it still exports the traces and explicitly marks the graph/model unavailable. It refuses to overwrite an existing bundle.

For collection troubleshooting, bring the ZIP and the approximate failure time/timezone. `summary.json` identifies the application build and model. `trace.ndjson` correlates session/job/batch/attempt IDs, file parsing, HTTP status, provider request IDs and stop reason. `attempts.json` separates response-format, evidence, output-limit, transport, quota/policy and persistence failures. `token-usage.csv` includes failed/retried requests where usage was returned.

Traces rotate at 8 MiB without automatic deletion. A ZIP includes the newest trace segments up to 64 MiB and lists any omissions in `trace-index.json`; preserve the workspace if older segments are needed. Unknown token usage after interrupted requests is not zero. Source graph limits, unrecognized formats and unresolved dynamic relationships remain coverage gaps, even when every planned request succeeds.

Diagnostic ZIP output is limited to 2 GiB. An oversized export fails explicitly; use the separate full source-graph JSON export for larger graphs and retain the workspace and traces.

## Connected DFD, STRIDE results and CWE review (0.7.0)

After updating, **Build source graph** once. This upgrades stored interface facts and automatically creates candidate HTTP, queue and shared-resource connections. Open **System model**. Solid endpoint matches and dashed route hypotheses retain their evidence; unresolved destinations remain visible. Actor assumptions and identity-boundary candidates are supplied for review. Manual connection entry is optional correction, not a prerequisite.

**STRIDE matrix** opens component rows by default. Counts are returned threat scenarios; checklist prompts are inside cell details. Read the repository progress table. **Request budget = 1 means one model call**, not one completed repository. Select **Run or continue STRIDE analysis** to process remaining packets. An empty cell does not mean that no threat exists.

For deterministic local CWE scanning, install Python 3.12 on the VM, then:

```powershell
py -3.12 -m venv C:/Tools/SynthesisScanner
& 'C:/Tools/SynthesisScanner/Scripts/python.exe' -m pip install semgrep==1.185.0
& 'C:/Tools/SynthesisScanner/Scripts/semgrep.exe' --version
$env:PYTHONUTF8 = '1'
$env:SYNTHESIS_CWE_SCANNER = 'C:/Tools/SynthesisScanner/Scripts/semgrep.exe'
```

Restart Synthesis in this same PowerShell window with your existing source-root, workspace, provider, model and gateway arguments. The scanner path can also be passed with `--cwe-scanner`. Scanner installation does not require installing dependencies in any target repository.

In **CWE code review**, **Scan selected repositories** runs the local rule pack. Inspect scanned/eligible file counts, source snapshot agreement and gaps. Select a finding to inspect its file hash, location and remediation; record reviewer and rationale. Export JSON, CSV or SARIF.

Run the local scanner first for fast, zero-model-token results. In the same tab, **CWE source review** uses the configured model and prioritizes source packets containing current Semgrep findings, then graph interactions and remaining code. Model review can also run if no local scanner is available. Enable **Send redacted source segments to the configured provider**, choose a model request budget, then **Run or continue CWE source review**. This transmits code to your approved gateway; it does not execute the code or contact the target product. The gateway deployment name must remain exactly the provisioned name. Continue until the source and interaction packets are processed, then review remaining gaps. Export the CWE source review and token-usage CSV. A budget stop preserves completed findings and batches.

The diagnostic bundle includes source graph, discovered connections, CWE coverage, failure traces and model token accounting. Model source segments are not saved in it. Inspect confidential architecture metadata before transferring the bundle. See the [architecture](../design/connected-dfd-cwe-review.md) and [test specification](../testing/connected-dfd-cwe-review.md) for supported cases and limits.

## Small error export and large DFD previews (0.7.1)

Select **Export errors** at the top of the application to download `synthesis-errors.json`. It works before a successful source build and includes request outcomes, scanner errors, connection extraction counts and recent failure events. It excludes the source graph, source excerpts and model response prose. Lists retain at most 100 entries and each scanner repository retains at most 10 errors; omitted counts are explicit. Keep the full diagnostic bundle locally for omitted history. The small file still contains confidential architecture metadata.

The DFD preview now selects both endpoints of each visible flow before filling remaining space with components. This avoids showing only isolated boxes when a model exceeds 80 objects. **Zero discovered connections remains a real discovery gap:** dashed unknown-peer relationships are not evidence of connected services. The DFD shows matchable HTTP call/route counts; export errors to diagnose missing extraction or unresolved matching. Rebuild once after this update to collect legacy .NET `RoutePrefix` and separate method `Route` attributes. Multiple ambiguous route declarations remain unresolved.

STRIDE **Request limit reached successfully** means the configured call budget was consumed and pending work remains; successful results are retained. A budget of two does not complete a portfolio.

Use **Export Semgrep JSON**, **Export Semgrep CSV** or **Export Semgrep SARIF** for local scan results. **Export model CWE review** is separate and disabled until a model source review exists. Running Semgrep does not implicitly run the model review.

## Architecture DFD upgrade (0.8.0)

Stop the local Synthesis server with Ctrl+C. Save the current model/report exports and back up the existing workspace before rebuilding. Keep the clones unchanged and reuse the same source root, workspace, gateway model and trace directory. Updating the application does not require reinstalling the scanner.

From the existing checkout:

```powershell
Set-Location "C:/Tools/Synthesis"
git status --short
# Stop here if you have local changes; preserve them before updating.
git switch main
git pull --ff-only
Set-Location packages/static-pilot
npm ci --ignore-scripts
node -p "require('./package.json').version"
npm run check
npm test
```

The version must be **0.8.0 or later** once this change is merged. Restart with your existing `node src/cli.mjs serve` command and the same `--workspace` and `--trace-dir`. Enter the gateway key through the existing secure prompt if using a new PowerShell session. Open the newly printed access link.

1. Export the previous results, then choose **Build source graph** once. The extractor cache version changes so existing files are reparsed for architecture and endpoint facts. Do not delete the workspace. Review records are retained, but changed evidence can make them stale; rebuilding is not a promise of retaining prior model-review coverage.
2. Open **System model → System DFD → Service DFD**. The default shows candidate hosts, connected source groups and resources. Test/generated groups and unresolved peers are excluded from the canvas, not from source analysis or registers.
3. Select a connector to see its member flows, supporting source locations, related threats and review decisions. Select an individual flow for its details. Library associations are shown as candidate project ownership, not proven deployment.
4. Open **Connection coverage** to filter unresolved locations and reasons. Use **Show unresolved peers** or **Include supporting source groups** when investigating gaps. A zero-connection view explicitly remains incomplete; increasing STRIDE request budgets cannot repair source extraction.
5. Select a trust lens or actor path. Candidate boundary badges remain pending until reviewed; declared trust zones are separate. Actor paths describe conditional access, not demonstrated attacks.
6. Use **Export this view · SVG/Mermaid** for the current level, focus, lens and overlays. Canvas limits are 80 objects and 240 grouped connections, with omission counts. Complete model JSON and registers preserve underlying records beyond these view limits.
7. Save **Export errors** and the current SVG/Mermaid under your export directory for troubleshooting. Error reports now include architecture classification counts. Automatic traces still require the configured `--trace-dir`; browser downloads do not automatically follow that directory.

The new resolver supports bounded same-file literal assignments, configuration-key references, `HttpClient.BaseAddress` plus relative paths, and explicit `HttpRequestMessage` method/URI assignments. Configuration lookup crosses files within the same source project, then matches endpoints across repositories. Conflicting configuration values remain gaps; Synthesis does not choose a deployment environment. Existing attribute-route, same-file JavaScript-wrapper, store and default-exchange queue adapters remain available. General cross-file symbol/DI binding, arbitrary wrappers, proxy rewrites and non-default broker routing remain limitations.

## Internal DFD and requested weakness coverage (0.9.0)

Version 0.9.0 adds internal worker/storage DFD extraction and the requested CWE coverage baseline. Save prior exports and back up the stopped workspace. Update main with `git pull --ff-only origin main`, install tool dependencies with `npm ci --ignore-scripts`, and verify the package version is 0.9.0 or later before restarting with the existing workspace.

After updating and installing Synthesis dependencies, rebuild the graph once. Run **CWE code review → Scan selected repositories** to use the 22-rule local pack. Then enable source sharing and run **CWE source review** with a small initial request budget. Model review uses the existing provider configuration. Each submitted packet must assess the 25 code-review areas; 4 other areas require additional evidence. The **Requested weakness coverage** panel preserves all 29 areas / 52 original identifiers, offers a repository filter, and exports JSON/CSV even before review runs. Old completed model packets do not count toward the new profile. Additional findings remain available.

Keep `--trace-dir` pointed outside the clones. Traces are automatic; report downloads are explicit. For compact troubleshooting export **errors**, **coverage JSON**, and **token usage CSV** first. Full model-review exports include assessment rationale and can be much larger. The diagnostic ZIP includes target coverage but omits model rationale prose.

See [design and limitations](../design/requested-cwe-coverage.md) and [verification](../testing/requested-cwe-coverage.md). No findings is not a pass, and graph/model completion does not demonstrate runtime exploitability.

## Security investigations (0.11.0)

The 0.11.0 investigation feature adds optional CWE mappings and a separate static evidence assessment. It introduces no new VM dependency. Use the already approved provider, exact gateway deployment, source root, workspace and scanner settings. These changes are available on main; verify the updated commit before restarting a VM.

1. Open the saved graph when the clones and extractor are unchanged.
2. Run Semgrep and/or continue model source review to produce candidates. Existing source sharing sends redacted excerpts to the configured provider.
3. Under **CWE code review → Security investigations**, select **Run or continue evidence assessment**. The existing request budget applies to the assessment and its bounded follow-ups.
4. Inspect findings without CWE mappings alongside mapped weaknesses. Read source evidence, controls, gaps and residual-risk recommendations. Source-supported means a static argument requiring human review.
5. Download **Export security investigations** to the existing exports folder. The browser controls the download destination; server trace persistence remains controlled by the existing trace-directory setting. Focused graph packages include related investigation records within their existing size limits.
6. Export small troubleshooting errors for failures and token usage for cost analysis. Rebuild when source/configuration changes; merely reopening the browser does not detect every working-tree change.

### Optional native JSON response mode

For an Anthropic endpoint that supports `output_config.format`, set this before starting Synthesis:

```powershell
$env:SYNTHESIS_STRUCTURED_OUTPUTS = '1'
```

This applies native JSON schemas to source-review and security-assessment requests. The source-location, CWE-eligibility and evidence checks still run locally. It does not change the approved model/deployment name. Gateway compatibility must be checked in that environment; HTTP failures remain visible and there is no silent fallback. Unset it, or set it to `0`, to retain the default prompt-based JSON protocol. The default gateway payload is unchanged.

### Static exploration (0.11.0)

Use the same VM, source root, gateway, exact model deployment and state directory. No target runtime, browser automation against applications or network scanning is introduced. This increment has not been released to main merely because the runbook exists.

1. Stop Synthesis and back up the workspace, then install the approved review commit using the existing update procedure. Start with the same `--workspace` and `--trace-dir` arguments. **Open saved graph** reuses the existing source graph; this exploration increment does not require a graph rebuild.
2. Open **6 · Exploration**. The overview branches into STRIDE, requested CWE checks and candidate assessment. **Browse** filters review records; double-click a card or choose **Open branch** to expand its children. **Show lineage** follows the records that led to the selected finding or observation. Grouped CWE obligations retain each individual outcome.
3. Choose **Run or continue exploration** only after checking the source-sharing box and request budget. Saved investigation steps select code review, STRIDE and candidate assessment work across repositories. Missing evidence creates indexed search or relationship-following steps; retrieved evidence returns to its originating review. Set **Requests**, **Token budget**, **Graph steps**, **Path depth** and **Seconds**. Compatible completed work is retained. The starting architectural context is frozen for this investigation; explicit source/declaration changes create a new scope. You may still run CWE review or assessments independently from their existing tab.
4. Unfinished requests, missing evidence, failed responses and additional-evidence targets remain visible. A budget of two means two model calls, not two repositories. Continue within an approved budget. No result promises complete vulnerability detection or runtime exploitability.
5. Use zoom, pan, fit and the minimap. Select an observation and **Read cited source** to read a redacted local window whose hash still matches. Changed or unavailable files are rejected. **Open system DFD** follows available interface/component references. The DFD inspector also links associated findings back to exploration.
6. Export the selected review graph as JSON or SVG. Each download is capped at **3 MiB**; expand/narrow the branch if necessary. These exports contain review metadata, not the full source graph. For source and controls, use the existing focused graph package export. Inspect all exports before sharing and save under `C:/SynthesisState/Exports` through the browser's download settings.
7. `exploration.sqlite` and its journal live beside `snapshot.json` inside the workspace, independently of `graph.sqlite`. With persistence enabled, reopening preserves review history. The **Snapshot** selector shows retained source revisions. Shut down before copying the workspace databases. Small **Export errors** reports include exploration phase and failure status; configured server traces remain automatic.

### Read code beside a CWE finding

Select a Semgrep finding, expand a model finding, or open a security investigation. Expand **Code evidence** beneath the source locations. Synthesis reads the selected clone on the VM and shows numbered source lines with the cited range highlighted, positioned near the first cited line. Surrounding lines remain available by scrolling; long cited ranges offer **Next cited lines**. Each location in a multi-file finding has its own panel.

Opening code evidence makes no model call and executes no repository code. The file must still match the hash recorded with the finding. Changed, missing, stale or unselected source produces an explicit message instead of showing different code as evidence. **Recheck source** reloads and verifies the file again. Recognized sensitive values are redacted. The cited lines support review of the candidate; highlighting does not confirm a vulnerability. Code windows are fetched locally on demand, not automatically added to existing finding exports; use the focused graph package to transfer bounded code context.

### Graph-driven investigation update

Use `main` for the released 0.11.0 changes, including threat references, boundary crossings and explicit STRIDE analysis status. Stop the server before updating and back up the entire existing workspace. Do not change the workspace location or delete its saved graph. From a clean checkout:

```powershell
Set-Location C:/Tools/Synthesis
git fetch origin
git switch main
git pull --ff-only origin main
Set-Location packages/static-pilot
npm ci --ignore-scripts
npm run check
npm test
```

Run commands individually and stop on any failure. Restart using the same source root, workspace, scanner and approved gateway arguments. No new dependency or second model is required. Use **Open saved graph**, then **6 · Exploration**. Start with 2 requests, 250000 tokens, 1000 steps, depth 12 and 600 seconds. Enable source sharing and select **Run or continue exploration**. Raise budgets after checking the provider result. A low token budget can stop before any model call; that is an explicit reservation stop.

Choose **Browse → Investigation steps** to inspect queued, waiting, completed, failed and blocked records. Select a step for its outcome and **Show lineage** for the path that created it. Use **Retry failed steps** only after reviewing the failure. At most three model attempts are allowed per failed step. Increasing path depth reopens steps blocked only by the prior depth limit. Additional-evidence gaps cannot be cleared by increasing model-call budgets.

**Include local Semgrep baseline** is optional and runs the bundled rules through the configured local scanner. Existing scanner results can seed investigations without selecting it again. Semgrep still reads staged source, while the investigation follows indexed relationships and cited controls. No target application is run.

Server traces are automatic under `--trace-dir`. They include `investigation.*` task IDs, searches, traversal basis, source hashes, provider outcomes, budget stops and usage. **Export errors** includes the frontier counters and stop reason; it does not include the whole source graph. Download errors and token CSV first. Selected exploration JSON/SVG and focused graph transfer ZIPs remain capped at 3 MiB each. Browser exports must be saved to `C:/SynthesisState/Exports`; `--trace-dir` does not change the browser download directory. Keep complete SQLite files and traces on the VM unless specifically needed.

### Repeated model JSON failures

A source-review run with attempted requests but no successful packets is reported as **failed**. Three consecutive response-format failures stop the action early; completed compatible packets and reported usage are retained. This prevents a larger request budget from repeatedly spending on the same response-contract failure. A single malformed response can still be followed by successful work in another packet. All requested-CWE and source-citation validation remains enforced.

If the exported source review says `outputContract: prompt-json` and repeated errors say **text outside the required JSON format**, stop the server and try the existing native JSON setting with **one** request:

```powershell
$env:SYNTHESIS_STRUCTURED_OUTPUTS = '1'
```

Restart with the same workspace, source root, exact approved gateway deployment and key. This requests a structured JSON response via `output_config.format`; gateway support must be established by that test. If the gateway rejects the parameter, stop and export the error instead of increasing the budget. Native JSON does not relax CWE mapping or code-evidence checks. Changing the output contract changes the review-plan key; prior findings remain available, but prior packet completion is not silently credited to the new contract.

Export errors after the test finishes. New exports retain provider-reported usage, failure classifications and response-shape metadata (text length, block count and format category). They exclude response prose, source text and secrets. Historical trace events whose failure was stored as a string now retain a classified error rather than an empty object. Earlier exports cannot reveal response contents that were never recorded. Retain the full workspace and token-usage CSV locally.


### STRIDE did not run or returned prose instead of JSON

Earlier builds omitted the STRIDE response schema even with `SYNTHESIS_STRUCTURED_OUTPUTS=1`. Update main using the commands above before retrying. The setting now applies to both STRIDE entry points and graph-driven STRIDE investigations. It requests the required structure; local evidence and threat validation remain mandatory. Gateway acceptance still needs a one-request test in your environment.

1. Stop the server with Ctrl+C and preserve the existing workspace. Update `main`, then run the checks above.
2. In the same PowerShell window, set `$env:SYNTHESIS_STRUCTURED_OUTPUTS = '1'` and ensure the approved gateway key is set in `CLAUDE_API_KEY`. Restart with your existing provider, deployment, source root, workspace and trace directory.
3. Open the new access link and **Open saved graph**. Do not rebuild unchanged clones for this fix.
4. In **STRIDE matrix**, set **Request budget** to **1**, then select **Run or continue STRIDE analysis**. A completed packet proves that call succeeded; it does not complete all repositories. Inspect returned scenarios and remaining coverage before increasing the budget.
5. Download **Export errors** after the call. The `stride.outputContract` field should say `native-json-schema`; attempted batches include safe response-format metadata and reported token usage. If the gateway rejects the structured-output parameter, send this small export for diagnosis before spending on further calls.

STRIDE's native schema is part of its cache identity, including the graph-driven investigation scope. Results produced under the earlier contract are not silently counted as completed under the corrected contract. Keep prior exports for comparison. The source graph itself remains reusable. A standalone STRIDE action stops after three consecutive format failures, preserves any successful packets and usage, and reports `repeated-response-format-failure`.

### Export CWE code evidence and threat model as PDF

Update main and restart using the same source root, saved workspace and gateway configuration. No new dependency, source rebuild or model call is required.

1. **Open saved graph**, then **5 · CWE code review → CWE evidence · PDF**. The report includes all saved scanner and model candidates, source scope, review/assessment status and highlighted code at each available verified location. It is independent of the on-screen finding filter. **CWE evidence · HTML** downloads the same evidence report for offline use.
2. In the report tab choose **Print / Save as PDF**, then **Save as PDF** in Edge/Chrome (or **Microsoft Print to PDF**). Save the file to your exports folder outside the clones. If the browser blocks the report tab, allow popups for the local Synthesis address or use the HTML export and Ctrl+P.
3. For the threat model, choose **3 · System model → Export review package → Threat model · PDF**, then the same print/save action. This review report includes DFDs, actors, grouped boundaries, components, controls, component STRIDE rows and actual threat scenarios. Detailed properties, the full evidence ledger and checklist prompts remain in **Complete HTML report** and JSON/CSV exports.
4. Verify that the report shows the expected completed/pending counts. An exported candidate is not automatically a confirmed vulnerability. Missing/changed local source appears as an evidence gap; the exporter will not fabricate a snippet from a model description.

PDFs and HTML reports are explicit downloads, not automatic traces. Existing JSON exports continue to omit source snippets. Existing graph and diagram coverage limits remain. See [report scope and tests](../testing/pdf-evidence-reports.md).

### Read threat references, boundaries and STRIDE status

After installing the threat-review presentation update, reopen the saved graph. Existing STRIDE results and reviewer decisions are retained. This display update does not require another graph build or a model call.

- **Threat register** shows T- references and an explained review order. Review priority is separate from severity; test-only applicability and unknown exposure remain visible. Select a threat to inspect impact, prerequisites, controls and evidence, then **Show on DFD** for its conditional path.
- **Trust boundaries** shows TB- references, trust transition, enforcement and named from/to crossings with F- references. Click a crossing to open its flow. The DFD badge uses the selected trust lens; a pending boundary is not a verified control or deployed trust zone.
- **STRIDE matrix** separates Not analyzed, Analysis failed, Partially analyzed, Stale analysis, Scenarios identified, and Analyzed — no scenario identified. Reviewer dispositions remain separate. Inspect failure counts and Export errors before increasing a failing request budget.
- CWE source review and STRIDE are separate actions. Successful CWE calls do not fill the STRIDE matrix. To continue STRIDE, open **4 · STRIDE matrix**, start with one request to verify the gateway, then raise the budget only after reviewing that outcome. Completed compatible packets are retained.

## Run STRIDE and CWE until the planned scope is finished

After updating and restarting with the same source root, workspace and provider, choose **Open saved graph**.

1. In **4 · STRIDE matrix**, check **Run until complete**. The bounded request-count input is disabled. Optionally enter **Token target this action (advisory)**; leave blank for no target. Choose **Run or continue STRIDE analysis** once.
2. Track completed/pending/failed packets, current-action reported tokens, unknown usage and repository review progress. Reaching the token target displays a warning but continues. The run does not stop after 100 calls or at the normal 24-minute action limit.
3. Use **Stop review** to interrupt. Compatible completed packets are retained. Closing the browser does not stop the server-side run; stopping PowerShell/server does. After a server restart, open the saved graph and explicitly start again to resume.
4. In **5 · CWE code review → CWE source review**, enable **Send redacted source segments**, check **Run until complete across selected repositories**, optionally set the advisory token target, and choose **Run or continue CWE source review**. This reviews source packets and graph interactions. Semgrep scanning is separate and already scans all selected local clones. Independent evidence assessment remains separately budgeted.
5. A provider failure, repeated invalid responses, changed source or persistence failure can stop a run. Inspect **Export errors** and the reported stop reason before resuming. A completed pass with failed packets or coverage gaps is still partial. No result promises every possible weakness was found.
6. Expand **Gaps** in scanner coverage to see recorded parsing errors and skipped paths. Unsupported file types are outside the scanner adapter, not automatically outside graph/model analysis.
7. Open a scanner/model finding and expand **Code evidence** to see the hash-checked local source window with cited lines highlighted. Use **CWE evidence · PDF → Print / Save as PDF** to include those windows in a report. JSON exports do not contain source snippets.

Token totals include failed attempts and retries. The advisory target is per action; the workspace token meter and CSV include historical requests. Existing trace and export locations remain unchanged. See [continuous review design and tests](../testing/continuous-review.md).

## Parallel review workers

Both **4 · STRIDE matrix** and **5 · CWE code review → CWE source review** offer **Parallel review workers**. Start with **2**, the default. Select **1** for a gateway that allows only serial calls, or **3–4** when the approved gateway capacity permits. Combine this with **Run until complete** to work through remaining packets without repeated clicks. A bounded request budget is shared by the whole action, not multiplied by the number of workers.

The coordinator combines validated results into the existing STRIDE register/matrix or CWE report. Active, queued, completed and failed work appears alongside token usage. Changing worker count reuses compatible completed packets. Stop prevents new requests; active work settles or is interrupted before the action becomes idle. Do not start a second operation while the first is running or cancelling.

CWE source retrieval now reads only planned files for each transient window, retaining source-hash and path checks. It no longer rescans entire repository trees for every window. The initial source-snapshot verification remains. These optimizations do not remove required CWE checks or claim fewer model tokens. Gateway throttling can constrain throughput; inspect exported errors and reduce workers if necessary.

No new service, Python package or agent-framework installation is needed. The coordinator runs inside the existing local Synthesis server and uses the same configured Claude deployment and key. Static-only restrictions, traces, export locations and explicit resume after restart remain unchanged.

## Saved-graph STRIDE recovery and unattended preflight

The disk scheduler now loads packet payloads only for active workers instead of retaining the entire pending queue. This update does not change extraction, packet identities or successful-result cache keys. Reuse the existing graph. A failed packet receives more explicit allowed-reference instructions when explicitly retried; evidence validation is not relaxed.

After updating, stop any active review, restart with the same workspace and provider, and choose **Open saved graph**. Then:

1. Open **4 · STRIDE matrix**. Leave **Run until complete** unchecked for the preflight. Set **Request budget = 4** and **Parallel review workers = 4** if gateway capacity permits.
2. Click **Run or continue STRIDE analysis**. Wait for the action to finish. Check that current completed packets increase and that the matrix reports analyzed subjects. Validated analysis may return no scenario; this differs from failed or stale analysis.
3. If packets fail, use **Export errors**. One explicit continuation retries failed response-format packets with stricter reference instructions. Persistent errors, authentication failures or throttling require attention; do not assume a larger budget will fix them.
4. Once the preflight succeeds, check **Run until complete**, retain the worker count and start again. Keep the server and VM running and prevent system sleep. Closing the browser does not stop the action. There is no automatic restart after the server stops.
5. Run CWE source review after STRIDE finishes or is stopped. These remain separate top-level actions; CWE does not populate the STRIDE matrix and neither action automatically starts the other.

The matrix now distinguishes historical stale results from current coverage and displays a separate latest-attempt failure when a worker fails before review begins. **Export errors** includes the stale cause when known and the failure stage. Genuine source, architecture or methodology changes still invalidate analysis; stale safeguards are not bypassed.

After at least three matching successful timed calls, progress includes a conditional remaining-time estimate based on up to twenty recent calls and the selected worker count. It assumes steady throughput and excludes retries and throttling. Thousands of packets can still take many hours; four workers reduce elapsed waiting but do not reduce total model tokens. A completed pass with unresolved or failed packets remains partial.


## Export a partial STRIDE review as PDF

Open **4 · STRIDE matrix → Export STRIDE review · PDF**. It works before the planned scope completes, including while the next packets are running. The export uses the latest available review checkpoint; in-flight responses are not included. Exporting does not stop or restart analysis.

In the new tab select **Print / Save as PDF**, choose **Save as PDF** in Edge/Chrome, and save outside the source clones. The report includes the overall system DFD, threat actors, trust boundaries and crossings, controls, component STRIDE matrix, prioritized threat scenarios with T- references, and supporting evidence. Pending and failed counts remain visible. Inferred actors/boundaries remain labeled; checklist prompts are not reported as threat scenarios. Stale exports are explicitly historical.

The same PDF remains available under **System model → Export review package → Threat model · PDF**. For an offline HTML copy use **Complete HTML report**. Browser popups must be allowed for the local Synthesis page. A partial report does not claim unreviewed areas are safe.


## Branded PDF reports and CWE summary

After updating and restarting Synthesis, existing saved findings export with the UnitOne logo and **Confidential — Do not share** notice. No graph rebuild, model rerun, new VM dependency or report setting is required. Use **CWE code review → CWE evidence · PDF** or **STRIDE matrix → Export STRIDE review · PDF**. The CWE report starts with a compact summary by CWE, candidate count, scanner/model totals and distinct affected repository counts; unmapped security issues remain included.

In Edge/Chrome's print dialog choose **Save as PDF** and turn **Headers and footers** off to exclude browser-added timestamps, URLs and titles. Save outside the repositories. The downloaded CWE HTML uses the same layout and embeds the logo for offline printing. Detailed execution/coverage data remain in the UI and JSON exports; STRIDE's partial or historical review status remains in its PDF.
