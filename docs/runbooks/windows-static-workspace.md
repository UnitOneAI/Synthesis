# Windows: static system threat modeling

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

## Disk graph requirements and backup

Disk mode is the CLI default and requires SQLite 3.51.3 or newer embedded in Node. Qualification used Node 24.22.1 / SQLite 3.54.1. The application checks the actual engine at startup. If it rejects the installed runtime, update Node 24. To deliberately use the prior capped backend, append `--graph-storage memory`; there is no automatic fallback.

The workspace contains `graph.sqlite`, its active journal files, `snapshot.json` and `traces`. Back up the **whole workspace after stopping Synthesis** with Ctrl+C. Do not copy only a live database file. Retain both the database and snapshot together; losing the database loses the graph referenced by the snapshot. A rebuild of unchanged clones reuses parsed files after hashing them. Review continuation does not rescan sources.

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
