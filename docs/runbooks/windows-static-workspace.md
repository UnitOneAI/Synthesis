# Windows: static system threat modeling

Requires Node.js 22 or 24, Git, a current Edge/Chrome browser, and readable local clones. No target application, build, installer, database, container or runtime service is started. Keep the source root, Synthesis checkout, workspace and exports in separate folders.

This can run inside a Windows VM. Open the browser inside that VM (including through Remote Desktop) using the printed local access link. Model review requires outbound access to the configured provider; static collection and manual review do not. The proposed [disk-backed graph and VM architecture](../design/disk-backed-static-graph.md) is not yet implemented; these commands still run the current pilot with its documented graph and process limits.

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
