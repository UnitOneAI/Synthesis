# Windows: static system threat modeling

Requires Node.js 22 or 24, Git, a current Edge/Chrome browser, and readable local clones. No target application, build, installer, database, container or runtime service is started. Keep the source root, Synthesis checkout, workspace and exports in separate folders.

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
