# JCI: feature threat review on the saved graph (0.12.0)

This update reuses the existing graph and saved STRIDE packets. It changes how results are presented and how individual threats are checked against controls. It does not make an incomplete JCI assessment complete. Unresolved assessments use an explicit engineering decision: entry, sensitive operation, path binding and applicable controls. Compatible results and their source references are retained. Positive findings receive a separate critical check before publication; existing positives can enter that check without repeating discovery. Prior attempts remain in history. Do not restart the entire discovery run just to generate the new report.

## Update

Stop the running Synthesis server with **Ctrl+C**, then paste this into PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
$workspace = 'C:/SynthesisState/JCI-Metasys'
if (-not (Test-Path "$workspace/snapshot.json")) { throw 'Saved snapshot not found.' }
if (-not (Test-Path "$workspace/graph.sqlite")) { throw 'Saved graph not found.' }
$backup = 'C:/SynthesisState/Backups/JCI-Metasys-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Force $backup | Out-Null
Copy-Item -LiteralPath $workspace -Destination "$backup/Workspace" -Recurse
Set-Location 'C:/Tools/Synthesis'
if (git status --porcelain) { throw 'This checkout has local changes. Preserve them before updating.' }
git fetch origin main
if ($LASTEXITCODE -ne 0) { throw 'GitHub fetch failed. Check GitHub access before continuing.' }
git switch main
if ($LASTEXITCODE -ne 0) { throw 'Could not switch to main.' }
git merge --ff-only origin/main
if ($LASTEXITCODE -ne 0) { throw 'Update was not a fast-forward. Keep the checkout and resolve the branch difference.' }
Set-Location 'C:/Tools/Synthesis/packages/static-pilot'
npm ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
npm run check
if ($LASTEXITCODE -ne 0) { throw 'Application checks failed.' }
node -p "require('./package.json').version"
```

The version should be **0.12.0 or later**. Keep the existing `C:/SynthesisState/JCI-Metasys` workspace and source clones.

## Start with the JCI gateway

Paste this into the same PowerShell window. Enter the approved gateway subscription key at the hidden prompt. No Azure login or Docker is needed for Synthesis.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'C:/Tools/Synthesis/packages/static-pilot'
if (-not (Test-Path 'C:/SynthesisState/JCI-Metasys/snapshot.json')) { throw 'Saved workspace snapshot was not found.' }
if (-not (Test-Path 'C:/SynthesisState/JCI-Metasys/graph.sqlite')) { throw 'Saved graph was not found.' }
New-Item -ItemType Directory -Force 'C:/SynthesisState/Exports/Traces' | Out-Null
$gatewaySecret = Read-Host 'JCI gateway subscription key' -AsSecureString
$env:CLAUDE_API_KEY = [System.Net.NetworkCredential]::new('', $gatewaySecret).Password
Remove-Variable gatewaySecret
if ([string]::IsNullOrWhiteSpace($env:CLAUDE_API_KEY)) { throw 'Gateway key is empty.' }
$env:SYNTHESIS_STRUCTURED_OUTPUTS = '1'
$env:SYNTHESIS_REQUEST_TIMEOUT_MS = '300000'
node src/cli.mjs serve --source-root 'C:/builds/git/jci-products' --workspace 'C:/SynthesisState/JCI-Metasys' --graph-storage sqlite --trace-dir 'C:/SynthesisState/Exports/Traces' --provider anthropic-gateway --base-url 'https://apim-apimhub-devqa-eastus2-ndmz.azure-api.net/anthropic' --model 'claude-opus-4-6-1' --api-version '2023-06-01'
```

These are the previously supplied JCI gateway/deployment settings. Keep native structured output enabled only on the gateway deployment already qualified for it. A 403 is a gateway-access failure: stop and resolve the subscription/deployment access, rather than spending further review attempts.

## Preview the smaller scope

1. Open the local access link printed by the server. **Sources → Open saved graph**. Enable redacted source context for the approved model provider.
2. In **STRIDE matrix → Choose repositories to review**, choose **API Gateway and MUI** as primary for this POC. Keep other loaded clones available as supporting evidence. Repository selection is generic; these names are not hardcoded.
3. Select **Review depth → Security features**. Entry points, outbound interactions, workers, stores, controls and configuration are primary subjects. Helpers remain available for traversal. **All subjects** remains available when every parsed helper must also be an independent primary review subject.
4. Save scope, choose **Scope for next run → Selected repos**, then **Preview saved scope**. Confirm primary/supporting names and subject/packet counts. A new scope preserves earlier results separately; it does not imply they satisfy the new scope.
5. **Actor access → External** filters the display. It does not exclude internal control paths or reduce the review plan.

Private networking does not remove authenticated-user or compromised-peer threats. The intended deployment/profile is an explicit assumption. Model completion does not approve inferred boundaries.

## Check the gateway, then investigate

1. Choose **1 request**, **1 worker**, **Run until complete off**. Start STRIDE. A successful call checks connectivity and the response contract, not complete threat modeling.
2. Then choose **12 requests**, **4 workers**, **Run until complete off** for a reviewable first cohort. In security-feature mode the request budget covers discovery **and** engineering follow-ups. The engine follows missing code and checks supported claims before expanding discovery. Engineering currently uses one writer; four workers parallelize discovery.
3. Inspect **Feature decisions** and **Priority threats**. Request completion, code decisions and deployment declarations are separate. Once the first cohort is useful, enable **Run until complete** and continue. Token targets remain advisory. Stop retains saved work.
4. In **Deployment decisions for the reviewer**, answer yes/no/unknown with reviewer and rationale. Each question explains what the answer changes. It cannot resolve missing code, prove runtime reachability or approve unrelated boundaries.
5. Resume reuses compatible saved work. Changed evidence/context may require reassessment. An implementation still missing after bounded follow-ups remains incomplete, not secure.

## Export intermediate results

**Export STRIDE review · PDF** works from saved partial checkpoints. It includes supported threats, code excerpts when the source hash matches, six-category coverage and deployment decisions. Select **Print / Save as PDF**, turn browser **Headers and footers off**, and save under `C:/SynthesisState/Exports`.

Use **Export complete technical review · HTML** for every hypothesis and investigation task. Browser downloads need Save As or a configured download folder; they do not automatically use the trace directory. Traces automatically go to `C:/SynthesisState/Exports/Traces`.

For JCI qualification, revisit the previously unresolved `ApplyAuthorization` / `TryRevokeAccess` / `SolutionAuthorizationHandler` path. Confirm actual definitions are cited, not only callers. If incomplete, export errors and the technical review with the exact remaining binding. Do not start another broad run to hide an unresolved first cohort.
