# JCI: update and review saved threats (0.11.1)

This update reuses the existing graph and saved STRIDE packets. It changes how results are presented and how individual threats are checked against controls. It does not make an incomplete JCI assessment complete. Older individual assessments require reassessment under the corrected validation rules; their history is retained. Do not restart the entire discovery run just to generate the new report.

## Update

Stop the running Synthesis server with **Ctrl+C**, then paste this into PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
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

The version should be **0.11.1 or later**. Keep the existing `C:/SynthesisState/JCI-Metasys` workspace and source clones.

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

## Review the existing results first

1. Open the new local access link printed by the server. In **Sources**, select **Open saved graph**. Enable hash-checked source context for the approved model provider.
2. Open **STRIDE matrix → Export STRIDE review · PDF**. Export works from partial checkpoints. The execution receipt distinguishes the saved STRIDE action from workspace-wide token history.
3. Read **Priority threats** for individually supported conditional threats. The **Complete scenario disposition register** preserves every returned scenario and separates supported, ruled-out and unresolved results. A category assessment does not establish every individual threat.
4. In the UI expand **Investigations requiring code**, then **Validate saved threats against code and controls**. Enable redacted source sharing. Start with **Top six priorities**, **1 request**, and **Continue across saved scenarios off** to verify gateway access. This is a connectivity check, not a complete assessment.
5. After a successful response, select **All current source-referenced scenarios**, enable **Continue across saved scenarios**, and choose **Validate saved threats**. This focused assessment follows named controls and candidate implementations using the existing graph. It preserves the STRIDE inventory, has at most three rounds per scenario, and meters model usage. Unresolved bindings remain explicit analysis tasks.
6. To finish pending STRIDE discovery, preview the intended saved repository scope, select **4 workers** and **Run until complete**. This is separate from focused threat assessment. **Actor access: External** filters the display; it does not reduce the planned review scope.
7. Export the PDF again after new results save. Choose **Print / Save as PDF**, turn browser **Headers and footers off**, and save to `C:/SynthesisState/Exports`. Browser downloads do not automatically follow the trace directory.

The report shows resolved named component paths only. If a path is unresolved it is not replaced with a fabricated destination. Review **Connection declarations / Connection coverage** for source locations and missing bindings. Static reachability is not a live network test. The hardening guide documents intended protections; it does not prove their effective deployment.
