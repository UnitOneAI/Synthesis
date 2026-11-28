# JCI automatic section threat modeling — 0.14.0

This runs on the existing graph. It automatically chooses small sections and finishes their code investigations before advancing. There is no operation-selection confirmation. Reports are available as sections finish. A real missing implementation can block a section; it is never exported as complete. Other independent sections continue. Gateway access failures stop the run and preserve saved progress.

## 1. Update Synthesis

Stop Synthesis with **Ctrl+C**. Paste into PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
$workspace = 'C:/SynthesisState/JCI-Metasys'
if (-not (Test-Path "$workspace/snapshot.json")) { throw 'Saved snapshot missing.' }
if (-not (Test-Path "$workspace/graph.sqlite")) { throw 'Saved graph missing.' }
$backup = 'C:/SynthesisState/Backups/JCI-Metasys-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Force $backup | Out-Null
Copy-Item -LiteralPath $workspace -Destination "$backup/Workspace" -Recurse
Set-Location 'C:/Tools/Synthesis'
if (git status --porcelain) { throw 'Preserve local tool changes before updating.' }
git fetch origin main
if ($LASTEXITCODE -ne 0) { throw 'GitHub fetch failed. Resolve GitHub access before continuing.' }
git switch main
if ($LASTEXITCODE -ne 0) { throw 'Could not switch to main.' }
git merge --ff-only origin/main
if ($LASTEXITCODE -ne 0) { throw 'Update failed. Keep the checkout and resolve its branch difference.' }
Set-Location 'C:/Tools/Synthesis/packages/static-pilot'
npm ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
npm run check
if ($LASTEXITCODE -ne 0) { throw 'Application checks failed.' }
node -p "require('./package.json').version"
```

Expect **0.14.0 or later**. Keep the JCI clones unchanged.

## 2. Start with the gateway

Use the approved JCI gateway key. No Azure login or Docker is needed for Synthesis.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'C:/Tools/Synthesis/packages/static-pilot'
New-Item -ItemType Directory -Force 'C:/SynthesisState/Exports/Traces' | Out-Null
$gatewaySecret = Read-Host 'JCI gateway subscription key' -AsSecureString
$env:CLAUDE_API_KEY = [System.Net.NetworkCredential]::new('', $gatewaySecret).Password
Remove-Variable gatewaySecret
if ([string]::IsNullOrWhiteSpace($env:CLAUDE_API_KEY)) { throw 'Gateway key is empty.' }
$env:SYNTHESIS_STRUCTURED_OUTPUTS = '1'
$env:SYNTHESIS_REQUEST_TIMEOUT_MS = '300000'
node src/cli.mjs serve --source-root 'C:/builds/git/jci-products' --workspace 'C:/SynthesisState/JCI-Metasys' --graph-storage sqlite --trace-dir 'C:/SynthesisState/Exports/Traces' --provider anthropic-gateway --base-url 'https://apim-apimhub-devqa-eastus2-ndmz.azure-api.net/anthropic' --model 'claude-opus-4-6-1' --api-version '2023-06-01'
```

These are the previously supplied gateway settings. Native structured output must be supported by the approved deployment. A 403 requires fixing gateway authorization; repeatedly resuming will not repair the key.

## 3. Run automatically

1. Open the server's local access link, then **Sources → Open saved graph**. Enable redacted source sharing with the configured gateway. Do not rebuild unchanged clones.
2. Open **4 · STRIDE matrix**. The **Automatic section threat modeling** panel states which saved primary repositories will be used. With no repository scope saved, it uses all loaded repositories. If API Gateway and MUI are already saved, that selection is retained; other repos remain supporting evidence.
3. Set parallel review workers to **4** if allowed by the gateway.
4. Click **Plan and run sections automatically**. No JSON, scope preview or operation confirmation is required. This mode continues across sections; the legacy request-budget box does not stop it after 12 calls.
5. Leave the Synthesis server running and prevent the Windows machine from sleeping. Each completed section gets its own **Export section · PDF** button. Save under `C:/SynthesisState/Exports` and disable browser print headers/footers.

The **complete** state requires every named operation to have a cited decision in all six categories, with all returned scenarios assessed. Supported conditional threats may still have deployment questions: these concern applicability, not missing code. A section can contain no identified threats, but must still show six evidence-backed category conclusions.

**Stop review** preserves checkpoints. After restart, click the same automatic-run button: compatible completed sections are skipped, interrupted work resumes, and remaining sections continue. Unchanged blocked investigations are not repeatedly billed. Inspect **Why not complete** for the exact missing code or binding. Provider failures stop globally; correct gateway access and resume. Partial diagnostic exports remain available but cannot carry a complete-section label.

Browser PDF downloads are not automatically placed in the trace directory. Traces are written automatically to `C:/SynthesisState/Exports/Traces`. Existing CWE scanning and manual STRIDE modes remain available.

## Local caching — no gateway change

Automatic sections now create `C:/SynthesisState/JCI-Metasys/review-cache.sqlite` automatically. The gateway settings above stay the same. No provider prompt caching is requested.

The section panel separates **provider requests**, **reported tokens**, **local assessments reused**, and **duplicate input avoided**. Reused assessments make no model call. New assessments receive compact source evidence with the same lines and citations. Byte savings are not a token estimate.

Keep the workspace when updating or restarting. Compatible completed sections already skip work; this cache additionally recovers exact validated responses when a review projection must be replayed. New code, assumptions, prompts or model settings require compatible fresh review. It does not reuse a conclusion for a different route simply because a helper matches. Existing 0.13.0 completed sections remain saved; the new cache starts empty and fills as new eligible requests finish.

If the cache is unavailable, the UI reports that review is proceeding without it. Do not delete `snapshot.json` or `graph.sqlite` to clear a cache. If troubleshooting requires clearing only the cache, stop Synthesis first and remove only `review-cache.sqlite`. Cached response prose is confidential workspace data, and is excluded from diagnostic/graph exports.

## Faster first runs and readable reports

The same **Plan and run sections automatically** button now batches up to three related threats within each section by default. Common source and control analysis are shared, but each threat retains its own cited path, conditions and independent challenge. Nothing additional needs enabling. Keep using the existing graph; completed compatible sections stay saved.

The section panel shows provider requests, case assessments/challenges and the requests that batched related threats. These are different counts: a shared request is billed once. All six categories still apply to every operation. A batch or section with missing evidence cannot claim completion.

Reports place the decision, impact, conditions and developer action first. The full supporting argument and category evidence follow in an appendix, including in PDF. Save the complete report; no need to expand hidden evidence before printing. This is static analysis of source and collected configuration, not a live reachability test.
