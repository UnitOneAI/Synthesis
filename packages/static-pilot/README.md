# Static multi-repository pilot

Graph-first local source review with optional Claude or Gemini analysis and no target-system access. Add existing clones or import inventory, build the source graph, review the DFD, run bounded STRIDE batches, and export HTML, SVG, Mermaid, CSV and JSON.

**This is a discovery and review pilot, not the completed Synthesis architecture.** Tree-sitter syntax graphs cover C#, C/C++, JavaScript, TypeScript and Python. Security interface collectors remain bounded lexical recognizers. Neither establishes effective authorization, compiler-resolved call paths or exploitable vulnerabilities. Structured collectors establish declarations in source, not deployed facts. Every report remains a draft with gaps. The existing Next.js product and its heuristic/demo pipeline are separate and unchanged.

## Run tonight

Prerequisites: **Node.js 22 or later**, a modern browser, and readable source folders. Windows, Linux and macOS use the same entry point. No .NET SDK, compiler, Python, database or application services are needed. Provider-free discovery needs no AI key; model review requires the selected provider key.

From the Synthesis repository:

```sh
cd packages/static-pilot
npm ci --ignore-scripts
node src/cli.mjs serve --source-root "/absolute/path/to/clones"
```

For Windows PowerShell, replace the source root with a path such as `"C:\Source\Product"`. Install only Synthesis's dependencies, never target-repository dependencies. Open the **access link printed in the terminal**. The server binds to `127.0.0.1:4173`; add `--port 4174` if occupied. The link contains a per-process access token. Do not expose the server through a proxy or use it as a shared service. Stop with Ctrl+C. Snapshots, review annotations and completed analysis batches are saved locally. Use `--workspace "C:/SynthesisState/Product"` to choose the folder; it must be outside the source root. The default is a root-specific directory under your home folder’s `.synthesis/workspaces`. Restart with the same source root and workspace to restore. Raw excerpts remain in memory only.

To preload a prepared inventory selection, append `--manifest "/private/scope.json"` to the serve command. Source folders and product profile can then be adjusted in the UI before analysis.

1. For existing clones, use **Add repository** for each folder (for example `repo-one` under the source root); no workbook is needed. Alternatively, import a workbook or CSV. Supported headers: `Repository`, `Description`, `URL`, `Threat-modeling tier`, `Primary category`, `Classification rationale`, `Recommended initial set`, `Confidence / basis`. Only `Repository` is required. `Yes` in the initial-set column selects a row. Duplicates are reported; formulas are rejected. XLSX uses `Repository Classification` or the first sheet.
2. Select the installer and any justified supporting repositories. Original selection remains separate from current selection. No customer-specific defaults are embedded in this generic tool.
3. Name one product variant/release profile. Naming a profile does not evaluate conditional installer/preprocessor branches; verify source applicability during review.
4. Map folders relative to the source root. For GitHub, choose GitHub and supply `https://github.com/owner/repository` plus an optional ref. It resolves to a pinned commit. Private access requires a server-side `GITHUB_TOKEN` with read access; never put credentials in URLs.
5. Select **Build source graph**. This stage makes no model calls. Review **Source graph** and **Evidence and details** for parsed files, unsupported languages, skipped content and interface coverage. If source excerpts were selected before building, bounded redacted excerpts are retained privately in memory for the later review.
6. Open **System model**. Review the whole-system DFD, then map source interfaces to components, resolve unknown peers, and declare supported flows. Review **Threat actors**, **Trust boundaries**, **Controls** and **Trust domains**. Choose a trust lens and context/system/component view. Record initial access, authority changes, controls, supporting evidence and counterevidence. Repository groupings do not establish runtime processes or trust zones.
7. In **STRIDE matrix**, inspect the estimated batch count, choose a request budget (default 12, maximum 100 per action), then **Run STRIDE review**. Review reuses the existing graph and DFD without rescanning source. **Continue STRIDE review** reuses completed batches and processes pending/failed batches in the saved workspace. Changing declarations, profile, graph, provider, model, prompt or packet invalidates incompatible cached batches. Source changes on disk are not detected until you rebuild the graph; continuing explicitly uses the original snapshot.
8. Select a matrix cell for threat scenarios, separate conditional checklist items, actor/access assumptions and source evidence. Not reviewed, partial review, stale and no-scenario-returned states remain distinct. No scenario returned is not evidence of safety or non-applicability.
9. Use **Export review package** for HTML, SVG, Mermaid, full JSON, source manifest and CSV registers (actors, boundaries, controls, threats, components, flows, assets and STRIDE). Exports use the complete model regardless of view filters. Open the HTML report and use **Print → Save as PDF**; keep SVG/Mermaid for detailed diagrams. The overview is capped at 80 objects with a visible omission notice; registers and JSON retain the complete scope. Excerpts are omitted from checkpoints and exports, but scenario prose can paraphrase submitted evidence: keep reports private.
10. Record review decisions with a reviewer, rationale, owner and severity assessment. These are local annotations, not authenticated organizational approvals. Rebuilding retains architecture declarations and marks decisions stale when evidence changes; repair stale references before relying on them. Source changes on disk are inspected only when rebuilding.


## Claude or Gemini underneath

Choose an organization-approved provider and an available model ID. Model IDs are configurable and are never silently replaced. Set the key in the **server environment**, using your normal secret-management process; never put it in a manifest, source URL or browser field.

| Provider | Flag | Key environment variable | Network destination |
| --- | --- | --- | --- |
| Claude | `--provider anthropic` | `ANTHROPIC_API_KEY` | `api.anthropic.com` |
| Claude via APIM gateway | `--provider anthropic-gateway` | `CLAUDE_API_KEY` | Operator-configured HTTPS base URL |
| Gemini | `--provider gemini` | `GOOGLE_GEMINI_API_KEY` | `generativelanguage.googleapis.com` |

```sh
# The key must already be in this process's environment.
node src/cli.mjs serve --source-root "/private/clones" --manifest "/private/scope.json" --provider anthropic --model YOUR_APPROVED_CLAUDE_MODEL

# Alternative provider, same analysis and export workflow:
node src/cli.mjs serve --source-root "/private/clones" --provider gemini --model YOUR_APPROVED_GEMINI_MODEL
```

`SYNTHESIS_LLM_PROVIDER` and `SYNTHESIS_LLM_MODEL` are optional environment alternatives to the flags. `--provider none` explicitly disables inference even when an environment provider is set. Direct Anthropic, Gemini and an Anthropic Messages-compatible APIM gateway are implemented. Bedrock, Vertex AI, Entra token authentication and other gateway protocols are not implemented.

### Claude through an enterprise APIM gateway

Set `CLAUDE_API_KEY` in the server environment using your organization's secret process. It is separate from `ANTHROPIC_API_KEY`, so both keys can exist on the machine. Select one connection per server/run; there is no automatic fallback. No key is entered into the browser or saved in a manifest.

```sh
node src/cli.mjs serve --source-root "/private/clones" --provider anthropic-gateway --base-url "https://your-approved-gateway.example/anthropic" --model example-deployment-v1 --api-version 2023-06-01
```

Use the provisioned gateway base URL in place of the example. **Keep the deployment ID exactly `example-deployment-v1`** when that is the provisioned name; it is passed unchanged. The adapter appends `/v1/messages` and sends `Ocp-Apim-Subscription-Key: <CLAUDE_API_KEY>`, `anthropic-version: 2023-06-01` and JSON content type. It does not send the direct Anthropic key or add an `x-api-key` header. URLs must be HTTPS with no credentials, query or fragment; give the base before `/v1/messages`. Redirects are rejected. Gateway policy must permit the Messages request, including `system`, `max_tokens` and `messages`.

Environment alternatives: `SYNTHESIS_LLM_PROVIDER=anthropic-gateway`, `SYNTHESIS_LLM_MODEL=example-deployment-v1`, `SYNTHESIS_LLM_BASE_URL=<approved-base>`, and optionally `SYNTHESIS_LLM_API_VERSION=2023-06-01` (the gateway default). Explicit flags take precedence. The base URL and version flags require the gateway provider; gateway environment defaults do not change direct-provider destinations. The same flags work with `analyze`.

The UI shows the selected gateway destination, model and API version. JSON exports retain that connection provenance without the key; treat gateway addresses and reports as internal information. A 403 remains a visible failure: check the exact deployment name, gateway subscription and policy. Successful mock protocol tests do not establish live gateway access.

The **Model review** area shows the configured provider and model. Starting the server with a provider enables the review checkbox by default; you can turn it off before analysis. Metadata-only mode sends repository names, file locations, operation labels, source hashes, evidence references, profile and relevant reviewer declarations. It does not send entire repositories or the inventory. Check **Include bounded, redacted source excerpts** for additional local code context. To preselect excerpts, add `--include-source-excerpts`; on the CLI this flag opts into sending them. Redaction is best effort, not a guarantee that all sensitive content is removed. Use a provider approved for the chosen data. The model has no tools or target-system access.

The same options work with `analyze`:

```sh
node src/cli.mjs analyze --manifest /private/scope.json --source-root /private/clones --out /private/new-model-report --provider anthropic --model YOUR_APPROVED_CLAUDE_MODEL --review-batches 12 --include-source-excerpts
```

The graph review plans repository-local batches (round-robin across repositories), cross-repository protocol cohorts, recursive candidate-call neighborhoods, and explicit flow / actor-access / boundary-crossing obligations. Large scopes are recursively split; relationships cut by partitions receive focused bridge requests. Two invalid responses on the same non-atomic packet trigger smaller child requests on continuation, up to six refinement levels. Each packet contains at most **60 records and 96 KiB**, including syntax ownership and call-site context. A shared protocol is a review candidate, never proof of a connection. The source graph itself is built before inference and is not replaced by model output. Partial excerpts are at most 12 lines / 1,600 characters each; collection takes up to 120 evidence records per file during streamed local analysis, with a 12,000-excerpt portfolio cap. Missing excerpts are not missing interfaces; metadata review remains available.

Each request allows 8,192 output tokens, a 120-second timeout and a 1 MiB response. A review action stops scheduling new requests after 24 minutes or its chosen request budget; completed batches are checkpointed for continuation after restart. HTTP 401/403/429 and transport failures stop further calls in that action. Other failed batches remain visible. Explicit continuation retries prior schema/evidence failures with smaller response instructions while retaining successful batches; every retry consumes the selected request budget. The UI/report tracks completed, failed and pending batches plus unique submitted/reviewed/unreviewed interface IDs. Completing all planned batches does not establish semantic completeness. CLI `analyze` without `--review-batches` retains the legacy one-request path (up to 120 records); use the flag for the graph batch pipeline.

Results are separately labeled **model-inferred / needs review** and must cite valid collected evidence IDs. Suggestions contain actor assumptions, prerequisites, assets, conditional threats, control uncertainty, mitigation questions and possible interface/authority transitions. Schema and citation checks reject fabricated references; they cannot prove the model's reasoning correct. Suggestions never create accepted DFD edges or establish controls/vulnerabilities. Review source before declaring a connection. Changing declarations marks prior suggestions stale. Run STRIDE review again against the revised DFD to refresh them; a source rescan is not required unless the code or scope changed.

Provider/model, prompt version/hash, packet hash, response hash, reviewed record IDs and base model revision are retained in JSON. Raw request/response bodies and keys are not retained. Generated text can still disclose source details. There is **no automatic retry, alternate-provider fallback or demo result**. A rejected, truncated or malformed response produces a visible failure and retains the static draft. HTML exports include model suggestions and status; SVG keeps the reviewer-declared DFD.

Protocol references: [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create) and [Gemini generateContent](https://ai.google.dev/api/generate-content). Provider availability and access policy must be checked in the customer's environment.

### Model response format failures

In **Evidence and details**, the **Model suggestions** card shows the failure reason. `Model did not return the required JSON object` means the provider returned a completed text response that the pilot could not parse; it is distinct from an HTTP authorization or connection error. Version 0.2.2 accepts valid JSON enclosed in a single whole-response Markdown code fence, while preserving schema and evidence validation. Prose around JSON, malformed JSON, multiple objects and invented evidence remain rejected. Failure messages describe the format without exposing returned source text.

Back up the workspace folder before updating. Stop the server, update, restart with the same source root and workspace, and open the newly printed access link. Existing snapshots restore automatically. If the format failure persists, try one or two selected repositories to narrow the response and report the exact error from the card. A smaller run is a diagnostic step, not a review of the whole portfolio. Changing the gateway key does not address a response-format failure.

## Offline transfer

On a connected preparation machine run `npm ci --ignore-scripts`, `npm test` and `npm run check`. Transfer this package directory **including `node_modules`** through the approved transfer process. Dependencies include prebuilt WebAssembly parsers and JavaScript; no customer-side dependency installation is needed. Node.js 22+ must be installed for the customer's OS. Start with `node src/cli.mjs serve --source-root ...`.

Local-source mode with model review disabled needs no network. Optional GitHub acquisition uses `api.github.com` and `codeload.github.com`, never runtime destinations found in code. Keep customer workbooks, manifests, reports, tokens and source outside the public Synthesis checkout. Exports can contain private repository names and architectural metadata even without source excerpts.

## CLI

```sh
node src/cli.mjs import --inventory /private/inventory.xlsx --profile "Server / release" --add example-installer --out /private/scope.json
node src/cli.mjs analyze --manifest /private/scope.json --source-root /private/clones --out /private/new-report
```

Import refuses to overwrite a manifest. Analysis requires a new output directory outside the source root. Outputs: `model.json`, `threat-model.html`, `dfd.svg`, `dfd.mmd`, `source-graph.json`, `stride-matrix.csv`, plus actor, boundary, control, threat, flow, component and asset CSV registers. Exit 2 means a source was unavailable, exit 3 means the requested model review failed or remains partial (the static draft is still exported), exit 1 means invalid input/fatal failure, and exit 0 means a draft was generated—not that security or completeness was established.

Minimal manifest:

```json
{
  "title": "Selected services and dependencies",
  "profile": "Server / release",
  "repositories": [
    {"name":"api","selected":true,"scope":"primary","source":"local","localPath":"api"},
    {"name":"setup","selected":true,"scope":"supporting","source":"github","url":"https://github.com/example/setup","ref":"main"}
  ],
  "declarations":{"bindings":[]}
}
```

Exported connection declarations include evidence fingerprints. Reusing them after selected source changes fails closed: remove obsolete declarations and review new evidence. Source evidence is not automatically remapped. Durable checkpoints restore the saved snapshot and completed batches. Incremental source analysis and authenticated risk approval are not implemented. Local risk-acceptance annotations require a named reviewer and rationale.

## Actual coverage

| Surface | Collected | Limit |
| --- | --- | --- |
| Portfolio | XLSX/CSV, local/GitHub mapping; 100 selected of up to 1000 entries | No automatic organization crawl or scope expansion |
| C#/.NET | Route, HTTP, auth, SQL, WCF, certificate and process references | Lexical candidates; no Roslyn, inherited middleware or interprocedural proof |
| JS/TS | Common Express/Next.js routes, fetch/axios and process references | Dynamic routing/wrappers unresolved |
| Python | FastAPI/Flask-style route decorators, requests/httpx, Depends/Security and database references | Lexical candidates; dynamic routing, wrappers and effective policy unresolved |
| OpenAPI JSON | Declared path/method | No YAML contract parsing, remote references or implementation verification |
| XML/WiX/config | Service, custom-action, permission, SQL, endpoint and certificate declarations | No MSI execution, condition evaluation or effective ACL analysis |
| Messaging/device/native | Selected API/protocol references | Resource identity, permissions and protocol semantics require review |
| Dependencies | Package/project names | Repository ownership requires confirmation; no restore/build |
| YAML, Terraform, other recognized text | File inventory/hashes | Discovery-only; diagnostic emitted |
| Actors/threats | Interface-specific conditional scenarios and access assumptions | Severity unassessed; no confirmed findings |
| DFD | Declared connections and unresolved interface sheets | Source groups are not proven processes; trust transitions require declarations |

Local analysis streams eligible files and has no aggregate file-count, inspected-byte or interface-candidate cutoff. The 1 MiB per-file limit remains. GitHub archives retain 20,000-entry and 64 MiB inspected-text bounds. Excluded directories are recorded but not recursively counted. UI worker limit: 768 MiB heap and 30 minutes. GitHub archive limits: 96 MiB compressed, 256 MiB expanded. Large scopes may require separate, explicitly bounded runs. Local digests cover inspected files and the ledger; they are not atomic snapshots or Git commits. Keep source trees stationary during analysis.

## Verify before a customer run

```sh
npm test
npm run check
node src/cli.mjs import --inventory fixtures/inventory.csv --profile synthetic --out /tmp/synthetic-scope.json
node src/cli.mjs analyze --manifest /tmp/synthetic-scope.json --source-root fixtures/repositories --out /tmp/synthetic-report
```

Use equivalent writable paths on Windows. Fixtures are synthetic and never executed. Review the generated report and declare a known caller/receiver connection. Then have the customer champion review critical ingress, privileged administration, messaging, data synchronization and certificate/device scenarios against customer source. Synthetic success is not customer-source qualification.

## Source graph bounds and qualification

Version 0.5.0 removes the previous local aggregate collection and candidate cutoffs. Each eligible local file is extracted independently, so a large repository does not prevent later repositories from contributing interfaces. Per-file, parser, graph, process and checkpoint safeguards remain; inspect their ledgers before claiming coverage.

The syntax graph allows 100,000 nodes, 200,000 edges and 5,000 emitted nodes per file. Parser time is bounded per file; malformed/unsupported/limited files remain visible. Call sites are source-supported, but target edges are only unique same-file scope candidates. Literal project-reference paths can link collected projects across local clones. This does not resolve runtime services, build conditions, dependency injection, polymorphism, macros, effective controls or deployed permissions. The graph preview Mermaid is limited to 200 nodes; full graph JSON retains all collected nodes/edges. DFD Mermaid aggregates unresolved interfaces by source component, protocol and direction; it never treats project containment as a trust zone.

The automated 12-repository fixture has 840 extracted interface records and verifies complete packet scheduling, continuation, graph provenance, export behavior and no fabricated DFD flows using mocked model responses. It is not a large customer-codebase performance benchmark or evidence of live provider reasoning quality. Customer qualification requires inspecting coverage ledgers and validating critical flows with the security champion.

## Release verification and Windows operation

See [functional test specification](../../docs/testing/system-threat-workspace.md) and [Windows runbook](../../docs/runbooks/windows-static-workspace.md).

## Token usage

Version 0.4.1 adds provider-reported token accounting in the STRIDE view, full request-ledger CSV/JSON and HTML summaries. Failed responses and retries are included; local cached batches add no requests. Shared cross-repository requests are counted once. Missing usage and older unmetered history remain explicit. See [accounting contract](../../docs/design/token-usage.md) and the [Windows instructions](../../docs/runbooks/windows-static-workspace.md#inspect-token-consumption-041).


## Recursive coverage and diagnostics (0.5.0)

**STRIDE matrix → Analysis coverage** separates interface, callable, candidate path, flow, actor-access and boundary-crossing obligations. A successful request counts only for obligations whose required records and context were submitted together. Unsupported files, unresolved targets, unconfirmed assumptions and limits remain explicit. This is submission coverage, not proof of security or complete semantic analysis.

**Download diagnostic bundle** is available even before a completed scan. It exports the retained source graph, source/parser ledgers, recursive worklist, request attempts, safe failure codes, provider request IDs, token counts and durable traces in one ZIP. Traces default to `<workspace>/traces`; `--trace-dir` chooses another directory outside the source root. The offline `diagnostics` command works without a provider key. Raw excerpts, prompts and model-response prose are excluded; graph metadata remains confidential.

See the [recursive review and observability contract](../../docs/design/recursive-coverage-observability.md) and [Windows diagnostic instructions](../../docs/runbooks/windows-static-workspace.md#collect-portable-diagnostics-050). The retained graph still has resource limits; full disk-backed graph indexing and compiler-aware cross-file dispatch are not implemented.
