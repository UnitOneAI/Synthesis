# Static multi-repository pilot

Local source review with no AI provider or target-system access. Import XLSX/CSV inventory, select primary and supporting sources, inspect evidence, declare connections and trust transitions, and export HTML, SVG and JSON.

**This is a discovery and review pilot, not the completed Synthesis architecture.** Code collectors are bounded lexical recognizers. They do not establish effective authorization, complete call paths or exploitable vulnerabilities. Structured collectors establish declarations in source, not deployed facts. Every report remains a draft with gaps. The existing Next.js product and its heuristic/demo pipeline are separate and unchanged.

## Run tonight

Prerequisites: **Node.js 22 or later**, a modern browser, and readable source folders. Windows, Linux and macOS use the same entry point. No .NET SDK, compiler, Python, database, application services or AI keys are needed.

From the Synthesis repository:

```sh
cd packages/static-pilot
npm ci --ignore-scripts
node src/cli.mjs serve --source-root "/absolute/path/to/clones"
```

For Windows PowerShell, replace the source root with a path such as `"C:\Source\Product"`. Install only Synthesis's dependencies, never target-repository dependencies. Open the **access link printed in the terminal**. The server binds to `127.0.0.1:4173`; add `--port 4174` if occupied. The link contains a per-process access token. Do not expose the server through a proxy or use it as a shared service. Stop with Ctrl+C. State is in memory: export results before stopping.

To preload a prepared inventory selection, append `--manifest "/private/scope.json"` to the serve command. Source folders and product profile can then be adjusted in the UI before analysis.

1. Import the workbook or CSV. Supported headers: `Repository`, `Description`, `URL`, `Threat-modeling tier`, `Primary category`, `Classification rationale`, `Recommended initial set`, `Confidence / basis`. Only `Repository` is required. `Yes` in the initial-set column selects a row. Duplicates are reported; formulas are rejected. XLSX uses `Repository Classification` or the first sheet.
2. Select the installer and any justified supporting repositories. Original selection remains separate from current selection. No customer-specific defaults are embedded in this generic tool.
3. Name one product variant/release profile. Naming a profile does not evaluate conditional installer/preprocessor branches; verify source applicability during review.
4. Map folders relative to the source root. For GitHub, choose GitHub and supply `https://github.com/owner/repository` plus an optional ref. It resolves to a pinned commit. Private access requires a server-side `GITHUB_TOKEN` with read access; never put credentials in URLs.
5. Analyze and review coverage. Missing sources, unsupported formats, parse failures and limits remain visible. File inspection is not semantic coverage. Source excerpts/configuration values are omitted from exports; inspect referenced files locally.
6. In **Connect and export**, select interface endpoints and give a rationale. Add data, controls and a trust transition only when justified. Declarations stay declared. Reviewer names are attribution, not authenticated organizational risk approval.
7. Export HTML, SVG, full model JSON and the reusable manifest. Reports are self-contained with no network assets. SVG contains all flow sheets; registers retain full labels. Printing HTML omits the long SVG, so retain the separate diagram file. Native paginated PDF is not implemented.

## Offline transfer

On a connected preparation machine run `npm ci --ignore-scripts`, `npm test` and `npm run check`. Transfer this package directory **including `node_modules`** through the approved transfer process. Dependencies are JavaScript-only; no customer-side dependency installation is needed. Node.js 22+ must be installed for the customer's OS. Start with `node src/cli.mjs serve --source-root ...`.

Local-source mode needs no network. Optional GitHub acquisition uses `api.github.com` and `codeload.github.com`, never runtime destinations found in code. Keep customer workbooks, manifests, reports, tokens and source outside the public Synthesis checkout. Exports can contain private repository names and architectural metadata even without source excerpts.

## CLI

```sh
node src/cli.mjs import --inventory /private/inventory.xlsx --profile "Server / release" --add example-installer --out /private/scope.json
node src/cli.mjs analyze --manifest /private/scope.json --source-root /private/clones --out /private/new-report
```

Import refuses to overwrite a manifest. Analysis requires a new output directory outside the source root. Outputs: `model.json`, `threat-model.html`, `dfd.svg`. Exit 2 means a source was unavailable, exit 1 means invalid input/fatal failure, and exit 0 means a draft was generated—not that security or completeness was established.

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

Exported connection declarations include evidence fingerprints. Reusing them after selected source changes fails closed: remove obsolete declarations and review new evidence. Automatic remapping, incremental analysis and risk acceptance are not implemented.

## Actual coverage

| Surface | Collected | Limit |
| --- | --- | --- |
| Portfolio | XLSX/CSV, local/GitHub mapping; 100 selected of up to 1000 entries | No automatic organization crawl or scope expansion |
| C#/.NET | Route, HTTP, auth, SQL, WCF, certificate and process references | Lexical candidates; no Roslyn, inherited middleware or interprocedural proof |
| JS/TS | Common Express routes, fetch/axios and process references | Dynamic routing/wrappers unresolved |
| OpenAPI JSON | Declared path/method | No YAML contract parsing, remote references or implementation verification |
| XML/WiX/config | Service, custom-action, permission, SQL, endpoint and certificate declarations | No MSI execution, condition evaluation or effective ACL analysis |
| Messaging/device/native | Selected API/protocol references | Resource identity, permissions and protocol semantics require review |
| Dependencies | Package/project names | Repository ownership requires confirmation; no restore/build |
| YAML, Terraform, other recognized text | File inventory/hashes | Discovery-only; diagnostic emitted |
| Actors/threats | Interface-specific conditional scenarios and access assumptions | Severity unassessed; no confirmed findings |
| DFD | Declared connections and unresolved interface sheets | Source groups are not proven processes; trust transitions require declarations |

Per-repository limits: 20,000 file entries, 1 MiB per inspected file, 64 MiB inspected text, 2,000 interface/control candidates. System extraction stops at a repository boundary after 10,000 candidates (maximum 11,999). Excluded directories are recorded but not recursively counted. UI worker limit: 768 MiB heap and 30 minutes. GitHub archive limits: 96 MiB compressed, 256 MiB expanded. Large scopes may require separate, explicitly bounded runs. Local digests cover inspected files and the ledger; they are not atomic snapshots or Git commits. Keep source trees stationary during analysis.

## Verify before a customer run

```sh
npm test
npm run check
node src/cli.mjs import --inventory fixtures/inventory.csv --profile synthetic --out /tmp/synthetic-scope.json
node src/cli.mjs analyze --manifest /tmp/synthetic-scope.json --source-root fixtures/repositories --out /tmp/synthetic-report
```

Use equivalent writable paths on Windows. Fixtures are synthetic and never executed. Review the generated report and declare a known caller/receiver connection. Then have the customer champion review critical ingress, privileged administration, messaging, data synchronization and certificate/device scenarios against customer source. Synthetic success is not customer-source qualification.
