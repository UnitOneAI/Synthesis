# Architecture DFD acceptance specification

The DFD presents static candidates, not confirmed deployed topology or exploited vulnerabilities. No target code may be executed during validation.

| Requirement | Verification |
| --- | --- |
| Cross-repository configured connections | Twelve .NET host fixtures, JSON URL configuration, BaseAddress, literal local variable, route/listener match; evidence, memory/disk parity and cache reuse |
| Conservative resolution | Conflicting environment configurations, reassignment, shadowed parameters, unknown expressions and ambiguous routes remain gaps |
| Request messages | Explicit HttpRequestMessage method/path and XML AppSettings base URL resolve; source/configuration evidence retained and credentials absent |
| Component semantics | Executable/web project, startup and installer facts create candidates; tests stay separate; uniquely referenced library associates with host; focus restores individual source group |
| Graph readability | 200 equivalent calls form one connector with all member IDs; reverse direction, control differences and review dispositions remain separate; cycles terminate |
| Coverage honesty | Default excludes unknown peers, explicit toggle restores them; counts distinguish filtering and canvas truncation; registers retain all flows |
| Trust and actor interpretation | Candidate identity boundaries remain pending, declared domains retain nesting and decisions, rejected/stale paths excluded, actor paths remain conditional |
| Functional UI | Group selection by keyboard, member-flow inspection, evidence, zoom/fit, unresolved search, selected-view export, candidate boundary badge and restart |
| Persistence | View/filter changes do not mutate saved model; source facts invalidate cache; existing architecture decisions retain fingerprint checks |
| Exports | SVG and Mermaid share projection, include coverage and stable member IDs; selected lens/focus preserved; full registers remain complete |
| Diagnostics | Compact errors include candidate/source/non-production/host counts and unchanged bounded failure lists; no source excerpts, credentials or provider prompts |

Run from `packages/static-pilot`:

```sh
npm run check
npm test
npm run test:ui
```

Set `SYNTHESIS_TEST_SEMGREP` to an already installed scanner to exercise the real scanner tests. CI also verifies Node 22/24 on Windows, macOS and Linux, browser flows on Windows/Linux, and real Semgrep on Windows/Linux.

The UnitOne validation uses a read-only open-autofix clone and a separate SQLite graph directory. Record inspected file count, discovered/unresolved interface counts, represented/filtered flows and grouped diagram connections. This validates the mechanism against a real codebase; it does not establish coverage of a customer's unavailable repositories.
