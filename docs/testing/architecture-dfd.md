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

Transport regression: calls with HTTP and HTTPS source URLs must form separate connections even when source, target and route match. SVG, Mermaid and the inspector retain the transport distinction; a source URL does not establish TLS validation or runtime enforcement.

Concurrency regression: eight simultaneous requests for the same disk-backed review plan must all succeed with the same revision and obligations. Pending identical plans share one query; worker slots are released on exit before completion is reported. The start/cancel browser flow must not produce resource errors during overlapping refreshes.

## Internal topology regression specification

The internal topology extension must pass these cases before release:

| Case | Required result |
|---|---|
| API imports and invokes a worker; worker invokes storage | Connected source candidates with call and definition evidence; worker remains an internal unit |
| Import without invocation, comment-only API, shadowed constructor | No fabricated invocation edge |
| Unique Python re-export | Resolve within the repository, retain import and definition evidence |
| SQLite/SQLAlchemy/file storage/provider SDK | Logical resources retain evidence; unknown physical identities/endpoints remain explicit gaps |
| Same-project connection string key | Connect source use to one configured identity; reject conflicting environment values |
| Twelve .NET repositories | Retain HTTP chain, hosted workers, shared SQL, RabbitMQ and WCF configuration references across disk/restart |
| Literal supervisor host and reverse proxy declarations | Connect matching loopback ports only; no configuration execution |
| Project-script declaration | CLI candidate points to a collected module; no name-based deployment guesses |
| Grouped system view | Hide test resources by default, retain full individual records, avoid merging reviewer decisions/trust memberships |
| Browser and exports | Worker/store visible; selection shows source locations; coverage shows identity gaps; Mermaid and restart retain topology |

Validate the actual repository separately from fixtures. Store customer-specific screenshots, evidence and reports outside the public checkout. Report source counts, visible and grouped connections, unresolved gaps, parser limits, model-call count and browser errors. A successful graph build or scan is not proof of exhaustive architecture or CWE coverage.
