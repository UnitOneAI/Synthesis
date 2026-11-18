# Focused graph export verification

Run the static-pilot unit/integration and browser suites. `test/graph-package.test.mjs` and the saved-graph browser scenario run through existing Linux/macOS/Windows CI.

Acceptance checks:

1. Restore SQLite after a clone becomes unavailable. Status remains ready with the same generation; export creates no generation or analyze request.
2. Distinguish current, older and unknown extractor identities, including legacy SQLite metadata. Never claim files were rechecked at restart.
3. Export every scope from memory and SQLite. Preserve evidence, snapshot identity and architecture context. Each edge endpoint is present or explicitly missing.
4. Force multipart output, record and traversal caps. Check ZIP/payload/manifest limits, hashes and explicit omissions.
5. Source text defaults off. Opt-in context preserves line references and redacts secrets. Hash changes, unavailable files, traversal and symlinks cannot leak file contents.
6. Reject invalid scopes/revisions, unauthenticated requests and invalid parts. Preparation produces a frozen snapshot; another preparation replaces it.
7. Browser: restart, open saved graph, select scope, prepare/download/read ZIP, enable source context and prepare again. No rebuild or browser errors.
8. Qualify the saved open-autofix assessment without another graph build. Record package sizes, counts, omissions and snapshot IDs. This does not validate unavailable customer clones or a live gateway.

No test proves exhaustive coverage or absence of vulnerabilities. Exports inherit collector/parser/planner and static-resolution limitations.
