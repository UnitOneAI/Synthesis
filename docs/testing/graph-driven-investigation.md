# Graph-driven static investigation acceptance

- Twelve selected repositories: a requested control search returns evidence from another repository to its originating review; a static reference chain supplies evidence across all twelve. Fixture edges are explicit candidate relationships, not a compiler-resolution benchmark.
- Restart: close/reopen exploration SQLite, recover accepted results and provider usage, and do not repeat completed requests. Interrupted outcomes require explicit retry.
- Limits: stop before requests that exceed token reservations; retain pending graph work on request/step/depth/time stops. Source changes reject continuation. No failure or missing evidence becomes a safe outcome.
- Evidence: model actions accept supplied record/node IDs and literal indexed queries only. Reject unsupported shell actions. Verify source hashes, scope and containment before returning code.
- Disk graph: paginate incident edges and indexed-name searches directly from SQLite; preserve all selected scope edges.
- CWE: retain 25 code-review obligations and four additional-evidence targets per repository; additional unmapped findings do not replace them.
- UI: budget controls reach the authenticated action; inspection exposes task states, outcomes and lineage. Existing source-evidence panels and small exports remain usable.
- Semgrep: existing staged-source baseline remains supported; no custom Synthesis graph is represented as Semgrep input.
- Actual validation: use the saved open-autofix graph without target execution. Record bounded live provider calls, reported tokens, pending scope and unresolved findings. JCI source is not available locally; synthetic multi-repository tests are not a JCI scan.

Tests: `test/investigation-frontier.test.mjs`, `test/exploration.test.mjs`, existing source/graph/CWE/API tests and Playwright review workflows.
