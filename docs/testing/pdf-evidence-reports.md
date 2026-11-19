# PDF evidence and threat-model reports

## User workflow

CWE code review offers **CWE evidence · PDF** and **CWE evidence · HTML**. Both include all saved scanner/model candidates, including security issues without CWE mappings. The PDF action opens an authenticated, local report preview with **Print / Save as PDF**. Edge/Chrome provide the PDF writer; no Python, Chromium installation or model call is added to the VM. The HTML file is portable and printable offline.

System model → Export review package → **Threat model · PDF** opens a print projection with context/system DFDs, connected-flow summary, actors, grouped trust boundaries, components, domains/assets, controls, component STRIDE matrix, actual threat scenarios, supporting scenario evidence, questions and token usage. The full HTML/JSON/CSV exports retain detailed flow properties, the full evidence ledger and checklist prompts. PDF explicitly discloses this scope. Existing graph and diagram limits still apply and are shown.

## Evidence contract

- Report generation uses saved finding IDs and the same source-window verifier as the UI: selected local repositories, contained paths, no symlink traversal, current snapshot and matching SHA-256.
- Snippets include cited lines plus up to three context lines on either side. Highlighting means citation, not confirmed exploitability. Each location retains repository, path, line range, hash and source scope (including tests).
- All finding locations are represented. Missing, changed or unverified source gets a visible gap; code is never reconstructed from model prose. Prior/stale reviews are identified and their snippets refused.
- Candidate origin, disposition and independent assessment stay separate. Scanner/model findings are not silently deduplicated. Failed/unreviewed packets and coverage limitations remain visible.
- Source windows use existing best-effort secret redaction; known server/provider secrets are also removed from the evidence report. Source/model text is HTML-escaped. Reports have no external dependencies or remote loads.
- At most four 80-line windows per location, 1,000 windows and 4 MiB of source text per report. Every affected location discloses a source omission. Report output over 24 MiB fails explicitly. These bounds do not remove finding metadata. The exporter blocks review mutations while reading evidence.
- Reports never invoke a model, execute a target, rebuild the graph or change candidate disposition. PDF downloads contain confidential code and architecture; inspect before sharing.

## Verification

`test/evidence-report.test.mjs` checks scanner/model inclusion, model-only export, current hashes, changed/stale/missing files, explicit long-range omissions, hostile HTML escaping, secret removal, incomplete coverage, access control, printable scope and retained threat-model sections.

`test/browser/pdf-report.spec.mjs` follows both UI export actions through authenticated preview, checks code highlighting and missing-source messaging, verifies the print button invokes browser printing, and generates actual PDFs using the browser renderer. No extra authentication token remains in the preview URL. Screenshots and PDFs are retained in test output.

Validate on Windows: stop/restart the updated server with the same workspace and source root, open the saved graph, and export both reports. Choose **Save as PDF** or **Microsoft Print to PDF**; save outside the repositories. No source rebuild or new model call is required. If the browser blocks the report tab, allow popups for the local Synthesis address or download the HTML and print it.
