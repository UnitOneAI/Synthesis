# PDF evidence and threat-model reports

## User workflow

CWE code review offers **CWE evidence · PDF** and **CWE evidence · HTML**. Both include all saved scanner/model candidates, including security issues without CWE mappings. The PDF action opens an authenticated, local report preview with **Print / Save as PDF**. Edge/Chrome provide the PDF writer; no Python, Chromium installation or model call is added to the VM. The HTML file is portable and printable offline.

System model → Export review package → **Threat model · PDF** opens a print projection with context/system DFDs, connected-flow summary, actors, grouped trust boundaries, components, domains/assets, controls, component STRIDE matrix, actual threat scenarios, supporting scenario evidence, questions and token usage. The full HTML/JSON/CSV exports retain detailed flow properties, the full evidence ledger and checklist prompts. PDF explicitly discloses this scope. Existing graph and diagram limits still apply and are shown.

## Evidence contract

- Report generation uses saved finding IDs and the same source-window verifier as the UI: selected local repositories, contained paths, no symlink traversal, current snapshot and matching SHA-256.
- Snippets include cited lines plus up to three context lines on either side. Highlighting means citation, not confirmed exploitability. Each location retains repository, path, line range, hash and source scope (including tests).
- All finding locations are represented. Missing, changed or unverified source gets a visible gap; code is never reconstructed from model prose. Prior/stale reviews are identified and their snippets refused.
- Candidate origin, disposition and independent assessment stay separate on each finding. Scanner/model findings are not silently deduplicated. Detailed execution counts and omitted summary limitations remain in UI/JSON/diagnostic exports; the shareable CWE report uses the concise summary described below. STRIDE retains its partial/stale coverage notice.
- Source windows use existing best-effort secret redaction; known server/provider secrets are also removed from the evidence report. Source/model text is HTML-escaped. Reports have no external dependencies or remote loads.
- At most four 80-line windows per location, 1,000 windows and 4 MiB of source text per report. Every affected location discloses a source omission. Report output over 24 MiB fails explicitly. These bounds do not remove finding metadata. The exporter blocks review mutations while reading evidence.
- Reports never invoke a model, execute a target, rebuild the graph or change candidate disposition. PDF downloads contain confidential code and architecture; inspect before sharing.

## Verification

`test/evidence-report.test.mjs` checks scanner/model inclusion, model-only export, current hashes, changed/stale/missing files, explicit long-range omissions, hostile HTML escaping, secret removal, incomplete coverage, access control, printable scope and retained threat-model sections.

`test/browser/pdf-report.spec.mjs` follows both UI export actions through authenticated preview, checks code highlighting and missing-source messaging, verifies the print button invokes browser printing, and generates actual PDFs using the browser renderer. No extra authentication token remains in the preview URL. Screenshots and PDFs are retained in test output.

Validate on Windows: stop/restart the updated server with the same workspace and source root, open the saved graph, and export both reports. Choose **Save as PDF** or **Microsoft Print to PDF**; save outside the repositories. No source rebuild or new model call is required. If the browser blocks the report tab, allow popups for the local Synthesis address or download the HTML and print it.


## Default UnitOne presentation

CWE evidence HTML/PDF and the threat-model PDF projection use the bundled UnitOne logo, a Confidential header and “Confidential — Do not share” footer. Table header/footer sections repeat branding on printed pages without covering code. Images are embedded in the document; offline HTML does not depend on a service or remote image fetch. The report preview CSP permits data images but no remote image destinations. Browser-added dates/URLs are controlled by the user's print dialog: turn **Headers and footers** off. The application removes its generated timestamp/revision line from these shareable projections; model/source provenance remains in JSON and per-location evidence.

The CWE report removes the finding index, summary assessment-state breakdown, scanner/model identity sentence, execution-status paragraph and the two specifically requested boilerplate limitations about Community Edition taint resolution and separate CWE/STRIDE obligations. Other limitations, individual disposition/assessment, stale evidence labels, source hashes and missing/changed source messages remain. This is a presentation change only; underlying reports and coverage are not mutated.

**CWE summary** groups every candidate once by its recorded CWE, sorted by candidate count then CWE ID. Columns show candidate records, scanner/model totals and distinct repository counts per CWE. Issues without a CWE remain in a “No CWE mapping” row. The total repository count is a union, not a sum across rows. These are candidate counts, not deduplicated or confirmed vulnerabilities. Detailed findings and code windows follow the summary and supporting tables.

Unit tests cover branding, narrow presentation omissions, preserved source reports, multi-location repository counting and unmapped issues. Browser tests check logo loading under CSP, offline HTML, the summary table, both print flows and partial STRIDE export. Generated multipage PDFs are checked for repeated branding and reviewed visually before release.

Release qualification: 215 engine tests passed with the qualified local Semgrep scanner. A synthetic 86-candidate report spanning a 13-repository snapshot table produced 51 pages; every page retained the UnitOne logo and confidentiality notice, all 86 finding IDs remained, and opening/middle/final pages were rendered for inspection. This is layout qualification, not a new customer scan.

Browser qualification: 28 cases passed in the full run; the scanner-dependent case passed separately with the qualified Semgrep executable (29 distinct passing cases). One optional saved-output fixture was unavailable and skipped. Syntax checks passed.
