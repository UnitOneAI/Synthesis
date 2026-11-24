# Selected-repository STRIDE review

Choose any nonempty set of primary repositories from the saved graph. Repository names are configuration, never customer-specific program logic. The rest of the loaded repositories remain available as supporting evidence. Changing this review selection does not rebuild the graph or change which clones were collected.

## Scope contract

Primary subjects include every extracted interface, configuration/control record and parsed definition in the selected repositories. This includes internal functions, workers, stores, outbound calls and supporting/test code, not only public HTTP controllers. Import bindings and candidate call edges remain navigation context rather than separate asserted attack surfaces. Every primary subject must appear in the plan; packet-size failures reject the preview instead of silently dropping it. There is no twelve-packet or forty-eight-interface cutoff in repository mode. The older operation-only POC remains available and retains its original limits.

The saved inventory is reconciled with parser records and interface/definition citations. Unmapped files, unsupported languages, read failures, parser limits and exclusions remain visible. A mapped file is not a claim that every line was examined or every call resolved. Large function windows and missing dispatch/configuration bindings remain explicit evidence limitations. Static analysis cannot guarantee identification of every threat.

Supporting repositories can supply authentication, authorization, configuration, deployment/installer declarations, storage implementations or other dependencies. Retrieved source must match the saved hash. Their entire repositories are not counted as assessed merely because some context was retrieved. All loaded local clones are checked for changes before source-backed review; no target code, installer, service or probe is executed. Effective deployment facts remain conditions when source/configuration cannot establish them.

## Six-category assessment

Every successful repository-mode response must account for all six STRIDE categories and every primary subject in its review unit. Each category records one of:

- Supported conditional threat: returned scenario, cited input and sensitive operation, relevant controls, remediation and separate deployment conditions.
- Ruled out for the reviewed path: cited control or counterevidence and an explanation.
- No scenario identified in reviewed evidence: explicit assessment, primary-subject citations and recorded scope; not proof of security.
- Specific evidence gap: missing source, implementation, binding or control; excluded from conclusive counts.

An empty threats array alone never completes category assessment. Source references must resolve to supplied windows and inclusive line ranges. A citation spanning overlapping or adjacent supplied windows is split into exact references only when repository, path and file hash match throughout; missing lines, changed hashes and unknown starting records are rejected. Uncited primary subjects and omitted source windows downgrade a claimed conclusion to an evidence gap. Invalid identifiers and unsupported categories are rejected. A claimed negative that contradicts returned scenarios is downgraded to an evidence gap. Scenario indexes are derived from validated category membership; missing conclusion evidence does not discard otherwise valid source-referenced scenarios. Graph-catalog pagination remains a coverage limit, not automatic evidence that every already-cited code conclusion is invalid.

These are model source assessments. Existing independent threat validation remains separately available; repository mode does not automatically run the older serial, per-scenario POC assessment after discovery. The UI and report distinguish the two and do not label category assessment independently validated. Actors and boundaries are not automatically approved. OWASP guidance, per-requirement statuses, CWE review and existing evidence validation remain available.

## Execution and costs

Primary subjects are grouped by repository, component, source file, kind, protocol and direction, with up to four primary records in a packet. Required context can force further splitting. Source/control retrieval uses the existing graph and unchanged clones. Four workers are the maximum; gateway quotas still govern actual throughput. Run until complete removes the action's request-count stop, not cancellation, provider-failure guards, source-integrity checks or evidence limits.

A fixed repository response schema permits provider grammar reuse; exact evidence ownership and source-line validation remain local. The schema omits generation of new connections because the saved graph supplies static connection candidates. Missing implementation remains an explicit gap. Token usage includes unsuccessful responses when the provider reports it. A completed request with an evidence gap is not a conclusive assessment.

Resume uses scope identity, packet hashes and provider/prompt provenance. Prior system, deep and operation-only reviews remain saved separately. The new explicit category contract requires its own review; old responses without category records are not silently upgraded into current conclusive coverage.

## UI

1. Keep supporting repositories loaded in Sources and choose **Open saved graph**.
2. Enable **Include hash-checked, redacted code context in STRIDE**.
3. Open **4 · STRIDE matrix → Select primary repositories**.
4. Check the primary repositories, enter a review title and a deployment assumption, then choose **Save repository scope**.
5. **Selected repositories** becomes the next review scope. Choose **Preview system scope** to see planned work before model calls.
6. Qualify one request with one worker. After a successful response, select up to four workers, enable **Run until complete**, and start or continue the review.
7. Read the six-category table: conclusive, evidence-gap, pending and failed cases are separate. The matrix does not treat an empty category as reviewed unless an explicit cited assessment exists.
8. Export the review package for the full inventory and category records. **Export STRIDE review · PDF** includes partial results, category counts, cited conclusions, actors, boundaries and assumptions. Independent validation is a separate action.

A JSON scope can also be imported:

```json
{
  "kind": "repositories",
  "title": "Selected application repositories",
  "profile": "Declared code and configuration; deployed reachability unverified",
  "repositories": ["repo-one", "repo-two"]
}
```

Names must exactly match the saved inventory. Do not deselect supporting clones in Sources to reduce primary review scope.

Saving and previewing repository scope open the existing disk graph read-only, including after exports or a server restart. Reopening a saved workspace restores its selected review scope; it does not rebuild the graph or call the model. If an older installation reports `Cannot read properties of null (reading 'prepare')` when saving, update Synthesis, restart the server, open the saved graph and save the scope again. Keep the existing workspace and graph files.
