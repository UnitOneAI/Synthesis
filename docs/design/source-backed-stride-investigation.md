# Source-backed STRIDE investigation

## Problem and behavior

STRIDE could consume a saved graph without the implementation of the controls it questioned. Exploration retrieved source for CWE discovery and candidate assessment, but its STRIDE branch still used an empty excerpt map. Reopening a workspace also rejected the explicit STRIDE source option when transient excerpts were lost.

Source-enabled STRIDE now verifies the local repository snapshots against the saved graph and reads hash-checked, redacted code windows only for active packets. It does not rebuild the parser graph or execute target code. Source sharing remains explicit. Metadata-only review remains available and is not described as source-backed analysis.

The ordinary STRIDE action retains its parallel scheduler and continuous-run behavior. The Exploration action additionally permits STRIDE to request indexed-name searches and graph-neighbor traversal. Those dependencies retrieve evidence across selected repositories and return it to the originating STRIDE assessment. A later response can revise its conditional conclusion. Missing external facts, source limits and unsuccessful searches stay unresolved. Normal STRIDE does not automatically launch Exploration; its status panel points to this follow-up workflow.

## Context, persistence and coverage

Three concerns remain separate: source graph, system/DFD model, and investigation history. Existing source evidence IDs remain owned by their original interfaces. Retrieved supporting windows are context, not automatically attributed controls or accepted DFD edges. Name matches and static adjacency do not prove binding or reachability.

A packet includes at most sixteen verified windows and stays within the existing packet byte limit. Omitted windows and graph-catalog limits appear as gaps. The durable record stores source references, hashes, gaps, response history and request fingerprints; fetched source windows are not checkpointed. Model responses can quote source, so saved responses and exports still need inspection before sharing. Identical evidence does not trigger endless reassessment. Evidence tasks are shared by file/hash/location across requesting investigations. Restart restores dependencies and reuses completed work; changed source requires a new graph generation.

Source-backed and metadata-only results have distinct cache provenance. Guidance, prompt and investigation versions enter context identity. Legacy results are retained as historical where existing stale-state rules apply, rather than silently relabeled with new standards.

Packet completion means that a response was accepted, not that evidence gaps were resolved. The source/control status panel exposes supplied windows, unresolved evidence and per-packet requirement statuses. The exploration frontier independently retains waiting, blocked and failed tasks. A completed queue is not proof of complete vulnerability detection. Requested CWE targets remain mandatory and separate from ASVS, CAPEC and STRIDE.

## Standards scope

- OWASP Web 2025 is added; Web 2021 and API 2023 mappings remain versioned and available.
- Eleven unchanged ASVS 5.0.0 requirements are bundled with official provenance, input hash and attribution. They cover selected encoding, authorization, transport and sensitive-data controls. This is a subset, not ASVS level certification.
- Each requirement may have a source-supported, needs-context or evidence-supported not-applicable assessment. Missing assessments stay not-reviewed. Unknown IDs, duplicate obligations and invented evidence are rejected. Source-supported assessments require supplied code context; they remain conditional static assessments.
- CAPEC 3.9 patterns 63, 122 and 180 supplement the existing curated ATT&CK techniques. They guide scenarios, not execution. Model mappings require a scenario-specific rationale and an allowed catalog ID.
- Full ASVS/ATT&CK/CAPEC coverage, runtime testing and compiler-level cross-file resolution are not implemented.

## Operator workflow

1. Open the saved graph with the same local clones and workspace.
2. Under Sources, enable the configured model and the explicit hash-checked code context option.
3. Run STRIDE normally; choose up to four workers and Run until complete if desired. Source verification may take time on large clones; progress names the repository.
4. Use Exploration with source sharing enabled for adaptive searches and path follow-up. Its existing per-action request, token, step, depth and time budgets still apply; completed work survives continuation.
5. Inspect unresolved evidence and requirement statuses alongside the matrix. Export the saved review and diagnostic trace before transferring results.

JCI's PR before/after snapshots remain necessary to validate the actual SecurityDB, FancyTree and NGINX cases. Fixtures and open-autofix validation do not establish JCI detection quality or deployed behavior.
