# Static analysis methodology and prior-analysis compatibility

Implemented in static-pilot 0.6.0 as `analysis-guidance.mjs`. The disk graph is evidence infrastructure; the analysis method remains explicit and versioned.

## Existing methodology carried forward

The pack draws on the existing `packages/core/src/prompts.ts`, `lib/threat-engine/threat-generator.ts`, `lib/threat-engine/owasp-risk-engine.ts`, and the UnitOne [threat-modeling skill](https://github.com/UnitOneAI/SecuritySkills/blob/70bc259bb01abb3015ad2ad859ad5253cbf0bcab/skills/appsec/threat-modeling/SKILL.md) with its [.NET supplement](https://github.com/UnitOneAI/SecuritySkills/blob/70bc259bb01abb3015ad2ad859ad5253cbf0bcab/skills/appsec/threat-modeling/csharp-dotnet.md). The upstream revision and content identities are bundled for provenance. This is a curated static adaptation, not execution of the entire upstream skill or a claim that every skill in SecuritySkills has been integrated.

Every packet receives asset/entry-point, actor/access, authority-transition, STRIDE-per-element, control/counterevidence, attack-chain and review-quality checks. Evidence selects additional HTTP/API, database, messaging, installation/privilege, certificate, device and .NET questions. No target code is executed and no target `SKILL.md` becomes an instruction. Installation in the customer environment needs no network access to fetch skills.

The baseline taxonomy explicitly retains OWASP Web **2021** and API **2023** identifiers, plus a small verified ATT&CK subset. It does not call the Web 2021 baseline the latest edition, provide the full ATT&CK catalog, or infer compliance. Sources are [OWASP Web 2021](https://owasp.org/Top10/2021/), [API 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), and the catalog's individual MITRE technique pages. The workflow follows [OWASP threat modeling](https://owasp.org/www-community/Threat_Modeling): describe scope and assumptions, identify threats, choose mitigations and review the resulting model.

## Threat reasoning and validation

The existing threat statement retains actor, initial access, asset, scenario, prerequisites, controls, mitigation and evidence IDs. Responses now request structured attack steps, conditional impact, assumptions, supplied control-evidence/boundary IDs and proposed taxonomy mappings with rationales. Unknown IDs are rejected; returned mappings remain proposals. Legacy-shaped responses remain readable but explicitly lack structured reasoning. Structural validation cannot determine whether a plausible-looking explanation is correct.

Actor capabilities and trust transitions must be supported or labeled assumptions. Source grouping, protocol similarity, control names and missing excerpts do not establish runtime reachability, enforcement or vulnerabilities. Empty findings never establish safety. The matrix continues to distinguish submitted evidence from reviewer decisions.

The guidance version/hash participates in review provenance and cache identity and appears in diagnostics. Changed guidance invalidates incompatible reviews. Rebuilding preserves compatible prior analysis; changed source or methodology retains scenarios as stale reference material. Existing reviewer declarations and decisions remain subject to source-reference and fingerprint checks. A new review does not treat previous model conclusions as source facts.

## Risk assessment

The optional reviewer form uses the existing OWASP technical-impact factors and risk matrix. All twelve factors must be supplied before a technical-risk estimate is calculated on the server. Unknown values remain unknown; there are no default fives, actor-type boosts or automatically inferred business consequences. The reviewer supplies rationale and identity, and the estimate becomes stale with its subject's evidence. This is an estimate for review, not a verified vulnerability or organizational risk acceptance. See [OWASP's risk-rating method](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) for the distinction between technical and business impact.

Attack reasoning, proposed mappings, risk estimates and provenance are retained in the workspace and normal reports. Portable diagnostics retain method identity and coverage but exclude model-response prose and source excerpts. See [acceptance tests](../testing/disk-graph-and-analysis-quality.md).

## Source-backed standards increment

The current static review additionally includes versioned OWASP Web 2025, eleven selected ASVS 5.0.0 requirements and three CAPEC 3.9 patterns. Older mappings remain available; incomplete requirements do not imply compliance. See [source-backed STRIDE investigation](source-backed-stride-investigation.md) for evidence retrieval, adaptive follow-up and the exact limits.
