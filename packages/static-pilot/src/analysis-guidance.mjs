import { sha } from "./sources.mjs";

// Reviewed, bundled methodology. Target repository SKILL.md files are never executed or loaded as instructions.
export const GUIDANCE_VERSION = "static-security-method-1";
export const GUIDANCE_SOURCES = Object.freeze([
  {
    name: "UnitOne threat-modeling skill",
    version: "1.0.0",
    revision: "70bc259bb01abb3015ad2ad859ad5253cbf0bcab",
    sha: "c9c41c34289aa72612088c2571f2b2b9436b0797",
    url: "https://github.com/UnitOneAI/SecuritySkills/blob/70bc259bb01abb3015ad2ad859ad5253cbf0bcab/skills/appsec/threat-modeling/SKILL.md",
  },
  {
    name: "UnitOne C#/.NET supplement",
    revision: "70bc259bb01abb3015ad2ad859ad5253cbf0bcab",
    sha: "810a8bc330da4a29877d5be2e87154af9737c2fa",
    url: "https://github.com/UnitOneAI/SecuritySkills/blob/70bc259bb01abb3015ad2ad859ad5253cbf0bcab/skills/appsec/threat-modeling/csharp-dotnet.md",
  },
  {
    name: "Existing Synthesis STRIDE and ATT&CK methodology",
    path: "packages/core/src/prompts.ts",
  },
  {
    name: "Existing Synthesis threat grammar and risk factors",
    path: "lib/threat-engine/threat-generator.ts",
  },
  {
    name: "OWASP threat modeling",
    url: "https://owasp.org/www-community/Threat_Modeling",
  },
  {
    name: "OWASP risk rating",
    url: "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
  },
]);
const web = [
  "Broken Access Control",
  "Cryptographic Failures",
  "Injection",
  "Insecure Design",
  "Security Misconfiguration",
  "Vulnerable and Outdated Components",
  "Identification and Authentication Failures",
  "Software and Data Integrity Failures",
  "Security Logging and Monitoring Failures",
  "Server-Side Request Forgery",
];
const api = [
  "Broken Object Level Authorization",
  "Broken Authentication",
  "Broken Object Property Level Authorization",
  "Unrestricted Resource Consumption",
  "Broken Function Level Authorization",
  "Unrestricted Access to Sensitive Business Flows",
  "Server Side Request Forgery",
  "Security Misconfiguration",
  "Improper Inventory Management",
  "Unsafe Consumption of APIs",
];
export const TAXONOMY = Object.freeze([
  ...web.map((name, i) => ({
    framework: "OWASP Web 2021",
    id: `A${String(i + 1).padStart(2, "0")}:2021`,
    name,
    url: "https://owasp.org/Top10/2021/",
  })),
  ...api.map((name, i) => ({
    framework: "OWASP API 2023",
    id: `API${i + 1}:2023`,
    name,
    url: "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  })),
  ...[
    ["T1078", "Valid Accounts"],
    ["T1190", "Exploit Public-Facing Application"],
    ["T1499", "Endpoint Denial of Service"],
  ].map(([id, name]) => ({
    framework: "MITRE ATT&CK",
    id,
    name,
    url: `https://attack.mitre.org/techniques/${id}/`,
  })),
]);
const core = [
  {
    id: "scope-assets",
    question:
      "Identify the protected asset, entry point and applicable product profile. State missing business/data classification context.",
  },
  {
    id: "actor-access",
    question:
      "Name a realistic actor, their initial access and needed capabilities. Consider external callers, insiders and compromised workloads only under explicit assumptions.",
  },
  {
    id: "authority-transition",
    question:
      "Trace caller identity, credential delegation, authorization decision and data ownership across represented flows. A repository or process boundary alone does not prove a trust transition.",
  },
  {
    id: "stride-per-element",
    question:
      "Consider authentication, integrity, accountability, confidentiality, availability and authorization for relevant processes, stores, flows and external entities; explain inapplicability rather than inventing scenarios.",
  },
  {
    id: "control-counterevidence",
    question:
      "Inspect available controls and counterevidence on the relevant path, including inherited middleware and failure behavior. A control name or absence in a partial packet does not establish enforcement or a vulnerability.",
  },
  {
    id: "attack-chain",
    question:
      "Describe prerequisites, concrete abuse steps, conditional impact and mitigation at the affected enforcement point. Cross-repository paths require evidence for each hop; identify unresolved hops.",
  },
  {
    id: "review-quality",
    question:
      "Use the threat grammar: an actor with prerequisites performs an action against an asset, causing an impact. Keep hypotheses distinct from source observations. Do not manufacture risk scores, vulnerability IDs or full-coverage claims.",
  },
];
const domains = [
  {
    id: "api-authorization",
    when: (r) => r.protocol === "HTTP",
    question:
      "Review object, property and function authorization, credential replay, browser/session boundaries, request limits, sensitive workflow abuse and API inventory. Check outbound URL selection and redirect/credential forwarding for SSRF.",
  },
  {
    id: "data-access",
    when: (r) => r.protocol === "database",
    question:
      "Trace untrusted input to query construction, parameterization, tenant/object scope, database identity, backup/log access and resource limits; do not infer SQL injection from a database API name.",
  },
  {
    id: "messaging",
    when: (r) => r.protocol === "messaging",
    question:
      "Check producer/consumer identity, broker resource permissions, payload validation, replay/idempotency, poison messages, dead-letter handling and backpressure across repositories.",
  },
  {
    id: "installation-privilege",
    when: (r) => ["installation", "host"].includes(r.protocol),
    question:
      "Assess package/artifact integrity, privileged custom actions, service identity, writable install paths, configuration ACLs and update/rollback behavior without executing installers.",
  },
  {
    id: "certificate-identity",
    when: (r) => r.protocol === "certificate",
    question:
      "Inspect certificate trust/hostname validation, private-key ownership, import/store permissions, rotation and revocation assumptions; no runtime TLS claim.",
  },
  {
    id: "device-boundary",
    when: (r) => r.protocol === "device",
    question:
      "Assess device identity, command authority, protocol gateways and availability consequences. Do not infer field-device access or physical safety impact from a protocol reference alone.",
  },
  {
    id: "dotnet-controls",
    when: (r) =>
      r.evidence?.some((e) => /\.(cs|csproj|config|wxs)$/i.test(e.path)),
    question:
      "Review ASP.NET authentication/authorization ordering and inherited policies, model binding, raw SQL construction, WCF identity, deserialization, forwarded-header trust, background services and privilege-bearing installation actions where supported by evidence.",
  },
];
export const GUIDANCE_HASH = sha(
  JSON.stringify({
    version: GUIDANCE_VERSION,
    sources: GUIDANCE_SOURCES,
    taxonomy: TAXONOMY,
    core,
    domains: domains.map(({ when, ...d }) => d),
  }),
);
export function analysisGuidance(records) {
  return {
    version: GUIDANCE_VERSION,
    hash: GUIDANCE_HASH,
    sources: GUIDANCE_SOURCES,
    checks: [
      ...core,
      ...domains.filter((d) => records.some(d.when)).map(({ when, ...d }) => d),
    ],
    taxonomy: TAXONOMY,
    scope:
      "Pinned offline methodology; taxonomy mappings are review proposals, not proof. Web 2021 is retained for baseline compatibility, not represented as the latest edition. ATT&CK catalog is a curated subset.",
  };
}
export const QUALITY_INSTRUCTIONS = `Apply the bundled analysisGuidance checks to the supplied evidence and architecture context. Preserve the prior Synthesis methodology: asset and entry-point identification, realistic actor access, explicit authority transitions, STRIDE per element, control and counterevidence review, conditional multi-step abuse and actionable mitigations. Taxonomy is a classification aid, not an attack checklist or proof. Never fill missing OWASP risk factors with defaults; severity remains unassessed until supported reviewer assessment. Do not automatically infer a vulnerability from an API name, missing excerpt or actor stereotype.
For each threat, also provide an analysis object with exactly: attackSteps (1-6 concise nonempty strings), impact (nonempty string), assumptions (array of up to 6 strings), controlEvidenceIds (0-12 evidence IDs from supplied control records), boundaryIds (0-6 IDs from systemContext.boundaries, empty if no supported boundary), mappings (0-4 objects, each exactly framework, id, rationale). Mapping IDs must come from analysisGuidance.taxonomy, with a scenario-specific rationale. Do not invent a mapping or boundary; an empty list is valid. This object supplements the required threat fields. A prose attack path remains conditional and is not an accepted DFD flow. Titles and attack steps must also be conditional when prerequisites are unverified. In metadata-only packets, do not claim that authentication, authorization, tenant filters, pagination or limits are absent: their implementation is not supplied. State the necessary verification instead.`;

export function validateAnalysis(value, packet, text, fail) {
  if (value === undefined)
    return {
      analysis: undefined,
      analysisQuality: {
        status: "incomplete",
        gaps: ["Structured attack reasoning not supplied by this response"],
      },
    };
  const keys = [
    "attackSteps",
    "impact",
    "assumptions",
    "controlEvidenceIds",
    "boundaryIds",
    "mappings",
  ];
  if (
    !value ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(value, k))
  )
    fail("invalid structured threat analysis");
  const list = (v, max) => {
    if (!Array.isArray(v) || v.length > max) fail("invalid analysis list");
    return v;
  };
  const steps = list(value.attackSteps, 6).map(text);
  if (!steps.length) fail("attack steps are required");
  const controls = new Set(
    packet.records
      .filter((r) => r.kind === "control")
      .flatMap((r) => r.evidence.map((e) => e.id)),
  );
  const boundaries = new Set(
    (packet.systemContext?.boundaries || []).map((b) => b.id),
  );
  const checked = (values, allowed, max) => {
    const items = list(values, max);
    if (
      new Set(items).size !== items.length ||
      items.some((x) => !allowed.has(x))
    )
      fail("analysis references are outside the supplied context");
    return [...items];
  };
  const mappings = list(value.mappings, 4).map((m) => {
    if (
      !m ||
      Object.keys(m).length !== 3 ||
      !["framework", "id", "rationale"].every((k) => Object.hasOwn(m, k))
    )
      fail("invalid taxonomy mapping");
    const entry = (packet.analysisGuidance?.taxonomy || []).find(
      (x) => x.framework === m.framework && x.id === m.id,
    );
    if (!entry) fail("taxonomy mapping is not in the pinned catalog");
    return { ...entry, rationale: text(m.rationale), status: "proposed" };
  });
  return {
    analysis: {
      attackSteps: steps,
      impact: text(value.impact),
      assumptions: list(value.assumptions, 6).map(text),
      controlEvidenceIds: checked(value.controlEvidenceIds, controls, 12),
      boundaryIds: checked(value.boundaryIds, boundaries, 6),
      mappings,
    },
    analysisQuality: {
      status: "structured-reasoning-supplied",
      gaps: packet.records.some((r) => r.evidence.some((e) => e.excerpt))
        ? [
            "Source excerpts are partial; effective enforcement remains unverified.",
          ]
        : [
            "Metadata-only review: code-level behavior and control absence are not established.",
          ],
      semantics:
        "Structural validation only; relevance, completeness and conclusions require security review.",
    },
  };
}

export const RISK_FACTORS = Object.freeze({
  likelihood: [
    "skillLevel",
    "motive",
    "opportunity",
    "size",
    "easeOfDiscovery",
    "easeOfExploit",
    "awareness",
    "intrusionDetection",
  ],
  impact: ["confidentiality", "integrity", "availability", "accountability"],
});
// Same OWASP technical-risk bands and matrix as the existing web engine, without invented defaults.
export function assessRisk(factors = {}) {
  const missing = [];
  for (const [group, keys] of Object.entries(RISK_FACTORS))
    for (const key of keys) {
      const value = factors[group]?.[key];
      if (value == null) missing.push(`${group}.${key}`);
      else if (!Number.isFinite(value) || value < 0 || value > 9)
        throw Error("Risk factors must be numbers from 0 to 9 or unknown");
    }
  if (missing.length) return { status: "unassessed", missing };
  const mean = (group) =>
    RISK_FACTORS[group].reduce((n, k) => n + factors[group][k], 0) /
    RISK_FACTORS[group].length;
  const likelihood = mean("likelihood"),
    impact = mean("impact"),
    band = (n) => (n < 3 ? 0 : n < 6 ? 1 : 2);
  const matrix = [
    ["note", "low", "medium"],
    ["low", "medium", "high"],
    ["medium", "high", "critical"],
  ];
  return {
    status: "estimate",
    likelihood,
    impact,
    severity: matrix[band(impact)][band(likelihood)],
    method:
      "OWASP technical risk; business impact and assumptions require reviewer confirmation",
  };
}
