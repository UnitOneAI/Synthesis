import {
  citationCoversEvidence,
  resolveSourceCitation,
} from "./source-citation.mjs";
import {
  STRIDE_INVESTIGATION_PROMPT,
  STRIDE_INVESTIGATION_SCHEMA,
  validateStrideInvestigation,
} from "./stride-evidence.mjs";
import { redact } from "./model-review.mjs";
import { REPOSITORY_CATEGORIES } from "./repository-assessment-summary.mjs";
export {
  REPOSITORY_CATEGORIES,
  repositoryAssessmentSummary,
} from "./repository-assessment-summary.mjs";
export const REPOSITORY_PROMPT =
  STRIDE_INVESTIGATION_PROMPT +
  `
Repository assessment contract v1. Omit connections and explorationRequests from this response; existing static connections are supplied and unresolved evidence belongs in missingEvidence. This overrides the base response field list. Also return categoryReviews: exactly one record for each of the six STRIDE categories. Each record covers ALL reviewUnit.primaryInterfaceIds (copy them to interfaceIds). Never infer a clean category from no returned threats. Use status supported-conditional, ruled-out, no-scenario-identified, or evidence-gap. Explain the reviewed behavior, relevant controls and why the actor capability matters. Cite sourceContext.records using recordId and inclusive line/endLine; role is input, operation, control, counterevidence, or context. These citations refer to actual supplied code, not graph names. Include threatIndexes (zero-based indexes into threats) for every scenario in this category. A supported-conditional result requires cited input and sensitive operation, remediation, and any deployment conditions stated separately. A ruled-out result requires a cited opposing control/counterevidence. A no-scenario-identified result needs cited review of every primary interface; it is not proof of security. A category with any missing implementation, binding, source window or unresolved scenario must be evidence-gap, with a specific missingEvidence description. Do not put missing implementation in deploymentConditions to claim completion. An unknown deployed profile can remain a deployment condition when the code path is established. Source retrieval omissions remain gaps. For mixed results in a category use evidence-gap and retain useful conditional scenarios. Keep each rationale concise (under 100 words). No runtime validation or organizational approval is claimed.`;
const string = { type: "string" };
const strings = { type: "array", items: string };
const citation = {
  type: "object",
  additionalProperties: false,
  properties: {
    recordId: string,
    line: { type: "integer" },
    endLine: { type: "integer" },
    role: {
      type: "string",
      enum: ["input", "operation", "control", "counterevidence", "context"],
    },
  },
  required: ["recordId", "line", "endLine", "role"],
};
export const REPOSITORY_SCHEMA = structuredClone(STRIDE_INVESTIGATION_SCHEMA);
delete REPOSITORY_SCHEMA.properties.connections;
delete REPOSITORY_SCHEMA.properties.explorationRequests;
REPOSITORY_SCHEMA.required = REPOSITORY_SCHEMA.required.filter(
  (k) => !["connections", "explorationRequests"].includes(k),
);
REPOSITORY_SCHEMA.properties.categoryReviews = {
  type: "array",
  items: {
    type: "object",
    additionalProperties: false,
    properties: {
      category: { type: "string", enum: REPOSITORY_CATEGORIES },
      status: {
        type: "string",
        enum: [
          "supported-conditional",
          "ruled-out",
          "no-scenario-identified",
          "evidence-gap",
        ],
      },
      interfaceIds: strings,
      rationale: string,
      citations: { type: "array", items: citation },
      threatIndexes: { type: "array", items: { type: "integer" } },
      missingEvidence: strings,
      deploymentConditions: strings,
      remediation: string,
    },
    required: [
      "category",
      "status",
      "interfaceIds",
      "rationale",
      "citations",
      "threatIndexes",
      "missingEvidence",
      "deploymentConditions",
      "remediation",
    ],
  },
};
REPOSITORY_SCHEMA.required.push("categoryReviews");
const equalIds = (a, b) =>
  a.length === b.length &&
  new Set(a).size === a.length &&
  b.every((id) => a.includes(id));
export function validateRepositoryReview(value, packet) {
  try {
    return validateRepositoryResponse(value, packet);
  } catch (error) {
    if (/schema or evidence validation/.test(error.message)) throw error;
    throw Error(
      "Model response failed schema or evidence validation: " + error.message,
    );
  }
}
function validateRepositoryResponse(value, packet) {
  const { categoryReviews, ...rest } = value || {};
  if (rest.connections?.length || rest.explorationRequests?.length)
    throw Error(
      "Repository assessment must retain static connections and record missing evidence",
    );
  const review = validateStrideInvestigation(
    { connections: [], explorationRequests: [], ...rest },
    packet,
  );
  if (
    !Array.isArray(categoryReviews) ||
    categoryReviews.length !== 6 ||
    !equalIds(
      categoryReviews.map((r) => r.category),
      REPOSITORY_CATEGORIES,
    )
  )
    throw Error(
      "Repository review must explicitly assess all six STRIDE categories",
    );
  const primary = packet.reviewUnit.primaryInterfaceIds,
    records = new Map(packet.sourceContext.records.map((r) => [r.id, r]));
  const interfaces = new Map(packet.records.map((r) => [r.id, r]));
  const text = (v) =>
    typeof v === "string" && v.trim().length > 0 && v.length <= 4000;
  const allowed = new Set(
    REPOSITORY_SCHEMA.properties.categoryReviews.items.required,
  );
  const categories = categoryReviews.map((c) => {
    if (
      Object.keys(c).some((k) => !allowed.has(k)) ||
      !Array.isArray(c.interfaceIds) ||
      !equalIds(c.interfaceIds, primary) ||
      !text(c.rationale) ||
      ![
        "supported-conditional",
        "ruled-out",
        "no-scenario-identified",
        "evidence-gap",
      ].includes(c.status)
    )
      throw Error("Invalid repository category assessment");
    for (const field of ["missingEvidence", "deploymentConditions"])
      if (
        !Array.isArray(c[field]) ||
        c[field].length > 20 ||
        c[field].some((v) => !text(v))
      )
        throw Error("Invalid repository assessment evidence gaps");
    if (
      typeof c.remediation !== "string" ||
      c.remediation.length > 4000 ||
      !Array.isArray(c.citations) ||
      c.citations.length > 40
    )
      throw Error("Invalid repository assessment citations");
    const suppliedCitations = c.citations;
    const resolvedCitations = suppliedCitations.flatMap((ref) => {
      if (
        Object.keys(ref).some((k) => !citation.required.includes(k)) ||
        !citation.properties.role.enum.includes(ref.role)
      )
        throw Error("Repository assessment cites unavailable source");
      const resolved = resolveSourceCitation(ref, records);
      if (!resolved)
        throw Error("Repository assessment cites unavailable source");
      return resolved;
    });
    c = { ...c, citations: resolvedCitations };
    const expected = review.threats
      .map((t, i) => (t.category === c.category ? i : null))
      .filter((i) => i !== null);
    if (
      !Array.isArray(c.threatIndexes) ||
      c.threatIndexes.some((i) => !Number.isInteger(i) || i < 0)
    )
      throw Error("Invalid repository scenario index");
    // Category membership follows validated scenarios, not model-supplied indexes.
    // Preserve useful source-referenced scenarios when their claimed conclusion
    // lacks proof; downgrade the conclusion rather than discarding the packet.
    const missing = [...c.missingEvidence],
      normalizationNotes =
        resolvedCitations.length !== suppliedCitations.length
          ? [
              "Citation range split across supplied windows of the same file and hash; no missing source inferred.",
            ]
          : [];
    if (!equalIds(c.threatIndexes, expected))
      normalizationNotes.push(
        "Scenario indexes reconciled with validated STRIDE categories.",
      );
    if (c.status === "no-scenario-identified" && expected.length)
      missing.push(
        "The no-scenario conclusion conflicts with returned scenarios; resolve their evidence before concluding this category.",
      );
    if (c.status === "supported-conditional") {
      if (!expected.length)
        missing.push(
          "No returned scenario supports the claimed conditional conclusion.",
        );
      if (!text(c.remediation))
        missing.push("A specific remediation is not supplied.");
      for (const role of ["input", "operation"])
        if (!c.citations.some((r) => r.role === role))
          missing.push(
            "Missing cited " +
              role +
              " evidence for the conditional conclusion.",
          );
    }
    if (
      c.status === "ruled-out" &&
      !c.citations.some((r) => ["control", "counterevidence"].includes(r.role))
    )
      missing.push(
        "Missing cited control or counterevidence for the ruled-out conclusion.",
      );
    for (const id of primary) {
      const owns = interfaces.get(id)?.evidence || [];
      if (
        !c.citations.some((ref) => {
          const r = records.get(ref.recordId);
          return owns.some((e) => citationCoversEvidence(ref, r, e));
        })
      )
        missing.push(
          "Primary interface " +
            id +
            " has no cited review of its source location.",
        );
    }
    const sourceGaps = (packet.sourceContext.gaps || []).filter(
      (g) =>
        !(packet.sourceContext.retrievalPolicy==='section-candidates-1'&&g.required===false)&&
        ![
          "source-graph-catalog-limited",
          "source-graph-context-byte-limit",
        ].includes(g.reason),
    );
    if (sourceGaps.length)
      missing.push(
        "Source retrieval is incomplete: " +
          [...new Set(sourceGaps.map((g) => g.reason))].join(", "),
      );
    if(c.status==="evidence-gap"&&!missing.length&&packet.sourceContext.retrievalPolicy==="section-candidates-1")throw Error("Model response failed schema or evidence validation: "+c.category+" declares an evidence gap but identifies no missing code, binding or citation. Give the cited disposition or name the exact missing implementation; do not invent a gap or promote a conclusion merely to pass validation.");
    if (c.status === "evidence-gap" && !missing.length)
      missing.push(
        "The assessment did not specify the missing implementation or binding; clarification is required.",
      );
    return {
      ...c,
      proposedStatus: c.status,
      modelMissingEvidence: c.missingEvidence.map(redact),
      threatIndexes: expected,
      normalizationNotes,
      rationale: redact(c.rationale),
      remediation: redact(c.remediation),
      deploymentConditions: c.deploymentConditions.map(redact),
      missingEvidence: [...new Set(missing.map(redact))],
      status: missing.length ? "evidence-gap" : c.status,
    };
  });
  return { ...review, categoryReviews: categories };
}

// Category closure must not rewrite settled hypotheses and invalidate their paid
// engineering decisions. New, distinct scenarios are still validated and added.
export function repositoryThreatWire(threat) {
 const fields=['title','category','actor','startingAccess','asset','scenario','prerequisites','controls','mitigation','interfaceIds','evidenceIds'];
 const value=Object.fromEntries(fields.map(k=>[k,threat[k]]));
 if(threat.analysis)value.analysis={...threat.analysis,mappings:threat.analysis.mappings.map(({framework,id,rationale})=>({framework,id,rationale}))};
 return value;
}
export const CATEGORY_FOLLOWUP_PROMPT=REPOSITORY_PROMPT+`\nCATEGORY CLOSURE OVERRIDE: sourceContext.priorReview.retainedThreats contains immutable prior candidate scenarios. They are hypotheses, not evidence. Their supplied engineering conclusions are also hypotheses to check against fresh source. Do not repeat, rename or rewrite retained scenarios in the threats array. Return ONLY genuinely additional scenarios in threats, or [] if none. The application retains the prior scenarios unchanged and appends the new ones. categoryReviews.threatIndexes refers to that combined list (retained scenarios first, new scenarios second). Reassess all six categories for every primary operation using the fresh cited code and counterevidence. The previousUnresolvedItems list contains prior hypotheses, not confirmed code gaps: independently decide whether each is resolved by cited source, a deployment condition, or an exact missing implementation. A known absent application control is established behavior, not missing source. For supported-conditional include citations with BOTH input and operation roles, and cite the handler location of EVERY primary interface in every category. A shared conclusion must still cite each operation. Keep a specific evidence-gap when implementation is missing. Unread supporting search candidates do not automatically block this section; inspect their relevance and name any specific unresolved applicable binding. Required source omissions remain incomplete. Effective deployment conditions remain separate. Preserve each operation's source citations even where a category has no additional scenario. Engineering conclusions identify their retainedIndex and may narrow an exaggerated original hypothesis. Evaluate that current assessed claim against fresh source; accepting its narrower impact is not a new contradiction and does not require proving excluded impacts from the original title. If fresh code contradicts the current engineering conclusion, describe the exact reassessment requirement in missingEvidence; do not silently hide it in a no-scenario result. An external authentication proxy, effective log retention, actual network exposure and intended data classification are deployment conditions, not unread source. Missing implementation of an invoked control remains a code gap. Examples of the distinction, not findings to copy: if the cited entry and application composition establish no authentication on that path, an unknown upstream proxy is a deployment condition. If the cited mutation and logging path omit actor identity, unknown centralized log retention is a deployment condition; an unread invoked logging wrapper is a code gap. If the cited operation grows persistent state without an application quota, effective network rate and deployed capacity are conditions; an unread storage quota check is a code gap. If a cited response returns known fields, their deployment-specific sensitivity is a condition; an unread response serializer is a code gap. No-scenario-identified means none identified after inspecting the supplied in-scope path, not proof against every hypothetical environment. A demonstrated unauthorized persistent write is a Tampering consequence in its own right; do not require command execution, SSRF, or other downstream consumers to conclude that narrower path. Once supplied request types, full handlers, invoked storage methods and application composition establish the path, do not request unspecified additional validation or controls elsewhere merely because they could hypothetically exist. Identify an actual unread call, registration or override that could change the conclusion; otherwise assess the shown behavior under explicit deployment conditions. Do not invent a threat to fill a category.`;
export function validateCategoryFollowUp(value,packet) {
 const retained=packet.sourceContext?.priorReview?.retainedThreats;
 if(!Array.isArray(retained)||!Array.isArray(value?.threats))throw Error('Model response failed schema or evidence validation: category follow-up requires retained and new scenario lists');
 return validateRepositoryReview({...value,threats:[...retained,...value.threats]},packet);
}
