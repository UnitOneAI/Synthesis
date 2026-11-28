import {sha} from './sources.mjs';
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
export const CATEGORY_FOLLOWUP_PROMPT=REPOSITORY_PROMPT.replace("Treat missing controls as unknown.", "Treat unread control implementations as unknown. A control demonstrated to be absent from the complete relevant code path is an assessed code behavior, not missing source; evaluate its consequence under explicit deployment conditions.")+`\nCATEGORY CLOSURE OVERRIDE: sourceContext.priorReview.retainedThreats contains indexed references to immutable prior candidate scenarios; the full records are retained by the application. They are hypotheses, not evidence. Their supplied engineering conclusions are also hypotheses to check against fresh source. Do not repeat, rename or rewrite retained scenarios in the threats array. Return ONLY additional category-specific scenarios in threats, or [] if none. The application retains the prior scenarios unchanged and appends the new ones. categoryReviews.threatIndexes refers to that combined list (retained scenarios first, new scenarios second). Reassess all six categories for every primary operation using the fresh cited code and counterevidence. The previousUnresolvedItems list contains prior hypotheses, not confirmed code gaps: independently decide whether each is resolved by cited source, a deployment condition, or an exact missing implementation. A known absent application control is established behavior, not missing source. For supported-conditional include citations with BOTH input and operation roles, and cite the handler location of EVERY primary interface in every category. A shared conclusion must still cite each operation. Keep a specific evidence-gap when implementation is missing. Unread supporting search candidates do not automatically block this section; inspect their relevance and name any specific unresolved applicable binding. Required source omissions remain incomplete. Effective deployment conditions remain separate. Preserve each operation's source citations even where a category has no additional scenario. Engineering conclusions identify their retainedIndex and may narrow an exaggerated original hypothesis. Evaluate that current assessed claim against fresh source; accepting its narrower impact is not a new contradiction and does not require proving excluded impacts from the original title. If fresh code contradicts the current engineering conclusion, describe the exact reassessment requirement in missingEvidence; do not silently hide it in a no-scenario result. An external authentication proxy, effective log retention, actual network exposure and intended data classification are deployment conditions, not unread source. Missing implementation of an invoked control remains a code gap. Examples of the distinction, not findings to copy: if the cited entry and application composition establish no authentication on that path, an unknown upstream proxy is a deployment condition. If the cited mutation and logging path omit actor identity, unknown centralized log retention is a deployment condition; an unread invoked logging wrapper is a code gap. If the cited operation grows persistent state without an application quota, effective network rate and deployed capacity are conditions; an unread storage quota check is a code gap. If a cited response returns known fields, their deployment-specific sensitivity is a condition; an unread response serializer is a code gap. No-scenario-identified means none identified after inspecting the supplied in-scope path, not proof against every hypothetical environment. A demonstrated unauthorized persistent write is a Tampering consequence in its own right; do not require command execution, SSRF, or other downstream consumers to conclude that narrower path. Once supplied request types, full handlers, invoked storage methods and application composition establish the path, do not request unspecified additional validation or controls elsewhere merely because they could hypothetically exist. Identify an actual unread call, registration or override that could change the conclusion; otherwise assess the shown behavior under explicit deployment conditions. Do not invent a threat to fill a category.
TARGETED CLOSURE: When priorReview.targetCategories is present, return categoryReviews for those categories only. Previously completed categories are independently retained by the application, not reassessed from this smaller evidence window. You may additionally return another category ONLY if fresh counterevidence requires reopening it; include the exact evidence. Each scenario has exactly ONE STRIDE category in this contract. A different supported STRIDE consequence of the same entry or root cause needs its own category-specific scenario, even if it shares the entry with a retained case. For example, do not leave a category incomplete merely because another category already describes the same entry. These are scenarios, not deduplicated vulnerabilities. If no retained case has this category and your decision is supported-conditional, add the corresponding scenario to threats for independent engineering assessment. Return new threats in the targeted/reopened categories; up to four NEW scenarios are allowed even when four older cases already exist. The combined retained list can contain up to twenty cases. The initial discovery limit is not a prohibition on completing other categories. A safeguard shown to be absent on a fully cited path is an assessed control deficiency, not unread source. Evaluate its conditional consequence and, if supported, return the new scenario. Validation of a future fix belongs in remediation, not missingEvidence. Do not classify unknown deployed logging infrastructure or external cleanup as missing implementation of the current code path. Conversely, do not treat an unread invoked control or dynamic binding as absent. Give its exact symbol and call site when it prevents a conclusion.`;
export function validateCategoryFollowUp(value,packet,retainedOriginals,categoryState) {
 const prior=packet.sourceContext?.priorReview;
 const retained=prior?.retainedDigest?retainedOriginals:prior?.retainedThreats;
 if(prior?.retainedDigest&&(!Array.isArray(retained)||sha(JSON.stringify(retained))!==prior.retainedDigest))throw Error('Model response failed schema or evidence validation: retained scenario integrity mismatch');
 if(!Array.isArray(retained)||!Array.isArray(value?.threats))throw Error('Model response failed schema or evidence validation: category follow-up requires retained and new scenario lists');
 const targets=prior?.targetCategories;
 if(!targets)return validateRepositoryReview({...value,threats:[...retained,...value.threats]},packet);
 if(!categoryState||sha(JSON.stringify(categoryState))!==prior.categoryStateDigest)throw Error('Model response failed schema or evidence validation: category checkpoint integrity mismatch');
 const returned=value.categoryReviews || [], names=returned.map(c=>c.category);
 if(new Set(names).size!==names.length||targets.some(c=>!names.includes(c))||names.some(c=>!REPOSITORY_CATEGORIES.includes(c)))throw Error('Model response failed schema or evidence validation: every targeted category must be assessed');
 if(value.threats.some(t=>!names.includes(t.category)))throw Error('Model response failed schema or evidence validation: an additional scenario must reopen its category explicitly');
 const fresh=new Map(packet.sourceContext.records.map(r=>[r.id,r]));
 for(const c of returned)for(const ref of c.citations || [])if(!resolveSourceCitation(ref,fresh))throw Error('Model response failed schema or evidence validation: new category decisions require fresh supplied source citations');
 const fields=REPOSITORY_SCHEMA.properties.categoryReviews.items.required;
 const cached=categoryState.categories.filter(c=>!names.includes(c.category));
 if(cached.some(c=>!['supported-conditional','ruled-out','no-scenario-identified'].includes(c.status)||c.missingEvidence.length))throw Error('Model response failed schema or evidence validation: unresolved categories cannot be reused as completed');
 const categories=REPOSITORY_CATEGORIES.map(category=>returned.find(c=>c.category===category)||Object.fromEntries(fields.map(k=>[k,cached.find(c=>c.category===category)?.[k]])));
 const combined={...value,threats:[...retained,...value.threats],categoryReviews:categories};
 const records=[...new Map([...categoryState.records,...packet.sourceContext.records].map(r=>[r.id,r])).values()];
 const virtual={...packet,sourceContext:{...packet.sourceContext,records}};
 const reviewed=validateRepositoryReview(combined,virtual);
 // A retrieval limit in this targeted follow-up cannot erase an already cited
 // category whose saved source hashes were rechecked before dispatch.
 const priorValidated=validateRepositoryReview(combined,{...virtual,sourceContext:{...virtual.sourceContext,gaps:[]}});
 reviewed.categoryReviews=reviewed.categoryReviews.map(c=>names.includes(c.category)?c:{...priorValidated.categoryReviews.find(p=>p.category===c.category),reused:true});
 return reviewed;
}
