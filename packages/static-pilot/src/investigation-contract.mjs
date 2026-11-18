import {
  CWE_RESPONSE_SCHEMA,
  SECURITY_RESPONSE_SCHEMA,
} from "./security-schemas.mjs";
import { validateCweModel, CWE_MODEL_PROMPT } from "./cwe-model.mjs";
import {
  validateSecurityAssessment,
  SECURITY_REVIEW_PROMPT,
} from "./security-intelligence.mjs";
import { redact } from "./model-review.mjs";
export const INVESTIGATION_VERSION = "static-frontier-1";
const extra = `\nYou are part of a persistent STATIC investigation. When local evidence is missing, return explorationRequests to inspect graph neighbors or search indexed names across the selected repositories. No shell, network, application execution or file writes are available. The graph is incomplete: adjacency and name matches are hypotheses, never proof of runtime reachability. Use {action:"neighbors"|"search",recordId:"submitted source record ID",nodeId:"submitted graph node ID, or empty for search",symbol:"literal identifier/config key to search, or empty for neighbors",reason:"specific missing evidence"}. Return at most 8 explorationRequests; [] is valid for evidence that cannot be obtained statically. Search only for relevant named callers, callees, authorization controls, configuration bindings or downstream assets. Cite current submitted code only. Distinguish external evidence needs from locally searchable gaps. Never mark missing evidence as safety. Prior rounds and their missing evidence are supplied for continuity.`;
export const DISCOVERY_PROMPT = CWE_MODEL_PROMPT + extra;
export const ASSESSMENT_PROMPT = SECURITY_REVIEW_PROMPT + extra;
const requestsSchema = {
  type: "array",
  items: {
    type: "object",
    properties: {
      action: { type: "string", enum: ["neighbors", "search"] },
      recordId: { type: "string" },
      nodeId: { type: "string" },
      symbol: { type: "string" },
      reason: { type: "string" },
    },
    required: ["action", "recordId", "nodeId", "symbol", "reason"],
    additionalProperties: false,
  },
};
export function investigationSchema(assessment = false) {
  const schema = structuredClone(
    assessment ? SECURITY_RESPONSE_SCHEMA : CWE_RESPONSE_SCHEMA,
  );
  schema.properties.explorationRequests = requestsSchema;
  schema.required.push("explorationRequests");
  return schema;
}
export function validateInvestigation(value, packet, assessment = false) {
  const { explorationRequests = [], ...review } = value || {};
  if (!Array.isArray(explorationRequests) || explorationRequests.length > 8)
    throw Error("Static investigation response has invalid evidence requests");
  const records = new Set(packet.records.map((r) => r.id)),
    nodes = new Set((packet.graphNodes || []).map((n) => n.id));
  const requests = explorationRequests.map((r) => {
    if (
      !r ||
      Object.keys(r).some(
        (k) =>
          !["action", "recordId", "nodeId", "symbol", "reason"].includes(k),
      ) ||
      !records.has(r.recordId) ||
      typeof r.reason !== "string" ||
      !r.reason.trim() ||
      r.reason.length > 1600 ||
      typeof r.nodeId !== "string" ||
      typeof r.symbol !== "string"
    )
      throw Error(
        "Static investigation response has invalid evidence requests",
      );
    if (r.action === "neighbors") {
      if (!nodes.has(r.nodeId) || r.symbol !== "")
        throw Error("Static investigation requested an unknown graph node");
    } else if (r.action === "search") {
      if (r.nodeId !== "" || !/^[A-Za-z_$][\w.$:/-]{0,119}$/.test(r.symbol))
        throw Error("Static investigation requested an invalid indexed search");
    } else throw Error("Static investigation requested an unsupported action");
    return { ...r, reason: redact(r.reason) };
  });
  return {
    ...(assessment
      ? validateSecurityAssessment(review, packet)
      : validateCweModel(review, packet)),
    explorationRequests: requests,
  };
}
