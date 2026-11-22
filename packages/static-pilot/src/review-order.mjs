import { sourceScope } from "./architecture.mjs";

export const REVIEW_STAGES = Object.freeze([
  { id: 0, label: "Declared external interfaces", description: "Operator-declared external parties and their crossings; deployment still requires confirmation." },
  { id: 1, label: "Potential external entry points", description: "Production network entry points and integrations. Unknown exposure is prioritized, not assumed internet-facing." },
  { id: 2, label: "Entry-point context and internal paths", description: "Related controls, candidate call paths and cross-service interactions from entry-point components." },
  { id: 3, label: "Internal actors and boundaries", description: "Remaining internal authority, workers, stores and trust transitions." },
  { id: 4, label: "Supporting and test code", description: "Test, generated and vendor-only evidence; deployment applicability remains a question." },
]);

// Scheduling evidence, not a declaration of deployed exposure or actor approval.
export function interfacePriorities(model, system) {
  const evidence = new Map((model.evidence || []).map((e) => [e.id, e]));
  const projected = new Map((system?.entities || []).map((r) => [r.id, r]));
  const decisions = new Map((model.architecture?.decisions || []).map((d) => [d.subjectId, d.state]));
  const external = new Set((model.architecture?.records?.entities || [])
    .filter((r) => r.type === "external" && !["rejected", "stale"].includes(projected.get(r.id)?.reviewState || decisions.get(r.id) || r.reviewState))
    .map((r) => r.id));
  const declared = new Set();
  for (const flow of system?.flows || model.architecture?.records?.flows || []) {
    if (["rejected", "stale"].includes(flow.reviewState) || ["rejected", "stale"].includes(decisions.get(flow.id))) continue;
    if (external.has(flow.source) || external.has(flow.target))
      for (const id of flow.interfaceIds || []) declared.add(id);
  }
  const entries = new Set(), result = new Map();
  for (const i of model.interfaces || []) {
    const refs = (i.evidence || []).map((id) => evidence.get(id)).filter(Boolean);
    const supporting = refs.length > 0 && refs.every((r) => sourceScope(r.path) !== "production-candidate");
    const declaredExternal = declared.has(i.id);
    const networkEntry = ["http-inbound", "http-outbound", "rpc", "device", "message-consume"].includes(i.kind);
    const stage = supporting ? 4 : declaredExternal ? 0 : networkEntry ? 1 : 3;
    result.set(i.id, { stage, component: i.component });
    if (stage < 2 && i.component) entries.add(i.component);
  }
  for (const value of result.values())
    if (value.stage === 3 && entries.has(value.component)) value.stage = 2;
  return result;
}

export function batchStage(batch, priorities) {
  const stages = batch.packet.records.map((r) => priorities.get(r.id)?.stage ?? 3);
  let stage = stages.length ? Math.min(...stages) : 3;
  if (stage < 2 && ["graph-neighborhood", "candidate-call-path", "callable-context", "cross-repository"].includes(batch.phase)) stage = 2;
  return stage;
}

export function reviewStageCoverage(plan, batches) {
  const status = new Map(batches.map((b) => [b.id, b.status]));
  return REVIEW_STAGES.map((stage) => {
    const members = plan.filter((b) => b.reviewStage === stage.id);
    const completed = members.filter((b) => status.get(b.id) === "completed").length;
    const failed = members.filter((b) => status.get(b.id) === "failed").length;
    return { ...stage, total: members.length, completed, failed, pending: members.length - completed - failed };
  });
}
