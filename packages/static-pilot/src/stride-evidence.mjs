import {controlContext} from './control-context.mjs';
import { InvestigationSource } from "./investigation-source.mjs";
import { localSource, sha } from "./sources.mjs";
import {
  REVIEW_LIMITS,
  SYSTEM_PROMPT,
  validateReview,
} from "./model-review.mjs";
import { STRIDE_RESPONSE_SCHEMA } from "./security-schemas.mjs";
import {
  validateExplorationRequests,
  requestsSchema,
} from "./investigation-contract.mjs";

export const STRIDE_EVIDENCE_VERSION = "static-stride-evidence-1";
export const STRIDE_INVESTIGATION_PROMPT =
  SYSTEM_PROMPT +
  `\nFor this static investigation, also return explorationRequests (an array, at most 8). This is an additional allowed top-level field. Use sourceContext.records as hash-checked source evidence, sourceContext.graphNodes as retrieval candidates, and sourceContext.gaps as unresolved facts. Source windows are partial. Additional source does not automatically prove interface ownership, effective controls or deployed reachability. When named caller, callee, sanitization, configuration or authorization evidence is missing, request {action:"search",recordId:"a sourceContext record ID",nodeId:"",symbol:"literal identifier",reason:"missing evidence"}, or {action:"neighbors",recordId:"a sourceContext record ID",nodeId:"a sourceContext graph node ID",symbol:"",reason:"missing evidence"}. Use [] for unavailable deployment facts. Reconsider prior conclusions when follow-up evidence supplies a control or counterevidence. Never infer absence from a missing window. SourceContext IDs are retrieval references; existing threat evidence ownership rules still apply.`;
export const STRIDE_INVESTIGATION_SCHEMA = structuredClone(
  STRIDE_RESPONSE_SCHEMA,
);
STRIDE_INVESTIGATION_SCHEMA.properties.explorationRequests = requestsSchema;
STRIDE_INVESTIGATION_SCHEMA.required.push("explorationRequests");
export function validateStrideInvestigation(value, packet) {
  const { explorationRequests = [], ...review } = value || {};
  return {
    ...validateReview(review, packet),
    explorationRequests: validateExplorationRequests(explorationRequests, {
      records: packet.sourceContext.records,
      graphNodes: packet.sourceContext.graphNodes,
    }),
  };
}
export async function verifiedStrideSource(model, manifest, root, progress) {
  for (const repo of manifest.repositories.filter(
    (r) => r.selected !== false,
  )) {
    if (repo.source === "github")
      throw Error("Source-backed STRIDE requires local clones");
    progress?.(`Verifying unchanged source: ${repo.name}`);
    const current = await localSource(repo, root, { onFile: async () => {} });
    if (
      current.snapshot !==
      model.sources.find((s) => s.name === repo.name)?.snapshot
    )
      throw Error(
        `Source changed for ${repo.name}; rebuild the graph before continuing`,
      );
  }
  return new InvestigationSource(model, manifest, root);
}
export const evidenceMetadata = ({ code, lines, ...ref }) => ref;

// Context is prepared only for an active worker. No source text is checkpointed.
export async function prepareStrideEvidence(original, source, options = {}) {
  const packet = structuredClone(original);
  const records = [],
    gaps = [...(options.gaps || [])],
    seen = new Set();
  for (const r of packet.records) {
    delete r.sourceGraph;
    for (const e of r.evidence) delete e.excerpt;
  }
  packet.sourceContext = {
    version: STRIDE_EVIDENCE_VERSION,
    records,
    graphNodes: [],
    gaps,
    priorReview: options.priorReview || null,
    graphDetails:
      "Retrieved on demand from the saved graph; per-interface neighborhoods omitted",
  };
  const primaryEvidence=new Set(packet.records.filter(r=>(packet.reviewUnit?.primaryInterfaceIds || []).includes(r.id)).flatMap(r=>r.evidence).map(r=>`${r.repository}\0${r.path}\0${r.line}`));
  if(options.sectionEvidence)packet.sourceContext.retrievalPolicy='section-candidates-1';
  const seedText=[],primaryWindows=[];
  if (original.reviewFocus?.selectedProfile) for (const ref of packet.records.flatMap(r=>r.evidence).slice(0,8)) {
    try {const window=await source.functionWindow(ref);seedText.push(window.code);if(primaryEvidence.has(`${ref.repository}\0${ref.path}\0${ref.line}`))primaryWindows.push(window);} catch { /* Regular retrieval records the evidence gap below. */ }
  }
  const controlLookup = original.reviewFocus?.selectedProfile ? await controlContext(source, packet.records.flatMap(r=>r.evidence), seedText.join('\n')) : null;
  if (controlLookup) packet.sourceContext.controlLookup = {searches:controlLookup.searches,omitted:controlLookup.omitted,basis:controlLookup.basis};
  const called=options.sectionEvidence&&source.calledImplementations?source.calledImplementations(primaryWindows):null;
  if(called)packet.sourceContext.calledImplementations={...called,references:undefined};
  const packetRefs=packet.records.flatMap(r=>r.evidence);
  const headers=options.sectionEvidence?[...new Map(primaryWindows.map(r=>[r.repository+'\0'+r.path,{repository:r.repository,path:r.path,line:1,required:false,basis:'Primary module declarations; applicability requires assessment'}])).values()].slice(0,2):[];
  const refs = options.sectionEvidence?[
    ...packetRefs.filter(r=>primaryEvidence.has(`${r.repository}\0${r.path}\0${r.line}`)),
    ...(options.references || []).filter(r=>r.required===true),
    ...(controlLookup?.references || []).filter(r=>r.basis==='application-registration-candidate'),
    ...headers,...(called?.references || []),
    ...(options.references || []).filter(r=>r.required!==true),...packetRefs,...(controlLookup?.references || []),
  ]:[...(options.references || []),...packetRefs,...(controlLookup?.references || []),...(called?.references || [])];
  const requiredRefs=new Set(refs.filter(r=>r.required===true||primaryEvidence.has(`${r.repository}\0${r.path}\0${r.line || r.startLine || 1}`)).map(r=>`${r.repository}\0${r.path}\0${r.line || r.startLine || 1}`));
  for (const ref of refs) {
    const key = `${ref.repository}\0${ref.path}\0${ref.line || ref.startLine || 1}`;
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      const line = ref.line || (ref.startLine ? ref.startLine + 20 : 1);
      const covering=records.find(w=>w.repository===ref.repository&&w.path===ref.path&&w.startLine<=line&&w.endLine>=line&&(!ref.blobSha256||ref.blobSha256===w.blobSha256));
      if(covering){if(options.sectionEvidence&&requiredRefs.has(key))covering.required=true;continue;}
      if (records.length >= (options.sectionEvidence?24:16)) throw Error("source-context-window-limit");
      const w = await (original.reviewFocus?.selectedProfile ? source.functionWindow.bind(source) : source.window.bind(source))({
        ...ref,
        line,
      });
      if (records.some((r) => r.id === w.id)) continue;
      // code already contains numbered lines. Sending the identical text again
      // as structured lines wastes context and can evict applicable controls.
      const {lines, ...transmitted} = w;
      if(options.sectionEvidence)transmitted.required=requiredRefs.has(key);
      records.push(transmitted);
      if (
        Buffer.byteLength(JSON.stringify(packet)) >
        REVIEW_LIMITS.packetBytes - 8000
      ) {
        records.pop();
        throw Error("source-context-byte-limit");
      }
      if(w.functionContext?.complete===false)gaps.push({repository:ref.repository,path:ref.path,line,reason:w.functionContext.reason,...(options.sectionEvidence?{required:requiredRefs.has(key)}:{})});
    } catch (error) {
      gaps.push({
        repository: ref.repository,
        path: ref.path,
        line: ref.line,
        ...(options.sectionEvidence?{required:requiredRefs.has(key),basis:'Unread retrieval candidate; only applicable missing bindings prevent a section conclusion.'}:{}),
        reason: /^source-/.test(error.message)
          ? error.message
          : "source-unavailable",
      });
    }
  }
  const catalog = source.catalog(records);
  packet.sourceContext.graphNodes = catalog.nodes;
  if (catalog.omitted) gaps.push({ reason: "source-graph-catalog-limited" });
  // Ownership is unchanged; windows are transmitted once and referenced by ID.
  for (const r of packet.records)
    for (const e of r.evidence) {
      const w = records.find(
        (w) =>
          w.repository === e.repository &&
          w.path === e.path &&
          w.startLine <= e.line &&
          w.endLine >= e.line,
      );
      if (w)
        e.excerpt = {
          firstLine: w.startLine,
          sourceRecordId: w.id,
          partial: true,
        };
    }
  packet.sourceContext.interfaceEvidence = packet.records.map((r) => ({
    interfaceId: r.id,
    evidenceIds: r.evidence.map((e) => e.id),
  }));
  packet.sourceContext.allowedControlEvidenceIds = [
    ...new Set(
      packet.records
        .filter((r) => r.kind === "control")
        .flatMap((r) => r.evidence.map((e) => e.id)),
    ),
  ];
  packet.sourceContext.allowedBoundaryIds = (
    packet.systemContext?.boundaries || []
  ).map((b) => b.id);
  let omittedNodes = 0;
  while (
    packet.sourceContext.graphNodes.length &&
    Buffer.byteLength(JSON.stringify(packet)) > REVIEW_LIMITS.packetBytes - 512
  ) {
    packet.sourceContext.graphNodes.pop();
    omittedNodes++;
  }
  if (omittedNodes)
    gaps.push({ reason: "source-graph-context-byte-limit", omittedNodes });
  while (
    records.length &&
    Buffer.byteLength(JSON.stringify(packet)) > REVIEW_LIMITS.packetBytes - 512
  ) {
    const omitted = records.pop();
    for (const r of packet.records)
      for (const e of r.evidence)
        if (e.excerpt?.sourceRecordId === omitted.id) delete e.excerpt;
    gaps.push({
      reason: "source-context-byte-limit",
      repository: omitted.repository,
      path: omitted.path,
      line: omitted.startLine,
      ...(options.sectionEvidence?{required:omitted.required!==false}:{}),
    });
  }
  if (Buffer.byteLength(JSON.stringify(packet)) > REVIEW_LIMITS.packetBytes)
    throw Error("source-packet-byte-budget");
  return {
    packet,
    context: {
      version: STRIDE_EVIDENCE_VERSION,
      controlLookup: packet.sourceContext.controlLookup || null,
      records: records.map(evidenceMetadata),
      gaps,
      fingerprint: sha(JSON.stringify([records.map((r) => r.id), gaps])),
      packetHash: sha(JSON.stringify(packet)),
    },
  };
}
