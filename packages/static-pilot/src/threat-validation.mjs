import {reviewSectionThreats} from './section-batch-review.mjs';
import { guidanceForRepositories } from './deployment-guidance.mjs';
import { ENGINEERING_SCHEMA, ENGINEERING_PROMPT, validateEngineeringArgument } from './threat-engineering.mjs';
import {sourceScope} from './architecture.mjs';
import {controlSymbols, controlContext} from './control-context.mjs';
import { SECURITY_RESPONSE_SCHEMA } from './security-schemas.mjs';
import { SECURITY_REVIEW_PROMPT, validateSecurityAssessment } from './security-intelligence.mjs';
import { sha } from './sources.mjs';
import { redact } from './model-review.mjs';
import { InvestigationSource } from './investigation-source.mjs';
import { reviewSecurityIssues, INVESTIGATION_LIMITS } from './security-review.mjs';
import { systemModel } from './system-model.mjs';
import { threatIssue, threatValidationKey } from './threat-validation-state.mjs';
export const THREAT_RETRIEVAL_VERSION = 'control-context-30';

// CWE's generic missingEvidence bucket mixes deployment questions with code
// blockers. STRIDE uses the four typed code obligations instead. The wire
// contract has no second, contradictory completeness checklist.
const {missingEvidence: _genericMissingEvidence, ...threatProperties}=SECURITY_RESPONSE_SCHEMA.properties;
// Group the wire object to bound native structured-output grammar size. The
// application still validates the same canonical fields and exact source ranges.
const wireObject=properties=>({type:'object',additionalProperties:false,properties,required:Object.keys(properties)});
const pick=keys=>Object.fromEntries(keys.map(k=>[k,threatProperties[k]]));
export const THREAT_ASSESSMENT_SCHEMA = wireObject({
  assessment:threatProperties.assessment,
  caseDetails:wireObject(pick(['actorKind','actor','initialAccess','input','impact','severityChangeConditions'])),
  evidenceReview:wireObject(pick(['trace','controls','counterEvidence','followUp'])),
  remediation:threatProperties.remediation,
  engineering:ENGINEERING_SCHEMA,
});
export const THREAT_ASSESSMENT_PROMPT = SECURITY_REVIEW_PROMPT + ENGINEERING_PROMPT + `
Challenge the original claim before extending it. A name/path search miss is not evidence of an absent control. In standard ASP.NET Core, an unresolved named authorization policy throws; do not assert fail-open or fallback-policy bypass without evidence of a custom path and its behavior. Resolve controller/base attributes, global filters, policy registration, requirement handlers and middleware ordering from supplied code. Distinguish custom behavior and framework version from assumptions. Do not invent a tenant isolation requirement: identify the actual role/object ownership rule and its enforcement. Echoing a caller's own headers does not establish theft of another user's credentials; cite the additional trust crossing or rule out that claimed path. For SSRF establish destination provenance, caller control and filtering before asserting access to a chosen internal service. Evaluate intended current behavior, not a hypothetical future code change. A hardening guide is a declared baseline, not proof of effective deployment; infrastructure controls do not automatically repair a product control flaw. A directly cited unauthorized persistent write is itself a sensitive operation; downstream uses are needed only for additional claimed impacts. Do not require an inventory of other affected endpoints or proof that operators commonly choose a configuration to assess the stated conditional path. Keep those broader questions in remediation.validation. Reviewer questions must identify a specific deployment or intended-access decision and how each answer changes this path. Missing code and bindings are retrieval work for this investigation, not generic questions for the reviewer.
For saved STRIDE assessment use engineering.conditions for the unverified deployment prerequisites. Do not return a duplicate deploymentAssumptions array. assessment describes the CODE argument under those explicit conditions, not deployed exploitability. Record missing CODE, callers, binding, control implementations or declared configuration in the affected engineering.obligations entry with status missing and a precise reason. Missing runtime network exposure, actual environment-variable values, effective runtime identity and selected deployed profile belong in engineering.conditions. A missing authorization filter, caller, ownership check or source-to-sink link must remain a missing engineering obligation; never move a code gap into engineering.conditions to obtain a favorable status. Conditional source-supported code concerns still require input and sink citations and consideration of opposing controls. Use needs-context if the code argument itself remains incomplete. No deployment assumption is verified or approved by this assessment. Assess the stated path, not the complete application blast radius. A complete list of other endpoints, unrelated startup warnings or every deployment template is not required to establish a cited conditional path; put broader follow-up work in remediation.validation. For static-supported, trace must contain both an input and sink step with exact recordId, startLine, endLine and reason; these cite the entry and sensitive operation. Use the control and transform steps for the rest of the path. Keep trace to at most 16 steps. Never invent a missing endpoint. The application derives input/sink evidence from those steps; do not repeat them in extra fields.
WIRE ENVELOPE: Return exactly five top-level fields: assessment, caseDetails, evidenceReview, remediation, engineering. caseDetails contains actorKind, actor, initialAccess, input, impact, severityChangeConditions. evidenceReview contains trace, controls, counterEvidence, followUp. The supplied schema is authoritative over the generic flat example. Do not return deploymentAssumptions or missingEvidence: conditions and code obligations are the respective sources of truth.`;
export function validateThreatAssessment(value, packet) {
  if(value?.caseDetails!==undefined || value?.evidenceReview!==undefined) {
    if(!value.caseDetails || !value.evidenceReview || typeof value.caseDetails!=='object' || typeof value.evidenceReview!=='object' || Array.isArray(value.caseDetails) || Array.isArray(value.evidenceReview))throw Error('Security assessment failed schema or evidence validation (complete grouped threat response required)');
    const trace=value.evidenceReview.trace;
    value={...value.caseDetails,...value.evidenceReview,assessment:value.assessment,remediation:value.remediation,engineering:value.engineering,
      inputEvidence:Array.isArray(trace)?trace.find(r=>r.role==='input') || null:null,
      sinkEvidence:Array.isArray(trace)?trace.find(r=>r.role==='sink') || null:null};
  }
  const {deploymentAssumptions=[],inputEvidence,sinkEvidence,engineering,missingEvidence,...rest}=value || {};
  const trace=Array.isArray(rest.trace)?[...rest.trace]:[];
  for(const [ref,role] of [[inputEvidence,'input'],[sinkEvidence,'sink']]) {
    if(ref===null)continue;
    if(!ref || typeof ref!=='object' || Array.isArray(ref))throw Error('Security assessment failed schema or evidence validation (inputEvidence and sinkEvidence must be a citation or null)');
    if(!trace.some(r=>r.role===role && r.recordId===ref.recordId && r.startLine===ref.startLine && r.endLine===ref.endLine))trace.push({...ref,role});
  }
  rest.trace=trace;
  if(!Array.isArray(deploymentAssumptions) || deploymentAssumptions.length>8 || deploymentAssumptions.some(x=>typeof x!=='string'||!x.trim()||x.length>1600)) throw Error('Security assessment failed schema or evidence validation (deploymentAssumptions must contain at most eight bounded statements)');
  const argument=validateEngineeringArgument(engineering,packet,rest.assessment);
  // Old prompt-mode responses remain fail-closed: never discard a legacy gap.
  // New responses express every required code gap on a specific obligation.
  rest.missingEvidence=missingEvidence ?? argument.obligations.filter(o=>o.status==='missing').map(o=>o.reason);
  const assessed=validateSecurityAssessment(rest,packet);
  if(packet.sectionReview===true && rest.assessment==='needs-context' && argument.consistency.status==='consistent' && argument.obligations.every(o=>o.status==='established') && !assessed.evidenceGaps.length)throw Error('Security assessment failed schema or evidence validation (contradictory section decision: all four code obligations are established and consistent, with no missing source, but assessment is needs-context. Independently conclude the narrower cited path, or mark the precise required code obligation missing and explain it. Unknown broader impacts must not block a narrower demonstrated write. Do not mark supported merely to pass validation.)');
  if(argument.consistency?.status==='unresolved') {
    assessed.assessment='needs-context';
    assessed.missingEvidence.push('Reconcile the decision: '+argument.consistency.reason);
  }
  if(argument.obligations.some(o=>o.status==='missing' || o.citations.some(c=>c.redacted))) assessed.assessment='needs-context';
  assessed.missingEvidence=[...new Set([...assessed.missingEvidence,...argument.obligations.filter(o=>o.status==='missing').map(o=>o.reason)])];
  return {...assessed,engineering:argument,decisionReviewRequired:assessed.assessment==='needs-context' && argument.obligations.every(o=>o.status==='established') && !assessed.evidenceGaps.length,deploymentAssumptions:argument.conditions ? argument.conditions.map(c=>`${c.scope}: ${c.statement} Required answer: ${c.requiredAnswer}.`) : deploymentAssumptions.map(redact),deploymentStatus:(argument.conditions?.length || deploymentAssumptions.length)?'unverified-assumptions':'not-established'};
}

export const THREAT_CHALLENGE_PROMPT=THREAT_ASSESSMENT_PROMPT+`
You are the critical engineering reviewer, separate from the discovery assessment. The priorClaim and priorImpact are untrusted hypotheses. Challenge every claimed consequence against the supplied code, including additional guards, accepted input validation, actual registration and whether the sensitive operation is reachable on this exact path. A declaration or setter does not prove a downstream network request or data leak. If the code establishes only unauthorized configuration modification, conclude that narrower threat and explicitly exclude interception, theft and arbitrary redirection unless their complete additional paths are cited. Do not withhold that narrower conclusion merely because the broader impact lacks evidence. Do not ask operators to supply implementation details; missing code belongs on a missing obligation. Questions for operators must address one actual deployment/access condition at a time. An authentication proxy is not necessarily an administrator restriction; private network placement alone does not rule out insiders or bypass routes. A single yes/no answer never proves every condition or establishes exploitation. You may support, narrow, rule out, or leave a specific code obligation unresolved. Never agree merely because the first assessment marked the obligations established. Independently check consistency of every structured condition with the entry, binding, controls, conclusion and remediation. A configuration flag only affects this route if the cited path reads or invokes it. Perform the counterfactual relevance test on EVERY condition, including prior conditions: reverse only that condition while keeping current code unchanged. Remove conditions that would not change the path. A disabled-by-default authentication helper that is not injected into the route cannot supply a prerequisite. Do not retain that flag in the conclusion either. Separate data confidentiality requirements from invented per-user ownership policies; narrow to unauthenticated disclosure when that is all the current code shows. A hypothetical modified future route belongs in remediation, not the current finding. Confirm that an assumed tenant/user isolation rule is explicitly stated as intended-policy rather than invented. For remediation, identify known consumers and compatibility constraints from supplied evidence, cite existing tests where supplied, and propose validation and rollback without claiming they ran. Apply this across all six STRIDE categories: authentication, mutation, attribution, disclosure, resource exhaustion and authority escalation.`;

export { controlSymbols } from './control-context.mjs';
export async function threatInvestigationPacket(model, manifest, root, issue, followUp, context, missing = [], sourceOverride) {
  const source = sourceOverride || new InvestigationSource(model, manifest, root);
  if(model.aiReview?.scope?.poc?.kind==='section') {
    const evidence=new Map(model.evidence.map(e=>[e.id,e]));
    const owned=model.interfaces.filter(i=>(issue.interfaceIds || []).includes(i.id)).flatMap(i=>i.evidence.map(id=>evidence.get(id))).filter(Boolean).map(e=>({repository:e.repository,path:e.path,line:e.line,blobSha256:e.blobSha256}));
    issue={...issue,locations:[...new Map([...issue.locations,...owned].map(r=>[r.repository+'\0'+r.path+'\0'+r.line,r])).values()]};
  }

  const requestedContext=[...missing,...followUp.filter(r=>r.required!==false).map(r=>r.reason || '')].join(' ');
  const requiredSymbols = new Set(controlSymbols(requestedContext));
  const symbols = [...new Set([...requiredSymbols,...controlSymbols([issue.controls, issue.explanation].join(' '))])];
  const definition = n => ['function','class','method','type'].includes(n.kind);
  const refs = [], searches = [], gaps = [];
  for (const symbol of symbols) {
    const local=source.localDefinitions?.(symbol,issue.locations);
    const matches = [...(local?.matches || [])]; let after = '';
    for (let page = 0; page < 2; page++) {
      const result = source.search(symbol, after);
      matches.push(...result.items.filter(n => n.kind === 'file' || n.name === symbol || n.name?.endsWith('.' + symbol) || n.name?.endsWith('::' + symbol)));
      after = result.next;
      if (!after) break;
    }
    const sameFile = n => issue.locations.some(r=>r.repository===n.repository && r.path===n.path);
    const sameRepository = n => issue.locations.some(r=>r.repository===n.repository);
    let found = [...new Map(matches.map(n=>[n.id,n])).values()].sort((a,b) => Number(definition(b))-Number(definition(a)) || Number(sameFile(b))-Number(sameFile(a)) ||
      Number(sourceScope(a.path)!=='production-candidate')-Number(sourceScope(b.path)!=='production-candidate') ||
      Number(sameRepository(b))-Number(sameRepository(a)) || Number(a.kind === 'file')-Number(b.kind === 'file')).slice(0,4);
    if(found.some(definition))found=found.filter(definition);
    const declarationMatches=symbol==='APIRouter'?found.filter(n=>n.kind==='call'&&sameFile(n)).length:0;
    searches.push({ symbol, matches: found.length, definitionMatches:found.filter(definition).length, declarationMatches, truncated: Boolean(after)||Boolean(local?.limited), nodeIds: found.map(n => n.id) });
    searches.at(-1).requested = requiredSymbols.has(symbol);
    const localDefinitions=found.filter(n=>sameFile(n)&&definition(n));
    for (const n of found.slice(0,requiredSymbols.has(symbol)?4:2)) if (!refs.some(r => r.repository === n.repository && r.path === n.path && r.line === (n.line || 1)))
      refs.push({ repository: n.repository, path: n.path, line: n.line || 1, nodeId:n.id, kind:n.kind, definition:definition(n), required:requiredSymbols.has(symbol)&&(!localDefinitions.length||localDefinitions.includes(n))&&(model.aiReview?.scope?.poc?.kind!=='section'||sameFile(n)||followUp.some(r=>r.repository===n.repository&&r.path===n.path)) });
  }
  // A focused claim does not need a repository-wide control catalog. Keep exact
  // seeds and requested controls first, then only nearby candidate call edges.
  const members=[...new Set(requestedContext.match(/\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){1,2}\b/g) || [])].slice(0,6);
  const unresolvedSymbols=[...members,...searches.filter(s=>s.requested&&!s.definitionMatches&&!s.declarationMatches).map(s=>s.symbol)];
  const fallback = source.findImplementation && unresolvedSymbols.length
    ? await source.findImplementation(unresolvedSymbols,issue.locations) : null;
  const authContext = await controlContext(source, issue.locations, [requestedContext,issue.controls,issue.explanation].join(' '));
  const bootstrapRefs=authContext.references.filter(r=>r.basis==='application-registration-candidate');
  // Text hits are unbound candidates. Explicit requested locations stay required;
  // unrelated hits must not become mandatory dependencies merely by matching a
  // framework/constant name. Omitted candidates remain visible in retrieval.
  const references = [...refs.filter(r=>r.required).map(r=>({...r,basis:r.definition?'requested-definition':'requested-symbol'})), ...(fallback?.references || []).filter(r=>issue.locations.some(s=>s.repository===r.repository&&s.path===r.path)).map(r=>({...r,required:Boolean(r.symbol?.includes('.')),basis:r.symbol?.includes('.')?'requested-member-use candidate':'requested-local-declaration candidate'})), ...followUp.map(r => ({...r, required:r.required!==false, basis:r.required===false?'prior-search-candidate':'requested-control'})), ...issue.locations.map(r => ({...r, required:true, basis:'saved-scenario'})), ...(fallback?.references || []).map(r=>({...r,required:false,basis:'requested-text-candidate'})), ...authContext.references.filter(r=>!bootstrapRefs.includes(r)), ...refs.filter(r=>!r.required).map(r => ({...r, basis:'named-control-candidate'}))];
  const resourceNames = [...new Set(issue.locations.map(r => r.path.split('/').at(-1).replace(/\.[^.]+$/, '').toLowerCase()).filter(n => n.length>4 && !['server','controller','program','security','settings_routes'].includes(n)))];
  const routeCandidates = /route|caller|endpoint|service layer/i.test(requestedContext) ? model.interfaces.filter(i => i.direction==='inbound' && resourceNames.some(n => String(i.connection?.path || i.operation || '').toLowerCase().includes(n))).slice(0,6) : [];
  const evidence=new Map(model.evidence.map(e=>[e.id,e]));
  for(const route of routeCandidates) for(const id of route.evidence || []) {
    const ref=evidence.get(id);if(ref)references.splice(issue.locations.length+followUp.length,0,{...ref,basis:'resource-route-candidate'});
  }
  let neighborhoodLimited = false;
  for (const seed of issue.locations.slice(0,4)) {
    const nodes = source.nodes({kind:'function',repository:seed.repository,path:seed.path,limit:129});
    neighborhoodLimited ||= nodes.length > 128;
    const nearby = nodes.filter(n => n.kind !== 'file' && (n.line || 1) <= (seed.line || 1) && (n.endLine || n.line || 1) >= (seed.line || 1)).slice(0,4);
    for (const node of nearby) {
      const edges=source.edges(node.id);neighborhoodLimited ||= Boolean(edges.next);
      for(const edge of edges.items.filter(e => !/contains|owns|member/.test(e.kind)).slice(0,8)) {
        const peer=source.node(edge.from === node.id ? edge.to : edge.from);
        if(peer?.path) references.push({...peer,basis:'candidate-call-neighbor'});
      }
    }
  }
  // Supply declarations before repeating the same middle-of-file window. Explicit
  // follow-up paths must still resolve to selected, hash-matched graph files.
  if(/initializ|declar|environment|config|startup/i.test(requestedContext)) {
    const seen=new Set();
    for(const r of [...followUp,...refs,...issue.locations]) {
      const k=r.repository+'\0'+r.path;
      if(!seen.has(k) && seen.size<2){seen.add(k);references.push({...r,line:1,required:model.aiReview?.scope?.poc?.kind!=='section',basis:'initialization candidate; applicability requires assessment'});}
    }
  }
  // Explicit code requests (including declaration windows) must precede
  // generic framework candidates and call neighbors under the byte limit.
  references.sort((a,b)=>Number(Boolean(b.required))-Number(Boolean(a.required)));
  // Declaration defaults in the same files complete the conditions without a
  // second model request; these remain candidate context, never proof of binding.
  const declarations=[...new Map(references.filter(r=>r.required).map(r=>[r.repository+'\0'+r.path,{...r,line:1,required:false,basis:'source-declarations'}])).values()].slice(0,3);
  references.splice(references.filter(r=>r.required).length,0,...bootstrapRefs,...declarations);
  if(model.aiReview?.scope?.poc?.kind==='section') {
    // Keep the primary operation and application composition visible while
    // following new controls; broad identifier matches must not evict them.
    const primaryWindows=[];
    if(source.calledImplementations)for(const ref of issue.locations.slice(0,4))try{primaryWindows.push(await source.functionWindow(ref));}catch{/* Required retrieval below records the source failure. */}
    const called=source.calledImplementations?.(primaryWindows);
    const first=[...issue.locations.map(r=>({...r,required:true,basis:'saved-scenario'})),...bootstrapRefs.slice(0,3),...refs.filter(r=>r.required),...followUp.filter(r=>r.required!==false).slice(0,8).map(r=>({...r,required:true,basis:'requested-control'}))];
    const keys=new Set(first.map(r=>r.repository+'\0'+r.path+'\0'+(r.line || 1)));
    const rest=references.filter(r=>!keys.has(r.repository+'\0'+r.path+'\0'+(r.line || 1)));
    references.splice(0,references.length,...first,...rest.filter(r=>r.required),...(called?.references || []),...rest.filter(r=>!r.required));
  }
  const sourceByteLimit=model.aiReview?.scope?.poc?.kind==='section'?Math.max(16000,Math.min(66000,INVESTIGATION_LIMITS.packetBytes-24000-Buffer.byteLength(JSON.stringify({candidate:issue,context})))):42000;
  let records=[]; const continuationReferences=[]; const availableFiles=new Map();let omitted=0,coalescedWindows=0;
  for(const ref of references) {
    const key=ref.repository+'\0'+ref.path;
    if(source.file(ref.repository,ref.path)) availableFiles.set(key,{repository:ref.repository,path:ref.path});
    if(records.some(r => r.repository===ref.repository && r.path===ref.path && r.startLine===Math.max(1,(ref.line || 1)-20)))continue;
    try {
      const {code,...record}=await source.functionWindow(ref);
      record.basis=ref.basis;
      const overlap=records.filter(r=>r.repository===record.repository && r.path===record.path && r.blobSha256===record.blobSha256 && r.startLine<=record.endLine+1 && r.endLine>=record.startLine-1);
      const mergedLines=[...new Map([...overlap.flatMap(r=>r.lines),...record.lines].map(l=>[l.line,l])).values()].sort((a,b)=>a.line-b.line);
      const merge=overlap.length && mergedLines.length<=200 && mergedLines.at(-1).line-mergedLines[0].line+1===mergedLines.length;
      const merged=merge ? {...record,id:sha(JSON.stringify([record.repository,record.path,record.blobSha256,mergedLines[0].line,mergedLines.at(-1).line])).slice(0,20),startLine:mergedLines[0].line,endLine:mergedLines.at(-1).line,lines:mergedLines,basis:'combined hash-matched source windows'} : record;
      const next=[...records.filter(r=>!merge || !overlap.includes(r)),merged];
      const reason=next.length>(model.aiReview?.scope?.poc?.kind==='section'?24:12) ? 'required-source-window-limit' : Buffer.byteLength(JSON.stringify(next))>sourceByteLimit ? 'required-source-byte-limit' : null;
      if(reason){omitted++;if(ref.required)gaps.push({reason,repository:ref.repository,path:ref.path,startLine:record.startLine,endLine:record.endLine});continue;}
      records=next;if(merge)coalescedWindows+=overlap.length;
      if(ref.required&&!continuationReferences.some(r=>r.repository===ref.repository&&r.path===ref.path&&r.line===(ref.line || 1)))continuationReferences.push({repository:ref.repository,path:ref.path,line:ref.line || 1,blobSha256:record.blobSha256,...(ref.kind?{kind:ref.kind}:{}),...(ref.nodeId?{nodeId:ref.nodeId}:{}),reason:'Previously requested source, re-read and hash checked; prior conclusions are not evidence.'});
      if(ref.required && record.functionContext?.complete===false)gaps.push({reason:record.functionContext.reason,repository:ref.repository,path:ref.path,line:ref.line,detail:'Only a partial function window was supplied; do not infer full control coverage.'});
    }catch(error){if(ref.required)gaps.push({reason:error.message,repository:ref.repository,path:ref.path});else omitted++;}
  }
  for(let i=gaps.length-1;i>=0;i--) if(gaps[i].startLine && records.some(r=>r.repository===gaps[i].repository && r.path===gaps[i].path && r.startLine<=gaps[i].startLine && r.endLine>=gaps[i].endLine)) gaps.splice(i,1);
  const packet={sectionReview:model.aiReview?.scope?.poc?.kind==='section',purpose:'Independent static assessment of one saved STRIDE scenario',candidate:issue,context,records,continuationReferences:continuationReferences.slice(0,16),availableFiles:[...availableFiles.values()].slice(0,64),gaps,
    citationPolicy:'Graph name-search misses and truncated candidate neighborhoods do not prove a missing control; record any required unresolved code path in a missing engineering obligation. Each citation must fit entirely inside ONE record startLine/endLine range. Split citations across windows even for the same file. Named matches and graph edges are candidates, not proof of enforcement. Assess this exact actor, operation and conditions. Missing context does not establish absent controls. Name missing functions in the affected engineering obligation reason for bounded follow-up retrieval.',
    retrieval:{sourceByteLimit,coalescedWindows,indexedSourceSearch:fallback ? {...fallback,references:undefined} : null,frameworkControlSearches:authContext.searches, frameworkCandidatesOmitted:authContext.omitted,routeCandidates:routeCandidates.map(i=>i.id),controlSearches:searches,includedWindows:records.length,gapCount:gaps.length,candidateWindowsOmitted:omitted,neighborhoodLimited,fullCallGraph:false}};
  if (Buffer.byteLength(JSON.stringify(packet)) > INVESTIGATION_LIMITS.packetBytes) throw Error('Security packet metadata exceeds size limit');
  return packet;
}
export async function reviewThreatScenarios(manifest, model, options = {}) {
  if (!model.aiReview?.coverage?.completedBatches || model.aiReview.status === 'stale' || (model.aiReview.basedOnRevision && model.aiReview.basedOnRevision !== model.modelRevision)) throw Error('Current completed STRIDE scenarios are required; open the matching saved review first');
  const system = systemModel(model, { matrix: false });
  const priority = new Map(system.threats.map(t => [t.id, t.reviewPriority?.rank ?? 9]));
  const selected = options.threatIds;
  if (selected && (!Array.isArray(selected) || !selected.length || selected.some(id => !model.aiReview.threats.some(t => t.id === id)))) throw Error('Select saved STRIDE threat IDs');
  const issues = model.aiReview.threats.filter(t => !selected || selected.includes(t.id)).map(t => threatIssue(model, t)).sort((a,b) => priority.get(a.id) - priority.get(b.id));
  const hashes = new Map(issues.map(i=>[i.id,sha(JSON.stringify(i))]));
  // Explicit one-case upgrade: presentation never spends tokens or resets work.
  // Keep the complete old report before challenging the selected legacy decision.
  if(options.recheckConditions===true) {
    if(selected?.length!==1)throw Error('Select exactly one threat for a condition recheck');
    const entry=model.threatValidation?.entries?.find(e=>e.sourceId===selected[0]);
    if(entry && ['static-supported','ruled-out'].includes(entry.assessment) && entry.issueHash===hashes.get(entry.sourceId) && model.threatValidation.contextKey===threatValidationKey(model)) {
      model.threatValidationHistory=[...(model.threatValidationHistory || []),structuredClone(model.threatValidation)].slice(-3);
      entry.draftAssessment=structuredClone(entry);entry.challengeStarted=true;entry.challengePending=true;
      entry.challengeCompleted=false;entry.assessment='not-assessed';entry.rounds=0;delete entry.continuationReferences;delete entry.stopReason;
    }
  }
  // Upgrade selected older positive assessments by challenging their existing
  // argument, not by repeating discovery. Their original response remains intact.
  if(model.threatValidation?.contextKey===threatValidationKey(model)) for(const entry of model.threatValidation.entries || []) {
    if(((entry.assessment==='static-supported'&&(!entry.challengeCompleted||(model.aiReview?.scope?.poc?.kind==='section'&&entry.draftAssessment?.assessment!=='static-supported')))||(entry.decisionReviewRequired&&!entry.challengeStarted)) && entry.issueHash===hashes.get(entry.sourceId)) {
      entry.draftAssessment=structuredClone(entry);entry.challengeStarted=true;entry.challengePending=true;
      if(entry.assessment==='static-supported'){entry.assessment='not-assessed';entry.followUp=[];entry.missingEvidence=[];delete entry.continuationReferences;}entry.rounds=0;
    }
  }
  // A changed retriever may resolve an exhausted code gap. Reopen it once for
  // this policy; retain prior attempts and never reset conclusive assessments.
  if (model.threatValidation && model.threatValidation.retrievalVersion !== THREAT_RETRIEVAL_VERSION) {
    for (const entry of model.threatValidation.entries || []) if ((entry.assessment === 'needs-context'||(entry.assessment==='failed'&&/^Security assessment failed|^Model did not return the required JSON/.test(entry.error || ''))) && entry.issueHash === hashes.get(entry.sourceId) && (entry.rounds >= INVESTIGATION_LIMITS.contextRounds || entry.stopReason === 'no-new-evidence')) {
      entry.history = [...(entry.history || []),{assessment:entry.assessment,packetHash:entry.packetHash,attemptId:entry.attemptId,usage:entry.usage,rounds:entry.rounds,continuationReferences:entry.continuationReferences,reason:'retrieval-policy-updated'}];
      entry.rounds=0;delete entry.continuationReferences;delete entry.stopReason;
    }
  }
  const priorEntries = new Map();
  for(const previous of [model.threatValidation,...(model.threatValidationHistory || []).slice().reverse()]) {
    for(const entry of previous?.entries || []) if(entry.issueHash===hashes.get(entry.sourceId) && !priorEntries.has(entry.sourceId) && (entry.followUp?.length || entry.missingEvidence?.length)) priorEntries.set(entry.sourceId,entry);
  }
  if(model.threatValidation && (model.threatValidation.contextKey !== threatValidationKey(model) || model.threatValidation.promptHash !== sha(THREAT_ASSESSMENT_PROMPT) || model.threatValidation.challengePromptHash !== sha(THREAT_CHALLENGE_PROMPT))) {
    model.threatValidationHistory=[...(model.threatValidationHistory || []),model.threatValidation].slice(-3);
  }
  const sharedSource = new InvestigationSource(model,manifest,options.sourceRoot);
  const reviewer=options.config?.batchThreats===true && model.aiReview?.scope?.poc?.kind==='section' ? reviewSectionThreats : reviewSecurityIssues;
  const report = await reviewer(manifest, model, {
    ...options, challengePrompt:THREAT_CHALLENGE_PROMPT, retainConclusiveOnPromptChange:true, checkpoint:async r=>{r.retrievalVersion=THREAT_RETRIEVAL_VERSION;await options.checkpoint?.(r);}, systemPrompt:THREAT_ASSESSMENT_PROMPT,responseSchema:THREAT_ASSESSMENT_SCHEMA,validateResponse:validateThreatAssessment, followMissingControls: true, retryInvalidAssessment: true, candidateIssues: issues, reportField: 'threatValidation', contextKeyOverride: threatValidationKey(model),
    packetBuilder: async (m, mf, root, issue, follow, context, missing, previous) => {
      const projected = system.threats.find(t => t.id === issue.id);
      const compact = r => ({ id: r.id, name: r.name, basis: r.basis, reviewState: r.reviewState, startingAccess: r.startingAccess, before: r.before, after: r.after, enforcement: r.enforcement, source: r.source, target: r.target, evidenceIds: r.evidenceIds?.slice(0,8) });
      const scoped = { ...context, declaredGuidance:guidanceForRepositories(model,issue.locations.map(l=>l.repository)), analysisProfile:model.aiReview?.scope?.poc ? {statement:model.aiReview.scope.poc.profile,basis:'Explicit analysis assumption, not a verified deployment fact. Assess the code argument under this condition.'} : null, actors: system.actors.filter(a => projected.actorIds.includes(a.id)).slice(0,8).map(compact), boundaries: system.boundaries.filter(b => projected.boundaryIds.includes(b.id)).slice(0,12).map(compact), flows: system.flows.filter(f => [...projected.flowIds, ...(projected.candidateFlowIds || [])].includes(f.id)).slice(0, 12).map(compact) };
      // Follow-up must extend the argument, not forget the control established
      // in the preceding round. Re-read cited anchors with their recorded hashes;
      // never treat a previous model conclusion as fresh source evidence.
      const prior=previous || priorEntries.get(issue.id);
      const anchors=[];
      // Carry established entry, operation, binding and control citations across
      // rounds. A new missing declaration must not erase an already-read helper.
      for(const obligation of prior?.engineering?.obligations || [])for(const ref of (obligation.citations || []).slice(0,1)) {
        if(!anchors.some(a=>a.repository===ref.repository&&a.path===ref.path&&a.line===ref.startLine))anchors.push({...ref,line:ref.startLine});
      }
      for(const role of ['control','input','sink']) for(const ref of (prior?.trace || []).filter(r=>r.role===role).slice(0,2)) {
        if(!anchors.some(a=>a.repository===ref.repository && a.path===ref.path && a.line===ref.line)) anchors.push({...ref,line:ref.line || ref.startLine});
      }
      for(const ref of anchors.slice()) {
        const initial=prior?.evidence?.find(r=>r.repository===ref.repository && r.path===ref.path && r.startLine===1);
        if(initial && !anchors.some(r=>r.repository===initial.repository && r.path===initial.path && r.line===1)) anchors.push({...initial,line:1,required:m.aiReview?.scope?.poc?.kind!=='section'});
      }
      for(const ref of [...(prior?.engineering?.obligations || []).flatMap(o=>o.citations),...(prior?.engineering?.conditions || []).flatMap(c=>c.citations)]) if(!anchors.some(a=>a.repository===ref.repository && a.path===ref.path && a.line===ref.startLine)) anchors.push({...ref,line:ref.startLine});
      const positive=prior?.challengeStarted&&prior.draftAssessment?.assessment==='static-supported'?prior.draftAssessment:null;
      const currentIssue=positive?{...issue,title:'Current source-supported claim under independent challenge',explanation:positive.engineering.conclusion,preconditions:positive.engineering.conditions.map(c=>c.statement),controls:positive.counterEvidence,analysis:positive.impact}:issue;
      const packet=await threatInvestigationPacket(m,mf,root,currentIssue,[...(follow?.length?follow:prior?.followUp || []),...anchors.slice(0,8),...(prior?.continuationReferences || []).map(r=>({...r,required:m.aiReview?.scope?.poc?.kind==='section'?false:true}))],scoped,missing?.length?missing:prior?.missingEvidence || [],sharedSource);
      if(positive)packet.challengeBasis='current-positive-1';
      if(prior?.decisionReviewRequired) packet.decisionReview={
        task:'Reconcile the previous code argument with its unresolved questions. It marked all four code obligations established but withheld the conclusion. Independently check the fresh code below. For each previous missing fact decide whether it changes this exact code path or is deployment context / broader follow-up. Return an honest supported conditional conclusion, a cited ruled-out path, or mark the exact code obligation missing. Do not change a status merely to satisfy this request. Narrow impact to the directly demonstrated operation; do not infer all downstream traffic, theft or exploitation from a configuration write. A reviewer answer establishes only that condition, not the full attack. Upstream authentication does not imply administrator authorization.',
        previousConclusion:prior.engineering.conclusion,
        questionsToResolve:prior.missingEvidence,
      };
      if(Buffer.byteLength(JSON.stringify(packet))>INVESTIGATION_LIMITS.packetBytes)throw Error('Security packet metadata exceeds size limit');
      return packet;
    },
  });
  return report;
}

export async function assessCompletedPoc(manifest, model, options) {
  if (!model.aiReview?.scope?.poc || model.aiReview.coverage?.pendingBatches || model.aiReview.coverage?.failedBatches || !model.aiReview.threats?.length) return null;
  return reviewThreatScenarios(manifest, model, {...options,budget:100,runUntilComplete:true});
}
