import { redact } from './model-review.mjs';

const text={type:'string'};
const object=properties=>({type:'object',additionalProperties:false,properties,required:Object.keys(properties)});
const list=items=>({type:'array',items});
// New condition enums are checked locally to keep the provider grammar small.
const conditionKinds=['network-access','identity','authority','configuration','deployment-control','intended-policy'];
const kinds=['entry','sensitive-operation','path-binding','applicable-controls'];
export const ENGINEERING_SCHEMA=object({
  conclusion:text,
  obligations:list(object({kind:{type:'string',enum:kinds},status:{type:'string',enum:['established','blocks-attack','missing']},reason:text,
    citations:list(object({recordId:text,startLine:{type:'integer'},endLine:{type:'integer'}}))})),
  conditions:list(object({id:text,kind:text,statement:text,scope:text,requiredAnswer:text,binding:text})),
  consistency:object({status:text,reason:text}),
  reviewerQuestions:list(text),
});
export const ENGINEERING_PROMPT=`
Act as the engineering reviewer of the stated attack path. Finish the CODE decision when the evidence permits it, rather than collecting general background. Return engineering with a concise conclusion, four obligations (exactly entry, sensitive-operation, path-binding, applicable-controls) and reviewerQuestions. Each obligation has status established, blocks-attack or missing, a reason, and at most eight exact source citations. Keep each reason and conclusion within 1600 characters. Established means the relevant fact is established, not that the application is secure. The status missing means MISSING EVIDENCE, never merely an absent or ineffective security control. For example: if supplied handler, router registration, global composition and applicable helper code demonstrate that this path has no authentication check, mark applicable-controls established with those citations and explain the absence; do not mark it missing because the application ought to have authentication. If router registration or an invoked authorization helper has not been supplied, mark it missing and name that exact implementation. Likewise, a cited audit path with no attribution is a supported fact; an unread logging implementation is missing evidence. A name-search miss alone never proves absence. Path-binding must connect this entry to this operation. Applicable-controls must consider route dependencies, registration/global middleware and the controls on that path, including opposing evidence. A candidate graph edge or similarly named symbol alone does not establish a binding. Once the complete relevant handler, helper and registration/composition functions are supplied, do not require every unrelated handler in the same file. Request additional code only for a concrete unresolved call, registration, override or mutation that could change this path; identify that binding explicitly. Do not infer the absence of an override merely from a search miss.
First resolve the four obligations using the submitted code. If a required implementation or binding is missing, use missing, name that exact code in missingEvidence, and request it via followUp. Do not mark a control obligation established solely because a search found nothing. If a cited control invalidates the stated attack, mark it blocks-attack and return ruled-out with cited counterevidence. If all four obligations are established and the attack follows under explicit conditions, return static-supported, even when production exposure has not been checked. A deliberate insecure configuration is still a supported CONDITIONAL path when the stated role/access assumptions apply. State those assumptions; do not call it a universal bypass.
Use structured conditions for every unverified prerequisite: id, kind (network-access, identity, authority, configuration, deployment-control, intended-policy), statement (a single affirmative yes/no proposition), scope (the named entry/operation), requiredAnswer (yes or no), binding (deployment-only, entry, sensitive-operation, path-binding, or applicable-controls). A configuration condition refers to a setting consumed by the reviewed code and must use a code-dependent binding, never deployment-only. Use deployment-control with binding deployment-only for an unverified compensating control outside the reviewed application, such as an authenticating reverse proxy or external identity-correlated audit logging. Such a condition is an explicit deployment assumption, never code evidence or approval. An unread control invoked by the application remains a missing code obligation; it cannot be reclassified as deployment-control. A code-dependent binding names the obligation whose citations demonstrate that exact condition on the path. A code-dependent condition such as a setting affecting a handler requires citations showing that exact binding; do not ask whether an unrelated authentication switch is enabled. Conditions about effective reachability or intended roles are deployment-only, never proof of missing code. At most eight conditions. reviewerQuestions is an array of condition IDs only; the application asks whether each linked affirmative statement is true. Do NOT generate free-form ifYes/ifNo advice. All required conditions apply together; a negative prerequisite does not clear other actors or paths. Before retaining ANY condition, apply a counterfactual relevance check: holding the cited code path unchanged, would reversing that condition change this exact attack? If no, REMOVE that condition. In particular, an enable-auth flag in a helper that this route never invokes is NOT a prerequisite, regardless of its default value. Do not ask about it or condition the finding on it. Return consistency {status: consistent or unresolved, reason}: briefly explain the relevance of each retained condition and check that the conclusion, code obligations, conditions, impact and remediation agree. If they contradict or an intended isolation policy is necessary but absent, narrow the claim or mark consistency unresolved. Never assert all routes are exposed from evidence about one route.
Keep effective environment values, reachable networks and intended operator roles in engineering.conditions. Ask at most four reviewerQuestions, each a distinct condition ID whose affirmative statement can be answered yes or no. The application derives the limited consequence of each answer. A guide warning, how commonly a setting is used, other endpoints and speculative downstream effects are not prerequisites for deciding the cited operation. Never put these broader questions in missingEvidence. A missing application-level control implementation IS a code gap; an unobserved upstream deployment restriction IS a deployment condition. Never reclassify missing code as a condition just to finish.
The conclusion describes ONE CURRENT path only. Do not append a different hypothetical threat after proposed code changes (such as "even if authentication were injected"). Do not label a data read IDOR/BOLA or cross-user access without an explicit per-user isolation policy; sensitive data alone does not establish ownership semantics. If the demonstrated concern is unauthenticated data disclosure, use that narrower conclusion and ask separately whether the deployment intends to restrict that data.
The conclusion must say who can do what, on which entry/operation, under which conditions, and the resulting directly supported impact. Narrow or reject exaggerated impacts in the original scenario. A configuration write does not by itself establish redirection of all traffic or credential theft. Do not copy a speculative original title into the conclusion. In reviewerQuestions, an answer resolves only the specific condition asked; never say a single answer confirms exploitation or the entire attack. Upstream authentication is not proof of administrator authorization. Describe how the combination of conditions changes applicability. No production reachability or exploitation is verified. This applies across all STRIDE categories, not only authorization.
WIRE CONTRACT OVERRIDE for saved STRIDE: do NOT return the generic missingEvidence field shown in the base security example. The supplied schema deliberately excludes it. Every missing CODE fact belongs in engineering.obligations: mark the affected obligation missing and explain the exact missing implementation/binding in its reason. Deployment facts belong in engineering.conditions and reviewerQuestions. Do not return deploymentAssumptions; the application derives that saved field from conditions. This replaces the generic missingEvidence checklist throughout the instructions below. assessment is the decision about the cited code path under those conditions. Do not require ALL valid inputs/provider names to establish one valid write path. If you need one accepted input to establish feasibility, retrieve that exact validation rather than expanding the claim.
`;

export function validateEngineeringArgument(value,packet,assessment) {
  const fail=m=>{throw Error('Security assessment failed schema or evidence validation (engineering: '+m+')');};
  const string=v=>{if(typeof v!=='string'||!v.trim()||v.length>1600)fail('bounded nonempty text required');return redact(v);};
  if(!value || !Array.isArray(value.obligations) || value.obligations.length!==4 || new Set(value.obligations.map(o=>o.kind)).size!==4)fail('exactly four distinct code obligations required');
  const obligations=value.obligations.map(o=>{
    if(!kinds.includes(o.kind)||!['established','blocks-attack','missing'].includes(o.status)||!Array.isArray(o.citations))fail('invalid code obligation kind, status or citations');
    if(o.citations.length>8)fail('at most eight citations per code obligation');
    if(o.status!=='missing'&&!o.citations.length)fail('a settled code obligation requires source citations');
    const citations=o.citations.map(c=>{
      const r=packet.records.find(r=>r.id===c.recordId);
      if(!r || !Number.isInteger(c.startLine)||!Number.isInteger(c.endLine)||c.startLine<r.startLine||c.endLine>r.endLine||c.startLine>c.endLine)fail('citation outside submitted source window');
      return {recordId:r.id,repository:r.repository,path:r.path,blobSha256:r.blobSha256,startLine:c.startLine,endLine:c.endLine,
        redacted:(r.lines||[]).some(l=>l.line>=c.startLine&&l.line<=c.endLine&&/\[(?:sensitive assignment|private key) omitted\]/.test(l.text))};
    });
    return {kind:o.kind,status:o.status,reason:string(o.reason),citations};
  });
  if(assessment==='static-supported' && obligations.some(o=>o.status==='blocks-attack'))fail('a blocking control contradicts a supported attack');
  if(assessment==='ruled-out'&&!obligations.some(o=>o.status==='blocks-attack'))fail('ruled-out requires a cited blocking fact');
  if(!Array.isArray(value.reviewerQuestions)||value.reviewerQuestions.length>4)fail('at most four reviewer questions');
  const conclusion=string(value.conclusion);
  // Saved records are projected without revalidation. New provider responses
  // must use the current contract, including in providers' prompt-only mode.
  if(!Array.isArray(value.conditions)||value.conditions.length>8)fail('at most eight structured conditions');
  const ids=new Set();
  const conditions=value.conditions.map(c=>{
    if(!c || typeof c!=='object' || Array.isArray(c))fail('invalid condition');
    // Wire references reuse an obligation's already validated citations instead
    // of compiling another nested citation grammar. Saved form stays explicit.
    if(c.binding!==undefined) {
      const obligation=obligations.find(o=>o.kind===c.binding);
      if(c.binding!=='deployment-only' && (!obligation || obligation.status==='missing'))fail('condition binding must name an established code obligation');
      c={...c,basis:c.binding==='deployment-only'?'deployment-only':'code-dependent',citations:obligation?.citations || []};
    }
    if(typeof c.id!=='string'||!/^[a-zA-Z0-9_-]{1,40}$/.test(c.id)||ids.has(c.id))fail('unique bounded condition IDs required');
    ids.add(c.id);
    if(!conditionKinds.includes(c.kind)||!['yes','no'].includes(c.requiredAnswer)||!['deployment-only','code-dependent'].includes(c.basis)||!Array.isArray(c.citations)||c.citations.length>8)fail('invalid condition contract');
    if(c.kind==='configuration'&&c.basis!=='code-dependent')fail('configuration condition requires a cited code binding');
    if(c.kind==='deployment-control'&&c.basis!=='deployment-only')fail('deployment-control is an unverified external condition, not a code-bound control');
    if(c.basis==='code-dependent'&&!c.citations.length)fail('code-dependent condition requires binding citations');
    const citations=c.citations.map(ref=>{
      const record=packet.records.find(r=>r.id===ref.recordId);
      if(!record||!Number.isInteger(ref.startLine)||!Number.isInteger(ref.endLine)||ref.startLine<record.startLine||ref.endLine>record.endLine||ref.startLine>ref.endLine)fail('condition citation outside submitted source window');
      return {recordId:record.id,repository:record.repository,path:record.path,blobSha256:record.blobSha256,startLine:ref.startLine,endLine:ref.endLine,
        redacted:(record.lines||[]).some(l=>l.line>=ref.startLine&&l.line<=ref.endLine&&/\[(?:sensitive assignment|private key) omitted\]/.test(l.text))};
    });
    return {id:c.id,kind:c.kind,statement:string(c.statement),scope:string(c.scope),requiredAnswer:c.requiredAnswer,basis:c.basis,citations};
  });
  if(!['consistent','unresolved'].includes(value.consistency?.status))fail('explicit consistency review required');
  const consistency={status:value.consistency.status,reason:string(value.consistency.reason)};
  if(conditions.some(c=>c.citations.some(r=>r.redacted))) {consistency.status='unresolved';consistency.reason='A required condition binding contains redacted source.';}
  const asked=new Set();
  const reviewerQuestions=value.reviewerQuestions.map(q=>{
    if(typeof q==='string')q={conditionId:q,question:conditions.find(c=>c.id===q)?.statement};
    if(!q || typeof q!=='object')fail('invalid reviewer question');
    if(!ids.has(q.conditionId)||asked.has(q.conditionId))fail('question must reference one distinct condition');
    asked.add(q.conditionId);
    return {conditionId:q.conditionId,question:string(q.question)};
  });
  return {version:2,conclusion,obligations,conditions,consistency,reviewerQuestions};
}
