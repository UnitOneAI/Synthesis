import { redact } from './model-review.mjs';

const text={type:'string'};
const object=properties=>({type:'object',additionalProperties:false,properties,required:Object.keys(properties)});
const list=items=>({type:'array',items});
const kinds=['entry','sensitive-operation','path-binding','applicable-controls'];
export const ENGINEERING_SCHEMA=object({
  conclusion:text,
  obligations:list(object({kind:{type:'string',enum:kinds},status:{type:'string',enum:['established','blocks-attack','missing']},reason:text,
    citations:list(object({recordId:text,startLine:{type:'integer'},endLine:{type:'integer'}}))})),
  reviewerQuestions:list(object({question:text,ifYes:text,ifNo:text})),
});
export const ENGINEERING_PROMPT=`
Act as the engineering reviewer of the stated attack path. Finish the CODE decision when the evidence permits it, rather than collecting general background. Return engineering with a concise conclusion, four obligations (exactly entry, sensitive-operation, path-binding, applicable-controls) and reviewerQuestions. Each obligation has status established, blocks-attack or missing, a reason, and exact source citations. Established means the relevant fact is established, not that the application is secure. Path-binding must connect this entry to this operation. Applicable-controls must consider route dependencies, registration/global middleware and the controls on that path, including opposing evidence. A candidate graph edge or similarly named symbol alone does not establish a binding.
First resolve the four obligations using the submitted code. If a required implementation or binding is missing, use missing, name that exact code in missingEvidence, and request it via followUp. Do not mark a control obligation established solely because a search found nothing. If a cited control invalidates the stated attack, mark it blocks-attack and return ruled-out with cited counterevidence. If all four obligations are established and the attack follows under explicit conditions, return static-supported, even when production exposure has not been checked. A deliberate insecure configuration is still a supported CONDITIONAL path when the stated role/access assumptions apply. State those assumptions; do not call it a universal bypass.
Keep effective environment values, reachable networks and intended operator roles in deploymentAssumptions. Ask at most four reviewerQuestions, each an answerable yes/no deployment or intended-access question with ifYes and ifNo explaining how that answer changes this threat. A guide warning, how commonly a setting is used, other endpoints and speculative downstream effects are not prerequisites for deciding the cited operation. Never put these broader questions in missingEvidence. A missing application-level control implementation IS a code gap; an unobserved upstream deployment restriction IS a deployment condition. Never reclassify missing code as a condition just to finish.
The conclusion must say who can do what, on which entry/operation, under which conditions, and the resulting directly supported impact. Narrow or reject exaggerated impacts in the original scenario. A configuration write does not by itself establish redirection of all traffic or credential theft. Do not copy a speculative original title into the conclusion. In reviewerQuestions, an answer resolves only the specific condition asked; never say a single answer confirms exploitation or the entire attack. Upstream authentication is not proof of administrator authorization. Describe how the combination of conditions changes applicability. No production reachability or exploitation is verified. This applies across all STRIDE categories, not only authorization.
WIRE CONTRACT OVERRIDE for saved STRIDE: do NOT return the generic missingEvidence field shown in the base security example. The supplied schema deliberately excludes it. Every missing CODE fact belongs in engineering.obligations: mark the affected obligation missing and explain the exact missing implementation/binding in its reason. Deployment facts belong in deploymentAssumptions and reviewerQuestions. This replaces the generic missingEvidence checklist throughout the instructions below. assessment is the decision about the cited code path under those conditions. Do not require ALL valid inputs/provider names to establish one valid write path. If you need one accepted input to establish feasibility, retrieve that exact validation rather than expanding the claim.
`;

export function validateEngineeringArgument(value,packet,assessment) {
  const fail=m=>{throw Error('Security assessment failed schema or evidence validation (engineering: '+m+')');};
  const string=v=>{if(typeof v!=='string'||!v.trim()||v.length>1600)fail('bounded nonempty text required');return redact(v);};
  if(!value || !Array.isArray(value.obligations) || value.obligations.length!==4 || new Set(value.obligations.map(o=>o.kind)).size!==4)fail('exactly four distinct code obligations required');
  const obligations=value.obligations.map(o=>{
    if(!kinds.includes(o.kind)||!['established','blocks-attack','missing'].includes(o.status)||!Array.isArray(o.citations)||o.citations.length>4)fail('invalid code obligation');
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
  return {conclusion:string(value.conclusion),obligations,reviewerQuestions:value.reviewerQuestions.map(q=>({question:string(q.question),ifYes:string(q.ifYes),ifNo:string(q.ifNo)}))};
}
